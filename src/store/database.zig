// Phora — In-Memory Analysis Database
// Holds all analysis results indexed by address for O(1) lookup.
// This is the central data store that all MCP tools query.

const std = @import("std");
const types = @import("../types.zig");
const xref_mod = @import("../analysis/xref.zig");

// ============================================================================
// Candidate-based procedure resolution
// ============================================================================

pub const Confidence = enum(u8) { exact = 4, high = 3, medium = 2, low = 1, unknown = 0 };
pub const CandidateSource = enum(u4) { sized_range, nearest_entry, section_clamped, call_target, prologue };

pub const ProcCandidate = struct {
    proc: types.Procedure,
    confidence: Confidence,
    source: CandidateSource,
};

/// Match a value against a pattern that may contain pipe-separated alternatives (OR match).
/// E.g., "cheat|exploit|hack" matches if any of the sub-patterns match.
fn substringMatchMulti(haystack: []const u8, pattern: []const u8) bool {
    // Check if pattern contains '|' for multi-pattern OR matching
    if (std.mem.indexOf(u8, pattern, "|") == null) {
        return std.mem.indexOf(u8, haystack, pattern) != null;
    }

    // Split on '|' and check each sub-pattern
    var rest: []const u8 = pattern;
    while (rest.len > 0) {
        const sep_pos = std.mem.indexOf(u8, rest, "|");
        const sub = if (sep_pos) |pos| rest[0..pos] else rest;
        if (sub.len > 0 and std.mem.indexOf(u8, haystack, sub) != null) {
            return true;
        }
        if (sep_pos) |pos| {
            rest = rest[pos + 1 ..];
        } else {
            break;
        }
    }
    return false;
}

/// Central analysis database. Indexes all results by address.
pub const Database = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    /// Read-write lock for concurrent access from MCP tool handlers.
    /// Readers (search, get_*, analyze_*, etc.) take shared locks.
    /// Writers (annotate, rebase, mark_data_type) take exclusive locks.
    rw_lock: std.Io.RwLock,

    /// Procedures indexed by entry address.
    procedures: std.AutoHashMap(u64, types.Procedure),

    /// Strings indexed by address.
    strings: std.AutoHashMap(u64, types.String),

    /// Cross-references.
    xrefs: xref_mod.XrefTracker,

    /// Imports indexed by address.
    imports: std.AutoHashMap(u64, types.Import),

    /// Annotations indexed by address (multiple per address).
    annotations: std.AutoHashMap(u64, std.array_list.Managed(types.Annotation)),

    /// Instructions indexed by address.
    instructions: std.AutoHashMap(u64, types.Instruction),

    /// Symbol names indexed by address.
    symbols: std.AutoHashMap(u64, []const u8),

    /// IR results indexed by procedure entry address.
    ir_cache: std.AutoHashMap(u64, types.IRFunction),

    /// CFG results indexed by procedure entry address.
    cfg_cache: std.AutoHashMap(u64, types.CfgResult),

    /// Pre-lowercased string cache for fast case-insensitive search.
    /// Built lazily on first case-insensitive query, invalidated on addString.
    strings_lower: ?std.AutoHashMap(u64, []const u8) = null,

    /// Monotonic snapshot counter — incremented on every mutation.
    /// Agents use this for snapshot isolation (detect stale reads).
    snapshot_id: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Database {
        return .{
            .allocator = allocator,
            .io = io,
            .rw_lock = .init,
            .procedures = std.AutoHashMap(u64, types.Procedure).init(allocator),
            .strings = std.AutoHashMap(u64, types.String).init(allocator),
            .xrefs = xref_mod.XrefTracker.init(allocator, io),
            .imports = std.AutoHashMap(u64, types.Import).init(allocator),
            .annotations = std.AutoHashMap(u64, std.array_list.Managed(types.Annotation)).init(allocator),
            .instructions = std.AutoHashMap(u64, types.Instruction).init(allocator),
            .symbols = std.AutoHashMap(u64, []const u8).init(allocator),
            .ir_cache = std.AutoHashMap(u64, types.IRFunction).init(allocator),
            .cfg_cache = std.AutoHashMap(u64, types.CfgResult).init(allocator),
        };
    }

    pub fn deinit(self: *Database) void {
        if (self.strings_lower) |*cache| {
            var it = cache.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.value_ptr.*);
            }
            cache.deinit();
        }

        self.procedures.deinit();
        self.strings.deinit();
        self.xrefs.deinit();
        self.imports.deinit();

        var ann_it = self.annotations.valueIterator();
        while (ann_it.next()) |list| {
            list.deinit();
        }
        self.annotations.deinit();

        self.instructions.deinit();
        self.symbols.deinit();
        self.ir_cache.deinit();
        self.cfg_cache.deinit();
    }

    // ========================================================================
    // Procedures
    // ========================================================================

    pub fn addProcedure(self: *Database, proc: types.Procedure) !void {
        try self.procedures.put(proc.entry, proc);
        self.snapshot_id += 1;
    }

    pub fn getProcedure(self: *const Database, address: u64) ?types.Procedure {
        return self.procedures.get(address);
    }

    /// Return up to `max` candidate procedures that may contain `address`,
    /// ranked by confidence. Callers get visibility into ambiguity.
    const CandidateResult = struct { items: [3]ProcCandidate, count: u8 };

    pub fn getProcedureCandidates(self: *const Database, address: u64, max: u8) CandidateResult {
        var result: CandidateResult = .{ .items = undefined, .count = 0 };
        const cap = @min(max, 3);

        // Pass 1: exact sized range match → exact confidence (size known and
        // addr falls within [entry, entry+size)). If the entry matches exactly
        // and size is known, promote to exact; otherwise high.
        var it = self.procedures.valueIterator();
        while (it.next()) |proc| {
            if (proc.size > 0 and address >= proc.entry and address < proc.entry + proc.size) {
                if (result.count < cap) {
                    const conf: Confidence = if (address == proc.entry) .exact else .high;
                    result.items[result.count] = .{
                        .proc = proc.*,
                        .confidence = conf,
                        .source = .sized_range,
                    };
                    result.count += 1;
                }
            }
        }

        // If we already found an exact/high match, return early.
        if (result.count > 0) return result;

        // Pass 2: nearest entry below → medium confidence.
        // Only consider procedures with unknown size (size=0). Procedures
        // with known sizes that didn't match in pass 1 are definitively
        // ruled out — the address is not inside them.
        var best: ?types.Procedure = null;
        var best_entry: u64 = 0;
        var it2 = self.procedures.valueIterator();
        while (it2.next()) |proc| {
            if (proc.size == 0 and proc.entry <= address and proc.entry >= best_entry) {
                best = proc.*;
                best_entry = proc.entry;
            }
        }

        if (best) |b| {
            if (result.count < cap) {
                result.items[result.count] = .{
                    .proc = b,
                    .confidence = .medium,
                    .source = .nearest_entry,
                };
                result.count += 1;
            }
        }

        // Pass 3: rank by proximity — if we have multiple candidates, sort
        // so the closest entry is first (already the case from pass 2 since
        // we only add one nearest-entry candidate, but future passes for
        // section_clamped / call_target may add more).
        if (result.count > 1) {
            // Simple insertion sort by confidence descending, then proximity.
            var i: u8 = 1;
            while (i < result.count) : (i += 1) {
                var j: u8 = i;
                while (j > 0) {
                    const a_conf = @intFromEnum(result.items[j].confidence);
                    const b_conf = @intFromEnum(result.items[j - 1].confidence);
                    if (a_conf > b_conf or
                        (a_conf == b_conf and
                            absDiff(result.items[j].proc.entry, address) <
                                absDiff(result.items[j - 1].proc.entry, address)))
                    {
                        const tmp = result.items[j];
                        result.items[j] = result.items[j - 1];
                        result.items[j - 1] = tmp;
                    }
                    j -= 1;
                }
            }
        }

        return result;
    }

    /// Find the procedure that contains a given address (backward-compat wrapper).
    /// Returns the top candidate from `getProcedureCandidates`.
    pub fn getProcedureContaining(self: *const Database, address: u64) ?types.Procedure {
        const candidates = self.getProcedureCandidates(address, 1);
        return if (candidates.count > 0) candidates.items[0].proc else null;
    }

    /// Return the current snapshot ID (monotonic mutation counter).
    pub fn getSnapshotId(self: *const Database) u64 {
        return self.snapshot_id;
    }

    pub fn getAllProcedures(self: *const Database, allocator: std.mem.Allocator) ![]types.Procedure {
        var result = std.array_list.Managed(types.Procedure).init(allocator);
        errdefer result.deinit();

        var it = self.procedures.valueIterator();
        while (it.next()) |proc| {
            try result.append(proc.*);
        }

        // Sort by entry address
        std.mem.sort(types.Procedure, result.items, {}, struct {
            fn lessThan(_: void, a: types.Procedure, b: types.Procedure) bool {
                return a.entry < b.entry;
            }
        }.lessThan);

        return result.toOwnedSlice();
    }

    // ========================================================================
    // Strings
    // ========================================================================

    pub fn addString(self: *Database, str: types.String) !void {
        try self.strings.put(str.address, str);
        // Invalidate lowercase cache so it gets rebuilt on next search.
        if (self.strings_lower) |*cache| {
            var it = cache.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.value_ptr.*);
            }
            cache.deinit();
            self.strings_lower = null;
        }
    }

    pub fn getString(self: *const Database, address: u64) ?types.String {
        return self.strings.get(address);
    }

    pub fn getAllStrings(self: *const Database, allocator: std.mem.Allocator) ![]types.String {
        var result = std.array_list.Managed(types.String).init(allocator);
        errdefer result.deinit();

        var it = self.strings.valueIterator();
        while (it.next()) |str| {
            try result.append(str.*);
        }

        std.mem.sort(types.String, result.items, {}, struct {
            fn lessThan(_: void, a: types.String, b: types.String) bool {
                return a.address < b.address;
            }
        }.lessThan);

        return result.toOwnedSlice();
    }

    /// Build the pre-lowercased string cache lazily on first use.
    fn ensureLowercaseCache(self: *Database) void {
        if (self.strings_lower != null) return;
        var cache = std.AutoHashMap(u64, []const u8).init(self.allocator);
        var it = self.strings.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.value;
            const lower = self.allocator.alloc(u8, s.len) catch continue;
            for (s, 0..) |c, i| {
                lower[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
            }
            cache.put(entry.key_ptr.*, lower) catch {};
        }
        self.strings_lower = cache;
    }

    /// Search strings by pattern (substring match, supports pipe-separated OR).
    pub fn searchStrings(
        self: *Database,
        allocator: std.mem.Allocator,
        pattern: []const u8,
        max_results: u32,
    ) ![]types.String {
        var result = std.array_list.Managed(types.String).init(allocator);
        errdefer result.deinit();

        var it = self.strings.valueIterator();
        while (it.next()) |str| {
            if (result.items.len >= max_results) break;
            if (str.value.len < pattern.len) continue;
            if (str.value.len < 4 and pattern.len >= 4) continue;
            if (substringMatchMulti(str.value, pattern)) {
                try result.append(str.*);
            }
        }

        return result.toOwnedSlice();
    }

    // ========================================================================
    // Imports
    // ========================================================================

    pub fn addImport(self: *Database, imp: types.Import) !void {
        try self.imports.put(imp.address, imp);
        self.snapshot_id += 1;
    }

    pub fn getImport(self: *const Database, address: u64) ?types.Import {
        return self.imports.get(address);
    }

    pub fn getAllImports(self: *const Database, allocator: std.mem.Allocator) ![]types.Import {
        var result = std.array_list.Managed(types.Import).init(allocator);
        errdefer result.deinit();

        var it = self.imports.valueIterator();
        while (it.next()) |imp| {
            try result.append(imp.*);
        }

        std.mem.sort(types.Import, result.items, {}, struct {
            fn lessThan(_: void, a: types.Import, b: types.Import) bool {
                return a.address < b.address;
            }
        }.lessThan);

        return result.toOwnedSlice();
    }

    // ========================================================================
    // Annotations
    // ========================================================================

    pub fn addAnnotation(self: *Database, ann: types.Annotation) !void {
        const entry = try self.annotations.getOrPut(ann.address);
        if (!entry.found_existing) {
            entry.value_ptr.* = std.array_list.Managed(types.Annotation).init(self.allocator);
        }
        try entry.value_ptr.append(ann);
        self.snapshot_id += 1;
    }

    pub fn getAnnotations(self: *const Database, address: u64) []const types.Annotation {
        if (self.annotations.get(address)) |list| {
            return list.items;
        }
        return &.{};
    }

    // ========================================================================
    // Instructions
    // ========================================================================

    pub fn addInstruction(self: *Database, inst: types.Instruction) !void {
        // Store the instruction. The operands are in the owned buffer
        // (operands_buf), but the operands slice points to the source struct's
        // buffer. After put(), fix up the slice to point to the stored copy's buffer.
        try self.instructions.put(inst.address, inst);
        if (self.instructions.getPtr(inst.address)) |stored| {
            stored.operands = stored.operands_buf[0..stored.operands_len];
        }
        self.snapshot_id += 1;
    }

    pub fn getInstruction(self: *const Database, address: u64) ?types.Instruction {
        const ptr = self.instructions.getPtr(address) orelse return null;
        var inst = ptr.*;
        // v7.15.2 C1: Instruction.operands is a self-referential slice into
        // operands_buf. addInstruction fixes it up to point at the stored
        // entry's buffer, but subsequent HashMap growth/rehash moves entries —
        // leaving .operands pointing at a freed bucket. Re-derive from the
        // CURRENT HashMap entry's own operands_buf via getPtr; the slice is
        // valid until the next addInstruction triggers another rehash. The
        // local-copy variant of this fix doesn't work — the slice would point
        // at the stack frame that dies on return. SIGSEGVs decompile when the
        // lift loop reads garbage operands (recursive panic in std.debug.print
        // on bad UTF-8).
        inst.operands = ptr.operands_buf[0..ptr.operands_len];
        return inst;
    }

    /// Get instruction operands as a properly-owned slice.
    /// The Instruction.operands slice is a self-referential pointer that becomes
    /// dangling after copies. Use this instead to get valid operand text.
    pub fn getInstructionOperands(self: *const Database, address: u64) []const u8 {
        if (self.instructions.getPtr(address)) |ptr| {
            return ptr.operands_buf[0..ptr.operands_len];
        }
        return &.{};
    }

    // ========================================================================
    // Symbols
    // ========================================================================

    pub fn addSymbol(self: *Database, address: u64, name: []const u8) !void {
        try self.symbols.put(address, name);
    }

    pub fn removeSymbol(self: *Database, address: u64) void {
        _ = self.symbols.remove(address);
    }

    pub fn getSymbolName(self: *const Database, address: u64) ?[]const u8 {
        return self.symbols.get(address);
    }

    /// Resolve an address to a name. Checks symbols first, then procedures, then imports.
    pub fn resolveName(self: *const Database, address: u64) ?[]const u8 {
        if (self.symbols.get(address)) |name| return name;
        if (self.procedures.get(address)) |proc| return proc.name;
        if (self.imports.get(address)) |imp| return imp.name;
        return null;
    }

    // ========================================================================
    // IR Cache
    // ========================================================================

    pub fn cacheIR(self: *Database, address: u64, ir: types.IRFunction) !void {
        try self.ir_cache.put(address, ir);
    }

    pub fn getCachedIR(self: *const Database, address: u64) ?types.IRFunction {
        return self.ir_cache.get(address);
    }

    // ========================================================================
    // CFG Cache
    // ========================================================================

    pub fn cacheCfg(self: *Database, address: u64, cfg_result: types.CfgResult) !void {
        try self.cfg_cache.put(address, cfg_result);
    }

    pub fn getCachedCfg(self: *const Database, address: u64) ?types.CfgResult {
        return self.cfg_cache.get(address);
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    pub fn getStats(self: *const Database) types.DocumentStats {
        return .{
            .procedure_count = @intCast(self.procedures.count()),
            .string_count = @intCast(self.strings.count()),
            .import_count = @intCast(self.imports.count()),
            .segment_count = 0, // segments live on Document, not DB
            .section_count = 0,
            .total_size = 0,
        };
    }

    // ========================================================================
    // Search
    // ========================================================================

    /// Unified search across all indexed data.
    pub fn search(
        self: *Database,
        allocator: std.mem.Allocator,
        query: types.SearchQuery,
    ) ![]types.SearchResult {
        var results = std.array_list.Managed(types.SearchResult).init(allocator);
        errdefer results.deinit();

        switch (query.query_type) {
            .name => {
                if (query.pattern) |pattern| {
                    // Search procedure names
                    var proc_it = self.procedures.iterator();
                    while (proc_it.next()) |entry| {
                        if (results.items.len >= query.max_results) break;
                        if (entry.value_ptr.name) |name| {
                            if (substringMatchMultiCI(name, pattern, query.case_insensitive)) {
                                const xref_count: u32 = @intCast(self.xrefs.getRefsTo(entry.key_ptr.*).len);
                                if (query.max_xrefs) |max| {
                                    if (xref_count > max) continue;
                                }
                                try results.append(.{
                                    .address = entry.key_ptr.*,
                                    .match_text = name,
                                    .result_type = "procedure",
                                    .xref_count = xref_count,
                                });
                            }
                        }
                    }
                    // Search symbol names
                    var sym_it = self.symbols.iterator();
                    while (sym_it.next()) |entry| {
                        if (results.items.len >= query.max_results) break;
                        if (substringMatchMultiCI(entry.value_ptr.*, pattern, query.case_insensitive)) {
                            const xref_count: u32 = @intCast(self.xrefs.getRefsTo(entry.key_ptr.*).len);
                            if (query.max_xrefs) |max| {
                                if (xref_count > max) continue;
                            }
                            try results.append(.{
                                .address = entry.key_ptr.*,
                                .match_text = entry.value_ptr.*,
                                .result_type = "symbol",
                                .xref_count = xref_count,
                            });
                        }
                    }
                }
            },
            .string => {
                if (query.pattern) |pattern| {
                    if (query.case_insensitive) {
                        // Use pre-lowered cache for O(1) lowercase lookups
                        self.ensureLowercaseCache();
                        var str_it = self.strings.iterator();
                        while (str_it.next()) |entry| {
                            if (results.items.len >= query.max_results) break;
                            const str = entry.value_ptr;
                            if (str.value.len < pattern.len) continue;
                            if (str.value.len < 4 and pattern.len >= 4) continue;
                            if (self.strings_lower.?.get(entry.key_ptr.*)) |lower_val| {
                                if (substringMatchMulti(lower_val, pattern)) {
                                    try results.append(.{
                                        .address = str.address,
                                        .match_text = str.value,
                                        .result_type = "string",
                                    });
                                }
                            }
                        }
                    } else {
                        var str_it = self.strings.valueIterator();
                        while (str_it.next()) |str| {
                            if (results.items.len >= query.max_results) break;
                            if (str.value.len < pattern.len) continue;
                            if (str.value.len < 4 and pattern.len >= 4) continue;
                            if (substringMatchMulti(str.value, pattern)) {
                                try results.append(.{
                                    .address = str.address,
                                    .match_text = str.value,
                                    .result_type = "string",
                                });
                            }
                        }
                    }
                }
            },
            .callers_of => {
                if (query.address) |addr| {
                    const refs = self.xrefs.getRefsTo(addr);
                    for (refs) |xref| {
                        if (results.items.len >= query.max_results) break;
                        if (xref.xref_type == .call) {
                            try results.append(.{
                                .address = xref.from,
                                .match_text = self.resolveName(xref.from) orelse "unknown",
                                .result_type = "caller",
                            });
                        }
                    }
                }
            },
            .callees_of => {
                if (query.address) |addr| {
                    const refs = self.xrefs.getRefsFrom(addr);
                    for (refs) |xref| {
                        if (results.items.len >= query.max_results) break;
                        if (xref.xref_type == .call) {
                            try results.append(.{
                                .address = xref.to,
                                .match_text = self.resolveName(xref.to) orelse "unknown",
                                .result_type = "callee",
                            });
                        }
                    }
                }
            },
            .procedures => {
                var proc_it = self.procedures.valueIterator();
                while (proc_it.next()) |proc| {
                    if (results.items.len >= query.max_results) break;
                    // Check symbols first (for annotated names), fall back to proc.name
                    const name = self.symbols.get(proc.entry) orelse proc.name orelse "unnamed";
                    if (query.pattern) |p| {
                        if (!substringMatchMultiCI(name, p, query.case_insensitive)) continue;
                    }
                    const xref_count: u32 = @intCast(self.xrefs.getRefsTo(proc.entry).len);
                    if (query.max_xrefs) |max| {
                        if (xref_count > max) continue;
                    }
                    try results.append(.{
                        .address = proc.entry,
                        .match_text = name,
                        .result_type = "procedure",
                        .xref_count = xref_count,
                    });
                }
            },
            .imports => {
                var imp_it = self.imports.valueIterator();
                while (imp_it.next()) |imp| {
                    if (results.items.len >= query.max_results) break;
                    if (query.pattern) |p| {
                        if (!substringMatchMultiCI(imp.name, p, query.case_insensitive)) continue;
                    }
                    try results.append(.{
                        .address = imp.address,
                        .match_text = imp.name,
                        .result_type = "import",
                    });
                }
            },
            .string_refs => {
                // Find procedures that reference strings matching pattern.
                // ARM64 string loads use ADRP (page) + ADD (offset). The xref
                // tracker records ADRP targets (page-aligned) and ADD targets
                // (exact address via data_read on the ADD's computed address).
                //
                // Strategy: collect exact matching string addresses, then check
                // xrefs that either hit the exact address OR hit the page when
                // the following instruction (ADD) resolves to a matching string.
                // For precision, we use the ADD instruction in the database to
                // compute the actual referenced address from ADRP+ADD pairs.
                if (query.pattern) |pattern| {
                    // Collect all matching string exact addresses
                    var match_addrs = std.AutoHashMap(u64, []const u8).init(allocator);
                    defer match_addrs.deinit();

                    if (query.case_insensitive) {
                        self.ensureLowercaseCache();
                        var str_it = self.strings.iterator();
                        while (str_it.next()) |entry| {
                            const str = entry.value_ptr;
                            if (str.value.len < pattern.len) continue;
                            if (str.value.len < 4 and pattern.len >= 4) continue;
                            if (self.strings_lower.?.get(entry.key_ptr.*)) |lower_val| {
                                if (substringMatchMulti(lower_val, pattern)) {
                                    match_addrs.put(str.address, str.value) catch {};
                                }
                            }
                        }
                    } else {
                        var str_it = self.strings.valueIterator();
                        while (str_it.next()) |str| {
                            if (str.value.len < pattern.len) continue;
                            if (str.value.len < 4 and pattern.len >= 4) continue;
                            if (substringMatchMulti(str.value, pattern)) {
                                match_addrs.put(str.address, str.value) catch {};
                            }
                        }
                    }

                    if (match_addrs.count() > 0) {

                        // Build a set of pages that contain matching strings
                        var match_pages = std.AutoHashMap(u64, void).init(allocator);
                        defer match_pages.deinit();
                        {
                            var ma_it = match_addrs.keyIterator();
                            while (ma_it.next()) |addr| {
                                match_pages.put(addr.* & ~@as(u64, 0xFFF), {}) catch {};
                            }
                        }

                        var seen_procs = std.AutoHashMap(u64, void).init(allocator);
                        defer seen_procs.deinit();

                        // Scan data_read xrefs for ADRP targets on matching pages,
                        // then verify by checking ADD instruction for exact string address
                        var xref_it = self.xrefs.refs_from.iterator();
                        while (xref_it.next()) |entry| {
                            if (results.items.len >= query.max_results) break;
                            const from_addr = entry.key_ptr.*;
                            for (entry.value_ptr.items) |xref| {
                                if (results.items.len >= query.max_results) break;

                                // Direct exact match (rare but possible)
                                if (match_addrs.get(xref.to)) |str_val| {
                                    if (self.getProcedureContaining(from_addr)) |proc| {
                                        // Skip stub trampolines (12-16 byte entries in __stubs/__auth_stubs)
                                        if (proc.size > 0 and proc.size <= 16) continue;
                                        if (!seen_procs.contains(proc.entry)) {
                                            seen_procs.put(proc.entry, {}) catch {};
                                            try results.append(.{
                                                .address = proc.entry,
                                                .match_text = proc.name orelse "unnamed",
                                                .result_type = "procedure",
                                                .context = str_val,
                                            });
                                        }
                                    }
                                    continue;
                                }

                                // ADRP page match: verify with ADD instruction
                                if (xref.xref_type == .data_read and match_pages.contains(xref.to)) {
                                    // Check the instruction 4 bytes after this one (ADD Xd, Xn, #off)
                                    if (self.getInstruction(from_addr + 4)) |next_inst| {
                                        const mn = next_inst.mnemonic;
                                        if (std.mem.eql(u8, mn, "add") or std.mem.eql(u8, mn, "ADD")) {
                                            // Parse the immediate from ADD operands to compute exact addr
                                            // Use getInstructionOperands for valid (non-dangling) operand text
                                            const add_ops = self.getInstructionOperands(from_addr + 4);
                                            if (parseAddImmediate(add_ops)) |imm| {
                                                const exact_addr = xref.to + imm;
                                                if (match_addrs.get(exact_addr)) |str_val| {
                                                    if (self.getProcedureContaining(from_addr)) |proc| {
                                                        // Skip stub trampolines
                                                        if (proc.size > 0 and proc.size <= 16) continue;
                                                        if (!seen_procs.contains(proc.entry)) {
                                                            seen_procs.put(proc.entry, {}) catch {};
                                                            try results.append(.{
                                                                .address = proc.entry,
                                                                .match_text = proc.name orelse "unnamed",
                                                                .result_type = "procedure",
                                                                .context = str_val,
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } // end if (match_addrs.count() > 0)
                }
            },
            .calls => {
                // Find all procedures that call a given function (by name pattern)
                if (query.pattern) |pattern| {
                    // First find addresses matching the pattern
                    var target_addrs = std.array_list.Managed(u64).init(allocator);
                    defer target_addrs.deinit();

                    var proc_it = self.procedures.iterator();
                    while (proc_it.next()) |entry| {
                        if (entry.value_ptr.name) |name| {
                            if (substringMatchMulti(name, pattern)) {
                                try target_addrs.append(entry.key_ptr.*);
                            }
                        }
                    }
                    var imp_it = self.imports.iterator();
                    while (imp_it.next()) |entry| {
                        if (substringMatchMulti(entry.value_ptr.name, pattern)) {
                            try target_addrs.append(entry.key_ptr.*);
                        }
                    }

                    // Now find all callers of those addresses
                    for (target_addrs.items) |target| {
                        const refs = self.xrefs.getRefsTo(target);
                        for (refs) |xref| {
                            if (results.items.len >= query.max_results) break;
                            if (xref.xref_type == .call) {
                                // Find which procedure contains this call site
                                if (self.getProcedureContaining(xref.from)) |caller_proc| {
                                    try results.append(.{
                                        .address = caller_proc.entry,
                                        .match_text = caller_proc.name orelse "unnamed",
                                        .result_type = "procedure",
                                    });
                                }
                            }
                        }
                    }
                }
            },
            .writers_of => {
                // v7.9.1 Q4: writers_of is handled by a dedicated path in
                // tools.zig (handleSearchWritersOf) that scans executable
                // segments for arch-specific lui+sw / adrp+str / mov-absolute
                // patterns targeting the given address. Return empty from the
                // generic db.search so the caller falls through to the
                // specialized handler.
            },
        }

        return results.toOwnedSlice();
    }
};

/// Parse the immediate value from an ADD instruction's operand string.
/// Expected format: "Xd, Xn, #0xOFF" or "Xd, Xn, #DEC"
fn parseAddImmediate(operands: []const u8) ?u64 {
    // Find '#' marker for immediate
    const hash_idx = std.mem.indexOf(u8, operands, "#") orelse return null;
    const after_hash = operands[hash_idx + 1 ..];

    if (after_hash.len >= 2 and after_hash[0] == '0' and after_hash[1] == 'x') {
        // Hex: #0xABC
        var end: usize = 2;
        while (end < after_hash.len and isHexDigit(after_hash[end])) : (end += 1) {}
        return std.fmt.parseInt(u64, after_hash[2..end], 16) catch null;
    } else {
        // Decimal: #123
        var end: usize = 0;
        while (end < after_hash.len and after_hash[end] >= '0' and after_hash[end] <= '9') : (end += 1) {}
        if (end == 0) return null;
        return std.fmt.parseInt(u64, after_hash[0..end], 10) catch null;
    }
}

/// Absolute difference between two u64 values.
fn absDiff(a: u64, b: u64) u64 {
    return if (a >= b) a - b else b - a;
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

/// Case-insensitive version of substringMatchMulti.
/// If case_insensitive is false, behaves identically to substringMatchMulti.
fn substringMatchMultiCI(haystack: []const u8, pattern: []const u8, case_insensitive: bool) bool {
    if (!case_insensitive) return substringMatchMulti(haystack, pattern);

    // Lowercase haystack into a stack buffer
    var lower_buf: [4096]u8 = undefined;
    const hay_len = @min(haystack.len, lower_buf.len);
    for (haystack[0..hay_len], 0..) |c, i| {
        lower_buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    const lower_hay = lower_buf[0..hay_len];

    // Pattern should already be lowercased by the caller
    return substringMatchMulti(lower_hay, pattern);
}

// ============================================================================
// Tests
// ============================================================================

test "database add and get procedure" {
    const allocator = std.testing.allocator;
    var db = Database.init(allocator, std.testing.io);
    defer db.deinit();

    try db.addProcedure(.{
        .entry = 0x1000,
        .size = 64,
        .name = "_main",
    });

    const proc = db.getProcedure(0x1000);
    try std.testing.expect(proc != null);
    try std.testing.expectEqualStrings("_main", proc.?.name.?);
}

test "database resolve name" {
    const allocator = std.testing.allocator;
    var db = Database.init(allocator, std.testing.io);
    defer db.deinit();

    try db.addSymbol(0x1000, "_start");
    try db.addProcedure(.{ .entry = 0x2000, .size = 32, .name = "_main" });
    try db.addImport(.{ .address = 0x3000, .name = "printf" });

    try std.testing.expectEqualStrings("_start", db.resolveName(0x1000).?);
    try std.testing.expectEqualStrings("_main", db.resolveName(0x2000).?);
    try std.testing.expectEqualStrings("printf", db.resolveName(0x3000).?);
    try std.testing.expect(db.resolveName(0xDEAD) == null);
}

test "database procedure containing address" {
    const allocator = std.testing.allocator;
    var db = Database.init(allocator, std.testing.io);
    defer db.deinit();

    try db.addProcedure(.{ .entry = 0x1000, .size = 64 });
    try db.addProcedure(.{ .entry = 0x2000, .size = 32 });

    const p1 = db.getProcedureContaining(0x1020);
    try std.testing.expect(p1 != null);
    try std.testing.expectEqual(@as(u64, 0x1000), p1.?.entry);

    const p2 = db.getProcedureContaining(0x2010);
    try std.testing.expect(p2 != null);
    try std.testing.expectEqual(@as(u64, 0x2000), p2.?.entry);

    const p3 = db.getProcedureContaining(0x9000);
    try std.testing.expect(p3 == null);
}

test "database stats" {
    const allocator = std.testing.allocator;
    var db = Database.init(allocator, std.testing.io);
    defer db.deinit();

    try db.addProcedure(.{ .entry = 0x1000, .size = 64 });
    try db.addString(.{ .address = 0x2000, .value = "hello", .length = 5 });
    try db.addImport(.{ .address = 0x3000, .name = "printf" });

    const stats = db.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats.procedure_count);
    try std.testing.expectEqual(@as(u32, 1), stats.string_count);
    try std.testing.expectEqual(@as(u32, 1), stats.import_count);
}
