// Phora — Unified Analysis Pipeline
// Single entry point for all binary analysis: disassembly, procedure detection,
// string detection, xref tracking, and lifting.
// Both CLI (main.zig) and MCP (tools.zig) call this — ensuring identical results.

const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../runtime.zig");
const types = @import("../types.zig");
const xref_mod = @import("xref.zig");
const strings_mod = @import("strings.zig");
const proc_detector = @import("procedures.zig");
const disassembler = @import("disassembler.zig");
const arm64_decoder = @import("../arch/arm64.zig");
const arm32_decoder = @import("../arch/arm32.zig");
const x86_64_decoder = @import("../arch/x86_64.zig");

const lifter = @import("../lifter/lift.zig");
const db_mod = @import("../store/database.zig");

// v7.8.0 W2/W3/W4 — structured CF, jump-table recovery, type recovery
const structure_mod = @import("structure.zig");
const jumptable_mod = @import("jumptable.zig");
const types_recovery_mod = @import("types.zig");
const parallel_mod = @import("parallel.zig");

/// v7.4.2 F4 — Progress logging for slow loads.
/// Emits stderr lines at phase boundaries so the user/LLM can see the load is
/// progressing instead of staring at a silent 226-second wait. Per user
/// feedback `feedback_load_timeout`: "Slow loads are OK; empty/timeout
/// responses are not." Lines look like:
///   [phora load] phase=disasm elapsed=12340ms
/// Always enabled — costs nothing and helps debug stuck loads.
inline fn logPhase(io: std.Io, name: []const u8, start_ms: i64) void {
    if (builtin.is_test) return;
    const elapsed = runtime.awakeMillis(io) - start_ms;
    std.debug.print("[phora load] phase={s} elapsed={d}ms\n", .{ name, elapsed });
}

/// Result of the unified analysis pipeline.
pub const AnalysisResult = struct {
    procedures: []proc_detector.DetectedProcedure,
    stub_count: usize,
    strings: std.array_list.Managed(types.String),
    xrefs: xref_mod.XrefTracker,
    instructions: ?std.array_list.Managed(types.Instruction),
    lift_success: bool,

    /// Code procedures only (for accuracy scoring against source truth).
    pub fn procedureCount(self: *const AnalysisResult) usize {
        return self.procedures.len - self.stub_count;
    }

    /// Total including stubs (for comparison with Hopper).
    pub fn totalProcedureCount(self: *const AnalysisResult) usize {
        return self.procedures.len;
    }

    pub fn stringCount(self: *const AnalysisResult) usize {
        return self.strings.items.len;
    }

    pub fn xrefCount(self: *const AnalysisResult) usize {
        return self.xrefs.count();
    }

    pub fn deinit(self: *AnalysisResult, allocator: std.mem.Allocator) void {
        allocator.free(self.procedures);
        self.strings.deinit();
        self.xrefs.deinit();
        if (self.instructions) |*insns| {
            insns.deinit();
        }
    }
};

/// Run the full analysis pipeline on a loaded document.
/// This is the single source of truth for analysis — both CLI and MCP use this.
/// Set keep_instructions=true for MCP path (stores in database), false for CLI (saves memory).
pub fn analyze(
    allocator: std.mem.Allocator,
    io: std.Io,
    doc: *types.Document,
    data: []const u8,
) !AnalysisResult {
    return analyzeWithOptions(allocator, io, doc, data, true);
}

/// Analyze without keeping decoded instructions in memory (CLI path).
pub fn analyzeLean(
    allocator: std.mem.Allocator,
    io: std.Io,
    doc: *types.Document,
    data: []const u8,
) !AnalysisResult {
    return analyzeWithOptions(allocator, io, doc, data, false);
}

fn analyzeWithOptions(
    allocator: std.mem.Allocator,
    io: std.Io,
    doc: *types.Document,
    data: []const u8,
    keep_instructions: bool,
) !AnalysisResult {
    const phase_start = runtime.awakeMillis(io);
    logPhase(io, "analyze_start", phase_start);

    var xrefs = xref_mod.XrefTracker.init(allocator, io);
    errdefer xrefs.deinit();

    var instructions: ?std.array_list.Managed(types.Instruction) = null;
    errdefer if (instructions) |*insns| insns.deinit();

    // Step 1: Disassemble code sections (ARM64), populating xrefs
    if (doc.arch == .arm64) {
        if (keep_instructions) {
            // Full mode (MCP): decode all instructions, track all xref types
            instructions = try disassembler.disassembleDocument(
                allocator,
                doc,
                arm64_decoder.decodeInstruction,
                &xrefs,
            );
        } else {
            // Lean mode (CLI): only extract call xrefs, don't store instructions.
            // Massively reduces memory for large binaries (90MB: 4GB→<1GB).
            _ = try disassembler.disassembleDocumentLean(
                allocator,
                doc,
                arm64_decoder.decodeInstruction,
                &xrefs,
            );
        }

        // Find __text/.text section boundaries
        var text_start: u64 = 0;
        var text_end: u64 = 0;
        for (doc.segments) |seg| {
            if (!seg.permissions.execute) continue;
            for (seg.sections) |sec| {
                if (std.mem.eql(u8, sec.name, "__text") or
                    std.mem.eql(u8, sec.name, ".text"))
                {
                    text_start = sec.start;
                    text_end = sec.start + sec.length;
                }
            }
        }

        // Add call targets from xrefs as procedures on the document,
        // but ONLY if the target is within __text (not stubs/helpers).
        // Use a HashSet for O(1) dedup instead of linear scan.
        var proc_set = std.AutoHashMap(u64, void).init(allocator);
        defer proc_set.deinit();
        for (doc.procedures.items) |p| {
            proc_set.put(p.entry, {}) catch {};
        }

        const call_targets = try xrefs.getCallTargets(allocator);
        defer allocator.free(call_targets);

        for (call_targets) |target| {
            if (target < text_start or target >= text_end) continue;
            if (!proc_set.contains(target)) {
                proc_set.put(target, {}) catch {};
                doc.procedures.append(.{
                    .entry = target,
                    .size = 0,
                    .name = null,
                }) catch {};
            }
        }

        // B-target jumps are NOT added as procedures — they are mostly
        // internal jumps within functions (loops, conditionals), not tail calls.
        // Including them causes massive overdetection (e.g. wc: 98 vs 6 real).
    } else if (doc.arch == .arm32) {
        // ARM32/Thumb lean disassembly — variable-size Thumb instructions
        _ = try disassembler.disassembleDocumentLean32(
            allocator,
            doc,
            &xrefs,
        );

        // Find .text section boundaries (ELF uses .text, not __text)
        var text_start: u64 = 0;
        var text_end: u64 = 0;
        for (doc.segments) |seg| {
            if (!seg.permissions.execute) continue;
            for (seg.sections) |sec| {
                if (std.mem.eql(u8, sec.name, ".text") or
                    std.mem.eql(u8, sec.name, "__text"))
                {
                    text_start = sec.start;
                    text_end = sec.start + sec.length;
                }
            }
        }

        // Add call targets as procedures (same logic as arm64 path)
        var proc_set = std.AutoHashMap(u64, void).init(allocator);
        defer proc_set.deinit();
        for (doc.procedures.items) |p| {
            proc_set.put(p.entry, {}) catch {};
        }

        const call_targets = try xrefs.getCallTargets(allocator);
        defer allocator.free(call_targets);

        for (call_targets) |target| {
            if (target < text_start or target >= text_end) continue;
            if (!proc_set.contains(target)) {
                proc_set.put(target, {}) catch {};
                doc.procedures.append(.{
                    .entry = target,
                    .size = 0,
                    .name = null,
                }) catch {};
            }
        }
    } else if (doc.arch == .mips32) {
        // MIPS32 lean disassembly — LUI+ADDIU/ORI data refs + call/jump xrefs
        try disassembler.disassembleDocumentLeanMips32(allocator, doc, &xrefs, data);

        // Find .text section boundaries
        var text_start: u64 = 0;
        var text_end: u64 = 0;
        for (doc.segments) |seg| {
            if (!seg.permissions.execute) continue;
            for (seg.sections) |sec| {
                if (std.mem.eql(u8, sec.name, ".text") or
                    std.mem.eql(u8, sec.name, "__text"))
                {
                    text_start = sec.start;
                    text_end = sec.start + sec.length;
                }
            }
        }

        // Add call targets as procedures (same logic as arm64/arm32 path)
        var proc_set = std.AutoHashMap(u64, void).init(allocator);
        defer proc_set.deinit();
        for (doc.procedures.items) |p| {
            proc_set.put(p.entry, {}) catch {};
        }

        const call_targets = try xrefs.getCallTargets(allocator);
        defer allocator.free(call_targets);

        for (call_targets) |target| {
            if (target < text_start or target >= text_end) continue;
            if (!proc_set.contains(target)) {
                proc_set.put(target, {}) catch {};
                doc.procedures.append(.{
                    .entry = target,
                    .size = 0,
                    .name = null,
                }) catch {};
            }
        }
    } else if (doc.arch == .x86_64) {
        // x86_64 lean disassembly — variable-length instructions
        _ = try disassembler.disassembleDocumentLeanX86_64(
            allocator,
            doc,
            &xrefs,
        );

        // Find __text/.text section boundaries
        var text_start: u64 = 0;
        var text_end: u64 = 0;
        for (doc.segments) |seg| {
            if (!seg.permissions.execute) continue;
            for (seg.sections) |sec| {
                if (std.mem.eql(u8, sec.name, "__text") or
                    std.mem.eql(u8, sec.name, ".text"))
                {
                    text_start = sec.start;
                    text_end = sec.start + sec.length;
                }
            }
        }

        // Add call targets as procedures
        var proc_set = std.AutoHashMap(u64, void).init(allocator);
        defer proc_set.deinit();
        for (doc.procedures.items) |p| {
            proc_set.put(p.entry, {}) catch {};
        }
        const call_targets = try xrefs.getCallTargets(allocator);
        defer allocator.free(call_targets);
        for (call_targets) |target| {
            if (target < text_start or target >= text_end) continue;
            if (!proc_set.contains(target)) {
                proc_set.put(target, {}) catch {};
                doc.procedures.append(.{ .entry = target, .size = 0, .name = null }) catch {};
            }
        }
    } else if (doc.arch == .x86) {
        // v7.13.0 B1+B2 — x86-32 (i386) PE binaries.
        // Pre-fix: no lean sweep ran for .x86 → 0 procs, 0 string_refs.
        _ = try disassembler.disassembleDocumentLeanX86(allocator, doc, &xrefs);

        var text_start: u64 = 0;
        var text_end: u64 = 0;
        for (doc.segments) |seg| {
            if (!seg.permissions.execute) continue;
            for (seg.sections) |sec| {
                if (std.mem.eql(u8, sec.name, "__text") or
                    std.mem.eql(u8, sec.name, ".text"))
                {
                    text_start = sec.start;
                    text_end = sec.start + sec.length;
                }
            }
        }

        // Add call targets as procedures (same logic as other archs).
        var proc_set = std.AutoHashMap(u64, void).init(allocator);
        defer proc_set.deinit();
        for (doc.procedures.items) |p| {
            proc_set.put(p.entry, {}) catch {};
        }
        const call_targets = try xrefs.getCallTargets(allocator);
        defer allocator.free(call_targets);
        for (call_targets) |target| {
            if (target < text_start or target >= text_end) continue;
            if (!proc_set.contains(target)) {
                proc_set.put(target, {}) catch {};
                doc.procedures.append(.{ .entry = target, .size = 0, .name = null }) catch {};
            }
        }
    }

    logPhase(io, "disasm_done", phase_start);

    // Step 2: Detect procedures via call targets + entry point + prologue
    // All sources are now filtered: call targets within __text only,
    // prologue scan restricted to __text/STP X29,X30 only.
    const text_procedures = if (doc.arch == .arm64 or doc.arch == .arm32 or doc.arch == .mips32 or doc.arch == .x86_64 or doc.arch == .x86)
        try proc_detector.detectProcedures(allocator, doc, &xrefs)
    else
        try allocator.alloc(proc_detector.DetectedProcedure, 0);
    defer allocator.free(text_procedures);

    // Step 2b: Count stub trampolines (__auth_stubs, __stubs) as procedures.
    // Each stub is a callable entry point (import trampoline). Hopper counts these.
    var stub_count: usize = 0;
    for (doc.segments) |seg| {
        if (!seg.permissions.execute) continue;
        for (seg.sections) |sec| {
            if (std.mem.eql(u8, sec.name, "__auth_stubs") or
                std.mem.eql(u8, sec.name, "__stubs"))
            {
                // Each auth_stub is 16 bytes, each regular stub is 12 bytes
                const stub_size: usize = if (std.mem.eql(u8, sec.name, "__auth_stubs")) 16 else 12;
                stub_count += @intCast(sec.length / stub_size);
            }
        }
    }

    // Merge text procedures + stub count into final result
    var all_procs = std.array_list.Managed(proc_detector.DetectedProcedure).init(allocator);
    errdefer all_procs.deinit();
    try all_procs.appendSlice(text_procedures);

    // Add stub entries as symbol-sourced procedures
    for (doc.segments) |seg| {
        if (!seg.permissions.execute) continue;
        for (seg.sections) |sec| {
            if (std.mem.eql(u8, sec.name, "__auth_stubs") or
                std.mem.eql(u8, sec.name, "__stubs"))
            {
                const stub_size: u64 = if (std.mem.eql(u8, sec.name, "__auth_stubs")) 16 else 12;
                var addr = sec.start;
                while (addr < sec.start + sec.length) : (addr += stub_size) {
                    try all_procs.append(.{
                        .entry = addr,
                        .source = .symbol,
                    });
                }
            }
        }
    }

    const procedures = try all_procs.toOwnedSlice();
    errdefer allocator.free(procedures);

    // Note: stub→import mapping for Mach-O is done in the loader via the
    // indirect symbol table (reserved1 + dysymtab). ELF PLT mapping is TODO.

    logPhase(io, "procedures_done", phase_start);

    // Step 3: Detect strings — uniform min_len=4 across all sections, no gap scanning
    var detected_strings = try strings_mod.detectAllStrings(allocator, doc);
    errdefer detected_strings.deinit();

    logPhase(io, "strings_done", phase_start);

    // ====================================================================
    // Phase 5: Lift procedures to IR (W1 — maturity passes wired)
    // Phase 6: Recover structured control flow (W2)
    // Phase 7: Detect jump tables (W3)
    // Phase 8: Recover types from IR (W4)
    //
    // PARALLELISATION: kept SERIAL for v7.8.0 — see W1A1 caveat.
    // `liftProcedure` reads from a `*Database` whose internal HashMaps are
    // not documented as thread-safe; running it in parallel risks racy reads
    // even though we never write through that pointer. Per the safety
    // guidance ("Default to option 2 if in doubt — ship safe first, optimize
    // later") we ship serial. The parallel scaffolding (parallel_mod) is
    // imported so W8 (v7.9) can flip a feature flag to enable it once a
    // thread-safe read API exists.
    //
    // Cost cap: we lift up to MAX_LIFT_FUNCS procedures so very large
    // binaries (10k+ functions) don't spend minutes here. The pseudocode
    // tool already lifts on demand.
    // ====================================================================
    var lift_success = false;
    runMaturityPipeline(allocator, io, doc, data) catch |err| {
        // Phase 5+ are best-effort: a failure here shouldn't block the rest
        // of the analysis result. We log and continue with lift_success=false.
        if (!builtin.is_test) std.debug.print("[phora load] phase=maturity_pipeline error={s}\n", .{@errorName(err)});
    };
    // If any structured function was produced, the lifter clearly succeeded
    // for at least one proc.
    if (doc.structured_functions) |sf_map| {
        if (sf_map.count() > 0) lift_success = true;
    }
    logPhase(io, "maturity_done", phase_start);

    logPhase(io, "analyze_done", phase_start);

    return .{
        .procedures = procedures,
        .stub_count = stub_count,
        .strings = detected_strings,
        .xrefs = xrefs,
        .instructions = instructions,
        .lift_success = lift_success,
    };
}

// ============================================================================
// v7.8.0 maturity pipeline (Phase 5 — Phase 8)
// ============================================================================

/// Cap on how many procedures we run the v7.8.0 maturity pipeline on per
/// load. Beyond this, agents can opt-in to per-function analysis via the
/// pseudocode/decompile MCP tools (which lift on demand). 4 KiB == ~32 ms
/// per proc on the typical 90 MB binary, so 1024 procs ~ 30 s budget.
const MAX_LIFT_FUNCS: usize = 1024;

/// Find the executable section (Mach-O `__text` / ELF `.text`) for the
/// document. Returns null if not present or not file-backed.
const TextSection = struct {
    code: []const u8,
    section_base: u64,
    file_offset: u64,
};

fn findTextSection(doc: *const types.Document, data: []const u8) ?TextSection {
    for (doc.segments) |seg| {
        if (!seg.permissions.execute) continue;
        for (seg.sections) |sec| {
            if (!std.mem.eql(u8, sec.name, "__text") and
                !std.mem.eql(u8, sec.name, ".text")) continue;
            if (sec.file_offset + sec.length > data.len) continue;
            return .{
                .code = data[sec.file_offset .. sec.file_offset + sec.length],
                .section_base = sec.start,
                .file_offset = sec.file_offset,
            };
        }
    }
    return null;
}

/// Decode at most `max_insns` instructions from `code` starting at
/// `entry_addr` until the first return. Appends each decoded instruction to
/// the supplied database. Returns the number of bytes consumed (procedure
/// size estimate) and the indices of indirect-branch instructions so the
/// jumptable phase can iterate them without re-scanning.
const DecodeResult = struct {
    proc_size: u64,
    insn_count: usize,
    /// Indices into the per-proc instructions (0-based) for indirect
    /// branches, used by the jumptable phase. Allocator-owned.
    indirect_branch_indices: []usize,
};

fn decodeProc(
    allocator: std.mem.Allocator,
    db: *db_mod.Database,
    arch: types.Arch,
    text: TextSection,
    entry_addr: u64,
    max_insns: usize,
    /// Output array: per-instruction record needed by jumptable.detect.
    /// Caller owns the returned slice (freed by caller).
    out_instructions: *std.array_list.Managed(types.Instruction),
) !DecodeResult {
    const text_end = text.section_base + text.code.len;
    var indirects = std.array_list.Managed(usize).init(allocator);
    errdefer indirects.deinit();

    var decode_addr = entry_addr;
    var proc_size: u64 = 0;
    var insn_count: usize = 0;

    if (arch == .mips32) {
        const mips32_decoder = @import("../arch/mips32.zig");
        while (decode_addr + 4 <= text_end and insn_count < max_insns) : (insn_count += 1) {
            const off = decode_addr - text.section_base;
            const inst_bytes = text.code[off .. off + 4];
            const decoded = mips32_decoder.decode(inst_bytes, decode_addr);
            const inst = decoded.toInstruction(decode_addr, inst_bytes);
            db.addInstruction(inst) catch break;
            try out_instructions.append(inst);
            // Indirect branch heuristic: jr to non-$ra is an indirect.
            if (decoded.is_branch and !decoded.is_call and decoded.branch_target == null) {
                try indirects.append(out_instructions.items.len - 1);
            }
            decode_addr += 4;
            proc_size += 4;
            if (decoded.is_return) {
                // Consume delay slot.
                if (decode_addr + 4 <= text_end and insn_count + 1 < max_insns) {
                    const ds_off = decode_addr - text.section_base;
                    const ds_bytes = text.code[ds_off .. ds_off + 4];
                    const ds_decoded = mips32_decoder.decode(ds_bytes, decode_addr);
                    const ds_inst = ds_decoded.toInstruction(decode_addr, ds_bytes);
                    db.addInstruction(ds_inst) catch {};
                    out_instructions.append(ds_inst) catch {};
                    decode_addr += 4;
                    proc_size += 4;
                    insn_count += 1;
                }
                break;
            }
        }
    } else if (arch == .arm64) {
        while (decode_addr + 4 <= text_end and insn_count < max_insns) : (insn_count += 1) {
            const off = decode_addr - text.section_base;
            const inst_bytes = text.code[off .. off + 4];
            const decoded = arm64_decoder.decode(inst_bytes, decode_addr);
            const inst = decoded.toInstruction(decode_addr, inst_bytes);
            db.addInstruction(inst) catch break;
            try out_instructions.append(inst);
            // Indirect branch: BR xN / BLR xN with no static target.
            if (decoded.is_branch and !decoded.is_call and decoded.branch_target == null) {
                try indirects.append(out_instructions.items.len - 1);
            }
            decode_addr += 4;
            proc_size += 4;
            if (decoded.is_return) break;
        }
    } else {
        // x86_64 / arm32: decoded in lean mode, no IR yet.
    }

    return .{
        .proc_size = proc_size,
        .insn_count = insn_count,
        .indirect_branch_indices = try indirects.toOwnedSlice(),
    };
}

/// Run Phase 5 — Phase 8 of v7.8.0. Allocates results onto `doc` via the
/// provided allocator (recorded on `doc.analysis_allocator` so deinit can
/// release them).
fn runMaturityPipeline(
    allocator: std.mem.Allocator,
    io: std.Io,
    doc: *types.Document,
    data: []const u8,
) !void {
    if (doc.procedures.items.len == 0) return;
    if (doc.arch != .arm64 and doc.arch != .mips32) return;

    const text = findTextSection(doc, data) orelse return;
    const text_end = text.section_base + text.code.len;

    // Allocate the doc-owned maps eagerly. If we early-return without
    // populating anything, the empty maps are still released by deinit.
    var sf_map = std.AutoHashMap(u64, *anyopaque).init(allocator);
    errdefer {
        var it = sf_map.valueIterator();
        while (it.next()) |val_ptr| {
            const sf: *structure_mod.StructuredFunction = @ptrCast(@alignCast(val_ptr.*));
            sf.deinit(allocator);
            allocator.destroy(sf);
        }
        sf_map.deinit();
    }

    var jt_map = std.AutoHashMap(u64, *anyopaque).init(allocator);
    errdefer {
        var it = jt_map.valueIterator();
        while (it.next()) |val_ptr| {
            const jt: *jumptable_mod.JumpTable = @ptrCast(@alignCast(val_ptr.*));
            allocator.free(jt.cases);
            allocator.destroy(jt);
        }
        jt_map.deinit();
    }

    // Per-proc arena for lifter + maturity-pass allocations. The lifter
    // (src/lifter/lift.zig) allocates many transient strings via
    // `std.fmt.allocPrint` into IRStatement string fields, plus passes
    // (const_fold/stack_slot) allocate replacement strings. Tracking every
    // one individually is brittle; an arena scoped to the IR's lifetime
    // frees them all on `deinit` without leaking. Per W1A1 caveat:
    // "use an arena allocator for each function's passes so all transient
    //  strings are freed together when the function is freed".
    //
    // We use a single shared arena across all functions processed in this
    // pipeline run. Type recovery reads from the arena'd strings, so the
    // arena must outlive Phase 8. It's deinit'd at the end of this
    // function.
    var ir_arena = std.heap.ArenaAllocator.init(allocator);
    defer ir_arena.deinit();
    const ir_alloc = ir_arena.allocator();

    // Collect lifted IR for type recovery (Phase 8). Each IRFunction's
    // slices live in `ir_arena` and are freed when the arena is deinit'd
    // above (the defer runs after Phase 8).
    var ir_funcs = std.array_list.Managed(types.IRFunction).init(allocator);
    defer ir_funcs.deinit();

    // Cap iteration: we run the maturity pipeline on at most MAX_LIFT_FUNCS
    // procedures within text. Stub procs and out-of-section entries are
    // filtered out implicitly by the bounds check below.
    var processed: usize = 0;
    for (doc.procedures.items) |proc| {
        if (processed >= MAX_LIFT_FUNCS) break;
        if (proc.entry < text.section_base or proc.entry >= text_end) continue;

        // Per-proc decode into a temporary database. Bounded at 256 insns
        // per proc to keep total work proportional to MAX_LIFT_FUNCS.
        // DB uses the outer allocator (it's local-scope and deinit'd below).
        var db = db_mod.Database.init(allocator, io);
        defer db.deinit();

        var insns = std.array_list.Managed(types.Instruction).init(allocator);
        defer insns.deinit();

        const dec = decodeProc(allocator, &db, doc.arch, text, proc.entry, 256, &insns) catch {
            continue;
        };
        defer allocator.free(dec.indirect_branch_indices);

        if (dec.proc_size == 0) continue;

        // Build a single-block CFG for the procedure (sufficient for the
        // decoded prefix; a richer CFG would require following all branch
        // targets, which W8 will tackle).
        var succ_arr = [_]u64{};
        var pred_arr = [_]u64{};
        var block = types.BasicBlock{
            .start = proc.entry,
            .size = dec.proc_size,
            .instruction_count = @as(u32, @intCast(dec.insn_count)),
            .successors = &succ_arr,
            .predecessors = &pred_arr,
            .terminator = .@"return",
        };
        const lift_proc = types.Procedure{
            .entry = proc.entry,
            .size = dec.proc_size,
            .name = proc.name,
            .basic_blocks = @as([*]types.BasicBlock, @ptrCast(&block))[0..1],
        };

        // -------- Phase 5: lift + maturity passes --------
        // Use the per-proc arena for all IR string / slice allocations so
        // transient strings inside IRStatement fields are freed together
        // when the arena is torn down at the end of this routine.
        const ir_func = lifter.liftProcedureMature(ir_alloc, &lift_proc, &db) catch continue;
        if (ir_func.statements.len == 0) continue;
        try ir_funcs.append(ir_func);

        // -------- Phase 6: structured CF recovery --------
        // Build the minimum CFG (single block) — structure.recover handles
        // empty edge lists by emitting a sequence/return. A future revision
        // will wire the full multi-block CFG produced by analysis/cfg.zig.
        const blocks_slice = @as([*]const types.BasicBlock, @ptrCast(&block))[0..1];
        const empty_edges: []const types.CfgEdge = &.{};
        if (structure_mod.recover(allocator, blocks_slice, empty_edges, proc.entry)) |sf_val| {
            const sf_ptr = allocator.create(structure_mod.StructuredFunction) catch {
                var sf_mut = sf_val;
                sf_mut.deinit(allocator);
                continue;
            };
            sf_ptr.* = sf_val;
            sf_map.put(proc.entry, @ptrCast(sf_ptr)) catch {
                sf_ptr.deinit(allocator);
                allocator.destroy(sf_ptr);
            };
        } else |_| {
            // structure recovery failure is non-fatal; continue.
        }

        // -------- Phase 7: jump-table detection --------
        for (dec.indirect_branch_indices) |idx| {
            const maybe_jt = jumptable_mod.detect(
                allocator,
                doc.arch,
                data,
                insns.items,
                idx,
                text.section_base - text.file_offset, // image_base
            ) catch null;
            if (maybe_jt) |jt_val| {
                const jt_ptr = allocator.create(jumptable_mod.JumpTable) catch {
                    allocator.free(jt_val.cases);
                    continue;
                };
                jt_ptr.* = jt_val;
                jt_map.put(jt_val.branch_addr, @ptrCast(jt_ptr)) catch {
                    allocator.free(jt_ptr.cases);
                    allocator.destroy(jt_ptr);
                };
            }
        }

        processed += 1;
    }

    // -------- Phase 8: type recovery (global) --------
    // Run on the lifted IR before we drop the IR slices below.
    var recovered_types_ptr: ?*types_recovery_mod.TypeRecoveryResult = null;
    if (ir_funcs.items.len > 0) {
        if (types_recovery_mod.recover(allocator, ir_funcs.items)) |tr_val| {
            const ptr = allocator.create(types_recovery_mod.TypeRecoveryResult) catch null;
            if (ptr) |p| {
                p.* = tr_val;
                recovered_types_ptr = p;
            } else {
                // Couldn't allocate the wrapper — release the result.
                freeTypeRecoveryInline(allocator, tr_val);
            }
        } else |_| {}
    }

    // Commit results to the document.
    doc.analysis_allocator = allocator;
    if (sf_map.count() > 0) {
        doc.structured_functions = sf_map;
    } else {
        sf_map.deinit();
    }
    if (jt_map.count() > 0) {
        doc.jump_tables = jt_map;
    } else {
        jt_map.deinit();
    }
    if (recovered_types_ptr) |p| {
        doc.recovered_types = @ptrCast(p);
    }
}

/// Inline freer mirroring `Document.deinitAnalysis`'s TypeRecoveryResult
/// branch — used when we fail to wrap the value in a heap pointer.
fn freeTypeRecoveryInline(
    allocator: std.mem.Allocator,
    tr_val: types_recovery_mod.TypeRecoveryResult,
) void {
    var tr = tr_val;
    var vt_it = tr.variable_types.iterator();
    while (vt_it.next()) |e| allocator.free(e.key_ptr.*);
    tr.variable_types.deinit();
    for (tr.structs) |s| {
        for (s.fields) |f| allocator.free(f.name);
        allocator.free(s.fields);
        for (s.pointer_origins) |po| allocator.free(po);
        allocator.free(s.pointer_origins);
        allocator.free(s.name);
    }
    allocator.free(tr.structs);
}
