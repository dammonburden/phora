// Phora — Core Data Types
// All types from spec § 5 (Data Model)

const std = @import("std");

// ============================================================================
// Enums
// ============================================================================

pub const BinaryFormat = enum {
    macho,
    elf,
    pe,
    zip,
    pbp,
    psx_exe,
    raw,

    pub fn toString(self: BinaryFormat) []const u8 {
        return switch (self) {
            .macho => "macho",
            .elf => "elf",
            .pe => "pe",
            .zip => "zip",
            .pbp => "pbp",
            .psx_exe => "psx_exe",
            .raw => "raw",
        };
    }
};

pub const Arch = enum {
    arm64,
    x86_64,
    arm32,
    x86,
    mips32,

    pub fn toString(self: Arch) []const u8 {
        return switch (self) {
            .arm64 => "arm64",
            .x86_64 => "x86_64",
            .arm32 => "arm32",
            .x86 => "x86",
            .mips32 => "mips32",
        };
    }
};

pub const Terminator = enum {
    branch,
    jump,
    call,
    @"return",
    fallthrough,

    pub fn toString(self: Terminator) []const u8 {
        return switch (self) {
            .branch => "branch",
            .jump => "jump",
            .call => "call",
            .@"return" => "return",
            .fallthrough => "fallthrough",
        };
    }
};

pub const IRStatementType = enum {
    assign,
    call,
    compare,
    branch,
    @"return",
    load,
    store,
    nop,

    pub fn toString(self: IRStatementType) []const u8 {
        return switch (self) {
            .assign => "assign",
            .call => "call",
            .compare => "compare",
            .branch => "branch",
            .@"return" => "return",
            .load => "load",
            .store => "store",
            .nop => "nop",
        };
    }
};

pub const AnnotationKind = enum {
    name,
    comment,
    tag,
    type_override,

    pub fn toString(self: AnnotationKind) []const u8 {
        return switch (self) {
            .name => "name",
            .comment => "comment",
            .tag => "tag",
            .type_override => "type_override",
        };
    }
};

pub const SegmentPermissions = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    _padding: u5 = 0,
};

pub const XrefDirection = enum {
    forward,
    backward,
    bidirectional,
};

pub const CallGraphDirection = enum {
    forward,
    backward,
    bidirectional,
};

pub const IncludeFlag = enum {
    ir,
    cfg,
    xrefs,
    types,
    strings,
    calls,
};

// ============================================================================
// Core Data Structures
// ============================================================================

/// A subdivision within a Segment.
pub const Section = struct {
    name: []const u8,
    start: u64,
    length: u64,
    /// Offset into the file where section data begins.
    file_offset: u64 = 0,
    /// Alignment (log2).
    alignment: u32 = 0,
    /// True for uninitialized (zerofill) sections: Mach-O S_ZEROFILL/S_GB_ZEROFILL/
    /// S_THREAD_LOCAL_ZEROFILL (__bss, __common, __thread_bss) and ELF SHT_NOBITS.
    /// These sections have no file backing — read_bytes should return zeros, entropy
    /// should not be computed over file bytes (which would point to wrong data).
    is_zerofill: bool = false,
};

/// A contiguous memory region in a binary.
pub const Segment = struct {
    name: []const u8,
    start: u64,
    length: u64,
    sections: []Section,
    permissions: SegmentPermissions,
    /// Offset into the file where segment data begins.
    file_offset: u64 = 0,
    /// Size of segment data in the file (may differ from length).
    file_size: u64 = 0,
};

/// An inferred function parameter.
pub const Parameter = struct {
    name: ?[]const u8 = null,
    type_name: ?[]const u8 = null,
    register: ?[]const u8 = null,
};

/// A basic block — straight-line instructions with no branches except at the end.
pub const BasicBlock = struct {
    start: u64,
    size: u64,
    instruction_count: u32,
    successors: []u64,
    predecessors: []u64,
    terminator: Terminator,
};

/// A recognized function with identified boundaries.
pub const Procedure = struct {
    entry: u64,
    size: u64,
    name: ?[]const u8 = null,
    basic_blocks: []BasicBlock = &.{},
    calls: []u64 = &.{},
    called_by: []u64 = &.{},
    parameters: []Parameter = &.{},
    return_type: ?[]const u8 = null,
    strings_referenced: []u64 = &.{},
};

/// A detected string constant in the binary.
pub const String = struct {
    address: u64,
    value: []const u8,
    length: u32,
};

/// An external symbol reference.
pub const Import = struct {
    address: u64,
    name: []const u8,
    library: ?[]const u8 = null,
    ordinal: ?u32 = null,
    /// PLT/stub trampoline address. Code calls this address, not the GOT entry.
    /// Set during pipeline analysis for Mach-O (__auth_stubs/__stubs) and ELF (.plt).
    stub_address: ?u64 = null,
};

/// User/agent-applied metadata.
pub const Annotation = struct {
    address: u64,
    kind: AnnotationKind,
    value: []const u8,
    session_id: []const u8,
    timestamp: i64,
};

/// A loaded binary file with its analysis state.
pub const Document = struct {
    id: u64,
    path: []const u8,
    format: BinaryFormat,
    arch: Arch,
    entry_point: u64,
    segments: []Segment,
    procedures: std.array_list.Managed(Procedure),
    strings: std.array_list.Managed(String),
    imports: std.array_list.Managed(Import),
    annotations: std.array_list.Managed(Annotation),
    /// Raw binary data.
    data: []const u8,
    /// MIPS $gp (global pointer) value: .data virtual address + 0x7FF0.
    gp_value: ?u64 = null,
    /// Hardening fields (v7.5.2 — tool #29 get_hardening_report)
    is_pie: bool = false,
    is_stripped: bool = false,
    has_relro: bool = false,
    relro_full: bool = false,
    /// ARM64 Pointer Authentication (PAC) — arm64e on Mach-O, GNU property on ELF.
    has_pac: bool = false,
    /// ARM64 Branch Target Identification (BTI) — GNU property on ELF.
    has_bti: bool = false,
    /// ELF DT_NEEDED shared library dependencies (e.g. "libc.so.6", "libm.so.6").
    needed_libs: []const []const u8 = &.{},
    /// v7.12.1 W3/W4: Mach-O filetype (MH_EXECUTE=2, MH_DYLIB=6, MH_BUNDLE=8).
    /// Default 0 keeps save/load compat with pre-v7.12.1 .phora files.
    macho_filetype: u32 = 0,

    /// v7.8.4: optional human-readable note surfaced in load_binary /
    /// list_documents JSON. Used to flag situations where the load technically
    /// succeeded but yielded a degenerate doc (e.g. a PBP container whose
    /// embedded module is encrypted — see `pbpEncryptedHint`).
    note: ?[]const u8 = null,

    // ------------------------------------------------------------------
    // v7.8.0 analysis results.
    //
    // Stored as `*anyopaque` to avoid a dependency cycle between this file
    // and `src/analysis/{structure,jumptable,types}.zig` (those modules
    // import types.zig). Consumers cast back to the concrete type via
    //   @as(*analysis_structure.StructuredFunction, @ptrCast(@alignCast(p)))
    // etc. All three fields are null until the pipeline populates them.
    //
    // Ownership / lifetime: the pipeline allocates these via the
    // `analysis_allocator` (stored on the doc so `deinit` can free them).
    // ------------------------------------------------------------------

    /// Map from function entry address to `*analysis.structure.StructuredFunction`.
    structured_functions: ?std.AutoHashMap(u64, *anyopaque) = null,
    /// Pointer to `*analysis.types.TypeRecoveryResult`.
    recovered_types: ?*anyopaque = null,
    /// Map from indirect-branch address to `*analysis.jumptable.JumpTable`.
    jump_tables: ?std.AutoHashMap(u64, *anyopaque) = null,

    /// Allocator used to allocate the v7.8.0 structures above. Set when any
    /// of `structured_functions`, `recovered_types`, or `jump_tables` is
    /// populated so `deinit` can release them.
    analysis_allocator: ?std.mem.Allocator = null,

    pub fn init(allocator: std.mem.Allocator, id: u64, path: []const u8, data: []const u8) Document {
        return .{
            .id = id,
            .path = path,
            .format = .raw,
            .arch = .arm64,
            .entry_point = 0,
            .segments = &.{},
            .procedures = std.array_list.Managed(Procedure).init(allocator),
            .strings = std.array_list.Managed(String).init(allocator),
            .imports = std.array_list.Managed(Import).init(allocator),
            .annotations = std.array_list.Managed(Annotation).init(allocator),
            .data = data,
        };
    }

    pub fn deinit(self: *Document) void {
        self.procedures.deinit();
        self.strings.deinit();
        self.imports.deinit();
        self.annotations.deinit();
        self.deinitAnalysis();
    }

    /// Release v7.8.0 analysis results if populated. Safe to call multiple
    /// times and safe when nothing was populated. Uses a late-binding import
    /// so the concrete analysis types don't force a compile-time cycle.
    pub fn deinitAnalysis(self: *Document) void {
        const alloc = self.analysis_allocator orelse return;

        const structure = @import("analysis/structure.zig");
        const jumptable = @import("analysis/jumptable.zig");
        const type_recovery = @import("analysis/types.zig");

        if (self.structured_functions) |*sf_map| {
            var it = sf_map.valueIterator();
            while (it.next()) |val_ptr| {
                const sf: *structure.StructuredFunction = @ptrCast(@alignCast(val_ptr.*));
                sf.deinit(alloc);
                alloc.destroy(sf);
            }
            sf_map.deinit();
            self.structured_functions = null;
        }

        if (self.jump_tables) |*jt_map| {
            var it = jt_map.valueIterator();
            while (it.next()) |val_ptr| {
                const jt: *jumptable.JumpTable = @ptrCast(@alignCast(val_ptr.*));
                alloc.free(jt.cases);
                alloc.destroy(jt);
            }
            jt_map.deinit();
            self.jump_tables = null;
        }

        if (self.recovered_types) |rt_ptr| {
            const rt: *type_recovery.TypeRecoveryResult = @ptrCast(@alignCast(rt_ptr));
            // `variable_types` is a StringHashMap whose keys are allocated
            // strings owned by the TypeRecoveryResult. Each struct's
            // `name`, `fields[].name`, and `pointer_origins[]` are also
            // allocated. Free them in the same order they were built.
            var vt_it = rt.variable_types.iterator();
            while (vt_it.next()) |e| alloc.free(e.key_ptr.*);
            rt.variable_types.deinit();
            for (rt.structs) |s| {
                for (s.fields) |f| alloc.free(f.name);
                alloc.free(s.fields);
                for (s.pointer_origins) |po| alloc.free(po);
                alloc.free(s.pointer_origins);
                alloc.free(s.name);
            }
            alloc.free(rt.structs);
            alloc.destroy(rt);
            self.recovered_types = null;
        }

        self.analysis_allocator = null;
    }
};

// ============================================================================
// IR (Lifter Output)
// ============================================================================

/// A single IR statement produced by the lifter.
pub const IRStatement = struct {
    type: IRStatementType,
    address: u64,
    dest: ?[]const u8 = null,
    src: ?[]const u8 = null,
    target: ?[]const u8 = null,
    args: ?[]const []const u8 = null,
    op: ?[]const u8 = null,
    condition: ?[]const u8 = null,
    true_block: ?u32 = null,
    false_block: ?u32 = null,
};

/// IR for a single lifted function.
pub const IRFunction = struct {
    address: u64,
    name: ?[]const u8 = null,
    statements: []IRStatement,
    variables: []Variable,
};

/// A variable inferred by the lifter (register → variable mapping).
pub const Variable = struct {
    name: []const u8,
    register: ?[]const u8 = null,
    type_name: ?[]const u8 = null,
};

// ============================================================================
// Session & MCP
// ============================================================================

/// A connection from an agent to Phora.
pub const Session = struct {
    id: []const u8,
    doc_id: u64,
    created_at: i64,
    last_active: i64,
};

// ============================================================================
// Cross-references
// ============================================================================

pub const XrefType = enum {
    call,
    jump,
    data_read,
    data_write,
    string_ref,
};

pub const Xref = struct {
    from: u64,
    to: u64,
    xref_type: XrefType,
};

// ============================================================================
// API Response Types (MCP universal response format)
// ============================================================================

pub const ResultItem = struct {
    input: []const u8,
    success: bool,
    result: ?[]const u8 = null, // JSON string
    @"error": ?[]const u8 = null,
    execution_time_ms: i64 = 0,
};

pub const BatchSummary = struct {
    total: u32,
    succeeded: u32,
    failed: u32,
};

pub const ApiResponse = struct {
    success: bool,
    results: []ResultItem,
    summary: BatchSummary,
};

// ============================================================================
// Disassembled instruction
// ============================================================================

pub const Instruction = struct {
    address: u64,
    bytes: []const u8,
    mnemonic: []const u8,
    operands: []const u8,
    size: u8,
    // Owned copy of operands — decodeInstruction copies here so the
    // operands slice can point to owned memory instead of the decoder's
    // stack-local buffer (which becomes dangling after return).
    operands_buf: [64]u8 = [_]u8{0} ** 64,
    operands_len: u8 = 0,
};

// ============================================================================
// Load options
// ============================================================================

pub const LoadOptions = struct {
    arch: ?Arch = null,
    analysis: bool = true,
    fat_arch: ?Arch = null,

    /// v7.9.0: explicit entry-point address for raw binaries (overrides
    /// any auto-detection). Used when the file format doesn't carry
    /// entry-point metadata but the caller knows it.
    entry: ?u64 = null,

    /// v7.9.0: explicit load-base virtual address for raw binaries.
    /// Synthesized raw segment starts at this VA instead of 0.
    base: ?u64 = null,
};

// ============================================================================
// Analysis state
// ============================================================================

pub const AnalysisState = enum {
    loaded,
    parsing,
    disassembly,
    procedure_detection,
    string_detection,
    xref_building,
    objc_recovery,
    ready,

    pub fn toString(self: AnalysisState) []const u8 {
        return switch (self) {
            .loaded => "loaded",
            .parsing => "parsing",
            .disassembly => "disassembly",
            .procedure_detection => "procedure_detection",
            .string_detection => "string_detection",
            .xref_building => "xref_building",
            .objc_recovery => "objc_recovery",
            .ready => "ready",
        };
    }
};

// ============================================================================
// Document statistics (returned from load_binary)
// ============================================================================

pub const DocumentStats = struct {
    procedure_count: u32 = 0,
    string_count: u32 = 0,
    import_count: u32 = 0,
    segment_count: u32 = 0,
    section_count: u32 = 0,
    total_size: u64 = 0,
};

// ============================================================================
// Search types
// ============================================================================

pub const SearchQueryType = enum {
    name,
    string,
    callers_of,
    callees_of,
    procedures,
    imports,
    calls,
    string_refs,
    /// v7.9.1 Q4: find all instructions that write to the given absolute
    /// address. Used for retro / bare-metal RE — correlates lui+sw on MIPS,
    /// adrp+str on ARM64, mov-absolute on x86.
    writers_of,
};

pub const SearchQuery = struct {
    pattern: ?[]const u8 = null,
    query_type: SearchQueryType,
    address: ?u64 = null,
    max_results: u32 = 100,
    case_insensitive: bool = false,
    max_xrefs: ?u32 = null,
};

pub const SearchResult = struct {
    address: u64,
    match_text: []const u8,
    context: ?[]const u8 = null,
    result_type: []const u8,
    doc_id: ?u64 = null,
    doc_name: ?[]const u8 = null,
    xref_count: ?u32 = null,
    /// v7.4.2 F1: when set, indicates this result came from the byte-grep
    /// fallback path (e.g. "byte_grep_fallback") rather than the indexed
    /// pre-built strings map. Tells the LLM that the hit's fidelity is
    /// lower than indexed hits — no xrefs, possibly bounded excerpts.
    via: ?[]const u8 = null,
    /// v7.4.2 F1: for string_refs fallback hits, indicates xrefs into the
    /// region cannot be enumerated structurally (e.g. "byte_scan").
    /// The string exists at the address but Phora cannot tell you who reads
    /// it. Strictly more honest than total_count:0.
    xref_origin: ?[]const u8 = null,
};

// ============================================================================
// Annotate operation
// ============================================================================

pub const AnnotateOpType = enum {
    set_name,
    set_comment,
    add_tag,
    set_type,
    remove_tag,
};

pub const AnnotateOp = struct {
    op_type: AnnotateOpType,
    address: u64,
    value: []const u8,
};

// ============================================================================
// Call graph
// ============================================================================

pub const CallGraphNode = struct {
    address: u64,
    name: ?[]const u8 = null,
    depth: u32 = 0,
};

pub const CallGraphEdge = struct {
    from: u64,
    to: u64,
};

pub const CallGraph = struct {
    nodes: []CallGraphNode,
    edges: []CallGraphEdge,
};

// ============================================================================
// CFG result
// ============================================================================

pub const CfgEdge = struct {
    from: u64,
    to: u64,
    edge_type: enum { branch_true, branch_false, unconditional, fallthrough },
};

pub const CfgResult = struct {
    basic_blocks: []BasicBlock,
    edges: []CfgEdge,
};

// ============================================================================
// Semantic facts (Phase 4 — used by concurrent analysis agents)
// ============================================================================

pub const FactKind = enum(u8) {
    function_entry,
    function_range,
    call_edge,
    jump_edge,
    data_ref,
    string_ref,
};

pub const FactSource = enum(u4) {
    lc_func_starts,
    prologue_scan,
    call_target,
    xref_scan,
    user_annotation,
};

pub const SemanticFact = struct {
    kind: FactKind,
    address: u64,
    target: u64,
    confidence: u8, // 0-100
    source: FactSource,
};

// ============================================================================
// Export format
// ============================================================================

pub const ExportFormat = enum {
    json,
    text,
    ir,
};
