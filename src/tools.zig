// Phora — MCP Tool Definitions & Handlers
// All MCP tools from spec § 6 with JSON Schema definitions and dispatch logic.
// Uses the real json.zig and database.zig interfaces.

const std = @import("std");
const arm64_steps = @import("analysis/arm64_steps.zig");
const arm64_loop_state = @import("analysis/arm64_loop_state.zig");
const arm64_semantics = @import("analysis/arm64_semantics.zig");
const arm64_addressing = @import("analysis/arm64_addressing.zig");
const arm64_arithmetic = @import("analysis/arm64_arithmetic.zig");
const arm64_branch_predicate = @import("analysis/arm64_branch_predicate.zig");
const arm64_bitfield = @import("analysis/arm64_bitfield.zig");
const builtin = @import("builtin");
const runtime = @import("runtime.zig");
const types = @import("types.zig");
const json = @import("util/json.zig");
const Database = @import("store/database.zig").Database;
const xref_mod = @import("analysis/xref.zig");
const macho = @import("loaders/macho.zig");
const elf_loader = @import("loaders/elf.zig");
const pe_loader = @import("loaders/pe.zig");
const dyld_cache = @import("loaders/dyld_cache.zig");
const pipeline = @import("analysis/pipeline.zig");
const strings_mod = @import("analysis/strings.zig");
const lifter = @import("lifter/lift.zig");
const cfg_mod = @import("analysis/cfg.zig");
const loops_mod = @import("analysis/loops.zig");
const register_flow = @import("analysis/register_flow.zig");
const abi_mod = @import("analysis/abi.zig");
const type_recovery = @import("analysis/types.zig");
const swift_mod = @import("analysis/swift.zig");
const arm64 = @import("arch/arm64.zig");
const arm32 = @import("arch/arm32.zig");
const mips32 = @import("arch/mips32.zig");

const Allocator = std.mem.Allocator;

/// Max binary size: 2GB. Real limit is available RAM.
const max_binary_size: usize = 4 * 1024 * 1024 * 1024;

/// Max single-file load limit (500 MiB). Reject before reading if larger.
const MAX_BINARY_SIZE: usize = 500 * 1024 * 1024;

/// Maximum characters in a tool response before truncation.
const max_response_chars: usize = 80_000;

// ============================================================================
// Tool Schema Definitions (static)
// ============================================================================

/// A single MCP tool definition with JSON Schema for parameters.
pub const ToolDef = struct {
    name: []const u8,
    description: []const u8,
    input_schema: []const u8, // Raw JSON Schema string
    annotations: []const u8, // MCP tool annotations (JSON)
};

/// All 30 MCP tools exposed through tools/list.
pub const tool_definitions = [_]ToolDef{
    .{
        .name = "load_binary",
        .description = "Load one or more binary files (Mach-O, ELF, PE, APK/ZIP, raw). APK/ZIP archives are auto-extracted and every native lib inside is loaded as a separate document. Pass a single path or an array of paths. Max 500 MiB per file; for FAT/universal binaries use options.fat_arch to pick a slice. Auto-detects PBP (PSP) and PSX-EXE (PS1) in addition to listed formats. Encrypted PBP modules (DATA.PSP not a plain ELF) load with a note instead of failing — disassembly is skipped. After loading, call `get_binary_context` next; it auto-dispatches full enumeration vs guided exploration. Response includes `format`/`arch`/`entry_point`/`stats`. Optional fields appear when relevant: `runtime` (e.g. `j2objc`, `bun`, `electron` — when an embedded runtime adapter fires), `bundle_size` (when ZIP/APK auto-extracted), `large_binary:true` + `file_size_mb` (for binaries >50 MB).",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "path": {
        \\      "oneOf": [
        \\        {"type": "string", "description": "Single binary path"},
        \\        {"type": "array", "items": {"type": "string"}, "description": "Array of paths"}
        \\      ],
        \\      "description": "Path(s) to binary file(s)"
        \\    },
        \\    "options": {
        \\      "type": "object",
        \\      "description": "Load options",
        \\      "properties": {
        \\        "arch": {
        \\          "type": "string",
        \\          "enum": ["arm64", "x86_64", "arm32", "x86", "mips32", "mipsel", "mips32le", "mips32-le", "mips-le"],
        \\          "description": "Force architecture (mipsel/mips32le/mips32-le/mips-le all map to little-endian MIPS32)"
        \\        },
        \\        "analysis": {
        \\          "type": "boolean",
        \\          "default": true,
        \\          "description": "Run analysis after loading"
        \\        },
        \\        "fat_arch": {
        \\          "type": "string",
        \\          "enum": ["arm64", "x86_64", "arm32", "x86", "mips32", "mipsel", "mips32le", "mips32-le", "mips-le"],
        \\          "description": "FAT binary arch slice"
        \\        },
        \\        "base": {
        \\          "type": "integer",
        \\          "description": "Override load base address (hex/dec). Useful for raw firmware blobs at non-zero base."
        \\        },
        \\        "entry": {
        \\          "type": "integer",
        \\          "description": "Override entry-point address. Useful for raw blobs without a header."
        \\        },
        \\        "budget_ms": {
        \\          "type": "integer",
        \\          "default": 600000,
        \\          "description": "Wall-clock budget for the analysis pipeline in milliseconds (default 600000 = 10 min). On exceed, the load fails fast with phase info instead of silently timing out the MCP transport. Set to 0 to disable."
        \\        }
        \\      },
        \\      "additionalProperties": false
        \\    }
        \\  },
        \\  "required": ["path"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":true}
        ,
    },
    .{
        .name = "get_binary_context",
        .description = "Adaptive context planner — call FIRST after load_binary. mode=auto picks full enumeration for tiny binaries (<=200 KiB, <=200 procs), guided ranking via get_remake_frontier for medium binaries, or a lightweight manifest for huge/opaque ones (>100 MiB or >30000 procs). Tiny single-procedure ARM64 full contexts use compact execution steps with current carried values; other architectures retain disassembly/provenance. control_flow_evidence.instruction_view identifies the CFG shape; follow its next_call if deferred. Interpret instructions in CFG edge order, not increasing address order. One call replaces 5-10 exploratory load_binary→get_strings→get_imports→get_segments→get_cfg→get_embedded_resources fan-outs.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [{"type":"integer"},{"type":"string"}],
        \\      "description": "Document ID or name. Optional when one document is loaded."
        \\    },
        \\    "mode": {
        \\      "type": "string",
        \\      "enum": ["auto","full","frontier","manifest"],
        \\      "default": "auto",
        \\      "description": "auto=heuristic dispatch (default); full=enumerate everything; frontier=delegate to get_remake_frontier; manifest=lightweight summary only."
        \\    },
        \\    "goal": {"type": "string", "description": "Optional human/LLM goal to bias frontier scoring."},
        \\    "patterns": {
        \\      "oneOf": [{"type":"string"},{"type":"array","items":{"type":"string"},"maxItems":20}],
        \\      "description": "Optional substring pattern(s) for frontier mode."
        \\    },
        \\    "seeds": {
        \\      "oneOf": [{"type":"integer"},{"type":"string"},{"type":"array","items":{"oneOf":[{"type":"integer"},{"type":"string"}]},"maxItems":50}],
        \\      "description": "Optional seed addresses for frontier mode."
        \\    },
        \\    "visited": {
        \\      "type": "array",
        \\      "items": {"oneOf":[{"type":"integer"},{"type":"string"}]},
        \\      "description": "Addresses already inspected (frontier mode)."
        \\    },
        \\    "max_chars": {"type": "integer", "default": 80000, "maximum": 200000, "description": "Hard cap on response length (bytes)."},
        \\    "max_candidates": {"type": "integer", "default": 24, "maximum": 128, "description": "Frontier candidate cap."},
        \\    "max_batch": {"type": "integer", "default": 12, "maximum": 50, "description": "Frontier parallel-batch cap."},
        \\    "include_bytes": {"type": "boolean", "default": false, "description": "Mode=full: add bounded per-section raw-byte previews with explicit zero-run encoding and read_bytes continuations. Off by default; up to 4096 bytes per section and 16384 total preview bytes."}
        \\  },
        \\  "required": [],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_remake_frontier",
        .description = "Deterministic harness-native planner: ranks the next functions/subsystems to inspect for remaking a binary, explains the evidence, and emits exact parallel MCP calls to fan out next. Use as the first call in an LLM-driven remake loop — feeds get_semantic_slice view=remake / get_cfg / suggest_names with prioritized targets instead of brute-forcing every procedure. Read-only; does not lift functions implicitly. For tiny binaries, `get_binary_context mode=auto` returns enumeration directly (skips frontier ranking when full enumeration is cheaper).",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [{"type":"integer"},{"type":"string"}],
        \\      "description": "Document ID or name. Optional only when one document is loaded."
        \\    },
        \\    "goal": {
        \\      "type": "string",
        \\      "description": "Optional human/LLM objective, e.g. 'recreate auth/session subsystem'. Used to bias scoring and role_hypothesis selection."
        \\    },
        \\    "seeds": {
        \\      "oneOf": [
        \\        {"type":"integer"},
        \\        {"type":"string"},
        \\        {"type":"array","items":{"oneOf":[{"type":"integer"},{"type":"string"}]},"maxItems":50}
        \\      ],
        \\      "description": "Optional seed function/address(es) to anchor the frontier."
        \\    },
        \\    "patterns": {
        \\      "oneOf": [
        \\        {"type":"string"},
        \\        {"type":"array","items":{"type":"string"},"maxItems":20}
        \\      ],
        \\      "description": "Optional substring pattern(s); supports `|` OR like search. Matched across procedure names, strings, and imports."
        \\    },
        \\    "visited": {
        \\      "type":"array",
        \\      "items":{"oneOf":[{"type":"integer"},{"type":"string"}]},
        \\      "description": "Addresses already inspected; downranked or skipped to push the frontier forward."
        \\    },
        \\    "max_candidates": {"type":"integer","default":24,"minimum":1,"maximum":128},
        \\    "max_batch":      {"type":"integer","default":12,"minimum":1,"maximum":50},
        \\    "depth":          {"type":"integer","default":1, "minimum":0,"maximum":3,
        \\                       "description": "Graph expansion hops (callers/callees) per candidate."},
        \\    "scan_budget":    {"type":"integer","default":50000,"minimum":1000,"maximum":100000,
        \\                       "description": "Soft cap on procedures evaluated; planner stays proportional to this. Cap lowered from 200000 in v7.12 — at 200K the planner could take 27+ min on 1.4M-proc binaries; 100K stays well under the per-tool token + wallclock budget."}
        \\  },
        \\  "required": [],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_semantic_slice",
        .description = "Binary-to-context compiler — the flagship RE tool. Three views: `facts` (typed structural facts: function entries, calls, jumps, data refs, string refs), `pack` (LLM-readable instruction evidence, strings, imports, callers/callees; no implicit lifting), `remake` (structured spec with interfaces, resources, evidence — for porting/rebuilding the binary). Use scope=cluster to expand beyond seed functions when context is sparse or the binary is stripped. Response always includes seed_diagnostics so you can see how well each seed address resolved.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [{"type": "integer"},{"type": "string"}],
        \\      "description": "Document ID or name"
        \\    },
        \\    "addresses": {
        \\      "oneOf": [{"type": "integer"},{"type": "string"},{"type": "array", "items": {"type": "integer"}, "maxItems": 50, "description": "Array of seed addresses (max 50)"}],
        \\      "description": "Center address(es) — seeds for the slice"
        \\    },
        \\    "view": {
        \\      "type": "string",
        \\      "enum": ["facts", "pack", "remake"],
        \\      "default": "facts",
        \\      "description": "facts=typed facts, pack=LLM context pack, remake=spec for rebuilding"
        \\    },
        \\    "scope": {
        \\      "type": "string",
        \\      "enum": ["function", "cluster"],
        \\      "default": "function",
        \\      "description": "function=seed procs only, cluster=expand to callees and neighbors (use when context is sparse or functions are stripped)"
        \\    },
        \\    "max_chars": {
        \\      "type": "integer",
        \\      "default": 12000,
        \\      "description": "Target text budget for pack/remake (clamped to 30000); fixed labels and evidence metadata may exceed this budget"
        \\    },
        \\    "kinds": {
        \\      "type": "array",
        \\      "items": {"type": "string", "enum": ["function_entry","function_range","call_edge","jump_edge","data_ref","string_ref"]},
        \\      "description": "Filter by fact kind (view=facts only)"
        \\    },
        \\    "radius": {"type": "integer", "default": 1, "description": "BFS hop depth"},
        \\    "max_nodes": {"type": "integer", "default": 50, "description": "Max facts (view=facts)"},
        \\    "include_names": {"type": "boolean", "default": true, "description": "Resolve symbol names"},
        \\    "max_cluster": {"type": "integer", "default": 30, "description": "Max cluster expansion nodes (scope=cluster only)"}
        \\  },
        \\  "required": ["doc_id", "addresses"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "search",
        .description = "Search a loaded binary by symbol name, string content, callers/callees, procedures, imports, calls, string references, surface-marker capabilities, or `writers_of` for static writers to an absolute address. Use pattern with `|` for OR (e.g. \"login|auth|token\"). Pass `type` and `pattern` at the top level (preferred) or nested inside a `query` object (legacy). Set max_results=1 for a fast count-only response. Omit doc_id to search across all loaded documents.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "query": {
        \\      "type": "object",
        \\      "description": "Search query",
        \\      "properties": {
        \\        "pattern": {
        \\          "type": "string",
        \\          "description": "Substring pattern (| for OR). For capabilities: filters by category name (feature_flag, endpoint, log_channel, build_path, crypto, telemetry, debug_bypass, credential, pii_field, internal_infra)"
        \\        },
        \\        "type": {
        \\          "type": "string",
        \\          "enum": ["name", "string", "callers_of", "callees_of", "procedures", "imports", "calls", "string_refs", "capabilities", "writers_of"],
        \\          "description": "Search type. string_refs finds procedures referencing matching strings. capabilities extracts categorized surface markers. writers_of=for retro/bare-metal RE: find all instructions that write to the given absolute address (correlates lui+sw on MIPS32, adrp+str on ARM64, and mov [rip+disp32]/[abs32], reg on x86_64)."
        \\        },
        \\        "address": {
        \\          "oneOf": [
        \\            {"type": "integer", "description": "Address (numeric)"},
        \\            {"type": "string", "description": "Hex address like 0x100000000"}
        \\          ],
        \\          "description": "Address for callers_of/callees_of/writers_of"
        \\        }
        \\      },
        \\      "required": ["type"],
        \\      "additionalProperties": false
        \\    },
        \\    "max_results": {
        \\      "type": "integer",
        \\      "default": 100,
        \\      "description": "Max results"
        \\    },
        \\    "offset": {
        \\      "type": "integer",
        \\      "default": 0,
        \\      "description": "Skip first N results"
        \\    },
        \\    "case_insensitive": {
        \\      "type": "boolean",
        \\      "default": false,
        \\      "description": "Case-insensitive matching"
        \\    },
        \\    "type": {
        \\      "type": "string",
        \\      "enum": ["name", "string", "callers_of", "callees_of", "procedures", "imports", "calls", "string_refs", "capabilities", "writers_of"],
        \\      "description": "Search type. name=symbol/proc names, string=string contents, callers_of/callees_of=call graph (needs address), procedures=all procs, imports/calls=import or call sites, string_refs=procs referencing matching strings (best for stripped binaries), capabilities=categorized surface markers (filter by category name), writers_of=for retro/bare-metal RE: find all instructions that write to the given absolute address (correlates lui+sw on MIPS32, adrp+str on ARM64, and mov [rip+disp32]/[abs32], reg on x86_64)."
        \\    },
        \\    "pattern": {
        \\      "type": "string",
        \\      "description": "Substring pattern (| for OR). For type=capabilities, filter by category name: feature_flag, endpoint, log_channel, build_path, crypto, telemetry, debug_bypass, credential, pii_field, internal_infra."
        \\    },
        \\    "max_xrefs": {
        \\      "type": "integer",
        \\      "description": "Filter results by max xref count (e.g. 0 for dead/unreferenced symbols)"
        \\    },
        \\    "address": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Address (numeric)"},
        \\        {"type": "string", "description": "Hex address like 0x100000000"}
        \\      ],
        \\      "description": "Address for callers_of/callees_of (top-level alternative to query.address)"
        \\    }
        \\  },
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "suggest_names",
        .description = "Gather naming evidence for one or more procedures: bounded code bytes, referenced strings, callers, callees, imports used. Does not generate pseudocode. Designed to feed an LLM that will propose better function names — does not generate names itself. Use annotate with op=set_name to apply names afterward.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "addresses": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Single function address"},
        \\        {"type": "string", "description": "Hex address"},
        \\        {"type": "array", "items": {"type": "integer"}, "maxItems": 50, "description": "Array of addresses (max 50)"}
        \\      ],
        \\      "description": "Function address(es)"
        \\    },
        \\    "max_context": {
        \\      "type": "integer",
        \\      "default": 5,
        \\      "description": "Max context items per function"
        \\    }
        \\  },
        \\  "required": ["doc_id", "addresses"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "annotate",
        .description = "Apply a batch of annotations atomically (set_name, set_comment, add_tag, set_type, remove_tag). All operations succeed or fail together. Addresses must fall within a segment with read/write/execute permission — guard regions like __PAGEZERO are rejected. Safe for multi-agent use — name conflicts in the same call are resolved deterministically.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "operations": {
        \\      "type": "array",
        \\      "description": "Annotation operations (atomic)",
        \\      "items": {
        \\        "type": "object",
        \\        "properties": {
        \\          "op": {
        \\            "type": "string",
        \\            "enum": ["set_name", "set_comment", "add_tag", "set_type", "remove_tag"],
        \\            "description": "Operation"
        \\          },
        \\          "address": {
        \\            "oneOf": [
        \\              {"type": "integer", "description": "Address (numeric)"},
        \\              {"type": "string", "description": "Hex address like 0x100000000"}
        \\            ],
        \\            "description": "Target address"
        \\          },
        \\          "value": {
        \\            "type": "string",
        \\            "description": "Content value"
        \\          }
        \\        },
        \\        "required": ["op", "address", "value"],
        \\        "additionalProperties": false
        \\      }
        \\    }
        \\  },
        \\  "required": ["doc_id", "operations"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":false,"destructiveHint":true}
        ,
    },
    .{
        .name = "save_project",
        .description = "Persist a document's full analysis state (procedures, strings, imports, xrefs, annotations) to a .phora file. Reload later with load_project to skip re-analysis.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "path": {
        \\      "type": "string",
        \\      "description": "Output file path"
        \\    }
        \\  },
        \\  "required": ["doc_id", "path"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":true}
        ,
    },
    .{
        .name = "load_project",
        .description = "Restore a previously-saved .phora project file. Brings back the document's procedures, strings, imports, xrefs, and annotations without re-running analysis on the original binary.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "path": {
        \\      "type": "string",
        \\      "description": "Project file path"
        \\    }
        \\  },
        \\  "required": ["path"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":true}
        ,
    },
    .{
        .name = "list_documents",
        .description = "List all loaded documents with doc_id, name, arch, format, and procedure count. Auto-summarizes when >20 docs are loaded; pass summary=true to force compact output or summary=false to force full detail regardless of count.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "summary": {
        \\      "type": "boolean",
        \\      "description": "Force compact output (true) or full detail (false). Omit to use auto behavior: full when ≤20 docs, compact when more."
        \\    }
        \\  },
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_strings",
        .description = "Lists strings with addresses. For all strings in a tiny binary use `get_binary_context mode=full` — it groups contiguous string blocks. Filter by segment, by pattern (| for OR), or both. Set include_xrefs=true to include the procedures referencing each string. Set scan=true to grep through ALL binary sections (slower but finds strings in non-standard locations) instead of using only pre-extracted strings. Omit doc_id to search across all loaded documents. Use max_results=1 for a fast count-only response. Set group_contiguous=true to group strings whose file offsets are within 16 bytes of each other into single block objects (defaults to true; pass false for legacy per-string paginated output).",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "segment": {
        \\      "type": "string",
        \\      "description": "Filter by segment name"
        \\    },
        \\    "pattern": {
        \\      "type": "string",
        \\      "description": "Filter pattern (| for OR)"
        \\    },
        \\    "max_results": {
        \\      "type": "integer",
        \\      "default": 500,
        \\      "description": "Max results"
        \\    },
        \\    "offset": {
        \\      "type": "integer",
        \\      "default": 0,
        \\      "description": "Skip first N results"
        \\    },
        \\    "case_insensitive": {
        \\      "type": "boolean",
        \\      "default": false,
        \\      "description": "Case-insensitive matching"
        \\    },
        \\    "include_xrefs": {
        \\      "type": "boolean",
        \\      "default": false,
        \\      "description": "Include xref addresses (procedures that reference each string)"
        \\    },
        \\    "scan": {
        \\      "type": "boolean",
        \\      "default": false,
        \\      "description": "Raw byte-level grep through all sections (not just pre-extracted strings). Slower but finds strings in non-standard sections."
        \\    },
        \\    "group_contiguous": {
        \\      "type": "boolean",
        \\      "default": true,
        \\      "description": "v7.12 W6: group strings with sequential file offsets (gap <=16 bytes) into single {block_address, block_size, strings:[{offset, text}]} objects. Cuts envelope size for tiny __cstring sections. Default ON; pass false for legacy per-string output."
        \\    }
        \\  },
        \\  "required": [],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_imports",
        .description = "List a binary's imported symbols. Filter by pattern (| for OR). Set include_xrefs=true to include the number of call sites for each import. Set group_by=\"library\" to nest results under each source library. For PSP binaries (PRX/ELF), NIDs are auto-resolved to known function names. Omit doc_id to search across all loaded documents. Use max_results=1 for a fast count-only response.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "pattern": {
        \\      "type": "string",
        \\      "description": "Filter pattern (| for OR)"
        \\    },
        \\    "max_results": {
        \\      "type": "integer",
        \\      "default": 500,
        \\      "description": "Max results"
        \\    },
        \\    "offset": {
        \\      "type": "integer",
        \\      "default": 0,
        \\      "description": "Skip first N matching imports"
        \\    },
        \\    "include_xrefs": {
        \\      "type": "boolean",
        \\      "default": false,
        \\      "description": "Include xref count per import"
        \\    },
        \\    "group_by": {
        \\      "type": "string",
        \\      "enum": ["library"],
        \\      "description": "Group by library"
        \\    },
        \\    "case_insensitive": {
        \\      "type": "boolean",
        \\      "default": false,
        \\      "description": "Case-insensitive matching"
        \\    }
        \\  },
        \\  "required": [],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_exports",
        .description = "List a binary's exported symbols — the functions and data it makes available to other binaries that link against it. Import stubs (system functions a binary depends on, not its own code) are filtered out automatically. Filter by pattern (| for OR). Omit doc_id to search across all loaded documents. Use max_results=1 for a fast count-only response.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "pattern": {
        \\      "type": "string",
        \\      "description": "Filter pattern (| for OR)"
        \\    },
        \\    "max_results": {
        \\      "type": "integer",
        \\      "default": 500,
        \\      "description": "Max results"
        \\    },
        \\    "case_insensitive": {
        \\      "type": "boolean",
        \\      "default": false,
        \\      "description": "Case-insensitive matching"
        \\    }
        \\  },
        \\  "required": [],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_xrefs",
        .description = "Get cross-references for one or more addresses. direction=forward returns sites that this address points to, backward returns sites that point to this address, bidirectional returns both. Useful for finding callers, data references, and string references.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "addresses": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Single address"},
        \\        {"type": "string", "description": "Hex address"},
        \\        {"type": "array", "items": {"type": "integer"}, "maxItems": 50, "description": "Array of addresses (max 50)"}
        \\      ],
        \\      "description": "Target address(es)"
        \\    },
        \\    "direction": {
        \\      "type": "string",
        \\      "enum": ["forward", "backward", "bidirectional"],
        \\      "default": "bidirectional",
        \\      "description": "Direction"
        \\    },
        \\    "max_results": {
        \\      "type": "integer",
        \\      "default": 200,
        \\      "description": "Max results per address"
        \\    }
        \\  },
        \\  "required": ["doc_id", "addresses"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_call_graph",
        .description = "Walk the call graph from a root function. Direction = forward (callees), backward (callers), or bidirectional. Depth is hard-capped at 5 hops. For very large binaries (>800K procs) lower max_nodes to keep responses fast.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "root": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Address (numeric)"},
        \\        {"type": "string", "description": "Hex address like 0x100000000"}
        \\      ],
        \\      "description": "Root function address"
        \\    },
        \\    "depth": {
        \\      "type": "integer",
        \\      "default": 5,
        \\      "description": "Max BFS depth from root (default and hard cap: 5)"
        \\    },
        \\    "direction": {
        \\      "type": "string",
        \\      "enum": ["forward", "backward", "bidirectional"],
        \\      "default": "forward",
        \\      "description": "Direction"
        \\    },
        \\    "max_nodes": {
        \\      "type": "integer",
        \\      "default": 200,
        \\      "description": "Max nodes"
        \\    },
        \\    "include": {
        \\      "type": "array",
        \\      "items": {"type": "string", "enum": ["strings", "calls", "size"]},
        \\      "default": [],
        \\      "description": "Inline details per node: strings, calls, size"
        \\    }
        \\  },
        \\  "required": ["doc_id", "root"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_cfg",
        .description = "Get the control-flow graph (basic blocks, edges, terminators) for a function. Set include_disassembly=true to inline instructions per block. ARM64 instruction_view=execution implies instructions and emits compact per-block versioned execution steps plus raw bytes; opaque operations invalidate local state and omitted steps have exact byte continuations. Its detailed_provenance_call selects the legacy disassembly/provenance view. Execution is unavailable for rebased views. Omit instruction_view for legacy behavior. Pages contain at most max_blocks blocks and their outgoing edges; follow next_call to complete the graph. Pages shrink to retain inline disassembly; a single oversized block may still require disassemble_range. partial describes pagination, not complete control-flow recovery. loop_evidence derives bounded natural loops from the full recovered graph independently of pages, with header/members/latches/exits and explicit omissions; dominance is relative to recovered edges and semantic completeness remains unknown. Every traversal executes header instructions; loop-assigned registers carry their updated values, so their initializers are not invariant. Trace current register values through at least two traversals before deriving a recurrence; arithmetic hoisting requires separate invariance proof. Not yet available for MIPS32.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "function_address": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Address (numeric)"},
        \\        {"type": "string", "description": "Hex address like 0x100000000"}
        \\      ],
        \\      "description": "Function address"
        \\    },
        \\    "offset": {"type": "integer", "minimum": 0, "default": 0, "description": "Skip this many basic blocks"},
        \\    "max_blocks": {"type": "integer", "minimum": 1, "maximum": 256, "default": 64, "description": "Blocks per page; outgoing edges may target blocks outside the page"},
        \\    "instruction_view": {"type": "string", "enum": ["execution", "disassembly"], "description": "ARM64 compact execution steps or legacy disassembly; execution implies instructions. Default preserves include_disassembly behavior."},
        \\    "include_disassembly": {
        \\      "type": "boolean",
        \\      "default": false,
        \\      "description": "Include instructions per block"
        \\    }
        \\  },
        \\  "required": ["doc_id", "function_address"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "lift",
        .description = "Explicitly lift selected functions to heuristic IR. This is not validated instruction semantics. Prefer disassemble_range for encoding-backed effects and read_bytes for primary evidence. Supports ARM64, ARM32 (incl. Thumb), MIPS32, and x86_64. Pages contain statements followed by variable records; follow each result.next_call until partial is false.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "addresses": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Single function address"},
        \\        {"type": "string", "description": "Hex address"},
        \\        {"type": "array", "items": {"type": "integer"}, "maxItems": 50, "description": "Array of function addresses (max 50)"}
        \\      ],
        \\      "description": "Function address(es)"
        \\    },
        \\    "offset": {"type": "integer", "minimum": 0, "default": 0, "description": "Record offset: statements first, then variables; use next_call for continuation"},
        \\    "max_results": {"type": "integer", "minimum": 1, "maximum": 256, "default": 128, "description": "Maximum records per function page; response budget may reduce this"}
        \\  },
        \\  "required": ["doc_id", "addresses"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "analyze_functions",
        .description = "Deep analysis for known function addresses (entry points). Returns CFG, xrefs, strings, callees, and optional derived IR, semantic facts, ABI register-use evidence (include=abi), or observed memory layouts (include=types). ABI defaults and layout hypotheses are not verified function prototypes or C structs. Use this when you already know the address is a function. For arbitrary addresses where you don't know the kind, use analyze_addresses instead.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "addresses": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Single function address"},
        \\        {"type": "string", "description": "Hex address"},
        \\        {"type": "array", "items": {"type": "integer"}, "maxItems": 50, "description": "Array of addresses (max 50)"}
        \\      ],
        \\      "description": "Function address(es). Arrays max 50."
        \\    },
        \\    "include": {
        \\      "type": "array",
        \\      "items": {
        \\        "type": "string",
        \\        "enum": ["ir", "cfg", "xrefs", "strings", "calls", "semantics", "abi", "types"]
        \\      },
        \\      "description": "Data to include",
        \\      "default": ["cfg", "xrefs", "strings", "calls"]
        \\    }
        \\  },
        \\  "required": ["doc_id", "addresses"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "analyze_addresses",
        .description = "Quick lookup for arbitrary addresses (code, data, strings, symbols). Returns containing segment, data type, name/label, and optional xrefs/details. Pass include=[\"xrefs\",\"strings\",\"calls\"] to enrich results with cross-references, nearby strings, or callee lists. Use this when you don't know whether an address is a function entry point. For known function addresses, prefer analyze_functions for deeper analysis.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "addresses": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Single address"},
        \\        {"type": "string", "description": "Hex address"},
        \\        {"type": "array", "items": {"type": "integer"}, "maxItems": 50, "description": "Array of addresses (max 50)"}
        \\      ],
        \\      "description": "Address(es) to look up"
        \\    },
        \\    "include": {
        \\      "type": "array",
        \\      "items": {
        \\        "type": "string",
        \\        "enum": ["ir", "cfg", "xrefs", "strings", "calls"]
        \\      },
        \\      "description": "Data to include",
        \\      "default": ["xrefs"]
        \\    }
        \\  },
        \\  "required": ["doc_id", "addresses"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "disassemble_range",
        .description = "Inspect bounded file-backed code: instructions, exact bytes, file offsets, and semantics status. ARM64 MOVZ/MOVN/MOVK have encoding-backed register effects; other instructions explicitly report unsupported. Coverage and partial-range metadata are included. byte_length is bytes, not instruction count (cap 4096).",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "start": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Address (numeric)"},
        \\        {"type": "string", "description": "Hex address like 0x100000000"}
        \\      ],
        \\      "description": "Start address"
        \\    },
        \\    "byte_length": {
        \\      "type": "integer",
        \\      "default": 4096,
        \\      "description": "Number of bytes to disassemble (max 4096). ARM64 = 4 bytes/insn, ARM32 Thumb = 2-4 bytes/insn, x86_64 = variable."
        \\    }
        \\  },
        \\  "required": ["doc_id", "start"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "read_bytes",
        .description = "Read raw bytes by virtual `address` OR raw `file_offset`. For small binaries, `get_binary_context mode=full include_bytes=true` adds bounded byte previews; use this tool for exact ranges and larger dumps. Primary byte evidence for direct reasoning about binary structure and behavior: use architecture, endianness and base context, then validate hypotheses with independent evidence. For code, cross-check instruction widths and loop/branch targets with disassemble_range and get_cfg. Pass `file_offset` (from `get_embedded_resources`) to carve an embedded bundle without resolving its virtual base — follow next_call to page through bounded reads. Requested length capped per page at 65536 bytes (64 KB), with smaller pages for expanded encodings. Address reads stop at mapping/backing boundaries. For numeric tables, pass element_size (1/2/4/8) and explicit byte_order (little/big) to receive exact unsigned decimal strings; at most 256 elements per typed read. Copy every table value, including repeated or exceptional entries. ASCII is a lossy printable preview: dots replace nonprintable bytes; use hex for byte identity. Encoding 'both' (default) returns both hex and ASCII; 'hex' or 'ascii' returns only one; 'hex_compact' returns hex bytes with no spaces and no ASCII column (densest output, ~2 chars per byte).",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "address": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Address (numeric)"},
        \\        {"type": "string", "description": "Hex address like 0x100000000"}
        \\      ],
        \\      "description": "Virtual address to read from (rebase-aware). Omit if using file_offset."
        \\    },
        \\    "file_offset": {
        \\      "type": "integer",
        \\      "minimum": 0,
        \\      "description": "Raw byte offset into the file to read from (alternative to address; as reported by get_embedded_resources). Bypasses virtual-address resolution."
        \\    },
        \\    "length": {
        \\      "type": "integer",
        \\      "default": 64,
        \\      "minimum": 1,
        \\      "description": "Requested bytes; each page is bounded by encoding budget and mapping/EOF. Follow next_call when present."
        \\    },
        \\    "element_size": {"type":"integer","enum":[1,2,4,8],"description":"Optional integer interpretation width in bytes; length must be at most 256 times this width"},
        \\    "byte_order": {"type":"string","enum":["little","big"],"description":"Required with element_size; explicit byte order, never inferred"},
        \\    "encoding": {
        \\      "type": "string",
        \\      "enum": ["ascii", "hex", "both", "hex_compact"],
        \\      "default": "both",
        \\      "description": "Output encoding"
        \\    }
        \\  },
        \\  "required": ["doc_id"],
        \\  "oneOf": [{"required":["address"]},{"required":["file_offset"]}],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_segments",
        .description = "List the binary's segments with their sections, permissions (rwx), virtual address ranges, per-section stats, and Shannon entropy (0=zeros, ~6.5=code, ~7.5+=compressed/encrypted).",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    }
        \\  },
        \\  "required": ["doc_id"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_hardening_report",
        .description = "Analyze binary hardening: NX (no-execute), W^X (write-xor-execute), PIE/PIC, RELRO, stack canaries (__stack_chk_fail), FORTIFY_SOURCE (*_chk imports), stripped status, and ARM64 PAC/BTI (pointer authentication and branch target identification). Returns a structured report in one call.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    }
        \\  },
        \\  "required": ["doc_id"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_embedded_resources",
        .description = "List structured embedded runtime resources (Bun JS bundle, etc.) discovered in a document, AND summarize what's IN them. Returns each resource with runtime, name, kind, size, address, file_offset, preview, and provenance. Unless include_surface=false, also returns a `surface` block for packed runtimes: a categorized-marker histogram, top markers per category (telemetry_event/env_toggle/model_id/endpoint/api_path/credential/...), and prefix `clusters` (a dark-launch codename family shows up as an unexpected shared prefix) — scanned on demand from the embedded text the string table skips. Optional `runtime` filter (e.g. 'bun') restricts to one adapter.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "runtime": {
        \\      "type": "string",
        \\      "description": "Optional filter — only return resources from this runtime (e.g. 'bun'). Omit to return all detected runtimes."
        \\    },
        \\    "include_surface": {
        \\      "type": "boolean",
        \\      "default": true,
        \\      "description": "Scan the embedded bundle text for categorized surface markers + codename clusters. Set false to skip (faster; metadata only)."
        \\    }
        \\  },
        \\  "required": ["doc_id"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "compare",
        .description = "Diff two loaded binaries by imports, strings, libraries, and (opt-in) procedure fingerprints. Default scope is [imports, strings, libraries]. Add \"procedures\" for fingerprint-based code diffing — expensive on large binaries. The `pattern` parameter currently filters only the strings scope (e.g. pattern=\"bypass|debug|secret\" to surface security-relevant string changes). v7.12 W3: include_changed=true (default) surfaces a top-level `changed[]` array of procedures with same name+address but different body fingerprint (instruction histogram + string-ref set + import-call set). Capped at max_changed=200. v7.14.0 B4: include_similar=true (default) adds a fuzzy-match `similar[]` bucket — same name across both binaries scored by Jaccard of import-calls (40%) + string-refs (30%) + cosine of instruction-mnemonic histograms (30%); emits when score ≥ 0.5. Pre-filters to procedures with ≥3 import calls (skips PLT stubs); capped at max_similar=200.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id_a": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "First document to compare"
        \\    },
        \\    "doc_id_b": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Second document to compare"
        \\    },
        \\    "scope": {
        \\      "type": "array",
        \\      "items": {"type": "string", "enum": ["imports", "strings", "libraries", "procedures"]},
        \\      "default": ["imports","strings","libraries"],
        \\      "description": "Compare: imports, strings, libraries, procedures (procedures is opt-in, expensive on large binaries)"
        \\    },
        \\    "max_results": {
        \\      "type": "integer",
        \\      "default": 50,
        \\      "description": "Max items per category"
        \\    },
        \\    "pattern": {
        \\      "type": "string",
        \\      "description": "Filter STRING diffs by pattern (| for OR, e.g. 'bypass|debug|secret'). Does not affect imports/libraries/procedures scopes."
        \\    },
        \\    "include_changed": {
        \\      "type": "boolean",
        \\      "default": true,
        \\      "description": "v7.12 W3: emit top-level `changed[]` array of procedures with same name+address but different body fingerprint. Default ON; pass false to skip."
        \\    },
        \\    "max_changed": {
        \\      "type": "integer",
        \\      "default": 200,
        \\      "description": "Cap on changed[] entries returned (default 200)."
        \\    },
        \\    "include_similar": {
        \\      "type": "boolean",
        \\      "default": true,
        \\      "description": "v7.14.0 B4: emit top-level `similar[]` bucket of cross-binary fuzzy matches (same name, score ≥ 0.5 across import-call/string-ref Jaccard + mnemonic-histogram cosine). Default ON; pass false to skip."
        \\    },
        \\    "max_similar": {
        \\      "type": "integer",
        \\      "default": 200,
        \\      "description": "Cap on similar[] entries returned (default 200)."
        \\    }
        \\  },
        \\  "required": ["doc_id_a", "doc_id_b"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "release_diff",
        .description = "Directional \"what's NEW & HIDDEN between two builds\" diff (old → new). Unlike `compare` (symmetric, native-code oriented), this diffs at the STRING + embedded-runtime-bundle (Bun __BUN etc.) + CAPABILITY level, keeps only markers present in `doc_id_new` and absent in `doc_id_old` (new-only lens), classifies each (telemetry_event/env_toggle/model_id/endpoint/credential/...), ranks the security/novel ones into `headlines[]`, and prefix-clusters them (a dark-launch codename shows up as an unexpected shared prefix). Pass `changelog` (raw release notes text) to auto-tag each new marker ANNOUNCED vs HIDDEN. Built for recurring per-release binary diffs. Load both builds with load_binary first.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id_old": {
        \\      "oneOf": [{"type": "integer"}, {"type": "string"}],
        \\      "description": "Previous build (document ID or name)"
        \\    },
        \\    "doc_id_new": {
        \\      "oneOf": [{"type": "integer"}, {"type": "string"}],
        \\      "description": "Current build (document ID or name)"
        \\    },
        \\    "sources": {
        \\      "type": "array",
        \\      "items": {"enum": ["strings", "bundle", "imports"]},
        \\      "description": "Which surfaces to diff (default: all). 'bundle' scans embedded-runtime segments; 'imports' diffs the import name set."
        \\    },
        \\    "changelog": {
        \\      "type": "string",
        \\      "description": "Optional raw changelog / announced-notes text. Each new marker whose value appears here is tagged announced:true; the rest are HIDDEN."
        \\    },
        \\    "max_per_cluster": {
        \\      "type": "integer",
        \\      "default": 40,
        \\      "description": "Cap on headlines[] entries returned."
        \\    }
        \\  },
        \\  "required": ["doc_id_old", "doc_id_new"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "get_dependency_graph",
        .description = "Build an import↔export dependency graph across all loaded binaries. Each edge shows the importer doc, the exporter doc, and the resolved symbols between them. Re-exported system stubs are filtered out automatically. C++/Rust symbols are matched in both raw and demangled forms. Pass doc_id to focus on one binary (only that doc + its direct neighbors are included). Unresolved imports (system libs not loaded) are reported separately per doc.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Focus on one binary's imports (omit for full graph)"
        \\    },
        \\    "pattern": {
        \\      "type": "string",
        \\      "description": "Filter to symbols matching pattern (| for OR)"
        \\    },
        \\    "max_results": {
        \\      "type": "integer",
        \\      "default": 20,
        \\      "description": "Max symbols shown per edge"
        \\    }
        \\  },
        \\  "required": [],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "close_document",
        .description = "Close a loaded document and free its memory. Does not delete the original binary file. Use this when you're done with a doc to keep the working set small.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    }
        \\  },
        \\  "required": ["doc_id"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":false,"destructiveHint":true}
        ,
    },
    .{
        .name = "get_demangled_name",
        .description = "Demangle a symbol. Supports C++ (Itanium ABI), Swift, and Rust (legacy `_ZN…$LT$…E` and v0 `_R…`). Accepts an address (int or hex string), or a raw mangled name. Returns the original, the demangled form, and the detected language. Note: load-time demangling already replaces names in the database — use this tool when you have a raw mangled string from outside.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "address_or_name": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Address integer"},
        \\        {"type": "string", "description": "Hex address or mangled name"}
        \\      ],
        \\      "description": "Address or mangled name"
        \\    }
        \\  },
        \\  "required": ["doc_id", "address_or_name"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
    .{
        .name = "mark_data_type",
        .description = "Tell analysis to interpret an address as a specific kind: code, an integer (int8..int64), an ASCII or unicode string, or a raw byte array. Use after spotting misclassified bytes (e.g., a string sitting in a data section that the loader didn't recognize). Set length>1 to cover an array of elements. Address must be in a segment with read/write/execute permission — guard regions like __PAGEZERO are rejected.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "address": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Address (numeric)"},
        \\        {"type": "string", "description": "Hex address like 0x100000000"}
        \\      ],
        \\      "description": "Target address to mark"
        \\    },
        \\    "data_type": {
        \\      "type": "string",
        \\      "enum": ["code", "int8", "int16", "int32", "int64", "ascii", "unicode", "byte_array"],
        \\      "description": "Data type"
        \\    },
        \\    "length": {
        \\      "type": "integer",
        \\      "default": 1,
        \\      "description": "Number of elements (default: 1)"
        \\    }
        \\  },
        \\  "required": ["doc_id", "address", "data_type"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":false,"destructiveHint":true}
        ,
    },
    .{
        .name = "rebase_document",
        .description = "Create a non-destructive rebased view of a binary at a new base address (e.g. shift __TEXT from 0x100000000 to 0x200000000). Returns a new doc_id; the original document is unchanged. Requires a numeric doc_id (not a name) since rebasing a wrong binary is hard to undo.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "type": "integer",
        \\      "description": "Source document ID (must be numeric for safety — names not accepted to avoid ambiguity)"
        \\    },
        \\    "new_base_address": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Address (numeric)"},
        \\        {"type": "string", "description": "Hex address like 0x200000000"}
        \\      ],
        \\      "description": "New base address — the first loadable segment will be placed here"
        \\    }
        \\  },
        \\  "required": ["doc_id", "new_base_address"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":true}
        ,
    },
    .{
        .name = "export",
        .description = "Export the binary's analysis as JSON (structured), text (human-readable), or IR. Pass an optional address to scope the export to a single function instead of the whole document.",
        .input_schema =
        \\{
        \\  "type": "object",
        \\  "properties": {
        \\    "doc_id": {
        \\      "oneOf": [
        \\        {"type": "integer", "description": "Document ID (numeric)"},
        \\        {"type": "string", "description": "Document name"}
        \\      ],
        \\      "description": "Document ID or name"
        \\    },
        \\    "format": {
        \\      "type": "string",
        \\      "enum": ["json", "text", "ir"],
        \\      "description": "Export format"
        \\    },
        \\    "address": {
        \\      "oneOf": [
        \\        {"type": "integer"},
        \\        {"type": "string"}
        \\      ],
        \\      "description": "Scope to one function at this address"
        \\    }
        \\  },
        \\  "required": ["doc_id", "format"],
        \\  "additionalProperties": false
        \\}
        ,
        .annotations =
        \\{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true}
        ,
    },
};

// ============================================================================
// Document Store — manages loaded documents and their databases
// ============================================================================

/// A loaded document with its analysis database.
pub const DocumentEntry = struct {
    doc: types.Document,
    db: Database,
    /// Pre-built call index: proc entry → list of callee addresses.
    /// Built lazily on first call_graph/callees_of request.
    call_index: ?std.AutoHashMap(u64, []const u64) = null,
    call_index_mutex: std.Io.Mutex = .init,
    rebase_parent: ?*DocumentEntry = null,
    rebase_parent_id: ?u64 = null,
    rebase_delta: i128 = 0,
    /// v7.15.0 B1 pass 2: when true, `doc.data` and `doc.path` were allocated
    /// from the store allocator (handleLoadBinary file-open path, dyld_cache,
    /// load_project) and close_document MUST free them. When false the data is
    /// a slice into a parent buffer (ZIP-extracted children, rebased views)
    /// and freeing it would double-free.
    owns_data: bool = true,
    /// v7.15.0 B1 pass 2: when true, `doc.path` was duped onto store_alloc
    /// and close_document must free it. Some paths (e.g. rebased views) own
    /// only the path; others own both.
    owns_path: bool = true,
};

/// Manages all loaded documents. The MCP server holds one of these.
pub const DocumentStore = struct {
    allocator: Allocator,
    io: std.Io,
    documents: std.AutoHashMap(u64, *DocumentEntry),
    next_id: u64,
    mutex: std.Io.Mutex,

    pub fn init(allocator: Allocator, io: std.Io) DocumentStore {
        return .{
            .allocator = allocator,
            .io = io,
            .documents = std.AutoHashMap(u64, *DocumentEntry).init(allocator),
            .mutex = .init,
            .next_id = 1,
        };
    }

    pub fn deinit(self: *DocumentStore) void {
        // v7.15.0 B1 pass 1: load handlers now allocate DocumentEntry/Doc/DB
        // and their backing data from `self.allocator` instead of the per-
        // request arena. We DON'T tear down individual entries here yet
        // because some load paths (ZIP extraction, raw byte slices into
        // parent buffers, load_project string aliasing into the parsed JSON)
        // still reference memory the doc doesn't own; pass 2 will track an
        // owns_data flag and walk per-entry. Process exit reclaims the GPA.
        self.documents.deinit();
    }

    pub fn nextId(self: *DocumentStore) u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    pub fn put(self: *DocumentStore, entry: *DocumentEntry) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.documents.put(entry.doc.id, entry);
    }

    pub fn get(self: *DocumentStore, doc_id: u64) ?*DocumentEntry {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.documents.get(doc_id);
    }

    pub fn remove(self: *DocumentStore, doc_id: u64) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const removed = self.documents.remove(doc_id);
        return removed;
    }
};

// ============================================================================
// Tool Context
// ============================================================================

/// Context available to all tool handlers.
pub const ToolContext = struct {
    io: std.Io,
    store: *DocumentStore,
    session_id: []const u8,
    allocator: Allocator,
    /// Optional pointer to the McpServer. Real MCP requests set this from the
    /// server side. Tests construct ToolContext without a server (server=null)
    /// so they can drive the dispatcher directly. queueNotification is a no-op
    /// when null. Previously this was `*anyopaque = undefined`, which silently
    /// crashed test_integration with an `incorrect alignment` panic when load_binary
    /// (via finalizeLoad) called queueNotification on the undefined pointer.
    server: ?*anyopaque = null,
    /// v7.11 W5: client-supplied `_meta.progressToken` from the tools/call request.
    /// When non-null, handlers may emit progress events via `emitProgress`. When
    /// null, all `emitProgress` calls are zero-cost no-ops (clients must opt in).
    progress_token: ?[]const u8 = null,

    /// Queue a notification to be sent after the current response.
    /// Uses the McpServer's queueNotification through an opaque pointer to avoid
    /// circular imports (server.zig imports tools.zig).
    pub fn queueNotification(self: ToolContext, method: []const u8) void {
        const srv_ptr = self.server orelse return;
        const McpServer = @import("server.zig").McpServer;
        const srv: *McpServer = @ptrCast(@alignCast(srv_ptr));
        srv.queueNotification(method);
    }

    /// v7.11 W5: emit a `notifications/progress` event. No-op if the caller
    /// did not pass `_meta.progressToken` in the tools/call request, or if the
    /// server pointer is unset (test contexts).
    pub fn emitProgress(self: ToolContext, progress: u32, total: u32, message: []const u8) void {
        const token = self.progress_token orelse return;
        const srv_ptr = self.server orelse return;
        const McpServer = @import("server.zig").McpServer;
        const srv: *McpServer = @ptrCast(@alignCast(srv_ptr));
        srv.queueProgressNotification(self.session_id, token, progress, total, message);
    }

    /// v7.11 W6: emit a `notifications/message` event. Gated by the session's
    /// log_level (default info). Pass empty string for `data_context_json` to
    /// skip the optional context object. No-op when server pointer is unset.
    pub fn emitLog(self: ToolContext, level_str: []const u8, logger: []const u8, text: []const u8, context_json: []const u8) void {
        const srv_ptr = self.server orelse return;
        const McpServer = @import("server.zig").McpServer;
        const srv: *McpServer = @ptrCast(@alignCast(srv_ptr));
        const lvl = McpServer.LogLevel.fromString(level_str) orelse .info;
        srv.queueLogNotification(self.session_id, lvl, logger, text, context_json);
    }
};

// ============================================================================
// Tool Dispatcher
// ============================================================================

pub const ToolError = error{
    UnknownTool,
    InvalidParams,
    DocumentNotFound,
    OutOfMemory,
    WriteFailed,
};

/// Result of a tool handler — JSON response string and error flag.
pub const ToolResult = struct {
    json_response: []const u8,
    is_error: bool = false,
    /// MCP _meta["anthropic/maxResultSizeChars"] — overrides the 80K default cap per-tool.
    meta_max_chars: ?usize = null,
};

/// Dispatch a tool call by name. Returns JSON response string.
pub fn dispatch(ctx: ToolContext, method: []const u8, params: std.json.Value) ToolError!ToolResult {
    const result: ToolResult = if (eql(method, "load_binary"))
        try handleLoadBinary(ctx, params)
    else if (eql(method, "list_documents"))
        try handleListDocuments(ctx, params)
    else if (eql(method, "close_document"))
        try handleCloseDocument(ctx, params)
    else if (eql(method, "analyze_functions"))
        try handleAnalyzeFunctions(ctx, params)
    else if (eql(method, "analyze_addresses"))
        try handleAnalyzeAddresses(ctx, params)
    else if (eql(method, "search"))
        try handleSearch(ctx, params)
    else if (eql(method, "get_segments"))
        try handleGetSegments(ctx, params)
    else if (eql(method, "get_call_graph"))
        try handleGetCallGraph(ctx, params)
    else if (eql(method, "get_cfg"))
        try handleGetCfg(ctx, params)
    else if (eql(method, "get_xrefs"))
        try handleGetXrefs(ctx, params)
    else if (eql(method, "lift"))
        try handleLift(ctx, params)
    else if (eql(method, "annotate"))
        try handleAnnotate(ctx, params)
    else if (eql(method, "save_project"))
        try handleSaveProject(ctx, params)
    else if (eql(method, "load_project"))
        try handleLoadProject(ctx, params)
    else if (eql(method, "export"))
        try handleExport(ctx, params)
    else if (eql(method, "get_strings"))
        try handleGetStrings(ctx, params)
    else if (eql(method, "get_imports"))
        try handleGetImports(ctx, params)
    else if (eql(method, "get_exports"))
        try handleGetExports(ctx, params)
    else if (eql(method, "disassemble_range"))
        try handleDisassembleRange(ctx, params)
    else if (eql(method, "read_bytes"))
        try handleReadBytes(ctx, params)
    else if (eql(method, "get_embedded_resources"))
        try handleGetEmbeddedResources(ctx, params)
    else if (eql(method, "rebase_document"))
        try handleRebaseDocument(ctx, params)
    else if (eql(method, "mark_data_type"))
        try handleMarkDataType(ctx, params)
    else if (eql(method, "get_demangled_name"))
        try handleGetDemangledName(ctx, params)
    else if (eql(method, "compare"))
        try handleCompare(ctx, params)
    else if (eql(method, "release_diff"))
        try handleReleaseDiff(ctx, params)
    else if (eql(method, "get_dependency_graph"))
        try handleGetDependencyGraph(ctx, params)
    else if (eql(method, "suggest_names"))
        try handleSuggestNames(ctx, params)
    else if (eql(method, "get_remake_frontier"))
        try handleGetRemakeFrontier(ctx, params)
    else if (eql(method, "get_binary_context"))
        try handleGetBinaryContext(ctx, params)
    else if (eql(method, "get_semantic_slice"))
        try handleGetSemanticSlice(ctx, params)
    else if (eql(method, "get_hardening_report"))
        try handleGetHardeningReport(ctx, params)
    else
        return ToolError.UnknownTool;

    // Apply output safety cap; respect per-tool _meta override, else use 80K default.
    const effective_limit = if (result.meta_max_chars) |m| @min(m, 500_000) else max_response_chars;
    if (result.json_response.len > effective_limit) {
        // v7.16 W5: non-destructive truncation. The old path threw the entire
        // body away and returned only an error stub, forcing a blind re-query.
        // Instead keep a JSON-escaped preview of the FRONT of the real response
        // (where summary/counts/first results live) so the LLM has usable
        // context alongside the paginate hint.
        var preview_len = @min(result.json_response.len, 2000);
        // v7.16 W5 fix: don't cut mid-UTF-8 (bodies carry em dashes/ellipses/
        // symbol names) or the escaped preview becomes invalid UTF-8 and strict
        // clients reject the whole reply. Back off any trailing continuation
        // bytes (0b10xxxxxx). Also clamp to the cap for very small limits.
        preview_len = @min(preview_len, @max(effective_limit / 4, 256));
        if (preview_len < result.json_response.len) {
            while (preview_len > 0 and (result.json_response[preview_len] & 0xC0) == 0x80) preview_len -= 1;
        }
        var pbuf = std.Io.Writer.Allocating.init(ctx.allocator);
        const pw = &pbuf.writer;
        pw.writeAll("{\"error\":\"Response too large — paginate with offset/max_results (or lower max_chars).\",\"truncated\":true") catch return ToolError.OutOfMemory;
        pw.print(",\"original_size\":{d},\"cap\":{d}", .{ result.json_response.len, effective_limit }) catch return ToolError.OutOfMemory;
        pw.writeAll(",\"preview\":") catch return ToolError.OutOfMemory;
        json.writeJsonString(pw, result.json_response[0..preview_len]) catch return ToolError.OutOfMemory;
        pw.writeByte('}') catch return ToolError.OutOfMemory;
        const msg = pbuf.toOwnedSlice() catch return ToolError.OutOfMemory;
        return .{ .json_response = msg, .is_error = false, .meta_max_chars = result.meta_max_chars };
    }

    return result;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Parse Mach-O indirect symbol table to map stub addresses to import symbol names.
/// For each __auth_stubs/__stubs section, the section's reserved1 field gives the
/// starting index into the indirect symbol table. Each entry in the indirect symbol
/// table is a 4-byte index into the symbol table. We look up the symbol name and
/// register it at the stub address via db.addSymbol.
fn registerStubSymbols(allocator: std.mem.Allocator, data: []const u8, doc: *const types.Document, db: *Database) void {
    _ = allocator;
    if (data.len < 4) return;

    // Determine if FAT binary and find the Mach-O slice
    var slice_offset: usize = 0;
    const magic = std.mem.readInt(u32, data[0..4], .little);
    const FAT_MAGIC: u32 = 0xBEBAFECA;
    const FAT_MAGIC_64: u32 = 0xBFBAFECA;
    if (magic == FAT_MAGIC or magic == FAT_MAGIC_64) {
        // For FAT binaries, find __TEXT segment's file_offset to derive slice_offset.
        // __TEXT has segment_fileoff=0 in the Mach-O, so its stored file_offset IS the slice offset.
        // Skip __PAGEZERO (which also has fileoff=0 but is not useful).
        for (doc.segments) |seg| {
            if (std.mem.eql(u8, seg.name, "__TEXT")) {
                if (seg.file_offset > 0 and seg.file_offset < data.len) {
                    slice_offset = seg.file_offset;
                }
                break;
            }
        }
    }

    // Read the Mach-O header from the slice
    if (slice_offset + 32 > data.len) return;
    const slice_magic = std.mem.readInt(u32, data[slice_offset..][0..4], .little);
    const MH_MAGIC_64: u32 = 0xFEEDFACF;
    const MH_CIGAM_64: u32 = 0xCFFAEDFE;
    const needs_swap = (slice_magic == MH_CIGAM_64);
    if (slice_magic != MH_MAGIC_64 and slice_magic != MH_CIGAM_64) return;

    // Parse header to get ncmds and sizeofcmds
    const ncmds = readU32Swap(data, slice_offset + 16, needs_swap);
    const header_size: usize = 32; // mach_header_64 size

    // First pass: find LC_SYMTAB and LC_DYSYMTAB
    var symoff: u32 = 0;
    var nsyms: u32 = 0;
    var stroff: u32 = 0;
    var strsize: u32 = 0;
    var indirectsymoff: u32 = 0;
    var nindirectsyms: u32 = 0;

    // Also collect stub sections with their reserved1 values
    const StubSectionInfo = struct {
        addr: u64,
        size: u64,
        stub_size: u64,
        indirect_index: u32,
    };
    var stub_sections: [8]StubSectionInfo = undefined;
    var stub_section_count: usize = 0;

    var cmd_offset: usize = slice_offset + header_size;
    var cmd_idx: u32 = 0;
    while (cmd_idx < ncmds) : (cmd_idx += 1) {
        if (cmd_offset + 8 > data.len) break;
        const cmd = readU32Swap(data, cmd_offset, needs_swap);
        const cmdsize = readU32Swap(data, cmd_offset + 4, needs_swap);
        if (cmdsize < 8) break;

        const LC_SYMTAB: u32 = 0x02;
        const LC_DYSYMTAB: u32 = 0x0B;
        const LC_SEGMENT_64: u32 = 0x19;

        if (cmd == LC_SYMTAB) {
            if (cmd_offset + 24 <= data.len) {
                symoff = readU32Swap(data, cmd_offset + 8, needs_swap);
                nsyms = readU32Swap(data, cmd_offset + 12, needs_swap);
                stroff = readU32Swap(data, cmd_offset + 16, needs_swap);
                strsize = readU32Swap(data, cmd_offset + 20, needs_swap);
            }
        } else if (cmd == LC_DYSYMTAB) {
            // DysymtabCommand: indirectsymoff at offset 8+4*12=56, nindirectsyms at offset 60
            if (cmd_offset + 64 <= data.len) {
                indirectsymoff = readU32Swap(data, cmd_offset + 56, needs_swap);
                nindirectsyms = readU32Swap(data, cmd_offset + 60, needs_swap);
            }
        } else if (cmd == LC_SEGMENT_64) {
            // Parse sections to find __auth_stubs and __stubs
            if (cmd_offset + 72 <= data.len) {
                const seg_nsects = readU32Swap(data, cmd_offset + 64, needs_swap);
                var sect_off: usize = cmd_offset + 72;
                var si: u32 = 0;
                while (si < seg_nsects and stub_section_count < 8) : (si += 1) {
                    if (sect_off + 80 > data.len) break; // SectionHeader64 is 80 bytes
                    // sectname is at offset 0 (16 bytes), segname at 16 (16 bytes)
                    const sect_name = getSectName(data, sect_off);
                    const sect_addr = readU64Swap(data, sect_off + 32, needs_swap);
                    const sect_size = readU64Swap(data, sect_off + 40, needs_swap);
                    const sect_reserved1 = readU32Swap(data, sect_off + 68, needs_swap);
                    const sect_reserved2 = readU32Swap(data, sect_off + 72, needs_swap);

                    if (std.mem.eql(u8, sect_name, "__auth_stubs") or
                        std.mem.eql(u8, sect_name, "__stubs") or
                        std.mem.eql(u8, sect_name, "__auth_got") or
                        std.mem.eql(u8, sect_name, "__got") or
                        std.mem.eql(u8, sect_name, "__la_symbol_ptr") or
                        std.mem.eql(u8, sect_name, "__nl_symbol_ptr"))
                    {
                        const st_size: u64 = if (sect_reserved2 != 0) sect_reserved2 else if (std.mem.eql(u8, sect_name, "__auth_stubs")) 16 else if (std.mem.eql(u8, sect_name, "__stubs")) 12 else 8; // GOT/symbol_ptr entries are 8 bytes
                        stub_sections[stub_section_count] = .{
                            .addr = sect_addr,
                            .size = sect_size,
                            .stub_size = st_size,
                            .indirect_index = sect_reserved1,
                        };
                        stub_section_count += 1;
                    }
                    sect_off += 80;
                }
            }
        }

        cmd_offset += cmdsize;
    }

    // Preserve defined data symbols without advertising them as functions.
    const strings_start = slice_offset + stroff;
    if (symoff != 0 and strings_start <= data.len and strsize <= data.len - strings_start) {
        const strings = data[strings_start..][0..strsize];
        for (0..nsyms) |i| {
            const offset = slice_offset + symoff + i * 16;
            if (offset > data.len or data.len - offset < 16) break;
            const kind = data[offset + 4];
            if ((kind & 0xe0) != 0 or (kind & 0x0e) != 0x0e) continue;
            const index = readU32Swap(data, offset, needs_swap);
            const address = readU64Swap(data, offset + 8, needs_swap);
            if (index >= strings.len or address == 0) continue;
            const name = std.mem.sliceTo(strings[index..], 0);
            if (name.len > 0) db.addSymbol(address, name) catch {};
        }
    }

    if (indirectsymoff == 0 or nindirectsyms == 0 or symoff == 0 or nsyms == 0) return;

    // Build the symbol name table (nlist64 entries)
    const sym_start = slice_offset + symoff;
    const str_start = slice_offset + stroff;
    const str_end = str_start + strsize;
    if (str_end > data.len) return;
    const strtab = data[str_start..str_end];

    const indirect_start = slice_offset + indirectsymoff;
    if (indirect_start + @as(usize, nindirectsyms) * 4 > data.len) return;

    // For each stub section, map stubs to symbol names
    for (stub_sections[0..stub_section_count]) |ss| {
        var stub_addr = ss.addr;
        var idx: u32 = ss.indirect_index;
        while (stub_addr < ss.addr + ss.size) : ({
            stub_addr += ss.stub_size;
            idx += 1;
        }) {
            if (idx >= nindirectsyms) break;

            // Read the indirect symbol table entry (4-byte symbol index)
            const isym_off = indirect_start + @as(usize, idx) * 4;
            if (isym_off + 4 > data.len) break;
            const sym_idx = readU32Swap(data, isym_off, needs_swap);

            // INDIRECT_SYMBOL_LOCAL or INDIRECT_SYMBOL_ABS
            if (sym_idx == 0x80000000 or sym_idx == 0x40000000 or sym_idx >= nsyms) continue;

            // Read the nlist64 entry for this symbol
            const nlist_off = sym_start + @as(usize, sym_idx) * 16; // sizeof(nlist_64) = 16
            if (nlist_off + 16 > data.len) continue;
            const n_strx = readU32Swap(data, nlist_off, needs_swap);

            // Look up the name in the string table
            if (n_strx < strsize) {
                var name_len: usize = 0;
                while (n_strx + name_len < strsize and strtab[n_strx + name_len] != 0) : (name_len += 1) {}
                if (name_len > 0) {
                    const name = strtab[n_strx .. n_strx + name_len];
                    db.addSymbol(stub_addr, name) catch {};
                }
            }
        }
    }
}

fn readU32Swap(data: []const u8, offset: usize, needs_swap: bool) u32 {
    if (offset + 4 > data.len) return 0;
    const val = std.mem.readInt(u32, data[offset..][0..4], .little);
    return if (needs_swap) @byteSwap(val) else val;
}

fn readU64Swap(data: []const u8, offset: usize, needs_swap: bool) u64 {
    if (offset + 8 > data.len) return 0;
    const val = std.mem.readInt(u64, data[offset..][0..8], .little);
    return if (needs_swap) @byteSwap(val) else val;
}

fn getSectName(data: []const u8, offset: usize) []const u8 {
    if (offset + 16 > data.len) return "";
    const name_bytes = data[offset..][0..16];
    var name_len: usize = 0;
    while (name_len < 16 and name_bytes[name_len] != 0) : (name_len += 1) {}
    return name_bytes[0..name_len];
}

fn detectFormat(data: []const u8) types.BinaryFormat {
    if (macho.isMacho(data)) return .macho;
    if (elf_loader.isElf(data)) return .elf;
    if (pe_loader.isPe(data)) return .pe;
    if (isZip(data)) return .zip;
    if (data.len >= 40 and data[0] == 0x00 and data[1] == 'P' and data[2] == 'B' and data[3] == 'P') return .pbp;
    // v7.9.0: PSX-EXE (PlayStation 1 executable) — magic "PS-X EXE" at offset 0
    // followed by a 0x800-byte header. Must come BEFORE the raw fallback so MIPS
    // PS1 binaries get auto-arch + entry-point recovery instead of arm64 raw.
    if (data.len >= 0x800 and data[0] == 'P' and data[1] == 'S' and data[2] == '-' and data[3] == 'X' and
        data[4] == ' ' and data[5] == 'E' and data[6] == 'X' and data[7] == 'E') return .psx_exe;
    return .raw;
}

fn isZip(data: []const u8) bool {
    return data.len >= 4 and data[0] == 'P' and data[1] == 'K' and data[2] == 0x03 and data[3] == 0x04;
}

/// v7.9.0 K.5: parse an arch string with aliases. Accepts canonical names
/// (`arm64`, `x86_64`, `arm32`, `x86`, `mips32`) plus little-endian MIPS
/// aliases (`mipsel`, `mips32le`, `mips32-le`, `mips-le` — all map to .mips32).
/// Returns null for unknown strings so callers can keep their existing
/// "first match wins" pattern.
fn parseArchString(s: []const u8) ?types.Arch {
    if (std.ascii.eqlIgnoreCase(s, "arm64")) return .arm64;
    if (std.ascii.eqlIgnoreCase(s, "x86_64")) return .x86_64;
    if (std.ascii.eqlIgnoreCase(s, "arm32")) return .arm32;
    if (std.ascii.eqlIgnoreCase(s, "x86")) return .x86;
    if (std.ascii.eqlIgnoreCase(s, "mips32")) return .mips32;
    // K.5 aliases — all little-endian MIPS, all map to .mips32.
    if (std.ascii.eqlIgnoreCase(s, "mipsel")) return .mips32;
    if (std.ascii.eqlIgnoreCase(s, "mips32le")) return .mips32;
    if (std.ascii.eqlIgnoreCase(s, "mips32-le")) return .mips32;
    if (std.ascii.eqlIgnoreCase(s, "mips-le")) return .mips32;
    return null;
}

/// v7.9.0 K.4: parse `options.{arch, fat_arch, entry, base}` from MCP params.
/// Sets `doc.arch` and the corresponding fields on `out_opts`. Used by all
/// 3 load_binary handlers to share parsing logic.
fn parseLoadOptions(params: std.json.Value, doc: *types.Document, out_opts: *types.LoadOptions) void {
    const param_opts = getObject(params, "options") orelse return;
    if (getString(param_opts, "arch")) |arch_str| {
        if (parseArchString(arch_str)) |a| {
            doc.arch = a;
            out_opts.arch = a;
        }
    }
    if (getString(param_opts, "fat_arch")) |fat_str| {
        if (parseArchString(fat_str)) |a| out_opts.fat_arch = a;
    }
    if (getInt(param_opts, "entry")) |e| {
        if (e >= 0) out_opts.entry = @intCast(e);
    }
    if (getInt(param_opts, "base")) |b| {
        if (b >= 0) out_opts.base = @intCast(b);
    }
}

/// Create a single synthetic "raw" segment spanning the entire file for raw-format
/// v7.8.4: when a PBP container's embedded module isn't ELF (it's an encrypted
/// PSP module — `~PSP` or `PSAR` magic), the load technically succeeds but
/// yields a degenerate doc (0 procs / 0 segments / 0 imports). Return a
/// human-readable hint so the user knows what happened and how to proceed.
/// Returns null when the blob isn't a known encrypted format (caller leaves
/// note unset).
fn pbpEncryptedHint(blob: []const u8) ?[]const u8 {
    if (blob.len >= 4 and blob[0] == '~' and blob[1] == 'P' and blob[2] == 'S' and blob[3] == 'P') {
        return "PBP DATA.PSP section is an encrypted ~PSP module — Phora cannot disassemble it as-is. Decrypt with pspdecrypt (https://github.com/PSP-Archive/pspdecrypt) or load the corresponding `.dec` / extracted ELF instead.";
    }
    if (blob.len >= 4 and blob[0] == 'P' and blob[1] == 'S' and blob[2] == 'A' and blob[3] == 'R') {
        return "PBP DATA.PSP section is a PSAR archive — extract the inner module first (e.g. via psardumper) and load the resulting ELF.";
    }
    return null;
}

/// documents. This makes get_segments, read_bytes, and analyze_addresses all work
/// with the same mental model as formatted binaries — no need for special-case logic.
fn synthesizeRawSegment(allocator: Allocator, doc: *types.Document, data: []const u8) !void {
    const sections = try allocator.alloc(types.Section, 1);
    sections[0] = .{
        .name = "raw",
        .start = 0,
        .length = data.len,
        .file_offset = 0,
        .alignment = 0,
        .is_code = true,
    };
    const segments = try allocator.alloc(types.Segment, 1);
    segments[0] = .{
        .name = "raw",
        .start = 0,
        .length = data.len,
        .sections = sections,
        // v7.9.1 Q1.a: mark exec=true so procedure detection (which only
        // scans exec segments) discovers procs in raw-loaded binaries.
        .permissions = .{ .read = true, .execute = true },
        .file_offset = 0,
        .file_size = data.len,
    };
    doc.segments = segments;
}

/// v7.9.0: shared helper for the .raw branch in all 3 load_binary handlers.
/// Re-inits the document but PRESERVES the arch from options (which the
/// caller set via `entry.doc.arch = opts_arch_or_default` BEFORE format
/// detection). Honors `entry`/`base` overrides if provided.
///
/// Why this exists: `Document.init()` hardcodes `.arch = .arm64`. Before
/// this helper, the .raw branches would call init() AFTER the arch was
/// already set from options, silently clobbering it. The friend's bug was
/// `load_binary path=raw.bin options={arch:mips32}` defaulting to arm64.
fn finalizeRawDocument(
    allocator: Allocator,
    doc: *types.Document,
    data: []const u8,
    arch_override: types.Arch,
    entry_override: ?u64,
    base_override: ?u64,
) void {
    const id = doc.id;
    const path = doc.path;
    doc.* = types.Document.init(allocator, id, path, data);
    doc.format = .raw;
    doc.arch = arch_override;
    if (entry_override) |e| doc.entry_point = e;
    synthesizeRawSegment(allocator, doc, data) catch {};
    // base_override: if provided, shift the synthesized segment's start to base.
    if (base_override) |b| {
        if (doc.segments.len > 0) {
            doc.segments[0].start = b;
            // Update sections too (synthesized segment usually has 1 section).
            for (doc.segments[0].sections) |*sect| sect.start = b;
        }
    }
}

/// v7.9.0: PSX-EXE (PlayStation 1 executable) loader. Header at offset 0:
///   0x00..0x07: magic "PS-X EXE"
///   0x10: pc0 (entry point, u32 LE)
///   0x18: t_addr (load base, u32 LE)
///   0x1C: t_size (code size, u32 LE)
/// Code starts at file offset 0x800.
fn synthesizePsxExeSegments(
    allocator: Allocator,
    doc: *types.Document,
    data: []const u8,
) !void {
    // v7.9.1 Q1.b: set arch BEFORE early returns so even malformed PSX-EXE
    // (truncated, t_size=0, etc.) reports the correct mips32 arch.
    doc.arch = .mips32;
    if (data.len < 0x800) return;
    const pc0 = std.mem.readInt(u32, data[0x10..0x14], .little);
    const t_addr = std.mem.readInt(u32, data[0x18..0x1C], .little);
    const t_size = std.mem.readInt(u32, data[0x1C..0x20], .little);
    const code_end = @min(@as(u64, 0x800) + @as(u64, t_size), data.len);
    if (code_end <= 0x800) return;

    doc.entry_point = pc0;

    const sections = try allocator.alloc(types.Section, 1);
    sections[0] = .{
        .name = ".text",
        .start = t_addr,
        .length = code_end - 0x800,
        .file_offset = 0x800,
        .alignment = 0,
    };
    const segments = try allocator.alloc(types.Segment, 1);
    segments[0] = .{
        .name = "PSX_TEXT",
        .start = t_addr,
        .length = code_end - 0x800,
        .sections = sections,
        .permissions = .{ .read = true, .execute = true },
        .file_offset = 0x800,
        .file_size = code_end - 0x800,
    };
    doc.segments = segments;
}

/// Extract native binaries (.so, .dylib, .dll) from a ZIP/APK and load each.
/// Returns a batch response JSON, or null if no binaries found.
fn extractBinariesFromZip(ctx: ToolContext, zip_path: []const u8, data: []const u8, params: std.json.Value, _: i64) ?[]const u8 {
    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var entries_scanned: u32 = 0;
    var skipped_compression: u32 = 0;
    var skipped_decompress: u32 = 0;
    var skipped_format: u32 = 0;
    var skipped_non_native: u32 = 0;

    // Scan for local file headers (PK\x03\x04)
    var pos: usize = 0;
    while (pos + 30 < data.len) {
        // Find next local file header
        if (data[pos] != 'P' or data[pos + 1] != 'K' or data[pos + 2] != 0x03 or data[pos + 3] != 0x04) {
            pos += 1;
            continue;
        }

        entries_scanned += 1;

        // Parse local file header
        const compressed_size = std.mem.readInt(u32, data[pos + 18 ..][0..4], .little);
        const uncompressed_size = std.mem.readInt(u32, data[pos + 22 ..][0..4], .little);
        const name_len = std.mem.readInt(u16, data[pos + 26 ..][0..2], .little);
        const extra_len = std.mem.readInt(u16, data[pos + 28 ..][0..2], .little);
        const compression = std.mem.readInt(u16, data[pos + 8 ..][0..2], .little);

        const name_start = pos + 30;
        if (name_start + name_len > data.len) break;
        const name = data[name_start .. name_start + name_len];

        const data_start = name_start + name_len + extra_len;

        // Move past this entry
        const entry_size = if (compressed_size > 0) compressed_size else uncompressed_size;
        pos = data_start + entry_size;

        // Only handle stored (0) or deflate (8) compressed native binaries
        if (compression != 0 and compression != 8) {
            skipped_compression += 1;
            continue;
        }
        if (data_start + compressed_size > data.len) continue;
        if (compression == 0 and data_start + uncompressed_size > data.len) continue;

        // Check if this is a native binary by extension
        const is_native = std.mem.endsWith(u8, name, ".so") or
            hasSoVersion(name) or
            std.mem.endsWith(u8, name, ".dylib") or
            std.mem.endsWith(u8, name, ".dll") or
            std.mem.endsWith(u8, name, ".exe");
        if (!is_native) {
            skipped_non_native += 1;
            continue;
        }

        // Get file data — decompress if needed
        var file_data: []const u8 = undefined;
        if (compression == 8) {
            // Deflate: decompress using std.compress.flate
            const compressed = data[data_start .. data_start + compressed_size];
            const decompressed = ctx.allocator.alloc(u8, uncompressed_size) catch continue;
            var comp_stream: std.Io.Reader = .fixed(compressed);
            var out_writer: std.Io.Writer = .fixed(decompressed);
            var decompressor: std.compress.flate.Decompress = .init(&comp_stream, .raw, &.{});
            const decompressed_len = decompressor.reader.streamRemaining(&out_writer) catch {
                skipped_decompress += 1;
                continue;
            };
            if (decompressed_len != uncompressed_size) {
                skipped_decompress += 1;
                continue;
            }
            file_data = decompressed[0..decompressed_len];
        } else {
            file_data = data[data_start .. data_start + uncompressed_size];
        }
        const fmt = detectFormat(file_data);
        if (fmt == .raw or fmt == .zip) {
            skipped_format += 1;
            continue;
        }

        // Build a virtual path: "apk_path!/entry_name"
        const virtual_path = std.fmt.allocPrint(ctx.allocator, "{s}!/{s}", .{ zip_path, name }) catch continue;

        // Load it via the normal single-binary path
        const item_start = timestampMs(ctx.io);
        const result = loadSingleBinaryFromData(ctx, virtual_path, file_data, params);
        const item_elapsed = timestampMs(ctx.io) - item_start;

        if (result) |result_json| {
            items.append(.{ .input = virtual_path, .success = true, .result = result_json, .time_ms = item_elapsed }) catch {};
        } else |_| {
            items.append(.{ .input = virtual_path, .success = false, .err = "load failed", .time_ms = item_elapsed }) catch {};
        }
    }

    if (items.items.len == 0) {
        const diag = std.fmt.allocPrint(ctx.allocator, "ZIP/APK contains {d} entries: {d} non-native extensions, {d} unsupported compression, {d} decompression failed, {d} unrecognized binary format. No loadable native binaries (.so/.dylib/.dll/.exe) found.", .{ entries_scanned, skipped_non_native, skipped_compression, skipped_decompress, skipped_format }) catch "no native binaries found in ZIP/APK";
        var err_items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
        err_items.append(.{ .input = zip_path, .success = false, .err = diag, .time_ms = 0 }) catch {};
        return json.batchResponse(ctx.allocator, err_items.items) catch null;
    }

    return json.batchResponse(ctx.allocator, items.items) catch null;
}

fn hasSoVersion(name: []const u8) bool {
    // Match libfoo.so.1, libfoo.so.1.2.3, etc.
    if (std.mem.indexOf(u8, name, ".so.")) |_| return true;
    return false;
}

// ============================================================================
// Helpers
// ============================================================================

fn timestampMs(io: std.Io) i64 {
    return runtime.awakeMillis(io);
}

const NativeFileWriter = struct {
    file: std.Io.File,
    io: std.Io,

    pub fn writeAll(self: NativeFileWriter, bytes: []const u8) !void {
        try self.file.writeStreamingAll(self.io, bytes);
    }

    pub fn writeByte(self: NativeFileWriter, byte: u8) !void {
        try self.writeAll(&.{byte});
    }

    pub fn print(self: NativeFileWriter, comptime fmt: []const u8, args: anytype) !void {
        var stack_buf: [4096]u8 = undefined;
        const rendered = std.fmt.bufPrint(&stack_buf, fmt, args) catch {
            const allocated = try std.fmt.allocPrint(std.heap.page_allocator, fmt, args);
            defer std.heap.page_allocator.free(allocated);
            try self.writeAll(allocated);
            return;
        };
        try self.writeAll(rendered);
    }
};

fn readNativeFileToEndAlloc(file: std.Io.File, io: std.Io, allocator: Allocator, limit: usize) ![]u8 {
    var file_reader = file.reader(io, &.{});
    return file_reader.interface.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        else => |e| return e,
    };
}

/// Get a string field from a JSON Value object.
// ============================================================================
// Lenient Parameter Parsing
// LLMs are nondeterministic — they may send strings instead of ints, hex
// strings instead of decimal, floats instead of ints, etc. These parsers
// accept any reasonable representation and coerce it to the right type.
// ============================================================================

/// Trim leading/trailing whitespace from a string.
fn trimString(s: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = s.len;
    while (start < end and (s[start] == ' ' or s[start] == '\t' or s[start] == '\n')) start += 1;
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t' or s[end - 1] == '\n')) end -= 1;
    return s[start..end];
}

/// Get a string field. If the value is an integer, formats it as a string.
/// Trims leading/trailing whitespace for robustness against LLM formatting.
fn getString(params: std.json.Value, key: []const u8) ?[]const u8 {
    if (params != .object) return null;
    const val = params.object.get(key) orelse return null;
    return switch (val) {
        .string => |s| if (s.len == 0) null else trimString(s),
        else => null,
    };
}

/// Get an integer field. Accepts: integer, float (truncated), or string
/// (decimal "123" or hex "0x1234" or "0X1234"). This is the key leniency
/// point — LLMs frequently send doc_id as "1" or addresses as "0x100000960".
fn getInt(params: std.json.Value, key: []const u8) ?i64 {
    if (params != .object) return null;
    const val = params.object.get(key) orelse return null;
    return coerceToInt(val);
}

/// Coerce any JSON value to an integer if possible.
fn coerceToInt(val: std.json.Value) ?i64 {
    return switch (val) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        .string => |s| parseIntLenient(s),
        .number_string => |s| parseIntLenient(s),
        else => null,
    };
}

/// Parse a string as an integer, accepting decimal ("123"), hex ("0x1abc"),
/// or negative ("-42") formats.
pub fn parseIntLenient(s: []const u8) ?i64 {
    if (s.len == 0) return null;

    // Trim leading/trailing whitespace for robustness (LLMs sometimes pad values).
    var ts = s;
    while (ts.len > 0 and (ts[0] == ' ' or ts[0] == '\t')) ts = ts[1..];
    while (ts.len > 0 and (ts[ts.len - 1] == ' ' or ts[ts.len - 1] == '\t')) ts = ts[0 .. ts.len - 1];
    if (ts.len == 0) return null;

    // Handle hex: "0x..." or "0X..."
    if (ts.len > 2 and ts[0] == '0' and (ts[1] == 'x' or ts[1] == 'X')) {
        const hex_part = ts[2..];
        var result: u64 = 0;
        for (hex_part) |c| {
            const digit: u64 = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => c - 'a' + 10,
                'A'...'F' => c - 'A' + 10,
                '_' => continue, // allow underscores
                else => return null,
            };
            result = result *% 16 +% digit;
        }
        return @bitCast(result);
    }

    // Handle negative
    var start: usize = 0;
    var negative = false;
    if (ts[0] == '-') {
        negative = true;
        start = 1;
    }

    // Decimal
    var result: i64 = 0;
    for (ts[start..]) |c| {
        if (c >= '0' and c <= '9') {
            result = result * 10 + @as(i64, c - '0');
        } else if (c == '_' or c == ',') {
            continue; // allow separators
        } else {
            return null;
        }
    }
    return if (negative) -result else result;
}

/// Get a boolean field. Accepts: bool, integer (0/1), or string ("true"/"false"/"yes"/"no"/"1"/"0").
/// String comparisons are case-insensitive for robustness.
fn getBool(params: std.json.Value, key: []const u8) ?bool {
    if (params != .object) return null;
    const val = params.object.get(key) orelse return null;
    return switch (val) {
        .bool => |b| b,
        .integer => |i| i != 0,
        .string => |s| {
            if (std.ascii.eqlIgnoreCase(s, "true") or std.ascii.eqlIgnoreCase(s, "yes") or eql(s, "1")) return true;
            if (std.ascii.eqlIgnoreCase(s, "false") or std.ascii.eqlIgnoreCase(s, "no") or eql(s, "0")) return false;
            return null;
        },
        else => null,
    };
}

/// Get a nested object field from a JSON Value.
fn getObject(params: std.json.Value, key: []const u8) ?std.json.Value {
    if (params != .object) return null;
    const val = params.object.get(key) orelse return null;
    if (val != .object) return null;
    return val;
}

/// Get an array field from a JSON Value.
fn getArray(params: std.json.Value, key: []const u8) ?std.json.Value {
    if (params != .object) return null;
    const val = params.object.get(key) orelse return null;
    if (val != .array) return null;
    return val;
}

/// Match a value against a pattern that may contain pipe-separated alternatives (OR match).
/// E.g., "cheat|exploit|hack" matches if any of the sub-patterns match.
/// If case_insensitive is true, the pattern should already be lowercased.
fn matchesMultiPattern(value: []const u8, pattern: []const u8, case_insensitive: bool) bool {
    // Pre-lowercase value once if case-insensitive
    var lower_val_buf: [4096]u8 = undefined;
    var match_value = value;
    if (case_insensitive) {
        const val_len = @min(value.len, lower_val_buf.len);
        for (value[0..val_len], 0..) |c, ci| {
            lower_val_buf[ci] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        match_value = lower_val_buf[0..val_len];
    }

    // Check for pipe-separated OR patterns
    if (std.mem.indexOf(u8, pattern, "|") == null) {
        return std.mem.indexOf(u8, match_value, pattern) != null;
    }
    var rest: []const u8 = pattern;
    while (rest.len > 0) {
        const sep_pos = std.mem.indexOf(u8, rest, "|");
        const sub = if (sep_pos) |pos| rest[0..pos] else rest;
        if (sub.len > 0 and std.mem.indexOf(u8, match_value, sub) != null) return true;
        if (sep_pos) |pos| {
            rest = rest[pos + 1 ..];
        } else break;
    }
    return false;
}

/// Parse the "addresses" field which can be:
/// - A single integer: 4294970720
/// - A single hex string: "0x100000960"
/// - An array of integers: [4294970720, 4294970880]
/// - An array of hex strings: ["0x100000960", "0x100000a00"]
/// - A mix of the above
fn parseBatchAddresses(allocator: Allocator, params: std.json.Value) ![]u64 {
    if (params != .object) return error.OutOfMemory;

    // Try "addresses" first, then "address" (common LLM mistake)
    const val = params.object.get("addresses") orelse
        params.object.get("address") orelse
        return error.OutOfMemory;

    switch (val) {
        .integer => |i| {
            const result = try allocator.alloc(u64, 1);
            result[0] = @intCast(i);
            return result;
        },
        .float => |f| {
            const result = try allocator.alloc(u64, 1);
            result[0] = @intFromFloat(f);
            return result;
        },
        .string, .number_string => |s| {
            // Single hex or decimal string
            const parsed = parseIntLenient(s) orelse return error.OutOfMemory;
            const result = try allocator.alloc(u64, 1);
            result[0] = @bitCast(parsed);
            return result;
        },
        .array => |arr| {
            if (arr.items.len == 0) return error.OutOfMemory;
            // Parse valid elements, skip null/unparseable ones
            var valid = std.array_list.Managed(u64).init(allocator);
            errdefer valid.deinit();
            for (arr.items) |item| {
                if (item == .null) continue; // skip null elements
                const parsed = coerceToInt(item) orelse continue; // skip unparseable
                valid.append(@bitCast(parsed)) catch return error.OutOfMemory;
            }
            if (valid.items.len == 0) return error.OutOfMemory;
            return valid.toOwnedSlice() catch return error.OutOfMemory;
        },
        else => return error.OutOfMemory,
    }
}

/// Parse include flags from JSON array.
/// Unknown flags are silently skipped for robustness. If the array exists but
/// contains no valid flags, defaults (cfg, xrefs, strings, calls) are used.
fn parseIncludeFlagsValidated(params: std.json.Value) IncludeFlags {
    var flags = IncludeFlags{};
    var any_valid = false;
    if (getArray(params, "include")) |arr| {
        for (arr.array.items) |item| {
            if (item == .string) {
                if (std.ascii.eqlIgnoreCase(item.string, "ir")) {
                    flags.ir = true;
                    any_valid = true;
                } else if (std.ascii.eqlIgnoreCase(item.string, "cfg")) {
                    flags.cfg = true;
                    any_valid = true;
                } else if (std.ascii.eqlIgnoreCase(item.string, "xrefs")) {
                    flags.xrefs = true;
                    any_valid = true;
                } else if (std.ascii.eqlIgnoreCase(item.string, "strings")) {
                    flags.strings = true;
                    any_valid = true;
                } else if (std.ascii.eqlIgnoreCase(item.string, "calls")) {
                    flags.calls = true;
                    any_valid = true;
                } else if (std.ascii.eqlIgnoreCase(item.string, "semantics")) {
                    flags.semantics = true;
                    any_valid = true;
                } else if (std.ascii.eqlIgnoreCase(item.string, "abi")) {
                    flags.abi = true;
                    any_valid = true;
                } else if (std.ascii.eqlIgnoreCase(item.string, "types")) {
                    flags.types = true;
                    any_valid = true;
                }
                // unknown flags silently skipped
            }
        }
        // If array existed but had no valid flags, use defaults
        if (!any_valid) {
            flags.strings = true;
            flags.cfg = true;
            flags.xrefs = true;
            flags.calls = true;
        }
    } else {
        // Default includes
        flags.strings = true;
        flags.cfg = true;
        flags.xrefs = true;
        flags.calls = true;
    }
    return flags;
}

/// Parse include flags (legacy wrapper — now identical since validated version is lenient).
fn parseIncludeFlags(params: std.json.Value) IncludeFlags {
    return parseIncludeFlagsValidated(params);
}

const IncludeFlags = struct {
    ir: bool = false,
    cfg: bool = false,
    xrefs: bool = false,
    strings: bool = false,
    calls: bool = false,
    semantics: bool = false,
    abi: bool = false,
    types: bool = false,
};

fn addrStr(buf: []u8, address: u64) []const u8 {
    return json.formatAddress(buf, address);
}

/// Validate and return a doc_id from params. Returns null if missing or negative.
fn getDocIdValidated(params: std.json.Value) ?u64 {
    const raw = getInt(params, "doc_id") orelse return null;
    if (raw < 0) return null;
    return @intCast(raw);
}

/// Resolve doc_id from params: try integer first, then string name matching against
/// loaded document basenames. Returns null if no doc_id param or no unique match.
fn resolveDocId(ctx: ToolContext, params: std.json.Value) ?u64 {
    // Try integer first
    if (getDocIdValidated(params)) |id| return id;
    // Try string name — match against basename of loaded document paths
    if (getString(params, "doc_id")) |name| {
        var match_id: ?u64 = null;
        var match_count: u32 = 0;
        ctx.store.mutex.lockUncancelable(ctx.io);
        var it = ctx.store.documents.iterator();
        while (it.next()) |entry| {
            const path = entry.value_ptr.*.doc.path;
            const basename = std.fs.path.basename(path);
            if (std.mem.eql(u8, basename, name)) {
                match_id = entry.key_ptr.*;
                match_count += 1;
            }
        }
        ctx.store.mutex.unlock(ctx.io);
        if (match_count == 1) return match_id;
    }
    // Auto-pick when exactly one document is loaded and no doc_id was provided.
    ctx.store.mutex.lockUncancelable(ctx.io);
    const doc_count = ctx.store.documents.count();
    if (doc_count == 1) {
        var auto_it = ctx.store.documents.keyIterator();
        const only_id = auto_it.next().?.*;
        ctx.store.mutex.unlock(ctx.io);
        return only_id;
    }
    ctx.store.mutex.unlock(ctx.io);
    return null;
}

/// Like resolveDocId but reads from an arbitrary field name instead of "doc_id".
fn resolveDocIdField(ctx: ToolContext, params: std.json.Value, field: []const u8) ?u64 {
    // Try integer first
    if (getInt(params, field)) |raw| {
        if (raw < 0) return null;
        return @intCast(raw);
    }
    // Try string name — match against basename of loaded document paths
    if (getString(params, field)) |name| {
        var match_id: ?u64 = null;
        var match_count: u32 = 0;
        ctx.store.mutex.lockUncancelable(ctx.io);
        var it = ctx.store.documents.iterator();
        while (it.next()) |entry| {
            const path = entry.value_ptr.*.doc.path;
            const basename = std.fs.path.basename(path);
            if (std.mem.eql(u8, basename, name)) {
                match_id = entry.key_ptr.*;
                match_count += 1;
            }
        }
        ctx.store.mutex.unlock(ctx.io);
        if (match_count == 1) return match_id;
    }
    return null;
}

fn applyRebaseDelta(addr: u64, delta: i128) u64 {
    const result = @as(i128, addr) + delta;
    if (result < 0) return 0;
    return @intCast(@as(u128, @bitCast(result)) & 0xFFFFFFFFFFFFFFFF);
}

fn removeRebaseDelta(addr: u64, delta: i128) u64 {
    return applyRebaseDelta(addr, -delta);
}

const EffectiveDb = struct {
    db: *Database,
    delta: i128,
    entry: *DocumentEntry,
};

fn resolveEffectiveDb(entry: *DocumentEntry) EffectiveDb {
    if (entry.rebase_parent) |parent| {
        return .{ .db = &parent.db, .delta = entry.rebase_delta, .entry = parent };
    }
    return .{ .db = &entry.db, .delta = 0, .entry = entry };
}

/// Check if an address falls within any segment of a document.
/// For documents with no segments (raw binaries), returns true (permissive).
/// When checking a rebased address, caller should subtract the delta first.
pub fn isAddressInSegments(address: u64, segments: []const types.Segment) bool {
    if (segments.len == 0) return true;
    for (segments) |seg| {
        if (address >= seg.start and address < seg.start + seg.length) return true;
    }
    return false;
}

/// Like isAddressInSegments but rejects segments with no permissions (e.g. __PAGEZERO).
/// Use this for mutating tools (annotate, mark_data_type) where writing to a
/// guard region is meaningless noise.
pub fn isAddressInMutableSegments(address: u64, segments: []const types.Segment) bool {
    if (segments.len == 0) return true;
    for (segments) |seg| {
        if (!seg.permissions.read and !seg.permissions.write and !seg.permissions.execute) continue;
        if (address >= seg.start and address < seg.start + seg.length) return true;
    }
    return false;
}

/// Build an error response listing available documents when doc_id resolution fails.
fn docNotFoundError(ctx: ToolContext, tool_name: []const u8) ToolError!ToolResult {
    return docNotFoundErrorFull(ctx, tool_name, .null);
}

/// Like docNotFoundError but detects ambiguous name matches when params are available.
fn docNotFoundErrorFull(ctx: ToolContext, tool_name: []const u8, params: std.json.Value) ToolError!ToolResult {
    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;

    // Check if doc_id was a string that matches multiple documents
    if (getString(params, "doc_id")) |name| {
        var match_count: u32 = 0;
        var match_ids: [32]u64 = undefined;
        ctx.store.mutex.lockUncancelable(ctx.io);
        var it = ctx.store.documents.iterator();
        while (it.next()) |entry| {
            const basename = std.fs.path.basename(entry.value_ptr.*.doc.path);
            if (std.mem.eql(u8, basename, name) and match_count < 32) {
                match_ids[match_count] = entry.key_ptr.*;
                match_count += 1;
            }
        }
        ctx.store.mutex.unlock(ctx.io);
        if (match_count > 1) {
            w.print("Multiple documents named '{s}': use numeric doc_id (", .{name}) catch {};
            for (match_ids[0..match_count], 0..) |id, i| {
                if (i > 0) w.writeAll(", ") catch {};
                w.print("{d}", .{id}) catch {};
            }
            w.writeAll(")") catch {};
            const msg = buf.toOwnedSlice() catch "ambiguous document name";
            const resp = json.errorResponse(ctx.allocator, tool_name, msg, 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        }
    }

    // Standard "not found" message
    w.writeAll("document not found. Loaded: ") catch {};
    ctx.store.mutex.lockUncancelable(ctx.io);
    var it2 = ctx.store.documents.iterator();
    var first = true;
    while (it2.next()) |entry| {
        if (!first) w.writeAll(", ") catch {};
        first = false;
        w.print("{d}={s}", .{ entry.key_ptr.*, std.fs.path.basename(entry.value_ptr.*.doc.path) }) catch {};
    }
    ctx.store.mutex.unlock(ctx.io);
    if (first) w.writeAll("(none)") catch {};
    const msg = buf.toOwnedSlice() catch "document not found";
    const resp = json.errorResponse(ctx.allocator, tool_name, msg, 0) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .is_error = true };
}

/// Lazily build and cache the callees list for a single procedure.
/// On first access for a given proc_entry, scans refs_from to find call xrefs
/// v7.9.1 Q4: byte-scan executable segments for static-writer patterns that
/// target `target_addr`. Mirrors the friend's `find_writes.py` algorithm.
/// Currently implements MIPS32 (lui+sw/sh/sb) and ARM64 (adrp+str/stur). x86_64
/// is mostly covered by the existing IR xref pipeline and is not re-scanned here.
fn findWritersOf(
    allocator: Allocator,
    doc: types.Document,
    target_addr: u64,
    out: *std.array_list.Managed(types.SearchResult),
    delta: i128,
) !void {
    for (doc.segments) |seg| {
        if (!seg.permissions.execute) continue;
        if (seg.file_size == 0) continue;
        const file_start = seg.file_offset;
        const file_end = @min(file_start + seg.file_size, doc.data.len);
        if (file_end <= file_start) continue;
        const bytes = doc.data[file_start..file_end];

        switch (doc.arch) {
            .mips32 => try scanMipsWriters(bytes, seg.start, target_addr, out, delta, allocator),
            .arm64 => try scanArm64Writers(bytes, seg.start, target_addr, out, delta, allocator),
            .x86_64 => try scanX86_64Writers(bytes, seg.start, target_addr, out, delta, allocator),
            else => {}, // arm32 / x86: rely on existing IR-level xrefs
        }
        if (out.items.len >= 100) return;
    }
}

/// MIPS32 `lui rX, hi; ...; sw/sh/sb rY, lo(rX)` correlation.
fn scanMipsWriters(
    bytes: []const u8,
    seg_start: u64,
    target: u64,
    out: *std.array_list.Managed(types.SearchResult),
    delta: i128,
    allocator: Allocator,
) !void {
    var i: usize = 0;
    while (i + 4 <= bytes.len) : (i += 4) {
        const w = std.mem.readInt(u32, bytes[i..][0..4], .little);
        const op = (w >> 26) & 0x3F;
        if (op != 0x0F) continue; // lui
        const rt = (w >> 16) & 0x1F;
        const hi: u64 = @as(u64, @intCast(w & 0xFFFF)) << 16;
        // Look ahead up to 12 instructions for a matching sw/sh/sb.
        var j: usize = i + 4;
        const look_end = @min(i + 4 + 12 * 4, bytes.len);
        while (j + 4 <= look_end) : (j += 4) {
            const w2 = std.mem.readInt(u32, bytes[j..][0..4], .little);
            const op2 = (w2 >> 26) & 0x3F;
            if (op2 == 0x28 or op2 == 0x29 or op2 == 0x2B) { // sb / sh / sw
                const base_rs = (w2 >> 21) & 0x1F;
                if (base_rs != rt) continue;
                const lo_u16: u32 = w2 & 0xFFFF;
                const lo_signed: i32 = if (lo_u16 & 0x8000 != 0)
                    @as(i32, @intCast(lo_u16)) - 0x10000
                else
                    @as(i32, @intCast(lo_u16));
                const eff: u64 = @intCast(@as(i64, @intCast(hi)) + lo_signed);
                if (eff == target) {
                    const mnem = switch (op2) {
                        0x28 => "sb",
                        0x29 => "sh",
                        else => "sw",
                    };
                    const pc = seg_start + @as(u64, @intCast(j));
                    const rtext = try std.fmt.allocPrint(allocator, "{s} (lui@0x{x})", .{ mnem, seg_start + @as(u64, @intCast(i)) });
                    out.append(.{
                        .address = applyRebaseDelta(pc, delta),
                        .match_text = rtext,
                        .result_type = "writer",
                    }) catch {};
                    if (out.items.len >= 100) return;
                    break; // one sw per lui
                }
            }
            // Another lui with same rt invalidates the scan for this lui.
            const op2_op = (w2 >> 26) & 0x3F;
            if (op2_op == 0x0F and ((w2 >> 16) & 0x1F) == rt) break;
        }
    }
}

/// ARM64 `adrp xX, page; str/stur yY, [xX, #lo]` correlation. Best-effort.
fn scanArm64Writers(
    bytes: []const u8,
    seg_start: u64,
    target: u64,
    out: *std.array_list.Managed(types.SearchResult),
    delta: i128,
    allocator: Allocator,
) !void {
    var i: usize = 0;
    while (i + 4 <= bytes.len) : (i += 4) {
        const w = std.mem.readInt(u32, bytes[i..][0..4], .little);
        // ADRP: bits 31,24..28 = 1,10000 → 0x9000_0000 with op(bit31)=1
        if ((w & 0x9F000000) != 0x90000000) continue;
        const rd = w & 0x1F;
        // immhi (21 bits from bits 5..23), immlo (2 bits from bits 29..30)
        const immhi: u64 = @as(u64, @intCast((w >> 5) & 0x7FFFF));
        const immlo: u64 = @as(u64, @intCast((w >> 29) & 0x3));
        const imm_raw: u64 = (immhi << 2) | immlo;
        // sign-extend 21 bits then shift left by 12
        const sign_ext: i64 = if ((imm_raw & (1 << 20)) != 0)
            @as(i64, @intCast(imm_raw)) - (1 << 21)
        else
            @as(i64, @intCast(imm_raw));
        const pc: u64 = seg_start + @as(u64, @intCast(i));
        const page: u64 = @intCast(@as(i64, @intCast(pc & ~@as(u64, 0xFFF))) + (sign_ext << 12));
        // Look ahead up to 8 instructions for a str/stur using rd as base.
        var j: usize = i + 4;
        const look_end = @min(i + 4 + 8 * 4, bytes.len);
        while (j + 4 <= look_end) : (j += 4) {
            const w2 = std.mem.readInt(u32, bytes[j..][0..4], .little);
            // str (immediate) unsigned offset: size:10,111001 00 imm12 Rn Rt
            //   64-bit:  F9 000000 (0xF9000000); 32-bit: B9 000000
            const is_str64 = (w2 & 0xFFC00000) == 0xF9000000;
            const is_str32 = (w2 & 0xFFC00000) == 0xB9000000;
            if (!(is_str64 or is_str32)) continue;
            const rn = (w2 >> 5) & 0x1F;
            if (rn != rd) continue;
            const imm12 = (w2 >> 10) & 0xFFF;
            const scale: u64 = if (is_str64) 8 else 4;
            const lo_byte: u64 = @as(u64, imm12) * scale;
            const eff = page + lo_byte;
            if (eff == target) {
                const mnem = if (is_str64) "str (64b)" else "str (32b)";
                const pc_str = seg_start + @as(u64, @intCast(j));
                const rtext = try std.fmt.allocPrint(allocator, "{s} (adrp@0x{x})", .{ mnem, pc });
                out.append(.{
                    .address = applyRebaseDelta(pc_str, delta),
                    .match_text = rtext,
                    .result_type = "writer",
                }) catch {};
                if (out.items.len >= 100) return;
                break;
            }
        }
    }
}

/// x86_64 `mov [mem], reg` byte-scan. Matches two common static-writer forms:
///
///   1. RIP-relative: `[REX.W] 89 /r` with ModR/M mod=00, rm=101.
///      Effective addr = (RIP of next insn) + sext(disp32).
///      32-bit store (no REX.W):  `89 05 dd dd dd dd`       (6 bytes, reg=eax)
///      64-bit store (REX.W):     `48 89 05 dd dd dd dd`    (7 bytes, reg=rax)
///      Any REX prefix byte (0x40..0x4F) is tolerated; REX.R/REX.B don't affect
///      the address math for RIP-relative.
///
///   2. SIB-absolute: `[REX.W] 89 /r 25 dd dd dd dd` with ModR/M mod=00, rm=100
///      (→ SIB follows) and SIB base=101, index=100 (→ abs32 disp, no index).
///      Effective addr = sext(disp32).
///      32-bit store:             `89 04 25 dd dd dd dd`    (7 bytes)
///      64-bit store (REX.W):     `48 89 04 25 dd dd dd dd` (8 bytes)
///
/// We don't attempt full x86 length-decoding; the above two forms cover the
/// overwhelming majority of globals stores that static-linked absolute xrefs
/// target, which is what writers_of cares about for retro/bare-metal RE.
fn scanX86_64Writers(
    bytes: []const u8,
    seg_start: u64,
    target: u64,
    out: *std.array_list.Managed(types.SearchResult),
    delta: i128,
    allocator: Allocator,
) !void {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        // Optional REX prefix (0x40..0x4F). Remember whether REX.W was set so we
        // can tag the mnemonic size.
        var p: usize = i;
        var rex_w = false;
        if (p < bytes.len and (bytes[p] & 0xF0) == 0x40) {
            rex_w = (bytes[p] & 0x08) != 0;
            p += 1;
        }
        // Opcode must be 0x89 (MOV r/m, r).
        if (p >= bytes.len or bytes[p] != 0x89) continue;
        const modrm_off = p + 1;
        if (modrm_off >= bytes.len) continue;
        const modrm = bytes[modrm_off];
        const mod: u8 = (modrm >> 6) & 0x3;
        const rm: u8 = modrm & 0x7;
        if (mod != 0) continue;

        if (rm == 0b101) {
            // RIP-relative: [REX?] 89 /r disp32
            const disp_off = modrm_off + 1;
            const inst_end = disp_off + 4;
            if (inst_end > bytes.len) continue;
            const disp_raw = std.mem.readInt(u32, bytes[disp_off..][0..4], .little);
            const disp_s: i64 = @as(i32, @bitCast(disp_raw));
            const next_rip: u64 = seg_start + @as(u64, @intCast(inst_end));
            const eff: u64 = @bitCast(@as(i64, @bitCast(next_rip)) + disp_s);
            if (eff == target) {
                const mnem = if (rex_w) "mov [rip+disp32], r64" else "mov [rip+disp32], r32";
                const pc = seg_start + @as(u64, @intCast(i));
                const rtext = try std.fmt.allocPrint(allocator, "{s} (disp=0x{x})", .{ mnem, disp_raw });
                out.append(.{
                    .address = applyRebaseDelta(pc, delta),
                    .match_text = rtext,
                    .result_type = "writer",
                }) catch {};
                if (out.items.len >= 100) return;
            }
        } else if (rm == 0b100) {
            // SIB follows. [REX?] 89 /r SIB disp32
            const sib_off = modrm_off + 1;
            if (sib_off >= bytes.len) continue;
            const sib = bytes[sib_off];
            const sib_base: u8 = sib & 0x7;
            const sib_index: u8 = (sib >> 3) & 0x7;
            // Absolute disp32: mod=00 + SIB base=101 + index=100 (no index).
            if (sib_base != 0b101) continue;
            if (sib_index != 0b100) continue;
            const disp_off = sib_off + 1;
            const inst_end = disp_off + 4;
            if (inst_end > bytes.len) continue;
            const disp_raw = std.mem.readInt(u32, bytes[disp_off..][0..4], .little);
            const disp_s: i64 = @as(i32, @bitCast(disp_raw));
            const eff: u64 = @bitCast(disp_s);
            if (eff == target) {
                const mnem = if (rex_w) "mov [abs32], r64" else "mov [abs32], r32";
                const pc = seg_start + @as(u64, @intCast(i));
                const rtext = try std.fmt.allocPrint(allocator, "{s} (disp=0x{x})", .{ mnem, disp_raw });
                out.append(.{
                    .address = applyRebaseDelta(pc, delta),
                    .match_text = rtext,
                    .result_type = "writer",
                }) catch {};
                if (out.items.len >= 100) return;
            }
        }
    }
}

/// within the procedure's range, caches the result in entry.call_index, and
/// returns the slice. Subsequent calls return the cached slice directly.
fn ensureCalleesCached(entry: *DocumentEntry, db: *Database, proc_entry: u64, allocator: Allocator) []const u64 {
    // v7.15.1 A1: call_index outlives any single request; it's stored on the
    // long-lived DocumentEntry and freed by teardownDocumentEntry via
    // store_alloc. Earlier callers passed `ctx.allocator` (a per-request
    // arena), so the HashMap and its value slices ended up arena-owned —
    // which `teardownDocumentEntry` later tried to free with store_alloc,
    // hitting GPA's "Invalid free" and SIGABRTing on the first close after
    // a frontier query. We now ignore the passed `allocator` parameter and
    // always use `entry.db.allocator` (the store-owned long-lived allocator
    // confirmed by Database.init in handleLoadBinary). The parameter is
    // retained for signature compatibility with all 9 call sites.
    _ = allocator;
    const long_lived = entry.db.allocator;

    entry.call_index_mutex.lockUncancelable(entry.db.io);
    defer entry.call_index_mutex.unlock(entry.db.io);
    // Check if call_index exists and has this proc already cached
    if (entry.call_index) |ci| {
        if (ci.get(proc_entry)) |callees| return callees;
    } else {
        // Create the HashMap on first access
        entry.call_index = std.AutoHashMap(u64, []const u64).init(long_lived);
    }

    // Build callees for this one procedure by scanning refs_from
    var callees_list = std.array_list.Managed(u64).init(long_lived);
    const proc = db.getProcedureContaining(proc_entry) orelse {
        // Cache empty slice so we don't re-scan
        const empty: []const u64 = &.{};
        entry.call_index.?.put(proc_entry, empty) catch {};
        return empty;
    };
    const proc_end = proc.entry + @max(proc.size, 256);

    // O(log N + K) range query via sorted xref array
    const callee_xrefs = db.xrefs.getRefsFromRange(proc.entry, proc_end);
    for (callee_xrefs) |xref| {
        if (xref.xref_type == .call) {
            callees_list.append(xref.to) catch {};
        }
    }

    const callees = callees_list.toOwnedSlice() catch {
        const empty: []const u64 = &.{};
        return empty;
    };
    entry.call_index.?.put(proc_entry, callees) catch {};
    return callees;
}

/// Serialize a procedure's analysis to JSON using the writer-based approach.
fn serializeProcedureJson(allocator: Allocator, proc: types.Procedure, db: *Database, flags: IncludeFlags, call_index: ?std.AutoHashMap(u64, []const u64), doc_id: u64, delta: i128, ir_budget: usize) ![]const u8 {
    var buf = std.Io.Writer.Allocating.init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{");
    try w.writeAll("\"address\":");
    try json.writeAddress(w, proc.entry);
    try w.writeAll(",\"size\":");
    try w.print("{d}", .{proc.size});

    if (proc.name) |name| {
        try w.writeAll(",\"name\":");
        try json.writeJsonString(w, name);
    }

    if (flags.calls) {
        // Use call_index for callees (C2 fix) — proc.calls is typically empty
        const callees: []const u64 = if (call_index) |ci|
            (ci.get(proc.entry) orelse &[_]u64{})
        else
            proc.calls;

        try w.writeAll(",\"calls\":[");
        for (callees, 0..) |call_addr, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeByte('{');
            try w.writeAll("\"address\":");
            try json.writeAddress(w, call_addr);
            if (db.resolveName(call_addr)) |name| {
                try w.writeAll(",\"name\":");
                try json.writeJsonString(w, name);
            }
            try w.writeByte('}');
        }
        try w.writeByte(']');

        // called_by: look up refs_to for call xrefs targeting this proc
        try w.writeAll(",\"called_by\":[");
        const refs_to_proc = db.xrefs.getRefsTo(proc.entry);
        var called_by_count: usize = 0;
        for (refs_to_proc) |xref| {
            if (xref.xref_type == .call) {
                if (called_by_count > 0) try w.writeByte(',');
                // Resolve to containing procedure entry if possible
                if (db.getProcedureContaining(xref.from)) |caller_proc| {
                    try json.writeAddress(w, caller_proc.entry);
                } else {
                    try json.writeAddress(w, xref.from);
                }
                called_by_count += 1;
            }
        }
        try w.writeByte(']');
    }

    if (flags.xrefs) {
        const xrefs_from = db.xrefs.getRefsFrom(proc.entry);
        const xrefs_to = db.xrefs.getRefsTo(proc.entry);

        try w.writeAll(",\"xrefs\":{\"from\":[");
        for (xrefs_from, 0..) |xref, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"to\":");
            try json.writeAddress(w, xref.to);
            try w.writeAll(",\"type\":\"");
            try w.writeAll(xrefTypeStr(xref.xref_type));
            try w.writeAll("\"}");
        }
        try w.writeAll("],\"to\":[");
        for (xrefs_to, 0..) |xref, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"from\":");
            try json.writeAddress(w, xref.from);
            try w.writeAll(",\"type\":\"");
            try w.writeAll(xrefTypeStr(xref.xref_type));
            try w.writeAll("\"}");
        }
        try w.writeAll("]}");
    }

    if (flags.cfg) {
        if (db.getCachedCfg(proc.entry)) |cfg_result| {
            var cfg_json = std.Io.Writer.Allocating.init(allocator);
            defer cfg_json.deinit();
            // Reserve room for the other requested evidence in a batch. Full
            // graph traversal is available through the paginated get_cfg tool.
            if (cfg_result.basic_blocks.len <= 16 and cfg_result.edges.len <= 32)
                try writeCfgJson(&cfg_json.writer, cfg_result);
            try w.writeAll(",\"cfg\":");
            if (cfg_json.written().len > 0 and cfg_json.written().len <= ir_budget / 3) {
                try w.writeAll(cfg_json.written());
            } else {
                try w.print("{{\"total_blocks\":{d},\"total_edges\":{d},\"partial\":true,\"note\":\"Graph omitted from batch summary; follow get_cfg pages for block and edge evidence\",\"next_call\":{{\"tool\":\"get_cfg\",\"arguments\":{{\"doc_id\":{d},\"function_address\":", .{ cfg_result.basic_blocks.len, cfg_result.edges.len, doc_id });
                try json.writeAddress(w, applyRebaseDelta(proc.entry, delta));
                try w.writeAll(",\"offset\":0,\"max_blocks\":64}}}");
            }
        }
    }

    if (flags.ir) {
        if (db.getCachedIR(proc.entry)) |ir_func| {
            try w.writeAll(",\"ir\":");
            try w.writeAll(try irPageJson(allocator, ir_func, doc_id, applyRebaseDelta(proc.entry, delta), 0, 64, ir_budget));
        }
    }

    if (flags.strings) {
        try w.writeAll(",\"strings_referenced\":[");
        for (proc.strings_referenced, 0..) |str_addr, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeByte('{');
            try w.writeAll("\"address\":");
            try json.writeAddress(w, str_addr);
            if (db.getString(str_addr)) |s| {
                try w.writeAll(",\"value\":");
                try json.writeJsonString(w, s.value);
            }
            try w.writeByte('}');
        }
        try w.writeByte(']');
    }

    if (flags.semantics) {
        try w.writeAll(",\"semantics\":[");
        // Emit function_entry fact
        try w.print("{{\"kind\":\"function_entry\",\"address\":", .{});
        try json.writeAddress(w, proc.entry);
        try w.writeAll(",\"confidence\":90,\"source\":\"prologue_scan\"}");
        // Emit function_range if size > 0
        if (proc.size > 0) {
            try w.print(",{{\"kind\":\"function_range\",\"address\":", .{});
            try json.writeAddress(w, proc.entry);
            try w.print(",\"target\":", .{});
            try json.writeAddress(w, proc.entry + proc.size);
            try w.writeAll(",\"confidence\":90,\"source\":\"prologue_scan\"}");
        }
        // Emit call_edge facts from call index
        const callees: []const u64 = if (call_index) |ci|
            (ci.get(proc.entry) orelse &[_]u64{})
        else
            proc.calls;
        for (callees) |callee_addr| {
            try w.print(",{{\"kind\":\"call_edge\",\"address\":", .{});
            try json.writeAddress(w, proc.entry);
            try w.writeAll(",\"target\":");
            try json.writeAddress(w, callee_addr);
            try w.writeAll(",\"confidence\":100,\"source\":\"xref_scan\"}");
        }
        // Emit string_ref facts from xrefs (not proc.strings_referenced which may be empty)
        {
            var xr_it = db.xrefs.refs_from.iterator();
            while (xr_it.next()) |xr_entry| {
                const from = xr_entry.key_ptr.*;
                if (from >= proc.entry and from < proc.entry + @max(proc.size, 1)) {
                    for (xr_entry.value_ptr.items) |xref| {
                        if (xref.xref_type == .data_read or xref.xref_type == .string_ref) {
                            try w.print(",{{\"kind\":\"string_ref\",\"address\":", .{});
                            try json.writeAddress(w, proc.entry);
                            try w.writeAll(",\"target\":");
                            try json.writeAddress(w, xref.to);
                            try w.writeAll(",\"confidence\":90,\"source\":\"xref_scan\"");
                            if (db.getString(xref.to)) |s| {
                                try w.writeAll(",\"name\":");
                                try json.writeJsonString(w, s.value);
                            }
                            try w.writeByte('}');
                        }
                    }
                }
            }
        }
        try w.writeByte(']');
    }

    try w.writeByte('}');
    return buf.toOwnedSlice();
}

fn xrefTypeStr(t: types.XrefType) []const u8 {
    return switch (t) {
        .call => "call",
        .jump => "jump",
        .data_read => "data_read",
        .data_write => "data_write",
        .string_ref => "string_ref",
    };
}

fn writeCfgJson(w: anytype, cfg_result: types.CfgResult) !void {
    try w.writeAll("{\"basic_blocks\":[");
    for (cfg_result.basic_blocks, 0..) |block, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"start\":");
        try json.writeAddress(w, block.start);
        try w.print(",\"size\":{d},\"instruction_count\":{d}", .{ block.size, block.instruction_count });
        try w.writeAll(",\"terminator\":\"");
        try w.writeAll(block.terminator.toString());
        try w.writeAll("\",\"successors\":[");
        for (block.successors, 0..) |succ, j| {
            if (j > 0) try w.writeByte(',');
            try json.writeAddress(w, succ);
        }
        try w.writeAll("],\"predecessors\":[");
        for (block.predecessors, 0..) |pred, j| {
            if (j > 0) try w.writeByte(',');
            try json.writeAddress(w, pred);
        }
        try w.writeAll("]}");
    }
    try w.writeAll("],\"edges\":[");
    for (cfg_result.edges, 0..) |edge, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"from\":");
        try json.writeAddress(w, edge.from);
        try w.writeAll(",\"to\":");
        try json.writeAddress(w, edge.to);
        try w.writeAll("}");
    }
    try w.writeAll("]}");
}

// Count only fully emitted slots: the caller advances covered_bytes after
// success. A failed warning or newline must not make decoded_bytes underflow.
fn writeArm64PackInstruction(w: anytype, raw: []const u8, addr: u64, display_addr: u64, decode_gaps: *usize, previous_word: ?u32) !void {
    const d = arm64.decode(raw, addr);
    try w.print("  0x{x}: {s}", .{ display_addr, d.mnemonic });
    if (d.decode_status != .decoded)
        try w.print(" ; unsupported decode, raw=0x{x:0>8}, effects/control flow unknown", .{std.mem.readInt(u32, raw[0..4], .little)});
    const ops = d.operands[0..d.operands_len];
    if (ops.len > 0) try w.print(" {s}", .{ops});
    if (previous_word) |previous| try arm64_branch_predicate.writeText(w, previous, std.mem.readInt(u32, raw[0..4], .little));
    try w.writeByte('\n');
    if (d.decode_status != .decoded) decode_gaps.* += 1;
}

// Always read encoding bytes, including for cached mnemonic records.
fn writeArm64AddressingAt(w: anytype, entry: *DocumentEntry, addr: u64, block_start: u64) !void {
    if (entry.doc.arch != .arm64) return;
    const info = resolveRawBytesInfo(entry, addr) orelse return;
    const off = info.file_offset + (addr - info.section_base);
    if (off > entry.doc.data.len or entry.doc.data.len - off < 4) return;
    const raw = entry.doc.data[off..][0..4];
    const decoded = arm64.decode(raw, addr);
    try w.print(",\"decode_status\":\"{s}\"", .{@tagName(decoded.decode_status)});
    if (decoded.decode_status != .decoded)
        try w.writeAll(",\"decode_warning\":\"Opaque ARM64 decoder fallback; control flow and instruction effects are unknown.\"");
    try arm64_addressing.writeJsonMember(w, std.mem.readInt(u32, raw, .little));
    try arm64_arithmetic.writeJsonMember(w, std.mem.readInt(u32, raw, .little));
    try arm64_bitfield.writeJsonMember(w, std.mem.readInt(u32, raw, .little));
    // Do not attribute flags across a recovered basic-block entry.
    if (addr >= block_start +| 4) {
        const previous_raw = instructionBytes(&entry.doc, addr - 4, 4) orelse return;
        if (previous_raw.data.len >= 4)
            try arm64_branch_predicate.writeJsonMember(w, std.mem.readInt(u32, previous_raw.data[0..4], .little), std.mem.readInt(u32, raw, .little), addr - 4);
    }
}

// Shared guidance is bounded and describes a reconstruction process, not an
// inferred recurrence or instruction effect. Legacy get_cfg is unchanged.
const reconstruction_workflow = "First transcribe blocks and edges, retaining every assignment and both destinations of each conditional branch. Preserve every update at its loop nesting level. Trace at least two visits with carried values distinct from initializers; follow each exit and backedge exactly. Check encoded widths and read every RHS from the state before that instruction writes. Only simplify, hoist, or replace gotos with break/continue after checking equivalence to the transcribed control flow and updates.";
const execution_rows_note = "Incoming-state links in execution.text bind each block input to the previous write for each predecessor, including backedges; unresolved alternatives remain explicit. loop_context locates every block in recovered natural loops. Each instruction row includes its address, raw bytes, and assembly. OPAQUE describes an unmodeled effect, not a missing instruction; retain that instruction and follow detailed provenance for its effects.";

fn writeReconstructionGuide(w: anytype, instructions_at: []const u8, execution_view: bool) !void {
    try w.writeAll("\"instructions_at\":");
    try json.writeJsonString(w, instructions_at);
    try w.writeAll(",\"reconstruction_workflow\":");
    try json.writeJsonString(w, reconstruction_workflow);
    if (execution_view) {
        try w.writeAll(",\"instruction_rows_note\":");
        try json.writeJsonString(w, execution_rows_note);
    }
}

/// Compact instruction evidence. Missing or bounded tails always have exact
/// raw-byte continuations; block pagination and instruction omissions differ.
fn writeCfgJsonExecution(w: anytype, cfg_result: types.CfgResult, full_cfg: types.CfgResult, loop_ev: *const loops_mod.Evidence, page_start: usize, entry_addr: u64, entry: *DocumentEntry, doc_id: u64, allocator: Allocator, omit_steps: bool) !void {
    const Words = struct {
        entry: *DocumentEntry,
        pub fn word(self: @This(), addr: u64) ?u32 {
            const raw = instructionBytes(&self.entry.doc, addr, 4) orelse return null;
            if (raw.data.len != 4) return null;
            return std.mem.readInt(u32, raw.data[0..4], .little);
        }
    };
    const incoming = arm64_loop_state.derive(full_cfg.basic_blocks, full_cfg.edges, Words{ .entry = entry });
    var incoming_budget: arm64_loop_state.Budget = .{};
    var omitted_binding_blocks: usize = 0;
    try w.writeByte('{');
    try writeReconstructionGuide(w, "basic_blocks[].execution.text", true);
    try w.writeAll(",\"basic_blocks\":[");
    for (cfg_result.basic_blocks, 0..) |block, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"start\":");
        try json.writeAddress(w, block.start);
        try w.print(",\"size\":{d},\"instruction_count\":{d},\"successors\":[", .{ block.size, block.instruction_count });
        for (block.successors, 0..) |succ, j| {
            if (j > 0) try w.writeByte(',');
            try json.writeAddress(w, succ);
        }
        try w.writeAll("]");
        var emitted_bytes: u64 = 0;
        var status: []const u8 = "unavailable_instruction_bytes";
        if (instructionBytes(&entry.doc, block.start, block.size)) |raw| {
            const aligned_len = raw.data.len - raw.data.len % 4;
            if (block.start % 4 == 0 and aligned_len > 0) {
                var execution_text = std.Io.Writer.Allocating.init(allocator);
                defer execution_text.deinit();
                if (!omit_steps) {
                    var links = std.Io.Writer.Allocating.init(allocator);
                    defer links.deinit();
                    arm64_loop_state.writeBlockText(&links.writer, &incoming, full_cfg.basic_blocks, full_cfg.edges, 0, page_start + i, entry_addr, &incoming_budget) catch |err| switch (err) {
                        error.InvalidBlockIndex => return ToolError.InvalidParams,
                        else => return ToolError.OutOfMemory,
                    };
                    if (links.written().len <= 8192) {
                        try execution_text.writer.writeAll(links.written());
                    } else {
                        omitted_binding_blocks += 1;
                        try execution_text.writer.writeAll("Incoming-state links omitted: block output budget (8192 characters); use detailed_provenance_call.\n");
                    }
                }
                const summary = arm64_steps.writeBlockText(&execution_text.writer, block.start, raw.data[0..aligned_len], block.successors, .{ .max_steps = if (omit_steps) 0 else 256 }) catch return ToolError.OutOfMemory;
                try w.writeAll(",\"execution\":{\"text\":");
                try json.writeJsonString(w, execution_text.written());
                try w.print(",\"total_steps\":{d},\"emitted_steps\":{d},\"opaque_steps\":{d},\"omitted_steps\":{d},\"partial\":{}}}", .{ summary.total_steps, summary.emitted_steps, summary.opaque_steps, summary.total_steps - summary.emitted_steps, summary.partial });
                emitted_bytes = summary.emitted_steps * 4;
                status = if (omit_steps) "omitted_response_budget" else if (emitted_bytes < aligned_len) "omitted_step_budget" else if (raw.data.len < block.size or aligned_len < raw.data.len) "incomplete_instruction_bytes" else "included";
            }
        }
        try w.writeAll(",\"execution_status\":");
        try json.writeJsonString(w, status);
        try w.writeAll(",\"loop_context\":{\"status\":");
        try json.writeJsonString(w, if (loop_ev.omitted) "omitted_graph_budget_or_missing_entry" else "derived_recovered_graph");
        try w.writeAll(",\"containing_headers\":[");
        var containing: usize = 0;
        var returned_headers: usize = 0;
        if (!loop_ev.omitted) for (full_cfg.basic_blocks, 0..) |header, h| {
            if (!loop_ev.members[h][h] or !loop_ev.members[h][page_start + i]) continue;
            containing += 1;
            if (returned_headers == 16) continue;
            if (returned_headers != 0) try w.writeByte(',');
            try json.writeAddress(w, header.start);
            returned_headers += 1;
        };
        try w.print("],\"total_containing_headers\":{d},\"omitted_headers\":{d},\"is_loop_header\":{},\"execution_rule\":\"Every visit starts at this block's first instruction and executes its rows in order; a backedge repeats header rows. Incoming values are predecessor outputs on that visit.\"}}", .{ containing, containing - returned_headers, !loop_ev.omitted and loop_ev.members[page_start + i][page_start + i] });
        if (emitted_bytes < block.size) {
            try w.print(",\"omitted_bytes\":{{\"status\":\"requires_instruction_followup\",\"start\":", .{});
            try json.writeAddress(w, block.start + emitted_bytes);
            try w.print(",\"byte_length\":{d},\"next_call\":{{\"tool\":\"disassemble_range\",\"arguments\":{{\"doc_id\":{d},\"start\":", .{ block.size - emitted_bytes, doc_id });
            try json.writeAddress(w, block.start + emitted_bytes);
            try w.print(",\"byte_length\":{d}}}}},\"raw_bytes_call\":{{\"tool\":\"read_bytes\",\"arguments\":{{\"doc_id\":{d},\"address\":", .{ @min(block.size - emitted_bytes, 4096), doc_id });
            try json.writeAddress(w, block.start + emitted_bytes);
            try w.print(",\"length\":{d},\"encoding\":\"hex_compact\"}}}}}}", .{@min(block.size - emitted_bytes, 65536)});
        }
        try w.writeByte('}');
    }
    try w.print("],\"incoming_state_evidence\":{{\"status\":\"{s}\",\"scope\":\"full_recovered_graph; visible_block_inputs\",\"instructions_scanned\":{d},\"instruction_limit\":4096,\"bindings_processed\":{d},\"binding_limit\":128,\"work_used\":{d},\"work_limit\":262144,\"work_exhausted\":{},\"truncated\":{},\"omitted_block_outputs\":{d},\"block_output_character_limit\":8192}}}}", .{ if (omit_steps) "omitted_response_budget" else @tagName(incoming.status), incoming.instructions, incoming_budget.bindings, arm64_loop_state.max_work - incoming_budget.remaining, incoming_budget.exhausted, incoming_budget.truncated or omitted_binding_blocks != 0, omitted_binding_blocks });
}

/// Write CFG JSON with inline disassembly in each basic block (#8).
fn writeCfgJsonWithDisasm(w: anytype, cfg_result: types.CfgResult, db: *const Database, entry: *DocumentEntry) !void {
    const doc_data = entry.doc.data;
    const doc_arch = entry.doc.arch;
    if (doc_arch == .arm32) {
        try w.writeAll("{\"instruction_context\":\"Raw decoded mnemonics: Thumb IT predication and implicit flag suppression are not rendered inline here. Use disassemble_range from the function entry for execution_condition and effective sets_flags.\",\"basic_blocks\":[");
    } else try w.writeAll("{\"basic_blocks\":[");
    for (cfg_result.basic_blocks, 0..) |block, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"start\":");
        try json.writeAddress(w, block.start);
        try w.print(",\"size\":{d},\"instruction_count\":{d}", .{ block.size, block.instruction_count });
        try w.writeAll(",\"terminator\":\"");
        try w.writeAll(block.terminator.toString());
        try w.writeAll("\",\"successors\":[");
        for (block.successors, 0..) |succ, j| {
            if (j > 0) try w.writeByte(',');
            try json.writeAddress(w, succ);
        }
        try w.writeAll("],\"predecessors\":[");
        for (block.predecessors, 0..) |pred, j| {
            if (j > 0) try w.writeByte(',');
            try json.writeAddress(w, pred);
        }
        // Embed decoded instructions (from cache or on-demand from raw bytes)
        try w.writeAll("],\"instructions\":[");
        var addr = block.start;
        const end_addr = block.start + block.size;
        var inst_idx: usize = 0;
        while (addr < end_addr) {
            if (db.getInstruction(addr)) |inst| {
                if (inst_idx > 0) try w.writeByte(',');
                try w.writeAll("{\"address\":");
                try json.writeAddress(w, inst.address);
                try w.writeAll(",\"mnemonic\":");
                try json.writeJsonString(w, inst.mnemonic);
                const ops = db.getInstructionOperands(addr);
                if (ops.len > 0) {
                    try w.writeAll(",\"operands\":");
                    try json.writeJsonString(w, ops);
                }
                try writeArm64AddressingAt(w, entry, addr, block.start);
                try w.writeByte('}');
                inst_idx += 1;
                addr += inst.size;
            } else {
                // Virtual addresses are not file offsets, including in FAT slices.
                const info = resolveRawBytesInfo(entry, addr) orelse break;
                const byte_off = info.file_offset + (addr - info.section_base);
                if (byte_off >= doc_data.len) break;
                var got_inst = false;
                if (doc_arch == .arm64 and doc_data.len - byte_off >= 4) {
                    const inst = arm64.decode(doc_data[byte_off..], addr);
                    if (inst_idx > 0) try w.writeByte(',');
                    try w.writeAll("{\"address\":");
                    try json.writeAddress(w, addr);
                    try w.writeAll(",\"mnemonic\":");
                    try json.writeJsonString(w, inst.mnemonic);
                    if (inst.operands_len > 0) {
                        try w.writeAll(",\"operands\":");
                        try json.writeJsonString(w, inst.operands[0..inst.operands_len]);
                    }
                    try writeArm64AddressingAt(w, entry, addr, block.start);
                    try w.writeByte('}');
                    inst_idx += 1;
                    addr += 4;
                    got_inst = true;
                } else if (doc_arch == .arm32 and doc_data.len - byte_off >= 2) {
                    const inst = arm32.decode(doc_data[byte_off..], addr);
                    if (inst_idx > 0) try w.writeByte(',');
                    try w.writeAll("{\"address\":");
                    try json.writeAddress(w, addr);
                    try w.writeAll(",\"mnemonic\":");
                    try json.writeJsonString(w, inst.mnemonic);
                    if (inst.operands_len > 0) {
                        try w.writeAll(",\"operands\":");
                        try json.writeJsonString(w, inst.operands[0..inst.operands_len]);
                    }
                    try w.writeByte('}');
                    inst_idx += 1;
                    addr += inst.length;
                    got_inst = true;
                } else if (doc_arch == .mips32 and doc_data.len - byte_off >= 4) {
                    const inst = mips32.decode(doc_data[byte_off..], addr);
                    if (inst_idx > 0) try w.writeByte(',');
                    try w.writeAll("{\"address\":");
                    try json.writeAddress(w, addr);
                    try w.writeAll(",\"mnemonic\":");
                    try json.writeJsonString(w, inst.mnemonic);
                    if (inst.operands_len > 0) {
                        try w.writeAll(",\"operands\":");
                        try json.writeJsonString(w, inst.operands[0..inst.operands_len]);
                    }
                    try w.writeByte('}');
                    inst_idx += 1;
                    addr += 4;
                    got_inst = true;
                } else if (doc_arch == .x86_64 or doc_arch == .x86) {
                    const x86 = @import("arch/x86_64.zig");
                    const inst = if (doc_arch == .x86) x86.decode32(doc_data[byte_off..], addr) else x86.decode(doc_data[byte_off..], addr);
                    if (x86DecodeGap(inst.mnemonic)) break;
                    if (inst_idx > 0) try w.writeByte(',');
                    try w.writeAll("{\"address\":");
                    try json.writeAddress(w, addr);
                    try w.writeAll(",\"mnemonic\":");
                    try json.writeJsonString(w, inst.mnemonic);
                    if (inst.operands_len > 0) {
                        try w.writeAll(",\"operands\":");
                        try json.writeJsonString(w, inst.operands[0..inst.operands_len]);
                    }
                    try w.writeByte('}');
                    inst_idx += 1;
                    addr += inst.length;
                    got_inst = true;
                }
                if (!got_inst) addr += if (doc_arch == .x86_64) @as(usize, 1) else @as(usize, 4);
            }
        }
        try w.writeAll("]}");
    }
    try w.writeAll("],\"edges\":[");
    for (cfg_result.edges, 0..) |edge, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"from\":");
        try json.writeAddress(w, edge.from);
        try w.writeAll(",\"to\":");
        try json.writeAddress(w, edge.to);
        try w.writeAll("}");
    }
    try w.writeAll("]}");
}

fn writeIrJson(w: anytype, ir_func: types.IRFunction) !void {
    try writeIrJsonRecords(w, ir_func, 0, ir_func.statements.len + ir_func.variables.len, true);
}

/// A single stable cursor covers statements followed by variable metadata.
fn writeIrJsonRecords(w: anytype, ir_func: types.IRFunction, start: usize, end: usize, include_note: bool) !void {
    const stmt_start = @min(start, ir_func.statements.len);
    const stmt_end = @min(end, ir_func.statements.len);
    const var_start = @min(start -| ir_func.statements.len, ir_func.variables.len);
    const var_end = @min(end -| ir_func.statements.len, ir_func.variables.len);
    try w.writeAll("{\"analysis_kind\":\"heuristic_ir\",\"verification_required\":true,\"address\":");
    try json.writeAddress(w, ir_func.address);
    if (ir_func.name) |name| {
        try w.writeAll(",\"name\":");
        try json.writeJsonString(w, name);
    }
    // Guidance is repeated on normal single-function pages. Tight batches
    // retain every evidence field and continuation without repeating this prose.
    if (include_note) try w.writeAll(",\"interpretation_note\":\"Register views are not stable source variables or parameter types. On ARM64 Wn and Xn alias: a Wn write replaces Xn with a zero-extended 32-bit result. On x86-64 EAX-like writes likewise clear the high half of RAX-like storage. Return sources are architectural candidates, not recovered prototypes.\"");
    try w.writeAll(",\"statements\":[");
    for (ir_func.statements[stmt_start..stmt_end], 0..) |stmt, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"type\":\"");
        try w.writeAll(stmt.type.toString());
        try w.writeAll("\",\"address\":");
        try json.writeAddress(w, stmt.address);
        if (stmt.block_start) try w.writeAll(",\"block_start\":true");
        if (stmt.memory_width) |width| try w.print(",\"memory_width_bytes\":{d}", .{width});
        if (stmt.memory_signedness != .unknown) {
            try w.writeAll(",\"load_extension\":");
            try json.writeJsonString(w, @tagName(stmt.memory_signedness));
        }
        if (stmt.dest) |dest| {
            try w.writeAll(",\"dest\":");
            try json.writeJsonString(w, dest);
        }
        if (stmt.src) |src| {
            try w.writeAll(",\"src\":");
            try json.writeJsonString(w, src);
        }
        if (stmt.target) |target| {
            try w.writeAll(",\"target\":");
            try json.writeJsonString(w, target);
        }
        if (stmt.op) |op| {
            try w.writeAll(",\"op\":");
            try json.writeJsonString(w, op);
        }
        if (stmt.condition) |cond| {
            try w.writeAll(",\"condition\":");
            try json.writeJsonString(w, cond);
        }
        if (stmt.type == .call and stmt.args == null)
            try w.writeAll(",\"arguments_status\":\"unknown\"");
        if (stmt.args) |args| {
            try w.writeAll(",\"args\":[");
            for (args, 0..) |arg, j| {
                if (j > 0) try w.writeByte(',');
                try json.writeJsonString(w, arg);
            }
            try w.writeByte(']');
        }
        if (stmt.true_block) |tb| try w.print(",\"true_block\":{d}", .{tb});
        if (stmt.false_block) |fb| try w.print(",\"false_block\":{d}", .{fb});
        try w.writeByte('}');
    }
    try w.writeAll("],\"variables\":[");
    for (ir_func.variables[var_start..var_end], 0..) |v, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":");
        try json.writeJsonString(w, v.name);
        if (v.register) |reg| {
            try w.writeAll(",\"register\":");
            try json.writeJsonString(w, reg);
        }
        if (v.type_name) |tn| {
            try w.writeAll(",\"type\":");
            try json.writeJsonString(w, tn);
        }
        try w.writeByte('}');
    }
    try w.writeAll("]}");
}

/// Serialize bounded IR without dropping records or returning a JSON preview.
/// A large batch receives smaller per-function pages; its continuations use
/// one function each and can therefore recover the usual page budget.
fn irPageJson(allocator: Allocator, ir_func: types.IRFunction, doc_id: u64, address: u64, offset: usize, max_results: usize, budget: usize) ![]const u8 {
    const total = ir_func.statements.len + ir_func.variables.len;
    const start = @min(offset, total);
    var count = @min(max_results, total - start);
    while (true) {
        var buf = std.Io.Writer.Allocating.init(allocator);
        defer buf.deinit();
        const end = start + count;
        try writeIrJsonRecords(&buf.writer, ir_func, start, end, budget >= 2048);
        // Reopen the root object to attach lossless continuation metadata.
        buf.writer.end -= 1;
        const w = &buf.writer;
        try w.print(",\"pagination_order\":\"statements_then_variables\",\"total_statements\":{d},\"total_variables\":{d},\"total_results\":{d},\"offset\":{d},\"returned_results\":{d},\"partial\":{s}", .{ ir_func.statements.len, ir_func.variables.len, total, start, count, if (end < total) "true" else "false" });
        if (end < total) {
            try w.print(",\"next_offset\":{d},\"next_call\":{{\"tool\":\"lift\",\"arguments\":{{\"doc_id\":{d},\"addresses\":", .{ end, doc_id });
            try json.writeAddress(w, address);
            try w.print(",\"offset\":{d},\"max_results\":{d}}}}}", .{ end, max_results });
        }
        try w.writeByte('}');
        if (buf.written().len <= budget) return try buf.toOwnedSlice();
        if (count <= 1) return error.RecordTooLarge;
        count = @max(count / 2, 1);
    }
}

// ============================================================================
// Tool Handlers
// ============================================================================

/// v7.4.3 F3 — load budget enforcement. Caller-supplied deadline (absolute
/// monotonic awake clock value). finalizeLoad checks this at each phase
/// boundary and returns `error.BudgetExceeded` if the deadline has passed.
/// `last_phase` records the last completed phase so the caller can build a
/// useful error message ("exceeded budget after phase=demangle_done").
pub const LoadBudget = struct {
    io: std.Io,
    deadline_ms: i64,
    last_phase: []const u8 = "init",

    fn check(self: *LoadBudget, phase: []const u8) !void {
        self.last_phase = phase;
        if (runtime.awakeMillis(self.io) > self.deadline_ms) return error.BudgetExceeded;
    }
};

/// Common post-load logic shared by all load paths (handleLoadBinary inline,
/// loadSingleBinary, loadSingleBinaryFromData). entry.doc and entry.db must
/// be fully initialized before calling this.
///
/// `budget` (optional) enforces a deadline. On exceed, returns
/// `error.BudgetExceeded`. Every error discards the unpublished `entry` and
/// its resources; callers must not access or free it after failure.
fn finalizeLoad(ctx: ToolContext, entry: *DocumentEntry, data: []const u8, budget: ?*LoadBudget) !void {
    // Publication is the final fallible step. Any failure before it must
    // release the unpublished document for single, batch and borrowed-data loads.
    errdefer {
        // Container loaders may replace doc.data with a view into this buffer.
        // Free the owned allocation, rather than its embedded ELF sub-slice.
        if (entry.owns_data) entry.doc.data = data;
        teardownDocumentEntry(ctx.store.allocator, entry);
    }
    // v7.4.2 F4: progress logging for slow loads. Per feedback_load_timeout
    // ("Slow loads are OK; empty/timeout responses are not"), the user just
    // needs to see that work is happening — silence is the bug, not slowness.
    const finalize_start = runtime.awakeMillis(ctx.io);
    finalizePhaseLog(ctx.io, "finalize_start", finalize_start);
    // v7.11 W5: emit progress events at each phase boundary. No-op when the
    // tools/call request didn't include _meta.progressToken.
    ctx.emitProgress(1, 6, "parse done; running disassemble");

    // 1. Copy imports with address fixup (address=0 → synthetic unique address)
    for (entry.doc.imports.items, 0..) |imp, idx| {
        var fixed_imp = imp;
        if (fixed_imp.address == 0) {
            fixed_imp.address = 0xFFFF000000000000 + idx;
        }
        entry.db.addImport(fixed_imp) catch {};
    }

    // 2. Register Mach-O stub symbols (self-guards for non-macho formats).
    // v7.15.0 B1: use the store-backed db allocator so any allocations land in
    // the persistent allocator, not the per-request arena.
    const store_alloc_inner = entry.db.allocator;
    registerStubSymbols(store_alloc_inner, data, &entry.doc, &entry.db);
    finalizePhaseLog(ctx.io, "stubs_done", finalize_start);
    if (budget) |b| try b.check("stubs_done");
    ctx.emitProgress(2, 6, "disassemble done; detecting strings");

    // 3. Initial xref finalize — build sorted array for O(log N) range queries
    entry.db.xrefs.finalize();

    // 4. Run pipeline.analyzeLean() and merge results (strings, xrefs, procedures).
    // v7.15.0 B1: pipeline runs against store_alloc_inner so the strings/xrefs
    // it returns (and that get merged into entry.doc/entry.db) survive the
    // per-request arena.
    var analyze_result = pipeline.analyzeLean(store_alloc_inner, ctx.io, &entry.doc, data);
    if (analyze_result) |*result| {
        errdefer result.deinit(store_alloc_inner);
        // Merge strings
        for (result.strings.items) |s| {
            entry.doc.strings.append(s) catch {};
            entry.db.addString(s) catch {};
        }
        // Reserve before replaying hash-bucket order, avoiding probe clusters.
        try entry.db.xrefs.mergeFrom(&result.xrefs);
        // Seed the index before merging to avoid duplicating every loader entry.
        for (entry.doc.procedures.items) |proc| {
            entry.db.addProcedure(proc) catch {};
        }
        // Add detected procedures to database and document
        for (result.procedures) |dp| {
            if (entry.db.getProcedure(dp.entry) == null) {
                const proc = types.Procedure{ .entry = dp.entry, .size = 0, .name = null };
                entry.db.addProcedure(proc) catch {};
                entry.doc.procedures.append(proc) catch {};
            }
        }
        // Copy loader procedures into database too
        for (entry.doc.procedures.items) |proc| {
            if (entry.db.getProcedure(proc.entry) == null) {
                entry.db.addProcedure(proc) catch {};
            }
        }
        // v7.15.0 B1 pass 2: free the AnalysisResult's intermediate buffers
        // (strings/xrefs/procedures arrays). The string/xref values were
        // copied by-reference into entry.doc/entry.db, so it's safe to drop
        // the wrapper structures now. Pre-fix this leaked per load.
        result.deinit(store_alloc_inner);
    } else |_| {
        // Pipeline failed — non-fatal, continue with loader-only data
        for (entry.doc.procedures.items) |proc| {
            entry.db.addProcedure(proc) catch {};
        }
    }
    ctx.emitProgress(3, 6, "strings + procedures done; computing sizes + xrefs");

    // 5. Compute procedure sizes (sort by entry, set size = next - this)
    {
        const procs = entry.doc.procedures.items;
        if (procs.len > 1) {
            std.mem.sort(types.Procedure, procs, {}, struct {
                fn lessThan(_: void, a: types.Procedure, b: types.Procedure) bool {
                    return a.entry < b.entry;
                }
            }.lessThan);
        }
        for (procs, 0..) |*p, idx| {
            var end = entry.doc.codeRangeEnd(p.entry) orelse (p.entry +| 64);
            if (idx + 1 < procs.len) end = @min(end, procs[idx + 1].entry);
            if (p.size == 0 or p.size > end - p.entry) p.size = end - p.entry;
        }
        // Update database with computed sizes
        for (procs) |p| {
            entry.db.addProcedure(p) catch {};
        }
    }

    // 6. Register named procedures as symbols (enables dependency graph + name search).
    // Stubs from registerStubSymbols are already in db.symbols; this adds genuine code symbols.
    for (entry.doc.procedures.items) |proc| {
        if (proc.name) |name| {
            if (name.len > 0) {
                entry.db.addSymbol(proc.entry, name) catch {};
            }
        }
    }

    // 7. Call index built lazily on first call_graph/callees_of request.
    entry.call_index = null;

    finalizePhaseLog(ctx.io, "merge_done", finalize_start);
    if (budget) |b| try b.check("merge_done");
    ctx.emitProgress(4, 6, "xrefs merged; demangling symbols");

    // 8. Demangling: use db.allocator (persists), NOT ctx.allocator (per-request arena)
    // v7.8.2: Swift demangle is always safe (pure parser, no recursion).
    // Native (C++ Itanium / Rust) demangler triggers SIGSEGV/SIGBUS on certain
    // dyld-style symbols (specific content patterns, not length). Skip native
    // demangling on large symbol tables (>2500) where the risk outweighs the
    // benefit — dyld and similar shared-cache fragments are the main victims;
    // normal user binaries have <2500 symbols. Names still resolve raw via
    // db.symbols / db.procedures / db.imports.
    _ = swift_mod.demangleAllSymbols(entry.db.allocator, &entry.db) catch {};
    const symbol_count = entry.db.symbols.count();
    if (symbol_count <= 2500) {
        demangleAllNativeSymbols(entry.db.allocator, &entry.db);
    } else {
        if (!builtin.is_test) std.debug.print("[phora load] phase=native_demangle_skipped count={d}\n", .{symbol_count});
        // v7.11 W6: surface as a notification/message warning so users see why
        // some C++/Rust mangled names didn't resolve.
        var ctx_buf: [128]u8 = undefined;
        const ctx_str = std.fmt.bufPrint(&ctx_buf, "{{\"symbol_count\":{d}}}", .{symbol_count}) catch "";
        ctx.emitLog("warning", "phora.loader", "native demangler skipped (large symbol table) — names still resolve raw", ctx_str);
    }
    finalizePhaseLog(ctx.io, "demangle_done", finalize_start);
    if (budget) |b| try b.check("demangle_done");
    ctx.emitProgress(5, 6, "demangle done; finalizing maturity passes");

    // 9. Final xref finalize (sorted array needs rebuilding after pipeline merge)
    entry.db.xrefs.sorted_finalized = false;
    entry.db.xrefs.finalize();

    // v7.9.1 Q1.c: generic zero-procs warning. If we ended up with no
    // procedures, no other note, and the format isn't a known container
    // (zip/pbp) or a known-malformed-tolerant format (psx_exe), surface a
    // hint that the arch is probably wrong.
    if (entry.doc.procedures.items.len == 0 and entry.doc.note == null and
        entry.doc.format != .zip and entry.doc.format != .pbp and entry.doc.format != .psx_exe)
    {
        // v7.15.0 B1: doc-owned note allocates from the persistent allocator.
        entry.doc.note = std.fmt.allocPrint(
            store_alloc_inner,
            "Loaded with arch={s} but found zero procedures. Likely arch mismatch — try options.arch=… (e.g. mips32, x86_64, arm64) or check file format.",
            .{entry.doc.arch.toString()},
        ) catch null;
        // v7.11 W6: also emit as a warning notification so the user sees it
        // streamed live, not just in the response body.
        var arch_ctx_buf: [64]u8 = undefined;
        const arch_ctx = std.fmt.bufPrint(&arch_ctx_buf, "{{\"arch\":\"{s}\"}}", .{entry.doc.arch.toString()}) catch "";
        ctx.emitLog("warning", "phora.loader", "zero procedures detected after analysis — likely arch mismatch", arch_ctx);
    }

    // v7.11 W6: surface PBP encrypted-module hint as a warning notification.
    // (entry.doc.note is set during PBP detection if DATA.PSP isn't a plain ELF.)
    if (entry.doc.format == .pbp and entry.doc.note != null) {
        ctx.emitLog("warning", "phora.loader", "PBP module is encrypted — disassembly skipped", "");
    }

    // 10. Store entry and queue notification
    ctx.store.put(entry) catch return error.OutOfMemory;
    ctx.queueNotification("notifications/tools/list_changed");
    // v7.16 W5: loaded docs are exposed as `phora://doc/{id}` resources, so the
    // resource list changed too — tell clients or their view goes stale.
    ctx.queueNotification("notifications/resources/list_changed");
    finalizePhaseLog(ctx.io, "finalize_done", finalize_start);
    ctx.emitProgress(6, 6, "load complete");
}

/// v7.4.2 F4 — phase logger used by finalizeLoad. Same format as the
/// pipeline.zig version: "[phora load] phase=X elapsed=Yms".
inline fn finalizePhaseLog(io: std.Io, name: []const u8, start_ms: i64) void {
    if (builtin.is_test) return;
    const elapsed = runtime.awakeMillis(io) - start_ms;
    std.debug.print("[phora load] phase={s} elapsed={d}ms\n", .{ name, elapsed });
}

fn invalidLoadOptions(params: std.json.Value) ?[]const u8 {
    if (params != .object) return "load_binary arguments must be an object";
    for ([_][]const u8{ "arch", "base", "entry", "fat_arch", "analysis", "budget_ms" }) |key| {
        if (params.object.contains(key)) return "load_binary option is misplaced at top level; move arch/base/entry/fat_arch/analysis/budget_ms under options, for example {path:...,options:{arch:arm64,base:4096,entry:4096}}";
    }
    if (params.object.get("options")) |opts| {
        if (opts != .object) return "load_binary options must be an object";
        for ([_][]const u8{ "arch", "fat_arch" }) |key| if (opts.object.get(key)) |value| {
            if (value != .string or parseArchString(value.string) == null) return "unsupported options.arch or options.fat_arch; use arm64, arm32, x86_64, x86, or mips32";
        };
        for ([_][]const u8{ "base", "entry", "budget_ms" }) |key| if (opts.object.get(key)) |value| {
            if (value != .integer or value.integer < 0) return "options.base, options.entry, and options.budget_ms must be nonnegative integers";
        };
    }
    return null;
}

fn handleLoadBinary(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    if (invalidLoadOptions(params)) |message| {
        const resp = json.errorResponse(ctx.allocator, "load_binary", message, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    // v7.11 W5: announce phase 0/6 immediately so the client sees activity even
    // before the file open. Subsequent phases fire from inside finalizeLoad.
    ctx.emitProgress(0, 6, "load_binary started — opening file");

    // Support batch loading: path can be a string or array of strings
    if (getArray(params, "path")) |path_arr| {
        var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
        for (path_arr.array.items) |pv| {
            if (pv == .string) {
                const item_start = timestampMs(ctx.io);
                const single_result = loadSingleBinary(ctx, pv.string, params);
                const item_elapsed = timestampMs(ctx.io) - item_start;
                if (single_result) |result_json| {
                    items.append(.{ .input = pv.string, .success = true, .result = result_json, .time_ms = item_elapsed }) catch {};
                } else |_| {
                    items.append(.{ .input = pv.string, .success = false, .err = "load failed", .time_ms = item_elapsed }) catch {};
                }
            }
        }
        const resp = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp };
    }

    const path = getString(params, "path") orelse {
        const resp = json.errorResponse(ctx.allocator, "load_binary", "missing required parameter: path", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    // v7.13.0 B8 — `dyld_shared_cache:<image>` URI form. Extracts the named
    // image from the system shared cache and loads
    // it as a normal Mach-O document.
    if (std.mem.startsWith(u8, path, "dyld_shared_cache:")) {
        const image_name = path["dyld_shared_cache:".len..];
        if (image_name.len == 0) {
            const resp = json.errorResponse(ctx.allocator, path, "dyld_shared_cache: requires an image name (e.g. 'Foundation')", 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        }
        // v7.15.0 B1: extract the image with store_alloc so its path/data
        // buffers outlive the per-request arena and become owned by the doc.
        const store_alloc = ctx.store.allocator;
        const extracted = dyld_cache.loadImage(store_alloc, ctx.io, image_name) catch |err| {
            const reason: []const u8 = switch (err) {
                error.UnknownCachePath => "dyld shared cache file not found at /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e (or legacy path) — only arm64e system caches are supported",
                error.UnsupportedMagic => "cache header magic not recognized (only `dyld_v1` is supported; macOS 14+)",
                error.TruncatedHeader => "dyld cache header is truncated or unreadable",
                error.ImagesTableNotFound => "dyld cache header has no images table at the expected offset (format drift?)",
                error.ImageNotFound => "image not found in cache — pass either a basename like 'Foundation' or full install path",
                error.ImageSpansSubcaches => "image spans into a subcache file (.01 / .02) — not supported in this release; ship in v7.14",
                error.Truncated => "extracted image is empty or exceeds 200 MiB after packing — try a smaller framework, or use `nm -gU` and `otool -L` directly on the cache file for libSystem-class megaliths",
                error.OutOfMemory => "out of memory while extracting image",
                error.OpenFailed => "failed to open the dyld shared cache file (permission denied?)",
                error.ReadFailed => "I/O error reading the dyld shared cache",
            };
            const resp = json.errorResponse(ctx.allocator, path, reason, 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        };

        // (store_alloc declared above)
        const doc_id = ctx.store.nextId();
        const entry = store_alloc.create(DocumentEntry) catch return ToolError.OutOfMemory;
        entry.* = .{
            .doc = types.Document.init(store_alloc, doc_id, extracted.path, extracted.data),
            .db = Database.init(store_alloc, ctx.io),
        };

        var dc_load_opts = types.LoadOptions{};
        parseLoadOptions(params, &entry.doc, &dc_load_opts);

        // Parse via the macho loader directly. The extracted slice is a
        // standard Mach-O image. Loader uses store_alloc so its outputs
        // (segments, etc.) outlive the request arena.
        entry.doc = macho.parse(store_alloc, doc_id, extracted.path, extracted.data, dc_load_opts) catch {
            const resp = json.errorResponse(ctx.allocator, path, "extracted image failed Mach-O parse — possible cache format drift", 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        };

        var dc_budget = LoadBudget{ .io = ctx.io, .deadline_ms = start + 600_000 };
        finalizeLoad(ctx, entry, extracted.data, &dc_budget) catch {
            const resp = json.errorResponse(ctx.allocator, path, "extracted image loaded but analysis pipeline failed", 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        };

        ctx.store.put(entry) catch return ToolError.OutOfMemory;
        const result_json = json.serializeDocumentInfo(ctx.allocator, entry.doc) catch return ToolError.OutOfMemory;
        const elapsed = timestampMs(ctx.io) - start;
        const resp = json.successResponse(ctx.allocator, path, result_json, elapsed) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp };
    }

    // Dedup: if a document with this path is already loaded, return its existing doc_id.
    {
        ctx.store.mutex.lockUncancelable(ctx.io);
        defer ctx.store.mutex.unlock(ctx.io);
        var dedup_it = ctx.store.documents.valueIterator();
        while (dedup_it.next()) |entry_ptr| {
            if (std.mem.eql(u8, entry_ptr.*.doc.path, path)) {
                const existing = entry_ptr.*;
                const result_json = json.serializeDocumentInfo(ctx.allocator, existing.doc) catch return ToolError.OutOfMemory;
                const elapsed = timestampMs(ctx.io) - start;
                const resp = json.successResponse(ctx.allocator, path, result_json, elapsed) catch return ToolError.OutOfMemory;
                // v7.11 W6: surface dedup as an info-level notification.
                ctx.emitLog("info", "phora.loader", "load_binary: path already loaded — returning existing doc_id", "");
                return .{ .json_response = resp };
            }
        }
    }

    // Read the binary file.
    const file = std.Io.Dir.cwd().openFile(ctx.io, path, .{}) catch {
        const err_msg = std.fmt.allocPrint(ctx.allocator, "cannot open '{s}': file not found or permission denied", .{path}) catch "cannot open file";
        const resp = json.errorResponse(ctx.allocator, path, err_msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    defer file.close(ctx.io);

    // Check file size — cap at MAX_BINARY_SIZE
    const single_stat = file.stat(ctx.io) catch null;
    const single_file_size: u64 = if (single_stat) |s| s.size else 0;
    if (single_file_size > MAX_BINARY_SIZE) {
        const err_msg = std.fmt.allocPrint(ctx.allocator, "binary too large ({d}MB, max {d}MB). For FAT/universal binaries, use options.fat_arch to select one architecture slice.", .{ single_file_size / (1024 * 1024), MAX_BINARY_SIZE / (1024 * 1024) }) catch "binary too large";
        const resp = json.errorResponse(ctx.allocator, path, err_msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    // v7.15.0 B1: data buffer + path string + doc/db go on the long-lived
    // store allocator so they outlive the per-request arena. This is what
    // lets close_document actually free a doc later (pass 2).
    const store_alloc = ctx.store.allocator;
    const data = readNativeFileToEndAlloc(file, ctx.io, store_alloc, MAX_BINARY_SIZE) catch |err| {
        const err_msg = std.fmt.allocPrint(ctx.allocator, "cannot read '{s}': {s}", .{ path, @errorName(err) }) catch "file too large or read error";
        const resp = json.errorResponse(ctx.allocator, path, err_msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    const stored_path = store_alloc.dupe(u8, path) catch return ToolError.OutOfMemory;

    // Create document and database (store_alloc).
    const doc_id = ctx.store.nextId();
    const entry = store_alloc.create(DocumentEntry) catch return ToolError.OutOfMemory;
    entry.* = .{
        .doc = types.Document.init(store_alloc, doc_id, stored_path, data),
        .db = Database.init(store_alloc, ctx.io),
    };

    // Parse options. v7.9.0 K.4/K.5: shared parser handles arch + aliases,
    // fat_arch, and the new `entry` / `base` raw-binary overrides.
    var load_opts = types.LoadOptions{};
    parseLoadOptions(params, &entry.doc, &load_opts);
    if (getObject(params, "options")) |param_opts| {
        if (getObject(param_opts, "analysis")) |_| {} else if (getString(param_opts, "analysis")) |_| {} else {
            // analysis defaults to true already
        }
    }

    // v7.4.3 F3: parse options.budget_ms (ms wall-clock cap on the analysis pipeline).
    // Default 600_000 = 10 min for large binaries. Set to 0 or omit to disable.
    var budget_ms_value: i64 = 600_000;
    if (getObject(params, "options")) |param_opts| {
        if (getInt(param_opts, "budget_ms")) |bm| {
            if (bm > 0) budget_ms_value = bm;
        }
    }
    var load_budget = LoadBudget{ .io = ctx.io, .deadline_ms = start + budget_ms_value };

    // Detect format and parse with appropriate loader
    const format = detectFormat(data);
    const opts = load_opts;

    switch (format) {
        .macho => {
            entry.doc = macho.parse(store_alloc, doc_id, stored_path, data, opts) catch {
                const resp = json.errorResponse(ctx.allocator, path, "failed to parse Mach-O", 0) catch return ToolError.OutOfMemory;
                return .{ .json_response = resp, .is_error = true };
            };
        },
        .elf => {
            entry.doc = elf_loader.parse(store_alloc, doc_id, stored_path, data, opts) catch {
                const resp = json.errorResponse(ctx.allocator, path, "failed to parse ELF", 0) catch return ToolError.OutOfMemory;
                return .{ .json_response = resp, .is_error = true };
            };
        },
        .pe => {
            entry.doc = pe_loader.parse(store_alloc, doc_id, stored_path, data, opts) catch {
                const resp = json.errorResponse(ctx.allocator, path, "failed to parse PE", 0) catch return ToolError.OutOfMemory;
                return .{ .json_response = resp, .is_error = true };
            };
        },
        .zip => {
            // APK/ZIP: find .so/.dylib/.dll inside, load each as separate document
            if (extractBinariesFromZip(ctx, path, data, params, start)) |resp| {
                return .{ .json_response = resp };
            }
            // No binaries found — load as raw
            entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
            entry.doc.format = .zip;
        },
        .pbp => {
            // PBP container: extract ELF from section 6 (DATA.PSP)
            // Header: magic(4) + version(4) + 8 section offsets (8 * u32)
            // [0]=PARAM.SFO [1]=ICON0 [2]=ICON1 [3]=PIC0 [4]=PIC1
            // [5]=SND0 [6]=DATA.PSP [7]=DATA.PSAR
            if (data.len >= 40) {
                const elf_offset = std.mem.readInt(u32, data[32..36], .little); // offset[6]
                const raw_end = std.mem.readInt(u32, data[36..40], .little); // offset[7]
                const elf_end = if (raw_end > elf_offset) raw_end else @as(u32, @intCast(@min(data.len, std.math.maxInt(u32))));
                if (elf_offset < elf_end and elf_end <= data.len) {
                    const elf_data = data[elf_offset..elf_end];
                    if (elf_loader.isElf(elf_data)) {
                        entry.doc = elf_loader.parse(store_alloc, doc_id, stored_path, elf_data, opts) catch {
                            const resp = json.errorResponse(ctx.allocator, path, "failed to parse ELF from PBP", 0) catch return ToolError.OutOfMemory;
                            return .{ .json_response = resp, .is_error = true };
                        };
                    } else {
                        entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
                        entry.doc.format = .pbp;
                        entry.doc.note = pbpEncryptedHint(elf_data);
                    }
                } else {
                    entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
                    entry.doc.format = .pbp;
                }
            } else {
                entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
                entry.doc.format = .pbp;
            }
        },
        .psx_exe => {
            entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
            entry.doc.format = .psx_exe;
            synthesizePsxExeSegments(store_alloc, &entry.doc, data) catch {};
            // Honor explicit overrides if the user passed them.
            if (load_opts.entry) |e| entry.doc.entry_point = e;
        },
        .raw => {
            // v7.9.0 K.2: route through finalizeRawDocument so the arch set
            // from options (above) is preserved instead of clobbered by
            // Document.init()'s arm64 default.
            finalizeRawDocument(store_alloc, &entry.doc, data, entry.doc.arch, load_opts.entry, load_opts.base);
        },
    }

    finalizeLoad(ctx, entry, data, &load_budget) catch |err| {
        if (err == error.BudgetExceeded) {
            // finalizeLoad already discarded the unpublished entry.
            const elapsed_ms = timestampMs(ctx.io) - start;
            const err_msg = std.fmt.allocPrint(
                ctx.allocator,
                "load_binary exceeded budget {d}ms after phase={s} (elapsed {d}ms); partial state discarded. Increase options.budget_ms.",
                .{ budget_ms_value, load_budget.last_phase, elapsed_ms },
            ) catch "load_binary exceeded budget";
            const resp = json.errorResponse(ctx.allocator, path, err_msg, 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        }
        return ToolError.OutOfMemory;
    };

    // Build result JSON — use database stats which now have real data
    const base_result = json.serializeDocumentInfo(ctx.allocator, entry.doc) catch return ToolError.OutOfMemory;
    const single_is_large = single_file_size > 50 * 1024 * 1024;
    const result_json = if (single_is_large)
        std.fmt.allocPrint(ctx.allocator, "{s},\"large_binary\":true,\"file_size_mb\":{d}{s}", .{ base_result[0 .. base_result.len - 1], single_file_size / (1024 * 1024), "}" }) catch return ToolError.OutOfMemory
    else
        base_result;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, path, result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

/// Load a single binary with fast analysis and return the result JSON string.
/// This runs the same pipeline as the single-path handler: parse → streaming decode →
/// detect procedures → compute sizes → build call index → detect strings.
fn loadSingleBinary(ctx: ToolContext, path: []const u8, params: std.json.Value) ![]const u8 {
    const start_b = timestampMs(ctx.io);
    // v7.14.1 A4: handle the `dyld_shared_cache:` URI prefix BEFORE falling
    // through to the file-open path. The single-path handleLoadBinary already
    // had this check; the batched array dispatcher (which calls
    // loadSingleBinary per entry) skipped it, so URI entries returned
    // "load failed" while raw paths in the same batch loaded fine.
    if (std.mem.startsWith(u8, path, "dyld_shared_cache:")) {
        const image_name = path["dyld_shared_cache:".len..];
        if (image_name.len == 0) return error.OutOfMemory;
        // v7.15.0 B1: doc/db/loaders allocate from store_alloc (long-lived).
        const store_alloc = ctx.store.allocator;
        const extracted = dyld_cache.loadImage(store_alloc, ctx.io, image_name) catch return error.OutOfMemory;

        const dc_doc_id = ctx.store.nextId();
        const dc_entry = store_alloc.create(DocumentEntry) catch return error.OutOfMemory;
        dc_entry.* = .{
            .doc = types.Document.init(store_alloc, dc_doc_id, extracted.path, extracted.data),
            .db = Database.init(store_alloc, ctx.io),
            .call_index = null,
        };

        var dc_load_opts = types.LoadOptions{};
        parseLoadOptions(params, &dc_entry.doc, &dc_load_opts);

        dc_entry.doc = macho.parse(store_alloc, dc_doc_id, extracted.path, extracted.data, dc_load_opts) catch {
            store_alloc.destroy(dc_entry);
            return error.OutOfMemory;
        };

        var dc_budget = LoadBudget{ .io = ctx.io, .deadline_ms = start_b + 600_000 };
        finalizeLoad(ctx, dc_entry, extracted.data, &dc_budget) catch return error.OutOfMemory;

        ctx.store.put(dc_entry) catch return error.OutOfMemory;
        return json.serializeDocumentInfo(ctx.allocator, dc_entry.doc) catch return error.OutOfMemory;
    }

    // Dedup: if a document with this path is already loaded, return its existing doc_id.
    {
        ctx.store.mutex.lockUncancelable(ctx.io);
        defer ctx.store.mutex.unlock(ctx.io);
        var it = ctx.store.documents.valueIterator();
        while (it.next()) |entry_ptr| {
            if (std.mem.eql(u8, entry_ptr.*.doc.path, path)) {
                const existing = entry_ptr.*;
                // v7.9.1 Q1.d: detect arch mismatch — if caller passed a
                // different arch in options, warn that re-load is needed.
                var requested_arch: ?types.Arch = null;
                if (getObject(params, "options")) |po| {
                    if (getString(po, "arch")) |arch_str| {
                        requested_arch = parseArchString(arch_str);
                    }
                }
                const arch_mismatch = requested_arch != null and requested_arch.? != existing.doc.arch;
                if (arch_mismatch) {
                    return try std.fmt.allocPrint(ctx.allocator,
                        \\{{"doc_id":{d},"path":"{s}","format":"{s}","arch":"{s}","already_loaded":true,"note":"Path already loaded (doc_id={d}) with arch={s}. New options ignored. Call close_document first to reload fresh.","stats":{{"procedure_count":{d},"string_count":{d},"import_count":{d},"segment_count":{d}}}}}
                    , .{
                        existing.doc.id,
                        existing.doc.path,
                        existing.doc.format.toString(),
                        existing.doc.arch.toString(),
                        existing.doc.id,
                        existing.doc.arch.toString(),
                        @as(u32, @intCast(existing.doc.procedures.items.len)),
                        @as(u32, @intCast(existing.doc.strings.items.len)),
                        @as(u32, @intCast(existing.doc.imports.items.len)),
                        @as(u32, @intCast(existing.doc.segments.len)),
                    });
                }
                return try std.fmt.allocPrint(ctx.allocator,
                    \\{{"doc_id":{d},"path":"{s}","format":"{s}","arch":"{s}","already_loaded":true,"stats":{{"procedure_count":{d},"string_count":{d},"import_count":{d},"segment_count":{d}}}}}
                , .{
                    existing.doc.id,
                    existing.doc.path,
                    existing.doc.format.toString(),
                    existing.doc.arch.toString(),
                    @as(u32, @intCast(existing.doc.procedures.items.len)),
                    @as(u32, @intCast(existing.doc.strings.items.len)),
                    @as(u32, @intCast(existing.doc.imports.items.len)),
                    @as(u32, @intCast(existing.doc.segments.len)),
                });
            }
        }
    }

    const file = std.Io.Dir.cwd().openFile(ctx.io, path, .{}) catch |err| {
        _ = std.fmt.allocPrint(ctx.allocator, "cannot open '{s}': {s}", .{ path, @errorName(err) }) catch {};
        return error.OutOfMemory;
    };
    defer file.close(ctx.io);

    // Check file size before reading — cap at MAX_BINARY_SIZE
    const file_stat = file.stat(ctx.io) catch null;
    const file_size: u64 = if (file_stat) |s| s.size else 0;
    const is_large = file_size > 50 * 1024 * 1024;

    // Reject before reading if file is too large
    if (file_size > MAX_BINARY_SIZE) {
        _ = std.fmt.allocPrint(ctx.allocator, "binary too large ({d}MB, max {d}MB). For FAT/universal binaries, use options.fat_arch to select one architecture slice.", .{ file_size / (1024 * 1024), MAX_BINARY_SIZE / (1024 * 1024) }) catch {};
        return error.OutOfMemory;
    }

    // v7.15.0 B1: data, path, doc, db all live on store_alloc — outlive the
    // request arena so docs survive arena death.
    const store_alloc = ctx.store.allocator;
    const data = readNativeFileToEndAlloc(file, ctx.io, store_alloc, MAX_BINARY_SIZE) catch |err| {
        _ = std.fmt.allocPrint(ctx.allocator, "cannot read '{s}': {s}", .{ path, @errorName(err) }) catch {};
        return error.OutOfMemory;
    };
    const stored_path = store_alloc.dupe(u8, path) catch return error.OutOfMemory;

    const doc_id = ctx.store.nextId();
    const entry = store_alloc.create(DocumentEntry) catch return error.OutOfMemory;
    entry.* = .{
        .doc = types.Document.init(store_alloc, doc_id, stored_path, data),
        .db = Database.init(store_alloc, ctx.io),
        .call_index = null,
    };

    var single_opts = types.LoadOptions{};
    parseLoadOptions(params, &entry.doc, &single_opts);

    const format = detectFormat(data);
    const opts = single_opts;
    switch (format) {
        .macho => {
            entry.doc = macho.parse(store_alloc, doc_id, stored_path, data, opts) catch return error.OutOfMemory;
        },
        .elf => {
            entry.doc = elf_loader.parse(store_alloc, doc_id, stored_path, data, opts) catch return error.OutOfMemory;
        },
        .pe => {
            entry.doc = pe_loader.parse(store_alloc, doc_id, stored_path, data, opts) catch return error.OutOfMemory;
        },
        .zip => {
            // APK/ZIP in batch mode — skip (handle at top level only)
            entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
            entry.doc.format = .zip;
        },
        .pbp => {
            // PBP container: extract ELF from section 6 (DATA.PSP)
            if (data.len >= 40) {
                const elf_offset = std.mem.readInt(u32, data[32..36], .little); // offset[6]
                const raw_end = std.mem.readInt(u32, data[36..40], .little); // offset[7]
                const elf_end = if (raw_end > elf_offset) raw_end else @as(u32, @intCast(@min(data.len, std.math.maxInt(u32))));
                if (elf_offset < elf_end and elf_end <= data.len) {
                    const elf_data = data[elf_offset..elf_end];
                    if (elf_loader.isElf(elf_data)) {
                        entry.doc = elf_loader.parse(store_alloc, doc_id, stored_path, elf_data, opts) catch return error.OutOfMemory;
                    } else {
                        entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
                        entry.doc.format = .pbp;
                        entry.doc.note = pbpEncryptedHint(elf_data);
                    }
                } else {
                    entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
                    entry.doc.format = .pbp;
                }
            } else {
                entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
                entry.doc.format = .pbp;
            }
        },
        .psx_exe => {
            entry.doc = types.Document.init(store_alloc, doc_id, stored_path, data);
            entry.doc.format = .psx_exe;
            synthesizePsxExeSegments(store_alloc, &entry.doc, data) catch {};
            if (single_opts.entry) |e| entry.doc.entry_point = e;
        },
        .raw => {
            // v7.9.0 K.2: route through finalizeRawDocument so the arch set
            // from options (above) is preserved instead of clobbered by
            // Document.init()'s arm64 default.
            finalizeRawDocument(store_alloc, &entry.doc, data, entry.doc.arch, single_opts.entry, single_opts.base);
        },
    }

    try finalizeLoad(ctx, entry, data, null);

    // Check for name collisions and append note if other docs share this basename
    const new_basename = std.fs.path.basename(path);
    var collision_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const cw = &collision_buf.writer;
    var collision_count: u32 = 0;
    {
        ctx.store.mutex.lockUncancelable(ctx.io);
        defer ctx.store.mutex.unlock(ctx.io);
        var cit = ctx.store.documents.iterator();
        while (cit.next()) |de| {
            if (de.key_ptr.* == entry.doc.id) continue;
            if (std.mem.eql(u8, std.fs.path.basename(de.value_ptr.*.doc.path), new_basename)) {
                if (collision_count > 0) cw.writeAll(", ") catch {};
                cw.print("{d}", .{de.key_ptr.*}) catch {};
                collision_count += 1;
            }
        }
    }

    const base_json = json.serializeDocumentInfo(ctx.allocator, entry.doc) catch return error.OutOfMemory;

    // Append extra metadata fields if needed (collision note, large_binary flag)
    var extra = std.Io.Writer.Allocating.init(ctx.allocator);
    const ew = &extra.writer;
    if (collision_count > 0) {
        const collision_ids = collision_buf.toOwnedSlice() catch "";
        ew.print(",\"note\":\"Other documents share this name (use numeric doc_id): {s}\"", .{collision_ids}) catch {};
    }
    if (is_large) {
        ew.print(",\"large_binary\":true,\"file_size_mb\":{d}", .{file_size / (1024 * 1024)}) catch {};
    }
    if (extra.written().len > 0) {
        const extra_str = extra.toOwnedSlice() catch "";
        return std.fmt.allocPrint(
            ctx.allocator,
            "{s}{s}{s}",
            .{ base_json[0 .. base_json.len - 1], extra_str, "}" },
        ) catch return error.OutOfMemory;
    }
    return base_json;
}

/// Load a binary from raw bytes (used by ZIP/APK extraction).
/// Same as loadSingleBinary but skips file I/O.
fn loadSingleBinaryFromData(ctx: ToolContext, path: []const u8, data: []const u8, params: std.json.Value) ![]const u8 {
    // v7.15.0 B1: doc/db/path/data persist on store_alloc. Caller passes `data`
    // sliced from a parent ZIP buffer (in the per-request arena), so we
    // alias here WITHOUT copying — owns_data=false so close_document doesn't
    // double-free. `path` is a synthesized virtual path that we dupe; owns_path=true.
    const store_alloc = ctx.store.allocator;
    const stored_path = store_alloc.dupe(u8, path) catch return error.OutOfMemory;
    const doc_id = ctx.store.nextId();
    const entry = store_alloc.create(DocumentEntry) catch return error.OutOfMemory;
    entry.* = .{
        .doc = types.Document.init(store_alloc, doc_id, stored_path, data),
        .db = Database.init(store_alloc, ctx.io),
        .call_index = null,
        .owns_data = false,
        .owns_path = true,
    };

    if (getObject(params, "options")) |opts| {
        if (getString(opts, "arch")) |arch_str| {
            if (std.ascii.eqlIgnoreCase(arch_str, "arm64")) entry.doc.arch = .arm64;
            if (std.ascii.eqlIgnoreCase(arch_str, "x86_64")) entry.doc.arch = .x86_64;
            if (std.ascii.eqlIgnoreCase(arch_str, "arm32")) entry.doc.arch = .arm32;
            if (std.ascii.eqlIgnoreCase(arch_str, "x86")) entry.doc.arch = .x86;
            if (std.ascii.eqlIgnoreCase(arch_str, "mips32")) entry.doc.arch = .mips32;
        }
    }

    const format = detectFormat(data);
    const opts = types.LoadOptions{};
    switch (format) {
        .macho => {
            entry.doc = macho.parse(store_alloc, doc_id, stored_path, data, opts) catch return error.OutOfMemory;
        },
        .elf => {
            entry.doc = elf_loader.parse(store_alloc, doc_id, stored_path, data, opts) catch return error.OutOfMemory;
        },
        .pe => {
            entry.doc = pe_loader.parse(store_alloc, doc_id, stored_path, data, opts) catch return error.OutOfMemory;
        },
        .pbp => {
            // PBP container: extract ELF from section 6 (DATA.PSP)
            if (data.len >= 40) {
                const elf_offset = std.mem.readInt(u32, data[32..36], .little); // offset[6]
                const raw_end = std.mem.readInt(u32, data[36..40], .little); // offset[7]
                const elf_end = if (raw_end > elf_offset) raw_end else @as(u32, @intCast(@min(data.len, std.math.maxInt(u32))));
                if (elf_offset < elf_end and elf_end <= data.len) {
                    const elf_data = data[elf_offset..elf_end];
                    if (elf_loader.isElf(elf_data)) {
                        entry.doc = elf_loader.parse(store_alloc, doc_id, stored_path, elf_data, opts) catch return error.OutOfMemory;
                    } else {
                        entry.doc.format = .pbp;
                        entry.doc.note = pbpEncryptedHint(elf_data);
                    }
                } else {
                    entry.doc.format = .pbp;
                }
            } else {
                entry.doc.format = .pbp;
            }
        },
        .zip, .raw => {
            entry.doc.format = format;
        },
        .psx_exe => {
            entry.doc.format = .psx_exe;
            synthesizePsxExeSegments(store_alloc, &entry.doc, data) catch {};
        },
    }

    try finalizeLoad(ctx, entry, data, null);
    return json.serializeDocumentInfo(ctx.allocator, entry.doc) catch return error.OutOfMemory;
}

fn handleListDocuments(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const explicit_summary = getBool(params, "summary");
    const doc_count = ctx.store.documents.count();
    const summary = if (explicit_summary) |s| s else (doc_count > 20);
    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;

    w.writeByte('[') catch return ToolError.OutOfMemory;
    var it = ctx.store.documents.valueIterator();
    var first = true;
    while (it.next()) |entry_ptr| {
        if (!first) w.writeByte(',') catch {};
        first = false;
        // For rebased views, use parent's stats (view's doc has empty stats)
        const stats_doc = if (entry_ptr.*.rebase_parent) |parent| parent.doc else entry_ptr.*.doc;
        if (summary) {
            // Compact: {"doc_id":1,"name":"ssh","arch":"arm64","procs":3207}
            w.writeAll("{\"doc_id\":") catch {};
            w.print("{d}", .{entry_ptr.*.doc.id}) catch {};
            w.writeAll(",\"name\":") catch {};
            const name = std.fs.path.basename(stats_doc.path);
            json.writeJsonString(w, name) catch {};
            w.writeAll(",\"arch\":") catch {};
            json.writeJsonString(w, stats_doc.arch.toString()) catch {};
            w.print(",\"procs\":{d}", .{stats_doc.procedures.items.len}) catch {};
            w.writeByte('}') catch {};
        } else {
            var doc_for_info = entry_ptr.*.doc;
            doc_for_info.procedures = stats_doc.procedures;
            doc_for_info.strings = stats_doc.strings;
            doc_for_info.imports = stats_doc.imports;
            if (doc_for_info.segments.len == 0) doc_for_info.segments = stats_doc.segments;
            const doc_json = json.serializeDocumentInfo(ctx.allocator, doc_for_info) catch continue;
            // Inject rebase metadata if present, before the closing brace
            if (entry_ptr.*.rebase_parent_id) |pid| {
                // doc_json ends with '}', insert rebase fields before it
                if (doc_json.len > 0 and doc_json[doc_json.len - 1] == '}') {
                    w.writeAll(doc_json[0 .. doc_json.len - 1]) catch {};
                    w.print(",\"is_rebased_view\":true,\"parent_doc_id\":{d},\"rebase_delta\":\"0x{x}\"", .{
                        pid,
                        if (entry_ptr.*.rebase_delta < 0) @as(u128, @bitCast(-entry_ptr.*.rebase_delta)) else @as(u128, @bitCast(entry_ptr.*.rebase_delta)),
                    }) catch {};
                    w.writeByte('}') catch {};
                } else {
                    w.writeAll(doc_json) catch {};
                }
            } else {
                w.writeAll(doc_json) catch {};
            }
        }
    }
    w.writeByte(']') catch {};

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "list_documents", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

fn handleCloseDocument(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "close_document", params);
    };

    // Check if any documents have this as their rebase parent.
    // v7.15.0 B4: hold store.mutex across the iteration; HTTP thread pool can
    // mutate the documents map concurrently (load_binary inserts, close_document
    // removes), and an unsynchronized iterator was undefined behavior.
    var child_ids = std.array_list.Managed(u64).init(ctx.allocator);
    defer child_ids.deinit();
    {
        ctx.store.mutex.lockUncancelable(ctx.io);
        defer ctx.store.mutex.unlock(ctx.io);
        var it = ctx.store.documents.iterator();
        while (it.next()) |de| {
            if (de.value_ptr.*.rebase_parent_id) |pid| {
                if (pid == doc_id) {
                    child_ids.append(de.key_ptr.*) catch {};
                }
            }
        }
    }
    if (child_ids.items.len > 0) {
        var err_buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const ew = &err_buf.writer;
        ew.print("Cannot close document {d}: it has rebased views [", .{doc_id}) catch {};
        for (child_ids.items, 0..) |cid, i| {
            if (i > 0) ew.writeAll(", ") catch {};
            ew.print("{d}", .{cid}) catch {};
        }
        ew.writeAll("]. Close those first.") catch {};
        const err_msg = err_buf.toOwnedSlice() catch "Cannot close document: has rebased views";
        const resp = json.errorResponse(ctx.allocator, "close_document", err_msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    // v7.15.0 B1 pass 2: actually free the doc's allocations (was a leak in
    // v7.11 hotfix #1 because docs were arena-allocated). Pull the entry out
    // of the store under the same lock used by remove so concurrent loaders
    // can't race with our free.
    var freed_entry: ?*DocumentEntry = null;
    {
        ctx.store.mutex.lockUncancelable(ctx.io);
        defer ctx.store.mutex.unlock(ctx.io);
        if (ctx.store.documents.fetchRemove(doc_id)) |kv| {
            freed_entry = kv.value;
        }
    }
    const entry_to_free = freed_entry orelse return docNotFoundError(ctx, "close_document");
    teardownDocumentEntry(ctx.store.allocator, entry_to_free);
    ctx.queueNotification("notifications/tools/list_changed");
    ctx.queueNotification("notifications/resources/list_changed"); // v7.16 W5: doc resource removed

    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "close_document", "{\"closed\":true}", elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

/// v7.15.0 B1 pass 2: free everything a DocumentEntry owns. Called from
/// close_document and from DocumentStore.deinit (process shutdown).
/// Best-effort: each step is independent so a partial setup (e.g. budget
/// abort during finalizeLoad) can also use this.
fn teardownDocumentEntry(store_alloc: Allocator, entry: *DocumentEntry) void {
    // Tear down call_index (lazily built on first call_graph request).
    if (entry.call_index) |*ci| {
        var it = ci.valueIterator();
        while (it.next()) |list_ptr| {
            store_alloc.free(list_ptr.*);
        }
        ci.deinit();
    }
    entry.db.deinit();
    // Free segments[].sections then segments[] — these are toOwnedSlice'd from
    // loader-internal ArrayLists, so Document.deinit doesn't free them.
    for (entry.doc.segments) |seg| {
        if (seg.sections.len > 0) {
            store_alloc.free(seg.sections);
        }
    }
    if (entry.doc.segments.len > 0) {
        store_alloc.free(entry.doc.segments);
    }
    entry.doc.deinit();
    if (entry.owns_data and entry.doc.data.len > 0) {
        store_alloc.free(entry.doc.data);
    }
    if (entry.owns_path and entry.doc.path.len > 0) {
        store_alloc.free(@constCast(entry.doc.path));
    }
    store_alloc.destroy(entry);
}

/// Decode a bounded entry prefix directly from immutable file bytes. Operand
/// slices are copied because decoder-return buffers are transient.
fn evidencePrefix(a: Allocator, entry: *DocumentEntry, proc: types.Procedure) ![]types.Instruction {
    var out = std.array_list.Managed(types.Instruction).init(a);
    var address = proc.entry;
    const end = std.math.add(u64, proc.entry, @min(proc.size, 4096)) catch return out.toOwnedSlice();
    while (address < end and out.items.len < 96) {
        const info = resolveRawBytesInfo(entry, address) orelse break;
        const off = std.math.add(u64, info.file_offset, address - info.section_base) catch break;
        if (off >= entry.doc.data.len) break;
        const bytes = entry.doc.data[@intCast(off)..][0..@intCast(@min(end - address, entry.doc.data.len - off))];
        const inst = switch (entry.doc.arch) {
            .arm64 => if (bytes.len >= 4) arm64.decodeInstruction(bytes, address) else break,
            .arm32 => if (bytes.len >= 2) arm32.decodeInstruction(bytes, address) else break,
            .mips32 => if (bytes.len >= 4) mips32.decodeInstruction(bytes, address) else break,
            .x86_64 => @import("arch/x86_64.zig").decodeInstruction(bytes, address),
            .x86 => break,
        };
        if (inst.size == 0 or inst.size > bytes.len) break;
        var copy = inst;
        copy.operands = try a.dupe(u8, inst.operands_buf[0..inst.operands_len]);
        try out.append(copy);
        address += inst.size;
    }
    return out.toOwnedSlice();
}

fn writeRecoveryStringArray(w: anytype, values: []const []const u8) !void {
    try w.writeByte('[');
    for (values, 0..) |value, i| {
        if (i != 0) try w.writeByte(',');
        try json.writeJsonString(w, value);
    }
    try w.writeByte(']');
}

fn appendRecoveryEvidence(a: Allocator, original: []const u8, proc: types.Procedure, db: *Database, entry: *DocumentEntry, flags: IncludeFlags, doc_id: u64, delta: i128, budget: usize) ![]const u8 {
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const temp = scratch.allocator();
    var extra = std.Io.Writer.Allocating.init(a);
    defer extra.deinit();
    const w = &extra.writer;
    if (flags.abi) {
        const profile = abi_mod.profileForDocument(&entry.doc);
        const prefix = try evidencePrefix(temp, entry, proc);
        const candidates = try abi_mod.candidateArguments(temp, prefix, profile);
        try w.writeAll(",\"abi_evidence\":{\"profile\":");
        try json.writeJsonString(w, profile.name);
        try w.writeAll(",\"confidence\":");
        try json.writeJsonString(w, @tagName(profile.confidence));
        try w.writeAll(",\"note\":");
        try json.writeJsonString(w, profile.reason);
        try w.writeAll(",\"candidate_order\":\"first observed read, not parameter position\"");
        if (entry.doc.arch == .arm64)
            try w.writeAll(",\"register_alias_note\":\"Wn and Xn share storage: writing Wn replaces Xn with the zero-extended 32-bit result. First-read width is not a parameter type.\"");
        try w.writeAll(",\"integer_argument_registers\":");
        try writeRecoveryStringArray(w, profile.integer_args);
        try w.writeAll(",\"floating_argument_registers\":");
        try writeRecoveryStringArray(w, profile.floating_args);
        try w.writeAll(",\"return_registers\":");
        try writeRecoveryStringArray(w, profile.return_registers);
        if (profile.stack_alignment) |alignment| try w.print(",\"stack_alignment\":{d}", .{alignment});
        try w.print(",\"shadow_space_bytes\":{d},\"prototype_recovered\":false,\"parameter_count\":null,\"candidate_scope\":\"entry prefix before the first control-flow or unsupported-instruction barrier; incomplete by design\",\"decoded_prefix_instructions\":{d},\"candidate_arguments\":[", .{ profile.shadow_space_bytes, prefix.len });
        for (candidates, 0..) |candidate, i| {
            if (i != 0) try w.writeByte(',');
            try w.writeAll("{\"register\":");
            try json.writeJsonString(w, candidate.register);
            try w.writeAll(",\"first_read_address\":");
            try json.writeAddress(w, applyRebaseDelta(candidate.first_read_address, delta));
            if (candidate.width) |width| try w.print(",\"first_read_width_bytes\":{d}", .{width});
            try w.writeByte('}');
        }
        try w.writeAll("]}");
    }
    if (flags.types) {
        try w.writeAll(",\"type_evidence\":{");
        if (db.getCachedIR(proc.entry)) |function| {
            var bounded = function;
            bounded.address = applyRebaseDelta(function.address, delta);
            bounded.statements = function.statements[0..@min(function.statements.len, 256)];
            const recovered = try type_recovery.recover(temp, &.{bounded});
            const returned = @min(recovered.structs.len, 4);
            try w.print("\"analysis_kind\":\"observed_memory_layouts\",\"source_statements\":{d},\"total_statements\":{d},\"total_layouts_in_prefix\":{d},\"returned_layouts\":{d},\"partial\":{},\"note\":\"Observed access offsets and widths, not proven C members or source types. Size hints are heuristic, including legacy frame padding, not proven object extents. Indexed and unknown-width evidence is excluded; arrays, unions, and reused base-register names remain possible. Follow lift for complete instruction evidence.\",\"layouts\":[", .{ bounded.statements.len, function.statements.len, recovered.structs.len, returned, bounded.statements.len < function.statements.len or returned < recovered.structs.len });
            for (recovered.structs[0..returned], 0..) |layout, i| {
                if (i != 0) try w.writeByte(',');
                try w.writeAll("{\"name\":");
                try json.writeJsonString(w, layout.name);
                try w.print(",\"size_hint_bytes\":{d},\"overlapping_accesses\":{},\"total_fields\":{d},\"returned_fields\":{d},\"fields_partial\":{},\"pointer_origins\":", .{ layout.size_hint, layout.has_overlapping_accesses, layout.fields.len, @min(layout.fields.len, 16), layout.fields.len > 16 });
                try writeRecoveryStringArray(w, layout.pointer_origins[0..@min(layout.pointer_origins.len, 8)]);
                try w.print(",\"total_pointer_origins\":{d},\"pointer_origins_partial\":{}", .{ layout.pointer_origins.len, layout.pointer_origins.len > 8 });
                try w.writeAll(",\"fields\":[");
                for (layout.fields[0..@min(layout.fields.len, 16)], 0..) |field, j| {
                    if (j != 0) try w.writeByte(',');
                    try w.print("{{\"offset\":{d},\"maximum_access_width\":{d},\"reads\":{d},\"writes\":{d},\"signed_reads\":{d},\"unsigned_reads\":{d},\"observed_widths_bytes\":[", .{ field.offset, field.width, field.read_count, field.write_count, field.signed_read_count, field.unsigned_read_count });
                    var comma = false;
                    for (0..8) |bit| {
                        if (field.observed_widths & (@as(u8, 1) << @intCast(bit)) != 0) {
                            if (comma) try w.writeByte(',');
                            try w.print("{d}", .{@as(u8, 1) << @intCast(bit)});
                            comma = true;
                        }
                    }
                    try w.writeAll("]}");
                }
                try w.writeAll("]}");
            }
            try w.writeByte(']');
        } else try w.writeAll("\"status\":\"ir_unavailable\",\"partial\":true");
        try w.print(",\"next_call\":{{\"tool\":\"lift\",\"arguments\":{{\"doc_id\":{d},\"addresses\":", .{doc_id});
        try json.writeAddress(w, applyRebaseDelta(proc.entry, delta));
        try w.writeAll(",\"offset\":0,\"max_results\":256}}}");
    }
    if (extra.written().len > budget) {
        extra.clearRetainingCapacity();
        try w.writeAll(",\"recovery_evidence\":{\"status\":\"batch_budget\",\"note\":\"Retry this function alone for bounded ABI and type evidence\",\"next_call\":{\"tool\":\"analyze_functions\",\"arguments\":{");
        try w.print("\"doc_id\":{d},\"addresses\":", .{doc_id});
        try json.writeAddress(w, applyRebaseDelta(proc.entry, delta));
        try w.writeAll(",\"include\":[\"abi\",\"types\"]}}}");
    }
    var result = std.Io.Writer.Allocating.init(a);
    errdefer result.deinit();
    try result.writer.writeAll(original[0 .. original.len - 1]);
    try result.writer.writeAll(extra.written());
    try result.writer.writeByte('}');
    return result.toOwnedSlice();
}

fn handleAnalyzeFunctions(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "analyze_functions", params);
    };
    const all_addresses = parseBatchAddresses(ctx.allocator, params) catch {
        const resp = json.errorResponse(ctx.allocator, "analyze_functions", "missing or invalid 'addresses' parameter. Accepts: integer, hex string (\"0x1234\"), or array of integers/hex strings.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    defer ctx.allocator.free(all_addresses);
    const addresses = all_addresses[0..@min(all_addresses.len, 50)];
    const flags = parseIncludeFlagsValidated(params);

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "analyze_functions");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var addr_buf: [32]u8 = undefined;

    for (addresses) |addr| {
        const item_start = timestampMs(ctx.io);

        // v7.9.3 W4: dylib entry-point fallback. If the caller passed address=0
        // AND the doc itself has no recorded entry_point AND we have at least
        // one detected procedure, substitute the first procedure's address.
        // Mirrors the fallback in handleLift so callers don't
        // have to special-case dylibs. The substitution is surfaced via the
        // batch item's `input` label ("0x0 (dylib fallback -> 0x...)").
        var effective_addr: u64 = addr;
        var dylib_fallback = false;
        if (addr == 0 and entry.doc.entry_point == 0 and entry.doc.procedures.items.len > 0) {
            effective_addr = entry.doc.procedures.items[0].entry;
            dylib_fallback = true;
            // v7.11 W6: surface the implicit substitution as a notification.
            ctx.emitLog("notice", "phora.analyze", "analyze_functions: address=0x0 substituted with first procedure (dylib fallback)", "");
        }

        const label_copy = if (dylib_fallback)
            std.fmt.allocPrint(ctx.allocator, "0x0 (dylib fallback -> 0x{x})", .{effective_addr}) catch "0x0 (dylib fallback)"
        else
            ctx.allocator.dupe(u8, addrStr(&addr_buf, addr)) catch "?";

        // Translate input address
        const eff_addr = removeRebaseDelta(effective_addr, eff.delta);

        // Strict entry-point match only. Falling back to getProcedureContaining
        // here is dangerous because Mach-O size inference can wildly overestimate
        // procedure sizes (we've seen multi-MiB procs in stripped vendor builds), so a
        // string or data address would match a containing proc and trigger a
        // multi-MB IR lift. Require an exact entry; on failure, surface the
        // containing-proc address in the error so callers know where to look.
        if (eff.db.getProcedure(eff_addr)) |proc| {
            // Belt-and-suspenders: reject implausibly large procedures even when
            // the entry matches exactly. Real functions are virtually never
            // > 256 KiB; anything larger is a size-inference bug.
            const MAX_LIFT_BYTES: u64 = 1 * 1024 * 1024; // 1 MiB
            if (proc.size > MAX_LIFT_BYTES) {
                const err_msg = std.fmt.allocPrint(
                    ctx.allocator,
                    "procedure 0x{x} size {d} exceeds lift cap (1 MiB); use disassemble_range for partial inspection",
                    .{ applyRebaseDelta(proc.entry, eff.delta), proc.size },
                ) catch "procedure size exceeds lift cap";
                items.append(.{ .input = label_copy, .success = false, .err = err_msg, .time_ms = timestampMs(ctx.io) - item_start }) catch {};
                continue;
            }
            // Lift IR on demand if requested and not yet cached
            if ((flags.ir or flags.types) and eff.db.getCachedIR(proc.entry) == null) {
                ensureLiftedIR(ctx.allocator, proc, eff.db, eff.entry);
            }
            if (flags.cfg) _ = ensureFunctionCfg(ctx.allocator, proc, eff.db, eff.entry);
            // Prime callees cache before serialization so semantic facts have data
            _ = ensureCalleesCached(eff.entry, eff.db, proc.entry, ctx.allocator);
            const base_result_json = serializeProcedureJson(ctx.allocator, proc, eff.db, flags, eff.entry.call_index, doc_id, eff.delta, (max_response_chars - 8192) / (@max(addresses.len, 1) * @as(usize, if (flags.abi or flags.types) 2 else 1))) catch {
                items.append(.{ .input = label_copy, .success = false, .err = "serialization error", .time_ms = timestampMs(ctx.io) - item_start }) catch {};
                continue;
            };
            const result_json = if (flags.abi or flags.types)
                appendRecoveryEvidence(ctx.allocator, base_result_json, proc, eff.db, eff.entry, flags, doc_id, eff.delta, (max_response_chars - 8192) / (@max(addresses.len, 1) * 2)) catch {
                    items.append(.{ .input = label_copy, .success = false, .err = "recovery evidence serialization failed", .time_ms = timestampMs(ctx.io) - item_start }) catch {};
                    continue;
                }
            else
                base_result_json;
            items.append(.{ .input = label_copy, .success = true, .result = result_json, .time_ms = timestampMs(ctx.io) - item_start }) catch {};
        } else if (eff.db.getProcedureContaining(eff_addr)) |containing| {
            const err_msg = std.fmt.allocPrint(
                ctx.allocator,
                "address 0x{x} is not a procedure entry; it lies inside procedure 0x{x} (pass that address, or use analyze_addresses for classification)",
                .{ addr, applyRebaseDelta(containing.entry, eff.delta) },
            ) catch "address is not a procedure entry";
            items.append(.{ .input = label_copy, .success = false, .err = err_msg, .time_ms = timestampMs(ctx.io) - item_start }) catch {};
        } else {
            const err_msg = std.fmt.allocPrint(ctx.allocator, "no procedure at address 0x{x}", .{addr}) catch "no procedure at address";
            items.append(.{ .input = label_copy, .success = false, .err = err_msg, .time_ms = timestampMs(ctx.io) - item_start }) catch {};
        }
    }

    const resp = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

fn handleAnalyzeAddresses(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "analyze_addresses", params);
    };
    const addresses = parseBatchAddresses(ctx.allocator, params) catch {
        const resp = json.errorResponse(ctx.allocator, "analyze_addresses", "missing or invalid 'addresses' parameter. Accepts: integer, hex string (\"0x1234\"), or array of integers/hex strings.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    defer ctx.allocator.free(addresses);

    const flags = parseIncludeFlagsValidated(params);

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "analyze_addresses");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var addr_buf: [32]u8 = undefined;

    for (addresses) |addr| {
        const item_start = timestampMs(ctx.io);
        const label_copy = ctx.allocator.dupe(u8, addrStr(&addr_buf, addr)) catch "?";

        // Translate input address
        const eff_addr = removeRebaseDelta(addr, eff.delta);

        var result_buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const w = &result_buf.writer;

        w.writeAll("{\"address\":") catch {};
        json.writeAddress(w, addr) catch {};

        // Determine what's at this address.
        if (eff.db.resolveName(eff_addr)) |name| {
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, name) catch {};
        }

        // Check if it's in a procedure — store for later use by calls flag.
        const containing_proc = eff.db.getProcedureContaining(eff_addr);
        if (containing_proc) |proc| {
            w.writeAll(",\"type\":\"code\",\"procedure\":") catch {};
            json.writeAddress(w, applyRebaseDelta(proc.entry, eff.delta)) catch {};
        } else if (eff.db.getString(eff_addr) != null) {
            w.writeAll(",\"type\":\"string\"") catch {};
        } else if (eff.db.getImport(eff_addr) != null) {
            w.writeAll(",\"type\":\"import\"") catch {};
        } else {
            w.writeAll(",\"type\":\"unknown\"") catch {};
        }

        // Find containing segment.
        for (eff.entry.doc.segments) |seg| {
            if (eff_addr >= seg.start and eff_addr < seg.start + seg.length) {
                w.writeAll(",\"segment\":") catch {};
                json.writeJsonString(w, seg.name) catch {};
                break;
            }
        }

        // --- Include-flag enrichments (B2 fix) ---

        if (flags.xrefs) {
            const xrefs_from = eff.db.xrefs.getRefsFrom(eff_addr);
            const xrefs_to = eff.db.xrefs.getRefsTo(eff_addr);

            w.writeAll(",\"xrefs\":{\"from\":[") catch {};
            for (xrefs_from, 0..) |xref, i| {
                if (i > 0) w.writeByte(',') catch {};
                w.writeAll("{\"to\":") catch {};
                json.writeAddress(w, applyRebaseDelta(xref.to, eff.delta)) catch {};
                w.writeAll(",\"type\":\"") catch {};
                w.writeAll(xrefTypeStr(xref.xref_type)) catch {};
                w.writeAll("\"}") catch {};
            }
            w.writeAll("],\"to\":[") catch {};
            for (xrefs_to, 0..) |xref, i| {
                if (i > 0) w.writeByte(',') catch {};
                w.writeAll("{\"from\":") catch {};
                json.writeAddress(w, applyRebaseDelta(xref.from, eff.delta)) catch {};
                w.writeAll(",\"type\":\"") catch {};
                w.writeAll(xrefTypeStr(xref.xref_type)) catch {};
                w.writeAll("\"}") catch {};
            }
            w.writeAll("]}") catch {};
        }

        if (flags.calls) {
            if (containing_proc) |proc| {
                const callees = ensureCalleesCached(eff.entry, eff.db, proc.entry, ctx.allocator);
                w.writeAll(",\"calls\":[") catch {};
                for (callees, 0..) |call_addr, i| {
                    if (i > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"address\":") catch {};
                    json.writeAddress(w, applyRebaseDelta(call_addr, eff.delta)) catch {};
                    if (eff.db.resolveName(call_addr)) |cname| {
                        w.writeAll(",\"name\":") catch {};
                        json.writeJsonString(w, cname) catch {};
                    }
                    w.writeByte('}') catch {};
                }
                w.writeByte(']') catch {};
            }
        }

        if (flags.strings) {
            if (eff.db.getString(eff_addr)) |s| {
                w.writeAll(",\"string\":") catch {};
                json.writeJsonString(w, s.value) catch {};
            }
        }

        w.writeByte('}') catch {};
        const result_json = result_buf.toOwnedSlice() catch {
            items.append(.{ .input = label_copy, .success = false, .err = "serialization error", .time_ms = timestampMs(ctx.io) - item_start }) catch {};
            continue;
        };
        items.append(.{ .input = label_copy, .success = true, .result = result_json, .time_ms = timestampMs(ctx.io) - item_start }) catch {};
    }

    const resp = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

/// Check if "password" appears in a credential-like context (variable name, config key),
/// not in error messages or documentation text.
fn isCredentialPassword(s: []const u8) bool {
    // High-confidence: variable-name patterns
    if (std.mem.indexOf(u8, s, "password=") != null or
        std.mem.indexOf(u8, s, "password:") != null or
        std.mem.indexOf(u8, s, "PASSWORD=") != null or
        std.mem.indexOf(u8, s, "PASSWORD:") != null or
        std.mem.indexOf(u8, s, "_password") != null or
        std.mem.indexOf(u8, s, "_PASSWORD") != null or
        std.mem.indexOf(u8, s, "password_") != null or
        std.mem.indexOf(u8, s, "PASSWORD_") != null or
        std.mem.startsWith(u8, s, "password") or
        std.mem.startsWith(u8, s, "PASSWORD"))
    {
        // Reject if it looks like an error/warning message
        if (std.mem.indexOf(u8, s, "deprecated") != null or
            std.mem.indexOf(u8, s, "Deprecated") != null or
            std.mem.indexOf(u8, s, "warning") != null or
            std.mem.indexOf(u8, s, "obsolete") != null or
            std.mem.indexOf(u8, s, "invalid") != null or
            std.mem.indexOf(u8, s, "incorrect") != null or
            std.mem.indexOf(u8, s, "wrong") != null)
            return false;
        return true;
    }
    return false;
}

/// Confidence level for a capability match.
pub const CapConfidence = enum { high, medium, low };

/// Max capability categories a single string can be tagged with. Sized well
/// above the number of category blocks in `categorizeCapabilityImpl` so the
/// `count += 1` writes can never overrun the caller's fixed array (each new
/// block also guards with `if (count < cats_out.len)`). Bump this if you add
/// more categories than the current headroom allows.
pub const MAX_CAP_CATS = 24;

/// Categorize a string for capability/surface extraction.
/// Returns the number of categories written to `cats_out`, or 0 if no match.
/// If `conf_out` is non-null, writes the confidence level for each category.
pub fn categorizeCapabilityWithConfidence(s: []const u8, cats_out: *[MAX_CAP_CATS][]const u8, conf_out: ?*[MAX_CAP_CATS]CapConfidence) usize {
    return categorizeCapabilityImpl(s, cats_out, conf_out);
}

pub fn categorizeCapability(s: []const u8, cats_out: *[MAX_CAP_CATS][]const u8) usize {
    return categorizeCapabilityImpl(s, cats_out, null);
}

fn categorizeCapabilityImpl(s: []const u8, cats_out: *[MAX_CAP_CATS][]const u8, conf_out: ?*[MAX_CAP_CATS]CapConfidence) usize {
    var count: usize = 0;

    // Runtime feature flags (FFlag/DFFlag/SFFlag/RFlag + generic patterns)
    if (std.mem.indexOf(u8, s, "FFlag") != null or std.mem.indexOf(u8, s, "DFFlag") != null or
        std.mem.indexOf(u8, s, "SFFlag") != null or std.mem.indexOf(u8, s, "RFlag") != null or
        std.mem.startsWith(u8, s, "FEATURE_") or std.mem.startsWith(u8, s, "feature_") or
        std.mem.startsWith(u8, s, "EXPERIMENT_") or std.mem.startsWith(u8, s, "experiment_") or
        std.mem.indexOf(u8, s, "launch_darkly") != null or std.mem.indexOf(u8, s, "LaunchDarkly") != null or
        std.mem.indexOf(u8, s, "unleash") != null)
    {
        cats_out[count] = "feature_flag";
        if (conf_out) |co| co[count] = .medium;
        count += 1;
    }
    // Log channels
    if (std.mem.indexOf(u8, s, "FLog::") != null or std.mem.indexOf(u8, s, "DFLog::") != null) {
        cats_out[count] = "log_channel";
        if (conf_out) |co| co[count] = .medium;
        count += 1;
    }
    // Endpoints — filter XML/spec namespace URIs that aren't real service endpoints
    if (s.len >= 7 and (std.mem.startsWith(u8, s, "http://") or std.mem.startsWith(u8, s, "https://"))) endpoint_blk: {
        // Reject well-known namespace/schema URIs
        if (std.mem.indexOf(u8, s, "www.w3.org") != null or
            std.mem.indexOf(u8, s, "www.ietf.org") != null or
            std.mem.indexOf(u8, s, "purl.org") != null or
            std.mem.indexOf(u8, s, "schemas.xmlsoap.org") != null or
            std.mem.indexOf(u8, s, "schemas.microsoft.com") != null or
            std.mem.indexOf(u8, s, "xml.apache.org") != null or
            std.mem.indexOf(u8, s, "xmlns.") != null or
            std.mem.indexOf(u8, s, "/XMLSchema") != null or
            std.mem.indexOf(u8, s, "/xml/ns/") != null)
        {
            break :endpoint_blk;
        }
        cats_out[count] = "endpoint";
        if (conf_out) |co| co[count] = .medium;
        count += 1;
        if (std.mem.indexOf(u8, s, "telemetry") != null or std.mem.indexOf(u8, s, "analytics") != null or
            std.mem.indexOf(u8, s, "tracing") != null or std.mem.indexOf(u8, s, "backtrace") != null or
            std.mem.indexOf(u8, s, "otlp") != null or std.mem.indexOf(u8, s, "opentelemetry") != null or
            std.mem.indexOf(u8, s, ":4317") != null or std.mem.indexOf(u8, s, ":4318") != null)
        {
            cats_out[count] = "telemetry";
            if (conf_out) |co| co[count] = .high;
            count += 1;
        }
    }
    // Build paths
    const mac_user_prefix = "/" ++ "Users/";
    if (std.mem.indexOf(u8, s, "teamcity") != null or std.mem.indexOf(u8, s, "jenkins") != null or
        std.mem.startsWith(u8, s, "/private/var/") or std.mem.indexOf(u8, s, mac_user_prefix) != null)
    {
        cats_out[count] = "build_path";
        if (conf_out) |co| co[count] = .medium;
        count += 1;
    }
    // Crypto markers — require word-boundary context to avoid false positives
    // (e.g., "AES" in "AESGetInventory" = Avatar Editor Service, not crypto)
    const has_pem = std.mem.indexOf(u8, s, "BEGIN") != null and std.mem.indexOf(u8, s, "KEY") != null;
    const has_aes = blk: {
        var idx: usize = 0;
        while (std.mem.indexOfPos(u8, s, idx, "AES")) |pos| {
            const after = pos + 3;
            if (after >= s.len or s[after] == '-' or (s[after] >= '0' and s[after] <= '9') or s[after] == ' ') break :blk true;
            // Allow underscore only when followed by a digit (AES_128, AES_256)
            if (s[after] == '_' and after + 1 < s.len and s[after + 1] >= '0' and s[after + 1] <= '9') break :blk true;
            idx = after;
        }
        break :blk false;
    };
    const has_rsa = blk: {
        var idx: usize = 0;
        while (std.mem.indexOfPos(u8, s, idx, "RSA")) |pos| {
            const after = pos + 3;
            if (after >= s.len or s[after] == '-' or (s[after] >= '0' and s[after] <= '9') or s[after] == ' ') break :blk true;
            // Allow underscore only when followed by a digit (RSA_2048)
            if (s[after] == '_' and after + 1 < s.len and s[after + 1] >= '0' and s[after + 1] <= '9') break :blk true;
            idx = after;
        }
        break :blk false;
    };
    const has_other_crypto = std.mem.indexOf(u8, s, "ECDSA") != null or
        std.mem.indexOf(u8, s, "ECDHE") != null or std.mem.indexOf(u8, s, "SHA256") != null or
        std.mem.indexOf(u8, s, "SHA384") != null or std.mem.indexOf(u8, s, "HMAC") != null or
        std.mem.indexOf(u8, s, "CHACHA") != null or std.mem.indexOf(u8, s, "POLY1305") != null;
    if (has_pem or has_aes or has_rsa or has_other_crypto) {
        cats_out[count] = "crypto";
        if (conf_out) |co| co[count] = if (has_pem) .high else if (has_other_crypto) .high else .medium;
        count += 1;
    }

    // debug_bypass: requires debug/test prefix AND bypass verb
    {
        const has_debug_prefix = std.mem.startsWith(u8, s, "Debug") or
            std.mem.startsWith(u8, s, "debug_") or
            std.mem.startsWith(u8, s, "TEST_") or
            std.mem.startsWith(u8, s, "Mock") or
            std.mem.startsWith(u8, s, "mock_") or
            std.mem.startsWith(u8, s, "Fake") or
            std.mem.startsWith(u8, s, "fake_") or
            std.mem.startsWith(u8, s, "Dummy") or
            std.mem.startsWith(u8, s, "dummy_");
        if (has_debug_prefix) {
            const has_bypass_verb = std.mem.indexOf(u8, s, "Disable") != null or
                std.mem.indexOf(u8, s, "Bypass") != null or
                std.mem.indexOf(u8, s, "Skip") != null or
                std.mem.indexOf(u8, s, "Override") != null or
                std.mem.indexOf(u8, s, "Force") != null or
                std.mem.indexOf(u8, s, "Insecure") != null or
                std.mem.indexOf(u8, s, "disable") != null or
                std.mem.indexOf(u8, s, "bypass") != null or
                std.mem.indexOf(u8, s, "skip") != null or
                std.mem.indexOf(u8, s, "override") != null or
                std.mem.indexOf(u8, s, "force") != null or
                std.mem.indexOf(u8, s, "insecure") != null;
            if (has_bypass_verb) {
                cats_out[count] = "debug_bypass";
                if (conf_out) |co| co[count] = .high;
                count += 1;
            }
        }
    }

    // pii_field: privacy/compliance markers
    if (std.mem.startsWith(u8, s, "pii_") or std.mem.startsWith(u8, s, "PII_") or
        std.mem.indexOf(u8, s, "GDPR") != null or std.mem.indexOf(u8, s, "CCPA") != null or
        std.mem.indexOf(u8, s, "HIPAA") != null or std.mem.indexOf(u8, s, "personally_identifiable") != null or
        std.mem.indexOf(u8, s, "data_subject") != null or std.mem.indexOf(u8, s, "data_protection") != null)
    {
        cats_out[count] = "pii_field";
        if (conf_out) |co| co[count] = .medium;
        count += 1;
    }

    // credential: API keys, secrets, passwords, cloud credentials
    {
        const has_cred = std.mem.indexOf(u8, s, "api_key") != null or
            std.mem.indexOf(u8, s, "apikey") != null or
            std.mem.indexOf(u8, s, "ApiKey") != null or
            std.mem.indexOf(u8, s, "API_KEY") != null or
            std.mem.indexOf(u8, s, "secret_key") != null or
            std.mem.indexOf(u8, s, "SecretKey") != null or
            std.mem.indexOf(u8, s, "SECRET_KEY") != null or
            std.mem.indexOf(u8, s, "client_secret") != null or
            std.mem.indexOf(u8, s, "CLIENT_SECRET") != null or
            isCredentialPassword(s) or
            std.mem.indexOf(u8, s, "bearer") != null or
            std.mem.indexOf(u8, s, "BEARER") != null or
            (std.mem.indexOf(u8, s, "BEGIN PRIVATE KEY") != null) or
            (std.mem.indexOf(u8, s, "BEGIN RSA PRIVATE") != null) or
            (std.mem.indexOf(u8, s, "BEGIN EC PRIVATE") != null) or
            std.mem.indexOf(u8, s, "AWS_SECRET") != null or
            std.mem.indexOf(u8, s, "AZURE_CLIENT_SECRET") != null or
            std.mem.indexOf(u8, s, "GOOGLE_APPLICATION_CREDENTIALS") != null;
        if (has_cred) {
            cats_out[count] = "credential";
            // PEM headers and cloud creds are high confidence; password/bearer are medium
            const is_high_cred = std.mem.indexOf(u8, s, "BEGIN PRIVATE KEY") != null or
                std.mem.indexOf(u8, s, "BEGIN RSA PRIVATE") != null or
                std.mem.indexOf(u8, s, "BEGIN EC PRIVATE") != null or
                std.mem.indexOf(u8, s, "AWS_SECRET") != null or
                std.mem.indexOf(u8, s, "AZURE_CLIENT_SECRET") != null or
                std.mem.indexOf(u8, s, "GOOGLE_APPLICATION_CREDENTIALS") != null;
            if (conf_out) |co| co[count] = if (is_high_cred) .high else .medium;
            count += 1;
        }
    }

    // internal_infra: cloud metadata and infra service references
    {
        const has_infra = std.mem.indexOf(u8, s, "metadata.google.internal") != null or
            std.mem.indexOf(u8, s, "169.254.169.254") != null or
            std.mem.indexOf(u8, s, "metadata.azure.com") != null or
            std.mem.indexOf(u8, s, "AWS_ACCESS_KEY_ID") != null or
            std.mem.indexOf(u8, s, "AWS_SECRET_ACCESS_KEY") != null or
            std.mem.indexOf(u8, s, "AWS_SESSION_TOKEN") != null;
        if (has_infra) {
            cats_out[count] = "internal_infra";
            if (conf_out) |co| co[count] = .high;
            count += 1;
        }
    }

    // ------------------------------------------------------------------
    // v7.16 W2 — modern app-surface markers. Shape-first so they fire
    // identically on the pre-extracted string table AND on embedded-runtime
    // (Bun __BUN) text. Each block guards `count` so it can never overrun
    // cats_out even if every category matched.
    // ------------------------------------------------------------------

    // telemetry_event: analytics event names (product prefix or vendor SDK)
    if (count < cats_out.len) {
        const is_tengu = std.mem.startsWith(u8, s, "tengu_");
        const has_vendor = std.mem.indexOf(u8, s, "amplitude") != null or
            std.mem.indexOf(u8, s, "mixpanel") != null or
            std.mem.indexOf(u8, s, "posthog") != null or
            std.mem.indexOf(u8, s, "statsig") != null or
            std.mem.indexOf(u8, s, "datadoghq") != null or
            std.mem.indexOf(u8, s, "segment.io") != null or
            std.mem.indexOf(u8, s, "bugsnag") != null;
        if (is_tengu or has_vendor) {
            cats_out[count] = "telemetry_event";
            if (conf_out) |co| co[count] = if (is_tengu) .high else .medium;
            count += 1;
        }
    }

    // env_toggle: environment-variable feature switches. Require pure
    // ALLCAPS_UNDERSCORE shape AND a recognized verb/product prefix or suffix.
    if (count < cats_out.len and capIsEnvTokenShape(s)) {
        const is_env = std.mem.startsWith(u8, s, "CLAUDE_CODE_") or
            std.mem.startsWith(u8, s, "ANTHROPIC_") or
            std.mem.startsWith(u8, s, "DISABLE_") or
            std.mem.startsWith(u8, s, "ENABLE_") or
            std.mem.startsWith(u8, s, "SKIP_") or
            std.mem.startsWith(u8, s, "FORCE_") or
            std.mem.startsWith(u8, s, "USE_") or
            std.mem.startsWith(u8, s, "ALLOW_") or
            std.mem.startsWith(u8, s, "NO_") or
            std.mem.startsWith(u8, s, "BUN_") or
            std.mem.startsWith(u8, s, "ELECTRON_") or
            std.mem.endsWith(u8, s, "_ENABLED") or
            std.mem.endsWith(u8, s, "_DISABLED") or
            std.mem.endsWith(u8, s, "_OVERRIDE") or
            std.mem.endsWith(u8, s, "_TOGGLE");
        if (is_env) {
            cats_out[count] = "env_toggle";
            if (conf_out) |co| co[count] = .high;
            count += 1;
        }
    }

    // model_id: LLM model identifiers (prefix family + a digit guard to skip prose)
    if (count < cats_out.len) {
        const has_prefix = std.mem.startsWith(u8, s, "claude-") or
            std.mem.startsWith(u8, s, "gpt-") or
            std.mem.startsWith(u8, s, "gemini-") or
            std.mem.startsWith(u8, s, "text-embedding-") or
            std.mem.indexOf(u8, s, "anthropic.claude") != null or
            std.mem.indexOf(u8, s, "models/gemini") != null;
        if (has_prefix and s.len < 64 and capHasDigit(s) and std.mem.indexOfScalar(u8, s, ' ') == null) {
            cats_out[count] = "model_id";
            if (conf_out) |co| co[count] = .high;
            count += 1;
        }
    }

    // mcp_tool: MCP tool identifiers and JSON-RPC method names
    if (count < cats_out.len) {
        const is_mcp = std.mem.indexOf(u8, s, "mcp__") != null or
            std.mem.eql(u8, s, "tools/call") or std.mem.eql(u8, s, "tools/list") or
            std.mem.eql(u8, s, "resources/read") or std.mem.eql(u8, s, "resources/list") or
            std.mem.eql(u8, s, "prompts/get") or std.mem.eql(u8, s, "prompts/list");
        if (is_mcp) {
            cats_out[count] = "mcp_tool";
            if (conf_out) |co| co[count] = .high;
            count += 1;
        }
    }

    // oauth_scope: `word:word[:word]` scope tokens with recognized scope vocab
    if (count < cats_out.len and capIsOAuthScope(s)) {
        cats_out[count] = "oauth_scope";
        if (conf_out) |co| co[count] = .medium;
        count += 1;
    }

    // api_path: bare service route templates (not filesystem paths)
    if (count < cats_out.len) {
        const looks_api = s.len >= 4 and s.len < 200 and
            std.mem.startsWith(u8, s, "/") and
            std.mem.indexOfScalar(u8, s, ' ') == null and
            !capIsFsPath(s) and
            (std.mem.indexOf(u8, s, "/api/") != null or
                std.mem.startsWith(u8, s, "/v1/") or
                std.mem.startsWith(u8, s, "/v2/") or
                std.mem.indexOf(u8, s, "/graphql") != null or
                std.mem.startsWith(u8, s, "/.well-known/") or
                std.mem.startsWith(u8, s, "/oauth"));
        if (looks_api) {
            cats_out[count] = "api_path";
            if (conf_out) |co| co[count] = .medium;
            count += 1;
        }
    }

    return count;
}

/// True when `s` is a pure ALLCAPS_UNDERSCORE env-var-shaped token (used by the
/// env_toggle capability category to avoid matching prose containing an '=').
fn capIsEnvTokenShape(s: []const u8) bool {
    if (s.len < 3 or s.len > 80) return false;
    var has_underscore = false;
    for (s) |c| {
        if (c == '_') {
            has_underscore = true;
            continue;
        }
        if (c >= 'A' and c <= 'Z') continue;
        if (c >= '0' and c <= '9') continue;
        return false;
    }
    return has_underscore;
}

fn capHasDigit(s: []const u8) bool {
    for (s) |c| {
        if (c >= '0' and c <= '9') return true;
    }
    return false;
}

/// True when `s` looks like a filesystem/library path (excluded from api_path).
fn capIsFsPath(s: []const u8) bool {
    const prefixes = [_][]const u8{
        "/usr/",          "/lib/", "/System/", "/private/", "/Users/", "/opt/",
        "/etc/",          "/var/", "/bin/",    "/sbin/",    "/tmp/",   "/Library/",
        "/Applications/",
    };
    for (prefixes) |p| {
        if (std.mem.startsWith(u8, s, p)) return true;
    }
    return std.mem.indexOf(u8, s, ".dylib") != null or
        std.mem.indexOf(u8, s, ".framework") != null or
        std.mem.endsWith(u8, s, ".so");
}

/// True when `s` is a plausible OAuth scope token: 2-3 lowercase `:`-separated
/// parts containing a recognized scope word. Rejects C++ `::`, URLs, `C:` drives.
fn capIsOAuthScope(s: []const u8) bool {
    if (s.len < 5 or s.len > 48) return false;
    if (std.mem.indexOf(u8, s, "::") != null) return false;
    if (std.mem.indexOf(u8, s, "//") != null) return false;
    var colon_count: usize = 0;
    for (s) |c| {
        if (c == ':') {
            colon_count += 1;
            continue;
        }
        const ok = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or
            c == '_' or c == '-' or c == '.';
        if (!ok) return false;
    }
    if (colon_count < 1 or colon_count > 2) return false;
    const vocab = [_][]const u8{
        "user:",     "org:",   "repo:", "read:",     "write:", "admin:", "account:",
        "team:",     "mcp:",   "api:",  "projects:", ":read",  ":write", ":inference",
        ":projects", ":admin",
    };
    for (vocab) |v| {
        if (std.mem.indexOf(u8, s, v) != null) return true;
    }
    return false;
}

/// Ranking weight for a capability category (higher = surfaced first). Security
/// and "what's-new" markers outrank ubiquitous ones. Used to sort the
/// `capabilities` search output so the scary/novel float to the top.
fn capCategoryWeight(cat: []const u8) u8 {
    const high = [_][]const u8{ "credential", "debug_bypass", "internal_infra", "model_id" };
    const mid = [_][]const u8{ "telemetry_event", "endpoint", "api_path", "env_toggle", "oauth_scope", "mcp_tool", "pii_field" };
    for (high) |h| {
        if (std.mem.eql(u8, cat, h)) return 3;
    }
    for (mid) |m| {
        if (std.mem.eql(u8, cat, m)) return 2;
    }
    return 1; // crypto, build_path, log_channel, feature_flag, telemetry
}

fn capConfRank(c: CapConfidence) u8 {
    return switch (c) {
        .high => 3,
        .medium => 2,
        .low => 1,
    };
}

/// Leading identifier token of `s` up to the first delimiter (`_`, `.`, `/`,
/// `-`, `:`). Prefix-clustering these is a codename detector — a dark-launched
/// family surfaces as an unexpectedly large shared prefix (e.g. `tengu_`).
/// Returns null when there's no delimiter or the prefix is too short to matter.
fn capClusterPrefix(s: []const u8) ?[]const u8 {
    // v7.16 W2 fix: don't cluster URLs — the ':' delimiter would collapse every
    // endpoint under "https:"/"http:" and bury the codename signal this exists
    // for. URLs are already their own category; skip them here.
    if (std.mem.startsWith(u8, s, "http://") or std.mem.startsWith(u8, s, "https://") or
        std.mem.startsWith(u8, s, "www."))
    {
        return null;
    }
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '_' or c == '.' or c == '/' or c == '-' or c == ':') {
            if (i >= 3) return s[0 .. i + 1]; // include the delimiter
            return null;
        }
    }
    return null;
}

fn handleSearch(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const max_results: u32 = if (getInt(params, "max_results")) |m| @intCast(@max(m, 0)) else 100;

    // Lenient query parsing:
    // Accept structured: {"type": "name", "pattern": "malloc"}
    // Accept flat string: "malloc" (defaults to name search)
    // Accept just type: {"type": "procedures"} (no pattern needed)
    var query_type_str: []const u8 = "name";
    var pattern: ?[]const u8 = null;
    var address: ?u64 = null;

    if (getObject(params, "query")) |query_obj| {
        // Structured query object
        query_type_str = getString(query_obj, "type") orelse "name";
        pattern = getString(query_obj, "pattern");
        address = if (getInt(query_obj, "address")) |a| @as(?u64, if (a >= 0) @as(u64, @intCast(a)) else @as(u64, @bitCast(a))) else null;
    } else if (getString(params, "query")) |flat_query| {
        // Flat string query — treat as a name search
        pattern = flat_query;
        query_type_str = "name";
    } else {
        // Accept top-level type/pattern/address (LLM-friendly flat format)
        if (getString(params, "type")) |t| query_type_str = t;
        pattern = getString(params, "pattern");
        if (getInt(params, "address")) |a| {
            address = if (a >= 0) @as(?u64, @intCast(a)) else @as(?u64, @bitCast(a));
        }
    }

    // #11: case_insensitive — lowercase the pattern for best-effort matching
    const case_insensitive = getBool(params, "case_insensitive") orelse false;

    // #12: max_xrefs — filter results by cross-reference count (e.g., max_xrefs=0 finds dead symbols)
    const max_xrefs: ?u32 = if (getInt(params, "max_xrefs")) |m| @intCast(@max(m, 0)) else null;
    var lower_pattern_buf: [1024]u8 = undefined;
    if (case_insensitive and pattern != null) {
        const p = pattern.?;
        const copy_len = @min(p.len, lower_pattern_buf.len);
        for (p[0..copy_len], 0..) |c, ci| {
            lower_pattern_buf[ci] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        pattern = lower_pattern_buf[0..copy_len];
    }

    // --- capabilities search: special path (no SearchQueryType variant needed) ---
    if (std.ascii.eqlIgnoreCase(query_type_str, "capabilities")) {
        const offset_raw_cap: i64 = getInt(params, "offset") orelse 0;
        const offset_cap: u32 = if (offset_raw_cap > 0) @intCast(offset_raw_cap) else 0;

        const CapResult = struct { address: u64, value: []const u8, cats: [MAX_CAP_CATS][]const u8, confs: [MAX_CAP_CATS]CapConfidence = undefined, cat_count: usize, doc_id: ?u64, doc_name: ?[]const u8, count: usize = 1, weight: u8 = 0, best_conf: u8 = 0 };
        var cap_results = std.array_list.Managed(CapResult).init(ctx.allocator);

        // Determine if we filter by category name using the pattern field
        const cat_filter = pattern; // pattern filters by category name for capabilities

        const cap_doc_id = resolveDocId(ctx, params);
        if (cap_doc_id == null and (getInt(params, "doc_id") != null or getString(params, "doc_id") != null)) {
            return docNotFoundError(ctx, "search");
        }

        // v7.16 W1/W2: dedup categorized strings (same value collapses to one
        // result with an occurrence `count`) AND scan packed runtime segments
        // (Bun __BUN etc.) that the pre-extracted string table skips — so
        // `capabilities` finally sees embedded-JS markers (tengu_*, CLAUDE_CODE_*,
        // model IDs, /api/... paths) instead of returning 0 on Bun/Electron apps.
        var cap_seen = std.StringHashMap(usize).init(ctx.allocator);
        defer cap_seen.deinit();
        var packed_truncated = false;

        // Helper to scan one document (pre-extracted table + packed segments).
        const scanDoc = struct {
            fn addCap(value: []const u8, addr: u64, cat_f: ?[]const u8, results: *std.array_list.Managed(CapResult), seen: *std.StringHashMap(usize), did: ?u64, dname: ?[]const u8) void {
                var cats: [MAX_CAP_CATS][]const u8 = undefined;
                var confs: [MAX_CAP_CATS]CapConfidence = undefined;
                const cat_count = categorizeCapabilityWithConfidence(value, &cats, &confs);
                if (cat_count == 0) return;
                if (cat_f) |cf| {
                    var matched = false;
                    for (cats[0..cat_count]) |cat| {
                        if (matchesMultiPattern(cat, cf, false)) {
                            matched = true;
                            break;
                        }
                    }
                    if (!matched) return;
                }
                // Dedup by string value: bump the occurrence count on repeat.
                if (seen.get(value)) |idx| {
                    results.items[idx].count += 1;
                    return;
                }
                // Precompute the ranking key: strongest category weight + confidence.
                var weight: u8 = 0;
                var best_conf: u8 = 0;
                for (cats[0..cat_count], confs[0..cat_count]) |cat, cf2| {
                    const w = capCategoryWeight(cat);
                    if (w > weight) weight = w;
                    const cr = capConfRank(cf2);
                    if (cr > best_conf) best_conf = cr;
                }
                const new_idx = results.items.len;
                results.append(.{
                    .address = addr,
                    .value = value,
                    .cats = cats,
                    .confs = confs,
                    .cat_count = cat_count,
                    .doc_id = did,
                    .doc_name = dname,
                    .count = 1,
                    .weight = weight,
                    .best_conf = best_conf,
                }) catch return;
                seen.put(value, new_idx) catch {};
            }

            fn scan(alloc: Allocator, db: anytype, doc: *const types.Document, cat_f: ?[]const u8, results: *std.array_list.Managed(CapResult), seen: *std.StringHashMap(usize), max_res: u32, did: ?u64, dname: ?[]const u8, packed_trunc: *bool) void {
                const cap = max_res * 10; // distinct-result ceiling (avoids unbounded growth)
                // Pass 1: pre-extracted string table.
                if (db.getAllStrings(alloc) catch null) |all_strings| {
                    for (all_strings) |str| {
                        if (results.items.len >= cap) return;
                        addCap(str.value, str.address, cat_f, results, seen, did, dname);
                    }
                }
                // Pass 2: packed runtime segments (skipped at load — scan on demand).
                if (strings_mod.hasPackedSegment(doc)) {
                    const extraction_cap: usize = 1_000_000;
                    var bundle = strings_mod.detectBundleStrings(alloc, doc, 5, extraction_cap) catch return;
                    defer bundle.deinit();
                    if (bundle.items.len >= extraction_cap) packed_trunc.* = true;
                    for (bundle.items) |str| {
                        if (results.items.len >= cap) return;
                        addCap(str.value, str.address, cat_f, results, seen, did, dname);
                    }
                }
            }
        };

        if (cap_doc_id) |doc_id| {
            const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "search");
            const eff = resolveEffectiveDb(entry);
            eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
            defer eff.db.rw_lock.unlockShared(eff.db.io);
            scanDoc.scan(ctx.allocator, eff.db, &eff.entry.doc, cat_filter, &cap_results, &cap_seen, max_results, null, null, &packed_truncated);
        } else {
            var doc_it = ctx.store.documents.iterator();
            while (doc_it.next()) |doc_entry| {
                const de = doc_entry.value_ptr.*;
                de.db.rw_lock.lockSharedUncancelable(de.db.io);
                defer de.db.rw_lock.unlockShared(de.db.io);
                scanDoc.scan(ctx.allocator, &de.db, &de.doc, cat_filter, &cap_results, &cap_seen, max_results, doc_entry.key_ptr.*, std.fs.path.basename(de.doc.path), &packed_truncated);
            }
        }

        // v7.16 W2: rank so security/novel markers surface first (safe after
        // scanning — `cap_seen` indices are no longer needed).
        const CapSort = struct {
            fn lessThan(_: void, a: CapResult, b: CapResult) bool {
                if (a.weight != b.weight) return a.weight > b.weight;
                if (a.best_conf != b.best_conf) return a.best_conf > b.best_conf;
                return a.count > b.count;
            }
        };
        std.sort.pdq(CapResult, cap_results.items, {}, CapSort.lessThan);

        // Category histogram + prefix-cluster summary (codename detector).
        var cap_hist = std.StringHashMap(usize).init(ctx.allocator);
        defer cap_hist.deinit();
        const ClusterInfo = struct { count: usize, example: []const u8 };
        var cap_clusters = std.StringHashMap(ClusterInfo).init(ctx.allocator);
        defer cap_clusters.deinit();
        for (cap_results.items) |cr| {
            for (cr.cats[0..cr.cat_count]) |cat| {
                const g = cap_hist.getOrPut(cat) catch continue;
                if (!g.found_existing) g.value_ptr.* = 0;
                g.value_ptr.* += cr.count;
            }
            if (capClusterPrefix(cr.value)) |pfx| {
                const g = cap_clusters.getOrPut(pfx) catch continue;
                if (!g.found_existing) g.value_ptr.* = .{ .count = 0, .example = cr.value };
                g.value_ptr.count += 1;
            }
        }

        const cap_total: usize = cap_results.items.len;
        const cap_offset: usize = @intCast(offset_cap);
        const cap_paginated = if (cap_offset < cap_total) cap_results.items[cap_offset..] else cap_results.items[0..0];
        const cap_returned = if (cap_paginated.len > max_results) cap_paginated[0..max_results] else cap_paginated;

        var buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const cw = &buf.writer;
        cw.writeAll("{\"total_count\":") catch {};
        cw.print("{d}", .{cap_total}) catch {};
        cw.writeAll(",\"returned_count\":") catch {};
        cw.print("{d}", .{cap_returned.len}) catch {};
        cw.writeAll(",\"has_more\":") catch {};
        cw.writeAll(if (cap_offset + cap_returned.len < cap_total) "true" else "false") catch {};
        if (packed_truncated) {
            cw.writeAll(",\"packed_scan_truncated\":true,\"note\":\"embedded-runtime scan hit the 1,000,000-string cap; some bundle markers may be omitted\"") catch {};
        }
        if (cap_doc_id == null) {
            cw.print(",\"searched_docs\":{d}", .{ctx.store.documents.count()}) catch {};
        }
        // v7.16 W2: category histogram (occurrence-weighted) + prefix clusters.
        cw.writeAll(",\"category_histogram\":{") catch {};
        {
            var hist_it = cap_hist.iterator();
            var hist_first = true;
            while (hist_it.next()) |e| {
                if (!hist_first) cw.writeByte(',') catch {};
                hist_first = false;
                json.writeJsonString(cw, e.key_ptr.*) catch {};
                cw.print(":{d}", .{e.value_ptr.*}) catch {};
            }
        }
        cw.writeAll("}") catch {};
        const ClusterRow = struct { prefix: []const u8, count: usize, example: []const u8 };
        var cluster_rows = std.array_list.Managed(ClusterRow).init(ctx.allocator);
        {
            var cl_it = cap_clusters.iterator();
            while (cl_it.next()) |e| {
                if (e.value_ptr.count >= 2) cluster_rows.append(.{ .prefix = e.key_ptr.*, .count = e.value_ptr.count, .example = e.value_ptr.example }) catch {};
            }
            std.sort.pdq(ClusterRow, cluster_rows.items, {}, struct {
                fn lt(_: void, a: ClusterRow, b: ClusterRow) bool {
                    return a.count > b.count;
                }
            }.lt);
        }
        cw.writeAll(",\"clusters\":[") catch {};
        {
            const cl_n = @min(cluster_rows.items.len, 24);
            for (cluster_rows.items[0..cl_n], 0..) |row, i| {
                if (i > 0) cw.writeByte(',') catch {};
                cw.writeAll("{\"prefix\":") catch {};
                json.writeJsonString(cw, row.prefix) catch {};
                cw.print(",\"count\":{d},\"example\":", .{row.count}) catch {};
                json.writeJsonString(cw, row.example) catch {};
                cw.writeByte('}') catch {};
            }
        }
        cw.writeAll("]") catch {};
        cw.writeAll(",\"results\":[") catch {};
        for (cap_returned, 0..) |cr, ci| {
            if (ci > 0) cw.writeByte(',') catch {};
            cw.writeAll("{\"address\":") catch {};
            json.writeAddress(cw, cr.address) catch {};
            cw.writeAll(",\"match\":") catch {};
            json.writeJsonString(cw, cr.value) catch {};
            cw.writeAll(",\"type\":\"capability\"") catch {};
            cw.writeAll(",\"categories\":[") catch {};
            for (cr.cats[0..cr.cat_count], 0..) |cat, cati| {
                if (cati > 0) cw.writeByte(',') catch {};
                json.writeJsonString(cw, cat) catch {};
            }
            cw.writeByte(']') catch {};
            cw.writeAll(",\"confidence\":") catch {};
            cw.writeAll(switch (cr.best_conf) {
                3 => "\"high\"",
                2 => "\"medium\"",
                else => "\"low\"",
            }) catch {};
            if (cr.count > 1) {
                cw.print(",\"count\":{d}", .{cr.count}) catch {};
            }
            if (cr.doc_id) |did| {
                cw.print(",\"doc_id\":{d}", .{did}) catch {};
            }
            if (cr.doc_name) |dn| {
                cw.writeAll(",\"doc_name\":") catch {};
                json.writeJsonString(cw, dn) catch {};
            }
            cw.writeByte('}') catch {};
        }
        cw.writeAll("]}") catch {};

        const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
        const elapsed = timestampMs(ctx.io) - start;
        const resp = json.successResponse(ctx.allocator, "search", result_json, elapsed) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .meta_max_chars = 200_000 };
    }

    // Map string to SearchQueryType (case-insensitive).
    const query_type: types.SearchQueryType = if (std.ascii.eqlIgnoreCase(query_type_str, "name"))
        .name
    else if (std.ascii.eqlIgnoreCase(query_type_str, "string"))
        .string
    else if (std.ascii.eqlIgnoreCase(query_type_str, "callers_of"))
        .callers_of
    else if (std.ascii.eqlIgnoreCase(query_type_str, "callees_of"))
        .callees_of
    else if (std.ascii.eqlIgnoreCase(query_type_str, "procedures"))
        .procedures
    else if (std.ascii.eqlIgnoreCase(query_type_str, "imports"))
        .imports
    else if (std.ascii.eqlIgnoreCase(query_type_str, "calls"))
        .calls
    else if (std.ascii.eqlIgnoreCase(query_type_str, "string_refs"))
        .string_refs
    else if (std.ascii.eqlIgnoreCase(query_type_str, "writers_of"))
        .writers_of
    else {
        const resp = json.errorResponse(ctx.allocator, "search", "unknown query type. Valid: name, string, procedures, imports, calls, callers_of, callees_of, string_refs, capabilities, writers_of", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    const offset_raw: i64 = getInt(params, "offset") orelse 0;
    if (offset_raw < 0) {
        const resp = json.errorResponse(ctx.allocator, "search", "offset must be non-negative", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    const offset: u32 = @intCast(offset_raw);

    // Determine whether to search a single doc or all docs
    const maybe_doc_id = resolveDocId(ctx, params);

    // If doc_id was explicitly provided but couldn't be resolved, return actionable error
    if (maybe_doc_id == null and (getInt(params, "doc_id") != null or getString(params, "doc_id") != null)) {
        return docNotFoundError(ctx, "search");
    }

    var all_results = std.array_list.Managed(types.SearchResult).init(ctx.allocator);

    if (maybe_doc_id) |doc_id| {
        // Single-doc search (existing behavior)
        const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "search");
        const eff = resolveEffectiveDb(entry);
        eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
        defer eff.db.rw_lock.unlockShared(eff.db.io);

        // Translate input address for rebase
        if (address) |a| {
            address = removeRebaseDelta(a, eff.delta);
        }

        // #12: Name-based callers_of/callees_of — resolve pattern to addresses if no address given
        var resolved_address = address;
        if ((query_type == .callers_of or query_type == .callees_of) and address == null and pattern != null) {
            var proc_it = eff.db.procedures.iterator();
            while (proc_it.next()) |proc_entry| {
                if (proc_entry.value_ptr.name) |name| {
                    if (std.mem.indexOf(u8, name, pattern.?) != null) {
                        resolved_address = proc_entry.key_ptr.*;
                        break;
                    }
                }
            }
            if (resolved_address == null) {
                var imp_it = eff.db.imports.iterator();
                while (imp_it.next()) |imp_entry| {
                    if (std.mem.indexOf(u8, imp_entry.value_ptr.name, pattern.?) != null) {
                        // Prefer stub_address (PLT trampoline) — this is what code actually calls.
                        // Fall back to import address (GOT entry) if no stub is known.
                        resolved_address = imp_entry.value_ptr.stub_address orelse imp_entry.key_ptr.*;
                        break;
                    }
                }
            }
        }

        // callees_of: use lazy cached callees lookup
        if (query_type == .callees_of and resolved_address != null) {
            const callees = ensureCalleesCached(eff.entry, eff.db, resolved_address.?, ctx.allocator);
            for (callees) |callee_addr| {
                all_results.append(.{
                    .address = applyRebaseDelta(callee_addr, eff.delta),
                    .match_text = eff.db.resolveName(callee_addr) orelse "unknown",
                    .result_type = "callee",
                }) catch {};
            }
        } else if (query_type == .writers_of and resolved_address != null) {
            // v7.9.1 Q4: byte-scan executable segments for arch-specific
            // static-writer patterns (lui+sw on MIPS32, adrp+str on ARM64).
            findWritersOf(ctx.allocator, eff.entry.doc, resolved_address.?, &all_results, eff.delta) catch {};
            // v7.11 W6: writers_of caps at 100 hits per scan. If we hit the cap,
            // surface a notice so callers know there may be more.
            if (all_results.items.len >= 100) {
                ctx.emitLog("notice", "phora.search", "writers_of: scan budget exhausted at 100 hits — narrow the address or scan a smaller segment for more", "");
            }
        } else {
            const query = types.SearchQuery{
                .pattern = pattern,
                .query_type = query_type,
                .address = resolved_address,
                .max_results = 100000,
                .case_insensitive = case_insensitive,
                .max_xrefs = max_xrefs,
            };

            const results = eff.db.search(ctx.allocator, query) catch {
                const resp = json.errorResponse(ctx.allocator, "search", "search failed", 0) catch return ToolError.OutOfMemory;
                return .{ .json_response = resp, .is_error = true };
            };
            for (results) |r| {
                var rebased_r = r;
                rebased_r.address = applyRebaseDelta(r.address, eff.delta);
                all_results.append(rebased_r) catch {};
            }
        }
    } else {
        // Cross-document search: iterate all loaded documents
        var doc_it = ctx.store.documents.iterator();
        while (doc_it.next()) |doc_entry| {
            const de = doc_entry.value_ptr.*;
            de.db.rw_lock.lockSharedUncancelable(de.db.io);
            defer de.db.rw_lock.unlockShared(de.db.io);

            // Resolve callers_of/callees_of per doc
            var resolved_address = address;
            if ((query_type == .callers_of or query_type == .callees_of) and address == null and pattern != null) {
                var proc_it = de.db.procedures.iterator();
                while (proc_it.next()) |proc_entry| {
                    if (proc_entry.value_ptr.name) |name| {
                        if (std.mem.indexOf(u8, name, pattern.?) != null) {
                            resolved_address = proc_entry.key_ptr.*;
                            break;
                        }
                    }
                }
                if (resolved_address == null) {
                    var imp_it = de.db.imports.iterator();
                    while (imp_it.next()) |imp_entry| {
                        if (std.mem.indexOf(u8, imp_entry.value_ptr.name, pattern.?) != null) {
                            resolved_address = imp_entry.key_ptr.*;
                            break;
                        }
                    }
                }
            }

            // callees_of: use lazy cached callees lookup
            if (query_type == .callees_of and resolved_address != null) {
                const callees = ensureCalleesCached(de, &de.db, resolved_address.?, ctx.allocator);
                for (callees) |callee_addr| {
                    all_results.append(.{
                        .address = callee_addr,
                        .match_text = de.db.resolveName(callee_addr) orelse "unknown",
                        .result_type = "callee",
                        .doc_id = doc_entry.key_ptr.*,
                        .doc_name = std.fs.path.basename(de.doc.path),
                    }) catch {};
                }
            } else {
                const query = types.SearchQuery{
                    .pattern = pattern,
                    .query_type = query_type,
                    .address = resolved_address,
                    .max_results = 100000,
                    .case_insensitive = case_insensitive,
                    .max_xrefs = max_xrefs,
                };

                const doc_results = de.db.search(ctx.allocator, query) catch continue;
                for (doc_results) |r| {
                    var result = r;
                    result.doc_id = doc_entry.key_ptr.*;
                    result.doc_name = std.fs.path.basename(de.doc.path);
                    all_results.append(result) catch {};
                }
            }
        }
    }

    // ========================================================================
    // v7.4.2 F1: __BUN byte-grep fallback for string / string_refs.
    // ========================================================================
    // db.search() only consults the pre-built strings map, which deliberately
    // excludes packed segments (__BUN, etc.) because byte-by-byte indexing at
    // load time costs 200+ s on 100+ MB sections. When the indexed search
    // returns nothing for a packed-segment-bearing binary, we fall through to
    // the on-demand byte-grep used by get_strings Phase 2 — extracted to
    // analysis/strings.zig:searchPackedSegments. Hits are tagged
    // via="byte_grep_fallback" so the LLM can tell where each result came
    // from. For string_refs, hits also carry xref_origin="byte_scan" because
    // we cannot enumerate xrefs into packed bytes (no instructions to scan).
    // fallback_ran: did the byte-grep actually execute (regardless of hits)?
    // fallback_used: did the byte-grep contribute at least one hit to the results?
    // The two are distinct so the serializer can honestly report which segments
    // were scanned vs. which contributed.
    var fallback_ran = false;
    var fallback_used = false;
    var fallback_runtime: ?[]const u8 = null;
    if ((query_type == .string or query_type == .string_refs) and pattern != null) {
        // Single-doc fallback. Cross-doc search currently doesn't run the
        // fallback (would multiply scan cost across N docs); the LLM can
        // re-issue with an explicit doc_id when needed.
        if (maybe_doc_id) |doc_id| {
            const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "search");
            const eff = resolveEffectiveDb(entry);
            // v7.4.3 F1: pagination fix. Fetch max_results + offset hits so the
            // serializer's pagination slice can correctly handle non-zero offset.
            // The previous wiring capped at `max_results - already`, which made
            // total_count under-report and prevented offset from paginating past
            // the cap. The byte-grep is fast (~30-400ms even on 121 MiB) so the
            // over-fetch is cheap.
            const offset_u32: u32 = @intCast(offset);
            const fetch_window: u32 = if (max_results > std.math.maxInt(u32) - offset_u32)
                std.math.maxInt(u32)
            else
                max_results + offset_u32;
            const have_already: u32 = @intCast(all_results.items.len);
            if (strings_mod.hasPackedSegment(&eff.entry.doc) and have_already < fetch_window) {
                eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
                defer eff.db.rw_lock.unlockShared(eff.db.io);

                const remaining: u32 = fetch_window - have_already;
                var packed_results = strings_mod.searchPackedSegments(
                    ctx.allocator,
                    &eff.entry.doc,
                    pattern.?,
                    .{
                        .case_insensitive = case_insensitive,
                        .max_results = remaining,
                        .excerpt_radius = 50,
                    },
                ) catch null;
                if (packed_results) |*pr| {
                    defer pr.deinit();
                    fallback_ran = true; // we ran the byte-grep over packed segments
                    // v7.16 W1: report the actual detected runtime, not a hard-coded "bun".
                    fallback_runtime = strings_mod.detectRuntime(&eff.entry.doc) orelse "packed";
                    if (pr.hits.items.len > 0) {
                        fallback_used = true;
                        for (pr.hits.items) |h| {
                            const result_type_str: []const u8 = if (query_type == .string) "string" else "string_ref";
                            const xref_origin_tag: ?[]const u8 = if (query_type == .string_refs) "byte_scan" else null;
                            all_results.append(.{
                                .address = applyRebaseDelta(h.address, eff.delta),
                                .match_text = h.excerpt,
                                .result_type = result_type_str,
                                .xref_count = 0,
                                .via = "byte_grep_fallback",
                                .xref_origin = xref_origin_tag,
                            }) catch {};
                            if (all_results.items.len >= fetch_window) break;
                        }
                    }
                }
            }
        }
    }

    const results = all_results.items;

    // total_count reflects filtered results (pattern filtering applied in database.search)
    const total_count = results.len;
    const offset_usize: usize = @intCast(offset);
    const paginated = if (offset_usize < results.len) results[offset_usize..] else results[0..0];
    const returned = if (paginated.len > max_results) paginated[0..max_results] else paginated;

    // Serialize search results with summary envelope (#7).
    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;
    w.writeAll("{\"total_count\":") catch {};
    w.print("{d}", .{total_count}) catch {};
    w.writeAll(",\"returned_count\":") catch {};
    w.print("{d}", .{returned.len}) catch {};
    w.writeAll(",\"has_more\":") catch {};
    w.writeAll(if (offset_usize + returned.len < total_count) "true" else "false") catch {};
    // Cross-doc search metadata: how many documents were searched
    if (maybe_doc_id == null) {
        w.print(",\"searched_docs\":{d}", .{ctx.store.documents.count()}) catch {};
    }
    w.writeAll(",\"results\":[") catch {};
    for (returned, 0..) |r, i| {
        if (i > 0) w.writeByte(',') catch {};
        w.writeAll("{\"address\":") catch {};
        json.writeAddress(w, r.address) catch {};
        w.writeAll(",\"match\":") catch {};
        json.writeJsonString(w, r.match_text) catch {};
        w.writeAll(",\"type\":") catch {};
        json.writeJsonString(w, r.result_type) catch {};
        if (r.context) |c| {
            w.writeAll(",\"context\":") catch {};
            json.writeJsonString(w, c) catch {};
        }
        if (r.doc_id) |did| {
            w.print(",\"doc_id\":{d}", .{did}) catch {};
        }
        if (r.doc_name) |dn| {
            w.writeAll(",\"doc_name\":") catch {};
            json.writeJsonString(w, dn) catch {};
        }
        if (r.xref_count) |xc| {
            w.print(",\"xref_count\":{d}", .{xc}) catch {};
        }
        // v7.4.2 F1: fallback provenance fields
        if (r.via) |v| {
            w.writeAll(",\"via\":") catch {};
            json.writeJsonString(w, v) catch {};
        }
        if (r.xref_origin) |xo| {
            w.writeAll(",\"xref_origin\":") catch {};
            json.writeJsonString(w, xo) catch {};
        }
        w.writeByte('}') catch {};
    }
    w.writeAll("]") catch {};

    // v7.4.2 F1: scanned_regions — always emit for single-doc string/string_refs
    // searches, regardless of whether the fallback fired. Walking the segment
    // list gives the LLM a structured "what was actually searched" so a 0-result
    // response can never be a confident-zero. Skip for cross-doc and for query
    // types that don't traverse strings (name, procedures, imports, etc.).
    if (maybe_doc_id != null and (query_type == .string or query_type == .string_refs)) {
        if (ctx.store.get(maybe_doc_id.?)) |sd_entry| {
            const sd_eff = resolveEffectiveDb(sd_entry);
            w.writeAll(",\"scanned_regions\":[") catch {};
            var sr_first = true;
            for (sd_eff.entry.doc.segments) |seg| {
                if (sr_first) {
                    sr_first = false;
                } else {
                    w.writeByte(',') catch {};
                }
                w.writeAll("{\"name\":") catch {};
                json.writeJsonString(w, seg.name) catch {};
                if (strings_mod.isPackedSegment(seg.name)) {
                    w.writeAll(",\"kind\":\"packed_runtime\"") catch {};
                    if (fallback_ran) {
                        // The byte-grep ran over this segment. Report it as
                        // scanned, regardless of whether it found anything.
                        w.writeAll(",\"fully_scanned\":true,\"via\":\"byte_grep_fallback\"") catch {};
                    } else {
                        // The fallback didn't run (e.g. results already at
                        // max_results from the indexed path, or fallback
                        // disabled). Be honest: this segment was NOT scanned.
                        w.writeAll(",\"fully_scanned\":false,\"skipped_reason\":\"fallback_not_run\"") catch {};
                    }
                } else if (seg.permissions.execute and !seg.permissions.write) {
                    // v7.12 W1: for string_refs the xref index already covers
                    // executable segments (ARM64 adrp+add, MIPS32 lui+addiu,
                    // x86_64 lea rip-rel — all live IN code). Report code as
                    // scanned via xref_index so the LLM doesn't think we
                    // missed anything; for raw `string` scans the byte content
                    // truly isn't searched in code, so keep skipping there.
                    if (query_type == .string_refs) {
                        if (sd_eff.db.xrefs.refs_from.count() > 0) {
                            w.writeAll(",\"kind\":\"code\",\"fully_scanned\":true,\"via\":\"xref_index\"") catch {};
                        } else {
                            w.writeAll(",\"kind\":\"code\",\"fully_scanned\":false,\"skipped_reason\":\"xref_index_empty\"") catch {};
                        }
                    } else {
                        w.writeAll(",\"kind\":\"code\",\"fully_scanned\":false,\"skipped_reason\":\"code_section\"") catch {};
                    }
                } else if (seg.permissions.read) {
                    w.writeAll(",\"kind\":\"data\",\"fully_scanned\":true") catch {};
                } else {
                    w.writeAll(",\"kind\":\"other\",\"fully_scanned\":false,\"skipped_reason\":\"unreadable\"") catch {};
                }
                w.writeByte('}') catch {};
            }
            w.writeByte(']') catch {};
            w.writeAll(",\"fallback_used\":") catch {};
            w.writeAll(if (fallback_used) "true" else "false") catch {};
            if (fallback_runtime) |rh| {
                w.writeAll(",\"runtime_hint\":") catch {};
                json.writeJsonString(w, rh) catch {};
            }
        }
    }

    w.writeByte('}') catch {};

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "search", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .meta_max_chars = 200_000 };
}

fn computeSectionEntropy(data: []const u8) f64 {
    if (data.len == 0) return 0.0;
    var freq: [256]u32 = @splat(0);
    for (data) |byte| {
        freq[byte] += 1;
    }
    var entropy: f64 = 0.0;
    const total: f64 = @floatFromInt(data.len);
    for (freq) |count| {
        if (count > 0) {
            const p: f64 = @as(f64, @floatFromInt(count)) / total;
            entropy -= p * std.math.log2(p);
        }
    }
    return entropy;
}

fn handleGetSegments(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_segments", params);
    };
    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_segments");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;
    w.writeByte('[') catch {};
    for (eff.entry.doc.segments, 0..) |seg, i| {
        if (i > 0) w.writeByte(',') catch {};
        w.writeAll("{\"name\":") catch {};
        json.writeJsonString(w, seg.name) catch {};
        w.writeAll(",\"start\":") catch {};
        json.writeAddress(w, applyRebaseDelta(seg.start, eff.delta)) catch {};
        w.print(",\"length\":{d}", .{seg.length}) catch {};
        w.writeAll(",\"permissions\":{") catch {};
        w.print("\"read\":{s},\"write\":{s},\"execute\":{s}", .{
            if (seg.permissions.read) "true" else "false",
            if (seg.permissions.write) "true" else "false",
            if (seg.permissions.execute) "true" else "false",
        }) catch {};
        w.writeAll("},\"sections\":[") catch {};
        for (seg.sections, 0..) |sect, j| {
            if (j > 0) w.writeByte(',') catch {};
            w.writeAll("{\"name\":") catch {};
            json.writeJsonString(w, sect.name) catch {};
            w.writeAll(",\"start\":") catch {};
            json.writeAddress(w, applyRebaseDelta(sect.start, eff.delta)) catch {};
            w.print(",\"length\":{d}", .{sect.length}) catch {};
            // Skip entropy for zerofill sections (no file backing — would read wrong bytes)
            if (sect.length > 0 and !sect.is_zerofill) {
                const end = sect.file_offset + sect.length;
                if (end <= eff.entry.doc.data.len) {
                    const section_data = eff.entry.doc.data[sect.file_offset..end];
                    const ent = computeSectionEntropy(section_data);
                    w.print(",\"entropy\":{d:.2}", .{ent}) catch {};
                }
            }
            w.writeByte('}') catch {};
        }
        w.writeAll("]}") catch {};
    }
    w.writeByte(']') catch {};

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "get_segments", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

fn handleGetCallGraph(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_call_graph", params);
    };
    const root: u64 = @intCast(getInt(params, "root") orelse getInt(params, "address") orelse {
        const resp = json.errorResponse(ctx.allocator, "get_call_graph", "missing required parameter: root", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    });
    const depth: u32 = if (getInt(params, "depth")) |d| @min(@as(u32, @intCast(d)), 5) else 5;
    const max_nodes: usize = if (getInt(params, "max_nodes")) |m| @intCast(@max(m, 1)) else 200;
    const direction_str = getString(params, "direction") orelse "forward";

    // Parse include flags for inline node details
    var inc_strings = false;
    var inc_calls = false;
    var inc_size = false;
    if (getArray(params, "include")) |inc_arr| {
        for (inc_arr.array.items) |v| {
            if (v == .string) {
                const s = v.string;
                if (std.ascii.eqlIgnoreCase(s, "strings")) inc_strings = true else if (std.ascii.eqlIgnoreCase(s, "calls")) inc_calls = true else if (std.ascii.eqlIgnoreCase(s, "size")) inc_size = true;
            }
        }
    }

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_call_graph");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    // Translate input root address
    const eff_root = removeRebaseDelta(root, eff.delta);

    // Build call graph by traversing xrefs.
    var nodes = std.array_list.Managed(types.CallGraphNode).init(ctx.allocator);
    var graph_edges = std.array_list.Managed(types.CallGraphEdge).init(ctx.allocator);
    var edge_set = std.AutoHashMap(u128, void).init(ctx.allocator); // dedup edges
    defer edge_set.deinit();
    var visited = std.AutoHashMap(u64, void).init(ctx.allocator);
    defer visited.deinit();

    const forward = std.ascii.eqlIgnoreCase(direction_str, "forward") or std.ascii.eqlIgnoreCase(direction_str, "bidirectional");
    const backward = std.ascii.eqlIgnoreCase(direction_str, "backward") or std.ascii.eqlIgnoreCase(direction_str, "bidirectional");

    // BFS traversal.
    var queue = std.array_list.Managed(struct { addr: u64, depth: u32 }).init(ctx.allocator);
    defer queue.deinit();

    queue.append(.{ .addr = eff_root, .depth = 0 }) catch {};

    var nodes_truncated = false;
    while (queue.items.len > 0) {
        const item = queue.orderedRemove(0);
        if (visited.contains(item.addr)) continue;
        if (nodes.items.len >= max_nodes) {
            nodes_truncated = true;
            break;
        }
        visited.put(item.addr, {}) catch continue;

        nodes.append(.{
            .address = item.addr,
            .name = eff.db.resolveName(item.addr),
            .depth = item.depth,
        }) catch continue;

        if (item.depth >= depth) continue;

        if (forward) {
            // Follow callees: use pre-built call_index for O(1) lookup per proc.
            if (eff.entry.call_index) |ci| {
                if (ci.get(item.addr)) |callees| {
                    for (callees) |callee_addr| {
                        {
                            const ek = @as(u128, item.addr) << 64 | callee_addr;
                            if (!edge_set.contains(ek)) {
                                edge_set.put(ek, {}) catch {};
                                graph_edges.append(.{ .from = item.addr, .to = callee_addr }) catch {};
                            }
                        }
                        if (!visited.contains(callee_addr)) {
                            queue.append(.{ .addr = callee_addr, .depth = item.depth + 1 }) catch {};
                        }
                    }
                }
            } else {
                // Lazily build and cache callees for this procedure
                const callees = ensureCalleesCached(eff.entry, eff.db, item.addr, ctx.allocator);
                for (callees) |callee_addr| {
                    graph_edges.append(.{ .from = item.addr, .to = callee_addr }) catch {};
                    if (!visited.contains(callee_addr)) {
                        queue.append(.{ .addr = callee_addr, .depth = item.depth + 1 }) catch {};
                    }
                }
            }
        }
        if (backward) {
            // Follow callers: find all call xrefs targeting this address.
            const refs = eff.db.xrefs.getRefsTo(item.addr);
            for (refs) |xref| {
                if (xref.xref_type == .call) {
                    // Resolve calling instruction to its containing procedure
                    const caller_addr = if (eff.db.getProcedureContaining(xref.from)) |p| p.entry else xref.from;
                    {
                        const ek = @as(u128, caller_addr) << 64 | item.addr;
                        if (!edge_set.contains(ek)) {
                            edge_set.put(ek, {}) catch {};
                            graph_edges.append(.{ .from = caller_addr, .to = item.addr }) catch {};
                        }
                    }
                    if (!visited.contains(caller_addr)) {
                        queue.append(.{ .addr = caller_addr, .depth = item.depth + 1 }) catch {};
                    }
                }
            }
        }
    }

    // Serialize call graph with rebase delta applied to output addresses.
    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;
    w.writeAll("{\"nodes\":[") catch {};
    for (nodes.items, 0..) |node, i| {
        if (i > 0) w.writeByte(',') catch {};
        w.writeAll("{\"address\":") catch {};
        json.writeAddress(w, applyRebaseDelta(node.address, eff.delta)) catch {};
        if (node.name) |n| {
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, n) catch {};
        }
        w.print(",\"depth\":{d}", .{node.depth}) catch {};

        // Inline details if requested
        if (inc_size or inc_strings or inc_calls) {
            if (eff.db.getProcedure(node.address)) |proc| {
                if (inc_size) {
                    w.print(",\"size\":{d}", .{proc.size}) catch {};
                }
                if (inc_calls) {
                    // Use call_index for O(1) lookup (C2 fix)
                    const callees: []const u64 = if (eff.entry.call_index) |ci|
                        (ci.get(node.address) orelse &[_]u64{})
                    else
                        proc.calls;
                    if (callees.len > 0) {
                        w.writeAll(",\"calls\":[") catch {};
                        for (callees, 0..) |callee, ci_idx| {
                            if (ci_idx > 0) w.writeByte(',') catch {};
                            json.writeAddress(w, applyRebaseDelta(callee, eff.delta)) catch {};
                        }
                        w.writeByte(']') catch {};
                    }
                }
                if (inc_strings) {
                    // Find strings via O(log N) range query
                    const p_end = proc.entry + @max(proc.size, 1);
                    w.writeAll(",\"strings\":[") catch {};
                    var str_i: u32 = 0;
                    const str_range = eff.db.xrefs.getRefsFromRange(proc.entry, p_end);
                    for (str_range) |xref| {
                        if (str_i >= 5) break;
                        if (xref.xref_type == .data_read) {
                            const found = eff.db.getString(xref.to) orelse eff.db.getString(xref.to & ~@as(u64, 0xFFF));
                            if (found) |str| {
                                if (str_i > 0) w.writeByte(',') catch {};
                                json.writeJsonString(w, str.value[0..@min(str.value.len, 60)]) catch {};
                                str_i += 1;
                            }
                        }
                    }
                    w.writeByte(']') catch {};
                }
            }
        }
        w.writeByte('}') catch {};
    }
    w.writeAll("],\"edges\":[") catch {};
    for (graph_edges.items, 0..) |edge, i| {
        if (i > 0) w.writeByte(',') catch {};
        w.writeAll("{\"from\":") catch {};
        json.writeAddress(w, applyRebaseDelta(edge.from, eff.delta)) catch {};
        w.writeAll(",\"to\":") catch {};
        json.writeAddress(w, applyRebaseDelta(edge.to, eff.delta)) catch {};
        w.writeByte('}') catch {};
    }
    w.writeAll("]") catch {};
    if (nodes_truncated) {
        w.print(",\"truncated\":true,\"max_nodes\":{d}", .{max_nodes}) catch {};
    }
    w.writeByte('}') catch {};

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "get_call_graph", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .meta_max_chars = 200_000 };
}

/// Decode the terminator itself: a predicated Thumb BX has a fallthrough
/// successor but still lacks a known taken target. Pagination is unrelated.
fn hasUnresolvedIndirectJump(entry: *DocumentEntry, block: types.BasicBlock) bool {
    if (block.terminator != .jump and block.terminator != .branch) return false;
    const info = resolveRawBytesInfo(entry, block.start) orelse return false;
    const arch = entry.doc.arch;
    const decode_fn: cfg_mod.DecodeFn = if (arch == .arm32) &cfg_mod.arm32CfgDecode else if (arch == .x86) &cfg_mod.x86CfgDecode else if (arch == .x86_64) &cfg_mod.x86_64CfgDecode else if (arch == .mips32) &mips32CfgDecode else &arm64CfgDecode;
    const end = block.start +| block.size;
    var address = if ((arch == .arm64 or arch == .mips32) and block.size >= 4) end - 4 else block.start;
    while (address < end) {
        const offset = info.file_offset + (address - info.section_base);
        if (offset >= entry.doc.data.len) return false;
        const raw = entry.doc.data[@intCast(offset)..][0..@intCast(@min(end - address, entry.doc.data.len - offset))];
        const decoded = decode_fn(raw, address);
        if (decoded.size == 0 or decoded.size > raw.len) return false;
        address += decoded.size;
        if (address == end) return decoded.is_branch and !decoded.is_call and !decoded.is_return and decoded.branch_target == null;
    }
    return false;
}

/// Cache an immutable graph with store lifetime. Analysis allocations are
/// temporary; Database.cacheCfg copies every block, adjacency and edge slice.
fn ensureFunctionCfg(allocator: Allocator, proc: types.Procedure, db: *Database, entry: *DocumentEntry) ?types.CfgResult {
    if (entry.doc.arch == .mips32) return null;
    if (db.getCachedCfg(proc.entry)) |cached| return cached;
    if (proc.size > 1024 * 1024) return null;
    const info = resolveRawBytesInfo(entry, proc.entry) orelse return null;
    const arch = entry.doc.arch;
    const decoder: cfg_mod.DecodeFn = if (arch == .arm32) &cfg_mod.arm32CfgDecode else if (arch == .x86) &cfg_mod.x86CfgDecode else if (arch == .x86_64) &cfg_mod.x86_64CfgDecode else &arm64CfgDecode;
    // An unknown extent is only a request-local preview. Caching its 64-byte
    // fallback would truncate a later lift that discovers a longer function.
    if (proc.size == 0)
        return cfg_mod.buildCfgWithRecovery(allocator, &entry.doc, info.file_offset, info.section_base, proc.entry, 64, decoder) catch null;
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const built = cfg_mod.buildCfgWithRecovery(scratch.allocator(), &entry.doc, info.file_offset, info.section_base, proc.entry, proc.size, decoder) catch return null;
    db.cacheCfg(proc.entry, built) catch return null;
    return db.getCachedCfg(proc.entry);
}

fn handleGetCfg(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_cfg", params);
    };
    const func_addr: u64 = @intCast(getInt(params, "function_address") orelse getInt(params, "address") orelse getInt(params, "addr") orelse {
        const resp = json.errorResponse(ctx.allocator, "get_cfg", "missing required parameter: function_address", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    });

    const instruction_view = getString(params, "instruction_view");
    if (params.object.get("instruction_view") != null and (instruction_view == null or (!eql(instruction_view.?, "execution") and !eql(instruction_view.?, "disassembly")))) {
        const resp = try json.errorResponse(ctx.allocator, "get_cfg", "instruction_view must be execution or disassembly", 0);
        return .{ .json_response = resp, .is_error = true };
    }
    const execution_view = if (instruction_view) |view| eql(view, "execution") else false;
    const include_disasm = execution_view or (getBool(params, "include_disassembly") orelse false);

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_cfg");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    if (execution_view and (eff.entry.doc.arch != .arm64 or eff.delta != 0)) {
        const resp = try json.errorResponse(ctx.allocator, "get_cfg", if (eff.delta != 0)
            "execution view is unavailable for rebased documents; request instruction_view=disassembly with include_disassembly=true, or execution on the original parent document and original function address"
        else
            "execution view supports ARM64 only; request instruction_view=disassembly with include_disassembly=true for this architecture", 0);
        return .{ .json_response = resp, .is_error = true };
    }

    if (eff.entry.doc.arch == .mips32) {
        const resp = json.errorResponse(ctx.allocator, "get_cfg", "MIPS32 CFG not yet supported (delay slot handling required). Use disassemble_range for instruction-level analysis.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    // Translate input address
    const eff_func_addr = removeRebaseDelta(func_addr, eff.delta);

    const proc = eff.db.getProcedure(eff_func_addr) orelse eff.db.getProcedureContaining(eff_func_addr);
    const cfg_result = if (proc) |p| ensureFunctionCfg(ctx.allocator, p, eff.db, eff.entry) else null;

    const final_cfg = cfg_result orelse {
        // #13: include the address that failed
        const err_msg = std.fmt.allocPrint(ctx.allocator, "no CFG available for address 0x{x}", .{func_addr}) catch "no CFG available for address";
        const resp = json.errorResponse(ctx.allocator, "get_cfg", err_msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    const offset: usize = @intCast(@max(getInt(params, "offset") orelse 0, 0));
    const max_blocks: usize = @intCast(@min(@max(getInt(params, "max_blocks") orelse 64, 1), 256));
    const page_start = @min(offset, final_cfg.basic_blocks.len);
    var page_end = @min(page_start + max_blocks, final_cfg.basic_blocks.len);
    var page_edges = std.array_list.Managed(types.CfgEdge).init(ctx.allocator);
    defer page_edges.deinit();
    for (final_cfg.edges) |edge| {
        for (final_cfg.basic_blocks[page_start..page_end]) |block| {
            if (edge.from == block.start) {
                try page_edges.append(edge);
                break;
            }
        }
    }
    const loop_evidence = loops_mod.derive(final_cfg.basic_blocks, final_cfg.edges, if (proc) |p| p.entry else eff_func_addr);
    var page_cfg = types.CfgResult{ .basic_blocks = final_cfg.basic_blocks[page_start..page_end], .edges = page_edges.items };

    // Note: CFG addresses in output are from the parent db; we need to apply delta.
    // For simplicity, we serialize and the addresses are already in the parent's space.
    // We apply delta at the serialization level below.
    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    if (eff.delta == 0) {
        if (execution_view) {
            try writeCfgJsonExecution(&buf.writer, page_cfg, final_cfg, &loop_evidence, page_start, if (proc) |p| p.entry else eff_func_addr, eff.entry, doc_id, ctx.allocator, false);
        } else if (include_disasm) {
            writeCfgJsonWithDisasm(&buf.writer, page_cfg, eff.db, eff.entry) catch return ToolError.OutOfMemory;
        } else {
            writeCfgJson(&buf.writer, page_cfg) catch return ToolError.OutOfMemory;
        }
    } else {
        // Write CFG with rebased addresses
        const cw = &buf.writer;
        cw.writeAll("{\"basic_blocks\":[") catch return ToolError.OutOfMemory;
        for (page_cfg.basic_blocks, 0..) |block, i| {
            if (i > 0) cw.writeByte(',') catch {};
            cw.writeAll("{\"start\":") catch {};
            json.writeAddress(cw, applyRebaseDelta(block.start, eff.delta)) catch {};
            cw.print(",\"size\":{d},\"instruction_count\":{d}", .{ block.size, block.instruction_count }) catch {};
            cw.writeAll(",\"terminator\":\"") catch {};
            cw.writeAll(block.terminator.toString()) catch {};
            cw.writeAll("\",\"successors\":[") catch {};
            for (block.successors, 0..) |succ, j| {
                if (j > 0) cw.writeByte(',') catch {};
                json.writeAddress(cw, applyRebaseDelta(succ, eff.delta)) catch {};
            }
            cw.writeAll("],\"predecessors\":[") catch {};
            for (block.predecessors, 0..) |pred, j| {
                if (j > 0) cw.writeByte(',') catch {};
                json.writeAddress(cw, applyRebaseDelta(pred, eff.delta)) catch {};
            }
            cw.writeAll("]}") catch {};
        }
        cw.writeAll("],\"edges\":[") catch {};
        for (page_cfg.edges, 0..) |edge, i| {
            if (i > 0) cw.writeByte(',') catch {};
            cw.writeAll("{\"from\":") catch {};
            json.writeAddress(cw, applyRebaseDelta(edge.from, eff.delta)) catch {};
            cw.writeAll(",\"to\":") catch {};
            json.writeAddress(cw, applyRebaseDelta(edge.to, eff.delta)) catch {};
            cw.writeAll("}") catch {};
        }
        cw.writeAll("]}") catch {};
    }
    // max_blocks is an upper bound. Prefer a smaller complete instruction
    // page to discarding all inline evidence for an oversized graph page.
    const instruction_page_budget = max_response_chars - @as(usize, if (execution_view) 8192 else 2048);
    while (include_disasm and eff.delta == 0 and buf.written().len > instruction_page_budget and page_end - page_start > 1) {
        page_end = page_start + @max((page_end - page_start) / 2, 1);
        page_edges.clearRetainingCapacity();
        for (final_cfg.edges) |edge| {
            for (final_cfg.basic_blocks[page_start..page_end]) |block| {
                if (edge.from == block.start) {
                    try page_edges.append(edge);
                    break;
                }
            }
        }
        page_cfg = .{ .basic_blocks = final_cfg.basic_blocks[page_start..page_end], .edges = page_edges.items };
        buf.clearRetainingCapacity();
        if (execution_view)
            try writeCfgJsonExecution(&buf.writer, page_cfg, final_cfg, &loop_evidence, page_start, if (proc) |p| p.entry else eff_func_addr, eff.entry, doc_id, ctx.allocator, false)
        else
            try writeCfgJsonWithDisasm(&buf.writer, page_cfg, eff.db, eff.entry);
    }
    var disassembly_omitted = include_disasm and eff.delta != 0;
    if (include_disasm and eff.delta == 0 and buf.written().len > instruction_page_budget) {
        buf.clearRetainingCapacity();
        if (execution_view)
            try writeCfgJsonExecution(&buf.writer, page_cfg, final_cfg, &loop_evidence, page_start, if (proc) |p| p.entry else eff_func_addr, eff.entry, doc_id, ctx.allocator, true)
        else
            writeCfgJson(&buf.writer, page_cfg) catch return ToolError.OutOfMemory;
        disassembly_omitted = true;
    }
    // Append page metadata to the existing graph object without changing its keys.
    buf.writer.end -= 1;
    const pw = &buf.writer;
    try pw.print(",\"total_blocks\":{d},\"returned_blocks\":{d},\"offset\":{d},\"partial\":{},\"disassembly_omitted\":{}", .{
        final_cfg.basic_blocks.len, page_end - page_start, page_start, page_end < final_cfg.basic_blocks.len, disassembly_omitted,
    });
    if (instruction_view) |view| {
        try pw.writeAll(",\"instruction_view\":");
        try json.writeJsonString(pw, view);
    }
    if (execution_view) {
        try pw.writeAll(",\"execution_semantics\":");
        try json.writeJsonString(pw, arm64_steps.text_legend);
        try pw.writeAll(",\"execution_model\":\"a64_local_steps_v1\",\"detailed_provenance_call\":{\"tool\":\"get_cfg\",\"arguments\":{");
        try pw.print("\"doc_id\":{d},\"function_address\":", .{doc_id});
        try json.writeAddress(pw, func_addr);
        try pw.print(",\"offset\":{d},\"max_blocks\":{d},\"include_disassembly\":true,\"instruction_view\":\"disassembly\"}}}}", .{ page_start, max_blocks });
    }
    var unknown_terminator_blocks: usize = 0;
    for (final_cfg.basic_blocks) |block| {
        if (block.terminator == .unknown) unknown_terminator_blocks += 1;
    }
    try pw.print(",\"unknown_terminator_blocks\":{d}", .{unknown_terminator_blocks});
    var unresolved_jumps: usize = 0;
    var recovered_jumps: usize = 0;
    for (final_cfg.basic_blocks) |block| {
        if (hasUnresolvedIndirectJump(eff.entry, block)) {
            // ARM64 BR has no fallthrough: known successors here are validated
            // table cases. A predicated Thumb BX may have only its fallthrough.
            if (eff.entry.doc.arch == .arm64 and block.successors.len > 0)
                recovered_jumps += 1
            else
                unresolved_jumps += 1;
        }
    }
    try pw.print(",\"unresolved_indirect_jumps\":{d},\"recovered_indirect_jumps\":{d},\"edge_coverage\":\"reachable_direct_and_validated_table_branches\",\"coverage_note\":\"partial describes pagination only; unsupported indirect patterns and undecoded paths may be missing\"", .{ unresolved_jumps, recovered_jumps });
    // Reuse the full-graph evidence, including headers outside this page.
    var loop_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    defer loop_buf.deinit();
    try loops_mod.write(&loop_buf.writer, &loop_evidence, final_cfg.basic_blocks, final_cfg.edges, eff.delta, page_start, page_end);
    if (buf.written().len + loop_buf.written().len < max_response_chars - 4096) {
        try pw.writeAll(loop_buf.written());
    } else {
        try pw.writeAll(",\"loop_evidence\":{\"status\":\"omitted_response_budget\",\"semantic_completeness\":\"unknown\",\"loops\":null}");
    }
    if (eff.entry.doc.arch == .arm64 and !execution_view) {
        const Words = struct {
            entry: *DocumentEntry,
            pub fn word(self: @This(), addr: u64) ?u32 {
                const info = resolveRawBytesInfo(self.entry, addr) orelse return null;
                const off = info.file_offset + (addr - info.section_base);
                const data = self.entry.doc.data;
                if (off > data.len or data.len - off < 4) return null;
                return std.mem.readInt(u32, data[off..][0..4], .little);
            }
        };
        var flow_buf = std.Io.Writer.Allocating.init(ctx.allocator);
        defer flow_buf.deinit();
        try register_flow.write(&flow_buf.writer, final_cfg.basic_blocks, final_cfg.edges, Words{ .entry = eff.entry }, eff.delta, page_start, page_end, if (proc) |p| p.entry else eff_func_addr);
        if (buf.written().len + flow_buf.written().len < max_response_chars - 4096) {
            try pw.writeAll(flow_buf.written());
        } else {
            try pw.writeAll(",\"register_flow_evidence\":{\"status\":\"omitted_response_budget\",\"inputs\":null}");
        }
    }
    if (page_end < final_cfg.basic_blocks.len) {
        try pw.print(",\"next_offset\":{d},\"next_call\":{{\"tool\":\"get_cfg\",\"arguments\":{{\"doc_id\":{d},\"function_address\":", .{ page_end, doc_id });
        try json.writeAddress(pw, func_addr);
        try pw.print(",\"offset\":{d},\"max_blocks\":{d},\"include_disassembly\":{}", .{ page_end, max_blocks, include_disasm });
        if (instruction_view) |view| {
            try pw.writeAll(",\"instruction_view\":");
            try json.writeJsonString(pw, view);
        }
        try pw.writeAll("}}");
    }
    if (disassembly_omitted) {
        try pw.print(",\"next_disassembly_call\":{{\"tool\":\"disassemble_range\",\"arguments\":{{\"doc_id\":{d},\"start\":", .{doc_id});
        try json.writeAddress(pw, if (page_cfg.basic_blocks.len > 0) applyRebaseDelta(page_cfg.basic_blocks[0].start, eff.delta) else func_addr);
        try pw.writeAll(",\"byte_length\":256}}");
    }
    try pw.writeByte('}');
    if (buf.written().len > max_response_chars - 2048) {
        buf.deinit();
        const resp = json.errorResponse(ctx.allocator, "get_cfg", "CFG adjacency exceeds the response budget. Retry with max_blocks=1 and include_disassembly=false. If one block still exceeds the limit, use disassemble_range; complete adjacency cannot be returned for this block.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;

    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "get_cfg", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

fn handleGetXrefs(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_xrefs", params);
    };
    const addresses = parseBatchAddresses(ctx.allocator, params) catch {
        const resp = json.errorResponse(ctx.allocator, "get_xrefs", "missing or invalid 'addresses' parameter. Accepts: integer, hex string (\"0x1234\"), or array of integers/hex strings.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    defer ctx.allocator.free(addresses);
    const direction_str = getString(params, "direction") orelse "bidirectional";
    const max_results: usize = if (getInt(params, "max_results")) |m| @intCast(@max(m, 1)) else 200;

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_xrefs");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    const direction: types.XrefDirection = if (std.ascii.eqlIgnoreCase(direction_str, "forward"))
        .forward
    else if (std.ascii.eqlIgnoreCase(direction_str, "backward"))
        .backward
    else
        .bidirectional;

    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var addr_buf: [32]u8 = undefined;

    for (addresses) |addr| {
        const item_start = timestampMs(ctx.io);
        const label_copy = ctx.allocator.dupe(u8, addrStr(&addr_buf, addr)) catch "?";

        // Translate input address
        const eff_addr = removeRebaseDelta(addr, eff.delta);

        // Range query for procedure addresses (find all xrefs within the function)
        const proc_at_addr = eff.db.getProcedure(eff_addr);
        const use_range = proc_at_addr != null and (direction == .forward or direction == .bidirectional);

        var range_from: []const types.Xref = &.{};
        if (use_range) {
            const proc = proc_at_addr.?;
            const proc_end = proc.entry + (if (proc.size > 0) proc.size else 64);
            range_from = eff.db.xrefs.getRefsFromRange(proc.entry, proc_end);
        }

        const point_result = eff.db.xrefs.getXrefs(eff_addr, direction);
        const refs_from = if (use_range and range_from.len > 0) range_from else point_result.from;
        const refs_to = point_result.to;

        // Cap output per direction
        const capped_from = refs_from[0..@min(refs_from.len, max_results)];
        const capped_to = refs_to[0..@min(refs_to.len, max_results)];

        var buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const w = &buf.writer;
        w.writeAll("{\"address\":") catch {};
        json.writeAddress(w, addr) catch {};
        w.writeAll(",\"refs_from\":[") catch {};
        for (capped_from, 0..) |xref, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"to\":") catch {};
            json.writeAddress(w, applyRebaseDelta(xref.to, eff.delta)) catch {};
            w.writeAll(",\"type\":\"") catch {};
            w.writeAll(xrefTypeStr(xref.xref_type)) catch {};
            w.writeAll("\"}") catch {};
        }
        w.writeAll("],\"refs_to\":[") catch {};
        for (capped_to, 0..) |xref, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"from\":") catch {};
            json.writeAddress(w, applyRebaseDelta(xref.from, eff.delta)) catch {};
            w.writeAll(",\"type\":\"") catch {};
            w.writeAll(xrefTypeStr(xref.xref_type)) catch {};
            w.writeAll("\"}") catch {};
        }
        w.writeByte(']') catch {};
        w.print(",\"total_from\":{d},\"total_to\":{d}", .{ refs_from.len, refs_to.len }) catch {};
        if (refs_from.len > max_results or refs_to.len > max_results) {
            w.writeAll(",\"truncated\":true") catch {};
        }
        w.writeByte('}') catch {};

        const result_json = buf.toOwnedSlice() catch {
            items.append(.{ .input = label_copy, .success = false, .err = "serialization error", .time_ms = timestampMs(ctx.io) - item_start }) catch {};
            continue;
        };
        items.append(.{ .input = label_copy, .success = true, .result = result_json, .time_ms = timestampMs(ctx.io) - item_start }) catch {};
    }

    const resp = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

fn handleLift(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "lift", params);
    };
    const addresses = parseBatchAddresses(ctx.allocator, params) catch {
        const resp = json.errorResponse(ctx.allocator, "lift", "missing or invalid 'addresses' parameter. Accepts: integer, hex string (\"0x1234\"), or array of integers/hex strings.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    defer ctx.allocator.free(addresses);
    if (params == .object and params.object.contains("format")) {
        const resp = json.errorResponse(ctx.allocator, "lift", "lift returns heuristic IR only; the format parameter has been removed", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "lift");
    const eff = resolveEffectiveDb(entry);

    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    if (eff.entry.doc.arch == .x86) {
        const resp = json.errorResponse(ctx.allocator, "lift", "32-bit x86 lifting is not yet supported. Use get_cfg and disassemble_range for decoded instruction evidence; this is not a missing-procedure error.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var addr_buf: [32]u8 = undefined;
    const offset: usize = @intCast(@max(getInt(params, "offset") orelse 0, 0));
    const max_results: usize = @intCast(@min(@max(getInt(params, "max_results") orelse 128, 1), 256));
    const page_budget = (max_response_chars - 8192) / @max(addresses.len, 1);

    for (addresses) |addr| {
        const item_start = timestampMs(ctx.io);

        // Translate input address
        const eff_addr = removeRebaseDelta(addr, eff.delta);

        // Look up the procedure and lift on demand if needed
        var proc = eff.db.getProcedure(eff_addr) orelse eff.db.getProcedureContaining(eff_addr);
        var dylib_fallback = false;

        // Auto-fallback for 0x0 (dynamic library with no entry point):
        // find the first real procedure in the database and lift that instead.
        if (proc == null and eff_addr == 0) {
            var proc_it = eff.db.procedures.iterator();
            while (proc_it.next()) |proc_entry| {
                if (proc_entry.value_ptr.entry > 0) {
                    proc = proc_entry.value_ptr.*;
                    dylib_fallback = true;
                    break;
                }
            }
        }

        const label_copy = if (dylib_fallback and proc != null)
            std.fmt.allocPrint(ctx.allocator, "0x0 (dylib fallback -> 0x{x})", .{proc.?.entry}) catch "0x0 (dylib fallback)"
        else
            ctx.allocator.dupe(u8, addrStr(&addr_buf, addr)) catch "?";

        if (proc) |p| {
            ensureLiftedIR(ctx.allocator, p, eff.db, eff.entry);
        }

        if (eff.db.getCachedIR(if (proc) |p| p.entry else eff_addr)) |ir_func| {
            const result_json = irPageJson(ctx.allocator, ir_func, doc_id, if (proc) |p| applyRebaseDelta(p.entry, eff.delta) else addr, offset, max_results, page_budget) catch |err| {
                items.append(.{ .input = label_copy, .success = false, .err = if (err == error.RecordTooLarge) "IR record exceeds this batch's response budget. Retry lift with one address and max_results=1, or use disassemble_range for primary evidence." else "serialization error", .time_ms = timestampMs(ctx.io) - item_start }) catch {};
                continue;
            };
            items.append(.{ .input = label_copy, .success = true, .result = result_json, .time_ms = timestampMs(ctx.io) - item_start }) catch {};
        } else {
            const err_msg = std.fmt.allocPrint(ctx.allocator, "no procedure at address 0x{x}", .{addr}) catch "no procedure at address";
            items.append(.{ .input = label_copy, .success = false, .err = err_msg, .time_ms = timestampMs(ctx.io) - item_start }) catch {};
        }
    }

    const resp = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

/// Lift a procedure to IR on demand and cache the result in the database.
/// When instructions are not already stored (large binaries with lean/fast-load),
/// decodes them on-demand from the raw binary data and adds them to the DB.
fn ensureLiftedIR(allocator: Allocator, proc: types.Procedure, db: *Database, doc_entry: *DocumentEntry) void {
    // x86 32-bit has no lifter yet — skip to avoid garbled interpretation.
    // x86_64 lifter added in v7.7.0.
    if (doc_entry.doc.arch == .x86) return;

    // v7.16 W4: serialize the whole check+lift+put. Callers hold only the
    // SHARED rw_lock, so without this two concurrent lifts on one doc would
    // race the (non-thread-safe) ir_arena + ir_cache. Use the RAW ir_cache map
    // here (not getCachedIR/cacheIR) since those re-acquire ir_mutex.
    db.ir_mutex.lockUncancelable(db.io);
    defer db.ir_mutex.unlock(db.io);

    // Already cached — nothing to do (re-check under the mutex).
    if (db.ir_cache.get(proc.entry) != null) return;

    var lift_proc = proc;
    const is_arm32 = doc_entry.doc.arch == .arm32;
    const is_mips32 = doc_entry.doc.arch == .mips32;
    const is_x86_64 = doc_entry.doc.arch == .x86_64;
    const default_step: u8 = if (is_arm32) 2 else if (is_x86_64) 1 else 4;

    // Resolve the file offset for this procedure's virtual address.
    // Needed for on-demand decoding from raw bytes when instructions aren't stored.
    const raw_info = resolveRawBytesInfo(doc_entry, lift_proc.entry);

    // Estimate size if unknown: scan forward from entry for RET/BX LR/POP {pc}
    if (lift_proc.size == 0) {
        var found_size = false;
        var scan_addr = lift_proc.entry;
        const max_scan: u64 = 4096;
        while (scan_addr < lift_proc.entry + max_scan) {
            if (db.getInstruction(scan_addr)) |inst| {
                const mn = inst.mnemonic;
                if (isReturnMnemonic(mn, is_arm32)) {
                    lift_proc.size = (scan_addr - lift_proc.entry) + inst.size;
                    found_size = true;
                    break;
                }
                scan_addr += inst.size;
            } else {
                // No stored instruction — try decoding from raw bytes
                if (raw_info) |info| {
                    const byte_off = info.file_offset + (scan_addr - info.section_base);
                    if (byte_off + default_step <= doc_entry.doc.data.len) {
                        if (is_arm32) {
                            const decoded = arm32.decode(doc_entry.doc.data[byte_off..], scan_addr);
                            if (isReturnMnemonic(decoded.mnemonic, true)) {
                                lift_proc.size = (scan_addr - lift_proc.entry) + decoded.length;
                                found_size = true;
                                break;
                            }
                            scan_addr += decoded.length;
                        } else if (is_mips32) {
                            const decoded = mips32.decode(doc_entry.doc.data[byte_off..], scan_addr);
                            if (decoded.is_return) {
                                lift_proc.size = (scan_addr - lift_proc.entry) + decoded.length + 4; // +4 for delay slot
                                found_size = true;
                                break;
                            }
                            scan_addr += decoded.length;
                        } else if (is_x86_64) {
                            const x86 = @import("arch/x86_64.zig");
                            const decoded = x86.decode(doc_entry.doc.data[byte_off..], scan_addr);
                            if (decoded.is_return) {
                                lift_proc.size = (scan_addr - lift_proc.entry) + decoded.length;
                                found_size = true;
                                break;
                            }
                            scan_addr += decoded.length;
                        } else {
                            const decoded = arm64.decode(doc_entry.doc.data[byte_off..], scan_addr);
                            if (isReturnMnemonic(decoded.mnemonic, false)) {
                                lift_proc.size = (scan_addr - lift_proc.entry) + decoded.length;
                                found_size = true;
                                break;
                            }
                            scan_addr += decoded.length;
                        }
                    } else break;
                } else break;
            }
        }
        if (!found_size) lift_proc.size = 64; // fallback
    }

    // Ensure instructions exist in the DB for the procedure's address range.
    // If they don't (lean/fast-load mode), decode from raw bytes and store them.
    if (raw_info) |info| {
        var decode_addr = lift_proc.entry;
        const proc_end = lift_proc.entry + lift_proc.size;
        while (decode_addr < proc_end) {
            if (db.getInstruction(decode_addr)) |existing| {
                decode_addr += existing.size;
                continue;
            }
            const byte_off = info.file_offset + (decode_addr - info.section_base);
            if (byte_off + default_step > doc_entry.doc.data.len) break;
            if (is_arm32) {
                const inst = arm32.decodeInstruction(doc_entry.doc.data[byte_off..], decode_addr);
                decode_addr += inst.size;
                db.addInstruction(inst) catch {};
            } else if (is_mips32) {
                const inst = mips32.decodeInstruction(doc_entry.doc.data[byte_off..], decode_addr);
                decode_addr += inst.size;
                db.addInstruction(inst) catch {};
            } else if (is_x86_64) {
                const x86 = @import("arch/x86_64.zig");
                const inst = x86.decodeInstruction(doc_entry.doc.data[byte_off..], decode_addr);
                decode_addr += inst.size;
                db.addInstruction(inst) catch {};
            } else {
                const inst = arm64.decodeInstruction(doc_entry.doc.data[byte_off..], decode_addr);
                decode_addr += inst.size;
                db.addInstruction(inst) catch {};
            }
        }
    }

    // Reuse recovered case blocks and real joins when constructing IR.
    // A fallback remains for architectures whose CFG is explicitly unsupported.
    if (ensureFunctionCfg(allocator, lift_proc, db, doc_entry)) |graph| {
        lift_proc.basic_blocks = graph.basic_blocks;
    }

    // Create a synthetic basic block if needed
    const inst_size_avg: u32 = if (is_arm32) 2 else if (is_x86_64) 3 else 4;
    var synthetic_block: [1]types.BasicBlock = undefined;
    if (lift_proc.basic_blocks.len == 0 and lift_proc.size > 0) {
        synthetic_block[0] = .{
            .start = lift_proc.entry,
            .size = lift_proc.size,
            .instruction_count = @intCast(lift_proc.size / inst_size_avg),
            .successors = &.{},
            .predecessors = &.{},
            .terminator = .@"return",
        };
        lift_proc.basic_blocks = &synthetic_block;
    }

    // v7.9.2: use liftProcedureMature so the 6 maturity passes (call_arg_fixup,
    // const_fold, dead_store, stack_slot, fp_alias, reg_to_var) actually run on
    // the IR that gets cached + rendered. Previously called liftProcedure, which
    // bypassed the entire maturity pipeline — so v7.8.0+ pass benefits never
    // reached user-facing IR output.
    //
    // v7.16 W4 (IR-cache cross-request UAF fix): lift into the STORE-OWNED
    // allocator (`db.allocator`), not the per-request arena passed in. The
    // resulting IRFunction (and every string/variable/statement it owns) is
    // cached in `db.ir_cache`, which outlives the request. Allocating it from
    // the request arena meant the next request read freed memory — a UAF only
    // masked today by the deliberate per-request arena leak in server.zig.
    // Same class of bug as `ensureCalleesCached`; here we lift into the db's
    // dedicated IR arena (`db.irAllocator()`) so ALL cached-IR content is freed
    // wholesale on `db.deinit` — no per-string ownership tracking (the trap the
    // v7.15.x series kept hitting). The passed `allocator` is retained for
    // signature compatibility.
    const ir_func = lifter.liftProcedureMatureForArch(db.irAllocator(), &lift_proc, db, doc_entry.doc.arch) catch return;
    db.ir_cache.put(proc.entry, ir_func) catch {}; // raw put — already holding ir_mutex
}

/// Info needed to resolve a virtual address to raw binary bytes.
const RawBytesInfo = struct {
    file_offset: usize,
    section_base: u64,
};

/// Find the executable segment/section containing a virtual address,
/// returning the file offset and section base needed for byte-level access.
/// For ELF binaries, segment-level p_offset mapping is authoritative.
/// For Mach-O, section-level offsets are checked first.
fn resolveRawBytesInfo(doc_entry: *DocumentEntry, addr: u64) ?RawBytesInfo {
    const is_elf = doc_entry.doc.format == .elf;
    for (doc_entry.doc.segments) |seg| {
        if (!seg.permissions.execute) continue;
        // ELF: use segment p_offset directly (authoritative vaddr→file mapping).
        // Check segment first since section headers may be stripped or unreliable.
        if (is_elf) {
            if (addr >= seg.start and addr < seg.start + seg.length) {
                return .{ .file_offset = @intCast(seg.file_offset), .section_base = seg.start };
            }
        } else {
            // Mach-O/other: check sections first (each has its own file offset).
            for (seg.sections) |sec| {
                if (addr >= sec.start and addr < sec.start + sec.length) {
                    return .{ .file_offset = @intCast(sec.file_offset), .section_base = sec.start };
                }
            }
            if (addr >= seg.start and addr < seg.start + seg.length) {
                return .{ .file_offset = @intCast(seg.file_offset), .section_base = seg.start };
            }
        }
    }
    return null;
}

fn handleAnnotate(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "annotate", params);
    };
    const ops_array = getArray(params, "operations") orelse getArray(params, "annotations") orelse {
        const resp = json.errorResponse(ctx.allocator, "annotate", "missing required parameter: operations", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "annotate");
    const eff = resolveEffectiveDb(entry);
    // For rebased docs, lock parent DB first (for set_name symbol writes), then view DB.
    // Fixed ordering prevents deadlocks.
    const is_rebased = entry.rebase_parent != null;
    if (is_rebased) eff.db.rw_lock.lockUncancelable(eff.db.io);
    entry.db.rw_lock.lockUncancelable(entry.db.io);
    defer {
        entry.db.rw_lock.unlock(entry.db.io);
        if (is_rebased) eff.db.rw_lock.unlock(eff.db.io);
    }

    // Parse and validate all operations first (transaction semantics).
    var ops = std.array_list.Managed(types.AnnotateOp).init(ctx.allocator);
    for (ops_array.array.items, 0..) |op_val, op_idx| {
        const op_str = getString(op_val, "op") orelse {
            const err_msg = std.fmt.allocPrint(ctx.allocator, "operation {d}: missing 'op' field", .{op_idx}) catch "missing 'op' field";
            const resp = json.errorResponse(ctx.allocator, "annotate", err_msg, 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        };
        const address: u64 = @intCast(getInt(op_val, "address") orelse {
            const err_msg = std.fmt.allocPrint(ctx.allocator, "operation {d}: missing 'address' field", .{op_idx}) catch "missing 'address' field";
            const resp = json.errorResponse(ctx.allocator, "annotate", err_msg, 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        });
        const value = getString(op_val, "value") orelse {
            const err_msg = std.fmt.allocPrint(ctx.allocator, "operation {d}: missing 'value' field", .{op_idx}) catch "missing 'value' field";
            const resp = json.errorResponse(ctx.allocator, "annotate", err_msg, 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        };

        const op_type: types.AnnotateOpType = if (std.ascii.eqlIgnoreCase(op_str, "set_name") or std.ascii.eqlIgnoreCase(op_str, "rename"))
            .set_name
        else if (std.ascii.eqlIgnoreCase(op_str, "set_comment") or std.ascii.eqlIgnoreCase(op_str, "comment"))
            .set_comment
        else if (std.ascii.eqlIgnoreCase(op_str, "add_tag") or std.ascii.eqlIgnoreCase(op_str, "tag"))
            .add_tag
        else if (std.ascii.eqlIgnoreCase(op_str, "set_type") or std.ascii.eqlIgnoreCase(op_str, "type"))
            .set_type
        else if (std.ascii.eqlIgnoreCase(op_str, "remove_tag") or std.ascii.eqlIgnoreCase(op_str, "untag"))
            .remove_tag
        else {
            const err_msg = std.fmt.allocPrint(ctx.allocator, "operation {d}: unknown op '{s}'. Valid: set_name, set_comment, add_tag, set_type, remove_tag (aliases: rename, comment, tag, type, untag)", .{ op_idx, op_str }) catch "unknown op type";
            const resp = json.errorResponse(ctx.allocator, "annotate", err_msg, 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        };

        ops.append(.{ .op_type = op_type, .address = address, .value = value }) catch return ToolError.OutOfMemory;
    }

    // Fix 12: Empty operations no-op
    if (ops.items.len == 0) {
        const elapsed = timestampMs(ctx.io) - start;
        const resp = json.successResponse(ctx.allocator, "annotate", "{\"applied\":0,\"message\":\"no operations to apply\"}", elapsed) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp };
    }

    // Validate all addresses fall within known segments (rebase-aware).
    for (ops.items) |op| {
        const check_addr = if (eff.delta != 0) removeRebaseDelta(op.address, eff.delta) else op.address;
        if (!isAddressInMutableSegments(check_addr, eff.entry.doc.segments)) {
            const err_msg = std.fmt.allocPrint(ctx.allocator, "address 0x{x} is outside all known segments; use get_segments to see valid ranges", .{op.address}) catch "address outside segments";
            const resp = json.errorResponse(ctx.allocator, "annotate", err_msg, 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        }
    }

    // Snapshot annotation state for rollback on failure.
    // Clone the annotations map so we can restore it if any operation fails.
    var snapshot = std.AutoHashMap(u64, std.array_list.Managed(types.Annotation)).init(ctx.allocator);
    defer snapshot.deinit();
    {
        var snap_it = entry.db.annotations.iterator();
        while (snap_it.next()) |ann_entry| {
            var cloned = std.array_list.Managed(types.Annotation).init(ctx.allocator);
            cloned.appendSlice(ann_entry.value_ptr.items) catch {};
            snapshot.put(ann_entry.key_ptr.*, cloned) catch {};
        }
    }

    // Apply all operations atomically with rollback.
    const now = runtime.awakeMillis(ctx.io);
    var applied: usize = 0;
    var tx_failed = false;
    // Track symbol writes to parent DB for rollback.
    var symbol_writes = std.array_list.Managed(u64).init(ctx.allocator);
    defer symbol_writes.deinit();

    for (ops.items) |op| {
        const kind: types.AnnotationKind = switch (op.op_type) {
            .set_name => .name,
            .set_comment => .comment,
            .add_tag => .tag,
            .set_type => .type_override,
            .remove_tag => .tag,
        };

        entry.db.addAnnotation(.{
            .address = op.address,
            .kind = kind,
            .value = op.value,
            .session_id = ctx.session_id,
            .timestamp = now,
        }) catch {
            tx_failed = true;
            break;
        };

        if (op.op_type == .set_name) {
            // Store symbol at the effective (un-rebased) address so that
            // procedures search can find it via symbols.get(proc.entry).
            const sym_addr = removeRebaseDelta(op.address, eff.delta);
            eff.db.addSymbol(sym_addr, op.value) catch {};
            symbol_writes.append(sym_addr) catch {};
        }
        applied += 1;
    }

    // Rollback on failure: restore annotations from snapshot + undo symbol writes
    if (tx_failed) {
        // Undo symbol writes to parent DB
        for (symbol_writes.items) |sym_addr| {
            eff.db.removeSymbol(sym_addr);
        }

        // Clear current annotations and restore snapshot
        var clear_it = entry.db.annotations.valueIterator();
        while (clear_it.next()) |list| {
            list.deinit();
        }
        entry.db.annotations.clearAndFree();

        var restore_it = snapshot.iterator();
        while (restore_it.next()) |snap_entry| {
            entry.db.annotations.put(snap_entry.key_ptr.*, snap_entry.value_ptr.*) catch {};
        }
        // Prevent snapshot deinit from freeing the restored lists
        snapshot.clearRetainingCapacity();

        const rollback_msg = std.fmt.allocPrint(ctx.allocator, "transaction rolled back: operation {d} of {d} failed", .{ applied + 1, ops.items.len }) catch "transaction rolled back";
        const resp = json.errorResponse(ctx.allocator, "annotate", rollback_msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(
        ctx.allocator,
        "annotate",
        std.fmt.allocPrint(ctx.allocator, "{{\"applied\":{d}}}", .{ops.items.len}) catch "{\"applied\":0}",
        elapsed,
    ) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

fn handleSaveProject(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "save_project", params);
    };
    const path = getString(params, "path") orelse {
        const resp = json.errorResponse(ctx.allocator, "save_project", "missing required parameter: path", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "save_project");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    const file = std.Io.Dir.cwd().createFile(ctx.io, path, .{}) catch |err| {
        const err_msg = std.fmt.allocPrint(ctx.allocator, "cannot create '{s}': {s}", .{ path, @errorName(err) }) catch "cannot create file";
        const resp = json.errorResponse(ctx.allocator, path, err_msg, 0) catch return ToolError.OutOfMemory;
        // v7.11 W6: surface save_project error as a notification.
        ctx.emitLog("error", "phora.project", "save_project failed to create file", "");
        return .{ .json_response = resp, .is_error = true };
    };
    defer file.close(ctx.io);
    const w = NativeFileWriter{ .file = file, .io = ctx.io };

    // Write full .phora project file with all restorable state
    // Use effective entry (parent for rebased views) for data
    const save_doc = &eff.entry.doc;
    w.writeAll("{\"phora_version\":1") catch {};
    w.writeAll(",\"path\":") catch {};
    json.writeJsonString(w, save_doc.path) catch {};
    w.writeAll(",\"format\":") catch {};
    json.writeJsonString(w, save_doc.format.toString()) catch {};
    w.writeAll(",\"arch\":") catch {};
    json.writeJsonString(w, save_doc.arch.toString()) catch {};
    if (save_doc.gp_value) |gp| {
        w.print(",\"gp_value\":{d}", .{gp}) catch {};
    }
    w.writeAll(",\"entry_point\":") catch {};
    json.writeAddress(w, save_doc.entry_point) catch {};

    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(save_doc.data, &source_digest, .{});
    const source_hex = std.fmt.bytesToHex(source_digest, .lower);
    w.writeAll(",\"source_sha256\":") catch {};
    json.writeJsonString(w, &source_hex) catch {};

    // Preserve entry provenance across project round trips.
    w.writeAll(",\"linker_function_starts\":[") catch {};
    for (save_doc.linker_function_starts, 0..) |address, i| {
        if (i > 0) w.writeByte(',') catch {};
        json.writeAddress(w, address) catch {};
    }
    w.writeByte(']') catch {};

    // Procedures
    w.writeAll(",\"procedures\":[") catch {};
    for (save_doc.procedures.items, 0..) |proc, i| {
        if (i > 0) w.writeByte(',') catch {};
        w.writeAll("{\"entry\":") catch {};
        json.writeAddress(w, proc.entry) catch {};
        w.print(",\"size\":{d}", .{proc.size}) catch {};
        if (proc.name) |n| {
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, n) catch {};
        }
        w.writeByte('}') catch {};
    }
    w.writeByte(']') catch {};

    // Strings
    w.writeAll(",\"strings\":[") catch {};
    for (save_doc.strings.items, 0..) |s, i| {
        if (i > 0) w.writeByte(',') catch {};
        w.writeAll("{\"address\":") catch {};
        json.writeAddress(w, s.address) catch {};
        w.print(",\"length\":{d},\"value\":", .{s.length}) catch {};
        json.writeJsonString(w, s.value) catch {};
        w.writeByte('}') catch {};
    }
    w.writeByte(']') catch {};

    // Imports
    w.writeAll(",\"imports\":[") catch {};
    for (save_doc.imports.items, 0..) |imp, i| {
        if (i > 0) w.writeByte(',') catch {};
        w.writeAll("{\"address\":") catch {};
        json.writeAddress(w, imp.address) catch {};
        w.writeAll(",\"name\":") catch {};
        json.writeJsonString(w, imp.name) catch {};
        if (imp.library) |lib| {
            w.writeAll(",\"library\":") catch {};
            json.writeJsonString(w, lib) catch {};
        }
        if (imp.ordinal) |nid| {
            w.print(",\"ordinal\":{d}", .{nid}) catch {};
        }
        w.writeByte('}') catch {};
    }
    w.writeByte(']') catch {};

    // Segments
    w.writeAll(",\"segments\":[") catch {};
    for (save_doc.segments, 0..) |seg, si| {
        if (si > 0) w.writeByte(',') catch {};
        w.writeAll("{\"name\":") catch {};
        json.writeJsonString(w, seg.name) catch {};
        w.writeAll(",\"start\":") catch {};
        json.writeAddress(w, seg.start) catch {};
        w.print(",\"length\":{d}", .{seg.length}) catch {};
        w.print(",\"file_offset\":{d}", .{seg.file_offset}) catch {};
        w.print(",\"file_size\":{d}", .{seg.file_size}) catch {};
        w.writeAll(",\"permissions\":{") catch {};
        w.print("\"read\":{s},\"write\":{s},\"execute\":{s}", .{
            if (seg.permissions.read) "true" else "false",
            if (seg.permissions.write) "true" else "false",
            if (seg.permissions.execute) "true" else "false",
        }) catch {};
        w.writeAll("},\"sections\":[") catch {};
        for (seg.sections, 0..) |sec, sj| {
            if (sj > 0) w.writeByte(',') catch {};
            w.writeAll("{\"name\":") catch {};
            json.writeJsonString(w, sec.name) catch {};
            w.writeAll(",\"start\":") catch {};
            json.writeAddress(w, sec.start) catch {};
            w.print(",\"length\":{d}", .{sec.length}) catch {};
            w.print(",\"file_offset\":{d}", .{sec.file_offset}) catch {};
            w.print(",\"alignment\":{d}", .{sec.alignment}) catch {};
            w.print(",\"is_code\":{s},\"is_zerofill\":{s}", .{
                if (sec.isCode()) "true" else "false",
                if (sec.is_zerofill) "true" else "false",
            }) catch {};
            w.writeByte('}') catch {};
        }
        w.writeAll("]}") catch {};
    }
    w.writeByte(']') catch {};

    // Annotations
    w.writeAll(",\"annotations\":[") catch {};
    var ann_first = true;
    var ann_it = eff.db.annotations.iterator();
    while (ann_it.next()) |ann_entry| {
        for (ann_entry.value_ptr.items) |ann| {
            if (!ann_first) w.writeByte(',') catch {};
            ann_first = false;
            w.writeAll("{\"address\":") catch {};
            json.writeAddress(w, ann.address) catch {};
            w.writeAll(",\"kind\":") catch {};
            json.writeJsonString(w, @tagName(ann.kind)) catch {};
            w.writeAll(",\"value\":") catch {};
            json.writeJsonString(w, ann.value) catch {};
            w.writeByte('}') catch {};
        }
    }
    w.writeByte(']') catch {};

    // Serialize xrefs (deduplicated by from+to+type triple)
    w.writeAll(",\"xrefs\":[") catch {};
    {
        const XrefKey = struct { from: u64, to: u64, kind: u8 };
        const XrefKeyCtx = struct {
            pub fn hash(_: @This(), k: XrefKey) u64 {
                var h = std.hash.Wyhash.init(0);
                h.update(std.mem.asBytes(&k.from));
                h.update(std.mem.asBytes(&k.to));
                h.update(std.mem.asBytes(&k.kind));
                return h.final();
            }
            pub fn eql(_: @This(), a: XrefKey, b: XrefKey) bool {
                return a.from == b.from and a.to == b.to and a.kind == b.kind;
            }
        };
        var xref_seen = std.HashMap(XrefKey, void, XrefKeyCtx, 80).init(ctx.allocator);
        defer xref_seen.deinit();
        var xref_first = true;
        var xref_it = eff.db.xrefs.refs_from.iterator();
        while (xref_it.next()) |xref_entry| {
            for (xref_entry.value_ptr.items) |xref| {
                const key = XrefKey{ .from = xref.from, .to = xref.to, .kind = @backingInt(xref.xref_type) };
                if (xref_seen.contains(key)) continue;
                xref_seen.put(key, {}) catch {};
                if (!xref_first) w.writeByte(',') catch {};
                xref_first = false;
                w.writeAll("{\"f\":") catch {};
                json.writeAddress(w, xref.from) catch {};
                w.writeAll(",\"t\":") catch {};
                json.writeAddress(w, xref.to) catch {};
                w.writeAll(",\"k\":\"") catch {};
                w.writeAll(@tagName(xref.xref_type)) catch {};
                w.writeAll("\"}") catch {};
            }
        }
    }
    w.writeByte(']') catch {};

    w.writeByte('}') catch {};

    const elapsed = timestampMs(ctx.io) - start;
    const result_str = std.fmt.allocPrint(ctx.allocator, "{{\"success\":true,\"path\":\"{s}\"}}", .{path}) catch return ToolError.OutOfMemory;
    const resp = json.successResponse(ctx.allocator, path, result_str, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

fn handleLoadProject(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const path = getString(params, "path") orelse {
        const resp = json.errorResponse(ctx.allocator, "load_project", "missing required parameter: path", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    // Read the .phora file.
    const file = std.Io.Dir.cwd().openFile(ctx.io, path, .{}) catch |err| {
        const err_msg = std.fmt.allocPrint(ctx.allocator, "cannot open '{s}': {s}", .{ path, @errorName(err) }) catch "cannot open project file";
        const resp = json.errorResponse(ctx.allocator, path, err_msg, 0) catch return ToolError.OutOfMemory;
        // v7.11 W6: surface load_project open error as a notification.
        ctx.emitLog("error", "phora.project", "load_project: cannot open project file", "");
        return .{ .json_response = resp, .is_error = true };
    };
    defer file.close(ctx.io);

    const data = readNativeFileToEndAlloc(file, ctx.io, ctx.allocator, max_binary_size) catch |err| {
        const err_msg = std.fmt.allocPrint(ctx.allocator, "cannot read '{s}': {s}", .{ path, @errorName(err) }) catch "read error";
        const resp = json.errorResponse(ctx.allocator, path, err_msg, 0) catch return ToolError.OutOfMemory;
        ctx.emitLog("error", "phora.project", "load_project: read error", "");
        return .{ .json_response = resp, .is_error = true };
    };

    // Parse .phora JSON and rebuild document + database
    const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, data, .{}) catch {
        const resp = json.errorResponse(ctx.allocator, path, "invalid project JSON", 0) catch return ToolError.OutOfMemory;
        ctx.emitLog("error", "phora.project", "load_project: invalid project JSON", "");
        return .{ .json_response = resp, .is_error = true };
    };
    const root = parsed.value;

    // v7.15.0 B1: doc/db/path/data live on store_alloc so the doc survives
    // arena teardown. Note: this handler reads many fields out of the parsed
    // JSON (which still lives in the request arena) and stores them as direct
    // slices on the doc — those are tracked separately in pass 2 / via deep
    // copy where needed. For pass 1 the critical fix is the entry+db+data
    // ownership.
    const store_alloc = ctx.store.allocator;
    const doc_id = ctx.store.nextId();
    const entry = store_alloc.create(DocumentEntry) catch return ToolError.OutOfMemory;

    // Restore the original binary path and re-read bytes for on-demand decoding
    const orig_path_raw = getString(root, "path") orelse path;
    const orig_path = store_alloc.dupe(u8, orig_path_raw) catch return ToolError.OutOfMemory;
    var binary_data: []const u8 = &.{};
    var reload_warning: ?[]const u8 = null;
    if (std.Io.Dir.cwd().openFile(ctx.io, orig_path, .{})) |reload_file| {
        defer reload_file.close(ctx.io);
        binary_data = readNativeFileToEndAlloc(reload_file, ctx.io, store_alloc, MAX_BINARY_SIZE) catch blk: {
            reload_warning = "original binary too large or unreadable; disassembly unavailable";
            break :blk &.{};
        };
    } else |_| {
        reload_warning = "original binary not found at saved path; disassembly unavailable";
    }
    var source_matches = false;
    if (getString(root, "source_sha256")) |saved_digest| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(binary_data, &digest, .{});
        const current_hex = std.fmt.bytesToHex(digest, .lower);
        source_matches = reload_warning == null and std.mem.eql(u8, saved_digest, &current_hex);
        if (!source_matches and reload_warning == null)
            reload_warning = "source binary has changed since save; restored analysis is stale and linker provenance is omitted. Use load_binary to refresh analysis.";
    }
    entry.* = .{
        .doc = types.Document.init(store_alloc, doc_id, orig_path, binary_data),
        .db = Database.init(store_alloc, ctx.io),
    };

    // Restore format and arch
    if (getString(root, "format")) |fmt| {
        if (eql(fmt, "macho")) entry.doc.format = .macho else if (eql(fmt, "elf")) entry.doc.format = .elf else if (eql(fmt, "pe")) entry.doc.format = .pe else if (eql(fmt, "pbp")) entry.doc.format = .pbp;
    }
    if (getString(root, "arch")) |arch| {
        if (eql(arch, "arm64")) entry.doc.arch = .arm64 else if (eql(arch, "x86_64")) entry.doc.arch = .x86_64 else if (eql(arch, "arm32")) entry.doc.arch = .arm32 else if (eql(arch, "x86")) entry.doc.arch = .x86 else if (eql(arch, "mips32")) entry.doc.arch = .mips32;
    }
    entry.doc.entry_point = @intCast(getInt(root, "entry_point") orelse 0);
    entry.doc.gp_value = if (getInt(root, "gp_value")) |g| @as(?u64, @bitCast(g)) else null;

    // Restore segments
    if (getArray(root, "segments")) |segs_arr| {
        var segments = std.array_list.Managed(types.Segment).init(ctx.allocator);
        for (segs_arr.array.items) |sv| {
            const seg_name = getString(sv, "name") orelse continue;
            const seg_start: u64 = @intCast(getInt(sv, "start") orelse continue);
            const seg_length: u64 = @intCast(getInt(sv, "length") orelse 0);
            const seg_file_offset: u64 = @intCast(getInt(sv, "file_offset") orelse 0);
            const seg_file_size: u64 = @intCast(getInt(sv, "file_size") orelse 0);

            // Parse permissions
            var perms = types.SegmentPermissions{};
            if (getObject(sv, "permissions")) |pobj| {
                perms.read = getBool(pobj, "read") orelse false;
                perms.write = getBool(pobj, "write") orelse false;
                perms.execute = getBool(pobj, "execute") orelse false;
            }

            // Parse sections
            var sections = std.array_list.Managed(types.Section).init(ctx.allocator);
            if (getArray(sv, "sections")) |secs_arr| {
                for (secs_arr.array.items) |secv| {
                    const sec_name = getString(secv, "name") orelse continue;
                    const sec_start: u64 = @intCast(getInt(secv, "start") orelse continue);
                    const sec_length: u64 = @intCast(getInt(secv, "length") orelse 0);
                    const sec_file_offset: u64 = @intCast(getInt(secv, "file_offset") orelse 0);
                    const sec_alignment: u32 = @intCast(getInt(secv, "alignment") orelse 0);
                    sections.append(.{
                        .name = sec_name,
                        .start = sec_start,
                        .length = sec_length,
                        .file_offset = sec_file_offset,
                        .alignment = sec_alignment,
                        .is_code = getBool(secv, "is_code"),
                        .is_zerofill = getBool(secv, "is_zerofill") orelse false,
                    }) catch {};
                }
            }

            segments.append(.{
                .name = seg_name,
                .start = seg_start,
                .length = seg_length,
                .sections = sections.toOwnedSlice() catch &.{},
                .permissions = perms,
                .file_offset = seg_file_offset,
                .file_size = seg_file_size,
            }) catch {};
        }
        entry.doc.segments = segments.toOwnedSlice() catch &.{};
    }

    // Old projects lack this optional field. Reject the entire list if it is
    // unsorted, duplicated or outside code, rather than inventing provenance.
    if (source_matches) if (getArray(root, "linker_function_starts")) |starts_json| {
        var starts = std.array_list.Managed(u64).init(store_alloc);
        defer starts.deinit();
        var valid = true;
        for (starts_json.array.items) |value| {
            const address: u64 = switch (value) {
                .integer => |n| if (n >= 0) @intCast(n) else {
                    valid = false;
                    break;
                },
                .string => |v| std.fmt.parseInt(u64, v, 0) catch {
                    valid = false;
                    break;
                },
                else => {
                    valid = false;
                    break;
                },
            };
            if (entry.doc.codeRangeEnd(address) == null or (starts.items.len > 0 and address <= starts.items[starts.items.len - 1])) {
                valid = false;
                break;
            }
            try starts.append(address);
        }
        if (valid) entry.doc.linker_function_starts = try starts.toOwnedSlice();
    };

    // Pre-scan annotations to find addresses with user-set names (these take priority over proc names)
    var ann_name_addrs = std.AutoHashMap(u64, []const u8).init(ctx.allocator);
    defer ann_name_addrs.deinit();
    if (getArray(root, "annotations")) |anns_pre| {
        for (anns_pre.array.items) |av| {
            const ann_addr_pre: u64 = @intCast(getInt(av, "address") orelse continue);
            const ann_val_pre = getString(av, "value") orelse continue;
            const kind_str_pre = getString(av, "kind") orelse "comment";
            if (eql(kind_str_pre, "name")) {
                ann_name_addrs.put(ann_addr_pre, ann_val_pre) catch {};
            }
        }
    }

    // Restore procedures (skip name if annotation overrides it)
    if (getArray(root, "procedures")) |procs_arr| {
        for (procs_arr.array.items) |pv| {
            const proc_entry: u64 = @intCast(getInt(pv, "entry") orelse continue);
            const proc_size: u64 = @intCast(getInt(pv, "size") orelse 0);
            const proc_name = if (ann_name_addrs.get(proc_entry)) |ann_name| ann_name else getString(pv, "name");
            const proc = types.Procedure{
                .entry = proc_entry,
                .size = proc_size,
                .name = proc_name,
            };
            entry.doc.procedures.append(proc) catch {};
            entry.db.addProcedure(proc) catch {};
        }
    }

    // Restore strings
    if (getArray(root, "strings")) |strs_arr| {
        for (strs_arr.array.items) |sv| {
            const str_addr: u64 = @intCast(getInt(sv, "address") orelse continue);
            const str_val = getString(sv, "value") orelse continue;
            const str_len: u32 = @intCast(getInt(sv, "length") orelse @as(i64, @intCast(str_val.len)));
            const s = types.String{
                .address = str_addr,
                .value = str_val,
                .length = str_len,
            };
            entry.doc.strings.append(s) catch {};
            entry.db.addString(s) catch {};
        }
    }

    // Restore imports (apply synthetic address fixup for address=0 entries)
    if (getArray(root, "imports")) |imps_arr| {
        for (imps_arr.array.items, 0..) |iv, imp_idx| {
            var imp_addr: u64 = @intCast(getInt(iv, "address") orelse continue);
            const imp_name = getString(iv, "name") orelse continue;
            const imp_lib = getString(iv, "library");
            const imp_ordinal = if (getInt(iv, "ordinal")) |n| @as(?u32, @intCast(@as(u64, @bitCast(n)))) else null;
            // Same fixup as handleLoadBinary: prevent HashMap key collisions for address=0 imports
            if (imp_addr == 0) imp_addr = 0xFFFF000000000000 + imp_idx;
            const imp = types.Import{
                .address = imp_addr,
                .name = imp_name,
                .library = imp_lib,
                .ordinal = imp_ordinal,
            };
            entry.doc.imports.append(imp) catch {};
            entry.db.addImport(imp) catch {};
        }
    }

    // Restore annotations
    if (getArray(root, "annotations")) |anns_arr| {
        for (anns_arr.array.items) |av| {
            const ann_addr: u64 = @intCast(getInt(av, "address") orelse continue);
            const ann_val = getString(av, "value") orelse continue;
            const kind_str = getString(av, "kind") orelse "comment";
            const kind: types.AnnotationKind = if (eql(kind_str, "name"))
                .name
            else if (eql(kind_str, "comment"))
                .comment
            else if (eql(kind_str, "tag"))
                .tag
            else
                .type_override;
            entry.db.addAnnotation(.{
                .address = ann_addr,
                .kind = kind,
                .value = ann_val,
                .session_id = "restored",
                .timestamp = runtime.awakeMillis(ctx.io),
            }) catch {};
            // Sync name annotations to symbol table so resolveName() returns custom names
            if (kind == .name) {
                entry.db.addSymbol(ann_addr, ann_val) catch {};
            }
        }
    }

    // Restore xrefs
    if (root.object.get("xrefs")) |xrefs_val| {
        if (xrefs_val == .array) {
            for (xrefs_val.array.items) |xv| {
                if (xv != .object) continue;
                const xf = getInt(xv, "f") orelse continue;
                const xt = getInt(xv, "t") orelse continue;
                const xk_str = getString(xv, "k") orelse "call";
                const xref_type: types.XrefType = if (std.mem.eql(u8, xk_str, "call")) .call else if (std.mem.eql(u8, xk_str, "jump")) .jump else if (std.mem.eql(u8, xk_str, "data_read")) .data_read else if (std.mem.eql(u8, xk_str, "data_write")) .data_write else if (std.mem.eql(u8, xk_str, "string_ref")) .string_ref else .call;
                const from: u64 = @bitCast(xf);
                const to: u64 = @bitCast(xt);
                entry.db.xrefs.addXref(from, to, xref_type) catch {};
            }
            // Build sorted array for O(log N) range queries
            entry.db.xrefs.finalize();
        }
    }

    ctx.store.put(entry) catch return ToolError.OutOfMemory;
    // v7.16 W5: restoring a project adds a doc (+ its phora://doc/{id} resource).
    ctx.queueNotification("notifications/tools/list_changed");
    ctx.queueNotification("notifications/resources/list_changed");

    const elapsed = timestampMs(ctx.io) - start;
    const warn_str: []const u8 = if (reload_warning) |w| w else "";
    const result_str = if (reload_warning != null)
        std.fmt.allocPrint(ctx.allocator, "{{\"doc_id\":{d},\"procedures\":{d},\"strings\":{d},\"imports\":{d},\"segments\":{d},\"warning\":\"{s}\"}}", .{
            doc_id, entry.doc.procedures.items.len, entry.doc.strings.items.len, entry.doc.imports.items.len, entry.doc.segments.len, warn_str,
        }) catch return ToolError.OutOfMemory
    else
        std.fmt.allocPrint(ctx.allocator, "{{\"doc_id\":{d},\"procedures\":{d},\"strings\":{d},\"imports\":{d},\"segments\":{d}}}", .{
            doc_id, entry.doc.procedures.items.len, entry.doc.strings.items.len, entry.doc.imports.items.len, entry.doc.segments.len,
        }) catch return ToolError.OutOfMemory;
    const resp = json.successResponse(ctx.allocator, path, result_str, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

fn handleExport(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "export", params);
    };
    const format_str = getString(params, "format") orelse getString(params, "type") orelse {
        const resp = json.errorResponse(ctx.allocator, "export", "missing required parameter: format", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "export");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    // Optional: scope to a single function by address
    const scope_addr: ?u64 = if (getInt(params, "address")) |a| @as(u64, @bitCast(a)) else null;

    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;

    if (std.ascii.eqlIgnoreCase(format_str, "json")) {
        // Full JSON export.
        w.writeAll("{\"document\":") catch {};
        const doc_json = json.serializeDocumentInfo(ctx.allocator, eff.entry.doc) catch return ToolError.OutOfMemory;
        w.writeAll(doc_json) catch {};

        // Include all procedures — use doc.procedures for consistency with stats count.
        const procs = eff.entry.doc.procedures.items;
        w.writeAll(",\"procedures\":[") catch {};
        var json_first = true;
        for (procs) |proc| {
            if (scope_addr) |sa| {
                const re = applyRebaseDelta(proc.entry, eff.delta);
                if (re != sa and (proc.size == 0 or sa < re or sa >= re + proc.size)) continue;
            }
            if (!json_first) w.writeByte(',') catch {};
            json_first = false;
            w.writeAll("{\"address\":") catch {};
            json.writeAddress(w, applyRebaseDelta(proc.entry, eff.delta)) catch {};
            w.print(",\"size\":{d}", .{proc.size}) catch {};
            if (proc.name) |n| {
                w.writeAll(",\"name\":") catch {};
                json.writeJsonString(w, n) catch {};
            }
            w.writeByte('}') catch {};
        }

        w.writeAll("]}") catch {};
    } else if (std.ascii.eqlIgnoreCase(format_str, "text")) {
        // Disassembly listing with real decoded instructions.
        w.writeAll("\"") catch {}; // Wrap in JSON string.
        const procs = eff.entry.doc.procedures.items;
        for (procs) |proc| {
            if (scope_addr) |sa| {
                const re = applyRebaseDelta(proc.entry, eff.delta);
                if (re != sa and (proc.size == 0 or sa < re or sa >= re + proc.size)) continue;
            }
            if (proc.name) |n| {
                w.print("{s}:\\n", .{n}) catch {};
            } else {
                w.print("sub_0x{x}:\\n", .{applyRebaseDelta(proc.entry, eff.delta)}) catch {};
            }
            // Emit decoded instructions from the database
            if (proc.size > 0) {
                var addr = proc.entry;
                const end_addr = proc.entry + proc.size;
                while (addr < end_addr) {
                    if (eff.db.getInstruction(addr)) |inst| {
                        w.print("  0x{x}:  {s}", .{ applyRebaseDelta(inst.address, eff.delta), inst.mnemonic }) catch {};
                        const ops = eff.db.getInstructionOperands(addr);
                        if (ops.len > 0) {
                            w.print(" {s}", .{ops}) catch {};
                        }
                        w.writeAll("\\n") catch {};
                        addr += inst.size;
                    } else {
                        addr += 4; // skip unknown
                    }
                }
            } else {
                w.print("  ; size unknown\\n", .{}) catch {};
            }
            w.writeAll("\\n") catch {};
        }
        w.writeAll("\"") catch {};
    } else if (std.ascii.eqlIgnoreCase(format_str, "ir")) {
        // IR export for all functions — lift on demand if not cached.
        w.writeByte('[') catch {};
        const procs = eff.entry.doc.procedures.items;
        var first = true;
        for (procs) |proc| {
            if (scope_addr) |sa| {
                const re = applyRebaseDelta(proc.entry, eff.delta);
                if (re != sa and (proc.size == 0 or sa < re or sa >= re + proc.size)) continue;
            }
            ensureLiftedIR(ctx.allocator, proc, eff.db, eff.entry);
            if (eff.db.getCachedIR(proc.entry)) |ir_func| {
                if (!first) w.writeByte(',') catch {};
                first = false;
                writeIrJson(w, ir_func) catch {};
            }
        }
        w.writeByte(']') catch {};
    } else {
        const resp = json.errorResponse(ctx.allocator, "export", "invalid format. Valid: json, text, ir", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const result_wrapped = std.fmt.allocPrint(ctx.allocator, "{{\"data\":{s}}}", .{result_json}) catch return ToolError.OutOfMemory;
    const resp = json.successResponse(ctx.allocator, "export", result_wrapped, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .meta_max_chars = 500_000 };
}

/// Resolve a string's file offset by walking the document's segments/sections.
/// Returns null if the address doesn't fall in any readable segment.
/// Used by handleGetStrings (W6 grouping) and handleGetBinaryContext (W4 mode=full).
fn fileOffsetForAddress(doc: *const types.Document, addr: u64) ?usize {
    for (doc.segments) |seg| {
        if (!seg.permissions.read) continue;
        for (seg.sections) |sec| {
            if (addr >= sec.start and addr < sec.start + sec.length) {
                return @intCast(sec.file_offset + (addr - sec.start));
            }
        }
        if (addr >= seg.start and addr < seg.start + seg.length) {
            return @intCast(seg.file_offset + (addr - seg.start));
        }
    }
    return null;
}

/// v7.12 W6/W4: a contiguous block of strings emitted as a single JSON object.
/// `strings` are sorted by file offset; `block_address` is the VA of the first
/// string in the block (already rebase-adjusted).
pub const StringBlock = struct {
    block_address: u64,
    block_size: u64,
    strings: []StringEntry,
};

pub const StringEntry = struct {
    offset: u32, // offset into the block
    address: u64, // absolute VA (rebase-adjusted)
    text: []const u8,
};

/// Group strings into contiguous blocks. Strings within `gap_threshold` bytes
/// of the previous string's tail (in file-offset space, same section) are
/// fused into the same block. Returns owned slice of blocks; each block's
/// `strings` slice is also owned by `allocator`.
pub fn groupContiguousStrings(
    allocator: Allocator,
    doc: *const types.Document,
    strings: []const types.String,
    eff_delta: i128,
    gap_threshold: u64,
) ![]StringBlock {
    if (strings.len == 0) return &[_]StringBlock{};

    // Build (file_offset, original_string) tuples; drop strings without a
    // resolvable file offset (segments may be missing for raw blobs).
    const Sortable = struct { foff: usize, str: types.String };
    var items = std.array_list.Managed(Sortable).init(allocator);
    defer items.deinit();
    for (strings) |s| {
        if (fileOffsetForAddress(doc, s.address)) |foff| {
            try items.append(.{ .foff = foff, .str = s });
        }
    }

    // Sort by file offset (ascending).
    std.mem.sort(Sortable, items.items, {}, struct {
        fn lt(_: void, a: Sortable, b: Sortable) bool {
            return a.foff < b.foff;
        }
    }.lt);

    var blocks = std.array_list.Managed(StringBlock).init(allocator);
    var current_entries = std.array_list.Managed(StringEntry).init(allocator);
    var current_first_foff: usize = 0;
    var current_first_addr: u64 = 0;
    var prev_end_foff: usize = 0;

    for (items.items) |it| {
        const tail_foff = it.foff + it.str.length;
        const rebased_addr = applyRebaseDelta(it.str.address, eff_delta);

        const start_new_block = current_entries.items.len == 0 or
            it.foff > prev_end_foff + gap_threshold;

        if (start_new_block and current_entries.items.len > 0) {
            // Emit pending block.
            const block_size = prev_end_foff - current_first_foff;
            try blocks.append(.{
                .block_address = current_first_addr,
                .block_size = block_size,
                .strings = try current_entries.toOwnedSlice(),
            });
            current_entries = std.array_list.Managed(StringEntry).init(allocator);
        }

        if (current_entries.items.len == 0) {
            current_first_foff = it.foff;
            current_first_addr = rebased_addr;
        }

        const off_in_block: u32 = @intCast(it.foff - current_first_foff);
        try current_entries.append(.{
            .offset = off_in_block,
            .address = rebased_addr,
            .text = it.str.value,
        });
        prev_end_foff = tail_foff;
    }

    if (current_entries.items.len > 0) {
        const block_size = prev_end_foff - current_first_foff;
        try blocks.append(.{
            .block_address = current_first_addr,
            .block_size = block_size,
            .strings = try current_entries.toOwnedSlice(),
        });
    }

    return blocks.toOwnedSlice();
}

fn handleGetStrings(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const pattern = getString(params, "pattern");
    const max_results: u32 = if (getInt(params, "max_results")) |m| @intCast(@max(m, 0)) else 500;
    const offset_raw: i64 = getInt(params, "offset") orelse 0;
    if (offset_raw < 0) {
        const resp = json.errorResponse(ctx.allocator, "get_strings", "offset must be non-negative", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    const offset: u32 = @intCast(offset_raw);
    const case_insensitive = getBool(params, "case_insensitive") orelse false;
    const include_xrefs = getBool(params, "include_xrefs") orelse false;
    const scan_mode = getBool(params, "scan") orelse false;
    const segment_filter = getString(params, "segment");
    const group_contiguous = getBool(params, "group_contiguous") orelse true;

    // Determine whether to search a single doc or all docs
    const maybe_doc_id = resolveDocId(ctx, params);

    // If doc_id was explicitly provided but couldn't be resolved, return actionable error
    if (maybe_doc_id == null and (getInt(params, "doc_id") != null or getString(params, "doc_id") != null)) {
        return docNotFoundErrorFull(ctx, "get_strings", params);
    }

    // Validate segment filter against loaded document segments
    if (segment_filter) |seg_name| {
        if (maybe_doc_id) |doc_id| {
            const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_strings");
            const eff = resolveEffectiveDb(entry);
            var found_seg = false;
            for (eff.entry.doc.segments) |seg| {
                if (std.mem.eql(u8, seg.name, seg_name)) {
                    found_seg = true;
                    break;
                }
            }
            if (!found_seg) {
                var seg_buf = std.Io.Writer.Allocating.init(ctx.allocator);
                const sw = &seg_buf.writer;
                sw.print("unknown segment '{s}'. Available: ", .{seg_name}) catch {};
                for (eff.entry.doc.segments, 0..) |seg, si| {
                    if (si > 0) sw.writeAll(", ") catch {};
                    sw.writeAll(seg.name) catch {};
                }
                const seg_msg = seg_buf.toOwnedSlice() catch "unknown segment";
                const resp = json.errorResponse(ctx.allocator, "get_strings", seg_msg, 0) catch return ToolError.OutOfMemory;
                return .{ .json_response = resp, .is_error = true };
            }
        }
    }

    // Pre-lowercase the pattern if case_insensitive
    var lower_pattern_buf: [1024]u8 = undefined;
    var effective_pattern: ?[]const u8 = pattern;
    if (case_insensitive and pattern != null) {
        const p = pattern.?;
        const copy_len = @min(p.len, lower_pattern_buf.len);
        for (p[0..copy_len], 0..) |c, ci| {
            lower_pattern_buf[ci] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        effective_pattern = lower_pattern_buf[0..copy_len];
    }

    // Collect document entries to process
    const DocInfo = struct { entry: *DocumentEntry, doc_id: u64, eff_db: *Database, eff_delta: i128 };
    var docs_to_search = std.array_list.Managed(DocInfo).init(ctx.allocator);

    if (maybe_doc_id) |doc_id| {
        const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_strings");
        const eff = resolveEffectiveDb(entry);
        docs_to_search.append(.{ .entry = entry, .doc_id = doc_id, .eff_db = eff.db, .eff_delta = eff.delta }) catch {};
    } else {
        // All loaded docs
        var doc_it = ctx.store.documents.iterator();
        while (doc_it.next()) |doc_entry| {
            const de = doc_entry.value_ptr.*;
            const eff = resolveEffectiveDb(de);
            docs_to_search.append(.{ .entry = de, .doc_id = doc_entry.key_ptr.*, .eff_db = eff.db, .eff_delta = eff.delta }) catch {};
        }
    }

    const is_cross_doc = (maybe_doc_id == null);

    // v7.12 W6: contiguous-block grouping path. Bypasses the per-string emit
    // loop and produces a `blocks[]` array, one entry per run of strings whose
    // file offsets are within 16 bytes of the previous string's tail.
    if (group_contiguous) {
        var resp_buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const rw = &resp_buf.writer;
        rw.writeAll("{\"grouping\":\"contiguous\",\"blocks\":[") catch {};

        var first_block = true;
        var total_strings: u32 = 0;
        var emitted_blocks: u32 = 0;

        for (docs_to_search.items) |di| {
            di.eff_db.rw_lock.lockSharedUncancelable(di.eff_db.io);
            defer di.eff_db.rw_lock.unlockShared(di.eff_db.io);

            const all_strings = di.eff_db.getAllStrings(ctx.allocator) catch &[_]types.String{};

            // Pre-filter strings by pattern + segment.
            var filtered = std.array_list.Managed(types.String).init(ctx.allocator);
            for (all_strings) |s| {
                if (effective_pattern) |p| {
                    if (!matchesMultiPattern(s.value, p, case_insensitive)) continue;
                }
                if (segment_filter) |seg_name| {
                    const fo = fileOffsetForAddress(&di.entry.doc, s.address) orelse continue;
                    var in_seg = false;
                    for (di.entry.doc.segments) |seg| {
                        if (!std.mem.eql(u8, seg.name, seg_name)) continue;
                        if (fo >= seg.file_offset and fo < seg.file_offset + seg.file_size) {
                            in_seg = true;
                            break;
                        }
                    }
                    if (!in_seg) continue;
                }
                filtered.append(s) catch {};
            }

            const blocks = groupContiguousStrings(ctx.allocator, &di.entry.doc, filtered.items, di.eff_delta, 16) catch &[_]StringBlock{};
            for (blocks) |blk| {
                if (emitted_blocks >= max_results) break;
                if (!first_block) rw.writeByte(',') catch {};
                first_block = false;
                rw.writeAll("{\"block_address\":") catch {};
                json.writeAddress(rw, blk.block_address) catch {};
                rw.print(",\"block_size\":{d}", .{blk.block_size}) catch {};
                if (is_cross_doc) {
                    rw.print(",\"doc_id\":{d}", .{di.doc_id}) catch {};
                    rw.writeAll(",\"doc_name\":") catch {};
                    json.writeJsonString(rw, std.fs.path.basename(di.entry.doc.path)) catch {};
                }
                rw.writeAll(",\"strings\":[") catch {};
                for (blk.strings, 0..) |se, i| {
                    if (i > 0) rw.writeByte(',') catch {};
                    rw.print("{{\"offset\":{d},\"address\":", .{se.offset}) catch {};
                    json.writeAddress(rw, se.address) catch {};
                    rw.writeAll(",\"text\":") catch {};
                    json.writeJsonString(rw, se.text) catch {};
                    rw.writeByte('}') catch {};
                    total_strings += 1;
                }
                rw.writeAll("]}") catch {};
                emitted_blocks += 1;
            }

            // v7.16 W1: the default (grouped) path used to return before the
            // packed-segment scan, so `get_strings pattern=X` silently missed
            // embedded-runtime bundles (__BUN etc.). Run the on-demand byte-grep
            // here too when a pattern is set and the segment filter (if any)
            // names a packed segment. Emit hits as a `source:"bundle"` block.
            if (effective_pattern) |pp| {
                const seg_ok = segment_filter == null or strings_mod.isPackedSegment(segment_filter.?);
                if (seg_ok and emitted_blocks < max_results and strings_mod.hasPackedSegment(&di.entry.doc)) {
                    const budget: u32 = max_results - emitted_blocks;
                    const BundleHit = struct { address: u64, excerpt: []const u8, full_length: usize, segment_name: []const u8 };
                    var hits = std.array_list.Managed(BundleHit).init(ctx.allocator);
                    var seen_addr = std.AutoHashMap(u64, void).init(ctx.allocator);
                    defer seen_addr.deinit();
                    // v7.16 W1 fix: searchPackedSegments byte-greps LITERALLY, so
                    // split the pattern on '|' and run one search per alternative
                    // (matchesMultiPattern's OR semantics), deduping by address.
                    var alt_it = std.mem.tokenizeScalar(u8, pp, '|');
                    while (alt_it.next()) |alt| {
                        if (hits.items.len >= budget) break;
                        const rem: u32 = budget - @as(u32, @intCast(hits.items.len));
                        var packed_res = strings_mod.searchPackedSegments(ctx.allocator, &di.entry.doc, alt, .{
                            .case_insensitive = case_insensitive,
                            .max_results = rem,
                            .excerpt_radius = 60,
                        }) catch continue;
                        defer packed_res.deinit();
                        for (packed_res.hits.items) |h| {
                            if (hits.items.len >= budget) break;
                            // Honor an explicit packed segment_filter (searchPackedSegments scans ALL packed segments).
                            if (segment_filter) |sf| {
                                if (!std.mem.eql(u8, h.segment_name, sf)) continue;
                            }
                            if (seen_addr.contains(h.address)) continue;
                            seen_addr.put(h.address, {}) catch {};
                            hits.append(.{ .address = h.address, .excerpt = h.excerpt, .full_length = h.full_length, .segment_name = h.segment_name }) catch {};
                        }
                    }
                    if (hits.items.len > 0) {
                        if (!first_block) rw.writeByte(',') catch {};
                        first_block = false;
                        rw.writeAll("{\"source\":\"bundle\"") catch {};
                        if (is_cross_doc) {
                            rw.print(",\"doc_id\":{d}", .{di.doc_id}) catch {};
                        }
                        rw.writeAll(",\"strings\":[") catch {};
                        for (hits.items, 0..) |h, i| {
                            if (i > 0) rw.writeByte(',') catch {};
                            rw.writeAll("{\"address\":") catch {};
                            json.writeAddress(rw, applyRebaseDelta(h.address, di.eff_delta)) catch {};
                            rw.writeAll(",\"text\":") catch {};
                            json.writeJsonString(rw, h.excerpt) catch {};
                            rw.print(",\"full_length\":{d},\"segment\":", .{h.full_length}) catch {};
                            json.writeJsonString(rw, h.segment_name) catch {};
                            rw.writeByte('}') catch {};
                            total_strings += 1;
                        }
                        rw.writeAll("]}") catch {};
                        emitted_blocks += 1;
                    }
                }
            }
        }

        rw.writeAll("]") catch {};
        rw.print(",\"total_blocks\":{d},\"total_strings\":{d}", .{ emitted_blocks, total_strings }) catch {};
        if (is_cross_doc) rw.print(",\"searched_docs\":{d}", .{docs_to_search.items.len}) catch {};
        rw.writeByte('}') catch {};

        const final_resp = resp_buf.toOwnedSlice() catch return ToolError.OutOfMemory;
        return .{ .json_response = final_resp, .meta_max_chars = 200_000 };
    }

    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var seen_addrs = std.AutoHashMap(u64, void).init(ctx.allocator);
    defer seen_addrs.deinit();
    var addr_buf: [32]u8 = undefined;
    var total_matching: u32 = 0;
    var skipped: u32 = 0;

    for (docs_to_search.items) |di| {
        di.eff_db.rw_lock.lockSharedUncancelable(di.eff_db.io);
        defer di.eff_db.rw_lock.unlockShared(di.eff_db.io);

        const all_strings = di.eff_db.getAllStrings(ctx.allocator) catch &[_]types.String{};

        for (all_strings) |s| {
            if (effective_pattern) |p| {
                if (!matchesMultiPattern(s.value, p, case_insensitive)) continue;
            }

            total_matching += 1;

            if (skipped < offset) {
                skipped += 1;
                continue;
            }

            if (items.items.len >= max_results) continue;

            const rebased_addr = applyRebaseDelta(s.address, di.eff_delta);
            seen_addrs.put(rebased_addr, {}) catch {};
            const label_copy = ctx.allocator.dupe(u8, addrStr(&addr_buf, rebased_addr)) catch "?";

            var buf = std.Io.Writer.Allocating.init(ctx.allocator);
            const w = &buf.writer;
            w.writeAll("{\"address\":") catch {};
            json.writeAddress(w, rebased_addr) catch {};
            w.writeAll(",\"value\":") catch {};
            json.writeJsonString(w, s.value) catch {};
            w.print(",\"length\":{d}", .{s.length}) catch {};

            if (is_cross_doc) {
                w.print(",\"doc_id\":{d}", .{di.doc_id}) catch {};
                w.writeAll(",\"doc_name\":") catch {};
                json.writeJsonString(w, std.fs.path.basename(di.entry.doc.path)) catch {};
            }

            // Include xrefs to this string (conditional on include_xrefs flag).
            w.writeAll(",\"xrefs\":[") catch {};
            if (include_xrefs) {
                const max_xrefs_per_string: usize = 10;
                var xref_count: usize = 0;
                const refs_exact = di.eff_db.xrefs.getRefsTo(s.address);
                for (refs_exact) |xref| {
                    if (xref_count >= max_xrefs_per_string) break;
                    if (xref_count > 0) w.writeByte(',') catch {};
                    json.writeAddress(w, applyRebaseDelta(xref.from, di.eff_delta)) catch {};
                    xref_count += 1;
                }
                const page_addr = s.address & ~@as(u64, 0xFFF);
                if (page_addr != s.address and xref_count < max_xrefs_per_string) {
                    const refs_page = di.eff_db.xrefs.getRefsTo(page_addr);
                    for (refs_page) |xref| {
                        if (xref_count >= max_xrefs_per_string) break;
                        if (xref.xref_type == .data_read) {
                            if (di.eff_db.getInstruction(xref.from + 4)) |next_inst| {
                                const mn = next_inst.mnemonic;
                                if (std.mem.eql(u8, mn, "add") or std.mem.eql(u8, mn, "ADD")) {
                                    const add_ops = di.eff_db.getInstructionOperands(xref.from + 4);
                                    if (parseStringXrefImmediate(add_ops)) |imm| {
                                        if (page_addr + imm == s.address) {
                                            if (xref_count > 0) w.writeByte(',') catch {};
                                            json.writeAddress(w, applyRebaseDelta(xref.from, di.eff_delta)) catch {};
                                            xref_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            w.writeAll("]}") catch {};

            const result_json = buf.toOwnedSlice() catch continue;
            items.append(.{ .input = label_copy, .success = true, .result = result_json }) catch {};
        }
    }

    // Byte-level scan: packed runtime segments always, all segments when scan=true.
    // Grep-style: scan raw bytes for the pattern, extract surrounding printable string.
    // v7.16 W1: consult the RuntimeAdapter registry instead of hard-coding "__BUN"
    // so asar/ggml/j2objc/upb/etc. packed segments are covered too.
    if (effective_pattern != null and items.items.len < max_results) {
        const pat = effective_pattern.?;
        for (docs_to_search.items) |di| {
            for (di.entry.doc.segments) |seg| {
                const is_packed = strings_mod.isPackedSegment(seg.name);
                if (!is_packed and !scan_mode) continue;
                const source_tag: []const u8 = if (is_packed) "bundle" else "scan";
                for (seg.sections) |section| {
                    const sec_end = section.file_offset + section.length;
                    if (sec_end > di.entry.doc.data.len) continue;
                    const sec_data = di.entry.doc.data[section.file_offset..sec_end];

                    // Byte-scan for pattern matches (grep-style)
                    var pos: usize = 0;
                    while (pos + pat.len <= sec_data.len) : (pos += 1) {
                        // Check for pattern match (case-sensitive or insensitive)
                        var match = true;
                        for (pat, 0..) |pc, pi| {
                            const dc = sec_data[pos + pi];
                            if (case_insensitive) {
                                const pl = if (pc >= 'A' and pc <= 'Z') pc + 32 else pc;
                                const dl = if (dc >= 'A' and dc <= 'Z') dc + 32 else dc;
                                if (pl != dl) {
                                    match = false;
                                    break;
                                }
                            } else {
                                if (pc != dc) {
                                    match = false;
                                    break;
                                }
                            }
                        }
                        if (!match) continue;

                        // Found pattern — extract surrounding null-terminated string
                        var str_start = pos;
                        while (str_start > 0 and sec_data[str_start - 1] >= 0x20 and sec_data[str_start - 1] <= 0x7E) {
                            str_start -= 1;
                        }
                        var str_end = pos + pat.len;
                        while (str_end < sec_data.len and sec_data[str_end] >= 0x20 and sec_data[str_end] <= 0x7E) {
                            str_end += 1;
                        }

                        const str_val = sec_data[str_start..str_end];
                        if (str_val.len < 4) {
                            continue;
                        }

                        const addr = section.start + str_start;
                        const rebased_addr = applyRebaseDelta(addr, di.eff_delta);
                        // Skip addresses already found in Phase 1 (string table)
                        if (seen_addrs.contains(rebased_addr)) {
                            pos = str_end;
                            continue;
                        }

                        total_matching += 1;
                        if (skipped < offset) {
                            skipped += 1;
                            pos = str_end;
                            continue;
                        }
                        if (items.items.len >= max_results) break;
                        const label_copy = ctx.allocator.dupe(u8, addrStr(&addr_buf, rebased_addr)) catch "?";

                        var buf = std.Io.Writer.Allocating.init(ctx.allocator);
                        const bw = &buf.writer;
                        bw.writeAll("{\"address\":") catch {};
                        json.writeAddress(bw, rebased_addr) catch {};
                        bw.writeAll(",\"value\":") catch {};
                        // Limit individual string length to prevent huge output
                        const max_str_len: usize = 200;
                        const display_val = if (str_val.len > max_str_len) str_val[0..max_str_len] else str_val;
                        json.writeJsonString(bw, display_val) catch {};
                        bw.print(",\"length\":{d}", .{str_val.len}) catch {};
                        bw.writeAll(",\"source\":\"") catch {};
                        bw.writeAll(source_tag) catch {};
                        bw.writeByte('"') catch {};

                        if (is_cross_doc) {
                            bw.print(",\"doc_id\":{d}", .{di.doc_id}) catch {};
                            bw.writeAll(",\"doc_name\":") catch {};
                            json.writeJsonString(bw, std.fs.path.basename(di.entry.doc.path)) catch {};
                        }

                        bw.writeAll(",\"xrefs\":[]}") catch {};
                        const result_json = buf.toOwnedSlice() catch continue;
                        items.append(.{ .input = label_copy, .success = true, .result = result_json }) catch {};

                        // Skip past this string to avoid duplicate matches
                        pos = str_end;
                    }
                }
            }
        }
    }

    // Build response with summary envelope (#7)
    const returned_count: u32 = @intCast(items.items.len);
    var resp_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const rw = &resp_buf.writer;
    rw.print("{{\"total_count\":{d},\"returned_count\":{d},\"has_more\":{s}", .{
        total_matching,
        returned_count,
        if (offset + returned_count < total_matching) "true" else "false",
    }) catch {};
    // Cross-doc search metadata: how many documents were searched
    if (is_cross_doc) {
        rw.print(",\"searched_docs\":{d}", .{docs_to_search.items.len}) catch {};
    }
    rw.writeAll(",\"results\":") catch {};
    const batch_json = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
    rw.writeAll(batch_json) catch {};
    rw.writeByte('}') catch {};

    const final_resp = resp_buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    return .{ .json_response = final_resp };
}

/// Count xrefs to an import by finding calls to any address that resolves to the import name
/// or to the import's stub address in __auth_stubs/__stubs.
/// Import addresses are synthetic (0xFFFF...) so direct xref lookup fails.
/// The stub_addr parameter (if non-zero) is the actual address in the stub section
/// that code calls to reach this import.
fn countImportXrefs(db: *const Database, import_name: []const u8, stub_addr: u64) usize {
    var count: usize = 0;

    // Check xrefs to the stub address (this is how stripped binaries call imports)
    if (stub_addr != 0) {
        const refs = db.xrefs.getRefsTo(stub_addr);
        for (refs) |xref| {
            if (xref.xref_type == .call) count += 1;
        }
    }

    // Check xrefs to any symbol with this name
    var sym_it = db.symbols.iterator();
    while (sym_it.next()) |entry| {
        if (std.mem.eql(u8, entry.value_ptr.*, import_name)) {
            const refs = db.xrefs.getRefsTo(entry.key_ptr.*);
            for (refs) |xref| {
                if (xref.xref_type == .call) count += 1;
            }
        }
    }
    // Also check procedure names matching import
    var proc_it = db.procedures.iterator();
    while (proc_it.next()) |entry| {
        if (entry.value_ptr.name) |name| {
            if (std.mem.eql(u8, name, import_name)) {
                const refs = db.xrefs.getRefsTo(entry.key_ptr.*);
                for (refs) |xref| {
                    if (xref.xref_type == .call) count += 1;
                }
            }
        }
    }
    return count;
}

fn countCallXrefsToAddress(db: *const Database, address: u64) usize {
    var count: usize = 0;
    const refs = db.xrefs.getRefsTo(address);
    for (refs) |xref| {
        if (xref.xref_type == .call) count += 1;
    }
    return count;
}

const ImportXrefCounter = struct {
    name_counts: std.StringHashMap(usize),
    stub_counts: std.AutoHashMap(u64, usize),

    fn deinit(self: *ImportXrefCounter) void {
        self.name_counts.deinit();
        self.stub_counts.deinit();
    }

    fn count(self: *const ImportXrefCounter, imp: types.Import) usize {
        var total: usize = self.name_counts.get(imp.name) orelse 0;
        if (imp.stub_address) |stub_addr| {
            total += self.stub_counts.get(stub_addr) orelse 0;
        }
        return total;
    }
};

fn buildImportXrefCounter(allocator: Allocator, db: *const Database, imports: []const types.Import) !ImportXrefCounter {
    var counter = ImportXrefCounter{
        .name_counts = std.StringHashMap(usize).init(allocator),
        .stub_counts = std.AutoHashMap(u64, usize).init(allocator),
    };
    errdefer counter.deinit();

    var wanted_names = std.StringHashMap(void).init(allocator);
    defer wanted_names.deinit();
    var wanted_stubs = std.AutoHashMap(u64, void).init(allocator);
    defer wanted_stubs.deinit();

    for (imports) |imp| {
        try wanted_names.put(imp.name, {});
        if (imp.stub_address) |stub_addr| {
            if (stub_addr != 0) try wanted_stubs.put(stub_addr, {});
        }
    }

    var stub_it = wanted_stubs.keyIterator();
    while (stub_it.next()) |stub_addr| {
        try counter.stub_counts.put(stub_addr.*, countCallXrefsToAddress(db, stub_addr.*));
    }

    var sym_it = db.symbols.iterator();
    while (sym_it.next()) |entry| {
        const name = entry.value_ptr.*;
        if (!wanted_names.contains(name)) continue;
        const gop = try counter.name_counts.getOrPut(name);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += countCallXrefsToAddress(db, entry.key_ptr.*);
    }

    var proc_it = db.procedures.iterator();
    while (proc_it.next()) |entry| {
        const name = entry.value_ptr.name orelse continue;
        if (!wanted_names.contains(name)) continue;
        const gop = try counter.name_counts.getOrPut(name);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += countCallXrefsToAddress(db, entry.key_ptr.*);
    }

    return counter;
}

fn handleGetImports(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    var pattern = getString(params, "pattern");
    const include_xrefs = getBool(params, "include_xrefs") orelse false;
    const group_by = getString(params, "group_by");
    const case_insensitive = getBool(params, "case_insensitive") orelse false;
    const max_results: usize = if (getInt(params, "max_results")) |m| @intCast(@max(m, 0)) else 500;
    const offset_raw: i64 = getInt(params, "offset") orelse 0;
    if (offset_raw < 0) {
        const resp = json.errorResponse(ctx.allocator, "get_imports", "offset must be non-negative", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    const offset: usize = @intCast(offset_raw);

    // Determine whether to search a single doc or all docs
    const maybe_doc_id = resolveDocId(ctx, params);

    // If doc_id was explicitly provided but couldn't be resolved, return actionable error
    if (maybe_doc_id == null and (getInt(params, "doc_id") != null or getString(params, "doc_id") != null)) {
        return docNotFoundError(ctx, "get_imports");
    }

    // Pre-lowercase the pattern if case_insensitive
    var lower_pattern_buf: [1024]u8 = undefined;
    if (case_insensitive and pattern != null) {
        const p = pattern.?;
        const copy_len = @min(p.len, lower_pattern_buf.len);
        for (p[0..copy_len], 0..) |c, ci| {
            lower_pattern_buf[ci] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        pattern = lower_pattern_buf[0..copy_len];
    }

    // Collect document entries to process
    const DocInfo = struct { entry: *DocumentEntry, doc_id: u64, eff_db: *Database, eff_delta: i128 };
    var docs_to_search = std.array_list.Managed(DocInfo).init(ctx.allocator);

    if (maybe_doc_id) |doc_id| {
        const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_imports");
        const eff = resolveEffectiveDb(entry);
        docs_to_search.append(.{ .entry = entry, .doc_id = doc_id, .eff_db = eff.db, .eff_delta = eff.delta }) catch {};
    } else {
        var doc_it = ctx.store.documents.iterator();
        while (doc_it.next()) |doc_entry| {
            const de = doc_entry.value_ptr.*;
            const eff = resolveEffectiveDb(de);
            docs_to_search.append(.{ .entry = de, .doc_id = doc_entry.key_ptr.*, .eff_db = eff.db, .eff_delta = eff.delta }) catch {};
        }
    }

    const is_cross_doc = (maybe_doc_id == null);

    if (group_by != null and std.ascii.eqlIgnoreCase(group_by.?, "library")) {
        const GroupedImport = struct {
            imp: types.Import,
            rebased_address: u64,
            xref_count: ?usize,
            doc_id: u64,
            doc_name: []const u8,
        };
        var groups = std.StringHashMap(std.array_list.Managed(GroupedImport)).init(ctx.allocator);
        defer {
            var git = groups.valueIterator();
            while (git.next()) |list| list.deinit();
            groups.deinit();
        }
        var group_totals = std.StringHashMap(usize).init(ctx.allocator);
        defer group_totals.deinit();

        var total_imports: usize = 0;
        var returned_count: usize = 0;
        var skipped: usize = 0;

        for (docs_to_search.items) |di| {
            di.eff_db.rw_lock.lockSharedUncancelable(di.eff_db.io);
            defer di.eff_db.rw_lock.unlockShared(di.eff_db.io);
            const all_imports = di.eff_db.getAllImports(ctx.allocator) catch &[_]types.Import{};
            var maybe_counter: ?ImportXrefCounter = null;
            if (include_xrefs and max_results > 0) {
                maybe_counter = buildImportXrefCounter(ctx.allocator, di.eff_db, all_imports) catch return ToolError.OutOfMemory;
            }
            defer if (maybe_counter) |*counter| counter.deinit();

            for (all_imports) |imp| {
                if (pattern) |p| {
                    if (!matchesMultiPattern(normalizeForComparison(imp.name), p, case_insensitive)) continue;
                }

                total_imports += 1;
                const lib = imp.library orelse "unknown";
                const total_gop = group_totals.getOrPut(lib) catch continue;
                if (!total_gop.found_existing) total_gop.value_ptr.* = 0;
                total_gop.value_ptr.* += 1;

                if (skipped < offset) {
                    skipped += 1;
                    continue;
                }
                if (returned_count >= max_results) continue;

                const gop = groups.getOrPut(lib) catch continue;
                if (!gop.found_existing) {
                    gop.value_ptr.* = std.array_list.Managed(GroupedImport).init(ctx.allocator);
                }
                const xref_count: ?usize = if (include_xrefs) blk: {
                    if (maybe_counter) |*counter| break :blk counter.count(imp);
                    break :blk null;
                } else null;
                gop.value_ptr.append(.{
                    .imp = imp,
                    .rebased_address = applyRebaseDelta(imp.address, di.eff_delta),
                    .xref_count = xref_count,
                    .doc_id = di.doc_id,
                    .doc_name = std.fs.path.basename(di.entry.doc.path),
                }) catch continue;
                returned_count += 1;
            }
        }

        var buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const w = &buf.writer;
        const visible_after_offset = if (total_imports > offset) total_imports - offset else 0;
        w.print("{{\"total_count\":{d},\"returned_count\":{d},\"offset\":{d},\"has_more\":{s}", .{
            total_imports,
            returned_count,
            offset,
            if (returned_count < visible_after_offset) "true" else "false",
        }) catch {};
        if (is_cross_doc) {
            w.print(",\"searched_docs\":{d}", .{docs_to_search.items.len}) catch {};
        }
        w.writeAll(",\"groups\":{") catch {};
        var first_group = true;
        var group_it = group_totals.iterator();
        while (group_it.next()) |ge| {
            if (!first_group) w.writeByte(',') catch {};
            first_group = false;
            json.writeJsonString(w, ge.key_ptr.*) catch {};
            const returned = groups.getPtr(ge.key_ptr.*);
            const returned_len = if (returned) |list| list.items.len else 0;
            w.print(":{{\"count\":{d},\"returned_count\":{d},\"imports\":[", .{ ge.value_ptr.*, returned_len }) catch {};
            if (returned) |list| {
                for (list.items, 0..) |item, ii| {
                    if (ii > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"address\":") catch {};
                    json.writeAddress(w, item.rebased_address) catch {};
                    w.writeAll(",\"name\":") catch {};
                    json.writeJsonString(w, item.imp.name) catch {};
                    if (item.imp.ordinal) |nid| {
                        w.print(",\"ordinal\":\"0x{x:0>8}\"", .{nid}) catch {};
                    }
                    if (is_cross_doc) {
                        w.print(",\"doc_id\":{d}", .{item.doc_id}) catch {};
                        w.writeAll(",\"doc_name\":") catch {};
                        json.writeJsonString(w, item.doc_name) catch {};
                    }
                    if (item.xref_count) |xc| {
                        w.print(",\"xref_count\":{d}", .{xc}) catch {};
                    }
                    w.writeByte('}') catch {};
                }
            }
            w.writeAll("]}") catch {};
        }
        w.writeAll("}}") catch {};

        const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
        const resp = json.successResponse(ctx.allocator, "get_imports", result_json, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp };
    }

    // Flat mode (original behavior + optional xref counts), supports cross-doc
    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var total_imports: usize = 0;
    var skipped: usize = 0;

    for (docs_to_search.items) |di| {
        di.eff_db.rw_lock.lockSharedUncancelable(di.eff_db.io);
        defer di.eff_db.rw_lock.unlockShared(di.eff_db.io);
        const all_imports = di.eff_db.getAllImports(ctx.allocator) catch &[_]types.Import{};
        var maybe_counter: ?ImportXrefCounter = null;
        if (include_xrefs and max_results > 0) {
            maybe_counter = buildImportXrefCounter(ctx.allocator, di.eff_db, all_imports) catch return ToolError.OutOfMemory;
        }
        defer if (maybe_counter) |*counter| counter.deinit();

        for (all_imports) |imp| {
            if (pattern) |p| {
                if (!matchesMultiPattern(normalizeForComparison(imp.name), p, case_insensitive)) continue;
            }
            total_imports += 1;
            if (skipped < offset) {
                skipped += 1;
                continue;
            }
            if (items.items.len >= max_results) continue;

            var buf = std.Io.Writer.Allocating.init(ctx.allocator);
            const w = &buf.writer;
            w.writeAll("{\"address\":") catch {};
            json.writeAddress(w, applyRebaseDelta(imp.address, di.eff_delta)) catch {};
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, imp.name) catch {};
            if (imp.ordinal) |nid| {
                w.print(",\"ordinal\":\"0x{x:0>8}\"", .{nid}) catch {};
            }
            if (imp.library) |lib| {
                w.writeAll(",\"library\":") catch {};
                json.writeJsonString(w, lib) catch {};
            }
            if (is_cross_doc) {
                w.print(",\"doc_id\":{d}", .{di.doc_id}) catch {};
                w.writeAll(",\"doc_name\":") catch {};
                json.writeJsonString(w, std.fs.path.basename(di.entry.doc.path)) catch {};
            }
            if (include_xrefs) {
                const xc = if (maybe_counter) |*counter| counter.count(imp) else 0;
                w.print(",\"xref_count\":{d}", .{xc}) catch {};
            }
            w.writeByte('}') catch {};

            const result_json = buf.toOwnedSlice() catch continue;
            items.append(.{ .input = imp.name, .success = true, .result = result_json }) catch {};
        }
    }

    // Build response with summary envelope (#7)
    const returned_count: usize = items.items.len;
    var resp_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const rw = &resp_buf.writer;
    const visible_after_offset = if (total_imports > offset) total_imports - offset else 0;
    const has_more = returned_count < visible_after_offset;
    rw.print("{{\"total_count\":{d},\"returned_count\":{d},\"offset\":{d},\"has_more\":{s}", .{
        total_imports,
        returned_count,
        offset,
        if (has_more) "true" else "false",
    }) catch {};
    // Cross-doc search metadata: how many documents were searched
    if (is_cross_doc) {
        rw.print(",\"searched_docs\":{d}", .{docs_to_search.items.len}) catch {};
    }
    rw.writeAll(",\"results\":") catch {};
    const batch_json = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
    rw.writeAll(batch_json) catch {};
    rw.writeByte('}') catch {};

    const final_resp = resp_buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    return .{ .json_response = final_resp };
}

fn handleGetExports(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    var pattern = getString(params, "pattern");
    const case_insensitive = getBool(params, "case_insensitive") orelse false;
    const max_results: usize = if (getInt(params, "max_results")) |m| @intCast(@max(m, 0)) else 500;

    // Determine whether to search a single doc or all docs
    const maybe_doc_id = resolveDocId(ctx, params);

    // If doc_id was explicitly provided but couldn't be resolved, return actionable error
    if (maybe_doc_id == null and (getInt(params, "doc_id") != null or getString(params, "doc_id") != null)) {
        return docNotFoundError(ctx, "get_exports");
    }

    // Pre-lowercase the pattern if case_insensitive
    var lower_pattern_buf: [1024]u8 = undefined;
    if (case_insensitive and pattern != null) {
        const p = pattern.?;
        const copy_len = @min(p.len, lower_pattern_buf.len);
        for (p[0..copy_len], 0..) |c, ci| {
            lower_pattern_buf[ci] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        pattern = lower_pattern_buf[0..copy_len];
    }

    // Collect document entries to process
    const DocInfo = struct { entry: *DocumentEntry, doc_id: u64, eff_db: *Database, eff_delta: i128 };
    var docs_to_search = std.array_list.Managed(DocInfo).init(ctx.allocator);

    if (maybe_doc_id) |doc_id| {
        const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_exports");
        const eff = resolveEffectiveDb(entry);
        docs_to_search.append(.{ .entry = entry, .doc_id = doc_id, .eff_db = eff.db, .eff_delta = eff.delta }) catch {};
    } else {
        var doc_it = ctx.store.documents.iterator();
        while (doc_it.next()) |doc_entry| {
            const de = doc_entry.value_ptr.*;
            const eff = resolveEffectiveDb(de);
            docs_to_search.append(.{ .entry = de, .doc_id = doc_entry.key_ptr.*, .eff_db = eff.db, .eff_delta = eff.delta }) catch {};
        }
    }

    const is_cross_doc = (maybe_doc_id == null);

    // Iterate over exported symbols (db.symbols map: address → name)
    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var total_exports: u32 = 0;

    for (docs_to_search.items) |di| {
        di.eff_db.rw_lock.lockSharedUncancelable(di.eff_db.io);
        defer di.eff_db.rw_lock.unlockShared(di.eff_db.io);

        // Build import stub set so we filter out re-exports masquerading as exports.
        // db.symbols contains both genuine exports AND stub symbols registered for
        // imports (especially on Mach-O via registerStubSymbols).
        var import_set = buildImportStubSet(ctx.allocator, di.eff_db);
        defer import_set.deinit();

        var sym_it = di.eff_db.symbols.iterator();
        while (sym_it.next()) |sym_entry| {
            const addr = sym_entry.key_ptr.*;
            const name = sym_entry.value_ptr.*;
            const normalized = normalizeForComparison(name);

            // Skip import stubs — these are not genuine exports
            if (import_set.contains(normalized)) continue;

            if (pattern) |p| {
                if (!matchesMultiPattern(normalized, p, case_insensitive)) continue;
            }
            total_exports += 1;
            if (items.items.len >= max_results) continue;

            var entry_buf = std.Io.Writer.Allocating.init(ctx.allocator);
            const ew = &entry_buf.writer;
            ew.writeAll("{\"address\":") catch {};
            json.writeAddress(ew, applyRebaseDelta(addr, di.eff_delta)) catch {};
            ew.writeAll(",\"name\":") catch {};
            json.writeJsonString(ew, name) catch {};
            if (is_cross_doc) {
                ew.print(",\"doc_id\":{d}", .{di.doc_id}) catch {};
                ew.writeAll(",\"doc_name\":") catch {};
                json.writeJsonString(ew, std.fs.path.basename(di.entry.doc.path)) catch {};
            }
            ew.writeByte('}') catch {};

            const result_json = entry_buf.toOwnedSlice() catch continue;
            items.append(.{ .input = name, .success = true, .result = result_json }) catch {};
        }
    }

    // Build response with summary envelope
    const returned_count: u32 = @intCast(items.items.len);
    var resp_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const rw = &resp_buf.writer;
    const has_more = returned_count < total_exports;
    rw.print("{{\"total_count\":{d},\"returned_count\":{d},\"has_more\":{s}", .{
        total_exports,
        returned_count,
        if (has_more) "true" else "false",
    }) catch {};
    if (is_cross_doc) {
        rw.print(",\"searched_docs\":{d}", .{docs_to_search.items.len}) catch {};
    }
    rw.writeAll(",\"results\":") catch {};
    const batch_json = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
    rw.writeAll(batch_json) catch {};
    rw.writeByte('}') catch {};

    const final_resp = resp_buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    return .{ .json_response = final_resp };
}

const InstructionBytes = struct {
    data: []const u8,
    file_offset: u64,
};

/// Restrict instruction evidence to file-backed code and the caller's byte budget.
fn instructionBytes(doc: *const types.Document, address: u64, budget: u64) ?InstructionBytes {
    const code_end = doc.codeRangeEnd(address) orelse return null;
    for (doc.segments) |seg| {
        if (!seg.permissions.execute or address < seg.start or address - seg.start >= seg.length) continue;
        var offset: u64 = undefined;
        var available: u64 = undefined;
        if (doc.format == .elf or seg.sections.len == 0) {
            const relative = address - seg.start;
            if (relative >= seg.file_size) return null;
            offset = std.math.add(u64, seg.file_offset, relative) catch return null;
            available = seg.file_size - relative;
        } else {
            var section: ?types.Section = null;
            for (seg.sections) |sec| {
                if (sec.isCode() and address >= sec.start and address - sec.start < sec.length) {
                    section = sec;
                    break;
                }
            }
            const sec = section orelse return null;
            const relative = address - sec.start;
            offset = std.math.add(u64, sec.file_offset, relative) catch return null;
            available = sec.length - relative;
        }
        if (offset >= doc.data.len) return null;
        const size = @min(available, doc.data.len - offset, code_end - address, budget);
        return .{ .data = doc.data[@intCast(offset)..][0..@intCast(size)], .file_offset = offset };
    }
    return null;
}

fn x86DecodeGap(mnemonic: []const u8) bool {
    return std.mem.eql(u8, mnemonic, "udf") or std.mem.eql(u8, mnemonic, "db") or std.mem.eql(u8, mnemonic, "unsupported");
}

fn handleDisassembleRange(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    if (params == .object and (params.object.contains("end") or params.object.contains("end_address"))) {
        const resp = json.errorResponse(ctx.allocator, "disassemble_range", "Use start plus byte_length (bytes, not instructions); end/end_address is unsupported. Compute byte_length = end_exclusive - start.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    const doc_id = resolveDocId(ctx, params) orelse return docNotFoundErrorFull(ctx, "disassemble_range", params);
    const raw_start = getInt(params, "start") orelse getInt(params, "address") orelse -1;
    const raw_length = getInt(params, "byte_length") orelse getInt(params, "length") orelse blk: {
        if (getInt(params, "count")) |count| break :blk count *| 4;
        break :blk @as(i64, 4096);
    };
    if (raw_start < 0 or raw_length <= 0) {
        const resp = json.errorResponse(ctx.allocator, "disassemble_range", "start must be a non-negative address and byte_length must be positive", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    const length: u64 = @intCast(@min(raw_length, 4096));
    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "disassemble_range");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);
    const doc = &eff.entry.doc;
    const eff_start = removeRebaseDelta(@intCast(raw_start), eff.delta);
    if (doc.arch == .arm64 and eff_start % 4 != 0) {
        const resp = json.errorResponse(ctx.allocator, "disassemble_range", "ARM64 instruction address must be 4-byte aligned", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    var items = std.array_list.Managed(json.BatchItem).init(ctx.allocator);
    var addr_buf: [32]u8 = undefined;
    var addr = eff_start;
    const end_addr = eff_start +| length;
    var stop_reason: []const u8 = "complete";
    var modeled: u32 = 0;
    var unsupported: u32 = 0;
    var invalid: u32 = 0;
    var decode_gaps: u32 = 0;
    var output_bytes: usize = 1024;
    var thumb_state: arm32.ItState = .{};
    while (addr < end_addr) {
        const raw = instructionBytes(doc, addr, end_addr - addr) orelse {
            stop_reason = "not_file_backed_code";
            break;
        };
        const min_size: usize = switch (doc.arch) {
            .arm64, .mips32 => 4,
            .arm32 => 2,
            .x86, .x86_64 => 1,
        };
        if (raw.data.len < min_size) {
            stop_reason = "incomplete_instruction";
            break;
        }
        const thumb_decoded: ?arm32.DecodedInstruction = if (doc.arch == .arm32) arm32.decode(raw.data, addr) else null;
        const predicate = thumb_state.currentCondition();
        const cached = eff.db.getInstruction(addr);
        const inst = cached orelse switch (doc.arch) {
            .arm64 => arm64.decodeInstruction(raw.data, addr),
            .arm32 => arm32.decodeInstruction(raw.data, addr),
            .mips32 => mips32.decodeInstruction(raw.data, addr),
            .x86_64 => @import("arch/x86_64.zig").decodeInstruction(raw.data, addr),
            .x86 => @import("arch/x86_64.zig").decodeInstruction32(raw.data, addr),
        };
        if ((doc.arch == .x86 or doc.arch == .x86_64) and x86DecodeGap(inst.mnemonic)) {
            decode_gaps += 1;
            stop_reason = "undecoded_instruction";
            break;
        }
        if (inst.size == 0 or inst.size > raw.data.len or (doc.arch == .arm64 and inst.size != 4)) {
            stop_reason = "incomplete_instruction";
            break;
        }
        const rebased_addr = applyRebaseDelta(addr, eff.delta);
        const label = ctx.allocator.dupe(u8, addrStr(&addr_buf, rebased_addr)) catch return ToolError.OutOfMemory;
        var buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const w = &buf.writer;
        w.writeAll("{\"address\":") catch return ToolError.OutOfMemory;
        json.writeAddress(w, rebased_addr) catch return ToolError.OutOfMemory;
        w.writeAll(",\"mnemonic\":") catch return ToolError.OutOfMemory;
        const display_mnemonic = if (thumb_decoded) |d| (if (predicate != null and d.flags_suppressed_in_it and std.mem.endsWith(u8, d.mnemonic, "s")) d.mnemonic[0 .. d.mnemonic.len - 1] else d.mnemonic) else inst.mnemonic;
        json.writeJsonString(w, display_mnemonic) catch return ToolError.OutOfMemory;
        w.writeAll(",\"operands\":") catch return ToolError.OutOfMemory;
        const operands = if (cached != null) eff.db.getInstructionOperands(addr) else inst.operands_buf[0..inst.operands_len];
        json.writeJsonString(w, operands) catch return ToolError.OutOfMemory;
        w.print(",\"size\":{d},\"file_offset\":{d},\"bytes\":\"", .{ inst.size, raw.file_offset }) catch return ToolError.OutOfMemory;
        for (raw.data[0..inst.size]) |byte| w.print("{x:0>2}", .{byte}) catch return ToolError.OutOfMemory;
        w.writeAll("\",\"semantics\":") catch return ToolError.OutOfMemory;
        if (doc.arch == .arm64) {
            const word = std.mem.readInt(u32, raw.data[0..4], .little);
            arm64_semantics.writeJson(w, word) catch return ToolError.OutOfMemory;
            arm64_addressing.writeJsonMember(w, word) catch return ToolError.OutOfMemory;
            arm64_arithmetic.writeJsonMember(w, word) catch return ToolError.OutOfMemory;
            arm64_bitfield.writeJsonMember(w, word) catch return ToolError.OutOfMemory;
            if (addr >= eff_start +| 4) {
                if (instructionBytes(doc, addr - 4, 4)) |previous_raw| {
                    if (previous_raw.data.len >= 4)
                        arm64_branch_predicate.writeJsonMember(w, std.mem.readInt(u32, previous_raw.data[0..4], .little), word, applyRebaseDelta(addr - 4, eff.delta)) catch return ToolError.OutOfMemory;
                }
            }
            const status = arm64.decode(raw.data[0..4], addr).decode_status;
            w.print(",\"decode_status\":\"{s}\"", .{@tagName(status)}) catch return ToolError.OutOfMemory;
            if (status != .decoded) {
                w.writeAll(",\"decode_warning\":\"Opaque ARM64 decoder fallback; fixed four-byte slots preserve raw bytes but establish no instruction identity, effects, or fallthrough.\"") catch return ToolError.OutOfMemory;
            }
        } else {
            w.writeAll("{\"status\":\"unsupported\",\"reason\":\"architecture_not_modeled\"}") catch return ToolError.OutOfMemory;
        }
        if (doc.arch == .x86 or doc.arch == .x86_64) {
            const gap = std.mem.eql(u8, inst.mnemonic, "udf") or std.mem.eql(u8, inst.mnemonic, "db") or std.mem.eql(u8, inst.mnemonic, "unsupported");
            w.print(",\"decode_status\":\"{s}\"", .{if (gap) "undecoded" else "decoded"}) catch return ToolError.OutOfMemory;
            if (gap) {
                decode_gaps += 1;
                w.writeAll(",\"decode_warning\":\"Opaque decoder fallback; mnemonic does not establish an undefined CPU operation. Subsequent boundaries may be heuristic.\"") catch return ToolError.OutOfMemory;
            }
        }
        if (thumb_decoded) |d| {
            if (d.decode_status != .decoded) decode_gaps += 1;
            w.print(",\"decode_status\":\"{s}\"", .{@tagName(d.decode_status)}) catch return ToolError.OutOfMemory;
            if (predicate) |condition| {
                w.print(",\"execution_condition\":\"{s}\"", .{arm32.conditionName(condition)}) catch return ToolError.OutOfMemory;
            }
            if (d.sets_flags) |sets_flags| {
                w.print(",\"sets_flags\":{}", .{sets_flags and !(predicate != null and d.flags_suppressed_in_it)}) catch return ToolError.OutOfMemory;
            }
            thumb_state.advance();
            if (d.it_block) |block| thumb_state.begin(block);
        }
        w.writeByte('}') catch return ToolError.OutOfMemory;
        // Reserve per-item batch envelope space before the global safety cap.
        if (output_bytes + buf.written().len + 192 > max_response_chars) {
            buf.deinit();
            stop_reason = "output_budget";
            break;
        }
        output_bytes += buf.written().len + 192;
        const result = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
        items.append(.{ .input = label, .success = true, .result = result }) catch return ToolError.OutOfMemory;
        if (doc.arch == .arm64) {
            if (arm64.decode(raw.data[0..4], addr).decode_status != .decoded) decode_gaps += 1;
            switch (arm64_semantics.decode(std.mem.readInt(u32, raw.data[0..4], .little))) {
                .modeled => modeled += 1,
                .unsupported => unsupported += 1,
                .invalid_encoding => invalid += 1,
            }
        } else unsupported += 1;
        addr += inst.size;
    }

    const partial = addr - eff_start < @as(u64, @intCast(raw_length));
    if (partial and std.mem.eql(u8, stop_reason, "complete")) stop_reason = "byte_limit";
    var response = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &response.writer;
    w.print("{{\"total_instructions\":{d},\"covered_bytes\":{d},\"partial\":{},\"stop_reason\":", .{ items.items.len, addr - eff_start, partial }) catch return ToolError.OutOfMemory;
    json.writeJsonString(w, stop_reason) catch return ToolError.OutOfMemory;
    if (partial) {
        w.writeAll(",\"next_address\":") catch return ToolError.OutOfMemory;
        json.writeAddress(w, applyRebaseDelta(addr, eff.delta)) catch return ToolError.OutOfMemory;
    }
    w.print(",\"decode_gaps\":{d}", .{decode_gaps}) catch return ToolError.OutOfMemory;
    if (doc.arch == .arm64)
        w.print(",\"decode_summary\":{{\"decoded\":{d},\"unsupported\":{d},\"inspected_slots\":{d}}}", .{ items.items.len - decode_gaps, decode_gaps, items.items.len }) catch return ToolError.OutOfMemory;
    if (std.mem.eql(u8, stop_reason, "undecoded_instruction")) {
        w.print(",\"next_call\":{{\"tool\":\"read_bytes\",\"arguments\":{{\"doc_id\":{d},\"address\":", .{doc_id}) catch return ToolError.OutOfMemory;
        json.writeAddress(w, applyRebaseDelta(addr, eff.delta)) catch return ToolError.OutOfMemory;
        w.writeAll(",\"length\":16}}") catch return ToolError.OutOfMemory;
    }
    if (doc.arch == .arm32) {
        w.writeAll(",\"predication_note\":\"IT conditions are tracked within this range. Start at the function entry to include any preceding IT instruction; ranges starting inside an IT block have unknown initial predication.\"") catch return ToolError.OutOfMemory;
    }
    w.writeAll(",\"semantics_note\":\"unsupported means no formal effect model is available; it does not mean the instruction failed to decode. Do not treat unsupported instructions as no-ops.\"") catch return ToolError.OutOfMemory;
    w.print(",\"semantics_summary\":{{\"modeled\":{d},\"unsupported\":{d},\"invalid_encoding\":{d}}},\"results\":", .{ modeled, unsupported, invalid }) catch return ToolError.OutOfMemory;
    const batch = json.batchResponse(ctx.allocator, items.items) catch return ToolError.OutOfMemory;
    w.writeAll(batch) catch return ToolError.OutOfMemory;
    w.writeByte('}') catch return ToolError.OutOfMemory;
    return .{ .json_response = response.toOwnedSlice() catch return ToolError.OutOfMemory };
}

// ============================================================================
// read_bytes: primary raw byte evidence
// ============================================================================
//
// Preserve file byte identity and distinguish virtual zero-fill from file backing.
// Hex is exact; ASCII is a lossy preview. Bound pages to the response budget and
// bound address reads to the selected mapping/backing range.

fn handleReadBytes(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "read_bytes", params);
    };

    // v7.16 W1: allow reading by raw `file_offset` (as reported by
    // get_embedded_resources) in addition to virtual `address` — lets the LLM
    // carve an embedded bundle by offset without resolving its virtual base.
    const has_address = params.object.contains("address");
    const has_offset = params.object.contains("file_offset");
    if (has_address == has_offset or (has_offset and (getInt(params, "file_offset") orelse -1) < 0)) {
        const resp = json.errorResponse(ctx.allocator, "read_bytes", "provide exactly one of address or nonnegative integer file_offset", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    const fo_param: ?usize = if (getInt(params, "file_offset")) |f| (if (f >= 0) @as(?usize, @intCast(f)) else null) else null;
    const addr_raw = getInt(params, "address") orelse blk: {
        if (fo_param != null) break :blk @as(i64, 0);
        const resp = json.errorResponse(ctx.allocator, "read_bytes", "missing 'address' or 'file_offset' parameter (address accepts integer or hex string like 0x100000000; file_offset is a raw byte offset into the file)", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    const address: u64 = @bitCast(addr_raw);

    const length_raw = getInt(params, "length") orelse 64;
    if (length_raw <= 0) {
        const resp = json.errorResponse(ctx.allocator, "read_bytes", "length must be positive", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    const length: usize = @intCast(@min(length_raw, 65536));
    const element_size = getInt(params, "element_size");
    const byte_order = getString(params, "byte_order");
    if (params.object.contains("element_size") or params.object.contains("byte_order")) {
        const width = element_size orelse 0;
        const valid_order = if (byte_order) |order| eql(order, "little") or eql(order, "big") else false;
        if ((width != 1 and width != 2 and width != 4 and width != 8) or !valid_order) {
            const resp = json.errorResponse(ctx.allocator, "read_bytes", "integer interpretation requires element_size 1, 2, 4 or 8 and explicit byte_order little or big", 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        }
        if (length_raw > width * 256) {
            const resp = json.errorResponse(ctx.allocator, "read_bytes", "typed reads allow at most 256 elements; reduce length to 256 * element_size and advance address or file_offset for subsequent reads", 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        }
    }

    const encoding = getString(params, "encoding") orelse "both";
    const want_hex_compact = std.ascii.eqlIgnoreCase(encoding, "hex_compact");
    const want_hex = want_hex_compact or std.ascii.eqlIgnoreCase(encoding, "hex") or std.ascii.eqlIgnoreCase(encoding, "both");
    const want_ascii = !want_hex_compact and (std.ascii.eqlIgnoreCase(encoding, "ascii") or std.ascii.eqlIgnoreCase(encoding, "both"));
    if (!want_hex and !want_ascii) {
        const resp = json.errorResponse(ctx.allocator, "read_bytes", "encoding must be 'ascii', 'hex', 'both', or 'hex_compact'", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "read_bytes");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    // Translate input address through any active rebase delta.
    const eff_address = removeRebaseDelta(address, eff.delta);

    // Locate the segment/section containing eff_address. Walk every readable
    // segment (not just executable, unlike disassemble_range) so the LLM can
    // inspect __DATA, __cstring, __BUN, __LINKEDIT — anything mappable.
    var file_offset: ?usize = null;
    var found_segment_name: []const u8 = "";
    var in_zerofill: bool = false;
    var mapping_available: u64 = std.math.maxInt(u64);
    var invalid_mapping = false;
    if (fo_param) |fo| {
        // Direct file-offset read: no virtual-address resolution needed.
        file_offset = fo;
        for (eff.entry.doc.segments) |seg| {
            if (fo >= seg.file_offset and fo - seg.file_offset < seg.file_size) {
                found_segment_name = seg.name;
                break;
            }
        }
    } else for (eff.entry.doc.segments) |seg| {
        if (!seg.permissions.read) continue;
        if (eff_address < seg.start or eff_address - seg.start >= seg.length) continue;
        // Try sections first (more precise file offsets on Mach-O).
        for (seg.sections) |sec| {
            if (eff_address >= sec.start and eff_address - sec.start < sec.length) {
                file_offset = if (sec.is_zerofill) 0 else @intCast(std.math.add(u64, sec.file_offset, eff_address - sec.start) catch {
                    invalid_mapping = true;
                    break;
                });
                found_segment_name = seg.name;
                in_zerofill = sec.is_zerofill;
                mapping_available = @min(sec.length - (eff_address - sec.start), seg.length - (eff_address - seg.start));
                if (!in_zerofill) {
                    if (file_offset.? < seg.file_offset) {
                        invalid_mapping = true;
                        break;
                    }
                    const relative = file_offset.? - seg.file_offset;
                    mapping_available = @min(mapping_available, seg.file_size -| relative);
                }
                break;
            }
        }
        if (file_offset != null or invalid_mapping) break;
        if (eff_address >= seg.start and eff_address - seg.start < seg.length) {
            found_segment_name = seg.name;
            const relative = eff_address - seg.start;
            in_zerofill = relative >= seg.file_size;
            file_offset = if (in_zerofill) 0 else @intCast(std.math.add(u64, seg.file_offset, relative) catch {
                invalid_mapping = true;
                break;
            });
            mapping_available = if (in_zerofill) seg.length - relative else @min(seg.length - relative, seg.file_size - relative);
            break;
        }
    }

    if (invalid_mapping or (file_offset != null and mapping_available == 0)) {
        const resp = json.errorResponse(ctx.allocator, "read_bytes", "invalid mapping: file backing offset overflow or section outside segment backing", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }
    if (file_offset == null) {
        // Build an actionable error listing the segment ranges.
        var err_buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const ew = &err_buf.writer;
        ew.print("address 0x{x} not in any readable segment. Segments: ", .{address}) catch {};
        var first = true;
        for (eff.entry.doc.segments) |seg| {
            if (!seg.permissions.read) continue;
            if (!first) ew.writeAll(", ") catch {};
            first = false;
            ew.print("{s}=0x{x}-0x{x}", .{
                seg.name,
                applyRebaseDelta(seg.start, eff.delta),
                @as(u64, @intCast(std.math.clamp(@as(i128, seg.start) + @as(i128, seg.length) + eff.delta, 0, std.math.maxInt(u64)))),
            }) catch {};
        }
        const err_msg = err_buf.toOwnedSlice() catch "address not in any readable segment";
        const resp = json.errorResponse(ctx.allocator, "read_bytes", err_msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    const foff = file_offset.?;

    // Zerofill sections (Mach-O __bss/__common/__thread_bss, ELF SHT_NOBITS) have
    // no file backing. Return zeros instead of reading arbitrary file bytes.
    // Expanded hex plus JSON-escaped ASCII costs at most five chars per byte.
    // Leave headroom for metadata and the response envelope under 200 KB.
    const page_limit: usize = if (want_hex and want_ascii) 32768 else if (want_hex and !want_hex_compact) 60000 else 65536;
    const address_available = if (fo_param == null) (std.math.maxInt(u64) - address) +| 1 else std.math.maxInt(u64);
    const bounded_length: usize = @intCast(@min(@as(u64, @min(length, page_limit)), @min(mapping_available, address_available)));
    var bytes: []const u8 = undefined;
    if (in_zerofill) {
        const want = bounded_length;
        const zbuf = ctx.allocator.alloc(u8, want) catch return ToolError.OutOfMemory;
        @memset(zbuf, 0);
        bytes = zbuf;
    } else {
        if (foff > eff.entry.doc.data.len or (foff == eff.entry.doc.data.len and fo_param == null)) {
            const resp = json.errorResponse(ctx.allocator, "read_bytes", "address resolves to file offset beyond loaded data", 0) catch return ToolError.OutOfMemory;
            return .{ .json_response = resp, .is_error = true };
        }
        const available = eff.entry.doc.data.len - foff;
        const actual = @min(bounded_length, available);
        bytes = eff.entry.doc.data[foff .. foff + actual];
    }
    const actual_length = bytes.len;

    // Build the response. Hex is space-separated, lowercase. ASCII uses '.'
    // for any byte outside printable range to keep the JSON safe.
    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;
    // v7.16 W1: when reading purely by file_offset (no explicit address), emit
    // address:null instead of a misleading 0x0 that reads as a real VA.
    const addr_explicit = getInt(params, "address") != null;
    w.writeAll("{\"address\":") catch {};
    if (fo_param != null and !addr_explicit) {
        w.writeAll("null") catch {};
    } else {
        json.writeAddress(w, address) catch {};
    }
    if (in_zerofill) w.writeAll(",\"file_offset\":null") catch {} else w.print(",\"file_offset\":{d}", .{foff}) catch {};
    w.writeAll(",\"document_architecture\":") catch {};
    json.writeJsonString(w, eff.entry.doc.arch.toString()) catch {};
    w.writeAll(",\"architecture_source\":\"parsed_or_configured_document\"") catch {};
    w.writeAll(",\"segment\":") catch {};
    json.writeJsonString(w, found_segment_name) catch {};
    w.print(",\"length\":{d},\"requested_length\":{d},\"returned_length\":{d},\"backing\":\"{s}\",\"ascii_is_lossy_preview\":true", .{ actual_length, length_raw, actual_length, if (in_zerofill) "zero_fill" else "file" }) catch {};
    const source_available = if (in_zerofill) mapping_available else @min(mapping_available, eff.entry.doc.data.len - foff);
    const more = actual_length < @as(u64, @intCast(length_raw)) and actual_length < source_available and actual_length < address_available;
    w.print(",\"partial\":{},\"stop_reason\":\"{s}\"", .{ actual_length < @as(u64, @intCast(length_raw)), if (more) "page_limit" else if (actual_length == @as(u64, @intCast(length_raw))) "requested_length" else if (fo_param == null and actual_length == address_available) "address_space_boundary" else if (source_available == mapping_available and fo_param == null) "mapping_boundary" else "end_of_file" }) catch {};
    if (more) {
        w.print(",\"next_call\":{{\"tool\":\"read_bytes\",\"arguments\":{{\"doc_id\":{d},", .{doc_id}) catch {};
        if (fo_param != null) w.print("\"file_offset\":{d}", .{foff + actual_length}) catch {} else {
            w.writeAll("\"address\":") catch {};
            json.writeAddress(w, address + actual_length) catch {};
        }
        w.print(",\"length\":{d},\"encoding\":", .{@as(u64, @intCast(length_raw)) - actual_length}) catch {};
        json.writeJsonString(w, encoding) catch {};
        w.writeAll("}}") catch {};
    }
    if (element_size) |width| {
        const size: usize = @intCast(width);
        const little = eql(byte_order.?, "little");
        try w.print(",\"integer_view\":{{\"element_size\":{d},\"byte_order\":\"{s}\",\"value_encoding\":\"unsigned_decimal_strings\",\"complete_elements\":{d},\"uninterpreted_trailing_bytes\":{d},\"values\":[", .{ size, byte_order.?, bytes.len / size, bytes.len % size });
        for (0..bytes.len / size) |index| {
            if (index != 0) try w.writeByte(',');
            var value: u64 = 0;
            for (bytes[index * size ..][0..size], 0..) |byte, i| {
                const shift: u6 = @intCast((if (little) i else size - 1 - i) * 8);
                value |= @as(u64, byte) << shift;
            }
            try w.print("\"{d}\"", .{value});
        }
        try w.writeAll("]}");
    }

    if (want_hex) {
        w.writeAll(",\"hex\":\"") catch {};
        for (bytes, 0..) |b, i| {
            // v7.12 W5: hex_compact omits the space separators so a 64 KB
            // dump fits in ~131 KB of JSON instead of ~256 KB.
            if (i > 0 and !want_hex_compact) w.writeByte(' ') catch {};
            w.print("{x:0>2}", .{b}) catch {};
        }
        w.writeByte('"') catch {};
    }
    if (want_ascii) {
        w.writeAll(",\"ascii\":\"") catch {};
        // Build ascii into a temp buffer so we can JSON-escape it via writeJsonString.
        var ascii_buf = std.array_list.Managed(u8).init(ctx.allocator);
        defer ascii_buf.deinit();
        for (bytes) |b| {
            if (b >= 0x20 and b <= 0x7E) {
                ascii_buf.append(b) catch {};
            } else {
                ascii_buf.append('.') catch {};
            }
        }
        // We're emitting raw inside an existing string literal, so escape any
        // characters that would break JSON. The ascii buffer can only contain
        // printable ASCII or '.', so we just need to escape '"' and '\\'.
        for (ascii_buf.items) |c| {
            if (c == '"' or c == '\\') w.writeByte('\\') catch {};
            w.writeByte(c) catch {};
        }
        w.writeByte('"') catch {};
    }
    w.writeByte('}') catch {};

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "read_bytes", result_json, elapsed) catch return ToolError.OutOfMemory;
    // Page limits above leave sufficient headroom in this response envelope,
    // including worst-case JSON escaping of the ASCII preview.
    return .{ .json_response = resp, .meta_max_chars = 200_000 };
}

// ============================================================================
// v7.4.3 F5 — get_embedded_resources MCP tool
// ============================================================================
//
// Surfaces structured runtime resources as first-class facts so the LLM
// doesn't have to discover them via byte-grep. Iterates the RuntimeAdapter
// registry from analysis/strings.zig:ADAPTERS — adding a new runtime is a
// one-line append there.

fn handleGetEmbeddedResources(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_embedded_resources", params);
    };

    const filter_runtime = getString(params, "runtime");
    // v7.16 bonus: summarize WHAT'S IN the bundle (categorized surface markers +
    // codename clusters), not just its metadata. Default on; opt out for speed.
    const include_surface = getBool(params, "include_surface") orelse true;

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_embedded_resources");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;
    w.writeAll("{\"doc_id\":") catch {};
    w.print("{d}", .{doc_id}) catch {};
    w.writeAll(",\"resources\":[") catch {};

    var first_resource = true;
    // v7.14.0 B2: per-runtime info now carries the resolved next_target so
    // get_embedded_resources can emit objects (not just names).
    const RuntimeInfo = struct { name: []const u8, next_target: ?[]u8 };
    var detected_runtimes = std.array_list.Managed(RuntimeInfo).init(ctx.allocator);
    defer {
        for (detected_runtimes.items) |ri| {
            if (ri.next_target) |nt| ctx.allocator.free(nt);
        }
        detected_runtimes.deinit();
    }

    for (strings_mod.ADAPTERS) |adapter| {
        // Optional filter — skip adapters whose name doesn't match.
        if (filter_runtime) |fr| {
            if (!std.ascii.eqlIgnoreCase(fr, adapter.name)) continue;
        }
        if (!adapter.detect(&eff.entry.doc)) continue;
        const nt: ?[]u8 = if (adapter.next_target_template) |tpl|
            strings_mod.resolveNextTarget(ctx.allocator, tpl, eff.entry.doc.path)
        else
            null;
        detected_runtimes.append(.{ .name = adapter.name, .next_target = nt }) catch {};

        if (adapter.enumerate_resources) |enumer| {
            var list = enumer(ctx.allocator, &eff.entry.doc) catch continue;
            defer list.deinit();
            for (list.items.items) |r| {
                if (!first_resource) w.writeByte(',') catch {};
                first_resource = false;
                w.writeAll("{\"runtime\":") catch {};
                json.writeJsonString(w, r.runtime) catch {};
                w.writeAll(",\"name\":") catch {};
                json.writeJsonString(w, r.name) catch {};
                w.writeAll(",\"kind\":") catch {};
                json.writeJsonString(w, r.kind) catch {};
                w.print(",\"size\":{d}", .{r.size}) catch {};
                w.writeAll(",\"address\":") catch {};
                json.writeAddress(w, applyRebaseDelta(r.address, eff.delta)) catch {};
                w.print(",\"file_offset\":{d}", .{r.file_offset}) catch {};
                w.writeAll(",\"preview\":") catch {};
                json.writeJsonString(w, r.preview) catch {};
                w.writeAll(",\"provenance\":") catch {};
                json.writeJsonString(w, r.provenance) catch {};
                w.writeByte('}') catch {};
            }
        }
    }

    w.writeAll("],\"runtimes_detected\":[") catch {};
    for (detected_runtimes.items, 0..) |ri, i| {
        if (i > 0) w.writeByte(',') catch {};
        json.writeJsonString(w, ri.name) catch {};
    }
    w.writeAll("],\"runtimes\":[") catch {};
    for (detected_runtimes.items, 0..) |ri, i| {
        if (i > 0) w.writeByte(',') catch {};
        w.writeAll("{\"name\":") catch {};
        json.writeJsonString(w, ri.name) catch {};
        if (ri.next_target) |nt| {
            w.writeAll(",\"next_target\":") catch {};
            json.writeJsonString(w, nt) catch {};
        }
        w.writeByte('}') catch {};
    }
    w.writeAll("]") catch {};

    // v7.16 bonus — bundle surface summary: categorized markers + prefix
    // clusters over the embedded-runtime text, so the tool an LLM calls right
    // after runtime detection answers "what's IN it" instead of just "where".
    if (include_surface and strings_mod.hasPackedSegment(&eff.entry.doc)) {
        const surface_cap: usize = 500_000;
        var bundle = strings_mod.detectBundleStrings(ctx.allocator, &eff.entry.doc, 5, surface_cap) catch null;
        if (bundle) |*b| {
            defer b.deinit();
            const truncated = b.items.len >= surface_cap;
            var seen = std.StringHashMap(void).init(ctx.allocator);
            defer seen.deinit();
            var hist = std.StringHashMap(usize).init(ctx.allocator);
            defer hist.deinit();
            var by_cat = std.StringHashMap(std.array_list.Managed([]const u8)).init(ctx.allocator);
            defer by_cat.deinit();
            const CI2 = struct { count: usize, example: []const u8 };
            var clusters = std.StringHashMap(CI2).init(ctx.allocator);
            defer clusters.deinit();
            const per_cat_cap: usize = 12;

            for (b.items) |s| {
                if (seen.contains(s.value)) continue;
                var cats: [MAX_CAP_CATS][]const u8 = undefined;
                const n = categorizeCapability(s.value, &cats);
                if (n == 0) continue;
                seen.put(s.value, {}) catch {};
                for (cats[0..n]) |cat| {
                    const gh = hist.getOrPut(cat) catch continue;
                    if (!gh.found_existing) gh.value_ptr.* = 0;
                    gh.value_ptr.* += 1;
                    const gc = by_cat.getOrPut(cat) catch continue;
                    if (!gc.found_existing) gc.value_ptr.* = std.array_list.Managed([]const u8).init(ctx.allocator);
                    if (gc.value_ptr.items.len < per_cat_cap) gc.value_ptr.append(s.value) catch {};
                }
                if (capClusterPrefix(s.value)) |pfx| {
                    const g = clusters.getOrPut(pfx) catch continue;
                    if (!g.found_existing) g.value_ptr.* = .{ .count = 0, .example = s.value };
                    g.value_ptr.count += 1;
                }
            }

            w.writeAll(",\"surface\":{\"scanned\":true") catch {};
            if (truncated) w.writeAll(",\"truncated\":true") catch {};
            w.writeAll(",\"category_histogram\":{") catch {};
            {
                var hi = hist.iterator();
                var f = true;
                while (hi.next()) |e| {
                    if (!f) w.writeByte(',') catch {};
                    f = false;
                    json.writeJsonString(w, e.key_ptr.*) catch {};
                    w.print(":{d}", .{e.value_ptr.*}) catch {};
                }
            }
            w.writeAll("},\"top_markers\":{") catch {};
            {
                var bi = by_cat.iterator();
                var f = true;
                while (bi.next()) |e| {
                    if (!f) w.writeByte(',') catch {};
                    f = false;
                    json.writeJsonString(w, e.key_ptr.*) catch {};
                    w.writeAll(":[") catch {};
                    for (e.value_ptr.items, 0..) |v, i| {
                        if (i > 0) w.writeByte(',') catch {};
                        json.writeJsonString(w, v) catch {};
                    }
                    w.writeAll("]") catch {};
                }
            }
            w.writeAll("},\"clusters\":[") catch {};
            {
                const CRow2 = struct { prefix: []const u8, count: usize, example: []const u8 };
                var rows = std.array_list.Managed(CRow2).init(ctx.allocator);
                var ci = clusters.iterator();
                while (ci.next()) |e| {
                    if (e.value_ptr.count >= 2) rows.append(.{ .prefix = e.key_ptr.*, .count = e.value_ptr.count, .example = e.value_ptr.example }) catch {};
                }
                std.sort.pdq(CRow2, rows.items, {}, struct {
                    fn lt(_: void, a: CRow2, bb: CRow2) bool {
                        return a.count > bb.count;
                    }
                }.lt);
                const rn = @min(rows.items.len, 24);
                for (rows.items[0..rn], 0..) |row, i| {
                    if (i > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"prefix\":") catch {};
                    json.writeJsonString(w, row.prefix) catch {};
                    w.print(",\"count\":{d},\"example\":", .{row.count}) catch {};
                    json.writeJsonString(w, row.example) catch {};
                    w.writeByte('}') catch {};
                }
            }
            w.writeAll("]}") catch {};
        }
    }

    w.writeAll("}") catch {};

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "get_embedded_resources", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .meta_max_chars = 200_000 };
}

// ============================================================================
// 1A. rebase_document tool
// ============================================================================

fn handleRebaseDocument(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = getDocIdValidated(params) orelse {
        // Rebase requires numeric doc_id for safety. But still list what's available.
        var buf = std.Io.Writer.Allocating.init(ctx.allocator);
        const w = &buf.writer;
        w.writeAll("rebase_document requires a numeric doc_id for safety. Loaded: ") catch {};
        var first = true;
        ctx.store.mutex.lockUncancelable(ctx.io);
        var it = ctx.store.documents.iterator();
        while (it.next()) |entry| {
            if (!first) w.writeAll(", ") catch {};
            first = false;
            w.print("{d}={s}", .{ entry.key_ptr.*, std.fs.path.basename(entry.value_ptr.*.doc.path) }) catch {};
        }
        ctx.store.mutex.unlock(ctx.io);
        const msg = buf.toOwnedSlice() catch "rebase_document requires a numeric doc_id";
        const resp = json.errorResponse(ctx.allocator, "rebase_document", msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    const new_base_raw = getInt(params, "new_base_address") orelse getInt(params, "new_base") orelse getInt(params, "base") orelse {
        const resp = json.errorResponse(ctx.allocator, "rebase_document", "missing required parameter: new_base_address", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    const new_base: u64 = @bitCast(new_base_raw);

    const parent_entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "rebase_document");

    // Determine current base: first loadable segment start (typically __TEXT at 0x100000000).
    // This is more intuitive than entry_point — when a user says "rebase to 0x200000000",
    // they mean "put __TEXT at 0x200000000", not "put the entry point there".
    var old_base: u64 = 0;
    for (parent_entry.doc.segments) |seg| {
        if (seg.permissions.read or seg.permissions.execute) {
            if (seg.start > 0) {
                old_base = seg.start;
                break;
            }
        }
    }
    if (old_base == 0 and parent_entry.doc.entry_point != 0) {
        old_base = parent_entry.doc.entry_point;
    }

    const delta: i128 = @as(i128, new_base) - @as(i128, old_base);

    // Flatten: if parent is itself a rebased view, use parent's parent + combined delta
    var effective_parent = parent_entry;
    var effective_parent_id = doc_id;
    var effective_delta = delta;
    if (parent_entry.rebase_parent) |grandparent| {
        effective_parent = grandparent;
        effective_parent_id = parent_entry.rebase_parent_id.?;
        effective_delta = parent_entry.rebase_delta + delta;
    }

    // Create new DocumentEntry as a rebased view with empty db (reads delegate to parent).
    // v7.15.0 B1: rebased views also live on store_alloc so they outlive the
    // request arena.
    const store_alloc = ctx.store.allocator;
    const new_doc_id = ctx.store.nextId();
    const new_entry = store_alloc.create(DocumentEntry) catch return ToolError.OutOfMemory;

    // Build modified path
    const abs_delta = if (effective_delta < 0) @as(u128, @bitCast(-effective_delta)) else @as(u128, @bitCast(effective_delta));
    const sign_char: u8 = if (effective_delta < 0) '-' else '+';
    const new_path = std.fmt.allocPrint(store_alloc, "{s} [rebased {c}0x{x}]", .{ parent_entry.doc.path, sign_char, abs_delta }) catch return ToolError.OutOfMemory;

    new_entry.* = .{
        .doc = types.Document.init(store_alloc, new_doc_id, new_path, &.{}),
        .db = Database.init(store_alloc, ctx.io),
        .rebase_parent = effective_parent,
        .rebase_parent_id = effective_parent_id,
        .rebase_delta = effective_delta,
        // v7.15.0 B1: rebased view owns its synthesized path string but not
        // any data (data is empty; reads delegate to parent doc).
        .owns_data = false,
        .owns_path = true,
    };
    // Copy format/arch from parent
    new_entry.doc.format = parent_entry.doc.format;
    new_entry.doc.arch = parent_entry.doc.arch;
    new_entry.doc.entry_point = applyRebaseDelta(parent_entry.doc.entry_point, delta);

    ctx.store.put(new_entry) catch return ToolError.OutOfMemory;
    // v7.16 W5: a rebased view is a new doc id (+ its phora://doc/{id} resource).
    ctx.queueNotification("notifications/tools/list_changed");
    ctx.queueNotification("notifications/resources/list_changed");

    const elapsed = timestampMs(ctx.io) - start;
    const result_str = std.fmt.allocPrint(ctx.allocator, "{{\"doc_id\":{d},\"parent_doc_id\":{d},\"old_base\":\"0x{x}\",\"new_base\":\"0x{x}\",\"delta\":{d}}}", .{ new_doc_id, doc_id, old_base, new_base, effective_delta }) catch return ToolError.OutOfMemory;
    const resp = json.successResponse(ctx.allocator, "rebase_document", result_str, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

// ============================================================================
// 1B. mark_data_type tool
// ============================================================================

fn handleMarkDataType(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "mark_data_type", params);
    };
    const address: u64 = @bitCast(getInt(params, "address") orelse {
        const resp = json.errorResponse(ctx.allocator, "mark_data_type", "missing required parameter: address", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    });
    const data_type_str = getString(params, "data_type") orelse getString(params, "type") orelse {
        const resp = json.errorResponse(ctx.allocator, "mark_data_type", "missing required parameter: data_type", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    const length: u64 = if (getInt(params, "length")) |l| @bitCast(l) else 1;

    // Validate data_type
    const valid_types = [_][]const u8{ "code", "int8", "int16", "int32", "int64", "ascii", "unicode", "byte_array" };
    var type_valid = false;
    for (valid_types) |vt| {
        if (std.ascii.eqlIgnoreCase(data_type_str, vt)) {
            type_valid = true;
            break;
        }
    }
    if (!type_valid) {
        const resp = json.errorResponse(ctx.allocator, "mark_data_type", "invalid data_type; valid types: code, int8, int16, int32, int64, ascii, unicode, byte_array", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "mark_data_type");
    const eff = resolveEffectiveDb(entry);

    // Validate address against effective (parent) segments, with rebase delta.
    const check_addr = if (eff.delta != 0) removeRebaseDelta(address, eff.delta) else address;
    if (!isAddressInMutableSegments(check_addr, eff.entry.doc.segments)) {
        const err_msg = std.fmt.allocPrint(ctx.allocator, "address 0x{x} is outside all known segments; use get_segments to see valid ranges", .{address}) catch "address outside segments";
        const resp = json.errorResponse(ctx.allocator, "mark_data_type", err_msg, 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    entry.db.rw_lock.lockUncancelable(entry.db.io);
    defer entry.db.rw_lock.unlock(entry.db.io);

    // Format annotation value: "int32" or "byte_array:64"
    const value = if (length > 1)
        std.fmt.allocPrint(ctx.allocator, "{s}:{d}", .{ data_type_str, length }) catch return ToolError.OutOfMemory
    else
        data_type_str;

    entry.db.addAnnotation(.{
        .address = address,
        .kind = .type_override,
        .value = value,
        .session_id = ctx.session_id,
        .timestamp = runtime.awakeMillis(ctx.io),
    }) catch {
        const resp = json.errorResponse(ctx.allocator, "mark_data_type", "failed to add annotation", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    const elapsed = timestampMs(ctx.io) - start;
    const result_str = std.fmt.allocPrint(ctx.allocator, "{{\"success\":true,\"address\":\"0x{x}\",\"data_type\":\"{s}\",\"length\":{d}}}", .{ address, data_type_str, length }) catch return ToolError.OutOfMemory;
    const resp = json.successResponse(ctx.allocator, "mark_data_type", result_str, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

// ============================================================================
// 1C. get_demangled_name tool — inline Swift demangler (basic)
// ============================================================================

/// Basic Swift symbol demangler. Parses $s/<module-len><module><type-len><type><member-len><member> patterns.
fn tryDemangleSwift(allocator: Allocator, name: []const u8) ?[]const u8 {
    // Swift mangled names start with "$s" or "_$s"
    var s = name;
    if (s.len > 1 and s[0] == '_') s = s[1..];
    if (s.len < 3 or s[0] != '$' or s[1] != 's') return null;
    s = s[2..];

    // Parse length-prefixed components: <decimal-length><chars>
    var parts: [3][]const u8 = .{ "", "", "" };
    var pi: usize = 0;
    while (pi < 3 and s.len > 0 and s[0] >= '0' and s[0] <= '9') {
        var n: usize = 0;
        while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
            n = n * 10 + (s[0] - '0');
            s = s[1..];
        }
        if (n == 0 or n > s.len) break;
        parts[pi] = s[0..n];
        s = s[n..];
        pi += 1;
    }
    if (pi == 0) return null;

    // Format: Module.Type.member or Module.member
    var buf = std.array_list.Managed(u8).init(allocator);
    buf.appendSlice(parts[0]) catch return null;
    if (pi > 1 and parts[1].len > 0) {
        buf.append('.') catch return null;
        buf.appendSlice(parts[1]) catch return null;
    }
    if (pi > 2 and parts[2].len > 0) {
        buf.append('.') catch return null;
        buf.appendSlice(parts[2]) catch return null;
    }
    if (s.len > 0) {
        // Append suffix hint
        const suffix = switch (s[0]) {
            'F' => "()",
            'C' => ".init()",
            'g' => ".getter",
            's' => ".setter",
            else => "",
        };
        buf.appendSlice(suffix) catch return null;
    }
    return buf.toOwnedSlice() catch null;
}

fn parseItaniumType(allocator: Allocator, input: []const u8, pos: *usize) ?[]const u8 {
    if (pos.* >= input.len) return null;
    const c = input[pos.*];
    pos.* += 1;
    return switch (c) {
        'v' => "void",
        'b' => "bool",
        'c' => "char",
        'i' => "int",
        'l' => "long",
        'd' => "double",
        'f' => "float",
        's' => "short",
        'j' => "unsigned int",
        'm' => "unsigned long",
        'x' => "long long",
        'y' => "unsigned long long",
        'P' => blk: {
            const inner = parseItaniumType(allocator, input, pos) orelse break :blk null;
            break :blk std.fmt.allocPrint(allocator, "{s}*", .{inner}) catch null;
        },
        'R' => blk: {
            const inner = parseItaniumType(allocator, input, pos) orelse break :blk null;
            break :blk std.fmt.allocPrint(allocator, "{s}&", .{inner}) catch null;
        },
        'K' => blk: {
            const inner = parseItaniumType(allocator, input, pos) orelse break :blk null;
            break :blk std.fmt.allocPrint(allocator, "const {s}", .{inner}) catch null;
        },
        'N' => blk: {
            // Nested name: parse components until E
            var buf = std.array_list.Managed(u8).init(allocator);
            while (pos.* < input.len and input[pos.*] != 'E') {
                if (input[pos.*] == 'S' and pos.* + 1 < input.len and input[pos.* + 1] == 't') {
                    if (buf.items.len > 0) buf.appendSlice("::") catch {};
                    buf.appendSlice("std") catch {};
                    pos.* += 2;
                } else if (input[pos.*] >= '0' and input[pos.*] <= '9') {
                    if (buf.items.len > 0 and !std.mem.endsWith(u8, buf.items, "::")) buf.appendSlice("::") catch {};
                    var len: usize = 0;
                    while (pos.* < input.len and input[pos.*] >= '0' and input[pos.*] <= '9') {
                        len = len * 10 + (input[pos.*] - '0');
                        pos.* += 1;
                    }
                    if (pos.* + len <= input.len) {
                        buf.appendSlice(input[pos.* .. pos.* + len]) catch {};
                        pos.* += len;
                    } else break;
                } else if (input[pos.*] == 'I') {
                    // Template args — attach directly to preceding component, no ::
                    pos.* += 1;
                    buf.append('<') catch {};
                    var first_tmpl = true;
                    while (pos.* < input.len and input[pos.*] != 'E') {
                        // Defer the comma until we know we have content. parseItaniumType
                        // returns null for substitution references (S_, S<n>_), which it
                        // does correctly *consume* — emitting a separator first would leave
                        // an orphaned ", " in the output ("ratio<,, >").
                        if (parseItaniumType(allocator, input, pos)) |type_str| {
                            if (!first_tmpl) buf.appendSlice(", ") catch {};
                            first_tmpl = false;
                            buf.appendSlice(type_str) catch {};
                        }
                        // If null, parseItaniumType already advanced pos past whatever it
                        // couldn't render — we just skip emitting anything for this arg.
                    }
                    if (pos.* < input.len and input[pos.*] == 'E') pos.* += 1;
                    buf.append('>') catch {};
                } else if (input[pos.*] == 'S') {
                    // Substitution references: S_, S0_, S1_, etc. — consume, no text
                    pos.* += 1;
                    if (pos.* < input.len and input[pos.*] == '_') {
                        pos.* += 1;
                    } else {
                        while (pos.* < input.len and input[pos.*] != '_' and input[pos.*] != 'E') pos.* += 1;
                        if (pos.* < input.len and input[pos.*] == '_') pos.* += 1;
                    }
                } else break;
            }
            if (pos.* < input.len and input[pos.*] == 'E') pos.* += 1;
            break :blk buf.toOwnedSlice() catch null;
        },
        '0'...'9' => blk: {
            pos.* -= 1; // back up to re-read digit
            var len: usize = 0;
            while (pos.* < input.len and input[pos.*] >= '0' and input[pos.*] <= '9') {
                len = len * 10 + (input[pos.*] - '0');
                pos.* += 1;
            }
            if (pos.* + len <= input.len) {
                const n = input[pos.* .. pos.* + len];
                pos.* += len;
                break :blk allocator.dupe(u8, n) catch null;
            }
            break :blk null;
        },
        'S' => blk_s: {
            // Substitution references: St=std::, S_=first sub, S<n>_=nth sub
            if (pos.* < input.len) {
                if (input[pos.*] == 't') {
                    pos.* += 1;
                    // St optionally followed by length-prefixed name
                    if (pos.* < input.len and input[pos.*] >= '0' and input[pos.*] <= '9') {
                        var len: usize = 0;
                        while (pos.* < input.len and input[pos.*] >= '0' and input[pos.*] <= '9') {
                            len = len * 10 + (input[pos.*] - '0');
                            pos.* += 1;
                        }
                        if (pos.* + len <= input.len) {
                            const name = input[pos.* .. pos.* + len];
                            pos.* += len;
                            break :blk_s std.fmt.allocPrint(allocator, "std::{s}", .{name}) catch null;
                        }
                    }
                    break :blk_s allocator.dupe(u8, "std") catch null;
                } else if (input[pos.*] == '_') {
                    // S_ = first substitution, consume token
                    pos.* += 1;
                    break :blk_s null;
                } else {
                    // S<seq-id>_ where seq-id is base-36
                    while (pos.* < input.len and input[pos.*] != '_' and input[pos.*] != 'E') pos.* += 1;
                    if (pos.* < input.len and input[pos.*] == '_') pos.* += 1;
                    break :blk_s null;
                }
            }
            break :blk_s null;
        },
        else => null,
    };
}

// ============================================================================
// Rust Symbol Demangling (legacy + v0)
// ============================================================================

/// Rust v0 mangling helper: skip a disambiguator (base-62 number prefixed by 's', ending in '_').
fn skipRustV0Disambiguator(input: []const u8, pos: *usize) void {
    if (pos.* < input.len and input[pos.*] == 's') {
        pos.* += 1;
        while (pos.* < input.len and input[pos.*] != '_') pos.* += 1;
        if (pos.* < input.len) pos.* += 1; // skip trailing _
    }
}

/// Rust v0 mangling helper: parse a length-prefixed identifier.
fn parseRustV0Ident(input: []const u8, pos: *usize, buf: *std.array_list.Managed(u8)) bool {
    if (pos.* >= input.len) return false;
    var len: usize = 0;
    var has_digit = false;
    while (pos.* < input.len and input[pos.*] >= '0' and input[pos.*] <= '9') {
        len = len * 10 + @as(usize, input[pos.*] - '0');
        pos.* += 1;
        has_digit = true;
    }
    if (!has_digit) return false;
    // Skip the '_' separator between length and name (if present and length > 0)
    if (pos.* < input.len and input[pos.*] == '_') pos.* += 1;
    if (len == 0 or pos.* + len > input.len) return false;
    buf.appendSlice(input[pos.* .. pos.* + len]) catch {};
    pos.* += len;
    return true;
}

/// Rust v0 mangling helper: parse a basic type code.
fn parseRustV0Type(input: []const u8, pos: *usize, buf: *std.array_list.Managed(u8)) bool {
    if (pos.* >= input.len) return false;
    const c = input[pos.*];
    pos.* += 1;
    switch (c) {
        'a' => {
            buf.appendSlice("i8") catch {};
            return true;
        },
        'b' => {
            buf.appendSlice("bool") catch {};
            return true;
        },
        'c' => {
            buf.appendSlice("char") catch {};
            return true;
        },
        'd' => {
            buf.appendSlice("f64") catch {};
            return true;
        },
        'e' => {
            buf.appendSlice("str") catch {};
            return true;
        },
        'f' => {
            buf.appendSlice("f32") catch {};
            return true;
        },
        'h' => {
            buf.appendSlice("u8") catch {};
            return true;
        },
        'i' => {
            buf.appendSlice("i32") catch {};
            return true;
        },
        'j' => {
            buf.appendSlice("u32") catch {};
            return true;
        },
        'l' => {
            buf.appendSlice("i64") catch {};
            return true;
        },
        'm' => {
            buf.appendSlice("u64") catch {};
            return true;
        },
        'o' => {
            buf.appendSlice("u128") catch {};
            return true;
        },
        'u' => {
            buf.appendSlice("()") catch {};
            return true;
        },
        'z' => {
            buf.appendSlice("!") catch {};
            return true;
        },
        'R' => {
            buf.append('&') catch {};
            return parseRustV0Type(input, pos, buf);
        },
        'Q' => {
            buf.appendSlice("&mut ") catch {};
            return parseRustV0Type(input, pos, buf);
        },
        'P' => {
            buf.appendSlice("*const ") catch {};
            return parseRustV0Type(input, pos, buf);
        },
        'O' => {
            buf.appendSlice("*mut ") catch {};
            return parseRustV0Type(input, pos, buf);
        },
        else => {
            pos.* -= 1;
            return parseRustV0Path(input, pos, buf);
        },
    }
}

/// Rust v0 mangling helper: parse a path (C = crate root, N = nested, M = impl, X = trait impl).
fn parseRustV0Path(input: []const u8, pos: *usize, buf: *std.array_list.Managed(u8)) bool {
    if (pos.* >= input.len) return false;
    switch (input[pos.*]) {
        'C' => { // Crate root: C <disambiguator> <identifier>
            pos.* += 1;
            skipRustV0Disambiguator(input, pos);
            return parseRustV0Ident(input, pos, buf);
        },
        'N' => { // Nested path: N <namespace> <path> <identifier>
            pos.* += 1;
            if (pos.* < input.len) {
                const ns = input[pos.*];
                // Namespace tags are lowercase letters; uppercase = next path tag, not namespace
                if (ns >= 'a' and ns <= 'z') {
                    pos.* += 1; // skip namespace tag (v=value, t=type, etc.)
                }
            }
            if (!parseRustV0Path(input, pos, buf)) return false;
            buf.appendSlice("::") catch {};
            skipRustV0Disambiguator(input, pos);
            return parseRustV0Ident(input, pos, buf);
        },
        'M' => { // Inherent impl: M <disambiguator> <type>
            pos.* += 1;
            skipRustV0Disambiguator(input, pos);
            buf.append('<') catch {};
            _ = parseRustV0Type(input, pos, buf);
            buf.append('>') catch {};
            return true;
        },
        'X' => { // Trait impl: X <disambiguator> <type> <path>
            pos.* += 1;
            skipRustV0Disambiguator(input, pos);
            buf.append('<') catch {};
            _ = parseRustV0Type(input, pos, buf);
            buf.appendSlice(" as ") catch {};
            _ = parseRustV0Path(input, pos, buf);
            buf.append('>') catch {};
            return true;
        },
        else => return false,
    }
}

/// Demangle a Rust v0 mangled symbol (_R prefix).
fn demangleRustV0(allocator: Allocator, input: []const u8) ?[]const u8 {
    var pos: usize = 0;
    var buf = std.array_list.Managed(u8).init(allocator);
    if (!parseRustV0Path(input, &pos, &buf)) {
        buf.deinit();
        return null;
    }
    if (buf.items.len == 0) {
        buf.deinit();
        return null;
    }
    return buf.toOwnedSlice() catch null;
}

/// Rust symbol demangler. Handles both legacy Rust mangling (_ZN...E with $ escapes)
/// and Rust v0 mangling (_R prefix). Returns null for non-Rust or unparseable symbols.
fn tryDemangleRust(allocator: Allocator, name: []const u8) ?[]const u8 {
    var s = name;
    // Strip Mach-O leading underscores
    while (s.len > 0 and s[0] == '_') s = s[1..];

    // --- Rust v0 mangling: starts with R followed by an uppercase letter ---
    if (s.len >= 2 and s[0] == 'R' and s[1] >= 'A' and s[1] <= 'Z') {
        return demangleRustV0(allocator, s[1..]);
    }

    // --- Legacy Rust mangling: starts with ZN and contains $ ---
    if (s.len < 3 or s[0] != 'Z' or s[1] != 'N') return null;

    // v7.12 W2: must contain a Rust-specific escape token OR a Rust hash
    // suffix to distinguish from plain C++ Itanium ABI. A bare `$` is not
    // enough — Itanium ABI permits `$` in identifiers too. Require a
    // recognized punycode-style escape (`$LT$`, `$GT$`, `$RF$`, `$u20$`,
    // `$C$`, `$LP$`, `$RP$`, `$u7b$`, `$u7d$`, `$u5b$`, `$u5d$`) OR the
    // legacy hash suffix `17h<16 hex>E`. This keeps `_ZN3RBX5Voice7StratusE`
    // (pure Itanium C++) from being accepted as Rust and falling through to
    // the misclassification path.
    const rust_tokens = [_][]const u8{
        "$LT$",  "$GT$", "$RF$",  "$u20$", "$C$",
        "$LP$",  "$RP$", "$u7b$", "$u7d$", "$u5b$",
        "$u5d$",
    };
    var has_rust_token = false;
    for (rust_tokens) |tok| {
        if (std.mem.indexOf(u8, s, tok) != null) {
            has_rust_token = true;
            break;
        }
    }
    const has_rust_hash = blk: {
        if (s.len > 21 and s[s.len - 1] == 'E') {
            // Check last component is 17h + 16 hex digits
            const inner = s[2 .. s.len - 1]; // between ZN and E
            if (inner.len >= 19) {
                const hs = inner.len - 19;
                if (inner[hs] == '1' and inner[hs + 1] == '7' and inner[hs + 2] == 'h') {
                    for (inner[hs + 3 ..]) |c| {
                        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) break :blk false;
                    }
                    break :blk true;
                }
            }
        }
        break :blk false;
    };

    if (!has_rust_token and !has_rust_hash) return null;

    s = s[2..]; // skip ZN

    var buf = std.array_list.Managed(u8).init(allocator);
    var first = true;

    while (s.len > 0 and s[0] != 'E') {
        // Parse length prefix
        var comp_len: usize = 0;
        var has_digit = false;
        while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
            comp_len = comp_len * 10 + @as(usize, s[0] - '0');
            s = s[1..];
            has_digit = true;
        }
        if (!has_digit or comp_len == 0 or comp_len > s.len) break;

        const component = s[0..comp_len];
        s = s[comp_len..];

        // Check if this is a hash suffix (last component before E)
        if (s.len > 0 and s[0] == 'E' and comp_len == 17 and component[0] == 'h') {
            var is_hash = true;
            for (component[1..]) |ch| {
                if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) {
                    is_hash = false;
                    break;
                }
            }
            if (is_hash) continue; // Skip hash suffix
        }

        if (!first) buf.appendSlice("::") catch {};
        first = false;

        // Unescape the component: replace $XX$ sequences and .. with ::
        var i: usize = 0;
        // In Rust legacy mangling, a leading '_' before '$' is a padding
        // character used for impl blocks -- skip it.
        if (component.len > 1 and component[0] == '_' and component[1] == '$') {
            i = 1;
        }
        while (i < component.len) {
            if (component[i] == '$') {
                const rest = component[i + 1 ..];
                if (std.mem.startsWith(u8, rest, "LT$")) {
                    buf.append('<') catch {};
                    i += 4;
                } else if (std.mem.startsWith(u8, rest, "GT$")) {
                    buf.append('>') catch {};
                    i += 4;
                    // After closing '>', remaining chars may contain embedded
                    // length-prefixed sub-components (e.g. "3fmt17h...").
                    while (i < component.len and component[i] >= '0' and component[i] <= '9') {
                        var sub_len: usize = 0;
                        while (i < component.len and component[i] >= '0' and component[i] <= '9') {
                            sub_len = sub_len * 10 + @as(usize, component[i] - '0');
                            i += 1;
                        }
                        if (sub_len == 0) break;
                        // If sub-component extends past the component boundary,
                        // check if it's a truncated hash (length prefix 17, next char 'h').
                        // The hash spills past the mega-component into the outer string.
                        if (i + sub_len > component.len) {
                            if (sub_len == 17 and i < component.len and component[i] == 'h') {
                                // Truncated hash suffix — skip remaining chars
                                i = component.len;
                            }
                            break;
                        }
                        const sub = component[i .. i + sub_len];
                        i += sub_len;
                        // Skip hash suffix (17 chars, 'h' + 16 hex digits)
                        if (sub_len == 17 and sub[0] == 'h') {
                            var is_hash = true;
                            for (sub[1..]) |hc| {
                                if (!((hc >= '0' and hc <= '9') or (hc >= 'a' and hc <= 'f'))) {
                                    is_hash = false;
                                    break;
                                }
                            }
                            if (is_hash) continue;
                        }
                        buf.appendSlice("::") catch {};
                        buf.appendSlice(sub) catch {};
                    }
                } else if (std.mem.startsWith(u8, rest, "C$")) {
                    buf.appendSlice(", ") catch {};
                    i += 3;
                } else if (std.mem.startsWith(u8, rest, "u20$")) {
                    buf.append(' ') catch {};
                    i += 5;
                } else if (std.mem.startsWith(u8, rest, "RF$")) {
                    buf.append('&') catch {};
                    i += 4;
                } else if (std.mem.startsWith(u8, rest, "LP$")) {
                    buf.append('(') catch {};
                    i += 4;
                } else if (std.mem.startsWith(u8, rest, "RP$")) {
                    buf.append(')') catch {};
                    i += 4;
                } else if (std.mem.startsWith(u8, rest, "u7b$")) {
                    buf.append('{') catch {};
                    i += 5;
                } else if (std.mem.startsWith(u8, rest, "u7d$")) {
                    buf.append('}') catch {};
                    i += 5;
                } else if (std.mem.startsWith(u8, rest, "u5b$")) {
                    buf.append('[') catch {};
                    i += 5;
                } else if (std.mem.startsWith(u8, rest, "u5d$")) {
                    buf.append(']') catch {};
                    i += 5;
                } else {
                    buf.append('$') catch {};
                    i += 1;
                }
            } else if (component[i] == '.' and i + 1 < component.len and component[i + 1] == '.') {
                buf.appendSlice("::") catch {};
                i += 2;
            } else {
                buf.append(component[i]) catch {};
                i += 1;
            }
        }
    }

    if (buf.items.len == 0) {
        buf.deinit();
        return null;
    }
    return buf.toOwnedSlice() catch null;
}

/// C++ Itanium ABI demangler. Handles nested names (_ZN...E), simple names (_Z<len>...),
/// vtables/typeinfo (TV/TI/TS/TT), global operators, global std:: (St), destructors,
/// constructors, and template indicators. Returns null for anything it can't parse.
fn tryDemangleCpp(allocator: Allocator, name: []const u8) ?[]const u8 {
    // v7.8.2: hard-cap input length. The deeply-templated C++ symbols in
    // dyld/Swift runtime (200+ bytes) trigger pathological behaviour in this
    // hand-rolled parser. Anything legitimately useful demangles well under
    // 256 bytes; bigger names just stay raw.
    if (name.len > 256) return null;

    var s = name;
    // Strip leading underscore (macOS convention: __Z... or _Z...)
    if (s.len > 2 and s[0] == '_' and s[1] == '_' and s[2] == 'Z') {
        s = s[3..]; // strip __Z
    } else if (s.len > 2 and s[0] == '_' and s[1] == 'Z') {
        s = s[2..]; // strip _Z
    } else {
        return null;
    }

    // v7.13.0 B4 — extended Itanium ABI prefix support beyond `_ZN…E`.
    //   Z + L<num>...     → internal linkage function. Example:
    //                       _ZL22getkFigSTSLabel_Globalv → getkFigSTSLabel_Global()
    //   Z + GV<rest>      → guard variable for static-local initialization.
    //   Z + TI<rest>      → typeinfo for <rest>          (handled by 'T' branch below)
    //   Z + TS<rest>      → typeinfo string for <rest>   (handled by 'T' branch)
    //   Z + Thn<offset>_<sym>  → virtual non-virtual thunk to <sym>
    //   Z + Tv<vcall>_<vbase>_<sym> → virtual covariant thunk to <sym>
    //
    // The 'T'-prefixed cases (TI/TS/TT/TV) already work in the existing
    // branch below. We add explicit handling for 'L', 'GV', and the thunk
    // forms here so the 'N…E' parser can consume the body.
    if (s.len > 0 and s[0] == 'L') {
        // _ZL<len><name><param-types>
        s = s[1..];
        var name_buf = std.array_list.Managed(u8).init(allocator);
        name_buf.appendSlice("(internal) ") catch return null;
        var len_v: usize = 0;
        while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
            len_v = len_v * 10 + @as(usize, s[0] - '0');
            s = s[1..];
        }
        if (len_v == 0 or len_v > s.len) return null;
        name_buf.appendSlice(s[0..len_v]) catch return null;
        s = s[len_v..];
        // Body params: 'v' = void, anything else just gets parens.
        if (s.len == 0) {
            name_buf.appendSlice("()") catch return null;
        } else if (s[0] == 'v') {
            name_buf.appendSlice("()") catch return null;
        } else {
            // Best-effort: emit parens but include a note about unparsed args.
            name_buf.appendSlice("(...)") catch return null;
        }
        return name_buf.toOwnedSlice() catch null;
    }

    if (s.len >= 2 and s[0] == 'G' and s[1] == 'V') {
        // _ZGV<rest> — guard variable for static initialization.
        s = s[2..];
        var name_buf = std.array_list.Managed(u8).init(allocator);
        name_buf.appendSlice("guard variable for ") catch return null;
        // Reuse the 'N...E' parser path if present; otherwise emit raw len-prefixed.
        if (s.len > 0 and s[0] == 'N') {
            s = s[1..];
            while (s.len > 0 and s[0] != 'E') {
                if (s[0] == 'K' or s[0] == 'V' or s[0] == 'r') {
                    s = s[1..];
                    continue;
                }
                var comp_len: usize = 0;
                while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
                    comp_len = comp_len * 10 + @as(usize, s[0] - '0');
                    s = s[1..];
                }
                if (comp_len == 0 or comp_len > s.len) break;
                if (name_buf.items.len > "guard variable for ".len and !std.mem.endsWith(u8, name_buf.items, "::")) {
                    name_buf.appendSlice("::") catch return null;
                }
                name_buf.appendSlice(s[0..comp_len]) catch return null;
                s = s[comp_len..];
            }
        } else {
            var len_v: usize = 0;
            while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
                len_v = len_v * 10 + @as(usize, s[0] - '0');
                s = s[1..];
            }
            if (len_v > 0 and len_v <= s.len) {
                name_buf.appendSlice(s[0..len_v]) catch return null;
            }
        }
        if (name_buf.items.len <= "guard variable for ".len) return null;
        return name_buf.toOwnedSlice() catch null;
    }

    if (s.len >= 2 and s[0] == 'T' and (s[1] == 'h' or s[1] == 'v')) {
        // _ZTh<offset>_<symbol>  /  _ZTv<vcall>_<vbase>_<symbol>
        // Strip the offset(s) then recursively demangle the trailing symbol.
        const prefix = if (s[1] == 'h') "non-virtual thunk to " else "virtual thunk to ";
        s = s[2..];
        // Skip n + digits + '_' (offset). For Tv, skip two such groups.
        const groups: u32 = if (std.mem.startsWith(u8, prefix, "virtual thunk")) 2 else 1;
        var grp: u32 = 0;
        while (grp < groups) : (grp += 1) {
            if (s.len > 0 and s[0] == 'n') s = s[1..];
            while (s.len > 0 and s[0] >= '0' and s[0] <= '9') s = s[1..];
            if (s.len > 0 and s[0] == '_') s = s[1..];
        }
        // The remainder is a mangled name without the leading _Z (it's the
        // body that follows). Synthesize "_Z" + remainder and recurse.
        const synth = std.fmt.allocPrint(allocator, "_Z{s}", .{s}) catch return null;
        defer allocator.free(synth);
        const inner = tryDemangleCpp(allocator, synth) orelse return null;
        defer allocator.free(inner);
        const out = std.fmt.allocPrint(allocator, "{s}{s}", .{ prefix, inner }) catch return null;
        return out;
    }

    var buf = std.array_list.Managed(u8).init(allocator);

    // --- (b) Global operators (before any other check) ---
    // Match with parameter type suffixes: nwm = new(unsigned long), dlPv = delete(void*), etc.
    if (s.len >= 2) {
        if (s[0] == 'n' and s[1] == 'w') {
            buf.appendSlice("operator new(unsigned long)") catch return null;
            return buf.toOwnedSlice() catch null;
        }
        if (s[0] == 'n' and s[1] == 'a') {
            buf.appendSlice("operator new[](unsigned long)") catch return null;
            return buf.toOwnedSlice() catch null;
        }
        if (s[0] == 'd' and s[1] == 'l') {
            buf.appendSlice("operator delete(void*)") catch return null;
            return buf.toOwnedSlice() catch null;
        }
        if (s[0] == 'd' and s[1] == 'a') {
            buf.appendSlice("operator delete[](void*)") catch return null;
            return buf.toOwnedSlice() catch null;
        }
    }

    // --- (a) Special prefixes: vtable, typeinfo, VTT ---
    if (s.len >= 2 and s[0] == 'T') {
        const prefix: []const u8 = switch (s[1]) {
            'V' => "vtable for ",
            'I' => "typeinfo for ",
            'S' => "typeinfo name for ",
            'T' => "VTT for ",
            else => "",
        };
        if (prefix.len > 0) {
            buf.appendSlice(prefix) catch return null;
            s = s[2..];
            // Parse the type that follows (nested name or simple name)
            if (s.len > 0 and s[0] == 'N') {
                s = s[1..];
                while (s.len > 0 and s[0] != 'E') {
                    if (s[0] == 'K' or s[0] == 'V' or s[0] == 'r') {
                        s = s[1..];
                        continue;
                    }
                    if (s.len >= 2 and s[0] == 'S' and s[1] == 't') {
                        buf.appendSlice("std::") catch return null;
                        s = s[2..];
                        continue;
                    }
                    if (s[0] == 'I') {
                        s = s[1..];
                        var tmpl_buf = std.array_list.Managed(u8).init(allocator);
                        tmpl_buf.append('<') catch return null;
                        var first_arg = true;
                        while (s.len > 0 and s[0] != 'E') {
                            var tpos: usize = 0;
                            if (parseItaniumType(allocator, s, &tpos)) |type_str| {
                                if (!first_arg) tmpl_buf.appendSlice(", ") catch {};
                                first_arg = false;
                                tmpl_buf.appendSlice(type_str) catch {};
                                s = s[tpos..];
                            } else {
                                // Substitution reference or unrecognized type — skip
                                // without emitting a separator (otherwise we'd leave
                                // an orphaned ", " before the next real arg).
                                const skip = if (tpos > 0) tpos else @as(usize, 1);
                                s = s[skip..];
                            }
                        }
                        if (s.len > 0 and s[0] == 'E') s = s[1..];
                        tmpl_buf.append('>') catch {};
                        buf.appendSlice(tmpl_buf.items) catch return null;
                        continue;
                    }
                    var comp_len: usize = 0;
                    while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
                        comp_len = comp_len * 10 + @as(usize, s[0] - '0');
                        s = s[1..];
                    }
                    if (comp_len == 0 or comp_len > s.len) break;
                    if (buf.items.len > prefix.len and !std.mem.endsWith(u8, buf.items, "::")) {
                        buf.appendSlice("::") catch return null;
                    }
                    buf.appendSlice(s[0..comp_len]) catch return null;
                    s = s[comp_len..];
                }
            } else if (s.len >= 2 and s[0] == 'S' and s[1] == 't') {
                buf.appendSlice("std::") catch return null;
                s = s[2..];
                var comp_len: usize = 0;
                while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
                    comp_len = comp_len * 10 + @as(usize, s[0] - '0');
                    s = s[1..];
                }
                if (comp_len > 0 and comp_len <= s.len) {
                    buf.appendSlice(s[0..comp_len]) catch return null;
                }
            } else {
                var comp_len: usize = 0;
                while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
                    comp_len = comp_len * 10 + @as(usize, s[0] - '0');
                    s = s[1..];
                }
                if (comp_len > 0 and comp_len <= s.len) {
                    buf.appendSlice(s[0..comp_len]) catch return null;
                }
            }
            if (buf.items.len <= prefix.len) return null;
            return buf.toOwnedSlice() catch null;
        }
    }

    // --- (c) Global std:: (St at top level, outside nested name) ---
    if (s.len >= 2 and s[0] == 'S' and s[1] == 't') {
        buf.appendSlice("std::") catch return null;
        s = s[2..];
        var comp_len: usize = 0;
        while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
            comp_len = comp_len * 10 + @as(usize, s[0] - '0');
            s = s[1..];
        }
        if (comp_len == 0 or comp_len > s.len) return null;
        buf.appendSlice(s[0..comp_len]) catch return null;
        s = s[comp_len..];
        // Only append () if there are remaining parameter type chars (e.g., 'v' for void)
        if (s.len > 0) {
            buf.appendSlice("()") catch return null;
        }
        return buf.toOwnedSlice() catch null;
    }

    // --- Nested name: N ... E ---
    if (s.len > 0 and s[0] == 'N') {
        s = s[1..]; // skip N
        // Track last parsed component name (stored from the mangled input, not buf)
        // to avoid self-referencing appendSlice on buf reallocation.
        var last_component: []const u8 = "";
        // Substitution table: tracks accumulated qualified names for S_ / S0_ / S1_ references
        var subs = std.array_list.Managed([]const u8).init(allocator);
        defer subs.deinit();
        // Parse components until E
        while (s.len > 0 and s[0] != 'E') {
            // Handle cv-qualifiers (const/volatile/restrict) that precede nested names
            if (s[0] == 'K' or s[0] == 'V' or s[0] == 'r') {
                s = s[1..];
                continue;
            }
            // Handle substitutions: St = std::, S_ = sub[0], S0_ = sub[1], etc.
            if (s[0] == 'S') {
                if (s.len >= 2 and s[1] == 't') {
                    buf.appendSlice("std::") catch return null;
                    subs.append(allocator.dupe(u8, "std") catch "std") catch {};
                    s = s[2..];
                    continue;
                }
                // S_ or S<seq-id>_: resolve from substitution table
                if (s.len >= 2) {
                    s = s[1..]; // skip S
                    if (s[0] == '_') {
                        // S_ = substitution[0]
                        s = s[1..];
                        if (subs.items.len > 0) {
                            if (buf.items.len > 0 and !std.mem.endsWith(u8, buf.items, "::")) {
                                buf.appendSlice("::") catch return null;
                            }
                            buf.appendSlice(subs.items[0]) catch return null;
                            last_component = subs.items[0];
                        }
                        continue;
                    }
                    // S<base-36-digit(s)>_
                    var sub_id: usize = 0;
                    while (s.len > 0 and s[0] != '_' and s[0] != 'E') {
                        const c = s[0];
                        s = s[1..];
                        const digit: usize = if (c >= '0' and c <= '9') c - '0' else if (c >= 'A' and c <= 'Z') c - 'A' + 10 else break;
                        sub_id = sub_id * 36 + digit;
                    }
                    if (s.len > 0 and s[0] == '_') s = s[1..];
                    const idx = sub_id + 1; // S0_ = substitution[1]
                    if (idx < subs.items.len) {
                        if (buf.items.len > 0 and !std.mem.endsWith(u8, buf.items, "::")) {
                            buf.appendSlice("::") catch return null;
                        }
                        buf.appendSlice(subs.items[idx]) catch return null;
                        last_component = subs.items[idx];
                    }
                    continue;
                }
            }
            // Handle template args — parse type codes between I and matching E
            if (s[0] == 'I') {
                s = s[1..];
                var tmpl_buf = std.array_list.Managed(u8).init(allocator);
                tmpl_buf.append('<') catch return null;
                var first_arg = true;
                while (s.len > 0 and s[0] != 'E') {
                    var tpos: usize = 0;
                    if (parseItaniumType(allocator, s, &tpos)) |type_str| {
                        if (!first_arg) tmpl_buf.appendSlice(", ") catch {};
                        first_arg = false;
                        tmpl_buf.appendSlice(type_str) catch {};
                        s = s[tpos..];
                    } else {
                        // Substitution reference or unrecognized type — skip
                        // without emitting a separator (otherwise we'd leave
                        // an orphaned ", " before the next real arg).
                        const skip = if (tpos > 0) tpos else @as(usize, 1);
                        s = s[skip..];
                    }
                }
                if (s.len > 0 and s[0] == 'E') s = s[1..];
                tmpl_buf.append('>') catch {};
                buf.appendSlice(tmpl_buf.items) catch return null;
                continue;
            }
            // Handle destructor — use tracked last_component
            if (s[0] == 'D') {
                if (s.len >= 2 and (s[1] == '0' or s[1] == '1' or s[1] == '2')) {
                    if (buf.items.len > 0 and !std.mem.endsWith(u8, buf.items, "::")) {
                        buf.appendSlice("::") catch return null;
                    }
                    buf.appendSlice("~") catch return null;
                    if (last_component.len > 0) {
                        buf.appendSlice(last_component) catch return null;
                    }
                    s = s[2..];
                    continue;
                }
                break; // Unknown D-code
            }
            // Handle constructor — use tracked last_component
            if (s[0] == 'C') {
                if (s.len >= 2 and (s[1] == '1' or s[1] == '2' or s[1] == '3')) {
                    if (buf.items.len > 0 and !std.mem.endsWith(u8, buf.items, "::")) {
                        buf.appendSlice("::") catch return null;
                    }
                    if (last_component.len > 0) {
                        buf.appendSlice(last_component) catch return null;
                    }
                    s = s[2..];
                    continue;
                }
                break;
            }
            // Parse length-prefixed component
            var comp_len: usize = 0;
            while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
                comp_len = comp_len * 10 + @as(usize, s[0] - '0');
                s = s[1..];
            }
            if (comp_len == 0 or comp_len > s.len) break;
            if (buf.items.len > 0 and !std.mem.endsWith(u8, buf.items, "::")) {
                buf.appendSlice("::") catch return null;
            }
            // Track component from the input slice (stable, not reallocated)
            last_component = s[0..comp_len];
            buf.appendSlice(s[0..comp_len]) catch return null;
            // Record accumulated qualified name for substitution table
            subs.append(allocator.dupe(u8, buf.items) catch "") catch {};
            s = s[comp_len..];
        }
        if (s.len > 0 and s[0] == 'E') s = s[1..]; // skip E
    } else {
        // Simple name: just length-prefixed
        if (s.len == 0) return null;
        var comp_len: usize = 0;
        while (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
            comp_len = comp_len * 10 + @as(usize, s[0] - '0');
            s = s[1..];
        }
        if (comp_len == 0 or comp_len > s.len) return null;
        buf.appendSlice(s[0..comp_len]) catch return null;
    }

    // Parse function parameter types
    buf.append('(') catch return null;
    var first_param = true;
    while (s.len > 0) {
        var ppos: usize = 0;
        if (parseItaniumType(allocator, s, &ppos)) |ptype| {
            if (std.mem.eql(u8, ptype, "void") and first_param) break; // void params = ()
            if (!first_param) buf.appendSlice(", ") catch {};
            first_param = false;
            buf.appendSlice(ptype) catch {};
            s = s[ppos..];
        } else break; // Stop on unrecognized
    }
    buf.append(')') catch return null;

    if (buf.items.len <= 2) return null; // Just "()" means nothing was parsed
    return buf.toOwnedSlice() catch null;
}

fn demangleAllNativeSymbols(allocator: Allocator, db: *Database) void {
    // Collect addresses first to avoid iterator invalidation from addSymbol
    var addrs = std.array_list.Managed(u64).init(allocator);
    defer addrs.deinit();
    {
        var it = db.symbols.iterator();
        while (it.next()) |entry| {
            addrs.append(entry.key_ptr.*) catch {};
        }
    }
    for (addrs.items) |address| {
        const name = db.symbols.get(address) orelse continue;
        const demangled = tryDemangleRust(allocator, name) orelse
            tryDemangleCpp(allocator, name) orelse continue;
        db.addSymbol(address, demangled) catch {};
        if (db.procedures.getPtr(address)) |proc| {
            proc.name = demangled;
        }
    }
}

fn handleGetDemangledName(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_demangled_name", params);
    };

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_demangled_name");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    // Accept address_or_name as either an integer address or a string (hex addr or name)
    var name_to_demangle: ?[]const u8 = null;
    var resolved_addr: ?u64 = null;

    if (getInt(params, "address_or_name") orelse getInt(params, "symbol") orelse getInt(params, "name")) |addr_val| {
        const input_addr: u64 = @bitCast(addr_val);
        const eff_addr = removeRebaseDelta(input_addr, eff.delta);
        resolved_addr = input_addr;
        // Look up name at effective address
        name_to_demangle = eff.db.resolveName(eff_addr);
    } else if (getString(params, "address_or_name") orelse getString(params, "symbol") orelse getString(params, "name")) |name_str| {
        // Try parsing as hex/int address first
        if (parseIntLenient(name_str)) |addr_val| {
            const input_addr: u64 = @bitCast(addr_val);
            const eff_addr = removeRebaseDelta(input_addr, eff.delta);
            resolved_addr = input_addr;
            name_to_demangle = eff.db.resolveName(eff_addr);
        } else {
            // Treat as a raw mangled name
            name_to_demangle = name_str;
        }
    } else {
        const resp = json.errorResponse(ctx.allocator, "get_demangled_name", "missing required parameter: address_or_name", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    if (name_to_demangle == null) {
        const resp = json.errorResponse(ctx.allocator, "get_demangled_name", "no symbol found at the given address", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    const original = name_to_demangle.?;

    // Try Swift demangling
    var result_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &result_buf.writer;
    w.writeAll("{\"original\":") catch {};
    json.writeJsonString(w, original) catch {};

    if (resolved_addr) |ra| {
        w.writeAll(",\"address\":") catch {};
        json.writeAddress(w, ra) catch {};
    }

    if (tryDemangleSwift(ctx.allocator, original)) |demangled| {
        w.writeAll(",\"demangled\":") catch {};
        json.writeJsonString(w, demangled) catch {};
        w.writeAll(",\"language\":\"swift\"") catch {};
    } else if (tryDemangleRust(ctx.allocator, original)) |demangled| {
        w.writeAll(",\"demangled\":") catch {};
        json.writeJsonString(w, demangled) catch {};
        w.writeAll(",\"language\":\"rust\"") catch {};
    } else if (tryDemangleCpp(ctx.allocator, original)) |demangled| {
        w.writeAll(",\"demangled\":") catch {};
        json.writeJsonString(w, demangled) catch {};
        w.writeAll(",\"language\":\"cpp\"") catch {};
    } else {
        w.writeAll(",\"demangled\":null,\"note\":\"not a Swift, Rust, or C++ mangled name, or demangling failed\"") catch {};
    }

    w.writeByte('}') catch {};

    const result_json = result_buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "get_demangled_name", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

// ============================================================================
// Compare Tool — cross-binary diffing
// ============================================================================

/// Strip leading underscore for cross-format comparison (Mach-O `_malloc` vs ELF `malloc`).
fn normalizeForComparison(name: []const u8) []const u8 {
    if (name.len > 1 and name[0] == '_') return name[1..];
    return name;
}

/// Build a set of normalized import names for the given database, including
/// demangled C++ and Rust variants. Used to filter out import stubs that
/// `registerStubSymbols` registers in `db.symbols` (so they don't appear as
/// fake "exports" in get_exports / get_dependency_graph).
/// Caller must hold db.rw_lock at least shared.
fn buildImportStubSet(allocator: Allocator, db: *const Database) std.StringHashMap(void) {
    var import_set = std.StringHashMap(void).init(allocator);
    var imp_it = db.imports.iterator();
    while (imp_it.next()) |imp_entry| {
        const raw = imp_entry.value_ptr.name;
        import_set.put(normalizeForComparison(raw), {}) catch {};
        if (tryDemangleCpp(allocator, raw)) |dem| {
            import_set.put(dem, {}) catch {};
        }
        if (tryDemangleRust(allocator, raw)) |dem| {
            import_set.put(dem, {}) catch {};
        }
    }
    return import_set;
}

/// True when release_diff should include `name` in its `sources` (default: all
/// enabled when `sources` is absent).
fn releaseSourceEnabled(params: std.json.Value, name: []const u8) bool {
    const sources = switch (params) {
        .object => |o| o.get("sources"),
        else => null,
    } orelse return true;
    switch (sources) {
        .array => |a| {
            for (a.items) |it| {
                if (it == .string and std.mem.eql(u8, it.string, name)) return true;
            }
            return false;
        },
        else => return true,
    }
}

// v7.16 W3 — release_diff: a directional, control-gated "what's NEW & HIDDEN
// between two builds" tool. Unlike `compare` (symmetric, native-code oriented),
// this diffs at the string + embedded-bundle + capability level with a
// new-only default lens, classifies each new marker, ranks the security/novel
// ones into `headlines[]`, and optionally tags ANNOUNCED vs HIDDEN against a
// changelog the caller passes. Built for recurring per-release binary diffs.
fn handleReleaseDiff(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const alloc = ctx.allocator;

    const old_id: u64 = resolveDocIdField(ctx, params, "doc_id_old") orelse {
        const resp = json.errorResponse(alloc, "release_diff", "could not resolve doc_id_old — provide a valid document ID or name", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    const new_id: u64 = resolveDocIdField(ctx, params, "doc_id_new") orelse {
        const resp = json.errorResponse(alloc, "release_diff", "could not resolve doc_id_new — provide a valid document ID or name", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    const entry_old = ctx.store.get(old_id) orelse return docNotFoundError(ctx, "release_diff");
    const entry_new = ctx.store.get(new_id) orelse return docNotFoundError(ctx, "release_diff");
    const eff_old = resolveEffectiveDb(entry_old);
    const eff_new = resolveEffectiveDb(entry_new);

    const include_bundle = releaseSourceEnabled(params, "bundle");
    const include_imports = releaseSourceEnabled(params, "imports");
    const changelog: ?[]const u8 = getString(params, "changelog");
    const max_per_cluster: usize = if (getInt(params, "max_per_cluster")) |m| @intCast(@max(m, 1)) else 40;
    const extraction_cap: usize = 1_000_000;

    eff_old.db.rw_lock.lockSharedUncancelable(eff_old.db.io);
    defer eff_old.db.rw_lock.unlockShared(eff_old.db.io);
    // Compare the RESOLVED dbs, not the doc ids: resolveEffectiveDb follows
    // rebase parents, so two distinct doc ids can alias one db — locking the
    // same RwLock twice on this thread would deadlock a queued writer.
    const same = (eff_old.db == eff_new.db);
    if (!same) eff_new.db.rw_lock.lockSharedUncancelable(eff_new.db.io);
    defer {
        if (!same) eff_new.db.rw_lock.unlockShared(eff_new.db.io);
    }

    // --- Build the OLD string set (control corpus): table + bundle tokens. ---
    var old_set = std.StringHashMap(void).init(alloc);
    defer old_set.deinit();
    if (eff_old.db.getAllStrings(alloc) catch null) |arr| {
        for (arr) |s| old_set.put(s.value, {}) catch {};
    }
    var bundle_truncated = false;
    if (include_bundle and strings_mod.hasPackedSegment(&eff_old.entry.doc)) {
        var ob = strings_mod.detectBundleStrings(alloc, &eff_old.entry.doc, 5, extraction_cap) catch null;
        if (ob) |*b| {
            defer b.deinit();
            if (b.items.len >= extraction_cap) bundle_truncated = true;
            for (b.items) |s| old_set.put(s.value, {}) catch {};
        }
    }

    // --- Walk NEW strings; keep the ones absent from OLD; classify + dedup. ---
    const NewRec = struct { value: []const u8, cats: [MAX_CAP_CATS][]const u8, cat_count: usize, weight: u8, best_conf: u8, announced: bool };
    var new_recs = std.array_list.Managed(NewRec).init(alloc);
    var new_seen = std.StringHashMap(void).init(alloc);
    defer new_seen.deinit();

    const classifyNew = struct {
        fn go(value: []const u8, old_s: *std.StringHashMap(void), seen: *std.StringHashMap(void), recs: *std.array_list.Managed(NewRec), cl: ?[]const u8) void {
            if (old_s.contains(value)) return;
            if (seen.contains(value)) return;
            var cats: [MAX_CAP_CATS][]const u8 = undefined;
            var confs: [MAX_CAP_CATS]CapConfidence = undefined;
            const n = categorizeCapabilityWithConfidence(value, &cats, &confs);
            if (n == 0) return; // only surface classified markers (signal, not noise)
            seen.put(value, {}) catch {};
            var weight: u8 = 0;
            var best_conf: u8 = 0;
            for (cats[0..n], confs[0..n]) |cat, cf| {
                const w = capCategoryWeight(cat);
                if (w > weight) weight = w;
                const cr = capConfRank(cf);
                if (cr > best_conf) best_conf = cr;
            }
            const announced = if (cl) |c| (std.mem.indexOf(u8, c, value) != null) else false;
            recs.append(.{ .value = value, .cats = cats, .cat_count = n, .weight = weight, .best_conf = best_conf, .announced = announced }) catch {};
        }
    };

    if (releaseSourceEnabled(params, "strings")) {
        if (eff_new.db.getAllStrings(alloc) catch null) |arr| {
            for (arr) |s| classifyNew.go(s.value, &old_set, &new_seen, &new_recs, changelog);
        }
    }
    if (include_bundle and strings_mod.hasPackedSegment(&eff_new.entry.doc)) {
        var nb = strings_mod.detectBundleStrings(alloc, &eff_new.entry.doc, 5, extraction_cap) catch null;
        if (nb) |*b| {
            defer b.deinit();
            if (b.items.len >= extraction_cap) bundle_truncated = true;
            for (b.items) |s| classifyNew.go(s.value, &old_set, &new_seen, &new_recs, changelog);
        }
    }

    // --- NEW imports (name set diff). ---
    var new_imports = std.array_list.Managed([]const u8).init(alloc);
    if (include_imports) {
        var old_imp = std.StringHashMap(void).init(alloc);
        defer old_imp.deinit();
        var it_o = eff_old.db.imports.iterator();
        while (it_o.next()) |e| old_imp.put(e.value_ptr.name, {}) catch {};
        var seen_imp = std.StringHashMap(void).init(alloc);
        defer seen_imp.deinit();
        var it_n = eff_new.db.imports.iterator();
        while (it_n.next()) |e| {
            const nm = e.value_ptr.name;
            if (old_imp.contains(nm) or seen_imp.contains(nm)) continue;
            seen_imp.put(nm, {}) catch {};
            new_imports.append(nm) catch {};
        }
    }

    // --- Rank: hidden first, then weight, then confidence. ---
    const RSort = struct {
        fn lt(_: void, a: NewRec, b: NewRec) bool {
            if (a.announced != b.announced) return !a.announced; // hidden first
            if (a.weight != b.weight) return a.weight > b.weight;
            return a.best_conf > b.best_conf;
        }
    };
    std.sort.pdq(NewRec, new_recs.items, {}, RSort.lt);

    var announced_count: usize = 0;
    for (new_recs.items) |r| {
        if (r.announced) announced_count += 1;
    }

    // Category histogram + prefix clusters over new-only markers.
    var hist = std.StringHashMap(usize).init(alloc);
    defer hist.deinit();
    const CI = struct { count: usize, example: []const u8 };
    var clusters = std.StringHashMap(CI).init(alloc);
    defer clusters.deinit();
    for (new_recs.items) |r| {
        for (r.cats[0..r.cat_count]) |cat| {
            const g = hist.getOrPut(cat) catch continue;
            if (!g.found_existing) g.value_ptr.* = 0;
            g.value_ptr.* += 1;
        }
        if (capClusterPrefix(r.value)) |pfx| {
            const g = clusters.getOrPut(pfx) catch continue;
            if (!g.found_existing) g.value_ptr.* = .{ .count = 0, .example = r.value };
            g.value_ptr.count += 1;
        }
    }

    // --- Emit. ---
    var buf = std.Io.Writer.Allocating.init(alloc);
    const w = &buf.writer;
    w.print("{{\"old\":{{\"doc_id\":{d},\"name\":", .{old_id}) catch {};
    json.writeJsonString(w, std.fs.path.basename(eff_old.entry.doc.path)) catch {};
    w.print("}},\"new\":{{\"doc_id\":{d},\"name\":", .{new_id}) catch {};
    json.writeJsonString(w, std.fs.path.basename(eff_new.entry.doc.path)) catch {};
    w.writeAll("},\"lens\":\"new_only\"") catch {};
    w.print(",\"summary\":{{\"new_classified\":{d},\"announced\":{d},\"hidden\":{d},\"new_imports\":{d},\"changelog_provided\":{s},\"bundle_truncated\":{s}}}", .{
        new_recs.items.len,
        announced_count,
        new_recs.items.len - announced_count,
        new_imports.items.len,
        if (changelog != null) "true" else "false",
        if (bundle_truncated) "true" else "false",
    }) catch {};

    // category_histogram
    w.writeAll(",\"category_histogram\":{") catch {};
    {
        var hi = hist.iterator();
        var first = true;
        while (hi.next()) |e| {
            if (!first) w.writeByte(',') catch {};
            first = false;
            json.writeJsonString(w, e.key_ptr.*) catch {};
            w.print(":{d}", .{e.value_ptr.*}) catch {};
        }
    }
    w.writeAll("}") catch {};

    // prefix clusters (>=2), top 24 by size
    const CRow = struct { prefix: []const u8, count: usize, example: []const u8 };
    var crows = std.array_list.Managed(CRow).init(alloc);
    {
        var ci = clusters.iterator();
        while (ci.next()) |e| {
            if (e.value_ptr.count >= 2) crows.append(.{ .prefix = e.key_ptr.*, .count = e.value_ptr.count, .example = e.value_ptr.example }) catch {};
        }
        std.sort.pdq(CRow, crows.items, {}, struct {
            fn lt(_: void, a: CRow, b: CRow) bool {
                return a.count > b.count;
            }
        }.lt);
    }
    w.writeAll(",\"clusters\":[") catch {};
    {
        const n = @min(crows.items.len, 24);
        for (crows.items[0..n], 0..) |row, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"prefix\":") catch {};
            json.writeJsonString(w, row.prefix) catch {};
            w.print(",\"count\":{d},\"example\":", .{row.count}) catch {};
            json.writeJsonString(w, row.example) catch {};
            w.writeByte('}') catch {};
        }
    }
    w.writeAll("]") catch {};

    // headlines: top-ranked new-only classified markers
    w.writeAll(",\"headlines\":[") catch {};
    {
        const n = @min(new_recs.items.len, max_per_cluster);
        for (new_recs.items[0..n], 0..) |r, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"value\":") catch {};
            json.writeJsonString(w, r.value) catch {};
            w.writeAll(",\"category\":") catch {};
            json.writeJsonString(w, r.cats[0]) catch {};
            w.writeAll(",\"confidence\":") catch {};
            w.writeAll(switch (r.best_conf) {
                3 => "\"high\"",
                2 => "\"medium\"",
                else => "\"low\"",
            }) catch {};
            w.print(",\"announced\":{s}}}", .{if (r.announced) "true" else "false"}) catch {};
        }
    }
    w.writeAll("]") catch {};

    // new_imports (cap 60)
    w.writeAll(",\"new_imports\":[") catch {};
    {
        const n = @min(new_imports.items.len, 60);
        for (new_imports.items[0..n], 0..) |nm, i| {
            if (i > 0) w.writeByte(',') catch {};
            json.writeJsonString(w, nm) catch {};
        }
    }
    w.writeAll("]}") catch {};

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(alloc, "release_diff", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .meta_max_chars = 200_000 };
}

fn handleCompare(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);

    // Resolve both doc IDs (support name resolution)
    const doc_id_a: u64 = resolveDocIdField(ctx, params, "doc_id_a") orelse {
        const resp = json.errorResponse(ctx.allocator, "compare", "could not resolve doc_id_a — provide a valid document ID or name", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    const doc_id_b: u64 = resolveDocIdField(ctx, params, "doc_id_b") orelse {
        const resp = json.errorResponse(ctx.allocator, "compare", "could not resolve doc_id_b — provide a valid document ID or name", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };

    const entry_a = ctx.store.get(doc_id_a) orelse return docNotFoundError(ctx, "compare");
    const entry_b = ctx.store.get(doc_id_b) orelse return docNotFoundError(ctx, "compare");

    const eff_a = resolveEffectiveDb(entry_a);
    const eff_b = resolveEffectiveDb(entry_b);

    const comparing_same = (doc_id_a == doc_id_b);

    // Lock both databases (shared/read)
    eff_a.db.rw_lock.lockSharedUncancelable(eff_a.db.io);
    defer eff_a.db.rw_lock.unlockShared(eff_a.db.io);
    if (!comparing_same) {
        eff_b.db.rw_lock.lockSharedUncancelable(eff_b.db.io);
    }
    defer {
        if (!comparing_same) eff_b.db.rw_lock.unlockShared(eff_b.db.io);
    }

    const max_results: u32 = if (getInt(params, "max_results")) |m| @intCast(@max(m, 1)) else 200;
    const diff_pattern = getString(params, "pattern");
    const include_changed = getBool(params, "include_changed") orelse true;
    const max_changed: u32 = if (getInt(params, "max_changed")) |m| @intCast(@max(m, 1)) else 200;
    // v7.14.0 B4: cross-binary fuzzy similarity matching. ON by default.
    const include_similar = getBool(params, "include_similar") orelse true;
    const max_similar: u32 = if (getInt(params, "max_similar")) |m| @intCast(@max(m, 1)) else 200;

    // Parse scope array, default to ["imports","strings","libraries"]
    var do_imports = false;
    var do_strings = false;
    var do_libraries = false;
    var do_procedures = false;

    if (getArray(params, "scope")) |scope_arr| {
        for (scope_arr.array.items) |item| {
            if (item == .string) {
                if (eql(item.string, "imports")) do_imports = true;
                if (eql(item.string, "strings")) do_strings = true;
                if (eql(item.string, "libraries")) do_libraries = true;
                if (eql(item.string, "procedures")) do_procedures = true;
            }
        }
    } else {
        do_imports = true;
        do_strings = true;
        do_libraries = true;
    }

    const name_a = std.fs.path.basename(entry_a.doc.path);
    const name_b = std.fs.path.basename(entry_b.doc.path);

    var result_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &result_buf.writer;

    // Envelope
    w.writeAll("{\"doc_a\":{\"doc_id\":") catch {};
    w.print("{d}", .{doc_id_a}) catch {};
    w.writeAll(",\"name\":") catch {};
    json.writeJsonString(w, name_a) catch {};
    w.writeAll("},\"doc_b\":{\"doc_id\":") catch {};
    w.print("{d}", .{doc_id_b}) catch {};
    w.writeAll(",\"name\":") catch {};
    json.writeJsonString(w, name_b) catch {};
    w.writeByte('}') catch {};

    if (comparing_same) {
        w.writeAll(",\"note\":\"comparing document with itself\"") catch {};
    }

    // --- imports scope ---
    if (do_imports) {
        const imports_a = eff_a.db.getAllImports(ctx.allocator) catch &[_]types.Import{};
        const imports_b = eff_b.db.getAllImports(ctx.allocator) catch &[_]types.Import{};

        // Build name sets (normalized for cross-format: Mach-O _malloc == ELF malloc)
        var set_a = std.StringHashMap(void).init(ctx.allocator);
        for (imports_a) |imp| {
            set_a.put(normalizeForComparison(imp.name), {}) catch {};
        }
        var set_b = std.StringHashMap(void).init(ctx.allocator);
        for (imports_b) |imp| {
            set_b.put(normalizeForComparison(imp.name), {}) catch {};
        }

        // Compute diffs (normalized keys, original display names)
        var only_a = std.array_list.Managed([]const u8).init(ctx.allocator);
        var shared = std.array_list.Managed([]const u8).init(ctx.allocator);
        for (imports_a) |imp| {
            if (set_b.contains(normalizeForComparison(imp.name))) {
                if (shared.items.len < max_results) shared.append(imp.name) catch {};
            } else {
                if (only_a.items.len < max_results) only_a.append(imp.name) catch {};
            }
        }
        var only_b = std.array_list.Managed([]const u8).init(ctx.allocator);
        for (imports_b) |imp| {
            if (!set_a.contains(normalizeForComparison(imp.name))) {
                if (only_b.items.len < max_results) only_b.append(imp.name) catch {};
            }
        }

        // Count totals (without max_results cap)
        var only_a_count: u32 = 0;
        var shared_count: u32 = 0;
        for (imports_a) |imp| {
            if (set_b.contains(normalizeForComparison(imp.name))) {
                shared_count += 1;
            } else {
                only_a_count += 1;
            }
        }
        var only_b_count: u32 = 0;
        for (imports_b) |imp| {
            if (!set_a.contains(normalizeForComparison(imp.name))) {
                only_b_count += 1;
            }
        }

        w.writeAll(",\"imports\":{") catch {};
        writeStringArray(w, "only_in_a", only_a.items);
        w.writeByte(',') catch {};
        writeStringArray(w, "only_in_b", only_b.items);
        w.writeByte(',') catch {};
        writeStringArray(w, "shared", shared.items);
        w.print(",\"count_a\":{d},\"count_b\":{d}", .{ @as(u32, @intCast(imports_a.len)), @as(u32, @intCast(imports_b.len)) }) catch {};
        w.print(",\"only_in_a_count\":{d},\"only_in_b_count\":{d},\"shared_count\":{d}", .{ only_a_count, only_b_count, shared_count }) catch {};
        w.writeByte('}') catch {};
    }

    // --- strings scope ---
    if (do_strings) {
        const strings_a = eff_a.db.getAllStrings(ctx.allocator) catch &[_]types.String{};
        const strings_b = eff_b.db.getAllStrings(ctx.allocator) catch &[_]types.String{};

        var set_a = std.StringHashMap(void).init(ctx.allocator);
        for (strings_a) |s| {
            if (diff_pattern) |p| {
                if (!matchesMultiPattern(s.value, p, false)) continue;
            }
            set_a.put(s.value, {}) catch {};
        }
        var set_b = std.StringHashMap(void).init(ctx.allocator);
        for (strings_b) |s| {
            if (diff_pattern) |p| {
                if (!matchesMultiPattern(s.value, p, false)) continue;
            }
            set_b.put(s.value, {}) catch {};
        }

        var only_a = std.array_list.Managed([]const u8).init(ctx.allocator);
        var shared = std.array_list.Managed([]const u8).init(ctx.allocator);
        for (strings_a) |s| {
            if (diff_pattern) |p| {
                if (!matchesMultiPattern(s.value, p, false)) continue;
            }
            if (set_b.contains(s.value)) {
                if (shared.items.len < max_results) shared.append(s.value) catch {};
            } else {
                if (only_a.items.len < max_results) only_a.append(s.value) catch {};
            }
        }
        var only_b = std.array_list.Managed([]const u8).init(ctx.allocator);
        for (strings_b) |s| {
            if (diff_pattern) |p| {
                if (!matchesMultiPattern(s.value, p, false)) continue;
            }
            if (!set_a.contains(s.value)) {
                if (only_b.items.len < max_results) only_b.append(s.value) catch {};
            }
        }

        var only_a_count: u32 = 0;
        var shared_count: u32 = 0;
        for (strings_a) |s| {
            if (diff_pattern) |p| {
                if (!matchesMultiPattern(s.value, p, false)) continue;
            }
            if (set_b.contains(s.value)) {
                shared_count += 1;
            } else {
                only_a_count += 1;
            }
        }
        var only_b_count: u32 = 0;
        for (strings_b) |s| {
            if (diff_pattern) |p| {
                if (!matchesMultiPattern(s.value, p, false)) continue;
            }
            if (!set_a.contains(s.value)) {
                only_b_count += 1;
            }
        }

        w.writeAll(",\"strings\":{") catch {};
        writeStringArray(w, "only_in_a", only_a.items);
        w.writeByte(',') catch {};
        writeStringArray(w, "only_in_b", only_b.items);
        w.writeByte(',') catch {};
        writeStringArray(w, "shared", shared.items);
        w.print(",\"count_a\":{d},\"count_b\":{d}", .{ @as(u32, @intCast(strings_a.len)), @as(u32, @intCast(strings_b.len)) }) catch {};
        w.print(",\"only_in_a_count\":{d},\"only_in_b_count\":{d},\"shared_count\":{d}", .{ only_a_count, only_b_count, shared_count }) catch {};
        w.writeByte('}') catch {};
    }

    // --- libraries scope ---
    if (do_libraries) {
        const imports_a = eff_a.db.getAllImports(ctx.allocator) catch &[_]types.Import{};
        const imports_b = eff_b.db.getAllImports(ctx.allocator) catch &[_]types.Import{};

        // Extract unique library names
        var libs_a = std.StringHashMap(void).init(ctx.allocator);
        for (imports_a) |imp| {
            if (imp.library) |lib| {
                libs_a.put(lib, {}) catch {};
            }
        }
        var libs_b = std.StringHashMap(void).init(ctx.allocator);
        for (imports_b) |imp| {
            if (imp.library) |lib| {
                libs_b.put(lib, {}) catch {};
            }
        }

        var only_a = std.array_list.Managed([]const u8).init(ctx.allocator);
        var shared = std.array_list.Managed([]const u8).init(ctx.allocator);
        var libs_a_it = libs_a.keyIterator();
        while (libs_a_it.next()) |key| {
            if (libs_b.contains(key.*)) {
                if (shared.items.len < max_results) shared.append(key.*) catch {};
            } else {
                if (only_a.items.len < max_results) only_a.append(key.*) catch {};
            }
        }
        var only_b = std.array_list.Managed([]const u8).init(ctx.allocator);
        var libs_b_it = libs_b.keyIterator();
        while (libs_b_it.next()) |key| {
            if (!libs_a.contains(key.*)) {
                if (only_b.items.len < max_results) only_b.append(key.*) catch {};
            }
        }

        var only_a_count: u32 = 0;
        var shared_count: u32 = 0;
        var count_a_it = libs_a.keyIterator();
        while (count_a_it.next()) |key| {
            if (libs_b.contains(key.*)) {
                shared_count += 1;
            } else {
                only_a_count += 1;
            }
        }
        var only_b_count: u32 = 0;
        var count_b_it = libs_b.keyIterator();
        while (count_b_it.next()) |key| {
            if (!libs_a.contains(key.*)) {
                only_b_count += 1;
            }
        }

        w.writeAll(",\"libraries\":{") catch {};
        writeStringArray(w, "only_in_a", only_a.items);
        w.writeByte(',') catch {};
        writeStringArray(w, "only_in_b", only_b.items);
        w.writeByte(',') catch {};
        writeStringArray(w, "shared", shared.items);
        w.print(",\"count_a\":{d},\"count_b\":{d}", .{ @as(u32, @intCast(libs_a.count())), @as(u32, @intCast(libs_b.count())) }) catch {};
        w.print(",\"only_in_a_count\":{d},\"only_in_b_count\":{d},\"shared_count\":{d}", .{ only_a_count, only_b_count, shared_count }) catch {};
        w.writeByte('}') catch {};
    }

    // --- procedures scope ---
    if (do_procedures) {
        // Fingerprint: hash(size_bucket, string_ref_count, import_ref_count, call_count, first_string_hash, first_import_hash)
        const ProcInfo = struct { address: u64, name: []const u8, size: u64 };
        const FprintList = std.array_list.Managed(ProcInfo);
        var fp_map_a = std.AutoHashMap(u64, FprintList).init(ctx.allocator);
        var fp_map_b = std.AutoHashMap(u64, FprintList).init(ctx.allocator);
        // Name → (fingerprint, address, size) for change detection
        const NameInfo = struct { fingerprint: u64, address: u64, size: u64 };
        var name_map_a = std.StringHashMap(NameInfo).init(ctx.allocator);
        var name_map_b = std.StringHashMap(NameInfo).init(ctx.allocator);

        var count_a: u32 = 0;
        var count_b: u32 = 0;

        // Build fingerprint map for binary A
        {
            var proc_it = eff_a.db.procedures.iterator();
            while (proc_it.next()) |proc_entry| {
                const proc = proc_entry.value_ptr.*;
                count_a += 1;
                const proc_end = proc.entry + @max(proc.size, 1);
                const xrefs = eff_a.db.xrefs.getRefsFromRange(proc.entry, proc_end);

                var str_ref_count: u32 = 0;
                var imp_ref_count: u32 = 0;
                var call_count: u32 = 0;
                var first_str_hash: u64 = 0;
                var first_imp_hash: u64 = 0;

                for (xrefs) |xref| {
                    if (xref.xref_type == .data_read or xref.xref_type == .string_ref) {
                        str_ref_count += 1;
                        if (first_str_hash == 0) {
                            if (eff_a.db.getString(xref.to)) |str| {
                                var h: u64 = 5381;
                                for (str.value) |c| h = h *% 33 +% c;
                                first_str_hash = h;
                            }
                        }
                    }
                    if (xref.xref_type == .call) {
                        call_count += 1;
                        // Import ref: target is outside procedure's range (likely import stub)
                        if (eff_a.db.getImport(xref.to) != null or eff_a.db.getSymbolName(xref.to) != null) {
                            imp_ref_count += 1;
                            if (first_imp_hash == 0) {
                                const imp_name = if (eff_a.db.getImport(xref.to)) |imp| imp.name else (eff_a.db.getSymbolName(xref.to) orelse "");
                                var h: u64 = 5381;
                                for (imp_name) |c| h = h *% 33 +% c;
                                first_imp_hash = h;
                            }
                        }
                    }
                }

                // Hash first 32 bytes of function body for instruction entropy
                var body_hash: u64 = 0;
                if (resolveRawBytesInfo(eff_a.entry, proc.entry)) |info| {
                    const byte_off = info.file_offset + (proc.entry - info.section_base);
                    if (byte_off < eff_a.entry.doc.data.len) {
                        const body_end = @min(byte_off + 32, eff_a.entry.doc.data.len);
                        var bh: u64 = 5381;
                        for (eff_a.entry.doc.data[byte_off..body_end]) |b| bh = bh *% 33 +% b;
                        body_hash = bh;
                    }
                }

                const bb_count: u64 = @as(u64, @intCast(proc.basic_blocks.len));
                const size_bucket: u64 = proc.size / 32;
                const fingerprint = (size_bucket *% 2654435761) ^ (@as(u64, str_ref_count) << 17) ^ (@as(u64, imp_ref_count) << 23) ^ (@as(u64, call_count) << 11) ^ (first_str_hash >> 3) ^ (first_imp_hash >> 7) ^ (body_hash << 5) ^ (bb_count *% 7919);

                const proc_name = proc.name orelse eff_a.db.resolveName(proc.entry) orelse "";
                const info = ProcInfo{ .address = proc.entry, .name = proc_name, .size = proc.size };

                const gop = fp_map_a.getOrPut(fingerprint) catch continue;
                if (!gop.found_existing) {
                    gop.value_ptr.* = FprintList.init(ctx.allocator);
                }
                gop.value_ptr.append(info) catch {};

                if (proc_name.len > 0) {
                    name_map_a.put(proc_name, .{ .fingerprint = fingerprint, .address = proc.entry, .size = proc.size }) catch {};
                }
            }
        }

        // Build fingerprint map for binary B
        {
            var proc_it = eff_b.db.procedures.iterator();
            while (proc_it.next()) |proc_entry| {
                const proc = proc_entry.value_ptr.*;
                count_b += 1;
                const proc_end = proc.entry + @max(proc.size, 1);
                const xrefs = eff_b.db.xrefs.getRefsFromRange(proc.entry, proc_end);

                var str_ref_count: u32 = 0;
                var imp_ref_count: u32 = 0;
                var call_count: u32 = 0;
                var first_str_hash: u64 = 0;
                var first_imp_hash: u64 = 0;

                for (xrefs) |xref| {
                    if (xref.xref_type == .data_read or xref.xref_type == .string_ref) {
                        str_ref_count += 1;
                        if (first_str_hash == 0) {
                            if (eff_b.db.getString(xref.to)) |str| {
                                var h: u64 = 5381;
                                for (str.value) |c| h = h *% 33 +% c;
                                first_str_hash = h;
                            }
                        }
                    }
                    if (xref.xref_type == .call) {
                        call_count += 1;
                        if (eff_b.db.getImport(xref.to) != null or eff_b.db.getSymbolName(xref.to) != null) {
                            imp_ref_count += 1;
                            if (first_imp_hash == 0) {
                                const imp_name = if (eff_b.db.getImport(xref.to)) |imp| imp.name else (eff_b.db.getSymbolName(xref.to) orelse "");
                                var h: u64 = 5381;
                                for (imp_name) |c| h = h *% 33 +% c;
                                first_imp_hash = h;
                            }
                        }
                    }
                }

                // Hash first 32 bytes of function body for instruction entropy
                var body_hash: u64 = 0;
                if (resolveRawBytesInfo(eff_b.entry, proc.entry)) |info| {
                    const byte_off = info.file_offset + (proc.entry - info.section_base);
                    if (byte_off < eff_b.entry.doc.data.len) {
                        const body_end = @min(byte_off + 32, eff_b.entry.doc.data.len);
                        var bh: u64 = 5381;
                        for (eff_b.entry.doc.data[byte_off..body_end]) |b| bh = bh *% 33 +% b;
                        body_hash = bh;
                    }
                }

                const bb_count: u64 = @as(u64, @intCast(proc.basic_blocks.len));
                const size_bucket: u64 = proc.size / 32;
                const fingerprint = (size_bucket *% 2654435761) ^ (@as(u64, str_ref_count) << 17) ^ (@as(u64, imp_ref_count) << 23) ^ (@as(u64, call_count) << 11) ^ (first_str_hash >> 3) ^ (first_imp_hash >> 7) ^ (body_hash << 5) ^ (bb_count *% 7919);

                const proc_name = proc.name orelse eff_b.db.resolveName(proc.entry) orelse "";
                const info = ProcInfo{ .address = proc.entry, .name = proc_name, .size = proc.size };

                const gop = fp_map_b.getOrPut(fingerprint) catch continue;
                if (!gop.found_existing) {
                    gop.value_ptr.* = FprintList.init(ctx.allocator);
                }
                gop.value_ptr.append(info) catch {};

                if (proc_name.len > 0) {
                    name_map_b.put(proc_name, .{ .fingerprint = fingerprint, .address = proc.entry, .size = proc.size }) catch {};
                }
            }
        }

        // Matching — dynamic ambiguity threshold
        // Pre-pass: count how many procs fall into large buckets (>10) at default threshold
        var large_bucket_procs: u32 = 0;
        {
            var pre_it = fp_map_a.iterator();
            while (pre_it.next()) |entry| {
                const list_a = entry.value_ptr.items;
                if (fp_map_b.get(entry.key_ptr.*)) |list_b_val| {
                    if (list_a.len > 10 or list_b_val.items.len > 10) {
                        large_bucket_procs += @intCast(list_a.len);
                    }
                }
            }
        }
        // If >50% of A's procs are in oversized buckets, progressively raise threshold
        const ambiguity_threshold: usize = if (count_a > 0 and large_bucket_procs * 2 > count_a)
            // Scale: 50%→25, 60%→50, 70%→75, 80%→100, 90%→150, 100%→200
            @min(200, 25 + @as(usize, @intCast(large_bucket_procs)) * 200 / @as(usize, @intCast(count_a)))
        else
            10;

        var likely_same_count: u32 = 0;
        var ambiguous_count: u32 = 0;

        const ChangedEntry = struct { address_a: u64, address_b: u64, name: []const u8, size_a: u64, size_b: u64 };
        const AddedRemoved = struct { address: u64, size: u64, name: []const u8 };

        var likely_changed = std.array_list.Managed(ChangedEntry).init(ctx.allocator);
        var likely_added = std.array_list.Managed(AddedRemoved).init(ctx.allocator);
        var likely_removed = std.array_list.Managed(AddedRemoved).init(ctx.allocator);

        // Fingerprint-based matching
        var fp_it_a = fp_map_a.iterator();
        while (fp_it_a.next()) |entry| {
            const fp = entry.key_ptr.*;
            const list_a = entry.value_ptr.items;
            if (fp_map_b.get(fp)) |list_b_val| {
                const list_b = list_b_val.items;
                // Ambiguity check with dynamic threshold
                if (list_a.len > ambiguity_threshold or list_b.len > ambiguity_threshold) {
                    ambiguous_count += @intCast(list_a.len);
                } else {
                    likely_same_count += @intCast(@min(list_a.len, list_b.len));
                    // Extra in A are candidates for removal
                    if (list_a.len > list_b.len) {
                        for (list_a[list_b.len..]) |info| {
                            if (likely_removed.items.len < max_results) {
                                likely_removed.append(.{ .address = info.address, .size = info.size, .name = info.name }) catch {};
                            }
                        }
                    }
                }
            } else {
                // Not in B → likely removed
                for (list_a) |info| {
                    if (likely_removed.items.len < max_results) {
                        likely_removed.append(.{ .address = info.address, .size = info.size, .name = info.name }) catch {};
                    }
                }
            }
        }

        // Fingerprints in B but not in A → likely added
        var fp_it_b = fp_map_b.iterator();
        while (fp_it_b.next()) |entry| {
            const fp = entry.key_ptr.*;
            const list_b = entry.value_ptr.items;
            if (!fp_map_a.contains(fp)) {
                for (list_b) |info| {
                    if (likely_added.items.len < max_results) {
                        likely_added.append(.{ .address = info.address, .size = info.size, .name = info.name }) catch {};
                    }
                }
            } else {
                // Check for extra in B (B has more than A for same fingerprint)
                const list_a_val = fp_map_a.get(fp).?;
                if (list_b.len > list_a_val.items.len and list_a_val.items.len <= ambiguity_threshold and list_b.len <= ambiguity_threshold) {
                    for (list_b[list_a_val.items.len..]) |info| {
                        if (likely_added.items.len < max_results) {
                            likely_added.append(.{ .address = info.address, .size = info.size, .name = info.name }) catch {};
                        }
                    }
                }
            }
        }

        // Name-based change detection: same name, different fingerprint
        var name_it = name_map_a.iterator();
        while (name_it.next()) |entry| {
            const name = entry.key_ptr.*;
            const info_a = entry.value_ptr.*;
            if (name_map_b.get(name)) |info_b| {
                if (info_a.fingerprint != info_b.fingerprint) {
                    if (likely_changed.items.len < max_results) {
                        likely_changed.append(.{
                            .address_a = info_a.address,
                            .address_b = info_b.address,
                            .name = name,
                            .size_a = info_a.size,
                            .size_b = info_b.size,
                        }) catch {};
                    }
                }
            }
        }

        // Output
        w.writeAll(",\"procedures\":{") catch {};
        w.print("\"likely_same_count\":{d}", .{likely_same_count}) catch {};

        // likely_changed
        w.writeAll(",\"likely_changed\":[") catch {};
        for (likely_changed.items, 0..) |ch, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"address_a\":") catch {};
            json.writeAddress(w, ch.address_a) catch {};
            w.writeAll(",\"address_b\":") catch {};
            json.writeAddress(w, ch.address_b) catch {};
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, ch.name) catch {};
            w.print(",\"size_a\":{d},\"size_b\":{d}}}", .{ ch.size_a, ch.size_b }) catch {};
        }
        w.writeByte(']') catch {};

        // likely_added
        w.writeAll(",\"likely_added\":[") catch {};
        for (likely_added.items, 0..) |a, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"address\":") catch {};
            json.writeAddress(w, a.address) catch {};
            w.print(",\"size\":{d}", .{a.size}) catch {};
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, a.name) catch {};
            w.writeByte('}') catch {};
        }
        w.writeByte(']') catch {};

        // likely_removed
        w.writeAll(",\"likely_removed\":[") catch {};
        for (likely_removed.items, 0..) |r, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"address\":") catch {};
            json.writeAddress(w, r.address) catch {};
            w.print(",\"size\":{d}", .{r.size}) catch {};
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, r.name) catch {};
            w.writeByte('}') catch {};
        }
        w.writeByte(']') catch {};

        w.print(",\"ambiguous_count\":{d}", .{ambiguous_count}) catch {};
        w.print(",\"count_a\":{d},\"count_b\":{d}", .{ count_a, count_b }) catch {};
        w.writeByte('}') catch {};
    }

    // --- v7.12 W3: top-level changed[] bucket ---
    // Same name+address, different body fingerprint. Body fingerprint =
    // instruction histogram + string-ref set + import-call set hash. Cheaper
    // than full procedures-scope fingerprinting because we only iterate procs
    // whose name appears in BOTH binaries.
    if (include_changed) {
        const ChangedRow = struct { name: []const u8, address_a: u64, address_b: u64, size_a: u64, size_b: u64 };
        var changed = std.array_list.Managed(ChangedRow).init(ctx.allocator);

        // Build name → (proc, eff_db, entry) maps for both docs.
        const NamedProc = struct { proc: types.Procedure, eff: EffectiveDb };
        var names_a = std.StringHashMap(NamedProc).init(ctx.allocator);
        var names_b = std.StringHashMap(NamedProc).init(ctx.allocator);

        {
            var pit = eff_a.db.procedures.iterator();
            while (pit.next()) |pe| {
                const proc = pe.value_ptr.*;
                const nm = proc.name orelse eff_a.db.resolveName(proc.entry) orelse continue;
                if (nm.len == 0) continue;
                if (std.mem.startsWith(u8, nm, "sub_") or std.mem.startsWith(u8, nm, "proc_")) continue;
                names_a.put(nm, .{ .proc = proc, .eff = eff_a }) catch {};
            }
        }
        {
            var pit = eff_b.db.procedures.iterator();
            while (pit.next()) |pe| {
                const proc = pe.value_ptr.*;
                const nm = proc.name orelse eff_b.db.resolveName(proc.entry) orelse continue;
                if (nm.len == 0) continue;
                if (std.mem.startsWith(u8, nm, "sub_") or std.mem.startsWith(u8, nm, "proc_")) continue;
                names_b.put(nm, .{ .proc = proc, .eff = eff_b }) catch {};
            }
        }

        var name_it = names_a.iterator();
        while (name_it.next()) |entry| {
            if (changed.items.len >= max_changed) break;
            const name = entry.key_ptr.*;
            const a = entry.value_ptr.*;
            const b = names_b.get(name) orelse continue;

            // Same identity = same name AND (same address OR same name in both).
            // The plan's wording is "same name+address", but cross-version diffs
            // routinely shift addresses by reloc; require name match and accept
            // any address. (The address pair is reported so callers can decide.)
            const fpa = computeBodyFingerprint(a.eff, a.proc);
            const fpb = computeBodyFingerprint(b.eff, b.proc);
            if (fpa != fpb) {
                changed.append(.{
                    .name = name,
                    .address_a = applyRebaseDelta(a.proc.entry, a.eff.delta),
                    .address_b = applyRebaseDelta(b.proc.entry, b.eff.delta),
                    .size_a = a.proc.size,
                    .size_b = b.proc.size,
                }) catch {};
            }
        }

        w.writeAll(",\"changed\":[") catch {};
        for (changed.items, 0..) |ch, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"name\":") catch {};
            json.writeJsonString(w, ch.name) catch {};
            w.writeAll(",\"address_a\":") catch {};
            json.writeAddress(w, ch.address_a) catch {};
            w.writeAll(",\"address_b\":") catch {};
            json.writeAddress(w, ch.address_b) catch {};
            w.print(",\"size_a\":{d},\"size_b\":{d}}}", .{ ch.size_a, ch.size_b }) catch {};
        }
        w.writeAll("]") catch {};
        w.print(",\"changed_count\":{d}", .{changed.items.len}) catch {};
    }

    // ------------------------------------------------------------------------
    // v7.14.0 B4 — fuzzy similarity bucket for cross-binary lineage tracking.
    // ------------------------------------------------------------------------
    // The existing `changed[]` only fires when names match AND fingerprints
    // differ. Field-test agents found that's nearly useless for sibling
    // binaries (syslogd vs newsyslog → just `__mh_execute_header`). This
    // bucket emits fuzzy matches: same name across both binaries, score
    // computed from import-call Jaccard (40%) + string-ref Jaccard (30%) +
    // mnemonic-histogram cosine (30%). Score ≥0.5 → emit.
    //
    // Cost guard: prefilter procs with import_calls >= 3 (eliminates PLT
    // stubs and trivial leaves), then cap output to max_similar (default
    // 200). Worst case observed: ~2K procs each side after filter, so the
    // O(N) name-keyed lookup keeps this bounded.
    if (include_similar) {
        const SimilarRow = struct {
            name: []const u8,
            address_a: u64,
            address_b: u64,
            size_a: u64,
            size_b: u64,
            score: f32,
        };
        var similar = std.array_list.Managed(SimilarRow).init(ctx.allocator);

        // Build name → proc maps with the import-call ≥ 3 filter.
        const SimProc = struct { proc: types.Procedure, eff: EffectiveDb, import_calls: u32 };
        var sim_a = std.StringHashMap(SimProc).init(ctx.allocator);
        var sim_b = std.StringHashMap(SimProc).init(ctx.allocator);
        defer sim_a.deinit();
        defer sim_b.deinit();

        const Inner = struct {
            fn collect(eff: EffectiveDb, into: *std.StringHashMap(SimProc)) void {
                var pit = eff.db.procedures.iterator();
                while (pit.next()) |pe| {
                    const proc = pe.value_ptr.*;
                    const nm = proc.name orelse eff.db.resolveName(proc.entry) orelse continue;
                    if (nm.len == 0) continue;
                    if (std.mem.startsWith(u8, nm, "sub_") or std.mem.startsWith(u8, nm, "proc_")) continue;
                    // Count import calls inside the proc range.
                    const proc_end = proc.entry + @max(proc.size, 1);
                    const xrefs = eff.db.xrefs.getRefsFromRange(proc.entry, proc_end);
                    var ic: u32 = 0;
                    for (xrefs) |xr| {
                        if (xr.xref_type == .call) {
                            if (eff.db.imports.get(xr.to) != null or eff.db.resolveName(xr.to) != null) {
                                ic += 1;
                            }
                        }
                    }
                    if (ic < 3) continue;
                    into.put(nm, .{ .proc = proc, .eff = eff, .import_calls = ic }) catch {};
                }
            }
            // Jaccard for two sorted arrays of u64 hashes.
            fn jaccard(a: []const u64, b: []const u64) f32 {
                if (a.len == 0 and b.len == 0) return 0.0;
                var i: usize = 0;
                var j: usize = 0;
                var inter: usize = 0;
                while (i < a.len and j < b.len) {
                    if (a[i] == b[j]) {
                        inter += 1;
                        i += 1;
                        j += 1;
                    } else if (a[i] < b[j]) {
                        i += 1;
                    } else {
                        j += 1;
                    }
                }
                const uni: usize = a.len + b.len - inter;
                if (uni == 0) return 0.0;
                return @as(f32, @floatFromInt(inter)) / @as(f32, @floatFromInt(uni));
            }
        };
        Inner.collect(eff_a, &sim_a);
        Inner.collect(eff_b, &sim_b);

        // For each name in A that's also in B, compute similarity. Allocate
        // import-set / string-set / mnemonic-histogram per call inline (small
        // N — bounded by import_calls and proc.size).
        var sim_it = sim_a.iterator();
        while (sim_it.next()) |se| {
            if (similar.items.len >= max_similar) break;
            const name = se.key_ptr.*;
            const a_info = se.value_ptr.*;
            const b_info = sim_b.get(name) orelse continue;

            // Build sorted hash sets for A and B: imports, string-refs.
            const aend = a_info.proc.entry + @max(a_info.proc.size, 1);
            const bend = b_info.proc.entry + @max(b_info.proc.size, 1);
            const ax = a_info.eff.db.xrefs.getRefsFromRange(a_info.proc.entry, aend);
            const bx = b_info.eff.db.xrefs.getRefsFromRange(b_info.proc.entry, bend);

            var a_imps = std.array_list.Managed(u64).init(ctx.allocator);
            var b_imps = std.array_list.Managed(u64).init(ctx.allocator);
            var a_strs = std.array_list.Managed(u64).init(ctx.allocator);
            var b_strs = std.array_list.Managed(u64).init(ctx.allocator);
            defer a_imps.deinit();
            defer b_imps.deinit();
            defer a_strs.deinit();
            defer b_strs.deinit();

            for (ax) |xr| {
                switch (xr.xref_type) {
                    .call => {
                        const n: ?[]const u8 = if (a_info.eff.db.imports.get(xr.to)) |imp| imp.name else a_info.eff.db.resolveName(xr.to);
                        if (n) |nm2| {
                            var h: u64 = 5381;
                            for (nm2) |c| h = h *% 33 +% c;
                            a_imps.append(h) catch {};
                        }
                    },
                    .data_read, .string_ref => {
                        if (a_info.eff.db.getString(xr.to)) |s| {
                            var h: u64 = 5381;
                            for (s.value) |c| h = h *% 33 +% c;
                            a_strs.append(h) catch {};
                        }
                    },
                    else => {},
                }
            }
            for (bx) |xr| {
                switch (xr.xref_type) {
                    .call => {
                        const n: ?[]const u8 = if (b_info.eff.db.imports.get(xr.to)) |imp| imp.name else b_info.eff.db.resolveName(xr.to);
                        if (n) |nm2| {
                            var h: u64 = 5381;
                            for (nm2) |c| h = h *% 33 +% c;
                            b_imps.append(h) catch {};
                        }
                    },
                    .data_read, .string_ref => {
                        if (b_info.eff.db.getString(xr.to)) |s| {
                            var h: u64 = 5381;
                            for (s.value) |c| h = h *% 33 +% c;
                            b_strs.append(h) catch {};
                        }
                    },
                    else => {},
                }
            }
            // Dedup + sort each set.
            std.mem.sort(u64, a_imps.items, {}, std.sort.asc(u64));
            std.mem.sort(u64, b_imps.items, {}, std.sort.asc(u64));
            std.mem.sort(u64, a_strs.items, {}, std.sort.asc(u64));
            std.mem.sort(u64, b_strs.items, {}, std.sort.asc(u64));
            // Dedup in place (keep first of each run).
            const Dedup = struct {
                fn run(arr: *std.array_list.Managed(u64)) void {
                    if (arr.items.len <= 1) return;
                    var w_idx: usize = 1;
                    var i: usize = 1;
                    while (i < arr.items.len) : (i += 1) {
                        if (arr.items[i] != arr.items[w_idx - 1]) {
                            arr.items[w_idx] = arr.items[i];
                            w_idx += 1;
                        }
                    }
                    arr.shrinkRetainingCapacity(w_idx);
                }
            };
            Dedup.run(&a_imps);
            Dedup.run(&b_imps);
            Dedup.run(&a_strs);
            Dedup.run(&b_strs);

            const j_imp = Inner.jaccard(a_imps.items, b_imps.items);
            const j_str = Inner.jaccard(a_strs.items, b_strs.items);

            // Mnemonic histogram cosine similarity. We hash mnemonic into a
            // bucket index 0..63 — small fixed bins keep this O(proc.size).
            var hist_a: [64]u32 = @splat(0);
            var hist_b: [64]u32 = @splat(0);
            {
                var addr = a_info.proc.entry;
                var n_inst: u32 = 0;
                while (addr < aend and n_inst < 4096) {
                    if (a_info.eff.db.getInstruction(addr)) |inst| {
                        var h: u64 = 5381;
                        for (inst.mnemonic) |c| h = h *% 33 +% c;
                        hist_a[@intCast(h & 63)] += 1;
                        addr += inst.size;
                        n_inst += 1;
                    } else {
                        addr += 4;
                    }
                }
            }
            {
                var addr = b_info.proc.entry;
                var n_inst: u32 = 0;
                while (addr < bend and n_inst < 4096) {
                    if (b_info.eff.db.getInstruction(addr)) |inst| {
                        var h: u64 = 5381;
                        for (inst.mnemonic) |c| h = h *% 33 +% c;
                        hist_b[@intCast(h & 63)] += 1;
                        addr += inst.size;
                        n_inst += 1;
                    } else {
                        addr += 4;
                    }
                }
            }
            var dot: f64 = 0.0;
            var na: f64 = 0.0;
            var nb: f64 = 0.0;
            for (hist_a, 0..) |va, k| {
                const vb = hist_b[k];
                dot += @as(f64, @floatFromInt(va)) * @as(f64, @floatFromInt(vb));
                na += @as(f64, @floatFromInt(va)) * @as(f64, @floatFromInt(va));
                nb += @as(f64, @floatFromInt(vb)) * @as(f64, @floatFromInt(vb));
            }
            const cosine: f32 = if (na > 0.0 and nb > 0.0)
                @floatCast(dot / (@sqrt(na) * @sqrt(nb)))
            else
                0.0;

            const score: f32 = 0.4 * j_imp + 0.3 * j_str + 0.3 * cosine;
            if (score >= 0.5) {
                similar.append(.{
                    .name = name,
                    .address_a = applyRebaseDelta(a_info.proc.entry, a_info.eff.delta),
                    .address_b = applyRebaseDelta(b_info.proc.entry, b_info.eff.delta),
                    .size_a = a_info.proc.size,
                    .size_b = b_info.proc.size,
                    .score = score,
                }) catch {};
            }
        }

        w.writeAll(",\"similar\":[") catch {};
        for (similar.items, 0..) |sim, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"name\":") catch {};
            json.writeJsonString(w, sim.name) catch {};
            w.writeAll(",\"doc_a_addr\":") catch {};
            json.writeAddress(w, sim.address_a) catch {};
            w.writeAll(",\"doc_b_addr\":") catch {};
            json.writeAddress(w, sim.address_b) catch {};
            w.print(",\"doc_a_size\":{d},\"doc_b_size\":{d},\"similarity_score\":{d:.3}}}", .{ sim.size_a, sim.size_b, sim.score }) catch {};
        }
        w.writeAll("]") catch {};
        w.print(",\"similar_count\":{d}", .{similar.items.len}) catch {};
    }

    w.writeByte('}') catch {};

    const result_json = result_buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "compare", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

/// v7.12 W3: cheap body fingerprint = instruction-mnemonic histogram (top 16)
/// XOR'd with operand-byte hash, referenced-string set hash, and import-call
/// set hash. Two procs with the same name in two binaries that produce the
/// same fingerprint are considered "same body"; otherwise they're flagged
/// as `changed`. Including operand bytes catches stub trampolines that have
/// the same instruction sequence but reference different GOT entries (a
/// real difference between two stripped binaries' shared symbol stubs).
fn computeBodyFingerprint(eff: EffectiveDb, proc: types.Procedure) u64 {
    var h: u64 = 1469598103934665603; // FNV-64 offset basis

    // Instruction histogram + operand hash: walk instructions in
    // [proc.entry, proc.entry+size) and fold both mnemonic bytes and
    // operand bytes (sans absolute addresses) into the hash.
    var addr = proc.entry;
    const end_addr = proc.entry + @max(proc.size, 1);
    var inst_count: u32 = 0;
    while (addr < end_addr and inst_count < 4096) {
        if (eff.db.getInstruction(addr)) |inst| {
            for (inst.mnemonic) |c| h ^= (@as(u64, c) *% 1099511628211);
            const ops = eff.db.getInstructionOperands(addr);
            for (ops) |c| h ^= (@as(u64, c) *% 16777619);
            addr += inst.size;
            inst_count += 1;
        } else {
            addr += 4;
        }
    }
    h = h *% 1099511628211 ^ @as(u64, inst_count);
    h ^= @as(u64, @intCast(proc.size)) *% 2246822519; // FNV-1a 32-bit prime, sized

    // String-ref + import-call sets, derived from xrefs from the proc range.
    const xrefs = eff.db.xrefs.getRefsFromRange(proc.entry, end_addr);
    var str_hash: u64 = 14695981039346656037 % 4294967311;
    var imp_hash: u64 = 1099511628211;
    for (xrefs) |xr| {
        if (xr.xref_type == .data_read or xr.xref_type == .string_ref) {
            if (eff.db.getString(xr.to)) |s| {
                var sh: u64 = 5381;
                for (s.value) |c| sh = sh *% 33 +% c;
                str_hash ^= sh;
            }
        } else if (xr.xref_type == .call) {
            if (eff.db.imports.get(xr.to)) |imp| {
                var ih: u64 = 5381;
                for (imp.name) |c| ih = ih *% 33 +% c;
                imp_hash ^= ih;
            } else if (eff.db.resolveName(xr.to)) |n| {
                var ih: u64 = 5381;
                for (n) |c| ih = ih *% 33 +% c;
                imp_hash ^= ih;
            }
        }
    }
    h ^= str_hash *% 2654435761;
    h ^= imp_hash *% 40503;
    return h;
}

fn handleGetDependencyGraph(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const max_results: usize = if (getInt(params, "max_results")) |m| @intCast(@max(m, 1)) else 20;
    const pattern = getString(params, "pattern");
    const focus_doc_id: ?u64 = resolveDocId(ctx, params);

    // If doc_id was explicitly provided but couldn't be resolved, return actionable error
    if (focus_doc_id == null and (getInt(params, "doc_id") != null or getString(params, "doc_id") != null)) {
        return docNotFoundError(ctx, "get_dependency_graph");
    }

    var result_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &result_buf.writer;

    // Phase 1: Collect all document IDs and names under store mutex
    var doc_ids = std.array_list.Managed(u64).init(ctx.allocator);
    var doc_names = std.array_list.Managed([]const u8).init(ctx.allocator);
    {
        ctx.store.mutex.lockUncancelable(ctx.io);
        defer ctx.store.mutex.unlock(ctx.io);
        var it = ctx.store.documents.iterator();
        while (it.next()) |entry| {
            doc_ids.append(entry.key_ptr.*) catch {};
            doc_names.append(std.fs.path.basename(entry.value_ptr.*.doc.path)) catch {};
        }
    }

    if (doc_ids.items.len == 0) {
        const resp = json.errorResponse(ctx.allocator, "get_dependency_graph", "no documents loaded", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    }

    // Phase 2: Build global export index (normalized_name -> doc_id)
    // First exporter wins — if multiple binaries export the same name, first encountered is used.
    var export_index = std.StringHashMap(u64).init(ctx.allocator);

    for (doc_ids.items) |did| {
        const entry = ctx.store.get(did) orelse continue;
        const eff = resolveEffectiveDb(entry);
        eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
        defer eff.db.rw_lock.unlockShared(eff.db.io);

        // Build import set to detect re-exports (stubs registered as symbols).
        // Includes raw + demangled names; see buildImportStubSet for details.
        var import_set = buildImportStubSet(ctx.allocator, eff.db);
        defer import_set.deinit();

        // Add genuine exports from symbols (filtering out stubs/re-exports)
        var sym_it = eff.db.symbols.iterator();
        while (sym_it.next()) |sym_entry| {
            const name = sym_entry.value_ptr.*;
            const normalized = normalizeForComparison(name);
            if (import_set.contains(normalized)) continue; // re-export stub, skip
            if (!export_index.contains(normalized)) {
                export_index.put(normalized, did) catch {};
            }
        }
        // Also add named procedures — these are the binary's own code
        var proc_it = eff.db.procedures.iterator();
        while (proc_it.next()) |proc_entry| {
            const pname = proc_entry.value_ptr.name orelse continue;
            if (pname.len == 0) continue;
            if (std.mem.startsWith(u8, pname, "sub_") or std.mem.startsWith(u8, pname, "proc_")) continue; // auto-named, not real exports
            const normalized = normalizeForComparison(pname);
            if (import_set.contains(normalized)) continue;
            if (!export_index.contains(normalized)) {
                export_index.put(normalized, did) catch {};
            }
        }
    }

    // Phase 3: Build edges, unresolved, and collect relevant doc_ids (pre-pass before nodes)
    // We buffer edges into a separate buffer so we can write nodes first in the final output.
    var edge_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const ew = &edge_buf.writer;
    var first_edge = true;

    // Collect unresolved data per doc during the same pass
    const UnresolvedInfo = struct {
        doc_id: u64,
        count: u32,
        samples: std.array_list.Managed([]const u8),
    };
    var unresolved_list = std.array_list.Managed(UnresolvedInfo).init(ctx.allocator);

    // In focus mode, track which doc_ids are relevant (focused + edge targets + unresolved)
    var relevant_docs = std.AutoHashMap(u64, void).init(ctx.allocator);
    if (focus_doc_id) |fid| {
        relevant_docs.put(fid, {}) catch {};
    }

    for (doc_ids.items) |did| {
        // In focus mode, only process the focused document's imports
        if (focus_doc_id) |fid| {
            if (did != fid) continue;
        }

        const entry = ctx.store.get(did) orelse continue;
        const eff = resolveEffectiveDb(entry);
        eff.db.rw_lock.lockSharedUncancelable(eff.db.io);

        const all_imports = eff.db.getAllImports(ctx.allocator) catch &[_]types.Import{};

        // Group resolved imports by target doc_id
        var edge_targets = std.AutoHashMap(u64, std.array_list.Managed([]const u8)).init(ctx.allocator);
        var unresolved_count: u32 = 0;
        var unresolved_samples = std.array_list.Managed([]const u8).init(ctx.allocator);

        for (all_imports) |imp| {
            const normalized = normalizeForComparison(imp.name);

            // Apply pattern filter if given
            if (pattern) |p| {
                if (!matchesMultiPattern(normalized, p, true)) continue;
            }

            // Try matching import against export index: raw name first, then demangled.
            // For ELF: prefer matches from DT_NEEDED libraries when available.
            const target_did_opt: ?u64 = export_index.get(normalized) orelse blk: {
                // Import names are mangled; export index has demangled names from procedures.
                // Try demangling the import name to match.
                if (tryDemangleCpp(ctx.allocator, imp.name)) |dem| {
                    if (export_index.get(dem)) |tid| break :blk tid;
                }
                if (tryDemangleRust(ctx.allocator, imp.name)) |dem| {
                    if (export_index.get(dem)) |tid| break :blk tid;
                }
                break :blk null;
            };

            if (target_did_opt) |target_did| {
                if (target_did == did) continue; // Skip self-references
                const gop = edge_targets.getOrPut(target_did) catch continue;
                if (!gop.found_existing) {
                    gop.value_ptr.* = std.array_list.Managed([]const u8).init(ctx.allocator);
                }
                if (gop.value_ptr.items.len < max_results) {
                    gop.value_ptr.append(imp.name) catch {};
                }
            } else {
                unresolved_count += 1;
                if (unresolved_samples.items.len < max_results) {
                    unresolved_samples.append(imp.name) catch {};
                }
            }
        }

        eff.db.rw_lock.unlockShared(eff.db.io);

        // Buffer edges for this doc
        var edge_it = edge_targets.iterator();
        while (edge_it.next()) |edge_entry| {
            if (!first_edge) ew.writeByte(',') catch {};
            first_edge = false;
            const target_id = edge_entry.key_ptr.*;
            ew.print("{{\"importer\":{d},\"exporter\":{d},\"count\":{d},\"resolved_symbols\":[", .{
                did,
                target_id,
                edge_entry.value_ptr.items.len,
            }) catch {};
            for (edge_entry.value_ptr.items, 0..) |sym, si| {
                if (si > 0) ew.writeByte(',') catch {};
                json.writeJsonString(ew, sym) catch {};
            }
            ew.writeAll("]}") catch {};

            // Track edge target as relevant in focus mode
            if (focus_doc_id != null) {
                relevant_docs.put(target_id, {}) catch {};
            }
        }

        // Collect unresolved for this doc
        if (unresolved_count > 0) {
            unresolved_list.append(.{
                .doc_id = did,
                .count = unresolved_count,
                .samples = unresolved_samples,
            }) catch {};

            // Track this doc as relevant in focus mode (it has unresolved imports)
            if (focus_doc_id != null) {
                relevant_docs.put(did, {}) catch {};
            }
        }
    }

    // Phase 4: Write nodes array — each loaded binary with export/import counts
    // In focus mode, only include relevant docs (focused + edge targets + unresolved)
    w.writeAll("{\"nodes\":[") catch {};
    var first_node = true;
    for (doc_ids.items, doc_names.items) |did, dname| {
        if (focus_doc_id != null and !relevant_docs.contains(did)) continue;

        if (!first_node) w.writeByte(',') catch {};
        first_node = false;
        const entry = ctx.store.get(did) orelse continue;
        const eff = resolveEffectiveDb(entry);
        eff.db.rw_lock.lockSharedUncancelable(eff.db.io);

        var export_count: u32 = 0;
        {
            var sym_it = eff.db.symbols.iterator();
            while (sym_it.next()) |_| export_count += 1;
        }

        var import_count: u32 = 0;
        {
            var imp_it = eff.db.imports.iterator();
            while (imp_it.next()) |_| import_count += 1;
        }

        eff.db.rw_lock.unlockShared(eff.db.io);

        w.print("{{\"doc_id\":{d},\"name\":", .{did}) catch {};
        json.writeJsonString(w, dname) catch {};
        w.print(",\"exports\":{d},\"imports\":{d}}}", .{ export_count, import_count }) catch {};
    }
    w.writeAll("]") catch {};

    // Phase 5: Write pre-built edges
    w.writeAll(",\"edges\":[") catch {};
    w.writeAll(edge_buf.written()) catch {};
    w.writeAll("]") catch {};

    // Phase 6: Write unresolved_by_doc section
    w.writeAll(",\"unresolved_by_doc\":[") catch {};
    for (unresolved_list.items, 0..) |ur, ui| {
        if (ui > 0) w.writeByte(',') catch {};
        w.print("{{\"doc_id\":{d},\"count\":{d},\"samples\":[", .{ ur.doc_id, ur.count }) catch {};
        for (ur.samples.items, 0..) |samp, si| {
            if (si > 0) w.writeByte(',') catch {};
            json.writeJsonString(w, samp) catch {};
        }
        w.writeAll("]}") catch {};
    }
    w.writeAll("]") catch {};

    // v7.12 W10: Phase 6.5 — write system_imports[] (imports grouped by library
    // name, e.g. "/usr/lib/libSystem.B.dylib"). Today get_dependency_graph
    // returns 0 unresolved imports for binaries with hundreds of system imports
    // because the system libs aren't loaded as separate docs — actively
    // misleading. Surface them as a top-level summary so the caller can see
    // "yes I observed your imports, here's the per-library count."
    {
        var sys_libs = std.StringHashMap(u32).init(ctx.allocator);
        for (doc_ids.items) |did| {
            if (focus_doc_id) |fid| {
                if (did != fid) continue;
            }
            const entry = ctx.store.get(did) orelse continue;
            const eff = resolveEffectiveDb(entry);
            eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
            defer eff.db.rw_lock.unlockShared(eff.db.io);
            const all_imports = eff.db.getAllImports(ctx.allocator) catch &[_]types.Import{};
            for (all_imports) |imp| {
                const lib = imp.library orelse "<unknown>";
                const gop = sys_libs.getOrPut(lib) catch continue;
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* += 1;
            }
        }
        w.writeAll(",\"system_imports\":[") catch {};
        var first_lib = true;
        var lit = sys_libs.iterator();
        while (lit.next()) |le| {
            if (!first_lib) w.writeByte(',') catch {};
            first_lib = false;
            w.writeAll("{\"library\":") catch {};
            json.writeJsonString(w, le.key_ptr.*) catch {};
            w.print(",\"import_count\":{d}}}", .{le.value_ptr.*}) catch {};
        }
        w.writeAll("]") catch {};
        w.print(",\"system_library_count\":{d}", .{sys_libs.count()}) catch {};
    }

    // Summary stats
    w.print(",\"total_docs\":{d},\"total_exports\":{d}", .{ doc_ids.items.len, export_index.count() }) catch {};
    if (focus_doc_id) |fid| {
        w.print(",\"focus_doc_id\":{d}", .{fid}) catch {};
    }
    w.writeByte('}') catch {};

    const dep_result_json = result_buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "get_dependency_graph", dep_result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .meta_max_chars = 200_000 };
}

fn handleSuggestNames(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "suggest_names", params);
    };
    const addresses = parseBatchAddresses(ctx.allocator, params) catch {
        const resp = json.errorResponse(ctx.allocator, "suggest_names", "missing or invalid 'addresses' parameter. Accepts: integer, hex string (\"0x1234\"), or array of integers/hex strings.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    defer ctx.allocator.free(addresses);
    const max_context: u32 = if (getInt(params, "max_context")) |m| @intCast(@max(m, 1)) else 5;

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "suggest_names");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    var result_buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &result_buf.writer;
    w.writeByte('[') catch {};

    for (addresses, 0..) |addr, addr_idx| {
        if (addr_idx > 0) w.writeByte(',') catch {};
        const eff_addr = removeRebaseDelta(addr, eff.delta);

        w.writeAll("{\"address\":") catch {};
        json.writeAddress(w, addr) catch {};

        // Find the procedure containing this address
        const proc = eff.db.getProcedure(eff_addr) orelse eff.db.getProcedureContaining(eff_addr);
        if (proc == null) {
            w.writeAll(",\"error\":\"no procedure found at this address\"}") catch {};
            continue;
        }
        const p = proc.?;
        const proc_end = p.entry + @max(p.size, 1);

        // Size
        w.print(",\"size\":{d}", .{p.size}) catch {};

        // Existing name (if any)
        if (p.name) |name| {
            w.writeAll(",\"current_name\":") catch {};
            json.writeJsonString(w, name) catch {};
        } else if (eff.db.getSymbolName(p.entry)) |name| {
            w.writeAll(",\"current_name\":") catch {};
            json.writeJsonString(w, name) catch {};
        }

        var has_bytes = false;
        if (resolveRawBytesInfo(eff.entry, p.entry)) |info| {
            const offset = info.file_offset + p.entry - info.section_base;
            const code_end = eff.entry.doc.codeRangeEnd(p.entry) orelse p.entry;
            if (offset < eff.entry.doc.data.len) {
                const len = @min(@min(@min(p.size, code_end - p.entry), 32), eff.entry.doc.data.len - offset);
                w.writeAll(",\"byte_evidence\":{\"address\":") catch {};
                json.writeAddress(w, applyRebaseDelta(p.entry, eff.delta)) catch {};
                w.print(",\"file_offset\":{d},\"hex\":\"", .{offset}) catch {};
                for (eff.entry.doc.data[offset..][0..len]) |byte| w.print("{x:0>2}", .{byte}) catch {};
                w.writeAll("\"}") catch {};
                has_bytes = len > 0;
            }
        }

        // String references: scan xrefs from within the procedure range for data refs
        var total_str_count: u32 = 0;
        var collected_strs: [8][]const u8 = undefined;
        var collected_str_count: u32 = 0;
        w.writeAll(",\"string_refs\":[") catch {};
        {
            var str_count: u32 = 0;
            const sn_xrefs = eff.db.xrefs.getRefsFromRange(p.entry, proc_end);
            for (sn_xrefs) |xref| {
                if (str_count >= max_context) break;
                if (xref.xref_type == .data_read or xref.xref_type == .string_ref) {
                    const found_str = eff.db.getString(xref.to) orelse eff.db.getString(xref.to & ~@as(u64, 0xFFF));
                    if (found_str) |str| {
                        if (str_count > 0) w.writeByte(',') catch {};
                        json.writeJsonString(w, str.value) catch {};
                        if (collected_str_count < 8) {
                            collected_strs[collected_str_count] = str.value;
                            collected_str_count += 1;
                        }
                        str_count += 1;
                    }
                }
            }
            total_str_count = str_count;
        }
        w.writeByte(']') catch {};

        // Callers: addresses that call this procedure's entry
        var total_caller_count: u32 = 0;
        w.writeAll(",\"callers\":[") catch {};
        {
            const refs = eff.db.xrefs.getRefsTo(p.entry);
            var caller_count: u32 = 0;
            for (refs) |xref| {
                if (caller_count >= max_context) break;
                if (xref.xref_type == .call) {
                    if (caller_count > 0) w.writeByte(',') catch {};
                    json.writeAddress(w, applyRebaseDelta(xref.from, eff.delta)) catch {};
                    caller_count += 1;
                }
            }
            total_caller_count = caller_count;
        }
        w.writeByte(']') catch {};

        // Callees: functions called from within this procedure
        const callees = ensureCalleesCached(eff.entry, eff.db, p.entry, ctx.allocator);
        w.writeAll(",\"callees\":[") catch {};
        {
            const limit = @min(callees.len, max_context);
            for (callees[0..limit], 0..) |callee_addr, ci| {
                if (ci > 0) w.writeByte(',') catch {};
                // Resolve to name if possible, otherwise emit address
                if (eff.db.resolveName(callee_addr)) |name| {
                    json.writeJsonString(w, name) catch {};
                } else {
                    json.writeAddress(w, applyRebaseDelta(callee_addr, eff.delta)) catch {};
                }
            }
        }
        w.writeByte(']') catch {};

        // Imports called: subset of callees that are imports
        var total_imp_count: u32 = 0;
        var collected_imps: [8][]const u8 = undefined;
        var collected_imp_count: u32 = 0;
        w.writeAll(",\"imports_called\":[") catch {};
        {
            var imp_count: u32 = 0;
            for (callees) |callee_addr| {
                if (imp_count >= max_context) break;
                const imp_name = if (eff.db.getImport(callee_addr)) |imp| imp.name else eff.db.getSymbolName(callee_addr);
                if (imp_name) |name| {
                    if (imp_count > 0) w.writeByte(',') catch {};
                    json.writeJsonString(w, name) catch {};
                    if (collected_imp_count < 8) {
                        collected_imps[collected_imp_count] = name;
                        collected_imp_count += 1;
                    }
                    imp_count += 1;
                }
            }
            total_imp_count = imp_count;
        }
        w.writeByte(']') catch {};

        // Context quality signal: count how many of the 5 signal types are non-empty
        const signal_count: u32 = @as(u32, @intFromBool(has_bytes)) +
            @as(u32, @intFromBool(total_str_count > 0)) +
            @as(u32, @intFromBool(total_caller_count > 0)) +
            @as(u32, @intFromBool(callees.len > 0)) +
            @as(u32, @intFromBool(total_imp_count > 0));
        const quality_label: []const u8 = if (signal_count == 0) "insufficient" else if (signal_count == 1) "minimal" else "rich";
        w.writeAll(",\"context_quality\":") catch {};
        json.writeJsonString(w, quality_label) catch {};

        // Suggested analysis hint based on collected context
        w.writeAll(",\"suggested_analysis\":") catch {};
        if (signal_count == 0) {
            json.writeJsonString(w, "Insufficient context: no string refs, callers, callees, or code bytes available. Try analyzing a callee or a function that references this one.") catch {};
        } else {
            var hint_buf = std.Io.Writer.Allocating.init(ctx.allocator);
            const hw = &hint_buf.writer;
            hw.writeAll("Function at ") catch {};
            var ab: [32]u8 = undefined;
            hw.writeAll(json.formatAddress(&ab, addr)) catch {};
            if (p.size > 0) {
                hw.print(" ({d} bytes)", .{p.size}) catch {};
            }
            // Mention string refs — O(log N) via sorted xref array
            {
                var str_count: u32 = 0;
                const hint_xrefs = eff.db.xrefs.getRefsFromRange(p.entry, proc_end);
                for (hint_xrefs) |xref| {
                    if (xref.xref_type == .data_read or xref.xref_type == .string_ref) {
                        if (eff.db.getString(xref.to) != null) str_count += 1;
                    }
                }
                if (str_count > 0) {
                    hw.print(". References {d} string(s)", .{str_count}) catch {};
                }
            }
            // Mention import calls
            {
                var imp_count: u32 = 0;
                for (callees) |callee_addr| {
                    if (eff.db.getImport(callee_addr) != null or eff.db.getSymbolName(callee_addr) != null) {
                        imp_count += 1;
                    }
                }
                if (imp_count > 0) {
                    hw.print(". Calls {d} import(s)", .{imp_count}) catch {};
                }
            }
            hw.writeByte('.') catch {};
            const hint = hint_buf.toOwnedSlice() catch "analysis unavailable";
            json.writeJsonString(w, hint) catch {};
        }

        // Generate actual name suggestions from collected context
        w.writeAll(",\"suggested_names\":[") catch {};
        {
            var name_idx: u32 = 0;

            // Keep current name as first suggestion if it's a real symbol
            if (p.name) |existing| {
                if (!std.mem.startsWith(u8, existing, "sub_") and existing.len > 0) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":") catch {};
                    json.writeJsonString(w, existing) catch {};
                    w.writeAll(",\"reason\":\"existing symbol\",\"confidence\":\"high\"}") catch {};
                    name_idx += 1;
                }
            }

            // ============================================================
            // v7.14.0 B3 — heuristic name candidates with confidence
            // ============================================================
            // Five rules in priority order (capped at 3 total candidates).
            // Each emits {"name", "confidence":"high|medium|low", "reason"}.
            // Field-test data: a function calling only fts_open/fts_read/
            // fts_children was a clear "fts_walk" wrapper but suggest_names
            // returned an empty array. These rules close that gap.

            // Helper: count distinct callees and import-call frequency.
            var unique_imp_calls: u32 = 0;
            var dominant_imp: ?[]const u8 = null;
            var dominant_imp_calls: u32 = 0;
            {
                // Tally callees by name. The single-import-wrapper rule needs
                // to know if the proc calls one import N times AND has ≤3
                // other distinct callees.
                const NameCount = struct { name: []const u8, count: u32 };
                var tallies: [16]NameCount = undefined;
                var tally_n: usize = 0;
                for (callees) |c_addr| {
                    const cn: ?[]const u8 = if (eff.db.getImport(c_addr)) |imp| imp.name else eff.db.getSymbolName(c_addr);
                    const nm = cn orelse continue;
                    var found_i: ?usize = null;
                    var ti: usize = 0;
                    while (ti < tally_n) : (ti += 1) {
                        if (std.mem.eql(u8, tallies[ti].name, nm)) {
                            found_i = ti;
                            break;
                        }
                    }
                    if (found_i) |fi| {
                        tallies[fi].count += 1;
                    } else if (tally_n < tallies.len) {
                        tallies[tally_n] = .{ .name = nm, .count = 1 };
                        tally_n += 1;
                    }
                }
                unique_imp_calls = @intCast(tally_n);
                // Pick the dominant import (most calls).
                var ti2: usize = 0;
                while (ti2 < tally_n) : (ti2 += 1) {
                    if (tallies[ti2].count > dominant_imp_calls) {
                        dominant_imp_calls = tallies[ti2].count;
                        dominant_imp = tallies[ti2].name;
                    }
                }
            }

            // Rule 1 — Single-import wrapper (HIGH).
            // Function calls exactly 1 import N times AND has ≤3 distinct
            // other callees.
            if (name_idx < 3 and unique_imp_calls == 1 and dominant_imp != null and callees.len <= 4) {
                const imp_full = dominant_imp.?;
                // Strip leading underscores (Mach-O `_strftime` → `strftime`).
                var ofs: usize = 0;
                while (ofs < imp_full.len and imp_full[ofs] == '_') ofs += 1;
                const imp_short = imp_full[ofs..];
                if (imp_short.len > 0) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"") catch {};
                    for (imp_short[0..@min(imp_short.len, 40)]) |ch| {
                        if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_') {
                            w.writeByte(ch) catch {};
                        }
                    }
                    w.writeAll("_wrapper\",\"confidence\":\"high\",\"reason\":\"calls ") catch {};
                    for (imp_full[0..@min(imp_full.len, 40)]) |ch| {
                        if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_') {
                            w.writeByte(ch) catch {};
                        }
                    }
                    w.print(" exclusively ({d}x)\"}}", .{dominant_imp_calls}) catch {};
                    name_idx += 1;
                }
            }

            // Rule 2 — Import family (HIGH).
            // ≥3 imports sharing a common prefix (fts_*, EVP_*, dispatch_*).
            // We look for a prefix that ≥3 imports share, not necessarily ALL.
            if (name_idx < 3 and collected_imp_count >= 3) {
                // Strategy: for each import, derive its candidate "family"
                // prefix (chars up to and including the first underscore).
                // The prefix shared by the most imports wins, provided ≥3.
                const FamCount = struct { prefix: []const u8, count: u32, exemplar: []const u8 };
                var fams: [16]FamCount = undefined;
                var fam_n: usize = 0;
                for (collected_imps[0..collected_imp_count]) |imp_n| {
                    var skip: usize = 0;
                    while (skip < imp_n.len and imp_n[skip] == '_') skip += 1;
                    const norm = imp_n[skip..];
                    // Find first underscore inside norm.
                    var us: usize = 0;
                    while (us < norm.len and norm[us] != '_') us += 1;
                    if (us == 0 or us >= norm.len) continue; // no family prefix
                    const fam = norm[0..us]; // e.g. "fts" from "fts_open"
                    if (fam.len < 2) continue;
                    // Tally.
                    var ti: usize = 0;
                    var found: ?usize = null;
                    while (ti < fam_n) : (ti += 1) {
                        if (std.mem.eql(u8, fams[ti].prefix, fam)) {
                            found = ti;
                            break;
                        }
                    }
                    if (found) |fi| {
                        fams[fi].count += 1;
                    } else if (fam_n < fams.len) {
                        fams[fam_n] = .{ .prefix = fam, .count = 1, .exemplar = imp_n };
                        fam_n += 1;
                    }
                }
                // Pick the family with the most members, ≥3.
                var best_i: ?usize = null;
                var best_count: u32 = 0;
                var fi2: usize = 0;
                while (fi2 < fam_n) : (fi2 += 1) {
                    if (fams[fi2].count > best_count and fams[fi2].count >= 3) {
                        best_count = fams[fi2].count;
                        best_i = fi2;
                    }
                }
                if (best_i) |bi| {
                    const fam = fams[bi].prefix;
                    const exemplar = fams[bi].exemplar;
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"") catch {};
                    for (fam[0..@min(fam.len, 24)]) |ch| {
                        if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_') {
                            w.writeByte(ch) catch {};
                        }
                    }
                    w.writeAll("_operation\",\"confidence\":\"high\",\"reason\":\"calls ") catch {};
                    for (exemplar[0..@min(exemplar.len, 30)]) |ch| {
                        if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_') {
                            w.writeByte(ch) catch {};
                        }
                    }
                    w.print(" and {d} others ({s} family)\"}}", .{ best_count - 1, fam }) catch {};
                    name_idx += 1;
                }
            }

            // Rule 3 — String-anchored (MEDIUM).
            // 1 distinctive string with verb-like pattern → verb_noun.
            if (name_idx < 3 and collected_str_count >= 1) {
                const VERBS = [_][]const u8{ "load", "init", "parse", "validate", "setup", "open", "close", "read", "write" };
                var matched_str: ?[]const u8 = null;
                var matched_verb: []const u8 = "";
                for (collected_strs[0..collected_str_count]) |s| {
                    if (s.len < 4) continue;
                    for (VERBS) |v| {
                        if (containsCI(s, v)) {
                            matched_str = s;
                            matched_verb = v;
                            break;
                        }
                    }
                    if (matched_str != null) break;
                }
                if (matched_str) |ms| {
                    // Extract a noun: the first identifier-like token AFTER
                    // the verb. Falls back to a generic "_action" if none.
                    var noun_buf: [32]u8 = undefined;
                    var nb_len: usize = 0;
                    var search_from: usize = 0;
                    if (indexOfCI(ms, matched_verb)) |vp| search_from = vp + matched_verb.len;
                    var k: usize = search_from;
                    // Skip non-identifier chars.
                    while (k < ms.len and !isIdentChar(ms[k])) k += 1;
                    while (k < ms.len and nb_len < noun_buf.len and isIdentChar(ms[k])) {
                        noun_buf[nb_len] = std.ascii.toLower(ms[k]);
                        nb_len += 1;
                        k += 1;
                    }
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"") catch {};
                    w.writeAll(matched_verb) catch {};
                    if (nb_len > 0) {
                        w.writeByte('_') catch {};
                        w.writeAll(noun_buf[0..nb_len]) catch {};
                    } else {
                        w.writeAll("_action") catch {};
                    }
                    w.writeAll("\",\"confidence\":\"medium\",\"reason\":\"references string '") catch {};
                    // Truncated string preview (escape-safe via writeJsonString-lite).
                    for (ms[0..@min(ms.len, 40)]) |ch| {
                        if (ch == '"' or ch == '\\') {
                            w.writeByte('\\') catch {};
                            w.writeByte(ch) catch {};
                        } else if (ch >= 0x20 and ch < 0x7F) {
                            w.writeByte(ch) catch {};
                        }
                    }
                    w.writeAll("'\"}") catch {};
                    name_idx += 1;
                }
            }

            // Rule 4 — Error handler (MEDIUM).
            // Error format strings + warn/err/fprintf/perror callee.
            if (name_idx < 3 and collected_str_count > 0 and collected_imp_count > 0) {
                var has_err_str = false;
                var err_str: []const u8 = "";
                for (collected_strs[0..collected_str_count]) |s| {
                    if (s.len < 4) continue;
                    if (containsCI(s, "failed") or containsCI(s, "cannot") or
                        std.mem.indexOf(u8, s, "%s: %s") != null or
                        std.mem.indexOf(u8, s, "error") != null)
                    {
                        has_err_str = true;
                        err_str = s;
                        break;
                    }
                }
                var has_err_call = false;
                for (collected_imps[0..collected_imp_count]) |i_n| {
                    if (containsCI(i_n, "_warn") or containsCI(i_n, "_err") or
                        containsCI(i_n, "fprintf") or containsCI(i_n, "perror") or
                        containsCI(i_n, "syslog"))
                    {
                        has_err_call = true;
                        break;
                    }
                }
                if (has_err_str and has_err_call) {
                    // Pick a verb out of the error string for the name.
                    var verb_buf: [16]u8 = undefined;
                    var vb_len: usize = 0;
                    if (indexOfCI(err_str, "load")) |_| {
                        @memcpy(verb_buf[0..4], "load");
                        vb_len = 4;
                    } else if (indexOfCI(err_str, "open")) |_| {
                        @memcpy(verb_buf[0..4], "open");
                        vb_len = 4;
                    } else if (indexOfCI(err_str, "read")) |_| {
                        @memcpy(verb_buf[0..4], "read");
                        vb_len = 4;
                    } else if (indexOfCI(err_str, "write")) |_| {
                        @memcpy(verb_buf[0..5], "write");
                        vb_len = 5;
                    } else if (indexOfCI(err_str, "parse")) |_| {
                        @memcpy(verb_buf[0..5], "parse");
                        vb_len = 5;
                    } else {
                        @memcpy(verb_buf[0..6], "handle");
                        vb_len = 6;
                    }
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"report_") catch {};
                    w.writeAll(verb_buf[0..vb_len]) catch {};
                    w.writeAll("_error\",\"confidence\":\"medium\",\"reason\":\"references error string '") catch {};
                    for (err_str[0..@min(err_str.len, 40)]) |ch| {
                        if (ch == '"' or ch == '\\') {
                            w.writeByte('\\') catch {};
                            w.writeByte(ch) catch {};
                        } else if (ch >= 0x20 and ch < 0x7F) {
                            w.writeByte(ch) catch {};
                        }
                    }
                    w.writeAll("' and calls _warn/_err family\"}") catch {};
                    name_idx += 1;
                }
            }

            // Rule 5 — Dispatcher (LOW).
            // ≥5 callees, no shared prefix, no string refs.
            if (name_idx < 3 and callees.len >= 5 and collected_str_count == 0) {
                // Compute shared prefix across callees we resolved to names.
                // If shared prefix length < 3, treat as "no shared prefix".
                var first_name: ?[]const u8 = null;
                for (callees) |c_addr| {
                    if (eff.db.getImport(c_addr)) |imp| {
                        first_name = imp.name;
                        break;
                    }
                    if (eff.db.getSymbolName(c_addr)) |s| {
                        first_name = s;
                        break;
                    }
                }
                var max_shared: usize = if (first_name) |fn_| fn_.len else 0;
                if (first_name) |fn_| {
                    for (callees) |c_addr| {
                        const cn: ?[]const u8 = if (eff.db.getImport(c_addr)) |imp| imp.name else eff.db.getSymbolName(c_addr);
                        if (cn) |n| {
                            var k: usize = 0;
                            while (k < max_shared and k < n.len and fn_[k] == n[k]) : (k += 1) {}
                            max_shared = k;
                        }
                    }
                }
                if (max_shared < 3) {
                    var addr_short_buf: [8]u8 = undefined;
                    const hex_chars = "0123456789abcdef";
                    var v: u64 = addr & 0xFFFF;
                    var bi: usize = 4;
                    while (bi > 0) {
                        bi -= 1;
                        addr_short_buf[bi] = hex_chars[v & 0xF];
                        v >>= 4;
                    }
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"dispatch_") catch {};
                    w.writeAll(addr_short_buf[0..4]) catch {};
                    w.print("\",\"confidence\":\"low\",\"reason\":\"≥5 distinct callees ({d}), no shared prefix\"}}", .{callees.len}) catch {};
                    name_idx += 1;
                }
            }

            // Name from FuncName: pattern — check ALL strings for "Name:" or "Name(" prefix
            // Examples: "COM_FindFile: both handle and file set" → COM_FindFile
            //           "SV_Physics: bad movetype" → SV_Physics
            //           "R_RenderView: NULL worldmodel" → R_RenderView
            var found_funcname = false;
            if (name_idx < 3 and collected_str_count > 0) {
                var best_funcname: []const u8 = "";
                var best_funcname_len: usize = 0;
                for (collected_strs[0..collected_str_count]) |s| {
                    // Extract leading alphanumeric+underscore prefix
                    var end: usize = 0;
                    while (end < s.len and end < 60) : (end += 1) {
                        const c = s[end];
                        if (!((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_')) break;
                    }
                    // Must be at least 4 chars and followed by ':' or '('
                    if (end >= 4 and end < s.len and (s[end] == ':' or s[end] == '(')) {
                        if (end > best_funcname_len) {
                            best_funcname = s[0..end];
                            best_funcname_len = end;
                        }
                    }
                }
                if (best_funcname_len >= 4) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"") catch {};
                    // Write the extracted function name directly (preserve case)
                    w.writeAll(best_funcname) catch {};
                    w.writeAll("\",\"reason\":\"extracted FuncName: prefix from string '") catch {};
                    // Write the safe portion for the reason
                    w.writeAll(best_funcname) catch {};
                    w.writeAll("'\"}") catch {};
                    name_idx += 1;
                    found_funcname = true;
                }
            }

            // Fallback: name from dominant string reference keyword (with handle_ prefix)
            if (!found_funcname and name_idx < 3 and collected_str_count > 0) {
                var best_str: []const u8 = collected_strs[0];
                var kw_end: usize = 0;
                for (collected_strs[0..collected_str_count]) |s| {
                    var end: usize = 0;
                    while (end < s.len and end < 30) : (end += 1) {
                        const c = s[end];
                        if (!((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_')) break;
                    }
                    if (end >= 4 and end > kw_end) {
                        best_str = s;
                        kw_end = end;
                    }
                }
                if (kw_end == 0) {
                    while (kw_end < best_str.len and kw_end < 30) : (kw_end += 1) {
                        const c = best_str[kw_end];
                        if (!((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_')) break;
                    }
                }
                if (kw_end >= 4) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"handle_") catch {};
                    for (best_str[0..kw_end]) |c| {
                        const lc: u8 = if (c >= 'A' and c <= 'Z') c + 32 else c;
                        w.writeByte(lc) catch {};
                    }
                    w.writeAll("\",\"reason\":\"references ") catch {};
                    w.print("{d}", .{collected_str_count}) catch {};
                    w.writeAll(" string(s) starting with '") catch {};
                    for (best_str[0..kw_end]) |c2| {
                        const lc2: u8 = if (c2 >= 'A' and c2 <= 'Z') c2 + 32 else c2;
                        w.writeByte(lc2) catch {};
                    }
                    w.writeAll("'\"}") catch {};
                    name_idx += 1;
                }
            }

            // Name from import calls
            if (name_idx < 3 and collected_imp_count > 0) {
                const imp_name = normalizeForComparison(collected_imps[0]);
                // Categorize the import
                const category: ?[]const u8 = if (containsAnyCI(imp_name, &.{ "crypt", "sha", "aes", "rsa", "ssl", "tls", "hash", "sign", "verify", "cert" }))
                    "crypto"
                else if (containsAnyCI(imp_name, &.{ "socket", "connect", "send", "recv", "http", "url", "net" }))
                    "network"
                else if (containsAnyCI(imp_name, &.{ "alloc", "malloc", "free", "realloc", "dealloc" }))
                    "memory"
                else if (containsAnyCI(imp_name, &.{ "file", "open", "close", "read", "write", "fstat", "seek" }))
                    "file_io"
                else if (containsAnyCI(imp_name, &.{ "dispatch", "thread", "mutex", "lock", "semaphore", "queue" }))
                    "concurrency"
                else if (containsAnyCI(imp_name, &.{ "objc_msg", "class_get", "sel_register" }))
                    "objc_runtime"
                else
                    null;

                if (category) |cat| {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"") catch {};
                    w.writeAll(cat) catch {};
                    w.writeAll("_operation\",\"reason\":\"calls ") catch {};
                    // Write only safe chars from import name
                    for (imp_name[0..@min(imp_name.len, 30)]) |ic| {
                        if ((ic >= 'a' and ic <= 'z') or (ic >= 'A' and ic <= 'Z') or (ic >= '0' and ic <= '9') or ic == '_') {
                            w.writeByte(ic) catch {};
                        }
                    }
                    if (collected_imp_count > 1) {
                        w.print(" and {d} others", .{collected_imp_count - 1}) catch {};
                    }
                    w.writeAll("\"}") catch {};
                    name_idx += 1;
                }
            }

            // Change B: Import library patterns — if no name from strings, check if imports
            // are dominated by a single library prefix (SCE, pthread, crypto, etc.)
            if (!found_funcname and name_idx < 3 and collected_str_count == 0 and collected_imp_count > 0) {
                const LibPattern = struct { prefix: []const u8, domain: []const u8 };
                const lib_patterns = [_]LibPattern{
                    .{ .prefix = "sceaudio", .domain = "audio" },
                    .{ .prefix = "sceDisplay", .domain = "display" },
                    .{ .prefix = "scedisplay", .domain = "display" },
                    .{ .prefix = "sceGe", .domain = "graphics" },
                    .{ .prefix = "scege", .domain = "graphics" },
                    .{ .prefix = "pthread", .domain = "thread" },
                    .{ .prefix = "crypto", .domain = "crypto" },
                    .{ .prefix = "ssl", .domain = "crypto" },
                    .{ .prefix = "aes", .domain = "crypto" },
                    .{ .prefix = "SSL_", .domain = "crypto" },
                    .{ .prefix = "AES_", .domain = "crypto" },
                };
                var dominant_domain: ?[]const u8 = null;
                var domain_match_count: u32 = 0;
                for (lib_patterns) |lp| {
                    var match_count: u32 = 0;
                    for (collected_imps[0..collected_imp_count]) |imp_n| {
                        if (imp_n.len >= lp.prefix.len) {
                            var matches = true;
                            for (lp.prefix, 0..) |pc, pi| {
                                const ic = imp_n[pi];
                                const plc = if (pc >= 'A' and pc <= 'Z') pc + 32 else pc;
                                const ilc = if (ic >= 'A' and ic <= 'Z') ic + 32 else ic;
                                if (plc != ilc) {
                                    matches = false;
                                    break;
                                }
                            }
                            if (matches) match_count += 1;
                        }
                    }
                    if (match_count > domain_match_count) {
                        domain_match_count = match_count;
                        dominant_domain = lp.domain;
                    }
                }
                // If majority of imports match a single library domain
                if (dominant_domain) |domain| {
                    if (domain_match_count * 2 >= collected_imp_count) {
                        if (name_idx > 0) w.writeByte(',') catch {};
                        w.writeAll("{\"name\":\"") catch {};
                        w.writeAll(domain) catch {};
                        w.writeAll("_operation\",\"reason\":\"majority of imports (") catch {};
                        w.print("{d}/{d}", .{ domain_match_count, collected_imp_count }) catch {};
                        w.writeAll(") are from ") catch {};
                        w.writeAll(domain) catch {};
                        w.writeAll(" library\"}") catch {};
                        name_idx += 1;
                    }
                }
            }

            // Change C: Role detection from callees
            if (name_idx < 3 and callees.len > 0) {
                var calls_exit = false;
                var calls_cleanup = false;
                var cleanup_count: u32 = 0;
                for (callees) |callee_addr| {
                    const callee_name = eff.db.resolveName(callee_addr);
                    if (callee_name) |cn| {
                        const norm = normalizeForComparison(cn);
                        if (containsAnyCI(norm, &.{ "exit", "abort", "_exit" })) {
                            calls_exit = true;
                        }
                        if (containsAnyCI(norm, &.{ "free", "close", "release", "deinit" })) {
                            calls_cleanup = true;
                            cleanup_count += 1;
                        }
                    }
                }
                // exit/abort + error strings → fatal error handler
                if (calls_exit and collected_str_count > 0) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"fatal_error_handler\",\"reason\":\"calls exit/abort and has error strings\"}") catch {};
                    name_idx += 1;
                } else if (calls_exit) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"error_exit\",\"reason\":\"calls exit/abort\"}") catch {};
                    name_idx += 1;
                }
                // Cleanup pattern
                if (name_idx < 3 and calls_cleanup and cleanup_count >= 2) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"cleanup_resources\",\"reason\":\"calls multiple free/close/release functions\"}") catch {};
                    name_idx += 1;
                }
            }

            // Structural suggestion: wrapper/stub/thunk
            if (name_idx < 3 and p.size > 0) {
                if (p.size <= 16 and callees.len == 1) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"thunk\",\"reason\":\"tiny function that jumps to one target\"}") catch {};
                    name_idx += 1;
                } else if (p.size <= 64 and callees.len == 1) {
                    if (name_idx > 0) w.writeByte(',') catch {};
                    w.writeAll("{\"name\":\"wrapper\",\"reason\":\"small function calling one other\"}") catch {};
                    name_idx += 1;
                }
            }
        }
        w.writeByte(']') catch {};

        w.writeByte('}') catch {};
    }

    w.writeByte(']') catch {};

    const result_json = result_buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "suggest_names", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .meta_max_chars = 200_000 };
}

// ============================================================================
// get_remake_frontier — deterministic harness-native planner (v7.10.0)
// ----------------------------------------------------------------------------
// Ranks the next functions for an LLM/harness to inspect when remaking a
// binary. Read-only. Performs no full decompilation — emits `next[]` MCP
// calls so the harness fans out using other tools (get_semantic_slice,
// get_cfg, suggest_names, get_xrefs, get_call_graph).
//
// Score weights live as named consts so v7.10.1 can tune them. Any change to
// the schemas of the tools referenced in `next[]` / `parallel_batches[].calls`
// must update this generator too.
// ============================================================================

// --- Score weights (top-level so v7.10.1 polish can tune) ------------------
const SCORE_SEED_EXACT: i32 = 50;
const SCORE_NAME_PATTERN: i32 = 25;
const SCORE_STRING_PATTERN: i32 = 20;
const SCORE_IMPORT_PATTERN: i32 = 25;
const SCORE_GOAL_KEYWORD: i32 = 15;
const SCORE_RESOURCE_STRING: i32 = 15;
const SCORE_EXTERNAL_IMPORT: i32 = 20;
const SCORE_HIGH_CONNECTIVITY: i32 = 10;
const SCORE_DISPATCH_FANOUT: i32 = 10;
const SCORE_NAME_QUALITY: i32 = 5;
const SCORE_NOVELTY_NEW_EVIDENCE: i32 = 10;
const SCORE_GOAL_BIAS_NUM: i32 = 3; // multiplier numerator (3/2 = 1.5x)
const SCORE_GOAL_BIAS_DEN: i32 = 2;
const PENALTY_VISITED: i32 = -25;
const PENALTY_SUBSUMED: i32 = -25;
const PENALTY_THUNK: i32 = -15;
const PENALTY_LIBRARY_WRAPPER: i32 = -10;
const PENALTY_TINY_LEAF: i32 = -10;
const HIGH_CONNECTIVITY_THRESHOLD: u32 = 5;
const DISPATCH_MIN_CALLEES: usize = 3;
const TINY_LEAF_MAX_INSNS: u64 = 5;
const COVERAGE_GAPS_MAX: usize = 5;

const RemakeWhy = struct {
    source: []const u8,
    confidence: []const u8, // "high" | "medium" | "low"
    text: []const u8,
};

const RemakeSignals = struct {
    string_count: u32 = 0,
    import_count: u32 = 0,
    callers: u32 = 0,
    callees: u32 = 0,
    external_interfaces: u32 = 0,
    resources: u32 = 0,
};

const RemakeCandidate = struct {
    address: u64,
    score: i32,
    role_hypothesis: []const u8,
    why: std.array_list.Managed(RemakeWhy),
    signals: RemakeSignals,
    strings_seen: std.array_list.Managed([]const u8),
    imports_seen: std.array_list.Managed([]const u8),
    /// v7.13.0 B3 — addresses absorbed during adjacent-aliased dedup.
    /// Empty when the candidate stands alone. When non-empty, the candidate
    /// represents a cluster of nearby procs (within ±64 bytes) that shared a
    /// common string-ref signal — typically compiler-emitted variants or
    /// adjacent thunks for the same logical subsystem.
    aliases: std.array_list.Managed(u64),
};

/// Case-insensitive substring containment. Returns true for an empty needle.
fn rfContains(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var ok = true;
        for (needle, 0..) |nc, ni| {
            const hc = haystack[i + ni];
            const a = if (nc >= 'A' and nc <= 'Z') nc + 32 else nc;
            const b = if (hc >= 'A' and hc <= 'Z') hc + 32 else hc;
            if (a != b) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

/// Match haystack against a `|`-separated OR pattern list. Each element is
/// trimmed; empty elements are skipped.
fn rfMatchesPatternList(haystack: []const u8, pattern: []const u8) bool {
    var rest = pattern;
    while (rest.len > 0) {
        const sep = std.mem.indexOfScalar(u8, rest, '|');
        const raw = if (sep) |pos| rest[0..pos] else rest;
        const item = trimString(raw);
        if (item.len > 0 and rfContains(haystack, item)) return true;
        if (sep) |pos| {
            rest = rest[pos + 1 ..];
        } else break;
    }
    return false;
}

/// Read `patterns` (string or array of strings) from params and append each
/// non-empty entry to `out`. Returns the count appended.
fn rfCollectPatterns(params: std.json.Value, out: *std.array_list.Managed([]const u8)) usize {
    var n: usize = 0;
    if (getString(params, "patterns")) |s| {
        out.append(s) catch return n;
        n += 1;
        return n;
    }
    if (getArray(params, "patterns")) |arr| {
        for (arr.array.items) |item| {
            if (item == .string and item.string.len > 0) {
                out.append(item.string) catch break;
                n += 1;
            }
        }
    }
    return n;
}

/// Match against any pattern in the collected list.
fn rfAnyPatternMatch(haystack: []const u8, patterns: []const []const u8) bool {
    for (patterns) |p| {
        if (rfMatchesPatternList(haystack, p)) return true;
    }
    return false;
}

/// v7.12.1 W5: stop-word filter for goal tokenizer. Pre-fix, generic prompt
/// words like "and"/"the"/"tool" matched as substrings against function names
/// (e.g. "and" → "_DisposeCommand"), promoting destructors and boilerplate
/// in frontier candidates. Field test: GeForceNOWRelaunch + /usr/bin/plutil.
const RF_STOP_WORDS = std.StaticStringMap(void).initComptime(.{
    .{ "and", {} },       .{ "are", {} },        .{ "the", {} },     .{ "its", {} },
    .{ "for", {} },       .{ "from", {} },       .{ "with", {} },    .{ "what", {} },
    .{ "how", {} },       .{ "why", {} },        .{ "main", {} },    .{ "this", {} },
    .{ "that", {} },      .{ "into", {} },       .{ "tool", {} },    .{ "does", {} },
    .{ "app", {} },       .{ "was", {} },        .{ "use", {} },     .{ "all", {} },
    .{ "subsystem", {} }, .{ "subsystems", {} }, .{ "explain", {} }, .{ "your", {} },
    .{ "one", {} },       .{ "can", {} },        .{ "get", {} },     .{ "now", {} },
    .{ "has", {} },       .{ "will", {} },       .{ "who", {} },     .{ "where", {} },
    .{ "when", {} },      .{ "also", {} },       .{ "but", {} },     .{ "not", {} },
    .{ "any", {} },       .{ "some", {} },       .{ "may", {} },     .{ "more", {} },
    .{ "less", {} },      .{ "most", {} },       .{ "then", {} },    .{ "than", {} },
});

/// Very small word-tokenizer — splits on non-alphanumerics, lowercase, drops
/// 1-2 char tokens (mostly noise: "a", "to", "of"). Used only on the `goal`
/// string for keyword bias.
fn rfTokenizeGoal(allocator: Allocator, goal: []const u8) std.array_list.Managed([]const u8) {
    var out = std.array_list.Managed([]const u8).init(allocator);
    var i: usize = 0;
    while (i < goal.len) {
        while (i < goal.len and !std.ascii.isAlphanumeric(goal[i])) : (i += 1) {}
        const start = i;
        while (i < goal.len and std.ascii.isAlphanumeric(goal[i])) : (i += 1) {}
        if (i - start >= 3) {
            const lower = allocator.alloc(u8, i - start) catch continue;
            for (goal[start..i], 0..) |c, k| {
                lower[k] = if (c >= 'A' and c <= 'Z') c + 32 else c;
            }
            // v7.12.1 W5: drop generic prompt stop-words before they bias
            // candidate scoring against unrelated function-name fragments.
            if (RF_STOP_WORDS.has(lower)) {
                allocator.free(lower);
                continue;
            }
            out.append(lower) catch {};
        }
    }
    return out;
}

/// Known-import categories that count as "external interface" evidence and
/// usually anchor remake-relevant boundaries.
fn rfIsExternalImport(name: []const u8) bool {
    return containsAnyCI(name, &.{
        // network
        "socket",   "connect", "send",   "recv", "bind", "listen", "accept", "curl",   "http",
        // file/IO
        "fopen",    "fread",   "fwrite", "open", "read", "write",  "close",  "stat",
        // crypto
          "crypto",
        "ssl",      "tls",     "aes",    "sha",  "rsa",  "hmac",   "evp_",
        // db
          "sqlite", "mysql",
        "postgres", "redis",
    });
}

fn rfIsParserImport(name: []const u8) bool {
    return containsAnyCI(name, &.{ "strchr", "strtok", "strstr", "strsep", "json", "xml", "regex", "yaml", "scanf", "getopt" });
}

fn rfIsResourceAdapterImport(name: []const u8) bool {
    return containsAnyCI(name, &.{ "fopen", "open(", "socket", "sqlite", "curl", "mmap", "shmget", "pipe(", "_open" });
}

fn rfIsValidatorImport(name: []const u8) bool {
    return containsAnyCI(name, &.{ "verify", "validate", "_chk", "_check", "compare", "cmp_constant", "_constant_time" });
}

fn rfIsCryptoImport(name: []const u8) bool {
    return containsAnyCI(name, &.{ "evp_", "aes_", "sha", "md5", "hmac", "rsa_", "ecdsa", "chacha", "poly1305", "_encrypt", "_decrypt" });
}

fn rfIsErrorHandlerImport(name: []const u8) bool {
    return containsAnyCI(name, &.{ "abort", "_exit", "panic", "__assert", "__cxa_throw", "fatal", "longjmp" });
}

fn rfIsBoundaryImport(name: []const u8) bool {
    return containsAnyCI(name, &.{ "getopt", "argv", "_main", "exit", "atexit" });
}

/// Heuristic: looks like a thunk/PLT trampoline (single-callee leaf with no
/// strings or imports of its own and a tiny body).
fn rfLooksLikeThunk(proc_size: u64, callee_count: usize, string_count: u32) bool {
    return callee_count == 1 and string_count == 0 and proc_size > 0 and proc_size <= 32;
}

/// Heuristic: name suggests a generic library wrapper (libc/libstdc++ etc).
fn rfIsLibraryWrapperName(name: ?[]const u8) bool {
    const n = name orelse return false;
    if (std.mem.startsWith(u8, n, "_dyld_") or std.mem.startsWith(u8, n, "__dyld_")) return true;
    if (std.mem.startsWith(u8, n, "___chkstk")) return true;
    if (rfContains(n, "libc++")) return true;
    if (rfContains(n, "_objc_msgSend_stub")) return true;
    return false;
}

/// Tier-1 role hypothesis. Returns "unknown" when no hard trigger fires.
fn rfRoleHypothesis(
    db: *const Database,
    proc_name: ?[]const u8,
    callees: []const u64,
    callees_resolved: []const ?[]const u8,
    string_count: u32,
    is_entry_point: bool,
) []const u8 {
    // boundary
    if (is_entry_point) return "boundary";
    if (proc_name) |n| {
        if (rfContains(n, "main") or rfContains(n, "argv") or rfContains(n, "getopt")) return "boundary";
        if (rfContains(n, "err") or rfContains(n, "panic") or rfContains(n, "abort") or rfContains(n, "fatal")) return "error_handler";
        if (rfContains(n, "valid") or rfContains(n, "verify") or rfContains(n, "check")) return "validator";
        if (rfContains(n, "parse_") or rfContains(n, "tokenize_") or rfContains(n, "lex_")) return "parser";
    }
    // import-driven role tags (highest priority after explicit name patterns)
    var any_parser_imp = false;
    var any_resource_imp = false;
    var any_validator_imp = false;
    var any_crypto_imp = false;
    var any_err_imp = false;
    for (callees_resolved) |maybe_name| {
        const name = maybe_name orelse continue;
        if (!any_parser_imp and rfIsParserImport(name)) any_parser_imp = true;
        if (!any_resource_imp and rfIsResourceAdapterImport(name)) any_resource_imp = true;
        if (!any_validator_imp and rfIsValidatorImport(name)) any_validator_imp = true;
        if (!any_crypto_imp and rfIsCryptoImport(name)) any_crypto_imp = true;
        if (!any_err_imp and rfIsErrorHandlerImport(name)) any_err_imp = true;
    }
    if (any_validator_imp) return "validator";
    if (any_crypto_imp) return "codec_or_crypto";
    if (any_parser_imp) return "parser";
    if (any_resource_imp) return "resource_adapter";
    if (any_err_imp) return "error_handler";

    // dispatcher: ≥3 distinct callees, no shared 4-char prefix, no own strings.
    if (string_count == 0 and callees.len >= DISPATCH_MIN_CALLEES) {
        var distinct = std.AutoHashMap(u64, void).init(db.allocator);
        defer distinct.deinit();
        for (callees) |c| distinct.put(c, {}) catch {};
        if (distinct.count() >= DISPATCH_MIN_CALLEES) {
            // Check no shared 4-char prefix among resolved names.
            var first_name: ?[]const u8 = null;
            var shared = true;
            for (callees_resolved) |maybe_name| {
                const name = maybe_name orelse continue;
                if (first_name == null) {
                    first_name = name;
                    continue;
                }
                const a = first_name.?;
                const b = name;
                const min_len = @min(@min(a.len, b.len), @as(usize, 4));
                if (min_len < 4 or !std.mem.eql(u8, a[0..min_len], b[0..min_len])) {
                    shared = false;
                    break;
                }
            }
            if (!shared) return "dispatcher";
        }
    }

    return "unknown";
}

/// Build the visited-set HashMap. Visited addresses are stored in their
/// internal (delta-removed) form so they line up with procedure entries.
fn rfBuildVisited(
    allocator: Allocator,
    params: std.json.Value,
    eff: EffectiveDb,
) std.AutoHashMap(u64, void) {
    var set = std.AutoHashMap(u64, void).init(allocator);
    if (params != .object) return set;
    const v = params.object.get("visited") orelse return set;
    if (v != .array) return set;
    for (v.array.items) |item| {
        const i64v = coerceToInt(item) orelse continue;
        const ext: u64 = @bitCast(i64v);
        const internal = removeRebaseDelta(ext, eff.delta);
        if (eff.db.getProcedureContaining(internal)) |proc| {
            set.put(proc.entry, {}) catch {};
        } else {
            set.put(internal, {}) catch {};
        }
    }
    return set;
}

/// Build a sorted ascending list of all procedure entry addresses in the DB.
/// Determinism anchor: every later loop iterates this list in the same order.
fn rfSortedProcedures(allocator: Allocator, db: *const Database) []u64 {
    var keys = std.array_list.Managed(u64).init(allocator);
    var it = db.procedures.keyIterator();
    while (it.next()) |k| keys.append(k.*) catch {};
    std.mem.sort(u64, keys.items, {}, struct {
        fn lt(_: void, a: u64, b: u64) bool {
            return a < b;
        }
    }.lt);
    return keys.toOwnedSlice() catch &.{};
}

fn rfPushWhy(allocator: Allocator, list: *std.array_list.Managed(RemakeWhy), source: []const u8, confidence: []const u8, text: []const u8) void {
    if (list.items.len >= 8) return;
    _ = allocator;
    list.append(.{ .source = source, .confidence = confidence, .text = text }) catch {};
}

fn rfAppendUnique(list: *std.array_list.Managed([]const u8), s: []const u8, max_items: usize) void {
    if (s.len == 0 or list.items.len >= max_items) return;
    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, s)) return;
    }
    list.append(s) catch {};
}

fn handleGetRemakeFrontier(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);

    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_remake_frontier", params);
    };
    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_remake_frontier");
    const eff = resolveEffectiveDb(entry);
    const allocator = ctx.allocator;

    // --- Parameters with bounds ---
    const goal: []const u8 = getString(params, "goal") orelse "";
    const max_candidates: usize = blk: {
        const v = getInt(params, "max_candidates") orelse 24;
        break :blk @min(@as(usize, @intCast(@max(v, 1))), 128);
    };
    const max_batch: usize = blk: {
        const v = getInt(params, "max_batch") orelse 12;
        break :blk @min(@as(usize, @intCast(@max(v, 1))), 50);
    };
    const depth: u32 = blk: {
        const v = getInt(params, "depth") orelse 1;
        break :blk @min(@as(u32, @intCast(@max(v, 0))), 3);
    };
    const scan_budget: usize = blk: {
        const v = getInt(params, "scan_budget") orelse 50000;
        // v7.12 W11: cap lowered from 200000 → 100000 to bound worst-case
        // wall time on 1M+-proc binaries.
        break :blk @min(@as(usize, @intCast(@max(v, 1000))), 100000);
    };

    // Read-only shared lock; auto-release.
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    // Patterns (string or array, `|` OR within each).
    var patterns_list = std.array_list.Managed([]const u8).init(allocator);
    _ = rfCollectPatterns(params, &patterns_list);
    const patterns = patterns_list.items;

    // Goal token list (lower-cased ≥3 char tokens).
    const goal_tokens = rfTokenizeGoal(allocator, goal);
    const goal_active = goal_tokens.items.len > 0;

    // Visited set (procedure-entry granularity, internal addresses).
    var visited = rfBuildVisited(allocator, params, eff);
    var visited_strings = std.StringHashMap(void).init(allocator);
    var visited_imports = std.StringHashMap(void).init(allocator);

    // Seeds (anchor candidates).
    var seed_set = std.AutoHashMap(u64, void).init(allocator);
    if (params == .object and (params.object.get("seeds") != null or params.object.get("addresses") != null or params.object.get("address") != null)) {
        // parseBatchAddresses reads "addresses"/"address". For "seeds" we
        // mirror the value into "addresses" (in a copy of params) by hand.
        const seeds_val = params.object.get("seeds");
        if (seeds_val) |sv| {
            switch (sv) {
                .integer, .float, .string, .number_string => {
                    const i64v = coerceToInt(sv) orelse 0;
                    const ext: u64 = @bitCast(i64v);
                    const internal = removeRebaseDelta(ext, eff.delta);
                    if (eff.db.getProcedureContaining(internal)) |p| seed_set.put(p.entry, {}) catch {};
                },
                .array => {
                    for (sv.array.items) |item| {
                        const i64v = coerceToInt(item) orelse continue;
                        const ext: u64 = @bitCast(i64v);
                        const internal = removeRebaseDelta(ext, eff.delta);
                        if (eff.db.getProcedureContaining(internal)) |p| seed_set.put(p.entry, {}) catch {};
                    }
                },
                else => {},
            }
        } else if (parseBatchAddresses(allocator, params) catch null) |addrs| {
            for (addrs) |a| {
                const internal = removeRebaseDelta(a, eff.delta);
                if (eff.db.getProcedureContaining(internal)) |p| seed_set.put(p.entry, {}) catch {};
            }
        }
    }

    // Build evidence sets aggregated across "visited" procs (for novelty bias).
    {
        var vit = visited.keyIterator();
        while (vit.next()) |k| {
            const proc = eff.db.getProcedureContaining(k.*) orelse continue;
            const range_end = proc.entry + @max(proc.size, 256);
            const refs = eff.db.xrefs.getRefsFromRange(proc.entry, range_end);
            for (refs) |xr| {
                if (eff.db.getString(xr.to)) |s| {
                    visited_strings.put(s.value, {}) catch {};
                }
                if (xr.xref_type == .call) {
                    if (eff.db.imports.get(xr.to)) |imp| visited_imports.put(imp.name, {}) catch {};
                    if (eff.db.resolveName(xr.to)) |n| visited_imports.put(n, {}) catch {};
                }
            }
        }
    }

    // Deterministic procedure ordering: ascending entry address.
    const proc_keys = rfSortedProcedures(allocator, eff.db);

    // Per-procedure scoring is independent. We do it serially: ParallelFor
    // requires hand-rolled allocator sharding (every per-proc allocation —
    // why[] strings, signal lists — must come from a thread-local arena to
    // avoid ArrayList contention on `allocator`). For v7.10.0 that's not
    // worth the complexity; serial scoring of <=200k procs is fast enough.

    var candidates = std.array_list.Managed(RemakeCandidate).init(allocator);
    candidates.ensureTotalCapacity(@min(proc_keys.len, max_candidates * 4)) catch {};

    // v7.13.0 B7 — wall-clock guard: cap the per-proc scan at 3 seconds.
    // Pre-fix, dense procedure scans could take several seconds per
    // get_binary_context call; the proc-count threshold (lowered to 30K in
    // pickBinaryContextMode) catches the worst offenders, but this guard backstops anything that
    // slips past — e.g. moderate-size binaries with very dense xref graphs.
    // Checked every 256 iterations to avoid syscall overhead in the hot loop.
    const SCAN_DEADLINE_MS: i64 = 3000;
    const scan_start_ms: i64 = runtime.awakeMillis(ctx.io);
    var time_aborted = false;

    var scanned: usize = 0;
    for (proc_keys) |proc_entry| {
        if (scanned >= scan_budget) break;
        if (scanned > 0 and scanned % 256 == 0) {
            if (runtime.awakeMillis(ctx.io) - scan_start_ms > SCAN_DEADLINE_MS) {
                time_aborted = true;
                break;
            }
        }
        scanned += 1;

        const proc = eff.db.procedures.get(proc_entry) orelse continue;
        const proc_name = proc.name orelse eff.db.resolveName(proc_entry);
        const range_end = proc.entry + @max(proc.size, 256);

        // Range-scan the proc body once for strings + call targets.
        const refs = eff.db.xrefs.getRefsFromRange(proc.entry, range_end);
        var sigs = RemakeSignals{};
        var strings_seen = std.array_list.Managed([]const u8).init(allocator);
        var imports_seen = std.array_list.Managed([]const u8).init(allocator);
        var pattern_string_hit: ?[]const u8 = null;
        var pattern_import_hit: ?[]const u8 = null;
        var resource_string_hit: ?[]const u8 = null;
        var external_import_hit: ?[]const u8 = null;
        var has_resource_string = false;
        var has_external_import = false;
        for (refs) |xr| {
            if (eff.db.getString(xr.to)) |s| {
                sigs.string_count +%= 1;
                rfAppendUnique(&strings_seen, s.value, 8);
                if (patterns.len > 0 and pattern_string_hit == null and rfAnyPatternMatch(s.value, patterns)) {
                    pattern_string_hit = s.value;
                }
                if (!has_resource_string) {
                    var cats: [MAX_CAP_CATS][]const u8 = undefined;
                    const cat_count = categorizeCapability(s.value, &cats);
                    if (cat_count > 0) {
                        has_resource_string = true;
                        sigs.resources +%= 1;
                        resource_string_hit = s.value;
                    }
                }
            }
            if (xr.xref_type == .call) {
                // Resolve the callee name (import name preferred).
                const imp_opt: ?[]const u8 = if (eff.db.imports.get(xr.to)) |imp| imp.name else eff.db.resolveName(xr.to);
                if (imp_opt) |imp_name| {
                    sigs.import_count +%= 1;
                    rfAppendUnique(&imports_seen, imp_name, 8);
                    if (patterns.len > 0 and pattern_import_hit == null and rfAnyPatternMatch(imp_name, patterns)) {
                        pattern_import_hit = imp_name;
                    }
                    if (!has_external_import and rfIsExternalImport(imp_name)) {
                        has_external_import = true;
                        sigs.external_interfaces +%= 1;
                        external_import_hit = imp_name;
                    }
                }
            }
        }

        // Caller / callee counts.
        var caller_count: u32 = 0;
        for (eff.db.xrefs.getRefsTo(proc_entry)) |xr| {
            if (xr.xref_type == .call) caller_count +%= 1;
        }
        sigs.callers = caller_count;
        const callees = ensureCalleesCached(eff.entry, eff.db, proc_entry, allocator);
        sigs.callees = @intCast(@min(callees.len, std.math.maxInt(u32)));

        // Resolve callee names once for role hypothesis + dispatcher checks.
        var callees_resolved = std.array_list.Managed(?[]const u8).init(allocator);
        for (callees) |c| {
            const n: ?[]const u8 = if (eff.db.imports.get(c)) |imp| imp.name else eff.db.resolveName(c);
            callees_resolved.append(n) catch break;
        }

        // ---- Score this procedure ----
        var score: i32 = 0;
        var why_list = std.array_list.Managed(RemakeWhy).init(allocator);

        const is_seed = seed_set.contains(proc_entry);
        if (is_seed) {
            score += SCORE_SEED_EXACT;
            rfPushWhy(allocator, &why_list, "seed", "high", "explicit seed address");
        }

        const goal_bias_active = goal_active;

        if (proc_name) |n| {
            if (patterns.len > 0 and rfAnyPatternMatch(n, patterns)) {
                var s = SCORE_NAME_PATTERN;
                if (goal_bias_active) s = @divTrunc(s * SCORE_GOAL_BIAS_NUM, SCORE_GOAL_BIAS_DEN);
                score += s;
                const txt = std.fmt.allocPrint(allocator, "name matches pattern: {s}", .{n}) catch "pattern_match name";
                rfPushWhy(allocator, &why_list, "pattern_match", "high", txt);
            }
            if (goal_active) {
                for (goal_tokens.items) |tok| {
                    if (rfContains(n, tok)) {
                        score += SCORE_GOAL_KEYWORD;
                        const txt = std.fmt.allocPrint(allocator, "name matches goal keyword '{s}'", .{tok}) catch "goal keyword";
                        rfPushWhy(allocator, &why_list, "goal_keyword", "medium", txt);
                        break;
                    }
                }
            }
            // Name quality: not a thunk/stub, has letters.
            const looks_decent = n.len >= 4 and !std.mem.startsWith(u8, n, "sub_") and !std.mem.startsWith(u8, n, "loc_") and !rfIsLibraryWrapperName(n);
            if (looks_decent) score += SCORE_NAME_QUALITY;
            if (rfIsLibraryWrapperName(n)) score += PENALTY_LIBRARY_WRAPPER;
        }

        if (pattern_string_hit) |s| {
            var bump = SCORE_STRING_PATTERN;
            if (goal_bias_active) bump = @divTrunc(bump * SCORE_GOAL_BIAS_NUM, SCORE_GOAL_BIAS_DEN);
            score += bump;
            const slim = s[0..@min(s.len, 80)];
            const txt = std.fmt.allocPrint(allocator, "references string matching pattern: {s}", .{slim}) catch "pattern_match string";
            rfPushWhy(allocator, &why_list, "string_ref", "high", txt);
        }
        if (pattern_import_hit) |n| {
            var bump = SCORE_IMPORT_PATTERN;
            if (goal_bias_active) bump = @divTrunc(bump * SCORE_GOAL_BIAS_NUM, SCORE_GOAL_BIAS_DEN);
            score += bump;
            const txt = std.fmt.allocPrint(allocator, "calls import matching pattern: {s}", .{n}) catch "pattern_match import";
            rfPushWhy(allocator, &why_list, "import_call", "high", txt);
        }
        if (has_resource_string) {
            score += SCORE_RESOURCE_STRING;
            const rs: []const u8 = resource_string_hit orelse "";
            const sample = rs[0..@min(rs.len, 80)];
            const txt = std.fmt.allocPrint(allocator, "references resource/config string '{s}'", .{sample}) catch "resource string";
            rfPushWhy(allocator, &why_list, "string_ref", "medium", txt);
        }
        if (has_external_import) {
            score += SCORE_EXTERNAL_IMPORT;
            const txt = std.fmt.allocPrint(allocator, "calls external import {s}", .{external_import_hit orelse ""}) catch "external import";
            rfPushWhy(allocator, &why_list, "import_call", "high", txt);
        }
        if (sigs.callers >= HIGH_CONNECTIVITY_THRESHOLD or sigs.callees >= HIGH_CONNECTIVITY_THRESHOLD) {
            score += SCORE_HIGH_CONNECTIVITY;
            const txt = std.fmt.allocPrint(allocator, "high connectivity: {d} callers, {d} callees", .{ sigs.callers, sigs.callees }) catch "graph connectivity";
            rfPushWhy(allocator, &why_list, "graph", "medium", txt);
        }

        // Dispatch fan-out heuristic: ≥3 distinct callees with no shared 4-char prefix.
        if (callees.len >= DISPATCH_MIN_CALLEES) {
            var distinct = std.AutoHashMap(u64, void).init(allocator);
            defer distinct.deinit();
            for (callees) |c| distinct.put(c, {}) catch {};
            if (distinct.count() >= DISPATCH_MIN_CALLEES) {
                // Check for shared prefix in resolved names.
                var first_name: ?[]const u8 = null;
                var shared = true;
                for (callees_resolved.items) |maybe_name| {
                    const name = maybe_name orelse continue;
                    if (first_name == null) {
                        first_name = name;
                        continue;
                    }
                    const a = first_name.?;
                    const b = name;
                    const min_len = @min(@min(a.len, b.len), @as(usize, 4));
                    if (min_len < 4 or !std.mem.eql(u8, a[0..min_len], b[0..min_len])) {
                        shared = false;
                        break;
                    }
                }
                if (!shared) {
                    score += SCORE_DISPATCH_FANOUT;
                    rfPushWhy(allocator, &why_list, "graph", "medium", "dispatch fan-out (≥3 distinct callees, no shared prefix)");
                }
            }
        }

        // Wrapper/thunk filter.
        if (rfLooksLikeThunk(proc.size, callees.len, sigs.string_count)) {
            score += PENALTY_THUNK;
            rfPushWhy(allocator, &why_list, "graph", "low", "looks like single-callee thunk/stub");
        }
        // Tiny leaf penalty.
        if (proc.size > 0 and proc.size < TINY_LEAF_MAX_INSNS * 4 and callees.len == 0) {
            score += PENALTY_TINY_LEAF;
        }

        // Novelty vs visited evidence.
        if (visited.count() > 0 or visited_strings.count() > 0 or visited_imports.count() > 0) {
            var new_strings: u32 = 0;
            var new_imports: u32 = 0;
            for (strings_seen.items) |s| {
                if (visited_strings.get(s) == null) new_strings += 1;
            }
            for (imports_seen.items) |n| {
                if (visited_imports.get(n) == null) new_imports += 1;
            }
            if (new_strings >= 2 or new_imports >= 2) {
                score += SCORE_NOVELTY_NEW_EVIDENCE;
                rfPushWhy(allocator, &why_list, "novelty", "medium", "adds ≥2 new strings or imports vs visited set");
            }
            const total_strings = strings_seen.items.len;
            const total_imports = imports_seen.items.len;
            const subsumed = (total_strings + total_imports) > 0 and new_strings == 0 and new_imports == 0;
            if (subsumed) score += PENALTY_SUBSUMED;
        }

        // Visited penalty (last so it always applies).
        if (visited.contains(proc_entry)) {
            score += PENALTY_VISITED;
            rfPushWhy(allocator, &why_list, "novelty", "low", "address is in visited set");
        }

        // Drop candidates with no positive evidence at all (skip noise).
        // Seeds always survive even if score went negative.
        if (!is_seed and score <= 0 and why_list.items.len == 0) continue;

        // Role hypothesis.
        const is_entry_pt = (proc_entry == eff.entry.doc.entry_point);
        const role = rfRoleHypothesis(
            eff.db,
            proc_name,
            callees,
            callees_resolved.items,
            sigs.string_count,
            is_entry_pt,
        );

        candidates.append(.{
            .address = proc_entry,
            .score = score,
            .role_hypothesis = role,
            .why = why_list,
            .signals = sigs,
            .strings_seen = strings_seen,
            .imports_seen = imports_seen,
            .aliases = std.array_list.Managed(u64).init(allocator),
        }) catch break;
    }

    // Sort: descending score, ties ascending address.
    std.mem.sort(RemakeCandidate, candidates.items, {}, struct {
        fn lessThan(_: void, a: RemakeCandidate, b: RemakeCandidate) bool {
            if (a.score != b.score) return a.score > b.score;
            return a.address < b.address;
        }
    }.lessThan);

    // v7.13.0 B3 — adjacent-aliased candidate dedup.
    // Field test: `sandboxd` burned 5/24 frontier slots on procs within ±64
    // bytes sharing the same string-ref signal; libCommCenterAWDMetrics had
    // 24 consecutive `MergePartialFromCodedStream` candidates. We collapse
    // adjacent procs that share at least one string ref into the highest-
    // scoring representative, surfacing the absorbed addresses in `aliases[]`
    // so the LLM can still reach them if needed.
    //
    // Implementation: build an address-sorted view (separate from the score-
    // sorted list), walk pairs within ±64 bytes, and if their `strings_seen`
    // sets overlap, mark the lower-scored as absorbed.
    if (candidates.items.len > 1) {
        // Sort candidates by address into a parallel index for the merge pass.
        const AddrIdx = struct { addr: u64, src_idx: usize };
        var addr_idx_list = std.array_list.Managed(AddrIdx).init(allocator);
        addr_idx_list.ensureTotalCapacity(candidates.items.len) catch {};
        for (candidates.items, 0..) |c, i| {
            addr_idx_list.append(.{ .addr = c.address, .src_idx = i }) catch {};
        }
        std.mem.sort(AddrIdx, addr_idx_list.items, {}, struct {
            fn lt(_: void, a: AddrIdx, b: AddrIdx) bool {
                return a.addr < b.addr;
            }
        }.lt);

        // For each address-adjacent pair within ±64 bytes that shares a
        // string signal, mark the lower-scored as absorbed and record its
        // address on the higher-scored candidate's aliases list.
        var absorbed = std.AutoHashMap(usize, void).init(allocator);
        defer absorbed.deinit();

        {
            // Pairwise merging borrows candidate pointers while nested alias
            // lists grow. End the borrow before compacting the outer list.
            candidates.lockPointers();
            defer candidates.unlockPointers();
            var i: usize = 0;
            while (i + 1 < addr_idx_list.items.len) : (i += 1) {
                const a_view = addr_idx_list.items[i];
                if (absorbed.contains(a_view.src_idx)) continue;
                var j: usize = i + 1;
                while (j < addr_idx_list.items.len) : (j += 1) {
                    const b_view = addr_idx_list.items[j];
                    if (absorbed.contains(b_view.src_idx)) continue;
                    // Distance check: ±64 bytes.
                    const dist = if (b_view.addr > a_view.addr) b_view.addr - a_view.addr else a_view.addr - b_view.addr;
                    if (dist > 64) break;

                    // String-signal overlap: any shared string in strings_seen.
                    const a_c = &candidates.items[a_view.src_idx];
                    const b_c = &candidates.items[b_view.src_idx];
                    var overlap = false;
                    for (a_c.strings_seen.items) |sa| {
                        for (b_c.strings_seen.items) |sb| {
                            if (std.mem.eql(u8, sa, sb)) {
                                overlap = true;
                                break;
                            }
                        }
                        if (overlap) break;
                    }
                    if (!overlap) continue;

                    // Absorb the lower-scored. Preserve the higher-scored.
                    const winner_idx = if (a_c.score >= b_c.score) a_view.src_idx else b_view.src_idx;
                    const loser_idx = if (winner_idx == a_view.src_idx) b_view.src_idx else a_view.src_idx;
                    candidates.items[winner_idx].aliases.append(candidates.items[loser_idx].address) catch {};
                    absorbed.put(loser_idx, {}) catch {};
                }
            }
        }

        // Compact: drop absorbed entries.
        if (absorbed.count() > 0) {
            var write_i: usize = 0;
            for (candidates.items, 0..) |c, idx| {
                if (absorbed.contains(idx)) continue;
                candidates.items[write_i] = c;
                write_i += 1;
            }
            candidates.shrinkRetainingCapacity(write_i);
        }
    }

    // Optional one-hop graph expansion. We don't *add* expansion candidates
    // (they'd push real evidence hits out of the top N). Instead, depth is a
    // strategy hint surfaced in `meta` and used when emitting `next[]` calls
    // (scope=cluster vs single).

    const total_candidates = candidates.items.len;
    const returned = @min(total_candidates, max_candidates);

    // ---- Coverage gaps (heuristic, hard-capped at 5) ----
    var seen_role_boundary = false;
    var seen_role_parser = false;
    // v7.14.1 A3: removed seen_role_state — rfRoleHypothesis never returns
    // "state_holder" today, so the gap fired unconditionally and misled the
    // LLM. Restore once a real read/write classifier ships (v7.16+).
    var seen_role_resource = false;
    var seen_role_error = false;
    var seen_role_validator = false;
    var seen_role_codec = false;
    for (candidates.items[0..returned]) |c| {
        if (std.mem.eql(u8, c.role_hypothesis, "boundary")) seen_role_boundary = true;
        if (std.mem.eql(u8, c.role_hypothesis, "parser")) seen_role_parser = true;
        if (std.mem.eql(u8, c.role_hypothesis, "resource_adapter")) seen_role_resource = true;
        if (std.mem.eql(u8, c.role_hypothesis, "error_handler")) seen_role_error = true;
        if (std.mem.eql(u8, c.role_hypothesis, "validator")) seen_role_validator = true;
        if (std.mem.eql(u8, c.role_hypothesis, "codec_or_crypto")) seen_role_codec = true;
    }

    // ---- Build the JSON response ----
    var buf = std.Io.Writer.Allocating.init(allocator);
    const w = &buf.writer;

    w.print("{{\"snapshot_id\":{d}", .{eff.db.getSnapshotId()}) catch {};
    w.print(",\"doc_id\":{d}", .{doc_id}) catch {};
    w.writeAll(",\"doc_name\":") catch {};
    json.writeJsonString(w, std.fs.path.basename(eff.entry.doc.path)) catch {};
    w.writeAll(",\"goal\":") catch {};
    json.writeJsonString(w, goal) catch {};
    {
        const strat = std.fmt.allocPrint(
            allocator,
            "pattern+seed expansion (depth={d}, budget={d})",
            .{ depth, scan_budget },
        ) catch "pattern+seed expansion";
        w.writeAll(",\"strategy\":") catch {};
        json.writeJsonString(w, strat) catch {};
    }

    w.writeAll(",\"frontier\":[") catch {};
    for (candidates.items[0..returned], 0..) |c, i| {
        if (i > 0) w.writeByte(',') catch {};
        const out_addr = applyRebaseDelta(c.address, eff.delta);
        w.writeAll("{\"address\":") catch {};
        json.writeAddress(w, out_addr) catch {};
        // v7.12.1 W2: never emit a candidate without a name — fall back to
        // raw-mangled symbol bytes, then sub_<hex>. Pre-fix, many mangled
        // frontier candidates were nameless because resolveName requires a
        // demangled procedure or import, neither of which fires on raw mangled
        // symbols.
        if (eff.db.resolveName(c.address)) |name| {
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, name) catch {};
        } else if (eff.db.procedures.get(c.address)) |p| blk: {
            if (p.name) |name| {
                w.writeAll(",\"name\":") catch {};
                json.writeJsonString(w, name) catch {};
                break :blk;
            }
            if (eff.db.symbols.get(c.address)) |raw| {
                w.writeAll(",\"name\":") catch {};
                json.writeJsonString(w, raw) catch {};
            } else {
                var buf2: [40]u8 = undefined;
                const fallback = std.fmt.bufPrint(&buf2, "sub_{x}", .{out_addr}) catch "sub_unknown";
                w.writeAll(",\"name\":") catch {};
                json.writeJsonString(w, fallback) catch {};
            }
        } else if (eff.db.symbols.get(c.address)) |raw| {
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, raw) catch {};
        } else {
            var buf2: [40]u8 = undefined;
            const fallback = std.fmt.bufPrint(&buf2, "sub_{x}", .{out_addr}) catch "sub_unknown";
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, fallback) catch {};
        }
        w.print(",\"score\":{d}", .{c.score}) catch {};
        w.writeAll(",\"role_hypothesis\":") catch {};
        json.writeJsonString(w, c.role_hypothesis) catch {};
        w.writeAll(",\"why\":[") catch {};
        for (c.why.items, 0..) |why, wi| {
            if (wi > 0) w.writeByte(',') catch {};
            w.writeAll("{\"source\":") catch {};
            json.writeJsonString(w, why.source) catch {};
            w.writeAll(",\"confidence\":") catch {};
            json.writeJsonString(w, why.confidence) catch {};
            w.writeAll(",\"text\":") catch {};
            json.writeJsonString(w, why.text) catch {};
            w.writeByte('}') catch {};
        }
        w.print(
            "],\"signals\":{{\"string_count\":{d},\"import_count\":{d},\"callers\":{d},\"callees\":{d},\"external_interfaces\":{d},\"resources\":{d}}}",
            .{ c.signals.string_count, c.signals.import_count, c.signals.callers, c.signals.callees, c.signals.external_interfaces, c.signals.resources },
        ) catch {};

        // v7.13.0 B3 — aliases[] for adjacent-aliased dedup absorbed addresses.
        // Only emit when non-empty so unchanged binaries don't get noise.
        if (c.aliases.items.len > 0) {
            w.writeAll(",\"aliases\":[") catch {};
            for (c.aliases.items, 0..) |al, ai| {
                if (ai > 0) w.writeByte(',') catch {};
                json.writeAddress(w, applyRebaseDelta(al, eff.delta)) catch {};
            }
            w.writeAll("]") catch {};
        }

        // next[] — exact MCP calls the harness should fan out.
        const hex = std.fmt.allocPrint(allocator, "0x{x}", .{out_addr}) catch "0x0";
        w.writeAll(",\"next\":[") catch {};
        // get_semantic_slice view=remake, scope=cluster
        w.writeAll("{\"tool\":\"get_semantic_slice\",\"args\":{") catch {};
        w.print("\"doc_id\":{d},\"addresses\":\"{s}\",\"view\":\"remake\",\"scope\":\"cluster\"}}}}", .{ doc_id, hex }) catch {};
        // Inspect control flow before requesting speculative source rendering.
        if (eff.entry.doc.arch == .mips32) {
            w.writeAll(",{\"tool\":\"disassemble_range\",\"args\":{") catch {};
            w.print("\"doc_id\":{d},\"start\":\"{s}\",\"byte_length\":128}}}}", .{ doc_id, hex }) catch {};
        } else {
            w.writeAll(",{\"tool\":\"get_cfg\",\"args\":{") catch {};
            w.print("\"doc_id\":{d},\"function_address\":\"{s}\",\"include_disassembly\":true}}}}", .{ doc_id, hex }) catch {};
        }
        // suggest_names
        w.writeAll(",{\"tool\":\"suggest_names\",\"args\":{") catch {};
        w.print("\"doc_id\":{d},\"addresses\":\"{s}\"}}}}", .{ doc_id, hex }) catch {};
        w.writeAll("]") catch {};

        w.writeByte('}') catch {};
    }
    w.writeAll("]") catch {};

    // ---- parallel_batches[] — chunk frontier into <=max_batch get_semantic_slice calls ----
    w.writeAll(",\"parallel_batches\":[") catch {};
    {
        var batch_id: u32 = 1;
        var i: usize = 0;
        var first_batch = true;
        while (i < returned) {
            const batch_end = @min(i + max_batch, returned);
            if (!first_batch) w.writeByte(',') catch {};
            first_batch = false;
            w.print("{{\"batch_id\":{d}", .{batch_id}) catch {};
            w.writeAll(",\"rationale\":") catch {};
            const rationale = if (batch_id == 1)
                "high-confidence remake-spec material"
            else
                "next wave: lower-score candidates / deeper expansion";
            json.writeJsonString(w, rationale) catch {};
            w.writeAll(",\"calls\":[") catch {};
            var first_call = true;
            for (candidates.items[i..batch_end]) |c| {
                const out_addr = applyRebaseDelta(c.address, eff.delta);
                const hex = std.fmt.allocPrint(allocator, "0x{x}", .{out_addr}) catch "0x0";
                if (!first_call) w.writeByte(',') catch {};
                first_call = false;
                w.writeAll("{\"tool\":\"get_semantic_slice\",\"args\":{") catch {};
                w.print("\"doc_id\":{d},\"addresses\":\"{s}\",\"view\":\"remake\",\"scope\":\"cluster\"}}}}", .{ doc_id, hex }) catch {};
            }
            w.writeAll("]}") catch {};
            i = batch_end;
            batch_id += 1;
        }
    }
    w.writeAll("]") catch {};

    // ---- coverage_gaps[] ----
    // v7.12.1 W4: dylibs HAVE no main/CLI parser by definition. Suppress the
    // boundary/parser/state-holder/etc. gaps for them and emit one explicit
    // dylib-shaped gap pointing the LLM at get_exports for the public API.
    const is_dylib = eff.entry.doc.format == .macho and eff.entry.doc.macho_filetype == 6;
    w.writeAll(",\"coverage_gaps\":[") catch {};
    if (is_dylib) {
        w.writeAll("{\"kind\":\"dylib\",\"description\":\"this is a dylib — no main entry; call get_exports for the public API surface\"}") catch {};
    } else {
        var emitted: usize = 0;
        var first = true;
        if (!seen_role_boundary and emitted < COVERAGE_GAPS_MAX) {
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"kind\":\"boundary\",\"description\":\"no clear program entry/cli-parse function found yet — try patterns 'main|argv|getopt'\"}") catch {};
            emitted += 1;
        }
        if (!seen_role_parser and emitted < COVERAGE_GAPS_MAX) {
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"kind\":\"parser\",\"description\":\"no parser/tokenizer detected — try patterns 'parse|tokenize|json|xml|regex'\"}") catch {};
            emitted += 1;
        }
        // v7.14.1 A3: removed unreachable state_holder gap. rfRoleHypothesis
        // never returns "state_holder", so the prior gate was always false
        // and the gap fired unconditionally. Restore once v7.16+ adds real
        // read/write classification across globals.
        if (!seen_role_resource and emitted < COVERAGE_GAPS_MAX) {
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"kind\":\"resource\",\"description\":\"no embedded asset/config strings or resource-adapter calls — try get_embedded_resources\"}") catch {};
            emitted += 1;
        }
        if (!seen_role_error and emitted < COVERAGE_GAPS_MAX) {
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"kind\":\"error_handler\",\"description\":\"no error/abort/panic paths surfaced — try patterns 'err|panic|abort|fatal'\"}") catch {};
            emitted += 1;
        }
        if (emitted == 0 and (!seen_role_validator or !seen_role_codec)) {
            // Fall through — nothing else to add. Suppress empty array fill.
        }
    }
    w.writeAll("]") catch {};

    // ---- meta ----
    const elapsed = timestampMs(ctx.io) - start;
    const truncated = total_candidates > returned;
    // v7.13.0 B7: surface time_aborted so handleGetBinaryContext (and the LLM)
    // can see when the 3-sec deadline tripped — that's a strong signal that
    // manifest mode would have been a better choice.
    w.print(
        ",\"meta\":{{\"scanned_procedures\":{d},\"elapsed_ms\":{d},\"truncated\":{s},\"time_aborted\":{s}}}}}",
        .{ scanned, elapsed, if (truncated) "true" else "false", if (time_aborted) "true" else "false" },
    ) catch {};

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const resp = json.successResponse(allocator, "get_remake_frontier", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .meta_max_chars = 200_000 };
}

/// Check if a string contains any of the given substrings (case-insensitive).
fn containsAnyCI(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (needle.len > haystack.len) continue;
        var i: usize = 0;
        while (i + needle.len <= haystack.len) : (i += 1) {
            var match = true;
            for (needle, 0..) |nc, ni| {
                const hc = haystack[i + ni];
                const nlc = if (nc >= 'A' and nc <= 'Z') nc + 32 else nc;
                const hlc = if (hc >= 'A' and hc <= 'Z') hc + 32 else hc;
                if (nlc != hlc) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

/// v7.14.0 B3 helpers — case-insensitive substring search and identifier
/// character predicate, used by the suggest_names heuristic name rules.
fn containsCI(haystack: []const u8, needle: []const u8) bool {
    return indexOfCI(haystack, needle) != null;
}

fn indexOfCI(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or needle.len > haystack.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, ni| {
            const hc = haystack[i + ni];
            const nlc = if (nc >= 'A' and nc <= 'Z') nc + 32 else nc;
            const hlc = if (hc >= 'A' and hc <= 'Z') hc + 32 else hc;
            if (nlc != hlc) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return null;
}

fn isIdentChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or c == '_';
}

/// Helper: write a JSON array of strings with a key name.
fn writeStringArray(w: anytype, key: []const u8, items: []const []const u8) void {
    w.writeByte('"') catch {};
    w.writeAll(key) catch {};
    w.writeAll("\":[") catch {};
    for (items, 0..) |item, i| {
        if (i > 0) w.writeByte(',') catch {};
        json.writeJsonString(w, item) catch {};
    }
    w.writeByte(']') catch {};
}

// ============================================================================
// CFG Decode Adapter — bridges arm64 decoder to cfg.zig's DecodeFn interface
// ============================================================================

/// Parse the immediate value from an ADD instruction's operand string.
/// Expected format: "Xd, Xn, #0xOFF" or "Xd, Xn, #DEC"
fn parseStringXrefImmediate(operands: []const u8) ?u64 {
    const hash_idx = std.mem.indexOf(u8, operands, "#") orelse return null;
    const after_hash = operands[hash_idx + 1 ..];

    if (after_hash.len >= 2 and after_hash[0] == '0' and after_hash[1] == 'x') {
        var end: usize = 2;
        while (end < after_hash.len and isHexDigitChar(after_hash[end])) : (end += 1) {}
        return std.fmt.parseInt(u64, after_hash[2..end], 16) catch null;
    } else {
        var end: usize = 0;
        while (end < after_hash.len and after_hash[end] >= '0' and after_hash[end] <= '9') : (end += 1) {}
        if (end == 0) return null;
        return std.fmt.parseInt(u64, after_hash[0..end], 10) catch null;
    }
}

fn isHexDigitChar(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn arm64CfgDecode(data: []const u8, address: u64) cfg_mod.DecodedInstruction {
    const decoded = arm64.decode(data, address);
    return cfg_mod.fromArm64Decoded(decoded, address);
}

fn arm32CfgDecode(data: []const u8, address: u64) cfg_mod.DecodedInstruction {
    const decoded = arm32.decode(data, address);
    return .{
        .address = address,
        .size = decoded.length,
        .mnemonic = decoded.mnemonic,
        .is_branch = decoded.is_branch,
        .is_conditional_branch = decoded.is_conditional_branch,
        .is_call = decoded.is_call,
        .is_return = decoded.is_return,
        .branch_target = decoded.branch_target,
    };
}

fn mips32CfgDecode(data: []const u8, address: u64) cfg_mod.DecodedInstruction {
    const decoded = mips32.decode(data, address);
    return .{
        .address = address,
        .size = decoded.length,
        .mnemonic = decoded.mnemonic,
        .is_branch = decoded.is_branch,
        .is_conditional_branch = decoded.is_conditional_branch,
        .is_call = decoded.is_call,
        .is_return = decoded.is_return,
        .branch_target = decoded.branch_target,
    };
}

/// Check if a mnemonic represents a return instruction.
/// For arm64: ret, retab, retaa. For arm32: bx (with lr), pop (with pc). For mips32: jr.
fn isReturnMnemonic(mn: []const u8, is_arm32_arch: bool) bool {
    if (is_arm32_arch) {
        // arm32 Thumb return patterns: "pop" (containing pc), "bx" (lr)
        return std.mem.eql(u8, mn, "pop") or std.mem.eql(u8, mn, "bx");
    }
    return std.mem.eql(u8, mn, "ret") or std.mem.eql(u8, mn, "RET") or
        std.mem.eql(u8, mn, "retab") or std.mem.eql(u8, mn, "RETAB") or
        std.mem.eql(u8, mn, "retaa") or std.mem.eql(u8, mn, "RETAA") or
        std.mem.eql(u8, mn, "jr") or std.mem.eql(u8, mn, "JR");
}

// ============================================================================
// v7.12 W4 — get_binary_context: adaptive document-level planner
// ============================================================================
//
// One MCP call after load_binary that picks the right enumeration strategy
// for the binary in front of you:
//   - tiny (<128 KiB, <=50 procs): mode=full enumerates everything (header,
//     segments, complete strings as contiguous blocks, complete imports
//     w/ xref counts, complete exports, full disasm of __text up to 32 KiB).
//   - medium: mode=frontier delegates to handleGetRemakeFrontier.
//   - huge / opaque (>100 MiB or >100k procs or doc.note set): mode=manifest
//     emits a lightweight summary — segment map, import/export/capability
//     counts, embedded resources — and suggests seeds for follow-up.
//
// Hard cap at max_chars (default 60 KiB, max 200 KiB). On overflow the
// response is truncated and `truncated:true` is set with a "switch to manifest"
// note in the payload.

const BinCtxMode = enum { full, frontier, manifest };

fn pickBinaryContextMode(doc: *const types.Document) BinCtxMode {
    if (doc.note != null) return .manifest;
    if (doc.data.len > 100 * 1024 * 1024) return .manifest;
    // v7.13.0 B7 — lower the proc-count threshold from 100K → 30K so dense
    // dynamic libraries auto-route to manifest. The frontier scan otherwise
    // burns seconds per call even though the LLM only needs a manifest summary first.
    if (doc.procedures.items.len > 30_000) return .manifest;
    // v7.12 W4: tuned to /usr/bin/caffeinate (~136 KB FAT, ~57 procs after
    // arm64 slice). The plan's stricter <=128 KiB / <=50 procs missed
    // caffeinate by a few KB / a few procs; bumped to 200 KiB / 200 procs
    // so the headline smoke test ("full enumeration of caffeinate in one
    // call") routes to .full deterministically.
    if (doc.data.len <= 200 * 1024 and doc.procedures.items.len <= 200) return .full;
    return .frontier;
}

/// v7.12.1 W1: imports that show up in nearly every Mach-O binary; suppress
/// them from the "top imports" list because they don't tell the LLM anything
/// about what the binary IS. Substring match (case-sensitive) handles the
/// `_os_log_*` family.
fn rfIsUbiquitousImport(name: []const u8) bool {
    const exact = [_][]const u8{
        "_objc_msgSendSuper2",     "_malloc",                             "_free",
        "___SC_log_send",          "_dispatch_async",                     "_dispatch_after",
        "_dispatch_main",          "_dispatch_release",                   "_dispatch_resume",
        "_dispatch_source_create", "_dispatch_source_set_cancel_handler", "_dispatch_source_set_event_handler",
        "_dispatch_time",          "___stack_chk_fail",                   "___stack_chk_guard",
    };
    for (exact) |e| if (std.mem.eql(u8, name, e)) return true;
    if (std.mem.startsWith(u8, name, "_os_log_")) return true;
    return false;
}

/// True if the string is mostly punctuation / whitespace / control bytes.
/// Used to drop "------" / ":" / "()" noise from the top-strings list.
fn rfIsPurePunctuation(s: []const u8) bool {
    var alnum: usize = 0;
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c)) alnum += 1;
    }
    return alnum == 0;
}

const SubsystemHintSpec = struct {
    name: []const u8,
    reason: []const u8,
    pattern: []const u8,
    keywords: []const []const u8,
};

const SubsystemEvidence = struct {
    kind: []const u8,
    text: []const u8,
    address: ?u64 = null,
};

fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn matchesSubsystemKeywords(value: []const u8, keywords: []const []const u8) bool {
    for (keywords) |keyword| {
        if (containsAsciiIgnoreCase(value, keyword)) return true;
    }
    return false;
}

fn appendSubsystemEvidence(
    evidence: *std.array_list.Managed(SubsystemEvidence),
    kind: []const u8,
    text: []const u8,
    address: ?u64,
) !void {
    if (evidence.items.len >= 4) return;
    for (evidence.items) |item| {
        if (std.mem.eql(u8, item.kind, kind) and std.mem.eql(u8, item.text, text)) return;
    }
    try evidence.append(.{
        .kind = kind,
        .text = if (text.len > 120) text[0..120] else text,
        .address = address,
    });
}

fn collectSubsystemEvidence(
    allocator: Allocator,
    doc: *const types.Document,
    db: *Database,
    spec: SubsystemHintSpec,
) !std.array_list.Managed(SubsystemEvidence) {
    var evidence = std.array_list.Managed(SubsystemEvidence).init(allocator);
    errdefer evidence.deinit();

    for (doc.strings.items) |s| {
        if (evidence.items.len >= 4) return evidence;
        if (matchesSubsystemKeywords(s.value, spec.keywords)) {
            try appendSubsystemEvidence(&evidence, "string", s.value, s.address);
        }
    }
    for (doc.imports.items) |imp| {
        if (evidence.items.len >= 4) return evidence;
        if (matchesSubsystemKeywords(imp.name, spec.keywords)) {
            try appendSubsystemEvidence(&evidence, "import", imp.name, imp.address);
        }
    }

    var sym_it = db.symbols.iterator();
    while (sym_it.next()) |entry| {
        if (evidence.items.len >= 4) return evidence;
        if (matchesSubsystemKeywords(entry.value_ptr.*, spec.keywords)) {
            try appendSubsystemEvidence(&evidence, "symbol", entry.value_ptr.*, entry.key_ptr.*);
        }
    }
    var proc_it = db.procedures.iterator();
    while (proc_it.next()) |entry| {
        if (evidence.items.len >= 4) return evidence;
        const name = entry.value_ptr.name orelse continue;
        if (matchesSubsystemKeywords(name, spec.keywords)) {
            try appendSubsystemEvidence(&evidence, "procedure", name, entry.key_ptr.*);
        }
    }

    return evidence;
}

fn emitSubsystemHints(
    w: anytype,
    allocator: Allocator,
    doc: *const types.Document,
    db: *Database,
    delta: i128,
) !void {
    // Generic initialize/protocolVersion strings also occur in TLS, crypto and runtimes.
    // Require actual RPC/MCP markers before surfacing this hypothesis.
    const protocol_keywords = [_][]const u8{ "jsonrpc", "tools/list", "tools/call", "prompts/list", "resources/list", "McpServer" };
    const persistence_keywords = [_][]const u8{ "save_project", "load_project", ".phora", "phora_version", "close_document", "list_documents" };
    const concurrency_keywords = [_][]const u8{ "session", "thread", "mutex", "rw_lock", "lockShared", "ThreadPool", "notifications" };
    const loader_keywords = [_][]const u8{ "Mach-O", "ELF", "PE", "APK", "ZIP", "PBP", "PSX-EXE", "dyld", "raw" };
    const runtime_keywords = [_][]const u8{ "__BUN", "v8_context_snapshot", ".asar", "j2objc", "upb", "python3.", "gguf", "ggml" };
    const analysis_keywords = [_][]const u8{ "disassemble_range", "get_semantic_slice", "get_remake_frontier", "annotate", "suggest_names", "get_binary_context" };

    const specs = [_]SubsystemHintSpec{
        .{ .name = "mcp_protocol", .reason = "RPC/MCP-specific markers suggest protocol handling; verify methods before identifying the protocol.", .pattern = "jsonrpc|tools/list|tools/call|McpServer", .keywords = protocol_keywords[0..] },
        .{ .name = "persistence", .reason = "Project/document lifecycle clues suggest save/load or close/list behavior.", .pattern = "save_project|load_project|.phora|close_document|list_documents", .keywords = persistence_keywords[0..] },
        .{ .name = "concurrency", .reason = "Session, notification, thread, or lock clues suggest concurrent server behavior.", .pattern = "session|thread|mutex|rw_lock|ThreadPool|notifications", .keywords = concurrency_keywords[0..] },
        .{ .name = "loaders", .reason = "Format names suggest loader and container support worth mapping early.", .pattern = "Mach-O|ELF|PE|APK|ZIP|PBP|PSX-EXE|dyld|raw", .keywords = loader_keywords[0..] },
        .{ .name = "embedded_runtimes", .reason = "Runtime markers suggest packed resources or secondary analysis targets.", .pattern = "__BUN|v8_context_snapshot|.asar|j2objc|upb|python3.|gguf|ggml", .keywords = runtime_keywords[0..] },
        .{ .name = "analysis_surface", .reason = "Analysis-tool strings or symbols suggest primary user-facing reverse-engineering workflows.", .pattern = "disassemble_range|get_semantic_slice|get_remake_frontier|annotate|suggest_names|get_binary_context", .keywords = analysis_keywords[0..] },
    };

    try w.writeAll(",\"subsystem_hints\":[");
    var first_hint = true;
    for (specs) |spec| {
        var evidence = try collectSubsystemEvidence(allocator, doc, db, spec);
        defer evidence.deinit();
        if (evidence.items.len == 0) continue;

        if (!first_hint) try w.writeByte(',');
        first_hint = false;
        try w.writeAll("{\"name\":");
        try json.writeJsonString(w, spec.name);
        try w.writeAll(",\"reason\":");
        try json.writeJsonString(w, spec.reason);
        try w.writeAll(",\"evidence\":[");
        for (evidence.items, 0..) |item, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"kind\":");
            try json.writeJsonString(w, item.kind);
            try w.writeAll(",\"text\":");
            try json.writeJsonString(w, item.text);
            if (item.address) |address| {
                try w.writeAll(",\"address\":");
                try json.writeAddress(w, applyRebaseDelta(address, delta));
            }
            try w.writeByte('}');
        }
        try w.writeAll("],\"suggested_next_call\":{\"tool\":\"search\",\"args\":{\"pattern\":");
        try json.writeJsonString(w, spec.pattern);
        try w.writeAll(",\"max_results\":20}}}");
    }
    try w.writeAll("]");
}

/// v7.12.1 W1: doc-level context summary prepended to mode=frontier responses
/// so a single get_binary_context call still tells the LLM what the binary
/// IS (top strings, top imports, segment map). Caps each list at 20 entries
/// to bound prefix size <8 KiB even on /bin/bash-class binaries.
fn emitFrontierEnvelopePrefix(
    w: anytype,
    doc: *const types.Document,
    db: *Database,
    delta: i128,
) !void {
    // doc_summary block.
    try w.writeAll(",\"doc_summary\":{");
    try w.writeAll("\"format\":");
    try json.writeJsonString(w, doc.format.toString());
    try w.writeAll(",\"arch\":");
    try json.writeJsonString(w, doc.arch.toString());
    try w.print(",\"file_size\":{d}", .{doc.data.len});
    try w.writeAll(",\"entry_point\":");
    try json.writeAddress(w, applyRebaseDelta(doc.entry_point, delta));
    try w.print(",\"procedure_count\":{d},\"string_count\":{d},\"import_count\":{d}", .{
        doc.procedures.items.len,
        doc.strings.items.len,
        doc.imports.items.len,
    });
    if (doc.note) |n| {
        try w.writeAll(",\"note\":");
        try json.writeJsonString(w, n);
    }
    try w.writeByte('}');

    // Top 20 strings sorted by xref count (deduped against runtime/error noise).
    const StrEntry = struct {
        addr: u64,
        value: []const u8,
        length: u32,
        refs: usize,
    };

    const alloc = db.allocator;

    var str_list = std.array_list.Managed(StrEntry).init(alloc);
    defer str_list.deinit();
    for (doc.strings.items) |s| {
        if (s.length < 4) continue;
        if (rfIsPurePunctuation(s.value)) continue;
        const refs = db.xrefs.getRefsTo(s.address);
        if (refs.len == 0) {
            // Also try the page-aligned address (ARM64 adrp+add lands at page).
            const page_addr = s.address & ~@as(u64, 0xFFF);
            if (page_addr != s.address) {
                const page_refs = db.xrefs.getRefsTo(page_addr);
                if (page_refs.len == 0) continue;
                str_list.append(.{
                    .addr = s.address,
                    .value = s.value,
                    .length = s.length,
                    .refs = page_refs.len,
                }) catch continue;
                continue;
            }
            continue;
        }
        str_list.append(.{
            .addr = s.address,
            .value = s.value,
            .length = s.length,
            .refs = refs.len,
        }) catch continue;
    }

    const StrSort = struct {
        fn lt(_: void, a: StrEntry, b: StrEntry) bool {
            if (a.refs != b.refs) return a.refs > b.refs;
            return a.addr < b.addr;
        }
    };
    std.mem.sort(StrEntry, str_list.items, {}, StrSort.lt);

    try w.writeAll(",\"top_strings\":[");
    {
        var emitted: usize = 0;
        for (str_list.items) |se| {
            if (emitted >= 20) break;
            if (emitted > 0) try w.writeByte(',');
            try w.writeAll("{\"address\":");
            try json.writeAddress(w, applyRebaseDelta(se.addr, delta));
            try w.writeAll(",\"text\":");
            try json.writeJsonString(w, se.value);
            try w.print(",\"xref_count\":{d}", .{se.refs});
            try w.writeByte('}');
            emitted += 1;
        }
    }
    try w.writeAll("]");

    // Top 20 imports sorted by xref count (deduped against the ubiquitous set).
    const ImpEntry = struct {
        name: []const u8,
        library: ?[]const u8,
        refs: usize,
    };

    var imp_list = std.array_list.Managed(ImpEntry).init(alloc);
    defer imp_list.deinit();
    for (doc.imports.items) |imp| {
        if (rfIsUbiquitousImport(imp.name)) continue;
        const stub_addr: u64 = imp.stub_address orelse 0;
        const refs = countImportXrefs(db, imp.name, stub_addr);
        if (refs == 0) continue;
        imp_list.append(.{
            .name = imp.name,
            .library = imp.library,
            .refs = refs,
        }) catch continue;
    }
    const ImpSort = struct {
        fn lt(_: void, a: ImpEntry, b: ImpEntry) bool {
            if (a.refs != b.refs) return a.refs > b.refs;
            return std.mem.lessThan(u8, a.name, b.name);
        }
    };
    std.mem.sort(ImpEntry, imp_list.items, {}, ImpSort.lt);

    try w.writeAll(",\"top_imports\":[");
    {
        var emitted: usize = 0;
        for (imp_list.items) |ie| {
            if (emitted >= 20) break;
            if (emitted > 0) try w.writeByte(',');
            try w.writeAll("{\"name\":");
            try json.writeJsonString(w, ie.name);
            if (ie.library) |lib| {
                try w.writeAll(",\"library\":");
                try json.writeJsonString(w, lib);
            }
            try w.print(",\"xref_count\":{d}", .{ie.refs});
            try w.writeByte('}');
            emitted += 1;
        }
    }
    try w.writeAll("]");

    try emitSubsystemHints(w, alloc, doc, db, delta);

    // segments[]: name + start + length + permissions + entropy.
    try w.writeAll(",\"segments\":[");
    for (doc.segments, 0..) |seg, si| {
        if (si > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":");
        try json.writeJsonString(w, seg.name);
        try w.writeAll(",\"start\":");
        try json.writeAddress(w, applyRebaseDelta(seg.start, delta));
        try w.print(",\"length\":{d}", .{seg.length});
        try w.print(",\"permissions\":{{\"read\":{s},\"write\":{s},\"execute\":{s}}}", .{
            if (seg.permissions.read) "true" else "false",
            if (seg.permissions.write) "true" else "false",
            if (seg.permissions.execute) "true" else "false",
        });
        if (seg.length > 0 and seg.file_offset + seg.length <= doc.data.len) {
            const seg_data = doc.data[seg.file_offset .. seg.file_offset + seg.length];
            const ent = computeSectionEntropy(seg_data);
            try w.print(",\"entropy\":{d:.2}", .{ent});
        }
        try w.writeByte('}');
    }
    try w.writeAll("]");
}

/// Extract the raw `result` field from a `successResponse`-wrapped envelope.
/// Returns a slice into the input buffer (no allocation). Used by
/// handleGetBinaryContext mode=frontier to splice the inner frontier payload
/// into the composite envelope without nesting one wrapper inside another.
/// Format: {"success":true,"results":[{"input":"<n>","success":true,"result":<JSON>,"error":null,"metadata":{...}}],"summary":{...}}
fn extractInnerResult(wrapped: []const u8) ?[]const u8 {
    const marker = "\"result\":";
    const start = std.mem.indexOf(u8, wrapped, marker) orelse return null;
    const value_start = start + marker.len;
    if (value_start >= wrapped.len) return null;

    var depth: i32 = 0;
    var in_string = false;
    var prev_escape = false;
    var i: usize = value_start;
    while (i < wrapped.len) : (i += 1) {
        const c = wrapped[i];
        if (in_string) {
            if (prev_escape) {
                prev_escape = false;
            } else if (c == '\\') {
                prev_escape = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            '{', '[' => depth += 1,
            '}', ']' => {
                depth -= 1;
                if (depth == 0) {
                    return wrapped[value_start .. i + 1];
                }
            },
            ',' => {
                if (depth == 0) return wrapped[value_start..i];
            },
            else => {},
        }
    }
    return null;
}

fn handleGetBinaryContext(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start_ts = timestampMs(ctx.io);

    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_binary_context", params);
    };
    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_binary_context");
    const eff = resolveEffectiveDb(entry);

    // v7.12 W4: default max_chars sized so caffeinate (the headline binary)
    // returns full disasm in one call without tripping truncation.
    const max_chars_raw: i64 = getInt(params, "max_chars") orelse 80_000;
    const max_chars: usize = @intCast(@min(@max(max_chars_raw, 1000), 200_000));
    const include_bytes = getBool(params, "include_bytes") orelse false;

    const requested_mode_str = getString(params, "mode") orelse "auto";
    const chosen: BinCtxMode = blk: {
        if (std.ascii.eqlIgnoreCase(requested_mode_str, "full")) break :blk .full;
        if (std.ascii.eqlIgnoreCase(requested_mode_str, "frontier")) break :blk .frontier;
        if (std.ascii.eqlIgnoreCase(requested_mode_str, "manifest")) break :blk .manifest;
        // auto
        break :blk pickBinaryContextMode(&entry.doc);
    };

    // Mode=frontier: delegate straight through. Same params; the handler
    // already accepts seeds/patterns/visited/max_candidates/max_batch.
    //
    // v7.12.1 W1: PREPEND a doc-level envelope so frontier-routed binaries
    // are identifiable in a single call. Pre-fix, the entire response was
    // just the inner frontier JSON — for /bin/ls (102 strings, 90 imports)
    // the LLM saw zero strings, zero imports, zero segments. Field-test
    // result: 4/4 frontier-routed binaries failed single-call sufficiency.
    if (chosen == .frontier) {
        // v7.14.1 A1: unify the response envelope across all three modes.
        // Prior to this fix, mode=frontier returned the raw inner shape with
        // a `frontier:{success,results,summary}` field — i.e. a successResponse
        // envelope nested inside another field. mode=full and mode=manifest
        // were already wrapped in the standard `successResponse` envelope.
        // Now: extract just the inner `result` payload of get_remake_frontier
        // (drop its outer success/results/summary wrapping), build the
        // composite { strategy, doc_summary..., frontier:<inner_result> }, and
        // wrap that composite via json.successResponse like the other modes.
        const inner = handleGetRemakeFrontier(ctx, params) catch |err| return err;
        const inner_result = extractInnerResult(inner.json_response) orelse {
            // Fallback: pass through unchanged so we never silently drop the
            // frontier output when the wrapper format drifts.
            var passthrough = inner;
            passthrough.meta_max_chars = @max(passthrough.meta_max_chars orelse 0, max_chars);
            return passthrough;
        };

        var composite = std.Io.Writer.Allocating.init(ctx.allocator);
        const composite_w = &composite.writer;
        composite_w.writeAll("{\"strategy\":\"frontier (delegated)\"") catch return ToolError.OutOfMemory;
        // v7.15.0 B3: prefix emission reads doc.imports/strings + db.xrefs;
        // hold the shared DB lock so concurrent annotate/rebase writers
        // can't mid-mutate the maps while we walk them. handleGetRemakeFrontier
        // (called above) takes/releases its own shared lock; we acquire ours
        // here AFTER it returned to avoid relying on recursive shared locking
        // semantics across pthread/Default RwLock impls.
        eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
        emitFrontierEnvelopePrefix(composite_w, &entry.doc, eff.db, eff.delta) catch {
            eff.db.rw_lock.unlockShared(eff.db.io);
            return ToolError.OutOfMemory;
        };
        eff.db.rw_lock.unlockShared(eff.db.io);
        composite_w.writeAll(",\"frontier\":") catch return ToolError.OutOfMemory;
        composite_w.writeAll(inner_result) catch return ToolError.OutOfMemory;
        composite_w.writeAll("}") catch return ToolError.OutOfMemory;

        const composite_json = composite.toOwnedSlice() catch return ToolError.OutOfMemory;
        const elapsed_fr = timestampMs(ctx.io) - start_ts;
        const wrapped = json.successResponse(ctx.allocator, "get_binary_context", composite_json, elapsed_fr) catch return ToolError.OutOfMemory;
        return .{ .json_response = wrapped, .meta_max_chars = @max(max_chars + 1024, 200_000) };
    }

    // Tiny single-procedure contexts expose graph provenance on the first call.
    // Delegate before taking this handler's shared lock; get_cfg owns its lock.
    var automatic_cfg: ?[]const u8 = null;
    defer if (automatic_cfg) |payload| ctx.allocator.free(payload);
    var automatic_cfg_address: ?u64 = null;
    var automatic_cfg_bytes: u64 = 0;
    const automatic_execution = eff.entry.doc.arch == .arm64 and eff.delta == 0;
    var executable_bytes: u64 = 0;
    for (entry.doc.segments) |seg| {
        if (!seg.permissions.execute) continue;
        if (seg.sections.len == 0) {
            executable_bytes +|= seg.length;
        } else {
            for (seg.sections) |sec| {
                if (sec.isCode()) executable_bytes +|= sec.length;
            }
        }
    }
    if (chosen == .full and entry.doc.procedures.items.len == 1 and executable_bytes <= 512) {
        const p = entry.doc.procedures.items[0];
        if (p.size > 0 and p.size <= 512) {
            const addr = applyRebaseDelta(p.entry, eff.delta);
            automatic_cfg_address = addr;
            const args = if (automatic_execution)
                try json.stringify(ctx.allocator, .{ .doc_id = doc_id, .function_address = addr, .instruction_view = "execution", .max_blocks = 128 })
            else
                try json.stringify(ctx.allocator, .{ .doc_id = doc_id, .function_address = addr, .include_disassembly = true, .max_blocks = 128 });
            defer ctx.allocator.free(args);
            const parsed_args = std.json.parseFromSlice(std.json.Value, ctx.allocator, args, .{}) catch return ToolError.OutOfMemory;
            defer parsed_args.deinit();
            const result = try handleGetCfg(ctx, parsed_args.value);
            defer ctx.allocator.free(result.json_response);
            if (!result.is_error) {
                const parsed_result = std.json.parseFromSlice(std.json.Value, ctx.allocator, result.json_response, .{}) catch return ToolError.OutOfMemory;
                defer parsed_result.deinit();
                const payload = parsed_result.value.object.get("results").?.array.items[0].object.get("result").?;
                for (payload.object.get("basic_blocks").?.array.items) |block| {
                    automatic_cfg_bytes +|= @intCast(block.object.get("size").?.integer);
                }
                automatic_cfg = try json.stringify(ctx.allocator, payload);
            }
        }
    }

    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    var rb = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &rb.writer;

    // Common header (both full and manifest emit it).
    w.writeAll("{\"strategy\":") catch {};
    json.writeJsonString(w, switch (chosen) {
        .full => "full",
        .manifest => "manifest",
        .frontier => "frontier",
    }) catch {};
    w.writeAll(",\"doc_id\":") catch {};
    w.print("{d}", .{doc_id}) catch {};
    w.writeAll(",\"name\":") catch {};
    json.writeJsonString(w, std.fs.path.basename(entry.doc.path)) catch {};
    w.writeAll(",\"format\":") catch {};
    json.writeJsonString(w, entry.doc.format.toString()) catch {};
    w.writeAll(",\"arch\":") catch {};
    json.writeJsonString(w, entry.doc.arch.toString()) catch {};
    w.print(",\"file_size\":{d},\"entry_point\":", .{entry.doc.data.len}) catch {};
    json.writeAddress(w, applyRebaseDelta(entry.doc.entry_point, eff.delta)) catch {};
    w.print(",\"procedure_count\":{d},\"string_count\":{d},\"import_count\":{d}", .{
        entry.doc.procedures.items.len,
        entry.doc.strings.items.len,
        entry.doc.imports.items.len,
    }) catch {};
    if (automatic_cfg_address) |addr| {
        if (automatic_cfg != null and rb.written().len + automatic_cfg.?.len + reconstruction_workflow.len + execution_rows_note.len + 1024 < max_chars) {
            try w.writeAll(",\"control_flow_evidence\":{\"status\":\"included\",\"selection\":\"single_procedure_and_executable_bytes_at_most_512\",\"semantic_completeness\":\"unknown\",\"function_address\":");
            try json.writeAddress(w, addr);
            try w.writeAll(",\"instruction_view\":");
            try json.writeJsonString(w, if (automatic_execution) "execution" else "disassembly");
            try w.writeByte(',');
            try writeReconstructionGuide(w, if (automatic_execution) "cfg.basic_blocks[].execution.text" else "cfg.basic_blocks[].instructions", automatic_execution);
            try w.writeAll(",\"cfg\":");
            try w.writeAll(automatic_cfg.?);
            try w.writeByte('}');
        } else {
            try w.writeAll(",\"control_flow_evidence\":{\"status\":\"deferred\",\"reason\":\"context_budget_or_CFG_unavailable\",\"next_call\":{\"tool\":\"get_cfg\",\"arguments\":{");
            try w.print("\"doc_id\":{d},\"function_address\":", .{doc_id});
            try json.writeAddress(w, addr);
            if (automatic_execution) try w.writeAll(",\"instruction_view\":\"execution\"");
            try w.writeAll(",\"include_disassembly\":true,\"max_blocks\":128}}}");
        }
    }
    if (entry.doc.note) |n| {
        w.writeAll(",\"note\":") catch {};
        json.writeJsonString(w, n) catch {};
    }
    emitSubsystemHints(w, ctx.allocator, &entry.doc, eff.db, eff.delta) catch return ToolError.OutOfMemory;

    // ---- Segments + sections (both modes — manifest skips entropy) ----
    w.writeAll(",\"segments\":[") catch {};
    for (entry.doc.segments, 0..) |seg, si| {
        if (si > 0) w.writeByte(',') catch {};
        w.writeAll("{\"name\":") catch {};
        json.writeJsonString(w, seg.name) catch {};
        w.writeAll(",\"start\":") catch {};
        json.writeAddress(w, applyRebaseDelta(seg.start, eff.delta)) catch {};
        w.print(",\"length\":{d},\"file_offset\":{d}", .{ seg.length, seg.file_offset }) catch {};
        w.print(",\"permissions\":{{\"read\":{s},\"write\":{s},\"execute\":{s}}}", .{
            if (seg.permissions.read) "true" else "false",
            if (seg.permissions.write) "true" else "false",
            if (seg.permissions.execute) "true" else "false",
        }) catch {};
        w.writeAll(",\"sections\":[") catch {};
        for (seg.sections, 0..) |sec, sj| {
            if (sj > 0) w.writeByte(',') catch {};
            w.writeAll("{\"name\":") catch {};
            json.writeJsonString(w, sec.name) catch {};
            w.writeAll(",\"start\":") catch {};
            json.writeAddress(w, applyRebaseDelta(sec.start, eff.delta)) catch {};
            w.print(",\"length\":{d},\"file_offset\":{d}", .{ sec.length, sec.file_offset }) catch {};
            // Entropy + zero-padding accounting (full mode only).
            if (chosen == .full and sec.length > 0 and !sec.is_zerofill) {
                const sec_end = sec.file_offset + sec.length;
                if (sec_end <= entry.doc.data.len) {
                    const sec_data = entry.doc.data[sec.file_offset..sec_end];
                    const ent = computeSectionEntropy(sec_data);
                    w.print(",\"entropy\":{d:.2}", .{ent}) catch {};
                    var zero_count: usize = 0;
                    for (sec_data) |b| if (b == 0) {
                        zero_count += 1;
                    };
                    if (zero_count * 10 > sec_data.len * 9) {
                        // Report zero density without assuming padding or omission.
                        w.print(",\"zero_byte_count\":{d}", .{zero_count}) catch {};
                    }
                }
            }
            w.writeByte('}') catch {};
        }
        w.writeAll("]}") catch {};
    }
    w.writeAll("]") catch {};

    // ---- Mode=manifest output stops here (lightweight) ----
    if (chosen == .manifest) {
        // Imports grouped by library, capability category counts, embedded
        // resources, and suggested seeds — no bytes / no disasm.
        var lib_counts = std.StringHashMap(u32).init(ctx.allocator);
        for (entry.doc.imports.items) |imp| {
            const lib = imp.library orelse "<unknown>";
            const gop = lib_counts.getOrPut(lib) catch continue;
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += 1;
        }
        w.writeAll(",\"imports_by_library\":[") catch {};
        var first_lib = true;
        var lit = lib_counts.iterator();
        while (lit.next()) |le| {
            if (!first_lib) w.writeByte(',') catch {};
            first_lib = false;
            w.writeAll("{\"library\":") catch {};
            json.writeJsonString(w, le.key_ptr.*) catch {};
            w.print(",\"count\":{d}}}", .{le.value_ptr.*}) catch {};
        }
        w.writeAll("]") catch {};

        // Capability counts: scan strings, bucket by category.
        var cap_counts = std.StringHashMap(u32).init(ctx.allocator);
        for (entry.doc.strings.items) |s| {
            var cats: [MAX_CAP_CATS][]const u8 = undefined;
            const n = categorizeCapability(s.value, &cats);
            for (cats[0..n]) |c| {
                const gop = cap_counts.getOrPut(c) catch continue;
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* += 1;
            }
        }
        w.writeAll(",\"capability_counts\":{") catch {};
        var first_cap = true;
        var cit = cap_counts.iterator();
        while (cit.next()) |ce| {
            if (!first_cap) w.writeByte(',') catch {};
            first_cap = false;
            json.writeJsonString(w, ce.key_ptr.*) catch {};
            w.print(":{d}", .{ce.value_ptr.*}) catch {};
        }
        w.writeAll("}") catch {};

        // Suggested next call: frontier ranking with empty seeds.
        w.writeAll(",\"next_call\":{\"tool\":\"get_binary_context\",\"args\":{\"mode\":\"frontier\"}}") catch {};

        // v7.14.1 A5: honor max_chars for manifest mode. Pre-fix, large
        // manifests returned the framework "Response too large" error wrapper instead
        // of truncated content. The user passed a cap; respect it.
        const trunc_overhead_m: usize = 250;
        const needs_trunc = (rb.written().len + trunc_overhead_m) > max_chars;
        if (needs_trunc) {
            // Walk the buffer and find the last top-level field boundary
            // (brace_depth==1, bracket_depth==0) at or before cap_at.
            const cap_at = if (max_chars > trunc_overhead_m) max_chars - trunc_overhead_m else max_chars / 2;
            const scan_end = @min(rb.written().len, cap_at);
            var brace_depth: i32 = 0;
            var bracket_depth: i32 = 0;
            var in_string = false;
            var prev_escape = false;
            var safe_end: usize = 0;
            var i: usize = 0;
            while (i < scan_end) : (i += 1) {
                const c = rb.written()[i];
                if (in_string) {
                    if (prev_escape) {
                        prev_escape = false;
                    } else if (c == '\\') {
                        prev_escape = true;
                    } else if (c == '"') {
                        in_string = false;
                    }
                    continue;
                }
                switch (c) {
                    '"' => in_string = true,
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        if (brace_depth == 1 and bracket_depth == 0) safe_end = i + 1;
                    },
                    '[' => bracket_depth += 1,
                    ']' => {
                        bracket_depth -= 1;
                        if (brace_depth == 1 and bracket_depth == 0) safe_end = i + 1;
                    },
                    else => {},
                }
            }
            if (safe_end > 100) {
                rb.shrinkRetainingCapacity(safe_end);
                rb.writer.writeAll(",\"truncated\":true,\"truncation_note\":\"manifest exceeded max_chars; fields beyond this point were dropped\"}") catch {};
            } else {
                // No safe break — emit a minimal valid response.
                rb.clearRetainingCapacity();
                rb.writer.writeAll("{\"strategy\":\"manifest\",\"truncated\":true,\"truncation_note\":\"no safe truncation point under max_chars\"}") catch {};
            }
        } else {
            w.writeAll(",\"truncated\":false}") catch {};
        }
        const final_resp = rb.toOwnedSlice() catch return ToolError.OutOfMemory;
        const elapsed = timestampMs(ctx.io) - start_ts;
        const resp = json.successResponse(ctx.allocator, "get_binary_context", final_resp, elapsed) catch return ToolError.OutOfMemory;
        // Match full-mode envelope sizing — meta_max_chars must accommodate
        // the JSON-RPC wrapper (~1 KiB beyond the raw content) so the
        // outer dispatcher doesn't replace our truncated content with the
        // generic "Response too large" error wrapper.
        return .{ .json_response = resp, .meta_max_chars = @max(max_chars + 1024, 200_000) };
    }

    // ---- Mode=full: complete strings as contiguous blocks ----
    {
        const all_strings = entry.doc.strings.items;
        const blocks = groupContiguousStrings(ctx.allocator, &entry.doc, all_strings, eff.delta, 16) catch &[_]StringBlock{};
        w.writeAll(",\"string_blocks\":[") catch {};
        var first_blk = true;
        for (blocks) |blk| {
            if (!first_blk) w.writeByte(',') catch {};
            first_blk = false;
            w.writeAll("{\"block_address\":") catch {};
            json.writeAddress(w, blk.block_address) catch {};
            w.print(",\"block_size\":{d},\"strings\":[", .{blk.block_size}) catch {};
            for (blk.strings, 0..) |se, ei| {
                if (ei > 0) w.writeByte(',') catch {};
                w.print("{{\"offset\":{d},\"address\":", .{se.offset}) catch {};
                json.writeAddress(w, se.address) catch {};
                w.writeAll(",\"text\":") catch {};
                json.writeJsonString(w, se.text) catch {};
                w.writeByte('}') catch {};
            }
            w.writeAll("]}") catch {};
        }
        w.writeAll("]") catch {};
    }

    // ---- Complete imports list ----
    {
        w.writeAll(",\"imports\":[") catch {};
        for (entry.doc.imports.items, 0..) |imp, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"address\":") catch {};
            json.writeAddress(w, applyRebaseDelta(imp.address, eff.delta)) catch {};
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, imp.name) catch {};
            if (imp.library) |lib| {
                w.writeAll(",\"library\":") catch {};
                json.writeJsonString(w, lib) catch {};
            }
            const stub = imp.stub_address orelse 0;
            const xc = countImportXrefs(eff.db, imp.name, stub);
            w.print(",\"xref_count\":{d}}}", .{xc}) catch {};
        }
        w.writeAll("]") catch {};
    }

    // ---- Complete exports list (named procedures + symbols) ----
    {
        w.writeAll(",\"exports\":[") catch {};
        var first_exp = true;
        var pit = eff.db.procedures.iterator();
        while (pit.next()) |pe| {
            const proc = pe.value_ptr.*;
            const nm = proc.name orelse continue;
            if (nm.len == 0) continue;
            if (std.mem.startsWith(u8, nm, "sub_") or std.mem.startsWith(u8, nm, "proc_")) continue;
            if (!first_exp) w.writeByte(',') catch {};
            first_exp = false;
            w.writeAll("{\"address\":") catch {};
            json.writeAddress(w, applyRebaseDelta(proc.entry, eff.delta)) catch {};
            w.writeAll(",\"name\":") catch {};
            json.writeJsonString(w, nm) catch {};
            w.print(",\"size\":{d}}}", .{proc.size}) catch {};
        }
        w.writeAll("]") catch {};
    }

    // ---- Full disasm of __text when total exec bytes <= 32 KiB ----
    {
        var total_exec_bytes: u64 = 0;
        for (entry.doc.segments) |seg| {
            if (!seg.permissions.execute) continue;
            for (seg.sections) |sec| {
                if (sec.isCode()) total_exec_bytes += sec.length;
            }
            if (seg.sections.len == 0) total_exec_bytes += seg.length;
        }
        const disasm_cap: u64 = 32 * 1024;
        if (automatic_execution and automatic_cfg_address != null) {
            try w.writeAll(",\"instruction_evidence\":\"control_flow_evidence.cfg execution steps, or its exact next_call when deferred\"");
            if (automatic_cfg != null and automatic_cfg_bytes < total_exec_bytes) {
                try w.print(",\"executable_coverage\":{{\"status\":\"bytes_outside_recovered_cfg\",\"recovered_cfg_bytes\":{d},\"executable_bytes\":{d},\"note\":\"CFG recovery does not cover all executable bytes; these calls expose complete executable ranges including unvisited or undecoded tails. No effects or edges are inferred for uncovered bytes.\",\"range_calls\":[", .{ automatic_cfg_bytes, total_exec_bytes });
                var first_range = true;
                for (entry.doc.segments) |seg| {
                    if (!seg.permissions.execute) continue;
                    if (seg.sections.len == 0) {
                        if (!first_range) try w.writeByte(',');
                        first_range = false;
                        try w.print("{{\"tool\":\"disassemble_range\",\"arguments\":{{\"doc_id\":{d},\"start\":", .{doc_id});
                        try json.writeAddress(w, seg.start);
                        try w.print(",\"byte_length\":{d}}}}}", .{seg.length});
                    } else for (seg.sections) |sec| {
                        if (!sec.isCode()) continue;
                        if (!first_range) try w.writeByte(',');
                        first_range = false;
                        try w.print("{{\"tool\":\"disassemble_range\",\"arguments\":{{\"doc_id\":{d},\"start\":", .{doc_id});
                        try json.writeAddress(w, sec.start);
                        try w.print(",\"byte_length\":{d}}}}}", .{sec.length});
                    }
                }
                try w.writeAll("]}");
            }
        } else if (total_exec_bytes <= disasm_cap) {
            w.writeAll(",\"disasm\":[") catch {};
            var first_inst = true;
            for (entry.doc.segments) |seg| {
                if (!seg.permissions.execute) continue;
                for (seg.sections) |sec| {
                    if (!sec.isCode()) continue;
                    var addr = sec.start;
                    const sec_end = sec.start + sec.length;
                    while (addr < sec_end) {
                        if (eff.db.getInstruction(addr)) |inst| {
                            if (!first_inst) w.writeByte(',') catch {};
                            first_inst = false;
                            w.writeAll("{\"address\":") catch {};
                            json.writeAddress(w, applyRebaseDelta(addr, eff.delta)) catch {};
                            w.writeAll(",\"mnemonic\":") catch {};
                            json.writeJsonString(w, inst.mnemonic) catch {};
                            const ops = eff.db.getInstructionOperands(addr);
                            if (ops.len > 0) {
                                w.writeAll(",\"operands\":") catch {};
                                json.writeJsonString(w, ops) catch {};
                            }
                            w.print(",\"size\":{d}}}", .{inst.size}) catch {};
                            addr += inst.size;
                        } else {
                            // No cached instruction — best-effort decode.
                            const min_size: usize = if (entry.doc.arch == .arm32) 2 else if (entry.doc.arch == .x86_64 or entry.doc.arch == .x86) 1 else 4;
                            const file_off = sec.file_offset + (addr - sec.start);
                            if (file_off + min_size > entry.doc.data.len) break;
                            // Decode via arch decoder.
                            var mnem: []const u8 = "?";
                            var ops_buf: [128]u8 = undefined;
                            var ops_len: u8 = 0;
                            var inst_size: u8 = @intCast(min_size);
                            switch (entry.doc.arch) {
                                .arm64 => {
                                    const d = arm64.decode(entry.doc.data[file_off..], addr);
                                    mnem = d.mnemonic;
                                    @memcpy(ops_buf[0..d.operands_len], d.operands[0..d.operands_len]);
                                    ops_len = d.operands_len;
                                    inst_size = d.length;
                                },
                                .arm32 => {
                                    const d = arm32.decode(entry.doc.data[file_off..], addr);
                                    mnem = d.mnemonic;
                                    @memcpy(ops_buf[0..d.operands_len], d.operands[0..d.operands_len]);
                                    ops_len = d.operands_len;
                                    inst_size = d.length;
                                },
                                .mips32 => {
                                    const d = mips32.decode(entry.doc.data[file_off..], addr);
                                    mnem = d.mnemonic;
                                    @memcpy(ops_buf[0..d.operands_len], d.operands[0..d.operands_len]);
                                    ops_len = d.operands_len;
                                    inst_size = d.length;
                                },
                                .x86_64, .x86 => {
                                    const x86 = @import("arch/x86_64.zig");
                                    const d = if (entry.doc.arch == .x86) x86.decode32(entry.doc.data[file_off..], addr) else x86.decode(entry.doc.data[file_off..], addr);
                                    if (x86DecodeGap(d.mnemonic)) break;
                                    mnem = d.mnemonic;
                                    @memcpy(ops_buf[0..d.operands_len], d.operands[0..d.operands_len]);
                                    ops_len = d.operands_len;
                                    inst_size = d.length;
                                },
                            }
                            if (inst_size == 0) break;
                            if (!first_inst) w.writeByte(',') catch {};
                            first_inst = false;
                            w.writeAll("{\"address\":") catch {};
                            json.writeAddress(w, applyRebaseDelta(addr, eff.delta)) catch {};
                            w.writeAll(",\"mnemonic\":") catch {};
                            json.writeJsonString(w, mnem) catch {};
                            if (ops_len > 0) {
                                w.writeAll(",\"operands\":") catch {};
                                json.writeJsonString(w, ops_buf[0..ops_len]) catch {};
                            }
                            w.print(",\"size\":{d}}}", .{inst_size}) catch {};
                            addr += inst_size;
                        }
                    }
                }
            }
            w.writeAll("]") catch {};
        } else {
            w.print(",\"disasm_omitted\":\"exec_bytes={d} > 32 KiB cap; call disassemble_range or get_cfg to inspect specific addresses\"", .{total_exec_bytes}) catch {};
        }
    }

    // Optional primary-byte previews are bounded before serialization. Zero
    // markers preserve actual zeros; they never classify bytes as padding.
    if (include_bytes) {
        w.writeAll(",\"byte_encoding\":\"compact_hex_with_zero_runs\",\"zero_run_syntax\":\"[ZERO*N] means N actual zero bytes; zeros are not assumed padding\",\"bytes\":[") catch {};
        var byte_budget: usize = @min(16384, max_chars / 4);
        var byte_sections: usize = 0;
        var omitted_sections: usize = 0;
        var bytes_partial = false;
        for (entry.doc.segments) |seg| {
            for (seg.sections) |sec| {
                if (sec.is_zerofill or sec.length == 0) continue;
                if (sec.file_offset > entry.doc.data.len or sec.length > entry.doc.data.len - sec.file_offset or byte_sections >= 32) {
                    omitted_sections += 1;
                    bytes_partial = true;
                    continue;
                }
                if (byte_sections != 0) w.writeByte(',') catch {};
                byte_sections += 1;
                const count: usize = @intCast(@min(sec.length, @min(byte_budget, 4096)));
                byte_budget -= count;
                const partial = count < sec.length;
                bytes_partial = bytes_partial or partial;
                w.writeAll("{\"section\":") catch {};
                json.writeJsonString(w, sec.name) catch {};
                w.writeAll(",\"start\":") catch {};
                const out_start = applyRebaseDelta(sec.start, eff.delta);
                json.writeAddress(w, out_start) catch {};
                w.print(",\"file_offset\":{d},\"section_length\":{d},\"returned_length\":{d},\"partial\":{},\"hex\":\"", .{ sec.file_offset, sec.length, count, partial }) catch {};
                const data_slice = entry.doc.data[sec.file_offset..][0..count];
                var i: usize = 0;
                while (i < data_slice.len) {
                    if (data_slice[i] == 0) {
                        var j = i;
                        while (j < data_slice.len and data_slice[j] == 0) : (j += 1) {}
                        const run = j - i;
                        if (run >= 8) {
                            w.print("[ZERO*{d}]", .{run}) catch {};
                            i = j;
                            continue;
                        }
                    }
                    w.print("{x:0>2}", .{data_slice[i]}) catch {};
                    i += 1;
                }
                w.writeByte('"') catch {};
                if (partial) {
                    w.print(",\"next_call\":{{\"tool\":\"read_bytes\",\"arguments\":{{\"doc_id\":{d},\"file_offset\":{d},\"length\":{d},\"encoding\":\"hex_compact\"}}}}", .{ doc_id, sec.file_offset + count, sec.length - count }) catch {};
                }
                w.writeByte('}') catch {};
            }
        }
        w.print("],\"bytes_partial\":{},\"byte_sections_omitted\":{d}", .{ bytes_partial, omitted_sections }) catch {};
    }

    // Finalize. Truncate at max_chars if we overflowed.
    var truncated = false;
    // Reserve ~250 bytes for the truncation suffix + JSON envelope.
    const trunc_overhead: usize = 250;
    if (rb.written().len + trunc_overhead > max_chars) {
        truncated = true;
    }
    if (truncated) {
        // Walk the buffer, scanning byte by byte while tracking JSON string
        // and brace/bracket depth. Find the latest position <= cap_at that
        // is OUTSIDE a string AND immediately follows a closing `}` or `]`
        // (so we know we're at a clean field boundary). Then chop, write
        // any needed closing brackets to balance, and append the suffix.
        const cap_at = if (max_chars > trunc_overhead) max_chars - trunc_overhead else max_chars / 2;
        const scan_end = @min(rb.written().len, cap_at);
        var brace_depth: i32 = 0;
        var bracket_depth: i32 = 0;
        var in_string = false;
        var prev_escape = false;
        var safe_end: usize = 0;
        var i: usize = 0;
        while (i < scan_end) : (i += 1) {
            const c = rb.written()[i];
            if (in_string) {
                if (prev_escape) {
                    prev_escape = false;
                } else if (c == '\\') {
                    prev_escape = true;
                } else if (c == '"') {
                    in_string = false;
                }
                continue;
            }
            switch (c) {
                '"' => in_string = true,
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    // Top-level field just closed if brace_depth == 1 (we
                    // started inside the outer `{`). Record this position
                    // as a safe truncation boundary.
                    if (brace_depth == 1 and bracket_depth == 0) {
                        safe_end = i + 1;
                    }
                },
                '[' => bracket_depth += 1,
                ']' => {
                    bracket_depth -= 1;
                    if (brace_depth == 1 and bracket_depth == 0) {
                        safe_end = i + 1;
                    }
                },
                else => {},
            }
        }
        if (safe_end > 100) {
            rb.shrinkRetainingCapacity(safe_end);
            // safe_end already lands at a top-level boundary (brace_depth=1,
            // bracket_depth=0), so we just append the truncation suffix and
            // close the outer brace.
            rb.writer.writeAll(",\"truncated\":true,\"truncation_note\":\"response would exceed max_chars; retry with mode=manifest for a lighter summary\"}") catch {};
        } else {
            // Couldn't find a clean break — emit a minimal valid response.
            rb.clearRetainingCapacity();
            try rb.writer.writeAll("{\"strategy\":\"manifest\",\"truncated\":true,\"truncation_note\":\"no safe truncation point; retry with mode=manifest\"");
            if (automatic_cfg_address) |addr| {
                try rb.writer.writeAll(",\"control_flow_evidence\":{\"status\":\"deferred\",\"next_call\":{\"tool\":\"get_cfg\",\"arguments\":{");
                try rb.writer.print("\"doc_id\":{d},\"function_address\":", .{doc_id});
                try json.writeAddress(&rb.writer, addr);
                if (automatic_execution) try rb.writer.writeAll(",\"instruction_view\":\"execution\"");
                try rb.writer.writeAll(",\"include_disassembly\":true,\"max_blocks\":128}}}");
            }
            try rb.writer.writeByte('}');
        }
    } else {
        w.writeAll(",\"truncated\":false}") catch {};
    }

    const final_resp = rb.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start_ts;
    const resp = json.successResponse(ctx.allocator, "get_binary_context", final_resp, elapsed) catch return ToolError.OutOfMemory;
    // Per-tool envelope cap: max_chars + JSON-RPC envelope (~250 bytes).
    return .{ .json_response = resp, .meta_max_chars = @max(max_chars + 1024, 200_000) };
}

// ============================================================================
// get_semantic_slice handler
// ============================================================================

fn handleGetSemanticSlice(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start = timestampMs(ctx.io);

    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_semantic_slice", params);
    };
    const all_addresses = parseBatchAddresses(ctx.allocator, params) catch {
        const resp = json.errorResponse(ctx.allocator, "get_semantic_slice", "missing or invalid 'addresses' parameter. Accepts: integer, hex string (\"0x1234\"), or array of integers/hex strings.", 0) catch return ToolError.OutOfMemory;
        return .{ .json_response = resp, .is_error = true };
    };
    defer ctx.allocator.free(all_addresses);
    const addresses = all_addresses[0..@min(all_addresses.len, 20)];

    // Parse view mode: facts (default), pack, remake
    const view_str = getString(params, "view") orelse "facts";
    const is_pack = std.ascii.eqlIgnoreCase(view_str, "pack");
    const is_remake = std.ascii.eqlIgnoreCase(view_str, "remake");
    const raw_max_chars: ?i64 = getInt(params, "max_chars");
    const max_chars: u32 = if (raw_max_chars) |m| @intCast(@min(@max(m, 100), 30000)) else 12000;
    const max_chars_was_clamped = if (raw_max_chars) |m| (m < 100 or m > 30000) else false;
    const scope_str = getString(params, "scope") orelse "function";
    const is_cluster = std.ascii.eqlIgnoreCase(scope_str, "cluster");

    const radius: u32 = if (getInt(params, "radius")) |r| @intCast(@max(r, 0)) else if (is_pack or is_remake) 1 else 1;
    const max_nodes: u32 = if (getInt(params, "max_nodes")) |m| @intCast(@max(m, 1)) else if (is_pack or is_remake) 200 else 50;
    const include_names = getBool(params, "include_names") orelse true;
    const max_cluster_param: u32 = if (getInt(params, "max_cluster")) |m| @intCast(@max(m, 1)) else 30;

    // Parse kinds filter bitmask (0 = all kinds)
    var kinds_mask: u8 = 0;
    if (getArray(params, "kinds")) |arr| {
        for (arr.array.items) |item| {
            if (item == .string) {
                if (std.mem.eql(u8, item.string, "function_entry")) kinds_mask |= 1 else if (std.mem.eql(u8, item.string, "function_range")) kinds_mask |= 2 else if (std.mem.eql(u8, item.string, "call_edge")) kinds_mask |= 4 else if (std.mem.eql(u8, item.string, "jump_edge")) kinds_mask |= 8 else if (std.mem.eql(u8, item.string, "data_ref")) kinds_mask |= 16 else if (std.mem.eql(u8, item.string, "string_ref")) kinds_mask |= 32;
            }
        }
    }

    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_semantic_slice");
    const eff = resolveEffectiveDb(entry);
    eff.db.rw_lock.lockSharedUncancelable(eff.db.io);
    defer eff.db.rw_lock.unlockShared(eff.db.io);

    const snapshot = eff.db.getSnapshotId();

    // Route to pack/remake formatter if requested
    if (is_pack or is_remake) {
        return buildContextPack(ctx, eff, doc_id, addresses, snapshot, max_chars, is_remake, is_cluster, max_chars_was_clamped, max_cluster_param, start);
    }

    // Seed diagnostics — match the schema emitted by buildContextPack so all
    // three views (facts/pack/remake) report seed resolution identically.
    const SeedDiag = struct { addr: u64, resolved: bool, confidence: []const u8 };
    var seed_diags = std.array_list.Managed(SeedDiag).init(ctx.allocator);
    defer seed_diags.deinit();
    for (addresses) |addr| {
        const eff_addr = removeRebaseDelta(addr, eff.delta);
        const candidates = eff.db.getProcedureCandidates(eff_addr, 1);
        if (candidates.count == 0) {
            seed_diags.append(.{ .addr = addr, .resolved = false, .confidence = "none" }) catch {};
        } else {
            const conf: []const u8 = switch (candidates.items[0].confidence) {
                .exact => "exact",
                .high => "high",
                .medium => "medium",
                .low => "low",
                .unknown => "unknown",
            };
            seed_diags.append(.{ .addr = addr, .resolved = true, .confidence = conf }) catch {};
        }
    }

    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.print("{{\"snapshot_id\":{d},\"facts\":[", .{snapshot});

    var fact_count: u32 = 0;
    var truncated = false;

    // BFS queue for multi-hop traversal
    var visited = std.AutoHashMap(u64, void).init(ctx.allocator);
    defer visited.deinit();
    var queue = std.array_list.Managed(struct { addr: u64, depth: u32 }).init(ctx.allocator);
    defer queue.deinit();

    // Seed queue with requested addresses
    for (addresses) |addr| {
        if (!visited.contains(addr)) {
            visited.put(addr, {}) catch {};
            queue.append(.{ .addr = addr, .depth = 0 }) catch {};
        }
    }

    var qi: usize = 0;
    while (qi < queue.items.len) : (qi += 1) {
        if (fact_count >= max_nodes) {
            truncated = true;
            break;
        }
        const item = queue.items[qi];
        const addr = item.addr;
        const depth = item.depth;

        // Find containing procedure
        const candidates = eff.db.getProcedureCandidates(addr, 1);
        const maybe_proc: ?types.Procedure = if (candidates.count > 0) candidates.items[0].proc else null;

        // Radius 0: function_entry + function_range
        if (maybe_proc) |proc| {
            if (passesFilter(kinds_mask, 0)) { // function_entry = bit 0
                if (fact_count >= max_nodes) {
                    truncated = true;
                    break;
                }
                if (fact_count > 0) try w.writeByte(',');
                try writeFactJson(w, "function_entry", proc.entry, 0, 90, "prologue_scan", if (include_names) (proc.name orelse eff.db.resolveName(proc.entry)) else null);
                fact_count += 1;
            }
            if (proc.size > 0 and passesFilter(kinds_mask, 1)) { // function_range = bit 1
                if (fact_count >= max_nodes) {
                    truncated = true;
                    break;
                }
                if (fact_count > 0) try w.writeByte(',');
                try writeFactJson(w, "function_range", proc.entry, proc.entry + proc.size, 90, "prologue_scan", null);
                fact_count += 1;
            }

            // Radius 1+: edges and refs via RANGE SCAN across procedure body
            if (depth < radius) {
                const proc_end = proc.entry + @max(proc.size, 1);
                const want_calls = passesFilter(kinds_mask, 2);
                const want_jumps = passesFilter(kinds_mask, 3);
                const want_data = passesFilter(kinds_mask, 4);
                const want_strings = passesFilter(kinds_mask, 5);

                // Range scan: O(log N + K) via sorted xref array
                const range_xrefs = eff.db.xrefs.getRefsFromRange(proc.entry, proc_end);
                for (range_xrefs) |xref| {
                    if (fact_count >= max_nodes) {
                        truncated = true;
                        break;
                    }

                    if (xref.xref_type == .call and want_calls) {
                        if (fact_count > 0) try w.writeByte(',');
                        const tgt_name = if (include_names) eff.db.resolveName(xref.to) else null;
                        try writeFactJson(w, "call_edge", xref.from, xref.to, 100, "xref_scan", tgt_name);
                        fact_count += 1;
                        if (!visited.contains(xref.to)) {
                            visited.put(xref.to, {}) catch {};
                            queue.append(.{ .addr = xref.to, .depth = depth + 1 }) catch {};
                        }
                    } else if (xref.xref_type == .jump and want_jumps) {
                        if (fact_count > 0) try w.writeByte(',');
                        try writeFactJson(w, "jump_edge", xref.from, xref.to, 90, "xref_scan", null);
                        fact_count += 1;
                    } else if ((xref.xref_type == .data_read or xref.xref_type == .data_write) and (want_data or want_strings)) {
                        const found_str = if (want_strings) (eff.db.getString(xref.to) orelse eff.db.getString(xref.to & ~@as(u64, 0xFFF))) else null;
                        if (found_str) |str| {
                            if (fact_count > 0) try w.writeByte(',');
                            const str_name = if (include_names) str.value else null;
                            try writeFactJson(w, "string_ref", xref.from, xref.to, 90, "xref_scan", str_name);
                            fact_count += 1;
                        } else if (want_data) {
                            if (fact_count > 0) try w.writeByte(',');
                            try writeFactJson(w, "data_ref", xref.from, xref.to, 85, "xref_scan", null);
                            fact_count += 1;
                        }
                    }
                }

                // Callers (refs_to at entry — these are correct as point lookups)
                if (want_calls) {
                    const refs_to = eff.db.xrefs.getRefsTo(proc.entry);
                    for (refs_to) |xref| {
                        if (xref.xref_type == .call) {
                            if (fact_count >= max_nodes) {
                                truncated = true;
                                break;
                            }
                            if (fact_count > 0) try w.writeByte(',');
                            const caller_name = if (include_names) eff.db.resolveName(xref.from) else null;
                            try writeFactJson(w, "call_edge", xref.from, proc.entry, 95, "xref_scan", caller_name);
                            fact_count += 1;
                            if (!visited.contains(xref.from)) {
                                visited.put(xref.from, {}) catch {};
                                queue.append(.{ .addr = xref.from, .depth = depth + 1 }) catch {};
                            }
                        }
                    }
                }
            }
        }
    }

    try w.print("],\"fact_count\":{d},\"truncated\":{s}", .{ fact_count, if (truncated) "true" else "false" });

    // Seed diagnostics — same shape as buildContextPack (pack/remake views).
    try w.writeAll(",\"seed_diagnostics\":[");
    for (seed_diags.items, 0..) |sd, si| {
        if (si > 0) try w.writeByte(',');
        try w.writeAll("{\"address\":");
        try json.writeAddress(w, sd.addr);
        try w.print(",\"resolved\":{s},\"confidence\":\"{s}\"}}", .{
            if (sd.resolved) "true" else "false", sd.confidence,
        });
    }
    try w.writeAll("]}");

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start;
    const resp = json.successResponse(ctx.allocator, "get_semantic_slice", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .is_error = false, .meta_max_chars = 200_000 };
}

/// Build an LLM-native context pack or remake spec from the analysis database.
/// This is the binary-to-context compiler: assembles functions, control flow, strings,
/// imports, and unknowns into a deterministic, label-mapped text pack.
fn buildContextPack(
    ctx: ToolContext,
    eff: EffectiveDb,
    doc_id: u64,
    addresses: []const u64,
    snapshot: u64,
    max_chars: u32,
    is_remake: bool,
    is_cluster: bool,
    max_chars_was_clamped: bool,
    max_cluster: u32,
    start_time: i64,
) ToolError!ToolResult {
    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;

    // Collect functions in scope
    const FuncInfo = struct { proc: types.Procedure, label: u32 };
    var funcs = std.array_list.Managed(FuncInfo).init(ctx.allocator);
    var func_set = std.AutoHashMap(u64, u32).init(ctx.allocator); // entry → label
    defer funcs.deinit();
    defer func_set.deinit();

    // Seed: find procedures for each address, track diagnostics
    const SeedDiag = struct { addr: u64, resolved: bool, confidence: []const u8 };
    var seed_diags = std.array_list.Managed(SeedDiag).init(ctx.allocator);
    defer seed_diags.deinit();

    for (addresses) |addr| {
        const eff_addr = removeRebaseDelta(addr, eff.delta);
        const candidates = eff.db.getProcedureCandidates(eff_addr, 1);
        if (candidates.count == 0) {
            seed_diags.append(.{ .addr = addr, .resolved = false, .confidence = "none" }) catch {};
            continue;
        }
        const proc = candidates.items[0].proc;
        const conf: []const u8 = switch (candidates.items[0].confidence) {
            .exact => "exact",
            .high => "high",
            .medium => "medium",
            .low => "low",
            .unknown => "unknown",
        };
        seed_diags.append(.{ .addr = addr, .resolved = true, .confidence = conf }) catch {};
        if (!func_set.contains(proc.entry)) {
            const idx: u32 = @intCast(funcs.items.len);
            func_set.put(proc.entry, idx) catch {};
            funcs.append(.{ .proc = proc, .label = idx }) catch {};
        }
    }

    const seed_count = funcs.items.len;

    // Import calls (declared early so cluster expansion can add thunk resolutions)
    const ImpRef = struct { func_label: u32, imp_name: []const u8 };
    var imp_refs = std.array_list.Managed(ImpRef).init(ctx.allocator);
    defer imp_refs.deinit();

    // Cluster expansion: add informative neighbors, resolve thunks to import names
    var thunks_resolved: u32 = 0;
    // max_cluster is passed as a parameter from handleGetSemanticSlice
    var cluster_callee_found: u32 = 0;
    var cluster_caller_found: u32 = 0;
    if (is_cluster) {
        var extra = std.array_list.Managed(FuncInfo).init(ctx.allocator);
        defer extra.deinit();
        for (funcs.items) |fi| {
            const proc_end = fi.proc.entry + @max(fi.proc.size, 1);
            const cluster_xrefs = eff.db.xrefs.getRefsFromRange(fi.proc.entry, proc_end);
            for (cluster_xrefs) |xref| {
                if (xref.xref_type == .call and !func_set.contains(xref.to)) {
                    if (eff.db.getProcedure(xref.to)) |callee| {
                        // Filter thunk stubs: small functions that are import trampolines
                        if (callee.size > 0 and callee.size <= 32) {
                            if (eff.db.resolveName(callee.entry)) |name| {
                                // Add as import ref instead of cluster member
                                if (imp_refs.items.len < 50) {
                                    imp_refs.append(.{ .func_label = fi.label, .imp_name = normalizeForComparison(name) }) catch {};
                                }
                                thunks_resolved += 1;
                                func_set.put(callee.entry, 0) catch {}; // mark visited
                                continue;
                            }
                        }
                        cluster_callee_found += 1;
                        if (extra.items.len < max_cluster) {
                            const idx: u32 = @intCast(funcs.items.len + extra.items.len);
                            func_set.put(callee.entry, idx) catch {};
                            extra.append(.{ .proc = callee, .label = idx }) catch {};
                        }
                    }
                }
            }
        }

        // Caller expansion: add functions that CALL the seed functions (lower priority than callees)
        for (funcs.items) |fi| {
            const caller_refs = eff.db.xrefs.getRefsTo(fi.proc.entry);
            for (caller_refs) |xref| {
                if (xref.xref_type == .call) {
                    if (!func_set.contains(xref.from)) {
                        const caller_proc = eff.db.getProcedureContaining(xref.from);
                        if (caller_proc) |cp| {
                            if (!func_set.contains(cp.entry)) {
                                cluster_caller_found += 1;
                                if (extra.items.len < max_cluster) {
                                    const idx: u32 = @intCast(funcs.items.len + extra.items.len);
                                    func_set.put(cp.entry, idx) catch {};
                                    extra.append(.{ .proc = cp, .label = idx }) catch {};
                                }
                            }
                        }
                    }
                }
            }
        }

        for (extra.items) |efi| funcs.append(efi) catch {};
    }

    // Collect strings referenced by functions in scope
    const StrRef = struct { func_label: u32, str_addr: u64, value: []const u8 };
    var str_refs = std.array_list.Managed(StrRef).init(ctx.allocator);
    defer str_refs.deinit();

    // Import calls (declared above, before cluster expansion)

    // Collect callers from outside scope
    const CallerRef = struct { caller_addr: u64, callee_label: u32, name: ?[]const u8 };
    var external_callers = std.array_list.Managed(CallerRef).init(ctx.allocator);
    defer external_callers.deinit();

    // Unknowns
    var unknowns = std.array_list.Managed([]const u8).init(ctx.allocator);
    defer unknowns.deinit();

    for (funcs.items) |fi| {
        const proc_end = fi.proc.entry + @max(fi.proc.size, 1);

        // Scan xrefs within procedure range — O(log N + K) via sorted array
        const pack_xrefs = eff.db.xrefs.getRefsFromRange(fi.proc.entry, proc_end);
        for (pack_xrefs) |xref| {
            if ((xref.xref_type == .data_read or xref.xref_type == .string_ref)) {
                const found_str = eff.db.getString(xref.to) orelse eff.db.getString(xref.to & ~@as(u64, 0xFFF));
                if (found_str) |str| {
                    if (str_refs.items.len < 50) {
                        str_refs.append(.{ .func_label = fi.label, .str_addr = xref.to, .value = str.value }) catch {};
                    }
                }
            }
            if (xref.xref_type == .call) {
                if (eff.db.getSymbolName(xref.to)) |sym_name| {
                    if (imp_refs.items.len < 50) {
                        imp_refs.append(.{ .func_label = fi.label, .imp_name = normalizeForComparison(sym_name) }) catch {};
                    }
                } else if (eff.db.getImport(xref.to)) |imp| {
                    if (imp_refs.items.len < 50) {
                        imp_refs.append(.{ .func_label = fi.label, .imp_name = normalizeForComparison(imp.name) }) catch {};
                    }
                }
            }
        }

        // Also resolve callees via call_index (catches stubs that xref scan misses)
        const callees = ensureCalleesCached(eff.entry, eff.db, fi.proc.entry, ctx.allocator);
        for (callees) |callee_addr| {
            if (imp_refs.items.len >= 50) break;
            if (eff.db.getSymbolName(callee_addr)) |sym_name| {
                // Has a symbol → likely import stub or named API
                imp_refs.append(.{ .func_label = fi.label, .imp_name = normalizeForComparison(sym_name) }) catch {};
            }
        }

        // External callers
        const refs_to = eff.db.xrefs.getRefsTo(fi.proc.entry);
        for (refs_to) |xref| {
            if (xref.xref_type == .call and !func_set.contains(xref.from)) {
                if (external_callers.items.len < 10) {
                    external_callers.append(.{
                        .caller_addr = applyRebaseDelta(xref.from, eff.delta),
                        .callee_label = fi.label,
                        .name = eff.db.resolveName(xref.from),
                    }) catch {};
                }
            }
        }

        // Track unknowns
        if (fi.proc.size == 0) {
            unknowns.append("procedure size unknown — boundaries may be inaccurate") catch {};
        }
    }

    // === Build the pack text ===
    // Start JSON envelope
    try w.print("{{\"snapshot_id\":{d},\"view\":\"{s}\",\"scope\":\"{s}\",", .{
        snapshot,
        if (is_remake) "remake" else "pack",
        if (is_cluster) "cluster" else "function",
    });

    // Label map (JSON)
    try w.writeAll("\"labels\":{");
    for (funcs.items, 0..) |fi, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("\"F{d}\":", .{fi.label});
        try json.writeAddress(w, applyRebaseDelta(fi.proc.entry, eff.delta));
    }
    try w.writeAll("},");

    // Build the text body
    var text = std.Io.Writer.Allocating.init(ctx.allocator);
    const tw = &text.writer;

    tw.writeAll("=== CONTEXT PACK ===\n") catch {};
    tw.print("Binary: {s} | Arch: {s} | Scope: {d} function(s)", .{
        std.fs.path.basename(eff.entry.doc.path),
        eff.entry.doc.arch.toString(),
        funcs.items.len,
    }) catch {};
    if (thunks_resolved > 0) tw.print(" | {d} import stubs resolved", .{thunks_resolved}) catch {};
    tw.writeAll("\n") catch {};

    // Section: Functions
    tw.writeAll("--- FUNCTIONS ---\n") catch {};
    var instruction_evidence_truncated = false;
    var coverage = std.Io.Writer.Allocating.init(ctx.allocator);
    defer coverage.deinit();
    const cw = &coverage.writer;
    const instruction_budget = max_chars * 60 / 100;
    const seed_budget = if (funcs.items.len > seed_count) instruction_budget * 80 / 100 else instruction_budget;
    for (funcs.items, 0..) |fi, func_index| {
        const rebased = applyRebaseDelta(fi.proc.entry, eff.delta);
        const name = fi.proc.name orelse eff.db.resolveName(fi.proc.entry) orelse "unnamed";
        tw.print("F{d}: {s} (0x{x}, {d} bytes)\n", .{ fi.label, name, rebased, fi.proc.size }) catch {};

        // Requested seeds retain their evidence budget when a cluster grows.
        const per_func_budget = if (func_index < seed_count)
            seed_budget / @max(seed_count, 1)
        else
            (instruction_budget - seed_budget) / @max(funcs.items.len - seed_count, 1);
        var covered_bytes: u64 = 0;
        var decode_gaps: usize = 0;
        if (per_func_budget > 0) {
            tw.writeAll("  ; instruction evidence\n") catch {};

            const proc_addr = fi.proc.entry;
            const proc_size = fi.proc.size;
            const doc_data = eff.entry.doc.data;
            const doc_arch = eff.entry.doc.arch;

            // Resolve file offset for this procedure's virtual address
            const raw_info = resolveRawBytesInfo(eff.entry, proc_addr);

            if (raw_info) |info| {
                const byte_off = info.file_offset + (proc_addr - info.section_base);
                // Decode up to per_func_budget characters worth of instructions
                const max_disasm: usize = per_func_budget;
                const is_arm32_disasm = doc_arch == .arm32;
                const is_mips32_disasm = doc_arch == .mips32;
                const is_x86_64_disasm = doc_arch == .x86_64 or doc_arch == .x86;
                const step: usize = if (is_arm32_disasm) 2 else if (is_x86_64_disasm) 1 else 4;
                const code_end = eff.entry.doc.codeRangeEnd(proc_addr) orelse proc_addr;
                const max_bytes: usize = @intCast(@min(code_end - proc_addr, if (proc_size > 0) @min(proc_size, 4096) else 256));
                var off: usize = 0;
                var thumb_state: arm32.ItState = .{};
                const disasm_start = text.written().len;

                while (off < max_bytes and (text.written().len - disasm_start) < max_disasm) {
                    const abs_off = byte_off + off;
                    if (abs_off >= doc_data.len) break;
                    const remaining = @min(max_bytes - off, doc_data.len - abs_off);
                    if (remaining < step) break;
                    const raw = doc_data[abs_off..][0..remaining];

                    const addr = proc_addr + off;
                    const display_addr = applyRebaseDelta(addr, eff.delta);

                    if (is_arm32_disasm) {
                        const d = arm32.decode(raw, addr);
                        if (d.length == 0 or d.length > remaining) break;
                        const predicate = thumb_state.currentCondition();
                        const mnemonic = if (predicate != null and d.flags_suppressed_in_it and std.mem.endsWith(u8, d.mnemonic, "s")) d.mnemonic[0 .. d.mnemonic.len - 1] else d.mnemonic;
                        tw.print("  0x{x}: {s}", .{ display_addr, mnemonic }) catch break;
                        const ops = d.operands[0..d.operands_len];
                        if (ops.len > 0) {
                            tw.print(" {s}", .{ops}) catch break;
                        }
                        if (predicate) |condition| tw.print(" ; if {s}", .{arm32.conditionName(condition)}) catch break;
                        if (predicate != null and d.flags_suppressed_in_it) tw.writeAll(", flags unchanged") catch break;
                        tw.writeByte('\n') catch break;
                        thumb_state.advance();
                        if (d.it_block) |block| thumb_state.begin(block);
                        off += d.length;
                    } else if (is_mips32_disasm) {
                        const d = mips32.decode(raw, addr);
                        tw.print("  0x{x}: {s}", .{ display_addr, d.mnemonic }) catch break;
                        const ops = d.operands[0..d.operands_len];
                        if (ops.len > 0) {
                            tw.print(" {s}", .{ops}) catch break;
                        }
                        tw.writeByte('\n') catch break;
                        off += 4;
                    } else if (is_x86_64_disasm) {
                        const x86 = @import("arch/x86_64.zig");
                        const d = if (doc_arch == .x86) x86.decode32(raw, addr) else x86.decode(raw, addr);
                        if (x86DecodeGap(d.mnemonic)) break;
                        if (d.length == 0 or d.length > remaining) break;
                        tw.print("  0x{x}: {s}", .{ display_addr, d.mnemonic }) catch break;
                        const ops = d.operands[0..d.operands_len];
                        if (ops.len > 0) {
                            tw.print(" {s}", .{ops}) catch break;
                        }
                        tw.writeByte('\n') catch break;
                        off += d.length;
                    } else {
                        writeArm64PackInstruction(tw, raw, addr, display_addr, &decode_gaps, if (off >= 4) std.mem.readInt(u32, doc_data[abs_off - 4 ..][0..4], .little) else null) catch break;
                        off += 4;
                    }
                }
                covered_bytes = off;
            }
        }
        if (decode_gaps > 0)
            unknowns.append("opaque ARM64 decoder slots: instruction identity, effects, and control flow unknown") catch {};
        const complete = fi.proc.size > 0 and covered_bytes == fi.proc.size;
        if (func_index > 0) try cw.writeByte(',');
        try cw.writeAll("{\"function_address\":");
        try json.writeAddress(cw, rebased);
        try cw.print(",\"known_bytes\":{d},\"covered_bytes\":{d},\"complete\":{},\"boundary_kind\":\"{s}\"", .{ fi.proc.size, covered_bytes, complete, if (eff.entry.doc.isLinkerFunctionStart(fi.proc.entry)) @as([]const u8, "linker_start_next_boundary") else "inferred" });
        try cw.print(",\"decode_gaps\":{d},\"decoded_bytes\":{d},\"decode_complete\":{}", .{ decode_gaps, covered_bytes - @as(u64, @intCast(decode_gaps)) * 4, complete and decode_gaps == 0 });
        if (!complete) {
            const next_length = if (fi.proc.size > covered_bytes) @min(fi.proc.size - covered_bytes, 256) else 256;
            try cw.print(",\"next_call\":{{\"tool\":\"disassemble_range\",\"arguments\":{{\"doc_id\":{d},\"start\":", .{doc_id});
            try json.writeAddress(cw, applyRebaseDelta(fi.proc.entry + covered_bytes, eff.delta));
            try cw.print(",\"byte_length\":{d}}}}}", .{next_length});
        }
        try cw.writeByte('}');
        if (!complete) {
            instruction_evidence_truncated = true;
            tw.print("  ; partial instruction evidence ({d}/{d} known bytes); continue with disassemble_range start=0x{x} byte_length=256\n", .{
                covered_bytes, fi.proc.size, applyRebaseDelta(fi.proc.entry + covered_bytes, eff.delta),
            }) catch {};
        }
    }

    // Section: Capabilities — surface categorized markers from string references
    {
        var cap_count: usize = 0;
        var cap_started = false;
        for (str_refs.items) |sr| {
            if (cap_count >= 30) break;
            var cats: [MAX_CAP_CATS][]const u8 = undefined;
            var confs: [MAX_CAP_CATS]CapConfidence = undefined;
            const n_cats = categorizeCapabilityWithConfidence(sr.value, &cats, &confs);
            if (n_cats > 0) {
                if (!cap_started) {
                    tw.writeAll("\n--- CAPABILITIES ---\n") catch {};
                    cap_started = true;
                }
                for (cats[0..n_cats], confs[0..n_cats]) |cat, conf| {
                    const conf_str: []const u8 = switch (conf) {
                        .high => "high",
                        .medium => "med",
                        .low => "low",
                    };
                    tw.print("[{s}:{s}] ", .{ cat, conf_str }) catch {};
                    const display_len = @min(sr.value.len, 50);
                    for (sr.value[0..display_len]) |c| {
                        if (c >= 0x20 and c <= 0x7E) tw.writeByte(c) catch {} else tw.writeByte('.') catch {};
                    }
                    tw.print(" (F{d})\n", .{sr.func_label}) catch {};
                    cap_count += 1;
                    if (cap_count >= 30) break;
                }
            }
        }
    }

    // Section: String References — always emit (reserved 25% budget for context)
    const context_limit = max_chars * 85 / 100; // strings/imports stop at 85% of total
    if (str_refs.items.len > 0) {
        tw.writeAll("\n--- STRINGS ---\n") catch {};
        for (str_refs.items) |sr| {
            if (text.written().len >= context_limit) break;
            const display_len = @min(sr.value.len, 60);
            tw.print("F{d} refs: \"", .{sr.func_label}) catch {};
            // Write only safe chars
            for (sr.value[0..display_len]) |c| {
                if (c >= 0x20 and c <= 0x7E) tw.writeByte(c) catch {} else tw.writeByte('.') catch {};
            }
            tw.writeAll("\"\n") catch {};
        }
    }

    // Section: Import Calls (deduped per function)
    if (imp_refs.items.len > 0) {
        tw.writeAll("\n--- IMPORTS CALLED ---\n") catch {};
        var imp_text_seen = std.StringHashMap(void).init(ctx.allocator);
        defer imp_text_seen.deinit();
        for (imp_refs.items) |ir2| {
            if (text.written().len >= context_limit) break;
            if (imp_text_seen.contains(ir2.imp_name)) continue;
            imp_text_seen.put(ir2.imp_name, {}) catch {};
            tw.print("F{d} calls: {s}\n", .{ ir2.func_label, ir2.imp_name }) catch {};
        }
    }

    // Section: External Callers
    if (external_callers.items.len > 0) {
        tw.writeAll("\n--- CALLERS (outside scope) ---\n") catch {};
        for (external_callers.items) |ec| {
            if (text.written().len >= max_chars) break;
            tw.print("0x{x}", .{ec.caller_addr}) catch {};
            if (ec.name) |n| tw.print(" ({s})", .{n}) catch {};
            tw.print(" -> F{d}\n", .{ec.callee_label}) catch {};
        }
    }

    // Section: Unknowns
    if (unknowns.items.len > 0 and text.written().len < max_chars) {
        tw.writeAll("\n--- UNKNOWNS ---\n") catch {};
        for (unknowns.items) |unk| {
            if (text.written().len >= max_chars) break;
            tw.print("- {s}\n", .{unk}) catch {};
        }
    }

    // For remake view, add structured spec sections
    var purpose_hyps = std.array_list.Managed([]const u8).init(ctx.allocator);
    defer purpose_hyps.deinit();
    if (is_remake and text.written().len < max_chars) {
        tw.writeAll("\n--- PURPOSE HYPOTHESIS ---\n") catch {};
        // Derive from string AND import evidence
        var hypothesis_count: u32 = 0;
        // Scan string refs for domain keywords — count matches, require 2+ to avoid false positives
        var auth_hits: u32 = 0;
        var net_hits: u32 = 0;
        var db_hits: u32 = 0;
        var crypto_hits: u32 = 0;
        var io_hits: u32 = 0;
        for (str_refs.items) |sr| {
            if (sr.value.len < 6) continue; // skip very short strings
            if (containsAnyCI(sr.value, &.{ "password", "auth", "login", "credential", "session" })) auth_hits += 1;
            if (containsAnyCI(sr.value, &.{ "http://", "https://", "socket", "connect", "request" })) net_hits += 1;
            if (containsAnyCI(sr.value, &.{ "CREATE ", "SELECT ", "INSERT ", "DELETE ", "sqlite" })) db_hits += 1;
            if (containsAnyCI(sr.value, &.{ "encrypt", "decrypt", "cipher", "certificate" })) crypto_hits += 1;
            if (containsAnyCI(sr.value, &.{ "fopen", "fclose", "readdir", "mkdir", "chmod" })) io_hits += 1;
        }
        if (auth_hits >= 2 and hypothesis_count < 3) {
            tw.writeAll("Authentication/authorization subsystem.\n") catch {};
            purpose_hyps.append("Authentication/authorization subsystem") catch {};
            hypothesis_count += 1;
        }
        if (net_hits >= 2 and hypothesis_count < 3) {
            tw.writeAll("Network/HTTP handler.\n") catch {};
            purpose_hyps.append("Network/HTTP handler") catch {};
            hypothesis_count += 1;
        }
        if (db_hits >= 2 and hypothesis_count < 3) {
            tw.writeAll("Database operations.\n") catch {};
            purpose_hyps.append("Database operations") catch {};
            hypothesis_count += 1;
        }
        if (crypto_hits >= 2 and hypothesis_count < 3) {
            tw.writeAll("Cryptographic operations.\n") catch {};
            purpose_hyps.append("Cryptographic operations") catch {};
            hypothesis_count += 1;
        }
        if (io_hits >= 2 and hypothesis_count < 3) {
            tw.writeAll("File system operations.\n") catch {};
            purpose_hyps.append("File system operations") catch {};
            hypothesis_count += 1;
        }
        // Fallback to import-based detection
        for (imp_refs.items) |ir3| {
            if (hypothesis_count >= 3) break;
            if (containsAnyCI(ir3.imp_name, &.{ "crypt", "sha", "aes", "ssl", "tls", "sign", "verify" })) {
                tw.writeAll("Calls cryptographic APIs.\n") catch {};
                purpose_hyps.append("Calls cryptographic APIs") catch {};
                hypothesis_count += 1;
                break;
            }
        }
        for (imp_refs.items) |ir3| {
            if (hypothesis_count >= 3) break;
            if (containsAnyCI(ir3.imp_name, &.{ "socket", "connect", "send", "recv", "http", "url" })) {
                tw.writeAll("Calls network APIs.\n") catch {};
                purpose_hyps.append("Calls network APIs") catch {};
                hypothesis_count += 1;
                break;
            }
        }
        if (hypothesis_count == 0) {
            tw.writeAll("Purpose unclear from strings and imports. Inspect get_cfg with include_disassembly=true and follow address references.\n") catch {};
            purpose_hyps.append("Purpose unclear from strings and imports") catch {};
        }

        tw.writeAll("\n--- INTERFACES ---\n") catch {};
        {
            var iface_text_seen = std.StringHashMap(void).init(ctx.allocator);
            defer iface_text_seen.deinit();
            for (imp_refs.items) |ir3| {
                if (iface_text_seen.contains(ir3.imp_name)) continue;
                iface_text_seen.put(ir3.imp_name, {}) catch {};
                tw.print("External: {s} (called by F{d})\n", .{ ir3.imp_name, ir3.func_label }) catch {};
            }
        }

        tw.writeAll("\n--- EVIDENCE ---\n") catch {};
        tw.print("{d} functions, {d} string refs, {d} import calls, {d} external callers\n", .{
            funcs.items.len, str_refs.items.len, imp_refs.items.len, external_callers.items.len,
        }) catch {};
    }

    // Emit text field
    try w.writeAll("\"text\":");
    try json.writeJsonString(w, text.written());

    try w.writeAll(",\"instruction_coverage\":[");
    try w.writeAll(coverage.written());
    try w.writeAll("],\"evidence_note\":\"covered_bytes and complete describe inspected raw instruction slots within reported bounds; decoded_bytes and decode_complete exclude opaque ARM64 fallbacks. No coverage field verifies semantics or source equivalence. linker_start_next_boundary uses a validated linker entry through the next entry or section end; padding and split code may remain. Follow next_call before reconstructing omitted code.\"");

    // Emit stats
    try w.print(",\"functions\":{d},\"string_refs\":{d},\"import_calls\":{d},\"unknowns\":{d}", .{
        funcs.items.len, str_refs.items.len, imp_refs.items.len, unknowns.items.len,
    });
    try w.print(",\"truncated\":{s},\"instruction_evidence_truncated\":{s}", .{
        if (text.written().len >= max_chars or instruction_evidence_truncated) "true" else "false",
        if (instruction_evidence_truncated) "true" else "false",
    });
    if (max_chars_was_clamped) {
        try w.print(",\"max_chars_clamped\":{d}", .{max_chars});
    }
    {
        const cluster_total_found = cluster_callee_found + cluster_caller_found;
        const cluster_omitted = if (cluster_total_found > max_cluster) cluster_total_found - max_cluster else 0;
        if (cluster_omitted > 0) {
            try w.print(",\"cluster_omitted\":{d},\"cluster_total_found\":{d}", .{ cluster_omitted, cluster_total_found });
        }
    }

    // Seed diagnostics
    try w.writeAll(",\"seed_diagnostics\":[");
    for (seed_diags.items, 0..) |sd, si| {
        if (si > 0) try w.writeByte(',');
        try w.writeAll("{\"address\":");
        try json.writeAddress(w, sd.addr);
        try w.print(",\"resolved\":{s},\"confidence\":\"{s}\"}}", .{
            if (sd.resolved) "true" else "false", sd.confidence,
        });
    }
    try w.writeByte(']');

    // For remake view, emit structured JSON fields alongside text
    if (is_remake) {
        // Interfaces: resolved import calls as structured array (deduped by name)
        try w.writeAll(",\"interfaces\":[");
        var iface_seen = std.StringHashMap(void).init(ctx.allocator);
        defer iface_seen.deinit();
        var iface_count: u32 = 0;
        for (imp_refs.items) |ir2| {
            if (iface_seen.contains(ir2.imp_name)) continue;
            iface_seen.put(ir2.imp_name, {}) catch {};
            if (iface_count > 0) try w.writeByte(',');
            try w.writeAll("{\"name\":");
            try json.writeJsonString(w, ir2.imp_name);
            try w.print(",\"called_by\":\"F{d}\"}}", .{ir2.func_label});
            iface_count += 1;
        }
        try w.writeByte(']');

        // Resources: string refs as structured array (deduplicated by value)
        try w.writeAll(",\"resources\":[");
        var res_count: u32 = 0;
        var res_seen = std.StringHashMap(void).init(ctx.allocator);
        defer res_seen.deinit();
        for (str_refs.items) |sr| {
            if (res_count >= 20) break;
            if (res_seen.contains(sr.value)) continue;
            res_seen.put(sr.value, {}) catch {};
            if (res_count > 0) try w.writeByte(',');
            try w.writeAll("{\"type\":\"string\",\"value\":");
            // Emit safe substring
            const safe_len = @min(sr.value.len, 60);
            var safe_buf: [64]u8 = undefined;
            var safe_i: usize = 0;
            for (sr.value[0..safe_len]) |c| {
                if (c >= 0x20 and c <= 0x7E) {
                    safe_buf[safe_i] = c;
                    safe_i += 1;
                }
            }
            try json.writeJsonString(w, safe_buf[0..safe_i]);
            try w.print(",\"ref_by\":\"F{d}\"}}", .{sr.func_label});
            res_count += 1;
        }
        try w.writeByte(']');

        // Evidence summary
        try w.print(",\"evidence_summary\":{{\"functions\":{d},\"string_refs\":{d},\"import_calls\":{d},\"external_callers\":{d}}}", .{
            funcs.items.len, str_refs.items.len, imp_refs.items.len, external_callers.items.len,
        });

        // Emit purpose_hypotheses
        try w.writeAll(",\"purpose_hypotheses\":[");
        for (purpose_hyps.items, 0..) |hyp, hi| {
            if (hi > 0) try w.writeByte(',');
            try json.writeJsonString(w, hyp);
        }
        try w.writeByte(']');
    }

    try w.writeByte('}');

    const result_json = buf.toOwnedSlice() catch return ToolError.OutOfMemory;
    const elapsed = timestampMs(ctx.io) - start_time;
    const resp = json.successResponse(ctx.allocator, "get_semantic_slice", result_json, elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp, .is_error = false, .meta_max_chars = 200_000 };
}

fn passesFilter(mask: u8, bit: u3) bool {
    return mask == 0 or (mask & (@as(u8, 1) << bit)) != 0;
}

fn writeFactJson(w: anytype, kind: []const u8, address: u64, target: u64, confidence: u8, source: []const u8, name: ?[]const u8) !void {
    try w.writeAll("{\"kind\":\"");
    try w.writeAll(kind);
    try w.writeAll("\",\"address\":");
    try json.writeAddress(w, address);
    if (target != 0) {
        try w.writeAll(",\"target\":");
        try json.writeAddress(w, target);
    }
    try w.print(",\"confidence\":{d},\"source\":\"{s}\"", .{ confidence, source });
    if (name) |n| {
        try w.writeAll(",\"name\":");
        try json.writeJsonString(w, n);
    }
    try w.writeByte('}');
}

// ============================================================================
// get_hardening_report handler (#29)
// ============================================================================

fn handleGetHardeningReport(ctx: ToolContext, params: std.json.Value) ToolError!ToolResult {
    const start_ts = timestampMs(ctx.io);
    const doc_id: u64 = resolveDocId(ctx, params) orelse {
        return docNotFoundErrorFull(ctx, "get_hardening_report", params);
    };
    const entry = ctx.store.get(doc_id) orelse return docNotFoundError(ctx, "get_hardening_report");
    const doc = &entry.doc;

    // NX: no segment with both write and execute (W^X violation)
    var has_nx = true;
    var has_w_xor_x = true;
    for (doc.segments) |seg| {
        if (seg.permissions.write and seg.permissions.execute) {
            has_w_xor_x = false;
            has_nx = false;
        }
    }

    // Canaries: check for __stack_chk_fail or __stack_chk_guard in imports
    var has_canaries = false;
    var has_fortify = false;
    for (doc.imports.items) |imp| {
        if (std.mem.indexOf(u8, imp.name, "__stack_chk_fail") != null or
            std.mem.indexOf(u8, imp.name, "__stack_chk_guard") != null)
        {
            has_canaries = true;
        }
        // FORTIFY_SOURCE: *_chk variants (memcpy_chk, sprintf_chk, etc.)
        if (imp.name.len > 4 and std.mem.endsWith(u8, imp.name, "_chk")) {
            has_fortify = true;
        }
    }

    // RELRO level
    const relro_str: []const u8 = if (doc.relro_full) "full" else if (doc.has_relro) "partial" else "none";

    // Build JSON response
    var buf = std.Io.Writer.Allocating.init(ctx.allocator);
    const w = &buf.writer;
    w.writeAll("{\"nx\":") catch {};
    w.writeAll(if (has_nx) "true" else "false") catch {};
    w.writeAll(",\"w_xor_x\":") catch {};
    w.writeAll(if (has_w_xor_x) "true" else "false") catch {};
    w.writeAll(",\"pie\":") catch {};
    w.writeAll(if (doc.is_pie) "true" else "false") catch {};
    w.writeAll(",\"relro\":\"") catch {};
    w.writeAll(relro_str) catch {};
    w.writeAll("\",\"canaries\":") catch {};
    w.writeAll(if (has_canaries) "true" else "false") catch {};
    w.writeAll(",\"fortify\":") catch {};
    w.writeAll(if (has_fortify) "true" else "false") catch {};
    w.writeAll(",\"stripped\":") catch {};
    w.writeAll(if (doc.is_stripped) "true" else "false") catch {};
    w.writeAll(",\"pac\":") catch {};
    w.writeAll(if (doc.has_pac) "true" else "false") catch {};
    w.writeAll(",\"bti\":") catch {};
    w.writeAll(if (doc.has_bti) "true" else "false") catch {};
    w.writeAll(",\"format\":\"") catch {};
    w.writeAll(switch (doc.format) {
        .macho => "macho",
        .elf => "elf",
        .pe => "pe",
        .zip => "zip",
        .pbp => "pbp",
        .psx_exe => "psx_exe",
        .raw => "raw",
    }) catch {};
    w.writeAll("\"}") catch {};

    const elapsed = timestampMs(ctx.io) - start_ts;
    const resp = json.successResponse(ctx.allocator, "get_hardening_report", buf.written(), elapsed) catch return ToolError.OutOfMemory;
    return .{ .json_response = resp };
}

// ============================================================================
// Tests — Rust symbol demangling
// ============================================================================

test "demangle Rust legacy" {
    const alloc = std.testing.allocator;

    // Basic path with hash suffix
    const r1 = tryDemangleRust(alloc, "_ZN4core6option6unwrap17h1234567890abcdefE").?;
    defer alloc.free(r1);
    try std.testing.expectEqualStrings("core::option::unwrap", r1);

    // With $ escape sequences
    const r2 = tryDemangleRust(alloc, "_ZN4core6option15Option$LT$T$GT$6unwrap17h1234567890abcdefE").?;
    defer alloc.free(r2);
    try std.testing.expectEqualStrings("core::option::Option<T>::unwrap", r2);

    // Mach-O double underscore prefix
    const r3 = tryDemangleRust(alloc, "__ZN3std2io5Write9write_all17habcdef1234567890E").?;
    defer alloc.free(r3);
    try std.testing.expectEqualStrings("std::io::Write::write_all", r3);

    // Should NOT match C++ (no $ escapes)
    try std.testing.expect(tryDemangleRust(alloc, "__ZNSt3__115recursive_mutexD1Ev") == null);

    // Multiple escapes: <core::fmt::Arguments as core::fmt::Display>::fmt
    const r4 = tryDemangleRust(alloc, "_ZN68_$LT$core..fmt..Arguments$u20$as$u20$core..fmt..Display$GT$3fmt17h0000000000000000E").?;
    defer alloc.free(r4);
    try std.testing.expectEqualStrings("<core::fmt::Arguments as core::fmt::Display>::fmt", r4);

    // Simpler impl block: <T>::method  (padding underscore, no hash)
    const r5 = tryDemangleRust(alloc, "_ZN37_$LT$alloc..vec..Vec$LT$T$GT$$GT$3newE").?;
    defer alloc.free(r5);
    try std.testing.expectEqualStrings("<alloc::vec::Vec<T>>::new", r5);

    // Impl with embedded method and hash suffix stripped
    const r6 = tryDemangleRust(alloc, "_ZN89_$LT$core..option..Option$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17habcdef0123456789E").?;
    defer alloc.free(r6);
    try std.testing.expectEqualStrings("<core::option::Option<T> as core::fmt::Debug>::fmt", r6);
}

test "demangle C++ template with substitution refs (no empty slots)" {
    // Arena allocator: tryDemangleCpp accumulates intermediate template/type
    // buffers that the current implementation doesn't free incrementally; an
    // arena bounds those allocations to the test scope.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Regression: chrono::time_point<system_clock, duration<long long, ratio<...>>>
    // The inner ratio<Ll1, Ll1000000000> uses substitution references (S_) for
    // long. Before the fix the template parser emitted ", , " around them,
    // producing patterns like "ratio<,,>".
    const mangled = "_ZNSt3__16chrono10time_pointINS0_12system_clockENS0_8durationIxNS_5ratioILl1ELl1000000000EEEEEED1Ev";
    if (tryDemangleCpp(alloc, mangled)) |r| {
        // No empty template arg slots
        try std.testing.expect(std.mem.indexOf(u8, r, ",,") == null);
        try std.testing.expect(std.mem.indexOf(u8, r, "<,") == null);
        try std.testing.expect(std.mem.indexOf(u8, r, ", >") == null);
    }
    // If demangler returned null, that's acceptable (the symbol uses features
    // we don't fully support yet) — but if it DID demangle, the output must
    // not contain orphaned commas.
}

test {
    _ = @import("test_loops.zig");
    _ = @import("test_register_flow.zig");
    _ = @import("test_context_flow.zig");
    _ = @import("test_execution_view.zig");
    _ = @import("test_branch_predicate.zig");
}

test "opaque ARM64 pack allocation failure does not count an uncommitted slot" {
    const t = std.testing;
    var failing = t.FailingAllocator.init(t.allocator, .{});
    var text = try std.Io.Writer.Allocating.initCapacity(failing.allocator(), 32);
    defer text.deinit();
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    var gaps: usize = 0;
    // The instruction prefix fits, but its opaque warning requires growth.
    try t.expectError(error.WriteFailed, writeArm64PackInstruction(&text.writer, &.{ 0xcc, 0xcc, 0xcc, 0xcc }, 0x1000, 0x1000, &gaps, null));
    try t.expect(failing.has_induced_failure);
    try t.expect(text.written().len > 0);
    try t.expectEqual(@as(usize, 0), gaps);
    const covered_bytes: u64 = 0;
    try t.expectEqual(@as(u64, 0), covered_bytes - @as(u64, @intCast(gaps)) * 4);
}

test "load finalization OOM discards unpublished owned and borrowed documents" {
    const t = std.testing;
    for ([_]bool{ true, false }) |merge_failure| {
        for ([_]bool{ true, false }) |owns_data| {
            // Fail precisely in xref merge or final store publication; the
            // analysis/database allocator remains available in both cases.
            var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
            var store = DocumentStore.init(if (merge_failure) t.allocator else failing.allocator(), t.io);
            defer store.deinit();
            var arena = std.heap.ArenaAllocator.init(t.allocator);
            defer arena.deinit();
            const borrowed = [_]u8{ 0x20, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6 }; // BL external; RET
            const backing = if (owns_data) try t.allocator.dupe(u8, &.{ 0, 0, 0, 0, 0x20, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6 }) else &borrowed;
            const viewed = if (owns_data) backing[4..] else backing;
            const path = try t.allocator.dupe(u8, "finalize-oom");
            const entry = try t.allocator.create(DocumentEntry);
            entry.* = .{ .doc = types.Document.init(t.allocator, 1, path, viewed), .db = Database.init(t.allocator, t.io), .owns_data = owns_data };
            finalizeRawDocument(t.allocator, &entry.doc, viewed, .arm64, 0x1000, 0x1000);
            if (merge_failure) {
                entry.db.xrefs = xref_mod.XrefTracker.init(failing.allocator(), t.io);
            } else {
                // Include a pre-existing allocation in both indices for teardown.
                try entry.db.xrefs.addXref(0x1000, 0x2000, .call);
            }
            const ctx = ToolContext{ .io = t.io, .store = &store, .session_id = "finalize-oom", .allocator = arena.allocator() };
            try t.expectError(error.OutOfMemory, finalizeLoad(ctx, entry, backing, null));
            try t.expect(failing.has_induced_failure);
            try t.expectEqual(@as(usize, 0), store.documents.count());
            // std.testing.allocator verifies all owned state was freed, including
            // the original backing allocation rather than its embedded subview.
            // Borrowed stack bytes must remain intact and must not be freed.
            try t.expectEqual(@as(u8, 0x20), borrowed[0]);
        }
    }
}

test "load options reject misplaced and unsupported overrides before loading" {
    const samples = [_][]const u8{
        "{\"arch\":\"x86_64\"}",             "{\"base\":4096}",     "{\"entry\":4096}",                     "{\"fat_arch\":\"arm64\"}",
        "{\"analysis\":\"full\"}",           "{\"budget_ms\":100}", "{\"options\":{\"arch\":\"unknown\"}}", "{\"options\":{\"entry\":-1}}",
        "{\"options\":{\"base\":\"4096\"}}",
    };
    for (samples) |sample| {
        const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, sample, .{});
        defer parsed.deinit();
        try std.testing.expect(invalidLoadOptions(parsed.value) != null);
    }
    const valid = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"options\":{\"arch\":\"arm64\",\"base\":4096,\"entry\":4100}}", .{});
    defer valid.deinit();
    try std.testing.expect(invalidLoadOptions(valid.value) == null);
    var doc: types.Document = undefined;
    var opts: types.LoadOptions = .{};
    parseLoadOptions(valid.value, &doc, &opts);
    try std.testing.expectEqual(types.Arch.arm64, opts.arch.?);
    try std.testing.expectEqual(@as(u64, 4096), opts.base.?);
    try std.testing.expectEqual(@as(u64, 4100), opts.entry.?);
}
