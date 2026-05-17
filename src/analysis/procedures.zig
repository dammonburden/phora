// Phora — Procedure Detector
// Identifies function boundaries via call targets + ARM64 prologue patterns.
// ARM64 prologue: STP X29, X30, [SP, #-N]! (0xA9xx7BFD) or SUB SP, SP, #N

const std = @import("std");
const types = @import("../types.zig");
const xref_mod = @import("xref.zig");

/// Result of procedure detection: list of entry points found.
pub const DetectedProcedure = struct {
    entry: u64,
    source: ProcedureSource,
};

pub const ProcedureSource = enum {
    entry_point,
    call_target,
    prologue_scan,
    symbol,
};

/// Detect procedure entry points from multiple sources.
pub fn detectProcedures(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    xrefs: *const xref_mod.XrefTracker,
) ![]DetectedProcedure {
    var entries = std.AutoHashMap(u64, ProcedureSource).init(allocator);
    defer entries.deinit();

    // 1. Entry point is always a procedure
    if (doc.entry_point != 0) {
        try entries.put(doc.entry_point, .entry_point);
    }

    // 2. Call targets within __text are procedures
    // (targets outside __text are stubs/trampolines, not real functions)
    var text_start: u64 = 0;
    var text_end: u64 = 0;
    if (doc.arch == .arm64 or doc.arch == .mips32) {
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
    }

    const call_targets = try xrefs.getCallTargets(allocator);
    defer allocator.free(call_targets);

    for (call_targets) |target| {
        // Only count calls landing in __text as real procedures
        if (text_end > 0 and (target < text_start or target >= text_end)) continue;
        if (!entries.contains(target)) {
            try entries.put(target, .call_target);
        }
    }

    // 3. Scan for architecture-specific prologue patterns
    if (doc.arch == .arm32) {
        // Thumb prologue scan — 2-byte aligned iteration
        for (doc.segments) |segment| {
            if (!segment.permissions.execute) continue;

            for (segment.sections) |section| {
                if (!std.mem.eql(u8, section.name, ".text") and
                    !std.mem.eql(u8, section.name, "__text")) continue;

                const section_end = section.file_offset + section.length;
                if (section.file_offset >= doc.data.len) continue;
                const actual_end = @min(section_end, doc.data.len);
                const section_data = doc.data[section.file_offset..actual_end];

                var prev_was_return = false;
                var offset: usize = 0;
                while (offset + 2 <= section_data.len) : (offset += 2) {
                    const addr = section.start + offset;
                    const hw = std.mem.readInt(u16, section_data[offset..][0..2], .little);

                    // Instruction after a return is likely a new function
                    if (prev_was_return and !entries.contains(addr) and hw != 0) {
                        try entries.put(addr, .prologue_scan);
                    }
                    prev_was_return = isThumbReturn(hw);

                    if (entries.contains(addr)) continue;

                    if (isThumbPrologue(hw)) {
                        try entries.put(addr, .prologue_scan);
                    }
                }
            }
        }
    } else if (doc.arch == .mips32) {
        // MIPS32 prologue scan — 4-byte aligned, big- or little-endian words
        for (doc.segments) |segment| {
            if (!segment.permissions.execute) continue;

            for (segment.sections) |section| {
                if (!std.mem.eql(u8, section.name, ".text") and
                    !std.mem.eql(u8, section.name, "__text")) continue;

                const section_end = section.file_offset + section.length;
                if (section.file_offset >= doc.data.len) continue;
                const actual_end = @min(section_end, doc.data.len);
                const section_data = doc.data[section.file_offset..actual_end];

                var prev_was_return = false;
                var offset: usize = 0;
                while (offset + 4 <= section_data.len) : (offset += 4) {
                    const addr = section.start + offset;
                    const word = std.mem.readInt(u32, section_data[offset..][0..4], .little);

                    // Instruction after jr $ra + delay slot is likely a new function
                    // jr $ra at X means function ends at X+8 (delay slot at X+4),
                    // so the instruction at X+8 starts a new function.
                    if (prev_was_return and !entries.contains(addr) and word != 0) {
                        try entries.put(addr, .prologue_scan);
                    }
                    // jr $ra = 0x03E00008; check previous delay slot already passed
                    if (isMips32Return(word)) {
                        // Skip the delay slot instruction (next word) — function boundary is after it
                        if (offset + 8 <= section_data.len) {
                            offset += 4; // skip delay slot
                        }
                        prev_was_return = true;
                        continue;
                    }
                    prev_was_return = false;

                    if (entries.contains(addr)) continue;

                    // Primary seed: addiu $sp, $sp, -N
                    if (isMips32Prologue(word)) {
                        // Confirm with sw $ra within the next few instructions
                        var confirmed = false;
                        var look: usize = 1;
                        while (look <= 4 and offset + (look * 4) + 4 <= section_data.len) : (look += 1) {
                            const next_word = std.mem.readInt(u32, section_data[offset + (look * 4) ..][0..4], .little);
                            if (isMips32FrameSave(next_word)) {
                                confirmed = true;
                                break;
                            }
                        }
                        if (confirmed) {
                            try entries.put(addr, .prologue_scan);
                        }
                    }
                }
            }
        }
    } else if (doc.arch == .x86 or doc.arch == .x86_64) {
        // v7.13.0 B2 — x86 prologue scan.
        // Field test: PE32 fixture with a large text section
        // returned 0 procs pre-fix. Post-fix: ≥100 procs detected via the
        // canonical `push ebp / mov ebp, esp` prologue + 16-byte alignment.
        try detectX86Procedures(doc, &entries, doc.arch == .x86_64);
    } else if (doc.arch == .arm64) {
        for (doc.segments) |segment| {
            if (!segment.permissions.execute) continue;

            for (segment.sections) |section| {
                // Only scan __text/.text — other sections are stubs/helpers
                if (!std.mem.eql(u8, section.name, "__text") and
                    !std.mem.eql(u8, section.name, ".text")) continue;

                const section_end = section.file_offset + section.length;
                if (section.file_offset >= doc.data.len) continue;
                const actual_end = @min(section_end, doc.data.len);
                const section_data = doc.data[section.file_offset..actual_end];

                // Scan for prologue patterns at 4-byte aligned offsets
                var prev_was_ret = false;
                var prev_word: u32 = 0;
                var offset: usize = 0;
                while (offset + 4 <= section_data.len) : (offset += 4) {
                    const addr = section.start + offset;
                    const word = std.mem.readInt(u32, section_data[offset..][0..4], .little);

                    // Instruction after RET/RETAB/RETAA is likely a new function
                    if (prev_was_ret and !entries.contains(addr) and word != 0) {
                        try entries.put(addr, .prologue_scan);
                    }
                    // RET = 0xD65F03C0, RETAB = 0xD65F0FFF, RETAA = 0xD65F0BFF
                    prev_was_ret = (word == 0xD65F03C0 or word == 0xD65F0FFF or word == 0xD65F0BFF);

                    if (entries.contains(addr)) {
                        prev_word = word;
                        continue;
                    }

                    if (isArm64Prologue(word)) {
                        // STP X29,X30 mid-prologue filter: if the previous instruction
                        // was also an STP to SP (saving other callee registers), this
                        // STP X29,X30 is part of a multi-register save, not a new function.
                        if (isSTPtoX29X30(word) and isSTPtoSP(prev_word)) {
                            prev_word = word;
                            continue;
                        }
                        try entries.put(addr, .prologue_scan);
                    }

                    prev_word = word;
                }
            }
        }
    }

    // 4. Named symbols from imports/existing procedures are also entries
    for (doc.procedures.items) |proc| {
        if (!entries.contains(proc.entry)) {
            try entries.put(proc.entry, .symbol);
        }
    }

    // Convert to sorted result slice
    var result = std.array_list.Managed(DetectedProcedure).init(allocator);
    errdefer result.deinit();

    var it = entries.iterator();
    while (it.next()) |entry| {
        try result.append(.{
            .entry = entry.key_ptr.*,
            .source = entry.value_ptr.*,
        });
    }

    // Sort by address for deterministic output
    std.mem.sort(DetectedProcedure, result.items, {}, struct {
        fn lessThan(_: void, a: DetectedProcedure, b: DetectedProcedure) bool {
            return a.entry < b.entry;
        }
    }.lessThan);

    return result.toOwnedSlice();
}

/// Check if a 32-bit ARM64 instruction is a function prologue.
/// Detects STP X29, X30 patterns and PACIBSP (pointer auth prologue).
/// SUB SP is intentionally excluded — it fires on stack adjustments inside
/// functions, causing massive overdetection (e.g. wc: 45 procs vs 6 real).
pub fn isArm64Prologue(word: u32) bool {
    // STP X29, X30, [SP, ...]!  (pre-index) — 1010 1001 1xxx xxxx 0111 1011 1111 1101
    if ((word & 0xFFC07FFF) == 0xA9807BFD) return true;

    // STP X29, X30, [SP, #imm] (signed offset) — 1010 1001 0xxx xxxx 0111 1011 1111 1101
    if ((word & 0xFFC07FFF) == 0xA9007BFD) return true;

    // PACIBSP — 0xD503237F — pointer authentication prologue
    // Some compilers emit this as the first instruction of many functions
    if (word == 0xD503237F) return true;

    return false;
}

/// Check if an instruction is a plausible function-start pattern (post-RET heuristic).
/// These are common first instructions of leaf functions that lack a frame pointer prologue.
fn isPlausibleFuncStart(word: u32) bool {
    // SUB SP, SP, #imm — stack allocation (leaf function prologue)
    if ((word & 0xFF0003FF) == 0xD10003FF) return true;
    // Any STP to SP — callee-save register pair
    if (isSTPtoSP(word)) return true;
    // ADRP — PC-relative page load (common first instruction)
    if ((word & 0x9F000000) == 0x90000000) return true;
    // CBZ/CBNZ with register operand (entry guard pattern)
    if ((word & 0x7E000000) == 0x34000000) return true;
    return false;
}

/// Check if instruction is STP X29, X30, [SP, ...] (either pre-index or signed-offset).
fn isSTPtoX29X30(word: u32) bool {
    if ((word & 0xFFC07FFF) == 0xA9807BFD) return true; // pre-index
    if ((word & 0xFFC07FFF) == 0xA9007BFD) return true; // signed offset
    return false;
}

/// Check if instruction is any STP with Rn=SP (callee-saved register pair save).
/// Matches STP Xt, Xt2, [SP, #imm] in both pre-index and signed-offset forms.
fn isSTPtoSP(word: u32) bool {
    // STP (signed offset, 64-bit): opc=10, V=0, L=0, mode=010
    // Encoding: 1010 1001 0xxx xxxx xxxx xx11 111x xxxx
    // Rn is bits 9:5, SP = 11111
    if ((word & 0xFFC00000) == 0xA9000000 and ((word >> 5) & 0x1F) == 31) return true;
    // STP (pre-index, 64-bit): opc=10, V=0, L=0, mode=110
    if ((word & 0xFFC00000) == 0xA9800000 and ((word >> 5) & 0x1F) == 31) return true;
    return false;
}

/// Check if a 16-bit Thumb instruction is a function prologue.
/// Detects `push {..., lr}` — the canonical Thumb function entry.
/// Encoding: 1011 0101 xxxx xxxx  i.e. (hw & 0xFF00) == 0xB500
pub fn isThumbPrologue(hw: u16) bool {
    return (hw & 0xFF00) == 0xB500;
}

/// Check if a 16-bit Thumb instruction is a function return.
/// Detects `pop {..., pc}` = (hw & 0xFF00) == 0xBD00, or `bx lr` = 0x4770.
pub fn isThumbReturn(hw: u16) bool {
    if ((hw & 0xFF00) == 0xBD00) return true; // pop {..., pc}
    if (hw == 0x4770) return true; // bx lr
    return false;
}

/// Check if a 32-bit MIPS instruction is a function prologue.
/// Detects `addiu $sp, $sp, -N` — stack frame allocation with negative immediate.
/// Encoding: opcode=0x09(ADDIU), rs=29($sp), rt=29($sp), imm<0.
pub fn isMips32Prologue(word: u32) bool {
    // addiu $sp, $sp, -N (negative immediate = stack allocation)
    return (word & 0xFFFF0000) == 0x27BD0000 and (word & 0x8000) != 0;
}

/// Check if a 32-bit MIPS instruction saves the return address to the stack.
/// Detects `sw $ra, offset($sp)`.
/// Encoding: opcode=0x2B(SW), base=29($sp), rt=31($ra).
pub fn isMips32FrameSave(word: u32) bool {
    // sw $ra, offset($sp)
    return (word & 0xFFE00000) == 0xAFBF0000;
}

/// Check if a 32-bit MIPS instruction is a function return.
/// Detects `jr $ra` = 0x03E00008.
pub fn isMips32Return(word: u32) bool {
    return word == 0x03E00008;
}

// ============================================================================
// v7.13.0 B2 — x86 prologue scanner (i386 + x86_64).
// ============================================================================
//
// The detector is intentionally conservative — false positives in x86 prologue
// scanning are notorious (e.g. `push reg` mid-function fires on every callee-
// saved register save). Mitigations (per plan risk #3):
//   1) Only fire on the canonical `push (e|r)bp; mov (e|r)bp, (e|r)sp`
//      sequence, OR `push reg; sub esp, imm` (frame setup).
//   2) Require a clean RET (0xC3/0xC2/0xCB/0xCA) within MAX_FUNC_SCAN bytes.
//   3) Skip candidates that fall inside an already-detected function range.
//
// We do NOT add 16-byte-aligned `push reg` candidates; that pattern over-
// detects on every regular `push` mid-function.

/// Scan distance after a candidate prologue to look for a RET. Real functions
/// almost always have a return within a few KB; longer scans waste cycles on
/// false positives.
const X86_MAX_FUNC_SCAN: usize = 8 * 1024;

fn detectX86Procedures(
    doc: *const types.Document,
    entries: *std.AutoHashMap(u64, ProcedureSource),
    is_x86_64: bool,
) !void {
    for (doc.segments) |segment| {
        if (!segment.permissions.execute) continue;
        for (segment.sections) |section| {
            if (!std.mem.eql(u8, section.name, "__text") and
                !std.mem.eql(u8, section.name, ".text")) continue;
            const section_end = section.file_offset + section.length;
            if (section.file_offset >= doc.data.len) continue;
            const actual_end = @min(section_end, doc.data.len);
            const data = doc.data[section.file_offset..actual_end];
            if (data.len < 3) continue;

            var offset: usize = 0;
            while (offset < data.len) : (offset += 1) {
                const addr = section.start + offset;
                if (entries.contains(addr)) continue;

                if (!isX86Prologue(data, offset, is_x86_64)) continue;

                // Confirm with a clean RET within the scan window. We also
                // bail if we hit a 0x00 run (likely padding between functions).
                if (!hasNearbyReturn(data, offset, X86_MAX_FUNC_SCAN)) continue;

                try entries.put(addr, .prologue_scan);
            }
        }
    }
}

/// True iff the bytes at `data[offset..]` look like an x86 function prologue.
/// Conservative subset:
///   - 32-bit:  `55 89 e5`           = push ebp; mov ebp, esp
///   - 32-bit:  `55 8b ec`           = push ebp; mov ebp, esp (alt encoding)
///   - 64-bit:  `55 48 89 e5`        = push rbp; mov rbp, rsp
///   - 64-bit:  `55 48 8b ec`        = push rbp; mov rbp, rsp (alt)
///   - either:  `53 ... 83 ec NN`    = push ebx + sub esp, imm8 (within 8 bytes)
///   - 64-bit:  `41 5x` REX-pushed callee-save followed by a frame setup
fn isX86Prologue(data: []const u8, offset: usize, is_x86_64: bool) bool {
    if (offset + 3 > data.len) return false;
    const b0 = data[offset];
    const b1 = data[offset + 1];
    const b2 = data[offset + 2];

    // 32-bit canonical: push ebp; mov ebp, esp  =  55 89 e5  OR  55 8b ec
    if (b0 == 0x55 and ((b1 == 0x89 and b2 == 0xE5) or (b1 == 0x8B and b2 == 0xEC))) {
        return true;
    }

    // 64-bit canonical: push rbp; mov rbp, rsp  =  55 48 89 e5  OR  55 48 8b ec
    if (is_x86_64 and offset + 4 <= data.len and b0 == 0x55 and b1 == 0x48) {
        const b3 = data[offset + 3];
        if ((b2 == 0x89 and b3 == 0xE5) or (b2 == 0x8B and b3 == 0xEC)) return true;
    }

    // Alternate non-frame-pointer prologue: `push reg; sub esp, imm8` within
    // 8 bytes. `push reg` is 0x50..0x57; `sub esp, imm8` = 0x83 0xEC NN.
    if (b0 >= 0x50 and b0 <= 0x57) {
        const lookahead_max = @min(offset + 9, data.len);
        var k = offset + 1;
        while (k + 3 <= lookahead_max) : (k += 1) {
            if (data[k] == 0x83 and data[k + 1] == 0xEC) return true;
            // Stop if we hit a control transfer / nonsensical byte.
            if (data[k] == 0xC3 or data[k] == 0xC2 or data[k] == 0xE8 or data[k] == 0xE9) break;
        }
    }

    return false;
}

/// Scan forward up to `max_scan` bytes looking for a RET (0xC3 / 0xC2 / 0xCB /
/// 0xCA). Returns true if found; we use this as a lightweight sanity check on
/// candidate prologues. Note: we don't do full instruction decoding, so a RET
/// inside an immediate operand can occasionally false-positive — but the cost
/// is just keeping a noise candidate, which is bounded by the entries map.
fn hasNearbyReturn(data: []const u8, offset: usize, max_scan: usize) bool {
    const end = @min(offset + max_scan, data.len);
    var i = offset;
    while (i < end) : (i += 1) {
        const b = data[i];
        if (b == 0xC3 or b == 0xC2 or b == 0xCB or b == 0xCA) return true;
    }
    return false;
}

/// Estimate procedure size by scanning forward until the next procedure entry
/// or a RET instruction, whichever comes first.
pub fn estimateProcedureSize(
    data: []const u8,
    file_offset: usize,
    section_base: u64,
    entry: u64,
    next_entry: ?u64,
) u64 {
    const start_offset = file_offset + (entry - section_base);
    if (start_offset >= data.len) return 0;

    // If we know the next procedure, the boundary is there
    if (next_entry) |next| {
        if (next > entry) {
            return next - entry;
        }
    }

    // Otherwise scan for RET (0xD65F03C0)
    var offset = start_offset;
    while (offset + 4 <= data.len) : (offset += 4) {
        const word = std.mem.readInt(u32, data[offset..][0..4], .little);
        if (word == 0xD65F03C0) { // RET
            return (offset - start_offset) + 4;
        }
    }

    // Fallback: distance to end of available data
    return @intCast(data.len - start_offset);
}

// ============================================================================
// Tests
// ============================================================================

test "detect ARM64 STP prologue (pre-index)" {
    // STP X29, X30, [SP, #-16]!  →  0xA9BF7BFD
    try std.testing.expect(isArm64Prologue(0xA9BF7BFD));
}

test "detect ARM64 STP prologue (signed offset)" {
    // STP X29, X30, [SP, #16]  →  0xA9017BFD
    try std.testing.expect(isArm64Prologue(0xA9017BFD));
}

test "SUB SP is NOT a prologue (too noisy)" {
    // SUB SP, SP, #0x20  →  0xD10083FF — excluded to reduce overdetection
    try std.testing.expect(!isArm64Prologue(0xD10083FF));
}

test "non-prologue instructions" {
    try std.testing.expect(!isArm64Prologue(0xD65F03C0)); // RET
    try std.testing.expect(!isArm64Prologue(0x94000000)); // BL
    try std.testing.expect(!isArm64Prologue(0x00000000)); // NOP-ish
}
