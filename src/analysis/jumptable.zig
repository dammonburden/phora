// Phora — Switch / Jump-Table Recovery (W3, v7.8.0)
//
// When a function ends in an indirect branch (br xN, jmp [table+rax*8],
// jr $t9), figure out whether the compiler emitted a switch jump table and,
// if so, recover (table_addr, entry_count, entry_width, cases).
//
// Conservative by design: we'd rather miss a switch (return null) than
// invent fake case targets. Each pattern matcher is deliberately strict
// about register flow, instruction order, and operand shape.
//
// Patterns covered (per arch):
//   ARM64
//     - tbb / tbh: adr + ldrb|ldrh + add (lsl #2) + br        — relative
//     - absolute 8-byte: adrp + add + ldr [base, x?, lsl #3] + br
//   x86_64
//     - 4-byte rip-relative: lea rX,[rip+T]; movsxd rY,[rX+rZ*4]; add rY,rX; jmp rY
//     - 8-byte absolute:     lea rX,[rip+T]; mov  rY,[rX+rZ*8]; jmp rY
//     - direct:              jmp qword ptr [rZ*8 + T]
//   MIPS32
//     - sll; lui; addu; lw; jr — absolute 4-byte table
//
// All access into binary_data is bounds-checked. Out-of-range reads or
// pattern mismatches yield null. Allocation failures bubble up via !.

const std = @import("std");
const types = @import("../types.zig");

pub const JumpTableCase = struct {
    /// Case value (index or specific constant). For dense tables this is
    /// just the table index; sparse-value reconstruction is out of scope.
    value: i64,
    /// Branch target address.
    target: u64,
};

pub const JumpTable = struct {
    /// Address of the indirect branch instruction itself.
    branch_addr: u64,
    /// Address of the jump-table data in the binary.
    table_addr: u64,
    entry_count: u32,
    /// Bytes per entry: 1, 2, 4, or 8.
    entry_width: u8,
    /// True if entries are full addresses (4 or 8 bytes).
    /// False for relative encodings (ARM64 tbb/tbh — entries are byte offsets
    /// from a base, scaled by 4; x86_64 4-byte form — signed offsets from
    /// table_addr).
    entries_are_absolute: bool,
    /// For relative tables: the base from which entries are offsets.
    /// For absolute tables: 0 (unused).
    base_addr: u64,
    /// Resolved cases. Length == entry_count when fully resolved.
    cases: []JumpTableCase,
    /// Where index-out-of-range goes (the b.hi/ja fall-through), if known.
    default_target: ?u64 = null,
};

// ============================================================================
// Public entry point
// ============================================================================

pub fn detect(
    allocator: std.mem.Allocator,
    arch: types.Arch,
    binary_data: []const u8,
    instructions: []const types.Instruction,
    branch_idx: usize,
    image_base: u64,
) !?JumpTable {
    if (branch_idx >= instructions.len) return null;
    return switch (arch) {
        .arm64 => try detectArm64(allocator, binary_data, instructions, branch_idx, image_base),
        .x86_64 => try detectX86_64(allocator, binary_data, instructions, branch_idx, image_base),
        .mips32 => try detectMips32(allocator, binary_data, instructions, branch_idx, image_base),
        .arm32, .x86 => null, // not yet handled
    };
}

// ============================================================================
// Shared helpers
// ============================================================================

const max_lookback: usize = 20;

fn lookbackStart(branch_idx: usize) usize {
    if (branch_idx > max_lookback) return branch_idx - max_lookback;
    return 0;
}

fn opText(inst: *const types.Instruction) []const u8 {
    return inst.operands_buf[0..inst.operands_len];
}

fn mnemEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        const ca = std.ascii.toLower(a[i]);
        const cb = std.ascii.toLower(b[i]);
        if (ca != cb) return false;
    }
    return true;
}

fn parseHex(text: []const u8) ?u64 {
    if (std.mem.indexOf(u8, text, "0x")) |idx| {
        var i: usize = idx + 2;
        const start = i;
        while (i < text.len) : (i += 1) {
            const c = text[i];
            const ok = (c >= '0' and c <= '9') or
                (c >= 'a' and c <= 'f') or
                (c >= 'A' and c <= 'F');
            if (!ok) break;
        }
        if (i > start) return std.fmt.parseInt(u64, text[start..i], 16) catch null;
    }
    return null;
}

/// Read N entries of `width` bytes each from `binary_data` starting at file
/// offset `(table_addr - image_base)`. Returns null on any out-of-range.
fn readTable(
    allocator: std.mem.Allocator,
    binary_data: []const u8,
    image_base: u64,
    table_addr: u64,
    entry_count: u32,
    entry_width: u8,
    /// For relative tables, scale (e.g. ARM64 tbb scales offsets by 4).
    rel_scale: u32,
    base_addr: u64,
    is_signed: bool,
    is_absolute: bool,
) !?[]JumpTableCase {
    if (table_addr < image_base) return null;
    const file_off_u64 = table_addr - image_base;
    if (file_off_u64 > std.math.maxInt(usize)) return null;
    const file_off: usize = @intCast(file_off_u64);
    const total_u64: u64 = @as(u64, entry_count) * @as(u64, entry_width);
    if (total_u64 > std.math.maxInt(usize)) return null;
    const total: usize = @intCast(total_u64);
    if (file_off + total > binary_data.len) return null;

    var cases = try allocator.alloc(JumpTableCase, entry_count);
    errdefer allocator.free(cases);

    var i: u32 = 0;
    while (i < entry_count) : (i += 1) {
        const off = file_off + @as(usize, i) * @as(usize, entry_width);
        const slice = binary_data[off..][0..entry_width];

        const raw: i64 = switch (entry_width) {
            1 => if (is_signed)
                @as(i64, @as(i8, @bitCast(slice[0])))
            else
                @as(i64, @as(u8, slice[0])),
            2 => blk: {
                const v = std.mem.readInt(u16, slice[0..2], .little);
                break :blk if (is_signed)
                    @as(i64, @as(i16, @bitCast(v)))
                else
                    @as(i64, v);
            },
            4 => blk: {
                const v = std.mem.readInt(u32, slice[0..4], .little);
                break :blk if (is_signed)
                    @as(i64, @as(i32, @bitCast(v)))
                else
                    @as(i64, v);
            },
            8 => blk: {
                const v = std.mem.readInt(u64, slice[0..8], .little);
                break :blk @as(i64, @bitCast(v));
            },
            else => return null,
        };

        const target: u64 = if (is_absolute)
            @as(u64, @bitCast(raw))
        else
            base_addr +% (@as(u64, @bitCast(raw)) *% @as(u64, rel_scale));

        cases[i] = .{ .value = @as(i64, i), .target = target };
    }
    return cases;
}

/// Walk backward looking for `cmp Wn, #imm` immediately followed
/// (anywhere later, before branch_idx) by `b.hi`/`b.cs`/`b.gt`. Returns the
/// immediate as the entry-count bound (count = imm + 1 for b.hi style;
/// imm for b.cs style — we use imm + 1 conservatively; close enough for
/// table sizing).
fn findArm64EntryCount(
    instructions: []const types.Instruction,
    branch_idx: usize,
) ?struct { count: u32, default_target: ?u64 } {
    const start = lookbackStart(branch_idx);
    var i: usize = branch_idx;
    var found_cmp_imm: ?u64 = null;
    var default_target: ?u64 = null;

    while (i > start) {
        i -= 1;
        const inst = &instructions[i];
        const m = inst.mnemonic;
        const ops = opText(inst);

        // Look for the conditional branch first (closer to br).
        if (default_target == null and (mnemEql(m, "b.hi") or mnemEql(m, "b.cs") or
            mnemEql(m, "b.ge") or mnemEql(m, "b.gt") or mnemEql(m, "b.hs")))
        {
            if (parseHex(ops)) |t| default_target = t;
            continue;
        }
        // cmp Wn, #imm
        if (mnemEql(m, "cmp") or mnemEql(m, "subs")) {
            if (std.mem.indexOf(u8, ops, "#")) |hash_idx| {
                const tail = ops[hash_idx + 1 ..];
                // Try hex first then decimal.
                if (parseHex(tail)) |v| {
                    found_cmp_imm = v;
                    break;
                } else {
                    // Decimal fallback.
                    var end: usize = 0;
                    while (end < tail.len and tail[end] >= '0' and tail[end] <= '9') end += 1;
                    if (end > 0) {
                        if (std.fmt.parseInt(u64, tail[0..end], 10) catch null) |v| {
                            found_cmp_imm = v;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (found_cmp_imm) |v| {
        // `cmp Wn, #N` followed by `b.hi default` => table size N+1.
        const cnt: u32 = if (v < std.math.maxInt(u32)) @intCast(v + 1) else return null;
        return .{ .count = cnt, .default_target = default_target };
    }
    return null;
}

// ============================================================================
// ARM64
// ============================================================================

fn detectArm64(
    allocator: std.mem.Allocator,
    binary_data: []const u8,
    instructions: []const types.Instruction,
    branch_idx: usize,
    image_base: u64,
) !?JumpTable {
    const branch = &instructions[branch_idx];
    if (!mnemEql(branch.mnemonic, "br") and !mnemEql(branch.mnemonic, "braa") and
        !mnemEql(branch.mnemonic, "braaz") and !mnemEql(branch.mnemonic, "brab") and
        !mnemEql(branch.mnemonic, "brabz"))
        return null;

    // Try tbb/tbh-style relative table first.
    if (try detectArm64Relative(allocator, binary_data, instructions, branch_idx, image_base)) |jt|
        return jt;
    // Fall back to absolute 8-byte table.
    return try detectArm64Absolute(allocator, binary_data, instructions, branch_idx, image_base);
}

fn detectArm64Relative(
    allocator: std.mem.Allocator,
    binary_data: []const u8,
    instructions: []const types.Instruction,
    branch_idx: usize,
    image_base: u64,
) !?JumpTable {
    const start = lookbackStart(branch_idx);
    if (branch_idx == 0) return null;

    var add_idx: ?usize = null;
    var ldr_idx: ?usize = null;
    var adr_idx: ?usize = null;
    var entry_width: u8 = 1;

    var i: usize = branch_idx;
    while (i > start) {
        i -= 1;
        const inst = &instructions[i];
        const m = inst.mnemonic;
        const ops = opText(inst);

        if (add_idx == null and mnemEql(m, "add")) {
            // Look for shape like "x1, x1, w2, uxtw #2" — the #2 hint means
            // base += offset << 2, characteristic of tbb/tbh.
            if (std.mem.indexOf(u8, ops, "uxtw") != null and
                std.mem.indexOf(u8, ops, "#2") != null)
            {
                add_idx = i;
                continue;
            }
        }
        if (add_idx != null and ldr_idx == null and
            (mnemEql(m, "ldrb") or mnemEql(m, "ldrh")))
        {
            ldr_idx = i;
            entry_width = if (mnemEql(m, "ldrb")) 1 else 2;
            continue;
        }
        if (ldr_idx != null and adr_idx == null and mnemEql(m, "adr")) {
            adr_idx = i;
            break;
        }
    }

    if (add_idx == null or ldr_idx == null or adr_idx == null) return null;

    const adr = &instructions[adr_idx.?];
    const table_addr = parseHex(opText(adr)) orelse return null;

    const ec = findArm64EntryCount(instructions, branch_idx);
    const entry_count: u32 = if (ec) |x| x.count else 8;
    const default_target: ?u64 = if (ec) |x| x.default_target else null;

    // tbb/tbh: target = table_addr + (entry << 2)
    const cases_opt = try readTable(
        allocator,
        binary_data,
        image_base,
        table_addr,
        entry_count,
        entry_width,
        4,
        table_addr,
        false,
        false,
    );
    const cases = cases_opt orelse return null;

    return JumpTable{
        .branch_addr = instructions[branch_idx].address,
        .table_addr = table_addr,
        .entry_count = entry_count,
        .entry_width = entry_width,
        .entries_are_absolute = false,
        .base_addr = table_addr,
        .cases = cases,
        .default_target = default_target,
    };
}

fn detectArm64Absolute(
    allocator: std.mem.Allocator,
    binary_data: []const u8,
    instructions: []const types.Instruction,
    branch_idx: usize,
    image_base: u64,
) !?JumpTable {
    const start = lookbackStart(branch_idx);
    if (branch_idx == 0) return null;

    var ldr_idx: ?usize = null;
    var add_idx: ?usize = null;
    var adrp_idx: ?usize = null;

    var i: usize = branch_idx;
    while (i > start) {
        i -= 1;
        const inst = &instructions[i];
        const m = inst.mnemonic;
        const ops = opText(inst);

        if (ldr_idx == null and mnemEql(m, "ldr")) {
            // Want shape "x?, [x?, x?, lsl #3]"
            if (std.mem.indexOf(u8, ops, "lsl") != null and
                std.mem.indexOf(u8, ops, "#3") != null)
            {
                ldr_idx = i;
                continue;
            }
        }
        if (ldr_idx != null and add_idx == null and mnemEql(m, "add")) {
            // Optional add x1, x1, #lo12:table. Consume but don't require.
            add_idx = i;
            continue;
        }
        if (ldr_idx != null and adrp_idx == null and mnemEql(m, "adrp")) {
            adrp_idx = i;
            break;
        }
    }

    if (ldr_idx == null or adrp_idx == null) return null;

    // table_addr: prefer add's full address operand if present, else adrp page.
    var table_addr: u64 = 0;
    if (add_idx) |ai| {
        if (parseHex(opText(&instructions[ai]))) |t| table_addr = t;
    }
    if (table_addr == 0) {
        table_addr = parseHex(opText(&instructions[adrp_idx.?])) orelse return null;
    }

    const ec = findArm64EntryCount(instructions, branch_idx);
    const entry_count: u32 = if (ec) |x| x.count else 8;
    const default_target: ?u64 = if (ec) |x| x.default_target else null;

    const cases_opt = try readTable(
        allocator,
        binary_data,
        image_base,
        table_addr,
        entry_count,
        8,
        0,
        0,
        false,
        true,
    );
    const cases = cases_opt orelse return null;

    return JumpTable{
        .branch_addr = instructions[branch_idx].address,
        .table_addr = table_addr,
        .entry_count = entry_count,
        .entry_width = 8,
        .entries_are_absolute = true,
        .base_addr = 0,
        .cases = cases,
        .default_target = default_target,
    };
}

// ============================================================================
// x86_64
// ============================================================================

/// Compute the target of a `[rip + disp]` operand given the instruction
/// containing it (rip == addr-of-next-insn).
fn ripRelTarget(inst: *const types.Instruction, ops: []const u8) ?u64 {
    const idx = std.mem.indexOf(u8, ops, "rip") orelse return null;
    const tail = ops[idx + 3 ..];
    // Look for "+ 0xNN" or "- 0xNN".
    var sign: i64 = 1;
    var i: usize = 0;
    while (i < tail.len and (tail[i] == ' ' or tail[i] == '\t')) i += 1;
    if (i < tail.len and (tail[i] == '+' or tail[i] == '-')) {
        if (tail[i] == '-') sign = -1;
        i += 1;
    }
    while (i < tail.len and (tail[i] == ' ' or tail[i] == '\t')) i += 1;
    const hex = parseHex(tail[i..]) orelse return null;
    const next_rip = inst.address + inst.size;
    if (sign < 0) {
        return next_rip -% hex;
    } else {
        return next_rip +% hex;
    }
}

fn detectX86_64(
    allocator: std.mem.Allocator,
    binary_data: []const u8,
    instructions: []const types.Instruction,
    branch_idx: usize,
    image_base: u64,
) !?JumpTable {
    const branch = &instructions[branch_idx];
    if (!mnemEql(branch.mnemonic, "jmp")) return null;
    const branch_ops = opText(branch);

    // Direct memory form: jmp qword ptr [rZ*8 + 0xTABLE]
    // (no rip — table is an absolute 32-bit imm; only valid for non-PIC.)
    if (std.mem.indexOf(u8, branch_ops, "qword ptr [") != null and
        std.mem.indexOf(u8, branch_ops, "rip") == null)
    {
        if (std.mem.indexOf(u8, branch_ops, "*8")) |_| {
            // The disp is the table address.
            const table_addr = parseHex(branch_ops) orelse return null;
            // Default to 8 entries — no cmp lookback path implemented here.
            const ec = findX86_64EntryCount(instructions, branch_idx);
            const entry_count: u32 = if (ec) |x| x.count else 8;
            const default_target: ?u64 = if (ec) |x| x.default_target else null;
            const cases_opt = try readTable(
                allocator,
                binary_data,
                image_base,
                table_addr,
                entry_count,
                8,
                0,
                0,
                false,
                true,
            );
            const cases = cases_opt orelse return null;
            return JumpTable{
                .branch_addr = branch.address,
                .table_addr = table_addr,
                .entry_count = entry_count,
                .entry_width = 8,
                .entries_are_absolute = true,
                .base_addr = 0,
                .cases = cases,
                .default_target = default_target,
            };
        }
    }

    // Register-indirect: jmp rX  — walk back to determine table style.
    if (std.mem.indexOf(u8, branch_ops, "[") != null) return null; // already handled
    return try detectX86_64FromRegister(allocator, binary_data, instructions, branch_idx, image_base);
}

fn detectX86_64FromRegister(
    allocator: std.mem.Allocator,
    binary_data: []const u8,
    instructions: []const types.Instruction,
    branch_idx: usize,
    image_base: u64,
) !?JumpTable {
    const start = lookbackStart(branch_idx);
    if (branch_idx == 0) return null;

    var lea_idx: ?usize = null;
    var load_idx: ?usize = null;
    var add_idx: ?usize = null;
    var entry_width: u8 = 8;
    var entries_are_absolute: bool = true;

    var i: usize = branch_idx;
    while (i > start) {
        i -= 1;
        const inst = &instructions[i];
        const m = inst.mnemonic;
        const ops = opText(inst);

        // 4-byte relative form needs an `add` between the load and the jmp.
        if (load_idx == null and add_idx == null and mnemEql(m, "add")) {
            // Only register-only adds (no [, no immediate constants, no rip).
            // Operand should look like "rdx, rax".
            if (std.mem.indexOf(u8, ops, "[") == null and
                std.mem.indexOf(u8, ops, "0x") == null and
                std.mem.indexOf(u8, ops, "rip") == null)
            {
                add_idx = i;
                continue;
            }
        }
        if (load_idx == null and (mnemEql(m, "movsxd") or mnemEql(m, "mov"))) {
            // mov/movsxd reading from [rX + rY*W]
            if (std.mem.indexOf(u8, ops, "[") != null and
                std.mem.indexOf(u8, ops, "rip") == null)
            {
                if (mnemEql(m, "movsxd") and std.mem.indexOf(u8, ops, "*4") != null) {
                    entry_width = 4;
                    entries_are_absolute = false;
                    load_idx = i;
                    continue;
                }
                if (mnemEql(m, "mov") and std.mem.indexOf(u8, ops, "*8") != null and
                    std.mem.indexOf(u8, ops, "qword") != null)
                {
                    entry_width = 8;
                    entries_are_absolute = true;
                    load_idx = i;
                    continue;
                }
            }
        }
        if (load_idx != null and lea_idx == null and mnemEql(m, "lea")) {
            // We need a rip-relative lea producing the table address.
            if (std.mem.indexOf(u8, ops, "rip") != null) {
                lea_idx = i;
                break;
            }
        }
    }

    if (lea_idx == null or load_idx == null) return null;
    // 4-byte form requires the trailing add reg, reg.
    if (entry_width == 4 and add_idx == null) return null;

    const lea = &instructions[lea_idx.?];
    const table_addr = ripRelTarget(lea, opText(lea)) orelse return null;

    const ec = findX86_64EntryCount(instructions, branch_idx);
    const entry_count: u32 = if (ec) |x| x.count else 8;
    const default_target: ?u64 = if (ec) |x| x.default_target else null;

    const cases_opt = try readTable(
        allocator,
        binary_data,
        image_base,
        table_addr,
        entry_count,
        entry_width,
        1,
        if (entries_are_absolute) 0 else table_addr,
        entry_width == 4, // signed 32-bit offsets
        entries_are_absolute,
    );
    const cases = cases_opt orelse return null;

    return JumpTable{
        .branch_addr = instructions[branch_idx].address,
        .table_addr = table_addr,
        .entry_count = entry_count,
        .entry_width = entry_width,
        .entries_are_absolute = entries_are_absolute,
        .base_addr = if (entries_are_absolute) 0 else table_addr,
        .cases = cases,
        .default_target = default_target,
    };
}

fn findX86_64EntryCount(
    instructions: []const types.Instruction,
    branch_idx: usize,
) ?struct { count: u32, default_target: ?u64 } {
    const start = lookbackStart(branch_idx);
    var i: usize = branch_idx;
    var found_cmp_imm: ?u64 = null;
    var default_target: ?u64 = null;

    while (i > start) {
        i -= 1;
        const inst = &instructions[i];
        const m = inst.mnemonic;
        const ops = opText(inst);
        if (default_target == null and (mnemEql(m, "ja") or mnemEql(m, "jae") or
            mnemEql(m, "jnbe") or mnemEql(m, "jg") or mnemEql(m, "jnle")))
        {
            if (parseHex(ops)) |t| default_target = t;
            continue;
        }
        if (mnemEql(m, "cmp")) {
            // "cmp <reg>, 0xNN" or "cmp <reg>, NN"
            if (std.mem.lastIndexOf(u8, ops, ",")) |comma| {
                const tail_raw = ops[comma + 1 ..];
                var t = tail_raw;
                while (t.len > 0 and (t[0] == ' ' or t[0] == '\t')) t = t[1..];
                if (parseHex(t)) |v| {
                    found_cmp_imm = v;
                    break;
                }
                var end: usize = 0;
                while (end < t.len and t[end] >= '0' and t[end] <= '9') end += 1;
                if (end > 0) {
                    if (std.fmt.parseInt(u64, t[0..end], 10) catch null) |v| {
                        found_cmp_imm = v;
                        break;
                    }
                }
            }
        }
    }

    if (found_cmp_imm) |v| {
        const cnt: u32 = if (v < std.math.maxInt(u32)) @intCast(v + 1) else return null;
        return .{ .count = cnt, .default_target = default_target };
    }
    return null;
}

// ============================================================================
// MIPS32
// ============================================================================

fn detectMips32(
    allocator: std.mem.Allocator,
    binary_data: []const u8,
    instructions: []const types.Instruction,
    branch_idx: usize,
    image_base: u64,
) !?JumpTable {
    const branch = &instructions[branch_idx];
    if (!mnemEql(branch.mnemonic, "jr")) return null;
    // Don't treat `jr $ra` (return) as a switch.
    if (std.mem.indexOf(u8, opText(branch), "ra") != null) return null;

    const start = lookbackStart(branch_idx);
    if (branch_idx == 0) return null;

    var lw_idx: ?usize = null;
    var addu_idx: ?usize = null;
    var lui_idx: ?usize = null;
    var ori_idx: ?usize = null;
    var sll_idx: ?usize = null;

    var i: usize = branch_idx;
    while (i > start) {
        i -= 1;
        const inst = &instructions[i];
        const m = inst.mnemonic;

        if (lw_idx == null and mnemEql(m, "lw")) {
            lw_idx = i;
            continue;
        }
        if (lw_idx != null and addu_idx == null and (mnemEql(m, "addu") or mnemEql(m, "add"))) {
            addu_idx = i;
            continue;
        }
        if (addu_idx != null and lui_idx == null and mnemEql(m, "lui")) {
            lui_idx = i;
            continue;
        }
        if (lui_idx != null and ori_idx == null and mnemEql(m, "ori")) {
            // ori is optional — only some compilers split %hi/%lo this way.
            ori_idx = i;
            continue;
        }
        if (lui_idx != null and sll_idx == null and mnemEql(m, "sll")) {
            sll_idx = i;
            break;
        }
    }
    if (lw_idx == null or lui_idx == null) return null;

    // Recover table address: lui hi16, plus either ori lo16 or lw's offset
    // operand if it's a %lo() encoded as a hex disp.
    const lui_ops = opText(&instructions[lui_idx.?]);
    const hi = parseHex(lui_ops) orelse return null;
    var lo: u64 = 0;
    if (ori_idx) |oi| {
        if (std.mem.lastIndexOf(u8, opText(&instructions[oi]), ",")) |c| {
            const tail = opText(&instructions[oi])[c + 1 ..];
            if (parseHex(tail)) |v| lo = v;
        }
    } else {
        // Try the lw's displacement: "lw $t9, 0xLO($v0)"
        const lw_ops = opText(&instructions[lw_idx.?]);
        if (std.mem.indexOf(u8, lw_ops, ",")) |c| {
            const tail = lw_ops[c + 1 ..];
            if (parseHex(tail)) |v| lo = v;
        }
    }
    const table_addr: u64 = (hi << 16) +% lo;

    const ec = findMips32EntryCount(instructions, branch_idx);
    const entry_count: u32 = if (ec) |x| x.count else 8;
    const default_target: ?u64 = if (ec) |x| x.default_target else null;

    const cases_opt = try readTable(
        allocator,
        binary_data,
        image_base,
        table_addr,
        entry_count,
        4,
        0,
        0,
        false,
        true,
    );
    const cases = cases_opt orelse return null;

    return JumpTable{
        .branch_addr = branch.address,
        .table_addr = table_addr,
        .entry_count = entry_count,
        .entry_width = 4,
        .entries_are_absolute = true,
        .base_addr = 0,
        .cases = cases,
        .default_target = default_target,
    };
}

fn findMips32EntryCount(
    instructions: []const types.Instruction,
    branch_idx: usize,
) ?struct { count: u32, default_target: ?u64 } {
    const start = lookbackStart(branch_idx);
    var i: usize = branch_idx;
    var found_imm: ?u64 = null;
    var default_target: ?u64 = null;

    while (i > start) {
        i -= 1;
        const inst = &instructions[i];
        const m = inst.mnemonic;
        const ops = opText(inst);

        if (default_target == null and (mnemEql(m, "bgtu") or mnemEql(m, "bgeu") or
            mnemEql(m, "beqz") or mnemEql(m, "bnez") or mnemEql(m, "beq")))
        {
            if (parseHex(ops)) |t| default_target = t;
            continue;
        }
        if (mnemEql(m, "sltiu") or mnemEql(m, "sltu") or mnemEql(m, "slti")) {
            if (std.mem.lastIndexOf(u8, ops, ",")) |c| {
                const tail = ops[c + 1 ..];
                if (parseHex(tail)) |v| {
                    found_imm = v;
                    break;
                }
                var end: usize = 0;
                while (end < tail.len and tail[end] >= '0' and tail[end] <= '9') end += 1;
                if (end > 0) {
                    if (std.fmt.parseInt(u64, tail[0..end], 10) catch null) |v| {
                        found_imm = v;
                        break;
                    }
                }
            }
        }
    }

    if (found_imm) |v| {
        const cnt: u32 = if (v < std.math.maxInt(u32)) @intCast(v) else return null;
        // sltiu rd, rs, N => rd = (rs < N), so legal indices are 0..N-1
        return .{ .count = cnt, .default_target = default_target };
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

/// Helper to build a fake Instruction with mnemonic + operand text.
fn makeInst(addr: u64, mnem: []const u8, ops: []const u8, size: u8) types.Instruction {
    var inst = types.Instruction{
        .address = addr,
        .bytes = &.{},
        .mnemonic = mnem,
        .operands = "",
        .size = size,
    };
    const n: u8 = @intCast(@min(ops.len, inst.operands_buf.len));
    @memcpy(inst.operands_buf[0..n], ops[0..n]);
    inst.operands_len = n;
    inst.operands = inst.operands_buf[0..n];
    return inst;
}

test "arm64 tbb relative table" {
    const allocator = testing.allocator;

    // image_base = 0x1000. Code at 0x1100. Table at 0x2000 (4 bytes: 1,2,3,4).
    // Targets = base(0x2000) + (entry << 2) = 0x2004, 0x2008, 0x200c, 0x2010.
    const image_base: u64 = 0x1000;
    var data: [0x4000]u8 = [_]u8{0} ** 0x4000;
    // Table at file_off 0x2000-0x1000 = 0x1000.
    data[0x1000] = 1;
    data[0x1001] = 2;
    data[0x1002] = 3;
    data[0x1003] = 4;

    const insts = [_]types.Instruction{
        makeInst(0x1100, "cmp", "w0, #0x3", 4),
        makeInst(0x1104, "b.hi", "0x12345", 4),
        makeInst(0x1108, "adr", "x1, 0x2000", 4),
        makeInst(0x110c, "ldrb", "w2, [x1, w0, uxtw]", 4),
        makeInst(0x1110, "add", "x1, x1, w2, uxtw #2", 4),
        makeInst(0x1114, "br", "x1", 4),
    };

    const jt_opt = try detect(allocator, .arm64, &data, &insts, 5, image_base);
    try testing.expect(jt_opt != null);
    const jt = jt_opt.?;
    defer allocator.free(jt.cases);

    try testing.expectEqual(@as(u64, 0x2000), jt.table_addr);
    try testing.expectEqual(@as(u8, 1), jt.entry_width);
    try testing.expectEqual(false, jt.entries_are_absolute);
    try testing.expectEqual(@as(u32, 4), jt.entry_count);
    try testing.expectEqual(@as(u64, 0x12345), jt.default_target.?);
    try testing.expectEqual(@as(u64, 0x2004), jt.cases[0].target);
    try testing.expectEqual(@as(u64, 0x2008), jt.cases[1].target);
    try testing.expectEqual(@as(u64, 0x200c), jt.cases[2].target);
    try testing.expectEqual(@as(u64, 0x2010), jt.cases[3].target);
}

test "arm64 absolute 8-byte table" {
    const allocator = testing.allocator;

    const image_base: u64 = 0x100000000;
    var data: [0x4000]u8 = [_]u8{0} ** 0x4000;
    // Table at virtual 0x100002000 == file offset 0x2000.
    const targets = [_]u64{ 0x100001000, 0x100001100, 0x100001200 };
    for (targets, 0..) |t, i| {
        std.mem.writeInt(u64, data[0x2000 + i * 8 ..][0..8], t, .little);
    }

    const insts = [_]types.Instruction{
        makeInst(0x100001000, "cmp", "w0, #0x2", 4),
        makeInst(0x100001004, "b.hi", "0xdead", 4),
        makeInst(0x100001008, "adrp", "x1, 0x100002000", 4),
        makeInst(0x10000100c, "add", "x1, x1, #0x0", 4),
        makeInst(0x100001010, "ldr", "x2, [x1, x0, lsl #3]", 4),
        makeInst(0x100001014, "br", "x2", 4),
    };

    const jt_opt = try detect(allocator, .arm64, &data, &insts, 5, image_base);
    try testing.expect(jt_opt != null);
    const jt = jt_opt.?;
    defer allocator.free(jt.cases);

    try testing.expectEqual(@as(u64, 0x100002000), jt.table_addr);
    try testing.expectEqual(@as(u8, 8), jt.entry_width);
    try testing.expectEqual(true, jt.entries_are_absolute);
    try testing.expectEqual(@as(u32, 3), jt.entry_count);
    try testing.expectEqual(targets[0], jt.cases[0].target);
    try testing.expectEqual(targets[1], jt.cases[1].target);
    try testing.expectEqual(targets[2], jt.cases[2].target);
}

test "x86_64 4-byte rip-relative table" {
    const allocator = testing.allocator;

    const image_base: u64 = 0x400000;
    var data: [0x4000]u8 = [_]u8{0} ** 0x4000;
    // Table at virtual 0x402000 (file off 0x2000). Three offsets relative to
    // table_addr: targets = 0x402000 + entry.
    const offsets = [_]i32{ 0x100, 0x200, 0x300 };
    for (offsets, 0..) |o, i| {
        std.mem.writeInt(i32, data[0x2000 + i * 4 ..][0..4], o, .little);
    }

    // lea rax, [rip + 0x... ] at addr 0x401000, size 7.
    // next_rip = 0x401007. Want target = 0x402000 => disp = 0xff9.
    const insts = [_]types.Instruction{
        makeInst(0x401000, "cmp", "edi, 0x2", 3),
        makeInst(0x401003, "ja", "0xbadbad", 6),
        makeInst(0x401009, "lea", "rax, [rip + 0xff0]", 7),
        makeInst(0x401010, "movsxd", "rdx, dword ptr [rax + rdi*4]", 4),
        makeInst(0x401014, "add", "rdx, rax", 3),
        makeInst(0x401017, "jmp", "rdx", 2),
    };

    const jt_opt = try detect(allocator, .x86_64, &data, &insts, 5, image_base);
    try testing.expect(jt_opt != null);
    const jt = jt_opt.?;
    defer allocator.free(jt.cases);

    try testing.expectEqual(@as(u64, 0x402000), jt.table_addr);
    try testing.expectEqual(@as(u8, 4), jt.entry_width);
    try testing.expectEqual(false, jt.entries_are_absolute);
    try testing.expectEqual(@as(u32, 3), jt.entry_count);
    try testing.expectEqual(@as(u64, 0xbadbad), jt.default_target.?);
    try testing.expectEqual(@as(u64, 0x402100), jt.cases[0].target);
    try testing.expectEqual(@as(u64, 0x402200), jt.cases[1].target);
    try testing.expectEqual(@as(u64, 0x402300), jt.cases[2].target);
}

test "x86_64 8-byte absolute rip-relative table" {
    const allocator = testing.allocator;

    const image_base: u64 = 0x400000;
    var data: [0x4000]u8 = [_]u8{0} ** 0x4000;
    const targets = [_]u64{ 0x401100, 0x401200 };
    for (targets, 0..) |t, i| {
        std.mem.writeInt(u64, data[0x2000 + i * 8 ..][0..8], t, .little);
    }

    // lea rax, [rip + 0xff7] at addr 0x401009, size 7 -> table 0x402000.
    const insts = [_]types.Instruction{
        makeInst(0x401000, "cmp", "edi, 0x1", 3),
        makeInst(0x401003, "ja", "0xdef", 6),
        makeInst(0x401009, "lea", "rax, [rip + 0xff0]", 7),
        makeInst(0x401010, "mov", "rdx, qword ptr [rax + rdi*8]", 4),
        makeInst(0x401014, "jmp", "rdx", 2),
    };

    const jt_opt = try detect(allocator, .x86_64, &data, &insts, 4, image_base);
    try testing.expect(jt_opt != null);
    const jt = jt_opt.?;
    defer allocator.free(jt.cases);

    try testing.expectEqual(@as(u64, 0x402000), jt.table_addr);
    try testing.expectEqual(@as(u8, 8), jt.entry_width);
    try testing.expectEqual(true, jt.entries_are_absolute);
    try testing.expectEqual(@as(u32, 2), jt.entry_count);
    try testing.expectEqual(targets[0], jt.cases[0].target);
    try testing.expectEqual(targets[1], jt.cases[1].target);
}

test "mips32 absolute 4-byte table" {
    const allocator = testing.allocator;

    const image_base: u64 = 0x400000;
    var data: [0x4000]u8 = [_]u8{0} ** 0x4000;
    const targets = [_]u32{ 0x401100, 0x401200, 0x401300 };
    // Table at 0x402100 → file off 0x2100.
    for (targets, 0..) |t, i| {
        std.mem.writeInt(u32, data[0x2100 + i * 4 ..][0..4], t, .little);
    }

    // table_addr = (0x40 << 16) + 0x2100 = 0x402100.
    const insts = [_]types.Instruction{
        makeInst(0x401000, "sltiu", "$v0, $a0, 0x3", 4),
        makeInst(0x401004, "beqz", "$v0, 0xbeef", 4),
        makeInst(0x401008, "sll", "$v0, $a0, 0x2", 4),
        makeInst(0x40100c, "lui", "$v1, 0x40", 4),
        makeInst(0x401010, "addu", "$v0, $v0, $v1", 4),
        makeInst(0x401014, "lw", "$t9, 0x2100($v0)", 4),
        makeInst(0x401018, "jr", "$t9", 4),
    };

    const jt_opt = try detect(allocator, .mips32, &data, &insts, 6, image_base);
    try testing.expect(jt_opt != null);
    const jt = jt_opt.?;
    defer allocator.free(jt.cases);

    try testing.expectEqual(@as(u64, 0x402100), jt.table_addr);
    try testing.expectEqual(@as(u8, 4), jt.entry_width);
    try testing.expectEqual(true, jt.entries_are_absolute);
    try testing.expectEqual(@as(u32, 3), jt.entry_count);
    try testing.expectEqual(@as(u64, targets[0]), jt.cases[0].target);
    try testing.expectEqual(@as(u64, targets[1]), jt.cases[1].target);
    try testing.expectEqual(@as(u64, targets[2]), jt.cases[2].target);
}

test "mips32 jr ra is not a switch" {
    const allocator = testing.allocator;
    var data: [0x100]u8 = [_]u8{0} ** 0x100;
    const insts = [_]types.Instruction{
        makeInst(0x401000, "jr", "$ra", 4),
    };
    const jt_opt = try detect(allocator, .mips32, &data, &insts, 0, 0x400000);
    try testing.expect(jt_opt == null);
}

test "out-of-range table address yields null" {
    const allocator = testing.allocator;
    var data: [0x100]u8 = [_]u8{0} ** 0x100;
    // Table address way past binary_data end.
    const insts = [_]types.Instruction{
        makeInst(0x1100, "cmp", "w0, #0x3", 4),
        makeInst(0x1104, "b.hi", "0x12345", 4),
        makeInst(0x1108, "adr", "x1, 0xdeadbeef", 4),
        makeInst(0x110c, "ldrb", "w2, [x1, w0, uxtw]", 4),
        makeInst(0x1110, "add", "x1, x1, w2, uxtw #2", 4),
        makeInst(0x1114, "br", "x1", 4),
    };
    const jt_opt = try detect(allocator, .arm64, &data, &insts, 5, 0x1000);
    try testing.expect(jt_opt == null);
}

test "no pattern match yields null" {
    const allocator = testing.allocator;
    var data: [0x100]u8 = [_]u8{0} ** 0x100;
    // Just a `br x0` with no preceding pattern.
    const insts = [_]types.Instruction{
        makeInst(0x1100, "mov", "x0, x1", 4),
        makeInst(0x1104, "br", "x0", 4),
    };
    const jt_opt = try detect(allocator, .arm64, &data, &insts, 1, 0x1000);
    try testing.expect(jt_opt == null);
}

test "non-indirect branch yields null" {
    const allocator = testing.allocator;
    var data: [0x100]u8 = [_]u8{0} ** 0x100;
    const insts = [_]types.Instruction{
        makeInst(0x1100, "ret", "", 4),
    };
    const jt_opt = try detect(allocator, .arm64, &data, &insts, 0, 0x1000);
    try testing.expect(jt_opt == null);
}

test "arm32 currently unsupported" {
    const allocator = testing.allocator;
    var data: [0x100]u8 = [_]u8{0} ** 0x100;
    const insts = [_]types.Instruction{
        makeInst(0x1100, "bx", "r0", 4),
    };
    const jt_opt = try detect(allocator, .arm32, &data, &insts, 0, 0x1000);
    try testing.expect(jt_opt == null);
}
