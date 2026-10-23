const std = @import("std");
const builtin = @import("builtin");
const arithmetic = @import("arm64_arithmetic.zig");

/// Bounded pair evidence, not data flow: only SUBS (including CMP aliases)
/// immediately followed by ordinary B.cond. BC.cond and other flag writers
/// are excluded. Callers must not skip instructions when forming the pair.
pub const Pair = struct {
    width: u7,
    left: u5,
    destination: u5,
    immediate: ?u64,
    register_effect: ?arithmetic.Effect,
    condition: u4,

    pub fn mask(self: Pair) u64 {
        return if (self.width == 64) std.math.maxInt(u64) else std.math.maxInt(u32);
    }

    pub fn rightValue(self: Pair, right_before: u64) u64 {
        if (self.immediate) |imm| return imm;
        const e = self.register_effect.?;
        // Reuse the encoding-backed shift implementation with a zero LHS.
        var shifted = e;
        shifted.subtract = false;
        shifted.left = 31;
        return shifted.result(0, right_before);
    }

    pub fn flags(self: Pair, left_before: u64, right_before: u64) Flags {
        const left = if (self.left == 31 and self.immediate == null) 0 else left_before & self.mask();
        const right = self.rightValue(right_before);
        const result = (left -% right) & self.mask();
        const sign = @as(u64, 1) << @as(u6, @intCast(self.width - 1));
        return .{ .n = result & sign != 0, .z = result == 0, .c = left >= right, .v = ((left ^ right) & (left ^ result) & sign) != 0 };
    }
};

pub const Flags = struct {
    n: bool,
    z: bool,
    c: bool,
    v: bool,

    pub fn holds(self: Flags, condition: u4) bool {
        return switch (condition) {
            0 => self.z,
            1 => !self.z,
            2 => self.c,
            3 => !self.c,
            4 => self.n,
            5 => !self.n,
            6 => self.v,
            7 => !self.v,
            8 => self.c and !self.z,
            9 => !self.c or self.z,
            10 => self.n == self.v,
            11 => self.n != self.v,
            12 => !self.z and self.n == self.v,
            13 => self.z or self.n != self.v,
            14, 15 => true, // A64 ConditionHolds: AL and NV both always.
        };
    }
};

pub fn decode(previous: u32, branch: u32) ?Pair {
    if (branch & 0xff000010 != 0x54000000) return null;
    if (previous & 0x7f800000 == 0x71000000) {
        const immediate = @as(u64, (previous >> 10) & 0xfff) << @as(u6, if (previous & 0x400000 != 0) 12 else 0);
        return .{ .width = if (previous >> 31 != 0) 64 else 32, .left = @truncate(previous >> 5), .destination = @truncate(previous), .immediate = immediate, .register_effect = null, .condition = @truncate(branch) };
    }
    const effect = arithmetic.decode(previous) orelse return null;
    if (!effect.subtract or !effect.sets_flags) return null;
    return .{ .width = effect.width, .left = effect.left, .destination = effect.destination, .immediate = null, .register_effect = effect, .condition = @truncate(branch) };
}

const condition_names = [_][]const u8{ "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv" };
const flag_predicates = [_][]const u8{ "Z", "!Z", "C", "!C", "N", "!N", "V", "!V", "C && !Z", "!C || Z", "N == V", "N != V", "!Z && N == V", "Z || N != V", "true", "true" };
const exact_predicates = [_][]const u8{
    "left_before == right_operand",                     "left_before != right_operand",
    "unsigned(left_before) >= unsigned(right_operand)", "unsigned(left_before) < unsigned(right_operand)",
    "sign_bit(subtraction_result) == 1",                "sign_bit(subtraction_result) == 0",
    "signed_subtraction_overflow",                      "!signed_subtraction_overflow",
    "unsigned(left_before) > unsigned(right_operand)",  "unsigned(left_before) <= unsigned(right_operand)",
    "signed(left_before) >= signed(right_operand)",     "signed(left_before) < signed(right_operand)",
    "signed(left_before) > signed(right_operand)",      "signed(left_before) <= signed(right_operand)",
    "true",                                             "true",
};

fn writeSource(w: anytype, register: u5, width: u7, sp: bool) !void {
    try w.print("{{\"kind\":\"{s}\",\"index\":{d},\"width_bits\":{d},\"value_phase\":\"input_before_instruction\"}}", .{ if (register != 31) @as([]const u8, "gpr") else if (sp) "stack_pointer" else "zero_register", register, width });
}

pub fn writeJsonMember(w: anytype, previous: u32, branch: u32, previous_address: u64) !void {
    const pair = decode(previous, branch) orelse return;
    try w.print(",\"branch_predicate_evidence\":{{\"model\":\"a64_adjacent_subs_bcond_v1\",\"scope\":\"when_pair_executes_consecutively\",\"flags_source_address\":\"0x{x}\",\"flags_source_encoding\":\"0x{x:0>8}\",\"condition\":\"{s}\",\"width_bits\":{d},\"left_source\":", .{ previous_address, previous, condition_names[pair.condition], pair.width });
    try writeSource(w, pair.left, pair.width, pair.immediate != null);
    try w.writeAll(",\"right_operand\":");
    if (pair.immediate) |immediate| {
        try w.print("{{\"kind\":\"immediate\",\"value\":{d}}}", .{immediate});
    } else {
        const effect = pair.register_effect.?;
        try w.writeAll("{\"source\":");
        try writeSource(w, effect.right, pair.width, false);
        try w.print(",\"shift\":\"{s}\",\"amount\":{d},\"truncate_to_width\":true}}", .{ @tagName(effect.shift), effect.amount });
    }
    try w.print(",\"destination\":{{\"index\":{d},\"write_discarded\":{},\"value_phase\":\"updated_after_instruction\"}},\"taken_flags_predicate\":\"{s}\",\"taken_predicate\":\"{s}\",\"fallthrough_predicate\":\"negation_of_taken_predicate\",\"flags_rule\":\"result=(left_before-right_operand) modulo 2^width; N=result sign bit; Z=(result==0); C=unsigned(left_before)>=unsigned(right_operand), no borrow; V=signed subtraction overflow\",\"execution_note\":\"Operands use current values BEFORE the SUBS/CMP, even when its destination overlaps a source. HI requires no borrow AND a nonzero result: it is not unsigned(updated_destination)>0. Evidence applies only when the immediately preceding instruction executed; another entry directly at the branch may supply different flags. No flag provenance across intervening instructions is inferred.\"}}", .{ pair.destination, pair.destination == 31, flag_predicates[pair.condition], exact_predicates[pair.condition] });
}

pub fn writeText(w: anytype, previous: u32, branch: u32) !void {
    const pair = decode(previous, branch) orelse return;
    try w.print(" ; adjacent SUBS/CMP if executed: {s}; operands before subtraction", .{exact_predicates[pair.condition]});
    if (pair.immediate) |immediate| {
        try w.writeAll(" (left=");
        if (pair.left == 31) try w.writeAll(if (pair.width == 64) "sp" else "wsp") else try w.print("{s}{d}", .{ if (pair.width == 64) @as([]const u8, "x") else "w", pair.left });
        try w.print(", right={d})", .{immediate});
    }
    if (pair.condition == 8) try w.writeAll("; C && !Z = no borrow AND nonzero, not unsigned(updated destination)>0");
}

test "Go memmove adjacent subs branch identifies input phase and unsigned carry" {
    const pair = decode(0xf1010042, 0x54fffee8).?;
    try std.testing.expectEqual(@as(u64, 64), pair.immediate.?);
    try std.testing.expectEqual(@as(u5, 2), pair.left);
    try std.testing.expectEqual(@as(u5, 2), pair.destination);
    for ([_]u64{ 0, 1, 63, 64, 65, 128, std.math.maxInt(u64) }) |value|
        try std.testing.expectEqual(value > 64, pair.flags(value, 0).holds(pair.condition));
    try std.testing.expect(!pair.flags(1, 0).holds(pair.condition)); // Underflowed result is nonzero.
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try writeJsonMember(&output.writer, 0xf1010042, 0x54fffee8, 0x10008af50);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "unsigned(left_before) > unsigned(right_operand)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "input_before_instruction") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "C && !Z") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "updated_after_instruction") != null);
}

test "bounded decoder accepts subtraction immediate and shifted register only" {
    for ([_]u32{ 0xf100405f, 0x7100043f, 0xf1400442, 0xeb0201df, 0x6b4724c5, 0xeb821c42 }) |word|
        try std.testing.expect(decode(word, 0x54000008) != null);
    try std.testing.expectEqual(@as(u64, 4096), decode(0xf1400442, 0x54000008).?.immediate.?);
    try std.testing.expectEqual(@as(u64, 0xffffffffffffffff), decode(0xeb82fc42, 0x54000008).?.rightValue(0x8000000000000000));
    for ([_]u32{ 0xd1010042, 0xb1010042, 0xeb220042, 0xebc20042, 0x6b028042, 0xd503201f, 0xf1800042 }) |word|
        try std.testing.expect(decode(word, 0x54000008) == null);
    for ([_]u32{ 0x54000018, 0x14000008, 0xb4000002, 0x36000002 }) |word|
        try std.testing.expect(decode(0xf1010042, word) == null);
    // Intervening NOP or unsupported flag writer must not be skipped.
    try std.testing.expect(decode(0xd503201f, 0x54000008) == null);
    try std.testing.expect(decode(0xfa420020, 0x54000008) == null);
}

fn signedValue(value: u64, width: u7) i128 {
    const sign = @as(u64, 1) << @as(u6, @intCast(width - 1));
    return if (value & sign == 0) @as(i128, value) else @as(i128, value) - (@as(i128, 1) << width);
}

test "every condition agrees with independent signed and unsigned boundary oracle" {
    for ([_]u7{ 32, 64 }) |width| {
        const mask: u64 = if (width == 64) std.math.maxInt(u64) else std.math.maxInt(u32);
        const sign = @as(u64, 1) << @as(u6, @intCast(width - 1));
        const values = [_]u64{ 0, 1, 63, 64, 65, sign - 1, sign, sign + 1, mask - 1, mask };
        const pair = decode(if (width == 64) 0xeb020020 else 0x6b020020, 0x54000000).?;
        for (values) |left| for (values) |right| {
            const result = (left -% right) & mask;
            const signed_left = signedValue(left, width);
            const signed_right = signedValue(right, width);
            const mathematical = signed_left - signed_right;
            const overflow = mathematical < -@as(i128, sign) or mathematical >= @as(i128, sign);
            const expected = [_]bool{ left == right, left != right, left >= right, left < right, result & sign != 0, result & sign == 0, overflow, !overflow, left > right, left <= right, signed_left >= signed_right, signed_left < signed_right, signed_left > signed_right, signed_left <= signed_right, true, true };
            for (expected, 0..) |taken, condition| try std.testing.expectEqual(taken, pair.flags(left, right).holds(@intCast(condition)));
        };
    }
}

test "register 31 means SP for immediate and zero for shifted register" {
    const immediate = decode(0xf10007ff, 0x54000008).?;
    const shifted = decode(0xeb0203ff, 0x54000008).?;
    try std.testing.expect(immediate.flags(2, 1).holds(8));
    try std.testing.expect(!shifted.flags(2, 1).holds(8));
    try std.testing.expectEqual(@as(u64, 0), decode(0xeb1f0020, 0x54000008).?.rightValue(std.math.maxInt(u64)));
}

test "host AArch64 native NZCV agrees for both widths and every condition" {
    if (builtin.cpu.arch != .aarch64) return error.SkipZigTest;
    for ([_]u7{ 32, 64 }) |width| {
        const mask: u64 = if (width == 64) std.math.maxInt(u64) else std.math.maxInt(u32);
        const sign = @as(u64, 1) << @as(u6, @intCast(width - 1));
        const values = [_]u64{ 0, 1, 63, 64, 65, sign - 1, sign, sign + 1, mask - 1, mask };
        const pair = decode(if (width == 64) 0xeb020020 else 0x6b020020, 0x54000000).?;
        for (values) |left| for (values) |right| {
            // Execute test instructions only; no target binary is executed.
            const nzcv = if (width == 64)
                asm volatile ("subs xzr, x13, x12\nmrs x11, nzcv"
                    : [out] "={x11}" (-> u64),
                    : [left] "{x13}" (left),
                      [right] "{x12}" (right),
                    : .{ .nzcv = true })
            else
                asm volatile ("subs wzr, w13, w12\nmrs x11, nzcv"
                    : [out] "={x11}" (-> u64),
                    : [left] "{x13}" (left),
                      [right] "{x12}" (right),
                    : .{ .nzcv = true });
            const native = Flags{ .n = nzcv & (1 << 31) != 0, .z = nzcv & (1 << 30) != 0, .c = nzcv & (1 << 29) != 0, .v = nzcv & (1 << 28) != 0 };
            const modeled = pair.flags(left, right);
            try std.testing.expectEqual(native, modeled);
            for (0..16) |condition| try std.testing.expectEqual(native.holds(@intCast(condition)), modeled.holds(@intCast(condition)));
        };
    }
}

test "text uses SP spelling for immediate register 31" {
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try writeText(&output.writer, 0xf10007ff, 0x54000008);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "left=sp") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "left=x31") == null);
}
