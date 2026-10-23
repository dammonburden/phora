const std = @import("std");
const builtin = @import("builtin");

pub const Shift = enum(u2) { lsl, lsr, asr };
pub const Effect = struct {
    width: u7,
    subtract: bool,
    sets_flags: bool,
    destination: u5,
    left: u5,
    right: u5,
    shift: Shift,
    amount: u6,

    pub fn result(self: Effect, left_before: u64, right_before: u64) u64 {
        const mask: u64 = if (self.width == 64) std.math.maxInt(u64) else std.math.maxInt(u32);
        const left = if (self.left == 31) 0 else left_before & mask;
        const right = if (self.right == 31) 0 else right_before & mask;
        const shifted = switch (self.shift) {
            .lsl => right << self.amount,
            .lsr => right >> self.amount,
            .asr => if (self.width == 64)
                @as(u64, @bitCast(@as(i64, @bitCast(right)) >> self.amount))
            else
                @as(u32, @bitCast(@as(i32, @bitCast(@as(u32, @truncate(right)))) >> @as(u5, @intCast(self.amount)))),
        } & mask;
        return (if (self.subtract) left -% shifted else left +% shifted) & mask;
    }
};

/// Encoding-backed ADD/SUB shifted-register only; extended-register is excluded.
pub fn decode(word: u32) ?Effect {
    if (word & 0x1f200000 != 0x0b000000) return null;
    const width: u7 = if (word >> 31 != 0) 64 else 32;
    const shift: u2 = @truncate(word >> 22);
    const amount: u6 = @truncate(word >> 10);
    if (shift == 3 or (width == 32 and amount >= 32)) return null;
    return .{ .width = width, .subtract = word & 0x40000000 != 0, .sets_flags = word & 0x20000000 != 0, .destination = @truncate(word), .left = @truncate(word >> 5), .right = @truncate(word >> 16), .shift = @fromBackingInt(@intCast(shift)), .amount = amount };
}

fn writeRegister(w: anytype, register: u5, width: u7) !void {
    try w.print("{{\"kind\":\"{s}\",\"index\":{d},\"width_bits\":{d}}}", .{ if (register == 31) @as([]const u8, "zero_register") else "gpr", register, width });
}

pub fn writeJsonMember(w: anytype, word: u32) !void {
    const e = decode(word) orelse return;
    try w.print(",\"arithmetic_evidence\":{{\"model\":\"a64_add_sub_shifted_register_v1\",\"scope\":\"arithmetic_only\",\"encoding\":\"0x{x:0>8}\",\"operation\":\"{s}\",\"width_bits\":{d},\"left_source\":", .{ word, if (e.subtract) @as([]const u8, "subtract") else "add", e.width });
    try writeRegister(w, e.left, e.width);
    try w.writeAll(",\"right_source\":");
    try writeRegister(w, e.right, e.width);
    try w.print(",\"right_shift\":{{\"operation\":\"{s}\",\"amount\":{d}}},\"destination\":", .{ @tagName(e.shift), e.amount });
    try writeRegister(w, e.destination, e.width);
    try w.print(",\"discard_destination_write\":{},\"w_write_zero_extends_x\":{},\"flags_written\":{},\"flags\":\"{s}\",\"source_read_phase\":\"before_destination_update\",\"source_state\":\"current_instruction_register_values\",\"result_rule\":\"left_before op shift(right_before), modulo 2^width\",\"execution_note\":\"Read both sources from the current state before writing the destination, including overlapping registers. On later loop traversals use the updated carried values; an initializer is not an invariant when its register is assigned in the loop. Flags, when written, are NZCV from this arithmetic result; this metadata is not full instruction semantics.\"}}", .{ e.destination == 31, e.width == 32 and e.destination != 31, e.sets_flags, if (e.sets_flags) @as([]const u8, "NZCV") else "unchanged" });
}

test "clang literal arithmetic fields and reserved shifts" {
    const words = [_]u32{ 0x4b0b01ad, 0x0b0b0dab, 0xab841c62, 0x6b4724c5 };
    const widths = [_]u7{ 32, 32, 64, 32 };
    const amounts = [_]u6{ 0, 3, 7, 9 };
    const shifts = [_]Shift{ .lsl, .lsl, .asr, .lsr };
    const destinations = [_]u5{ 13, 11, 2, 5 };
    for (words, 0..) |word, i| {
        const e = decode(word).?;
        try std.testing.expectEqual(widths[i], e.width);
        try std.testing.expectEqual(amounts[i], e.amount);
        try std.testing.expectEqual(shifts[i], e.shift);
        try std.testing.expectEqual(destinations[i], e.destination);
        try std.testing.expectEqual(i == 0 or i == 3, e.subtract);
        try std.testing.expectEqual(i >= 2, e.sets_flags);
    }
    for ([_]u32{ 0x0bc00000, 0x0b008000, 0x0b200000, 0x91000400, 0xcccccccc }) |word|
        try std.testing.expect(decode(word) == null);
}

test "before-state sources preserve carried values over two traversals" {
    const sub = decode(0x4b0b01ad).?;
    const add = decode(0x0b0b0dab).?;
    var carried: u64 = 1;
    for ([_]u64{ 5, 6 }, [_]u64{ 12, 90 }) |input, expected| {
        const temporary = sub.result(input, carried);
        carried = add.result(temporary, carried);
        try std.testing.expectEqual(expected, carried);
    }
    try std.testing.expectEqual(@as(u64, 0xffffffff), sub.result(0, 1));
    try std.testing.expectEqual(@as(u64, 0), decode(0x0b1f03e0).?.result(123, 456));
    try std.testing.expectEqual(@as(u64, 0xffffffffffffffff), decode(0x8b81fc20).?.result(0, 0x8000000000000000));
}

test "native two-traversal read-before-write oracle" {
    if (builtin.cpu.arch != .aarch64) return error.SkipZigTest;
    var carried: u64 = 1;
    for ([_]u64{ 5, 6 }) |input| {
        const actual = asm volatile ("sub w13, w13, w11\nadd w11, w13, w11, lsl #3"
            : [out] "={x11}" (-> u64),
            : [left] "{x13}" (input),
              [right] "{x11}" (carried),
            : .{ .x13 = true });
        const expected = decode(0x0b0b0dab).?.result(decode(0x4b0b01ad).?.result(input, carried), carried);
        try std.testing.expectEqual(expected, actual);
        carried = actual;
    }
}

test "arithmetic metadata explicitly reads current before-state sources and flags" {
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try writeJsonMember(&output.writer, 0x0b0b0dab);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"source_read_phase\":\"before_destination_update\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"source_state\":\"current_instruction_register_values\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"right_source\":{\"kind\":\"gpr\",\"index\":11,\"width_bits\":32}") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"destination\":{\"kind\":\"gpr\",\"index\":11,\"width_bits\":32}") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"flags_written\":false") != null);
    const len = output.written().len;
    try writeJsonMember(&output.writer, 0x0bc00000);
    try std.testing.expectEqual(len, output.written().len);
    try writeJsonMember(&output.writer, 0xab841c62);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"flags_written\":true,\"flags\":\"NZCV\"") != null);
}
