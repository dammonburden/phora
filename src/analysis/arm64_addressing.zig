const std = @import("std");
const builtin = @import("builtin");

/// Addressing evidence only: ordinary scalar unsigned LDR/STR imm9 writeback.
/// Does not model faults, tags, alignment, privilege checks, or full load semantics.
pub const Effect = struct {
    base: u5,
    data: u5,
    immediate: i16,
    width_bits: u7,
    load: bool,
    pre_index: bool,

    pub fn updatedBase(self: Effect, old: u64) u64 {
        return old +% @as(u64, @bitCast(@as(i64, self.immediate)));
    }
    pub fn effectiveAddress(self: Effect, old: u64) u64 {
        return if (self.pre_index) self.updatedBase(old) else old;
    }
};

pub fn decode(word: u32) ?Effect {
    // Fixed scalar load/store immediate class; excludes SIMD and register offsets.
    if (word & 0x3f200000 != 0x38000000) return null;
    const opc: u2 = @truncate(word >> 22);
    const mode: u2 = @truncate(word >> 10);
    if (opc > 1 or (mode != 1 and mode != 3)) return null;
    const base: u5 = @truncate(word >> 5);
    const data: u5 = @truncate(word);
    // Writeback overlap is constrained unpredictable, except SP / ZR.
    if (base == data and base != 31) return null;
    const imm: u9 = @truncate(word >> 12);
    return .{
        .base = base,
        .data = data,
        .immediate = std.math.signExtend(i16, imm),
        .width_bits = @as(u7, 8) << @as(u2, @truncate(word >> 30)),
        .load = opc == 1,
        .pre_index = mode == 3,
    };
}

/// Append a separate metadata member, leaving full semantic coverage unchanged.
pub fn writeJsonMember(w: anytype, word: u32) !void {
    const e = decode(word) orelse return;
    try w.print(",\"addressing_evidence\":{{\"model\":\"a64_scalar_imm9_writeback_v1\",\"scope\":\"addressing_only\",\"encoding\":\"0x{x:0>8}\",\"operation\":\"{s}\",\"transfer_width_bits\":{d},\"mode\":\"{s}\",\"signed_immediate\":{d}", .{ word, if (e.load) @as([]const u8, "load") else "store", e.width_bits, if (e.pre_index) @as([]const u8, "pre_index") else "post_index", e.immediate });
    try w.print(",\"base_register\":{{\"kind\":\"{s}\",\"index\":{d},\"width_bits\":64}},\"data_register\":{{\"kind\":\"{s}\",\"index\":{d},\"width_bits\":{d}}}", .{ if (e.base == 31) @as([]const u8, "sp") else "gpr", e.base, if (e.data == 31) @as([]const u8, "zero_register") else "gpr", e.data, @as(u7, if (e.width_bits == 64) 64 else 32) });
    try w.print(",\"effective_address\":{{\"operation\":\"{s}\",\"input\":\"base_before\",\"offset\":{d}}},\"base_update\":{{\"operation\":\"add\",\"input\":\"base_before\",\"signed_immediate\":{d},\"width_bits\":64,\"dereference\":false}},\"execution_caveat\":\"Address and base update describe normal completion; faults and constrained unpredictable overlaps are not modeled. This is not full instruction semantics or recovered type information.\"}}", .{ if (e.pre_index) @as([]const u8, "add") else "identity", @as(i16, if (e.pre_index) e.immediate else 0), e.immediate });
}

test "scalar writeback literal assembled words and signed boundaries" {
    const e = decode(0xf8428e61).?; // ldr x1, [x19, #40]!
    try std.testing.expectEqual(@as(u5, 19), e.base);
    try std.testing.expectEqual(@as(i16, 40), e.immediate);
    try std.testing.expectEqual(@as(u64, 1040), e.effectiveAddress(1000));
    try std.testing.expectEqual(@as(u64, 1040), e.updatedBase(1000));
    for (0..512) |imm| {
        const p = decode(0xf8000422 | (@as(u32, @intCast(imm)) << 12)).?;
        const signed: i16 = if (imm < 256) @intCast(imm) else @as(i16, @intCast(imm)) - 512;
        try std.testing.expectEqual(signed, p.immediate);
        try std.testing.expectEqual(@as(u64, 1024), p.effectiveAddress(1024));
        try std.testing.expectEqual(@as(u64, @intCast(1024 + signed)), p.updatedBase(1024));
    }
}

test "unsupported and overlap encodings do not claim addressing evidence" {
    for ([_]u32{ 0, 0xffffffff, 0xf9400261, 0xf8400261, 0xf8400a61, 0x3cc10c22, 0xa9bf7bfd, 0xb8800c22, 0xf8400c21, 0xf8600c22 }) |word|
        try std.testing.expect(decode(word) == null);
    try std.testing.expect(decode(0xf8400fff) != null); // SP base and XZR data
}

test "native scalar pre and post load store pointer oracle" {
    if (builtin.cpu.arch != .aarch64) return error.SkipZigTest;
    var cells = [_]u64{ 11, 22, 33 };
    const start = @intFromPtr(&cells[0]);
    var loaded: u64 = undefined;
    const after_pre = asm volatile ("ldr x1, [x0, #8]!\nstr x1, [%[out]]"
        : [base] "={x0}" (-> u64),
        : [old] "{x0}" (start),
          [out] "r" (&loaded),
        : .{ .x1 = true, .memory = true });
    try std.testing.expectEqual(@as(u64, 22), loaded);
    try std.testing.expectEqual(decode(0xf8408c01).?.updatedBase(start), after_pre);
    const after_post = asm volatile ("str x1, [x0], #8"
        : [base] "={x0}" (-> u64),
        : [old] "{x0}" (after_pre),
          [value] "{x1}" (@as(u64, 77)),
        : .{ .memory = true });
    try std.testing.expectEqual(@as(u64, 77), cells[1]);
    try std.testing.expectEqual(decode(0xf8008401).?.updatedBase(after_pre), after_post);
}

test "clang assembled scalar widths modes and register roles" {
    // clang -c on Darwin ARM64, objdump __text words, independent of decoder.
    const words = [_]u32{ 0xf8428e61, 0xf8100422, 0x384ffc83, 0x781fe7e5, 0xb84044e6, 0xf81f8fff };
    const widths = [_]u7{ 64, 64, 8, 16, 32, 64 };
    const immediates = [_]i16{ 40, -256, 255, -2, 4, -8 };
    const bases = [_]u5{ 19, 1, 4, 31, 7, 31 };
    const registers = [_]u5{ 1, 2, 3, 5, 6, 31 };
    for (words, 0..) |word, i| {
        const e = decode(word).?;
        try std.testing.expectEqual(widths[i], e.width_bits);
        try std.testing.expectEqual(immediates[i], e.immediate);
        try std.testing.expectEqual(bases[i], e.base);
        try std.testing.expectEqual(registers[i], e.data);
        try std.testing.expectEqual(i == 0 or i == 2 or i == 4, e.load);
        try std.testing.expectEqual(i == 0 or i == 2 or i == 5, e.pre_index);
    }
}

test "addressing JSON is separate and marks base update as arithmetic" {
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try writeJsonMember(&output.writer, 0xf8428e61);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"scope\":\"addressing_only\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"base_update\":{\"operation\":\"add\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"dereference\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"status\":\"modeled\"") == null);
    const len = output.written().len;
    try writeJsonMember(&output.writer, 0xf8400c21);
    try std.testing.expectEqual(len, output.written().len);
}
