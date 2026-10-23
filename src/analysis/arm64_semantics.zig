const std = @import("std");
const builtin = @import("builtin");

pub const Operation = enum(u2) { movn = 0, movz = 2, movk = 3 };

/// A bitvector transfer over the 64-bit X register backing W/X views.
/// This models normal execution, not instruction-fetch faults or debug traps.
pub const RegisterEffect = struct {
    operation: Operation,
    width_bits: u7,
    register: u5,
    immediate: u16,
    shift: u6,
    preserve_mask: u64,
    value_bits: u64,

    pub fn discardsWrite(self: RegisterEffect) bool {
        return self.register == 31;
    }

    pub fn readsDestination(self: RegisterEffect) bool {
        return self.operation == .movk and !self.discardsWrite();
    }

    pub fn resultBits(self: RegisterEffect, old_x: u64) u64 {
        const source = if (self.discardsWrite()) 0 else old_x;
        return (source & self.preserve_mask) | self.value_bits;
    }
};

pub const Decode = union(enum) {
    modeled: RegisterEffect,
    unsupported,
    invalid_encoding,
};

/// Decode the move-wide family from encoding bits, never mnemonic aliases.
pub fn decode(word: u32) Decode {
    if (word & 0x1f800000 != 0x12800000) return .unsupported;
    const wide = word >> 31 != 0;
    const opc: u2 = @truncate(word >> 29);
    const lane: u2 = @truncate(word >> 21);
    if (opc == 1 or (!wide and lane >= 2)) return .invalid_encoding;
    const operation: Operation = @fromBackingInt(@intCast(opc));
    const shift: u6 = @as(u6, lane) * 16;
    const immediate: u16 = @truncate(word >> 5);
    const mask: u64 = if (wide) std.math.maxInt(u64) else std.math.maxInt(u32);
    const inserted = @as(u64, immediate) << shift;
    return .{ .modeled = .{
        .operation = operation,
        .width_bits = if (wide) 64 else 32,
        .register = @truncate(word),
        .immediate = immediate,
        .shift = shift,
        .preserve_mask = if (operation == .movk) mask & ~(@as(u64, 0xffff) << shift) else 0,
        .value_bits = if (operation == .movn) ~inserted & mask else inserted,
    } };
}

pub fn writeJson(w: *std.Io.Writer, word: u32) !void {
    const decoded = decode(word);
    try w.writeAll("{\"model\":");
    if (decoded == .unsupported) try w.writeAll("null") else try w.writeAll("\"a64_move_wide_v1\"");
    try w.print(",\"encoding\":\"0x{x:0>8}\",\"status\":", .{word});
    switch (decoded) {
        .unsupported => try w.writeAll("\"unsupported\"}"),
        .invalid_encoding => try w.writeAll("\"invalid_encoding\"}"),
        .modeled => |effect| {
            try w.print("\"modeled\",\"operation\":\"{s}\",\"width_bits\":{d},\"immediate\":{d},\"shift\":{d}", .{
                @tagName(effect.operation), effect.width_bits, effect.immediate, effect.shift,
            });
            try w.print(",\"destination\":{{\"kind\":\"{s}\",\"index\":{d},\"storage_width_bits\":64}},\"discard_write\":{},\"reads_destination\":{}", .{
                if (effect.discardsWrite()) @as([]const u8, "zero_register") else "gpr",
                effect.register,
                effect.discardsWrite(),
                effect.readsDestination(),
            });
            try w.print(",\"transfer\":{{\"op\":\"masked_insert\",\"preserve_mask\":\"0x{x:0>16}\",\"value_bits\":\"0x{x:0>16}\"}}", .{
                effect.preserve_mask, effect.value_bits,
            });
            try w.writeAll(",\"flags_written\":false,\"memory\":\"none\",\"control_flow\":\"fallthrough\",\"pc_delta\":4}");
        },
    }
}

fn encode(wide: bool, op: Operation, lane: u2, imm: u16, rd: u5) u32 {
    return (@as(u32, @intFromBool(wide)) << 31) | (@as(u32, @backingInt(op)) << 29) |
        0x12800000 | (@as(u32, lane) << 21) | (@as(u32, imm) << 5) | rd;
}

// Independent lane-wise reference: replace 16-bit lanes rather than mask bits.
fn laneReference(wide: bool, op: Operation, lane: usize, imm: u16, old: u64) u64 {
    var lanes: [4]u16 = undefined;
    inline for (0..4) |i| {
        lanes[i] = if (!wide and i >= 2) 0 else if (i == lane)
            (if (op == .movn) ~imm else imm)
        else switch (op) {
            .movn => 0xffff,
            .movz => 0,
            .movk => @truncate(old >> (i * 16)),
        };
    }
    var result: u64 = 0;
    inline for (0..4) |i| result |= @as(u64, lanes[i]) << (i * 16);
    return result;
}

test "move-wide: exhaustive immediates across operations, widths and lanes" {
    for ([_]bool{ false, true }) |wide| {
        for ([_]Operation{ .movn, .movz, .movk }) |op| {
            for (0..@as(usize, if (wide) 4 else 2)) |lane| {
                for (0..65536) |imm| {
                    const effect = decode(encode(wide, op, @intCast(lane), @intCast(imm), 7)).modeled;
                    const old: u64 = 0x0123456789abcdef;
                    try std.testing.expectEqual(laneReference(wide, op, lane, @intCast(imm), old), effect.resultBits(old));
                }
            }
        }
    }
}

test "move-wide: all registers, zero register, old states and W zero extension" {
    for ([_]bool{ false, true }) |wide| {
        for ([_]Operation{ .movn, .movz, .movk }) |op| {
            for (0..@as(usize, if (wide) 4 else 2)) |lane| {
                for (0..32) |rd| {
                    for ([_]u64{ 0, 0xffffffffffffffff, 0x8000000080000000, 0x55aa55aa55aa55aa }) |old| {
                        const effect = decode(encode(wide, op, @intCast(lane), 0xabcd, @intCast(rd))).modeled;
                        try std.testing.expectEqual(rd == 31, effect.discardsWrite());
                        try std.testing.expectEqual(op == .movk and rd != 31, effect.readsDestination());
                        try std.testing.expectEqual(@as(u7, if (wide) 64 else 32), effect.width_bits);
                        try std.testing.expectEqual(rd, effect.register);
                        try std.testing.expectEqual(laneReference(wide, op, lane, 0xabcd, if (rd == 31) 0 else old), effect.resultBits(old));
                        if (!wide) try std.testing.expectEqual(@as(u64, 0), effect.resultBits(old) >> 32);
                    }
                }
            }
        }
    }
}

test "move-wide: reserved encodings are not modeled and other families are unsupported" {
    for ([_]u32{ 0x32800000, 0xb2800000, 0x52c00000, 0x52e00000, 0x12c00000, 0x72e00000 }) |word|
        try std.testing.expect(decode(word) == .invalid_encoding);
    for ([_]u32{ 0xd503201f, 0xd65f03c0, 0xaa0003e1, 0x91000400, 0, 0xffffffff }) |word|
        try std.testing.expect(decode(word) == .unsupported);
}

test "move-wide: fixed native instruction oracle" {
    if (builtin.cpu.arch != .aarch64) return error.SkipZigTest;
    const old: u64 = 0xfedcba9876543210;
    const got_wk = asm volatile ("movk w0, #0xabcd, lsl #16"
        : [out] "={x0}" (-> u64),
        : [old] "{x0}" (old),
    );
    const got_xk = asm volatile ("movk x0, #0xabcd, lsl #48"
        : [out] "={x0}" (-> u64),
        : [old] "{x0}" (old),
    );
    const got_wn = asm volatile ("movn w0, #0xabcd, lsl #16"
        : [out] "={x0}" (-> u64),
    );
    const got_xn = asm volatile ("movn x0, #0xabcd, lsl #48"
        : [out] "={x0}" (-> u64),
    );
    const got_wz = asm volatile ("movz w0, #0xabcd, lsl #16"
        : [out] "={x0}" (-> u64),
    );
    const got_xz = asm volatile ("movz x0, #0xabcd, lsl #48"
        : [out] "={x0}" (-> u64),
    );
    // Literal words also test field extraction independently of encode().
    const words = [_]u32{ 0x72b579a0, 0xf2f579a0, 0x12b579a0, 0x92f579a0, 0x52b579a0, 0xd2f579a0 };
    for (words, [_]u64{ got_wk, got_xk, got_wn, got_xn, got_wz, got_xz }) |word, actual|
        try std.testing.expectEqual(actual, decode(word).modeled.resultBits(old));
}

test "unsupported instruction has no claimed semantics model" {
    var w = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer w.deinit();
    try writeJson(&w.writer, 0x38e08108);
    const p = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, w.written(), .{});
    defer p.deinit();
    try std.testing.expect(p.value.object.get("model").? == .null);
    try std.testing.expectEqualStrings("unsupported", p.value.object.get("status").?.string);
}
