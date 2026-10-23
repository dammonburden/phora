const std = @import("std");

/// Ordinary GPR LDP/STP immediate subset, on normal completion only.
/// This describes per-element addresses and writeback, not memory ordering,
/// atomicity, faults, tags, alignment or privilege checks. LDPSW is not accepted.
pub const Effect = struct {
    base: u5,
    data: [2]u5,
    width_bits: u7,
    immediate: i16,
    load: bool,
    writeback: bool,
    pre_index: bool,

    pub fn updatedBase(self: Effect, old: u64) u64 {
        return if (self.writeback) old +% @as(u64, @bitCast(@as(i64, self.immediate))) else old;
    }

    pub fn effectiveAddress(self: Effect, old: u64, element: u1) u64 {
        const offset: i64 = (if (self.pre_index or !self.writeback) @as(i64, self.immediate) else 0) + @as(i64, element) * (self.width_bits / 8);
        return old +% @as(u64, @bitCast(offset));
    }
};

pub fn decode(word: u32) ?Effect {
    // opc:31..30, fixed 101:29..27, V=0:26, fixed 0:25,
    // addressing mode:24..23, L:22, signed scaled imm7:21..15.
    if (word & 0x3e000000 != 0x28000000) return null;
    const opc: u2 = @truncate(word >> 30);
    const mode: u2 = @truncate(word >> 23);
    // Reject SIMD, non-temporal mode 00, LDPSW and unallocated opc 11.
    if ((opc != 0 and opc != 2) or mode == 0) return null;
    const base: u5 = @truncate(word >> 5);
    const data = [2]u5{ @truncate(word), @truncate(word >> 10) };
    const load = word & 0x00400000 != 0;
    const writeback = mode != 2;
    // Both restrictions are constrained unpredictable, including duplicate
    // load destinations XZR/WZR. SP base and ZR data have distinct roles.
    if (load and data[0] == data[1]) return null;
    if (writeback and base != 31 and (base == data[0] or base == data[1])) return null;
    const width: u7 = if (opc == 2) 64 else 32;
    return .{
        .base = base,
        .data = data,
        .width_bits = width,
        .immediate = std.math.signExtend(i16, @as(u7, @truncate(word >> 15))) * @as(i16, width / 8),
        .load = load,
        .writeback = writeback,
        .pre_index = mode == 3,
    };
}

test "pair independent clang literals cover width mode sign and SP ZR" {
    // clang -target arm64-apple-macos; otool -s __TEXT __text.
    const words = [_]u32{ 0xa984346c, 0xa9bc346c, 0xa9c4346c, 0xa9fc346c, 0xa884346c, 0xa8fc346c, 0x29817fe1, 0x29ff7fe2, 0x29018864, 0xa9418c62 };
    const offsets = [_]i16{ 64, -64, 64, -64, 64, -64, 8, -8, 12, 24 };
    for (words, offsets, 0..) |word, offset, i| {
        const e = decode(word).?;
        try std.testing.expectEqual(offset, e.immediate);
        try std.testing.expectEqual(i != 8 and i != 9, e.writeback);
        try std.testing.expectEqual(i == 2 or i == 3 or i == 5 or i == 7 or i == 9, e.load);
        try std.testing.expectEqual(if (i == 6 or i == 7 or i == 8) @as(u7, 32) else @as(u7, 64), e.width_bits);
    }
    try std.testing.expectEqual(@as(u5, 31), decode(words[6]).?.base);
    try std.testing.expectEqual(@as(u5, 31), decode(words[6]).?.data[1]);
}

test "pair every signed imm7 address and writeback mode wraps modulo 64" {
    for ([_]u32{ 0x28800820, 0x29800820, 0x29000820, 0xa8800820, 0xa9800820, 0xa9000820 }) |base| {
        for (0..128) |imm| {
            const e = decode(base | (@as(u32, @intCast(imm)) << 15)).?;
            const signed: i64 = if (imm < 64) @intCast(imm) else @as(i64, @intCast(imm)) - 128;
            const offset = signed * (e.width_bits / 8);
            try std.testing.expectEqual(offset, e.immediate);
            for ([_]u64{ 0, 1, 1024, 0xffffffffffffffff }) |old| {
                const delta: u64 = @bitCast(offset);
                const first = old +% if (e.pre_index or !e.writeback) delta else 0;
                try std.testing.expectEqual(first, e.effectiveAddress(old, 0));
                try std.testing.expectEqual(first +% (e.width_bits / 8), e.effectiveAddress(old, 1));
                try std.testing.expectEqual(old +% if (e.writeback) delta else 0, e.updatedBase(old));
            }
        }
    }
}

test "pair constrained overlaps SIMD LDPSW and non-temporal are rejected" {
    for ([_]u32{ 0x28800000, 0x29800000, 0xa8800000, 0xa9800000 }) |base| {
        for (0..31) |n| {
            const reg: u32 = @intCast(n);
            const other: u32 = (reg + 1) % 31;
            for ([_]u32{ base, base | 0x00400000 }) |op| {
                try std.testing.expect(decode(op | reg | (reg << 5) | (other << 10)) == null);
                try std.testing.expect(decode(op | other | (reg << 5) | (reg << 10)) == null);
            }
        }
    }
    for (0..32) |reg| {
        const r: u32 = @intCast(reg);
        try std.testing.expect(decode(0xa9400000 | r | (r << 10) | (31 << 5)) == null);
    }
    // Duplicate store inputs are valid; no-WB base/data overlap is valid.
    try std.testing.expect(decode(0xa9000000) != null);
    try std.testing.expect(decode(0xa9400400) != null);
    try std.testing.expect(decode(0xa9bf7fff) != null); // STP ZR,ZR,[SP,#-16]!
    try std.testing.expect(decode(0xa9ff7fe0) != null); // LDP X0,ZR,[SP,#-16]!
    for ([_]u32{ 0x69400440, 0x69c00440, 0xe9400440, 0xa8000440, 0xa8400440, 0x28000440, 0x28400440, 0xad000440, 0x2d400440, 0xed400440 }) |word| {
        try std.testing.expect(decode(word) == null);
    }
    try std.testing.expect(decode(0x29400440) != null);
}
