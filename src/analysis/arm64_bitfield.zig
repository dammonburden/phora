const std = @import("std");

pub const Extension = enum { signed, zero };
pub const Effect = struct {
    width: u7,
    source: u5,
    destination: u5,
    field_lsb: u6,
    field_width_bits: u7,
    extension: Extension,

    pub fn result(self: Effect, source_before: u64) u64 {
        const width_mask: u64 = if (self.width == 64) std.math.maxInt(u64) else std.math.maxInt(u32);
        const field_mask: u64 = if (self.field_width_bits == 64) std.math.maxInt(u64) else (@as(u64, 1) << @as(u6, @intCast(self.field_width_bits))) - 1;
        const field = (if (self.source == 31) 0 else source_before >> self.field_lsb) & field_mask;
        const sign = @as(u64, 1) << @as(u6, @intCast(self.field_width_bits - 1));
        return (if (self.extension == .signed and field & sign != 0) field | ~field_mask else field) & width_mask;
    }
};

/// Only non-wrapping SBFM/UBFM extraction; BFM and insertion forms are omitted.
pub fn decode(word: u32) ?Effect {
    if (word & 0x1f800000 != 0x13000000) return null;
    const sf = word >> 31;
    const opc: u2 = @truncate(word >> 29);
    if (opc != 0 and opc != 2) return null;
    if ((word >> 22) & 1 != sf) return null;
    const width: u7 = if (sf == 1) 64 else 32;
    const immr: u6 = @truncate(word >> 16);
    const imms: u6 = @truncate(word >> 10);
    if (immr >= width or imms >= width or immr > imms) return null;
    return .{ .width = width, .source = @truncate(word >> 5), .destination = @truncate(word), .field_lsb = immr, .field_width_bits = @as(u7, imms) - immr + 1, .extension = if (opc == 0) .signed else .zero };
}

fn writeRegister(w: anytype, register: u5, width: u7) !void {
    try w.print("{{\"kind\":\"{s}\",\"index\":{d},\"width_bits\":{d}}}", .{ if (register == 31) @as([]const u8, "zero_register") else "gpr", register, width });
}

pub fn writeJsonMember(w: anytype, word: u32) !void {
    const e = decode(word) orelse return;
    try w.print(",\"bitfield_evidence\":{{\"model\":\"a64_nonwrapping_bitfield_extract_v1\",\"encoding\":\"0x{x:0>8}\",\"width_bits\":{d},\"field_lsb\":{d},\"field_width_bits\":{d},\"extension\":\"{s}\",\"source\":", .{ word, e.width, e.field_lsb, e.field_width_bits, @tagName(e.extension) });
    try writeRegister(w, e.source, e.width);
    try w.writeAll(",\"destination\":");
    try writeRegister(w, e.destination, e.width);
    try w.print(",\"discard_destination_write\":{},\"w_write_zero_extends_x\":{},\"flags_written\":false,\"flags\":\"unchanged\",\"source_read_phase\":\"before_destination_update\",\"source_state\":\"current_instruction_register_values\",\"result_rule\":\"Extract field_width_bits starting at field_lsb from source_before; sign-extend or zero-extend the extracted field to width_bits. A signed one-bit field yields all ones within width_bits when the extracted bit is 1, otherwise zero. A W destination write zero-extends the resulting 32-bit value into X.\"}}", .{ e.destination == 31, e.width == 32 and e.destination != 31 });
}

fn reference(e: Effect, value: u64) u64 {
    var out: u64 = 0;
    var bit: u7 = 0;
    while (bit < e.width) : (bit += 1) {
        const source_bit: u7 = if (bit < e.field_width_bits) e.field_lsb + bit else e.field_lsb + e.field_width_bits - 1;
        if ((bit < e.field_width_bits or e.extension == .signed) and ((value >> @as(u6, @intCast(source_bit))) & 1) != 0)
            out |= @as(u64, 1) << @as(u6, @intCast(bit));
    }
    return out;
}

test "all nonwrapping fields agree with independent bitwise extension" {
    for ([_]u7{ 32, 64 }) |width| {
        var lsb: u7 = 0;
        while (lsb < width) : (lsb += 1) {
            var length: u7 = 1;
            while (length <= width - lsb) : (length += 1) {
                for ([_]Extension{ .signed, .zero }) |extension| {
                    const word: u32 = 0x13000020 | (if (width == 64) @as(u32, 0x80400000) else 0) | (if (extension == .zero) @as(u32, 0x40000000) else 0) | (@as(u32, lsb) << 16) | (@as(u32, lsb + length - 1) << 10);
                    const e = decode(word).?;
                    try std.testing.expectEqual(length, e.field_width_bits);
                    const sign_bit = @as(u64, 1) << @as(u6, @intCast(lsb + length - 1));
                    for ([_]u64{ 0, 1, 2, std.math.maxInt(u64), 0xaaaaaaaaaaaaaaaa, 0x5555555555555555, sign_bit, sign_bit - 1, sign_bit +% 1 }) |value|
                        try std.testing.expectEqual(reference(e, value), e.result(value));
                }
            }
        }
    }
}

test "literal signed one bit and excluded encodings" {
    const e = decode(0x1300014c).?;
    try std.testing.expectEqual(@as(u5, 10), e.source);
    try std.testing.expectEqual(@as(u5, 12), e.destination);
    try std.testing.expectEqual(@as(u7, 1), e.field_width_bits);
    try std.testing.expectEqual(@as(u64, 0xffffffff), e.result(1));
    try std.testing.expectEqual(@as(u64, 0), e.result(2));
    for ([_]u32{ 0x3300014c, 0x7300014c, 0x1340014c, 0x9300014c, 0x1320014c, 0x1300814c, 0x1301014c, 0x1200014c }) |word|
        try std.testing.expect(decode(word) == null);
    try std.testing.expectEqual(@as(u64, 0), decode(0x130003ec).?.result(std.math.maxInt(u64)));
}

test "JSON states bit semantics and before write source phase" {
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try writeJsonMember(&output.writer, 0x1300014c);
    for ([_][]const u8{ "\"field_width_bits\":1", "\"extension\":\"signed\"", "\"w_write_zero_extends_x\":true", "\"flags_written\":false", "\"source_read_phase\":\"before_destination_update\"", "signed one-bit field yields all ones" }) |needle|
        try std.testing.expect(std.mem.indexOf(u8, output.written(), needle) != null);
    const length = output.written().len;
    try writeJsonMember(&output.writer, 0x1301014c);
    try std.testing.expectEqual(length, output.written().len);
}
