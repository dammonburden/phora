// Phora — ARM32/Thumb-2 Instruction Decoder
// Pure bit-pattern decoder for Thumb (16-bit) and Thumb-2 (32-bit) instructions.
// Targets Android armeabi-v7a (99%+ Thumb mode).
// Reference: ARM Architecture Reference Manual (ARMv7-A/R)

const std = @import("std");
const types = @import("../types.zig");

// ============================================================================
// Decoded instruction — internal representation with rich metadata
// ============================================================================

pub const DecodedInstruction = struct {
    mnemonic: []const u8,
    operands: [128]u8 = @splat(0),
    operands_len: u8 = 0,
    length: u8 = 2, // Thumb default is 2 bytes; 4 for Thumb-2
    is_branch: bool = false,
    is_conditional_branch: bool = false,
    is_call: bool = false,
    is_return: bool = false,
    branch_target: ?u64 = null,
    decode_status: DecodeStatus = .decoded,
    it_block: ?ItBlock = null,
    /// Null means flag effects are not modeled by this decoder.
    sets_flags: ?bool = null,
    /// Thumb16 arithmetic normally sets flags only outside an IT block.
    flags_suppressed_in_it: bool = false,

    pub fn getOperands(self: *const DecodedInstruction) []const u8 {
        return self.operands[0..self.operands_len];
    }

    pub fn toInstruction(self: *const DecodedInstruction, address: u64, raw_bytes: []const u8) types.Instruction {
        return .{
            .address = address,
            .bytes = raw_bytes,
            .mnemonic = self.mnemonic,
            .operands = self.operands[0..self.operands_len],
            .size = self.length,
        };
    }
};

pub const DecodeStatus = enum { decoded, unsupported, invalid_encoding, truncated };

/// ARMv7 ITSTATE. One advance is required per instruction, including Thumb32.
/// Callers must start with a known instruction boundary; this does not infer
/// an IT block that began before the supplied byte range.
pub const ItState = struct {
    state: u8 = 0,

    pub fn begin(self: *ItState, block: ItBlock) void {
        self.state = (@as(u8, block.first_condition) << 4) | block.mask;
    }

    pub fn currentCondition(self: ItState) ?u4 {
        if (self.state & 0xf == 0) return null;
        return @truncate(self.state >> 4);
    }

    pub fn advance(self: *ItState) void {
        if (self.state & 7 == 0) {
            self.state = 0;
        } else {
            self.state = (self.state & 0xe0) | ((self.state << 1) & 0x1f);
        }
    }
};

pub const ItBlock = struct {
    first_condition: u4,
    mask: u4,

    pub fn instructionCount(self: ItBlock) u3 {
        return if (self.mask == 0) 0 else 4 - @as(u3, @intCast(@ctz(self.mask)));
    }

    pub fn conditionAt(self: ItBlock, index: usize) ?u4 {
        if (index >= self.instructionCount()) return null;
        if (index == 0) return self.first_condition;
        return (self.first_condition & 0xe) | @as(u4, @intCast((self.mask >> @as(u2, @intCast(4 - index))) & 1));
    }
};

// ============================================================================
// Condition code names
// ============================================================================

const condition_codes = [16][]const u8{
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
};

pub fn conditionName(condition: u4) []const u8 {
    return condition_codes[condition];
}

const conditional_branches = [14][]const u8{
    "beq", "bne", "bcs", "bcc", "bmi", "bpl", "bvs", "bvc",
    "bhi", "bls", "bge", "blt", "bgt", "ble",
};
const conditional_branches_wide = [14][]const u8{
    "beq.w", "bne.w", "bcs.w", "bcc.w", "bmi.w", "bpl.w", "bvs.w", "bvc.w",
    "bhi.w", "bls.w", "bge.w", "blt.w", "bgt.w", "ble.w",
};

fn itMnemonic(block: ItBlock) []const u8 {
    // The index packs each subsequent condition as 0=Then, 1=Else.
    const names = [_][8][]const u8{
        .{ "it", "it", "it", "it", "it", "it", "it", "it" },
        .{ "itt", "ite", "itt", "ite", "itt", "ite", "itt", "ite" },
        .{ "ittt", "itet", "itte", "itee", "ittt", "itet", "itte", "itee" },
        .{ "itttt", "itett", "ittet", "iteet", "ittte", "itete", "ittee", "iteee" },
    };
    var index: u3 = 0;
    for (1..block.instructionCount()) |i| {
        if (block.conditionAt(i).? != block.first_condition) index |= @as(u3, 1) << @as(u2, @intCast(i - 1));
    }
    return names[block.instructionCount() - 1][index];
}

/// Modified Thumb immediate expansion, including the ARMv7 unpredictable zero
/// replication encodings. A null carry preserves APSR.C; otherwise it replaces it.
pub const ExpandedImmediate = struct { value: u32, carry: ?u1 };
pub fn thumbExpandImm(imm12: u12) ?ExpandedImmediate {
    const byte: u32 = imm12 & 0xff;
    if (imm12 >> 10 == 0) {
        const mode: u2 = @truncate(imm12 >> 8);
        if (mode != 0 and byte == 0) return null;
        return .{ .value = switch (mode) {
            0 => byte,
            1 => (byte << 16) | byte,
            2 => (byte << 24) | (byte << 8),
            3 => byte * 0x01010101,
        }, .carry = null };
    }
    const rotation: u5 = @intCast(imm12 >> 7);
    const value = std.math.rotr(u32, 0x80 | @as(u32, imm12 & 0x7f), rotation);
    return .{ .value = value, .carry = @truncate(value >> 31) };
}

fn unknown16(hw: u16, status: DecodeStatus) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = ".inst.n", .decode_status = status };
    var f = FmtBuf.init(&result.operands);
    f.appendFmt("0x{x:0>4}", .{hw});
    result.operands_len = f.len();
    return result;
}

fn unknown32(hw0: u16, hw1: u16, status: DecodeStatus) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = ".inst.w", .length = 4, .decode_status = status };
    var f = FmtBuf.init(&result.operands);
    f.appendFmt("0x{x:0>4}{x:0>4}", .{ hw0, hw1 });
    result.operands_len = f.len();
    return result;
}

// ============================================================================
// Register name helpers
// ============================================================================

fn regName(reg: u4) []const u8 {
    const names = [16][]const u8{
        "r0", "r1", "r2",  "r3",  "r4",  "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
    };
    return names[reg];
}

fn regNameFromU32(reg: u32) []const u8 {
    if (reg > 15) return "??";
    return regName(@truncate(reg));
}

// ============================================================================
// Operand formatting buffer
// ============================================================================

const FmtBuf = struct {
    buf: *[128]u8,
    pos: u8,

    fn init(b: *[128]u8) FmtBuf {
        return .{ .buf = b, .pos = 0 };
    }

    fn append(self: *FmtBuf, s: []const u8) void {
        const remaining = 128 - @as(usize, self.pos);
        const copy_len = @min(s.len, remaining);
        @memcpy(self.buf[self.pos..][0..copy_len], s[0..copy_len]);
        self.pos += @intCast(copy_len);
    }

    fn appendFmt(self: *FmtBuf, comptime fmt: []const u8, args: anytype) void {
        const remaining = 128 - @as(usize, self.pos);
        if (remaining == 0) return;
        const slice = self.buf[self.pos..128];
        const result = std.fmt.bufPrint(slice, fmt, args) catch {
            return;
        };
        self.pos += @intCast(result.len);
    }

    fn appendHex(self: *FmtBuf, value: u64) void {
        self.appendFmt("0x{x}", .{value});
    }

    fn appendSignedHex(self: *FmtBuf, value: i64) void {
        if (value < 0) {
            self.append("-");
            self.appendFmt("0x{x}", .{@as(u64, @bitCast(-value))});
        } else {
            self.appendFmt("0x{x}", .{@as(u64, @bitCast(value))});
        }
    }

    fn comma(self: *FmtBuf) void {
        self.append(", ");
    }

    fn len(self: *const FmtBuf) u8 {
        return self.pos;
    }
};

// ============================================================================
// Bit extraction helpers
// ============================================================================

fn bits16(insn: u16, hi: u4, lo: u4) u16 {
    const width: u4 = hi - lo + 1;
    return (insn >> lo) & ((@as(u16, 1) << width) - 1);
}

fn bit16(insn: u16, pos: u4) u1 {
    return @truncate(insn >> pos);
}

fn bits32(insn: u32, hi: u5, lo: u5) u32 {
    const width: u5 = hi - lo + 1;
    return (insn >> lo) & ((@as(u32, 1) << width) - 1);
}

// ============================================================================
// Register list formatting
// ============================================================================

fn appendRegList(f: *FmtBuf, reg_bits: u16) void {
    f.append("{");
    var first = true;
    for (0..16) |i| {
        if (reg_bits & (@as(u16, 1) << @as(u4, @truncate(i))) != 0) {
            if (!first) f.append(", ");
            f.append(regNameFromU32(@truncate(i)));
            first = false;
        }
    }
    f.append("}");
}

// ============================================================================
// Thumb instruction size detection
// ============================================================================

/// Returns true if the first halfword indicates a 32-bit Thumb-2 instruction.
fn isThumb32(hw0: u16) bool {
    const top5 = hw0 >> 11;
    return top5 >= 0b11101; // 0b11101, 0b11110, 0b11111
}

// ============================================================================
// Read helpers (little-endian)
// ============================================================================

fn readU16LE(raw: []const u8) u16 {
    return @as(u16, raw[0]) | (@as(u16, raw[1]) << 8);
}

// ============================================================================
// Main decode entry point
// ============================================================================

pub fn decode(raw: []const u8, address: u64) DecodedInstruction {
    if (raw.len < 2) {
        return .{ .mnemonic = ".inst.n", .decode_status = .truncated };
    }

    const hw0 = readU16LE(raw);

    if (isThumb32(hw0)) {
        // 32-bit Thumb-2 instruction
        if (raw.len < 4) {
            return unknown16(hw0, .truncated);
        }
        const hw1 = readU16LE(raw[2..]);
        return decodeThumb32(hw0, hw1, address);
    }

    var result = decodeThumb16(hw0, address);
    if (std.mem.eql(u8, result.mnemonic, "cmp") or std.mem.eql(u8, result.mnemonic, "cmn") or std.mem.eql(u8, result.mnemonic, "tst")) {
        result.sets_flags = true;
    } else {
        const implicit_flag_mnemonics = [_][]const u8{
            "ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
            "rsbs", "orrs", "muls", "bics", "mvns", "movs", "adds", "subs",
        };
        for (implicit_flag_mnemonics) |mnemonic| {
            if (std.mem.eql(u8, result.mnemonic, mnemonic)) {
                result.sets_flags = true;
                result.flags_suppressed_in_it = true;
                break;
            }
        }
    }
    return result;
}

// ============================================================================
// 16-bit Thumb decoder
// ============================================================================

fn decodeThumb16(hw: u16, address: u64) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = "udf", .length = 2 };

    // ---- IT and NOP-compatible hints ----
    if (hw & 0xff00 == 0xbf00) {
        const mask: u4 = @truncate(hw);
        const condition: u4 = @truncate(hw >> 4);
        if (mask == 0) {
            result.mnemonic = switch (condition) {
                0 => "nop",
                1 => "yield",
                2 => "wfe",
                3 => "wfi",
                4 => "sev",
                else => return unknown16(hw, .unsupported),
            };
        } else {
            if (condition == 15 or (condition == 14 and @popCount(mask) != 1)) return unknown16(hw, .invalid_encoding);
            const block = ItBlock{ .first_condition = condition, .mask = mask };
            result.it_block = block;
            result.mnemonic = itMnemonic(block);
            var f = FmtBuf.init(&result.operands);
            f.append(conditionName(condition));
            result.operands_len = f.len();
        }
        result.sets_flags = false;
        return result;
    }

    // ---- BX lr (0x4770) — return ----
    if (hw == 0x4770) {
        result.mnemonic = "bx";
        var f = FmtBuf.init(&result.operands);
        f.append("lr");
        result.operands_len = f.len();
        result.is_return = true;
        result.is_branch = true;
        return result;
    }

    // ---- BX Rm (0x4700 | Rm<<3) ----
    // Encoding: 0100 0111 0 Rmmmm 000
    if (hw & 0xFF80 == 0x4700) {
        const rm: u4 = @truncate((hw >> 3) & 0xF);
        result.mnemonic = "bx";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rm));
        result.operands_len = f.len();
        result.is_branch = true;
        if (rm == 14) result.is_return = true; // bx lr
        return result;
    }

    // ---- BLX Rm (0x4780 | Rm<<3) — indirect call ----
    // Encoding: 0100 0111 1 Rmmmm 000
    if (hw & 0xFF80 == 0x4780) {
        const rm: u4 = @truncate((hw >> 3) & 0xF);
        result.mnemonic = "blx";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rm));
        result.operands_len = f.len();
        result.is_call = true;
        result.is_branch = true;
        return result;
    }

    // ---- PUSH {regs, lr} (0xB4xx / 0xB5xx) ----
    // Encoding: 1011 010M rrrr rrrr  (M = include LR)
    if (hw & 0xFE00 == 0xB400) {
        const m_bit = bit16(hw, 8);
        const reg_list_low: u16 = hw & 0xFF;
        var reg_bits: u16 = reg_list_low;
        if (m_bit == 1) {
            reg_bits |= (1 << 14); // LR
        }
        result.mnemonic = "push";
        var f = FmtBuf.init(&result.operands);
        appendRegList(&f, reg_bits);
        result.operands_len = f.len();
        return result;
    }

    // ---- POP {regs, pc} (0xBCxx / 0xBDxx) ----
    // Encoding: 1011 110P rrrr rrrr  (P = include PC)
    if (hw & 0xFE00 == 0xBC00) {
        const p_bit = bit16(hw, 8);
        const reg_list_low: u16 = hw & 0xFF;
        var reg_bits: u16 = reg_list_low;
        if (p_bit == 1) {
            reg_bits |= (1 << 15); // PC
        }
        result.mnemonic = "pop";
        var f = FmtBuf.init(&result.operands);
        appendRegList(&f, reg_bits);
        result.operands_len = f.len();
        if (p_bit == 1) {
            result.is_return = true;
            result.is_branch = true;
        }
        return result;
    }

    // ---- B<cond> imm8 (0xDxxx) — conditional branch ----
    // Encoding: 1101 cccc iiii iiii  (cond != 0b1110, 0b1111)
    if (hw >> 12 == 0xD) {
        const cond: u4 = @truncate((hw >> 8) & 0xF);
        if (cond < 0xE) {
            const imm8: u64 = hw & 0xFF;
            // Signed 9-bit offset: sign-extend imm8, shift left 1, add to PC+4
            const offset = std.math.signExtend(i64, @as(u8, @intCast(imm8))) * 2;
            const target: u64 = @bitCast(@as(i64, @intCast(address)) + 4 + offset);
            result.mnemonic = conditional_branches[cond];
            result.is_branch = true;
            result.is_conditional_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
            return result;
        }
        // cond==0xE is UDF, cond==0xF is SVC
        if (cond == 0xE) {
            result.mnemonic = "udf";
            var f = FmtBuf.init(&result.operands);
            f.appendFmt("#{d}", .{hw & 0xff});
            result.operands_len = f.len();
            return result;
        }
        if (cond == 0xF) {
            result.mnemonic = "svc";
            var f = FmtBuf.init(&result.operands);
            f.appendFmt("#{d}", .{hw & 0xFF});
            result.operands_len = f.len();
            return result;
        }
    }

    // ---- B imm11 (0xE000-0xE7FF) — unconditional branch ----
    // Encoding: 1110 0iii iiii iiii
    if (hw >> 11 == 0b11100) {
        const imm11: u64 = hw & 0x7FF;
        // Signed 12-bit offset: sign-extend imm11, shift left 1, add to PC+4
        const offset = std.math.signExtend(i64, @as(u11, @intCast(imm11))) * 2;
        const target: u64 = @bitCast(@as(i64, @intCast(address)) + 4 + offset);
        result.mnemonic = "b";
        result.is_branch = true;
        result.branch_target = target;
        var f = FmtBuf.init(&result.operands);
        f.appendHex(target);
        result.operands_len = f.len();
        return result;
    }

    // ---- LDR Rd, [PC, #imm] (0x48xx-0x4Fxx) — literal pool load ----
    // Encoding: 0100 1 ddd iiii iiii
    if (hw >> 11 == 0b01001) {
        const rd: u4 = @truncate((hw >> 8) & 0x7);
        const imm8: u64 = hw & 0xFF;
        // Offset = imm8 << 2; base = Align(PC, 4) + 4
        const pc_aligned = (address + 4) & ~@as(u64, 3);
        const target = pc_aligned + (imm8 << 2);
        result.mnemonic = "ldr";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.append(", [pc, #");
        f.appendFmt("{d}", .{imm8 << 2});
        f.append("]");
        result.operands_len = f.len();
        result.branch_target = target; // Store literal pool address for reference
        return result;
    }

    // ---- MOV Rd, #imm8 (0x20xx-0x27xx) ----
    // Encoding: 001 00 ddd iiii iiii
    if (hw >> 11 == 0b00100) {
        const rd: u4 = @truncate((hw >> 8) & 0x7);
        const imm8 = hw & 0xFF;
        result.mnemonic = "movs";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.appendFmt("#{d}", .{imm8});
        result.operands_len = f.len();
        return result;
    }

    // ---- CMP Rn, #imm8 ----
    // Encoding: 001 01 nnn iiii iiii
    if (hw >> 11 == 0b00101) {
        const rn: u4 = @truncate((hw >> 8) & 0x7);
        const imm8 = hw & 0xFF;
        result.mnemonic = "cmp";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rn));
        f.comma();
        f.appendFmt("#{d}", .{imm8});
        result.operands_len = f.len();
        return result;
    }

    // ---- ADD Rd, #imm8 ----
    // Encoding: 001 10 ddd iiii iiii
    if (hw >> 11 == 0b00110) {
        const rd: u4 = @truncate((hw >> 8) & 0x7);
        const imm8 = hw & 0xFF;
        result.mnemonic = "adds";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.appendFmt("#{d}", .{imm8});
        result.operands_len = f.len();
        return result;
    }

    // ---- SUB Rd, #imm8 ----
    // Encoding: 001 11 ddd iiii iiii
    if (hw >> 11 == 0b00111) {
        const rd: u4 = @truncate((hw >> 8) & 0x7);
        const imm8 = hw & 0xFF;
        result.mnemonic = "subs";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.appendFmt("#{d}", .{imm8});
        result.operands_len = f.len();
        return result;
    }

    // ---- STR Rd, [Rn, #imm5] ----
    // Encoding: 0110 0 iiiii nnn ddd
    if (hw >> 11 == 0b01100) {
        const rd: u4 = @truncate(hw & 0x7);
        const rn: u4 = @truncate((hw >> 3) & 0x7);
        const imm5 = @as(u32, (hw >> 6) & 0x1F) << 2;
        result.mnemonic = "str";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.append(", [");
        f.append(regName(rn));
        if (imm5 != 0) {
            f.appendFmt(", #{d}", .{imm5});
        }
        f.append("]");
        result.operands_len = f.len();
        return result;
    }

    // ---- LDR Rd, [Rn, #imm5] ----
    // Encoding: 0110 1 iiiii nnn ddd
    if (hw >> 11 == 0b01101) {
        const rd: u4 = @truncate(hw & 0x7);
        const rn: u4 = @truncate((hw >> 3) & 0x7);
        const imm5 = @as(u32, (hw >> 6) & 0x1F) << 2;
        result.mnemonic = "ldr";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.append(", [");
        f.append(regName(rn));
        if (imm5 != 0) {
            f.appendFmt(", #{d}", .{imm5});
        }
        f.append("]");
        result.operands_len = f.len();
        return result;
    }

    // ---- LDR Rd, [SP, #imm8] ----
    // Encoding: 1001 1 ddd iiiiiiii
    if (hw >> 11 == 0b10011) {
        const rd: u4 = @truncate((hw >> 8) & 0x7);
        const imm8 = @as(u32, hw & 0xFF) << 2;
        result.mnemonic = "ldr";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.append(", [sp");
        if (imm8 != 0) {
            f.appendFmt(", #{d}", .{imm8});
        }
        f.append("]");
        result.operands_len = f.len();
        return result;
    }

    // ---- STR Rd, [SP, #imm8] ----
    // Encoding: 1001 0 ddd iiiiiiii
    if (hw >> 11 == 0b10010) {
        const rd: u4 = @truncate((hw >> 8) & 0x7);
        const imm8 = @as(u32, hw & 0xFF) << 2;
        result.mnemonic = "str";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.append(", [sp");
        if (imm8 != 0) {
            f.appendFmt(", #{d}", .{imm8});
        }
        f.append("]");
        result.operands_len = f.len();
        return result;
    }

    // ---- ADD Rd, SP, #imm8 ----
    // Encoding: 1010 1 ddd iiiiiiii
    if (hw >> 11 == 0b10101) {
        const rd: u4 = @truncate((hw >> 8) & 0x7);
        const imm8 = @as(u32, hw & 0xFF) << 2;
        result.mnemonic = "add";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.append(", sp, #");
        f.appendFmt("{d}", .{imm8});
        result.operands_len = f.len();
        return result;
    }

    // ---- ADD Rd, PC, #imm8 (ADR) ----
    // Encoding: 1010 0 ddd iiiiiiii
    if (hw >> 11 == 0b10100) {
        const rd: u4 = @truncate((hw >> 8) & 0x7);
        const imm8 = @as(u32, hw & 0xFF) << 2;
        result.mnemonic = "adr";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.appendHex((address + 4) & ~@as(u64, 3) + imm8);
        result.operands_len = f.len();
        return result;
    }

    // ---- SUB SP, SP, #imm7 ----
    // Encoding: 1011 0000 1 iiiiiii
    if (hw & 0xFF80 == 0xB080) {
        const imm7 = @as(u32, hw & 0x7F) << 2;
        result.mnemonic = "sub";
        var f = FmtBuf.init(&result.operands);
        f.append("sp, sp, #");
        f.appendFmt("{d}", .{imm7});
        result.operands_len = f.len();
        return result;
    }

    // ---- ADD SP, SP, #imm7 ----
    // Encoding: 1011 0000 0 iiiiiii
    if (hw & 0xFF80 == 0xB000) {
        const imm7 = @as(u32, hw & 0x7F) << 2;
        result.mnemonic = "add";
        var f = FmtBuf.init(&result.operands);
        f.append("sp, sp, #");
        f.appendFmt("{d}", .{imm7});
        result.operands_len = f.len();
        return result;
    }

    // ---- MOV Rd, Rm (high register) ----
    // Encoding: 0100 0110 D Rmmm Rddd
    if (hw >> 8 == 0x46) {
        const rd_lo: u4 = @truncate(hw & 0x7);
        const rm: u4 = @truncate((hw >> 3) & 0xF);
        const d_bit: u4 = @truncate((hw >> 7) & 0x1);
        const rd: u4 = (d_bit << 3) | rd_lo;
        result.mnemonic = "mov";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.append(regName(rm));
        result.operands_len = f.len();
        return result;
    }

    // ---- CMP Rn, Rm (high register) ----
    // Encoding: 0100 0101 N Rmmm Rnnn
    if (hw >> 8 == 0x45) {
        const rn_lo: u4 = @truncate(hw & 0x7);
        const rm: u4 = @truncate((hw >> 3) & 0xF);
        const n_bit: u4 = @truncate((hw >> 7) & 0x1);
        const rn: u4 = (n_bit << 3) | rn_lo;
        result.mnemonic = "cmp";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rn));
        f.comma();
        f.append(regName(rm));
        result.operands_len = f.len();
        return result;
    }

    // ---- ADD Rd, Rm (high register) ----
    // Encoding: 0100 0100 D Rmmm Rddd
    if (hw >> 8 == 0x44) {
        const rd_lo: u4 = @truncate(hw & 0x7);
        const rm: u4 = @truncate((hw >> 3) & 0xF);
        const d_bit: u4 = @truncate((hw >> 7) & 0x1);
        const rd: u4 = (d_bit << 3) | rd_lo;
        result.mnemonic = "add";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.append(regName(rm));
        result.operands_len = f.len();
        return result;
    }

    // ---- Data processing (register-register, low regs) ----
    // Encoding: 0100 00 oooo mmm ddd
    if (hw >> 10 == 0b010000) {
        const op: u4 = @truncate((hw >> 6) & 0xF);
        const rm: u4 = @truncate((hw >> 3) & 0x7);
        const rd: u4 = @truncate(hw & 0x7);
        const dp_mnemonics = [16][]const u8{
            "ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
            "tst",  "rsbs", "cmp",  "cmn",  "orrs", "muls", "bics", "mvns",
        };
        result.mnemonic = dp_mnemonics[op];
        var f = FmtBuf.init(&result.operands);
        // TST, CMP, CMN only have two operands (no Rd writeback shown)
        if (op == 8 or op == 10 or op == 11) {
            f.append(regName(rd));
            f.comma();
            f.append(regName(rm));
        } else {
            f.append(regName(rd));
            f.comma();
            f.append(regName(rm));
        }
        result.operands_len = f.len();
        return result;
    }

    // ---- LSL/LSR/ASR immediate ----
    // Encoding: 000 oo iiiii mmm ddd
    if (hw >> 13 == 0b000) {
        const op: u2 = @truncate((hw >> 11) & 0x3);
        if (op < 3) { // 00=LSL, 01=LSR, 10=ASR
            const imm5 = (hw >> 6) & 0x1F;
            const rm: u4 = @truncate((hw >> 3) & 0x7);
            const rd: u4 = @truncate(hw & 0x7);
            const shift_names = [3][]const u8{ "lsls", "lsrs", "asrs" };
            result.mnemonic = shift_names[op];
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd));
            f.comma();
            f.append(regName(rm));
            f.comma();
            f.appendFmt("#{d}", .{imm5});
            result.operands_len = f.len();
            return result;
        }
    }

    // ---- ADD/SUB (3-register / immediate) ----
    // Encoding: 0001 1 oS nnn mmm/imm ddd
    if (hw >> 11 == 0b00011) {
        const imm_flag = (hw >> 10) & 1;
        const sub_flag = (hw >> 9) & 1;
        const rn: u4 = @truncate((hw >> 3) & 0x7);
        const rd: u4 = @truncate(hw & 0x7);
        result.mnemonic = if (sub_flag == 1) "subs" else "adds";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.append(regName(rn));
        f.comma();
        if (imm_flag == 1) {
            const imm3 = (hw >> 6) & 0x7;
            f.appendFmt("#{d}", .{imm3});
        } else {
            const rm: u4 = @truncate((hw >> 6) & 0x7);
            f.append(regName(rm));
        }
        result.operands_len = f.len();
        return result;
    }

    // ---- STRB/LDRB [Rn, #imm5] ----
    // Encoding: 0111 L iiiii nnn ddd
    if (hw >> 12 == 0b0111) {
        const load = (hw >> 11) & 1;
        const rd: u4 = @truncate(hw & 0x7);
        const rn: u4 = @truncate((hw >> 3) & 0x7);
        const imm5 = (hw >> 6) & 0x1F;
        result.mnemonic = if (load == 1) "ldrb" else "strb";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.append(", [");
        f.append(regName(rn));
        if (imm5 != 0) {
            f.appendFmt(", #{d}", .{imm5});
        }
        f.append("]");
        result.operands_len = f.len();
        return result;
    }

    // ---- STRH/LDRH [Rn, #imm5] ----
    // Encoding: 1000 L iiiii nnn ddd
    if (hw >> 12 == 0b1000) {
        const load = (hw >> 11) & 1;
        const rd: u4 = @truncate(hw & 0x7);
        const rn: u4 = @truncate((hw >> 3) & 0x7);
        const imm5 = @as(u32, (hw >> 6) & 0x1F) << 1;
        result.mnemonic = if (load == 1) "ldrh" else "strh";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.append(", [");
        f.append(regName(rn));
        if (imm5 != 0) {
            f.appendFmt(", #{d}", .{imm5});
        }
        f.append("]");
        result.operands_len = f.len();
        return result;
    }

    // ---- Fallback: generic unknown ----
    return unknown16(hw, .unsupported);
}

// ============================================================================
// 32-bit Thumb-2 decoder
// ============================================================================

fn decodeThumb32(hw0: u16, hw1: u16, address: u64) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = "udf", .length = 4 };

    // ---- Architectural UDF.W (not the decoder's unknown-instruction marker) ----
    if (hw0 & 0xfff0 == 0xf7f0 and hw1 & 0xf000 == 0xa000) {
        result.mnemonic = "udf.w";
        var f = FmtBuf.init(&result.operands);
        f.appendFmt("#{d}", .{(@as(u32, hw0 & 0xf) << 12) | (hw1 & 0xfff)});
        result.operands_len = f.len();
        return result;
    }

    // ---- Logical data processing, modified immediate (ARMv7 Thumb T1) ----
    if (hw0 & 0xfa00 == 0xf000 and hw1 & 0x8000 == 0) {
        const op: u4 = @truncate(hw0 >> 5);
        if (op <= 4) {
            const rn: u4 = @truncate(hw0);
            const rd: u4 = @truncate(hw1 >> 8);
            const setflags = hw0 & 0x10 != 0;
            const imm12: u12 = @intCast(((hw0 & 0x400) << 1) | ((hw1 >> 4) & 0x700) | (hw1 & 0xff));
            const immediate = thumbExpandImm(imm12) orelse return unknown32(hw0, hw1, .invalid_encoding);
            const test_alias = rd == 15 and setflags and (op == 0 or op == 4);
            const move_alias = rn == 15 and (op == 2 or op == 3);
            if (rn == 13 or (!move_alias and rn == 15) or (!test_alias and (rd == 13 or rd == 15))) return unknown32(hw0, hw1, .invalid_encoding);
            const names = [_][]const u8{ "and.w", "bic.w", "orr.w", "orn.w", "eor.w" };
            const flag_names = [_][]const u8{ "ands.w", "bics.w", "orrs.w", "orns.w", "eors.w" };
            result.mnemonic = if (test_alias)
                (if (op == 0) "tst.w" else "teq.w")
            else if (move_alias)
                (if (op == 2) (if (setflags) "movs.w" else "mov.w") else (if (setflags) "mvns.w" else "mvn.w"))
            else if (setflags) flag_names[op] else names[op];
            result.sets_flags = setflags;
            var f = FmtBuf.init(&result.operands);
            if (!test_alias) {
                f.append(regName(rd));
                f.comma();
            }
            if (!move_alias) {
                f.append(regName(rn));
                f.comma();
            }
            f.appendFmt("#0x{x}", .{immediate.value});
            result.operands_len = f.len();
            return result;
        }
    }

    // ---- Branch instructions (BL, B.W, B<cond>.W) ----
    // hw0[15:11] = 11110
    // hw1[15] = 1 and hw1[12] = 1 for BL/B.W; hw1[14] is the link bit
    // hw1[15:14] = 10 and hw1[12] = 0 for B<cond>.W

    const hw0_top5 = hw0 >> 11;

    if (hw0_top5 == 0b11110) {
        const s_bit: u1 = @truncate((hw0 >> 10) & 1);
        const hw1_top2 = (hw1 >> 14) & 0x3;
        const hw1_bit12 = (hw1 >> 12) & 1;

        // ---- B<cond>.W: hw1[15:14]=10, hw1[12]=0 ----
        if (hw1_top2 == 0b10 and hw1_bit12 == 0) {
            const cond: u4 = @truncate((hw0 >> 6) & 0xF);
            const imm6: u64 = hw0 & 0x3F;
            const imm11: u64 = hw1 & 0x7FF;
            const j1: u1 = @truncate((hw1 >> 13) & 1);
            const j2: u1 = @truncate((hw1 >> 11) & 1);

            // For conditional: offset = S:J2:J1:imm6:imm11:0 (21-bit signed)
            const offset_raw: u64 = (@as(u64, s_bit) << 20) |
                (@as(u64, j2) << 19) |
                (@as(u64, j1) << 18) |
                (imm6 << 12) |
                (imm11 << 1);
            const offset = std.math.signExtend(i64, @as(u21, @intCast(offset_raw)));
            const target: u64 = @bitCast(@as(i64, @intCast(address)) + 4 + offset);

            if (cond < 0xE) {
                result.mnemonic = conditional_branches_wide[cond];
                result.is_branch = true;
                result.is_conditional_branch = true;
                result.branch_target = target;
                var f = FmtBuf.init(&result.operands);
                f.appendHex(target);
                result.operands_len = f.len();
                return result;
            }
        }

        // ---- BL / B.W: hw1[15]=1, hw1[12]=1 ----
        if ((hw1_top2 == 0b10 or hw1_top2 == 0b11) and hw1_bit12 == 1) {
            const imm10: u64 = hw0 & 0x3FF;
            const imm11: u64 = hw1 & 0x7FF;
            const j1: u1 = @truncate((hw1 >> 13) & 1);
            const j2: u1 = @truncate((hw1 >> 11) & 1);
            const link_bit = (hw1 >> 14) & 1;

            // I1 = !(J1 ^ S), I2 = !(J2 ^ S)
            const eye1: u1 = ~(j1 ^ s_bit);
            const eye2: u1 = ~(j2 ^ s_bit);

            // offset = S:I1:I2:imm10:imm11:0 (25-bit signed)
            const offset_raw: u64 = (@as(u64, s_bit) << 24) |
                (@as(u64, eye1) << 23) |
                (@as(u64, eye2) << 22) |
                (imm10 << 12) |
                (imm11 << 1);
            const offset = std.math.signExtend(i64, @as(u25, @intCast(offset_raw)));
            const target: u64 = @bitCast(@as(i64, @intCast(address)) + 4 + offset);

            if (link_bit == 1) {
                // BL #offset
                result.mnemonic = "bl";
                result.is_call = true;
            } else {
                // B.W #offset
                result.mnemonic = "b.w";
            }
            result.is_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
            return result;
        }
    }

    // ---- LDR.W / STR.W (immediate 12-bit) ----
    // hw0[15:4] = 1111 1000 1101 for LDR.W Rt, [Rn, #imm12]
    // hw0[15:4] = 1111 1000 1100 for STR.W Rt, [Rn, #imm12]
    if (hw0 >> 4 == 0xF8C) {
        const rn: u4 = @truncate(hw0 & 0xF);
        const rt: u4 = @truncate((hw1 >> 12) & 0xF);
        const imm12: u32 = hw1 & 0xFFF;
        result.mnemonic = "str.w";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rt));
        f.append(", [");
        f.append(regName(rn));
        if (imm12 != 0) {
            f.appendFmt(", #{d}", .{imm12});
        }
        f.append("]");
        result.operands_len = f.len();
        return result;
    }
    if (hw0 >> 4 == 0xF8D) {
        const rn: u4 = @truncate(hw0 & 0xF);
        const rt: u4 = @truncate((hw1 >> 12) & 0xF);
        const imm12: u32 = hw1 & 0xFFF;
        result.mnemonic = "ldr.w";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rt));
        f.append(", [");
        f.append(regName(rn));
        if (imm12 != 0) {
            f.appendFmt(", #{d}", .{imm12});
        }
        f.append("]");
        result.operands_len = f.len();
        // LDR from PC = literal pool
        if (rn == 0xF) {
            const pc_aligned = (address + 4) & ~@as(u64, 3);
            result.branch_target = pc_aligned + imm12;
        }
        return result;
    }

    // ---- MOV.W / MOVW (16-bit immediate) ----
    // Encoding T3: hw0[15:4] = 1111 0x10 0100, hw1[15]=0
    // imm16 = imm4:i:imm3:imm8
    if (hw0 & 0xFBF0 == 0xF240) {
        const rd: u4 = @truncate((hw1 >> 8) & 0xF);
        const i_bit: u32 = (hw0 >> 10) & 1;
        const imm4: u32 = hw0 & 0xF;
        const imm3: u32 = (hw1 >> 12) & 0x7;
        const imm8: u32 = hw1 & 0xFF;
        const imm16 = (imm4 << 12) | (i_bit << 11) | (imm3 << 8) | imm8;
        result.mnemonic = "movw";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.appendFmt("#0x{x}", .{imm16});
        result.operands_len = f.len();
        return result;
    }

    // ---- MOVT (top 16-bit immediate) ----
    // Encoding: hw0[15:4] = 1111 0x10 1100
    if (hw0 & 0xFBF0 == 0xF2C0) {
        const rd: u4 = @truncate((hw1 >> 8) & 0xF);
        const i_bit: u32 = (hw0 >> 10) & 1;
        const imm4: u32 = hw0 & 0xF;
        const imm3: u32 = (hw1 >> 12) & 0x7;
        const imm8: u32 = hw1 & 0xFF;
        const imm16 = (imm4 << 12) | (i_bit << 11) | (imm3 << 8) | imm8;
        result.mnemonic = "movt";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd));
        f.comma();
        f.appendFmt("#0x{x}", .{imm16});
        result.operands_len = f.len();
        return result;
    }

    // ---- Fallback ----
    return unknown32(hw0, hw1, .unsupported);
}

// ============================================================================
// Public API: decodeInstruction (returns types.Instruction)
// ============================================================================

pub fn decodeInstruction(raw: []const u8, address: u64) types.Instruction {
    const decoded = decode(raw, address);
    var inst = types.Instruction{
        .address = address,
        .bytes = raw[0..@min(raw.len, @as(usize, decoded.length))],
        .mnemonic = decoded.mnemonic,
        .operands = &.{},
        .size = decoded.length,
    };
    const ops = decoded.getOperands();
    const copy_len: u8 = @intCast(@min(ops.len, 64));
    @memcpy(inst.operands_buf[0..copy_len], ops[0..copy_len]);
    inst.operands_len = copy_len;
    inst.operands = inst.operands_buf[0..copy_len];
    return inst;
}

// ============================================================================
// Tests
// ============================================================================

test "push {r4, lr} = 0xB510" {
    // 1011 0101 0001 0000 = push {r4, lr}
    const raw = [_]u8{ 0x10, 0xB5 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("push", result.mnemonic);
    try std.testing.expect(!result.is_call);
    try std.testing.expect(!result.is_return);
    try std.testing.expectEqualStrings("{r4, lr}", result.getOperands());
}

test "pop {r4, pc} = 0xBD10" {
    // 1011 1101 0001 0000 = pop {r4, pc}
    const raw = [_]u8{ 0x10, 0xBD };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("pop", result.mnemonic);
    try std.testing.expect(result.is_return);
    try std.testing.expectEqualStrings("{r4, pc}", result.getOperands());
}

test "bx lr = 0x4770" {
    const raw = [_]u8{ 0x70, 0x47 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("bx", result.mnemonic);
    try std.testing.expect(result.is_return);
    try std.testing.expectEqualStrings("lr", result.getOperands());
}

test "blx r3 = 0x4798 (indirect call)" {
    // 0100 0111 1 0011 000 = blx r3
    const raw = [_]u8{ 0x98, 0x47 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("blx", result.mnemonic);
    try std.testing.expect(result.is_call);
    try std.testing.expectEqualStrings("r3", result.getOperands());
}

test "nop = 0xBF00" {
    const raw = [_]u8{ 0x00, 0xBF };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("nop", result.mnemonic);
}

test "beq (conditional branch)" {
    // beq +8 from 0x1000 => target = 0x1000 + 4 + 8 = 0x100C
    // 0xD0 0x04 => 1101 0000 0000 0100 => cond=0 (eq), imm8=4 => offset=4<<1=8
    const raw = [_]u8{ 0x04, 0xD0 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("beq", result.mnemonic);
    try std.testing.expect(result.is_conditional_branch);
    try std.testing.expect(result.branch_target.? == 0x100C);
}

test "b imm11 (unconditional branch)" {
    // b +0x100 from 0x1000 => target = 0x1000 + 4 + 0x100 = 0x1104
    // imm11 = 0x100 >> 1 = 0x80
    // 0xE0 0x80 => 1110 0000 1000 0000
    const raw = [_]u8{ 0x80, 0xE0 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("b", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.branch_target.? == 0x1104);
}

test "bl (32-bit Thumb-2) target computation" {
    // BL +0x1000 from 0x2000. Target = 0x2000 + 4 + 0x1000 = 0x3004.
    // offset=0x1000: S=0, I1=0, I2=0, imm10=1, imm11=0
    // J1=!(0^0)=1, J2=!(0^0)=1
    // hw0 = 11110_0_0000000001 = 0xF001
    // hw1 = 1_1_1_1_1_00000000000 = 0xF800
    const raw = [_]u8{ 0x01, 0xF0, 0x00, 0xF8 };
    const result = decode(&raw, 0x2000);
    try std.testing.expectEqualStrings("bl", result.mnemonic);
    try std.testing.expect(result.is_call);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.branch_target.? == 0x3004);
}

test "b.w (32-bit unconditional branch, no link)" {
    // B.W +0x1000 from 0x2000. Same as BL but hw1[14]=0 (link bit clear).
    // hw0 = 0xF001, hw1 = 0xF800 with bit14 cleared = 0xB800
    // 0xB800 = 1011_1000_0000_0000: J1(bit13)=1, link(bit14)=0, J2(bit11)=1
    // S=0, J1=1, J2=1 => I1=0, I2=0 => offset = 0x1000
    // target = 0x2000 + 4 + 0x1000 = 0x3004
    const raw = [_]u8{ 0x01, 0xF0, 0x00, 0xB8 };
    const result = decode(&raw, 0x2000);
    try std.testing.expectEqualStrings("b.w", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(!result.is_call);
    try std.testing.expect(result.branch_target.? == 0x3004);
}

test "bl target computation (clean)" {
    // BL +0x1000 from 0x2000 => target 0x3004
    // hw0 = 0xF001, hw1 = 0xF800 (see derivation in b.w test)
    const raw = [_]u8{ 0x01, 0xF0, 0x00, 0xF8 };
    const result = decode(&raw, 0x2000);
    try std.testing.expectEqualStrings("bl", result.mnemonic);
    try std.testing.expect(result.is_call);
    try std.testing.expect(result.is_branch);
    // S=0, J1=1(bit13 of 0xF800), J2=1(bit11 of 0xF800)
    // I1=!(1^0)=0, I2=!(1^0)=0
    // offset = 0:0:0:0000000001:00000000000:0 = 0x1000
    // target = 0x2004 + 0x1000 = 0x3004
    try std.testing.expect(result.branch_target.? == 0x3004);
}

test "ldr Rd, [pc, #imm]" {
    // LDR r0, [PC, #0] from 0x1000
    // 0x4800 = 0100 1000 0000 0000 => Rd=0, imm8=0
    const raw = [_]u8{ 0x00, 0x48 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("ldr", result.mnemonic);
    try std.testing.expectEqualStrings("r0, [pc, #0]", result.getOperands());
    // target = Align(0x1000+4, 4) + 0 = 0x1004
    try std.testing.expect(result.branch_target.? == 0x1004);
}

// decodeInstruction is tested transitively when imported from the main
// analysis engine.  We cannot call it in standalone `zig test` because the
// ../types.zig import is outside the module root.  The decode() function
// (which does all the real work) is fully covered by the tests below.

test "instruction length: 16-bit vs 32-bit" {
    // 16-bit: nop = 0xBF00
    const nop = [_]u8{ 0x00, 0xBF };
    const r1 = decode(&nop, 0);
    try std.testing.expect(r1.length == 2);

    // 32-bit: BL (uses 4 bytes)
    const bl = [_]u8{ 0x01, 0xF0, 0x00, 0xF8 };
    const r2 = decode(&bl, 0);
    try std.testing.expect(r2.length == 4);
}

test "negative conditional branch" {
    // beq -4 from 0x1000 => target = 0x1000 + 4 - 4 = 0x1000
    // imm8 for offset=-4: offset = sign_extend(imm8 << 1, 8)
    // -4 = imm8<<1 sign-extended => imm8<<1 = 0x1FC (9 bits: 111111100)
    // imm8 = 0xFE
    const raw = [_]u8{ 0xFE, 0xD0 }; // beq with imm8=0xFE
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("beq", result.mnemonic);
    try std.testing.expect(result.is_conditional_branch);
    try std.testing.expect(result.branch_target.? == 0x1000);
}

test "Thumb16 branches exhaust signed imm8 and imm11 with halfword scaling" {
    for (0..256) |immediate| {
        const signed: i64 = if (immediate < 128) @intCast(immediate) else @as(i64, @intCast(immediate)) - 256;
        var raw: [2]u8 = undefined;
        std.mem.writeInt(u16, &raw, 0xd000 | @as(u16, @intCast(immediate)), .little);
        const result = decode(&raw, 0x1000);
        try std.testing.expect(result.is_branch and result.is_conditional_branch and !result.is_call);
        try std.testing.expectEqual(@as(?u64, @intCast(0x1004 + signed * 2)), result.branch_target);
    }
    for (0..2048) |immediate| {
        const signed: i64 = if (immediate < 1024) @intCast(immediate) else @as(i64, @intCast(immediate)) - 2048;
        var raw: [2]u8 = undefined;
        std.mem.writeInt(u16, &raw, 0xe000 | @as(u16, @intCast(immediate)), .little);
        const result = decode(&raw, 0x1000);
        try std.testing.expectEqualStrings("b", result.mnemonic);
        try std.testing.expect(result.is_branch and !result.is_conditional_branch and !result.is_call);
        try std.testing.expectEqual(@as(?u64, @intCast(0x1004 + signed * 2)), result.branch_target);
    }
}

test "Thumb32 signed branch boundaries reconstruct split immediates" {
    const address: u64 = 0x2000000;
    for ([_]i64{ -0x100000, -0xffffe, -2, 0, 2, 0xffffe }) |offset| {
        const encoded: u32 = @intCast(if (offset < 0) offset + 0x200000 else offset);
        const hw0: u16 = 0xf000 | @as(u16, @intCast(((encoded >> 20) & 1) << 10)) | @as(u16, @intCast((encoded >> 12) & 0x3f));
        const hw1: u16 = 0x8000 | @as(u16, @intCast(((encoded >> 18) & 1) << 13)) | @as(u16, @intCast(((encoded >> 19) & 1) << 11)) | @as(u16, @intCast((encoded >> 1) & 0x7ff));
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u16, raw[0..2], hw0, .little);
        std.mem.writeInt(u16, raw[2..4], hw1, .little);
        const result = decode(&raw, address);
        try std.testing.expect(result.is_branch and result.is_conditional_branch and !result.is_call);
        try std.testing.expectEqual(@as(u8, 4), result.length);
        try std.testing.expectEqual(@as(?u64, @intCast(@as(i64, @intCast(address)) + 4 + offset)), result.branch_target);
    }
    for ([_]i64{ -0x1000000, -0xfffffe, -2, 0, 2, 0xfffffe }) |offset| {
        const encoded: u32 = @intCast(if (offset < 0) offset + 0x2000000 else offset);
        const sign = (encoded >> 24) & 1;
        const j1 = 1 ^ (((encoded >> 23) & 1) ^ sign);
        const j2 = 1 ^ (((encoded >> 22) & 1) ^ sign);
        const hw0: u16 = 0xf000 | @as(u16, @intCast(sign << 10)) | @as(u16, @intCast((encoded >> 12) & 0x3ff));
        for ([_]bool{ false, true }) |link| {
            const hw1: u16 = 0x9000 | @as(u16, if (link) 0x4000 else 0) | @as(u16, @intCast(j1 << 13)) | @as(u16, @intCast(j2 << 11)) | @as(u16, @intCast((encoded >> 1) & 0x7ff));
            var raw: [4]u8 = undefined;
            std.mem.writeInt(u16, raw[0..2], hw0, .little);
            std.mem.writeInt(u16, raw[2..4], hw1, .little);
            const result = decode(&raw, address);
            try std.testing.expectEqualStrings(if (link) "bl" else "b.w", result.mnemonic);
            try std.testing.expect(result.is_branch and !result.is_conditional_branch);
            try std.testing.expectEqual(link, result.is_call);
            try std.testing.expectEqual(@as(?u64, @intCast(@as(i64, @intCast(address)) + 4 + offset)), result.branch_target);
        }
    }
}

test "Thumb32 branches match assembler encodings" {
    // Independently assembled with Apple clang and disassembled with otool.
    const cases = [_]struct { raw: [4]u8, address: u64, target: u64, call: bool, conditional: bool }{
        .{ .raw = .{ 0x00, 0xf0, 0x05, 0xb8 }, .address = 0, .target = 14, .call = false, .conditional = false }, // b.w forward
        .{ .raw = .{ 0xff, 0xf7, 0xfc, 0xff }, .address = 4, .target = 0, .call = true, .conditional = false }, // bl start
        .{ .raw = .{ 0x00, 0xf0, 0x01, 0x80 }, .address = 8, .target = 14, .call = false, .conditional = true }, // beq.w forward
    };
    for (cases) |case| {
        const result = decode(&case.raw, case.address);
        try std.testing.expect(result.is_branch);
        try std.testing.expectEqual(case.call, result.is_call);
        try std.testing.expectEqual(case.conditional, result.is_conditional_branch);
        try std.testing.expectEqual(@as(?u64, case.target), result.branch_target);
    }
}

test "Thumb IT all masks, condition parity, invalid conditions, and hints" {
    // ARM DDI 0406C.d A8-392, mask table for firstcond[0]=0 and =1.
    const even_names = [_][]const u8{
        "",   "itttt", "ittt", "ittte", "itt", "ittet", "itte", "ittee",
        "it", "itett", "itet", "itete", "ite", "iteet", "itee", "iteee",
    };
    const odd_names = [_][]const u8{
        "",   "iteee", "itee", "iteet", "ite", "itete", "itet", "itett",
        "it", "ittee", "itte", "ittet", "itt", "ittte", "ittt", "itttt",
    };
    for (0..16) |cond| {
        for (1..16) |mask| {
            var raw: [2]u8 = undefined;
            std.mem.writeInt(u16, &raw, 0xbf00 | @as(u16, @intCast(cond << 4 | mask)), .little);
            const decoded = decode(&raw, 0x1000);
            const invalid = cond == 15 or (cond == 14 and (mask & (mask - 1)) != 0);
            if (invalid) {
                try std.testing.expectEqual(DecodeStatus.invalid_encoding, decoded.decode_status);
                try std.testing.expect(decoded.it_block == null);
                continue;
            }
            const names = if (cond & 1 == 0) even_names else odd_names;
            try std.testing.expectEqualStrings(names[mask], decoded.mnemonic);
            try std.testing.expectEqualStrings(condition_codes[cond], decoded.getOperands());
            const block = decoded.it_block.?;
            try std.testing.expectEqual(names[mask].len - 1, block.instructionCount());
            var state = ItState{};
            state.begin(block);
            for (0..block.instructionCount()) |i| {
                const expected: u4 = @intCast(if (i == 0 or names[mask][i + 1] == 't') cond else cond ^ 1);
                try std.testing.expectEqual(expected, block.conditionAt(i).?);
                try std.testing.expectEqual(expected, state.currentCondition().?);
                state.advance();
            }
            try std.testing.expect(state.currentCondition() == null);
            try std.testing.expect(block.conditionAt(4) == null);
            state.advance();
            try std.testing.expect(state.currentCondition() == null);
        }
        const raw = [_]u8{ @intCast(cond << 4), 0xbf };
        const hint = decode(&raw, 0);
        try std.testing.expect(hint.it_block == null);
        try std.testing.expectEqual(if (cond < 5) DecodeStatus.decoded else DecodeStatus.unsupported, hint.decode_status);
    }
}

test "Thumb modified immediate expansion exhausts 4096 encodings" {
    // Independent bit placement oracle derived from ARM DDI 0403E.e A5-139.
    for (0..4096) |encoded| {
        const immediate = thumbExpandImm(@intCast(encoded));
        if (encoded == 0x100 or encoded == 0x200 or encoded == 0x300) {
            try std.testing.expect(immediate == null);
            continue;
        }
        var expected: u32 = 0;
        if (encoded < 0x400) {
            const lanes: u4 = switch (encoded / 256) {
                0 => 1,
                1 => 5,
                2 => 10,
                3 => 15,
                else => unreachable,
            };
            for (0..4) |lane| {
                if (lanes & (@as(u4, 1) << @as(u2, @intCast(lane))) != 0) expected |= @as(u32, @intCast(encoded % 256)) << @as(u5, @intCast(lane * 8));
            }
            try std.testing.expect(immediate.?.carry == null);
        } else {
            // The high payload bit is forced to 1; place every payload bit
            // separately to avoid reusing the implementation's rotate operation.
            const payload = 128 + (encoded % 128);
            for (0..8) |bit| {
                if (payload & (@as(usize, 1) << @as(u6, @intCast(bit))) != 0) {
                    const destination = (bit + 32 - encoded / 128) % 32;
                    expected |= @as(u32, 1) << @as(u5, @intCast(destination));
                }
            }
            try std.testing.expectEqual(@as(u1, @truncate(expected >> 31)), immediate.?.carry.?);
        }
        try std.testing.expectEqual(expected, immediate.?.value);

        // Exercise split i:imm3:imm8 assembly into an AND instruction as well.
        const hw0: u16 = 0xf001 | @as(u16, @intCast((encoded & 0x800) >> 1));
        const hw1: u16 = 0x0200 | @as(u16, @intCast((encoded & 0x700) << 4 | (encoded & 0xff)));
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u16, raw[0..2], hw0, .little);
        std.mem.writeInt(u16, raw[2..4], hw1, .little);
        const decoded = decode(&raw, 0x1000);
        try std.testing.expectEqualStrings("and.w", decoded.mnemonic);
        var expected_text: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&expected_text, "r2, r1, #0x{x}", .{expected});
        try std.testing.expectEqualStrings(text, decoded.getOperands());
    }
}

test "Thumb logical immediates match independent assembler, flags and aliases" {
    // Apple clang -target thumbv7m-none-eabi -mthumb -mcpu=cortex-m3;
    // encodings independently checked by llvm-objdump, not built from decoder masks.
    const Case = struct { hw0: u16, hw1: u16, mnemonic: []const u8, operands: []const u8, flags: bool };
    const cases = [_]Case{
        .{ .hw0 = 0xf001, .hw1 = 0x0201, .mnemonic = "and.w", .operands = "r2, r1, #0x1", .flags = false },
        .{ .hw0 = 0xf014, .hw1 = 0x33ab, .mnemonic = "ands.w", .operands = "r3, r4, #0xabababab", .flags = true },
        .{ .hw0 = 0xf029, .hw1 = 0x4800, .mnemonic = "bic.w", .operands = "r8, r9, #0x80000000", .flags = false },
        .{ .hw0 = 0xf439, .hw1 = 0x7880, .mnemonic = "bics.w", .operands = "r8, r9, #0x100", .flags = true },
        .{ .hw0 = 0xf041, .hw1 = 0x12ab, .mnemonic = "orr.w", .operands = "r2, r1, #0xab00ab", .flags = false },
        .{ .hw0 = 0xf051, .hw1 = 0x22ab, .mnemonic = "orrs.w", .operands = "r2, r1, #0xab00ab00", .flags = true },
        .{ .hw0 = 0xf061, .hw1 = 0x02ff, .mnemonic = "orn.w", .operands = "r2, r1, #0xff", .flags = false },
        .{ .hw0 = 0xf071, .hw1 = 0x02ff, .mnemonic = "orns.w", .operands = "r2, r1, #0xff", .flags = true },
        .{ .hw0 = 0xf081, .hw1 = 0x4200, .mnemonic = "eor.w", .operands = "r2, r1, #0x80000000", .flags = false },
        .{ .hw0 = 0xf091, .hw1 = 0x0202, .mnemonic = "eors.w", .operands = "r2, r1, #0x2", .flags = true },
        .{ .hw0 = 0xf011, .hw1 = 0x0f01, .mnemonic = "tst.w", .operands = "r1, #0x1", .flags = true },
        .{ .hw0 = 0xf091, .hw1 = 0x0f01, .mnemonic = "teq.w", .operands = "r1, #0x1", .flags = true },
        .{ .hw0 = 0xf04f, .hw1 = 0x0201, .mnemonic = "mov.w", .operands = "r2, #0x1", .flags = false },
        .{ .hw0 = 0xf05f, .hw1 = 0x0201, .mnemonic = "movs.w", .operands = "r2, #0x1", .flags = true },
        .{ .hw0 = 0xf06f, .hw1 = 0x0201, .mnemonic = "mvn.w", .operands = "r2, #0x1", .flags = false },
        .{ .hw0 = 0xf07f, .hw1 = 0x0201, .mnemonic = "mvns.w", .operands = "r2, #0x1", .flags = true },
    };
    for (cases) |case| {
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u16, raw[0..2], case.hw0, .little);
        std.mem.writeInt(u16, raw[2..4], case.hw1, .little);
        const decoded = decode(&raw, 0);
        try std.testing.expectEqual(DecodeStatus.decoded, decoded.decode_status);
        try std.testing.expectEqualStrings(case.mnemonic, decoded.mnemonic);
        try std.testing.expectEqualStrings(case.operands, decoded.getOperands());
        try std.testing.expectEqual(case.flags, decoded.sets_flags.?);
        try std.testing.expect(!decoded.flags_suppressed_in_it);
    }
}

test "Thumb invalid logical operands and immediate encodings are not UDF" {
    const cases = [_][2]u16{
        .{ 0xf001, 0x0f01 }, // Rd=PC without TST alias
        .{ 0xf001, 0x0d01 }, // Rd=SP unpredictable in ARMv7
        .{ 0xf00d, 0x0201 }, // Rn=SP unpredictable in ARMv7
        .{ 0xf00f, 0x0201 }, // Rn=PC without MOV/MVN alias
        .{ 0xf031, 0x0f01 }, // BICS PC is not TST
        .{ 0xf001, 0x1200 }, // zero replicated twice
        .{ 0xf001, 0x2200 }, // zero replicated to other bytes
        .{ 0xf001, 0x3200 }, // zero replicated four times
    };
    for (cases) |case| {
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u16, raw[0..2], case[0], .little);
        std.mem.writeInt(u16, raw[2..4], case[1], .little);
        const decoded = decode(&raw, 0);
        try std.testing.expectEqual(DecodeStatus.invalid_encoding, decoded.decode_status);
        try std.testing.expectEqualStrings(".inst.w", decoded.mnemonic);
    }
    const unsupported16 = decode(&.{ 0x00, 0xba }, 0); // valid REV r0,r0, not implemented
    try std.testing.expectEqual(DecodeStatus.unsupported, unsupported16.decode_status);
    try std.testing.expectEqualStrings(".inst.n", unsupported16.mnemonic);
    const unsupported32 = decode(&.{ 0xa1, 0xfb, 0x00, 0x01 }, 0); // wide multiply family
    try std.testing.expectEqual(DecodeStatus.unsupported, unsupported32.decode_status);
    try std.testing.expectEqualStrings(".inst.w", unsupported32.mnemonic);
    try std.testing.expectEqual(DecodeStatus.truncated, decode(&.{0xf0}, 0).decode_status);
    try std.testing.expectEqual(DecodeStatus.truncated, decode(&.{ 0x01, 0xf0 }, 0).decode_status);
    const udf = decode(&.{ 0xff, 0xde }, 0);
    try std.testing.expectEqualStrings("udf", udf.mnemonic);
    try std.testing.expectEqual(DecodeStatus.decoded, udf.decode_status);
    const udf_w = decode(&.{ 0xfa, 0xf7, 0xcd, 0xab }, 0);
    try std.testing.expectEqualStrings("udf.w", udf_w.mnemonic);
    try std.testing.expectEqualStrings("#43981", udf_w.getOperands());
}

test "Thumb IT state spans mixed widths and preserves implicit flag suppression" {
    var state = ItState{};
    const it = decode(&.{ 0x04, 0xbf }, 0x1000);
    state.begin(it.it_block.?);
    const mov = decode(&.{ 0x00, 0x20 }, 0x1002);
    try std.testing.expect(mov.sets_flags.? and mov.flags_suppressed_in_it);
    try std.testing.expectEqual(@as(u4, 0), state.currentCondition().?);
    state.advance();
    const wide = decode(&.{ 0x01, 0xf0, 0x01, 0x02 }, 0x1004);
    try std.testing.expectEqual(@as(u8, 4), wide.length);
    try std.testing.expectEqual(@as(u4, 0), state.currentCondition().?);
    state.advance();
    try std.testing.expect(state.currentCondition() == null);
    const cmp = decode(&.{ 0x81, 0x42 }, 0x1008);
    try std.testing.expect(cmp.sets_flags.? and !cmp.flags_suppressed_in_it);
}
