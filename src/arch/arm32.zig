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
    operands: [128]u8 = [_]u8{0} ** 128,
    operands_len: u8 = 0,
    length: u8 = 2, // Thumb default is 2 bytes; 4 for Thumb-2
    is_branch: bool = false,
    is_conditional_branch: bool = false,
    is_call: bool = false,
    is_return: bool = false,
    branch_target: ?u64 = null,

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

// ============================================================================
// Condition code names
// ============================================================================

const condition_codes = [16][]const u8{
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
};

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

fn signExtend(value: u64, sign_bit: u6) i64 {
    const mask = @as(u64, 1) << sign_bit;
    if (value & mask != 0) {
        const ext: u64 = @as(u64, 0xFFFFFFFFFFFFFFFF) << @as(u6, sign_bit + 1);
        return @bitCast(ext | value);
    }
    return @intCast(value);
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
        return .{ .mnemonic = "udf" };
    }

    const hw0 = readU16LE(raw);

    if (isThumb32(hw0)) {
        // 32-bit Thumb-2 instruction
        if (raw.len < 4) {
            return .{ .mnemonic = "udf", .length = 2 };
        }
        const hw1 = readU16LE(raw[2..]);
        return decodeThumb32(hw0, hw1, address);
    }

    return decodeThumb16(hw0, address);
}

// ============================================================================
// 16-bit Thumb decoder
// ============================================================================

fn decodeThumb16(hw: u16, address: u64) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = "udf", .length = 2 };

    // ---- NOP (0xBF00) ----
    if (hw == 0xBF00) {
        result.mnemonic = "nop";
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
            const offset = signExtend(imm8 << 1, 8);
            const target: u64 = @bitCast(@as(i64, @intCast(address)) + 4 + offset);
            const cond_name = condition_codes[cond];

            // Build mnemonic: "b" + condition
            var mnem_buf: [4]u8 = undefined;
            mnem_buf[0] = 'b';
            @memcpy(mnem_buf[1..][0..cond_name.len], cond_name);
            const mnem_len = 1 + cond_name.len;

            result.mnemonic = mnem_buf[0..mnem_len];
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
        const offset = signExtend(imm11 << 1, 11);
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
    result.mnemonic = "udf";
    return result;
}

// ============================================================================
// 32-bit Thumb-2 decoder
// ============================================================================

fn decodeThumb32(hw0: u16, hw1: u16, address: u64) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = "udf", .length = 4 };

    // Combine for convenience
    const full: u32 = (@as(u32, hw0) << 16) | @as(u32, hw1);
    _ = full;

    // ---- Branch instructions (BL, B.W, B<cond>.W) ----
    // hw0[15:11] = 11110
    // hw1[15] = 1 for BL/B.W; hw1[14] distinguishes BL vs B.W
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
            const offset = signExtend(offset_raw, 20);
            const target: u64 = @bitCast(@as(i64, @intCast(address)) + 4 + offset);

            if (cond < 0xE) {
                const cond_name = condition_codes[cond];
                var mnem_buf: [6]u8 = undefined;
                mnem_buf[0] = 'b';
                @memcpy(mnem_buf[1..][0..cond_name.len], cond_name);
                const suffix = ".w";
                const off = 1 + cond_name.len;
                @memcpy(mnem_buf[off..][0..suffix.len], suffix);
                const mnem_len = off + suffix.len;

                result.mnemonic = mnem_buf[0..mnem_len];
                result.is_branch = true;
                result.is_conditional_branch = true;
                result.branch_target = target;
                var f = FmtBuf.init(&result.operands);
                f.appendHex(target);
                result.operands_len = f.len();
                return result;
            }
        }

        // ---- BL / B.W: hw1[15:14]=11 ----
        if (hw1_top2 == 0b11) {
            const imm10: u64 = hw0 & 0x3FF;
            const imm11: u64 = hw1 & 0x7FF;
            const j1: u1 = @truncate((hw1 >> 13) & 1);
            const j2: u1 = @truncate((hw1 >> 11) & 1);
            const link_bit = hw1_bit12;

            // I1 = !(J1 ^ S), I2 = !(J2 ^ S)
            const eye1: u1 = ~(j1 ^ s_bit);
            const eye2: u1 = ~(j2 ^ s_bit);

            // offset = S:I1:I2:imm10:imm11:0 (25-bit signed)
            const offset_raw: u64 = (@as(u64, s_bit) << 24) |
                (@as(u64, eye1) << 23) |
                (@as(u64, eye2) << 22) |
                (imm10 << 12) |
                (imm11 << 1);
            const offset = signExtend(offset_raw, 24);
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
    result.mnemonic = "udf";
    return result;
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
    // B.W +0x1000 from 0x2000. Same as BL but hw1[12]=0 (link bit clear).
    // hw0 = 0xF001, hw1 = 0xF800 with bit12 cleared = 0xE800
    // 0xE800 = 1110_1000_0000_0000: J1(bit13)=1, link(bit12)=0, J2(bit11)=1
    // S=0, J1=1, J2=1 => I1=0, I2=0 => offset = 0x1000
    // target = 0x2000 + 4 + 0x1000 = 0x3004
    const raw = [_]u8{ 0x01, 0xF0, 0x00, 0xE8 };
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
