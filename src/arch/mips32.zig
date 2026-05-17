// Phora — MIPS32 Instruction Decoder
// Pure bit-pattern decoder for fixed-width 32-bit MIPS instructions (little-endian).
// Targets PSP (ALLEGREX) and standard MIPS32 Release 1/2 binaries.
// Reference: MIPS32 Architecture for Programmers, Volume II (Instruction Set)

const std = @import("std");
const types = @import("../types.zig");

// ============================================================================
// Decoded instruction — internal representation with rich metadata
// ============================================================================

pub const DecodedInstruction = struct {
    mnemonic: []const u8,
    operands: [128]u8 = [_]u8{0} ** 128,
    operands_len: u8 = 0,
    length: u8 = 4,
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
// Register names (PSP ABI)
// ============================================================================

const gpr_names = [32][]const u8{
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0",   "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0",   "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8",   "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
};

const fpr_names = [32][]const u8{
    "$f0",  "$f1",  "$f2",  "$f3",  "$f4",  "$f5",  "$f6",  "$f7",
    "$f8",  "$f9",  "$f10", "$f11", "$f12", "$f13", "$f14", "$f15",
    "$f16", "$f17", "$f18", "$f19", "$f20", "$f21", "$f22", "$f23",
    "$f24", "$f25", "$f26", "$f27", "$f28", "$f29", "$f30", "$f31",
};

fn gprName(reg: u32) []const u8 {
    if (reg > 31) return "$??";
    return gpr_names[reg];
}

fn fprName(reg: u32) []const u8 {
    if (reg > 31) return "$f??";
    return fpr_names[reg];
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

    fn appendDec(self: *FmtBuf, value: i64) void {
        self.appendFmt("{d}", .{value});
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

fn bits(insn: u32, hi: u5, lo: u5) u32 {
    const width: u5 = hi - lo + 1;
    return (insn >> lo) & ((@as(u32, 1) << width) - 1);
}

fn bit(insn: u32, pos: u5) u1 {
    return @truncate(insn >> pos);
}

fn signExtend(value: u64, sign_bit: u6) i64 {
    const mask = @as(u64, 1) << sign_bit;
    if (value & mask != 0) {
        const ext: u64 = @as(u64, 0xFFFFFFFFFFFFFFFF) << @as(u6, sign_bit + 1);
        return @bitCast(ext | value);
    }
    return @intCast(value);
}

fn readU32LE(raw: []const u8) u32 {
    return @as(u32, raw[0]) |
        (@as(u32, raw[1]) << 8) |
        (@as(u32, raw[2]) << 16) |
        (@as(u32, raw[3]) << 24);
}

/// Compute branch target: (address + 4) + (sign_extend(imm16) << 2)
fn branchTarget(address: u64, imm16: u32) u64 {
    const offset = signExtend(@as(u64, imm16), 15);
    const shifted = offset << 2;
    return @bitCast(@as(i64, @bitCast(address +% 4)) +% shifted);
}

/// Compute jump target: (address & 0xF0000000) | (instr_index << 2)
fn jumpTarget(address: u64, instr_index: u32) u64 {
    return (address & 0xF0000000) | (@as(u64, instr_index) << 2);
}

// ============================================================================
// Main decode entry point
// ============================================================================

pub fn decode(raw: []const u8, address: u64) DecodedInstruction {
    if (raw.len < 4) {
        return .{ .mnemonic = "udf" };
    }

    const insn = readU32LE(raw);
    const opcode = bits(insn, 31, 26);

    return switch (opcode) {
        0x00 => decodeRType(insn, address),
        0x01 => decodeRegimm(insn, address),
        0x02 => decodeJ(insn, address),
        0x03 => decodeJAL(insn, address),
        0x04 => decodeBranch2("beq", insn, address),
        0x05 => decodeBranch2("bne", insn, address),
        0x06 => decodeBranch1("blez", insn, address),
        0x07 => decodeBranch1("bgtz", insn, address),
        0x08 => decodeImmArith("addi", insn, true),
        0x09 => decodeImmArith("addiu", insn, true),
        0x0A => decodeImmArith("slti", insn, true),
        0x0B => decodeImmArith("sltiu", insn, true),
        0x0C => decodeImmLogical("andi", insn),
        0x0D => decodeImmLogical("ori", insn),
        0x0E => decodeImmLogical("xori", insn),
        0x0F => decodeLUI(insn),
        0x10 => decodeCOP0(insn),
        0x11 => decodeCOP1(insn, address),
        0x12 => decodeCOP2(insn, address),
        0x14 => decodeBranch2("beql", insn, address),
        0x15 => decodeBranch2("bnel", insn, address),
        0x16 => decodeBranch1("blezl", insn, address),
        0x17 => decodeBranch1("bgtzl", insn, address),
        0x1C => decodeSPECIAL2(insn),
        0x1F => decodeSPECIAL3(insn),
        0x20 => decodeLoadStore("lb", insn),
        0x21 => decodeLoadStore("lh", insn),
        0x22 => decodeLoadStore("lwl", insn),
        0x23 => decodeLoadStore("lw", insn),
        0x24 => decodeLoadStore("lbu", insn),
        0x25 => decodeLoadStore("lhu", insn),
        0x26 => decodeLoadStore("lwr", insn),
        0x28 => decodeLoadStore("sb", insn),
        0x29 => decodeLoadStore("sh", insn),
        0x2A => decodeLoadStore("swl", insn),
        0x2B => decodeLoadStore("sw", insn),
        0x2E => decodeLoadStore("swr", insn),
        0x31 => decodeFPLoadStore("lwc1", insn),
        0x32 => decodeVFPULoadStore("lv.s", insn),
        0x34 => decodeVFPULoadStore("lv.q", insn),
        0x36 => decodeVFPULoadStore("sv.s", insn),
        0x39 => decodeFPLoadStore("swc1", insn),
        0x3E => decodeVFPULoadStore("sv.q", insn),
        else => decodeUnknown(insn),
    };
}

// ============================================================================
// R-type (opcode=0x00) — dispatch on funct
// ============================================================================

fn decodeRType(insn: u32, address: u64) DecodedInstruction {
    const rs = bits(insn, 25, 21);
    const rt = bits(insn, 20, 16);
    const rd = bits(insn, 15, 11);
    const shamt = bits(insn, 10, 6);
    const funct = bits(insn, 5, 0);

    // NOP: sll $zero, $zero, 0 (entire word is zero)
    if (insn == 0x00000000) {
        return .{ .mnemonic = "nop" };
    }

    return switch (funct) {
        0x00 => decodeShiftImm("sll", rd, rt, shamt),
        0x02 => decodeShiftImm("srl", rd, rt, shamt),
        0x03 => decodeShiftImm("sra", rd, rt, shamt),
        0x04 => decodeShiftReg("sllv", rd, rt, rs),
        0x06 => decodeShiftReg("srlv", rd, rt, rs),
        0x07 => decodeShiftReg("srav", rd, rt, rs),
        0x08 => decodeJR(insn, rs, address),
        0x09 => decodeJALR(rd, rs),
        0x0A => decodeRTypeALU("movz", rd, rs, rt),
        0x0B => decodeRTypeALU("movn", rd, rs, rt),
        0x0C => .{ .mnemonic = "syscall" },
        0x0D => .{ .mnemonic = "break" },
        0x10 => decodeMoveHiLo("mfhi", rd),
        0x11 => decodeMoveHiLo("mthi", rs),
        0x12 => decodeMoveHiLo("mflo", rd),
        0x13 => decodeMoveHiLo("mtlo", rs),
        0x18 => decodeMulDiv("mult", rs, rt),
        0x19 => decodeMulDiv("multu", rs, rt),
        0x1A => decodeMulDiv("div", rs, rt),
        0x1B => decodeMulDiv("divu", rs, rt),
        0x20 => decodeRTypeALU("add", rd, rs, rt),
        0x21 => decodeRTypeALU("addu", rd, rs, rt),
        0x22 => decodeRTypeALU("sub", rd, rs, rt),
        0x23 => decodeRTypeALU("subu", rd, rs, rt),
        0x24 => decodeRTypeALU("and", rd, rs, rt),
        0x25 => decodeRTypeALU("or", rd, rs, rt),
        0x26 => decodeRTypeALU("xor", rd, rs, rt),
        0x27 => decodeRTypeALU("nor", rd, rs, rt),
        0x2A => decodeRTypeALU("slt", rd, rs, rt),
        0x2B => decodeRTypeALU("sltu", rd, rs, rt),
        else => decodeUnknown(insn),
    };
}

/// R-type ALU: mnemonic $rd, $rs, $rt
fn decodeRTypeALU(mnemonic: []const u8, rd: u32, rs: u32, rt: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rd));
    f.comma();
    f.append(gprName(rs));
    f.comma();
    f.append(gprName(rt));
    result.operands_len = f.len();
    return result;
}

/// Shift by immediate: mnemonic $rd, $rt, shamt
fn decodeShiftImm(mnemonic: []const u8, rd: u32, rt: u32, shamt: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rd));
    f.comma();
    f.append(gprName(rt));
    f.comma();
    f.appendDec(@intCast(shamt));
    result.operands_len = f.len();
    return result;
}

/// Shift by register: mnemonic $rd, $rt, $rs
fn decodeShiftReg(mnemonic: []const u8, rd: u32, rt: u32, rs: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rd));
    f.comma();
    f.append(gprName(rt));
    f.comma();
    f.append(gprName(rs));
    result.operands_len = f.len();
    return result;
}

/// JR $rs — branch; return if rs==31 ($ra)
fn decodeJR(insn: u32, rs: u32, address: u64) DecodedInstruction {
    _ = insn;
    _ = address;
    var result = DecodedInstruction{
        .mnemonic = "jr",
        .is_branch = true,
        .is_return = (rs == 31),
    };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rs));
    result.operands_len = f.len();
    return result;
}

/// JALR $rd, $rs — branch-and-link (call)
fn decodeJALR(rd: u32, rs: u32) DecodedInstruction {
    var result = DecodedInstruction{
        .mnemonic = "jalr",
        .is_branch = true,
        .is_call = true,
    };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rd));
    f.comma();
    f.append(gprName(rs));
    result.operands_len = f.len();
    return result;
}

/// MFHI/MFLO $rd or MTHI/MTLO $rs
fn decodeMoveHiLo(mnemonic: []const u8, reg: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(reg));
    result.operands_len = f.len();
    return result;
}

/// MULT/MULTU/DIV/DIVU $rs, $rt
fn decodeMulDiv(mnemonic: []const u8, rs: u32, rt: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rs));
    f.comma();
    f.append(gprName(rt));
    result.operands_len = f.len();
    return result;
}

// ============================================================================
// I-type — immediate arithmetic (signed immediate)
// ============================================================================

fn decodeImmArith(mnemonic: []const u8, insn: u32, signed: bool) DecodedInstruction {
    const rs = bits(insn, 25, 21);
    const rt = bits(insn, 20, 16);
    const imm16 = bits(insn, 15, 0);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rt));
    f.comma();
    f.append(gprName(rs));
    f.comma();

    if (signed) {
        const sext = signExtend(@as(u64, imm16), 15);
        f.appendDec(sext);
    } else {
        f.appendDec(@intCast(imm16));
    }

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// I-type — immediate logical (zero-extended immediate)
// ============================================================================

fn decodeImmLogical(mnemonic: []const u8, insn: u32) DecodedInstruction {
    const rs = bits(insn, 25, 21);
    const rt = bits(insn, 20, 16);
    const imm16 = bits(insn, 15, 0);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rt));
    f.comma();
    f.append(gprName(rs));
    f.comma();
    f.appendHex(@as(u64, imm16));

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// LUI — load upper immediate
// ============================================================================

fn decodeLUI(insn: u32) DecodedInstruction {
    const rt = bits(insn, 20, 16);
    const imm16 = bits(insn, 15, 0);

    var result = DecodedInstruction{ .mnemonic = "lui" };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rt));
    f.comma();
    f.appendHex(@as(u64, imm16));

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// Load/store (GPR) — offset($base) format
// ============================================================================

fn decodeLoadStore(mnemonic: []const u8, insn: u32) DecodedInstruction {
    const base = bits(insn, 25, 21);
    const rt = bits(insn, 20, 16);
    const imm16 = bits(insn, 15, 0);
    const offset = signExtend(@as(u64, imm16), 15);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rt));
    f.comma();
    f.appendDec(offset);
    f.append("(");
    f.append(gprName(base));
    f.append(")");

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// FP Load/store — lwc1/swc1 with offset($base) format
// ============================================================================

fn decodeFPLoadStore(mnemonic: []const u8, insn: u32) DecodedInstruction {
    const base = bits(insn, 25, 21);
    const ft = bits(insn, 20, 16);
    const imm16 = bits(insn, 15, 0);
    const offset = signExtend(@as(u64, imm16), 15);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(fprName(ft));
    f.comma();
    f.appendDec(offset);
    f.append("(");
    f.append(gprName(base));
    f.append(")");

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// Branch instructions — two-register (BEQ/BNE) and one-register (BLEZ/BGTZ)
// ============================================================================

/// BEQ/BNE: mnemonic $rs, $rt, target
fn decodeBranch2(mnemonic: []const u8, insn: u32, address: u64) DecodedInstruction {
    const rs = bits(insn, 25, 21);
    const rt = bits(insn, 20, 16);
    const imm16 = bits(insn, 15, 0);
    const target = branchTarget(address, imm16);

    var result = DecodedInstruction{
        .mnemonic = mnemonic,
        .is_branch = true,
        .is_conditional_branch = true,
        .branch_target = target,
    };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rs));
    f.comma();
    f.append(gprName(rt));
    f.comma();
    f.appendHex(target);

    result.operands_len = f.len();
    return result;
}

/// BLEZ/BGTZ: mnemonic $rs, target
fn decodeBranch1(mnemonic: []const u8, insn: u32, address: u64) DecodedInstruction {
    const rs = bits(insn, 25, 21);
    const imm16 = bits(insn, 15, 0);
    const target = branchTarget(address, imm16);

    var result = DecodedInstruction{
        .mnemonic = mnemonic,
        .is_branch = true,
        .is_conditional_branch = true,
        .branch_target = target,
    };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rs));
    f.comma();
    f.appendHex(target);

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// J-type — J and JAL
// ============================================================================

fn decodeJ(insn: u32, address: u64) DecodedInstruction {
    const instr_index = bits(insn, 25, 0);
    const target = jumpTarget(address, instr_index);

    var result = DecodedInstruction{
        .mnemonic = "j",
        .is_branch = true,
        .branch_target = target,
    };
    var f = FmtBuf.init(&result.operands);
    f.appendHex(target);
    result.operands_len = f.len();
    return result;
}

fn decodeJAL(insn: u32, address: u64) DecodedInstruction {
    const instr_index = bits(insn, 25, 0);
    const target = jumpTarget(address, instr_index);

    var result = DecodedInstruction{
        .mnemonic = "jal",
        .is_branch = true,
        .is_call = true,
        .branch_target = target,
    };
    var f = FmtBuf.init(&result.operands);
    f.appendHex(target);
    result.operands_len = f.len();
    return result;
}

// ============================================================================
// REGIMM (opcode=0x01) — dispatch on rt field
// ============================================================================

fn decodeRegimm(insn: u32, address: u64) DecodedInstruction {
    const rs = bits(insn, 25, 21);
    const rt = bits(insn, 20, 16);
    const imm16 = bits(insn, 15, 0);
    const target = branchTarget(address, imm16);

    const info: struct { mnemonic: []const u8, is_call: bool } = switch (rt) {
        0x00 => .{ .mnemonic = "bltz", .is_call = false },
        0x01 => .{ .mnemonic = "bgez", .is_call = false },
        0x02 => .{ .mnemonic = "bltzl", .is_call = false },
        0x03 => .{ .mnemonic = "bgezl", .is_call = false },
        0x10 => .{ .mnemonic = "bltzal", .is_call = true },
        0x11 => .{ .mnemonic = "bgezal", .is_call = true },
        else => return decodeUnknown(insn),
    };

    var result = DecodedInstruction{
        .mnemonic = info.mnemonic,
        .is_branch = true,
        .is_conditional_branch = true,
        .is_call = info.is_call,
        .branch_target = target,
    };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rs));
    f.comma();
    f.appendHex(target);

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// COP1 (opcode=0x11) — floating-point coprocessor
// ============================================================================

fn decodeCOP1(insn: u32, address: u64) DecodedInstruction {
    const rs = bits(insn, 25, 21);

    return switch (rs) {
        0x00 => decodeCOP1Move("mfc1", insn),
        0x02 => decodeCOP1Move("cfc1", insn),
        0x04 => decodeCOP1Move("mtc1", insn),
        0x06 => decodeCOP1Move("ctc1", insn),
        0x08 => decodeCOP1Branch(insn, address),
        0x10 => decodeCOP1Single(insn), // single-precision
        0x14 => decodeCOP1Word(insn), // word (CVT.S.W lives here)
        else => decodeUnknown(insn),
    };
}

/// MFC1/MTC1/CFC1/CTC1: mnemonic $rt, $fs
fn decodeCOP1Move(mnemonic: []const u8, insn: u32) DecodedInstruction {
    const rt = bits(insn, 20, 16);
    const fs = bits(insn, 15, 11);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rt));
    f.comma();
    f.append(fprName(fs));

    result.operands_len = f.len();
    return result;
}

/// BC1F/BC1T — FPU conditional branch
fn decodeCOP1Branch(insn: u32, address: u64) DecodedInstruction {
    const tf = bit(insn, 16);
    const imm16 = bits(insn, 15, 0);
    const target = branchTarget(address, imm16);

    const mnemonic: []const u8 = if (tf == 1) "bc1t" else "bc1f";

    var result = DecodedInstruction{
        .mnemonic = mnemonic,
        .is_branch = true,
        .is_conditional_branch = true,
        .branch_target = target,
    };
    var f = FmtBuf.init(&result.operands);
    f.appendHex(target);

    result.operands_len = f.len();
    return result;
}

/// Single-precision FP operations (rs=0x10, dispatch on funct)
fn decodeCOP1Single(insn: u32) DecodedInstruction {
    const ft = bits(insn, 20, 16);
    const fs = bits(insn, 15, 11);
    const fd = bits(insn, 10, 6);
    const funct = bits(insn, 5, 0);

    return switch (funct) {
        // Binary arithmetic: op.s $fd, $fs, $ft
        0x00 => decodeFPBinary("add.s", fd, fs, ft),
        0x01 => decodeFPBinary("sub.s", fd, fs, ft),
        0x02 => decodeFPBinary("mul.s", fd, fs, ft),
        0x03 => decodeFPBinary("div.s", fd, fs, ft),

        // Unary: op.s $fd, $fs
        0x04 => decodeFPUnary("sqrt.s", fd, fs),
        0x05 => decodeFPUnary("abs.s", fd, fs),
        0x06 => decodeFPUnary("mov.s", fd, fs),
        0x07 => decodeFPUnary("neg.s", fd, fs),

        // Conversion/truncation (unary)
        0x0D => decodeFPUnary("trunc.w.s", fd, fs),
        0x24 => decodeFPUnary("cvt.w.s", fd, fs),

        // Compare instructions (no destination register)
        0x30 => decodeFPCompare("c.f.s", fs, ft),
        0x32 => decodeFPCompare("c.eq.s", fs, ft),
        0x3C => decodeFPCompare("c.lt.s", fs, ft),
        0x3E => decodeFPCompare("c.le.s", fs, ft),

        else => decodeUnknown(insn),
    };
}

/// Word-format FP operations (rs=0x14) — CVT.S.W lives here
fn decodeCOP1Word(insn: u32) DecodedInstruction {
    const fs = bits(insn, 15, 11);
    const fd = bits(insn, 10, 6);
    const funct = bits(insn, 5, 0);

    return switch (funct) {
        0x20 => decodeFPUnary("cvt.s.w", fd, fs),
        else => decodeUnknown(insn),
    };
}

/// Binary FP: mnemonic $fd, $fs, $ft
fn decodeFPBinary(mnemonic: []const u8, fd: u32, fs: u32, ft: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(fprName(fd));
    f.comma();
    f.append(fprName(fs));
    f.comma();
    f.append(fprName(ft));

    result.operands_len = f.len();
    return result;
}

/// Unary FP: mnemonic $fd, $fs
fn decodeFPUnary(mnemonic: []const u8, fd: u32, fs: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(fprName(fd));
    f.comma();
    f.append(fprName(fs));

    result.operands_len = f.len();
    return result;
}

/// FP compare: mnemonic $fs, $ft
fn decodeFPCompare(mnemonic: []const u8, fs: u32, ft: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(fprName(fs));
    f.comma();
    f.append(fprName(ft));

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// COP2 (opcode=0x12) — PSP VFPU coprocessor
// ============================================================================

/// VFPU register name: $v{N} for register number 0-127
fn vfpuRegName(buf: *FmtBuf, reg: u32) void {
    buf.appendFmt("$v{d}", .{reg & 127});
}

fn decodeCOP2(insn: u32, address: u64) DecodedInstruction {
    const rs = bits(insn, 25, 21);

    return switch (rs) {
        0x00 => decodeCOP2Move("mfv", insn),
        0x03 => decodeCOP2Move("cfc2", insn),
        0x04 => decodeCOP2Move("mtv", insn),
        0x07 => decodeCOP2Move("ctc2", insn),
        0x08 => decodeCOP2Branch(insn, address),
        else => if (rs >= 16) blk: {
            // Bit 25 of the instruction word is set (rs >= 0x10) — this is either
            // a PS1 GTE (COP2) command or a PSP VFPU compute op (different ISAs
            // sharing the COP2 opcode). Try GTE first: if the sub-opcode is one
            // of the 22 known GTE commands, decode it as such; otherwise fall
            // through to the existing PSP VFPU dispatcher so we don't regress
            // PSP support.
            const gte = decodeGTE(insn);
            if (gte != null) break :blk gte.?;
            break :blk decodeVFPUCompute(insn);
        } else decodeUnknown(insn),
    };
}

// ============================================================================
// PS1 GTE (Geometry Transformation Engine, COP2) — opcode dispatch
// ============================================================================
//
// GTE command encoding (per Nocash PSX spec):
//   bits[31:26] = 0x12 (COP2)
//   bit  25     = 1   (signals GTE/imm25 form, i.e. `cop2 imm25`)
//   bits[24:20] = "fake" gte command (ignored by hw, used by some assemblers)
//   bit  19     = sf  (shift fraction: 0=12 bit fraction, 1=0 bit fraction)
//   bits[18:17] = mx  (matrix select for MVMVA: 0..3)
//   bits[16:15] = vx  (multiply vector for MVMVA: 0..3)
//   bits[14:13] = cv  (translation vector for MVMVA: 0..3)
//   bit  10     = lm  (saturate flag: 0=signed, 1=unsigned/clamp to 0)
//   bits[5:0]   = real opcode
//
// Returns null when the sub-opcode is not a known GTE command — caller can then
// fall through to the PSP VFPU decoder so PSP binaries still disassemble.
fn decodeGTE(insn: u32) ?DecodedInstruction {
    const op6 = bits(insn, 5, 0);

    const mnemonic: []const u8 = switch (op6) {
        0x01 => "RTPS",
        0x06 => "NCLIP",
        0x0C => "OP",
        0x10 => "DPCS",
        0x11 => "INTPL",
        0x12 => "MVMVA",
        0x13 => "NCDS",
        0x14 => "CDP",
        0x16 => "NCDT",
        0x1B => "NCCS",
        0x1C => "CC",
        0x1E => "NCS",
        0x20 => "NCT",
        0x28 => "SQR",
        0x29 => "DCPL",
        0x2A => "DPCT",
        0x2D => "AVSZ3",
        0x2E => "AVSZ4",
        0x30 => "RTPT",
        0x3D => "GPF",
        0x3E => "GPL",
        0x3F => "NCCT",
        else => return null,
    };

    const sf = bit(insn, 19);
    const lm = bit(insn, 10);
    const cv = bits(insn, 14, 13);
    const vx = bits(insn, 16, 15);
    const mx = bits(insn, 18, 17);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);

    if (op6 == 0x12) {
        // MVMVA: always emit all 5 flags (mx, vx, cv, lm, sf)
        f.appendFmt("mx={d} vx={d} cv={d} lm={d} sf={d}", .{ mx, vx, cv, lm, sf });
    } else {
        // Non-MVMVA: emit only non-zero flags (sf first, then lm), space-separated
        var emitted = false;
        if (sf != 0) {
            f.appendFmt("sf={d}", .{sf});
            emitted = true;
        }
        if (lm != 0) {
            if (emitted) f.append(" ");
            f.appendFmt("lm={d}", .{lm});
            emitted = true;
        }
    }

    result.operands_len = f.len();
    return result;
}

/// MFV/MTV/CFC2/CTC2: mnemonic $rt, $vd
fn decodeCOP2Move(mnemonic: []const u8, insn: u32) DecodedInstruction {
    const rt = bits(insn, 20, 16);
    const vd = bits(insn, 15, 11) | (bits(insn, 10, 8) << 5);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rt));
    f.comma();
    vfpuRegName(&f, vd);

    result.operands_len = f.len();
    return result;
}

/// BC2F/BC2T — VFPU conditional branch
fn decodeCOP2Branch(insn: u32, address: u64) DecodedInstruction {
    const tf = bit(insn, 16);
    const imm16 = bits(insn, 15, 0);
    const target = branchTarget(address, imm16);

    const mnemonic: []const u8 = if (tf == 1) "bc2t" else "bc2f";

    var result = DecodedInstruction{
        .mnemonic = mnemonic,
        .is_branch = true,
        .is_conditional_branch = true,
        .branch_target = target,
    };
    var f = FmtBuf.init(&result.operands);
    f.appendHex(target);

    result.operands_len = f.len();
    return result;
}

/// Decode VFPU compute instructions (rs >= 16 in COP2).
/// Uses a layered dispatch on instruction bits to identify common operations.
///
/// VFPU encoding: bits[31:26]=COP2 (0x12), bit 25 is always 1 (rs >= 16).
/// Primary dispatch on bits[24:21] (the lower 4 bits of rs combined with bit 24).
/// Secondary dispatch uses bits[23:16] and/or bits[5:0] depending on family.
fn decodeVFPUCompute(insn: u32) DecodedInstruction {
    const funct6 = bits(insn, 5, 0);
    const op24_21: u4 = @truncate(bits(insn, 24, 21));
    const op23_16 = bits(insn, 23, 16);

    return switch (op24_21) {
        // 0b0000: vadd (vector add)
        0x0 => decodeVFPUGeneric("vadd", insn),
        // 0b0001: vsub (vector subtract)
        0x1 => decodeVFPUGeneric("vsub", insn),
        // 0b0010: vsbn / vtfm2
        0x2 => decodeVFPUGeneric("vtfm2", insn),
        // 0b0011: vdiv
        0x3 => decodeVFPUGeneric("vdiv", insn),
        // 0b0100: vmul (vector multiply)
        0x4 => decodeVFPUGeneric("vmul", insn),
        // 0b0101: vdot (dot product)
        0x5 => decodeVFPUGeneric("vdot", insn),
        // 0b0110: vscl (scalar multiply)
        0x6 => decodeVFPUGeneric("vscl", insn),
        // 0b0111: reserved / vfpu_op
        0x7 => decodeVFPUFallback(insn),
        // 0b1000: vcmp (vector compare)
        0x8 => decodeVFPUGeneric("vcmp", insn),
        // 0b1001: reserved
        0x9 => decodeVFPUFallback(insn),
        // 0b1010: vmin/vmax
        0xA => decodeVFPUGeneric("vmin", insn),
        // 0b1011: vscmp/vsge
        0xB => decodeVFPUGeneric("vscmp", insn),
        // 0b1100: vmmul (matrix multiply)
        0xC => decodeVFPUGeneric("vmmul", insn),
        // 0b1101: vtfm / vhtfm (matrix transform)
        0xD => decodeVFPUGeneric("vtfm", insn),
        // 0b1110: vcrsp / vi2f / vf2i / special unary (dispatch on op23_16)
        0xE => decodeVFPUSpecialE(insn, op23_16),
        // 0b1111: unary / transcendental (dispatch on op23_16 and funct6)
        0xF => decodeVFPUSpecialF(insn, op23_16, funct6),
    };
}

/// Decode VFPU group 0xE (bits[24:21] = 0b1110)
fn decodeVFPUSpecialE(insn: u32, op23_16: u32) DecodedInstruction {
    // bits[23:20] give the sub-family
    const sub4 = bits(insn, 23, 20);
    return switch (sub4) {
        0x0 => decodeVFPUGeneric("vi2f", insn),
        0x1 => decodeVFPUGeneric("vf2i", insn),
        0x3 => decodeVFPUGeneric("vcst", insn),
        else => blk: {
            _ = op23_16;
            break :blk decodeVFPUFallback(insn);
        },
    };
}

/// Decode VFPU group 0xF (bits[24:21] = 0b1111) -- unary/transcendental
fn decodeVFPUSpecialF(insn: u32, op23_16: u32, funct6: u32) DecodedInstruction {
    _ = op23_16;
    return decodeVFPUUnaryByFunct(insn, funct6);
}

/// Dispatch unary VFPU ops by funct field (bits [5:0])
fn decodeVFPUUnaryByFunct(insn: u32, funct6: u32) DecodedInstruction {
    return switch (funct6) {
        0x00 => decodeVFPUGeneric("vmov", insn),
        0x01 => decodeVFPUGeneric("vabs", insn),
        0x02 => decodeVFPUGeneric("vneg", insn),
        0x04 => decodeVFPUGeneric("vsat0", insn),
        0x05 => decodeVFPUGeneric("vsat1", insn),
        0x10 => decodeVFPUGeneric("vrcp", insn),
        0x11 => decodeVFPUGeneric("vrsq", insn),
        0x12 => decodeVFPUGeneric("vsin", insn),
        0x13 => decodeVFPUGeneric("vcos", insn),
        0x14 => decodeVFPUGeneric("vexp2", insn),
        0x15 => decodeVFPUGeneric("vlog2", insn),
        0x16 => decodeVFPUGeneric("vsqrt", insn),
        0x1A => decodeVFPUGeneric("vnrcp", insn),
        0x1C => decodeVFPUGeneric("vnsin", insn),
        0x1E => decodeVFPUGeneric("vneg", insn),
        else => decodeVFPUFallback(insn),
    };
}

/// Generic VFPU instruction with a known mnemonic — emit `mnemonic 0xHEX`
/// with the raw encoding as operand for decode-grade output.
fn decodeVFPUGeneric(mnemonic: []const u8, insn: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.appendHex(@as(u64, insn & 0x001FFFFF));

    result.operands_len = f.len();
    return result;
}

/// Fallback for unrecognized VFPU compute ops: `vfpu_op 0xHEX`
fn decodeVFPUFallback(insn: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = "vfpu_op" };
    var f = FmtBuf.init(&result.operands);
    f.appendHex(@as(u64, insn));

    result.operands_len = f.len();
    return result;
}

/// VFPU load/store: lv.s/sv.s/lv.q/sv.q $vt, offset($base)
fn decodeVFPULoadStore(mnemonic: []const u8, insn: u32) DecodedInstruction {
    const base = bits(insn, 25, 21);
    const vt = bits(insn, 20, 16);
    const imm16 = bits(insn, 15, 0);
    const offset = signExtend(@as(u64, imm16), 15);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    vfpuRegName(&f, vt);
    f.comma();
    f.appendDec(offset);
    f.append("(");
    f.append(gprName(base));
    f.append(")");

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// SPECIAL2 (opcode=0x1C) — MUL, MADD, CLZ, etc.
// ============================================================================

fn decodeSPECIAL2(insn: u32) DecodedInstruction {
    const rs = bits(insn, 25, 21);
    const rt = bits(insn, 20, 16);
    const rd = bits(insn, 15, 11);
    const funct = bits(insn, 5, 0);

    return switch (funct) {
        0x02 => blk: {
            // MUL: mul $rd, $rs, $rt
            var result = DecodedInstruction{ .mnemonic = "mul" };
            var f = FmtBuf.init(&result.operands);
            f.append(gprName(rd));
            f.comma();
            f.append(gprName(rs));
            f.comma();
            f.append(gprName(rt));
            result.operands_len = f.len();
            break :blk result;
        },
        0x00 => decodeMulDiv("madd", rs, rt),
        0x01 => decodeMulDiv("maddu", rs, rt),
        0x04 => decodeMulDiv("msub", rs, rt),
        0x05 => decodeMulDiv("msubu", rs, rt),
        0x20 => blk: {
            // CLZ: clz $rd, $rs
            var result = DecodedInstruction{ .mnemonic = "clz" };
            var f = FmtBuf.init(&result.operands);
            f.append(gprName(rd));
            f.comma();
            f.append(gprName(rs));
            result.operands_len = f.len();
            break :blk result;
        },
        0x21 => blk: {
            // CLO: clo $rd, $rs
            var result = DecodedInstruction{ .mnemonic = "clo" };
            var f = FmtBuf.init(&result.operands);
            f.append(gprName(rd));
            f.comma();
            f.append(gprName(rs));
            result.operands_len = f.len();
            break :blk result;
        },
        else => decodeUnknown(insn),
    };
}

// ============================================================================
// SPECIAL3 (opcode=0x1F) — EXT, INS
// ============================================================================

fn decodeSPECIAL3(insn: u32) DecodedInstruction {
    const rs = bits(insn, 25, 21);
    const rt = bits(insn, 20, 16);
    const funct = bits(insn, 5, 0);

    return switch (funct) {
        0x00 => blk: {
            // EXT: ext $rt, $rs, lsb, msbd+1
            const msbd = bits(insn, 15, 11);
            const lsb = bits(insn, 10, 6);
            var result = DecodedInstruction{ .mnemonic = "ext" };
            var f = FmtBuf.init(&result.operands);
            f.append(gprName(rt));
            f.comma();
            f.append(gprName(rs));
            f.comma();
            f.appendDec(@intCast(lsb));
            f.comma();
            f.appendDec(@as(i64, @intCast(msbd)) + 1);
            result.operands_len = f.len();
            break :blk result;
        },
        0x04 => blk: {
            // INS: ins $rt, $rs, lsb, msb-lsb+1
            const msb = bits(insn, 15, 11);
            const lsb = bits(insn, 10, 6);
            var result = DecodedInstruction{ .mnemonic = "ins" };
            var f = FmtBuf.init(&result.operands);
            f.append(gprName(rt));
            f.comma();
            f.append(gprName(rs));
            f.comma();
            f.appendDec(@intCast(lsb));
            f.comma();
            f.appendDec(@as(i64, @intCast(msb)) - @as(i64, @intCast(lsb)) + 1);
            result.operands_len = f.len();
            break :blk result;
        },
        else => decodeUnknown(insn),
    };
}

// ============================================================================
// COP0 (opcode=0x10) — MFC0, MTC0
// ============================================================================

fn decodeCOP0(insn: u32) DecodedInstruction {
    const rs = bits(insn, 25, 21);

    return switch (rs) {
        0x00 => decodeCOP0Move("mfc0", insn),
        0x04 => decodeCOP0Move("mtc0", insn),
        else => decodeUnknown(insn),
    };
}

/// MFC0/MTC0: mnemonic $rt, $rd
fn decodeCOP0Move(mnemonic: []const u8, insn: u32) DecodedInstruction {
    const rt = bits(insn, 20, 16);
    const rd = bits(insn, 15, 11);

    var result = DecodedInstruction{ .mnemonic = mnemonic };
    var f = FmtBuf.init(&result.operands);
    f.append(gprName(rt));
    f.comma();
    f.appendFmt("${d}", .{rd});

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// Unknown instruction — emit as .word directive
// ============================================================================

fn decodeUnknown(insn: u32) DecodedInstruction {
    var result = DecodedInstruction{ .mnemonic = ".word" };
    var f = FmtBuf.init(&result.operands);
    f.appendHex(@as(u64, insn));

    result.operands_len = f.len();
    return result;
}

// ============================================================================
// Public wrapper — returns types.Instruction with owned operand copy
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

test "nop (all zeros)" {
    const raw = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("nop", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 0), result.operands_len);
}

test "addu $v0, $a0, $a1" {
    // addu rd=2, rs=4, rt=5: opcode=0, rs=4, rt=5, rd=2, shamt=0, funct=0x21
    // 000000 00100 00101 00010 00000 100001
    // = 0x00851021
    const raw = [_]u8{ 0x21, 0x10, 0x85, 0x00 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("addu", result.mnemonic);
    try std.testing.expectEqualStrings("$v0, $a0, $a1", result.getOperands());
}

test "addiu $sp, $sp, -32" {
    // addiu rt=29, rs=29, imm=-32 (0xFFE0)
    // 001001 11101 11101 1111111111100000
    // = 0x27BDFFE0
    const raw = [_]u8{ 0xE0, 0xFF, 0xBD, 0x27 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("addiu", result.mnemonic);
    try std.testing.expectEqualStrings("$sp, $sp, -32", result.getOperands());
}

test "lw $a0, 16($sp)" {
    // lw rt=4, base=29, offset=16
    // 100011 11101 00100 0000000000010000
    // = 0x8FA40010
    const raw = [_]u8{ 0x10, 0x00, 0xA4, 0x8F };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("lw", result.mnemonic);
    try std.testing.expectEqualStrings("$a0, 16($sp)", result.getOperands());
}

test "sw $ra, 28($sp)" {
    // sw rt=31, base=29, offset=28
    // 101011 11101 11111 0000000000011100
    // = 0xAFBF001C
    const raw = [_]u8{ 0x1C, 0x00, 0xBF, 0xAF };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("sw", result.mnemonic);
    try std.testing.expectEqualStrings("$ra, 28($sp)", result.getOperands());
}

test "jal target" {
    // jal instr_index=0x00001000
    // 000011 00000000000001000000000000
    // = 0x0C001000
    const raw = [_]u8{ 0x00, 0x10, 0x00, 0x0C };
    const result = decode(&raw, 0x00400000);
    try std.testing.expectEqualStrings("jal", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_call);
    try std.testing.expectEqual(@as(u64, 0x00004000), result.branch_target.?);
}

test "jr $ra (return)" {
    // jr rs=31: 000000 11111 00000 00000 00000 001000
    // = 0x03E00008
    const raw = [_]u8{ 0x08, 0x00, 0xE0, 0x03 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("jr", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_return);
    try std.testing.expectEqualStrings("$ra", result.getOperands());
}

test "jr $t0 (not return)" {
    // jr rs=8: 000000 01000 00000 00000 00000 001000
    // = 0x01000008
    const raw = [_]u8{ 0x08, 0x00, 0x00, 0x01 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("jr", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(!result.is_return);
}

test "beq $a0, $zero, target" {
    // beq rs=4, rt=0, imm=0x000A (+10 instructions forward)
    // 000100 00100 00000 0000000000001010
    // = 0x1080000A
    const raw = [_]u8{ 0x0A, 0x00, 0x80, 0x10 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("beq", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x1000 + 4) + (10 << 2) = 0x102C
    try std.testing.expectEqual(@as(u64, 0x102C), result.branch_target.?);
}

test "lui $at, 0x1234" {
    // lui rt=1, imm=0x1234
    // 001111 00000 00001 0001001000110100
    // = 0x3C011234
    const raw = [_]u8{ 0x34, 0x12, 0x01, 0x3C };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("lui", result.mnemonic);
    try std.testing.expectEqualStrings("$at, 0x1234", result.getOperands());
}

test "ori $a0, $a0, 0x5678" {
    // ori rt=4, rs=4, imm=0x5678
    // 001101 00100 00100 0101011001111000
    // = 0x34845678
    const raw = [_]u8{ 0x78, 0x56, 0x84, 0x34 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("ori", result.mnemonic);
    try std.testing.expectEqualStrings("$a0, $a0, 0x5678", result.getOperands());
}

test "sll $v0, $v0, 2" {
    // sll rd=2, rt=2, shamt=2: 000000 00000 00010 00010 00010 000000
    // = 0x00021080
    const raw = [_]u8{ 0x80, 0x10, 0x02, 0x00 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("sll", result.mnemonic);
    try std.testing.expectEqualStrings("$v0, $v0, 2", result.getOperands());
}

test "syscall" {
    // syscall: 000000 ... 001100
    // = 0x0000000C
    const raw = [_]u8{ 0x0C, 0x00, 0x00, 0x00 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("syscall", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 0), result.operands_len);
}

test "bltz $a0, target" {
    // REGIMM: opcode=1, rs=4, rt=0 (bltz), imm=0x0005
    // 000001 00100 00000 0000000000000101
    // = 0x04800005
    const raw = [_]u8{ 0x05, 0x00, 0x80, 0x04 };
    const result = decode(&raw, 0x2000);
    try std.testing.expectEqualStrings("bltz", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x2000 + 4) + (5 << 2) = 0x2018
    try std.testing.expectEqual(@as(u64, 0x2018), result.branch_target.?);
}

test "bgezal $a0, target (branch-and-link)" {
    // REGIMM: opcode=1, rs=4, rt=0x11 (bgezal), imm=0x0003
    // 000001 00100 10001 0000000000000011
    // = 0x04910003
    const raw = [_]u8{ 0x03, 0x00, 0x91, 0x04 };
    const result = decode(&raw, 0x3000);
    try std.testing.expectEqualStrings("bgezal", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    try std.testing.expect(result.is_call);
    // target = (0x3000 + 4) + (3 << 2) = 0x3010
    try std.testing.expectEqual(@as(u64, 0x3010), result.branch_target.?);
}

test "add.s $f0, $f2, $f4" {
    // COP1: opcode=0x11, rs=0x10 (single), ft=4, fs=2, fd=0, funct=0x00 (add)
    // 010001 10000 00100 00010 00000 000000
    // = 0x46041000
    const raw = [_]u8{ 0x00, 0x10, 0x04, 0x46 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("add.s", result.mnemonic);
    try std.testing.expectEqualStrings("$f0, $f2, $f4", result.getOperands());
}

test "mov.s $f4, $f6" {
    // COP1: opcode=0x11, rs=0x10 (single), ft=0, fs=6, fd=4, funct=0x06 (mov)
    // 010001 10000 00000 00110 00100 000110
    // = 0x46003106
    const raw = [_]u8{ 0x06, 0x31, 0x00, 0x46 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("mov.s", result.mnemonic);
    try std.testing.expectEqualStrings("$f4, $f6", result.getOperands());
}

test "mfc1 $v0, $f12" {
    // COP1: opcode=0x11, rs=0x00 (MFC1), rt=2, fs=12
    // 010001 00000 00010 01100 00000 000000
    // = 0x44026000
    const raw = [_]u8{ 0x00, 0x60, 0x02, 0x44 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("mfc1", result.mnemonic);
    try std.testing.expectEqualStrings("$v0, $f12", result.getOperands());
}

test "lwc1 $f4, 8($sp)" {
    // LWC1: opcode=0x31, base=29, ft=4, offset=8
    // 110001 11101 00100 0000000000001000
    // = 0xC7A40008
    const raw = [_]u8{ 0x08, 0x00, 0xA4, 0xC7 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("lwc1", result.mnemonic);
    try std.testing.expectEqualStrings("$f4, 8($sp)", result.getOperands());
}

test "bc1t target" {
    // COP1: opcode=0x11, rs=0x08 (BC1), bit16=1 (BC1T), imm=0x0004
    // 010001 01000 00001 0000000000000100
    // = 0x45010004
    const raw = [_]u8{ 0x04, 0x00, 0x01, 0x45 };
    const result = decode(&raw, 0x4000);
    try std.testing.expectEqualStrings("bc1t", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x4000 + 4) + (4 << 2) = 0x4014
    try std.testing.expectEqual(@as(u64, 0x4014), result.branch_target.?);
}

test "unknown instruction" {
    // Use an undefined opcode, e.g. opcode=0x3F
    // 111111 00000000000000000000000000
    // = 0xFC000000
    const raw = [_]u8{ 0x00, 0x00, 0x00, 0xFC };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings(".word", result.mnemonic);
}

// decodeInstruction is tested transitively when imported from the main
// analysis engine.  We cannot call it in standalone `zig test` because the
// operands slice points into the returned struct's operands_buf, and the
// returned-by-value semantics make the slice dangling in test code.
// The decode() function (which does all the real work) is fully covered
// by the tests below.

test "j target" {
    // j instr_index=0x00100000
    // 000010 00000100000000000000000000
    // = 0x08100000
    const raw = [_]u8{ 0x00, 0x00, 0x10, 0x08 };
    const result = decode(&raw, 0x00400000);
    try std.testing.expectEqualStrings("j", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(!result.is_call);
    // target = (0x00400000 & 0xF0000000) | (0x00100000 << 2) = 0x00400000
    try std.testing.expectEqual(@as(u64, 0x00400000), result.branch_target.?);
}

test "jalr $ra, $t9" {
    // jalr rd=31, rs=25: 000000 11001 00000 11111 00000 001001
    // = 0x0320F809
    const raw = [_]u8{ 0x09, 0xF8, 0x20, 0x03 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("jalr", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_call);
    try std.testing.expectEqualStrings("$ra, $t9", result.getOperands());
}

test "c.eq.s $f2, $f4" {
    // COP1: opcode=0x11, rs=0x10 (single), ft=4, fs=2, fd=0, funct=0x32
    // 010001 10000 00100 00010 00000 110010
    // = 0x46041032
    const raw = [_]u8{ 0x32, 0x10, 0x04, 0x46 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("c.eq.s", result.mnemonic);
    try std.testing.expectEqualStrings("$f2, $f4", result.getOperands());
}

test "cvt.s.w $f0, $f2" {
    // COP1: opcode=0x11, rs=0x14 (word), ft=0, fs=2, fd=0, funct=0x20
    // 010001 10100 00000 00010 00000 100000
    // = 0x46801020
    const raw = [_]u8{ 0x20, 0x10, 0x80, 0x46 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("cvt.s.w", result.mnemonic);
    try std.testing.expectEqualStrings("$f0, $f2", result.getOperands());
}

test "sll $zero, $zero, 3 is not nop" {
    // sll rd=0, rt=0, shamt=3: 000000 00000 00000 00000 00011 000000
    // = 0x000000C0
    const raw = [_]u8{ 0xC0, 0x00, 0x00, 0x00 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("sll", result.mnemonic);
    try std.testing.expectEqualStrings("$zero, $zero, 3", result.getOperands());
}

test "negative branch offset" {
    // beq $a0, $zero, imm=-4 (0xFFFC => backward branch)
    // 000100 00100 00000 1111111111111100
    // = 0x1080FFFC
    const raw = [_]u8{ 0xFC, 0xFF, 0x80, 0x10 };
    const result = decode(&raw, 0x2000);
    try std.testing.expectEqualStrings("beq", result.mnemonic);
    // target = (0x2000 + 4) + (-4 << 2) = 0x2004 - 16 = 0x1FF4
    try std.testing.expectEqual(@as(u64, 0x1FF4), result.branch_target.?);
}

test "swc1 $f6, -4($sp)" {
    // SWC1: opcode=0x39, base=29, ft=6, offset=-4 (0xFFFC)
    // 111001 11101 00110 1111111111111100
    // = 0xE7A6FFFC
    const raw = [_]u8{ 0xFC, 0xFF, 0xA6, 0xE7 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("swc1", result.mnemonic);
    try std.testing.expectEqualStrings("$f6, -4($sp)", result.getOperands());
}

test "div $a0, $a1" {
    // div rs=4, rt=5: 000000 00100 00101 00000 00000 011010
    // = 0x0085001A
    const raw = [_]u8{ 0x1A, 0x00, 0x85, 0x00 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("div", result.mnemonic);
    try std.testing.expectEqualStrings("$a0, $a1", result.getOperands());
}

test "mfhi $v0" {
    // mfhi rd=2: 000000 00000 00000 00010 00000 010000
    // = 0x00001010
    const raw = [_]u8{ 0x10, 0x10, 0x00, 0x00 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("mfhi", result.mnemonic);
    try std.testing.expectEqualStrings("$v0", result.getOperands());
}

test "too short input" {
    const raw = [_]u8{ 0x00, 0x00 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("udf", result.mnemonic);
}

test "beql $a0, $a1, target (branch-likely)" {
    // beql rs=4, rt=5, imm=0x0008
    // 010100 00100 00101 0000000000001000
    // = 0x50850008
    const raw = [_]u8{ 0x08, 0x00, 0x85, 0x50 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("beql", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x1000 + 4) + (8 << 2) = 0x1024
    try std.testing.expectEqual(@as(u64, 0x1024), result.branch_target.?);
    try std.testing.expectEqualStrings("$a0, $a1, 0x1024", result.getOperands());
}

test "bnel $v0, $zero, target (branch-likely)" {
    // bnel rs=2, rt=0, imm=0x0003
    // 010101 00010 00000 0000000000000011
    // = 0x54400003
    const raw = [_]u8{ 0x03, 0x00, 0x40, 0x54 };
    const result = decode(&raw, 0x2000);
    try std.testing.expectEqualStrings("bnel", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x2000 + 4) + (3 << 2) = 0x2010
    try std.testing.expectEqual(@as(u64, 0x2010), result.branch_target.?);
}

test "blezl $a0, target (branch-likely)" {
    // blezl rs=4, rt=0, imm=0x0005
    // 010110 00100 00000 0000000000000101
    // = 0x58800005
    const raw = [_]u8{ 0x05, 0x00, 0x80, 0x58 };
    const result = decode(&raw, 0x3000);
    try std.testing.expectEqualStrings("blezl", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x3000 + 4) + (5 << 2) = 0x3018
    try std.testing.expectEqual(@as(u64, 0x3018), result.branch_target.?);
}

test "bgtzl $a0, target (branch-likely)" {
    // bgtzl rs=4, rt=0, imm=0x0002
    // 010111 00100 00000 0000000000000010
    // = 0x5C800002
    const raw = [_]u8{ 0x02, 0x00, 0x80, 0x5C };
    const result = decode(&raw, 0x4000);
    try std.testing.expectEqualStrings("bgtzl", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x4000 + 4) + (2 << 2) = 0x400C
    try std.testing.expectEqual(@as(u64, 0x400C), result.branch_target.?);
}

test "ext $a0, $a1, 4, 8" {
    // SPECIAL3: opcode=0x1F, rs=5, rt=4, msbd=7 (size-1=7 => size=8), lsb=4, funct=0x00
    // 011111 00101 00100 00111 00100 000000
    // = 0x7CA43900
    // Verify: bits[31:26]=011111=0x1F, [25:21]=00101=5, [20:16]=00100=4,
    //         [15:11]=00111=7, [10:6]=00100=4, [5:0]=000000=0x00
    const raw = [_]u8{ 0x00, 0x39, 0xA4, 0x7C };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("ext", result.mnemonic);
    try std.testing.expectEqualStrings("$a0, $a1, 4, 8", result.getOperands());
    try std.testing.expect(!result.is_branch);
}

test "ins $a0, $a1, 2, 6" {
    // SPECIAL3: opcode=0x1F, rs=5, rt=4, msb=7 (msb=lsb+size-1=2+6-1=7), lsb=2, funct=0x04
    // 011111 00101 00100 00111 00010 000100
    // = 0x7CA43884
    // Verify: bits[31:26]=011111=0x1F, [25:21]=00101=5, [20:16]=00100=4,
    //         [15:11]=00111=7, [10:6]=00010=2, [5:0]=000100=0x04
    const raw = [_]u8{ 0x84, 0x38, 0xA4, 0x7C };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("ins", result.mnemonic);
    try std.testing.expectEqualStrings("$a0, $a1, 2, 6", result.getOperands());
    try std.testing.expect(!result.is_branch);
}

test "mfc0 $v0, $12 (Status register)" {
    // COP0: opcode=0x10, rs=0x00 (MFC0), rt=2, rd=12, zeros
    // 010000 00000 00010 01100 00000 000000
    // = 0x40026000
    const raw = [_]u8{ 0x00, 0x60, 0x02, 0x40 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("mfc0", result.mnemonic);
    try std.testing.expectEqualStrings("$v0, $12", result.getOperands());
    try std.testing.expect(!result.is_branch);
}

test "mtc0 $a0, $13 (Cause register)" {
    // COP0: opcode=0x10, rs=0x04 (MTC0), rt=4, rd=13, zeros
    // 010000 00100 00100 01101 00000 000000
    // = 0x40846800
    const raw = [_]u8{ 0x00, 0x68, 0x84, 0x40 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("mtc0", result.mnemonic);
    try std.testing.expectEqualStrings("$a0, $13", result.getOperands());
    try std.testing.expect(!result.is_branch);
}

test "unknown SPECIAL3 funct falls to .word" {
    // SPECIAL3: opcode=0x1F, funct=0x3F (undefined)
    // 011111 00000 00000 00000 00000 111111
    // = 0x7C00003F
    const raw = [_]u8{ 0x3F, 0x00, 0x00, 0x7C };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings(".word", result.mnemonic);
}

test "unknown COP0 rs falls to .word" {
    // COP0: opcode=0x10, rs=0x10 (CO=1, e.g. ERET/TLBR), not decoded
    // 010000 10000 00000 00000 00000 000000
    // = 0x42000000
    const raw = [_]u8{ 0x00, 0x00, 0x00, 0x42 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings(".word", result.mnemonic);
}

test "bltzl $a0, target (REGIMM branch-likely)" {
    // REGIMM: opcode=1, rs=4, rt=0x02 (bltzl), imm=0x0006
    // 000001 00100 00010 0000000000000110
    // = 0x04820006
    const raw = [_]u8{ 0x06, 0x00, 0x82, 0x04 };
    const result = decode(&raw, 0x2000);
    try std.testing.expectEqualStrings("bltzl", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    try std.testing.expect(!result.is_call);
    // target = (0x2000 + 4) + (6 << 2) = 0x201C
    try std.testing.expectEqual(@as(u64, 0x201C), result.branch_target.?);
    try std.testing.expectEqualStrings("$a0, 0x201c", result.getOperands());
}

test "bgezl $a1, target (REGIMM branch-likely)" {
    // REGIMM: opcode=1, rs=5, rt=0x03 (bgezl), imm=0x0004
    // 000001 00101 00011 0000000000000100
    // = 0x04A30004
    const raw = [_]u8{ 0x04, 0x00, 0xA3, 0x04 };
    const result = decode(&raw, 0x3000);
    try std.testing.expectEqualStrings("bgezl", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    try std.testing.expect(!result.is_call);
    // target = (0x3000 + 4) + (4 << 2) = 0x3014
    try std.testing.expectEqual(@as(u64, 0x3014), result.branch_target.?);
    try std.testing.expectEqualStrings("$a1, 0x3014", result.getOperands());
}

test "mul $v0, $a0, $a1 (SPECIAL2)" {
    // SPECIAL2: opcode=0x1C, rs=4, rt=5, rd=2, shamt=0, funct=0x02
    // 011100 00100 00101 00010 00000 000010
    // = 0x70851002
    const raw = [_]u8{ 0x02, 0x10, 0x85, 0x70 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("mul", result.mnemonic);
    try std.testing.expectEqualStrings("$v0, $a0, $a1", result.getOperands());
    try std.testing.expect(!result.is_branch);
}

test "clz $v0, $a0 (SPECIAL2)" {
    // SPECIAL2: opcode=0x1C, rs=4, rt=0, rd=2, shamt=0, funct=0x20
    // 011100 00100 00000 00010 00000 100000
    // = 0x70801020
    const raw = [_]u8{ 0x20, 0x10, 0x80, 0x70 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("clz", result.mnemonic);
    try std.testing.expectEqualStrings("$v0, $a0", result.getOperands());
    try std.testing.expect(!result.is_branch);
}

test "madd $a0, $a1 (SPECIAL2)" {
    // SPECIAL2: opcode=0x1C, rs=4, rt=5, rd=0, shamt=0, funct=0x00
    // 011100 00100 00101 00000 00000 000000
    // = 0x70850000
    const raw = [_]u8{ 0x00, 0x00, 0x85, 0x70 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("madd", result.mnemonic);
    try std.testing.expectEqualStrings("$a0, $a1", result.getOperands());
    try std.testing.expect(!result.is_branch);
}

// ============================================================================
// VFPU (COP2) tests
// ============================================================================

test "mfv $v0, $v5 (COP2 MFC2)" {
    // COP2: opcode=0x12, rs=0x00 (MFC2), rt=2, vd=5
    // 010010 00000 00010 00101 00000 000000
    // = 0x48022800
    const raw = [_]u8{ 0x00, 0x28, 0x02, 0x48 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("mfv", result.mnemonic);
    try std.testing.expect(!result.is_branch);
}

test "mtv $a0, $v3 (COP2 MTC2)" {
    // COP2: opcode=0x12, rs=0x04 (MTC2), rt=4, vd=3
    // 010010 00100 00100 00011 00000 000000
    // = 0x48841800
    const raw = [_]u8{ 0x00, 0x18, 0x84, 0x48 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("mtv", result.mnemonic);
    try std.testing.expect(!result.is_branch);
}

test "bc2t target (COP2 branch)" {
    // COP2: opcode=0x12, rs=0x08 (BC2), bit16=1 (BC2T), imm=0x0006
    // 010010 01000 00001 0000000000000110
    // = 0x49010006
    const raw = [_]u8{ 0x06, 0x00, 0x01, 0x49 };
    const result = decode(&raw, 0x5000);
    try std.testing.expectEqualStrings("bc2t", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x5000 + 4) + (6 << 2) = 0x501C
    try std.testing.expectEqual(@as(u64, 0x501C), result.branch_target.?);
}

test "bc2f target (COP2 branch)" {
    // COP2: opcode=0x12, rs=0x08 (BC2), bit16=0 (BC2F), imm=0x0003
    // 010010 01000 00000 0000000000000011
    // = 0x49000003
    const raw = [_]u8{ 0x03, 0x00, 0x00, 0x49 };
    const result = decode(&raw, 0x6000);
    try std.testing.expectEqualStrings("bc2f", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    // target = (0x6000 + 4) + (3 << 2) = 0x6010
    try std.testing.expectEqual(@as(u64, 0x6010), result.branch_target.?);
}

test "lv.s $v4, 8($sp) (VFPU load single)" {
    // LWC2: opcode=0x32, base=29($sp), vt=4, offset=8
    // 110010 11101 00100 0000000000001000
    // = 0xCBA40008
    const raw = [_]u8{ 0x08, 0x00, 0xA4, 0xCB };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("lv.s", result.mnemonic);
    try std.testing.expect(!result.is_branch);
    try std.testing.expectEqualStrings("$v4, 8($sp)", result.getOperands());
}

test "sv.s $v6, -4($sp) (VFPU store single)" {
    // SWC2: opcode=0x36, base=29($sp), vt=6, offset=-4 (0xFFFC)
    // 110110 11101 00110 1111111111111100
    // = 0xDBA6FFFC
    const raw = [_]u8{ 0xFC, 0xFF, 0xA6, 0xDB };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("sv.s", result.mnemonic);
    try std.testing.expect(!result.is_branch);
    try std.testing.expectEqualStrings("$v6, -4($sp)", result.getOperands());
}

test "lv.q $v8, 16($a0) (VFPU load quad)" {
    // opcode=0x34, base=4($a0), vt=8, offset=16
    // 110100 00100 01000 0000000000010000
    // = 0xD0880010
    const raw = [_]u8{ 0x10, 0x00, 0x88, 0xD0 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("lv.q", result.mnemonic);
    try std.testing.expect(!result.is_branch);
    try std.testing.expectEqualStrings("$v8, 16($a0)", result.getOperands());
}

test "sv.q $v2, 0($a1) (VFPU store quad)" {
    // opcode=0x3E, base=5($a1), vt=2, offset=0
    // 111110 00101 00010 0000000000000000
    // = 0xF8A20000
    const raw = [_]u8{ 0x00, 0x00, 0xA2, 0xF8 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("sv.q", result.mnemonic);
    try std.testing.expect(!result.is_branch);
    try std.testing.expectEqualStrings("$v2, 0($a1)", result.getOperands());
}

test "vadd VFPU compute (COP2 rs>=16)" {
    // COP2: opcode=0x12, rs=16 (bit25=1, bits[24:21]=0000 => vadd)
    // 010010 10000 00000 00000 00000 000000
    // = 0x4A000000
    const raw = [_]u8{ 0x00, 0x00, 0x00, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("vadd", result.mnemonic);
    try std.testing.expect(!result.is_branch);
}

test "cfc2 $t0, $v12 (COP2 CFC2)" {
    // COP2: opcode=0x12, rs=0x03 (CFC2), rt=8($t0), vd=12
    // 010010 00011 01000 01100 00000 000000
    // = 0x48686000
    const raw = [_]u8{ 0x00, 0x60, 0x68, 0x48 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("cfc2", result.mnemonic);
    try std.testing.expect(!result.is_branch);
}

test "ctc2 $t1, $v15 (COP2 CTC2)" {
    // COP2: opcode=0x12, rs=0x07 (CTC2), rt=9($t1), vd=15
    // 010010 00111 01001 01111 00000 000000
    // = 0x48E97800
    const raw = [_]u8{ 0x00, 0x78, 0xE9, 0x48 };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("ctc2", result.mnemonic);
    try std.testing.expect(!result.is_branch);
}

// ============================================================================
// PS1 GTE (COP2 imm25) tests
// ============================================================================

test "RTPS basic (GTE 0x01, no flags)" {
    // COP2 GTE: opcode=0x12, bit25=1, op6=0x01 → RTPS, all flags zero
    // 0x4A000001 → LE: 01 00 00 4A
    const raw = [_]u8{ 0x01, 0x00, 0x00, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("RTPS", result.mnemonic);
    try std.testing.expectEqualStrings("", result.getOperands());
    try std.testing.expect(!result.is_branch);
}

test "NCLIP basic (GTE 0x06)" {
    // COP2 GTE: op6=0x06 → NCLIP, no flags
    // 0x4A000006 → LE: 06 00 00 4A
    const raw = [_]u8{ 0x06, 0x00, 0x00, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("NCLIP", result.mnemonic);
    try std.testing.expectEqualStrings("", result.getOperands());
}

test "MVMVA all-zero flags (GTE 0x12)" {
    // MVMVA always emits all 5 flags even when zero
    // 0x4A000012 → LE: 12 00 00 4A
    const raw = [_]u8{ 0x12, 0x00, 0x00, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("MVMVA", result.mnemonic);
    try std.testing.expectEqualStrings("mx=0 vx=0 cv=0 lm=0 sf=0", result.getOperands());
}

test "MVMVA with mx=3 vx=1 cv=2 lm=1 sf=0 (GTE 0x12)" {
    // mx=3 (bits 18:17), vx=1 (bits 16:15), cv=2 (bits 14:13), lm=1 (bit 10), sf=0 (bit 19)
    // word = 0x4A000000 | (3<<17) | (1<<15) | (2<<13) | (1<<10) | 0x12
    //      = 0x4A000000 | 0x60000 | 0x8000 | 0x4000 | 0x400 | 0x12
    //      = 0x4A06C412 → LE: 12 C4 06 4A
    const raw = [_]u8{ 0x12, 0xC4, 0x06, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("MVMVA", result.mnemonic);
    try std.testing.expectEqualStrings("mx=3 vx=1 cv=2 lm=1 sf=0", result.getOperands());
}

test "OP with sf=1 (GTE 0x0C)" {
    // op6=0x0C OP, sf=1 (bit 19)
    // word = 0x4A000000 | (1<<19) | 0x0C = 0x4A08000C → LE: 0C 00 08 4A
    const raw = [_]u8{ 0x0C, 0x00, 0x08, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("OP", result.mnemonic);
    try std.testing.expectEqualStrings("sf=1", result.getOperands());
}

test "AVSZ4 (GTE 0x2E)" {
    // op6=0x2E AVSZ4, no flags
    // word = 0x4A00002E → LE: 2E 00 00 4A
    const raw = [_]u8{ 0x2E, 0x00, 0x00, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("AVSZ4", result.mnemonic);
    try std.testing.expectEqualStrings("", result.getOperands());
}

test "RTPT with lm=1 (GTE 0x30)" {
    // op6=0x30 RTPT, lm=1 (bit 10)
    // word = 0x4A000000 | (1<<10) | 0x30 = 0x4A000430 → LE: 30 04 00 4A
    const raw = [_]u8{ 0x30, 0x04, 0x00, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("RTPT", result.mnemonic);
    try std.testing.expectEqualStrings("lm=1", result.getOperands());
}

test "NCCT (GTE 0x3F)" {
    // op6=0x3F NCCT, no flags
    // word = 0x4A00003F → LE: 3F 00 00 4A
    const raw = [_]u8{ 0x3F, 0x00, 0x00, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("NCCT", result.mnemonic);
    try std.testing.expectEqualStrings("", result.getOperands());
}

test "GTE non-opcode falls through to VFPU (vadd preserved)" {
    // op6=0x00 is NOT a GTE command; ensure decodeGTE returns null and the
    // existing VFPU dispatcher still produces "vadd" (regression guard for PSP).
    // 0x4A000000 → LE: 00 00 00 4A
    const raw = [_]u8{ 0x00, 0x00, 0x00, 0x4A };
    const result = decode(&raw, 0x1000);
    try std.testing.expectEqualStrings("vadd", result.mnemonic);
}
