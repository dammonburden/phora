// Phora — ARM64 (AArch64) Instruction Decoder
// Table-driven decoder for fixed 32-bit ARM64 instructions.
// Reference: ARM Architecture Reference Manual (ARMv8-A)

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
            .size = 4,
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

fn xRegName(reg: u5) []const u8 {
    const names = [32][]const u8{
        "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
        "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
    };
    return names[reg];
}

fn wRegName(reg: u5) []const u8 {
    const names = [32][]const u8{
        "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
        "w8",  "w9",  "w10", "w11", "w12", "w13", "w14", "w15",
        "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
        "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wsp",
    };
    return names[reg];
}

fn xRegOrZr(reg: u5) []const u8 {
    if (reg == 31) return "xzr";
    return xRegName(reg);
}

fn wRegOrZr(reg: u5) []const u8 {
    if (reg == 31) return "wzr";
    return wRegName(reg);
}

fn regName(reg: u5, sf: bool) []const u8 {
    if (sf) return xRegOrZr(reg);
    return wRegOrZr(reg);
}

fn regNameSp(reg: u5, sf: bool) []const u8 {
    if (sf) return xRegName(reg);
    return wRegName(reg);
}

// ============================================================================
// Shift type names
// ============================================================================

const shift_names = [4][]const u8{ "lsl", "lsr", "asr", "ror" };

// ============================================================================
// Bit extraction helpers
// ============================================================================

fn bits(insn: u32, hi: u5, lo: u5) u32 {
    const width = @as(u5, hi - lo + 1);
    return (insn >> lo) & ((@as(u32, 1) << width) - 1);
}

fn bit(insn: u32, pos: u5) u1 {
    return @truncate(insn >> pos);
}

fn signExtend(value: u64, sign_bit: u6) i64 {
    const mask = @as(u64, 1) << sign_bit;
    if (value & mask != 0) {
        // Sign bit is set, extend with 1s
        const ext: u64 = @as(u64, 0xFFFFFFFFFFFFFFFF) << @as(u6, sign_bit + 1);
        return @bitCast(ext | value);
    }
    return @intCast(value);
}

/// v7.12 W9: like signExtend but returns u64 (caller bitcasts to i64). Treats
/// `value` as an N+1-bit value where bit `sign_bit` is the sign. Pre-shift
/// sign-extension keeps imm26 / imm19 calculations identical regardless of
/// whether the caller multiplies the result by 4 (for 4-byte branch offsets).
fn signExtend64(value: u64, sign_bit: u6) u64 {
    const mask = @as(u64, 1) << sign_bit;
    if (value & mask == 0) return value;
    const ext: u64 = @as(u64, 0xFFFFFFFFFFFFFFFF) << @as(u6, sign_bit + 1);
    return ext | value;
}

// ============================================================================
// Operand formatting
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

    fn appendInt(self: *FmtBuf, value: i64) void {
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
// Main decode entry point
// ============================================================================

pub fn decode(raw: []const u8, address: u64) DecodedInstruction {
    if (raw.len < 4) {
        return .{ .mnemonic = "udf" };
    }

    const insn: u32 = @as(u32, raw[0]) |
        (@as(u32, raw[1]) << 8) |
        (@as(u32, raw[2]) << 16) |
        (@as(u32, raw[3]) << 24);

    var result = DecodedInstruction{ .mnemonic = "udf" };

    // Top-level decode by bits [28:25] — the main encoding group
    const op0 = bits(insn, 28, 25);

    switch (op0) {
        // 0b0000: Reserved / UDF
        0b0000 => {
            result.mnemonic = "udf";
        },

        // 0b100x: Data processing — immediate
        0b1000, 0b1001 => {
            decodeDPImmediate(insn, address, &result);
        },

        // 0b101x: Branches, exception generation, system
        0b1010, 0b1011 => {
            decodeBranchesAndSystem(insn, address, &result);
        },

        // 0bx1x0: Loads and stores
        0b0100, 0b0110, 0b1100, 0b1110 => {
            decodeLoadStore(insn, address, &result);
        },

        // 0bx101: Data processing — register
        0b0101, 0b1101 => {
            decodeDPRegister(insn, address, &result);
        },

        // 0bx111: Data processing — SIMD/FP (stub)
        0b0111, 0b1111 => {
            result.mnemonic = "simd/fp";
        },

        // 0b001x: SME / SVE (stub)
        0b0010, 0b0011 => {
            result.mnemonic = "sve";
        },

        // 0b0001: Unallocated
        0b0001 => {
            result.mnemonic = "udf";
        },

        else => {
            result.mnemonic = "udf";
        },
    }

    return result;
}

// ============================================================================
// Branches, Exception Generation, and System instructions
// bits [28:25] = 101x
// ============================================================================

fn decodeBranchesAndSystem(insn: u32, address: u64, result: *DecodedInstruction) void {
    // Primary dispatch on bits [31:29]
    const op0_hi = bits(insn, 31, 29);

    switch (op0_hi) {
        // 0b110: Exception generation, system instructions, unconditional branch (register)
        // Must be checked BEFORE B/BL since these share bit patterns
        0b110 => {
            decodeSystemAndBranchReg(insn, address, result);
        },
        // 0b000: B (unconditional immediate)
        0b000 => {
            // v7.12 W9: explicitly sign-extend imm26 (26-bit signed) before
            // shifting by 2. This matches the ARMv8-A reference pseudocode
            // SignExtend(imm26:'00', 64) and avoids any ambiguity that arose
            // from sign-extending the post-shift 28-bit value.
            const imm26 = bits(insn, 25, 0);
            const sext: i64 = @as(i64, @bitCast(signExtend64(imm26, 25)));
            const offset: i64 = sext * 4;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
            result.mnemonic = "b";
            result.is_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
        },
        // 0b100: BL (branch with link, immediate)
        0b100 => {
            const imm26 = bits(insn, 25, 0);
            const sext: i64 = @as(i64, @bitCast(signExtend64(imm26, 25)));
            const offset: i64 = sext * 4;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
            result.mnemonic = "bl";
            result.is_branch = true;
            result.is_call = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
        },
        // 0b010: B.cond (conditional branch immediate)
        0b010 => {
            const imm19 = bits(insn, 23, 5);
            const cond: u4 = @truncate(bits(insn, 3, 0));
            const offset = signExtend(imm19 << 2, 20);
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
            result.mnemonic = condBranchMnemonic(cond);
            result.is_branch = true;
            result.is_conditional_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
        },
        // 0b001, 0b101: CBZ/CBNZ
        0b001, 0b101 => {
            const sf = bit(insn, 31) == 1;
            const op = bit(insn, 24);
            const imm19 = bits(insn, 23, 5);
            const rt: u5 = @truncate(bits(insn, 4, 0));
            const offset = signExtend(imm19 << 2, 20);
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
            result.mnemonic = if (op == 0) "cbz" else "cbnz";
            result.is_branch = true;
            result.is_conditional_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rt, sf));
            f.comma();
            f.appendHex(target);
            result.operands_len = f.len();
        },
        // 0b011, 0b111: TBZ/TBNZ
        0b011, 0b111 => {
            const b5 = bit(insn, 31);
            const b40: u5 = @truncate(bits(insn, 23, 19));
            const op = bit(insn, 24);
            const imm14 = bits(insn, 18, 5);
            const rt: u5 = @truncate(bits(insn, 4, 0));
            const offset = signExtend(imm14 << 2, 15);
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
            const bit_num = (@as(u6, b5) << 5) | @as(u6, b40);
            const sf = b5 == 1;
            result.mnemonic = if (op == 0) "tbz" else "tbnz";
            result.is_branch = true;
            result.is_conditional_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rt, sf));
            f.comma();
            f.appendFmt("#{d}", .{bit_num});
            f.comma();
            f.appendHex(target);
            result.operands_len = f.len();
        },
        else => {},
    }
}

fn condBranchMnemonic(cond: u4) []const u8 {
    return switch (cond) {
        0b0000 => "b.eq",
        0b0001 => "b.ne",
        0b0010 => "b.cs",
        0b0011 => "b.cc",
        0b0100 => "b.mi",
        0b0101 => "b.pl",
        0b0110 => "b.vs",
        0b0111 => "b.vc",
        0b1000 => "b.hi",
        0b1001 => "b.ls",
        0b1010 => "b.ge",
        0b1011 => "b.lt",
        0b1100 => "b.gt",
        0b1101 => "b.le",
        0b1110 => "b.al",
        0b1111 => "b.nv",
    };
}

fn decodeSystemAndBranchReg(insn: u32, _: u64, result: *DecodedInstruction) void {
    const opc = bits(insn, 24, 21);
    const op2 = bits(insn, 20, 16);
    const op3 = bits(insn, 15, 10);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const op4 = bits(insn, 4, 0);

    // Exception generation
    if (bits(insn, 31, 24) == 0b11010100) {
        const exc_opc = bits(insn, 23, 21);
        const imm16 = bits(insn, 20, 5);
        switch (exc_opc) {
            0b000 => {
                // SVC
                result.mnemonic = "svc";
                var f = FmtBuf.init(&result.operands);
                f.appendFmt("#{d}", .{imm16});
                result.operands_len = f.len();
                return;
            },
            0b001 => {
                result.mnemonic = "hvc";
                var f = FmtBuf.init(&result.operands);
                f.appendFmt("#{d}", .{imm16});
                result.operands_len = f.len();
                return;
            },
            0b010 => {
                result.mnemonic = "smc";
                var f = FmtBuf.init(&result.operands);
                f.appendFmt("#{d}", .{imm16});
                result.operands_len = f.len();
                return;
            },
            0b011 => {
                result.mnemonic = "brk";
                var f = FmtBuf.init(&result.operands);
                f.appendFmt("#{d}", .{imm16});
                result.operands_len = f.len();
                return;
            },
            else => {},
        }
    }

    // System instructions (MSR, MRS, NOP, DMB, DSB, ISB)
    if (bits(insn, 31, 22) == 0b1101010100) {
        const l = bit(insn, 21);
        const op_1 = bits(insn, 18, 16);
        const crn: u4 = @truncate(bits(insn, 15, 12));
        const crm: u4 = @truncate(bits(insn, 11, 8));
        const op_2: u3 = @truncate(bits(insn, 7, 5));
        const rt: u5 = @truncate(bits(insn, 4, 0));

        // NOP, YIELD, WFE, WFI, SEV, SEVL
        if (l == 0 and op_1 == 0b011 and crn == 0b0010 and rt == 0b11111) {
            switch (crm) {
                0b0000 => {
                    result.mnemonic = switch (op_2) {
                        0b000 => "nop",
                        0b001 => "yield",
                        0b010 => "wfe",
                        0b011 => "wfi",
                        0b100 => "sev",
                        0b101 => "sevl",
                        else => "hint",
                    };
                    return;
                },
                else => {},
            }
        }

        // DMB, DSB, ISB
        if (l == 0 and op_1 == 0b011 and crn == 0b0011 and rt == 0b11111) {
            switch (op_2) {
                0b001 => {
                    result.mnemonic = "dsb";
                    var f = FmtBuf.init(&result.operands);
                    f.append(barrierOption(crm));
                    result.operands_len = f.len();
                    return;
                },
                0b101 => {
                    result.mnemonic = "dmb";
                    var f = FmtBuf.init(&result.operands);
                    f.append(barrierOption(crm));
                    result.operands_len = f.len();
                    return;
                },
                0b110 => {
                    result.mnemonic = "isb";
                    if (crm != 0b1111) {
                        var f = FmtBuf.init(&result.operands);
                        f.appendFmt("#{d}", .{crm});
                        result.operands_len = f.len();
                    }
                    return;
                },
                else => {},
            }
        }

        // MSR / MRS
        if (l == 1) {
            // MRS Xt, <sysreg>
            result.mnemonic = "mrs";
            var f = FmtBuf.init(&result.operands);
            f.append(xRegOrZr(rt));
            f.comma();
            appendSysReg(&f, op_1, crn, crm, op_2);
            result.operands_len = f.len();
            return;
        } else {
            // MSR <sysreg>, Xt
            result.mnemonic = "msr";
            var f = FmtBuf.init(&result.operands);
            appendSysReg(&f, op_1, crn, crm, op_2);
            f.comma();
            f.append(xRegOrZr(rt));
            result.operands_len = f.len();
            return;
        }
    }

    // Unconditional branch (register): BR, BLR, RET
    if (opc == 0b0000 and op2 == 0b11111 and op3 == 0b000000 and op4 == 0b00000) {
        // BR Xn
        result.mnemonic = "br";
        result.is_branch = true;
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rn));
        result.operands_len = f.len();
        return;
    }
    if (opc == 0b0001 and op2 == 0b11111 and op3 == 0b000000 and op4 == 0b00000) {
        // BLR Xn
        result.mnemonic = "blr";
        result.is_branch = true;
        result.is_call = true;
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rn));
        result.operands_len = f.len();
        return;
    }
    if (opc == 0b0010 and op2 == 0b11111 and op3 == 0b000000 and op4 == 0b00000) {
        // RET {Xn}
        result.mnemonic = "ret";
        result.is_branch = true;
        result.is_return = true;
        if (rn != 30) {
            var f = FmtBuf.init(&result.operands);
            f.append(xRegOrZr(rn));
            result.operands_len = f.len();
        }
        return;
    }

    // v7.13.0 B6c — ARMv8.3-A pointer-authenticated branches (arm64e).
    // Pre-fix every __auth_stub exit on /bin/sync, /bin/echo decoded as `udf`
    // because these encodings reuse the BR/BLR/RET space with op3!=0.
    // Conservative subset: BRAA/BRAB, BRAAZ/BRABZ, BLRAA/BLRAB, BLRAAZ/BLRABZ,
    // RETAA/RETAB. (PACIA/AUTIA/XPACI deferred to v7.14 per plan.)
    //
    // Encoding: opc selects branch class (0000=BR-Z, 0001=BLR-Z, 0010=RET-A,
    // 1000=BRAA/BRAB, 1001=BLRAA/BLRAB). op3 bits [11:10] select A vs B key
    // (op3=0b000010 → A, op3=0b000011 → B). For the *Z form (BRAAZ/BLRAAZ/...)
    // op4 (Rm) is ignored and conventionally encoded as 11111.
    if (opc == 0b1000 and op2 == 0b11111 and (op3 == 0b000010 or op3 == 0b000011)) {
        // BRAA Xn, Xm  /  BRAB Xn, Xm
        const rm: u5 = @truncate(op4);
        result.mnemonic = if (op3 == 0b000010) "braa" else "brab";
        result.is_branch = true;
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rn));
        f.comma();
        f.append(xRegOrZr(rm));
        result.operands_len = f.len();
        return;
    }
    if (opc == 0b1001 and op2 == 0b11111 and (op3 == 0b000010 or op3 == 0b000011)) {
        // BLRAA Xn, Xm  /  BLRAB Xn, Xm
        const rm: u5 = @truncate(op4);
        result.mnemonic = if (op3 == 0b000010) "blraa" else "blrab";
        result.is_branch = true;
        result.is_call = true;
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rn));
        f.comma();
        f.append(xRegOrZr(rm));
        result.operands_len = f.len();
        return;
    }
    if (opc == 0b0000 and op2 == 0b11111 and (op3 == 0b000010 or op3 == 0b000011) and op4 == 0b11111) {
        // BRAAZ Xn  /  BRABZ Xn
        result.mnemonic = if (op3 == 0b000010) "braaz" else "brabz";
        result.is_branch = true;
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rn));
        result.operands_len = f.len();
        return;
    }
    if (opc == 0b0001 and op2 == 0b11111 and (op3 == 0b000010 or op3 == 0b000011) and op4 == 0b11111) {
        // BLRAAZ Xn  /  BLRABZ Xn
        result.mnemonic = if (op3 == 0b000010) "blraaz" else "blrabz";
        result.is_branch = true;
        result.is_call = true;
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rn));
        result.operands_len = f.len();
        return;
    }
    if (opc == 0b0010 and op2 == 0b11111 and (op3 == 0b000010 or op3 == 0b000011) and rn == 0b11111 and op4 == 0b11111) {
        // RETAA  /  RETAB
        result.mnemonic = if (op3 == 0b000010) "retaa" else "retab";
        result.is_branch = true;
        result.is_return = true;
        return;
    }
}

fn barrierOption(crm: u4) []const u8 {
    return switch (crm) {
        0b0001 => "oshld",
        0b0010 => "oshst",
        0b0011 => "osh",
        0b0101 => "nshld",
        0b0110 => "nshst",
        0b0111 => "nsh",
        0b1001 => "ishld",
        0b1010 => "ishst",
        0b1011 => "ish",
        0b1101 => "ld",
        0b1110 => "st",
        0b1111 => "sy",
        else => "sy",
    };
}

fn appendSysReg(f: *FmtBuf, op1: u32, crn: u4, crm: u4, op2: u3) void {
    // Common system registers
    if (op1 == 3 and crn == 4 and crm == 2 and op2 == 0) {
        f.append("nzcv");
        return;
    }
    if (op1 == 3 and crn == 4 and crm == 2 and op2 == 1) {
        f.append("daif");
        return;
    }
    if (op1 == 3 and crn == 13 and crm == 0 and op2 == 2) {
        f.append("tpidr_el0");
        return;
    }
    if (op1 == 3 and crn == 4 and crm == 4 and op2 == 0) {
        f.append("fpcr");
        return;
    }
    if (op1 == 3 and crn == 4 and crm == 4 and op2 == 1) {
        f.append("fpsr");
        return;
    }
    // Generic encoding: S<op0>_<op1>_C<crn>_C<crm>_<op2>
    f.appendFmt("s3_{d}_c{d}_c{d}_{d}", .{ op1, crn, crm, op2 });
}

// ============================================================================
// Data Processing — Immediate
// bits [28:25] = 100x
// ============================================================================

fn decodeDPImmediate(insn: u32, address: u64, result: *DecodedInstruction) void {
    const op0 = bits(insn, 25, 23);

    switch (op0) {
        // 0b000: PC-rel addressing (ADR, ADRP)
        0b000, 0b001 => {
            decodePCRelAddr(insn, address, result);
        },
        // 0b010: Add/sub immediate
        0b010, 0b011 => {
            decodeAddSubImm(insn, result);
        },
        // 0b100: Logical immediate
        0b100 => {
            decodeLogicalImm(insn, result);
        },
        // 0b101: Move wide immediate
        0b101 => {
            decodeMoveWideImm(insn, result);
        },
        // 0b110: Bitfield
        0b110 => {
            decodeBitfield(insn, result);
        },
        // 0b111: Extract
        0b111 => {
            decodeExtract(insn, result);
        },
        else => {
            result.mnemonic = "udf";
        },
    }
}

fn decodePCRelAddr(insn: u32, address: u64, result: *DecodedInstruction) void {
    const op = bit(insn, 31);
    const immhi = bits(insn, 23, 5);
    const immlo = bits(insn, 30, 29);
    const rd: u5 = @truncate(bits(insn, 4, 0));
    const imm = (immhi << 2) | immlo;

    if (op == 0) {
        // ADR Xd, label
        const offset = signExtend(imm, 20);
        const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
        result.mnemonic = "adr";
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rd));
        f.comma();
        f.appendHex(target);
        result.operands_len = f.len();
    } else {
        // ADRP Xd, label (page-aligned)
        const offset = signExtend(@as(u64, imm) << 12, 32);
        const page = address & ~@as(u64, 0xFFF);
        const target = @as(u64, @bitCast(@as(i64, @bitCast(page)) +% offset));
        result.mnemonic = "adrp";
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rd));
        f.comma();
        f.appendHex(target);
        result.operands_len = f.len();
    }
}

fn decodeAddSubImm(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const op = bit(insn, 30);
    const s = bit(insn, 29);
    const sh = bit(insn, 22);
    const imm12 = bits(insn, 21, 10);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    const actual_imm: u64 = if (sh == 1) @as(u64, imm12) << 12 else @as(u64, imm12);

    // CMP is SUB with S=1 and Rd=ZR
    if (op == 1 and s == 1 and rd == 31) {
        result.mnemonic = "cmp";
        var f = FmtBuf.init(&result.operands);
        f.append(regNameSp(rn, sf));
        f.comma();
        f.appendFmt("#0x{x}", .{actual_imm});
        result.operands_len = f.len();
        return;
    }

    // CMN is ADD with S=1 and Rd=ZR
    if (op == 0 and s == 1 and rd == 31) {
        result.mnemonic = "cmn";
        var f = FmtBuf.init(&result.operands);
        f.append(regNameSp(rn, sf));
        f.comma();
        f.appendFmt("#0x{x}", .{actual_imm});
        result.operands_len = f.len();
        return;
    }

    // MOV (to/from SP) is ADD Rd, Rn, #0 when one is SP
    if (op == 0 and s == 0 and imm12 == 0 and (rd == 31 or rn == 31)) {
        result.mnemonic = "mov";
        var f = FmtBuf.init(&result.operands);
        f.append(regNameSp(rd, sf));
        f.comma();
        f.append(regNameSp(rn, sf));
        result.operands_len = f.len();
        return;
    }

    if (op == 0) {
        result.mnemonic = if (s == 1) "adds" else "add";
    } else {
        result.mnemonic = if (s == 1) "subs" else "sub";
    }

    var f = FmtBuf.init(&result.operands);
    if (s == 1) {
        f.append(regName(rd, sf));
    } else {
        f.append(regNameSp(rd, sf));
    }
    f.comma();
    f.append(regNameSp(rn, sf));
    f.comma();
    f.appendFmt("#0x{x}", .{actual_imm});
    result.operands_len = f.len();
}

fn decodeLogicalImm(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const opc = bits(insn, 30, 29);
    const n = bit(insn, 22);
    const immr: u6 = @truncate(bits(insn, 21, 16));
    const imms: u6 = @truncate(bits(insn, 15, 10));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    const imm_val = decodeBitmaskImm(n, imms, immr, sf);

    // TST is ANDS with Rd = ZR
    if (opc == 0b11 and rd == 31) {
        result.mnemonic = "tst";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rn, sf));
        f.comma();
        f.appendFmt("#0x{x}", .{imm_val});
        result.operands_len = f.len();
        return;
    }

    // MOV (bitmask immediate) is ORR with Rn=ZR
    if (opc == 0b01 and rn == 31) {
        result.mnemonic = "mov";
        var f = FmtBuf.init(&result.operands);
        f.append(regNameSp(rd, sf));
        f.comma();
        f.appendFmt("#0x{x}", .{imm_val});
        result.operands_len = f.len();
        return;
    }

    result.mnemonic = switch (opc) {
        0b00 => "and",
        0b01 => "orr",
        0b10 => "eor",
        0b11 => "ands",
        else => unreachable,
    };

    var f = FmtBuf.init(&result.operands);
    if (opc == 0b11) {
        f.append(regName(rd, sf));
    } else {
        f.append(regNameSp(rd, sf));
    }
    f.comma();
    f.append(regName(rn, sf));
    f.comma();
    f.appendFmt("#0x{x}", .{imm_val});
    result.operands_len = f.len();
}

fn decodeBitmaskImm(n: u1, imms_raw: u6, immr_raw: u6, sf: bool) u64 {
    const imms: u6 = imms_raw;
    const immr: u6 = immr_raw;
    const reg_size: u7 = if (sf) 64 else 32;

    // Determine element size
    var len: u6 = 0;
    if (n == 1) {
        len = 6;
    } else {
        // Find highest bit set in ~imms (within 6 bits)
        const not_imms: u6 = ~imms;
        if (not_imms & 0b100000 != 0) {
            len = 6;
        } else if (not_imms & 0b010000 != 0) {
            len = 5;
        } else if (not_imms & 0b001000 != 0) {
            len = 4;
        } else if (not_imms & 0b000100 != 0) {
            len = 3;
        } else if (not_imms & 0b000010 != 0) {
            len = 2;
        } else {
            len = 1;
        }
    }

    const esize: u7 = @as(u7, 1) << @as(u3, @truncate(len));
    const mask: u6 = @truncate(esize - 1);
    const s: u6 = imms & mask;
    const r: u6 = immr & mask;

    // Create the bitmask pattern for one element
    var welem: u64 = (@as(u64, 1) << @as(u6, s + 1)) - 1;

    // Rotate right by r
    if (r != 0) {
        const esize_trunc: u6 = @truncate(esize);
        if (r < esize_trunc) {
            welem = (welem >> @as(u6, r)) | (welem << @as(u6, esize_trunc - r));
            welem &= (@as(u64, 1) << @as(u6, esize_trunc)) - 1;
        }
    }

    // Replicate to fill register width
    var result: u64 = 0;
    var pos: u7 = 0;
    while (pos < reg_size) : (pos += esize) {
        result |= welem << @as(u6, @truncate(pos));
    }

    if (!sf) {
        result &= 0xFFFFFFFF;
    }

    return result;
}

fn decodeMoveWideImm(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const opc = bits(insn, 30, 29);
    const hw: u2 = @truncate(bits(insn, 22, 21));
    const imm16 = bits(insn, 20, 5);
    const rd: u5 = @truncate(bits(insn, 4, 0));
    const shift_amount: u6 = @as(u6, hw) * 16;

    switch (opc) {
        0b00 => {
            // MOVN — inverted immediate
            const shifted: u64 = @as(u64, imm16) << shift_amount;
            const value = ~shifted;
            const final_val = if (sf) value else value & 0xFFFFFFFF;
            // Alias: MOV if preferred
            result.mnemonic = "mov";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            f.appendFmt("#0x{x}", .{final_val});
            result.operands_len = f.len();
        },
        0b10 => {
            // MOVZ — zero and move
            if (shift_amount == 0 or imm16 == 0) {
                // Prefer MOV alias
                result.mnemonic = "mov";
            } else {
                result.mnemonic = "movz";
            }
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            const shifted: u64 = @as(u64, imm16) << shift_amount;
            if (result.mnemonic.ptr == "mov".ptr or std.mem.eql(u8, result.mnemonic, "mov")) {
                f.appendFmt("#0x{x}", .{shifted});
            } else {
                f.appendFmt("#0x{x}", .{@as(u64, imm16)});
                if (shift_amount != 0) {
                    f.comma();
                    f.appendFmt("lsl #{d}", .{shift_amount});
                }
            }
            result.operands_len = f.len();
        },
        0b11 => {
            // MOVK — keep and move
            result.mnemonic = "movk";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            f.appendFmt("#0x{x}", .{@as(u64, imm16)});
            if (shift_amount != 0) {
                f.comma();
                f.appendFmt("lsl #{d}", .{shift_amount});
            }
            result.operands_len = f.len();
        },
        else => {
            result.mnemonic = "udf";
        },
    }
}

fn decodeBitfield(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const opc = bits(insn, 30, 29);
    const immr: u6 = @truncate(bits(insn, 21, 16));
    const imms: u6 = @truncate(bits(insn, 15, 10));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));
    const reg_size: u6 = if (sf) 63 else 31;

    switch (opc) {
        0b00 => {
            // SBFM — also encodes ASR, SXTB, SXTH, SXTW, SBFX, SBFIZ
            if (imms == reg_size) {
                result.mnemonic = "asr";
                var f = FmtBuf.init(&result.operands);
                f.append(regName(rd, sf));
                f.comma();
                f.append(regName(rn, sf));
                f.comma();
                f.appendFmt("#{d}", .{immr});
                result.operands_len = f.len();
            } else if (immr == 0 and imms == 7) {
                result.mnemonic = "sxtb";
                var f = FmtBuf.init(&result.operands);
                f.append(regName(rd, sf));
                f.comma();
                f.append(wRegOrZr(rn));
                result.operands_len = f.len();
            } else if (immr == 0 and imms == 15) {
                result.mnemonic = "sxth";
                var f = FmtBuf.init(&result.operands);
                f.append(regName(rd, sf));
                f.comma();
                f.append(wRegOrZr(rn));
                result.operands_len = f.len();
            } else if (sf and immr == 0 and imms == 31) {
                result.mnemonic = "sxtw";
                var f = FmtBuf.init(&result.operands);
                f.append(xRegOrZr(rd));
                f.comma();
                f.append(wRegOrZr(rn));
                result.operands_len = f.len();
            } else {
                result.mnemonic = "sbfm";
                var f = FmtBuf.init(&result.operands);
                f.append(regName(rd, sf));
                f.comma();
                f.append(regName(rn, sf));
                f.comma();
                f.appendFmt("#{d}", .{immr});
                f.comma();
                f.appendFmt("#{d}", .{imms});
                result.operands_len = f.len();
            }
        },
        0b01 => {
            // BFM — also encodes BFI, BFXIL
            result.mnemonic = "bfm";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            f.append(regName(rn, sf));
            f.comma();
            f.appendFmt("#{d}", .{immr});
            f.comma();
            f.appendFmt("#{d}", .{imms});
            result.operands_len = f.len();
        },
        0b10 => {
            // UBFM — also encodes LSL, LSR, UXTB, UXTH, UBFX, UBFIZ
            if (imms == reg_size) {
                result.mnemonic = "lsr";
                var f = FmtBuf.init(&result.operands);
                f.append(regName(rd, sf));
                f.comma();
                f.append(regName(rn, sf));
                f.comma();
                f.appendFmt("#{d}", .{immr});
                result.operands_len = f.len();
            } else if (imms + 1 == immr) {
                result.mnemonic = "lsl";
                var f = FmtBuf.init(&result.operands);
                f.append(regName(rd, sf));
                f.comma();
                f.append(regName(rn, sf));
                f.comma();
                f.appendFmt("#{d}", .{reg_size - imms});
                result.operands_len = f.len();
            } else if (immr == 0 and imms == 7) {
                result.mnemonic = "uxtb";
                var f = FmtBuf.init(&result.operands);
                f.append(wRegOrZr(rd));
                f.comma();
                f.append(wRegOrZr(rn));
                result.operands_len = f.len();
            } else if (immr == 0 and imms == 15) {
                result.mnemonic = "uxth";
                var f = FmtBuf.init(&result.operands);
                f.append(wRegOrZr(rd));
                f.comma();
                f.append(wRegOrZr(rn));
                result.operands_len = f.len();
            } else {
                result.mnemonic = "ubfm";
                var f = FmtBuf.init(&result.operands);
                f.append(regName(rd, sf));
                f.comma();
                f.append(regName(rn, sf));
                f.comma();
                f.appendFmt("#{d}", .{immr});
                f.comma();
                f.appendFmt("#{d}", .{imms});
                result.operands_len = f.len();
            }
        },
        else => {
            result.mnemonic = "udf";
        },
    }
}

fn decodeExtract(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const imms: u6 = @truncate(bits(insn, 15, 10));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    // ROR alias: EXTR Rd, Rn, Rn, #imms when Rn == Rm
    if (rn == rm) {
        result.mnemonic = "ror";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd, sf));
        f.comma();
        f.append(regName(rn, sf));
        f.comma();
        f.appendFmt("#{d}", .{imms});
        result.operands_len = f.len();
        return;
    }

    result.mnemonic = "extr";
    var f = FmtBuf.init(&result.operands);
    f.append(regName(rd, sf));
    f.comma();
    f.append(regName(rn, sf));
    f.comma();
    f.append(regName(rm, sf));
    f.comma();
    f.appendFmt("#{d}", .{imms});
    result.operands_len = f.len();
}

// ============================================================================
// Loads and Stores
// bits [28:25] = x1x0
// ============================================================================

fn decodeLoadStore(insn: u32, _: u64, result: *DecodedInstruction) void {
    // ARM64 load/store dispatch.
    // The load/store encoding group (bits[28:25] = x1x0) is sub-classified by
    // bits [29:28] and [26] and [24:23].
    //
    // Key sub-groups:
    //   Load/store pair:            bit[29]=1, bit[28]=0, bit[26]=0
    //   Load/store reg (unsigned):  bit[29]=1, bit[28]=1, bit[26]=0, bit[24]=1
    //   Load/store reg (imm9):      bit[29]=1, bit[28]=1, bit[26]=0, bit[24]=0, bit[21]=0
    //   Load/store reg (register):  bit[29]=1, bit[28]=1, bit[26]=0, bit[24]=0, bit[21]=1
    //   Load/store SIMD pair:       bit[29]=1, bit[28]=0, bit[26]=1
    //   Other sub-groups exist but are less common

    const b29 = bit(insn, 29);
    const b28 = bit(insn, 28);

    // Load/store pair: x0 101 V 0xx imm7 Rt2 Rn Rt
    // bits [29:28] = 10 (i.e., bit29=1, bit28=0)
    if (b29 == 1 and b28 == 0) {
        decodeLoadStorePair(insn, result);
        return;
    }

    // Load/store register (various forms): bits [29:28] = 11
    if (b29 == 1 and b28 == 1) {
        if (bit(insn, 24) == 1) {
            // Unsigned immediate offset
            decodeLoadStoreUnsignedImm(insn, result);
        } else {
            // imm9 or register offset
            if (bit(insn, 21) == 0) {
                decodeLoadStoreRegImm9(insn, result);
            } else {
                decodeLoadStoreRegOff(insn, result);
            }
        }
        return;
    }

    // bits [29:28] = 0x: other load/store encodings (atomic, exclusive, etc.)
    // Try to handle based on bit[24]
    if (bit(insn, 24) == 1) {
        decodeLoadStoreUnsignedImm(insn, result);
        return;
    }

    result.mnemonic = "ldr/str";
}

fn loadStoreMnemonic(size: u2, v: u1, opc: u2) []const u8 {
    if (v == 0) {
        return switch (size) {
            0b00 => switch (opc) {
                0b00 => "strb",
                0b01 => "ldrb",
                0b10 => "ldrsb",
                0b11 => "ldrsb",
            },
            0b01 => switch (opc) {
                0b00 => "strh",
                0b01 => "ldrh",
                0b10 => "ldrsh",
                0b11 => "ldrsh",
            },
            0b10 => switch (opc) {
                0b00 => "str",
                0b01 => "ldr",
                0b10 => "ldrsw",
                0b11 => "udf",
            },
            0b11 => switch (opc) {
                0b00 => "str",
                0b01 => "ldr",
                else => "udf",
            },
        };
    }
    // SIMD/FP load/store (simplified)
    return switch (opc) {
        0b00 => "str",
        0b01 => "ldr",
        else => "ldr",
    };
}

fn decodeLoadStoreUnsignedImm(insn: u32, result: *DecodedInstruction) void {
    const size: u2 = @truncate(bits(insn, 31, 30));
    const v: u1 = @truncate(bits(insn, 26, 26));
    const opc: u2 = @truncate(bits(insn, 23, 22));
    const imm12 = bits(insn, 21, 10);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rt: u5 = @truncate(bits(insn, 4, 0));

    const scale: u3 = @as(u3, size);
    const offset: u64 = @as(u64, imm12) << scale;

    result.mnemonic = loadStoreMnemonic(size, v, opc);
    // v7.12 W8(b): UDF takes no memory operand. If loadStoreMnemonic returned
    // "udf" for an unallocated load/store encoding, leave operands empty so we
    // don't render absurd `udf x8, [x8, w9, lsl #0]` syntax.
    if (std.mem.eql(u8, result.mnemonic, "udf")) {
        result.operands_len = 0;
        return;
    }

    // Determine register width for the data register
    const sf = (size == 0b11) or (opc >= 0b10 and size == 0b10);

    var f = FmtBuf.init(&result.operands);
    if (v == 0) {
        f.append(regName(rt, sf));
    } else {
        // SIMD register
        const simd_prefix: []const u8 = switch (size) {
            0b00 => "b",
            0b01 => "h",
            0b10 => "s",
            0b11 => "d",
        };
        f.append(simd_prefix);
        f.appendFmt("{d}", .{rt});
    }
    f.comma();
    f.append("[");
    f.append(regNameSp(rn, true));
    if (offset != 0) {
        f.appendFmt(", #0x{x}", .{offset});
    }
    f.append("]");
    result.operands_len = f.len();
}

fn decodeLoadStoreRegImm9(insn: u32, result: *DecodedInstruction) void {
    const size: u2 = @truncate(bits(insn, 31, 30));
    const v: u1 = @truncate(bits(insn, 26, 26));
    const opc: u2 = @truncate(bits(insn, 23, 22));
    const imm9 = bits(insn, 20, 12);
    const idx_mode = bits(insn, 11, 10);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rt: u5 = @truncate(bits(insn, 4, 0));

    const offset = signExtend(imm9, 8);

    result.mnemonic = loadStoreMnemonic(size, v, opc);
    if (std.mem.eql(u8, result.mnemonic, "udf")) {
        result.operands_len = 0;
        return;
    }

    const sf = (size == 0b11) or (opc >= 0b10 and size == 0b10);

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rt, sf));
    f.comma();

    switch (idx_mode) {
        0b00 => {
            // Unscaled immediate
            f.append("[");
            f.append(regNameSp(rn, true));
            if (offset != 0) {
                f.append(", #");
                f.appendSignedHex(offset);
            }
            f.append("]");
        },
        0b01 => {
            // Post-index
            f.append("[");
            f.append(regNameSp(rn, true));
            f.append("], #");
            f.appendSignedHex(offset);
        },
        0b11 => {
            // Pre-index
            f.append("[");
            f.append(regNameSp(rn, true));
            f.append(", #");
            f.appendSignedHex(offset);
            f.append("]!");
        },
        0b10 => {
            // Unprivileged — treat like unscaled
            f.append("[");
            f.append(regNameSp(rn, true));
            if (offset != 0) {
                f.append(", #");
                f.appendSignedHex(offset);
            }
            f.append("]");
        },
        else => {
            f.append("[");
            f.append(regNameSp(rn, true));
            f.append("]");
        },
    }
    result.operands_len = f.len();
}

fn decodeLoadStoreRegOff(insn: u32, result: *DecodedInstruction) void {
    const size: u2 = @truncate(bits(insn, 31, 30));
    const v: u1 = @truncate(bits(insn, 26, 26));
    const opc: u2 = @truncate(bits(insn, 23, 22));
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const option: u3 = @truncate(bits(insn, 15, 13));
    const s_bit = bit(insn, 12);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rt: u5 = @truncate(bits(insn, 4, 0));

    result.mnemonic = loadStoreMnemonic(size, v, opc);
    if (std.mem.eql(u8, result.mnemonic, "udf")) {
        result.operands_len = 0;
        return;
    }

    const sf = (size == 0b11) or (opc >= 0b10 and size == 0b10);
    const rm_is_64 = (option & 0b001) == 1;

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rt, sf));
    f.comma();
    f.append("[");
    f.append(regNameSp(rn, true));
    f.comma();
    if (rm_is_64) {
        f.append(xRegOrZr(rm));
    } else {
        f.append(wRegOrZr(rm));
    }

    // Extend/shift
    const ext_name: []const u8 = switch (option) {
        0b010 => "uxtw",
        0b011 => "lsl",
        0b110 => "sxtw",
        0b111 => "sxtx",
        else => "lsl",
    };
    if (option != 0b011 or s_bit != 0) {
        f.comma();
        f.append(ext_name);
        if (s_bit == 1) {
            f.appendFmt(" #{d}", .{@as(u32, size)});
        } else if (option != 0b011) {
            f.append(" #0");
        }
    }
    f.append("]");
    result.operands_len = f.len();
}

fn decodeLoadStorePair(insn: u32, result: *DecodedInstruction) void {
    const opc: u2 = @truncate(bits(insn, 31, 30));
    const v = bit(insn, 26);
    const idx = bits(insn, 24, 23);
    const l = bit(insn, 22);
    const imm7 = bits(insn, 21, 15);
    const rt2: u5 = @truncate(bits(insn, 14, 10));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rt: u5 = @truncate(bits(insn, 4, 0));

    const sf = opc == 0b10;
    const scale: u3 = if (sf) 3 else 2;
    const offset = signExtend(imm7, 6) * (@as(i64, 1) << scale);

    if (v == 0) {
        if (l == 1) {
            result.mnemonic = if (opc == 0b01) "ldpsw" else "ldp";
        } else {
            result.mnemonic = "stp";
        }
    } else {
        result.mnemonic = if (l == 1) "ldp" else "stp";
    }

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rt, sf));
    f.comma();
    f.append(regName(rt2, sf));
    f.comma();

    switch (idx) {
        0b01 => {
            // Post-index
            f.append("[");
            f.append(regNameSp(rn, true));
            f.append("], #");
            f.appendSignedHex(offset);
        },
        0b10 => {
            // Signed offset
            f.append("[");
            f.append(regNameSp(rn, true));
            if (offset != 0) {
                f.append(", #");
                f.appendSignedHex(offset);
            }
            f.append("]");
        },
        0b11 => {
            // Pre-index
            f.append("[");
            f.append(regNameSp(rn, true));
            f.append(", #");
            f.appendSignedHex(offset);
            f.append("]!");
        },
        else => {
            f.append("[");
            f.append(regNameSp(rn, true));
            f.append("]");
        },
    }
    result.operands_len = f.len();
}

// ============================================================================
// Data Processing — Register
// bits [28:25] = x101
// ============================================================================

fn decodeDPRegister(insn: u32, _: u64, result: *DecodedInstruction) void {
    const op1 = bit(insn, 28);
    const op2 = bits(insn, 24, 21);

    if (op1 == 0) {
        if (bits(insn, 24, 24) == 0) {
            // Logical (shifted register)
            decodeDPLogicalShifted(insn, result);
        } else {
            // Add/sub (shifted/extended register)
            if (bit(insn, 21) == 0) {
                decodeDPAddSubShifted(insn, result);
            } else {
                decodeDPAddSubExtended(insn, result);
            }
        }
    } else {
        // op1 == 1
        if (op2 == 0b0110) {
            // Data processing (1 source) or (2 source)
            if (bit(insn, 30) == 0) {
                decodeDPTwoSource(insn, result);
            } else {
                decodeDPOneSource(insn, result);
            }
        } else if (op2 == 0b0000 and bits(insn, 15, 11) == 0b00000) {
            // Add/sub with carry
            decodeDPAddSubCarry(insn, result);
        } else if (op2 == 0b0000 and bits(insn, 15, 10) == 0b000001) {
            // Rotate right into flags (not common, stub)
            result.mnemonic = "rmif";
        } else if ((op2 & 0b1000) == 0b1000) {
            // Data processing (3 source)
            decodeDPThreeSource(insn, result);
        } else if (op2 == 0b0010) {
            // Conditional compare (register/immediate)
            decodeDPCondCompare(insn, result);
        } else if (op2 == 0b0100) {
            // Conditional select
            decodeDPCondSelect(insn, result);
        } else {
            result.mnemonic = "dp_reg";
        }
    }
}

fn decodeDPLogicalShifted(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const opc = bits(insn, 30, 29);
    const shift: u2 = @truncate(bits(insn, 23, 22));
    const n = bit(insn, 21);
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const imm6: u6 = @truncate(bits(insn, 15, 10));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    // MOV alias: ORR Rd, ZR, Rm when no shift
    if (opc == 0b01 and n == 0 and imm6 == 0 and rn == 31) {
        result.mnemonic = "mov";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd, sf));
        f.comma();
        f.append(regName(rm, sf));
        result.operands_len = f.len();
        return;
    }

    // MVN alias: ORN Rd, ZR, Rm
    if (opc == 0b01 and n == 1 and rn == 31) {
        result.mnemonic = "mvn";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd, sf));
        f.comma();
        f.append(regName(rm, sf));
        if (imm6 != 0) {
            f.comma();
            f.append(shift_names[shift]);
            f.appendFmt(" #{d}", .{imm6});
        }
        result.operands_len = f.len();
        return;
    }

    // TST alias: ANDS Rd=ZR, Rn, Rm
    if (opc == 0b11 and n == 0 and rd == 31) {
        result.mnemonic = "tst";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rn, sf));
        f.comma();
        f.append(regName(rm, sf));
        if (imm6 != 0) {
            f.comma();
            f.append(shift_names[shift]);
            f.appendFmt(" #{d}", .{imm6});
        }
        result.operands_len = f.len();
        return;
    }

    if (n == 0) {
        result.mnemonic = switch (opc) {
            0b00 => "and",
            0b01 => "orr",
            0b10 => "eor",
            0b11 => "ands",
            else => unreachable,
        };
    } else {
        result.mnemonic = switch (opc) {
            0b00 => "bic",
            0b01 => "orn",
            0b10 => "eon",
            0b11 => "bics",
            else => unreachable,
        };
    }

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rd, sf));
    f.comma();
    f.append(regName(rn, sf));
    f.comma();
    f.append(regName(rm, sf));
    if (imm6 != 0) {
        f.comma();
        f.append(shift_names[shift]);
        f.appendFmt(" #{d}", .{imm6});
    }
    result.operands_len = f.len();
}

fn decodeDPAddSubShifted(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const op = bit(insn, 30);
    const s = bit(insn, 29);
    const shift: u2 = @truncate(bits(insn, 23, 22));
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const imm6: u6 = @truncate(bits(insn, 15, 10));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    // CMP alias: SUBS Rd=ZR, Rn, Rm{, shift}
    if (op == 1 and s == 1 and rd == 31) {
        result.mnemonic = "cmp";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rn, sf));
        f.comma();
        f.append(regName(rm, sf));
        if (imm6 != 0) {
            f.comma();
            f.append(shift_names[shift]);
            f.appendFmt(" #{d}", .{imm6});
        }
        result.operands_len = f.len();
        return;
    }

    // CMN alias: ADDS Rd=ZR, Rn, Rm{, shift}
    if (op == 0 and s == 1 and rd == 31) {
        result.mnemonic = "cmn";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rn, sf));
        f.comma();
        f.append(regName(rm, sf));
        if (imm6 != 0) {
            f.comma();
            f.append(shift_names[shift]);
            f.appendFmt(" #{d}", .{imm6});
        }
        result.operands_len = f.len();
        return;
    }

    // NEG alias: SUB Rd, ZR, Rm
    if (op == 1 and s == 0 and rn == 31) {
        result.mnemonic = "neg";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd, sf));
        f.comma();
        f.append(regName(rm, sf));
        if (imm6 != 0) {
            f.comma();
            f.append(shift_names[shift]);
            f.appendFmt(" #{d}", .{imm6});
        }
        result.operands_len = f.len();
        return;
    }

    if (op == 0) {
        result.mnemonic = if (s == 1) "adds" else "add";
    } else {
        result.mnemonic = if (s == 1) "subs" else "sub";
    }

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rd, sf));
    f.comma();
    f.append(regName(rn, sf));
    f.comma();
    f.append(regName(rm, sf));
    if (imm6 != 0) {
        f.comma();
        f.append(shift_names[shift]);
        f.appendFmt(" #{d}", .{imm6});
    }
    result.operands_len = f.len();
}

fn decodeDPAddSubExtended(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const op = bit(insn, 30);
    const s = bit(insn, 29);
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const option: u3 = @truncate(bits(insn, 15, 13));
    const imm3: u3 = @truncate(bits(insn, 12, 10));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    // CMP alias
    if (op == 1 and s == 1 and rd == 31) {
        result.mnemonic = "cmp";
        var f = FmtBuf.init(&result.operands);
        f.append(regNameSp(rn, sf));
        f.comma();
        appendExtendedReg(&f, rm, option, imm3, sf);
        result.operands_len = f.len();
        return;
    }

    if (op == 0) {
        result.mnemonic = if (s == 1) "adds" else "add";
    } else {
        result.mnemonic = if (s == 1) "subs" else "sub";
    }

    var f = FmtBuf.init(&result.operands);
    if (s == 1) {
        f.append(regName(rd, sf));
    } else {
        f.append(regNameSp(rd, sf));
    }
    f.comma();
    f.append(regNameSp(rn, sf));
    f.comma();
    appendExtendedReg(&f, rm, option, imm3, sf);
    result.operands_len = f.len();
}

fn appendExtendedReg(f: *FmtBuf, rm: u5, option: u3, imm3: u3, sf: bool) void {
    const ext_names = [8][]const u8{
        "uxtb", "uxth", "uxtw", "uxtx",
        "sxtb", "sxth", "sxtw", "sxtx",
    };
    const rm_is_w = (option & 0b011) != 0b011;
    if (rm_is_w) {
        f.append(wRegOrZr(rm));
    } else {
        f.append(xRegOrZr(rm));
    }
    // LSL alias when option == 01x (W) or 011 (X) and shift == 0
    if ((sf and option == 0b011) or (!sf and option == 0b010)) {
        if (imm3 != 0) {
            f.append(", lsl #");
            f.appendFmt("{d}", .{imm3});
        }
    } else {
        f.comma();
        f.append(ext_names[option]);
        if (imm3 != 0) {
            f.appendFmt(" #{d}", .{imm3});
        }
    }
}

fn decodeDPTwoSource(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const opcode = bits(insn, 15, 10);
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    result.mnemonic = switch (opcode) {
        0b000010 => "udiv",
        0b000011 => "sdiv",
        0b001000 => "lslv",
        0b001001 => "lsrv",
        0b001010 => "asrv",
        0b001011 => "rorv",
        else => "dp2src",
    };

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rd, sf));
    f.comma();
    f.append(regName(rn, sf));
    f.comma();
    f.append(regName(rm, sf));
    result.operands_len = f.len();
}

fn decodeDPOneSource(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const opcode = bits(insn, 15, 10);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    result.mnemonic = switch (opcode) {
        0b000000 => "rbit",
        0b000001 => "rev16",
        0b000010 => if (sf) "rev32" else "rev",
        0b000011 => "rev",
        0b000100 => "clz",
        0b000101 => "cls",
        else => "dp1src",
    };

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rd, sf));
    f.comma();
    f.append(regName(rn, sf));
    result.operands_len = f.len();
}

fn decodeDPAddSubCarry(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const op = bit(insn, 30);
    const s = bit(insn, 29);
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    if (op == 0) {
        result.mnemonic = if (s == 1) "adcs" else "adc";
    } else {
        // NGC alias: SBC/SBCS with Rn=ZR
        if (rn == 31) {
            result.mnemonic = if (s == 1) "ngcs" else "ngc";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            f.append(regName(rm, sf));
            result.operands_len = f.len();
            return;
        }
        result.mnemonic = if (s == 1) "sbcs" else "sbc";
    }

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rd, sf));
    f.comma();
    f.append(regName(rn, sf));
    f.comma();
    f.append(regName(rm, sf));
    result.operands_len = f.len();
}

fn decodeDPCondCompare(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const op = bit(insn, 30);
    const o3 = bit(insn, 4);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const nzcv: u4 = @truncate(bits(insn, 3, 0));
    const cond: u4 = @truncate(bits(insn, 15, 12));

    if (o3 == 0) {
        // Conditional compare (register)
        const rm: u5 = @truncate(bits(insn, 20, 16));
        result.mnemonic = if (op == 0) "ccmn" else "ccmp";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rn, sf));
        f.comma();
        f.append(regName(rm, sf));
        f.comma();
        f.appendFmt("#{d}", .{nzcv});
        f.comma();
        f.append(condition_codes[cond]);
        result.operands_len = f.len();
    } else {
        // Conditional compare (immediate)
        const imm5 = bits(insn, 20, 16);
        result.mnemonic = if (op == 0) "ccmn" else "ccmp";
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rn, sf));
        f.comma();
        f.appendFmt("#{d}", .{imm5});
        f.comma();
        f.appendFmt("#{d}", .{nzcv});
        f.comma();
        f.append(condition_codes[cond]);
        result.operands_len = f.len();
    }
}

fn decodeDPCondSelect(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const op = bit(insn, 30);
    const op2 = bits(insn, 11, 10);
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const cond: u4 = @truncate(bits(insn, 15, 12));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    if (op == 0 and op2 == 0b00) {
        // CSEL
        result.mnemonic = "csel";
    } else if (op == 0 and op2 == 0b01) {
        // CSINC (with CSET/CINC aliases)
        if (rn == 31 and rm == 31) {
            result.mnemonic = "cset";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            // Invert condition
            f.append(condition_codes[cond ^ 1]);
            result.operands_len = f.len();
            return;
        }
        if (rn == rm and rn != 31) {
            result.mnemonic = "cinc";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            f.append(regName(rn, sf));
            f.comma();
            f.append(condition_codes[cond ^ 1]);
            result.operands_len = f.len();
            return;
        }
        result.mnemonic = "csinc";
    } else if (op == 1 and op2 == 0b00) {
        // CSINV (with CSETM alias)
        if (rn == 31 and rm == 31) {
            result.mnemonic = "csetm";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            f.append(condition_codes[cond ^ 1]);
            result.operands_len = f.len();
            return;
        }
        if (rn == rm and rn != 31) {
            result.mnemonic = "cinv";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            f.append(regName(rn, sf));
            f.comma();
            f.append(condition_codes[cond ^ 1]);
            result.operands_len = f.len();
            return;
        }
        result.mnemonic = "csinv";
    } else if (op == 1 and op2 == 0b01) {
        // CSNEG (with CNEG alias)
        if (rn == rm and rn != 31) {
            result.mnemonic = "cneg";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rd, sf));
            f.comma();
            f.append(regName(rn, sf));
            f.comma();
            f.append(condition_codes[cond ^ 1]);
            result.operands_len = f.len();
            return;
        }
        result.mnemonic = "csneg";
    } else {
        result.mnemonic = "csel";
    }

    var f = FmtBuf.init(&result.operands);
    f.append(regName(rd, sf));
    f.comma();
    f.append(regName(rn, sf));
    f.comma();
    f.append(regName(rm, sf));
    f.comma();
    f.append(condition_codes[cond]);
    result.operands_len = f.len();
}

fn decodeDPThreeSource(insn: u32, result: *DecodedInstruction) void {
    const sf = bit(insn, 31) == 1;
    const op31 = bits(insn, 23, 21);
    const o0 = bit(insn, 15);
    const rm: u5 = @truncate(bits(insn, 20, 16));
    const ra: u5 = @truncate(bits(insn, 14, 10));
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const rd: u5 = @truncate(bits(insn, 4, 0));

    if (sf) {
        // 64-bit
        if (op31 == 0b000 and o0 == 0) {
            // MADD (with MUL alias when Ra=ZR)
            if (ra == 31) {
                result.mnemonic = "mul";
                var f = FmtBuf.init(&result.operands);
                f.append(xRegOrZr(rd));
                f.comma();
                f.append(xRegOrZr(rn));
                f.comma();
                f.append(xRegOrZr(rm));
                result.operands_len = f.len();
                return;
            }
            result.mnemonic = "madd";
        } else if (op31 == 0b000 and o0 == 1) {
            if (ra == 31) {
                result.mnemonic = "mneg";
                var f = FmtBuf.init(&result.operands);
                f.append(xRegOrZr(rd));
                f.comma();
                f.append(xRegOrZr(rn));
                f.comma();
                f.append(xRegOrZr(rm));
                result.operands_len = f.len();
                return;
            }
            result.mnemonic = "msub";
        } else if (op31 == 0b001 and o0 == 0) {
            if (ra == 31) {
                result.mnemonic = "smull";
                var f = FmtBuf.init(&result.operands);
                f.append(xRegOrZr(rd));
                f.comma();
                f.append(wRegOrZr(rn));
                f.comma();
                f.append(wRegOrZr(rm));
                result.operands_len = f.len();
                return;
            }
            result.mnemonic = "smaddl";
        } else if (op31 == 0b010 and o0 == 0) {
            result.mnemonic = "smulh";
            var f = FmtBuf.init(&result.operands);
            f.append(xRegOrZr(rd));
            f.comma();
            f.append(xRegOrZr(rn));
            f.comma();
            f.append(xRegOrZr(rm));
            result.operands_len = f.len();
            return;
        } else if (op31 == 0b101 and o0 == 0) {
            if (ra == 31) {
                result.mnemonic = "umull";
                var f = FmtBuf.init(&result.operands);
                f.append(xRegOrZr(rd));
                f.comma();
                f.append(wRegOrZr(rn));
                f.comma();
                f.append(wRegOrZr(rm));
                result.operands_len = f.len();
                return;
            }
            result.mnemonic = "umaddl";
        } else if (op31 == 0b110 and o0 == 0) {
            result.mnemonic = "umulh";
            var f = FmtBuf.init(&result.operands);
            f.append(xRegOrZr(rd));
            f.comma();
            f.append(xRegOrZr(rn));
            f.comma();
            f.append(xRegOrZr(rm));
            result.operands_len = f.len();
            return;
        } else {
            result.mnemonic = "dp3src";
        }
    } else {
        // 32-bit
        if (op31 == 0b000 and o0 == 0) {
            if (ra == 31) {
                result.mnemonic = "mul";
                var f = FmtBuf.init(&result.operands);
                f.append(wRegOrZr(rd));
                f.comma();
                f.append(wRegOrZr(rn));
                f.comma();
                f.append(wRegOrZr(rm));
                result.operands_len = f.len();
                return;
            }
            result.mnemonic = "madd";
        } else if (op31 == 0b000 and o0 == 1) {
            if (ra == 31) {
                result.mnemonic = "mneg";
                var f = FmtBuf.init(&result.operands);
                f.append(wRegOrZr(rd));
                f.comma();
                f.append(wRegOrZr(rn));
                f.comma();
                f.append(wRegOrZr(rm));
                result.operands_len = f.len();
                return;
            }
            result.mnemonic = "msub";
        } else {
            result.mnemonic = "dp3src";
        }
    }

    // Generic 4-operand format for non-aliased forms
    if (result.operands_len == 0) {
        var f = FmtBuf.init(&result.operands);
        f.append(regName(rd, sf));
        f.comma();
        f.append(regName(rn, sf));
        f.comma();
        f.append(regName(rm, sf));
        f.comma();
        f.append(regName(ra, sf));
        result.operands_len = f.len();
    }
}

// ============================================================================
// Public API: decode a stream of instructions
// ============================================================================

pub fn decodeInstruction(raw: []const u8, address: u64) types.Instruction {
    const decoded = decode(raw, address);
    // Copy operands into the Instruction's owned buffer so they survive
    // after the decoded stack local goes out of scope.
    var inst = types.Instruction{
        .address = address,
        .bytes = raw[0..@min(raw.len, 4)],
        .mnemonic = decoded.mnemonic,
        .operands = &.{},
        .size = 4,
    };
    const ops = decoded.getOperands();
    const len: u8 = @intCast(@min(ops.len, 64));
    @memcpy(inst.operands_buf[0..len], ops[0..len]);
    inst.operands_len = len;
    inst.operands = inst.operands_buf[0..len];
    return inst;
}

// ============================================================================
// Tests
// ============================================================================

test "decode B (unconditional branch)" {
    // B #0x100 from address 0x1000
    // Encoding: 0b000101 | imm26
    // imm26 = 0x100 >> 2 = 0x40
    const insn = [4]u8{ 0x40, 0x00, 0x00, 0x14 }; // B #0x100
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("b", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(!result.is_call);
    try std.testing.expectEqual(@as(?u64, 0x1100), result.branch_target);
}

test "decode BL (branch with link)" {
    // BL #0x100 from address 0x1000
    const insn = [4]u8{ 0x40, 0x00, 0x00, 0x94 }; // BL #0x100
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("bl", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_call);
    try std.testing.expectEqual(@as(?u64, 0x1100), result.branch_target);
}

test "decode RET" {
    // RET (x30 implied)
    const insn = [4]u8{ 0xc0, 0x03, 0x5f, 0xd6 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("ret", result.mnemonic);
    try std.testing.expect(result.is_return);
}

test "decode B.EQ" {
    // B.EQ #0x20 from 0x1000
    // 01010100 imm19:00000 0:cond
    // imm19 = 0x20 >> 2 = 8
    const insn = [4]u8{ 0x00, 0x01, 0x00, 0x54 }; // b.eq #+0x20
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("b.eq", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    try std.testing.expectEqual(@as(?u64, 0x1020), result.branch_target);
}

test "decode CBZ" {
    // CBZ x0, #0x10 from 0x1000
    // 1 011010 0 imm19 Rt
    // imm19 = 0x10 >> 2 = 4
    const insn = [4]u8{ 0x80, 0x00, 0x00, 0xb4 }; // cbz x0, #+0x10
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("cbz", result.mnemonic);
    try std.testing.expect(result.is_conditional_branch);
}

test "decode ADD immediate" {
    // ADD x1, x2, #0x10
    // sf=1, op=0, S=0, 10 shift=0 imm12=0x10 Rn=x2 Rd=x1
    const insn = [4]u8{ 0x41, 0x40, 0x00, 0x91 }; // add x1, x2, #0x10
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("add", result.mnemonic);
}

test "decode MOV register" {
    // MOV x0, x1 is ORR x0, xzr, x1
    // sf=1, opc=01, shift=00, N=0, Rm=x1, imm6=0, Rn=xzr(31), Rd=x0
    const insn = [4]u8{ 0xe0, 0x03, 0x01, 0xaa }; // mov x0, x1
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("mov", result.mnemonic);
}

test "decode STP pre-index" {
    // STP x29, x30, [sp, #-0x10]!
    const insn = [4]u8{ 0xfd, 0x7b, 0xbf, 0xa9 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("stp", result.mnemonic);
}

test "decode LDR unsigned offset" {
    // LDR x0, [x1, #8]
    const insn = [4]u8{ 0x20, 0x04, 0x40, 0xf9 }; // ldr x0, [x1, #8]
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("ldr", result.mnemonic);
}

test "decode NOP" {
    const insn = [4]u8{ 0x1f, 0x20, 0x03, 0xd5 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("nop", result.mnemonic);
}

test "decode SVC" {
    // SVC #0x80
    const insn = [4]u8{ 0x01, 0x10, 0x00, 0xd4 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("svc", result.mnemonic);
}

test "decode MOVZ" {
    // MOV x0, #0x1234 (MOVZ x0, #0x1234)
    const insn = [4]u8{ 0x80, 0x46, 0x82, 0xd2 }; // movz x0, #0x1234
    const result = decode(&insn, 0x1000);
    try std.testing.expect(std.mem.eql(u8, result.mnemonic, "mov") or std.mem.eql(u8, result.mnemonic, "movz"));
}

test "decode BLR" {
    // BLR x8
    const insn = [4]u8{ 0x00, 0x01, 0x3f, 0xd6 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("blr", result.mnemonic);
    try std.testing.expect(result.is_call);
    try std.testing.expect(result.is_branch);
}

test "decode BR" {
    // BR x16
    const insn = [4]u8{ 0x00, 0x02, 0x1f, 0xd6 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("br", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(!result.is_call);
}

test "decode CMP immediate" {
    // CMP x0, #0 (SUBS xzr, x0, #0)
    const insn = [4]u8{ 0x1f, 0x00, 0x00, 0xf1 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("cmp", result.mnemonic);
}

test "decode ADRP" {
    // ADRP x0, #0x1000 (page-relative)
    // bit31=1, immlo=00, 10000, immhi=...0001, Rd=x0
    const insn = [4]u8{ 0x00, 0x00, 0x00, 0x90 }; // adrp x0, <page>
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("adrp", result.mnemonic);
}

test "decode instruction length always 4" {
    const insn = [4]u8{ 0x1f, 0x20, 0x03, 0xd5 }; // NOP
    const result = decode(&insn, 0x0);
    try std.testing.expectEqual(@as(u8, 4), result.length);
}
