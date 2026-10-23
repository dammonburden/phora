// Phora — ARM64 (AArch64) Instruction Decoder
// Table-driven decoder for fixed 32-bit ARM64 instructions.
// Reference: ARM Architecture Reference Manual (ARMv8-A)

const std = @import("std");
const types = @import("../types.zig");

// ============================================================================
// Decoded instruction — internal representation with rich metadata
// ============================================================================

pub const DecodeStatus = enum { decoded, unsupported };

/// Family labels are opaque decoder fallbacks, not instruction identities.
pub fn isOpaqueMnemonic(mnemonic: []const u8) bool {
    for ([_][]const u8{ "simd/ldst", "simd/fp", "dp_reg", "dp1src", "dp2src", "ldr/str", "sve", "udf" }) |name|
        if (std.mem.eql(u8, mnemonic, name)) return true;
    return false;
}

pub fn decodeStatus(word: u32, mnemonic: []const u8) DecodeStatus {
    // Architected UDF has fixed upper 16 bits zero; other UDF labels are fallback.
    if (std.mem.eql(u8, mnemonic, "udf") and word & 0xffff0000 == 0) return .decoded;
    return if (isOpaqueMnemonic(mnemonic)) .unsupported else .decoded;
}

pub const DecodedInstruction = struct {
    decode_status: DecodeStatus = .unsupported,
    mnemonic: []const u8,
    operands: [128]u8 = @splat(0),
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

        // 0bx111: Data processing — SIMD/FP
        0b0111, 0b1111 => {
            decodeSIMD(insn, &result);
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

    result.decode_status = decodeStatus(insn, result.mnemonic);
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
            const sext: i64 = std.math.signExtend(i64, @as(u26, @intCast(imm26)));
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
            const sext: i64 = std.math.signExtend(i64, @as(u26, @intCast(imm26)));
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
            const offset = std.math.signExtend(i64, @as(u19, @intCast(imm19))) * 4;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
            result.mnemonic = condBranchMnemonic(cond);
            result.is_branch = true;
            result.is_conditional_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
        },
        // 0b001, 0b101: compare-and-branch or test-and-branch.
        // Bit 25 distinguishes TBZ/TBNZ from CBZ/CBNZ; bit 31 selects width.
        0b001, 0b101 => {
            const sf = bit(insn, 31) == 1;
            const op = bit(insn, 24);
            const is_test = bit(insn, 25) == 1;
            const rt: u5 = @truncate(bits(insn, 4, 0));
            const offset = if (is_test)
                std.math.signExtend(i64, @as(u14, @intCast(bits(insn, 18, 5)))) * 4
            else
                std.math.signExtend(i64, @as(u19, @intCast(bits(insn, 23, 5)))) * 4;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
            result.mnemonic = if (is_test)
                (if (op == 0) "tbz" else "tbnz")
            else
                (if (op == 0) "cbz" else "cbnz");
            result.is_branch = true;
            result.is_conditional_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.append(regName(rt, sf));
            f.comma();
            if (is_test) {
                const bit_num = (@as(u6, bit(insn, 31)) << 5) | @as(u6, @intCast(bits(insn, 23, 19)));
                f.appendFmt("#{d}", .{bit_num});
                f.comma();
            }
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
        const offset = std.math.signExtend(i64, @as(u21, @intCast(imm)));
        const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% offset));
        result.mnemonic = "adr";
        var f = FmtBuf.init(&result.operands);
        f.append(xRegOrZr(rd));
        f.comma();
        f.appendHex(target);
        result.operands_len = f.len();
    } else {
        // ADRP Xd, label (page-aligned)
        const offset = std.math.signExtend(i64, @as(u21, @intCast(imm))) * 4096;
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

    const imm_val = decodeBitmaskImm(n, imms, immr, sf) orelse {
        result.mnemonic = "udf";
        result.operands_len = 0;
        return;
    };

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

/// ARM DecodeBitMasks with immediate=TRUE. Invalid encodings never invent
/// a zero/all-ones mask. The element width is 2^HighestSetBit(N:NOT(imms)).
fn decodeBitmaskImm(n: u1, imms: u6, immr: u6, sf: bool) ?u64 {
    if (!sf and n != 0) return null;
    const size_selector: u7 = (@as(u7, n) << 6) | @as(u7, ~imms);
    if (size_selector < 2) return null; // len < 1 is reserved.
    var probe = size_selector;
    var len: u3 = 0;
    while (probe > 1) : (probe >>= 1) len += 1;
    const element_size: u7 = @as(u7, 1) << len;
    const levels: u6 = @intCast(element_size - 1);
    const s = imms & levels;
    const r = immr & levels;
    if (s == levels) return null; // All-ones logical immediates are reserved.

    // s+1 is at most 63. Keep element_size in seven bits: truncating 64
    // before rotating previously disabled every 64-bit-element rotation.
    const element_mask = @as(u64, std.math.maxInt(u64)) >> @as(u6, @intCast(64 - element_size));
    var element = (@as(u64, 1) << @as(u6, @intCast(@as(u7, s) + 1))) - 1;
    if (r != 0) {
        element = ((element >> r) | (element << @as(u6, @intCast(element_size - r)))) & element_mask;
    }
    var result: u64 = 0;
    const register_size: u7 = if (sf) 64 else 32;
    var position: u7 = 0;
    while (position < register_size) : (position += element_size) {
        result |= element << @as(u6, @intCast(position));
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

// Finite SIMD/FP identities. Fixed-bit masks exclude unimplemented scalar FP,
// scalar SIMD, widening/narrowing operations, and other three-same opcodes.
// Their effects remain opaque: a familiar mnemonic must not invent scalar IR.
fn decodeSIMD(insn: u32, result: *DecodedInstruction) void {
    result.mnemonic = "simd/fp";
    // FADD scalar S/D only. Register fields and the S/D type bit vary; half
    // precision and neighboring FP operations remain unsupported. Identity and
    // fallthrough are known, while the lifter still treats FP effects as opaque.
    if (insn & 0xffa0fc00 == 0x1e202800) {
        result.mnemonic = "fadd";
        const kind: []const u8 = if (bit(insn, 22) == 0) "s" else "d";
        var f = FmtBuf.init(&result.operands);
        f.appendFmt("{s}{d}, {s}{d}, {s}{d}", .{ kind, bits(insn, 4, 0), kind, bits(insn, 9, 5), kind, bits(insn, 20, 16) });
        result.operands_len = f.len();
        return;
    }
    // MOVI .2D mask immediate: each imm8 bit selects an all-zero/all-one byte.
    // Require Q=1/op=1/cmode=1110 and all fixed bits; other modified-immediate
    // forms remain opaque until independently implemented.
    if (insn & 0xfff8fc00 == 0x6f00e400) {
        const imm8 = (bits(insn, 18, 16) << 5) | bits(insn, 9, 5);
        var immediate: u64 = 0;
        for (0..8) |i| {
            if (imm8 & (@as(u32, 1) << @as(u5, @intCast(i))) != 0)
                immediate |= @as(u64, 0xff) << @as(u6, @intCast(i * 8));
        }
        result.mnemonic = "movi";
        var f = FmtBuf.init(&result.operands);
        f.appendFmt("v{d}.2d, #0x{x}", .{ bits(insn, 4, 0), immediate });
        result.operands_len = f.len();
        return;
    }
    // SHA3 four-register Boolean operations have a fixed 128-bit arrangement.
    // Keep every fixed bit (including bit15) in the mask so reserved neighbors
    // and other crypto instructions cannot acquire these operand semantics.
    const crypto = insn & 0xffe08000;
    if (crypto == 0xce000000 or crypto == 0xce200000) {
        result.mnemonic = if (crypto == 0xce000000) "eor3" else "bcax";
        var f = FmtBuf.init(&result.operands);
        f.appendFmt("v{d}.16b, v{d}.16b, v{d}.16b, v{d}.16b", .{
            bits(insn, 4, 0), bits(insn, 9, 5), bits(insn, 20, 16), bits(insn, 14, 10),
        });
        result.operands_len = f.len();
        return;
    }
    const q = bit(insn, 30);
    var arrangement: []const u8 = undefined;
    switch (insn & 0xbfe0fc00) {
        0x0e201c00 => result.mnemonic = "and",
        0x0e601c00 => result.mnemonic = "bic",
        0x0ea01c00 => result.mnemonic = "orr",
        0x2e201c00 => result.mnemonic = "eor",
        else => {
            if ((insn & 0x9f20fc00) != 0x0e208400) return;
            const size: u2 = @truncate(bits(insn, 23, 22));
            // ADD/SUB (vector) reserves size=11 when Q=0; there is no .1d form.
            if (size == 3 and q == 0) {
                result.mnemonic = "udf";
                return;
            }
            result.mnemonic = if (bit(insn, 29) == 0) "add" else "sub";
            arrangement = if (q == 1)
                ([4][]const u8{ "16b", "8h", "4s", "2d" })[size]
            else
                ([4][]const u8{ "8b", "4h", "2s", "" })[size];
        },
    }
    if ((insn & 0x9f20fc00) != 0x0e208400)
        arrangement = if (q == 1) "16b" else "8b";

    var f = FmtBuf.init(&result.operands);
    f.appendFmt("v{d}.{s}, v{d}.{s}, v{d}.{s}", .{
        bits(insn, 4, 0),   arrangement,
        bits(insn, 9, 5),   arrangement,
        bits(insn, 20, 16), arrangement,
    });
    result.operands_len = f.len();
}

fn appendSIMDRegister(f: *FmtBuf, reg: u32, scale: u3) void {
    f.appendFmt("{s}{d}", .{ ([5][]const u8{ "b", "h", "s", "d", "q" })[scale], reg });
}

fn decodeSIMDMemory(insn: u32, address: u64, result: *DecodedInstruction) void {
    // Unknown structure/lane accesses and extensions stay explicitly opaque.
    result.mnemonic = "simd/ldst";
    const rt = bits(insn, 4, 0);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const opc: u2 = @truncate(bits(insn, 23, 22));
    const size: u2 = @truncate(bits(insn, 31, 30));
    var f = FmtBuf.init(&result.operands);

    // SIMD/FP literal loads: opc selects S/D/Q; opc=11 is unallocated.
    if ((insn & 0x3f000000) == 0x1c000000) {
        if (size == 3) {
            result.mnemonic = "udf";
            return;
        }
        const offset = std.math.signExtend(i64, @as(u19, @intCast(bits(insn, 23, 5)))) * 4;
        result.mnemonic = "ldr";
        appendSIMDRegister(&f, rt, @as(u3, size) + 2);
        f.comma();
        f.appendHex(address +% @as(u64, @bitCast(offset)));
        result.operands_len = f.len();
        return;
    }

    // Pair S/D/Q registers, scaled signed imm7. Non-temporal pairs have idx=00.
    if ((insn & 0x3e000000) == 0x2c000000) {
        // opc=11 includes newer LDTNP/STTNP extensions; preserve them opaque.
        if (size == 3) return;
        const scale: u3 = @as(u3, size) + 2;
        const idx = bits(insn, 24, 23);
        const load = bit(insn, 22) == 1;
        result.mnemonic = if (idx == 0)
            (if (load) "ldnp" else "stnp")
        else
            (if (load) "ldp" else "stp");
        const offset = std.math.signExtend(i64, @as(u7, @intCast(bits(insn, 21, 15)))) * (@as(i64, 1) << scale);
        appendSIMDRegister(&f, rt, scale);
        f.comma();
        appendSIMDRegister(&f, bits(insn, 14, 10), scale);
        f.comma();
        appendSIMDAddress(&f, rn, offset, if (idx == 0) 2 else @intCast(idx));
        result.operands_len = f.len();
        return;
    }

    const unsigned = (insn & 0x3f000000) == 0x3d000000;
    const imm9 = (insn & 0x3f200000) == 0x3c000000;
    const regoff = (insn & 0x3f200c00) == 0x3c200800;
    if (!unsigned and !imm9 and !regoff) return;
    // opc[1] selects a 128-bit transfer, which requires size=00.
    if (opc >= 2 and size != 0) {
        result.mnemonic = "udf";
        return;
    }
    const scale: u3 = if (opc >= 2) 4 else @as(u3, size);
    const load = (opc & 1) == 1;
    const idx: u2 = @truncate(bits(insn, 11, 10));
    const option: u3 = @truncate(bits(insn, 15, 13));
    // SIMD has no unprivileged imm9 form. Register offsets require option<1>=1.
    if ((imm9 and idx == 2) or (regoff and (option & 2) == 0)) {
        result.mnemonic = "udf";
        return;
    }
    result.mnemonic = if (imm9 and idx == 0)
        (if (load) "ldur" else "stur")
    else
        (if (load) "ldr" else "str");
    appendSIMDRegister(&f, rt, scale);
    f.comma();
    if (unsigned) {
        appendSIMDAddress(&f, rn, @as(i64, bits(insn, 21, 10)) << scale, 2);
    } else if (imm9) {
        const offset = std.math.signExtend(i64, @as(u9, @intCast(bits(insn, 20, 12))));
        appendSIMDAddress(&f, rn, offset, if (idx == 0) 2 else idx);
    } else {
        const rm: u5 = @truncate(bits(insn, 20, 16));
        const shifted = bit(insn, 12) == 1;
        f.appendFmt("[{s}, {s}", .{ xRegName(rn), if ((option & 1) == 1) xRegOrZr(rm) else wRegOrZr(rm) });
        if (option != 3 or shifted) {
            const ext = switch (option) {
                2 => "uxtw",
                3 => "lsl",
                6 => "sxtw",
                7 => "sxtx",
                else => unreachable,
            };
            f.appendFmt(", {s} #{d}", .{ ext, if (shifted) scale else @as(u3, 0) });
        }
        f.append("]");
    }
    result.operands_len = f.len();
}

fn appendSIMDAddress(f: *FmtBuf, rn: u5, offset: i64, idx: u2) void {
    f.appendFmt("[{s}", .{xRegName(rn)});
    if (idx != 1 and (offset != 0 or idx == 3)) {
        f.append(", #");
        f.appendSignedHex(offset);
    }
    f.append("]");
    if (idx == 1) {
        f.append(", #");
        f.appendSignedHex(offset);
    } else if (idx == 3) {
        f.append("!");
    }
}

// FEAT_LSE scalar atomic RMW identities. No memory/ordering semantics are
// inferred by the IR from this decoder. Reserved operations stay opaque.
fn decodeLseAtomic(insn: u32, result: *DecodedInstruction) bool {
    if (insn & 0x3f200c00 != 0x38200000) return false;
    const op: u4 = @truncate(insn >> 12);
    if (op > 8) return false;
    const size: u2 = @truncate(insn >> 30);
    const order: u2 = @truncate(insn >> 22);
    const names = [9][4][3][]const u8{
        .{ .{ "ldaddb", "ldaddh", "ldadd" }, .{ "ldaddlb", "ldaddlh", "ldaddl" }, .{ "ldaddab", "ldaddah", "ldadda" }, .{ "ldaddalb", "ldaddalh", "ldaddal" } },
        .{ .{ "ldclrb", "ldclrh", "ldclr" }, .{ "ldclrlb", "ldclrlh", "ldclrl" }, .{ "ldclrab", "ldclrah", "ldclra" }, .{ "ldclralb", "ldclralh", "ldclral" } },
        .{ .{ "ldeorb", "ldeorh", "ldeor" }, .{ "ldeorlb", "ldeorlh", "ldeorl" }, .{ "ldeorab", "ldeorah", "ldeora" }, .{ "ldeoralb", "ldeoralh", "ldeoral" } },
        .{ .{ "ldsetb", "ldseth", "ldset" }, .{ "ldsetlb", "ldsetlh", "ldsetl" }, .{ "ldsetab", "ldsetah", "ldseta" }, .{ "ldsetalb", "ldsetalh", "ldsetal" } },
        .{ .{ "ldsmaxb", "ldsmaxh", "ldsmax" }, .{ "ldsmaxlb", "ldsmaxlh", "ldsmaxl" }, .{ "ldsmaxab", "ldsmaxah", "ldsmaxa" }, .{ "ldsmaxalb", "ldsmaxalh", "ldsmaxal" } },
        .{ .{ "ldsminb", "ldsminh", "ldsmin" }, .{ "ldsminlb", "ldsminlh", "ldsminl" }, .{ "ldsminab", "ldsminah", "ldsmina" }, .{ "ldsminalb", "ldsminalh", "ldsminal" } },
        .{ .{ "ldumaxb", "ldumaxh", "ldumax" }, .{ "ldumaxlb", "ldumaxlh", "ldumaxl" }, .{ "ldumaxab", "ldumaxah", "ldumaxa" }, .{ "ldumaxalb", "ldumaxalh", "ldumaxal" } },
        .{ .{ "lduminb", "lduminh", "ldumin" }, .{ "lduminlb", "lduminlh", "lduminl" }, .{ "lduminab", "lduminah", "ldumina" }, .{ "lduminalb", "lduminalh", "lduminal" } },
        .{ .{ "swpb", "swph", "swp" }, .{ "swplb", "swplh", "swpl" }, .{ "swpab", "swpah", "swpa" }, .{ "swpalb", "swpalh", "swpal" } },
    };
    result.mnemonic = names[op][order][@min(size, 2)];
    var f = FmtBuf.init(&result.operands);
    f.append(regName(@truncate(insn >> 16), size == 3));
    f.comma();
    f.append(regName(@truncate(insn), size == 3));
    f.comma();
    f.appendFmt("[{s}]", .{xRegName(@truncate(insn >> 5))});
    result.operands_len = f.len();
    return true;
}

fn decodeLoadStore(insn: u32, address: u64, result: *DecodedInstruction) void {
    if (decodeLseAtomic(insn, result)) return;
    if (bit(insn, 26) == 1) {
        decodeSIMDMemory(insn, address, result);
        return;
    }
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

fn loadStoreTargetIs64(size: u2, opc: u2) bool {
    // opc=10 selects signed extension to 64 bits for byte, halfword, and word.
    // opc=11 selects signed extension to 32 bits only for byte and halfword.
    return size == 0b11 or opc == 0b10;
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
    const sf = loadStoreTargetIs64(size, opc);

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

    const offset = std.math.signExtend(i64, @as(u9, @intCast(imm9)));

    result.mnemonic = loadStoreMnemonic(size, v, opc);
    if (std.mem.eql(u8, result.mnemonic, "udf")) {
        result.operands_len = 0;
        return;
    }

    const sf = loadStoreTargetIs64(size, opc);

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

    // Keep atomics and other bit21=1 classes outside this register-offset form.
    if ((insn & 0x3f200c00) != 0x38200800) {
        result.mnemonic = "ldr/str";
        return;
    }
    if ((option & 0b010) == 0) {
        result.mnemonic = "udf";
        return;
    }

    result.mnemonic = loadStoreMnemonic(size, v, opc);
    if (std.mem.eql(u8, result.mnemonic, "udf")) {
        result.operands_len = 0;
        return;
    }

    const sf = loadStoreTargetIs64(size, opc);
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
    const offset = std.math.signExtend(i64, @as(u7, @intCast(imm7))) * (@as(i64, 1) << scale);

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

    if (shift == 3 or (!sf and imm6 >= 32)) {
        result.mnemonic = "udf";
        return;
    }

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
    // Finite register pointer-authentication families, independently assembled.
    // Exact opcode masks distinguish one-register zero-modifier forms from
    // two-register modifiers. Decoding identity does not model PAC effects.
    const one_name: ?[]const u8 = switch (insn & 0xffffffe0) {
        0xdac123e0 => "paciza",
        0xdac127e0 => "pacizb",
        0xdac12be0 => "pacdza",
        0xdac12fe0 => "pacdzb",
        0xdac133e0 => "autiza",
        0xdac137e0 => "autizb",
        0xdac13be0 => "autdza",
        0xdac13fe0 => "autdzb",
        0xdac143e0 => "xpaci",
        0xdac147e0 => "xpacd",
        else => null,
    };
    const two_name: ?[]const u8 = switch (insn & 0xfffffc00) {
        0xdac10000 => "pacia",
        0xdac10400 => "pacib",
        0xdac10800 => "pacda",
        0xdac10c00 => "pacdb",
        0xdac11000 => "autia",
        0xdac11400 => "autib",
        0xdac11800 => "autda",
        0xdac11c00 => "autdb",
        else => null,
    };
    if (one_name orelse two_name) |name| {
        result.mnemonic = name;
        var f = FmtBuf.init(&result.operands);
        f.append(regName(@truncate(insn), true));
        if (two_name != null) {
            f.comma();
            f.append(regNameSp(@truncate(insn >> 5), true));
        }
        result.operands_len = f.len();
        return;
    }
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
    // Bit 11 selects immediate versus register; bits 10 and 4 are reserved.
    if (insn & 0x20000410 != 0x20000000) {
        result.mnemonic = "dp_reg";
        return;
    }
    const immediate = bit(insn, 11);
    const rn: u5 = @truncate(bits(insn, 9, 5));
    const nzcv: u4 = @truncate(bits(insn, 3, 0));
    const cond: u4 = @truncate(bits(insn, 15, 12));

    if (immediate == 0) {
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

fn decodeTestWord(word: u32) DecodedInstruction {
    const raw = [4]u8{ @truncate(word), @truncate(word >> 8), @truncate(word >> 16), @truncate(word >> 24) };
    return decode(&raw, 0x1000);
}

test "signed GPR loads preserve W versus X destinations from LLVM encodings" {
    const cases = .{
        .{ @as(u32, 0x79800408), "ldrsh", "x8, [x0, #0x2]" }, // compiler R03
        .{ @as(u32, 0x79c00408), "ldrsh", "w8, [x0, #0x2]" },
        .{ @as(u32, 0x39800c29), "ldrsb", "x9, [x1, #0x3]" },
        .{ @as(u32, 0x39c00c29), "ldrsb", "w9, [x1, #0x3]" },
        .{ @as(u32, 0xb9800c4a), "ldrsw", "x10, [x2, #0xc]" },
        .{ @as(u32, 0x389ff46b), "ldrsb", "x11, [x3], #-0x1" },
        .{ @as(u32, 0x38dff46b), "ldrsb", "w11, [x3], #-0x1" },
        .{ @as(u32, 0x789fec8c), "ldrsh", "x12, [x4, #-0x2]!" },
        .{ @as(u32, 0x78dfec8c), "ldrsh", "w12, [x4, #-0x2]!" },
        .{ @as(u32, 0xb88044ad), "ldrsw", "x13, [x5], #0x4" },
        // Existing scalar unscaled names stay canonical LDRSB/SH/SW; the
        // architectural LDUR forms have identical data register widths.
        .{ @as(u32, 0x389f00ce), "ldrsb", "x14, [x6, #-0x10]" },
        .{ @as(u32, 0x38df00ce), "ldrsb", "w14, [x6, #-0x10]" },
        .{ @as(u32, 0x789f80ef), "ldrsh", "x15, [x7, #-0x8]" },
        .{ @as(u32, 0x78df80ef), "ldrsh", "w15, [x7, #-0x8]" },
        .{ @as(u32, 0xb89fc110), "ldrsw", "x16, [x8, #-0x4]" },
        .{ @as(u32, 0x38aa6931), "ldrsb", "x17, [x9, x10]" },
        .{ @as(u32, 0x38ea6931), "ldrsb", "w17, [x9, x10]" },
        .{ @as(u32, 0x78acd972), "ldrsh", "x18, [x11, w12, sxtw #1]" },
        .{ @as(u32, 0x78ecd972), "ldrsh", "w18, [x11, w12, sxtw #1]" },
        .{ @as(u32, 0xb8ae79b3), "ldrsw", "x19, [x13, x14, lsl #2]" },
    };
    inline for (cases) |case| {
        const decoded = decodeTestWord(case[0]);
        try std.testing.expectEqualStrings(case[1], decoded.mnemonic);
        try std.testing.expectEqualStrings(case[2], decoded.getOperands());
    }
    // Reserved word signed-to-W forms and reserved register-offset options.
    const invalid = [_]u32{ 0xb9c00c4a, 0xb8c044ad, 0xb8ee79b3, 0x38aa0931, 0x38aa2931, 0x38aa8931, 0x38aaa931 };
    for (invalid) |word| {
        const decoded = decodeTestWord(word);
        try std.testing.expectEqualStrings("udf", decoded.mnemonic);
        try std.testing.expectEqualStrings("", decoded.getOperands());
    }
    // Scalar literal loads remain explicitly unsupported in this finite pass.
    const literal = decodeTestWord(0x98000036);
    try std.testing.expectEqualStrings("ldr/str", literal.mnemonic);
}

test "SIMD finite vector families match LLVM assembled arrangements" {
    // clang -target arm64-apple-macos13; independently decoded by llvm-objdump.
    const cases = .{
        .{ @as(u32, 0x0e221c20), "and", "v0.8b, v1.8b, v2.8b" },
        .{ @as(u32, 0x4e251c83), "and", "v3.16b, v4.16b, v5.16b" },
        .{ @as(u32, 0x4ea81ce6), "orr", "v6.16b, v7.16b, v8.16b" },
        .{ @as(u32, 0x0e6b1d49), "bic", "v9.8b, v10.8b, v11.8b" },
        .{ @as(u32, 0x6e2e1dac), "eor", "v12.16b, v13.16b, v14.16b" },
        .{ @as(u32, 0x0e228420), "add", "v0.8b, v1.8b, v2.8b" },
        .{ @as(u32, 0x4e258483), "add", "v3.16b, v4.16b, v5.16b" },
        .{ @as(u32, 0x0e6884e6), "add", "v6.4h, v7.4h, v8.4h" },
        .{ @as(u32, 0x4e6b8549), "add", "v9.8h, v10.8h, v11.8h" },
        .{ @as(u32, 0x0eae85ac), "add", "v12.2s, v13.2s, v14.2s" },
        .{ @as(u32, 0x4eb1860f), "add", "v15.4s, v16.4s, v17.4s" },
        .{ @as(u32, 0x4ef48672), "add", "v18.2d, v19.2d, v20.2d" },
        .{ @as(u32, 0x6e3786d5), "sub", "v21.16b, v22.16b, v23.16b" },
        .{ @as(u32, 0x6efa8738), "sub", "v24.2d, v25.2d, v26.2d" },
    };
    inline for (cases) |case| {
        const decoded = decodeTestWord(case[0]);
        try std.testing.expectEqualStrings(case[1], decoded.mnemonic);
        try std.testing.expectEqualStrings(case[2], decoded.getOperands());
    }
}

test "SIMD SHA3 BCAX and EOR3 preserve four vector operands" {
    // clang -march=armv8.2-a+sha3; independent llvm-objdump references.
    // First BCAX is also observed in compiler-produced R02 at offset 0x334.
    const cases = .{
        .{ @as(u32, 0xce210040), "bcax", "v0.16b, v2.16b, v1.16b, v0.16b" },
        .{ @as(u32, 0xce3d73df), "bcax", "v31.16b, v30.16b, v29.16b, v28.16b" },
        .{ @as(u32, 0xce2f5ce4), "bcax", "v4.16b, v7.16b, v15.16b, v23.16b" },
        .{ @as(u32, 0xce230510), "bcax", "v16.16b, v8.16b, v3.16b, v1.16b" },
        .{ @as(u32, 0xce020c20), "eor3", "v0.16b, v1.16b, v2.16b, v3.16b" },
        .{ @as(u32, 0xce1d73df), "eor3", "v31.16b, v30.16b, v29.16b, v28.16b" },
        .{ @as(u32, 0xce0f5ce4), "eor3", "v4.16b, v7.16b, v15.16b, v23.16b" },
        .{ @as(u32, 0xce030510), "eor3", "v16.16b, v8.16b, v3.16b, v1.16b" },
    };
    inline for (cases) |case| {
        const decoded = decodeTestWord(case[0]);
        try std.testing.expectEqualStrings(case[1], decoded.mnemonic);
        try std.testing.expectEqualStrings(case[2], decoded.getOperands());
    }
    // Bit15=1 is reserved here; altered opcodes/widths must remain outside
    // the bounded Boolean family. RAX1/XAR/SHA512H are deliberately opaque.
    const neighbors = [_]u32{
        0xce218040, 0xce028c20, 0x8e210040, 0x8e020c20,
        0xce410040, 0xce608c20, 0xce820c20, 0xce608020,
    };
    for (neighbors) |word| {
        const decoded = decodeTestWord(word);
        try std.testing.expectEqualStrings("simd/fp", decoded.mnemonic);
        try std.testing.expectEqualStrings("", decoded.getOperands());
    }
}

test "SIMD memory preserves Q D S registers offset scales and address modes" {
    const cases = .{
        .{ @as(u32, 0x3dc00c20), "ldr", "q0, [x1, #0x30]" },
        .{ @as(u32, 0x3d800be2), "str", "q2, [sp, #0x20]" },
        .{ @as(u32, 0xfd400883), "ldr", "d3, [x4, #0x10]" },
        .{ @as(u32, 0xbd000cc5), "str", "s5, [x6, #0xc]" },
        .{ @as(u32, 0x3cdf0107), "ldur", "q7, [x8, #-0x10]" },
        .{ @as(u32, 0xfc1f8149), "stur", "d9, [x10, #-0x8]" },
        .{ @as(u32, 0x3cc1058b), "ldr", "q11, [x12], #0x10" },
        .{ @as(u32, 0xbc1fcdcd), "str", "s13, [x14, #-0x4]!" },
        .{ @as(u32, 0x3cf17a0f), "ldr", "q15, [x16, x17, lsl #4]" },
        .{ @as(u32, 0xfc345a72), "str", "d18, [x19, w20, uxtw #3]" },
        .{ @as(u32, 0xad410440), "ldp", "q0, q1, [x2, #0x20]" },
        .{ @as(u32, 0x6dbf13e3), "stp", "d3, d4, [sp, #-0x10]!" },
        .{ @as(u32, 0x2cc118e5), "ldp", "s5, s6, [x7], #0x8" },
        .{ @as(u32, 0xac410440), "ldnp", "q0, q1, [x2, #0x20]" },
        .{ @as(u32, 0x9c000020), "ldr", "q0, 0x1004" },
        .{ @as(u32, 0x5cffffe1), "ldr", "d1, 0xffc" },
    };
    inline for (cases) |case| {
        const decoded = decodeTestWord(case[0]);
        try std.testing.expectEqualStrings(case[1], decoded.mnemonic);
        try std.testing.expectEqualStrings(case[2], decoded.getOperands());
    }
}

test "SIMD reserved widths reject and neighboring instructions stay opaque" {
    const invalid = [_]u32{
        0x0ee28420, // ADD Q=0 size=11
        0x2ee28420, // SUB Q=0 size=11
        0x7dc00c20, 0xbdc00c20, 0xfdc00c20, // Q load requires size=00
        0x7d800c20, 0xbd800c20, 0xfd800c20, // Q store requires size=00
        0xdc000020, // SIMD literal opc=11
        0x3cc1098b, // SIMD unprivileged imm9 is unallocated
        0x3cf13a0f, // invalid register-offset option=001
    };
    for (invalid) |word| {
        const decoded = decodeTestWord(word);
        try std.testing.expectEqualStrings("udf", decoded.mnemonic);
        try std.testing.expectEqualStrings("", decoded.getOperands());
    }
    const unsupported = [_]u32{
        0x1e623820, // scalar FSUB D0,D1,D2 remains outside finite coverage
        0x5ee28420, // scalar SIMD ADD D0,D1,D2
        0x4ee21c20, // ORN vector, intentionally outside finite families
        0x6e621c20, // BSL vector
        0x4e228020, // SMLAL widening neighbor
    };
    for (unsupported) |word| {
        const decoded = decodeTestWord(word);
        try std.testing.expectEqualStrings("simd/fp", decoded.mnemonic);
    }
    const structure = decodeTestWord(0x4c407020); // LD1 structure access
    try std.testing.expectEqualStrings("simd/ldst", structure.mnemonic);
    const extended_pair = decodeTestWord(0xec410440); // newer LDTNP extension
    try std.testing.expectEqualStrings("simd/ldst", extended_pair.mnemonic);
}

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

test "TBZ and TBNZ decode every signed imm14 with word scaling" {
    for ([_]u32{ 0x36000000, 0x37000000, 0xb6000000, 0xb7000000 }) |opcode| {
        for (0..(1 << 14)) |immediate| {
            var raw: [4]u8 = undefined;
            std.mem.writeInt(u32, &raw, opcode | (@as(u32, @intCast(immediate)) << 5), .little);
            const result = decode(&raw, 0x10000);
            const signed: i64 = if (immediate < 0x2000) @intCast(immediate) else @as(i64, @intCast(immediate)) - 0x4000;
            const expected: u64 = @intCast(0x10000 + signed * 4);
            try std.testing.expectEqualStrings(if (opcode & 0x01000000 == 0) "tbz" else "tbnz", result.mnemonic);
            try std.testing.expect(result.is_branch and result.is_conditional_branch and !result.is_call);
            try std.testing.expectEqual(@as(?u64, expected), result.branch_target);
        }
    }
}

test "compare and test branches match assembler encodings" {
    // Independently assembled with Apple clang and disassembled with otool.
    const cases = [_]struct { word: u32, address: u64, mnemonic: []const u8, operands: []const u8, target: u64 }{
        .{ .word = 0x36f80083, .address = 0, .mnemonic = "tbz", .operands = "w3, #31, 0x10", .target = 0x10 },
        .{ .word = 0xb7ffffe5, .address = 4, .mnemonic = "tbnz", .operands = "x5, #63, 0x0", .target = 0 },
        .{ .word = 0x34000043, .address = 8, .mnemonic = "cbz", .operands = "w3, 0x10", .target = 0x10 },
        .{ .word = 0xb5ffffa5, .address = 12, .mnemonic = "cbnz", .operands = "x5, 0x0", .target = 0 },
    };
    for (cases) |case| {
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u32, &raw, case.word, .little);
        const result = decode(&raw, case.address);
        try std.testing.expectEqualStrings(case.mnemonic, result.mnemonic);
        try std.testing.expectEqualStrings(case.operands, result.getOperands());
        try std.testing.expectEqual(@as(?u64, case.target), result.branch_target);
    }
}

test "signed branch immediate boundaries and address wrapping" {
    const cases = .{
        .{ @as(u32, 0x14000000), 26, 0, "b" },
        .{ @as(u32, 0x94000000), 26, 0, "bl" },
        .{ @as(u32, 0x54000000), 19, 5, "b.eq" },
        .{ @as(u32, 0x34000000), 19, 5, "cbz" },
        .{ @as(u32, 0xb5000000), 19, 5, "cbnz" },
    };
    inline for (cases) |case| {
        const sign = 1 << (case[1] - 1);
        for ([_]u32{ 0, 1, sign - 1, sign, sign + 1, sign * 2 - 1 }) |immediate| {
            // The oracle uses subtraction, independently of signExtend.
            const signed: i64 = if (immediate < sign) immediate else @as(i64, immediate) - sign * 2;
            for ([_]u64{ 0, 0x100000000, std.math.maxInt(u64) - 3 }) |address| {
                var raw: [4]u8 = undefined;
                std.mem.writeInt(u32, &raw, case[0] | (immediate << case[2]), .little);
                const result = decode(&raw, address);
                const expected = address +% @as(u64, @bitCast(signed * 4));
                try std.testing.expectEqualStrings(case[3], result.mnemonic);
                try std.testing.expect(result.is_branch);
                try std.testing.expectEqual(case[0] == 0x94000000, result.is_call);
                try std.testing.expectEqual(@as(?u64, expected), result.branch_target);
            }
        }
    }
}

test "ADR and ADRP signed immediate boundaries preserve page scaling" {
    for ([_]u32{ 0, 1, 0xfffff, 0x100000, 0x100001, 0x1fffff }) |immediate| {
        const signed: i64 = if (immediate < 0x100000) immediate else @as(i64, immediate) - 0x200000;
        for ([_]u32{ 0x10000000, 0x90000000 }) |opcode| {
            const is_page = opcode == 0x90000000;
            for ([_]u64{ 0, 0x100001234, std.math.maxInt(u64) }) |address| {
                var raw: [4]u8 = undefined;
                const word = opcode | ((immediate & 3) << 29) | ((immediate >> 2) << 5);
                std.mem.writeInt(u32, &raw, word, .little);
                const result = decode(&raw, address);
                const base = if (is_page) address & ~@as(u64, 0xfff) else address;
                const offset = signed * @as(i64, if (is_page) 4096 else 1);
                const expected = base +% @as(u64, @bitCast(offset));
                var operands: [64]u8 = undefined;
                const expected_operands = try std.fmt.bufPrint(&operands, "x0, 0x{x}", .{expected});
                try std.testing.expectEqualStrings(if (is_page) "adrp" else "adr", result.mnemonic);
                try std.testing.expectEqualStrings(expected_operands, result.getOperands());
            }
        }
    }
}

test "signed load store immediates exhaust imm9 and scaled imm7" {
    for (0..512) |immediate| {
        const signed: i64 = if (immediate < 256) @intCast(immediate) else @as(i64, @intCast(immediate)) - 512;
        var raw: [4]u8 = undefined;
        // STR x0, [x1], #imm9 uses post-index syntax even when the offset is zero.
        std.mem.writeInt(u32, &raw, 0xf8000420 | (@as(u32, @intCast(immediate)) << 12), .little);
        const result = decode(&raw, 0x1000);
        var operands: [64]u8 = undefined;
        const expected = try std.fmt.bufPrint(&operands, "x0, [x1], #{s}0x{x}", .{ if (signed < 0) "-" else "", @abs(signed) });
        try std.testing.expectEqualStrings("str", result.mnemonic);
        try std.testing.expectEqualStrings(expected, result.getOperands());
    }
    for ([_]bool{ false, true }) |wide| {
        for (0..128) |immediate| {
            const signed: i64 = if (immediate < 64) @intCast(immediate) else @as(i64, @intCast(immediate)) - 128;
            const offset = signed * @as(i64, if (wide) 8 else 4);
            var raw: [4]u8 = undefined;
            const opcode: u32 = if (wide) 0xa8800820 else 0x28800820;
            std.mem.writeInt(u32, &raw, opcode | (@as(u32, @intCast(immediate)) << 15), .little);
            const result = decode(&raw, 0x1000);
            var operands: [64]u8 = undefined;
            const expected = try std.fmt.bufPrint(&operands, "{s}0, {s}2, [x1], #{s}0x{x}", .{ if (wide) "x" else "w", if (wide) "x" else "w", if (offset < 0) "-" else "", @abs(offset) });
            try std.testing.expectEqualStrings("stp", result.mnemonic);
            try std.testing.expectEqualStrings(expected, result.getOperands());
        }
    }
}

// Independent oracle: classify element-size ranges directly, then evaluate
// every output bit's membership in the rotated run. No production rotate,
// size-selector, replication, or mask-building helper is reused.
fn referenceLogicalImmediate(sf: bool, n: u1, imms: u6, immr: u6) ?u64 {
    if (!sf and n != 0) return null;
    const element_size: u8 = if (n == 1) 64 else if (imms < 32) 32 else if (imms < 48) 16 else if (imms < 56) 8 else if (imms < 60) 4 else if (imms < 62) 2 else return null;
    const ones: u8 = @as(u8, imms) % element_size + 1;
    if (ones == element_size) return null;
    var mask: u64 = 0;
    const width: u8 = if (sf) 64 else 32;
    var position: u8 = 0;
    while (position < width) : (position += 1) {
        const source_bit = (@as(u16, position) + immr) % element_size;
        if (source_bit < ones) mask |= @as(u64, 1) << @as(u6, @intCast(position));
    }
    return mask;
}

test "evidence: logical immediates exhaust widths selectors rotations and reserved encodings" {
    var valid: usize = 0;
    var invalid: usize = 0;
    const names = [_][]const u8{ "and", "orr", "eor", "ands" };
    for (0..2) |sf_raw| {
        for (0..2) |n_raw| {
            for (0..64) |s_raw| {
                for (0..64) |r_raw| {
                    const sf = sf_raw != 0;
                    const n: u1 = @intCast(n_raw);
                    const s: u6 = @intCast(s_raw);
                    const r: u6 = @intCast(r_raw);
                    const expected = referenceLogicalImmediate(sf, n, s, r);
                    try std.testing.expectEqual(expected, decodeBitmaskImm(n, s, r, sf));
                    if (expected != null) valid += 1 else invalid += 1;
                    for (0..4) |opc| {
                        const word: u32 = 0x12000043 | (@as(u32, @intCast(sf_raw)) << 31) |
                            (@as(u32, @intCast(opc)) << 29) | (@as(u32, n) << 22) |
                            (@as(u32, r) << 16) | (@as(u32, s) << 10);
                        var raw: [4]u8 = undefined;
                        std.mem.writeInt(u32, &raw, word, .little);
                        const decoded = decode(&raw, 0x1000);
                        if (expected) |mask| {
                            try std.testing.expectEqualStrings(names[opc], decoded.mnemonic);
                            var expected_buf: [80]u8 = undefined;
                            const operands = try std.fmt.bufPrint(&expected_buf, "{s}3, {s}2, #0x{x}", .{ if (sf) "x" else "w", if (sf) "x" else "w", mask });
                            try std.testing.expectEqualStrings(operands, decoded.getOperands());
                        } else {
                            try std.testing.expectEqualStrings("udf", decoded.mnemonic);
                            try std.testing.expectEqual(@as(u8, 0), decoded.operands_len);
                        }
                    }
                }
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 11328), valid);
    try std.testing.expectEqual(@as(usize, 5056), invalid);
}

test "evidence: logical immediate native regression and full width rotate" {
    const cases = [_]struct { word: u32, mnemonic: []const u8, operands: []const u8 }{
        .{ .word = 0x521d03c9, .mnemonic = "eor", .operands = "w9, w30, #0x8" },
        .{ .word = 0xb24103e0, .mnemonic = "mov", .operands = "x0, #0x8000000000000000" },
        .{ .word = 0xb24003e0, .mnemonic = "mov", .operands = "x0, #0x1" },
        .{ .word = 0x320003e0, .mnemonic = "mov", .operands = "w0, #0x1" },
        .{ .word = 0x324003e0, .mnemonic = "udf", .operands = "" },
        .{ .word = 0xb240ffe0, .mnemonic = "udf", .operands = "" },
    };
    for (cases) |case| {
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u32, &raw, case.word, .little);
        const decoded = decode(&raw, 0);
        try std.testing.expectEqualStrings(case.mnemonic, decoded.mnemonic);
        try std.testing.expectEqualStrings(case.operands, decoded.getOperands());
    }
}

test "opaque family labels do not claim decoded instruction identity" {
    for ([_][]const u8{ "simd/ldst", "simd/fp", "dp_reg", "dp1src", "dp2src", "ldr/str", "sve", "udf" }) |name|
        try std.testing.expectEqual(DecodeStatus.unsupported, decodeStatus(0xcccccccc, name));
    try std.testing.expectEqual(DecodeStatus.unsupported, decodeTestWord(0xcccccccc).decode_status);
    try std.testing.expectEqual(DecodeStatus.unsupported, decodeTestWord(0x1e623820).decode_status);
    try std.testing.expectEqual(DecodeStatus.decoded, decodeTestWord(0x3dc00c20).decode_status);
    try std.testing.expectEqual(DecodeStatus.decoded, decodeTestWord(0x4ee28420).decode_status);
    try std.testing.expectEqual(DecodeStatus.decoded, decodeTestWord(0x00001234).decode_status);
    try std.testing.expectEqual(DecodeStatus.unsupported, decodeTestWord(0xffffffff).decode_status);
    try std.testing.expectEqual(DecodeStatus.unsupported, decode(&.{ 0, 0 }, 0).decode_status);
}

test "finite MOVI 2D and register pointer authentication decode preserve known fallthrough" {
    const cases = .{
        .{ @as(u32, 0x6f00e400), "movi", "v0.2d, #0x0" },
        .{ @as(u32, 0x6f05e543), "movi", "v3.2d, #0xff00ff00ff00ff00" },
        .{ @as(u32, 0xdac123f0), "paciza", "x16" },
        .{ @as(u32, 0xdac127f1), "pacizb", "x17" },
        .{ @as(u32, 0xdac12bf2), "pacdza", "x18" },
        .{ @as(u32, 0xdac12ff3), "pacdzb", "x19" },
        .{ @as(u32, 0xdac133f4), "autiza", "x20" },
        .{ @as(u32, 0xdac137f5), "autizb", "x21" },
        .{ @as(u32, 0xdac13bf6), "autdza", "x22" },
        .{ @as(u32, 0xdac13ff7), "autdzb", "x23" },
        .{ @as(u32, 0xdac143f8), "xpaci", "x24" },
        .{ @as(u32, 0xdac147f9), "xpacd", "x25" },
        .{ @as(u32, 0xdac10041), "pacia", "x1, x2" },
        .{ @as(u32, 0xdac10483), "pacib", "x3, x4" },
        .{ @as(u32, 0xdac108c5), "pacda", "x5, x6" },
        .{ @as(u32, 0xdac10d07), "pacdb", "x7, x8" },
        .{ @as(u32, 0xdac11149), "autia", "x9, x10" },
        .{ @as(u32, 0xdac1158b), "autib", "x11, x12" },
        .{ @as(u32, 0xdac119cd), "autda", "x13, x14" },
        .{ @as(u32, 0xdac11e0f), "autdb", "x15, x16" },
    };
    inline for (cases) |case| {
        const d = decodeTestWord(case[0]);
        try std.testing.expectEqualStrings(case[1], d.mnemonic);
        try std.testing.expectEqualStrings(case[2], d.getOperands());
        try std.testing.expectEqual(DecodeStatus.decoded, d.decode_status);
        try std.testing.expect(!d.is_branch and !d.is_call and !d.is_return);
    }
    for ([_]u32{ 0x2f00e400, 0x6f00ec00, 0x6f00e000, 0xdac163f0, 0x5ac123f0, 0xcccccccc, 0x0bc00000, 0x0b008000 }) |word|
        try std.testing.expectEqual(DecodeStatus.unsupported, decodeTestWord(word).decode_status);
}

test "scalar FADD identity preserves CFG fallthrough without modeling FP effects" {
    const cases = .{
        .{ @as(u32, 0x1e202800), "s0, s0, s0" },
        .{ @as(u32, 0x1e622820), "d0, d1, d2" },
        .{ @as(u32, 0x1e3d2bdf), "s31, s30, s29" },
    };
    inline for (cases) |case| {
        const d = decodeTestWord(case[0]);
        try std.testing.expectEqualStrings("fadd", d.mnemonic);
        try std.testing.expectEqualStrings(case[1], d.getOperands());
        try std.testing.expectEqual(DecodeStatus.decoded, d.decode_status);
        try std.testing.expect(!d.is_branch and !d.is_call and !d.is_return);
    }
    for ([_]u32{ 0x1e623820, 0x1ee22820, 0x1ea22820, 0x9e622820, 0x1e222c20 }) |word|
        try std.testing.expectEqual(DecodeStatus.unsupported, decodeTestWord(word).decode_status);
}

test "CCMP CCMN immediate selector and reserved bits are exact" {
    const cases = .{
        .{ @as(u32, 0x7a462900), "ccmp", "w8, #6, #0, cs" },
        .{ @as(u32, 0x7a462100), "ccmp", "w8, w6, #0, cs" },
        .{ @as(u32, 0xba5ffbeF), "ccmn", "xzr, #31, #15, nv" },
        .{ @as(u32, 0x3a400800), "ccmn", "w0, #0, #0, eq" },
    };
    inline for (cases) |case| {
        const d = decodeTestWord(case[0]);
        try std.testing.expectEqualStrings(case[1], d.mnemonic);
        try std.testing.expectEqualStrings(case[2], d.getOperands());
    }
    for ([_]u32{ 0x7a462910, 0x7a462d00, 0x5a462900 }) |word|
        try std.testing.expectEqual(DecodeStatus.unsupported, decodeTestWord(word).decode_status);
}

test "LSE atomic identities preserve sequential CFG without claiming atomic IR semantics" {
    const cases = .{
        .{ @as(u32, 0x38e08108), "swpalb", "w0, w8, [x8]" },
        .{ @as(u32, 0xf8e90108), "ldaddal", "x9, x8, [x8]" },
        .{ @as(u32, 0x78203041), "ldseth", "w0, w1, [x2]" },
        .{ @as(u32, 0xb8bf23ff), "ldeora", "wzr, wzr, [sp]" },
    };
    inline for (cases) |case| {
        const d = decodeTestWord(case[0]);
        try std.testing.expectEqualStrings(case[1], d.mnemonic);
        try std.testing.expectEqualStrings(case[2], d.getOperands());
        try std.testing.expectEqual(DecodeStatus.decoded, d.decode_status);
        try std.testing.expect(!d.is_branch and !d.is_call and !d.is_return);
    }
    for ([_]u32{ 0x38e09108, 0x38e0a108, 0x38e0f108, 0x38e08508, 0x38e08d08 }) |word|
        try std.testing.expectEqual(DecodeStatus.unsupported, decodeTestWord(word).decode_status);
}
