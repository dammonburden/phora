// Phora — x86_64 Instruction Decoder
// Variable-length instruction decoder for AMD64/Intel 64.
// Reference: Intel SDM Vol. 2, AMD APM Vol. 3

const std = @import("std");
const types = @import("../types.zig");

threadlocal var instruction_operands_scratch: [64]u8 = [_]u8{0} ** 64;

// ============================================================================
// Decoded instruction — internal representation with rich metadata
// ============================================================================

pub const DecodedInstruction = struct {
    mnemonic: []const u8 = "udf",
    operands: [128]u8 = [_]u8{0} ** 128,
    operands_len: u8 = 0,
    length: u8 = 1,
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
            .bytes = raw_bytes[0..@min(raw_bytes.len, self.length)],
            .mnemonic = self.mnemonic,
            .operands = self.operands[0..self.operands_len],
            .size = self.length,
        };
    }
};

// ============================================================================
// Prefix state
// ============================================================================

const Prefixes = struct {
    rex: u8 = 0,
    has_rex: bool = false,
    has_66: bool = false, // operand size override
    has_67: bool = false, // address size override
    has_f0: bool = false, // LOCK
    has_f2: bool = false, // REPNE/REPNZ
    has_f3: bool = false, // REP/REPE/REPZ
    seg_override: u8 = 0, // segment override prefix byte (0 if none)

    fn rexW(self: *const Prefixes) bool {
        return self.has_rex and (self.rex & 0x08) != 0;
    }
    fn rexR(self: *const Prefixes) bool {
        return self.has_rex and (self.rex & 0x04) != 0;
    }
    fn rexX(self: *const Prefixes) bool {
        return self.has_rex and (self.rex & 0x02) != 0;
    }
    fn rexB(self: *const Prefixes) bool {
        return self.has_rex and (self.rex & 0x01) != 0;
    }
};

// ============================================================================
// Operand size helpers
// ============================================================================

const OperandSize = enum { bits8, bits16, bits32, bits64 };

fn effectiveOperandSize(pfx: *const Prefixes, default_64: bool) OperandSize {
    if (pfx.rexW()) return .bits64;
    if (default_64) return .bits64;
    if (pfx.has_66) return .bits16;
    return .bits32;
}

// ============================================================================
// Register name tables
// ============================================================================

const reg8_names = [16][]const u8{
    "al",  "cl",  "dl",   "bl",   "ah",   "ch",   "dh",   "bh",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
};

const reg8_rex_names = [16][]const u8{
    "al",  "cl",  "dl",   "bl",   "spl",  "bpl",  "sil",  "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
};

const reg16_names = [16][]const u8{
    "ax",  "cx",  "dx",   "bx",   "sp",   "bp",   "si",   "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
};

const reg32_names = [16][]const u8{
    "eax", "ecx", "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
};

const reg64_names = [16][]const u8{
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
};

fn regName(idx: u4, size: OperandSize, has_rex: bool) []const u8 {
    return switch (size) {
        .bits8 => if (has_rex) reg8_rex_names[idx] else reg8_names[idx],
        .bits16 => reg16_names[idx],
        .bits32 => reg32_names[idx],
        .bits64 => reg64_names[idx],
    };
}

// ============================================================================
// Condition code names (for Jcc, SETcc, CMOVcc)
// ============================================================================

const cc_names = [16][]const u8{
    "o", "no", "b", "ae", "e", "ne", "be", "a",
    "s", "ns", "p", "np", "l", "ge", "le", "g",
};

const jcc_mnemonics = [16][]const u8{
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
};

const cmovcc_mnemonics = [16][]const u8{
    "cmovo", "cmovno", "cmovb", "cmovae", "cmove", "cmovne", "cmovbe", "cmova",
    "cmovs", "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg",
};

const setcc_mnemonics = [16][]const u8{
    "seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta",
    "sets", "setns", "setp", "setnp", "setl", "setge", "setle", "setg",
};

// ============================================================================
// Formatting buffer (same pattern as ARM64 decoder)
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
        const result = std.fmt.bufPrint(slice, fmt, args) catch return;
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
// Stream reader — tracks position through the instruction bytes
// ============================================================================

const ByteReader = struct {
    data: []const u8,
    pos: usize,

    fn init(data: []const u8) ByteReader {
        return .{ .data = data, .pos = 0 };
    }

    fn remaining(self: *const ByteReader) usize {
        if (self.pos >= self.data.len) return 0;
        return self.data.len - self.pos;
    }

    fn readU8(self: *ByteReader) ?u8 {
        if (self.pos >= self.data.len) return null;
        const val = self.data[self.pos];
        self.pos += 1;
        return val;
    }

    fn peekU8(self: *const ByteReader) ?u8 {
        if (self.pos >= self.data.len) return null;
        return self.data[self.pos];
    }

    fn readI8(self: *ByteReader) ?i8 {
        const val = self.readU8() orelse return null;
        return @bitCast(val);
    }

    fn readU16(self: *ByteReader) ?u16 {
        if (self.pos + 2 > self.data.len) return null;
        const val = @as(u16, self.data[self.pos]) |
            (@as(u16, self.data[self.pos + 1]) << 8);
        self.pos += 2;
        return val;
    }

    fn readU32(self: *ByteReader) ?u32 {
        if (self.pos + 4 > self.data.len) return null;
        const val = @as(u32, self.data[self.pos]) |
            (@as(u32, self.data[self.pos + 1]) << 8) |
            (@as(u32, self.data[self.pos + 2]) << 16) |
            (@as(u32, self.data[self.pos + 3]) << 24);
        self.pos += 4;
        return val;
    }

    fn readI32(self: *ByteReader) ?i32 {
        const val = self.readU32() orelse return null;
        return @bitCast(val);
    }

    fn readU64(self: *ByteReader) ?u64 {
        if (self.pos + 8 > self.data.len) return null;
        const val = @as(u64, self.data[self.pos]) |
            (@as(u64, self.data[self.pos + 1]) << 8) |
            (@as(u64, self.data[self.pos + 2]) << 16) |
            (@as(u64, self.data[self.pos + 3]) << 24) |
            (@as(u64, self.data[self.pos + 4]) << 32) |
            (@as(u64, self.data[self.pos + 5]) << 40) |
            (@as(u64, self.data[self.pos + 6]) << 48) |
            (@as(u64, self.data[self.pos + 7]) << 56);
        self.pos += 8;
        return val;
    }
};

// ============================================================================
// ModR/M + SIB decoding
// ============================================================================

fn modrm_mod(b: u8) u2 {
    return @truncate(b >> 6);
}
fn modrm_reg(b: u8) u3 {
    return @truncate((b >> 3) & 0x7);
}
fn modrm_rm(b: u8) u3 {
    return @truncate(b & 0x7);
}

fn sib_scale(b: u8) u2 {
    return @truncate(b >> 6);
}
fn sib_index(b: u8) u3 {
    return @truncate((b >> 3) & 0x7);
}
fn sib_base(b: u8) u3 {
    return @truncate(b & 0x7);
}

fn extendReg(base: u3, rex_bit: bool) u4 {
    return @as(u4, if (rex_bit) 8 else 0) | @as(u4, base);
}

/// Decode a ModR/M memory reference and append it to the format buffer.
/// Returns false if we ran out of bytes.
fn appendModRM(f: *FmtBuf, reader: *ByteReader, modrm: u8, pfx: *const Prefixes, op_size: OperandSize) bool {
    const mod = modrm_mod(modrm);
    const rm = modrm_rm(modrm);
    const rm_ext = extendReg(rm, pfx.rexB());

    if (mod == 0b11) {
        // Register direct
        f.append(regName(rm_ext, op_size, pfx.has_rex));
        return true;
    }

    // Memory reference — add size prefix
    switch (op_size) {
        .bits8 => f.append("byte ptr ["),
        .bits16 => f.append("word ptr ["),
        .bits32 => f.append("dword ptr ["),
        .bits64 => f.append("qword ptr ["),
    }

    if (rm == 0b100) {
        // SIB byte follows
        const sib_byte = reader.readU8() orelse return false;
        const base = sib_base(sib_byte);
        const index = sib_index(sib_byte);
        const scale = sib_scale(sib_byte);
        const base_ext = extendReg(base, pfx.rexB());
        const index_ext = extendReg(index, pfx.rexX());

        if (mod == 0b00 and base == 0b101) {
            // [disp32 + index*scale] or [disp32] (no base)
            const disp = reader.readI32() orelse return false;
            if (index != 0b100) {
                f.append(reg64_names[index_ext]);
                if (scale > 0) {
                    f.appendFmt("*{d}", .{@as(u32, 1) << @as(u2, scale)});
                }
                if (disp > 0) {
                    f.append(" + ");
                    f.appendFmt("0x{x}", .{@as(u32, @bitCast(disp))});
                } else if (disp < 0) {
                    f.append(" - ");
                    f.appendFmt("0x{x}", .{@as(u32, @bitCast(-disp))});
                }
            } else {
                f.appendFmt("0x{x}", .{@as(u32, @bitCast(disp))});
            }
        } else {
            f.append(reg64_names[base_ext]);
            if (index != 0b100) {
                f.append(" + ");
                f.append(reg64_names[index_ext]);
                if (scale > 0) {
                    f.appendFmt("*{d}", .{@as(u32, 1) << @as(u2, scale)});
                }
            }
            if (mod == 0b01) {
                const disp = reader.readI8() orelse return false;
                if (disp > 0) {
                    f.appendFmt(" + 0x{x}", .{@as(u8, @bitCast(disp))});
                } else if (disp < 0) {
                    f.appendFmt(" - 0x{x}", .{@as(u8, @bitCast(-disp))});
                }
            } else if (mod == 0b10) {
                const disp = reader.readI32() orelse return false;
                if (disp > 0) {
                    f.appendFmt(" + 0x{x}", .{@as(u32, @bitCast(disp))});
                } else if (disp < 0) {
                    f.appendFmt(" - 0x{x}", .{@as(u32, @bitCast(-disp))});
                }
            }
        }
    } else if (mod == 0b00 and rm == 0b101) {
        // RIP-relative addressing [rip + disp32]
        const disp = reader.readI32() orelse return false;
        f.append("rip");
        if (disp > 0) {
            f.appendFmt(" + 0x{x}", .{@as(u32, @bitCast(disp))});
        } else if (disp < 0) {
            f.appendFmt(" - 0x{x}", .{@as(u32, @bitCast(-disp))});
        }
    } else {
        // Simple [reg], [reg+disp8], [reg+disp32]
        f.append(reg64_names[rm_ext]);
        if (mod == 0b01) {
            const disp = reader.readI8() orelse return false;
            if (disp > 0) {
                f.appendFmt(" + 0x{x}", .{@as(u8, @bitCast(disp))});
            } else if (disp < 0) {
                f.appendFmt(" - 0x{x}", .{@as(u8, @bitCast(-disp))});
            }
        } else if (mod == 0b10) {
            const disp = reader.readI32() orelse return false;
            if (disp > 0) {
                f.appendFmt(" + 0x{x}", .{@as(u32, @bitCast(disp))});
            } else if (disp < 0) {
                f.appendFmt(" - 0x{x}", .{@as(u32, @bitCast(-disp))});
            }
        }
    }

    f.append("]");
    return true;
}

// ============================================================================
// Main decode entry point
// ============================================================================

pub fn decode(raw: []const u8, address: u64) DecodedInstruction {
    if (raw.len == 0) {
        return .{};
    }

    var reader = ByteReader.init(raw);
    var pfx = Prefixes{};

    // Parse prefixes
    while (reader.peekU8()) |b| {
        switch (b) {
            0xF0 => {
                pfx.has_f0 = true;
                _ = reader.readU8();
            },
            0xF2 => {
                pfx.has_f2 = true;
                _ = reader.readU8();
            },
            0xF3 => {
                pfx.has_f3 = true;
                _ = reader.readU8();
            },
            0x66 => {
                pfx.has_66 = true;
                _ = reader.readU8();
            },
            0x67 => {
                pfx.has_67 = true;
                _ = reader.readU8();
            },
            0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65 => {
                pfx.seg_override = b;
                _ = reader.readU8();
            },
            0x40...0x4F => {
                // REX prefix
                pfx.rex = b;
                pfx.has_rex = true;
                _ = reader.readU8();
            },
            else => break,
        }
    }

    var result = DecodedInstruction{};
    const opcode = reader.readU8() orelse return result;

    // Two-byte opcode escape
    if (opcode == 0x0F) {
        return decodeTwoByteOpcode(&reader, &pfx, address);
    }

    // One-byte opcode map
    switch (opcode) {
        // ADD r/m, r (00-03)
        0x00 => return decodeRM(raw, &reader, &pfx, address, "add", .bits8, .rm_reg),
        0x01 => return decodeRM(raw, &reader, &pfx, address, "add", effectiveOperandSize(&pfx, false), .rm_reg),
        0x02 => return decodeRM(raw, &reader, &pfx, address, "add", .bits8, .reg_rm),
        0x03 => return decodeRM(raw, &reader, &pfx, address, "add", effectiveOperandSize(&pfx, false), .reg_rm),
        0x04 => return decodeALImm(raw, &reader, &pfx, address, "add", .bits8),
        0x05 => return decodeALImm(raw, &reader, &pfx, address, "add", effectiveOperandSize(&pfx, false)),

        // OR r/m, r (08-0D)
        0x08 => return decodeRM(raw, &reader, &pfx, address, "or", .bits8, .rm_reg),
        0x09 => return decodeRM(raw, &reader, &pfx, address, "or", effectiveOperandSize(&pfx, false), .rm_reg),
        0x0A => return decodeRM(raw, &reader, &pfx, address, "or", .bits8, .reg_rm),
        0x0B => return decodeRM(raw, &reader, &pfx, address, "or", effectiveOperandSize(&pfx, false), .reg_rm),
        0x0C => return decodeALImm(raw, &reader, &pfx, address, "or", .bits8),
        0x0D => return decodeALImm(raw, &reader, &pfx, address, "or", effectiveOperandSize(&pfx, false)),

        // AND r/m, r (20-25)
        0x20 => return decodeRM(raw, &reader, &pfx, address, "and", .bits8, .rm_reg),
        0x21 => return decodeRM(raw, &reader, &pfx, address, "and", effectiveOperandSize(&pfx, false), .rm_reg),
        0x22 => return decodeRM(raw, &reader, &pfx, address, "and", .bits8, .reg_rm),
        0x23 => return decodeRM(raw, &reader, &pfx, address, "and", effectiveOperandSize(&pfx, false), .reg_rm),
        0x24 => return decodeALImm(raw, &reader, &pfx, address, "and", .bits8),
        0x25 => return decodeALImm(raw, &reader, &pfx, address, "and", effectiveOperandSize(&pfx, false)),

        // SUB r/m, r (28-2D)
        0x28 => return decodeRM(raw, &reader, &pfx, address, "sub", .bits8, .rm_reg),
        0x29 => return decodeRM(raw, &reader, &pfx, address, "sub", effectiveOperandSize(&pfx, false), .rm_reg),
        0x2A => return decodeRM(raw, &reader, &pfx, address, "sub", .bits8, .reg_rm),
        0x2B => return decodeRM(raw, &reader, &pfx, address, "sub", effectiveOperandSize(&pfx, false), .reg_rm),
        0x2C => return decodeALImm(raw, &reader, &pfx, address, "sub", .bits8),
        0x2D => return decodeALImm(raw, &reader, &pfx, address, "sub", effectiveOperandSize(&pfx, false)),

        // XOR r/m, r (30-35)
        0x30 => return decodeRM(raw, &reader, &pfx, address, "xor", .bits8, .rm_reg),
        0x31 => return decodeRM(raw, &reader, &pfx, address, "xor", effectiveOperandSize(&pfx, false), .rm_reg),
        0x32 => return decodeRM(raw, &reader, &pfx, address, "xor", .bits8, .reg_rm),
        0x33 => return decodeRM(raw, &reader, &pfx, address, "xor", effectiveOperandSize(&pfx, false), .reg_rm),
        0x34 => return decodeALImm(raw, &reader, &pfx, address, "xor", .bits8),
        0x35 => return decodeALImm(raw, &reader, &pfx, address, "xor", effectiveOperandSize(&pfx, false)),

        // CMP r/m, r (38-3D)
        0x38 => return decodeRM(raw, &reader, &pfx, address, "cmp", .bits8, .rm_reg),
        0x39 => return decodeRM(raw, &reader, &pfx, address, "cmp", effectiveOperandSize(&pfx, false), .rm_reg),
        0x3A => return decodeRM(raw, &reader, &pfx, address, "cmp", .bits8, .reg_rm),
        0x3B => return decodeRM(raw, &reader, &pfx, address, "cmp", effectiveOperandSize(&pfx, false), .reg_rm),
        0x3C => return decodeALImm(raw, &reader, &pfx, address, "cmp", .bits8),
        0x3D => return decodeALImm(raw, &reader, &pfx, address, "cmp", effectiveOperandSize(&pfx, false)),

        // PUSH r64 (50-57)
        0x50...0x57 => {
            const reg_idx = extendReg(@truncate(opcode & 0x7), pfx.rexB());
            result.mnemonic = "push";
            var f = FmtBuf.init(&result.operands);
            f.append(reg64_names[reg_idx]);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // POP r64 (58-5F)
        0x58...0x5F => {
            const reg_idx = extendReg(@truncate(opcode & 0x7), pfx.rexB());
            result.mnemonic = "pop";
            var f = FmtBuf.init(&result.operands);
            f.append(reg64_names[reg_idx]);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // PUSH imm32/imm16
        0x68 => {
            const op_size = effectiveOperandSize(&pfx, false);
            result.mnemonic = "push";
            var f = FmtBuf.init(&result.operands);
            if (op_size == .bits16) {
                const imm = reader.readU16() orelse return result;
                f.appendHex(imm);
            } else {
                const imm = reader.readU32() orelse return result;
                f.appendHex(imm);
            }
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // PUSH imm8 (sign-extended)
        0x6A => {
            const imm = reader.readI8() orelse return result;
            result.mnemonic = "push";
            var f = FmtBuf.init(&result.operands);
            f.appendSignedHex(@intCast(imm));
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // Short Jcc (70-7F)
        0x70...0x7F => {
            const cc: u4 = @truncate(opcode & 0xF);
            const rel = reader.readI8() orelse return result;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% @as(i64, @intCast(reader.pos)) +% @as(i64, rel)));
            result.mnemonic = jcc_mnemonics[cc];
            result.is_branch = true;
            result.is_conditional_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm
        0x80 => return decodeGroup1(raw, &reader, &pfx, address, .bits8, .imm8),
        0x81 => return decodeGroup1(raw, &reader, &pfx, address, effectiveOperandSize(&pfx, false), .imm32),
        0x83 => return decodeGroup1(raw, &reader, &pfx, address, effectiveOperandSize(&pfx, false), .imm8),

        // TEST r/m, r
        0x84 => return decodeRM(raw, &reader, &pfx, address, "test", .bits8, .rm_reg),
        0x85 => return decodeRM(raw, &reader, &pfx, address, "test", effectiveOperandSize(&pfx, false), .rm_reg),

        // XCHG r/m, r
        0x86 => return decodeRM(raw, &reader, &pfx, address, "xchg", .bits8, .reg_rm),
        0x87 => return decodeRM(raw, &reader, &pfx, address, "xchg", effectiveOperandSize(&pfx, false), .reg_rm),

        // MOV r/m, r (88-8B)
        0x88 => return decodeRM(raw, &reader, &pfx, address, "mov", .bits8, .rm_reg),
        0x89 => return decodeRM(raw, &reader, &pfx, address, "mov", effectiveOperandSize(&pfx, false), .rm_reg),
        0x8A => return decodeRM(raw, &reader, &pfx, address, "mov", .bits8, .reg_rm),
        0x8B => return decodeRM(raw, &reader, &pfx, address, "mov", effectiveOperandSize(&pfx, false), .reg_rm),

        // LEA r, m
        0x8D => return decodeRM(raw, &reader, &pfx, address, "lea", effectiveOperandSize(&pfx, false), .reg_rm_lea),

        // NOP (XCHG eax, eax) / PAUSE
        0x90 => {
            if (pfx.has_f3) {
                result.mnemonic = "pause";
            } else {
                result.mnemonic = "nop";
            }
            result.length = @intCast(reader.pos);
            return result;
        },

        // XCHG rAX, r (91-97)
        0x91...0x97 => {
            const reg_idx = extendReg(@truncate(opcode & 0x7), pfx.rexB());
            const op_size = effectiveOperandSize(&pfx, false);
            result.mnemonic = "xchg";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(0, op_size, pfx.has_rex));
            f.comma();
            f.append(regName(reg_idx, op_size, pfx.has_rex));
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // CDQ / CQO
        0x99 => {
            result.mnemonic = if (pfx.rexW()) "cqo" else "cdq";
            result.length = @intCast(reader.pos);
            return result;
        },

        // TEST AL, imm8 / TEST rAX, imm
        0xA8 => return decodeALImm(raw, &reader, &pfx, address, "test", .bits8),
        0xA9 => return decodeALImm(raw, &reader, &pfx, address, "test", effectiveOperandSize(&pfx, false)),

        // MOV r8, imm8 (B0-B7)
        0xB0...0xB7 => {
            const reg_idx = extendReg(@truncate(opcode & 0x7), pfx.rexB());
            const imm = reader.readU8() orelse return result;
            result.mnemonic = "mov";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg_idx, .bits8, pfx.has_rex));
            f.comma();
            f.appendHex(imm);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // MOV r, imm (B8-BF)
        0xB8...0xBF => {
            const reg_idx = extendReg(@truncate(opcode & 0x7), pfx.rexB());
            const op_size = effectiveOperandSize(&pfx, false);
            result.mnemonic = "mov";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg_idx, op_size, pfx.has_rex));
            f.comma();
            if (pfx.rexW()) {
                const imm = reader.readU64() orelse return result;
                f.appendHex(imm);
            } else if (op_size == .bits16) {
                const imm = reader.readU16() orelse return result;
                f.appendHex(imm);
            } else {
                const imm = reader.readU32() orelse return result;
                f.appendHex(imm);
            }
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // Shift/rotate group (C0/C1 = imm8, D0/D1 = 1, D2/D3 = CL)
        0xC0 => return decodeShiftGroup(raw, &reader, &pfx, address, .bits8, .imm8),
        0xC1 => return decodeShiftGroup(raw, &reader, &pfx, address, effectiveOperandSize(&pfx, false), .imm8),
        0xD0 => return decodeShiftGroup(raw, &reader, &pfx, address, .bits8, .one),
        0xD1 => return decodeShiftGroup(raw, &reader, &pfx, address, effectiveOperandSize(&pfx, false), .one),
        0xD2 => return decodeShiftGroup(raw, &reader, &pfx, address, .bits8, .cl),
        0xD3 => return decodeShiftGroup(raw, &reader, &pfx, address, effectiveOperandSize(&pfx, false), .cl),

        // RET near
        0xC3 => {
            result.mnemonic = "ret";
            result.is_branch = true;
            result.is_return = true;
            result.length = @intCast(reader.pos);
            return result;
        },

        // RET near imm16
        0xC2 => {
            const imm = reader.readU16() orelse return result;
            result.mnemonic = "ret";
            result.is_branch = true;
            result.is_return = true;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(imm);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // MOV r/m, imm (C6/C7)
        0xC6 => return decodeMovImm(raw, &reader, &pfx, address, .bits8),
        0xC7 => return decodeMovImm(raw, &reader, &pfx, address, effectiveOperandSize(&pfx, false)),

        // ENTER
        0xC8 => {
            const size = reader.readU16() orelse return result;
            const level = reader.readU8() orelse return result;
            result.mnemonic = "enter";
            var f = FmtBuf.init(&result.operands);
            f.appendHex(size);
            f.comma();
            f.appendHex(level);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // LEAVE
        0xC9 => {
            result.mnemonic = "leave";
            result.length = @intCast(reader.pos);
            return result;
        },

        // INT 3
        0xCC => {
            result.mnemonic = "int3";
            result.length = @intCast(reader.pos);
            return result;
        },

        // INT imm8
        0xCD => {
            const imm = reader.readU8() orelse return result;
            result.mnemonic = "int";
            var f = FmtBuf.init(&result.operands);
            f.appendHex(imm);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // CALL rel32
        0xE8 => {
            const rel = reader.readI32() orelse return result;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% @as(i64, @intCast(reader.pos)) +% @as(i64, rel)));
            result.mnemonic = "call";
            result.is_branch = true;
            result.is_call = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // JMP rel32
        0xE9 => {
            const rel = reader.readI32() orelse return result;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% @as(i64, @intCast(reader.pos)) +% @as(i64, rel)));
            result.mnemonic = "jmp";
            result.is_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // JMP rel8
        0xEB => {
            const rel = reader.readI8() orelse return result;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% @as(i64, @intCast(reader.pos)) +% @as(i64, rel)));
            result.mnemonic = "jmp";
            result.is_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV r/m
        0xF6 => return decodeGroup3(raw, &reader, &pfx, address, .bits8),
        0xF7 => return decodeGroup3(raw, &reader, &pfx, address, effectiveOperandSize(&pfx, false)),

        // Group 5: INC/DEC/CALL/JMP/PUSH r/m
        0xFF => return decodeGroup5(raw, &reader, &pfx, address),

        // HLT
        0xF4 => {
            result.mnemonic = "hlt";
            result.length = @intCast(reader.pos);
            return result;
        },

        // CLC, STC, CLI, STI, CLD, STD
        0xF8 => {
            result.mnemonic = "clc";
            result.length = @intCast(reader.pos);
            return result;
        },
        0xF9 => {
            result.mnemonic = "stc";
            result.length = @intCast(reader.pos);
            return result;
        },
        0xFA => {
            result.mnemonic = "cli";
            result.length = @intCast(reader.pos);
            return result;
        },
        0xFB => {
            result.mnemonic = "sti";
            result.length = @intCast(reader.pos);
            return result;
        },
        0xFC => {
            result.mnemonic = "cld";
            result.length = @intCast(reader.pos);
            return result;
        },
        0xFD => {
            result.mnemonic = "std";
            result.length = @intCast(reader.pos);
            return result;
        },

        else => {
            // Unknown opcode — consume 1 byte
            result.mnemonic = "db";
            var f = FmtBuf.init(&result.operands);
            f.appendHex(opcode);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },
    }
}

// ============================================================================
// Two-byte opcode (0x0F xx)
// ============================================================================

fn decodeTwoByteOpcode(reader: *ByteReader, pfx: *const Prefixes, address: u64) DecodedInstruction {
    var result = DecodedInstruction{};
    const opcode2 = reader.readU8() orelse return result;

    switch (opcode2) {
        // SYSCALL
        0x05 => {
            result.mnemonic = "syscall";
            result.length = @intCast(reader.pos);
            return result;
        },

        // SYSRET
        0x07 => {
            result.mnemonic = "sysret";
            result.length = @intCast(reader.pos);
            return result;
        },

        // UD2
        0x0B => {
            result.mnemonic = "ud2";
            result.length = @intCast(reader.pos);
            return result;
        },

        // NOP r/m (0F 1F — multi-byte NOP)
        0x1F => {
            const modrm = reader.readU8() orelse return result;
            // Consume ModR/M operand but discard
            var f = FmtBuf.init(&result.operands);
            _ = appendModRM(&f, reader, modrm, pfx, effectiveOperandSize(pfx, false));
            result.mnemonic = "nop";
            result.operands_len = 0;
            result.length = @intCast(reader.pos);
            return result;
        },

        // CMOVcc (0F 40-4F)
        0x40...0x4F => {
            const cc: u4 = @truncate(opcode2 & 0xF);
            const modrm = reader.readU8() orelse return result;
            const op_size = effectiveOperandSize(pfx, false);
            const reg = extendReg(modrm_reg(modrm), pfx.rexR());

            result.mnemonic = cmovcc_mnemonics[cc];
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // Near Jcc rel32 (0F 80-8F)
        0x80...0x8F => {
            const cc: u4 = @truncate(opcode2 & 0xF);
            const rel = reader.readI32() orelse return result;
            const target = @as(u64, @bitCast(@as(i64, @bitCast(address)) +% @as(i64, @intCast(reader.pos)) +% @as(i64, rel)));
            result.mnemonic = jcc_mnemonics[cc];
            result.is_branch = true;
            result.is_conditional_branch = true;
            result.branch_target = target;
            var f = FmtBuf.init(&result.operands);
            f.appendHex(target);
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // SETcc (0F 90-9F)
        0x90...0x9F => {
            const cc: u4 = @truncate(opcode2 & 0xF);
            const modrm = reader.readU8() orelse return result;
            result.mnemonic = setcc_mnemonics[cc];
            var f = FmtBuf.init(&result.operands);
            if (!appendModRM(&f, reader, modrm, pfx, .bits8)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // IMUL r, r/m (0F AF)
        0xAF => {
            const modrm = reader.readU8() orelse return result;
            const op_size = effectiveOperandSize(pfx, false);
            const reg = extendReg(modrm_reg(modrm), pfx.rexR());
            result.mnemonic = "imul";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // MOVZX r, r/m8 (0F B6)
        0xB6 => {
            const modrm = reader.readU8() orelse return result;
            const op_size = effectiveOperandSize(pfx, false);
            const reg = extendReg(modrm_reg(modrm), pfx.rexR());
            result.mnemonic = "movzx";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, .bits8)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // MOVZX r, r/m16 (0F B7)
        0xB7 => {
            const modrm = reader.readU8() orelse return result;
            const op_size = effectiveOperandSize(pfx, false);
            const reg = extendReg(modrm_reg(modrm), pfx.rexR());
            result.mnemonic = "movzx";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, .bits16)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // MOVSX r, r/m8 (0F BE)
        0xBE => {
            const modrm = reader.readU8() orelse return result;
            const op_size = effectiveOperandSize(pfx, false);
            const reg = extendReg(modrm_reg(modrm), pfx.rexR());
            result.mnemonic = "movsx";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, .bits8)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // MOVSX r, r/m16 (0F BF)
        0xBF => {
            const modrm = reader.readU8() orelse return result;
            const op_size = effectiveOperandSize(pfx, false);
            const reg = extendReg(modrm_reg(modrm), pfx.rexR());
            result.mnemonic = "movsx";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, .bits16)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        // MOVSXD (63 with REX.W) — actually one-byte but placed here for convenience
        // BSF (0F BC), BSR (0F BD)
        0xBC => {
            const modrm = reader.readU8() orelse return result;
            const op_size = effectiveOperandSize(pfx, false);
            const reg = extendReg(modrm_reg(modrm), pfx.rexR());
            result.mnemonic = if (pfx.has_f3) "tzcnt" else "bsf";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },
        0xBD => {
            const modrm = reader.readU8() orelse return result;
            const op_size = effectiveOperandSize(pfx, false);
            const reg = extendReg(modrm_reg(modrm), pfx.rexR());
            result.mnemonic = if (pfx.has_f3) "lzcnt" else "bsr";
            var f = FmtBuf.init(&result.operands);
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },

        else => {
            result.mnemonic = "db";
            var f = FmtBuf.init(&result.operands);
            f.appendFmt("0x0f, 0x{x}", .{opcode2});
            result.operands_len = f.len();
            result.length = @intCast(reader.pos);
            return result;
        },
    }
}

// ============================================================================
// Encoding pattern decoders
// ============================================================================

const RMDirection = enum { rm_reg, reg_rm, reg_rm_lea };

fn decodeRM(raw: []const u8, reader: *ByteReader, pfx: *const Prefixes, address: u64, mnemonic: []const u8, base_size: OperandSize, dir: RMDirection) DecodedInstruction {
    _ = raw;
    _ = address;
    var result = DecodedInstruction{};
    const modrm = reader.readU8() orelse return result;
    const reg = extendReg(modrm_reg(modrm), pfx.rexR());

    const op_size = if (base_size == .bits8) OperandSize.bits8 else effectiveOperandSize(pfx, false);
    result.mnemonic = mnemonic;
    var f = FmtBuf.init(&result.operands);

    switch (dir) {
        .rm_reg => {
            if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
            f.comma();
            f.append(regName(reg, op_size, pfx.has_rex));
        },
        .reg_rm => {
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
        },
        .reg_rm_lea => {
            f.append(regName(reg, op_size, pfx.has_rex));
            f.comma();
            // LEA uses address-size memory reference, no size prefix
            if (!appendModRM_lea(&f, reader, modrm, pfx)) return result;
        },
    }

    result.operands_len = f.len();
    result.length = @intCast(reader.pos);
    return result;
}

/// LEA version of ModRM — no size prefix, and mod=11 is invalid
fn appendModRM_lea(f: *FmtBuf, reader: *ByteReader, modrm: u8, pfx: *const Prefixes) bool {
    const mod = modrm_mod(modrm);
    const rm = modrm_rm(modrm);
    const rm_ext = extendReg(rm, pfx.rexB());

    if (mod == 0b11) {
        // Invalid for LEA, but still decode
        f.append(reg64_names[rm_ext]);
        return true;
    }

    f.append("[");

    if (rm == 0b100) {
        const sib_byte = reader.readU8() orelse return false;
        const base = sib_base(sib_byte);
        const index = sib_index(sib_byte);
        const scale = sib_scale(sib_byte);
        const base_ext = extendReg(base, pfx.rexB());
        const index_ext = extendReg(index, pfx.rexX());

        if (mod == 0b00 and base == 0b101) {
            const disp = reader.readI32() orelse return false;
            if (index != 0b100) {
                f.append(reg64_names[index_ext]);
                if (scale > 0) {
                    f.appendFmt("*{d}", .{@as(u32, 1) << @as(u2, scale)});
                }
                if (disp > 0) {
                    f.appendFmt(" + 0x{x}", .{@as(u32, @bitCast(disp))});
                } else if (disp < 0) {
                    f.appendFmt(" - 0x{x}", .{@as(u32, @bitCast(-disp))});
                }
            } else {
                f.appendFmt("0x{x}", .{@as(u32, @bitCast(disp))});
            }
        } else {
            f.append(reg64_names[base_ext]);
            if (index != 0b100) {
                f.append(" + ");
                f.append(reg64_names[index_ext]);
                if (scale > 0) {
                    f.appendFmt("*{d}", .{@as(u32, 1) << @as(u2, scale)});
                }
            }
            if (mod == 0b01) {
                const disp = reader.readI8() orelse return false;
                if (disp > 0) {
                    f.appendFmt(" + 0x{x}", .{@as(u8, @bitCast(disp))});
                } else if (disp < 0) {
                    f.appendFmt(" - 0x{x}", .{@as(u8, @bitCast(-disp))});
                }
            } else if (mod == 0b10) {
                const disp = reader.readI32() orelse return false;
                if (disp > 0) {
                    f.appendFmt(" + 0x{x}", .{@as(u32, @bitCast(disp))});
                } else if (disp < 0) {
                    f.appendFmt(" - 0x{x}", .{@as(u32, @bitCast(-disp))});
                }
            }
        }
    } else if (mod == 0b00 and rm == 0b101) {
        const disp = reader.readI32() orelse return false;
        f.append("rip");
        if (disp > 0) {
            f.appendFmt(" + 0x{x}", .{@as(u32, @bitCast(disp))});
        } else if (disp < 0) {
            f.appendFmt(" - 0x{x}", .{@as(u32, @bitCast(-disp))});
        }
    } else {
        f.append(reg64_names[rm_ext]);
        if (mod == 0b01) {
            const disp = reader.readI8() orelse return false;
            if (disp > 0) {
                f.appendFmt(" + 0x{x}", .{@as(u8, @bitCast(disp))});
            } else if (disp < 0) {
                f.appendFmt(" - 0x{x}", .{@as(u8, @bitCast(-disp))});
            }
        } else if (mod == 0b10) {
            const disp = reader.readI32() orelse return false;
            if (disp > 0) {
                f.appendFmt(" + 0x{x}", .{@as(u32, @bitCast(disp))});
            } else if (disp < 0) {
                f.appendFmt(" - 0x{x}", .{@as(u32, @bitCast(-disp))});
            }
        }
    }

    f.append("]");
    return true;
}

fn decodeALImm(raw: []const u8, reader: *ByteReader, pfx: *const Prefixes, address: u64, mnemonic: []const u8, base_size: OperandSize) DecodedInstruction {
    _ = raw;
    _ = address;
    var result = DecodedInstruction{};
    const op_size = if (base_size == .bits8) OperandSize.bits8 else effectiveOperandSize(pfx, false);
    result.mnemonic = mnemonic;
    var f = FmtBuf.init(&result.operands);
    f.append(regName(0, op_size, pfx.has_rex));
    f.comma();
    switch (op_size) {
        .bits8 => {
            const imm = reader.readU8() orelse return result;
            f.appendHex(imm);
        },
        .bits16 => {
            const imm = reader.readU16() orelse return result;
            f.appendHex(imm);
        },
        else => {
            const imm = reader.readU32() orelse return result;
            f.appendHex(imm);
        },
    }
    result.operands_len = f.len();
    result.length = @intCast(reader.pos);
    return result;
}

// ============================================================================
// Group decoders
// ============================================================================

const group1_mnemonics = [8][]const u8{
    "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp",
};

const ImmType = enum { imm8, imm32 };

fn decodeGroup1(raw: []const u8, reader: *ByteReader, pfx: *const Prefixes, address: u64, base_size: OperandSize, imm_type: ImmType) DecodedInstruction {
    _ = raw;
    _ = address;
    var result = DecodedInstruction{};
    const modrm = reader.readU8() orelse return result;
    const reg_field = modrm_reg(modrm);
    const op_size = if (base_size == .bits8) OperandSize.bits8 else effectiveOperandSize(pfx, false);

    result.mnemonic = group1_mnemonics[reg_field];
    var f = FmtBuf.init(&result.operands);
    if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
    f.comma();

    switch (imm_type) {
        .imm8 => {
            if (base_size == .bits8) {
                const imm = reader.readU8() orelse return result;
                f.appendHex(imm);
            } else {
                // Sign-extended imm8
                const imm = reader.readI8() orelse return result;
                f.appendSignedHex(@intCast(imm));
            }
        },
        .imm32 => {
            switch (op_size) {
                .bits8 => {
                    const imm = reader.readU8() orelse return result;
                    f.appendHex(imm);
                },
                .bits16 => {
                    const imm = reader.readU16() orelse return result;
                    f.appendHex(imm);
                },
                else => {
                    const imm = reader.readU32() orelse return result;
                    f.appendHex(imm);
                },
            }
        },
    }

    result.operands_len = f.len();
    result.length = @intCast(reader.pos);
    return result;
}

const group3_mnemonics = [8][]const u8{
    "test", "test", "not", "neg", "mul", "imul", "div", "idiv",
};

fn decodeGroup3(raw: []const u8, reader: *ByteReader, pfx: *const Prefixes, address: u64, base_size: OperandSize) DecodedInstruction {
    _ = raw;
    _ = address;
    var result = DecodedInstruction{};
    const modrm = reader.readU8() orelse return result;
    const reg_field = modrm_reg(modrm);
    const op_size = if (base_size == .bits8) OperandSize.bits8 else effectiveOperandSize(pfx, false);

    result.mnemonic = group3_mnemonics[reg_field];
    var f = FmtBuf.init(&result.operands);
    if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;

    // TEST has an immediate operand
    if (reg_field == 0 or reg_field == 1) {
        f.comma();
        switch (op_size) {
            .bits8 => {
                const imm = reader.readU8() orelse return result;
                f.appendHex(imm);
            },
            .bits16 => {
                const imm = reader.readU16() orelse return result;
                f.appendHex(imm);
            },
            else => {
                const imm = reader.readU32() orelse return result;
                f.appendHex(imm);
            },
        }
    }

    result.operands_len = f.len();
    result.length = @intCast(reader.pos);
    return result;
}

fn decodeGroup5(raw: []const u8, reader: *ByteReader, pfx: *const Prefixes, address: u64) DecodedInstruction {
    _ = raw;
    _ = address;
    var result = DecodedInstruction{};
    const modrm = reader.readU8() orelse return result;
    const reg_field = modrm_reg(modrm);
    const op_size = effectiveOperandSize(pfx, true); // default 64-bit in 64-bit mode

    switch (reg_field) {
        0 => {
            // INC r/m
            result.mnemonic = "inc";
        },
        1 => {
            // DEC r/m
            result.mnemonic = "dec";
        },
        2 => {
            // CALL r/m64
            result.mnemonic = "call";
            result.is_branch = true;
            result.is_call = true;
        },
        3 => {
            // CALL FAR m16:32/64
            result.mnemonic = "call far";
            result.is_branch = true;
            result.is_call = true;
        },
        4 => {
            // JMP r/m64
            result.mnemonic = "jmp";
            result.is_branch = true;
        },
        5 => {
            // JMP FAR m16:32/64
            result.mnemonic = "jmp far";
            result.is_branch = true;
        },
        6 => {
            // PUSH r/m64
            result.mnemonic = "push";
        },
        7 => {
            result.mnemonic = "udf";
            result.length = @intCast(reader.pos);
            return result;
        },
    }

    var f = FmtBuf.init(&result.operands);
    if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
    result.operands_len = f.len();
    result.length = @intCast(reader.pos);
    return result;
}

const shift_mnemonics = [8][]const u8{
    "rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar",
};

const ShiftSource = enum { imm8, one, cl };

fn decodeShiftGroup(raw: []const u8, reader: *ByteReader, pfx: *const Prefixes, address: u64, base_size: OperandSize, src: ShiftSource) DecodedInstruction {
    _ = raw;
    _ = address;
    var result = DecodedInstruction{};
    const modrm = reader.readU8() orelse return result;
    const reg_field = modrm_reg(modrm);
    const op_size = if (base_size == .bits8) OperandSize.bits8 else effectiveOperandSize(pfx, false);

    result.mnemonic = shift_mnemonics[reg_field];
    var f = FmtBuf.init(&result.operands);
    if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
    f.comma();

    switch (src) {
        .imm8 => {
            const imm = reader.readU8() orelse return result;
            f.appendHex(imm);
        },
        .one => {
            f.append("1");
        },
        .cl => {
            f.append("cl");
        },
    }

    result.operands_len = f.len();
    result.length = @intCast(reader.pos);
    return result;
}

fn decodeMovImm(raw: []const u8, reader: *ByteReader, pfx: *const Prefixes, address: u64, base_size: OperandSize) DecodedInstruction {
    _ = raw;
    _ = address;
    var result = DecodedInstruction{};
    const modrm = reader.readU8() orelse return result;
    const op_size = if (base_size == .bits8) OperandSize.bits8 else effectiveOperandSize(pfx, false);

    result.mnemonic = "mov";
    var f = FmtBuf.init(&result.operands);
    if (!appendModRM(&f, reader, modrm, pfx, op_size)) return result;
    f.comma();

    switch (op_size) {
        .bits8 => {
            const imm = reader.readU8() orelse return result;
            f.appendHex(imm);
        },
        .bits16 => {
            const imm = reader.readU16() orelse return result;
            f.appendHex(imm);
        },
        else => {
            const imm = reader.readU32() orelse return result;
            f.appendHex(imm);
        },
    }

    result.operands_len = f.len();
    result.length = @intCast(reader.pos);
    return result;
}

// ============================================================================
// Public API
// ============================================================================

pub fn decodeInstruction(raw: []const u8, address: u64) types.Instruction {
    const decoded = decode(raw, address);
    // v7.8.1 H3 fix: copy operands into the Instruction's owned buffer so
    // they survive after the decoded stack local goes out of scope.
    // Previously this assigned `decoded.getOperands()` directly, which is
    // a slice into the about-to-die stack frame — once Database.addInstruction
    // re-derived `operands` from `operands_buf[0..operands_len]` the result
    // was empty (operands_len had never been set), producing pseudocode like
    // `xor ;`, `mov ;` for every x86_64 instruction. Mirror the arm64/arm32/
    // mips32 idiom: copy then re-slice from the owned buffer.
    var inst = types.Instruction{
        .address = address,
        .bytes = raw[0..@min(raw.len, decoded.length)],
        .mnemonic = decoded.mnemonic,
        .operands = &.{},
        .size = decoded.length,
    };
    const ops = decoded.getOperands();
    const copy_len: u8 = @intCast(@min(ops.len, 64));
    @memcpy(inst.operands_buf[0..copy_len], ops[0..copy_len]);
    inst.operands_len = copy_len;
    @memcpy(instruction_operands_scratch[0..copy_len], ops[0..copy_len]);
    inst.operands = instruction_operands_scratch[0..copy_len];
    return inst;
}

// ============================================================================
// Tests
// ============================================================================

test "decode RET" {
    const insn = [_]u8{0xC3};
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("ret", result.mnemonic);
    try std.testing.expect(result.is_return);
    try std.testing.expect(result.is_branch);
    try std.testing.expectEqual(@as(u8, 1), result.length);
}

// v7.8.1 H3: regression — decodeInstruction must populate the owned
// operands_buf so that operands survive the decoder's stack frame. The
// previous implementation returned a slice into the dying `decoded`
// stack local, which Database.addInstruction's fixup later turned into
// an empty string (since operands_len was zero), producing pseudocode
// like `xor ;`, `mov ;` for x86_64 ELF binaries (and Mach-O, latently).
test "H3: decodeInstruction populates owned operands buffer" {
    // 48 89 e5  mov rbp, rsp   -> "rbp, rsp"
    const bytes = [_]u8{ 0x48, 0x89, 0xe5 };
    const inst = decodeInstruction(&bytes, 0x1000);
    try std.testing.expectEqualStrings("mov", inst.mnemonic);
    try std.testing.expect(inst.operands_len > 0);
    try std.testing.expectEqualStrings("rbp, rsp", inst.operands_buf[0..inst.operands_len]);
    try std.testing.expectEqualStrings("rbp, rsp", inst.operands);

    // 31 c0  xor eax, eax  -> "eax, eax"
    const xor_bytes = [_]u8{ 0x31, 0xc0 };
    const xor_inst = decodeInstruction(&xor_bytes, 0x1000);
    try std.testing.expectEqualStrings("xor", xor_inst.mnemonic);
    try std.testing.expectEqualStrings("eax, eax", xor_inst.operands_buf[0..xor_inst.operands_len]);
    try std.testing.expectEqualStrings("eax, eax", xor_inst.operands);

    // 55  push rbp  -> "rbp"
    const push_bytes = [_]u8{0x55};
    const push_inst = decodeInstruction(&push_bytes, 0x1000);
    try std.testing.expectEqualStrings("push", push_inst.mnemonic);
    try std.testing.expectEqualStrings("rbp", push_inst.operands_buf[0..push_inst.operands_len]);

    // c3  ret  -> empty operands
    const ret_bytes = [_]u8{0xc3};
    const ret_inst = decodeInstruction(&ret_bytes, 0x1000);
    try std.testing.expectEqualStrings("ret", ret_inst.mnemonic);
    try std.testing.expectEqual(@as(u8, 0), ret_inst.operands_len);
}

test "decode NOP" {
    const insn = [_]u8{0x90};
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("nop", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 1), result.length);
}

test "decode PUSH rbp" {
    // 55 = push rbp
    const insn = [_]u8{0x55};
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("push", result.mnemonic);
    try std.testing.expectEqualStrings("rbp", result.getOperands());
    try std.testing.expectEqual(@as(u8, 1), result.length);
}

test "decode POP rbp" {
    // 5d = pop rbp
    const insn = [_]u8{0x5d};
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("pop", result.mnemonic);
    try std.testing.expectEqualStrings("rbp", result.getOperands());
}

test "decode CALL rel32" {
    // e8 fb ff ff ff = call -5 (relative to next insn)
    const insn = [_]u8{ 0xe8, 0xfb, 0xff, 0xff, 0xff };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("call", result.mnemonic);
    try std.testing.expect(result.is_call);
    try std.testing.expect(result.is_branch);
    try std.testing.expectEqual(@as(u8, 5), result.length);
    // target = 0x1000 + 5 + (-5) = 0x1000
    try std.testing.expectEqual(@as(?u64, 0x1000), result.branch_target);
}

test "decode JMP rel32" {
    // e9 0a 00 00 00 = jmp +10
    const insn = [_]u8{ 0xe9, 0x0a, 0x00, 0x00, 0x00 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("jmp", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(!result.is_call);
    try std.testing.expectEqual(@as(u8, 5), result.length);
    // target = 0x1000 + 5 + 10 = 0x100F
    try std.testing.expectEqual(@as(?u64, 0x100F), result.branch_target);
}

test "decode JMP rel8" {
    // eb 10 = jmp short +16
    const insn = [_]u8{ 0xeb, 0x10 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("jmp", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expectEqual(@as(u8, 2), result.length);
    // target = 0x1000 + 2 + 16 = 0x1012
    try std.testing.expectEqual(@as(?u64, 0x1012), result.branch_target);
}

test "decode JE rel8" {
    // 74 0a = je +10
    const insn = [_]u8{ 0x74, 0x0a };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("je", result.mnemonic);
    try std.testing.expect(result.is_branch);
    try std.testing.expect(result.is_conditional_branch);
    try std.testing.expectEqual(@as(?u64, 0x100C), result.branch_target);
}

test "decode JNE near rel32" {
    // 0f 85 00 01 00 00 = jne +256
    const insn = [_]u8{ 0x0f, 0x85, 0x00, 0x01, 0x00, 0x00 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("jne", result.mnemonic);
    try std.testing.expect(result.is_conditional_branch);
    // target = 0x1000 + 6 + 256 = 0x1106
    try std.testing.expectEqual(@as(?u64, 0x1106), result.branch_target);
}

test "decode MOV rdi, rsi (REX.W)" {
    // 48 89 f7 = mov rdi, rsi
    const insn = [_]u8{ 0x48, 0x89, 0xf7 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("mov", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 3), result.length);
}

test "decode MOV eax, imm32" {
    // b8 78 56 34 12 = mov eax, 0x12345678
    const insn = [_]u8{ 0xb8, 0x78, 0x56, 0x34, 0x12 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("mov", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 5), result.length);
}

test "decode MOV rax, imm64 (REX.W)" {
    // 48 b8 + 8 bytes imm64
    const insn = [_]u8{ 0x48, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("mov", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 10), result.length);
}

test "decode SUB rsp, imm8 (group1)" {
    // 48 83 ec 20 = sub rsp, 0x20
    const insn = [_]u8{ 0x48, 0x83, 0xec, 0x20 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("sub", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 4), result.length);
}

test "decode CMP eax, imm32 (group1)" {
    // 3d 00 01 00 00 = cmp eax, 0x100
    const insn = [_]u8{ 0x3d, 0x00, 0x01, 0x00, 0x00 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("cmp", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 5), result.length);
}

test "decode LEA rax, [rip + disp32]" {
    // 48 8d 05 10 00 00 00 = lea rax, [rip + 0x10]
    const insn = [_]u8{ 0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("lea", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 7), result.length);
}

test "decode SYSCALL" {
    const insn = [_]u8{ 0x0f, 0x05 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("syscall", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 2), result.length);
}

test "decode INT3" {
    const insn = [_]u8{0xCC};
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("int3", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 1), result.length);
}

test "decode LEAVE" {
    const insn = [_]u8{0xC9};
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("leave", result.mnemonic);
}

test "decode TEST al, imm8" {
    // a8 ff = test al, 0xff
    const insn = [_]u8{ 0xa8, 0xff };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("test", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 2), result.length);
}

test "decode XOR eax, eax" {
    // 31 c0 = xor eax, eax
    const insn = [_]u8{ 0x31, 0xc0 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("xor", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 2), result.length);
}

test "decode PUSH r12 (REX.B)" {
    // 41 54 = push r12
    const insn = [_]u8{ 0x41, 0x54 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("push", result.mnemonic);
    try std.testing.expectEqualStrings("r12", result.getOperands());
    try std.testing.expectEqual(@as(u8, 2), result.length);
}

test "decode CALL indirect [rax]" {
    // ff 10 = call [rax]
    const insn = [_]u8{ 0xff, 0x10 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("call", result.mnemonic);
    try std.testing.expect(result.is_call);
    try std.testing.expect(result.is_branch);
}

test "decode SHR eax, cl" {
    // d3 e8 = shr eax, cl
    const insn = [_]u8{ 0xd3, 0xe8 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("shr", result.mnemonic);
}

test "decode multi-byte NOP" {
    // 0f 1f 44 00 00 = nop dword ptr [rax + rax]
    const insn = [_]u8{ 0x0f, 0x1f, 0x44, 0x00, 0x00 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("nop", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 5), result.length);
}

test "decode MOVZX eax, byte ptr" {
    // 0f b6 00 = movzx eax, byte ptr [rax]
    const insn = [_]u8{ 0x0f, 0xb6, 0x00 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("movzx", result.mnemonic);
    try std.testing.expectEqual(@as(u8, 3), result.length);
}

test "decode UD2" {
    const insn = [_]u8{ 0x0f, 0x0b };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("ud2", result.mnemonic);
}

test "decode IMUL r, r/m" {
    // 0f af c1 = imul eax, ecx
    const insn = [_]u8{ 0x0f, 0xaf, 0xc1 };
    const result = decode(&insn, 0x1000);
    try std.testing.expectEqualStrings("imul", result.mnemonic);
}

test "variable length instructions" {
    // Verify we correctly determine instruction length for various encodings
    // 1-byte: ret (c3)
    try std.testing.expectEqual(@as(u8, 1), decode(&[_]u8{0xc3}, 0).length);
    // 2-byte: jmp rel8 (eb xx)
    try std.testing.expectEqual(@as(u8, 2), decode(&[_]u8{ 0xeb, 0x10 }, 0).length);
    // 5-byte: call rel32 (e8 xx xx xx xx)
    try std.testing.expectEqual(@as(u8, 5), decode(&[_]u8{ 0xe8, 0x00, 0x00, 0x00, 0x00 }, 0).length);
    // 3-byte: mov rdi, rsi (48 89 f7)
    try std.testing.expectEqual(@as(u8, 3), decode(&[_]u8{ 0x48, 0x89, 0xf7 }, 0).length);
}
