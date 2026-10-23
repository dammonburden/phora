// Phora — IR Types
// Intermediate representation for lifted assembly.
// These types are defined in types.zig (IRStatement, IRFunction, Variable).
// This module re-exports them and adds IR-specific utilities.

const std = @import("std");
const types = @import("../types.zig");

// Re-export core IR types
pub const IRStatement = types.IRStatement;
pub const IRStatementType = types.IRStatementType;
pub const IRFunction = types.IRFunction;
pub const Variable = types.Variable;

/// Create an assign statement: dest = src
pub fn assign(address: u64, dest: []const u8, src: []const u8) IRStatement {
    return .{
        .type = .assign,
        .address = address,
        .dest = dest,
        .src = src,
    };
}

/// Create a call statement: dest = target(args...)
pub fn call(address: u64, target: []const u8, args: ?[]const []const u8, dest: ?[]const u8) IRStatement {
    return .{
        .type = .call,
        .address = address,
        .target = target,
        .args = args,
        .dest = dest,
    };
}

/// Create a compare statement: op(dest, src)
pub fn compare(address: u64, op: []const u8, dest: []const u8, src: []const u8) IRStatement {
    return .{
        .type = .compare,
        .address = address,
        .op = op,
        .dest = dest,
        .src = src,
    };
}

/// Create a branch statement: if condition goto true_block else false_block
pub fn branch(address: u64, condition: ?[]const u8, true_block: ?u32, false_block: ?u32) IRStatement {
    return .{
        .type = .branch,
        .address = address,
        .condition = condition,
        .true_block = true_block,
        .false_block = false_block,
    };
}

/// Create a return statement.
pub fn ret(address: u64, src: ?[]const u8) IRStatement {
    return .{
        .type = .@"return",
        .address = address,
        .src = src,
    };
}

/// Create a load statement: dest = [src]
pub fn load(address: u64, dest: []const u8, src: []const u8) IRStatement {
    return .{
        .type = .load,
        .address = address,
        .dest = dest,
        .src = src,
    };
}

/// Create a store statement: [dest] = src
pub fn store(address: u64, dest: []const u8, src: []const u8) IRStatement {
    return .{
        .type = .store,
        .address = address,
        .dest = dest,
        .src = src,
    };
}

/// Create a nop statement.
pub fn nop(address: u64) IRStatement {
    return .{
        .type = .nop,
        .address = address,
    };
}

/// Preserve an instruction whose full effects are not modeled. This is a
/// dataflow barrier, never an assignment to the first textual operand.
pub fn opaqueInstruction(address: u64, mnemonic: []const u8, operands: []const u8) IRStatement {
    return .{ .type = .@"opaque", .address = address, .op = mnemonic, .src = operands };
}

pub const MemoryEvidence = struct {
    width: ?u8 = null,
    signedness: types.MemorySignedness = .unknown,
};

/// Register storage width, never inferred from a renamed variable. A q-register
/// is 16 bytes; the transfer width of extending loads is handled separately.
pub fn registerWidth(reg: []const u8) ?u8 {
    if (eqlI(reg, "xzr")) return 8;
    if (eqlI(reg, "wzr")) return 4;
    if (reg.len < 2) return null;
    const prefix = std.ascii.toLower(reg[0]);
    if (std.mem.indexOfScalar(u8, "wxbhsdqv", prefix) != null and std.ascii.isDigit(reg[1])) {
        const end = std.mem.indexOfScalar(u8, reg, '.') orelse reg.len;
        const n = std.fmt.parseInt(u8, reg[1..end], 10) catch return null;
        if (n > 31) return null;
        return switch (prefix) {
            'b' => 1,
            'h' => 2,
            'w', 's' => 4,
            'x', 'd' => 8,
            'q', 'v' => 16,
            else => null,
        };
    }
    const groups = [_]struct { width: u8, names: []const []const u8 }{
        .{ .width = 8, .names = &.{ "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp" } },
        .{ .width = 4, .names = &.{ "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" } },
        .{ .width = 2, .names = &.{ "ax", "bx", "cx", "dx", "si", "di", "bp", "sp" } },
        .{ .width = 1, .names = &.{ "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl", "spl" } },
    };
    for (groups) |g| for (g.names) |name| {
        if (eqlI(reg, name)) return g.width;
    };
    if (prefix == 'r' and std.ascii.isDigit(reg[1])) {
        var end = reg.len;
        const last = std.ascii.toLower(reg[end - 1]);
        const width: u8 = switch (last) {
            'b' => 1,
            'w' => 2,
            'd' => 4,
            else => 8,
        };
        if (width != 8) end -= 1;
        const n = std.fmt.parseInt(u8, reg[1..end], 10) catch return null;
        if (n >= 8 and n <= 15) return width;
    }
    return null;
}

pub fn memoryOperandWidth(operand: []const u8) ?u8 {
    // Test longer prefixes first: "word ptr" occurs inside "qword ptr".
    const hints = [_]struct { text: []const u8, width: u8 }{
        .{ .text = "zmmword ptr", .width = 64 }, .{ .text = "ymmword ptr", .width = 32 },
        .{ .text = "xmmword ptr", .width = 16 }, .{ .text = "qword ptr", .width = 8 },
        .{ .text = "dword ptr", .width = 4 },    .{ .text = "word ptr", .width = 2 },
        .{ .text = "byte ptr", .width = 1 },
    };
    for (hints) |h| if (std.mem.indexOf(u8, operand, h.text) != null) return h.width;
    return null;
}

/// Evidence about a single memory transfer. Pair, writeback and partial MIPS
/// transfers remain unknown rather than inventing a field width.
pub fn memoryEvidence(mnemonic: []const u8, operands: []const u8) MemoryEvidence {
    if (std.mem.indexOfScalar(u8, operands, '[') == null and
        std.mem.indexOfScalar(u8, operands, '(') == null) return .{};
    if (eqlI(mnemonic, "ldp") or eqlI(mnemonic, "stp") or
        std.mem.indexOfScalar(u8, operands, '!') != null or
        (std.mem.indexOf(u8, operands, "],") != null and
            (std.mem.indexOfScalar(u8, operands, ',') orelse operands.len) < (std.mem.indexOfScalar(u8, operands, '[') orelse 0))) return .{};
    const first = std.mem.trim(u8, operands[0 .. std.mem.indexOfScalar(u8, operands, ',') orelse operands.len], " \t");
    const signed = eqlI(mnemonic, "ldrsb") or eqlI(mnemonic, "ldrsh") or eqlI(mnemonic, "ldrsw") or
        eqlI(mnemonic, "ldursb") or eqlI(mnemonic, "ldursh") or eqlI(mnemonic, "ldursw") or
        eqlI(mnemonic, "lb") or eqlI(mnemonic, "lh") or eqlI(mnemonic, "movsx") or eqlI(mnemonic, "movsxd");
    const unsigned = eqlI(mnemonic, "ldrb") or eqlI(mnemonic, "ldrh") or eqlI(mnemonic, "ldurb") or
        eqlI(mnemonic, "ldurh") or eqlI(mnemonic, "lbu") or eqlI(mnemonic, "lhu") or eqlI(mnemonic, "movzx");
    const sign: types.MemorySignedness = if (signed) .signed else if (unsigned) .unsigned else .unknown;
    if (eqlI(mnemonic, "ldrb") or eqlI(mnemonic, "ldrsb") or eqlI(mnemonic, "strb") or
        eqlI(mnemonic, "ldurb") or eqlI(mnemonic, "ldursb") or eqlI(mnemonic, "sturb") or
        eqlI(mnemonic, "lb") or eqlI(mnemonic, "lbu") or eqlI(mnemonic, "sb")) return .{ .width = 1, .signedness = sign };
    if (eqlI(mnemonic, "ldrh") or eqlI(mnemonic, "ldrsh") or eqlI(mnemonic, "strh") or
        eqlI(mnemonic, "ldurh") or eqlI(mnemonic, "ldursh") or eqlI(mnemonic, "sturh") or
        eqlI(mnemonic, "lh") or eqlI(mnemonic, "lhu") or eqlI(mnemonic, "sh")) return .{ .width = 2, .signedness = sign };
    if (eqlI(mnemonic, "ldrsw") or eqlI(mnemonic, "ldursw") or eqlI(mnemonic, "movsxd") or
        eqlI(mnemonic, "lw") or eqlI(mnemonic, "sw") or eqlI(mnemonic, "lwc1") or eqlI(mnemonic, "swc1")) return .{ .width = 4, .signedness = sign };
    if (eqlI(mnemonic, "ldr") or eqlI(mnemonic, "str") or eqlI(mnemonic, "ldur") or eqlI(mnemonic, "stur"))
        return .{ .width = registerWidth(first), .signedness = sign };
    if (eqlI(mnemonic, "mov") or eqlI(mnemonic, "movzx") or eqlI(mnemonic, "movsx") or
        eqlI(mnemonic, "cmp") or eqlI(mnemonic, "test"))
    {
        if (memoryOperandWidth(operands)) |width| return .{ .width = width, .signedness = sign };
        // Extending moves need the source width, not the wider destination.
        if (eqlI(mnemonic, "movzx") or eqlI(mnemonic, "movsx")) return .{};
        if (registerWidth(first)) |width| return .{ .width = width };
        const comma = std.mem.lastIndexOfScalar(u8, operands, ',') orelse return .{};
        return .{ .width = registerWidth(std.mem.trim(u8, operands[comma + 1 ..], " \t")) };
    }
    return .{};
}

pub fn hasVectorOrFpOperand(operands: []const u8) bool {
    var tokens = std.mem.tokenizeAny(u8, operands, " ,[]!\t");
    while (tokens.next()) |tok| {
        if (tok.len < 2) continue;
        const c = std.ascii.toLower(tok[0]);
        if (std.mem.indexOfScalar(u8, "vbhsdq", c) != null and std.ascii.isDigit(tok[1]) and registerWidth(tok) != null) return true;
        if (std.mem.startsWith(u8, tok, "xmm") or std.mem.startsWith(u8, tok, "ymm") or std.mem.startsWith(u8, tok, "zmm")) return true;
    }
    return false;
}

/// ARM64 register to variable name mapping.
/// W-registers (32-bit views) get a "_32" suffix to distinguish from X-registers.
pub fn registerToVariable(reg: []const u8) []const u8 {
    // Check special-case registers first
    if (std.mem.eql(u8, reg, "sp") or std.mem.eql(u8, reg, "SP")) return "stack_ptr";
    if (std.mem.eql(u8, reg, "xzr") or std.mem.eql(u8, reg, "XZR") or
        std.mem.eql(u8, reg, "wzr") or std.mem.eql(u8, reg, "WZR"))
    {
        return "zero";
    }

    // X0-X7 / W0-W7: function arguments
    if (reg.len >= 2 and (reg[0] == 'x' or reg[0] == 'X' or reg[0] == 'w' or reg[0] == 'W')) {
        const is_32bit = (reg[0] == 'w' or reg[0] == 'W');
        const num_str = reg[1..];
        const num = std.fmt.parseInt(u8, num_str, 10) catch return reg;
        if (num <= 7) {
            if (is_32bit) {
                const arg_names_32 = [_][]const u8{ "arg0_32", "arg1_32", "arg2_32", "arg3_32", "arg4_32", "arg5_32", "arg6_32", "arg7_32" };
                return arg_names_32[num];
            }
            const arg_names = [_][]const u8{ "arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7" };
            return arg_names[num];
        }
        if (num == 8) return if (is_32bit) "indirect_result_32" else "indirect_result";
        if (num >= 9 and num <= 15) {
            if (is_32bit) {
                const tmp_names_32 = [_][]const u8{ "tmp0_32", "tmp1_32", "tmp2_32", "tmp3_32", "tmp4_32", "tmp5_32", "tmp6_32" };
                return tmp_names_32[num - 9];
            }
            const tmp_names = [_][]const u8{ "tmp0", "tmp1", "tmp2", "tmp3", "tmp4", "tmp5", "tmp6" };
            return tmp_names[num - 9];
        }
        if (num >= 19 and num <= 28) {
            if (is_32bit) {
                const saved_names_32 = [_][]const u8{ "saved_w19", "saved_w20", "saved_w21", "saved_w22", "saved_w23", "saved_w24", "saved_w25", "saved_w26", "saved_w27", "saved_w28" };
                return saved_names_32[num - 19];
            }
            const saved_names = [_][]const u8{ "saved_x19", "saved_x20", "saved_x21", "saved_x22", "saved_x23", "saved_x24", "saved_x25", "saved_x26", "saved_x27", "saved_x28" };
            return saved_names[num - 19]; // callee-saved
        }
        if (num == 29) return if (is_32bit) "frame_ptr_32" else "frame_ptr";
        if (num == 30) return if (is_32bit) "link_reg_32" else "link_reg";
    }
    return reg;
}

/// x86_64 (System V AMD64 ABI) register to variable name mapping.
/// Arguments: RDI, RSI, RDX, RCX, R8, R9. Return: RAX. Frame: RBP. Stack: RSP.
pub fn x86_64RegisterToVariable(reg: []const u8) []const u8 {
    // Strip "qword ptr" / "dword ptr" / size prefixes if present
    const r = if (std.mem.indexOf(u8, reg, "ptr")) |_| return reg else reg;

    if (eqlI(r, "rdi") or eqlI(r, "edi") or eqlI(r, "di")) return "arg0";
    if (eqlI(r, "rsi") or eqlI(r, "esi") or eqlI(r, "si")) return "arg1";
    if (eqlI(r, "rdx") or eqlI(r, "edx") or eqlI(r, "dx")) return "arg2";
    if (eqlI(r, "rcx") or eqlI(r, "ecx") or eqlI(r, "cx")) return "arg3";
    if (eqlI(r, "r8") or eqlI(r, "r8d") or eqlI(r, "r8w")) return "arg4";
    if (eqlI(r, "r9") or eqlI(r, "r9d") or eqlI(r, "r9w")) return "arg5";
    if (eqlI(r, "rax") or eqlI(r, "eax") or eqlI(r, "al") or eqlI(r, "ax")) return "result";
    if (eqlI(r, "rsp") or eqlI(r, "esp")) return "stack_ptr";
    if (eqlI(r, "rbp") or eqlI(r, "ebp")) return "frame_ptr";
    if (eqlI(r, "rbx") or eqlI(r, "ebx")) return "saved_rbx";
    if (eqlI(r, "r10") or eqlI(r, "r10d")) return "tmp0";
    if (eqlI(r, "r11") or eqlI(r, "r11d")) return "tmp1";
    if (eqlI(r, "r12") or eqlI(r, "r12d")) return "saved_r12";
    if (eqlI(r, "r13") or eqlI(r, "r13d")) return "saved_r13";
    if (eqlI(r, "r14") or eqlI(r, "r14d")) return "saved_r14";
    if (eqlI(r, "r15") or eqlI(r, "r15d")) return "saved_r15";
    return reg;
}

fn eqlI(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Identify overlapping architectural views without equating their values.
/// This is used for read liveness and clobbers, never for ABI positions.
pub fn registerFamily(reg: []const u8) ?u8 {
    if (reg.len >= 2 and (reg[0] == 'w' or reg[0] == 'x')) {
        const n = std.fmt.parseInt(u8, reg[1..], 10) catch return null;
        if (n <= 30) return n;
        return null;
    }
    const groups = [_][]const []const u8{
        &.{ "rax", "eax", "ax", "al", "ah" },
        &.{ "rbx", "ebx", "bx", "bl", "bh" },
        &.{ "rcx", "ecx", "cx", "cl", "ch" },
        &.{ "rdx", "edx", "dx", "dl", "dh" },
        &.{ "rsi", "esi", "si", "sil" },
        &.{ "rdi", "edi", "di", "dil" },
        &.{ "rbp", "ebp", "bp", "bpl" },
        &.{ "rsp", "esp", "sp", "spl" },
    };
    for (groups, 0..) |names, i| for (names) |name| {
        if (eqlI(reg, name)) return @intCast(32 + i);
    };
    if (reg.len >= 2 and reg[0] == 'r' and registerWidth(reg) != null) {
        const end = if (std.ascii.isDigit(reg[reg.len - 1])) reg.len else reg.len - 1;
        const n = std.fmt.parseInt(u8, reg[1..end], 10) catch return null;
        if (n >= 8 and n <= 15) return 32 + n;
    }
    return null;
}

/// Build a Variable from a register name.
pub fn variableFromRegister(reg: []const u8) Variable {
    return .{
        .name = reg,
        .register = reg,
        // Register storage alone does not prove a source-language integer type.
        .type_name = null,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "register to variable mapping" {
    try std.testing.expectEqualStrings("arg0", registerToVariable("x0"));
    try std.testing.expectEqualStrings("arg0", registerToVariable("X0"));
    try std.testing.expectEqualStrings("arg7", registerToVariable("x7"));
    try std.testing.expectEqualStrings("indirect_result", registerToVariable("x8"));
    try std.testing.expectEqualStrings("frame_ptr", registerToVariable("x29"));
    try std.testing.expectEqualStrings("link_reg", registerToVariable("x30"));
    try std.testing.expectEqualStrings("stack_ptr", registerToVariable("sp"));
    try std.testing.expectEqualStrings("zero", registerToVariable("xzr"));
    // 32-bit variants get _32 suffix
    try std.testing.expectEqualStrings("arg0_32", registerToVariable("w0"));
    try std.testing.expectEqualStrings("indirect_result_32", registerToVariable("w8"));
    try std.testing.expectEqualStrings("saved_w23", registerToVariable("w23"));
}

test "create IR statements" {
    const a = assign(0x1000, "arg0", "42");
    try std.testing.expectEqual(IRStatementType.assign, a.type);
    try std.testing.expectEqualStrings("arg0", a.dest.?);

    const c = call(0x1004, "printf", null, null);
    try std.testing.expectEqual(IRStatementType.call, c.type);
    try std.testing.expectEqualStrings("printf", c.target.?);

    const r = ret(0x1008, "arg0");
    try std.testing.expectEqual(IRStatementType.@"return", r.type);
    try std.testing.expectEqualStrings("arg0", r.src.?);
}

test "memory evidence uses transfer width before aliases and preserves q width" {
    const t = std.testing;
    try t.expectEqual(@as(?u8, 4), memoryEvidence("ldr", "w0, [x1, #4]").width);
    try t.expectEqual(@as(?u8, 8), memoryEvidence("str", "x0, [x1, #8]").width);
    try t.expectEqual(@as(?u8, 16), memoryEvidence("ldur", "q0, [x1, #-16]").width);
    const signed_byte = memoryEvidence("ldrsb", "x0, [x1]");
    try t.expectEqual(@as(?u8, 1), signed_byte.width);
    try t.expect(signed_byte.signedness == .signed);
    try t.expect(memoryEvidence("ldrh", "w0, [x1]").signedness == .unsigned);
    try t.expectEqual(@as(?u8, 1), memoryEvidence("movsx", "rax, byte ptr [rcx]").width);
    try t.expect(memoryEvidence("movsx", "rax, [rcx]").width == null);
    try t.expectEqual(@as(?u8, 4), memoryEvidence("mov", "dword ptr [rcx], eax").width);
    try t.expect(memoryEvidence("ldp", "q0, q1, [x2]").width == null);
    try t.expect(memoryEvidence("ldr", "x0, [x1], #8").width == null);
    try t.expect(registerWidth("arg0") == null);
    try t.expect(registerWidth("local_1") == null);
    try t.expect(registerWidth("x99") == null);
    try t.expectEqual(@as(?u8, 1), registerWidth("al"));
    try t.expectEqual(@as(?u8, 2), registerWidth("ax"));
    try t.expect(hasVectorOrFpOperand("v0.16b, v1.16b, v2.16b"));
    try t.expect(hasVectorOrFpOperand("s0, s1, s2"));
    try t.expect(!hasVectorOrFpOperand("x0, x1, x2"));
}

test "evidence: x86 byte and word views are not ARM vector registers" {
    try std.testing.expectEqual(@as(?u8, 1), registerWidth("bl"));
    try std.testing.expectEqual(@as(?u8, 1), registerWidth("sil"));
    try std.testing.expectEqual(@as(?u8, 2), registerWidth("bx"));
    try std.testing.expectEqual(@as(?u8, 2), registerWidth("dx"));
    try std.testing.expect(!hasVectorOrFpOperand("bl, sil"));
    try std.testing.expect(hasVectorOrFpOperand("b0, [x0]"));
}
