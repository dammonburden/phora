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

/// Build a Variable from a register name.
pub fn variableFromRegister(reg: []const u8) Variable {
    return .{
        .name = registerToVariable(reg),
        .register = reg,
        .type_name = if (reg.len > 0 and (reg[0] == 'w' or reg[0] == 'W'))
            "uint32_t"
        else
            "uint64_t",
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
