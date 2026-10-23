// Platform ABI defaults and bounded entry-prefix register-use evidence.
// This is not prototype recovery: custom, language/runtime and variadic
// conventions cannot be inferred from a container and architecture alone.
const std = @import("std");
const types = @import("../types.zig");
const ir = @import("../lifter/ir.zig");

pub const Profile = struct {
    name: []const u8 = "unknown",
    confidence: enum { unknown, platform_default } = .unknown,
    integer_args: []const []const u8 = &.{},
    floating_args: []const []const u8 = &.{},
    return_registers: []const []const u8 = &.{},
    stack_alignment: ?u8 = null,
    shadow_space_bytes: u8 = 0,
    reason: []const u8 = "Container and architecture do not establish a calling convention.",
};

const arm_args: []const []const u8 = &.{ "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7" };
const arm_fp: []const []const u8 = &.{ "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7" };
const x86_fp: []const []const u8 = &.{ "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7" };

pub fn profile(format: types.BinaryFormat, arch: types.Arch) Profile {
    const reason = "Platform C ABI default only; a function may use a language/runtime or custom convention. Register candidates are not a prototype.";
    if (arch == .arm64 and (format == .macho or format == .elf)) return .{
        .name = if (format == .macho) "darwin_aapcs64" else "aapcs64",
        .confidence = .platform_default,
        .integer_args = arm_args,
        .floating_args = arm_fp,
        .return_registers = &.{ "x0", "x1", "v0" },
        .stack_alignment = 16,
        .reason = reason,
    };
    if (arch == .x86_64 and format == .pe) return .{
        .name = "windows_x64",
        .confidence = .platform_default,
        .integer_args = &.{ "rcx", "rdx", "r8", "r9" },
        .floating_args = x86_fp[0..4],
        .return_registers = &.{ "rax", "xmm0" },
        .stack_alignment = 16,
        .shadow_space_bytes = 32,
        .reason = reason,
    };
    if (arch == .x86_64 and (format == .elf or format == .macho)) return .{
        .name = "sysv_amd64",
        .confidence = .platform_default,
        .integer_args = &.{ "rdi", "rsi", "rdx", "rcx", "r8", "r9" },
        .floating_args = x86_fp,
        .return_registers = &.{ "rax", "rdx", "xmm0" },
        .stack_alignment = 16,
        .reason = reason,
    };
    return .{};
}

pub fn profileForDocument(doc: *const types.Document) Profile {
    for (doc.segments) |segment| for (segment.sections) |section| {
        if (std.mem.eql(u8, section.name, ".gopclntab") or std.mem.eql(u8, section.name, "__gopclntab") or
            std.mem.eql(u8, section.name, ".go.buildinfo") or std.mem.eql(u8, section.name, "__go_buildinfo"))
            return .{ .reason = "Go runtime section evidence; the platform C ABI is not assumed for Go functions or wrappers." };
    };
    return profile(doc.format, doc.arch);
}

pub const CandidateArgument = struct {
    register: []const u8,
    first_read_address: u64,
    width: ?u8 = null,
};

/// Read-before-write evidence in a supplied, contiguous entry instruction
/// prefix. Stop at control flow, calls or an unmodeled instruction. No joins,
/// hidden arguments, stack parameters, varargs or callee prototypes are inferred.
/// The returned slice is allocator-owned; register names borrow the profile.
pub fn candidateArguments(allocator: std.mem.Allocator, instructions: []const types.Instruction, abi: Profile) ![]CandidateArgument {
    var out = std.array_list.Managed(CandidateArgument).init(allocator);
    errdefer out.deinit();
    if (abi.confidence == .unknown) return out.toOwnedSlice();
    var written: [16]bool = @splat(false);
    var observed: [16]bool = @splat(false);
    var next_address: ?u64 = null;
    for (instructions) |inst| {
        if (next_address) |address| if (inst.address != address) break;
        if (inst.size == 0) break;
        next_address = inst.address +| inst.size;
        const m = inst.mnemonic;
        if (eq(m, "nop") or eq(m, "paciasp") or eq(m, "pacibsp") or eq(m, "bti") or eq(m, "endbr64")) continue;
        // These branch instructions explicitly test a register before they
        // split control flow. Retain that read, then end the entry prefix.
        if (oneOf(m, &.{ "cbz", "cbnz", "tbz", "tbnz" })) {
            const tested = split(inst.operands);
            if (tested.count != 0) try noteReads(allocator, &out, tested.parts[0], inst.address, abi, &written, &observed);
            break;
        }
        const arm = abi.integer_args.len != 0 and abi.integer_args[0][0] == 'x';
        if (!arm and (eq(m, "push") or eq(m, "pop"))) {
            const operand = std.mem.trim(u8, inst.operands, " \t");
            // Only the ordinary GPR forms have modeled register effects.
            // Memory, immediate, flags and multi-operand forms remain barriers.
            const width = x86StackRegisterWidth(operand) orelse break;
            if (eq(m, "push")) {
                try noteReads(allocator, &out, operand, inst.address, abi, &written, &observed);
            } else if (candidateIndex(operand, abi)) |index| {
                // A 16-bit pop leaves the rest of its GPR unchanged.
                if (width == 8) written[index] = true;
            }
            continue;
        }
        const store = oneOf(m, &.{ "str", "strb", "strh", "stur", "sturb", "sturh", "stp" });
        const compare = oneOf(m, &.{ "cmp", "cmn", "tst", "test" });
        const pair_load = eq(m, "ldp");
        const load = oneOf(m, &.{ "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw" });
        const move = oneOf(m, &.{ "mov", "movzx", "movsx", "movsxd", "lea", "adr", "adrp" });
        const arithmetic = oneOf(m, &.{ "add", "sub", "and", "orr", "eor", "xor", "or", "lsl", "lsr", "asr", "shl", "shr", "sar" });
        if (!store and !compare and !pair_load and !load and !move and !arithmetic) break;
        // Updating an argument base is also a write; leave such instructions
        // outside this simple prefix analysis instead of ignoring writeback.
        if (std.mem.indexOfScalar(u8, inst.operands, '!') != null or std.mem.indexOf(u8, inst.operands, "],") != null) break;
        const operands = split(inst.operands);
        if (operands.count == 0) break;
        const first_memory = std.mem.indexOfScalar(u8, operands.parts[0], '[') != null;
        if (store or compare or first_memory) {
            for (operands.parts[0..operands.count]) |part| try noteReads(allocator, &out, part, inst.address, abi, &written, &observed);
        } else {
            const destinations: usize = if (pair_load) @min(@as(usize, 2), operands.count) else 1;
            // x86 two-operand arithmetic reads its destination unless it is a
            // proven self-zeroing xor/sub idiom.
            const self_zero = if (arm)
                operands.count == 3 and (eq(m, "eor") or eq(m, "sub")) and eq(operands.parts[1], operands.parts[2])
            else
                operands.count == 2 and (eq(m, "xor") or eq(m, "sub")) and eq(operands.parts[0], operands.parts[1]);
            if (!arm and arithmetic and !self_zero) try noteReads(allocator, &out, operands.parts[0], inst.address, abi, &written, &observed);
            if (!self_zero) for (operands.parts[destinations..operands.count]) |part| try noteReads(allocator, &out, part, inst.address, abi, &written, &observed);
            for (operands.parts[0..destinations]) |part| if (candidateIndex(part, abi)) |index| {
                // x86 byte/word writes leave the rest of the register intact.
                // Do not claim they define the whole parameter register.
                if (arm or (ir.registerWidth(part) orelse 0) >= 4 or index >= abi.integer_args.len)
                    written[index] = true;
            };
        }
    }
    return out.toOwnedSlice();
}

fn noteReads(allocator: std.mem.Allocator, out: *std.array_list.Managed(CandidateArgument), operand: []const u8, address: u64, abi: Profile, written: *[16]bool, observed: *[16]bool) !void {
    _ = allocator;
    var tokens = std.mem.tokenizeAny(u8, operand, " []()+-*,!#:\t");
    while (tokens.next()) |token| {
        const index = candidateIndex(token, abi) orelse continue;
        if (written[index] or observed[index]) continue;
        const reg = if (index < abi.integer_args.len) abi.integer_args[index] else abi.floating_args[index - abi.integer_args.len];
        try out.append(.{ .register = reg, .first_read_address = address, .width = ir.registerWidth(token) });
        observed[index] = true;
    }
}

fn x86StackRegisterWidth(operand: []const u8) ?u8 {
    const width = ir.registerWidth(operand) orelse return null;
    if (width == 8 and operand.len > 0 and std.ascii.toLower(operand[0]) == 'r') return width;
    if (width == 2 and (oneOf(operand, &.{ "ax", "bx", "cx", "dx", "si", "di", "bp", "sp" }) or
        (operand.len > 2 and std.ascii.toLower(operand[0]) == 'r'))) return width;
    return null;
}

fn candidateIndex(token: []const u8, abi: Profile) ?usize {
    for (abi.integer_args, 0..) |reg, i| if (sameRegister(token, reg)) return i;
    for (abi.floating_args, 0..) |reg, i| if (sameRegister(token, reg)) return abi.integer_args.len + i;
    return null;
}

fn sameRegister(token: []const u8, reg: []const u8) bool {
    if (eq(token, reg)) return true;
    if (reg.len >= 2 and (reg[0] == 'x' or reg[0] == 'v') and std.ascii.isDigit(reg[1])) {
        if (token.len < 2) return false;
        const c = std.ascii.toLower(token[0]);
        if (reg[0] == 'x' and c != 'x' and c != 'w') return false;
        if (reg[0] == 'v' and std.mem.indexOfScalar(u8, "vbhsdq", c) == null) return false;
        const end = std.mem.indexOfScalar(u8, token, '.') orelse token.len;
        return eq(token[1..end], reg[1..]);
    }
    const aliases = [_][]const []const u8{
        &.{ "rdi", "edi", "di", "dil" },      &.{ "rsi", "esi", "si", "sil" },
        &.{ "rdx", "edx", "dx", "dl", "dh" }, &.{ "rcx", "ecx", "cx", "cl", "ch" },
        &.{ "r8", "r8d", "r8w", "r8b" },      &.{ "r9", "r9d", "r9w", "r9b" },
    };
    for (aliases) |group| if (eq(group[0], reg)) {
        for (group[1..]) |alias| if (eq(token, alias)) return true;
    };
    return false;
}

const Operands = struct { parts: [4][]const u8 = @splat(""), count: usize = 0 };
fn split(text: []const u8) Operands {
    var result = Operands{};
    var depth: usize = 0;
    var start: usize = 0;
    for (text, 0..) |c, i| {
        if (c == '[' or c == '(') depth += 1;
        if ((c == ']' or c == ')') and depth > 0) depth -= 1;
        if (c == ',' and depth == 0) {
            if (result.count == result.parts.len) return .{};
            result.parts[result.count] = std.mem.trim(u8, text[start..i], " \t");
            result.count += 1;
            start = i + 1;
        }
    }
    if (depth != 0 or result.count == result.parts.len) return .{};
    result.parts[result.count] = std.mem.trim(u8, text[start..], " \t");
    if (result.parts[result.count].len != 0) result.count += 1;
    return result;
}
fn eq(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}
fn oneOf(m: []const u8, names: []const []const u8) bool {
    for (names) |name| if (eq(m, name)) return true;
    return false;
}

test "ABI defaults distinguish PE from SysV and raw stays unknown" {
    try std.testing.expectEqualStrings("windows_x64", profile(.pe, .x86_64).name);
    try std.testing.expectEqualStrings("rcx", profile(.pe, .x86_64).integer_args[0]);
    try std.testing.expectEqualStrings("rdi", profile(.elf, .x86_64).integer_args[0]);
    try std.testing.expect(profile(.raw, .arm64).confidence == .unknown);
}

test "ABI candidates respect writes aliases barriers and entry gaps" {
    const instructions = [_]types.Instruction{
        .{ .address = 0, .mnemonic = "mov", .operands = "w0, #1", .bytes = &.{}, .size = 4 },
        .{ .address = 4, .mnemonic = "add", .operands = "x9, x0, x1", .bytes = &.{}, .size = 4 },
        .{ .address = 8, .mnemonic = "ldr", .operands = "w2, [x3, #8]", .bytes = &.{}, .size = 4 },
        .{ .address = 12, .mnemonic = "bl", .operands = "0x100", .bytes = &.{}, .size = 4 },
        .{ .address = 16, .mnemonic = "mov", .operands = "x9, x4", .bytes = &.{}, .size = 4 },
    };
    const result = try candidateArguments(std.testing.allocator, &instructions, profile(.elf, .arm64));
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("x1", result[0].register);
    try std.testing.expectEqualStrings("x3", result[1].register);
    const gap = [_]types.Instruction{ instructions[0], instructions[2] };
    const gap_result = try candidateArguments(std.testing.allocator, &gap, profile(.elf, .arm64));
    defer std.testing.allocator.free(gap_result);
    try std.testing.expectEqual(@as(usize, 0), gap_result.len);
}

test "ABI self-zeroing x86 register is not an input argument" {
    const instructions = [_]types.Instruction{
        .{ .address = 0, .mnemonic = "xor", .operands = "ecx, ecx", .bytes = &.{}, .size = 2 },
        .{ .address = 2, .mnemonic = "mov", .operands = "rax, rcx", .bytes = &.{}, .size = 3 },
        .{ .address = 5, .mnemonic = "mov", .operands = "rax, rdx", .bytes = &.{}, .size = 3 },
    };
    const result = try candidateArguments(std.testing.allocator, &instructions, profile(.pe, .x86_64));
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("rdx", result[0].register);
}

test "ABI entry branch retains tested register then stops" {
    const instructions = [_]types.Instruction{
        .{ .address = 0, .mnemonic = "cbz", .operands = "w3, 0x10", .bytes = &.{}, .size = 4 },
        .{ .address = 4, .mnemonic = "mov", .operands = "x9, x4", .bytes = &.{}, .size = 4 },
    };
    const result = try candidateArguments(std.testing.allocator, &instructions, profile(.macho, .arm64));
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("x3", result[0].register);
    try std.testing.expectEqual(@as(?u8, 4), result[0].width);
}

test "ABI real Go section evidence disables the platform default" {
    var doc = types.Document.init(std.testing.allocator, 1, "unrelated-name", &.{});
    defer doc.deinit();
    doc.format = .elf;
    doc.arch = .x86_64;
    var sections = [_]types.Section{.{ .name = ".gopclntab", .start = 0, .length = 4 }};
    var segments = [_]types.Segment{.{ .name = "rodata", .start = 0, .length = 4, .sections = &sections, .permissions = .{ .read = true }, .file_offset = 0 }};
    doc.segments = &segments;
    try std.testing.expect(profileForDocument(&doc).confidence == .unknown);
}

test "ABI x86 frame prologue permits five SysV and four Windows register candidates" {
    const sysv = [_]types.Instruction{
        .{ .address = 0, .mnemonic = "push", .operands = "rbp", .bytes = &.{}, .size = 1 },
        .{ .address = 1, .mnemonic = "mov", .operands = "rbp, rsp", .bytes = &.{}, .size = 3 },
        .{ .address = 4, .mnemonic = "mov", .operands = "rax, rdi", .bytes = &.{}, .size = 3 },
        .{ .address = 7, .mnemonic = "add", .operands = "rax, rsi", .bytes = &.{}, .size = 3 },
        .{ .address = 10, .mnemonic = "add", .operands = "rax, rdx", .bytes = &.{}, .size = 3 },
        .{ .address = 13, .mnemonic = "add", .operands = "rax, rcx", .bytes = &.{}, .size = 3 },
        .{ .address = 16, .mnemonic = "add", .operands = "rax, r8", .bytes = &.{}, .size = 3 },
        .{ .address = 19, .mnemonic = "pop", .operands = "rbp", .bytes = &.{}, .size = 1 },
        .{ .address = 20, .mnemonic = "ret", .operands = "", .bytes = &.{}, .size = 1 },
    };
    const pe = [_]types.Instruction{
        sysv[0],                                                                                          sysv[1],
        .{ .address = 4, .mnemonic = "mov", .operands = "rax, rcx", .bytes = &.{}, .size = 3 },           .{ .address = 7, .mnemonic = "add", .operands = "rax, rdx", .bytes = &.{}, .size = 3 },
        .{ .address = 10, .mnemonic = "add", .operands = "rax, r8", .bytes = &.{}, .size = 3 },           .{ .address = 13, .mnemonic = "add", .operands = "rax, r9", .bytes = &.{}, .size = 3 },
        .{ .address = 16, .mnemonic = "add", .operands = "rax, [rbp + 0x30]", .bytes = &.{}, .size = 3 }, sysv[7],
        sysv[8],
    };
    const sysv_candidates = try candidateArguments(std.testing.allocator, &sysv, profile(.elf, .x86_64));
    defer std.testing.allocator.free(sysv_candidates);
    try std.testing.expectEqual(@as(usize, 5), sysv_candidates.len);
    for (sysv_candidates, 0..) |candidate, i| try std.testing.expectEqualStrings(profile(.elf, .x86_64).integer_args[i], candidate.register);
    const pe_candidates = try candidateArguments(std.testing.allocator, &pe, profile(.pe, .x86_64));
    defer std.testing.allocator.free(pe_candidates);
    try std.testing.expectEqual(@as(usize, 4), pe_candidates.len);
    for (pe_candidates, 0..) |candidate, i| try std.testing.expectEqualStrings(profile(.pe, .x86_64).integer_args[i], candidate.register);
}

test "ABI x86 push reads and pop writes without inventing stack parameters" {
    const instructions = [_]types.Instruction{
        .{ .address = 0, .mnemonic = "push", .operands = "rsp", .bytes = &.{}, .size = 1 },
        .{ .address = 1, .mnemonic = "push", .operands = "rdi", .bytes = &.{}, .size = 1 },
        .{ .address = 2, .mnemonic = "pop", .operands = "rsi", .bytes = &.{}, .size = 1 },
        .{ .address = 3, .mnemonic = "mov", .operands = "rax, rsi", .bytes = &.{}, .size = 3 },
        .{ .address = 6, .mnemonic = "pop", .operands = "cx", .bytes = &.{}, .size = 2 },
        .{ .address = 8, .mnemonic = "mov", .operands = "rax, rcx", .bytes = &.{}, .size = 3 },
    };
    const candidates = try candidateArguments(std.testing.allocator, &instructions, profile(.elf, .x86_64));
    defer std.testing.allocator.free(candidates);
    try std.testing.expectEqual(@as(usize, 2), candidates.len);
    try std.testing.expectEqualStrings("rdi", candidates[0].register);
    try std.testing.expectEqual(@as(u64, 1), candidates[0].first_read_address);
    try std.testing.expectEqualStrings("rcx", candidates[1].register);
}

test "ABI unsupported x86 stack forms remain prefix barriers" {
    const examples = [_]struct { mnemonic: []const u8, operands: []const u8 }{
        .{ .mnemonic = "push", .operands = "qword ptr [rdi]" },
        .{ .mnemonic = "pop", .operands = "[rdi]" },
        .{ .mnemonic = "push", .operands = "0x10" },
        .{ .mnemonic = "pushfq", .operands = "" },
        .{ .mnemonic = "popfq", .operands = "" },
        .{ .mnemonic = "push", .operands = "rbp, rdi" },
        .{ .mnemonic = "push", .operands = "x0" },
        .{ .mnemonic = "push", .operands = "h0" },
    };
    for (examples) |example| {
        const instructions = [_]types.Instruction{
            .{ .address = 0, .mnemonic = example.mnemonic, .operands = example.operands, .bytes = &.{}, .size = 1 },
            .{ .address = 1, .mnemonic = "mov", .operands = "rax, rdi", .bytes = &.{}, .size = 3 },
        };
        const candidates = try candidateArguments(std.testing.allocator, &instructions, profile(.elf, .x86_64));
        defer std.testing.allocator.free(candidates);
        try std.testing.expectEqual(@as(usize, 0), candidates.len);
    }
}
