// Phora — Dead Store Elimination Pass
// Removes assignments whose result is overwritten before being read, within a
// single basic block. Stops scanning at branch/call/return (block boundaries).
// Conservative: never removes call/store/compare (side effects).

const std = @import("std");
const types = @import("../../types.zig");
const util = @import("pass_util.zig");
const ir = @import("../ir.zig");

/// Apply dead-store elimination to a function in place. Replaces
/// `func.statements` with a new slice excluding dead stores.
pub fn run(allocator: std.mem.Allocator, func: *types.IRFunction) !void {
    if (func.statements.len == 0) return;

    var dead = try std.DynamicBitSet.initEmpty(allocator, func.statements.len);
    defer dead.deinit();

    for (func.statements, 0..) |stmt, i| {
        if (!isCandidate(stmt)) continue;
        const dest = stmt.dest orelse continue;

        // Scan forward in same block.
        var j: usize = i + 1;
        while (j < func.statements.len) : (j += 1) {
            const next = func.statements[j];

            // Hard block boundary — stop. Variable might be read after.
            if (next.block_start or isBlockBoundary(next)) {
                // Last chance: if the boundary itself reads dest, keep stmt i.
                if (util.stmtReads(next, dest)) break;
                // Conservative: assume dest may be read in a successor block.
                break;
            }

            if (readsWithRegisterAliases(func, next, dest)) {
                // dest is consumed before any overwrite — stmt i is live.
                break;
            }
            if (util.stmtWrites(next, dest)) {
                // dest overwritten with no intervening read — stmt i is dead,
                // BUT only if stmt i has no side effect itself (already filtered
                // by isCandidate).
                dead.set(i);
                break;
            }
        }
    }

    // Build new slice excluding dead statements.
    const live_count = func.statements.len - dead.count();
    if (live_count == func.statements.len) return; // Nothing to remove.

    const new_stmts = try allocator.alloc(types.IRStatement, live_count);
    var w: usize = 0;
    var pending_block_start = false;
    for (func.statements, 0..) |stmt, i| {
        pending_block_start = pending_block_start or stmt.block_start;
        if (dead.isSet(i)) continue;
        new_stmts[w] = stmt;
        new_stmts[w].block_start = pending_block_start;
        pending_block_start = false;
        w += 1;
    }
    func.statements = new_stmts;
}

fn readsWithRegisterAliases(func: *const types.IRFunction, stmt: types.IRStatement, variable: []const u8) bool {
    if (util.stmtReads(stmt, variable)) return true;
    if (ir.registerFamily(variable)) |family| {
        // A register read may use an untracked source view, including inside
        // LEA/memory brackets. Token scanning covers those expressions too.
        const views = [_][]const u8{ "rax", "eax", "ax", "al", "ah", "rbx", "ebx", "bx", "bl", "bh", "rcx", "ecx", "cx", "cl", "ch", "rdx", "edx", "dx", "dl", "dh", "rsi", "esi", "si", "sil", "rdi", "edi", "di", "dil", "rbp", "ebp", "bp", "bpl", "rsp", "esp", "sp", "spl" };
        for (views) |view| if (ir.registerFamily(view) == family and util.stmtReads(stmt, view)) return true;
        var buf: [8]u8 = undefined;
        if (family <= 30) {
            for ([_]u8{ 'w', 'x' }) |prefix| {
                const view = std.fmt.bufPrint(&buf, "{c}{d}", .{ prefix, family }) catch continue;
                if (util.stmtReads(stmt, view)) return true;
            }
        } else if (family >= 40 and family <= 47) {
            for ([_][]const u8{ "", "d", "w", "b" }) |suffix| {
                const view = std.fmt.bufPrint(&buf, "r{d}{s}", .{ family - 32, suffix }) catch continue;
                if (util.stmtReads(stmt, view)) return true;
            }
        }
    }
    // Memory operands retain architectural register spellings. Keep a value
    // when its register (or its W/X view) occurs in any expression.
    for (func.variables) |v| {
        if (!std.mem.eql(u8, v.name, variable)) continue;
        const reg = v.register orelse continue;
        if (util.stmtReads(stmt, reg)) return true;
        if (reg.len >= 2 and (reg[0] == 'w' or reg[0] == 'x')) {
            var alias_buf: [8]u8 = undefined;
            if (reg.len <= alias_buf.len) {
                @memcpy(alias_buf[0..reg.len], reg);
                alias_buf[0] = if (reg[0] == 'w') 'x' else 'w';
                if (util.stmtReads(stmt, alias_buf[0..reg.len])) return true;
            }
            const wide = if (std.mem.endsWith(u8, variable, "_32")) variable[0 .. variable.len - 3] else variable;
            if (util.stmtReads(stmt, wide)) return true;
            for (func.variables) |other| {
                const other_reg = other.register orelse continue;
                if (other_reg.len == reg.len and std.mem.eql(u8, other_reg[1..], reg[1..]) and
                    (other_reg[0] == 'w' or other_reg[0] == 'x') and util.stmtReads(stmt, other.name)) return true;
            }
        }
    }
    return false;
}

/// A statement is a candidate for elimination if it pure-defines `dest` and
/// has no observable side effect beyond that definition.
/// load is technically side-effect-free in our IR (no MMIO modeling), but
/// loads can fault — conservatively keep them.
fn isCandidate(stmt: types.IRStatement) bool {
    return switch (stmt.type) {
        .assign => stmt.dest != null and (stmt.op == null or !std.mem.eql(u8, stmt.op.?, "writes_flags")),
        .load, .call, .compare, .store, .branch, .@"return", .nop, .@"opaque" => false,
    };
}

/// Hard block boundaries — we never reason past these.
fn isBlockBoundary(stmt: types.IRStatement) bool {
    return switch (stmt.type) {
        .branch, .call, .@"return", .@"opaque" => true,
        else => false,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "dead_store removes overwritten assign" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "1" },
        .{ .type = .assign, .address = 4, .dest = "x", .src = "2" },
        .{ .type = .@"return", .address = 8, .src = "x" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    try run(a, &func);
    defer a.free(func.statements);
    try std.testing.expectEqual(@as(usize, 2), func.statements.len);
    try std.testing.expectEqualStrings("2", func.statements[0].src.?);
}

test "dead_store keeps live store" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "1" },
        .{ .type = .assign, .address = 4, .dest = "y", .src = "x" },
        .{ .type = .assign, .address = 8, .dest = "x", .src = "2" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    const orig_len = func.statements.len;
    try run(a, &func);
    // x = 1 is read by y = x, so it must be kept. No dead stores.
    try std.testing.expectEqual(orig_len, func.statements.len);
}

test "dead_store does not cross block boundary" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "1" },
        .{ .type = .branch, .address = 4, .condition = "cond", .true_block = 1, .false_block = 2 },
        .{ .type = .assign, .address = 8, .dest = "x", .src = "2" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    const orig_len = func.statements.len;
    try run(a, &func);
    // Must not delete x=1 — branch could lead to a block that reads x.
    try std.testing.expectEqual(orig_len, func.statements.len);
}

test "dead_store preserves call statements" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .call, .address = 0, .target = "side_effect", .dest = "x" },
        .{ .type = .assign, .address = 4, .dest = "x", .src = "0" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    const orig_len = func.statements.len;
    try run(a, &func);
    // Call has side effects — keep it even though x is overwritten.
    try std.testing.expectEqual(orig_len, func.statements.len);
}

test "dead_store handles empty function" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{};
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    try run(a, &func);
    try std.testing.expectEqual(@as(usize, 0), func.statements.len);
}

test "dead_store removes multiple dead stores" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "1" },
        .{ .type = .assign, .address = 4, .dest = "x", .src = "2" },
        .{ .type = .assign, .address = 8, .dest = "x", .src = "3" },
        .{ .type = .@"return", .address = 12, .src = "x" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    try run(a, &func);
    defer a.free(func.statements);
    // x=1 dead (overwritten by x=2), x=2 dead (overwritten by x=3), x=3 live.
    try std.testing.expectEqual(@as(usize, 2), func.statements.len);
    try std.testing.expectEqualStrings("3", func.statements[0].src.?);
}

test "evidence: dead store keeps arithmetic and address dependencies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "tmp0", .src = "input" },
        .{ .type = .assign, .address = 4, .dest = "y", .src = "tmp0 + #1" },
        .{ .type = .assign, .address = 8, .dest = "tmp0", .src = "other" },
        .{ .type = .load, .address = 12, .dest = "z", .src = "[x9, #8]" },
        .{ .type = .assign, .address = 16, .dest = "tmp0", .src = "last" },
    };
    var variables = [_]types.Variable{.{ .name = "tmp0", .register = "x9" }};
    var func = types.IRFunction{ .address = 0, .statements = &stmts, .variables = &variables };
    try run(arena.allocator(), &func);
    try std.testing.expectEqual(@as(usize, 5), func.statements.len);
}

test "evidence: dead store preserves predecessor definition at join" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "one" },
        .{ .type = .assign, .address = 4, .dest = "x", .src = "two", .block_start = true },
    };
    var func = types.IRFunction{ .address = 0, .statements = &stmts, .variables = &.{} };
    try run(arena.allocator(), &func);
    try std.testing.expectEqual(@as(usize, 2), func.statements.len);
}

test "evidence: physical register alias reads in addresses preserve narrow writes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "eax", .src = "input" },
        .{ .type = .assign, .address = 1, .dest = "rax", .src = "[rax + rdx*2]" },
        .{ .type = .assign, .address = 2, .dest = "eax", .src = "later" },
        .{ .type = .assign, .address = 3, .dest = "w0", .src = "input" },
        .{ .type = .load, .address = 4, .dest = "x0", .src = "[x0]" },
        .{ .type = .assign, .address = 5, .dest = "w0", .src = "later" },
    };
    var func = types.IRFunction{ .address = 0, .statements = &stmts, .variables = &.{} };
    try run(arena.allocator(), &func);
    try std.testing.expectEqual(@as(usize, 6), func.statements.len);
}
