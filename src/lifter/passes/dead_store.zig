// Phora — Dead Store Elimination Pass
// Removes assignments whose result is overwritten before being read, within a
// single basic block. Stops scanning at branch/call/return (block boundaries).
// Conservative: never removes call/store/compare (side effects).

const std = @import("std");
const types = @import("../../types.zig");
const util = @import("pass_util.zig");

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
            if (isBlockBoundary(next)) {
                // Last chance: if the boundary itself reads dest, keep stmt i.
                if (util.stmtReads(next, dest)) break;
                // Conservative: assume dest may be read in a successor block.
                break;
            }

            if (util.stmtReads(next, dest)) {
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
    for (func.statements, 0..) |stmt, i| {
        if (dead.isSet(i)) continue;
        new_stmts[w] = stmt;
        w += 1;
    }
    func.statements = new_stmts;
}

/// A statement is a candidate for elimination if it pure-defines `dest` and
/// has no observable side effect beyond that definition.
/// load is technically side-effect-free in our IR (no MMIO modeling), but
/// loads can fault — conservatively keep them.
fn isCandidate(stmt: types.IRStatement) bool {
    return switch (stmt.type) {
        .assign => stmt.dest != null,
        .load, .call, .compare, .store, .branch, .@"return", .nop => false,
    };
}

/// Hard block boundaries — we never reason past these.
fn isBlockBoundary(stmt: types.IRStatement) bool {
    return switch (stmt.type) {
        .branch, .call, .@"return" => true,
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
