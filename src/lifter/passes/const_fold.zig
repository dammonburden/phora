// Phora — Constant Folding Pass
// Tracks per-variable constant values within a single basic block and rewrites
// uses of known constants to literal strings. Conservative: invalidates the
// constant map on any control-flow break or potential clobber.

const std = @import("std");
const types = @import("../../types.zig");
const util = @import("pass_util.zig");
const ir = @import("../ir.zig");

const ConstMap = std.StringHashMap(i64);
const StringSet = std.StringHashMap(void);

/// Apply constant folding to a function in place.
pub fn run(allocator: std.mem.Allocator, func: *types.IRFunction) !void {
    var consts = ConstMap.init(allocator);
    defer consts.deinit();

    // Strings we allocated as replacements — must be freed when the function is freed
    // by the owner of `func`. We track them so we don't double-free or attempt to free
    // string-table entries that we did not allocate.
    var owned = StringSet.init(allocator);
    defer owned.deinit();

    for (func.statements, 0..) |*stmt, i| {
        _ = i;
        if (stmt.block_start) consts.clearRetainingCapacity();
        if (stmt.type == .@"opaque") {
            consts.clearRetainingCapacity();
            continue; // Raw instruction operands are evidence, not expressions.
        }

        // Rewrite reads first (src, condition, args) using current map.
        try foldReads(allocator, stmt, &consts, &owned);

        switch (stmt.type) {
            .assign => {
                // After folding, see if src is now a literal — record dest = const.
                if (stmt.dest) |d| {
                    if (stmt.src) |s| {
                        if (util.parseLiteral(s)) |v| {
                            try consts.put(d, v);
                        } else {
                            // Non-constant assignment kills any prior binding.
                            _ = consts.remove(d);
                        }
                    } else {
                        _ = consts.remove(d);
                    }
                }
                try updateArmAliases(func, stmt, &consts);
            },
            .load => {
                // We don't model memory; an unknown value is loaded into dest.
                if (stmt.dest) |d| _ = consts.remove(d);
                try updateArmAliases(func, stmt, &consts);
            },
            .call, .@"opaque" => {
                // Calls may clobber arbitrary state. Drop everything (conservative).
                consts.clearRetainingCapacity();
            },
            .branch, .@"return" => {
                // End of basic block — flush the map.
                consts.clearRetainingCapacity();
            },
            .store => {
                // Store may alias something; conservatively keep map (we only model
                // SSA-like variables, not memory). dest here is an address, not a var.
            },
            .compare, .nop => {
                // No definition; map unchanged.
            },
        }
    }
}

// W-register writes zero-extend into X-registers. Keep their constant bindings
// coherent, and invalidate both views after a load or a non-constant write.
fn updateArmAliases(func: *const types.IRFunction, stmt: *const types.IRStatement, consts: *ConstMap) !void {
    const dest = stmt.dest orelse return;
    if (ir.registerFamily(dest)) |family| {
        // Different width views overlap but are not interchangeable values.
        // Invalidate previously known views on every architectural write.
        var changed = true;
        while (changed) {
            changed = false;
            var keys = consts.keyIterator();
            while (keys.next()) |key| {
                if (!std.mem.eql(u8, key.*, dest) and ir.registerFamily(key.*) == family) {
                    _ = consts.remove(key.*);
                    changed = true;
                    break;
                }
            }
        }
        if (consts.get(dest)) |value| {
            const width = ir.registerWidth(dest) orelse 8;
            if (width < 8) {
                const bits: u6 = @intCast(width * 8);
                const mask = (@as(u64, 1) << bits) - 1;
                try consts.put(dest, @intCast(@as(u64, @bitCast(value)) & mask));
            }
        }
    }
    for (func.variables) |variable| {
        const reg = variable.register orelse continue;
        if (reg.len < 2 or reg[0] != 'w' or !std.mem.endsWith(u8, variable.name, "_32")) continue;
        const wide = variable.name[0 .. variable.name.len - 3];
        if (std.mem.eql(u8, dest, variable.name)) {
            if (consts.get(dest)) |value| {
                const extended: i64 = @as(u32, @truncate(@as(u64, @bitCast(value))));
                try consts.put(dest, extended);
                try consts.put(wide, extended);
            } else {
                _ = consts.remove(wide);
            }
        } else if (std.mem.eql(u8, dest, wide)) {
            _ = consts.remove(variable.name);
        }
    }
}

/// Rewrite reads in `stmt` using current constant map. Allocates replacement
/// strings via `allocator`; tracks them in `owned`.
fn foldReads(
    allocator: std.mem.Allocator,
    stmt: *types.IRStatement,
    consts: *const ConstMap,
    owned: *StringSet,
) !void {
    if (stmt.src) |s| {
        if (consts.get(s)) |v| {
            const lit = try util.formatLiteralAlloc(allocator, v, false);
            stmt.src = lit;
            try owned.put(lit, {});
        }
    }
    if (stmt.condition) |c| {
        if (consts.get(c)) |v| {
            const lit = try util.formatLiteralAlloc(allocator, v, false);
            stmt.condition = lit;
            try owned.put(lit, {});
        }
    }
    if (stmt.args) |args_const| {
        // We may need to mutate the args slice contents; rebuild if any change.
        var changed = false;
        for (args_const) |a| {
            if (consts.get(a) != null) {
                changed = true;
                break;
            }
        }
        if (changed) {
            const new_args = try allocator.alloc([]const u8, args_const.len);
            for (args_const, 0..) |a, idx| {
                if (consts.get(a)) |v| {
                    const lit = try util.formatLiteralAlloc(allocator, v, false);
                    new_args[idx] = lit;
                    try owned.put(lit, {});
                } else {
                    new_args[idx] = a;
                }
            }
            stmt.args = new_args;
        }
    }
    // For compare, also fold dest (which is a read here, source operand of cmp).
    if (stmt.type == .compare) {
        if (stmt.dest) |d| {
            if (consts.get(d)) |v| {
                const lit = try util.formatLiteralAlloc(allocator, v, false);
                stmt.dest = lit;
                try owned.put(lit, {});
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "evidence: ARM narrow writes zero-extend and unknown writes invalidate aliases" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var variables = [_]types.Variable{
        .{ .name = "arg0_32", .register = "w0" },
        .{ .name = "arg0", .register = "x0" },
    };
    var statements = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "arg0_32", .src = "#0xffffffff" },
        .{ .type = .assign, .address = 4, .dest = "seen", .src = "arg0" },
        .{ .type = .assign, .address = 8, .dest = "arg0_32", .src = "unknown" },
        .{ .type = .assign, .address = 12, .dest = "after_narrow", .src = "arg0" },
        .{ .type = .assign, .address = 16, .dest = "arg0_32", .src = "#42" },
        .{ .type = .load, .address = 20, .dest = "arg0", .src = "memory" },
        .{ .type = .@"return", .address = 24, .src = "arg0_32" },
    };
    var func = types.IRFunction{ .address = 0, .statements = &statements, .variables = &variables };
    try run(a, &func);
    try std.testing.expectEqualStrings("4294967295", statements[1].src.?);
    try std.testing.expectEqualStrings("arg0", statements[3].src.?);
    try std.testing.expectEqualStrings("arg0_32", statements[6].src.?);
}

test "const_fold basic assign-then-use" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "42" },
        .{ .type = .assign, .address = 4, .dest = "y", .src = "x" },
        .{ .type = .@"return", .address = 8, .src = "y" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "test",
        .statements = &stmts,
        .variables = &.{},
    };
    try run(a, &func);
    // After folding: y = 42, return 42
    try std.testing.expectEqualStrings("42", func.statements[1].src.?);
    try std.testing.expectEqualStrings("42", func.statements[2].src.?);
    // Free any strings we allocated.
    a.free(func.statements[1].src.?);
    a.free(func.statements[2].src.?);
}

test "const_fold rewrites call args" {
    const a = std.testing.allocator;
    const args = [_][]const u8{ "x", "y" };
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "7" },
        .{ .type = .call, .address = 4, .target = "func", .args = &args, .dest = "result" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    try run(a, &func);
    const new_args = func.statements[1].args.?;
    try std.testing.expectEqualStrings("7", new_args[0]);
    try std.testing.expectEqualStrings("y", new_args[1]); // unchanged
    a.free(new_args[0]);
    a.free(new_args);
}

test "const_fold call clobbers map" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "42" },
        .{ .type = .call, .address = 4, .target = "func", .args = null, .dest = "result" },
        .{ .type = .assign, .address = 8, .dest = "y", .src = "x" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    try run(a, &func);
    // After call, x is no longer known constant — y = x stays as "x"
    try std.testing.expectEqualStrings("x", func.statements[2].src.?);
}

test "const_fold leaves non-constants alone" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "arg0" },
        .{ .type = .@"return", .address = 4, .src = "x" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    try run(a, &func);
    try std.testing.expectEqualStrings("arg0", func.statements[0].src.?);
    try std.testing.expectEqualStrings("x", func.statements[1].src.?);
}

test "const_fold compare folds dest and src" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "x", .src = "5" },
        .{ .type = .compare, .address = 4, .op = "eq", .dest = "x", .src = "0" },
    };
    var func = types.IRFunction{
        .address = 0,
        .name = "t",
        .statements = &stmts,
        .variables = &.{},
    };
    try run(a, &func);
    try std.testing.expectEqualStrings("5", func.statements[1].dest.?);
    try std.testing.expectEqualStrings("0", func.statements[1].src.?);
    a.free(func.statements[1].dest.?);
}

test "evidence: physical register views invalidate stale full and partial constants" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "rax", .src = "42" },
        .{ .type = .assign, .address = 1, .dest = "eax", .src = "unknown" },
        .{ .type = .assign, .address = 2, .dest = "seen", .src = "rax" },
        .{ .type = .assign, .address = 3, .dest = "eax", .src = "0x100000001" },
        .{ .type = .assign, .address = 4, .dest = "narrow", .src = "eax" },
        .{ .type = .assign, .address = 5, .dest = "al", .src = "7" },
        .{ .type = .assign, .address = 6, .dest = "after_byte", .src = "eax" },
        .{ .type = .assign, .address = 7, .dest = "x0", .src = "9" },
        .{ .type = .assign, .address = 8, .dest = "w0", .src = "unknown" },
        .{ .type = .@"return", .address = 9, .src = "x0" },
    };
    var func = types.IRFunction{ .address = 0, .statements = &stmts, .variables = &.{} };
    try run(arena.allocator(), &func);
    try std.testing.expectEqualStrings("rax", stmts[2].src.?);
    try std.testing.expectEqualStrings("1", stmts[4].src.?);
    try std.testing.expectEqualStrings("eax", stmts[6].src.?);
    try std.testing.expectEqualStrings("x0", stmts[9].src.?);
}
