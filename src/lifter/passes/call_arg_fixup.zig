// Phora — IR Maturity Pass: call_arg_fixup
//
// Lifted `call` statements often arrive with `args = null`. This pass walks
// each function sequentially, tracks the most recent expression assigned to
// each `argN` (N in 0..7), and populates `call.args` so pseudocode can render
// `f(x, y, z)` instead of `f()`.
//
// Heuristic for arg count K at a call site: the highest N seen written since
// the last reset (call/branch/return). Ranges that have never been written
// are not included. If no `argN` was written, args stays null.

const std = @import("std");
const types = @import("../../types.zig");
const util = @import("pass_util.zig");

const NUM_ARG_REGS: usize = 8;

/// Internal rolling state for the pass.
const State = struct {
    allocator: std.mem.Allocator,
    /// Most recently assigned source expression for each argN. Each entry is
    /// either a freshly-allocated copy (owned by `allocator`) or a static
    /// reference into `default_names`. `owned[i]` tells which.
    last_write: [NUM_ARG_REGS]?[]const u8,
    /// True when `last_write[i]` was allocated and must be freed on overwrite
    /// or final drop.
    owned: [NUM_ARG_REGS]bool,
    /// True when an argN has been written since the last reset.
    written: [NUM_ARG_REGS]bool,
    /// The highest N (+1) ever written since the last reset. 0 means none.
    high_water: usize,

    fn init(allocator: std.mem.Allocator) State {
        return .{
            .allocator = allocator,
            .last_write = @splat(null),
            .owned = @splat(false),
            .written = @splat(false),
            .high_water = 0,
        };
    }

    fn freeSlot(self: *State, idx: usize) void {
        if (self.owned[idx]) {
            if (self.last_write[idx]) |s| self.allocator.free(s);
        }
        self.last_write[idx] = null;
        self.owned[idx] = false;
    }

    /// Reset rolling state. Releases any allocated copies.
    fn reset(self: *State) void {
        var i: usize = 0;
        while (i < NUM_ARG_REGS) : (i += 1) {
            self.freeSlot(i);
            self.written[i] = false;
        }
        self.high_water = 0;
    }

    /// Record that `argN` was just assigned `expr`. Stores an owned copy.
    fn recordWrite(self: *State, idx: usize, expr: []const u8) !void {
        self.freeSlot(idx);
        const dup = try self.allocator.dupe(u8, expr);
        self.last_write[idx] = dup;
        self.owned[idx] = true;
        self.written[idx] = true;
        if (idx + 1 > self.high_water) self.high_water = idx + 1;
    }

    fn deinit(self: *State) void {
        var i: usize = 0;
        while (i < NUM_ARG_REGS) : (i += 1) self.freeSlot(i);
    }
};

/// Parse a name of the form "argN" (N in 0..NUM_ARG_REGS-1). Returns the
/// numeric index, or null if the name doesn't match.
fn parseArgName(name: []const u8) ?usize {
    if (name.len < 4) return null;
    if (!std.mem.startsWith(u8, name, "arg")) return null;
    const tail = if (std.mem.endsWith(u8, name, "_32")) name[3 .. name.len - 3] else name[3..];
    // Single-digit only (we cap at 8 args). Reject "arg10", "arg-1", etc.
    if (tail.len != 1) return null;
    const c = tail[0];
    if (c < '0' or c > '9') return null;
    const idx = @as(usize, c - '0');
    if (idx >= NUM_ARG_REGS) return null;
    return idx;
}

/// Legacy alias-based heuristic for callers that already established their
/// alias convention. Excluded from liftProcedureMature: argN display labels
/// alone cannot certify the platform ABI, call arity or argument types.
/// Run the call_arg_fixup pass on a single function.
pub fn run(allocator: std.mem.Allocator, func: *types.IRFunction) !void {
    var state = State.init(allocator);
    defer state.deinit();

    for (func.statements) |*stmt| {
        if (stmt.block_start) state.reset();
        switch (stmt.type) {
            .assign => {
                // Track writes to argN; do not disturb state for other dests.
                const dest = stmt.dest orelse continue;
                const src = stmt.src orelse continue;
                if (parseArgName(dest)) |idx| {
                    // Replaying a historical expression at the call can read
                    // a later value of its source register. Only literals are
                    // timeless; retain the current argument register otherwise.
                    const value = if (util.isLiteral(src) and !std.mem.endsWith(u8, dest, "_32")) src else dest;
                    try state.recordWrite(idx, value);
                }
            },
            .call => {
                // Respect lifter-provided args if already populated.
                if (stmt.args == null and state.high_water > 0 and allWritten(state.written[0..state.high_water])) {
                    const k = state.high_water;
                    var out = try allocator.alloc([]const u8, k);
                    var filled: usize = 0;
                    errdefer {
                        // Free any strings already copied into `out` and the
                        // slice itself if we bail out partway.
                        var i: usize = 0;
                        while (i < filled) : (i += 1) allocator.free(out[i]);
                        allocator.free(out);
                    }
                    var i: usize = 0;
                    while (i < k) : (i += 1) {
                        const expr: []const u8 = state.last_write[i] orelse blk: {
                            // Gap: argN unwritten but a higher arg was. Fall
                            // back to the canonical name "argN" so we render
                            // a placeholder rather than crash.
                            const name = try std.fmt.allocPrint(allocator, "arg{d}", .{i});
                            break :blk name;
                        };
                        if (state.last_write[i] != null) {
                            out[i] = try allocator.dupe(u8, expr);
                        } else {
                            // expr was just allocPrinted above; it's already
                            // an owned, fresh copy.
                            out[i] = expr;
                        }
                        filled = i + 1;
                    }
                    stmt.args = out;
                }
                // A call clobbers caller-saved registers; reset tracking so
                // stale arg writes don't leak into the next call site.
                state.reset();
            },
            .load => {
                // Loads define the destination too. Its value at the call is
                // the register itself, not a stale earlier assignment.
                if (stmt.dest) |dest| {
                    if (parseArgName(dest)) |idx| try state.recordWrite(idx, dest);
                }
            },
            .@"opaque", .branch, .@"return" => {
                state.reset();
            },
            else => {
                // load/store/compare/nop don't rewrite argN by themselves.
            },
        }
    }
}

fn allWritten(written: []const bool) bool {
    for (written) |value| if (!value) return false;
    return true;
}

// ============================================================================
// Tests
// ============================================================================

test "parseArgName basics" {
    try std.testing.expectEqual(@as(?usize, 0), parseArgName("arg0"));
    try std.testing.expectEqual(@as(?usize, 7), parseArgName("arg7"));
    try std.testing.expectEqual(@as(?usize, null), parseArgName("arg8"));
    try std.testing.expectEqual(@as(?usize, null), parseArgName("arg"));
    try std.testing.expectEqual(@as(?usize, null), parseArgName("arg10"));
    try std.testing.expectEqual(@as(?usize, null), parseArgName("argX"));
    try std.testing.expectEqual(@as(?usize, null), parseArgName("tmp0"));
    try std.testing.expectEqual(@as(?usize, null), parseArgName("result"));
}

test "populates call.args from preceding assigns" {
    const a = std.testing.allocator;

    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "arg0", .src = "0x10" },
        .{ .type = .assign, .address = 0x1004, .dest = "arg1", .src = "0x20" },
        .{ .type = .call, .address = 0x1008, .target = "f" },
    };
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };

    try run(a, &func);
    defer {
        if (func.statements[2].args) |args| {
            for (args) |s| a.free(s);
            a.free(args);
        }
    }

    const args = func.statements[2].args orelse return error.TestExpectedArgs;
    try std.testing.expectEqual(@as(usize, 2), args.len);
    try std.testing.expectEqualStrings("0x10", args[0]);
    try std.testing.expectEqualStrings("0x20", args[1]);
}

test "non-arg dest does not disturb state" {
    const a = std.testing.allocator;

    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "arg0", .src = "0x10" },
        .{ .type = .assign, .address = 0x1004, .dest = "tmp0", .src = "0x99" },
        .{ .type = .call, .address = 0x1008, .target = "g" },
    };
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };

    try run(a, &func);
    defer {
        if (func.statements[2].args) |args| {
            for (args) |s| a.free(s);
            a.free(args);
        }
    }

    const args = func.statements[2].args orelse return error.TestExpectedArgs;
    try std.testing.expectEqual(@as(usize, 1), args.len);
    try std.testing.expectEqualStrings("0x10", args[0]);
}

test "call resets arg tracking for the next call" {
    const a = std.testing.allocator;

    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "arg0", .src = "0xa" },
        .{ .type = .call, .address = 0x1004, .target = "f" },
        // No new arg writes before the next call → args should stay null.
        .{ .type = .call, .address = 0x1008, .target = "g" },
    };
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };

    try run(a, &func);
    defer {
        if (func.statements[1].args) |args| {
            for (args) |s| a.free(s);
            a.free(args);
        }
    }

    const args1 = func.statements[1].args orelse return error.TestExpectedArgs;
    try std.testing.expectEqual(@as(usize, 1), args1.len);
    try std.testing.expectEqualStrings("0xa", args1[0]);
    try std.testing.expectEqual(@as(?[]const []const u8, null), func.statements[2].args);
}

test "branch resets arg tracking" {
    const a = std.testing.allocator;

    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "arg0", .src = "0x1" },
        .{ .type = .branch, .address = 0x1004, .condition = "cc", .true_block = 1, .false_block = 2 },
        .{ .type = .call, .address = 0x1008, .target = "h" },
    };
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };

    try run(a, &func);

    try std.testing.expectEqual(@as(?[]const []const u8, null), func.statements[2].args);
}

test "preserves lifter-provided args" {
    const a = std.testing.allocator;

    const preset = [_][]const u8{ "preset_a", "preset_b" };
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "arg0", .src = "ignored" },
        .{ .type = .call, .address = 0x1004, .target = "f", .args = preset[0..] },
    };
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };

    try run(a, &func);

    const args = func.statements[1].args orelse return error.TestExpectedArgs;
    try std.testing.expectEqual(@as(usize, 2), args.len);
    try std.testing.expectEqualStrings("preset_a", args[0]);
    try std.testing.expectEqualStrings("preset_b", args[1]);
}

test "later write to same argN overwrites earlier value" {
    const a = std.testing.allocator;

    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "arg0", .src = "0x1" },
        .{ .type = .assign, .address = 0x1004, .dest = "arg0", .src = "0x2" },
        .{ .type = .call, .address = 0x1008, .target = "f" },
    };
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };

    try run(a, &func);
    defer {
        if (func.statements[2].args) |args| {
            for (args) |s| a.free(s);
            a.free(args);
        }
    }

    const args = func.statements[2].args orelse return error.TestExpectedArgs;
    try std.testing.expectEqual(@as(usize, 1), args.len);
    try std.testing.expectEqualStrings("0x2", args[0]);
}

test "gap in arg writes does not invent positional arguments" {
    const a = std.testing.allocator;

    // A high argument-register write cannot establish earlier arguments.
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "arg2", .src = "0xc" },
        .{ .type = .call, .address = 0x1004, .target = "f" },
    };
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };

    try run(a, &func);
    defer {
        if (func.statements[1].args) |args| {
            for (args) |s| a.free(s);
            a.free(args);
        }
    }

    try std.testing.expect(func.statements[1].args == null);
}

test "no arg writes leaves args null" {
    const a = std.testing.allocator;

    var stmts = [_]types.IRStatement{
        .{ .type = .call, .address = 0x1000, .target = "f" },
    };
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };

    try run(a, &func);

    try std.testing.expectEqual(@as(?[]const []const u8, null), func.statements[0].args);
}

test "empty function does not crash" {
    const a = std.testing.allocator;
    var stmts = [_]types.IRStatement{};
    var vars = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars[0..],
    };
    try run(a, &func);
}

test "evidence: argument load and expression source overwrite cannot reuse stale values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0, .dest = "arg0", .src = "arg1" },
        .{ .type = .assign, .address = 4, .dest = "arg1", .src = "7" },
        .{ .type = .call, .address = 8, .target = "first" },
        .{ .type = .assign, .address = 12, .dest = "arg0", .src = "42" },
        .{ .type = .load, .address = 16, .dest = "arg0", .src = "[x1]" },
        .{ .type = .call, .address = 20, .target = "second" },
        .{ .type = .assign, .address = 24, .dest = "arg0", .src = "99" },
        .{ .type = .@"opaque", .address = 28, .op = "unknown" },
        .{ .type = .call, .address = 32, .target = "third" },
    };
    var func = types.IRFunction{ .address = 0, .statements = &stmts, .variables = &.{} };
    try run(arena.allocator(), &func);
    try std.testing.expectEqualStrings("arg0", stmts[2].args.?[0]);
    try std.testing.expectEqualStrings("7", stmts[2].args.?[1]);
    try std.testing.expectEqualStrings("arg0", stmts[5].args.?[0]);
    try std.testing.expect(stmts[8].args == null);
}
