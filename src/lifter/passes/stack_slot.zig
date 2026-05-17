// Phora — Maturity Pass: stack_slot
// Recognises stack-relative memory expressions (`[sp+N]`, `[sp, #N]`,
// `[sp-N]`, `[sp+0xN]`) and rewrites them to named slots (`stack_0`,
// `stack_1`, ...). Each unique offset becomes one slot. New variables are
// appended to the function's variable table.
//
// The slot prefix is `stack_` (not `local_`) to stay disjoint from the
// reg_to_var pass which produces `local_K` names.
//
// Part of Phora v7.8.0 maturity pipeline.

const std = @import("std");
const types = @import("../../types.zig");

// ---------------------------------------------------------------------------
// Pass entry point.
// ---------------------------------------------------------------------------

pub fn run(allocator: std.mem.Allocator, func: *types.IRFunction) !void {
    // Map from canonical offset (i64) to slot index.
    var slot_map = std.AutoHashMap(i64, u32).init(allocator);
    defer slot_map.deinit();

    // Ordered list of (offset, name) so we can preserve first-seen ordering
    // and emit new Variables at the end.
    var slot_names = std.array_list.Managed([]const u8).init(allocator);
    defer slot_names.deinit();

    // Pass 1: walk statements; for any `[sp...]` operand, allocate a slot
    // name on first sight and rewrite the operand to that name. Other
    // operands (registers, names, literals) are left untouched.
    for (func.statements) |*stmt| {
        if (try maybeRewrite(allocator, stmt.dest, &slot_map, &slot_names)) |new_name| {
            stmt.dest = new_name;
        }
        if (try maybeRewrite(allocator, stmt.src, &slot_map, &slot_names)) |new_name| {
            stmt.src = new_name;
        }
        if (try maybeRewrite(allocator, stmt.condition, &slot_map, &slot_names)) |new_name| {
            stmt.condition = new_name;
        }
        if (try maybeRewrite(allocator, stmt.target, &slot_map, &slot_names)) |new_name| {
            stmt.target = new_name;
        }
        if (stmt.args) |args| {
            const mut_args = @constCast(args);
            for (mut_args, 0..) |a, i| {
                if (try maybeRewrite(allocator, a, &slot_map, &slot_names)) |new_name| {
                    mut_args[i] = new_name;
                }
            }
        }
    }

    if (slot_names.items.len == 0) return;

    // Pass 2: append new variables. Build a fresh slice that combines the
    // existing variables and the new slot variables.
    const new_count = func.variables.len + slot_names.items.len;
    const new_vars = try allocator.alloc(types.Variable, new_count);
    @memcpy(new_vars[0..func.variables.len], func.variables);
    for (slot_names.items, 0..) |name, i| {
        new_vars[func.variables.len + i] = .{
            .name = name,
            .register = null,
            .type_name = null,
        };
    }
    func.variables = new_vars;
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// If `maybe_s` is a recognisable `[sp±N]` expression, return the slot name
/// (allocating it if first-seen). Otherwise return null and leave caller's
/// operand untouched.
fn maybeRewrite(
    allocator: std.mem.Allocator,
    maybe_s: ?[]const u8,
    slot_map: *std.AutoHashMap(i64, u32),
    slot_names: *std.array_list.Managed([]const u8),
) !?[]const u8 {
    const s = maybe_s orelse return null;
    const offset = parseSpOffset(s) orelse return null;

    if (slot_map.get(offset)) |idx| {
        return slot_names.items[idx];
    }
    const idx: u32 = @intCast(slot_names.items.len);
    const name = try std.fmt.allocPrint(allocator, "stack_{d}", .{idx});
    try slot_names.append(name);
    try slot_map.put(offset, idx);
    return name;
}

/// Parse `[sp+N]`, `[sp-N]`, `[sp, #N]`, `[sp,#-0xN]`, etc. and return the
/// signed byte offset. Returns null if not a stack-pointer expression.
///
/// We're intentionally lenient — anything that starts with `[`, ends with
/// `]`, has `sp` after the bracket (followed by a delimiter), and an integer
/// after the next sign character will parse. Whitespace is trimmed.
pub fn parseSpOffset(s: []const u8) ?i64 {
    if (s.len < 4) return null;
    if (s[0] != '[' or s[s.len - 1] != ']') return null;

    // Strip the brackets.
    var inner = std.mem.trim(u8, s[1 .. s.len - 1], " \t");
    if (inner.len < 2) return null;

    // Must start with "sp" (case-insensitive). Accept lowercase only — the
    // lifter normalises to lowercase.
    if (!(inner.len >= 2 and inner[0] == 's' and inner[1] == 'p')) return null;

    // Cursor past "sp".
    var i: usize = 2;
    // Skip optional separator: ',', whitespace.
    while (i < inner.len and (inner[i] == ',' or inner[i] == ' ' or inner[i] == '\t')) : (i += 1) {}

    if (i >= inner.len) {
        // Bare `[sp]` -> offset 0.
        return 0;
    }

    // Optional ARM32 immediate prefix '#'.
    if (inner[i] == '#') i += 1;
    if (i >= inner.len) return null;

    var negative = false;
    if (inner[i] == '+' or inner[i] == '-') {
        negative = inner[i] == '-';
        i += 1;
    }
    if (i >= inner.len) return null;

    // Skip a possible leading '#' after sign (e.g. `[sp+#8]` — uncommon but
    // be lenient).
    if (inner[i] == '#') i += 1;
    if (i >= inner.len) return null;

    // Parse the rest as decimal or hex digits up to the end of `inner`.
    var num_str = std.mem.trim(u8, inner[i..], " \t");
    if (num_str.len == 0) return null;

    // The value may have trailing bits we don't understand (e.g.
    // `[sp+8, x0, lsl #2]`). Truncate at first non-numeric/non-hex char.
    var end: usize = 0;
    var hex = false;
    if (num_str.len >= 2 and num_str[0] == '0' and (num_str[1] == 'x' or num_str[1] == 'X')) {
        hex = true;
        end = 2;
        while (end < num_str.len) : (end += 1) {
            const c = num_str[end];
            const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
            if (!is_hex) break;
        }
        if (end == 2) return null; // no digits after 0x
    } else {
        while (end < num_str.len) : (end += 1) {
            const c = num_str[end];
            if (c < '0' or c > '9') break;
        }
        if (end == 0) return null;
    }
    num_str = num_str[0..end];

    const magnitude: u64 = if (hex)
        (std.fmt.parseInt(u64, num_str[2..], 16) catch return null)
    else
        (std.fmt.parseInt(u64, num_str, 10) catch return null);

    // Cap to i64 range.
    if (magnitude > std.math.maxInt(i64)) return null;
    const v: i64 = @intCast(magnitude);
    return if (negative) -v else v;
}

// ===========================================================================
// Tests
// ===========================================================================

test "stack_slot: parseSpOffset accepts common forms" {
    try std.testing.expectEqual(@as(?i64, 0), parseSpOffset("[sp]"));
    try std.testing.expectEqual(@as(?i64, 8), parseSpOffset("[sp+8]"));
    try std.testing.expectEqual(@as(?i64, 16), parseSpOffset("[sp+0x10]"));
    try std.testing.expectEqual(@as(?i64, -4), parseSpOffset("[sp-4]"));
    try std.testing.expectEqual(@as(?i64, 32), parseSpOffset("[sp, #32]"));
    try std.testing.expectEqual(@as(?i64, 64), parseSpOffset("[sp, #0x40]"));
    try std.testing.expectEqual(@as(?i64, -16), parseSpOffset("[sp,#-0x10]"));
    try std.testing.expectEqual(@as(?i64, 8), parseSpOffset("[sp+8, x0, lsl #2]"));
}

test "stack_slot: parseSpOffset rejects non-sp expressions" {
    try std.testing.expectEqual(@as(?i64, null), parseSpOffset("[x0+8]"));
    try std.testing.expectEqual(@as(?i64, null), parseSpOffset("[fp+8]"));
    try std.testing.expectEqual(@as(?i64, null), parseSpOffset("arg0"));
    try std.testing.expectEqual(@as(?i64, null), parseSpOffset(""));
    try std.testing.expectEqual(@as(?i64, null), parseSpOffset("[sp+]"));
    try std.testing.expectEqual(@as(?i64, null), parseSpOffset("[sp+0x]"));
    try std.testing.expectEqual(@as(?i64, null), parseSpOffset("0x42"));
}

test "stack_slot: rewrites store and load to named slot" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .store, .address = 0x1000, .dest = "[sp+0x10]", .src = "arg0" },
        .{ .type = .load, .address = 0x1004, .dest = "tmp0", .src = "[sp+0x10]" },
        .{ .type = .@"return", .address = 0x1008, .src = "tmp0" },
    };
    var vars_list = [_]types.Variable{
        .{ .name = "arg0", .register = "x0" },
        .{ .name = "tmp0", .register = null },
    };
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try run(arena.allocator(), &func);

    // Same offset -> same slot name.
    try std.testing.expectEqualStrings("stack_0", func.statements[0].dest.?);
    try std.testing.expectEqualStrings("arg0", func.statements[0].src.?);
    try std.testing.expectEqualStrings("tmp0", func.statements[1].dest.?);
    try std.testing.expectEqualStrings("stack_0", func.statements[1].src.?);

    // Variable table was extended with one new slot.
    try std.testing.expectEqual(@as(usize, 3), func.variables.len);
    try std.testing.expectEqualStrings("stack_0", func.variables[2].name);
}

test "stack_slot: distinct offsets get distinct slots" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .store, .address = 0x2000, .dest = "[sp+0x10]", .src = "arg0" },
        .{ .type = .store, .address = 0x2004, .dest = "[sp+0x18]", .src = "arg1" },
        .{ .type = .store, .address = 0x2008, .dest = "[sp, #32]", .src = "arg2" },
        .{ .type = .load, .address = 0x200c, .dest = "tmp0", .src = "[sp+0x10]" },
    };
    var vars_list = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x2000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);

    try std.testing.expectEqualStrings("stack_0", func.statements[0].dest.?);
    try std.testing.expectEqualStrings("stack_1", func.statements[1].dest.?);
    try std.testing.expectEqualStrings("stack_2", func.statements[2].dest.?);
    try std.testing.expectEqualStrings("stack_0", func.statements[3].src.?); // reuses 0x10 -> stack_0
    try std.testing.expectEqual(@as(usize, 3), func.variables.len);
}

test "stack_slot: leaves unrecognised operands untouched" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x3000, .dest = "tmp0", .src = "arg0" },
        .{ .type = .store, .address = 0x3004, .dest = "[x0+8]", .src = "tmp0" },
        .{ .type = .load, .address = 0x3008, .dest = "tmp1", .src = "[x1, #0]" },
        .{ .type = .@"return", .address = 0x300c, .src = "tmp1" },
    };
    var vars_list = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x3000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);
    try std.testing.expectEqualStrings("[x0+8]", func.statements[1].dest.?);
    try std.testing.expectEqualStrings("[x1, #0]", func.statements[2].src.?);
    try std.testing.expectEqual(@as(usize, 0), func.variables.len);
}

test "stack_slot: handles empty function" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{};
    var vars_list = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x4000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);
    try std.testing.expectEqual(@as(usize, 0), func.variables.len);
}

test "stack_slot: negative offset is recognised" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .store, .address = 0x5000, .dest = "[sp-8]", .src = "arg0" },
        .{ .type = .load, .address = 0x5004, .dest = "tmp0", .src = "[sp-8]" },
    };
    var vars_list = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x5000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);
    try std.testing.expectEqualStrings("stack_0", func.statements[0].dest.?);
    try std.testing.expectEqualStrings("stack_0", func.statements[1].src.?);
    try std.testing.expectEqual(@as(usize, 1), func.variables.len);
    try std.testing.expectEqualStrings("stack_0", func.variables[0].name);
}
