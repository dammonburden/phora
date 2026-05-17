// Phora — IR Pass Utilities
// Shared helpers for IR maturity passes (const_fold, dead_store, ...).

const std = @import("std");
const types = @import("../../types.zig");

/// True if s looks like a numeric literal (decimal, hex 0x..., negative).
pub fn isLiteral(s: ?[]const u8) bool {
    const v = s orelse return false;
    if (v.len == 0) return false;
    var i: usize = 0;
    if (v[0] == '-' or v[0] == '+') {
        if (v.len == 1) return false;
        i = 1;
    }
    if (v.len >= i + 2 and v[i] == '0' and (v[i + 1] == 'x' or v[i + 1] == 'X')) {
        if (v.len == i + 2) return false;
        var j: usize = i + 2;
        while (j < v.len) : (j += 1) {
            const c = v[j];
            const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
            if (!is_hex) return false;
        }
        return true;
    }
    // Plain decimal: every remaining char must be a digit.
    if (i >= v.len) return false;
    var j: usize = i;
    while (j < v.len) : (j += 1) {
        if (v[j] < '0' or v[j] > '9') return false;
    }
    return true;
}

/// Parse a decimal or hex literal. Returns null if unparseable.
pub fn parseLiteral(s: []const u8) ?i64 {
    if (!isLiteral(s)) return null;
    var negative = false;
    var rest = s;
    if (rest.len > 0 and (rest[0] == '-' or rest[0] == '+')) {
        negative = rest[0] == '-';
        rest = rest[1..];
    }
    if (rest.len >= 2 and rest[0] == '0' and (rest[1] == 'x' or rest[1] == 'X')) {
        const u = std.fmt.parseInt(u64, rest[2..], 16) catch return null;
        const iv: i64 = @bitCast(u);
        return if (negative) -iv else iv;
    }
    const v = std.fmt.parseInt(i64, rest, 10) catch return null;
    return if (negative) -v else v;
}

/// Format a literal back to an allocated string. Hex uses 0x prefix.
pub fn formatLiteralAlloc(allocator: std.mem.Allocator, v: i64, hex: bool) ![]u8 {
    if (hex) {
        if (v < 0) {
            return std.fmt.allocPrint(allocator, "-0x{x}", .{@as(u64, @intCast(-v))});
        }
        return std.fmt.allocPrint(allocator, "0x{x}", .{@as(u64, @intCast(v))});
    }
    return std.fmt.allocPrint(allocator, "{d}", .{v});
}

/// True if stmt reads the given variable (src, condition, or any arg).
pub fn stmtReads(stmt: types.IRStatement, variable: []const u8) bool {
    if (stmt.src) |s| {
        if (std.mem.eql(u8, s, variable)) return true;
    }
    if (stmt.condition) |c| {
        if (std.mem.eql(u8, c, variable)) return true;
    }
    if (stmt.target) |t| {
        // Indirect call targets count as reads of the target variable.
        if (!isLiteral(t) and std.mem.eql(u8, t, variable)) return true;
    }
    if (stmt.args) |args| {
        for (args) |a| {
            if (std.mem.eql(u8, a, variable)) return true;
        }
    }
    // Compare reads both operands (dest is a flag-source here, not a write).
    if (stmt.type == .compare) {
        if (stmt.dest) |d| {
            if (std.mem.eql(u8, d, variable)) return true;
        }
    }
    // Store reads dest (address) as well as src (value).
    if (stmt.type == .store) {
        if (stmt.dest) |d| {
            if (std.mem.eql(u8, d, variable)) return true;
        }
    }
    return false;
}

/// True if stmt overwrites the given variable (dest on assign/call/load).
pub fn stmtWrites(stmt: types.IRStatement, variable: []const u8) bool {
    // Only these stmt types treat dest as a definition.
    switch (stmt.type) {
        .assign, .call, .load => {},
        else => return false,
    }
    const d = stmt.dest orelse return false;
    return std.mem.eql(u8, d, variable);
}

// ============================================================================
// Tests
// ============================================================================

test "isLiteral accepts decimal hex negative" {
    try std.testing.expect(isLiteral("42"));
    try std.testing.expect(isLiteral("0x10"));
    try std.testing.expect(isLiteral("-5"));
    try std.testing.expect(isLiteral("-0x1a"));
    try std.testing.expect(!isLiteral("arg0"));
    try std.testing.expect(!isLiteral(""));
    try std.testing.expect(!isLiteral(null));
    try std.testing.expect(!isLiteral("0x"));
    try std.testing.expect(!isLiteral("-"));
    try std.testing.expect(!isLiteral("12a"));
}

test "parseLiteral decodes forms" {
    try std.testing.expectEqual(@as(?i64, 42), parseLiteral("42"));
    try std.testing.expectEqual(@as(?i64, 16), parseLiteral("0x10"));
    try std.testing.expectEqual(@as(?i64, -5), parseLiteral("-5"));
    try std.testing.expectEqual(@as(?i64, -26), parseLiteral("-0x1a"));
    try std.testing.expectEqual(@as(?i64, null), parseLiteral("arg0"));
}

test "formatLiteralAlloc round trips" {
    const a = std.testing.allocator;
    const s1 = try formatLiteralAlloc(a, 42, false);
    defer a.free(s1);
    try std.testing.expectEqualStrings("42", s1);
    const s2 = try formatLiteralAlloc(a, 16, true);
    defer a.free(s2);
    try std.testing.expectEqualStrings("0x10", s2);
    const s3 = try formatLiteralAlloc(a, -5, false);
    defer a.free(s3);
    try std.testing.expectEqualStrings("-5", s3);
}

test "stmtReads and stmtWrites" {
    const assign_stmt = types.IRStatement{
        .type = .assign,
        .address = 0,
        .dest = "x",
        .src = "y",
    };
    try std.testing.expect(stmtReads(assign_stmt, "y"));
    try std.testing.expect(!stmtReads(assign_stmt, "x"));
    try std.testing.expect(stmtWrites(assign_stmt, "x"));
    try std.testing.expect(!stmtWrites(assign_stmt, "y"));

    const args = [_][]const u8{ "a", "b" };
    const call_stmt = types.IRStatement{
        .type = .call,
        .address = 0,
        .target = "func",
        .args = &args,
        .dest = "result",
    };
    try std.testing.expect(stmtReads(call_stmt, "a"));
    try std.testing.expect(stmtReads(call_stmt, "b"));
    try std.testing.expect(stmtWrites(call_stmt, "result"));

    const cmp_stmt = types.IRStatement{
        .type = .compare,
        .address = 0,
        .op = "eq",
        .dest = "x",
        .src = "y",
    };
    try std.testing.expect(stmtReads(cmp_stmt, "x"));
    try std.testing.expect(stmtReads(cmp_stmt, "y"));
    try std.testing.expect(!stmtWrites(cmp_stmt, "x"));
}
