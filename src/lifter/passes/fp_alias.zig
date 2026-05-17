// Phora — Maturity Pass: fp_alias  (v7.9.1 Q3)
//
// Tracks temp variables that alias `frame_ptr - N` (or fp / x29 / sp /
// stack_ptr) and rewrites their dereferences to direct `[fp - N]` form so
// the existing frame-struct renderer (which only recognises direct base+offset
// memory operands) fires for indirected access patterns like:
//
//     assign  arg0 = frame_ptr - #0x80
//     store   *([arg0]) = w1
//
// becomes effectively:
//
//     assign  arg0 = frame_ptr - #0x80
//     store   [frame_ptr - 0x80] = w1
//
// The original assign is left in place — its dest is still consumed by other
// references — but every load/store/compare that was indirecting through
// the alias is rewritten so the structure-recovery pass can fold them into
// frame-relative slots.
//
// Notes on safety:
//   * Aliases reset on .branch / .call / .@"return" — anything cross-block
//     is out of scope (and a real per-block dataflow analysis would be a
//     separate pass).
//   * If the same temp gets reassigned to a different value, we drop it
//     from the alias map so we don't rewrite stale references.
//   * Newly allocated rewrite strings come from `allocator`; the pipeline
//     wires this with the IR-lifetime arena so the rewritten operands
//     survive until the IR is freed.

const std = @import("std");
const types = @import("../../types.zig");

// ---------------------------------------------------------------------------
// Bases we treat as aliases for the frame pointer / stack pointer.
// All comparisons are case-sensitive — the lifter normalises to lowercase.
// ---------------------------------------------------------------------------

const ALIAS_BASES = [_][]const u8{
    "frame_ptr",
    "fp",
    "x29",
    "sp",
    "stack_ptr",
};

const Alias = struct {
    base: []const u8,
    offset: i64,
};

// ---------------------------------------------------------------------------
// Pass entry point.
// ---------------------------------------------------------------------------

pub fn run(allocator: std.mem.Allocator, func: *types.IRFunction) !void {
    var alias_map = std.StringHashMap(Alias).init(allocator);
    defer alias_map.deinit();

    for (func.statements) |*stmt| {
        // Reset the alias map at any control transfer — we don't do
        // cross-block dataflow.
        switch (stmt.type) {
            .branch, .call, .@"return" => {
                alias_map.clearRetainingCapacity();
                continue;
            },
            else => {},
        }

        // For load/store/compare, rewrite operands that indirect through an
        // aliased temp. Do this BEFORE recording any new alias from .assign
        // so a single statement can't both define and rewrite itself.
        if (stmt.type == .load or stmt.type == .store or stmt.type == .compare) {
            if (try maybeRewriteOperand(allocator, stmt.dest, &alias_map)) |new_s| {
                stmt.dest = new_s;
            }
            if (try maybeRewriteOperand(allocator, stmt.src, &alias_map)) |new_s| {
                stmt.src = new_s;
            }
        }

        if (stmt.type == .assign) {
            const dest = stmt.dest orelse continue;
            const src = stmt.src orelse {
                // No src — invalidate any previous alias on dest.
                _ = alias_map.remove(dest);
                continue;
            };
            if (parseFpExpr(src)) |a| {
                // Record / refresh.
                alias_map.put(dest, a) catch {};
            } else {
                // dest got a non-aliasing value — invalidate.
                _ = alias_map.remove(dest);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Operand rewriter.
// ---------------------------------------------------------------------------

/// If `maybe_s` is a memory operand of the form `*([V])`, `[V]`, or
/// `*([V, #N])` etc. AND V is in alias_map, return a freshly allocated
/// rewritten string in direct `[base ± offset]` form. Otherwise null.
fn maybeRewriteOperand(
    allocator: std.mem.Allocator,
    maybe_s: ?[]const u8,
    alias_map: *std.StringHashMap(Alias),
) !?[]const u8 {
    const s = maybe_s orelse return null;
    if (s.len < 3) return null;

    // Strip optional `*(...)` wrapping (the lifter uses both `*([x])` and
    // `[x]` shapes depending on whether it's been pseudocode-rendered yet).
    var inner = s;
    var wrap_star_paren = false;
    if (inner.len >= 4 and inner[0] == '*' and inner[1] == '(' and inner[inner.len - 1] == ')') {
        inner = inner[2 .. inner.len - 1];
        wrap_star_paren = true;
    }
    // Now require [ ... ].
    if (inner.len < 3 or inner[0] != '[' or inner[inner.len - 1] != ']') return null;

    // Inside the brackets, find the variable name segment (everything up to
    // the first separator: ',', '+', '-', whitespace, ']').
    const body = std.mem.trim(u8, inner[1 .. inner.len - 1], " \t");
    if (body.len == 0) return null;

    var name_end: usize = 0;
    while (name_end < body.len) : (name_end += 1) {
        const c = body[name_end];
        if (c == ',' or c == '+' or c == '-' or c == ' ' or c == '\t') break;
    }
    if (name_end == 0) return null;
    const name = body[0..name_end];

    // Skip the rewrite if the name is itself an alias-base — leave it alone
    // so the structure-renderer sees its existing direct form.
    for (ALIAS_BASES) |b| {
        if (std.mem.eql(u8, name, b)) return null;
    }

    const alias = alias_map.get(name) orelse return null;

    // Parse any trailing offset on the original operand (extra +/- N inside
    // the brackets) and add it to the alias offset. E.g. `[arg0, #0x10]`
    // where arg0 = fp-0x80 becomes `[fp - 0x70]`.
    const tail = std.mem.trim(u8, body[name_end..], " \t,");
    var extra_offset: i64 = 0;
    if (tail.len > 0) {
        extra_offset = parseSignedHex(tail) orelse 0;
    }
    const total_offset: i64 = alias.offset + extra_offset;

    // Build the rewritten operand. Always direct `[base ± hex]` form so
    // structure-recovery / parseMemRefForSubst pick it up.
    var buf = std.Io.Writer.Allocating.init(allocator);
    defer buf.deinit();
    const w = &buf.writer;
    if (wrap_star_paren) try w.writeAll("*(");
    try w.writeByte('[');
    try w.writeAll(alias.base);
    if (total_offset == 0) {
        // Bare [base] is fine.
    } else if (total_offset > 0) {
        try w.print(" + 0x{x}", .{@as(u64, @intCast(total_offset))});
    } else {
        try w.print(" - 0x{x}", .{@as(u64, @intCast(-total_offset))});
    }
    try w.writeByte(']');
    if (wrap_star_paren) try w.writeByte(')');

    return try buf.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// `frame_ptr - #0x80` / `fp + 0x10` / `x29 - 0x40` / `sp + #0x20` parser.
// ---------------------------------------------------------------------------

/// If `s` is a recognised `<base> ± [#]<hex|dec>` expression, return the
/// (base, signed-offset) pair. Otherwise null.
pub fn parseFpExpr(s: []const u8) ?Alias {
    const trimmed = std.mem.trim(u8, s, " \t");
    if (trimmed.len < 3) return null;

    // Match the longest base prefix.
    var base: ?[]const u8 = null;
    var cursor: usize = 0;
    inline for (ALIAS_BASES) |b| {
        if (trimmed.len >= b.len and std.mem.eql(u8, trimmed[0..b.len], b)) {
            // Must be followed by a separator (space, +, -, comma, end).
            const at = b.len;
            const ok = (at == trimmed.len) or trimmed[at] == ' ' or trimmed[at] == '\t' or
                trimmed[at] == '+' or trimmed[at] == '-' or trimmed[at] == ',';
            if (ok) {
                if (base == null or b.len > base.?.len) {
                    base = b;
                    cursor = b.len;
                }
            }
        }
    }
    const b = base orelse return null;

    // Bare `frame_ptr` with no offset → alias offset 0.
    if (cursor >= trimmed.len) return .{ .base = b, .offset = 0 };

    const tail = std.mem.trim(u8, trimmed[cursor..], " \t,");
    if (tail.len == 0) return .{ .base = b, .offset = 0 };

    return .{ .base = b, .offset = parseSignedHex(tail) orelse return null };
}

/// Parse `+ 0x80`, `- #0x80`, `+8`, `- 16`, `#-0x10`, etc. Returns null on
/// syntax error.
fn parseSignedHex(s_in: []const u8) ?i64 {
    var s = std.mem.trim(u8, s_in, " \t,");
    if (s.len == 0) return null;

    var negative = false;
    // Optional leading sign.
    if (s[0] == '+' or s[0] == '-') {
        negative = s[0] == '-';
        s = std.mem.trim(u8, s[1..], " \t");
    }
    if (s.len == 0) return null;
    // Optional '#' (ARM-style immediate).
    if (s[0] == '#') s = s[1..];
    if (s.len == 0) return null;
    // Optional sign AGAIN after `#` (e.g. `#-0x10`).
    if (s[0] == '+' or s[0] == '-') {
        if (s[0] == '-') negative = !negative;
        s = std.mem.trim(u8, s[1..], " \t");
    }
    if (s.len == 0) return null;

    // Truncate at first non-numeric char (hex or decimal).
    var end: usize = 0;
    var hex = false;
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
        hex = true;
        end = 2;
        while (end < s.len) : (end += 1) {
            const c = s[end];
            const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
            if (!is_hex) break;
        }
        if (end == 2) return null;
    } else {
        while (end < s.len) : (end += 1) {
            const c = s[end];
            if (c < '0' or c > '9') break;
        }
        if (end == 0) return null;
    }

    const num_str = s[0..end];
    const magnitude: u64 = if (hex)
        (std.fmt.parseInt(u64, num_str[2..], 16) catch return null)
    else
        (std.fmt.parseInt(u64, num_str, 10) catch return null);

    if (magnitude > std.math.maxInt(i64)) return null;
    const v: i64 = @intCast(magnitude);
    return if (negative) -v else v;
}

// ===========================================================================
// Tests
// ===========================================================================

test "fp_alias: parseFpExpr accepts canonical forms" {
    {
        const a = parseFpExpr("frame_ptr - #0x80") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("frame_ptr", a.base);
        try std.testing.expectEqual(@as(i64, -0x80), a.offset);
    }
    {
        const a = parseFpExpr("fp + 0x10") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("fp", a.base);
        try std.testing.expectEqual(@as(i64, 0x10), a.offset);
    }
    {
        const a = parseFpExpr("x29 - 0x40") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("x29", a.base);
        try std.testing.expectEqual(@as(i64, -0x40), a.offset);
    }
    {
        const a = parseFpExpr("sp + #0x20") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("sp", a.base);
        try std.testing.expectEqual(@as(i64, 0x20), a.offset);
    }
    {
        const a = parseFpExpr("stack_ptr") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("stack_ptr", a.base);
        try std.testing.expectEqual(@as(i64, 0), a.offset);
    }
}

test "fp_alias: parseFpExpr rejects unrelated bases" {
    try std.testing.expect(parseFpExpr("x0 + 8") == null);
    try std.testing.expect(parseFpExpr("arg0") == null);
    try std.testing.expect(parseFpExpr("") == null);
    try std.testing.expect(parseFpExpr("frame_ptrx + 8") == null);
}

test "fp_alias: rewrites *(arg0) where arg0 = fp - 0x80" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "arg0", .src = "frame_ptr - #0x80" },
        .{ .type = .store, .address = 0x1004, .dest = "*([arg0])", .src = "v0" },
    };
    var vars_list = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);

    try std.testing.expectEqualStrings("*([frame_ptr - 0x80])", func.statements[1].dest.?);
    // Source untouched.
    try std.testing.expectEqualStrings("v0", func.statements[1].src.?);
}

test "fp_alias: rewrites bracketed [arg0] form too" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x2000, .dest = "tmp", .src = "fp + 0x10" },
        .{ .type = .load, .address = 0x2004, .dest = "v1", .src = "[tmp]" },
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

    try std.testing.expectEqualStrings("[fp + 0x10]", func.statements[1].src.?);
}

test "fp_alias: combines alias offset with operand offset" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x3000, .dest = "arg0", .src = "frame_ptr - #0x80" },
        .{ .type = .load, .address = 0x3004, .dest = "v0", .src = "[arg0, #0x10]" },
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

    // -0x80 + 0x10 == -0x70.
    try std.testing.expectEqualStrings("[frame_ptr - 0x70]", func.statements[1].src.?);
}

test "fp_alias: invalidates alias when reassigned" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x4000, .dest = "arg0", .src = "frame_ptr - #0x80" },
        .{ .type = .assign, .address = 0x4004, .dest = "arg0", .src = "x1" },
        .{ .type = .store, .address = 0x4008, .dest = "*([arg0])", .src = "v0" },
    };
    var vars_list = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x4000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);

    // arg0 was clobbered → no rewrite.
    try std.testing.expectEqualStrings("*([arg0])", func.statements[2].dest.?);
}

test "fp_alias: resets on branch / call / return" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x5000, .dest = "arg0", .src = "fp - 0x40" },
        .{ .type = .branch, .address = 0x5004, .condition = "z", .true_block = 0x5100, .false_block = 0x5200 },
        .{ .type = .store, .address = 0x5008, .dest = "*([arg0])", .src = "v0" },
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

    // After the branch we have no aliases — store stays as-is.
    try std.testing.expectEqualStrings("*([arg0])", func.statements[2].dest.?);
}

test "fp_alias: leaves direct frame_ptr operands alone" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .store, .address = 0x6000, .dest = "[frame_ptr - 0x10]", .src = "v0" },
    };
    var vars_list = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x6000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);

    try std.testing.expectEqualStrings("[frame_ptr - 0x10]", func.statements[0].dest.?);
}
