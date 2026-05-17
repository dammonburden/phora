// Phora — Maturity Pass: reg_to_var
// Renames locally-used saved registers (`saved_xN`) and temporaries (`tmpN`)
// to `local_K` when they never escape the function (no return, no call arg,
// no store-to-memory usage). This improves readability of the lifted IR.
//
// Part of Phora v7.8.0 maturity pipeline.

const std = @import("std");
const types = @import("../../types.zig");

// ---------------------------------------------------------------------------
// Stubbed helpers. The peer agent is writing pass_util.zig; if present its
// `isLiteral`/`parseLiteral`/`stmtReads`/`stmtWrites` should be preferred.
// For self-containment (and so the file builds in isolation during tests),
// we keep local copies here. They're `fn` (not `pub`) so they don't collide.
// ---------------------------------------------------------------------------

fn isLiteral(s: []const u8) bool {
    if (s.len == 0) return false;
    // Accept hex 0x... or decimal (optionally with leading '-' or '#').
    var i: usize = 0;
    if (s[0] == '#') i += 1;
    if (i < s.len and s[i] == '-') i += 1;
    if (i + 2 <= s.len and s[i] == '0' and (s[i + 1] == 'x' or s[i + 1] == 'X')) {
        i += 2;
        if (i >= s.len) return false;
        while (i < s.len) : (i += 1) {
            const c = s[i];
            const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
            if (!is_hex) return false;
        }
        return true;
    }
    if (i >= s.len) return false;
    while (i < s.len) : (i += 1) {
        if (s[i] < '0' or s[i] > '9') return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Candidate detection.
// ---------------------------------------------------------------------------

/// Is `name` a candidate for renaming? Matches `saved_x<digits>` or `tmp<digits>`.
fn isCandidateName(name: []const u8) bool {
    if (std.mem.startsWith(u8, name, "saved_x")) {
        const tail = name["saved_x".len..];
        if (tail.len == 0) return false;
        for (tail) |c| {
            if (c < '0' or c > '9') return false;
        }
        return true;
    }
    if (std.mem.startsWith(u8, name, "tmp")) {
        const tail = name["tmp".len..];
        if (tail.len == 0) return false;
        for (tail) |c| {
            if (c < '0' or c > '9') return false;
        }
        return true;
    }
    return false;
}

/// True if the operand string is a memory expression like `[sp+0x10]`, `[x0,#4]`.
fn isMemoryOperand(s: ?[]const u8) bool {
    const v = s orelse return false;
    return v.len >= 2 and v[0] == '[' and v[v.len - 1] == ']';
}

/// Records whether a candidate name "escapes" (appears somewhere that isn't a local use).
const EscapeInfo = struct {
    escapes: bool = false,
    first_seen_index: usize = std.math.maxInt(usize),
};

// ---------------------------------------------------------------------------
// Main pass entry point.
// ---------------------------------------------------------------------------

pub fn run(allocator: std.mem.Allocator, func: *types.IRFunction) !void {
    // Map: candidate name -> EscapeInfo.
    // Keys are borrowed from existing IR strings; no duplication necessary.
    var info = std.StringHashMap(EscapeInfo).init(allocator);
    defer info.deinit();

    // Track first-appearance order of non-escaping candidates.
    var order = std.array_list.Managed([]const u8).init(allocator);
    defer order.deinit();

    // Pass 1: scan statements to collect candidates + mark escapes.
    for (func.statements, 0..) |stmt, idx| {
        // Consider every operand-like field.
        try noteOperand(&info, stmt.dest, idx, .not_escape);
        try noteOperand(&info, stmt.src, idx, .not_escape);
        try noteOperand(&info, stmt.condition, idx, .not_escape);
        // target is usually a branch/call label; treat as non-escaping read.
        try noteOperand(&info, stmt.target, idx, .not_escape);

        // Escape routes:
        //   1. return.src  -> escapes (caller will see this value).
        //   2. call.args[*] -> escapes (passed to external function).
        //   3. store.src   -> escapes (written to memory).
        //   4. store.dest  -> is a memory expression, the register embedded
        //      inside it (e.g. `[x0,#8]` uses x0) would escape. saved_/tmp
        //      aren't expected there, but we bail safely if they appear.
        switch (stmt.type) {
            .@"return" => {
                try noteOperand(&info, stmt.src, idx, .escape);
            },
            .call => {
                if (stmt.args) |args| {
                    for (args) |a| {
                        try noteOperand(&info, a, idx, .escape);
                    }
                }
                // target is a function name/address; don't mark as escape.
            },
            .store => {
                try noteOperand(&info, stmt.src, idx, .escape);
                // If a candidate appears *inside* the memory expression in
                // dest (unusual but possible), treat it as escape too.
                if (stmt.dest) |d| {
                    if (isMemoryOperand(d)) {
                        markCandidatesInsideExpr(&info, d, idx, .escape);
                    }
                }
            },
            else => {},
        }
    }

    // Pass 2: walk statements in order, record first-appearance for
    // non-escaping candidates.
    for (func.statements) |stmt| {
        try maybeAddToOrder(&info, &order, stmt.dest);
        try maybeAddToOrder(&info, &order, stmt.src);
        try maybeAddToOrder(&info, &order, stmt.condition);
        try maybeAddToOrder(&info, &order, stmt.target);
        if (stmt.args) |args| {
            for (args) |a| try maybeAddToOrder(&info, &order, a);
        }
    }

    if (order.items.len == 0) return; // nothing to rename

    // Pass 3: build rename map: old_name -> allocator-owned "local_K".
    var rename = std.StringHashMap([]const u8).init(allocator);
    defer rename.deinit();

    for (order.items, 0..) |old_name, k| {
        const new_name = try std.fmt.allocPrint(allocator, "local_{d}", .{k});
        try rename.put(old_name, new_name);
    }

    // Pass 4: rewrite all statement operands.
    for (func.statements) |*stmt| {
        stmt.dest = rewriteOperand(&rename, stmt.dest);
        stmt.src = rewriteOperand(&rename, stmt.src);
        stmt.condition = rewriteOperand(&rename, stmt.condition);
        stmt.target = rewriteOperand(&rename, stmt.target);
        if (stmt.args) |args| {
            // args is []const []const u8; it's fine to rewrite its elements
            // because the outer slice was allocator-owned by the lifter.
            const mut_args = @constCast(args);
            for (mut_args, 0..) |a, i| {
                mut_args[i] = rewriteOperand(&rename, a) orelse a;
            }
        }
    }

    // Pass 5: rewrite variable names. Keep `register` for provenance.
    for (func.variables) |*v| {
        if (rename.get(v.name)) |new_name| {
            v.name = new_name;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers (file-private).
// ---------------------------------------------------------------------------

const OperandRole = enum { not_escape, escape };

fn noteOperand(
    info: *std.StringHashMap(EscapeInfo),
    maybe_s: ?[]const u8,
    idx: usize,
    role: OperandRole,
) !void {
    const s = maybe_s orelse return;
    if (s.len == 0) return;
    // Memory expressions (e.g. `[sp+8]`) are handled by the stack_slot pass.
    // A candidate might still be embedded inside one (e.g. `[x19,#0]`) — we
    // scan for that below.
    if (isMemoryOperand(s)) {
        markCandidatesInsideExpr(info, s, idx, role);
        return;
    }
    if (isLiteral(s)) return;
    if (!isCandidateName(s)) return;

    const gop = try info.getOrPut(s);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{ .escapes = false, .first_seen_index = idx };
    }
    if (role == .escape) gop.value_ptr.escapes = true;
    if (idx < gop.value_ptr.first_seen_index) gop.value_ptr.first_seen_index = idx;
}

/// Scan for candidate-name substrings inside a memory expression and mark
/// them. This is a lenient "contains a token" check: we split the inner
/// payload (between `[` and `]`) on commas, `+`, `-`, `*`, `#` and inspect
/// each resulting token.
fn markCandidatesInsideExpr(
    info: *std.StringHashMap(EscapeInfo),
    expr: []const u8,
    idx: usize,
    role: OperandRole,
) void {
    if (expr.len < 2) return;
    const inner = expr[1 .. expr.len - 1];
    var start: usize = 0;
    var i: usize = 0;
    while (i <= inner.len) : (i += 1) {
        const at_boundary = i == inner.len or isTokenDelim(inner[i]);
        if (at_boundary) {
            if (i > start) {
                const tok = std.mem.trim(u8, inner[start..i], " \t");
                if (tok.len > 0 and isCandidateName(tok)) {
                    // StringHashMap wants an owned key or a stable slice.
                    // We can't put a substring safely because it's a slice
                    // into `expr` which is owned by caller. The value we
                    // record here is the token slice — callers must always
                    // re-query by the same pointer identity for renaming.
                    // For escape bookkeeping that's fine because we use
                    // lookupByBytes-equivalent semantics at rename time.
                    //
                    // To keep the map keyed consistently with the top-level
                    // operand case, we only mark pre-existing entries here.
                    if (info.getPtr(tok)) |entry| {
                        if (role == .escape) entry.escapes = true;
                        if (idx < entry.first_seen_index) entry.first_seen_index = idx;
                    }
                }
            }
            start = i + 1;
        }
    }
}

fn isTokenDelim(c: u8) bool {
    return c == ',' or c == '+' or c == '-' or c == '*' or c == '#' or c == ' ' or c == '\t';
}

fn maybeAddToOrder(
    info: *std.StringHashMap(EscapeInfo),
    order: *std.array_list.Managed([]const u8),
    maybe_s: ?[]const u8,
) !void {
    const s = maybe_s orelse return;
    if (s.len == 0) return;
    if (isMemoryOperand(s)) return;
    if (isLiteral(s)) return;
    if (!isCandidateName(s)) return;
    const entry = info.get(s) orelse return;
    if (entry.escapes) return;
    // Already in order?
    for (order.items) |existing| {
        if (std.mem.eql(u8, existing, s)) return;
    }
    try order.append(s);
}

fn rewriteOperand(
    rename: *std.StringHashMap([]const u8),
    maybe_s: ?[]const u8,
) ?[]const u8 {
    const s = maybe_s orelse return null;
    if (rename.get(s)) |new_name| return new_name;
    return s;
}

// ===========================================================================
// Tests
// ===========================================================================

test "reg_to_var: renames local-only saved register to local_0" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x1000, .dest = "saved_x19", .src = "arg0" },
        .{ .type = .assign, .address = 0x1004, .dest = "tmp0", .src = "saved_x19" },
        .{ .type = .@"return", .address = 0x1008, .src = "tmp0" },
    };
    var vars_list = [_]types.Variable{
        .{ .name = "saved_x19", .register = "x19" },
        .{ .name = "tmp0", .register = null },
    };
    var func = types.IRFunction{
        .address = 0x1000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };

    // Allocate mutable storage for the rename-produced strings.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try run(arena.allocator(), &func);

    // saved_x19 is local-only (never a call arg, never returned, never stored).
    // tmp0 escapes via return.
    try std.testing.expectEqualStrings("local_0", func.statements[0].dest.?);
    try std.testing.expectEqualStrings("arg0", func.statements[0].src.?);
    try std.testing.expectEqualStrings("tmp0", func.statements[1].dest.?);
    try std.testing.expectEqualStrings("local_0", func.statements[1].src.?);
    try std.testing.expectEqualStrings("tmp0", func.statements[2].src.?);

    // Variable table updated.
    try std.testing.expectEqualStrings("local_0", func.variables[0].name);
    try std.testing.expectEqualStrings("x19", func.variables[0].register.?);
    try std.testing.expectEqualStrings("tmp0", func.variables[1].name);
}

test "reg_to_var: tmp passed as call arg is not local" {
    const allocator = std.testing.allocator;
    var args = [_][]const u8{"tmp1"};
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x2000, .dest = "tmp1", .src = "arg0" },
        .{ .type = .call, .address = 0x2004, .target = "puts", .args = args[0..] },
    };
    var vars_list = [_]types.Variable{
        .{ .name = "tmp1", .register = null },
    };
    var func = types.IRFunction{
        .address = 0x2000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);
    try std.testing.expectEqualStrings("tmp1", func.statements[0].dest.?);
    try std.testing.expectEqualStrings("tmp1", func.statements[1].args.?[0]);
    try std.testing.expectEqualStrings("tmp1", func.variables[0].name);
}

test "reg_to_var: tmp stored to memory is not local" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x3000, .dest = "tmp2", .src = "arg0" },
        .{ .type = .store, .address = 0x3004, .dest = "[sp+0x10]", .src = "tmp2" },
        .{ .type = .@"return", .address = 0x3008 },
    };
    var vars_list = [_]types.Variable{
        .{ .name = "tmp2", .register = null },
    };
    var func = types.IRFunction{
        .address = 0x3000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);
    try std.testing.expectEqualStrings("tmp2", func.statements[0].dest.?);
    try std.testing.expectEqualStrings("tmp2", func.statements[1].src.?);
    try std.testing.expectEqualStrings("tmp2", func.variables[0].name);
}

test "reg_to_var: multiple locals numbered in first-appearance order" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x4000, .dest = "saved_x20", .src = "arg0" },
        .{ .type = .assign, .address = 0x4004, .dest = "saved_x19", .src = "arg1" },
        .{ .type = .compare, .address = 0x4008, .src = "saved_x20", .condition = "saved_x19" },
        .{ .type = .@"return", .address = 0x400c },
    };
    var vars_list = [_]types.Variable{
        .{ .name = "saved_x19", .register = "x19" },
        .{ .name = "saved_x20", .register = "x20" },
    };
    var func = types.IRFunction{
        .address = 0x4000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);
    // saved_x20 seen first -> local_0
    // saved_x19 seen second -> local_1
    try std.testing.expectEqualStrings("local_0", func.statements[0].dest.?);
    try std.testing.expectEqualStrings("local_1", func.statements[1].dest.?);
    try std.testing.expectEqualStrings("local_0", func.statements[2].src.?);
    try std.testing.expectEqualStrings("local_1", func.statements[2].condition.?);
}

test "reg_to_var: handles empty function gracefully" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{};
    var vars_list = [_]types.Variable{};
    var func = types.IRFunction{
        .address = 0x5000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);
}

test "reg_to_var: non-candidates (arg0, literals) are not renamed" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .assign, .address = 0x6000, .dest = "arg0", .src = "0x42" },
        .{ .type = .@"return", .address = 0x6004, .src = "arg0" },
    };
    var vars_list = [_]types.Variable{
        .{ .name = "arg0", .register = "x0" },
    };
    var func = types.IRFunction{
        .address = 0x6000,
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try run(arena.allocator(), &func);
    try std.testing.expectEqualStrings("arg0", func.statements[0].dest.?);
    try std.testing.expectEqualStrings("0x42", func.statements[0].src.?);
    try std.testing.expectEqualStrings("arg0", func.variables[0].name);
}
