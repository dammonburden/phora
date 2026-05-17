// Phora — Control Flow Pattern Detector
// Detects structured patterns: if/else (2 successors), loops (back-edges), switch/case.
// Enhances IR with high-level control flow annotations.

const std = @import("std");
const types = @import("../types.zig");

/// Detected control flow pattern.
pub const Pattern = struct {
    kind: PatternKind,
    /// Address of the block where the pattern starts.
    head_address: u64,
    /// Addresses of blocks involved in the pattern.
    body_addresses: []const u64,
    /// For if/else: address of the merge point. For loops: address of the back-edge source.
    merge_address: ?u64,
};

pub const PatternKind = enum {
    if_then,
    if_then_else,
    while_loop,
    do_while_loop,
    switch_case,
};

/// Detect control flow patterns in a procedure's CFG.
pub fn detectPatterns(
    allocator: std.mem.Allocator,
    blocks: []const types.BasicBlock,
) ![]Pattern {
    var patterns = std.array_list.Managed(Pattern).init(allocator);
    errdefer patterns.deinit();

    // Build block lookup by address
    var block_map = std.AutoHashMap(u64, types.BasicBlock).init(allocator);
    defer block_map.deinit();

    for (blocks) |block| {
        try block_map.put(block.start, block);
    }

    for (blocks) |block| {
        // If/else detection: block has exactly 2 successors (conditional branch)
        if (block.terminator == .branch and block.successors.len == 2) {
            const true_target = block.successors[0];
            const false_target = block.successors[1];

            // Check if both targets converge to a common successor (if/else)
            const merge = findMergePoint(block_map, true_target, false_target);
            if (merge != null) {
                // Both branches converge → if/then/else
                const body = try allocator.alloc(u64, 2);
                body[0] = true_target;
                body[1] = false_target;
                try patterns.append(.{
                    .kind = .if_then_else,
                    .head_address = block.start,
                    .body_addresses = body,
                    .merge_address = merge,
                });
            } else {
                // Only one branch has a body, the other falls through → if/then
                const body = try allocator.alloc(u64, 1);
                body[0] = true_target;
                try patterns.append(.{
                    .kind = .if_then,
                    .head_address = block.start,
                    .body_addresses = body,
                    .merge_address = false_target,
                });
            }
        }

        // Loop detection: look for back-edges (successor points to earlier block)
        for (block.successors) |succ| {
            if (succ <= block.start) {
                // Back-edge detected — this is a loop
                // Determine loop type
                if (block_map.get(succ)) |header| {
                    if (header.terminator == .branch) {
                        // While loop: header tests condition, body is one successor
                        const body = try allocator.alloc(u64, 1);
                        body[0] = block.start;
                        try patterns.append(.{
                            .kind = .while_loop,
                            .head_address = succ,
                            .body_addresses = body,
                            .merge_address = block.start, // back-edge source
                        });
                    } else {
                        // Do-while: body executes first, test at end
                        const body = try allocator.alloc(u64, 1);
                        body[0] = succ;
                        try patterns.append(.{
                            .kind = .do_while_loop,
                            .head_address = succ,
                            .body_addresses = body,
                            .merge_address = block.start,
                        });
                    }
                }
            }
        }

        // Switch/case detection: block with > 2 successors
        if (block.successors.len > 2) {
            const body = try allocator.dupe(u64, block.successors);
            try patterns.append(.{
                .kind = .switch_case,
                .head_address = block.start,
                .body_addresses = body,
                .merge_address = null,
            });
        }
    }

    return patterns.toOwnedSlice();
}

/// Free patterns and their allocated body slices.
pub fn freePatterns(allocator: std.mem.Allocator, patterns: []Pattern) void {
    for (patterns) |pattern| {
        allocator.free(pattern.body_addresses);
    }
    allocator.free(patterns);
}

/// Find a common successor of two blocks (merge point for if/else).
fn findMergePoint(
    block_map: std.AutoHashMap(u64, types.BasicBlock),
    addr_a: u64,
    addr_b: u64,
) ?u64 {
    const block_a = block_map.get(addr_a) orelse return null;
    const block_b = block_map.get(addr_b) orelse return null;

    // Check if any successor of A is also a successor of B
    for (block_a.successors) |succ_a| {
        for (block_b.successors) |succ_b| {
            if (succ_a == succ_b) return succ_a;
        }
    }

    // Check if B is a successor of A (then-only pattern)
    for (block_a.successors) |succ_a| {
        if (succ_a == addr_b) return addr_b;
    }

    // Check if A is a successor of B
    for (block_b.successors) |succ_b| {
        if (succ_b == addr_a) return addr_a;
    }

    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "detect if-then-else pattern" {
    const allocator = std.testing.allocator;

    // CFG: block 0x1000 branches to 0x1010 (true) and 0x1020 (false)
    // Both converge at 0x1030
    var succ_0 = [_]u64{ 0x1010, 0x1020 };
    var succ_1 = [_]u64{0x1030};
    var succ_2 = [_]u64{0x1030};
    var succ_3 = [_]u64{};

    var pred_0 = [_]u64{};
    var pred_1 = [_]u64{0x1000};
    var pred_2 = [_]u64{0x1000};
    var pred_3 = [_]u64{ 0x1010, 0x1020 };

    const blocks = [_]types.BasicBlock{
        .{ .start = 0x1000, .size = 16, .instruction_count = 4, .successors = &succ_0, .predecessors = &pred_0, .terminator = .branch },
        .{ .start = 0x1010, .size = 16, .instruction_count = 4, .successors = &succ_1, .predecessors = &pred_1, .terminator = .jump },
        .{ .start = 0x1020, .size = 16, .instruction_count = 4, .successors = &succ_2, .predecessors = &pred_2, .terminator = .jump },
        .{ .start = 0x1030, .size = 16, .instruction_count = 4, .successors = &succ_3, .predecessors = &pred_3, .terminator = .@"return" },
    };

    const patterns = try detectPatterns(allocator, &blocks);
    defer freePatterns(allocator, patterns);

    try std.testing.expect(patterns.len >= 1);
    try std.testing.expectEqual(PatternKind.if_then_else, patterns[0].kind);
    try std.testing.expectEqual(@as(u64, 0x1000), patterns[0].head_address);
    try std.testing.expectEqual(@as(?u64, 0x1030), patterns[0].merge_address);
}

test "detect while loop pattern" {
    const allocator = std.testing.allocator;

    // CFG: block 0x1000 (header, conditional) → 0x1010 (body) → back to 0x1000
    var succ_0 = [_]u64{ 0x1010, 0x1020 };
    var succ_1 = [_]u64{0x1000}; // back-edge
    var succ_2 = [_]u64{};

    var pred_0 = [_]u64{0x1010};
    var pred_1 = [_]u64{0x1000};
    var pred_2 = [_]u64{0x1000};

    const blocks = [_]types.BasicBlock{
        .{ .start = 0x1000, .size = 16, .instruction_count = 4, .successors = &succ_0, .predecessors = &pred_0, .terminator = .branch },
        .{ .start = 0x1010, .size = 16, .instruction_count = 4, .successors = &succ_1, .predecessors = &pred_1, .terminator = .jump },
        .{ .start = 0x1020, .size = 16, .instruction_count = 4, .successors = &succ_2, .predecessors = &pred_2, .terminator = .@"return" },
    };

    const patterns = try detectPatterns(allocator, &blocks);
    defer freePatterns(allocator, patterns);

    // Should detect the if pattern (2 successors) and the loop (back-edge)
    var found_loop = false;
    for (patterns) |p| {
        if (p.kind == .while_loop) {
            found_loop = true;
            try std.testing.expectEqual(@as(u64, 0x1000), p.head_address);
        }
    }
    try std.testing.expect(found_loop);
}
