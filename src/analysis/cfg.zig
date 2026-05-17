// Phora — Control Flow Graph Builder
// Recursive descent: entry points + call targets → basic blocks → edges.
// A basic block is a maximal sequence of instructions with no branches except at the end.

const std = @import("std");
const types = @import("../types.zig");
const arm32 = @import("../arch/arm32.zig");

/// Decoded instruction info needed for CFG construction.
/// Architecture-agnostic — adapters bridge from specific decoders.
pub const DecodedInstruction = struct {
    address: u64,
    size: u8,
    mnemonic: []const u8,
    is_branch: bool,
    is_conditional_branch: bool,
    is_call: bool,
    is_return: bool,
    branch_target: ?u64,
};

/// Instruction decoder function type.
/// Given binary data and an address, decode one instruction.
pub const DecodeFn = *const fn (data: []const u8, address: u64) DecodedInstruction;

/// Adapt an arm64.DecodedInstruction to a CFG DecodedInstruction.
pub fn fromArm64Decoded(
    decoded: anytype,
    address: u64,
) DecodedInstruction {
    return .{
        .address = address,
        .size = decoded.length,
        .mnemonic = decoded.mnemonic,
        .is_branch = decoded.is_branch,
        .is_conditional_branch = decoded.is_conditional_branch,
        .is_call = decoded.is_call,
        .is_return = decoded.is_return,
        .branch_target = decoded.branch_target,
    };
}

/// Adapt an arm32 DecodedInstruction to a CFG DecodedInstruction.
/// Matches the DecodeFn signature: fn([]const u8, u64) -> DecodedInstruction.
pub fn arm32CfgDecode(data: []const u8, address: u64) DecodedInstruction {
    const decoded = arm32.decode(data, address);
    return .{
        .address = address,
        .size = decoded.length,
        .mnemonic = decoded.mnemonic,
        .is_branch = decoded.is_branch,
        .is_conditional_branch = decoded.is_conditional_branch,
        .is_call = decoded.is_call,
        .is_return = decoded.is_return,
        .branch_target = decoded.branch_target,
    };
}

/// Adapt a mips32 DecodedInstruction to a CFG DecodedInstruction.
/// Matches the DecodeFn signature: fn([]const u8, u64) -> DecodedInstruction.
/// Note: delay slot handling is NOT done here — callers must account for it.
pub fn mips32CfgDecode(data: []const u8, address: u64) DecodedInstruction {
    const mips32_decoder = @import("../arch/mips32.zig");
    const decoded = mips32_decoder.decode(data, address);
    return .{
        .address = address,
        .size = decoded.length,
        .mnemonic = decoded.mnemonic,
        .is_branch = decoded.is_branch,
        .is_conditional_branch = decoded.is_conditional_branch,
        .is_call = decoded.is_call,
        .is_return = decoded.is_return,
        .branch_target = decoded.branch_target,
    };
}

/// Adapt an x86_64 DecodedInstruction to a CFG DecodedInstruction.
/// Matches the DecodeFn signature: fn([]const u8, u64) -> DecodedInstruction.
pub fn x86_64CfgDecode(data: []const u8, address: u64) DecodedInstruction {
    const x86_64_dec = @import("../arch/x86_64.zig");
    const decoded = x86_64_dec.decode(data, address);
    return .{
        .address = address,
        .size = decoded.length,
        .mnemonic = decoded.mnemonic,
        .is_branch = decoded.is_branch,
        .is_conditional_branch = decoded.is_conditional_branch,
        .is_call = decoded.is_call,
        .is_return = decoded.is_return,
        .branch_target = decoded.branch_target,
    };
}

/// Build a CFG for a procedure starting at entry_point.
/// Uses recursive descent: explores all reachable paths from the entry.
pub fn buildCfg(
    allocator: std.mem.Allocator,
    data: []const u8,
    file_offset: usize,
    section_base: u64,
    entry_point: u64,
    proc_size: u64,
    decode: DecodeFn,
) !types.CfgResult {
    var block_starts = std.AutoHashMap(u64, void).init(allocator);
    defer block_starts.deinit();

    var block_terminators = std.AutoHashMap(u64, BlockTermInfo).init(allocator);
    defer block_terminators.deinit();

    var edges = std.array_list.Managed(types.CfgEdge).init(allocator);
    errdefer edges.deinit();

    // Worklist for recursive descent
    var worklist = std.array_list.Managed(u64).init(allocator);
    defer worklist.deinit();

    var visited = std.AutoHashMap(u64, void).init(allocator);
    defer visited.deinit();

    // Start at the entry point
    try worklist.append(entry_point);
    try block_starts.put(entry_point, {});

    const proc_end = entry_point + proc_size;

    while (worklist.items.len > 0) {
        const addr = worklist.pop().?;
        if (visited.contains(addr)) continue;
        try visited.put(addr, {});

        // Bounds check
        if (addr < section_base or addr >= proc_end) continue;

        const offset_in_data = file_offset + (addr - section_base);
        if (offset_in_data >= data.len) continue;

        // Decode instructions linearly until we hit a terminator
        var current = addr;
        while (current < proc_end) {
            const cur_offset = file_offset + (current - section_base);
            if (cur_offset + 4 > data.len) break;

            const inst = decode(data[cur_offset..], current);

            if (inst.is_return) {
                try block_terminators.put(addr, .{
                    .terminator_addr = current,
                    .kind = .ret,
                    .target = null,
                });
                break;
            } else if (inst.is_branch and !inst.is_call) {
                if (inst.is_conditional_branch) {
                    // Conditional branch: two successors (target + fallthrough)
                    const fallthrough = current + inst.size;
                    try block_terminators.put(addr, .{
                        .terminator_addr = current,
                        .kind = .conditional_branch,
                        .target = inst.branch_target,
                    });

                    if (inst.branch_target) |target| {
                        if (target >= entry_point and target < proc_end) {
                            try addBlockStart(&block_starts, &worklist, target);
                            try edges.append(.{
                                .from = addr,
                                .to = target,
                                .edge_type = .branch_true,
                            });
                        }
                    }
                    if (fallthrough < proc_end) {
                        try addBlockStart(&block_starts, &worklist, fallthrough);
                        try edges.append(.{
                            .from = addr,
                            .to = fallthrough,
                            .edge_type = .branch_false,
                        });
                    }
                    break;
                } else {
                    // Unconditional branch
                    try block_terminators.put(addr, .{
                        .terminator_addr = current,
                        .kind = .unconditional_branch,
                        .target = inst.branch_target,
                    });

                    if (inst.branch_target) |target| {
                        if (target >= entry_point and target < proc_end) {
                            try addBlockStart(&block_starts, &worklist, target);
                            try edges.append(.{
                                .from = addr,
                                .to = target,
                                .edge_type = .unconditional,
                            });
                        }
                    }
                    break;
                }
            } else if (inst.is_call) {
                // Calls don't terminate blocks — execution continues at fallthrough
                current += inst.size;

                // But if the next address starts a new block, we need to split
                if (block_starts.contains(current)) {
                    try block_terminators.put(addr, .{
                        .terminator_addr = current - inst.size,
                        .kind = .fallthrough,
                        .target = null,
                    });
                    try edges.append(.{
                        .from = addr,
                        .to = current,
                        .edge_type = .fallthrough,
                    });
                    break;
                }
            } else {
                const next = current + inst.size;

                // If the next instruction is the start of another block, end this one
                if (block_starts.contains(next) and next != addr) {
                    try block_terminators.put(addr, .{
                        .terminator_addr = current,
                        .kind = .fallthrough,
                        .target = null,
                    });
                    try edges.append(.{
                        .from = addr,
                        .to = next,
                        .edge_type = .fallthrough,
                    });
                    break;
                }

                current = next;
            }
        }

        // If we exited the loop without a terminator, add a fallthrough
        if (!block_terminators.contains(addr)) {
            try block_terminators.put(addr, .{
                .terminator_addr = current,
                .kind = .fallthrough,
                .target = null,
            });
        }
    }

    // Build BasicBlock structs from collected data
    // Sort block starts by address
    var sorted_starts = std.array_list.Managed(u64).init(allocator);
    defer sorted_starts.deinit();

    var start_it = block_starts.keyIterator();
    while (start_it.next()) |key| {
        try sorted_starts.append(key.*);
    }
    std.mem.sort(u64, sorted_starts.items, {}, std.sort.asc(u64));

    var blocks = std.array_list.Managed(types.BasicBlock).init(allocator);
    errdefer blocks.deinit();

    // Build predecessor map
    var predecessors = std.AutoHashMap(u64, std.array_list.Managed(u64)).init(allocator);
    defer {
        var pred_it = predecessors.valueIterator();
        while (pred_it.next()) |list| {
            list.deinit();
        }
        predecessors.deinit();
    }

    for (edges.items) |edge| {
        const pred_entry = try predecessors.getOrPut(edge.to);
        if (!pred_entry.found_existing) {
            pred_entry.value_ptr.* = std.array_list.Managed(u64).init(allocator);
        }
        try pred_entry.value_ptr.append(edge.from);
    }

    for (sorted_starts.items, 0..) |block_start, i| {
        const term_info = block_terminators.get(block_start) orelse continue;

        // Calculate block size
        const next_start = if (i + 1 < sorted_starts.items.len)
            sorted_starts.items[i + 1]
        else
            proc_end;

        const block_size = @min(next_start, proc_end) - block_start;

        // Count instructions (ARM64: 4 bytes each)
        const inst_count: u32 = @intCast(block_size / 4);

        // Collect successors from edges
        var successors = std.array_list.Managed(u64).init(allocator);
        for (edges.items) |edge| {
            if (edge.from == block_start) {
                try successors.append(edge.to);
            }
        }

        // Get predecessors
        const preds = if (predecessors.get(block_start)) |list|
            try allocator.dupe(u64, list.items)
        else
            try allocator.alloc(u64, 0);

        const terminator: types.Terminator = switch (term_info.kind) {
            .ret => .@"return",
            .conditional_branch => .branch,
            .unconditional_branch => .jump,
            .fallthrough => .fallthrough,
        };

        try blocks.append(.{
            .start = block_start,
            .size = block_size,
            .instruction_count = inst_count,
            .successors = try successors.toOwnedSlice(),
            .predecessors = preds,
            .terminator = terminator,
        });
    }

    return .{
        .basic_blocks = try blocks.toOwnedSlice(),
        .edges = try edges.toOwnedSlice(),
    };
}

const BlockTermKind = enum {
    ret,
    conditional_branch,
    unconditional_branch,
    fallthrough,
};

const BlockTermInfo = struct {
    terminator_addr: u64,
    kind: BlockTermKind,
    target: ?u64,
};

fn addBlockStart(
    block_starts: *std.AutoHashMap(u64, void),
    worklist: *std.array_list.Managed(u64),
    addr: u64,
) !void {
    if (!block_starts.contains(addr)) {
        try block_starts.put(addr, {});
        try worklist.append(addr);
    }
}

/// Free CFG result memory.
pub fn freeCfgResult(allocator: std.mem.Allocator, result: *types.CfgResult) void {
    for (result.basic_blocks) |block| {
        allocator.free(block.successors);
        allocator.free(block.predecessors);
    }
    allocator.free(result.basic_blocks);
    allocator.free(result.edges);
}

/// v7.8.0 W3 wiring — enrich an already-built CFG with case→target edges
/// derived from the v7.8.0 jump-table phase. For each block whose terminator
/// is a `jump`/`branch` (i.e. an unconditional or indirect terminator) and
/// whose terminator address has a matching entry in `jump_tables`, append
/// one edge per case target.
///
/// `jump_tables` is the `*anyopaque` map stored on `Document` — we cast to
/// the concrete `JumpTable` type internally. Pass `null` to leave the CFG
/// unchanged.
///
/// The CFG's edge enum doesn't have a `.case` variant; we use
/// `.unconditional` for case edges (matches the project guidance: "good
/// enough"). Existing `.branch_true`/`.branch_false`/`.unconditional`/
/// `.fallthrough` edges are preserved.
///
/// On allocation failure, returns the error and leaves `result.edges`
/// reallocated to a temporary length — callers should treat this as a CFG
/// that may be partially extended.
pub fn applyJumpTableEdges(
    allocator: std.mem.Allocator,
    result: *types.CfgResult,
    jump_tables: ?std.AutoHashMap(u64, *anyopaque),
) !void {
    const jt_map = jump_tables orelse return;
    if (jt_map.count() == 0) return;

    const jumptable_mod = @import("jumptable.zig");

    var new_edges = std.array_list.Managed(types.CfgEdge).init(allocator);
    errdefer new_edges.deinit();
    try new_edges.appendSlice(result.edges);

    // Walk basic blocks; if the block's terminator address matches a
    // jump-table branch, emit one case edge per target.
    //
    // We approximate "terminator address" as `block.start + block.size - 4`
    // (ARM64/MIPS32 fixed 4-byte instructions). This is correct for those
    // archs and the only ones the v7.8.0 maturity pipeline currently runs
    // on. For x86_64 / ARM32 (variable width) we'd need terminator info
    // attached to BasicBlock — left for W8.
    for (result.basic_blocks) |block| {
        if (block.terminator != .jump and block.terminator != .branch) continue;
        if (block.size < 4) continue;
        const term_addr = block.start + block.size - 4;
        const opaque_jt = jt_map.get(term_addr) orelse continue;
        const jt: *jumptable_mod.JumpTable = @ptrCast(@alignCast(opaque_jt));
        for (jt.cases) |c| {
            try new_edges.append(.{
                .from = block.start,
                .to = c.target,
                .edge_type = .unconditional,
            });
        }
        if (jt.default_target) |dt| {
            try new_edges.append(.{
                .from = block.start,
                .to = dt,
                .edge_type = .unconditional,
            });
        }
    }

    if (new_edges.items.len == result.edges.len) {
        new_edges.deinit();
        return;
    }

    allocator.free(result.edges);
    result.edges = try new_edges.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

// Simple test decode function for unit testing.
// Treats every 4 bytes as a normal instruction unless it matches special patterns.
fn testDecode(data: []const u8, address: u64) DecodedInstruction {
    _ = data;
    // For testing: use address-based patterns
    return .{
        .address = address,
        .size = 4,
        .mnemonic = "nop",
        .is_branch = false,
        .is_conditional_branch = false,
        .is_call = false,
        .is_return = false,
        .branch_target = null,
    };
}

test "single block procedure" {
    // A procedure with just a RET — single basic block
    const allocator = std.testing.allocator;

    const ret_decode = struct {
        fn decode(_: []const u8, address: u64) DecodedInstruction {
            // First instruction is NOP, second is RET
            if (address == 0x1004) {
                return .{
                    .address = address,
                    .size = 4,
                    .mnemonic = "ret",
                    .is_branch = false,
                    .is_conditional_branch = false,
                    .is_call = false,
                    .is_return = true,
                    .branch_target = null,
                };
            }
            return testDecode(undefined, address);
        }
    }.decode;

    const data = [_]u8{0} ** 64;
    var result = try buildCfg(
        allocator,
        &data,
        0,
        0x1000,
        0x1000,
        64,
        ret_decode,
    );

    defer freeCfgResult(allocator, &result);

    try std.testing.expectEqual(@as(usize, 1), result.basic_blocks.len);
    try std.testing.expectEqual(@as(u64, 0x1000), result.basic_blocks[0].start);
    try std.testing.expect(result.basic_blocks[0].terminator == .@"return");
}
