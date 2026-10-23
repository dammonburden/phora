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
    // Thumb IT state is contextual; adapters carry the IT instruction metadata.
    it_block: ?arm32.ItBlock = null,
    is_predicated: bool = false,
    opaque_control_flow: bool = false,
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
        .opaque_control_flow = decoded.decode_status != .decoded or std.mem.eql(u8, decoded.mnemonic, "udf"),
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
        .it_block = decoded.it_block,
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
        .size = if (std.mem.eql(u8, decoded.mnemonic, "udf") or std.mem.eql(u8, decoded.mnemonic, "db") or std.mem.eql(u8, decoded.mnemonic, "unsupported")) 0 else decoded.length,
        .mnemonic = decoded.mnemonic,
        .is_branch = decoded.is_branch,
        .is_conditional_branch = decoded.is_conditional_branch,
        .is_call = decoded.is_call,
        .is_return = decoded.is_return,
        .branch_target = decoded.branch_target,
    };
}

/// Adapt the 32-bit x86 decoder without interpreting 0x40..0x4f as REX.
pub fn x86CfgDecode(data: []const u8, address: u64) DecodedInstruction {
    const decoded = @import("../arch/x86_64.zig").decode32(data, address);
    return .{
        .address = address,
        .size = if (std.mem.eql(u8, decoded.mnemonic, "udf") or std.mem.eql(u8, decoded.mnemonic, "db") or std.mem.eql(u8, decoded.mnemonic, "unsupported")) 0 else decoded.length,
        .mnemonic = decoded.mnemonic,
        .is_branch = decoded.is_branch,
        .is_conditional_branch = decoded.is_conditional_branch,
        .is_call = decoded.is_call,
        .is_return = decoded.is_return,
        .branch_target = decoded.branch_target,
    };
}

const BlockWork = struct {
    address: u64,
    it_state: arm32.ItState = .{},
};

/// Build the reachable CFG within the supplied procedure bounds. Direct branch
/// targets outside those bounds remain edges, but are not decoded as blocks.
/// Discover instructions first, then form blocks after every leader is known:
/// a backward branch can introduce a leader inside a path decoded earlier.
pub fn buildCfg(
    allocator: std.mem.Allocator,
    data: []const u8,
    file_offset: usize,
    section_base: u64,
    entry_point: u64,
    proc_size: u64,
    decode: DecodeFn,
) !types.CfgResult {
    return buildCfgWithTables(allocator, data, file_offset, section_base, entry_point, proc_size, decode, &.{}, null);
}

/// Discover ARM64 case blocks before forming basic blocks, then include each
/// proven case in edges and adjacency. All other architectures use direct CFGs.
pub fn buildCfgWithRecovery(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    file_offset: usize,
    section_base: u64,
    entry_point: u64,
    proc_size: u64,
    decode: DecodeFn,
) !types.CfgResult {
    const jumptable = @import("jumptable.zig");
    const tables = try jumptable.recoverArm64(allocator, doc, entry_point, proc_size);
    defer jumptable.freeRecoveredTables(allocator, tables);
    return buildCfgWithTables(allocator, doc.data, file_offset, section_base, entry_point, proc_size, decode, tables, if (doc.arch == .arm64) doc else null);
}

fn buildCfgWithTables(
    allocator: std.mem.Allocator,
    data: []const u8,
    file_offset: usize,
    section_base: u64,
    entry_point: u64,
    proc_size: u64,
    decode: DecodeFn,
    tables: []const @import("jumptable.zig").JumpTable,
    mapped_doc: ?*const types.Document,
) !types.CfgResult {
    const proc_end = std.math.add(u64, entry_point, proc_size) catch return error.InvalidAddressRange;
    if (entry_point < section_base) return error.InvalidAddressRange;

    var instructions = std.AutoHashMap(u64, DecodedInstruction).init(allocator);
    defer instructions.deinit();
    var block_starts = std.AutoHashMap(u64, void).init(allocator);
    defer block_starts.deinit();
    var worklist = std.array_list.Managed(BlockWork).init(allocator);
    defer worklist.deinit();
    try addBlockStart(&block_starts, &worklist, entry_point, .{});

    while (worklist.pop()) |work| {
        var current = work.address;
        var it_state = work.it_state;
        while (current < proc_end and !instructions.contains(current)) {
            var inst = (if (mapped_doc) |doc|
                decodeMappedArm64(doc, current, proc_end, decode)
            else
                decodeAt(data, file_offset, section_base, current, proc_end, decode)) orelse break;
            if (it_state.currentCondition()) |condition| inst.is_predicated = condition < 14;
            if (inst.it_block) |it| it_state.begin(it) else it_state.advance();
            try instructions.put(current, inst);
            const next = current + inst.size;
            if (inst.opaque_control_flow) break;
            if (inst.is_return) {
                if (inst.is_predicated and next < proc_end)
                    try addBlockStart(&block_starts, &worklist, next, it_state);
                break;
            }
            if (inst.is_branch and !inst.is_call) {
                if (inst.branch_target) |target| {
                    if (target >= entry_point and target < proc_end)
                        try addBlockStart(&block_starts, &worklist, target, .{});
                }
                if (inst.branch_target == null) {
                    for (tables) |table| {
                        if (table.branch_addr != current) continue;
                        for (table.cases) |case| try addBlockStart(&block_starts, &worklist, case.target, .{});
                    }
                }
                if ((inst.is_conditional_branch or inst.is_predicated) and next < proc_end)
                    try addBlockStart(&block_starts, &worklist, next, it_state);
                break;
            }
            current = next;
        }
    }

    var sorted_starts = std.array_list.Managed(u64).init(allocator);
    defer sorted_starts.deinit();
    var start_it = block_starts.keyIterator();
    while (start_it.next()) |key| {
        // A truncated or unmapped target is an edge, not an invented block.
        if (instructions.contains(key.*)) try sorted_starts.append(key.*);
    }
    std.mem.sort(u64, sorted_starts.items, {}, std.sort.asc(u64));

    var edges = std.array_list.Managed(types.CfgEdge).init(allocator);
    errdefer edges.deinit();
    var blocks = std.array_list.Managed(types.BasicBlock).init(allocator);
    errdefer {
        for (blocks.items) |block| {
            allocator.free(block.successors);
            allocator.free(block.predecessors);
        }
        blocks.deinit();
    }
    for (sorted_starts.items) |block_start| {
        var current = block_start;
        var block_end = block_start;
        var instruction_count: u32 = 0;
        var terminator: types.Terminator = .fallthrough;
        var successors_list = std.array_list.Managed(u64).init(allocator);
        defer successors_list.deinit();
        while (instructions.get(current)) |inst| {
            const next = current + inst.size;
            block_end = next;
            instruction_count += 1;
            if (inst.opaque_control_flow) {
                terminator = .unknown;
                break;
            }
            if (inst.is_return) {
                terminator = if (inst.is_predicated) .branch else .@"return";
                // The taken path returns to an unknown caller. The untaken
                // path must remain reachable when BX LR is inside Thumb IT.
                if (inst.is_predicated and next < proc_end) {
                    try edges.append(.{ .from = block_start, .to = next, .edge_type = .branch_false });
                    try successors_list.append(next);
                }
                break;
            }
            if (inst.is_branch and !inst.is_call) {
                const conditional = inst.is_conditional_branch or inst.is_predicated;
                terminator = if (conditional) .branch else .jump;
                if (inst.branch_target) |target| {
                    try edges.append(.{
                        .from = block_start,
                        .to = target,
                        .edge_type = if (conditional) .branch_true else .unconditional,
                    });
                    try successors_list.append(target);
                }
                if (inst.branch_target == null) {
                    for (tables) |table| {
                        if (table.branch_addr != current) continue;
                        for (table.cases) |case| {
                            if (std.mem.indexOfScalar(u64, successors_list.items, case.target) != null) continue;
                            try edges.append(.{ .from = block_start, .to = case.target, .edge_type = .unconditional });
                            try successors_list.append(case.target);
                        }
                    }
                }
                if (conditional and next < proc_end) {
                    try edges.append(.{ .from = block_start, .to = next, .edge_type = .branch_false });
                    if (std.mem.indexOfScalar(u64, successors_list.items, next) == null)
                        try successors_list.append(next);
                }
                break;
            }
            if (block_starts.contains(next)) {
                try edges.append(.{ .from = block_start, .to = next, .edge_type = .fallthrough });
                try successors_list.append(next);
                break;
            }
            current = next;
        }
        const successors = try successors_list.toOwnedSlice();
        errdefer allocator.free(successors);
        try blocks.append(.{
            .start = block_start,
            .size = block_end - block_start,
            .instruction_count = instruction_count,
            .successors = successors,
            .predecessors = &.{},
            .terminator = terminator,
        });
    }

    var predecessors = std.AutoHashMap(u64, std.array_list.Managed(u64)).init(allocator);
    defer {
        var pred_it = predecessors.valueIterator();
        while (pred_it.next()) |list| list.deinit();
        predecessors.deinit();
    }
    for (edges.items) |edge| {
        const pred_entry = try predecessors.getOrPut(edge.to);
        if (!pred_entry.found_existing)
            pred_entry.value_ptr.* = std.array_list.Managed(u64).init(allocator);
        // A conditional branch can have the same true/false destination.
        if (std.mem.indexOfScalar(u64, pred_entry.value_ptr.items, edge.from) == null)
            try pred_entry.value_ptr.append(edge.from);
    }
    for (blocks.items) |*block| {
        if (predecessors.get(block.start)) |preds|
            block.predecessors = try allocator.dupe(u64, preds.items);
    }
    const owned_edges = try edges.toOwnedSlice();
    errdefer allocator.free(owned_edges);
    return .{ .basic_blocks = try blocks.toOwnedSlice(), .edges = owned_edges };
}

/// Use Document mappings for recovered ARM64 paths as well as table reads.
/// A section boundary cannot silently switch the decoder to unrelated bytes.
fn decodeMappedArm64(doc: *const types.Document, address: u64, proc_end: u64, decode: DecodeFn) ?DecodedInstruction {
    if (address % 4 != 0 or address >= proc_end or proc_end - address < 4) return null;
    const code_end = doc.codeRangeEnd(address) orelse return null;
    if (code_end - address < 4) return null;
    const bytes = @import("arm64_jumptable.zig").mappedBytes(doc, address, 4) orelse return null;
    const inst = decode(bytes, address);
    if (inst.size != 4) return null;
    return inst;
}

/// Bound the decoder to both the mapped bytes and the procedure. Different
/// architectures have different minimum widths: x86 RET needs just one byte,
/// Thumb instructions can need two, while ARM64 needs four.
fn decodeAt(
    data: []const u8,
    file_offset: usize,
    section_base: u64,
    address: u64,
    proc_end: u64,
    decode: DecodeFn,
) ?DecodedInstruction {
    if (address < section_base or address >= proc_end or file_offset > data.len) return null;
    const delta = address - section_base;
    if (delta >= data.len - file_offset) return null;
    const offset = file_offset + @as(usize, @intCast(delta));
    const remaining: usize = @intCast(@min(proc_end - address, data.len - offset));
    const inst = decode(data[offset..][0..remaining], address);
    if (inst.size == 0 or inst.size > remaining) return null;
    return inst;
}

fn addBlockStart(
    block_starts: *std.AutoHashMap(u64, void),
    worklist: *std.array_list.Managed(BlockWork),
    addr: u64,
    it_state: arm32.ItState,
) !void {
    if (!block_starts.contains(addr)) {
        try block_starts.put(addr, {});
        try worklist.append(.{ .address = addr, .it_state = it_state });
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

/// Add known table case edges to an already-built fixed-width (ARM64/MIPS)
/// graph. This does not decode absent target blocks; a caller must separately
/// discover them before claiming complete reachability. The bounds-check
/// default edge originates at the guard, not at the indirect branch.
/// All edge and adjacency changes commit together, leaving the original graph
/// intact on allocation failure. Repeated case destinations are deduplicated.
pub fn applyJumpTableEdges(
    allocator: std.mem.Allocator,
    result: *types.CfgResult,
    jump_tables: ?std.AutoHashMap(u64, *anyopaque),
) !void {
    const jt_map = jump_tables orelse return;
    if (jt_map.count() == 0) return;
    const jumptable_mod = @import("jumptable.zig");
    var new_edges = std.array_list.Managed(types.CfgEdge).init(allocator);
    defer new_edges.deinit();
    try new_edges.appendSlice(result.edges);
    var pairs = std.AutoHashMap(u128, void).init(allocator);
    defer pairs.deinit();
    for (result.edges) |edge| try pairs.put((@as(u128, edge.from) << 64) | edge.to, {});
    for (result.basic_blocks) |block| {
        if (block.terminator != .jump and block.terminator != .branch) continue;
        if (block.size < 4) continue;
        const term_addr = block.start + block.size - 4;
        const opaque_jt = jt_map.get(term_addr) orelse continue;
        const jt: *jumptable_mod.JumpTable = @ptrCast(@alignCast(opaque_jt));
        for (jt.cases) |c| {
            const pair = try pairs.getOrPut((@as(u128, block.start) << 64) | c.target);
            if (!pair.found_existing)
                try new_edges.append(.{ .from = block.start, .to = c.target, .edge_type = .unconditional });
        }
    }
    if (new_edges.items.len == result.edges.len) return;
    const new_blocks = try rebuildAdjacency(allocator, result.basic_blocks, new_edges.items);
    errdefer {
        for (new_blocks) |block| {
            allocator.free(block.successors);
            allocator.free(block.predecessors);
        }
        allocator.free(new_blocks);
    }
    const owned_edges = try new_edges.toOwnedSlice();
    freeCfgResult(allocator, result);
    result.* = .{ .basic_blocks = new_blocks, .edges = owned_edges };
}

fn rebuildAdjacency(
    allocator: std.mem.Allocator,
    blocks: []const types.BasicBlock,
    edges: []const types.CfgEdge,
) ![]types.BasicBlock {
    const List = std.array_list.Managed(u64);
    const lists = try allocator.alloc(List, blocks.len * 2);
    defer allocator.free(lists);
    for (lists) |*list| list.* = List.init(allocator);
    defer for (lists) |*list| list.deinit();
    var indices = std.AutoHashMap(u64, usize).init(allocator);
    defer indices.deinit();
    for (blocks, 0..) |block, idx| try indices.put(block.start, idx);
    for (edges) |edge| {
        if (indices.get(edge.from)) |idx| {
            const list = &lists[idx * 2];
            if (std.mem.indexOfScalar(u64, list.items, edge.to) == null) try list.append(edge.to);
        }
        if (indices.get(edge.to)) |idx| {
            const list = &lists[idx * 2 + 1];
            if (std.mem.indexOfScalar(u64, list.items, edge.from) == null) try list.append(edge.from);
        }
    }
    const rebuilt = try allocator.alloc(types.BasicBlock, blocks.len);
    var initialized: usize = 0;
    errdefer {
        for (rebuilt[0..initialized]) |block| {
            allocator.free(block.successors);
            allocator.free(block.predecessors);
        }
        allocator.free(rebuilt);
    }
    for (blocks, 0..) |block, idx| {
        const successors = try lists[idx * 2].toOwnedSlice();
        errdefer allocator.free(successors);
        const predecessors = try lists[idx * 2 + 1].toOwnedSlice();
        rebuilt[idx] = block;
        rebuilt[idx].successors = successors;
        rebuilt[idx].predecessors = predecessors;
        initialized += 1;
    }
    return rebuilt;
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

    const data: [64]u8 = @splat(0);
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

test "CFG block ends at the return, not at the inferred procedure end" {
    const data = [_]u8{ 0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90 };
    var result = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, x86_64CfgDecode);
    defer freeCfgResult(std.testing.allocator, &result);
    try std.testing.expectEqual(@as(usize, 1), result.basic_blocks.len);
    try std.testing.expectEqual(@as(u64, 3), result.basic_blocks[0].size);
    try std.testing.expectEqual(@as(u32, 2), result.basic_blocks[0].instruction_count);
    try std.testing.expectEqual(types.Terminator.@"return", result.basic_blocks[0].terminator);
}

test "CFG decodes one-byte x86 and two-byte Thumb tails" {
    const x86 = [_]u8{ 0x31, 0xc0, 0xc3 }; // xor eax,eax; ret
    var x86_cfg = try buildCfg(std.testing.allocator, &x86, 0, 0x1000, 0x1000, x86.len, x86_64CfgDecode);
    defer freeCfgResult(std.testing.allocator, &x86_cfg);
    try std.testing.expectEqual(@as(u64, 3), x86_cfg.basic_blocks[0].size);
    try std.testing.expectEqual(@as(u32, 2), x86_cfg.basic_blocks[0].instruction_count);
    try std.testing.expectEqual(types.Terminator.@"return", x86_cfg.basic_blocks[0].terminator);

    const thumb = [_]u8{ 0x00, 0xbf, 0x70, 0x47 }; // nop; bx lr
    var thumb_cfg = try buildCfg(std.testing.allocator, &thumb, 0, 0x2000, 0x2000, thumb.len, arm32CfgDecode);
    defer freeCfgResult(std.testing.allocator, &thumb_cfg);
    try std.testing.expectEqual(@as(u64, 4), thumb_cfg.basic_blocks[0].size);
    try std.testing.expectEqual(@as(u32, 2), thumb_cfg.basic_blocks[0].instruction_count);
    try std.testing.expectEqual(types.Terminator.@"return", thumb_cfg.basic_blocks[0].terminator);
}

fn arm64TestDecode(data: []const u8, address: u64) DecodedInstruction {
    return fromArm64Decoded(@import("../arch/arm64.zig").decode(data, address), address);
}

test "CFG preserves an external jump without including unreachable following bytes" {
    // Seven instructions followed by B -0x60 matches the control-flow shape
    // observed in ssh's inferred fragment at 0x100037af8. The next instructions
    // belong to other paths; they must not be displayed inside this block.
    const data = [_]u8{
        0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5,
        0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5,
        0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5,
        0x1f, 0x20, 0x03, 0xd5, 0xe8, 0xff, 0xff, 0x17,
        0x40, 0x00, 0x00, 0x54, 0xc0, 0x03, 0x5f, 0xd6,
    };
    var result = try buildCfg(std.testing.allocator, &data, 0, 0x100037af8, 0x100037af8, data.len, arm64TestDecode);
    defer freeCfgResult(std.testing.allocator, &result);
    try std.testing.expectEqual(@as(usize, 1), result.basic_blocks.len);
    try std.testing.expectEqual(@as(u64, 32), result.basic_blocks[0].size);
    try std.testing.expectEqual(@as(u32, 8), result.basic_blocks[0].instruction_count);
    try std.testing.expectEqualSlices(u64, &.{0x100037ab4}, result.basic_blocks[0].successors);
    try std.testing.expectEqual(@as(usize, 1), result.edges.len);
    try std.testing.expectEqual(@as(u64, 0x100037ab4), result.edges[0].to);

    // Structural recovery must safely ignore targets outside this graph while
    // the original CFG retains the external transfer for instruction evidence.
    var structured = try @import("structure.zig").recover(std.testing.allocator, result.basic_blocks, result.edges, result.basic_blocks[0].start);
    defer structured.deinit(std.testing.allocator);
}

test "CFG splits a previously decoded loop and reparents its outgoing edges" {
    const data = [_]u8{ 0x90, 0x90, 0x75, 0xfd, 0xc3 }; // nop; loop: nop; jne loop; ret
    var result = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, x86_64CfgDecode);
    defer freeCfgResult(std.testing.allocator, &result);
    try std.testing.expectEqual(@as(usize, 3), result.basic_blocks.len);
    const entry = result.basic_blocks[0];
    const loop = result.basic_blocks[1];
    const exit = result.basic_blocks[2];
    try std.testing.expectEqual(@as(u64, 1), entry.size);
    try std.testing.expectEqual(types.Terminator.fallthrough, entry.terminator);
    try std.testing.expectEqualSlices(u64, &.{0x1001}, entry.successors);
    try std.testing.expectEqual(@as(u64, 3), loop.size);
    try std.testing.expectEqual(@as(u32, 2), loop.instruction_count);
    try std.testing.expectEqual(types.Terminator.branch, loop.terminator);
    try std.testing.expectEqualSlices(u64, &.{ 0x1001, 0x1004 }, loop.successors);
    try std.testing.expectEqualSlices(u64, &.{ 0x1000, 0x1001 }, loop.predecessors);
    try std.testing.expectEqualSlices(u64, &.{0x1001}, exit.predecessors);
    try std.testing.expectEqual(@as(usize, 3), result.edges.len);
    try std.testing.expectEqual(@as(u64, 0x1001), result.edges[1].from);
    try std.testing.expectEqual(@as(u64, 0x1001), result.edges[2].from);
}

test "CFG splits a join discovered after decoding its return path" {
    // je other; nop; join: nop; ret; other: jmp join
    const data = [_]u8{ 0x74, 0x03, 0x90, 0x90, 0xc3, 0xeb, 0xfc };
    var result = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, x86_64CfgDecode);
    defer freeCfgResult(std.testing.allocator, &result);
    try std.testing.expectEqual(@as(usize, 4), result.basic_blocks.len);
    try std.testing.expectEqual(@as(u64, 1), result.basic_blocks[1].size);
    try std.testing.expectEqual(types.Terminator.fallthrough, result.basic_blocks[1].terminator);
    try std.testing.expectEqualSlices(u64, &.{0x1003}, result.basic_blocks[1].successors);
    try std.testing.expectEqual(@as(u64, 2), result.basic_blocks[2].size);
    try std.testing.expectEqual(types.Terminator.@"return", result.basic_blocks[2].terminator);
    try std.testing.expectEqualSlices(u64, &.{ 0x1002, 0x1005 }, result.basic_blocks[2].predecessors);
}

test "CFG deduplicates adjacency when both branch outcomes reach the same block" {
    const data = [_]u8{ 0x74, 0x00, 0xc3 }; // je next; next: ret
    var result = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, x86_64CfgDecode);
    defer freeCfgResult(std.testing.allocator, &result);
    try std.testing.expectEqualSlices(u64, &.{0x1002}, result.basic_blocks[0].successors);
    try std.testing.expectEqualSlices(u64, &.{0x1000}, result.basic_blocks[1].predecessors);
    try std.testing.expectEqual(@as(usize, 2), result.edges.len); // Preserve each condition.
}

test "CFG rejects zero-width decodes and bounds fixed-width instructions" {
    const zero_decode = struct {
        fn decode(_: []const u8, address: u64) DecodedInstruction {
            var inst = testDecode(undefined, address);
            inst.size = 0;
            return inst;
        }
    }.decode;
    const data = [_]u8{ 0xc0, 0x03, 0x5f, 0xd6 };
    var zero = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, zero_decode);
    defer freeCfgResult(std.testing.allocator, &zero);
    try std.testing.expectEqual(@as(usize, 0), zero.basic_blocks.len);
    var truncated = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, 2, arm64TestDecode);
    defer freeCfgResult(std.testing.allocator, &truncated);
    try std.testing.expectEqual(@as(usize, 0), truncated.basic_blocks.len);
    var unmapped = try buildCfg(std.testing.allocator, &data, 100, 0x1000, 0x1000, data.len, arm64TestDecode);
    defer freeCfgResult(std.testing.allocator, &unmapped);
    try std.testing.expectEqual(@as(usize, 0), unmapped.basic_blocks.len);
    try std.testing.expectError(error.InvalidAddressRange, buildCfg(std.testing.allocator, &data, 0, 0, std.math.maxInt(u64) - 1, 4, arm64TestDecode));
}

fn allocationFailureCfg(allocator: std.mem.Allocator) !void {
    const data = [_]u8{ 0x90, 0x90, 0x75, 0xfd, 0xc3 };
    var result = try buildCfg(allocator, &data, 0, 0x1000, 0x1000, data.len, x86_64CfgDecode);
    defer freeCfgResult(allocator, &result);
}

test "CFG releases partial graphs on every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailureCfg, .{});
}

test "CFG x86 mode treats INC as an instruction rather than a REX prefix" {
    const data = [_]u8{ 0x40, 0xc3 }; // inc eax; ret
    var result = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, x86CfgDecode);
    defer freeCfgResult(std.testing.allocator, &result);
    try std.testing.expectEqual(@as(u64, 2), result.basic_blocks[0].size);
    try std.testing.expectEqual(@as(u32, 2), result.basic_blocks[0].instruction_count);
    try std.testing.expectEqual(types.Terminator.@"return", result.basic_blocks[0].terminator);
}

test "CFG Thumb IT conditional return preserves the untaken path" {
    // cmp r1,r0; itt eq; moveq r0,#0; bxeq lr; movs r0,#1; bx lr
    const data = [_]u8{ 0x81, 0x42, 0x04, 0xbf, 0x00, 0x20, 0x70, 0x47, 0x01, 0x20, 0x70, 0x47 };
    var result = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, arm32CfgDecode);
    defer freeCfgResult(std.testing.allocator, &result);
    try std.testing.expectEqual(@as(usize, 2), result.basic_blocks.len);
    try std.testing.expectEqual(@as(u64, 8), result.basic_blocks[0].size);
    try std.testing.expectEqual(@as(u32, 4), result.basic_blocks[0].instruction_count);
    try std.testing.expectEqual(types.Terminator.branch, result.basic_blocks[0].terminator);
    try std.testing.expectEqualSlices(u64, &.{0x1008}, result.basic_blocks[0].successors);
    try std.testing.expectEqual(.branch_false, result.edges[0].edge_type);
    try std.testing.expectEqual(types.Terminator.@"return", result.basic_blocks[1].terminator);
    try std.testing.expectEqual(@as(u64, 4), result.basic_blocks[1].size);
}

test "CFG Thumb IT predicates a direct branch without dropping fallthrough" {
    // it eq; beq target (encoded as B); nop; target: bx lr
    const data = [_]u8{ 0x08, 0xbf, 0x00, 0xe0, 0x00, 0xbf, 0x70, 0x47 };
    var result = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, arm32CfgDecode);
    defer freeCfgResult(std.testing.allocator, &result);
    try std.testing.expectEqual(@as(usize, 3), result.basic_blocks.len);
    try std.testing.expectEqual(types.Terminator.branch, result.basic_blocks[0].terminator);
    try std.testing.expectEqualSlices(u64, &.{ 0x1006, 0x1004 }, result.basic_blocks[0].successors);
    try std.testing.expectEqual(.branch_true, result.edges[0].edge_type);
    try std.testing.expectEqual(.branch_false, result.edges[1].edge_type);
}

fn graphFixtureDecode(data: []const u8, address: u64) DecodedInstruction {
    var inst = testDecode(data, address);
    switch (data[0]) {
        1 => inst.is_return = true,
        2, 3, 4 => {
            inst.is_branch = true;
            inst.is_conditional_branch = data[0] == 3;
            inst.is_call = data[0] == 4;
            inst.branch_target = 0x1000 + @as(u64, data[1]) * 4;
        },
        else => {},
    }
    return inst;
}

test "CFG randomized graphs partition precisely the reachable instructions" {
    var prng = std.Random.DefaultPrng.init(0x6c756e613330);
    const random = prng.random();
    for (0..256) |_| {
        const count = 64;
        var data: [count * 4]u8 = @splat(0);
        for (0..count) |i| {
            data[4 * i] = random.uintLessThan(u8, 5);
            data[4 * i + 1] = random.uintLessThan(u8, count + 8);
        }
        // Independent instruction-level BFS, without basic blocks.
        var reached: [count]bool = @splat(false);
        var leaders: [count]bool = @splat(false);
        var queue: [count]usize = undefined;
        reached[0] = true;
        leaders[0] = true;
        queue[0] = 0;
        var queued: usize = 1;
        var cursor: usize = 0;
        while (cursor < queued) : (cursor += 1) {
            const i = queue[cursor];
            const kind = data[i * 4];
            var nexts: [2]usize = undefined;
            var n: usize = 0;
            if (kind == 2 or kind == 3) {
                const target = data[i * 4 + 1];
                if (target < count) {
                    nexts[n] = target;
                    n += 1;
                    leaders[target] = true;
                }
            }
            if (kind != 1 and kind != 2 and i + 1 < count) {
                nexts[n] = i + 1;
                n += 1;
                if (kind == 3) leaders[i + 1] = true;
            }
            for (nexts[0..n]) |next| {
                if (!reached[next]) {
                    reached[next] = true;
                    queue[queued] = next;
                    queued += 1;
                }
            }
        }
        var result = try buildCfg(std.testing.allocator, &data, 0, 0x1000, 0x1000, data.len, graphFixtureDecode);
        defer freeCfgResult(std.testing.allocator, &result);
        var covered: [count]u8 = @splat(0);
        var expected_blocks: usize = 0;
        for (leaders) |leader| if (leader) {
            expected_blocks += 1;
        };
        try std.testing.expectEqual(expected_blocks, result.basic_blocks.len);
        for (result.basic_blocks) |block| {
            const first: usize = @intCast((block.start - 0x1000) / 4);
            const end: usize = first + @as(usize, @intCast(block.size / 4));
            try std.testing.expect(leaders[first]);
            try std.testing.expect(end <= count and end > first);
            try std.testing.expectEqual(@as(u32, @intCast(end - first)), block.instruction_count);
            for (first..end) |i| {
                covered[i] += 1;
                if (i + 1 < end) {
                    try std.testing.expect(data[i * 4] == 0 or data[i * 4] == 4);
                    try std.testing.expect(!leaders[i + 1]);
                }
            }
            const kind = data[(end - 1) * 4];
            const expected_terminator: types.Terminator = switch (kind) {
                1 => .@"return",
                2 => .jump,
                3 => .branch,
                else => .fallthrough,
            };
            try std.testing.expectEqual(expected_terminator, block.terminator);
            var expected_successors: [2]u64 = undefined;
            var expected_count: usize = 0;
            if (kind == 2 or kind == 3) {
                expected_successors[0] = 0x1000 + @as(u64, data[(end - 1) * 4 + 1]) * 4;
                expected_count = 1;
            }
            if (kind != 1 and kind != 2 and end < count) {
                const next = 0x1000 + @as(u64, @intCast(end)) * 4;
                if (expected_count == 0 or expected_successors[0] != next) {
                    expected_successors[expected_count] = next;
                    expected_count += 1;
                }
            }
            try std.testing.expectEqualSlices(u64, expected_successors[0..expected_count], block.successors);
        }
        for (reached, covered) |reachable, coverage|
            try std.testing.expectEqual(@as(u8, if (reachable) 1 else 0), coverage);
    }
}

fn tableFixtureDecode(_: []const u8, address: u64) DecodedInstruction {
    return .{
        .address = address,
        .size = 4,
        .mnemonic = "fixture",
        .is_branch = address < 0x1008,
        .is_conditional_branch = address == 0x1000,
        .is_call = false,
        .is_return = address >= 0x1008,
        .branch_target = if (address == 0x1000) 0x100c else null,
    };
}

fn tableAdjacencyAllocationTest(a: std.mem.Allocator) !void {
    const t = std.testing;
    var result = try buildCfg(a, &@as([16]u8, @splat(0)), 0, 0x1000, 0x1000, 16, tableFixtureDecode);
    defer freeCfgResult(a, &result);
    const old_blocks = result.basic_blocks.ptr;
    const old_edges = result.edges.ptr;
    const jt = @import("jumptable.zig");
    var cases = [_]jt.JumpTableCase{
        .{ .value = 0, .target = 0x100c },
        .{ .value = 1, .target = 0x100c },
        .{ .value = 2, .target = 0x2000 },
    };
    var table = jt.JumpTable{
        .branch_addr = 0x1004,
        .table_addr = 0x3000,
        .entry_count = 3,
        .entry_width = 8,
        .entries_are_absolute = true,
        .base_addr = 0,
        .cases = &cases,
        .default_target = 0x1008, // belongs to a guard, not this BR
    };
    var map = std.AutoHashMap(u64, *anyopaque).init(t.allocator);
    defer map.deinit();
    try map.put(table.branch_addr, @ptrCast(&table));
    applyJumpTableEdges(a, &result, map) catch |err| {
        try t.expectEqual(old_blocks, result.basic_blocks.ptr);
        try t.expectEqual(old_edges, result.edges.ptr);
        try t.expectEqual(@as(usize, 2), result.edges.len);
        try t.expectEqual(@as(usize, 0), result.basic_blocks[1].successors.len);
        try t.expectEqualSlices(u64, &.{0x1000}, result.basic_blocks[2].predecessors);
        return err;
    };
    try t.expectEqual(@as(usize, 4), result.edges.len);
    try t.expectEqualSlices(u64, &.{ 0x100c, 0x2000 }, result.basic_blocks[1].successors);
    try t.expectEqualSlices(u64, &.{ 0x1000, 0x1004 }, result.basic_blocks[2].predecessors);
    // Idempotence includes adjacency and no invented default edge.
    try applyJumpTableEdges(a, &result, map);
    try t.expectEqual(@as(usize, 4), result.edges.len);
}

test "known table edges update adjacency atomically with duplicate and external targets" {
    try tableAdjacencyAllocationTest(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, tableAdjacencyAllocationTest, .{});
}
