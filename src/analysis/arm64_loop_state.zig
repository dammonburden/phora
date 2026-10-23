//! Bounded predecessor-specific bindings for the names in arm64_steps.
//! No expression substitution or recurrence solving: each writer remains an
//! instruction on the path actually traversed, including a loop backedge.
const std = @import("std");
const types = @import("../types.zig");
const steps = @import("arm64_steps.zig");

pub const max_blocks = 512;
pub const max_edges = 4096;
pub const max_instructions = 4096;
pub const max_work = 262144;
pub const max_bindings = 128;
const flags_channel = 32;
const no_edge = std.math.maxInt(u16);
const all_channels: u64 = (@as(u64, 1) << 33) - 1;
const Origin = struct { address: u64 = 0, width: u7 = 64, literal: ?u64 = null, kind: enum { incoming, writer, unknown } = .incoming };
pub const Evidence = struct {
    status: enum { derived, omitted_graph_budget, omitted_instruction_budget, omitted_invalid_block } = .derived,
    block_count: usize = 0,
    instructions: usize = 0,
    edge_count: usize = 0,
    first_pred: [max_blocks]u16 = @splat(no_edge),
    next_pred: [max_edges]u16 = @splat(no_edge),
    edge_from: [max_edges]u16 = @splat(no_edge),
    live_in: [max_blocks]u64 = @splat(0),
    final: [max_blocks][33]Origin = @splat(@splat(.{})),
};
pub const Budget = struct {
    remaining: usize = max_work,
    bindings: usize = 0,
    exhausted: bool = false,
    truncated: bool = false,
    fn take(self: *Budget) bool {
        if (self.remaining == 0) {
            self.exhausted = true;
            return false;
        }
        self.remaining -= 1;
        return true;
    }
};
fn bit(reg: u5, sp: bool) u64 {
    return if (reg == 31 and !sp) 0 else @as(u64, 1) << reg;
}
fn readMask(e: steps.Effect) u64 {
    const left = bit(e.src[0], e.src_sp);
    const right = bit(e.src[1], false);
    return switch (e.op) {
        .add, .sub, .and_, .or_, .xor => left | (if (e.immediate == null) right else 0),
        .movk, .extract, .lsl, .load, .cbz, .cbnz, .tbz, .tbnz, .ret => left,
        .madd, .msub => left | right | bit(e.src[2], false),
        .store => left | right | (if (e.pair) bit(e.src[2], false) else 0),
        .csel => left | right | (if (e.condition < 14) @as(u64, 1) << flags_channel else 0),
        .bcond => if (e.condition < 14) @as(u64, 1) << flags_channel else 0,
        .movz, .movn, .branch, .nop => 0,
    };
}
fn writes(e: steps.Effect, origins: *[33]Origin, address: u64) u64 {
    var mask: u64 = 0;
    switch (e.op) {
        .branch, .bcond, .cbz, .cbnz, .tbz, .tbnz, .ret, .nop, .store => {},
        else => {
            mask = bit(e.dst, e.dst_sp);
            if (mask != 0) origins[e.dst] = .{ .kind = .writer, .address = address, .width = if (e.op == .load and e.width < 32) 32 else e.width };
        },
    }
    if (e.op == .movz or e.op == .movn) {
        if (mask != 0) origins[e.dst].literal = if (e.op == .movz) e.immediate.? else if (e.width == 32) @as(u32, @truncate(~e.immediate.?)) else ~e.immediate.?;
    }
    if (e.op == .load and e.pair and e.src[2] != 31) {
        mask |= bit(e.src[2], false);
        origins[e.src[2]] = .{ .kind = .writer, .address = address, .width = e.width };
    }
    if ((e.op == .load or e.op == .store) and e.writeback) {
        mask |= bit(e.src[0], true);
        origins[e.src[0]] = .{ .kind = .writer, .address = address };
    }
    if (e.flags) {
        mask |= @as(u64, 1) << flags_channel;
        origins[flags_channel] = .{ .kind = .writer, .address = address };
    }
    return mask;
}
/// `words.word(address) ?u32` supplies original little-endian instruction words.
/// Cache once over the full graph, independent of pagination. All instruction
/// effects use exactly arm64_steps.decode's accepted subset.
pub fn derive(bs: []const types.BasicBlock, es: []const types.CfgEdge, words: anytype) Evidence {
    var out: Evidence = .{ .block_count = bs.len };
    if (bs.len > max_blocks or es.len > max_edges) {
        out.status = .omitted_graph_budget;
        return out;
    }
    out.edge_count = es.len;
    var last_pred: [max_blocks]u16 = @splat(no_edge);
    for (es, 0..) |edge_value, edge_i| {
        const to = index(bs, edge_value.to) orelse continue;
        out.edge_from[edge_i] = if (index(bs, edge_value.from)) |from| @intCast(from) else no_edge;
        if (last_pred[to] == no_edge) out.first_pred[to] = @intCast(edge_i) else out.next_pred[last_pred[to]] = @intCast(edge_i);
        last_pred[to] = @intCast(edge_i);
    }
    for (bs, 0..) |b, i| {
        if (b.start % 4 != 0 or b.size % 4 != 0 or b.size > std.math.maxInt(u64) - b.start) {
            out.status = .omitted_invalid_block;
            return out;
        }
        if (b.size / 4 > max_instructions - out.instructions) {
            out.status = .omitted_instruction_budget;
            return out;
        }
        out.instructions += @intCast(b.size / 4);
        var defined: u64 = 0;
        var address = b.start;
        while (address < b.start + b.size) : (address += 4) {
            const effect = if (words.word(address)) |word| steps.decode(word) else null;
            if (effect) |e| {
                out.live_in[i] |= readMask(e) & ~defined;
                defined |= writes(e, &out.final[i], address);
            } else {
                // An opaque step reads arbitrary state, but no supported
                // incoming binding can explain it. Later reads are unknown
                // until rewritten, just as in arm64_steps.
                defined = all_channels;
                out.final[i] = @splat(.{ .kind = .unknown, .address = address });
            }
        }
    }
    return out;
}
fn index(bs: []const types.BasicBlock, address: u64) ?usize {
    for (bs, 0..) |b, i| if (b.start == address) return i;
    return null;
}
const Sources = struct {
    origins: [16]Origin = undefined,
    count: usize = 0,
    entry: bool = false,
    unknown: bool = false,
    revisited: bool = false,
    budget_exhausted: bool = false,
};
fn resolve(ev: *const Evidence, bs: []const types.BasicBlock, es: []const types.CfgEdge, first: usize, channel: u6, entry_addr: u64, budget: *Budget) Sources {
    _ = es;
    var out: Sources = .{};
    var seen: [max_blocks]bool = @splat(false);
    var queue: [max_blocks]usize = undefined;
    queue[0] = first;
    seen[first] = true;
    var end: usize = 1;
    var cursor: usize = 0;
    while (cursor < end) : (cursor += 1) {
        if (!budget.take()) {
            out.unknown = true;
            out.budget_exhausted = true;
            return out;
        }
        const block = queue[cursor];
        const origin = ev.final[block][channel];
        switch (origin.kind) {
            .unknown => {
                out.unknown = true;
                continue;
            },
            .writer => {
                var duplicate = false;
                for (out.origins[0..out.count]) |old| if (old.address == origin.address) {
                    duplicate = true;
                    break;
                };
                if (!duplicate) {
                    if (out.count == out.origins.len) out.unknown = true else {
                        out.origins[out.count] = origin;
                        out.count += 1;
                    }
                }
                continue;
            },
            .incoming => {},
        }
        if (bs[block].start == entry_addr) out.entry = true;
        var predecessors: usize = 0;
        var edge_i = ev.first_pred[block];
        while (edge_i != no_edge) : (edge_i = ev.next_pred[edge_i]) {
            if (!budget.take()) {
                out.unknown = true;
                out.budget_exhausted = true;
                return out;
            }
            predecessors += 1;
            const pred = ev.edge_from[edge_i];
            if (pred == no_edge) {
                out.unknown = true;
                continue;
            }
            if (seen[pred]) {
                // Conservatively includes converging paths; never claim an
                // invariant through an unproven no-write cycle.
                out.revisited = true;
                out.unknown = true;
            } else {
                seen[pred] = true;
                queue[end] = pred;
                end += 1;
            }
        }
        if (predecessors == 0 and bs[block].start != entry_addr) out.unknown = true;
    }
    return out;
}
fn rebased(address: u64, delta: i128) u64 {
    return @intCast(@max(0, @min(@as(i128, address) + delta, std.math.maxInt(u64))));
}
fn name(w: anytype, channel: u6, width: u7) !void {
    if (channel == flags_channel) return w.writeAll("NZCV");
    if (channel == 31) return w.writeAll(if (width == 32) "wsp" else "sp");
    try w.print("{s}{d}", .{ if (width == 32) @as([]const u8, "w") else "x", channel });
}
fn writerRef(w: anytype, channel: u6, origin: Origin, delta: i128) !void {
    if (origin.width == 32 and channel != flags_channel) try w.writeAll("zext32(");
    try name(w, channel, origin.width);
    try w.print("@0x{x}", .{rebased(origin.address, delta)});
    if (origin.width == 32 and channel != flags_channel) try w.writeByte(')');
    if (origin.literal) |literal| try w.print(" [u{d} literal {d}]", .{ origin.width, literal });
}
/// Append text inside the corresponding execution block, preferably before
/// its local equations. One shared Budget bounds the whole response. A single
/// exact source is an equation; alternatives/unknowns remain explicitly sets.
pub fn writeBlockText(w: anytype, ev: *const Evidence, bs: []const types.BasicBlock, es: []const types.CfgEdge, delta: i128, block_index: usize, entry_addr: u64, budget: *Budget) !void {
    if (ev.status != .derived) return w.print("  incoming bindings OMITTED: {s}\n", .{@tagName(ev.status)});
    if (block_index >= bs.len or ev.block_count != bs.len or ev.edge_count != es.len) return error.InvalidBlockIndex;
    if (budget.bindings >= max_bindings or budget.exhausted) {
        budget.truncated = true;
        return w.writeAll("  incoming bindings OMITTED: shared binding/work limit\n");
    }
    var reads = ev.live_in[block_index];
    if (reads == 0) return;
    try w.writeAll("  Incoming bindings (selected predecessor's final current value; recovered edges only):\n");
    while (reads != 0) {
        const channel: u6 = @intCast(@ctz(reads));
        reads &= reads - 1;
        if (budget.bindings >= max_bindings) {
            budget.truncated = true;
            try w.writeAll("    OMITTED remaining bindings: shared binding limit128\n");
            return;
        }
        budget.bindings += 1;
        try w.writeAll("    ");
        try name(w, channel, 64);
        try w.print("@in_0x{x}: ", .{rebased(bs[block_index].start, delta)});
        var predecessors: usize = 0;
        if (bs[block_index].start == entry_addr) {
            try w.writeAll("on function entry = ");
            try name(w, channel, 64);
            try w.writeAll("@function_entry; ");
        }
        var edge_i = ev.first_pred[block_index];
        while (edge_i != no_edge) : (edge_i = ev.next_pred[edge_i]) {
            if (!budget.take()) {
                budget.truncated = true;
                try w.writeAll("; OMITTED predecessors: shared work_limit");
                break;
            }
            const edge_value = es[edge_i];
            predecessors += 1;
            if (predecessors > 16) {
                budget.truncated = true;
                continue;
            }
            if (predecessors > 1) try w.writeAll("; ");
            try w.print("via 0x{x} ", .{rebased(edge_value.from, delta)});
            const sources = if (ev.edge_from[edge_i] != no_edge) resolve(ev, bs, es, ev.edge_from[edge_i], channel, entry_addr, budget) else Sources{ .unknown = true };
            const exact = sources.count + @intFromBool(sources.entry) == 1 and !sources.unknown;
            try w.writeAll(if (exact) "= " else "possible{");
            var printed: usize = 0;
            for (sources.origins[0..sources.count]) |origin| {
                if (printed != 0) try w.writeAll(", ");
                try writerRef(w, channel, origin, delta);
                printed += 1;
            }
            if (sources.entry) {
                if (printed != 0) try w.writeAll(", ");
                try name(w, channel, 64);
                try w.writeAll("@function_entry");
                printed += 1;
            }
            if (sources.unknown) {
                if (printed != 0) try w.writeAll(", ");
                try w.writeAll("unknown");
            }
            if (!exact) try w.writeByte('}');
            if (sources.revisited) try w.writeAll(" [cycle_or_revisited_no_write_path]");
            if (sources.budget_exhausted) try w.writeAll(" [work_limit]");
        }
        if (predecessors == 0 and bs[block_index].start != entry_addr and !budget.exhausted) try w.writeAll("unknown (no recovered predecessor)");
        if (predecessors > 16) try w.print("; OMITTED {d} predecessors", .{predecessors - 16});
        try w.writeByte('\n');
    }
}

fn testBlock(address: u64, size: u64) types.BasicBlock {
    return .{ .start = address, .size = size, .instruction_count = @intCast(size / 4), .successors = &.{}, .predecessors = &.{}, .terminator = .jump };
}
fn testEdge(from: u64, to: u64) types.CfgEdge {
    return .{ .from = from, .to = to, .edge_type = .unconditional };
}
const TestWords = struct {
    words: []const u32,
    pub fn word(self: @This(), address: u64) ?u32 {
        return if (address / 4 < self.words.len) self.words[@intCast(address / 4)] else null;
    }
};
test "predecessor bindings distinguish initialization and each carried update" {
    // mov w11,#1; add w11,w11,#1; b self; add x0,x11,#1
    const bs = [_]types.BasicBlock{ testBlock(0, 4), testBlock(4, 8), testBlock(12, 4) };
    const es = [_]types.CfgEdge{ testEdge(0, 4), testEdge(4, 4), testEdge(4, 12) };
    const ev = derive(&bs, &es, TestWords{ .words = &.{ 0x5280002b, 0x1100056b, 0x14000000, 0x91000560 } });
    var budget: Budget = .{};
    var w = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer w.deinit();
    try writeBlockText(&w.writer, &ev, &bs, &es, 4096, 1, 0, &budget);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "x11@in_0x1004: via 0x1000 = zext32(w11@0x1000) [u32 literal 1]; via 0x1004 = zext32(w11@0x1004)") != null);
    try std.testing.expectEqual(@as(usize, 1), budget.bindings);
    const exit = resolve(&ev, &bs, &es, 1, 11, 0, &budget);
    try std.testing.expectEqual(@as(usize, 1), exit.count);
    try std.testing.expectEqual(@as(u64, 4), exit.origins[0].address);
}
test "barriers, missing bytes and no-write cycles do not forward initializer" {
    const bs = [_]types.BasicBlock{ testBlock(0, 4), testBlock(4, 4), testBlock(8, 4) };
    const es = [_]types.CfgEdge{ testEdge(0, 4), testEdge(4, 8), testEdge(8, 8) };
    const ev = derive(&bs, &es, TestWords{ .words = &.{ 0x5280002b, 0x94000000, 0x14000000 } });
    var budget: Budget = .{};
    const call = resolve(&ev, &bs, &es, 1, 11, 0, &budget);
    try std.testing.expect(call.unknown and call.count == 0);
    const cycle = resolve(&ev, &bs, &es, 2, 11, 0, &budget);
    try std.testing.expect(cycle.unknown and cycle.revisited and cycle.count == 0);
    const absent = derive(&bs, &es, TestWords{ .words = &.{} });
    try std.testing.expect(resolve(&absent, &bs, &es, 0, 11, 0, &budget).unknown);
}
test "read-before-write, SP, flags and load writeback retain exact widths" {
    const bs = [_]types.BasicBlock{ testBlock(0, 8), testBlock(8, 4), testBlock(12, 4) };
    const es = [_]types.CfgEdge{ testEdge(0, 8), testEdge(8, 12) };
    const ev = derive(&bs, &es, TestWords{ .words = &.{ 0x7100057f, 0xb84044e6, 0x54000000, 0x910003ff } });
    try std.testing.expect(ev.live_in[0] & bit(11, false) != 0);
    try std.testing.expect(ev.live_in[0] & bit(7, false) != 0);
    try std.testing.expectEqual(@as(u7, 64), ev.final[0][7].width);
    try std.testing.expectEqual(@as(u7, 32), ev.final[0][6].width);
    try std.testing.expectEqual(@as(u64, 4), ev.final[0][7].address);
    try std.testing.expectEqual(@as(u64, 0), ev.final[0][flags_channel].address);
    try std.testing.expect(ev.live_in[1] & (@as(u64, 1) << flags_channel) != 0);
    try std.testing.expect(ev.live_in[2] & bit(31, true) != 0);
    try std.testing.expectEqual(@as(u64, 0), readMask(steps.decode(0xaa1f03ff).?));
}
test "graph instruction and work budgets fail explicitly and include512blocks" {
    const huge: [max_blocks + 1]types.BasicBlock = @splat(testBlock(0, 0));
    try std.testing.expectEqual(.omitted_graph_budget, derive(&huge, &.{}, TestWords{ .words = &.{} }).status);
    const bs: [max_blocks]types.BasicBlock = @splat(testBlock(0, 0));
    try std.testing.expectEqual(.derived, derive(&bs, &.{}, TestWords{ .words = &.{} }).status);
    try std.testing.expectEqual(.omitted_instruction_budget, derive(&.{testBlock(0, (max_instructions + 1) * 4)}, &.{}, TestWords{ .words = &.{} }).status);
    try std.testing.expectEqual(.omitted_invalid_block, derive(&.{testBlock(1, 4)}, &.{}, TestWords{ .words = &.{} }).status);
    var budget = Budget{ .remaining = 0 };
    const ev = derive(&.{testBlock(0, 4)}, &.{}, TestWords{ .words = &.{0xd503201f} });
    const sources = resolve(&ev, &.{testBlock(0, 4)}, &.{}, 0, 11, 0, &budget);
    try std.testing.expect(sources.unknown and sources.budget_exhausted and !sources.entry);
}

test "join alternatives and function entry reentry keep separate meanings" {
    const bs = [_]types.BasicBlock{ testBlock(0, 4), testBlock(4, 4), testBlock(8, 4), testBlock(12, 4), testBlock(16, 4) };
    const es = [_]types.CfgEdge{ testEdge(0, 4), testEdge(0, 8), testEdge(4, 12), testEdge(8, 12), testEdge(12, 16), testEdge(16, 16) };
    const ev = derive(&bs, &es, TestWords{ .words = &.{ 0x14000000, 0x52800025, 0x92800005, 0xd503201f, 0x910004a5 } });
    var budget: Budget = .{};
    const join = resolve(&ev, &bs, &es, 3, 5, 0, &budget);
    try std.testing.expectEqual(@as(usize, 2), join.count);
    try std.testing.expect(!join.unknown and !join.entry);
    try std.testing.expectEqual(@as(?u64, 1), join.origins[0].literal);
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), join.origins[1].literal);
    var w = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer w.deinit();
    try writeBlockText(&w.writer, &ev, &bs, &es, 0, 4, 16, &budget);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "on function entry = x5@function_entry") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "via 0xc possible{zext32(w5@0x4) [u32 literal 1], x5@0x8 [u64 literal 18446744073709551615]}") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "via 0x10 = x5@0x10") != null);
}

test "pair second load destination and second store source join bindings" {
    const load = steps.decode(0x28c11049).?; // ldp w9,w4,[x2],#8
    try std.testing.expect(load.pair and load.op == .load);
    var origins: [33]Origin = @splat(.{});
    const loaded = writes(load, &origins, 100);
    try std.testing.expect(loaded & bit(load.dst, false) != 0);
    try std.testing.expect(loaded & bit(load.src[2], false) != 0);
    try std.testing.expect(loaded & bit(load.src[0], true) != 0);
    try std.testing.expectEqual(@as(u7, 32), origins[load.src[2]].width);
    try std.testing.expectEqual(@as(u7, 64), origins[load.src[0]].width);
    try std.testing.expectEqual(bit(load.src[0], true), readMask(load));
    const store = steps.decode(0x29011049).?;
    try std.testing.expect(store.pair and store.op == .store);
    try std.testing.expect(readMask(store) & bit(store.src[2], false) != 0);
}

test "work and output failures are explicit on512block cyclic graph" {
    var bs: [max_blocks]types.BasicBlock = undefined;
    var es: [max_blocks]types.CfgEdge = undefined;
    const words: [max_blocks]u32 = @splat(0xd503201f);
    for (0..max_blocks) |i| {
        bs[i] = testBlock(i * 4, 4);
        es[i] = testEdge(i * 4, ((i + 1) % max_blocks) * 4);
    }
    const ev = derive(&bs, &es, TestWords{ .words = &words });
    var budget: Budget = .{};
    const cycle = resolve(&ev, &bs, &es, 0, 5, 0, &budget);
    try std.testing.expect(cycle.unknown and cycle.revisited and cycle.entry);
    try std.testing.expectEqual(@as(usize, max_blocks * 2), max_work - budget.remaining);
    const one = [_]types.BasicBlock{testBlock(0, 4)};
    const one_ev = derive(&one, &.{}, TestWords{ .words = &.{0x910004a5} });
    var tiny: [2]u8 = undefined;
    var writer = std.Io.Writer.fixed(&tiny);
    try std.testing.expectError(error.WriteFailed, writeBlockText(&writer, &one_ev, &one, &.{}, 0, 0, 0, &budget));
}
