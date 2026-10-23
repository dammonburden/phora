//! Conservative natural-loop evidence over the entire recovered graph, never a page.
const std = @import("std");
const types = @import("../types.zig");
const json = @import("../util/json.zig");
pub const max_blocks = 512;
pub const max_edges = 4096;
pub const Evidence = struct {
    count: usize = 0,
    omitted: bool = false,
    members: [max_blocks][max_blocks]bool = @splat(@splat(false)),
    latches: [max_blocks][max_blocks]bool = @splat(@splat(false)),
};
fn index(blocks: []const types.BasicBlock, addr: u64) ?usize {
    for (blocks, 0..) |b, i| if (b.start == addr) return i;
    return null;
}
fn reach(adj: *const [max_blocks][max_blocks]bool, n: usize, entry: usize, excluded: ?usize) [max_blocks]bool {
    var seen: [max_blocks]bool = @splat(false);
    var queue: [max_blocks]usize = undefined;
    if (excluded == entry) return seen;
    seen[entry] = true;
    queue[0] = entry;
    var end: usize = 1;
    var cursor: usize = 0;
    while (cursor < end) : (cursor += 1) {
        const from = queue[cursor];
        for (0..n) |to| if (adj[from][to] and excluded != to and !seen[to]) {
            seen[to] = true;
            queue[end] = to;
            end += 1;
        };
    }
    return seen;
}
pub fn derive(blocks: []const types.BasicBlock, edges: []const types.CfgEdge, entry_addr: u64) Evidence {
    var out: Evidence = .{};
    if (blocks.len == 0 or blocks.len > max_blocks or edges.len > max_edges) {
        out.omitted = true;
        return out;
    }
    const entry = index(blocks, entry_addr) orelse {
        out.omitted = true;
        return out;
    };
    var adj: [max_blocks][max_blocks]bool = @splat(@splat(false));
    for (edges) |e| {
        const from = index(blocks, e.from) orelse continue;
        const to = index(blocks, e.to) orelse continue;
        adj[from][to] = true;
    }
    const reachable = reach(&adj, blocks.len, entry, null);
    for (0..blocks.len) |header| {
        if (!reachable[header]) continue;
        const without = reach(&adj, blocks.len, entry, header);
        var found = false;
        for (0..blocks.len) |latch| {
            if (!reachable[latch] or !adj[latch][header] or without[latch]) continue;
            found = true;
            out.latches[header][latch] = true;
            out.members[header][header] = true;
            // Stop at the header, including for self loops: never walk into its preheader.
            var queue: [max_blocks]usize = undefined;
            var end: usize = 0;
            if (latch != header and !out.members[header][latch]) {
                out.members[header][latch] = true;
                queue[0] = latch;
                end = 1;
            }
            var cursor: usize = 0;
            while (cursor < end) : (cursor += 1) {
                for (0..blocks.len) |pred| if (reachable[pred] and adj[pred][queue[cursor]] and !out.members[header][pred]) {
                    out.members[header][pred] = true;
                    queue[end] = pred;
                    end += 1;
                };
            }
        }
        if (found) out.count += 1;
    }
    return out;
}
fn intersects(ev: *const Evidence, h: usize, start: usize, end: usize) bool {
    for (@min(start, max_blocks)..@min(end, max_blocks)) |i| if (ev.members[h][i]) return true;
    return false;
}
fn subset(ev: *const Evidence, child: usize, parent: usize, n: usize) bool {
    for (0..n) |i| if (ev.members[child][i] and !ev.members[parent][i]) return false;
    return true;
}
const Parent = struct { header: ?usize = null, ambiguous: bool = false };
/// A parent is the unique smallest strict containing natural loop. Overlapping
/// incomparable containers are left ambiguous rather than invented as a tree.
fn parentOf(ev: *const Evidence, h: usize, n: usize) Parent {
    var best: ?usize = null;
    var best_count: usize = max_blocks + 1;
    var child_count: usize = 0;
    for (0..n) |i| child_count += @intFromBool(ev.members[h][i]);
    for (0..n) |p| {
        if (p == h or !ev.members[p][p] or !subset(ev, h, p, n)) continue;
        var count: usize = 0;
        for (0..n) |i| count += @intFromBool(ev.members[p][i]);
        if (count > child_count and count < best_count) {
            best = p;
            best_count = count;
        }
    }
    const chosen = best orelse return .{};
    for (0..n) |p| {
        if (p == h or p == chosen or !ev.members[p][p] or !subset(ev, h, p, n)) continue;
        var count: usize = 0;
        for (0..n) |i| count += @intFromBool(ev.members[p][i]);
        if (count > child_count and (!subset(ev, chosen, p, n) or count == best_count)) return .{ .ambiguous = true };
    }
    return .{ .header = chosen };
}
fn address(w: anytype, addr: u64, delta: i128) !void {
    const value = @as(i128, addr) + delta;
    try json.writeAddress(w, @intCast(@max(0, @min(value, std.math.maxInt(u64)))));
}
/// Response work bounded by 512 blocks, 4096 edges, 16 loops and 64 members/loop.
/// Dominance proof is relative to recovered edges; missing paths can invalidate it.
pub fn write(w: anytype, ev: *const Evidence, blocks: []const types.BasicBlock, edges: []const types.CfgEdge, delta: i128, page_start: usize, page_end: usize) !void {
    var relevant: usize = 0;
    if (!ev.omitted) for (0..blocks.len) |h| {
        if (ev.members[h][h] and intersects(ev, h, page_start, page_end)) relevant += 1;
    };
    try w.print(",\"loop_evidence\":{{\"status\":\"{s}\",\"scope\":\"derivation_full_recovered_graph; selection_intersects_visible_page\",\"semantic_completeness\":\"unknown\",\"cycle_coverage\":\"natural_loops_only; irreducible_cycles_not_classified\",\"note\":\"Dominance is proven only in recovered edges; missing indirect or undecoded paths may invalidate it. Every traversal executes header instructions. Do not hoist header arithmetic or recurrence updates without a separate invariance proof. Registers assigned in the loop carry their updated values into the next traversal; an initializer is not proof of invariance. Trace at least two traversals. Zero natural loops does not prove absence of cycles.\",\"total_natural_loops\":", .{if (ev.omitted) "omitted_graph_budget_or_missing_entry" else "derived"});
    if (ev.omitted) try w.writeAll("null") else try w.print("{d}", .{ev.count});
    try w.writeAll(",\"total_relevant_loops\":");
    if (ev.omitted) try w.writeAll("null") else try w.print("{d}", .{relevant});
    try w.writeAll(",\"graph_block_limit\":512,\"graph_edge_limit\":4096,\"loops\":[");
    var emitted: usize = 0;
    if (!ev.omitted) for (blocks, 0..) |_, h| {
        if (!ev.members[h][h] or !intersects(ev, h, page_start, page_end) or emitted == 16) continue;
        if (emitted != 0) try w.writeByte(',');
        emitted += 1;
        try w.writeAll("{\"header\":");
        try address(w, blocks[h].start, delta);
        const parent = parentOf(ev, h, blocks.len);
        try w.writeAll(",\"parent_header\":");
        if (parent.header) |p| try address(w, blocks[p].start, delta) else try w.writeAll("null");
        try w.print(",\"nesting_status\":\"{s}\",\"entry_edges\":[", .{if (parent.ambiguous) @as([]const u8, "ambiguous_overlapping_containers") else if (parent.header != null) "strict_member_containment" else "no_containing_natural_loop"});
        var entries: usize = 0;
        for (edges) |e| {
            const to = index(blocks, e.to) orelse continue;
            const from = index(blocks, e.from);
            if (!ev.members[h][to] or (from != null and ev.members[h][from.?])) continue;
            entries += 1;
            if (entries > 64) continue;
            if (entries != 1) try w.writeByte(',');
            try w.writeAll("{\"from\":");
            try address(w, e.from, delta);
            try w.writeAll(",\"to\":");
            try address(w, e.to, delta);
            try w.writeByte('}');
        }
        try w.print("],\"total_entry_edges\":{d},\"entry_edges_truncated\":{}", .{ entries, entries > 64 });
        try w.writeAll(",\"backedge_proof\":\"header_dominates_latch_in_recovered_graph\",\"latches\":[");
        var lc: usize = 0;
        for (blocks, 0..) |b, i| if (ev.latches[h][i]) {
            lc += 1;
            if (lc > 64) continue;
            if (lc != 1) try w.writeByte(',');
            try address(w, b.start, delta);
        };
        try w.print("],\"total_latches\":{d},\"latches_truncated\":{},\"members\":[", .{ lc, lc > 64 });
        var mc: usize = 0;
        for (0..2) |pass| {
            for (blocks, 0..) |b, i| if (ev.members[h][i] and ((i >= page_start and i < page_end) == (pass == 0))) {
                mc += 1;
                if (mc > 64) continue;
                if (mc != 1) try w.writeByte(',');
                try w.writeAll("{\"start\":");
                try address(w, b.start, delta);
                try w.writeAll(",\"end_exclusive\":");
                try address(w, b.start +| b.size, delta);
                try w.print(",\"instruction_count\":{d}}}", .{b.instruction_count});
            };
        }
        try w.print("],\"total_members\":{d},\"members_truncated\":{},\"exits\":[", .{ mc, mc > 64 });
        var ec: usize = 0;
        for (edges) |e| {
            const from = index(blocks, e.from) orelse continue;
            const to = index(blocks, e.to);
            if (!ev.members[h][from] or (to != null and ev.members[h][to.?])) continue;
            ec += 1;
            if (ec > 64) continue;
            if (ec != 1) try w.writeByte(',');
            try w.writeAll("{\"from\":");
            try address(w, e.from, delta);
            try w.writeAll(",\"to\":");
            try address(w, e.to, delta);
            try w.writeByte('}');
        }
        try w.print("],\"total_exit_edges\":{d},\"exits_truncated\":{}}}", .{ ec, ec > 64 });
    };
    try w.print("],\"returned_loops\":{d},\"returned_relevant_loops\":{d},\"loops_truncated\":{}}}", .{ emitted, emitted, !ev.omitted and relevant > emitted });
}
fn block(addr: u64) types.BasicBlock {
    return .{ .start = addr, .size = 4, .instruction_count = 1, .successors = &.{}, .predecessors = &.{}, .terminator = .jump };
}
fn edge(from: u64, to: u64) types.CfgEdge {
    return .{ .from = from, .to = to, .edge_type = .unconditional };
}
test "self loop excludes preheader and graph budgets are exact" {
    const bs = [_]types.BasicBlock{ block(100), block(104), block(108) };
    const es = [_]types.CfgEdge{ edge(100, 104), edge(104, 104), edge(104, 108) };
    const ev = derive(&bs, &es, 100);
    try std.testing.expectEqual(@as(usize, 1), ev.count);
    try std.testing.expect(!ev.members[1][0] and ev.members[1][1] and !ev.members[1][2]);
    const huge: [max_blocks + 1]types.BasicBlock = @splat(block(100));
    try std.testing.expect(derive(&huge, &es, 100).omitted);
    try std.testing.expect(derive(&bs, &es, 999).omitted);
}
test "nested loops merge multiple latches; irreducible backward edge is not proof" {
    const bs = [_]types.BasicBlock{ block(0), block(4), block(8), block(12), block(16) };
    const es = [_]types.CfgEdge{ edge(0, 4), edge(4, 8), edge(8, 8), edge(8, 12), edge(12, 4), edge(8, 16), edge(16, 4) };
    const ev = derive(&bs, &es, 0);
    try std.testing.expectEqual(@as(usize, 2), ev.count);
    try std.testing.expect(ev.latches[1][3] and ev.latches[1][4]);
    try std.testing.expect(ev.members[1][2] and ev.members[2][2] and !ev.members[2][1]);
    const irr = [_]types.CfgEdge{ edge(0, 4), edge(0, 8), edge(4, 8), edge(8, 4) };
    try std.testing.expectEqual(@as(usize, 0), derive(&bs, &irr, 0).count);
}
test "full graph evidence preserves off-page header and rebases all ranges" {
    const bs = [_]types.BasicBlock{ block(100), block(104), block(108) };
    const es = [_]types.CfgEdge{ edge(100, 104), edge(104, 108), edge(108, 104) };
    const ev = derive(&bs, &es, 100);
    // A page containing only the latch does not alter derivation inputs.
    try std.testing.expect(ev.members[1][2]);
    var w = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer w.deinit();
    try write(&w.writer, &ev, &bs, &es, 4096, 2, 3);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "\"header\":\"0x1068\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "\"end_exclusive\":\"0x1070\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "\"loops_truncated\":false") != null);
}
test "nested loop parent and entry edges exclude the inner backedge" {
    const bs = [_]types.BasicBlock{ block(0), block(4), block(8), block(12), block(16) };
    const es = [_]types.CfgEdge{ edge(0, 4), edge(4, 8), edge(8, 8), edge(8, 12), edge(12, 4), edge(12, 16) };
    const ev = derive(&bs, &es, 0);
    try std.testing.expectEqual(@as(?usize, 1), parentOf(&ev, 2, bs.len).header);
    try std.testing.expectEqual(@as(?usize, null), parentOf(&ev, 1, bs.len).header);
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try output.writer.writeAll("{\"test\":true");
    try write(&output.writer, &ev, &bs, &es, 4096, 2, 3);
    try output.writer.writeByte('}');
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, output.written(), .{});
    defer parsed.deinit();
    const loops = parsed.value.object.get("loop_evidence").?.object.get("loops").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), loops.len);
    const inner = loops[1].object;
    try std.testing.expectEqualStrings("0x1004", inner.get("parent_header").?.string);
    const entries = inner.get("entry_edges").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("0x1004", entries[0].object.get("from").?.string);
    try std.testing.expectEqualStrings("0x1008", entries[0].object.get("to").?.string);
    try std.testing.expectEqualStrings("0x1008", inner.get("latches").?.array.items[0].string);
}
test "incomparable or equal containing sets do not invent a nesting parent" {
    var ev: Evidence = .{};
    ev.members[0][0] = true;
    ev.members[1][1] = true;
    ev.members[1][0] = true;
    ev.members[2][2] = true;
    ev.members[2][0] = true;
    try std.testing.expect(parentOf(&ev, 0, 3).ambiguous);
    ev.members[1][2] = true;
    try std.testing.expectEqual(@as(?usize, 2), parentOf(&ev, 0, 3).header);
    ev.members[2][1] = true;
    try std.testing.expect(parentOf(&ev, 0, 3).ambiguous);
}
test "inclusive graph limits and explicit omitted edge budget" {
    var bs: [max_blocks]types.BasicBlock = undefined;
    for (&bs, 0..) |*b, i| b.* = block(@intCast(i));
    const empty = derive(&bs, &.{}, 0);
    try std.testing.expect(!empty.omitted);
    const es: [max_edges]types.CfgEdge = @splat(edge(0, 0));
    try std.testing.expect(!derive(&bs, &es, 0).omitted);
    const too_many: [max_edges + 1]types.CfgEdge = @splat(edge(0, 0));
    try std.testing.expect(derive(&bs, &too_many, 0).omitted);
}
test "serialized loop truncation reports exact totals" {
    var bs: [18]types.BasicBlock = undefined;
    for (&bs, 0..) |*b, i| b.* = block(@intCast(i));
    var es: [34]types.CfgEdge = undefined;
    for (1..18) |i| {
        es[(i - 1) * 2] = edge(0, @intCast(i));
        es[(i - 1) * 2 + 1] = edge(@intCast(i), @intCast(i));
    }
    const ev = derive(&bs, &es, 0);
    var valid = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer valid.deinit();
    try valid.writer.writeAll("{\"test\":true");
    try write(&valid.writer, &ev, &bs, &es, 0, 0, bs.len);
    try valid.writer.writeByte('}');
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, valid.written(), .{});
    defer parsed.deinit();
    const result = parsed.value.object.get("loop_evidence").?;
    try std.testing.expectEqual(@as(i64, 17), result.object.get("total_natural_loops").?.integer);
    try std.testing.expectEqual(@as(i64, 16), result.object.get("returned_loops").?.integer);
    try std.testing.expect(result.object.get("loops_truncated").?.bool);
    valid.clearRetainingCapacity();
    try valid.writer.writeAll("{\"test\":true");
    try write(&valid.writer, &ev, &bs, &es, 0, 17, 18);
    try valid.writer.writeByte('}');
    const late = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, valid.written(), .{});
    defer late.deinit();
    const page = late.value.object.get("loop_evidence").?;
    try std.testing.expectEqual(@as(i64, 1), page.object.get("total_relevant_loops").?.integer);
    try std.testing.expectEqualStrings("0x11", page.object.get("loops").?.array.items[0].object.get("header").?.string);
    try std.testing.expect(!page.object.get("loops_truncated").?.bool);
}

test "loop benchmark bounded large graph shapes" {
    var bs: [max_blocks]types.BasicBlock = undefined;
    var es: [max_blocks]types.CfgEdge = undefined;
    for ([_]usize{ 337, 362, 512 }) |n| {
        for (0..n) |i| {
            bs[i] = block(@intCast(i));
            es[i] = edge(@intCast(i), @intCast((i + 1) % n));
        }
        const started = std.Io.Clock.Timestamp.now(std.testing.io, .awake);
        for (0..10) |_| {
            const ev = derive(bs[0..n], es[0..n], 0);
            try std.testing.expectEqual(@as(usize, 1), ev.count);
            try std.testing.expect(ev.members[0][n - 1]);
        }
        const elapsed = started.durationTo(std.Io.Clock.Timestamp.now(std.testing.io, .awake)).raw.toMicroseconds();
        std.debug.print(" loop derivation n={d}, ten runs={d}us\n", .{ n, elapsed });
    }
}
