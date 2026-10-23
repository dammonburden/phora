//! Bounded encoding-backed GPR provenance. This is not SSA or value/type recovery.
const std = @import("std");
const types = @import("../types.zig");
const json = @import("../util/json.zig");
const addressing = @import("arm64_addressing.zig");
pub const max_blocks = 512;
pub const max_instructions = 4096;
const Effects = struct { reads: u32 = 0, writes: u32 = 0, barrier: bool = false };
fn bit(r: u5, sp: bool) u32 {
    return if (r == 31 and !sp) 0 else @as(u32, 1) << r;
}
/// Register 31 means SP only in the families which architecturally permit SP.
fn effects(word: u32) Effects {
    const sf = word & 0x80000000 != 0;
    const amount = (word >> 10) & 63;
    const d: u5 = @truncate(word);
    const n: u5 = @truncate(word >> 5);
    const m: u5 = @truncate(word >> 16);
    if (word & 0xfc000000 == 0x94000000 or word & 0xfffffc1f == 0xd63f0000) return .{ .barrier = true };
    if (word & 0x7c000000 == 0x14000000 or word & 0xff000010 == 0x54000000 or word == 0xd503201f) return .{};
    if (word & 0x7e000000 == 0x34000000 or word & 0x7e000000 == 0x36000000) return .{ .reads = bit(d, false) };
    if (word & 0xfffffc1f == 0xd61f0000 or word & 0xfffffc1f == 0xd65f0000) return .{ .reads = bit(n, false) };
    if (word & 0x1f800000 == 0x11000000) return .{ .reads = bit(n, true), .writes = bit(d, word & 0x20000000 == 0) };
    if (word & 0x1f800000 == 0x12800000 and (word >> 29) & 3 != 1 and (sf or ((word >> 21) & 3) < 2)) return .{ .reads = if (word & 0x60000000 == 0x60000000) bit(d, false) else 0, .writes = bit(d, false) };
    if ((word & 0x1f000000 == 0x0a000000 or (word & 0x1f200000 == 0x0b000000 and (word >> 22) & 3 != 3)) and (sf or amount < 32)) return .{ .reads = bit(n, false) | bit(m, false), .writes = bit(d, false) };
    // Conditional compare writes flags only; bit 11 selects immediate vs register.
    if (word & 0x3fe00410 == 0x3a400000) return .{ .reads = bit(n, false) | (if (word & 0x800 == 0) bit(m, false) else @as(u32, 0)) };
    if (word & 0x1fe00000 == 0x1a800000 and word & 0x20000800 == 0) return .{ .reads = bit(n, false) | bit(m, false), .writes = bit(d, false) };
    if (word & 0x7fe00000 == 0x1b000000) return .{ .reads = bit(n, false) | bit(m, false) | bit(@truncate(word >> 10), false), .writes = bit(d, false) };
    if (word & 0x1f000000 == 0x10000000) return .{ .writes = bit(d, false) };
    if (addressing.decode(word)) |a| return .{ .reads = bit(a.base, true) | (if (a.load) @as(u32, 0) else bit(a.data, false)), .writes = bit(a.base, true) | (if (a.load) bit(a.data, false) else @as(u32, 0)) };
    // Scalar unsigned-offset loads/stores; exclude SIMD and prefetch/reserved opcodes.
    if (word & 0x3f000000 == 0x39000000 and ((word >> 22) & 3) <= 1) return if (word & 0x00400000 != 0) .{ .reads = bit(n, true), .writes = bit(d, false) } else .{ .reads = bit(n, true) | bit(d, false) };
    if (word & 0x1f800000 == 0x13000000 and (word >> 29) & 3 != 3 and ((word >> 22) & 1 == @intFromBool(sf)) and (sf or (amount < 32 and (word >> 16) & 63 < 32))) return .{ .reads = bit(n, false) | (if (word & 0x60000000 == 0x20000000) bit(d, false) else 0), .writes = bit(d, false) };
    if (word & 0x7fe0fc00 == 0x1ac00800 or word & 0x7fe0fc00 == 0x1ac00c00) return .{ .reads = bit(n, false) | bit(m, false), .writes = bit(d, false) };
    return .{ .barrier = true };
}
fn index(bs: []const types.BasicBlock, addr: u64) ?usize {
    for (bs, 0..) |b, i| if (b.start == addr) return i;
    return null;
}
pub const max_search_steps = 262144;
const Budget = struct {
    remaining: usize = max_search_steps,
    exhausted: bool = false,
    fn take(self: *Budget) bool {
        if (self.remaining == 0) {
            self.exhausted = true;
            return false;
        }
        self.remaining -= 1;
        return true;
    }
};
const Sources = struct { budget_exhausted: bool = false, addresses: [16]u64 = undefined, count: usize = 0, unknown: bool = false, entry: bool = false, cycle: bool = false };
fn sources(bs: []const types.BasicBlock, es: []const types.CfgEdge, words: anytype, first: usize, reg: u5, entry_addr: u64) Sources {
    var budget: Budget = .{};
    return sourcesBudget(bs, es, words, first, reg, entry_addr, &budget);
}
fn sourcesBudget(bs: []const types.BasicBlock, es: []const types.CfgEdge, words: anytype, first: usize, reg: u5, entry_addr: u64, budget: *Budget) Sources {
    if (budget.remaining == 0) {
        budget.exhausted = true;
        return .{ .unknown = true, .budget_exhausted = true };
    }
    var out: Sources = .{};
    var seen: [max_blocks]bool = @splat(false);
    var queue: [max_blocks]usize = undefined;
    queue[0] = first;
    seen[first] = true;
    var end: usize = 1;
    var pos: usize = 0;
    var instructions: usize = 0;
    while (pos < end) : (pos += 1) {
        const b = bs[queue[pos]];
        var addr = b.start +| b.size;
        var stopped = false;
        if (b.size % 4 != 0) {
            out.unknown = true;
            continue;
        }
        while (addr > b.start) {
            if (!budget.take()) {
                out.unknown = true;
                out.budget_exhausted = true;
                return out;
            }
            addr -= 4;
            instructions += 1;
            if (instructions > max_instructions) {
                out.unknown = true;
                return out;
            }
            const word = words.word(addr) orelse {
                out.unknown = true;
                stopped = true;
                break;
            };
            const e = effects(word);
            if (e.barrier) {
                out.unknown = true;
                stopped = true;
                break;
            }
            if (e.writes & bit(reg, true) != 0) {
                if (out.count < out.addresses.len) {
                    out.addresses[out.count] = addr;
                    out.count += 1;
                } else out.unknown = true;
                stopped = true;
                break;
            }
        }
        if (stopped) continue;
        var predecessors: usize = 0;
        for (es) |e| {
            if (!budget.take()) {
                out.unknown = true;
                out.budget_exhausted = true;
                return out;
            }
            if (e.to != b.start) continue;
            predecessors += 1;
            const p = index(bs, e.from) orelse {
                out.unknown = true;
                continue;
            };
            if (seen[p]) {
                out.cycle = true;
                out.unknown = true;
            } else {
                seen[p] = true;
                queue[end] = p;
                end += 1;
            }
        }
        if (predecessors == 0 or b.start == entry_addr) out.entry = true;
    }
    return out;
}
fn address(w: anytype, a: u64, delta: i128) !void {
    try json.writeAddress(w, @intCast(@max(0, @min(@as(i128, a) + delta, std.math.maxInt(u64)))));
}
pub fn write(w: anytype, bs: []const types.BasicBlock, es: []const types.CfgEdge, words: anytype, delta: i128, page_start: usize, page_end: usize, entry_addr: u64) !void {
    const omitted = bs.len > max_blocks or es.len > 4096;
    try w.print(",\"register_flow_evidence\":{{\"status\":\"{s}\",\"scope\":\"full_recovered_graph; visible_block_reads\",\"model\":\"bounded_backward_GPR_reaching_writes; W_X_aliases; register_31_is_SP\",\"completeness\":\"partial; unmodeled_instructions_and_calls_are_barriers; recovered_edges_only; not_SSA_or_value_recovery\",\"block_limit\":512,\"search_instruction_limit\":4096,\"inputs\":[", .{if (omitted) "omitted_graph_budget" else "derived_conservative"});
    var budget: Budget = .{};
    var count: usize = 0;
    var truncated = false;
    var barrier_blocks: usize = 0;
    if (!omitted) for (bs[page_start..page_end]) |b| {
        var written: u32 = 0;
        var reported: u32 = 0;
        var addr = b.start;
        var scanned: usize = 0;
        while (addr < b.start +| b.size) : (addr +|= 4) {
            scanned += 1;
            if (scanned > max_instructions) {
                truncated = true;
                break;
            }
            const word = words.word(addr) orelse {
                barrier_blocks += 1;
                break;
            };
            const e = effects(word);
            if (e.barrier) {
                barrier_blocks += 1;
                break;
            }
            var reads = e.reads & ~written & ~reported;
            reported |= reads;
            while (reads != 0) {
                const reg: u5 = @intCast(@ctz(reads));
                reads &= reads - 1;
                if (count == 128) {
                    truncated = true;
                    break;
                }
                if (count != 0) try w.writeByte(',');
                count += 1;
                try w.writeAll("{\"block\":");
                try address(w, b.start, delta);
                try w.writeAll(",\"read_at\":");
                try address(w, addr, delta);
                try w.print(",\"register\":{d},\"predecessors\":[", .{reg});
                var pc: usize = 0;
                for (es) |edge| if (edge.to == b.start) {
                    pc += 1;
                    if (pc > 16) {
                        truncated = true;
                        continue;
                    }
                    if (pc != 1) try w.writeByte(',');
                    const s = if (index(bs, edge.from)) |p| sourcesBudget(bs, es, words, p, reg, entry_addr, &budget) else Sources{ .unknown = true };
                    try w.writeAll("{\"from\":");
                    try address(w, edge.from, delta);
                    try w.writeAll(",\"reaching_writes\":[");
                    for (s.addresses[0..s.count], 0..) |a, j| {
                        if (j != 0) try w.writeByte(',');
                        try address(w, a, delta);
                    }
                    try w.print("],\"unknown\":{},\"entry_value_possible\":{},\"cycle_or_revisited_path\":{},\"search_budget_exhausted\":{}}}", .{ s.unknown, s.entry, s.cycle, s.budget_exhausted });
                };
                try w.print("],\"predecessors_truncated\":{},\"entry_value_possible\":{}}}", .{ pc > 16, pc == 0 or b.start == entry_addr });
            }
            written |= e.writes;
        }
    };
    try w.print("],\"returned_inputs\":{d},\"inputs_truncated\":{},\"visible_blocks_stopped_at_barrier\":{d},\"search_work_limit\":262144,\"search_work_used\":{d},\"search_budget_exhausted\":{}}}", .{ count, truncated, barrier_blocks, max_search_steps - budget.remaining, budget.exhausted });
}
test "encoding effects alias widths and distinguish SP from ZR" {
    try std.testing.expectEqual(@as(u32, 1) << 11, effects(0x1100056b).writes);
    try std.testing.expectEqual(@as(u32, 0), effects(0xaa1f03ff).writes);
    try std.testing.expect(effects(0x910003ff).writes & (@as(u32, 1) << 31) != 0);
    try std.testing.expect(effects(0x94000000).barrier);
    try std.testing.expect(effects(0xffffffff).barrier);
}
fn block(a: u64, size: u64) types.BasicBlock {
    return .{ .start = a, .size = size, .instruction_count = @intCast(size / 4), .successors = &.{}, .predecessors = &.{}, .terminator = .jump };
}
fn testEdge(a: u64, b: u64) types.CfgEdge {
    return .{ .from = a, .to = b, .edge_type = .unconditional };
}
const TestWords = struct {
    values: []const u32,
    pub fn word(self: @This(), a: u64) ?u32 {
        if (a / 4 >= self.values.len) return null;
        return self.values[@intCast(a / 4)];
    }
};
test "join and self loop retain updated writer instead of initializer" {
    const bs = [_]types.BasicBlock{ block(0, 4), block(4, 8), block(12, 4) };
    const es = [_]types.CfgEdge{ testEdge(0, 4), testEdge(4, 4), testEdge(0, 12), testEdge(4, 12) };
    const words = TestWords{ .values = &.{ 0x5280002b, 0x1100056b, 0x14000000, 0x11000560 } };
    const init = sources(&bs, &es, words, 0, 11, 0);
    const carried = sources(&bs, &es, words, 1, 11, 0);
    try std.testing.expectEqual(@as(u64, 0), init.addresses[0]);
    try std.testing.expectEqual(@as(u64, 4), carried.addresses[0]);
    var w = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer w.deinit();
    try write(&w.writer, &bs, &es, words, 4096, 2, 3, 0);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "\"read_at\":\"0x100c\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "\"reaching_writes\":[\"0x1004\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "\"reaching_writes\":[\"0x1000\"]") != null);
}
test "unknown call missing bytes and no-write cycles cannot forward initializer" {
    const bs = [_]types.BasicBlock{ block(0, 4), block(4, 4), block(8, 4) };
    const es = [_]types.CfgEdge{ testEdge(0, 4), testEdge(4, 8), testEdge(8, 8) };
    const words = TestWords{ .values = &.{ 0x5280002b, 0x94000000, 0x14000000 } };
    const call = sources(&bs, &es, words, 1, 11, 0);
    try std.testing.expect(call.unknown and call.count == 0);
    const cycle = sources(&bs, &es, words, 2, 11, 0);
    try std.testing.expect(cycle.unknown and cycle.cycle and cycle.count == 0);
    const missing = sources(&bs, &es, TestWords{ .values = &.{} }, 0, 11, 0);
    try std.testing.expect(missing.unknown);
    const entry = sources(&bs, &.{}, TestWords{ .values = &.{0x14000000} }, 0, 11, 0);
    try std.testing.expect(entry.entry);
}
test "graph budget and output allocation failures remain explicit" {
    const huge: [max_blocks + 1]types.BasicBlock = @splat(block(0, 4));
    var w = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer w.deinit();
    try write(&w.writer, &huge, &.{}, TestWords{ .values = &.{} }, 0, 0, 1, 0);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "omitted_graph_budget") != null);
    var empty: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&empty);
    var fail = std.Io.Writer.Allocating.init(fixed.allocator());
    defer fail.deinit();
    try std.testing.expectError(error.WriteFailed, write(&fail.writer, &.{}, &.{}, TestWords{ .values = &.{} }, 0, 0, 0, 0));
}
test "reserved encodings are barriers and writeback contributes actual base writes" {
    for ([_]u32{ 0x11800000, 0x52c00000, 0x0a008000, 0x0bc00000, 0x13400000 }) |word| try std.testing.expect(effects(word).barrier);
    const post = effects(0xb84044e6);
    try std.testing.expect(!post.barrier);
    try std.testing.expect(post.reads & bit(7, false) != 0);
    try std.testing.expect(post.writes & bit(7, false) != 0 and post.writes & bit(6, false) != 0);
    try std.testing.expect(effects(0xf8400c21).barrier);
}

test "multiply reserved high opcode bits cannot become reaching definitions" {
    const bs = [_]types.BasicBlock{block(0, 4)};
    for ([_]u32{ 0x3b000000, 0x5b000000, 0x7b000000, 0xbb000000, 0xdb000000, 0xfb000000 }) |word| {
        try std.testing.expect(effects(word).barrier);
        const s = sources(&bs, &.{}, TestWords{ .values = &.{word} }, 0, 0, 0);
        try std.testing.expect(s.unknown and s.count == 0);
    }
    try std.testing.expect(!effects(0x1b000000).barrier);
    try std.testing.expect(!effects(0x9b000000).barrier);
}
test "conditional compare immediate does not invent a register source" {
    const immediate = effects(0x7a462900);
    try std.testing.expect(!immediate.barrier and immediate.writes == 0);
    try std.testing.expectEqual(bit(8, false), immediate.reads);
    const register = effects(0x7a462100);
    try std.testing.expectEqual(bit(8, false) | bit(6, false), register.reads);
    for ([_]u32{ 0x7a462910, 0x7a462d00, 0x5a462900 }) |word| try std.testing.expect(effects(word).barrier);
}
test "shared search work budget bounds dense no-writer traversals" {
    const bs = [_]types.BasicBlock{ block(0, 4), block(4, 4), block(8, 4) };
    const es: [4096]types.CfgEdge = @splat(testEdge(0, 8));
    const words = TestWords{ .values = &.{ 0xd503201f, 0xd503201f, 0xd503201f } };
    var budget = Budget{ .remaining = 7 };
    const first = sourcesBudget(&bs, &es, words, 2, 11, 0, &budget);
    try std.testing.expect(first.unknown and first.budget_exhausted and first.count == 0);
    try std.testing.expectEqual(@as(usize, 0), budget.remaining);
    const next = sourcesBudget(&bs, &es, words, 0, 11, 0, &budget);
    try std.testing.expect(next.unknown and next.budget_exhausted and next.count == 0);
    try std.testing.expect(!next.entry);
}
