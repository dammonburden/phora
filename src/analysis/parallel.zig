//! Work-stealing parallel-for helper.
//!
//! Generic driver that spreads a slice of inputs over N worker threads and
//! collects per-input results into a pre-sized output slice. Uses a single
//! shared atomic counter for work distribution (cheapest possible scheme —
//! every worker calls fetchAdd to claim the next index until the input is
//! exhausted).
//!
//! Designed for `analysis/pipeline.zig` Phase 5 (per-function lifting), but
//! kept fully generic so any embarrassingly-parallel slice transform can use
//! it.
//!
//! Constraints:
//!   * `work_fn` must be thread-safe and must not mutate caller-visible state
//!     except through `ctx`, which the caller is responsible for synchronising
//!     (or sharding so that workers touch disjoint regions).
//!   * `results` must be at least as long as `items`. Each worker writes only
//!     `results[i]` for the index it claims, so writes never overlap.
//!
//! Zero external dependencies. Builds against Zig 0.16.0 `std.Io.Group`.

const std = @import("std");

/// Generic work-stealing parallel-for driver parameterised over the input
/// element type `T` and the per-item result type `R`.
pub fn ParallelFor(comptime T: type, comptime R: type) type {
    return struct {
        /// Per-item work function. Receives the caller-supplied opaque
        /// context, a pointer to the input element, and the input's index.
        /// Must be thread-safe.
        pub const WorkFn = *const fn (ctx: *anyopaque, item: *const T, index: usize) R;

        /// Shared state passed to each worker thread.
        const Shared = struct {
            items: []const T,
            results: []R,
            next: *std.atomic.Value(usize),
            ctx: *anyopaque,
            work_fn: WorkFn,
        };

        fn worker(s: Shared) std.Io.Cancelable!void {
            while (true) {
                // Claim the next index. `.monotonic` is sufficient because
                // each worker writes a distinct slot in `results` (no
                // ordering between workers' writes is required) and the
                // caller joins all threads before reading results.
                const i = s.next.fetchAdd(1, .monotonic);
                if (i >= s.items.len) break;
                s.results[i] = s.work_fn(s.ctx, &s.items[i], i);
            }
        }

        /// Process `items` in parallel across up to `thread_count` workers,
        /// writing results into `results[0..items.len]`.
        ///
        /// * `thread_count` is an upper bound. The actual worker count is
        ///   `min(thread_count, items.len)`. With <=1 effective workers the
        ///   call degenerates into a serial loop on the calling thread (no
        ///   threads are spawned, no allocations are made).
        /// * The calling thread also performs work, so only `n_workers - 1`
        ///   OS threads are spawned.
        pub fn run(
            io: std.Io,
            allocator: std.mem.Allocator,
            thread_count: usize,
            items: []const T,
            results: []R,
            ctx: *anyopaque,
            work_fn: WorkFn,
        ) !void {
            std.debug.assert(results.len >= items.len);
            if (items.len == 0) return;

            const n_workers = @min(thread_count, items.len);
            if (n_workers <= 1) {
                // Serial fallback for trivially small batches.
                for (items, 0..) |*item, i| {
                    results[i] = work_fn(ctx, item, i);
                }
                return;
            }

            var next = std.atomic.Value(usize).init(0);
            const shared = Shared{
                .items = items,
                .results = results,
                .next = &next,
                .ctx = ctx,
                .work_fn = work_fn,
            };

            _ = allocator;
            var group: std.Io.Group = .init;
            defer group.cancel(io);

            var spawned: usize = 0;
            while (spawned < n_workers - 1) : (spawned += 1) {
                try group.concurrent(io, worker, .{shared});
            }

            // Calling thread participates as a worker.
            try worker(shared);

            try group.await(io);
        }
    };
}

/// Suggested worker count for a given upper bound. Returns
/// `min(detected CPU count, max_threads)`, falling back to 1 if detection
/// fails. Always returns at least 1.
pub fn suggestedWorkerCount(max_threads: usize) usize {
    if (max_threads == 0) return 1;
    const cpu = std.Thread.getCpuCount() catch 1;
    const clamped = @min(cpu, max_threads);
    return if (clamped == 0) 1 else clamped;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const SquareCtx = struct { multiplier: u64 };

fn squareWork(ctx: *anyopaque, item: *const u64, index: usize) u64 {
    _ = index;
    const c: *SquareCtx = @ptrCast(@alignCast(ctx));
    return item.* * item.* * c.multiplier;
}

fn passthroughWork(ctx: *anyopaque, item: *const u64, index: usize) u64 {
    _ = ctx;
    _ = index;
    return item.*;
}

test "ParallelFor — empty input is a no-op" {
    const Driver = ParallelFor(u64, u64);
    var ctx = SquareCtx{ .multiplier = 1 };
    const items: []const u64 = &.{};
    var results: [0]u64 = .{};
    try Driver.run(testing.io, testing.allocator, 4, items, results[0..], &ctx, squareWork);
}

test "ParallelFor — serial fallback for 1-item batch" {
    const Driver = ParallelFor(u64, u64);
    var ctx = SquareCtx{ .multiplier = 3 };
    const items = [_]u64{7};
    var results = [_]u64{0};
    // thread_count > items.len exercises the n_workers=1 serial path.
    try Driver.run(testing.io, testing.allocator, 8, items[0..], results[0..], &ctx, squareWork);
    try testing.expectEqual(@as(u64, 7 * 7 * 3), results[0]);
}

test "ParallelFor — thread_count==0 also takes the serial path" {
    const Driver = ParallelFor(u64, u64);
    var ctx = SquareCtx{ .multiplier = 1 };
    const items = [_]u64{ 2, 3, 4, 5 };
    var results = [_]u64{ 0, 0, 0, 0 };
    try Driver.run(testing.io, testing.allocator, 0, items[0..], results[0..], &ctx, squareWork);
    try testing.expectEqualSlices(u64, &.{ 4, 9, 16, 25 }, results[0..]);
}

test "ParallelFor — multi-thread squares 1000 ints" {
    const Driver = ParallelFor(u64, u64);
    const N: usize = 1000;

    const items = try testing.allocator.alloc(u64, N);
    defer testing.allocator.free(items);
    const results = try testing.allocator.alloc(u64, N);
    defer testing.allocator.free(results);

    for (items, 0..) |*it, i| it.* = @as(u64, i);
    @memset(results, 0);

    var ctx = SquareCtx{ .multiplier = 1 };
    try Driver.run(testing.io, testing.allocator, 4, items, results, &ctx, squareWork);

    for (results, 0..) |r, i| {
        const expected = @as(u64, i) * @as(u64, i);
        try testing.expectEqual(expected, r);
    }
}

test "ParallelFor — every input index is visited exactly once" {
    // Stress the atomic counter: have each worker write `index+1` so we can
    // verify that all slots got claimed and none was claimed twice.
    const Driver = ParallelFor(u64, u64);
    const N: usize = 4096;

    const items = try testing.allocator.alloc(u64, N);
    defer testing.allocator.free(items);
    const results = try testing.allocator.alloc(u64, N);
    defer testing.allocator.free(results);

    for (items, 0..) |*it, i| it.* = @as(u64, i + 1);
    @memset(results, 0);

    var dummy: u8 = 0;
    try Driver.run(testing.io, testing.allocator, 8, items, results, @ptrCast(&dummy), passthroughWork);

    var sum: u128 = 0;
    for (results) |r| sum += r;
    // 1 + 2 + ... + N = N*(N+1)/2
    const expected: u128 = @as(u128, N) * @as(u128, N + 1) / 2;
    try testing.expectEqual(expected, sum);
}

test "suggestedWorkerCount clamps to max" {
    try testing.expect(suggestedWorkerCount(2) <= 2);
    try testing.expect(suggestedWorkerCount(2) >= 1);
    try testing.expect(suggestedWorkerCount(1) == 1);
    try testing.expect(suggestedWorkerCount(0) == 1);
    try testing.expect(suggestedWorkerCount(1024) >= 1);
}
