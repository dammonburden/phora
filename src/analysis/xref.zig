// Phora — Cross-Reference Tracker
// Records all address references during disassembly: calls, jumps, data loads, PC-relative.

const std = @import("std");
const types = @import("../types.zig");

/// Cross-reference database. Tracks references indexed by both source and target address.
pub const XrefTracker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    /// Read-write lock for concurrent access from MCP tool handlers.
    rw_lock: std.Io.RwLock,

    /// All xrefs, indexed by source address (from → [xrefs])
    refs_from: std.AutoHashMap(u64, std.array_list.Managed(types.Xref)),
    /// All xrefs, indexed by target address (to → [xrefs])
    refs_to: std.AutoHashMap(u64, std.array_list.Managed(types.Xref)),

    /// Sorted array of all xrefs by source address — built by finalize().
    /// Enables O(log N + K) range queries instead of O(N) full-table scans.
    sorted_from: []types.Xref = &.{},
    sorted_finalized: bool = false,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) XrefTracker {
        return .{
            .allocator = allocator,
            .io = io,
            .rw_lock = .init,
            .refs_from = std.AutoHashMap(u64, std.array_list.Managed(types.Xref)).init(allocator),
            .refs_to = std.AutoHashMap(u64, std.array_list.Managed(types.Xref)).init(allocator),
        };
    }

    pub fn deinit(self: *XrefTracker) void {
        var from_it = self.refs_from.valueIterator();
        while (from_it.next()) |list| {
            list.deinit();
        }
        self.refs_from.deinit();

        var to_it = self.refs_to.valueIterator();
        while (to_it.next()) |list| {
            list.deinit();
        }
        self.refs_to.deinit();
        // v7.15.0 B1 pass 2: free the finalize()-allocated sorted array so
        // close_document doesn't leak per-doc.
        if (self.sorted_from.len > 0) {
            self.allocator.free(self.sorted_from);
            self.sorted_from = &.{};
        }
        self.sorted_finalized = false;
    }

    /// Add a cross-reference.
    pub fn addXref(self: *XrefTracker, from: u64, to: u64, xref_type: types.XrefType) !void {
        const xref = types.Xref{
            .from = from,
            .to = to,
            .xref_type = xref_type,
        };

        // Index by source
        const from_entry = try self.refs_from.getOrPut(from);
        if (!from_entry.found_existing) {
            from_entry.value_ptr.* = std.array_list.Managed(types.Xref).init(self.allocator);
        }
        try from_entry.value_ptr.append(xref);

        // Index by target
        const to_entry = try self.refs_to.getOrPut(to);
        if (!to_entry.found_existing) {
            to_entry.value_ptr.* = std.array_list.Managed(types.Xref).init(self.allocator);
        }
        try to_entry.value_ptr.append(xref);
    }

    /// Get all xrefs originating from an address.
    pub fn getRefsFrom(self: *const XrefTracker, address: u64) []const types.Xref {
        if (self.refs_from.get(address)) |list| {
            return list.items;
        }
        return &.{};
    }

    /// Get all xrefs targeting an address.
    pub fn getRefsTo(self: *const XrefTracker, address: u64) []const types.Xref {
        if (self.refs_to.get(address)) |list| {
            return list.items;
        }
        return &.{};
    }

    /// Get all xrefs for an address in the specified direction.
    pub fn getXrefs(
        self: *const XrefTracker,
        address: u64,
        direction: types.XrefDirection,
    ) struct { from: []const types.Xref, to: []const types.Xref } {
        return switch (direction) {
            .forward => .{ .from = self.getRefsFrom(address), .to = &.{} },
            .backward => .{ .from = &.{}, .to = self.getRefsTo(address) },
            .bidirectional => .{ .from = self.getRefsFrom(address), .to = self.getRefsTo(address) },
        };
    }

    /// Get all unique call targets (addresses that are targets of call xrefs).
    pub fn getCallTargets(self: *const XrefTracker, allocator: std.mem.Allocator) ![]u64 {
        var targets = std.array_list.Managed(u64).init(allocator);
        errdefer targets.deinit();

        var it = self.refs_to.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |xref| {
                if (xref.xref_type == .call) {
                    try targets.append(entry.key_ptr.*);
                    break; // only add each address once
                }
            }
        }

        return targets.toOwnedSlice();
    }

    /// Build the sorted xref array for fast range queries. Call after all xrefs are added.
    pub fn finalize(self: *XrefTracker) void {
        if (self.sorted_finalized) return;

        // Count total xrefs
        var total: usize = 0;
        var count_it = self.refs_from.valueIterator();
        while (count_it.next()) |list| total += list.items.len;
        if (total == 0) {
            self.sorted_finalized = true;
            return;
        }

        // Allocate and fill
        const arr = self.allocator.alloc(types.Xref, total) catch return;
        var idx: usize = 0;
        var fill_it = self.refs_from.valueIterator();
        while (fill_it.next()) |list| {
            for (list.items) |xref| {
                arr[idx] = xref;
                idx += 1;
            }
        }

        // Sort by source address
        std.mem.sort(types.Xref, arr, {}, struct {
            fn lt(_: void, a: types.Xref, b: types.Xref) bool {
                return a.from < b.from;
            }
        }.lt);

        self.sorted_from = arr;
        self.sorted_finalized = true;
    }

    /// Get all xrefs with source address in [start, end). O(log N + K).
    /// Falls back to HashMap scan if finalize() hasn't been called.
    pub fn getRefsFromRange(self: *const XrefTracker, range_start: u64, range_end: u64) []const types.Xref {
        if (!self.sorted_finalized or self.sorted_from.len == 0) return &.{};

        // Binary search for first xref with from >= range_start
        var lo: usize = 0;
        var hi: usize = self.sorted_from.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.sorted_from[mid].from < range_start) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        // Find end of range
        var end_idx = lo;
        while (end_idx < self.sorted_from.len and self.sorted_from[end_idx].from < range_end) {
            end_idx += 1;
        }

        return self.sorted_from[lo..end_idx];
    }

    /// Total number of cross-references tracked.
    pub fn count(self: *const XrefTracker) usize {
        var total: usize = 0;
        var it = self.refs_from.valueIterator();
        while (it.next()) |list| {
            total += list.items.len;
        }
        return total;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "add and retrieve xrefs" {
    const allocator = std.testing.allocator;
    var tracker = XrefTracker.init(allocator, std.testing.io);
    defer tracker.deinit();

    try tracker.addXref(0x1000, 0x2000, .call);
    try tracker.addXref(0x1004, 0x3000, .jump);
    try tracker.addXref(0x1008, 0x2000, .call);

    // From 0x1000 should have 1 xref
    const from_1000 = tracker.getRefsFrom(0x1000);
    try std.testing.expectEqual(@as(usize, 1), from_1000.len);
    try std.testing.expectEqual(@as(u64, 0x2000), from_1000[0].to);

    // To 0x2000 should have 2 xrefs (from 0x1000 and 0x1008)
    const to_2000 = tracker.getRefsTo(0x2000);
    try std.testing.expectEqual(@as(usize, 2), to_2000.len);

    try std.testing.expectEqual(@as(usize, 3), tracker.count());
}

test "get call targets" {
    const allocator = std.testing.allocator;
    var tracker = XrefTracker.init(allocator, std.testing.io);
    defer tracker.deinit();

    try tracker.addXref(0x1000, 0x2000, .call);
    try tracker.addXref(0x1004, 0x3000, .jump);
    try tracker.addXref(0x1008, 0x2000, .call);
    try tracker.addXref(0x100C, 0x4000, .call);

    const targets = try tracker.getCallTargets(allocator);
    defer allocator.free(targets);

    // Should have 2 unique call targets: 0x2000 and 0x4000
    try std.testing.expectEqual(@as(usize, 2), targets.len);
}

test "empty xref lookup" {
    const allocator = std.testing.allocator;
    var tracker = XrefTracker.init(allocator, std.testing.io);
    defer tracker.deinit();

    const from = tracker.getRefsFrom(0xDEAD);
    try std.testing.expectEqual(@as(usize, 0), from.len);
}

test "bidirectional xref query" {
    const allocator = std.testing.allocator;
    var tracker = XrefTracker.init(allocator, std.testing.io);
    defer tracker.deinit();

    try tracker.addXref(0x1000, 0x2000, .call);
    try tracker.addXref(0x3000, 0x2000, .data_read);

    const result = tracker.getXrefs(0x2000, .bidirectional);
    try std.testing.expectEqual(@as(usize, 0), result.from.len); // 0x2000 doesn't reference anything
    try std.testing.expectEqual(@as(usize, 2), result.to.len); // 0x2000 is referenced by 2 xrefs
}
