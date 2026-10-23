test {
    _ = @import("analysis/loops.zig");
}
const std = @import("std");
const tools = @import("tools.zig");
const json = @import("util/json.zig");
fn call(ctx: tools.ToolContext, name: []const u8, args: anytype) !std.json.Value {
    const encoded = try json.stringify(ctx.allocator, args);
    const params = try std.json.parseFromSlice(std.json.Value, ctx.allocator, encoded, .{});
    const result = try tools.dispatch(ctx, name, params.value);
    try std.testing.expect(!result.is_error);
    const parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, result.json_response, .{});
    return parsed.value.object.get("results").?.array.items[0].object.get("result").?;
}
test "get_cfg loop evidence survives page split and rebased raw load" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Preheader nop; header nop; jne header; ret. Header instruction repeats.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "loop.bin", .data = &.{ 0x90, 0x90, 0x75, 0xfd, 0xc3 } });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "loop.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "loop-pages", .allocator = a };
    for ([_]u64{ 4096, 8192 }, 0..) |base, iteration| {
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "x86_64", .base = base, .entry = base } });
        const first = try call(ctx, "get_cfg", .{ .function_address = base, .max_blocks = 1, .offset = 1, .include_disassembly = true });
        const later = try call(ctx, "get_cfg", .{ .function_address = base, .max_blocks = 1, .offset = 1 });
        const ev = first.object.get("loop_evidence").?;
        try std.testing.expectEqualStrings("derived", ev.object.get("status").?.string);
        try std.testing.expectEqualStrings("unknown", ev.object.get("semantic_completeness").?.string);
        const loop = ev.object.get("loops").?.array.items[0];
        const header = try std.fmt.allocPrint(a, "0x{x}", .{base + 1});
        try std.testing.expectEqualStrings(header, loop.object.get("header").?.string);
        try std.testing.expectEqual(@as(usize, 1), loop.object.get("members").?.array.items.len);
        try std.testing.expectEqual(@as(i64, 2), loop.object.get("members").?.array.items[0].object.get("instruction_count").?.integer);
        try std.testing.expectEqualStrings(header, later.object.get("loop_evidence").?.object.get("loops").?.array.items[0].object.get("header").?.string);
        try std.testing.expect(std.mem.indexOf(u8, ev.object.get("note").?.string, "Every traversal executes header instructions") != null);
        _ = try call(ctx, "close_document", .{ .doc_id = iteration + 1 });
    }
    var large: [1027]u8 = undefined;
    for (0..513) |i| {
        large[i * 2] = 0x75;
        large[i * 2 + 1] = 0;
    }
    large[1026] = 0xc3;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "loop.bin", .data = &large });
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "x86_64", .base = 4096, .entry = 4096 } });
    const big = try call(ctx, "get_cfg", .{ .function_address = 4096, .max_blocks = 1 });
    const omitted = big.object.get("loop_evidence").?;
    try std.testing.expectEqualStrings("omitted_graph_budget_or_missing_entry", omitted.object.get("status").?.string);
    try std.testing.expect(omitted.object.get("total_natural_loops").? == .null);
    _ = try call(ctx, "close_document", .{ .doc_id = 3 });
}
test "C03 loop begins at recurrence instruction and excludes initialization" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // C03 ARM64: cbz; mov; mov; header add w8,w8,w8,lsl #4; ...; b.ne header.
    const data = [_]u8{ 0x41, 0x01, 0x00, 0x34, 0xe9, 0x03, 0x01, 0x2a, 0xe8, 0x00, 0x80, 0x52, 0x08, 0x11, 0x08, 0x0b, 0x0a, 0x14, 0x40, 0x38, 0x29, 0x05, 0x00, 0xf1, 0x08, 0x01, 0x0a, 0x0b, 0x81, 0xff, 0xff, 0x54, 0xe0, 0x03, 0x08, 0x2a, 0xc0, 0x03, 0x5f, 0xd6, 0xe8, 0x00, 0x80, 0x52, 0xe0, 0x03, 0x08, 0x2a, 0xc0, 0x03, 0x5f, 0xd6 };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "C03.bin", .data = &data });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "C03.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "C03-loop", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
    const page = try call(ctx, "get_cfg", .{ .function_address = 4096, .max_blocks = 1, .offset = 2 });
    const loop = page.object.get("loop_evidence").?.object.get("loops").?.array.items[0];
    try std.testing.expectEqualStrings("0x100c", loop.object.get("header").?.string);
    try std.testing.expectEqual(@as(usize, 1), loop.object.get("members").?.array.items.len);
    try std.testing.expectEqual(@as(i64, 5), loop.object.get("members").?.array.items[0].object.get("instruction_count").?.integer);
    const instructions = try call(ctx, "get_cfg", .{ .function_address = 4096, .max_blocks = 1, .offset = 2, .include_disassembly = true });
    const header_block = instructions.object.get("basic_blocks").?.array.items[0];
    try std.testing.expectEqualStrings("0x100c", header_block.object.get("start").?.string);
    _ = try call(ctx, "close_document", .{ .doc_id = 1 });
}
