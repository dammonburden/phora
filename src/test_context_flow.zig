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
test "tiny full context exposes loop provenance and budget-safe CFG continuation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // mov w11,#1; add w11,w11,#1; cbnz w0,add; ret.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tiny.bin", .data = &.{ 0x2b, 0, 0x80, 0x52, 0x6b, 0x05, 0, 0x11, 0xe0, 0xff, 0xff, 0x35, 0xc0, 0x03, 0x5f, 0xd6 } });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "tiny.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "context-flow", .allocator = a };
    for ([_]u64{ 0, 4096 }, 0..) |base, iteration| {
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = base, .entry = base } });
        const full = try call(ctx, "get_binary_context", .{ .mode = "full", .max_chars = 32000 });
        const evidence = full.object.get("control_flow_evidence").?;
        try std.testing.expectEqualStrings("included", evidence.object.get("status").?.string);
        const cfg = evidence.object.get("cfg").?;
        try std.testing.expectEqual(@as(i64, 1), cfg.object.get("loop_evidence").?.object.get("total_natural_loops").?.integer);
        try std.testing.expectEqualStrings("execution", evidence.object.get("instruction_view").?.string);
        try std.testing.expectEqualStrings("cfg.basic_blocks[].execution.text", evidence.object.get("instructions_at").?.string);
        try std.testing.expect(evidence.object.get("reconstruction_workflow").?.string.len < 600);
        try std.testing.expect(evidence.object.get("instruction_rows_note") != null);
        var instruction_rows: usize = 0;
        for (cfg.object.get("basic_blocks").?.array.items) |block| {
            const execution = block.object.get("execution").?;
            const text = execution.object.get("text").?.string;
            try std.testing.expect(std.mem.indexOf(u8, text, "; word=") != null);
            instruction_rows += @intCast(execution.object.get("emitted_steps").?.integer);
        }
        try std.testing.expectEqual(@as(usize, 4), instruction_rows);
        try std.testing.expect(cfg.object.get("register_flow_evidence") == null);
        try std.testing.expect(cfg.object.get("basic_blocks").?.array.items[0].object.get("execution") != null);
        try std.testing.expect(full.object.get("disasm") == null);
        const legacy = try call(ctx, "get_cfg", .{ .function_address = base, .include_disassembly = true });
        try std.testing.expect(legacy.object.get("register_flow_evidence").?.object.get("inputs").?.array.items.len > 0);
        try std.testing.expect(legacy.object.get("basic_blocks").?.array.items[0].object.get("instructions") != null);
        const small = try call(ctx, "get_binary_context", .{ .mode = "full", .max_chars = 1000 });
        const small_json = try json.stringify(a, small);
        try std.testing.expect(small_json.len <= 1000);
        const deferred = small.object.get("control_flow_evidence").?;
        try std.testing.expectEqualStrings("deferred", deferred.object.get("status").?.string);
        const next = deferred.object.get("next_call").?.object.get("arguments").?;
        const expected = try std.fmt.allocPrint(a, "0x{x}", .{base});
        try std.testing.expectEqualStrings(expected, next.object.get("function_address").?.string);
        try std.testing.expect(next.object.get("include_disassembly").?.bool);
        try std.testing.expectEqualStrings("execution", next.object.get("instruction_view").?.string);
        _ = try call(ctx, "close_document", .{ .doc_id = iteration + 1 });
    }
}
