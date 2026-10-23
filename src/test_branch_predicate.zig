const std = @import("std");
const tools = @import("tools.zig");
const json = @import("util/json.zig");

fn call(ctx: tools.ToolContext, name: []const u8, args: anytype) !std.json.Value {
    const encoded = try json.stringify(ctx.allocator, args);
    const params = try std.json.parseFromSlice(std.json.Value, ctx.allocator, encoded, .{});
    const result = try tools.dispatch(ctx, name, params.value);
    try std.testing.expect(!result.is_error);
    const parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, result.json_response, .{});
    const results = parsed.value.object.get("results") orelse return parsed.value;
    return if (results == .array) results.array.items[0].object.get("result").? else parsed.value;
}

fn countEvidence(value: std.json.Value) usize {
    var count: usize = 0;
    switch (value) {
        .object => |object| {
            if (object.get("branch_predicate_evidence") != null) count += 1;
            var iterator = object.iterator();
            while (iterator.next()) |item| count += countEvidence(item.value_ptr.*);
        },
        .array => |array| for (array.items) |item| {
            count += countEvidence(item);
        },
        else => {},
    }
    return count;
}

test "branch predicate handlers expose pair and do not cross CFG block entries or intervening writers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "branch-predicate", .allocator = a };
    // Positive pair; intervening NOP; intervening unsupported flag writer;
    // CBZ direct entry to B.HI creates a block boundary between SUBS and B.HI.
    const fixtures = [_][]const u32{
        &.{ 0xf1010042, 0x54ffffe8, 0xd65f03c0 },
        &.{ 0xf1010042, 0xd503201f, 0x54ffffc8, 0xd65f03c0 },
        &.{ 0xf1010042, 0xfa420020, 0x54ffffc8, 0xd65f03c0 },
        &.{ 0xb4000040, 0xf1010042, 0x54ffffc8, 0xd65f03c0 },
    };
    for (fixtures, 0..) |words, iteration| {
        var bytes: [16]u8 = undefined;
        for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], word, .little);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "branch.bin", .data = bytes[0 .. words.len * 4] });
        const path = try tmp.dir.realPathFileAlloc(std.testing.io, "branch.bin", a);
        const doc_id = iteration + 1;
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
        const cfg = try call(ctx, "get_cfg", .{ .doc_id = doc_id, .function_address = "0x1000", .include_disassembly = true });
        try std.testing.expectEqual(@as(usize, if (iteration == 0) 1 else 0), countEvidence(cfg));
        const disassembly = try call(ctx, "disassemble_range", .{ .doc_id = doc_id, .start = "0x1000", .byte_length = words.len * 4 });
        // Raw linear disassembly's scope remains explicitly conditional on
        // consecutive execution, so a direct branch entry does not certify NZCV.
        try std.testing.expectEqual(@as(usize, if (iteration == 0 or iteration == 3) 1 else 0), countEvidence(disassembly));
        const encoded = try json.stringify(a, disassembly);
        if (iteration == 0) {
            try std.testing.expect(std.mem.indexOf(u8, encoded, "unsigned(left_before) > unsigned(right_operand)") != null);
            try std.testing.expect(std.mem.indexOf(u8, encoded, "input_before_instruction") != null);
        }
        const pack = try call(ctx, "get_semantic_slice", .{ .doc_id = doc_id, .addresses = "0x1000", .view = "pack", .max_chars = 30000 });
        const pack_encoded = try json.stringify(a, pack);
        try std.testing.expectEqual(iteration == 0 or iteration == 3, std.mem.indexOf(u8, pack_encoded, "adjacent SUBS/CMP if executed") != null);
        _ = try call(ctx, "close_document", .{ .doc_id = doc_id });
    }
}
