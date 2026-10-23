const std = @import("std");
const tools = @import("tools.zig");
const json = @import("util/json.zig");

fn result(ctx: tools.ToolContext, name: []const u8, args: anytype) !tools.ToolResult {
    const encoded = try json.stringify(ctx.allocator, args);
    const params = try std.json.parseFromSlice(std.json.Value, ctx.allocator, encoded, .{});
    return tools.dispatch(ctx, name, params.value);
}
fn call(ctx: tools.ToolContext, name: []const u8, args: anytype) !std.json.Value {
    const response = try result(ctx, name, args);
    try std.testing.expect(!response.is_error);
    const parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, response.json_response, .{});
    const results = parsed.value.object.get("results") orelse return parsed.value;
    return if (results == .array) results.array.items[0].object.get("result").? else parsed.value;
}
fn stepsCount(cfg: std.json.Value) usize {
    var count: usize = 0;
    for (cfg.object.get("basic_blocks").?.array.items) |block| count += @intCast(block.object.get("execution").?.object.get("emitted_steps").?.integer);
    return count;
}

test "execution pages preserve every operation, header inputs, bytes and provenance continuation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // mov w11,#1; add w11,w11,#1; cbnz w0,add; ret.
    const bytes = [_]u8{ 0x2b, 0, 0x80, 0x52, 0x6b, 0x05, 0, 0x11, 0xe0, 0xff, 0xff, 0x35, 0xc0, 0x03, 0x5f, 0xd6 };
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "loop.bin", .data = &bytes });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "loop.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "execution", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
    const legacy = try call(ctx, "get_cfg", .{ .function_address = 4096, .include_disassembly = true });
    const graph = try call(ctx, "get_cfg", .{ .function_address = 4096 });
    try std.testing.expect(graph.object.get("instruction_view") == null);
    try std.testing.expect(graph.object.get("instructions_at") == null);
    try std.testing.expect(graph.object.get("reconstruction_workflow") == null);
    try std.testing.expect(graph.object.get("basic_blocks").?.array.items[0].object.get("instructions") == null);
    try std.testing.expect(legacy.object.get("register_flow_evidence") != null);
    var page = try call(ctx, "get_cfg", .{ .function_address = 4096, .instruction_view = "execution", .include_disassembly = false, .max_blocks = 1 });
    var total_steps: usize = 0;
    var total_blocks: usize = 0;
    var saw_header = false;
    while (true) {
        try std.testing.expectEqualStrings("execution", page.object.get("instruction_view").?.string);
        try std.testing.expectEqualStrings("basic_blocks[].execution.text", page.object.get("instructions_at").?.string);
        const workflow = page.object.get("reconstruction_workflow").?.string;
        try std.testing.expect(workflow.len < 600);
        try std.testing.expect(std.mem.indexOf(u8, workflow, "both destinations") != null);
        try std.testing.expect(std.mem.indexOf(u8, workflow, "checking equivalence") != null);
        try std.testing.expect(page.object.get("register_flow_evidence") == null);
        total_steps += stepsCount(page);
        total_blocks += page.object.get("basic_blocks").?.array.items.len;
        for (page.object.get("basic_blocks").?.array.items) |block| {
            try std.testing.expect(block.object.get("instructions") == null);
            try std.testing.expectEqualStrings("included", block.object.get("execution_status").?.string);
            const execution = block.object.get("execution").?;
            const row_text = execution.object.get("text").?.string;
            var row_count: usize = 0;
            var rows = std.mem.splitScalar(u8, row_text, '\n');
            while (rows.next()) |row| {
                if (!std.mem.startsWith(u8, row, "  0x")) continue;
                const bytes_begin = std.mem.indexOfScalar(u8, row, '[').? + 1;
                const original_word = try std.fmt.allocPrint(a, "{x}", .{bytes[(total_steps - @as(usize, @intCast(execution.object.get("emitted_steps").?.integer)) + row_count) * 4 ..][0..4]});
                try std.testing.expectEqualStrings(original_word, row[bytes_begin .. bytes_begin + 8]);
                try std.testing.expect(std.mem.indexOf(u8, row, "] ") != null);
                row_count += 1;
            }
            try std.testing.expectEqual(@as(usize, @intCast(execution.object.get("emitted_steps").?.integer)), row_count);
            if (std.mem.eql(u8, block.object.get("start").?.string, "0x1004")) {
                const text = execution.object.get("text").?.string;
                try std.testing.expect(std.mem.indexOf(u8, text, "@in_0x1004") != null);
                try std.testing.expect(std.mem.indexOf(u8, text, "via 0x1000 = zext32(w11@0x1000)") != null);
                try std.testing.expect(std.mem.indexOf(u8, text, "via 0x1004 = zext32(w11@0x1004)") != null);
                try std.testing.expect(block.object.get("loop_context").?.object.get("is_loop_header").?.bool);
                try std.testing.expectEqualStrings("0x1004", block.object.get("loop_context").?.object.get("containing_headers").?.array.items[0].string);
                try std.testing.expect(std.mem.indexOf(u8, text, "0x1004 [6b050011;") != null);
                saw_header = true;
            }
        }
        const follow = page.object.get("detailed_provenance_call").?.object.get("arguments").?;
        const detailed = try call(ctx, "get_cfg", follow);
        try std.testing.expect(detailed.object.get("register_flow_evidence") != null);
        if (!page.object.get("partial").?.bool) break;
        const next = page.object.get("next_call").?.object.get("arguments").?;
        try std.testing.expectEqualStrings("execution", next.object.get("instruction_view").?.string);
        page = try call(ctx, "get_cfg", next);
    }
    var legacy_count: usize = 0;
    for (legacy.object.get("basic_blocks").?.array.items) |block| legacy_count += block.object.get("instructions").?.array.items.len;
    try std.testing.expectEqual(legacy_count, total_steps);
    try std.testing.expectEqual(@as(usize, 4), total_steps);
    try std.testing.expectEqual(graph.object.get("basic_blocks").?.array.items.len, total_blocks);
    try std.testing.expect(saw_header);
    const rebased = try call(ctx, "rebase_document", .{ .doc_id = 1, .new_base_address = 8192 });
    const rebase_result = try result(ctx, "get_cfg", .{ .doc_id = rebased.object.get("doc_id").?.integer, .function_address = 8192, .instruction_view = "execution" });
    try std.testing.expect(rebase_result.is_error);
    try std.testing.expect(std.mem.indexOf(u8, rebase_result.json_response, "rebased documents") != null);
}

test "execution opaque barriers retain raw bytes and explicitly reset following sources" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // mov w0,#1; AND immediate (outside execution subset); add w0,w0,#1; ret.
    const bytes = [_]u8{ 0x20, 0, 0x80, 0x52, 0, 0x1c, 0, 0x12, 0, 4, 0, 0x11, 0xc0, 3, 0x5f, 0xd6 };
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "opaque.bin", .data = &bytes });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "opaque.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "execution", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 0, .entry = 0 } });
    const cfg = try call(ctx, "get_cfg", .{ .function_address = 0, .instruction_view = "execution" });
    var found_opaque = false;
    for (cfg.object.get("basic_blocks").?.array.items) |block| {
        const text = block.object.get("execution").?.object.get("text").?.string;
        if (std.mem.indexOf(u8, text, "OPAQUE") != null) {
            try std.testing.expect(std.mem.indexOf(u8, text, "0x4 [001c0012;") != null);
            found_opaque = true;
        }
    }
    try std.testing.expect(found_opaque);
    const row_note = cfg.object.get("instruction_rows_note").?.string;
    try std.testing.expect(std.mem.indexOf(u8, row_note, "not a missing instruction") != null);
    try std.testing.expectEqual(@as(usize, 4), stepsCount(cfg));
    const encoded_cfg = try json.stringify(a, cfg);
    try std.testing.expect(std.mem.indexOf(u8, encoded_cfg, "@opaque_0x4") != null);
    const invalid = try result(ctx, "get_cfg", .{ .function_address = 0, .instruction_view = "foo" });
    try std.testing.expect(invalid.is_error);
    const invalid_type = try result(ctx, "get_cfg", .{ .function_address = 0, .instruction_view = true });
    try std.testing.expect(invalid_type.is_error);
}

test "execution rejects unsupported architectures and retains x86 automatic context" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "x86.bin", .data = &.{ 0x31, 0xc0, 0xc3 } });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "x86.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "execution", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "x86_64", .base = 0, .entry = 0 } });
    const unsupported = try result(ctx, "get_cfg", .{ .function_address = 0, .instruction_view = "execution" });
    try std.testing.expect(unsupported.is_error);
    try std.testing.expect(std.mem.indexOf(u8, unsupported.json_response, "ARM64 only") != null);
    const full = try call(ctx, "get_binary_context", .{ .mode = "auto" });
    try std.testing.expect(full.object.get("disasm") != null);
    const evidence = full.object.get("control_flow_evidence").?;
    try std.testing.expectEqualStrings("disassembly", evidence.object.get("instruction_view").?.string);
    try std.testing.expectEqualStrings("cfg.basic_blocks[].instructions", evidence.object.get("instructions_at").?.string);
    try std.testing.expect(evidence.object.get("reconstruction_workflow").?.string.len < 600);
    try std.testing.expect(evidence.object.get("instruction_rows_note") == null);
    try std.testing.expect(evidence.object.get("cfg").?.object.get("basic_blocks").?.array.items[0].object.get("instructions") != null);
}

test "execution bounded instruction tail has exact primary byte continuation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bytes: [300 * 4]u8 = undefined;
    for (0..299) |i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], 0xd503201f, .little);
    std.mem.writeInt(u32, bytes[299 * 4 ..][0..4], 0xd65f03c0, .little);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "long.bin", .data = &bytes });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "long.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "execution", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
    const cfg = try call(ctx, "get_cfg", .{ .function_address = 4096, .instruction_view = "execution" });
    const block = cfg.object.get("basic_blocks").?.array.items[0];
    try std.testing.expectEqualStrings("omitted_step_budget", block.object.get("execution_status").?.string);
    try std.testing.expectEqual(@as(usize, 256), stepsCount(cfg));
    const omitted = block.object.get("omitted_bytes").?;
    try std.testing.expectEqualStrings("0x1400", omitted.object.get("start").?.string);
    try std.testing.expectEqual(@as(i64, 44 * 4), omitted.object.get("byte_length").?.integer);
    const exact = try call(ctx, "read_bytes", omitted.object.get("raw_bytes_call").?.object.get("arguments").?);
    const disassembly = try call(ctx, "disassemble_range", omitted.object.get("next_call").?.object.get("arguments").?);
    const disassembly_json = try json.stringify(a, disassembly);
    try std.testing.expect(std.mem.indexOf(u8, disassembly_json, "0x1400") != null);
    const expected = try std.fmt.allocPrint(a, "{x}", .{bytes[256 * 4 ..]});
    try std.testing.expectEqualStrings(expected, exact.object.get("hex").?.string);
    try std.testing.expect(!(cfg.object.get("partial").?.bool));
}

test "execution response budget shrinks blocks while continuations cover the graph" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bytes: [513 * 4]u8 = undefined;
    // cbnz w0,next creates many blocks without changing procedure discovery.
    for (0..512) |i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], 0x35000020, .little);
    std.mem.writeInt(u32, bytes[512 * 4 ..][0..4], 0xd65f03c0, .little);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "pages.bin", .data = &bytes });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "pages.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "execution", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
    var page = try call(ctx, "get_cfg", .{ .function_address = 4096, .instruction_view = "execution", .max_blocks = 256 });
    try std.testing.expect(page.object.get("returned_blocks").?.integer < 256);
    var count: usize = 0;
    var pages: usize = 0;
    while (true) {
        const encoded = try json.stringify(a, page);
        try std.testing.expect(encoded.len <= 80000 - 2048);
        try std.testing.expect(!page.object.get("disassembly_omitted").?.bool);
        for (page.object.get("basic_blocks").?.array.items) |block| {
            const expected = try std.fmt.allocPrint(a, "0x{x}", .{4096 + count * 4});
            try std.testing.expectEqualStrings(expected, block.object.get("start").?.string);
            count += 1;
        }
        pages += 1;
        if (!page.object.get("partial").?.bool) break;
        page = try call(ctx, "get_cfg", page.object.get("next_call").?.object.get("arguments").?);
    }
    try std.testing.expect(pages > 1);
    try std.testing.expectEqual(@as(usize, 513), count);
}

test "execution tiny undecoded CFG tail exposes complete executable byte continuation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = [_]u8{ 0x20, 0, 0x80, 0x52, 0, 0, 0, 0, 0, 4, 0, 0x11, 0xc0, 3, 0x5f, 0xd6 };
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "gap.bin", .data = &bytes });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "gap.bin", a);
    var store = tools.DocumentStore.init(a, std.testing.io);
    const ctx = tools.ToolContext{ .io = std.testing.io, .store = &store, .session_id = "execution", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
    const full = try call(ctx, "get_binary_context", .{ .mode = "auto" });
    const coverage = full.object.get("executable_coverage").?;
    try std.testing.expectEqualStrings("bytes_outside_recovered_cfg", coverage.object.get("status").?.string);
    try std.testing.expectEqual(@as(i64, 8), coverage.object.get("recovered_cfg_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, 16), coverage.object.get("executable_bytes").?.integer);
    const follow = coverage.object.get("range_calls").?.array.items[0];
    const disassembly = try call(ctx, "disassemble_range", follow.object.get("arguments").?);
    const encoded = try json.stringify(a, disassembly);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "0x100c") != null);
}
