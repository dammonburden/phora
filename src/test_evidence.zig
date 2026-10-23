const std = @import("std");
const tools = @import("tools.zig");
const json = @import("util/json.zig");
const types = @import("types.zig");
const macho = @import("loaders/macho.zig");
const disasm = @import("analysis/disassembler.zig");
const arm64 = @import("arch/arm64.zig");
const Xrefs = @import("analysis/xref.zig").XrefTracker;
const testing = std.testing;
const base: u64 = 0x100000000;
const entry_address = base + 0x200;

test "evidence: generic initialization does not imply an RPC protocol" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "protocol-hint", .allocator = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "uninitialized internal/cpu.Initialize protocolVersion", "jsonrpc tools/list" }, 0..) |markers, i| {
        const data = try std.mem.concat(a, u8, &.{ "\xc0\x03\x5f\xd6", markers, "\x00" });
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "protocol-hints", .data = data });
        const path = try tmp.dir.realPathFileAlloc(testing.io, "protocol-hints", a);
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
        const context = try call(ctx, "get_binary_context", .{ .mode = "full" });
        var rpc_hint = false;
        for (context.object.get("subsystem_hints").?.array.items) |hint| {
            if (std.mem.eql(u8, hint.object.get("name").?.string, "mcp_protocol")) rpc_hint = true;
        }
        try testing.expectEqual(i == 1, rpc_hint);
        _ = try call(ctx, "close_document", .{ .doc_id = i + 1 });
    }
}

test "evidence: context raw previews preserve zero runs and exact file continuation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const data = try a.alloc(u8, 70000);
    @memset(data, 0);
    for (0..16) |i| data[i] = @intCast(i);
    data[data.len - 1] = 255;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw-context", .data = data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "raw-context", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "raw-context", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 0x1000, .entry = 0x1000, .analysis = false } });
    const context = try call(ctx, "get_binary_context", .{ .mode = "full", .include_bytes = true });
    try testing.expect(!context.object.get("truncated").?.bool);
    try testing.expectEqualStrings("compact_hex_with_zero_runs", context.object.get("byte_encoding").?.string);
    const preview = context.object.get("bytes").?.array.items[0];
    try testing.expectEqual(@as(i64, 70000), preview.object.get("section_length").?.integer);
    try testing.expectEqual(@as(i64, 4096), preview.object.get("returned_length").?.integer);
    try testing.expectEqualStrings("000102030405060708090a0b0c0d0e0f[ZERO*4080]", preview.object.get("hex").?.string);
    try testing.expect(preview.object.get("partial").?.bool and context.object.get("bytes_partial").?.bool);
    var next = preview.object.get("next_call").?;
    var offset: usize = 4096;
    while (true) {
        const response = try tools.dispatch(ctx, "read_bytes", next.object.get("arguments").?);
        try testing.expect(!response.is_error);
        const decoded = try std.json.parseFromSlice(std.json.Value, a, response.json_response, .{});
        const page = decoded.value.object.get("results").?.array.items[0].object.get("result").?;
        try testing.expectEqual(@as(i64, @intCast(offset)), page.object.get("file_offset").?.integer);
        const hex = page.object.get("hex").?.string;
        const length: usize = @intCast(page.object.get("length").?.integer);
        try testing.expectEqual(length * 2, hex.len);
        for (0..length) |i| try testing.expectEqual(data[offset + i], try std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16));
        offset += length;
        if (!page.object.get("partial").?.bool) break;
        next = page.object.get("next_call").?;
        try testing.expect(length > 0 and offset < data.len);
    }
    try testing.expectEqual(data.len, offset);
    _ = try call(ctx, "close_document", .{ .doc_id = 1 });
}

test "evidence: typed byte reads preserve exceptional entries endianness and full u64 precision" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var data = fixture(0);
    for (0..16) |i| put32(&data, 0x208 + i * 4, @intCast(if (i == 15) 1 else i + 1));
    @memset(data[0x250..0x258], 0xff);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "integer-table", .data = &data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "integer-table", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "typed-bytes", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path });
    const table = try call(ctx, "read_bytes", .{ .address = entry_address + 8, .length = 64, .element_size = 4, .byte_order = "little" });
    const view = table.object.get("integer_view").?;
    const values = view.object.get("values").?.array.items;
    try testing.expectEqual(@as(usize, 16), values.len);
    for (values, 0..) |value, i| try testing.expectEqual(@as(u64, if (i == 15) 1 else i + 1), try std.fmt.parseInt(u64, value.string, 10));
    try testing.expectEqual(@as(i64, 0), view.object.get("uninterpreted_trailing_bytes").?.integer);
    const big = try call(ctx, "read_bytes", .{ .address = entry_address + 8, .length = 4, .element_size = 4, .byte_order = "big" });
    try testing.expectEqualStrings("16777216", big.object.get("integer_view").?.object.get("values").?.array.items[0].string);
    const wide = try call(ctx, "read_bytes", .{ .file_offset = 0x250, .length = 10, .element_size = 8, .byte_order = "little" });
    try testing.expect(wide.object.get("address").? == .null);
    const wide_view = wide.object.get("integer_view").?;
    try testing.expectEqual(@as(usize, 1), wide_view.object.get("values").?.array.items.len);
    try testing.expectEqualStrings("18446744073709551615", wide_view.object.get("values").?.array.items[0].string);
    try testing.expectEqual(@as(i64, 2), wide_view.object.get("uninterpreted_trailing_bytes").?.integer);
    for ([_][]const u8{
        "{\"doc_id\":1,\"file_offset\":520,\"element_size\":3,\"byte_order\":\"little\"}",
        "{\"doc_id\":1,\"file_offset\":520,\"element_size\":4}",
        "{\"doc_id\":1,\"file_offset\":520,\"element_size\":4,\"byte_order\":\"middle\"}",
        "{\"doc_id\":1,\"file_offset\":520,\"length\":1025,\"element_size\":4,\"byte_order\":\"little\"}",
    }) |bad| {
        const params = try std.json.parseFromSlice(std.json.Value, a, bad, .{});
        const response = try tools.dispatch(ctx, "read_bytes", params.value);
        try testing.expect(response.is_error);
    }
    _ = try call(ctx, "close_document", .{ .doc_id = 1 });
}

test "evidence: raw reads respect section boundaries and reject conflicting coordinates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const data = fixture(0);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw-boundary", .data = &data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "raw-boundary", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "raw-boundary", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path });
    const edge = try call(ctx, "read_bytes", .{ .address = entry_address + 6, .length = 64, .encoding = "hex_compact" });
    try testing.expectEqual(@as(i64, 2), edge.object.get("length").?.integer);
    try testing.expectEqualStrings("mapping_boundary", edge.object.get("stop_reason").?.string);
    const raw = try call(ctx, "read_bytes", .{ .file_offset = 0x206, .length = 64, .encoding = "hex_compact" });
    try testing.expectEqual(@as(i64, 64), raw.object.get("length").?.integer);
    for ([_][]const u8{ "{\"doc_id\":1,\"address\":512,\"file_offset\":512}", "{\"doc_id\":1,\"file_offset\":-1}" }) |bad| {
        const parsed = try std.json.parseFromSlice(std.json.Value, a, bad, .{});
        try testing.expect((try tools.dispatch(ctx, "read_bytes", parsed.value)).is_error);
    }
    const doc = &store.get(1).?.doc;
    doc.segments[0].sections[1].is_zerofill = true;
    const zero = try call(ctx, "read_bytes", .{ .address = entry_address + 70, .length = 64, .encoding = "hex_compact" });
    try testing.expectEqual(@as(i64, 2), zero.object.get("length").?.integer);
    try testing.expectEqualStrings("0000", zero.object.get("hex").?.string);
    try testing.expect(zero.object.get("file_offset").? == .null);
    doc.segments[0].file_size = 0x280;
    const backed_edge = try call(ctx, "read_bytes", .{ .address = base + 0x27e, .length = 64, .encoding = "hex_compact" });
    try testing.expectEqual(@as(i64, 2), backed_edge.object.get("returned_length").?.integer);
    try testing.expectEqualStrings("mapping_boundary", backed_edge.object.get("stop_reason").?.string);
    const tail = try call(ctx, "read_bytes", .{ .address = base + 0x300, .length = 8, .encoding = "hex_compact" });
    try testing.expectEqualStrings("0000000000000000", tail.object.get("hex").?.string);
    try testing.expectEqualStrings("zero_fill", tail.object.get("backing").?.string);
    // Malformed loader ranges must yield an error rather than overflow or invent bytes.
    doc.segments[0].file_offset = std.math.maxInt(u64);
    for ([_]u64{ base + 0x80, entry_address + 6 }) |bad_address| {
        const encoded = try json.stringify(a, .{ .doc_id = 1, .address = bad_address, .length = 64 });
        const params = try std.json.parseFromSlice(std.json.Value, a, encoded, .{});
        try testing.expect((try tools.dispatch(ctx, "read_bytes", params.value)).is_error);
    }
    doc.segments[0].file_offset = 0;
    doc.segments[0].sections[0].file_offset = std.math.maxInt(u64);
    const bad_section = try std.json.parseFromSlice(std.json.Value, a, try json.stringify(a, .{ .doc_id = 1, .address = entry_address + 6 }), .{});
    try testing.expect((try tools.dispatch(ctx, "read_bytes", bad_section.value)).is_error);
    doc.segments[0].start = std.math.maxInt(u64) - 4;
    doc.segments[0].length = 128;
    const outside = try std.json.parseFromSlice(std.json.Value, a, "{\"doc_id\":1,\"address\":0}", .{});
    try testing.expect((try tools.dispatch(ctx, "read_bytes", outside.value)).is_error);
    _ = try call(ctx, "close_document", .{ .doc_id = 1 });
}

test "evidence: raw byte identity EOF and response budget continuation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const data = try a.alloc(u8, 70000);
    for (data, 0..) |*byte, i| byte.* = @truncate(i);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw-pagination", .data = data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "raw-pagination", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "raw-pagination", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 0x1000 } });
    const params = try std.json.parseFromSlice(std.json.Value, a, "{\"doc_id\":1,\"file_offset\":0,\"length\":65536,\"encoding\":\"both\"}", .{});
    const response = try tools.dispatch(ctx, "read_bytes", params.value);
    try testing.expect(!response.is_error);
    try testing.expect(response.json_response.len < response.meta_max_chars.?);
    const page = try call(ctx, "read_bytes", .{ .file_offset = 0, .length = 65536, .encoding = "both" });
    try testing.expectEqual(@as(i64, 32768), page.object.get("returned_length").?.integer);
    const next = page.object.get("next_call").?.object.get("arguments").?;
    try testing.expectEqual(@as(i64, 32768), next.object.get("file_offset").?.integer);
    const second_response = try tools.dispatch(ctx, "read_bytes", next);
    try testing.expect(!second_response.is_error);
    const compact = try call(ctx, "read_bytes", .{ .file_offset = 0, .length = 65536, .encoding = "hex_compact" });
    const hex = compact.object.get("hex").?.string;
    for (data[0..65536], 0..) |byte, i| try testing.expectEqual(byte, try std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16));
    const eof = try call(ctx, "read_bytes", .{ .file_offset = 69997, .length = 10 });
    try testing.expectEqual(@as(i64, 3), eof.object.get("length").?.integer);
    try testing.expectEqualStrings("end_of_file", eof.object.get("stop_reason").?.string);
    try testing.expect(!eof.object.contains("next_call"));
    const end = try call(ctx, "read_bytes", .{ .file_offset = 70000, .length = 10 });
    try testing.expectEqual(@as(i64, 0), end.object.get("returned_length").?.integer);
    const rebased = try call(ctx, "rebase_document", .{ .doc_id = 1, .new_base_address = 0x5000 });
    const rebased_id = rebased.object.get("doc_id").?.integer;
    const moved = try call(ctx, "read_bytes", .{ .doc_id = rebased_id, .address = 0x5000, .length = 256, .encoding = "hex_compact" });
    try testing.expectEqualStrings(hex[0..512], moved.object.get("hex").?.string);
    const high = try call(ctx, "rebase_document", .{ .doc_id = 1, .new_base_address = "0xfffffffffffffff0" });
    const high_id = high.object.get("doc_id").?.integer;
    const high_bytes = try call(ctx, "read_bytes", .{ .doc_id = high_id, .address = "0xfffffffffffffff0", .length = 65536, .encoding = "both" });
    try testing.expectEqual(@as(i64, 16), high_bytes.object.get("returned_length").?.integer);
    try testing.expectEqualStrings("address_space_boundary", high_bytes.object.get("stop_reason").?.string);
    try testing.expect(!high_bytes.object.contains("next_call"));
    try testing.expectEqualStrings("arm64", high_bytes.object.get("document_architecture").?.string);
    // Worst-case printable previews need an extra JSON escape for every byte.
    const loaded_data = store.get(1).?.doc.data;
    const worst_data = try a.alloc(u8, loaded_data.len);
    store.get(1).?.doc.data = worst_data;
    for (worst_data, 0..) |*byte, i| byte.* = if (i % 2 == 0) '"' else '\\';
    const worst_response = try tools.dispatch(ctx, "read_bytes", params.value);
    try testing.expect(!worst_response.is_error);
    try testing.expect(worst_response.json_response.len < worst_response.meta_max_chars.?);
    const worst = try std.json.parseFromSlice(std.json.Value, a, worst_response.json_response, .{});
    const worst_page = worst.value.object.get("results").?.array.items[0].object.get("result").?;
    try testing.expectEqual(@as(i64, 32768), worst_page.object.get("returned_length").?.integer);
    try testing.expectEqual(@as(usize, 32768), worst_page.object.get("ascii").?.string.len);
    store.get(1).?.doc.data = loaded_data;
    _ = try call(ctx, "close_document", .{ .doc_id = high_id });
    _ = try call(ctx, "close_document", .{ .doc_id = rebased_id });
    _ = try call(ctx, "close_document", .{ .doc_id = 1 });
}

fn put32(data: []u8, off: usize, value: u32) void {
    std.mem.writeInt(u32, data[off..][0..4], value, .little);
}

fn put64(data: []u8, off: usize, value: u64) void {
    std.mem.writeInt(u64, data[off..][0..8], value, .little);
}

fn nameAt(data: []u8, off: usize, name: []const u8) void {
    @memcpy(data[off..][0..name.len], name);
}

// One function, two data labels and a header label in an executable segment.
// The function-start stream deliberately also names data, which must be rejected.
fn fixture(value: u16) [1024]u8 {
    var data: [1024]u8 = @splat(0);
    put32(&data, 0, 0xfeedfacf);
    put32(&data, 4, 0x0100000c);
    put32(&data, 12, 2);
    put32(&data, 16, 4);
    put32(&data, 20, 296);
    put32(&data, 32, 0x19);
    put32(&data, 36, 232);
    nameAt(&data, 40, "__TEXT");
    put64(&data, 56, base);
    put64(&data, 64, 1024);
    put64(&data, 80, 1024);
    put32(&data, 88, 5);
    put32(&data, 92, 5);
    put32(&data, 96, 2);
    nameAt(&data, 104, "__text");
    nameAt(&data, 120, "__TEXT");
    put64(&data, 136, entry_address);
    put64(&data, 144, 8);
    put32(&data, 152, 0x200);
    put32(&data, 156, 2);
    put32(&data, 168, 0x80000400);
    nameAt(&data, 184, "__const");
    nameAt(&data, 200, "__TEXT");
    put64(&data, 216, entry_address + 8);
    put64(&data, 224, 64);
    put32(&data, 232, 0x208);
    put32(&data, 236, 2);
    put32(&data, 264, 2);
    put32(&data, 268, 24);
    put32(&data, 272, 0x300);
    put32(&data, 276, 5);
    put32(&data, 280, 0x350);
    const names = "\x00_main\x00_version_string\x00_version_number\x00__mh_execute_header\x00_main_alias\x00";
    put32(&data, 284, names.len);
    nameAt(&data, 0x350, names);
    put32(&data, 288, 0x80000028);
    put32(&data, 292, 24);
    put64(&data, 296, 0x200);
    put32(&data, 312, 0x26);
    put32(&data, 316, 16);
    put32(&data, 320, 0x3d0);
    put32(&data, 324, 4);
    nameAt(&data, 0x3d0, "\x80\x04\x08\x00");
    const addresses = [_]u64{ entry_address, entry_address + 8, entry_address + 48, base, entry_address };
    const offsets = [_]u32{ 1, 7, 23, 39, 59 };
    for (addresses, offsets, 0..) |address, str_off, i| {
        const off = 0x300 + i * 16;
        put32(&data, off, str_off);
        data[off + 4] = 0x0f;
        data[off + 5] = if (i == 1 or i == 2) 2 else 1;
        put64(&data, off + 8, address);
    }
    put32(&data, 0x200, 0x52800000 | (@as(u32, value) << 5));
    put32(&data, 0x204, 0xd65f03c0);
    nameAt(&data, 0x208, "fixture version string");
    return data;
}

fn call(ctx: tools.ToolContext, tool: []const u8, args: anytype) !std.json.Value {
    const params = try json.stringify(ctx.allocator, args);
    const parsed = try std.json.parseFromSlice(std.json.Value, ctx.allocator, params, .{});
    const response = try tools.dispatch(ctx, tool, parsed.value);
    if (response.is_error) std.debug.print("{s}: {s}\n", .{ tool, response.json_response });
    try testing.expect(!response.is_error);
    const decoded = try std.json.parseFromSlice(std.json.Value, ctx.allocator, response.json_response, .{});
    if (decoded.value.object.contains("total_instructions")) return decoded.value;
    try testing.expect(decoded.value.object.get("success").?.bool);
    const item = decoded.value.object.get("results").?.array.items[0];
    try testing.expect(item.object.get("success").?.bool);
    return item.object.get("result").?;
}

test "evidence: instruction flags override misleading section names" {
    const section = types.Section{ .name = "__text", .start = 0, .length = 8, .file_offset = 0, .is_code = false };
    try testing.expect(!section.isCode());
    var custom = section;
    custom.name = ".custom";
    custom.is_code = true;
    try testing.expect(custom.isCode());
    custom.is_zerofill = true;
    try testing.expect(!custom.isCode());
}

test "evidence: explicit data sections are never swept as code" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var data = fixture(0);
    put32(&data, 168, 0); // __text is now explicitly data.
    var doc = try macho.parse(a, 1, "data-only", &data, .{});
    try testing.expectEqual(@as(usize, 0), doc.procedures.items.len);
    var xrefs = Xrefs.init(a, testing.io);
    const instructions = try disasm.disassembleDocument(a, &doc, arm64.decodeInstruction, &xrefs);
    try testing.expectEqual(@as(usize, 0), instructions.items.len);
    try testing.expectEqual(@as(usize, 0), try disasm.disassembleDocumentLean(a, &doc, arm64.decodeInstruction, &xrefs));
    var analysis = try @import("analysis/pipeline.zig").analyzeLean(a, testing.io, &doc, &data);
    defer analysis.deinit(a);
    try testing.expectEqual(@as(usize, 0), analysis.procedures.len);
}

test "evidence: tiny mapped Mach-O keeps data separate and exposes instruction effects" {
    for ([_]u16{ 0, 42 }) |value| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const data = fixture(value);
        // Also exercise a universal file whose slice does not start at offset 0.
        var fat: [5120]u8 = @splat(0);
        nameAt(&fat, 4096, &data);
        std.mem.writeInt(u32, fat[0..4], 0xcafebabe, .big);
        std.mem.writeInt(u32, fat[4..8], 1, .big);
        std.mem.writeInt(u32, fat[8..12], 0x0100000c, .big);
        std.mem.writeInt(u32, fat[16..20], 4096, .big);
        std.mem.writeInt(u32, fat[20..24], 1024, .big);
        std.mem.writeInt(u32, fat[24..28], 12, .big);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "tiny", .data = if (value == 0) &data else &fat });
        const path = try tmp.dir.realPathFileAlloc(testing.io, "tiny", a);
        var store = tools.DocumentStore.init(a, testing.io);
        const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "evidence-test", .allocator = a };
        _ = try call(ctx, "load_binary", .{ .path = path });
        const entry = store.get(1).?;
        try testing.expectEqual(@as(usize, 1), entry.doc.procedures.items.len);
        try testing.expectEqual(@as(usize, 1), entry.db.procedures.count());
        try testing.expectEqual(entry_address, entry.doc.procedures.items[0].entry);
        try testing.expectEqual(@as(u64, 8), entry.doc.procedures.items[0].size);
        try testing.expect(entry.db.symbols.contains(entry_address + 8));
        try testing.expect(!entry.db.procedures.contains(entry_address + 8));
        try testing.expectEqual(@as(usize, 0), entry.db.ir_cache.count());

        const context = try call(ctx, "get_binary_context", .{ .mode = "full" });
        const flow = context.object.get("control_flow_evidence").?;
        try testing.expectEqualStrings("execution", flow.object.get("instruction_view").?.string);
        const compact_blocks = flow.object.get("cfg").?.object.get("basic_blocks").?.array.items;
        try testing.expectEqual(@as(usize, 1), compact_blocks.len);
        const execution = compact_blocks[0].object.get("execution").?;
        try testing.expectEqual(@as(i64, 2), execution.object.get("emitted_steps").?.integer);
        try testing.expectEqual(@as(i64, 0), execution.object.get("opaque_steps").?.integer);
        try testing.expect(std.mem.indexOf(u8, execution.object.get("text").?.string, "w0@") != null);
        try testing.expect(std.mem.indexOf(u8, execution.object.get("text").?.string, "return to") != null);
        try testing.expect(!context.object.contains("disasm"));
        const bytes = try call(ctx, "read_bytes", .{ .address = entry_address, .length = 8, .encoding = "hex_compact" });
        try testing.expectEqualStrings(if (value == 0) "00008052c0035fd6" else "40058052c0035fd6", bytes.object.get("hex").?.string);
        try testing.expectEqual(@as(i64, if (value == 0) 512 else 4608), bytes.object.get("file_offset").?.integer);
        const cfg = try call(ctx, "get_cfg", .{ .function_address = entry_address, .include_disassembly = true });
        const cfg_text = try json.stringify(a, cfg);
        try testing.expect(std.mem.indexOf(u8, cfg_text, "\"mov\"") != null);
        try testing.expect(std.mem.indexOf(u8, cfg_text, "\"ret\"") != null);
        const pack = try call(ctx, "get_semantic_slice", .{ .addresses = entry_address, .view = "pack", .scope = "function" });
        const pack_text = try json.stringify(a, pack);
        try testing.expect(!pack.object.get("instruction_evidence_truncated").?.bool);
        try testing.expect(std.mem.indexOf(u8, pack_text, "instruction evidence") != null);
        try testing.expect(std.mem.indexOf(u8, pack_text, "mov") != null);
        const coverage = pack.object.get("instruction_coverage").?.array.items;
        try testing.expectEqual(@as(usize, 1), coverage.len);
        try testing.expect(coverage[0].object.get("complete").?.bool);
        try testing.expectEqual(@as(i64, 8), coverage[0].object.get("covered_bytes").?.integer);
        try testing.expect(!coverage[0].object.contains("next_call"));
        const short_pack = try call(ctx, "get_semantic_slice", .{ .addresses = entry_address, .view = "pack", .max_chars = 100 });
        const short_coverage = short_pack.object.get("instruction_coverage").?.array.items[0];
        if (!short_coverage.object.get("complete").?.bool) {
            const next = short_coverage.object.get("next_call").?;
            try testing.expectEqualStrings("disassemble_range", next.object.get("tool").?.string);
            const args = next.object.get("arguments").?;
            const continuation = try call(ctx, "disassemble_range", .{
                .doc_id = args.object.get("doc_id").?.integer,
                .start = args.object.get("start").?.string,
                .byte_length = args.object.get("byte_length").?.integer,
            });
            try testing.expectEqual(@as(i64, 8), short_coverage.object.get("covered_bytes").?.integer + continuation.object.get("covered_bytes").?.integer);
        }
        const naming = try call(ctx, "suggest_names", .{ .addresses = entry_address });
        try testing.expect(naming.array.items[0].object.contains("byte_evidence"));
        try testing.expect(!naming.array.items[0].object.contains("pseudocode"));
        _ = try call(ctx, "analyze_functions", .{ .addresses = entry_address });
        try testing.expectEqual(@as(usize, 0), entry.db.ir_cache.count());
        const frontier = try call(ctx, "get_remake_frontier", .{ .seeds = entry_address });
        for (frontier.object.get("frontier").?.array.items) |candidate| {
            for (candidate.object.get("next").?.array.items) |next| {
                try testing.expect(!std.mem.eql(u8, next.object.get("tool").?.string, "decompile"));
            }
        }

        const project_path = try std.fs.path.join(a, &.{ std.fs.path.dirname(path).?, "state.phora" });
        _ = try call(ctx, "save_project", .{ .path = project_path });
        _ = try call(ctx, "load_project", .{ .path = project_path });
        const restored = store.get(2).?;
        try testing.expectEqualSlices(u64, entry.doc.linker_function_starts, restored.doc.linker_function_starts);
        try testing.expectEqualStrings("linker_start_next_boundary", coverage[0].object.get("boundary_kind").?.string);
        try testing.expectEqual(true, restored.doc.segments[0].sections[0].is_code.?);
        try testing.expectEqual(false, restored.doc.segments[0].sections[1].is_code.?);

        const lifted = try call(ctx, "lift", .{ .doc_id = 1, .addresses = entry_address });
        try testing.expect(lifted.object.contains("statements"));
        try testing.expect(!lifted.object.contains("pseudocode"));
        try testing.expectEqualStrings("heuristic_ir", lifted.object.get("analysis_kind").?.string);
        // Raw and cached instruction paths must produce identical evidence.
        _ = entry.db.instructions.remove(entry_address);
        const instructions = try call(ctx, "disassemble_range", .{ .doc_id = 1, .start = entry_address, .byte_length = 8 });
        const rows = instructions.object.get("results").?.object.get("results").?.array.items;
        try testing.expectEqual(@as(usize, 2), rows.len);
        const first = rows[0].object.get("result").?;
        try testing.expectEqual(@as(i64, if (value == 0) 512 else 4608), first.object.get("file_offset").?.integer);
        const effect = first.object.get("semantics").?;
        try testing.expectEqualStrings("modeled", effect.object.get("status").?.string);
        try testing.expectEqualStrings("movz", effect.object.get("operation").?.string);
        try testing.expectEqual(@as(i64, 32), effect.object.get("width_bits").?.integer);
        const transfer = effect.object.get("transfer").?;
        try testing.expectEqualStrings("0x0000000000000000", transfer.object.get("preserve_mask").?.string);
        try testing.expectEqualStrings(if (value == 0) "0x0000000000000000" else "0x000000000000002a", transfer.object.get("value_bits").?.string);
        try testing.expectEqualStrings("unsupported", rows[1].object.get("result").?.object.get("semantics").?.object.get("status").?.string);
        try entry.db.addInstruction(arm64.decodeInstruction(data[0x200..0x204], entry_address));
        const cached = try call(ctx, "disassemble_range", .{ .doc_id = 1, .start = entry_address, .byte_length = 8 });
        try testing.expectEqualStrings(try json.stringify(a, instructions), try json.stringify(a, cached));
        const data_only = try call(ctx, "disassemble_range", .{ .doc_id = 1, .start = entry_address + 8, .byte_length = 8 });
        try testing.expectEqual(@as(i64, 0), data_only.object.get("total_instructions").?.integer);
        try testing.expectEqualStrings("not_file_backed_code", data_only.object.get("stop_reason").?.string);
        // A saved project's source path may now name different bytes.
        const changed_data = fixture(43);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "tiny", .data = &changed_data });
        const reloaded = try call(ctx, "load_project", .{ .path = project_path });
        try testing.expect(std.mem.indexOf(u8, reloaded.object.get("warning").?.string, "source binary has changed") != null);
        try testing.expectEqual(@as(usize, 0), store.get(3).?.doc.linker_function_starts.len);
        _ = try call(ctx, "close_document", .{ .doc_id = 3 });
        _ = try call(ctx, "close_document", .{ .doc_id = 1 });
        _ = try call(ctx, "close_document", .{ .doc_id = 2 });
        try testing.expectEqual(@as(usize, 0), store.documents.count());
    }
}

test "semantics: MCP coverage, invalid encodings, byte bounds, rebase and removed renderer" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data: [22]u8 = @splat(0);
    for ([_]u32{ 0x72b579a1, 0x92f579a2, 0xf2f579bf, 0x52c00000, 0xd65f03c0 }, 0..) |word, i| put32(&data, i * 4, word);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "instructions", .data = &data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "instructions", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "semantics-test", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 0x1000, .entry = 0x1000, .analysis = false } });
    const response = try call(ctx, "disassemble_range", .{ .start = 0x1000, .byte_length = 22 });
    const summary = response.object.get("semantics_summary").?;
    try testing.expectEqual(@as(i64, 3), summary.object.get("modeled").?.integer);
    try testing.expectEqual(@as(i64, 1), summary.object.get("unsupported").?.integer);
    try testing.expectEqual(@as(i64, 1), summary.object.get("invalid_encoding").?.integer);
    try testing.expect(response.object.get("partial").?.bool);
    try testing.expectEqualStrings("incomplete_instruction", response.object.get("stop_reason").?.string);
    try testing.expectEqual(@as(i64, 20), response.object.get("covered_bytes").?.integer);
    try testing.expectEqualStrings("0x1014", response.object.get("next_address").?.string);
    const rows = response.object.get("results").?.object.get("results").?.array.items;
    const wk = rows[0].object.get("result").?.object.get("semantics").?;
    try testing.expect(wk.object.get("reads_destination").?.bool);
    try testing.expectEqualStrings("0x000000000000ffff", wk.object.get("transfer").?.object.get("preserve_mask").?.string);
    try testing.expectEqualStrings("0x00000000abcd0000", wk.object.get("transfer").?.object.get("value_bits").?.string);
    const zero = rows[2].object.get("result").?.object.get("semantics").?;
    try testing.expect(zero.object.get("discard_write").?.bool);
    try testing.expect(!zero.object.get("reads_destination").?.bool);
    try testing.expectEqualStrings("zero_register", zero.object.get("destination").?.object.get("kind").?.string);
    const short = try call(ctx, "disassemble_range", .{ .start = 0x1000, .byte_length = 3 });
    try testing.expectEqual(@as(i64, 0), short.object.get("total_instructions").?.integer);
    try testing.expectEqualStrings("incomplete_instruction", short.object.get("stop_reason").?.string);

    const invalid_args = [_][]const u8{
        "{\"start\":-1}", "{\"start\":4097}", "{\"start\":4096,\"byte_length\":0}",
    };
    for (invalid_args) |text| {
        const params = try std.json.parseFromSlice(std.json.Value, a, text, .{});
        const result = try tools.dispatch(ctx, "disassemble_range", params.value);
        try testing.expect(result.is_error);
        _ = try std.json.parseFromSlice(std.json.Value, a, result.json_response, .{});
    }
    const count = try call(ctx, "disassemble_range", .{ .start = 0x1000, .count = std.math.maxInt(i64) });
    try testing.expectEqual(@as(i64, 5), count.object.get("total_instructions").?.integer);
    for (tools.tool_definitions) |definition| {
        try testing.expect(!std.mem.eql(u8, definition.name, "decompile"));
        if (std.mem.eql(u8, definition.name, "lift")) {
            const schema = try std.json.parseFromSlice(std.json.Value, a, definition.input_schema, .{});
            try testing.expect(!schema.value.object.get("properties").?.object.contains("format"));
        }
    }
    try testing.expectError(error.UnknownTool, tools.dispatch(ctx, "decompile", .null));
    const old_format = try std.json.parseFromSlice(std.json.Value, a, "{\"addresses\":4096,\"format\":\"pseudocode\"}", .{});
    const rejected = try tools.dispatch(ctx, "lift", old_format.value);
    try testing.expect(rejected.is_error);

    const rebased = try call(ctx, "rebase_document", .{ .doc_id = 1, .new_base_address = 0x2000 });
    const rebased_id = rebased.object.get("doc_id").?.integer;
    const moved = try call(ctx, "disassemble_range", .{ .doc_id = rebased_id, .start = 0x2000, .byte_length = 4 });
    const moved_first = moved.object.get("results").?.object.get("results").?.array.items[0].object.get("result").?;
    try testing.expectEqualStrings("0x2000", moved_first.object.get("address").?.string);
    try testing.expectEqual(@as(i64, 0), moved_first.object.get("file_offset").?.integer);
    try testing.expectEqualStrings(try json.stringify(a, wk), try json.stringify(a, moved_first.object.get("semantics").?));
    _ = try call(ctx, "close_document", .{ .doc_id = rebased_id });
    _ = try call(ctx, "close_document", .{ .doc_id = 1 });
}

test "evidence: instruction excerpts report truncation and a continuation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data: [300]u8 = undefined;
    for (0..75) |i| put32(&data, i * 4, 0xd503201f);
    put32(&data, 296, 0xd65f03c0);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw", .data = &data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "raw", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "evidence", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 0x1000, .entry = 0x1000 } });
    const pack = try call(ctx, "get_semantic_slice", .{ .addresses = 0x1000, .view = "pack", .max_chars = 500 });
    try testing.expect(pack.object.get("truncated").?.bool);
    try testing.expect(pack.object.get("instruction_evidence_truncated").?.bool);
    const coverage = pack.object.get("instruction_coverage").?.array.items[0];
    const covered = coverage.object.get("covered_bytes").?.integer;
    try testing.expect(covered > 0 and covered < data.len);
    const args = coverage.object.get("next_call").?.object.get("arguments").?;
    const next = args.object.get("start").?.string;
    try testing.expectEqual(@as(u64, @intCast(0x1000 + covered)), try std.fmt.parseInt(u64, next[2..], 16));
    const remainder = try call(ctx, "disassemble_range", .{ .doc_id = args.object.get("doc_id").?.integer, .start = next, .byte_length = args.object.get("byte_length").?.integer });
    try testing.expectEqual(@as(i64, data.len), covered + remainder.object.get("covered_bytes").?.integer);
    const full = try call(ctx, "get_semantic_slice", .{ .addresses = 0x1000, .view = "pack" });
    try testing.expect(!full.object.get("instruction_evidence_truncated").?.bool);
}

test "semantics: instruction effects paginate below the MCP response cap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data: [4096]u8 = undefined;
    for (0..1024) |i| put32(&data, i * 4, 0xd2800020);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "many", .data = &data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "many", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "budget-test", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 0x1000, .analysis = false } });
    var covered: u64 = 0;
    var count: i64 = 0;
    while (covered < data.len) {
        const result = try call(ctx, "disassemble_range", .{ .start = 0x1000 + covered, .byte_length = data.len - covered });
        try testing.expect(!result.object.contains("error"));
        const size: u64 = @intCast(result.object.get("covered_bytes").?.integer);
        try testing.expect(size > 0 and size % 4 == 0);
        const n = result.object.get("total_instructions").?.integer;
        try testing.expectEqual(n, result.object.get("semantics_summary").?.object.get("modeled").?.integer);
        covered += size;
        count += n;
        if (covered < data.len) {
            try testing.expect(result.object.get("partial").?.bool);
            try testing.expectEqualStrings("output_budget", result.object.get("stop_reason").?.string);
            const next = try std.fmt.allocPrint(a, "0x{x}", .{0x1000 + covered});
            try testing.expectEqualStrings(next, result.object.get("next_address").?.string);
        } else try testing.expect(!result.object.get("partial").?.bool);
    }
    try testing.expectEqual(@as(i64, 1024), count);
    _ = try call(ctx, "close_document", .{ .doc_id = 1 });
}

test "evidence: Thumb predication and i386 bytes agree across MCP views" {
    const Case = struct { arch: []const u8, bytes: []const u8, count: usize };
    const cases = [_]Case{
        .{ .arch = "arm32", .bytes = &.{ 0x81, 0x42, 0x04, 0xbf, 0x00, 0x20, 0x70, 0x47, 0x41, 0x40, 0x00, 0x20, 0x01, 0xf0, 0x01, 0x02, 0x49, 0x08, 0x10, 0x44, 0xfa, 0xd1, 0x70, 0x47 }, .count = 11 },
        .{ .arch = "x86", .bytes = &.{ 0x55, 0x89, 0xe5, 0x8b, 0x45, 0x08, 0x40, 0x5d, 0xc3 }, .count = 6 },
    };
    for (cases) |case| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw", .data = case.bytes });
        const path = try tmp.dir.realPathFileAlloc(testing.io, "raw", a);
        var store = tools.DocumentStore.init(a, testing.io);
        const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "cross-arch-evidence", .allocator = a };
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = case.arch, .base = 4096, .entry = 4096 } });
        const result = try call(ctx, "disassemble_range", .{ .doc_id = 1, .start = 4096, .byte_length = case.bytes.len });
        try testing.expectEqual(@as(i64, @intCast(case.bytes.len)), result.object.get("covered_bytes").?.integer);
        try testing.expectEqual(@as(i64, @intCast(case.count)), result.object.get("total_instructions").?.integer);
        const rows = result.object.get("results").?.object.get("results").?.array.items;
        if (std.mem.eql(u8, case.arch, "arm32")) {
            const mov = rows[2].object.get("result").?;
            try testing.expectEqualStrings("mov", mov.object.get("mnemonic").?.string);
            try testing.expectEqualStrings("eq", mov.object.get("execution_condition").?.string);
            try testing.expect(!mov.object.get("sets_flags").?.bool);
            const ret = rows[3].object.get("result").?;
            try testing.expectEqualStrings("eq", ret.object.get("execution_condition").?.string);
            try testing.expectEqualStrings("and.w", rows[6].object.get("result").?.object.get("mnemonic").?.string);
        } else {
            try testing.expectEqualStrings("ebp", rows[0].object.get("result").?.object.get("operands").?.string);
            try testing.expectEqualStrings("inc", rows[3].object.get("result").?.object.get("mnemonic").?.string);
        }
        const cfg = try call(ctx, "get_cfg", .{ .function_address = 4096, .include_disassembly = true });
        var decoded_count: i64 = 0;
        for (cfg.object.get("basic_blocks").?.array.items) |block| decoded_count += block.object.get("instruction_count").?.integer;
        try testing.expectEqual(@as(i64, @intCast(case.count)), decoded_count);
        const pack = try call(ctx, "get_semantic_slice", .{ .addresses = 4096, .view = "pack", .scope = "function" });
        const text = pack.object.get("text").?.string;
        try testing.expect(std.mem.indexOf(u8, text, if (std.mem.eql(u8, case.arch, "arm32")) "if eq, flags unchanged" else "inc eax") != null);
    }
}

test "evidence: opaque x86 addressing does not resume in the middle of an instruction" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw", .data = &.{ 0x67, 0x8b, 0x00, 0xc3 } });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "raw", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "opaque-x86", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "x86", .base = 4096, .entry = 4096 } });
    const result = try call(ctx, "disassemble_range", .{ .start = 4096, .byte_length = 4 });
    try testing.expectEqual(@as(i64, 0), result.object.get("covered_bytes").?.integer);
    try testing.expectEqual(@as(i64, 0), result.object.get("total_instructions").?.integer);
    try testing.expectEqualStrings("undecoded_instruction", result.object.get("stop_reason").?.string);
    try testing.expectEqualStrings("0x1000", result.object.get("next_address").?.string);
    try testing.expectEqualStrings("read_bytes", result.object.get("next_call").?.object.get("tool").?.string);
}

test "evidence: large CFGs paginate blocks and fall back to compact graph evidence" {
    for ([_]bool{ false, true }) |long_block| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const count: usize = if (long_block) 3000 else 71;
        const data = try a.alloc(u8, count * 4);
        for (0..count) |i| put32(data, i * 4, if (long_block) 0xd503201f else 0xb4000040);
        put32(data, data.len - 4, 0xd65f03c0);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw", .data = data });
        const path = try tmp.dir.realPathFileAlloc(testing.io, "raw", a);
        var store = tools.DocumentStore.init(a, testing.io);
        const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "paged-cfg", .allocator = a };
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
        const page = try call(ctx, "get_cfg", .{ .function_address = 4096, .include_disassembly = true });
        if (long_block) {
            try testing.expect(page.object.get("disassembly_omitted").?.bool);
            try testing.expectEqual(@as(i64, 1), page.object.get("total_blocks").?.integer);
            try testing.expectEqualStrings("disassemble_range", page.object.get("next_disassembly_call").?.object.get("tool").?.string);
            try testing.expect(!page.object.get("basic_blocks").?.array.items[0].object.contains("instructions"));
        } else {
            try testing.expect(page.object.get("partial").?.bool);
            try testing.expectEqual(@as(i64, 71), page.object.get("total_blocks").?.integer);
            try testing.expectEqual(@as(i64, 64), page.object.get("returned_blocks").?.integer);
            const next = page.object.get("next_call").?.object.get("arguments").?;
            const rest = try call(ctx, "get_cfg", .{ .function_address = next.object.get("function_address").?.string, .offset = next.object.get("offset").?.integer, .max_blocks = next.object.get("max_blocks").?.integer, .include_disassembly = true });
            try testing.expect(!rest.object.get("partial").?.bool);
            try testing.expectEqual(@as(i64, 7), rest.object.get("returned_blocks").?.integer);
            try testing.expectEqualStrings("0x1100", rest.object.get("basic_blocks").?.array.items[0].object.get("start").?.string);
            const compact = try call(ctx, "get_cfg", .{ .function_address = 4096, .offset = 64, .max_blocks = 64 });
            try testing.expectEqual(@as(usize, 7), compact.object.get("basic_blocks").?.array.items.len);
            try testing.expectEqualStrings("0x1100", compact.object.get("basic_blocks").?.array.items[0].object.get("start").?.string);
        }
    }
}

test "evidence: large IR pages preserve every cached statement and variable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const count = 1300;
    const data = try a.alloc(u8, count * 4);
    // Calls cannot be discarded by IR cleanup. Exercise a multi-page function.
    for (0..count) |i| put32(data, i * 4, 0x94001000);
    put32(data, data.len - 4, 0xd65f03c0);
    put32(data, 0, 0xd2800020); // MOV X0,#1 creates a variable record before calls.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw", .data = data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "raw", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "paged-ir", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
    var offset: i64 = 0;
    var statements: usize = 0;
    var variables: usize = 0;
    var pages: usize = 0;
    while (true) {
        const page = try call(ctx, "lift", .{ .addresses = 4096, .offset = offset, .max_results = 127 });
        try testing.expectEqual(offset, page.object.get("offset").?.integer);
        try testing.expectEqualStrings("statements_then_variables", page.object.get("pagination_order").?.string);
        const stmts = page.object.get("statements").?.array.items;
        const vars = page.object.get("variables").?.array.items;
        const cached = store.get(1).?.db.getCachedIR(4096).?;
        try testing.expect(cached.variables.len > 0);
        for (stmts, 0..) |stmt, i| {
            const expected = try std.fmt.allocPrint(a, "0x{x}", .{cached.statements[statements + i].address});
            try testing.expectEqualStrings(expected, stmt.object.get("address").?.string);
        }
        for (vars, 0..) |v, i| try testing.expectEqualStrings(cached.variables[variables + i].name, v.object.get("name").?.string);
        statements += stmts.len;
        variables += vars.len;
        pages += 1;
        try testing.expectEqual(@as(i64, @intCast(stmts.len + vars.len)), page.object.get("returned_results").?.integer);
        if (!page.object.get("partial").?.bool) {
            try testing.expectEqual(cached.statements.len, statements);
            try testing.expectEqual(cached.variables.len, variables);
            try testing.expectEqual(@as(i64, @intCast(statements + variables)), page.object.get("total_results").?.integer);
            try testing.expect(!page.object.contains("next_call"));
            break;
        }
        const next = page.object.get("next_call").?.object.get("arguments").?;
        try testing.expectEqual(@as(i64, 1), next.object.get("doc_id").?.integer);
        try testing.expectEqualStrings("0x1000", next.object.get("addresses").?.string);
        offset = next.object.get("offset").?.integer;
        try testing.expectEqual(@as(i64, @intCast(statements + variables)), offset);
        try testing.expect(pages < 30);
    }
    try testing.expect(pages > 8);
    const empty = try call(ctx, "lift", .{ .addresses = 4096, .offset = 999999 });
    try testing.expectEqual(@as(i64, 0), empty.object.get("returned_results").?.integer);
    try testing.expect(!empty.object.get("partial").?.bool);
    // A large batch must respect the same global response cap.
    var batch: [50]u64 = @splat(4096);
    const page = try call(ctx, "lift", .{ .addresses = &batch, .max_results = 256 });
    try testing.expect(page.object.get("partial").?.bool);
    const embedded = try call(ctx, "analyze_functions", .{ .addresses = &batch, .include = &[_][]const u8{"ir"} });
    try testing.expect(embedded.object.get("ir").?.object.get("partial").?.bool);
}

test "evidence: CFG page shrinks to retain requested instruction evidence" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const count = 129 * 24;
    const data = try a.alloc(u8, count * 4);
    for (0..count) |i| put32(data, i * 4, if (i % 24 == 23) 0xb4000020 else 0xd503201f);
    put32(data, data.len - 4, 0xd65f03c0);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw", .data = data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "raw", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "shrinking-cfg", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
    var offset: i64 = 0;
    var instructions: usize = 0;
    while (true) {
        const page = try call(ctx, "get_cfg", .{ .function_address = 4096, .offset = offset, .max_blocks = 128, .include_disassembly = true });
        try testing.expect(!page.object.get("disassembly_omitted").?.bool);
        const blocks = page.object.get("basic_blocks").?.array.items;
        if (offset == 0) try testing.expect(blocks.len < 128);
        for (blocks) |block| instructions += block.object.get("instructions").?.array.items.len;
        if (!page.object.get("partial").?.bool) break;
        const next = page.object.get("next_call").?.object.get("arguments").?.object.get("offset").?.integer;
        try testing.expectEqual(offset + @as(i64, @intCast(blocks.len)), next);
        offset = next;
    }
    try testing.expectEqual(@as(usize, count), instructions);
}

test "evidence: predicated indirect Thumb branch remains explicitly unresolved" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // IT NE; BX r0; BX LR. The taken target is unknown; fallthrough is known.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw", .data = &.{ 0x18, 0xbf, 0x00, 0x47, 0x70, 0x47 } });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "raw", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "indirect-predicate", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm32", .base = 4096, .entry = 4096 } });
    const page = try call(ctx, "get_cfg", .{ .function_address = 4096 });
    try testing.expectEqual(@as(i64, 1), page.object.get("unresolved_indirect_jumps").?.integer);
}

fn evidenceProcedure(entry: *tools.DocumentEntry, address: u64, size: u64) !void {
    var proc = entry.db.getProcedure(address) orelse types.Procedure{ .entry = address, .size = size };
    proc.size = size;
    try entry.db.addProcedure(proc);
    for (entry.doc.procedures.items) |*item| {
        if (item.entry == address) {
            item.size = size;
            return;
        }
    }
    try entry.doc.procedures.append(proc);
}

fn expectIrTail(ir: std.json.Value) !void {
    var tail_call = false;
    var tail_return = false;
    for (ir.object.get("statements").?.array.items) |statement| {
        const address = statement.object.get("address").?.string;
        const kind = statement.object.get("type").?.string;
        if (std.mem.eql(u8, address, "0x105c") and std.mem.eql(u8, kind, "call")) tail_call = true;
        if (std.mem.eql(u8, address, "0x1060") and std.mem.eql(u8, kind, "return")) tail_return = true;
    }
    try testing.expect(tail_call);
    try testing.expect(tail_return);
    try testing.expect(!ir.object.get("partial").?.bool);
}

test "evidence regression: unknown-size get_cfg cannot truncate a later lift or IR analysis" {
    // Exercise both entry points to on-demand IR recovery after the request
    // arena containing the short CFG preview has already been destroyed.
    for ([_]bool{ false, true }) |analyze_first| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var data: [100]u8 = undefined;
        for (0..25) |i| put32(&data, i * 4, 0x94001000); // calls survive IR cleanup
        put32(&data, 0, 0xd2800020);
        put32(&data, 96, 0xd65f03c0);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "unknown-size", .data = &data });
        const path = try tmp.dir.realPathFileAlloc(testing.io, "unknown-size", a);
        var store = tools.DocumentStore.init(a, testing.io);
        const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "unknown-size-regression", .allocator = a };
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096, .analysis = false } });
        const entry = store.get(1).?;
        try evidenceProcedure(entry, 4096, 0);
        try testing.expect(entry.db.getCachedCfg(4096) == null);
        {
            var request = std.heap.ArenaAllocator.init(testing.allocator);
            defer request.deinit();
            var request_ctx = ctx;
            request_ctx.allocator = request.allocator();
            const preview = try call(request_ctx, "get_cfg", .{ .function_address = 4096 });
            try testing.expectEqual(@as(i64, 1), preview.object.get("total_blocks").?.integer);
            try testing.expectEqual(@as(i64, 64), preview.object.get("basic_blocks").?.array.items[0].object.get("size").?.integer);
            try testing.expect(entry.db.getCachedCfg(4096) == null);
            try testing.expect(entry.db.getCachedIR(4096) == null);
            try testing.expectEqual(@as(u64, 0), entry.db.getProcedure(4096).?.size);
        }
        if (analyze_first) {
            const analyzed = try call(ctx, "analyze_functions", .{ .addresses = 4096, .include = &[_][]const u8{"ir"} });
            try expectIrTail(analyzed.object.get("ir").?);
            try expectIrTail(try call(ctx, "lift", .{ .addresses = 4096, .max_results = 256 }));
        } else {
            try expectIrTail(try call(ctx, "lift", .{ .addresses = 4096, .max_results = 256 }));
            const analyzed = try call(ctx, "analyze_functions", .{ .addresses = 4096, .include = &[_][]const u8{"ir"} });
            try expectIrTail(analyzed.object.get("ir").?);
        }
        const graph = entry.db.getCachedCfg(4096).?;
        try testing.expectEqual(@as(usize, 1), graph.basic_blocks.len);
        try testing.expectEqual(@as(u64, 100), graph.basic_blocks[0].size);
        const ir = entry.db.getCachedIR(4096).?;
        try testing.expect(ir.statements[ir.statements.len - 1].address > 4096 + 64);
        _ = try call(ctx, "close_document", .{ .doc_id = 1 });
    }
}

// A valid graph with an indirect jump followed by conditional blocks. Injecting
// its immutable cache isolates response-policy boundaries from byte discovery.
fn summaryBoundaryGraph(a: std.mem.Allocator, extra_edge: bool) !types.CfgResult {
    const blocks = try a.alloc(types.BasicBlock, 16);
    const edges = try a.alloc(types.CfgEdge, if (extra_edge) 33 else 32);
    var edge_index: usize = 0;
    for (blocks, 0..) |*block, i| {
        const successors = try a.alloc(u64, if (i == 0 and extra_edge) 3 else 2);
        for (successors, 0..) |*target, j| {
            target.* = 4096 + ((i + j + 1) % blocks.len) * 4;
            edges[edge_index] = .{ .from = 4096 + i * 4, .to = target.*, .edge_type = if (i == 0) .unconditional else if (j == 0) .branch_true else .branch_false };
            edge_index += 1;
        }
        block.* = .{ .start = 4096 + i * 4, .size = 4, .instruction_count = 1, .successors = successors, .predecessors = &.{}, .terminator = if (i == 0) .jump else .branch };
    }
    for (blocks) |*block| {
        var predecessors = std.array_list.Managed(u64).init(a);
        for (edges) |edge| if (edge.to == block.start) {
            try predecessors.append(edge.from);
        };
        block.predecessors = try predecessors.toOwnedSlice();
    }
    return .{ .basic_blocks = blocks, .edges = edges };
}

test "evidence regression: analyze CFG inline boundary and edge-only summary continuation" {
    for ([_]bool{ false, true }) |extra_edge| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var data: [64]u8 = undefined;
        for (0..16) |i| put32(&data, i * 4, 0xd503201f);
        put32(&data, 60, 0xd65f03c0);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "summary-boundary", .data = &data });
        const path = try tmp.dir.realPathFileAlloc(testing.io, "summary-boundary", a);
        var store = tools.DocumentStore.init(a, testing.io);
        const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "summary-boundary-regression", .allocator = a };
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096, .analysis = false } });
        const entry = store.get(1).?;
        try evidenceProcedure(entry, 4096, data.len);
        const graph = try summaryBoundaryGraph(a, extra_edge);
        try entry.db.cacheCfg(4096, graph);
        const analyzed = try call(ctx, "analyze_functions", .{ .addresses = 4096 });
        const cfg = analyzed.object.get("cfg").?;
        if (extra_edge) {
            try testing.expectEqual(@as(i64, 16), cfg.object.get("total_blocks").?.integer);
            try testing.expectEqual(@as(i64, 33), cfg.object.get("total_edges").?.integer);
            try testing.expect(cfg.object.get("partial").?.bool);
            try testing.expect(!cfg.object.contains("basic_blocks"));
            try testing.expect(!cfg.object.contains("edges"));
            const next = cfg.object.get("next_call").?;
            try testing.expectEqualStrings("get_cfg", next.object.get("tool").?.string);
            const args = next.object.get("arguments").?;
            try testing.expectEqual(@as(i64, 1), args.object.get("doc_id").?.integer);
            try testing.expectEqualStrings("0x1000", args.object.get("function_address").?.string);
            try testing.expectEqual(@as(i64, 0), args.object.get("offset").?.integer);
            const full = try call(ctx, "get_cfg", .{ .doc_id = args.object.get("doc_id").?.integer, .function_address = args.object.get("function_address").?.string, .offset = args.object.get("offset").?.integer, .max_blocks = args.object.get("max_blocks").?.integer });
            try testing.expectEqual(@as(usize, 16), full.object.get("basic_blocks").?.array.items.len);
            try testing.expectEqual(@as(usize, 33), full.object.get("edges").?.array.items.len);
            try testing.expect(!full.object.get("partial").?.bool);
        } else {
            try testing.expectEqual(@as(usize, 16), cfg.object.get("basic_blocks").?.array.items.len);
            try testing.expectEqual(@as(usize, 32), cfg.object.get("edges").?.array.items.len);
            try testing.expect(!cfg.object.contains("next_call"));
        }
        _ = try call(ctx, "close_document", .{ .doc_id = 1 });
    }
}

test "evidence regression: default large analyze CFG remains bounded and pages recover every edge" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data: [401 * 4]u8 = undefined;
    for (0..401) |i| put32(&data, i * 4, 0xb4000040); // CBZ X0,next+4
    put32(&data, data.len - 4, 0xd65f03c0);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "large-summary", .data = &data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "large-summary", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "large-summary-regression", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096, .analysis = false } });
    const entry = store.get(1).?;
    try evidenceProcedure(entry, 4096, data.len);
    const params = try std.json.parseFromSlice(std.json.Value, a, "{\"addresses\":4096}", .{});
    const response = try tools.dispatch(ctx, "analyze_functions", params.value);
    try testing.expect(!response.is_error);
    const envelope = try std.json.parseFromSlice(std.json.Value, a, response.json_response, .{});
    try testing.expect(!envelope.value.object.contains("truncated"));
    try testing.expect(!envelope.value.object.contains("error"));
    try testing.expect(envelope.value.object.get("success").?.bool);
    const analyzed = envelope.value.object.get("results").?.array.items[0].object.get("result").?;
    const cfg = analyzed.object.get("cfg").?;
    try testing.expectEqual(@as(i64, 401), cfg.object.get("total_blocks").?.integer);
    try testing.expect(cfg.object.get("partial").?.bool);
    try testing.expect(!cfg.object.contains("basic_blocks"));
    try testing.expect(!cfg.object.contains("edges"));
    try testing.expect(entry.db.getCachedIR(4096) == null);
    const cached = entry.db.getCachedCfg(4096).?;
    try testing.expectEqual(@as(i64, @intCast(cached.edges.len)), cfg.object.get("total_edges").?.integer);
    var next_call = cfg.object.get("next_call").?;
    var blocks: usize = 0;
    var edges: usize = 0;
    var pages: usize = 0;
    while (true) {
        try testing.expectEqualStrings("get_cfg", next_call.object.get("tool").?.string);
        const args = next_call.object.get("arguments").?;
        const page = try call(ctx, "get_cfg", .{ .doc_id = args.object.get("doc_id").?.integer, .function_address = args.object.get("function_address").?.string, .offset = args.object.get("offset").?.integer, .max_blocks = args.object.get("max_blocks").?.integer });
        try testing.expectEqual(@as(i64, @intCast(blocks)), page.object.get("offset").?.integer);
        blocks += page.object.get("basic_blocks").?.array.items.len;
        edges += page.object.get("edges").?.array.items.len;
        pages += 1;
        if (!page.object.get("partial").?.bool) break;
        next_call = page.object.get("next_call").?;
        try testing.expect(pages < 10);
    }
    try testing.expectEqual(@as(usize, 401), blocks);
    try testing.expectEqual(cached.edges.len, edges);
    try testing.expect(pages > 1);
    _ = try call(ctx, "close_document", .{ .doc_id = 1 });
}

test "evidence: BL plus opaque ARM64 slots preserve bytes without inventing control flow" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_]bool{ true, false }) |is_opaque| {
        var data: [32]u8 = undefined;
        put32(&data, 0, 0x94000020); // BL external to this raw procedure.
        for (1..8) |i| put32(&data, i * 4, if (is_opaque) 0xcccccccc else 0x3dc00c20);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "opaque-slots", .data = &data });
        const path = try tmp.dir.realPathFileAlloc(testing.io, "opaque-slots", a);
        var store = tools.DocumentStore.init(a, testing.io);
        const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "opaque-slots", .allocator = a };
        _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
        const range = try call(ctx, "disassemble_range", .{ .start = 4096, .byte_length = 32 });
        try testing.expectEqual(@as(i64, 32), range.object.get("covered_bytes").?.integer);
        try testing.expectEqual(@as(i64, if (is_opaque) 7 else 0), range.object.get("decode_gaps").?.integer);
        const rows = range.object.get("results").?.object.get("results").?.array.items;
        try testing.expectEqual(@as(usize, 8), rows.len);
        for (rows[1..]) |row| {
            const instruction = row.object.get("result").?;
            try testing.expectEqualStrings(if (is_opaque) "unsupported" else "decoded", instruction.object.get("decode_status").?.string);
            try testing.expectEqualStrings(if (is_opaque) "cccccccc" else "200cc03d", instruction.object.get("bytes").?.string);
        }
        const graph = try call(ctx, "get_cfg", .{ .function_address = 4096, .include_disassembly = true });
        try testing.expectEqual(@as(i64, if (is_opaque) 1 else 0), graph.object.get("unknown_terminator_blocks").?.integer);
        const blocks = graph.object.get("basic_blocks").?.array.items;
        try testing.expectEqual(@as(usize, 1), blocks.len);
        try testing.expectEqualStrings(if (is_opaque) "unknown" else "fallthrough", blocks[0].object.get("terminator").?.string);
        try testing.expectEqual(@as(i64, if (is_opaque) 8 else 32), blocks[0].object.get("size").?.integer);
        try testing.expectEqual(@as(usize, 0), blocks[0].object.get("successors").?.array.items.len);
        const pack = try call(ctx, "get_semantic_slice", .{ .addresses = 4096, .view = "pack", .scope = "function" });
        const coverage = pack.object.get("instruction_coverage").?.array.items[0];
        try testing.expectEqual(@as(i64, 32), coverage.object.get("covered_bytes").?.integer);
        try testing.expectEqual(@as(i64, if (is_opaque) 4 else 32), coverage.object.get("decoded_bytes").?.integer);
        try testing.expectEqual(@as(i64, if (is_opaque) 7 else 0), coverage.object.get("decode_gaps").?.integer);
        try testing.expectEqual(!is_opaque, coverage.object.get("decode_complete").?.bool);
        const text = try json.stringify(a, pack);
        try testing.expectEqual(is_opaque, std.mem.indexOf(u8, text, "unsupported decode") != null);
        try testing.expectEqual(@as(i64, if (is_opaque) 1 else 0), pack.object.get("unknowns").?.integer);
    }
}

test "evidence: arithmetic current-state operands and finite vector PAC identity reach CFG and range" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data: [20]u8 = undefined;
    for ([_]u32{ 0x4b0b01ad, 0x0b0b0dab, 0x6f00e400, 0xdac123f0, 0xd65f03c0 }, 0..) |word, i| put32(&data, i * 4, word);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "arithmetic-evidence", .data = &data });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "arithmetic-evidence", a);
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "arithmetic-evidence", .allocator = a };
    _ = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = "arm64", .base = 4096, .entry = 4096 } });
    const range = try call(ctx, "disassemble_range", .{ .start = 4096, .byte_length = data.len });
    try testing.expectEqual(@as(i64, 0), range.object.get("decode_gaps").?.integer);
    const rows = range.object.get("results").?.object.get("results").?.array.items;
    const add = rows[1].object.get("result").?;
    const evidence = add.object.get("arithmetic_evidence").?;
    try testing.expectEqualStrings("before_destination_update", evidence.object.get("source_read_phase").?.string);
    try testing.expectEqualStrings("current_instruction_register_values", evidence.object.get("source_state").?.string);
    try testing.expectEqual(@as(i64, 11), evidence.object.get("right_source").?.object.get("index").?.integer);
    try testing.expectEqual(@as(i64, 11), evidence.object.get("destination").?.object.get("index").?.integer);
    try testing.expectEqualStrings("unsupported", add.object.get("semantics").?.object.get("status").?.string);
    const cfg = try call(ctx, "get_cfg", .{ .function_address = 4096, .include_disassembly = true });
    try testing.expectEqual(@as(i64, 0), cfg.object.get("unknown_terminator_blocks").?.integer);
    const block = cfg.object.get("basic_blocks").?.array.items[0];
    try testing.expectEqual(@as(i64, 20), block.object.get("size").?.integer);
    try testing.expectEqualStrings("return", block.object.get("terminator").?.string);
    const inline_add = block.object.get("instructions").?.array.items[1].object.get("arithmetic_evidence").?;
    try testing.expectEqualStrings("before_destination_update", inline_add.object.get("source_read_phase").?.string);
}

test "raw zero entry remains a real procedure and CFG with default base" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "raw-zero-entry", .allocator = a };
    const cases = .{
        .{ "arm64", &[_]u8{ 0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6 } },
        .{ "x86_64", &[_]u8{ 0xb8, 1, 0, 0, 0, 0xc3 } },
    };
    inline for (cases, 0..) |case, i| {
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "raw-zero", .data = case[1] });
        const path = try tmp.dir.realPathFileAlloc(testing.io, "raw-zero", a);
        const loaded = try call(ctx, "load_binary", .{ .path = path, .options = .{ .arch = case[0] } });
        try testing.expectEqualStrings("0x0", loaded.object.get("entry_point").?.string);
        try testing.expect(loaded.object.get("stats").?.object.get("procedure_count").?.integer > 0);
        const g = try call(ctx, "get_cfg", .{ .function_address = 0, .include_disassembly = true });
        try testing.expectEqualStrings("0x0", g.object.get("basic_blocks").?.array.items[0].object.get("start").?.string);
        try testing.expectEqualStrings("return", g.object.get("basic_blocks").?.array.items[0].object.get("terminator").?.string);
        _ = try call(ctx, "close_document", .{ .doc_id = i + 1 });
    }
}

test "disassembly rejects end ranges instead of silently using a default length" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var store = tools.DocumentStore.init(a, testing.io);
    const ctx = tools.ToolContext{ .io = testing.io, .store = &store, .session_id = "end-diagnostic", .allocator = a };
    const params = try std.json.parseFromSlice(std.json.Value, a, "{\"doc_id\":1,\"start\":4096,\"end\":4100}", .{});
    const r = try tools.dispatch(ctx, "disassemble_range", params.value);
    try testing.expect(r.is_error);
    try testing.expect(std.mem.indexOf(u8, r.json_response, "byte_length = end_exclusive - start") != null);
}
