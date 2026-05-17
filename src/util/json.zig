// Phora — JSON Serializer/Parser
// Wraps std.json to serialize/parse Phora types to/from JSON.
// Handles field name mappings (Zig @"return" → JSON "return", etc.)

const std = @import("std");
const types = @import("../types.zig");
const strings_mod = @import("../analysis/strings.zig");

const Allocator = std.mem.Allocator;

// ============================================================================
// Serialization — Zig structs → JSON string
// ============================================================================

/// Serialize any value to a JSON string (allocated).
pub fn stringify(allocator: Allocator, value: anytype) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    try stringifyTo(value, &buf.writer);
    return buf.toOwnedSlice();
}

/// Serialize any value to a JSON string with pretty printing (allocated).
pub fn stringifyPretty(allocator: Allocator, value: anytype) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    try stringifyPrettyTo(value, &buf.writer);
    return buf.toOwnedSlice();
}

/// Serialize any value as minified JSON to the given writer.
pub fn stringifyTo(value: anytype, writer: anytype) !void {
    try stringifyToOptions(value, .{
        .emit_null_optional_fields = false,
    }, writer);
}

/// Serialize any value as pretty JSON to the given writer.
pub fn stringifyPrettyTo(value: anytype, writer: anytype) !void {
    try stringifyToOptions(value, .{
        .whitespace = .indent_2,
        .emit_null_optional_fields = false,
    }, writer);
}

fn stringifyToOptions(value: anytype, options: std.json.Stringify.Options, writer: anytype) !void {
    var out: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
    defer out.deinit();
    try std.json.Stringify.value(value, options, &out.writer);
    try writer.writeAll(out.written());
}

// ============================================================================
// Parsing — JSON string → Zig structs
// ============================================================================

/// Parse a JSON string into a typed value. Caller must call .deinit() on result.
pub fn parse(comptime T: type, allocator: Allocator, json_str: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, json_str, .{
        .ignore_unknown_fields = true,
    });
}

/// Parse a JSON string into a typed value using an arena (no cleanup needed if
/// the arena is freed).
pub fn parseLeaky(comptime T: type, allocator: Allocator, json_str: []const u8) !T {
    return std.json.parseFromSliceLeaky(T, allocator, json_str, .{
        .ignore_unknown_fields = true,
    });
}

// ============================================================================
// MCP Response Builders
// ============================================================================

/// Build a successful API response with a single result item.
pub fn successResponse(allocator: Allocator, input: []const u8, result_json: []const u8, time_ms: i64) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{\"success\":true,\"results\":[{\"input\":");
    try writeJsonString(w, input);
    try w.writeAll(",\"success\":true,\"result\":");
    try w.writeAll(result_json);
    try w.writeAll(",\"error\":null,\"metadata\":{\"execution_time_ms\":");
    try w.print("{d}", .{time_ms});
    try w.writeAll("}}],\"summary\":{\"total\":1,\"succeeded\":1,\"failed\":0}}");

    return buf.toOwnedSlice();
}

/// Build an error API response.
pub fn errorResponse(allocator: Allocator, input: []const u8, err_msg: []const u8, time_ms: i64) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{\"success\":false,\"results\":[{\"input\":");
    try writeJsonString(w, input);
    try w.writeAll(",\"success\":false,\"result\":null,\"error\":");
    try writeJsonString(w, err_msg);
    try w.writeAll(",\"metadata\":{\"execution_time_ms\":");
    try w.print("{d}", .{time_ms});
    try w.writeAll("}}],\"summary\":{\"total\":1,\"succeeded\":0,\"failed\":1}}");

    return buf.toOwnedSlice();
}

/// Build a batch API response from multiple result items.
pub fn batchResponse(allocator: Allocator, items: []const BatchItem) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    var succeeded: u32 = 0;
    var failed: u32 = 0;

    try w.writeAll("{\"success\":");
    // Determine overall success after counting
    const start_pos = buf.written().len;
    try w.writeAll("     "); // placeholder, will overwrite
    try w.writeAll(",\"results\":[");

    for (items, 0..) |item, i| {
        if (i > 0) try w.writeByte(',');

        try w.writeAll("{\"input\":");
        try writeJsonString(w, item.input);
        try w.print(",\"success\":{s}", .{if (item.success) "true" else "false"});

        if (item.result) |result| {
            try w.writeAll(",\"result\":");
            try w.writeAll(result);
        } else {
            try w.writeAll(",\"result\":null");
        }

        if (item.err) |err| {
            try w.writeAll(",\"error\":");
            try writeJsonString(w, err);
        } else {
            try w.writeAll(",\"error\":null");
        }

        try w.writeAll(",\"metadata\":{\"execution_time_ms\":");
        try w.print("{d}", .{item.time_ms});
        try w.writeAll("}}");

        if (item.success) {
            succeeded += 1;
        } else {
            failed += 1;
        }
    }

    try w.writeAll("],\"summary\":{");
    try w.print("\"total\":{d},\"succeeded\":{d},\"failed\":{d}", .{
        @as(u32, @intCast(items.len)),
        succeeded,
        failed,
    });
    try w.writeAll("}}");

    // Overwrite the success placeholder
    const overall = if (failed == 0) "true " else "false";
    @memcpy(buf.written()[start_pos .. start_pos + 5], overall);

    return buf.toOwnedSlice();
}

pub const BatchItem = struct {
    input: []const u8,
    success: bool,
    result: ?[]const u8 = null,
    err: ?[]const u8 = null,
    time_ms: i64 = 0,
};

// ============================================================================
// JSON-RPC 2.0 types (for MCP transport)
// ============================================================================

pub const JsonRpcRequest = struct {
    jsonrpc: []const u8 = "2.0",
    method: []const u8,
    params: ?std.json.Value = null,
    id: ?std.json.Value = null,
};

pub const JsonRpcError = struct {
    code: i32,
    message: []const u8,
    data: ?std.json.Value = null,
};

/// Build a JSON-RPC 2.0 success response.
pub fn jsonRpcSuccess(allocator: Allocator, id: ?std.json.Value, result_json: []const u8) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{\"jsonrpc\":\"2.0\",\"result\":");
    try w.writeAll(result_json);
    try w.writeAll(",\"id\":");
    if (id) |id_val| {
        try stringifyToOptions(id_val, .{}, w);
    } else {
        try w.writeAll("null");
    }
    try w.writeByte('}');

    return buf.toOwnedSlice();
}

/// Build a JSON-RPC 2.0 error response.
pub fn jsonRpcError(allocator: Allocator, id: ?std.json.Value, code: i32, message: []const u8) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":");
    try w.print("{d}", .{code});
    try w.writeAll(",\"message\":");
    try writeJsonString(w, message);
    try w.writeAll("},\"id\":");
    if (id) |id_val| {
        try stringifyToOptions(id_val, .{}, w);
    } else {
        try w.writeAll("null");
    }
    try w.writeByte('}');

    return buf.toOwnedSlice();
}

// Standard JSON-RPC error codes
pub const PARSE_ERROR = -32700;
pub const INVALID_REQUEST = -32600;
pub const METHOD_NOT_FOUND = -32601;
pub const INVALID_PARAMS = -32602;
pub const INTERNAL_ERROR = -32603;
pub const SESSION_EXPIRED: i32 = -32001;

// ============================================================================
// Helpers
// ============================================================================

/// Write a JSON-escaped string (with quotes) to the writer.
pub fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    // Write \uXXXX escape for control characters
                    const hex = "0123456789abcdef";
                    const escape = [6]u8{ '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0x0f] };
                    try writer.writeAll(&escape);
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

/// Format a u64 address as a hex string like "0x100001234".
pub fn formatAddress(buf: []u8, address: u64) []const u8 {
    const result = std.fmt.bufPrint(buf, "0x{x}", .{address}) catch return "0x?";
    return result;
}

/// Serialize a u64 address to a JSON string value.
pub fn writeAddress(writer: anytype, address: u64) !void {
    try writer.writeAll("\"0x");
    try writer.print("{x}", .{address});
    try writer.writeByte('"');
}

/// Serialize a document's basic info as JSON (for load_binary / list_documents).
pub fn serializeDocumentInfo(allocator: Allocator, doc: types.Document) ![]const u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const w = &buf.writer;

    try w.writeAll("{\"doc_id\":");
    try w.print("{d}", .{doc.id});
    try w.writeAll(",\"path\":");
    try writeJsonString(w, doc.path);
    try w.writeAll(",\"format\":");
    try writeJsonString(w, doc.format.toString());
    try w.writeAll(",\"arch\":");
    try writeJsonString(w, doc.arch.toString());
    try w.writeAll(",\"entry_point\":\"0x");
    try w.print("{x}", .{doc.entry_point});
    try w.writeAll("\",\"stats\":{\"procedure_count\":");
    try w.print("{d}", .{doc.procedures.items.len});
    try w.writeAll(",\"string_count\":");
    try w.print("{d}", .{doc.strings.items.len});
    try w.writeAll(",\"import_count\":");
    try w.print("{d}", .{doc.imports.items.len});
    try w.writeAll(",\"segment_count\":");
    try w.print("{d}", .{doc.segments.len});
    try w.writeAll("}");

    if (doc.note) |n| {
        try w.writeAll(",\"note\":");
        try writeJsonString(w, n);
    }

    // v7.4.3 F4: detect runtime via the RuntimeAdapter registry. Sum sizes of
    // any packed segments the detected runtime claims, exposed as bundle_size
    // for backward compat (field name preserved). Future runtimes
    // may emit additional sibling fields here.
    //
    // v7.14.0 B2: when EXACTLY ONE adapter fires AND it has a non-null
    // next_target_template, surface the resolved string at top level as
    // `runtime_next_target` so the LLM doesn't have to guess what to
    // inspect next.
    var fired_count: u32 = 0;
    var fired_idx: usize = 0;
    for (strings_mod.ADAPTERS, 0..) |adapter, ai| {
        if (adapter.detect(&doc)) {
            fired_count += 1;
            fired_idx = ai;
        }
    }
    if (strings_mod.detectRuntime(&doc)) |rt_name| {
        var bundle_size: u64 = 0;
        for (doc.segments) |seg| {
            if (strings_mod.isPackedSegment(seg.name)) {
                for (seg.sections) |sec| {
                    bundle_size += sec.length;
                }
            }
        }
        try w.writeAll(",\"runtime\":");
        try writeJsonString(w, rt_name);
        if (bundle_size > 0) {
            try w.print(",\"bundle_size\":{d}", .{bundle_size});
        }
        if (fired_count == 1) {
            const fired_adapter = strings_mod.ADAPTERS[fired_idx];
            if (fired_adapter.next_target_template) |tpl| {
                if (strings_mod.resolveNextTarget(allocator, tpl, doc.path)) |resolved| {
                    defer allocator.free(resolved);
                    try w.writeAll(",\"runtime_next_target\":");
                    try writeJsonString(w, resolved);
                }
            }
        }
    }

    try w.writeAll("}");

    return buf.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

test "writeJsonString escapes special chars" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);

    try writeJsonString(&w, "hello\n\"world\"");
    const result = buf[0..w.end];
    try std.testing.expectEqualStrings("\"hello\\n\\\"world\\\"\"", result);
}

test "formatAddress" {
    var buf: [32]u8 = undefined;
    const result = formatAddress(&buf, 0x100001234);
    try std.testing.expectEqualStrings("0x100001234", result);
}

test "formatAddress zero" {
    var buf: [32]u8 = undefined;
    const result = formatAddress(&buf, 0);
    try std.testing.expectEqualStrings("0x0", result);
}

test "stringify basic struct" {
    const allocator = std.testing.allocator;

    const T = struct { x: u32, y: []const u8 };
    const val = T{ .x = 42, .y = "hello" };
    const json_str = try stringify(allocator, val);
    defer allocator.free(json_str);

    try std.testing.expectEqualStrings("{\"x\":42,\"y\":\"hello\"}", json_str);
}

test "parse basic struct" {
    const allocator = std.testing.allocator;

    const T = struct { x: u32, y: []const u8 };
    const parsed = try parse(T, allocator, "{\"x\":42,\"y\":\"hello\"}");
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 42), parsed.value.x);
    try std.testing.expectEqualStrings("hello", parsed.value.y);
}

test "error response" {
    const allocator = std.testing.allocator;
    const json_str = try errorResponse(allocator, "test_input", "something failed", 5);
    defer allocator.free(json_str);

    // Verify it's valid JSON by parsing as dynamic value
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqual(false, obj.get("success").?.bool);
}

test "success response" {
    const allocator = std.testing.allocator;
    const json_str = try successResponse(allocator, "addr", "{\"data\":1}", 10);
    defer allocator.free(json_str);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqual(true, obj.get("success").?.bool);
}

test "jsonRpcSuccess" {
    const allocator = std.testing.allocator;
    const id = std.json.Value{ .integer = 1 };
    const json_str = try jsonRpcSuccess(allocator, id, "{\"tools\":[]}");
    defer allocator.free(json_str);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("2.0", obj.get("jsonrpc").?.string);
}

test "jsonRpcError" {
    const allocator = std.testing.allocator;
    const id = std.json.Value{ .integer = 1 };
    const json_str = try jsonRpcError(allocator, id, METHOD_NOT_FOUND, "Method not found");
    defer allocator.free(json_str);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const err_obj = obj.get("error").?.object;
    try std.testing.expectEqual(@as(i64, -32601), err_obj.get("code").?.integer);
}
