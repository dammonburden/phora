// Phora — Minimal HTTP Server for MCP Transport
// Streamable HTTP: POST /mcp for JSON-RPC tool calls.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const HttpResponse = struct {
    status: u16,
    body: []const u8,
    content_type: []const u8,
    session_id: ?[]const u8,
};

pub const RequestContext = struct {
    session_id: ?[]const u8,
    method: []const u8,
    path: []const u8,
};

pub fn serve(
    allocator: Allocator,
    io: std.Io,
    port: u16,
    context: anytype,
    handler_fn: anytype,
) !void {
    var address = try std.Io.net.IpAddress.parse("0.0.0.0", port);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.socket.close(io);
    var group: std.Io.Group = .init;
    defer group.cancel(io);

    while (true) {
        const stream = server.accept(io) catch |err| {
            std.log.err("Accept error: {s}", .{@errorName(err)});
            continue;
        };

        const Handler = struct {
            fn run(conn: std.Io.net.Stream, alloc: Allocator, run_io: std.Io, ctx: @TypeOf(context)) std.Io.Cancelable!void {
                var mutable_conn = conn;
                defer mutable_conn.close(run_io);
                handleConnection(alloc, run_io, mutable_conn, ctx, handler_fn) catch |err| {
                    std.log.err("Connection error: {s}", .{@errorName(err)});
                };
            }
        };

        group.concurrent(io, Handler.run, .{ stream, allocator, io, context }) catch {
            var mutable_stream = stream;
            defer mutable_stream.close(io);
            handleConnection(allocator, io, mutable_stream, context, handler_fn) catch {};
            continue;
        };
    }
}

fn handleConnection(
    allocator: Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    context: anytype,
    handler_fn: anytype,
) !void {
    var read_buf: [8192]u8 = undefined;
    var reader_state = stream.reader(io, &read_buf);
    const reader = &reader_state.interface;

    var write_buf: [8192]u8 = undefined;
    var writer_state = stream.writer(io, &write_buf);
    const writer = &writer_state.interface;

    while (true) {
        const header = readHeader(allocator, reader) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        defer allocator.free(header);

        const req = parseRequest(header) catch {
            try sendResponse(writer, 400, "application/json", null, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"bad request\"},\"id\":null}");
            continue;
        };

        if (std.ascii.eqlIgnoreCase(req.method, "POST")) {
            const body = try allocator.alloc(u8, req.content_length);
            defer allocator.free(body);
            try reader.readSliceAll(body);

            const req_ctx = RequestContext{
                .session_id = req.session_id,
                .method = req.method,
                .path = req.path,
            };
            const response = handler_fn(context, body, req_ctx);
            try sendResponse(writer, response.status, response.content_type, response.session_id, response.body);
        } else if (std.ascii.eqlIgnoreCase(req.method, "OPTIONS")) {
            try sendResponse(writer, 204, "text/plain", null, "");
        } else if (std.ascii.eqlIgnoreCase(req.method, "GET")) {
            try handleSseRequest(writer, context, req.session_id);
            return;
        } else {
            try sendResponse(writer, 405, "application/json", null, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"method not allowed\"},\"id\":null}");
        }
    }
}

const ParsedRequest = struct {
    method: []const u8,
    path: []const u8,
    content_length: usize,
    session_id: ?[]const u8,
};

fn readHeader(allocator: Allocator, reader: *std.Io.Reader) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    while (true) {
        const b = try reader.takeByte();
        try out.writer.writeByte(b);
        const written = out.written();
        if (written.len > 64 * 1024) return error.StreamTooLong;
        if (std.mem.endsWith(u8, written, "\r\n\r\n")) return out.toOwnedSlice();
    }
}

fn parseRequest(header: []const u8) !ParsedRequest {
    const first_line_end = std.mem.indexOf(u8, header, "\r\n") orelse return error.BadRequest;
    const first_line = header[0..first_line_end];
    var first_it = std.mem.splitScalar(u8, first_line, ' ');
    const method = first_it.next() orelse return error.BadRequest;
    const path = first_it.next() orelse return error.BadRequest;

    var content_length: usize = 0;
    var session_id: ?[]const u8 = null;

    var lines = std.mem.splitSequence(u8, header[first_line_end + 2 ..], "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.BadRequest;
        } else if (std.ascii.eqlIgnoreCase(name, "mcp-session-id")) {
            session_id = value;
        }
    }

    return .{
        .method = method,
        .path = path,
        .content_length = content_length,
        .session_id = session_id,
    };
}

fn handleSseRequest(
    writer: *std.Io.Writer,
    context: anytype,
    session_id: ?[]const u8,
) !void {
    try writer.writeAll("HTTP/1.1 200 OK\r\n");
    try writer.writeAll("Content-Type: text/event-stream\r\n");
    try writer.writeAll("Cache-Control: no-cache\r\n");
    try writer.writeAll("Connection: keep-alive\r\n");
    try writer.writeAll("Access-Control-Allow-Origin: *\r\n");
    try writer.writeAll("Access-Control-Allow-Headers: Content-Type, mcp-session-id, Authorization\r\n");
    try writer.writeAll("Access-Control-Expose-Headers: mcp-session-id\r\n");
    if (session_id) |sid| {
        try writer.writeAll("mcp-session-id: ");
        try writer.writeAll(sid);
        try writer.writeAll("\r\n");
    }
    try writer.writeAll("\r\n: keepalive\n\n");

    const ContextType = @TypeOf(context);
    const ChildType = @typeInfo(ContextType).pointer.child;
    if (@hasDecl(ChildType, "drainNotifications")) {
        const drain_sid = if (session_id) |sid| sid else "__stdio__";
        const notifications = context.drainNotifications(drain_sid);
        defer {
            for (notifications) |notification| context.allocator.free(notification);
            if (notifications.len > 0) context.allocator.free(notifications);
        }
        for (notifications) |notification| {
            try writer.writeAll("data: ");
            try writer.writeAll(notification);
            try writer.writeAll("\n\n");
        }
    }
    try writer.flush();
}

fn sendResponse(
    writer: *std.Io.Writer,
    status_code: u16,
    content_type: []const u8,
    session_id: ?[]const u8,
    body: []const u8,
) !void {
    const reason = switch (status_code) {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        else => "OK",
    };

    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ status_code, reason });
    try writer.writeAll("Content-Type: ");
    try writer.writeAll(content_type);
    try writer.writeAll("\r\nAccess-Control-Allow-Origin: *\r\n");
    try writer.writeAll("Access-Control-Allow-Headers: Content-Type, mcp-session-id, Authorization\r\n");
    try writer.writeAll("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
    try writer.writeAll("Access-Control-Expose-Headers: mcp-session-id\r\n");
    if (session_id) |sid| {
        try writer.writeAll("mcp-session-id: ");
        try writer.writeAll(sid);
        try writer.writeAll("\r\n");
    }
    try writer.print("Content-Length: {d}\r\n\r\n", .{body.len});
    try writer.writeAll(body);
    try writer.flush();
}
