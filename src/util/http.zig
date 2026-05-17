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

pub const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 42070,
    token: ?[]const u8 = null,
    cors_origin: ?[]const u8 = null,
    max_body_bytes: usize = 4 * 1024 * 1024,
};

pub fn serve(
    allocator: Allocator,
    io: std.Io,
    config: Config,
    context: anytype,
    handler_fn: anytype,
) !void {
    var address = try std.Io.net.IpAddress.parse(config.host, config.port);
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
            fn run(conn: std.Io.net.Stream, alloc: Allocator, run_io: std.Io, cfg: Config, ctx: @TypeOf(context)) std.Io.Cancelable!void {
                var mutable_conn = conn;
                defer mutable_conn.close(run_io);
                handleConnection(alloc, run_io, mutable_conn, cfg, ctx, handler_fn) catch |err| {
                    std.log.err("Connection error: {s}", .{@errorName(err)});
                };
            }
        };

        group.concurrent(io, Handler.run, .{ stream, allocator, io, config, context }) catch {
            var mutable_stream = stream;
            defer mutable_stream.close(io);
            handleConnection(allocator, io, mutable_stream, config, context, handler_fn) catch {};
            continue;
        };
    }
}

fn handleConnection(
    allocator: Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    config: Config,
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
            try sendResponse(writer, config, 400, "application/json", null, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"bad request\"},\"id\":null}");
            continue;
        };

        if (!std.mem.eql(u8, req.path, "/mcp")) {
            try sendResponse(writer, config, 404, "application/json", null, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32004,\"message\":\"not found\"},\"id\":null}");
            return;
        }

        if (std.ascii.eqlIgnoreCase(req.method, "POST")) {
            if (!isAuthorized(req, config)) {
                try sendResponse(writer, config, 401, "application/json", null, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"unauthorized\"},\"id\":null}");
                return;
            }
            if (req.content_length > config.max_body_bytes) {
                try sendResponse(writer, config, 413, "application/json", null, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32013,\"message\":\"request body too large\"},\"id\":null}");
                return;
            }
            const body = try allocator.alloc(u8, req.content_length);
            defer allocator.free(body);
            try reader.readSliceAll(body);

            const req_ctx = RequestContext{
                .session_id = req.session_id,
                .method = req.method,
                .path = req.path,
            };
            const response = handler_fn(context, body, req_ctx);
            try sendResponse(writer, config, response.status, response.content_type, response.session_id, response.body);
        } else if (std.ascii.eqlIgnoreCase(req.method, "OPTIONS")) {
            try sendResponse(writer, config, 204, "text/plain", null, "");
        } else if (std.ascii.eqlIgnoreCase(req.method, "GET")) {
            if (!isAuthorized(req, config)) {
                try sendResponse(writer, config, 401, "application/json", null, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"unauthorized\"},\"id\":null}");
                return;
            }
            try handleSseRequest(writer, config, context, req.session_id);
            return;
        } else {
            try sendResponse(writer, config, 405, "application/json", null, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"method not allowed\"},\"id\":null}");
            return;
        }
    }
}

const ParsedRequest = struct {
    method: []const u8,
    path: []const u8,
    content_length: usize,
    session_id: ?[]const u8,
    authorization: ?[]const u8,
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
    var authorization: ?[]const u8 = null;

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
        } else if (std.ascii.eqlIgnoreCase(name, "authorization")) {
            authorization = value;
        }
    }

    return .{
        .method = method,
        .path = path,
        .content_length = content_length,
        .session_id = session_id,
        .authorization = authorization,
    };
}

fn isAuthorized(req: ParsedRequest, config: Config) bool {
    const token = config.token orelse return true;
    const header = req.authorization orelse return false;
    const prefix = "Bearer ";
    if (!std.mem.startsWith(u8, header, prefix)) return false;
    return timingSafeEql(header[prefix.len..], token);
}

fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, 0..) |byte, i| {
        diff |= byte ^ b[i];
    }
    return diff == 0;
}

fn handleSseRequest(
    writer: *std.Io.Writer,
    config: Config,
    context: anytype,
    session_id: ?[]const u8,
) !void {
    try writer.writeAll("HTTP/1.1 200 OK\r\n");
    try writer.writeAll("Content-Type: text/event-stream\r\n");
    try writer.writeAll("Cache-Control: no-cache\r\n");
    try writer.writeAll("Connection: keep-alive\r\n");
    try writeCorsHeaders(writer, config);
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
    config: Config,
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
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        else => "OK",
    };

    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ status_code, reason });
    try writer.writeAll("Content-Type: ");
    try writer.writeAll(content_type);
    try writer.writeAll("\r\n");
    try writeCorsHeaders(writer, config);
    if (session_id) |sid| {
        try writer.writeAll("mcp-session-id: ");
        try writer.writeAll(sid);
        try writer.writeAll("\r\n");
    }
    try writer.print("Content-Length: {d}\r\n\r\n", .{body.len});
    try writer.writeAll(body);
    try writer.flush();
}

fn writeCorsHeaders(writer: *std.Io.Writer, config: Config) !void {
    const origin = config.cors_origin orelse return;
    try writer.writeAll("Access-Control-Allow-Origin: ");
    try writer.writeAll(origin);
    try writer.writeAll("\r\n");
    try writer.writeAll("Access-Control-Allow-Headers: Content-Type, mcp-session-id, Authorization\r\n");
    try writer.writeAll("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
    try writer.writeAll("Access-Control-Expose-Headers: mcp-session-id\r\n");
}

test "HTTP request parsing captures auth and session headers" {
    const header =
        "POST /mcp HTTP/1.1\r\n" ++
        "Host: 127.0.0.1:42070\r\n" ++
        "Content-Length: 2\r\n" ++
        "Authorization: Bearer secret\r\n" ++
        "mcp-session-id: session-test\r\n" ++
        "\r\n";
    const req = try parseRequest(header);
    try std.testing.expect(std.mem.eql(u8, req.method, "POST"));
    try std.testing.expect(std.mem.eql(u8, req.path, "/mcp"));
    try std.testing.expectEqual(@as(usize, 2), req.content_length);
    try std.testing.expect(std.mem.eql(u8, req.authorization.?, "Bearer secret"));
    try std.testing.expect(std.mem.eql(u8, req.session_id.?, "session-test"));
}

test "HTTP token authorization is strict bearer auth" {
    const config: Config = .{ .token = "secret" };
    try std.testing.expect(!isAuthorized(.{ .method = "POST", .path = "/mcp", .content_length = 0, .session_id = null, .authorization = null }, config));
    try std.testing.expect(!isAuthorized(.{ .method = "POST", .path = "/mcp", .content_length = 0, .session_id = null, .authorization = "Bearer wrong" }, config));
    try std.testing.expect(isAuthorized(.{ .method = "POST", .path = "/mcp", .content_length = 0, .session_id = null, .authorization = "Bearer secret" }, config));
    try std.testing.expect(isAuthorized(.{ .method = "POST", .path = "/mcp", .content_length = 0, .session_id = null, .authorization = null }, .{}));
}
