// Phora — MCP Server (JSON-RPC 2.0 over Streamable HTTP)
// Handles the MCP protocol: initialize handshake, tools/list, tool dispatch, sessions.
// Wires up src/util/http.zig for transport and src/tools.zig for tool dispatch.

const std = @import("std");
const runtime = @import("runtime.zig");
const types = @import("types.zig");
const tools = @import("tools.zig");
const json = @import("util/json.zig");
const http = @import("util/http.zig");

const Allocator = std.mem.Allocator;

// ============================================================================
// MCP Server
// ============================================================================

pub const McpServer = struct {
    allocator: Allocator,
    io: std.Io,
    store: tools.DocumentStore,
    sessions: std.StringHashMap(SessionState),
    http_config: http.Config,
    session_timeout_ms: i64,
    session_mutex: std.Io.Mutex,
    /// v7.15.0 B2: per-session notification queues. Keyed by session id.
    /// Broadcast notifications (e.g. `tools/list_changed`) get fanned out to
    /// every key in this map at queue time. Stdio uses the sentinel
    /// `STDIO_SESSION` key. Each value's strings are owned by `allocator`;
    /// drainNotifications transfers ownership to the caller.
    pending_notifications: std.StringHashMap(std.array_list.Managed([]const u8)),
    notification_mutex: std.Io.Mutex,

    /// v7.15.0 B2: stdio transport has no explicit session header, so all
    /// notifications routed to `null` session id land in this slot.
    pub const STDIO_SESSION: []const u8 = "__stdio__";

    const Self = @This();

    /// MCP standard syslog levels (`logging/setLevel` per RFC 5424). Order
    /// matters — `info` (3) > `debug` (2). Numerically higher = more severe.
    pub const LogLevel = enum(u4) {
        debug = 0,
        info = 1,
        notice = 2,
        warning = 3,
        @"error" = 4,
        critical = 5,
        alert = 6,
        emergency = 7,

        pub fn fromString(s: []const u8) ?LogLevel {
            if (std.mem.eql(u8, s, "debug")) return .debug;
            if (std.mem.eql(u8, s, "info")) return .info;
            if (std.mem.eql(u8, s, "notice")) return .notice;
            if (std.mem.eql(u8, s, "warning")) return .warning;
            if (std.mem.eql(u8, s, "error")) return .@"error";
            if (std.mem.eql(u8, s, "critical")) return .critical;
            if (std.mem.eql(u8, s, "alert")) return .alert;
            if (std.mem.eql(u8, s, "emergency")) return .emergency;
            return null;
        }

        pub fn toString(self: LogLevel) []const u8 {
            return switch (self) {
                .debug => "debug",
                .info => "info",
                .notice => "notice",
                .warning => "warning",
                .@"error" => "error",
                .critical => "critical",
                .alert => "alert",
                .emergency => "emergency",
            };
        }
    };

    const SessionState = struct {
        session: types.Session,
        initialized: bool,
        /// v7.11: per-session minimum log level (suppresses lower-severity events).
        /// Default `info` matches MCP convention. `logging/setLevel` updates this.
        log_level: LogLevel = .info,
    };

    pub fn init(allocator: Allocator, io: std.Io, port: u16) Self {
        return Self.initWithHttpConfig(allocator, io, .{ .port = port });
    }

    pub fn initWithHttpConfig(allocator: Allocator, io: std.Io, config: http.Config) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .store = tools.DocumentStore.init(allocator, io),
            .sessions = std.StringHashMap(SessionState).init(allocator),
            .http_config = config,
            .session_timeout_ms = 30 * 60 * 1000, // 30 minutes
            .session_mutex = .init,
            .pending_notifications = std.StringHashMap(std.array_list.Managed([]const u8)).init(allocator),
            .notification_mutex = .init,
        };
    }

    pub fn deinit(self: *Self) void {
        var qit = self.pending_notifications.iterator();
        while (qit.next()) |entry| {
            for (entry.value_ptr.items) |n| {
                self.allocator.free(n);
            }
            entry.value_ptr.deinit();
        }
        self.pending_notifications.deinit();
        self.store.deinit();
        self.sessions.deinit();
    }

    /// Append a heap-owned `msg` (allocated with `self.allocator`) to the
    /// per-session queue identified by `session_id`. On OOM the message is
    /// freed. Caller must hold `notification_mutex`.
    fn enqueueLocked(self: *Self, session_id: []const u8, msg: []const u8) void {
        const gop = self.pending_notifications.getOrPut(session_id) catch {
            self.allocator.free(msg);
            return;
        };
        if (!gop.found_existing) {
            gop.value_ptr.* = std.array_list.Managed([]const u8).init(self.allocator);
        }
        gop.value_ptr.append(msg) catch {
            self.allocator.free(msg);
        };
    }

    /// Queue a broadcast JSON-RPC notification (e.g. `tools/list_changed`) to
    /// every active session. Thread-safe — can be called from any tool handler.
    /// v7.15.0 B2: previously a single global queue; now fans out per-session
    /// so two HTTP clients don't see each other's events.
    pub fn queueNotification(self: *Self, method: []const u8) void {
        self.queueBroadcastNotification(method);
    }

    /// v7.15.0 B2: explicit broadcast variant. Posts the same JSON message to
    /// every known session's queue (and to the stdio sentinel slot so the
    /// stdio loop sees it too). Each session gets its own heap copy.
    pub fn queueBroadcastNotification(self: *Self, method: []const u8) void {
        // Build one canonical message; copy per-session below so each queue
        // owns its bytes independently.
        const template = std.fmt.allocPrint(self.allocator, "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\"}}", .{method}) catch return;
        defer self.allocator.free(template);

        // Collect destination keys under session_mutex first to avoid holding
        // session_mutex while we manipulate the notification map.
        var dests = std.array_list.Managed([]const u8).init(self.allocator);
        defer dests.deinit();
        {
            self.session_mutex.lockUncancelable(self.io);
            defer self.session_mutex.unlock(self.io);
            var sit = self.sessions.iterator();
            while (sit.next()) |se| {
                dests.append(se.key_ptr.*) catch {};
            }
        }
        // Always include the stdio sentinel so stdio drains see broadcasts even
        // when no HTTP session has been initialized.
        dests.append(STDIO_SESSION) catch {};

        self.notification_mutex.lockUncancelable(self.io);
        defer self.notification_mutex.unlock(self.io);
        for (dests.items) |sid| {
            const copy = self.allocator.dupe(u8, template) catch continue;
            self.enqueueLocked(sid, copy);
        }
    }

    /// v7.11 W5: queue an MCP `notifications/progress` notification.
    /// `token_raw_json` MUST be the progressToken value as raw JSON — i.e.
    /// `"\"abc\""` for a string token or `"42"` for an integer token. Per MCP
    /// spec, the notification's progressToken MUST match the type the client
    /// originally sent, or some clients may treat it as unknown and drop
    /// the connection. The handler's
    /// `_meta.progressToken` extraction is responsible for producing the right
    /// raw-JSON form. `message` may be empty; if non-empty it's JSON-escaped.
    pub fn queueProgressNotification(self: *Self, session_id: []const u8, token_raw_json: []const u8, progress: u32, total: u32, message: []const u8) void {
        var buf = std.Io.Writer.Allocating.init(self.allocator);
        defer buf.deinit();
        const w = &buf.writer;
        w.writeAll("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":") catch return;
        w.writeAll(token_raw_json) catch return;
        w.print(",\"progress\":{d},\"total\":{d}", .{ progress, total }) catch return;
        if (message.len > 0) {
            w.writeAll(",\"message\":") catch return;
            json.writeJsonString(w, message) catch return;
        }
        w.writeAll("}}") catch return;
        const msg = buf.toOwnedSlice() catch return;
        self.notification_mutex.lockUncancelable(self.io);
        defer self.notification_mutex.unlock(self.io);
        self.enqueueLocked(session_id, msg);
    }

    /// v7.11 W6: queue an MCP `notifications/message` notification, gated on
    /// the session's current `log_level`. Events below the threshold are dropped.
    /// `data_text` is the human-readable payload; `data_context_json` (optional,
    /// pass "" to skip) is a raw JSON object string spliced under data.context.
    pub fn queueLogNotification(
        self: *Self,
        session_id: []const u8,
        level: LogLevel,
        logger: []const u8,
        data_text: []const u8,
        data_context_json: []const u8,
    ) void {
        // Look up session log level (default info if not found).
        const min_level: LogLevel = blk: {
            self.session_mutex.lockUncancelable(self.io);
            defer self.session_mutex.unlock(self.io);
            if (self.sessions.get(session_id)) |state| break :blk state.log_level;
            break :blk .info;
        };
        if (@intFromEnum(level) < @intFromEnum(min_level)) return;

        var buf = std.Io.Writer.Allocating.init(self.allocator);
        defer buf.deinit();
        const w = &buf.writer;
        w.writeAll("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"") catch return;
        w.writeAll(level.toString()) catch return;
        w.writeAll("\",\"logger\":") catch return;
        json.writeJsonString(w, logger) catch return;
        w.writeAll(",\"data\":{\"text\":") catch return;
        json.writeJsonString(w, data_text) catch return;
        if (data_context_json.len > 0) {
            w.writeAll(",\"context\":") catch return;
            w.writeAll(data_context_json) catch return;
        }
        w.writeAll("}}}") catch return;
        const msg = buf.toOwnedSlice() catch return;
        self.notification_mutex.lockUncancelable(self.io);
        defer self.notification_mutex.unlock(self.io);
        self.enqueueLocked(session_id, msg);
    }

    /// Drain pending notifications for a specific session. Caller owns the
    /// returned slice and each string in it. v7.15.0 B2: per-session — was
    /// previously a single global queue that leaked events between sessions.
    /// Pass `STDIO_SESSION` for stdio drains.
    pub fn drainNotifications(self: *Self, session_id: []const u8) [][]const u8 {
        self.notification_mutex.lockUncancelable(self.io);
        defer self.notification_mutex.unlock(self.io);
        const list = self.pending_notifications.getPtr(session_id) orelse return &[_][]const u8{};
        return list.toOwnedSlice() catch &[_][]const u8{};
    }

    /// Start the MCP server. Blocks until shutdown.
    pub fn start(self: *Self, io: std.Io) !void {
        try http.serve(self.allocator, io, self.http_config, self, handleHttpRequest);
    }

    /// Public entry point for processing a JSON-RPC request (used by stdio transport).
    /// Pass null session_id on first call; the server creates one automatically.
    /// Extract session_id from the response and pass it on subsequent calls.
    pub fn processRequest(self: *Self, request_body: []const u8, session_id: ?[]const u8) http.HttpResponse {
        const context = http.RequestContext{ .session_id = session_id, .method = "POST", .path = "/" };
        return self.handleHttpRequest(request_body, context);
    }

    /// HTTP request handler — called by http.zig for each POST /mcp.
    /// v7.15.0 B1 pass 2 NOTE (DEFERRED again to v7.15.2): originally tried to
    /// wrap this in `var arena = ArenaAllocator.init(self.allocator); defer arena.deinit();`
    /// and dupe the response body onto `self.allocator` so the per-request arena
    /// could be reclaimed before this returns. Concurrent stress tests crashed
    /// the worker thread under that wrapping (HTTP timeouts then SIGSEGV).
    ///
    /// v7.15.1 A2 audit (in scope of the call_index hotfix) walked every
    /// `rw_lock.lock()` and `rw_lock.lockShared()` site in tools.zig — all
    /// 49 sites pair with a `defer ...unlock()` (or scoped manual unlock for
    /// short, return-free blocks). No unbalanced exclusive lock found, so the
    /// concurrent-stress hang's root cause is NOT a tool-handler lock leak.
    /// Per the v7.15.1 plan, A4 (arena.deinit reintroduction) is gated on a
    /// confirmed A2 fix; with A2 deferred, A4 also defers to v7.15.2.
    ///
    /// Pass-1 doc/db ownership shift to store.allocator (shipped in v7.15.0)
    /// remains in force — close_document actually frees the document. v7.15.1
    /// A1 plus this audit clear the SIGABRT regression that v7.15.0 surfaced.
    /// Per-request arenas still leak until the concurrent-stress hang is
    /// diagnosed in v7.15.2.
    fn handleHttpRequest(self: *Self, request_body: []const u8, context: http.RequestContext) http.HttpResponse {
        // Allocate a per-request arena for response building.
        // The response body is allocated in this arena and must outlive this function
        // because the HTTP layer sends it after handleHttpRequest returns.
        // Pre-v7.15.0 behavior — arena leaks per request, reclaimed at process exit.
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        const alloc = arena.allocator();
        // NOTE: arena deinit deferred to v7.15.2 (see comment block above).

        // Forward to the original implementation (now factored into a sub-function
        // so v7.15.2 can reintroduce the dupe/deinit wrapper without further edits).
        return self.handleHttpRequestInArena(alloc, request_body, context);
    }

    /// v7.15.0 B1 pass 2 scaffold (still deferred): original request handler
    /// scoped to a single arena allocator. v7.15.2 will reintroduce the
    /// arena.deinit() wrapper once the concurrent-stress crash is diagnosed.
    fn handleHttpRequestInArena(self: *Self, alloc: Allocator, request_body: []const u8, context: http.RequestContext) http.HttpResponse {

        // Parse JSON-RPC request FIRST to extract method (needed for session auth).
        const parsed = std.json.parseFromSlice(json.JsonRpcRequest, alloc, request_body, .{
            .ignore_unknown_fields = true,
        }) catch {
            const body = json.jsonRpcError(alloc, null, json.PARSE_ERROR, "Parse error") catch
                return self.httpError(alloc, "parse error");
            return .{
                .status = 200,
                .body = body,
                .content_type = "application/json",
                .session_id = null,
            };
        };

        const req = parsed.value;
        const rpc_id = req.id;

        // Get or create session (method-aware: only initialize can create without header).
        const session_id = self.resolveSession(context, req.method) catch |err| {
            if (err == error.SessionExpired) {
                return .{
                    .status = 404,
                    .body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"session expired\"},\"id\":null}",
                    .content_type = "application/json",
                    .session_id = null,
                };
            }
            // SessionRequired: no session header on non-initialize method
            return .{
                .status = 200,
                .body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"session required. Call initialize first to get a session ID.\"},\"id\":null}",
                .content_type = "application/json",
                .session_id = null,
            };
        };
        self.touchSession(session_id);
        self.expireSessions();

        // Route the method.
        if (std.mem.eql(u8, req.method, "initialize")) {
            return self.handleInitialize(alloc, rpc_id, session_id);
        }
        if (std.mem.eql(u8, req.method, "notifications/initialized")) {
            return self.handleInitialized(alloc, rpc_id, session_id);
        }
        if (std.mem.eql(u8, req.method, "tools/list")) {
            return self.handleToolsList(alloc, rpc_id);
        }
        if (std.mem.eql(u8, req.method, "tools/call")) {
            return self.handleToolCall(alloc, rpc_id, req.params orelse .null, session_id);
        }

        // MCP health check.
        if (std.mem.eql(u8, req.method, "ping")) {
            const body = json.jsonRpcSuccess(alloc, rpc_id, "{}") catch
                return self.httpError(alloc, "internal error");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        }

        // Accept all notifications gracefully (cancelled, progress, roots/list_changed, etc.)
        if (std.mem.startsWith(u8, req.method, "notifications/")) {
            return .{ .status = 202, .body = "", .content_type = "application/json", .session_id = session_id };
        }

        // MCP resource/prompt/completion protocol — return empty but valid responses
        if (std.mem.eql(u8, req.method, "roots/list")) {
            return self.handleRootsList(alloc, rpc_id);
        }
        if (std.mem.eql(u8, req.method, "prompts/list")) {
            return self.handlePromptsList(alloc, rpc_id, session_id);
        }
        if (std.mem.eql(u8, req.method, "prompts/get")) {
            return self.handlePromptsGet(alloc, rpc_id, req.params orelse .null, session_id);
        }
        if (std.mem.eql(u8, req.method, "resources/list")) {
            return self.handleResourcesList(alloc, rpc_id, session_id);
        }
        if (std.mem.eql(u8, req.method, "resources/read")) {
            return self.handleResourcesRead(alloc, rpc_id, req.params orelse .null, session_id);
        }
        if (std.mem.eql(u8, req.method, "resources/templates/list")) {
            const body = json.jsonRpcSuccess(alloc, rpc_id, "{\"resourceTemplates\":[]}") catch
                return self.httpError(alloc, "internal error");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        }
        if (std.mem.eql(u8, req.method, "logging/setLevel")) {
            // v7.11 W6: persist the requested level on the session so subsequent
            // emitLog calls can suppress events below the threshold. Quiet on
            // unknown levels (the spec says "should be one of" — be lenient).
            if (req.params) |p| {
                if (p == .object) {
                    if (p.object.get("level")) |lv| {
                        if (lv == .string) {
                            if (LogLevel.fromString(lv.string)) |new_level| {
                                self.session_mutex.lockUncancelable(self.io);
                                if (self.sessions.getPtr(session_id)) |state| {
                                    state.log_level = new_level;
                                }
                                self.session_mutex.unlock(self.io);
                            }
                        }
                    }
                }
            }
            const body = json.jsonRpcSuccess(alloc, rpc_id, "{}") catch
                return self.httpError(alloc, "internal error");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        }
        if (std.mem.eql(u8, req.method, "completion/complete")) {
            const body = json.jsonRpcSuccess(alloc, rpc_id, "{\"completion\":{\"values\":[]}}") catch
                return self.httpError(alloc, "internal error");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        }

        // Unknown method: log it for protocol diagnostics.
        std.log.warn("Unknown MCP method: {s}", .{req.method});
        const body = json.jsonRpcError(alloc, rpc_id, json.METHOD_NOT_FOUND, "Method not found") catch
            return self.httpError(alloc, "method not found");
        return .{
            .status = 200,
            .body = body,
            .content_type = "application/json",
            .session_id = session_id,
        };
    }

    // ========================================================================
    // MCP Protocol Handlers
    // ========================================================================

    fn handleInitialize(self: *Self, alloc: Allocator, rpc_id: ?std.json.Value, session_id: []const u8) http.HttpResponse {
        self.session_mutex.lockUncancelable(self.io);
        if (self.sessions.getPtr(session_id)) |state| {
            state.initialized = false;
        }
        self.session_mutex.unlock(self.io);

        const result =
            \\{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true},"logging":{},"prompts":{},"resources":{}},"serverInfo":{"name":"phora","version":"7.15.3"},"instructions":"Phora compiles binaries (Mach-O / ELF / PE / PBP / PSX-EXE / APK, ARM64 / ARM32 / MIPS32 / x86_64 / x86, <=500 MiB) into LLM-native context. Workflow: (1) `load_binary path=...` (raw needs `options.arch`; optional `options.base`/`options.entry`; system-cache images can be inspected via `path=dyld_shared_cache:<image>`). (2) `get_binary_context` — adaptive planner; call FIRST after load_binary. Auto-dispatches: tiny binaries get full enumeration, medium binaries delegate to get_remake_frontier, huge/opaque binaries return a manifest. (3) `decompile address=0x...` for a coherent C-like translation unit (pass `scope=cluster` for related funcs); or `get_semantic_slice view=pack scope=cluster` for multi-function context. (4) `annotate` to name funcs you understand — annotations propagate. (5) `save_project` to persist; `load_project` to resume. Available prompts: `start-here`, `remake-spec`, `find-crypto`, `find-strings`, `compare-binaries`, `understand-function`, `understand-subsystem`, `iterative-rename`, `analyze-binary`. Call prompts with `prompts/get name=<name>`. Loaded docs are also exposed as MCP resources (`@phora:phora://doc/{id}`). Targeted analysis: `search type=string_refs|writers_of|capabilities`, `get_hardening_report`, `get_embedded_resources`, `compare include_similar=true`, and `suggest_names addresses=...`. Omit `doc_id` when one doc is loaded."}
        ;

        const body = json.jsonRpcSuccess(alloc, rpc_id, result) catch
            return self.httpError(alloc, "internal error");
        return .{
            .status = 200,
            .body = body,
            .content_type = "application/json",
            .session_id = session_id,
        };
    }

    fn handleInitialized(self: *Self, _: Allocator, _: ?std.json.Value, session_id: []const u8) http.HttpResponse {
        self.session_mutex.lockUncancelable(self.io);
        if (self.sessions.getPtr(session_id)) |state| {
            state.initialized = true;
        }
        self.session_mutex.unlock(self.io);

        // Notifications return 202 with empty body per MCP spec
        return .{
            .status = 202,
            .body = "",
            .content_type = "application/json",
            .session_id = session_id,
        };
    }

    fn handleRootsList(self: *Self, alloc: Allocator, rpc_id: ?std.json.Value) http.HttpResponse {
        var buf = std.Io.Writer.Allocating.init(alloc);
        const w = &buf.writer;
        w.writeAll("{\"roots\":[") catch {};

        self.store.mutex.lockUncancelable(self.io);
        var it = self.store.documents.valueIterator();
        var first = true;
        while (it.next()) |entry| {
            if (!first) w.writeByte(',') catch {};
            first = false;
            w.writeAll("{\"uri\":") catch {};
            // Build file:// URI
            var uri_buf = std.Io.Writer.Allocating.init(alloc);
            uri_buf.writer.writeAll("file://") catch {};
            uri_buf.writer.writeAll(entry.*.doc.path) catch {};
            json.writeJsonString(w, uri_buf.written()) catch {};
            w.writeAll(",\"name\":") catch {};
            const basename = std.fs.path.basename(entry.*.doc.path);
            json.writeJsonString(w, basename) catch {};
            w.writeByte('}') catch {};
        }
        self.store.mutex.unlock(self.io);

        w.writeAll("]}") catch {};
        const result = buf.toOwnedSlice() catch return self.httpError(alloc, "OOM");
        const body = json.jsonRpcSuccess(alloc, rpc_id, result) catch return self.httpError(alloc, "OOM");
        return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = null };
    }

    fn handleResourcesList(self: *Self, alloc: Allocator, rpc_id: ?std.json.Value, session_id: []const u8) http.HttpResponse {
        var buf = std.Io.Writer.Allocating.init(alloc);
        const w = &buf.writer;
        w.writeAll("{\"resources\":[") catch {};

        self.store.mutex.lockUncancelable(self.io);
        var it = self.store.documents.iterator();
        var first = true;
        while (it.next()) |kv| {
            const entry = kv.value_ptr.*;
            if (!first) w.writeByte(',') catch {};
            first = false;
            // URI
            w.writeAll("{\"uri\":") catch {};
            var uri_buf = std.Io.Writer.Allocating.init(alloc);
            uri_buf.writer.print("phora://doc/{d}", .{entry.doc.id}) catch {};
            json.writeJsonString(w, uri_buf.written()) catch {};
            // name
            w.writeAll(",\"name\":") catch {};
            const basename = std.fs.path.basename(entry.doc.path);
            json.writeJsonString(w, basename) catch {};
            // mimeType
            w.writeAll(",\"mimeType\":\"application/json\"") catch {};
            // description
            w.writeAll(",\"description\":") catch {};
            var desc_buf = std.Io.Writer.Allocating.init(alloc);
            const dw = &desc_buf.writer;
            dw.writeAll(entry.doc.format.toString()) catch {};
            dw.writeByte(' ') catch {};
            dw.writeAll(entry.doc.arch.toString()) catch {};
            dw.print(" — {d} procedures, {d} strings", .{ entry.doc.procedures.items.len, entry.doc.strings.items.len }) catch {};
            json.writeJsonString(w, desc_buf.written()) catch {};
            w.writeByte('}') catch {};
        }
        self.store.mutex.unlock(self.io);

        w.writeAll("]}") catch {};
        const result_json = buf.toOwnedSlice() catch return self.httpError(alloc, "OOM");
        const body = json.jsonRpcSuccess(alloc, rpc_id, result_json) catch return self.httpError(alloc, "OOM");
        return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
    }

    fn handleResourcesRead(self: *Self, alloc: Allocator, rpc_id: ?std.json.Value, params: std.json.Value, session_id: []const u8) http.HttpResponse {
        // Extract URI from params
        const uri = blk: {
            if (params != .object) break :blk null;
            const val = params.object.get("uri") orelse break :blk null;
            if (val != .string) break :blk null;
            break :blk val.string;
        } orelse {
            const body = json.jsonRpcError(alloc, rpc_id, json.INVALID_PARAMS, "missing uri parameter") catch
                return self.httpError(alloc, "missing uri");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        };

        // Parse doc_id from "phora://doc/{id}"
        const prefix = "phora://doc/";
        if (!std.mem.startsWith(u8, uri, prefix)) {
            const body = json.jsonRpcError(alloc, rpc_id, json.INVALID_PARAMS, "invalid resource URI") catch
                return self.httpError(alloc, "invalid URI");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        }
        const id_str = uri[prefix.len..];
        const doc_id = std.fmt.parseInt(u64, id_str, 10) catch {
            const body = json.jsonRpcError(alloc, rpc_id, json.INVALID_PARAMS, "invalid doc_id in URI") catch
                return self.httpError(alloc, "invalid doc_id");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        };

        // Look up document
        const entry = self.store.get(doc_id) orelse {
            const body = json.jsonRpcError(alloc, rpc_id, json.INVALID_PARAMS, "document not found") catch
                return self.httpError(alloc, "doc not found");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        };

        // Build the text content JSON: metadata + stats
        var text_buf = std.Io.Writer.Allocating.init(alloc);
        const tw = &text_buf.writer;
        tw.writeAll("{") catch {};
        tw.print("\"doc_id\":{d}", .{entry.doc.id}) catch {};
        tw.writeAll(",\"path\":") catch {};
        json.writeJsonString(tw, entry.doc.path) catch {};
        tw.writeAll(",\"format\":") catch {};
        json.writeJsonString(tw, entry.doc.format.toString()) catch {};
        tw.writeAll(",\"arch\":") catch {};
        json.writeJsonString(tw, entry.doc.arch.toString()) catch {};
        var addr_buf: [20]u8 = undefined;
        const addr_str = json.formatAddress(&addr_buf, entry.doc.entry_point);
        tw.writeAll(",\"entry_point\":") catch {};
        json.writeJsonString(tw, addr_str) catch {};
        tw.print(",\"segment_count\":{d}", .{entry.doc.segments.len}) catch {};
        tw.writeAll(",\"segments\":[") catch {};
        for (entry.doc.segments, 0..) |seg, i| {
            if (i > 0) tw.writeByte(',') catch {};
            tw.writeAll("{\"name\":") catch {};
            json.writeJsonString(tw, seg.name) catch {};
            var seg_buf: [20]u8 = undefined;
            const seg_str = json.formatAddress(&seg_buf, seg.start);
            tw.writeAll(",\"start\":") catch {};
            json.writeJsonString(tw, seg_str) catch {};
            tw.print(",\"length\":{d},\"sections\":{d}", .{ seg.length, seg.sections.len }) catch {};
            tw.writeByte('}') catch {};
        }
        tw.writeAll("]") catch {};
        tw.print(",\"procedure_count\":{d}", .{entry.doc.procedures.items.len}) catch {};
        tw.print(",\"string_count\":{d}", .{entry.doc.strings.items.len}) catch {};
        tw.print(",\"import_count\":{d}", .{entry.doc.imports.items.len}) catch {};
        tw.print(",\"data_size\":{d}", .{entry.doc.data.len}) catch {};
        tw.writeAll("}") catch {};

        const text_content = text_buf.toOwnedSlice() catch return self.httpError(alloc, "OOM");

        // Build MCP contents response
        var rbuf = std.Io.Writer.Allocating.init(alloc);
        const rw = &rbuf.writer;
        rw.writeAll("{\"contents\":[{\"uri\":") catch {};
        json.writeJsonString(rw, uri) catch {};
        rw.writeAll(",\"mimeType\":\"application/json\",\"text\":") catch {};
        json.writeJsonString(rw, text_content) catch {};
        rw.writeAll("}]}") catch {};

        const result_json = rbuf.toOwnedSlice() catch return self.httpError(alloc, "OOM");
        const body = json.jsonRpcSuccess(alloc, rpc_id, result_json) catch return self.httpError(alloc, "OOM");
        return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
    }

    fn handleToolsList(self: *Self, alloc: Allocator, rpc_id: ?std.json.Value) http.HttpResponse {
        // Build the tools array JSON.
        var buf = std.Io.Writer.Allocating.init(alloc);
        const w = &buf.writer;

        w.writeAll("{\"tools\":[") catch {};
        for (tools.tool_definitions, 0..) |def, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll("{\"name\":") catch {};
            json.writeJsonString(w, def.name) catch {};
            w.writeAll(",\"description\":") catch {};
            json.writeJsonString(w, def.description) catch {};
            w.writeAll(",\"inputSchema\":") catch {};
            w.writeAll(def.input_schema) catch {};
            if (def.annotations.len > 0) {
                w.writeAll(",\"annotations\":") catch {};
                w.writeAll(def.annotations) catch {};
            }
            w.writeByte('}') catch {};
        }
        w.writeAll("]}") catch {};

        const result = buf.toOwnedSlice() catch
            return self.httpError(alloc, "OOM");
        const body = json.jsonRpcSuccess(alloc, rpc_id, result) catch
            return self.httpError(alloc, "OOM");
        return .{
            .status = 200,
            .body = body,
            .content_type = "application/json",
            .session_id = null,
        };
    }

    fn handleToolCall(self: *Self, alloc: Allocator, rpc_id: ?std.json.Value, params: std.json.Value, session_id: []const u8) http.HttpResponse {
        // Extract tool name and arguments from params.
        const tool_name = blk: {
            if (params != .object) break :blk null;
            const val = params.object.get("name") orelse break :blk null;
            if (val != .string) break :blk null;
            break :blk val.string;
        } orelse {
            const body = json.jsonRpcError(alloc, rpc_id, json.INVALID_PARAMS, "missing tool name") catch
                return self.httpError(alloc, "missing tool name");
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        };

        const arguments: std.json.Value = blk: {
            if (params != .object) break :blk .null;
            break :blk params.object.get("arguments") orelse .null;
        };

        // v7.11.2: progress notifications DISABLED at the source. Even with
        // type-preserved progressToken (integer→raw int, string→quoted), some
        // stdio clients drop the connection on progress notifications they
        // cannot associate with a pending request. The MCP spec says the
        // server MAY emit progress when `_meta.progressToken` is present in
        // params, but client implementations vary.
        // Setting progress_token = null makes ToolContext.emitProgress a no-op.
        // tools/list_changed and notifications/message paths are unaffected.
        // Re-enable in v7.12 once we work around the client bug or it's fixed
        // upstream.
        const progress_token: ?[]const u8 = null;

        const ctx = tools.ToolContext{
            .io = self.io,
            .store = &self.store,
            .session_id = session_id,
            .allocator = alloc,
            .server = self,
            .progress_token = progress_token,
        };

        const result = tools.dispatch(ctx, tool_name, arguments) catch |err| {
            const err_msg = switch (err) {
                error.UnknownTool => "unknown tool",
                error.InvalidParams => "invalid parameters",
                error.DocumentNotFound => "document not found",
                error.OutOfMemory => "out of memory",
                error.WriteFailed => "response serialization failed",
            };
            const body = json.jsonRpcError(alloc, rpc_id, json.INTERNAL_ERROR, err_msg) catch
                return self.httpError(alloc, err_msg);
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        };

        // Wrap tool result in MCP tools/call response format.
        var content_buf = std.Io.Writer.Allocating.init(alloc);
        const cw = &content_buf.writer;
        cw.writeAll("{\"content\":[{\"type\":\"text\",\"text\":") catch {};
        // The tool result is JSON — we need to embed it as a JSON string value.
        json.writeJsonString(cw, result.json_response) catch {};
        cw.writeAll("}]") catch {};
        // v7.11: MCP `structuredContent` — clients consume
        // typed JSON natively, skipping the re-parse of `content[0].text`.
        // Only emit on success when the response begins with `{` (a JSON object).
        // (v7.11.1 note: structuredContent was briefly suspected of causing the
        // session-state-loss bug — the real culprit was progressToken type
        // mismatch in queueProgressNotification. structuredContent is fine.)
        if (!result.is_error and result.json_response.len > 0 and result.json_response[0] == '{') {
            if (std.debug.runtime_safety) {
                // Cheap one-shot validity check; only runs in Debug/ReleaseSafe.
                if (std.json.parseFromSlice(std.json.Value, alloc, result.json_response, .{})) |parsed| {
                    parsed.deinit();
                } else |_| {
                    std.debug.panic("structuredContent splice: invalid JSON from handler '{s}': {s}", .{ tool_name, result.json_response[0..@min(result.json_response.len, 200)] });
                }
            }
            cw.writeAll(",\"structuredContent\":") catch {};
            cw.writeAll(result.json_response) catch {};
        }
        // MCP _meta annotation: tell clients this result can be larger than default.
        if (result.meta_max_chars) |max_chars| {
            cw.print(",\"_meta\":{{\"anthropic/maxResultSizeChars\":{d}}}", .{max_chars}) catch {};
        }
        if (result.is_error) {
            cw.writeAll(",\"isError\":true") catch {};
        }
        cw.writeByte('}') catch {};

        const content = content_buf.toOwnedSlice() catch
            return self.httpError(alloc, "OOM");
        const body = json.jsonRpcSuccess(alloc, rpc_id, content) catch
            return self.httpError(alloc, "OOM");
        return .{
            .status = 200,
            .body = body,
            .content_type = "application/json",
            .session_id = session_id,
        };
    }

    // ========================================================================
    // Prompts Handlers
    // ========================================================================

    fn handlePromptsList(self: *Self, alloc: Allocator, rpc_id: ?std.json.Value, session_id: []const u8) http.HttpResponse {
        _ = self;
        const result =
            \\{"prompts":[
            \\{"name":"start-here","description":"Bootstrap a Phora analysis session: load the binary, run get_remake_frontier to get a ranked plan, then iterate. Best entry point for a fresh user / fresh binary.","arguments":[{"name":"path","description":"Binary file path","required":true},{"name":"goal","description":"Optional goal hint (e.g. 'recreate audio subsystem')","required":false}]},
            \\{"name":"understand-function","description":"Get an LLM-native context pack for a function: pseudocode, strings, imports, call graph, control flow — everything needed to understand what it does. Use get_semantic_slice view=pack.","arguments":[{"name":"doc_id","description":"Document ID","required":true},{"name":"address","description":"Function address (hex like 0x100003a60)","required":true}]},
            \\{"name":"understand-subsystem","description":"Map a subsystem: start from seed functions, expand to callees/callers, get a cluster context pack with all related code, strings, and imports. Use get_semantic_slice view=pack scope=cluster.","arguments":[{"name":"doc_id","description":"Document ID","required":true},{"name":"address","description":"Seed function address","required":true}]},
            \\{"name":"remake-spec","description":"Generate a structured spec for remaking/porting a subsystem. Produces purpose hypothesis, interfaces, resources, and evidence summary. Use get_semantic_slice view=remake scope=cluster.","arguments":[{"name":"doc_id","description":"Document ID","required":true},{"name":"address","description":"Seed function address","required":true}]},
            \\{"name":"iterative-rename","description":"The power workflow: 1) get_semantic_slice view=pack to understand code. 2) annotate set_name on functions you identify. 3) Get another pack — annotations propagate, making everything clearer. Repeat until the subsystem is fully understood.","arguments":[{"name":"doc_id","description":"Document ID","required":true}]},
            \\{"name":"analyze-binary","description":"Full analysis: load binary, find key functions via string_refs search, examine segments and imports. Pairs with `get_remake_frontier` for ranked next-call planning.","arguments":[{"name":"path","description":"Binary file path","required":true}]},
            \\{"name":"find-crypto","description":"Find cryptographic functions and constants in a binary. Pairs with `get_remake_frontier` for ranked next-call planning.","arguments":[{"name":"doc_id","description":"Document ID","required":true}]},
            \\{"name":"compare-binaries","description":"Compare two binaries: imports, strings, and libraries unique to each and shared","arguments":[{"name":"path_a","description":"First binary path","required":true},{"name":"path_b","description":"Second binary path","required":true}]},
            \\{"name":"find-strings","description":"Search for interesting strings: URLs, passwords, API keys, SQL, error messages. Pairs with `get_remake_frontier` for ranked next-call planning.","arguments":[{"name":"doc_id","description":"Document ID","required":true},{"name":"pattern","description":"Pattern (| for OR)","required":false}]}
            \\]}
        ;

        const body = json.jsonRpcSuccess(alloc, rpc_id, result) catch
            return httpErrorStatic();
        return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
    }

    fn handlePromptsGet(self: *Self, alloc: Allocator, rpc_id: ?std.json.Value, params: std.json.Value, session_id: []const u8) http.HttpResponse {
        _ = self;
        // Extract prompt name from params.
        const prompt_name = blk: {
            if (params != .object) break :blk null;
            const val = params.object.get("name") orelse break :blk null;
            if (val != .string) break :blk null;
            break :blk val.string;
        } orelse {
            const body = json.jsonRpcError(alloc, rpc_id, json.INVALID_PARAMS, "missing prompt name") catch
                return httpErrorStatic();
            return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
        };

        // Extract arguments map from params.
        const arguments: ?std.json.ObjectMap = blk: {
            if (params != .object) break :blk null;
            const val = params.object.get("arguments") orelse break :blk null;
            if (val != .object) break :blk null;
            break :blk val.object;
        };

        if (std.mem.eql(u8, prompt_name, "start-here")) {
            const path = getArgString(arguments, "path") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: path", session_id);
            const goal = getArgString(arguments, "goal") orelse "explore this binary";
            return buildPromptMessage(alloc, rpc_id, session_id, &.{ path, goal }, "start-here");
        }
        if (std.mem.eql(u8, prompt_name, "understand-function")) {
            const doc_id = getArgString(arguments, "doc_id") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: doc_id", session_id);
            const address = getArgString(arguments, "address") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: address", session_id);
            return buildPromptMessage(alloc, rpc_id, session_id, &.{ doc_id, address }, "understand-function");
        }
        if (std.mem.eql(u8, prompt_name, "understand-subsystem")) {
            const doc_id = getArgString(arguments, "doc_id") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: doc_id", session_id);
            const address = getArgString(arguments, "address") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: address", session_id);
            return buildPromptMessage(alloc, rpc_id, session_id, &.{ doc_id, address }, "understand-subsystem");
        }
        if (std.mem.eql(u8, prompt_name, "remake-spec")) {
            const doc_id = getArgString(arguments, "doc_id") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: doc_id", session_id);
            const address = getArgString(arguments, "address") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: address", session_id);
            return buildPromptMessage(alloc, rpc_id, session_id, &.{ doc_id, address }, "remake-spec");
        }
        if (std.mem.eql(u8, prompt_name, "iterative-rename")) {
            const doc_id = getArgString(arguments, "doc_id") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: doc_id", session_id);
            return buildPromptMessage(alloc, rpc_id, session_id, &.{doc_id}, "iterative-rename");
        }
        if (std.mem.eql(u8, prompt_name, "analyze-binary")) {
            const path = getArgString(arguments, "path") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: path", session_id);
            return buildPromptMessage(alloc, rpc_id, session_id, &.{path}, "analyze-binary");
        }
        if (std.mem.eql(u8, prompt_name, "find-crypto")) {
            const doc_id = getArgString(arguments, "doc_id") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: doc_id", session_id);
            return buildPromptMessage(alloc, rpc_id, session_id, &.{doc_id}, "find-crypto");
        }
        if (std.mem.eql(u8, prompt_name, "compare-binaries")) {
            const path_a = getArgString(arguments, "path_a") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: path_a", session_id);
            const path_b = getArgString(arguments, "path_b") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: path_b", session_id);
            return buildPromptMessage(alloc, rpc_id, session_id, &.{ path_a, path_b }, "compare-binaries");
        }
        if (std.mem.eql(u8, prompt_name, "find-strings")) {
            const doc_id = getArgString(arguments, "doc_id") orelse
                return promptArgError(alloc, rpc_id, "missing required argument: doc_id", session_id);
            const pattern = getArgString(arguments, "pattern");
            if (pattern) |p| {
                return buildPromptMessage(alloc, rpc_id, session_id, &.{ doc_id, p }, "find-strings-pattern");
            }
            return buildPromptMessage(alloc, rpc_id, session_id, &.{doc_id}, "find-strings");
        }

        // Unknown prompt name.
        const body = json.jsonRpcError(alloc, rpc_id, json.INVALID_PARAMS, "unknown prompt name") catch
            return httpErrorStatic();
        return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
    }

    fn getArgString(arguments: ?std.json.ObjectMap, key: []const u8) ?[]const u8 {
        const args = arguments orelse return null;
        const val = args.get(key) orelse return null;
        if (val != .string) return null;
        return val.string;
    }

    fn promptArgError(alloc: Allocator, rpc_id: ?std.json.Value, msg: []const u8, session_id: []const u8) http.HttpResponse {
        const body = json.jsonRpcError(alloc, rpc_id, json.INVALID_PARAMS, msg) catch
            return httpErrorStatic();
        return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
    }

    fn httpErrorStatic() http.HttpResponse {
        return .{
            .status = 500,
            .body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\"internal error\"},\"id\":null}",
            .content_type = "application/json",
            .session_id = null,
        };
    }

    fn buildPromptMessage(alloc: Allocator, rpc_id: ?std.json.Value, session_id: []const u8, args: []const []const u8, prompt_type: []const u8) http.HttpResponse {
        var buf = std.Io.Writer.Allocating.init(alloc);
        const w = &buf.writer;
        w.writeAll("{\"messages\":[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":") catch {};

        // Build the prompt text, then JSON-encode it.
        var text_buf = std.Io.Writer.Allocating.init(alloc);
        const tw = &text_buf.writer;

        if (std.mem.eql(u8, prompt_type, "start-here")) {
            tw.print("Begin a Phora analysis session for {s}.\n" ++
                "1) load_binary path={s} — wait for completion; note doc_id and procedure_count.\n" ++
                "2) If procedure_count is 0, the arch was wrong. Retry with options.arch={{mips32|x86_64|arm64|arm32|x86}}; PBP/PSX auto-detect.\n" ++
                "3) get_remake_frontier{{goal: \"{s}\"}} — read role_hypothesis, coverage_gaps, parallel_batches.\n" ++
                "4) Execute the first parallel_batch (decompile / get_semantic_slice calls).\n" ++
                "5) annotate any function you confidently identify; re-call get_remake_frontier with the new visited[] list.\n" ++
                "6) Stop when coverage_gaps is empty or you've answered the user's goal. If any step errors, report the error and halt.", .{ args[0], args[0], args[1] }) catch {};
        } else if (std.mem.eql(u8, prompt_type, "analyze-binary")) {
            tw.print("Load and analyze the binary at {s}. Use load_binary to load it, then:\n1. list_documents to confirm it loaded\n2. get_segments to see memory layout\n3. get_imports to check external dependencies\n4. get_strings max_results=20 to see key strings\n5. search type=procedures to count functions\n6. analyze_functions on the entry point with include=[ir,calls,strings]\n\nSummarize what this binary does based on the findings.", .{args[0]}) catch {};
        } else if (std.mem.eql(u8, prompt_type, "find-crypto")) {
            tw.print("Search for cryptographic functions and constants in document {s}. Steps:\n1. search type=procedures query=crypt,aes,sha,md5,rsa,des,hmac,hash,cipher,encrypt,decrypt,sign,verify\n2. get_strings pattern=AES|SHA|MD5|RSA|DES|HMAC|ENCRYPT|DECRYPT\n3. get_imports and look for crypto-related libraries and APIs\n4. For any found crypto functions, use analyze_functions with include=[ir,calls] to understand the implementation\n\nReport all cryptographic algorithms, key sizes, and potential vulnerabilities found.", .{args[0]}) catch {};
        } else if (std.mem.eql(u8, prompt_type, "compare-binaries")) {
            tw.print("Compare these two binaries:\n- Binary A: {s}\n- Binary B: {s}\n\nSteps:\n1. load_binary for each path\n2. get_imports for both and diff the import lists\n3. get_strings max_results=50 for both and compare\n4. get_segments for both and compare memory layouts\n5. search type=procedures for both and compare function counts\n6. get_libraries for both and diff shared library dependencies\n\nSummarize the key differences between the two binaries.", .{ args[0], args[1] }) catch {};
        } else if (std.mem.eql(u8, prompt_type, "trace-function")) {
            tw.print("Deep-dive into the function at address {s} in document {s}. Steps:\n1. analyze_functions address={s} include=[disassembly,ir,calls,strings,xrefs]\n2. Examine the disassembly for the function logic\n3. Review the lifted IR/pseudocode for high-level understanding\n4. Trace the call graph - what does this function call?\n5. Check cross-references - what calls this function?\n6. Look at string references within the function\n\nProvide a detailed explanation of what this function does, its parameters, return value, and role in the binary.", .{ args[1], args[0], args[1] }) catch {};
        } else if (std.mem.eql(u8, prompt_type, "find-strings-pattern")) {
            tw.print("Search for strings matching pattern '{s}' in document {s}. Steps:\n1. get_strings doc_id={s} pattern={s} max_results=50\n2. For each interesting string found, note its address\n3. Use analyze_functions on nearby code to understand context\n\nCategorize findings into: URLs, file paths, API keys/tokens, error messages, configuration values, and other interesting strings.", .{ args[1], args[0], args[0], args[1] }) catch {};
        } else if (std.mem.eql(u8, prompt_type, "find-strings")) {
            tw.print("Search for interesting strings in document {s}. Steps:\n1. get_strings doc_id={s} pattern=http|https|ftp|file://|api|key|token|password|secret max_results=30\n2. get_strings doc_id={s} pattern=error|fail|exception|warning max_results=20\n3. get_strings doc_id={s} pattern=/usr|/etc|/var|/tmp|C:\\\\|.dll|.so|.dylib max_results=20\n4. For each interesting string found, note its address and potential significance\n\nCategorize findings into: URLs, file paths, API keys/tokens, error messages, configuration values, and other interesting strings.", .{ args[0], args[0], args[0], args[0] }) catch {};
        } else if (std.mem.eql(u8, prompt_type, "understand-function")) {
            // v7.14.1 A2: previously advertised in prompts/list but had no
            // body branch — prompts/get returned an empty messages text.
            tw.print("Use `get_semantic_slice doc_id={s} addresses={s} view=pack scope=function` to inspect this single function with its callers, callees, strings, and imports. The pack view returns pseudocode, a string-ref list, an import-call list, and a control-flow summary — everything needed to identify what the function does. If the seed address resolves to a stub, follow `seed_diagnostics[].redirect` to the real entry. Optionally call `decompile address={s}` for a tighter C-like rendering of the same function.", .{ args[0], args[1], args[1] }) catch {};
        } else if (std.mem.eql(u8, prompt_type, "understand-subsystem")) {
            tw.print("Use `get_semantic_slice doc_id={s} addresses={s} view=pack scope=cluster radius=2` to expand from the seed and inspect the whole subsystem (callees plus reverse-callers). Read the resulting `procedures[]`, `cluster_members[]`, shared `imports[]`, and `string_refs[]` to identify which functions form the subsystem, what external APIs they share, and which strings parametrize behavior. If `cluster_members[]` is too narrow, increase `radius` (cap 3) or pass additional seed addresses.", .{ args[0], args[1] }) catch {};
        } else if (std.mem.eql(u8, prompt_type, "remake-spec")) {
            tw.print("Use `get_semantic_slice doc_id={s} addresses={s} view=remake scope=cluster`. Read the resulting `interfaces[]` (callable entry signatures), `resources[]` (data files / strings consumed), `purpose_hypotheses[]` (heuristic role labels with evidence), and `evidence_summary` to draft a remake spec for this subsystem. The remake view is structured for porting — each interface entry includes the original address, inferred parameters, and call-site count so you can produce a minimal cleanroom replacement.", .{ args[0], args[1] }) catch {};
        } else if (std.mem.eql(u8, prompt_type, "iterative-rename")) {
            tw.print("Iterative naming loop for document {s}:\n1) Call `suggest_names doc_id={s} addresses=<target_address>` to get name candidates with `confidence` (high/medium/low) and a one-line `reason`. Pick the best candidate.\n2) Call `annotate doc_id={s} ops=[{{\"op\":\"set_name\",\"address\":<target_address>,\"name\":\"<chosen_name>\"}}]` to commit the name.\n3) Re-call `suggest_names` on this function's callers (use `get_xrefs` to find them) — the new name propagates into their context bundles and improves their candidates.\nRepeat until callers stabilize. Annotations live in the document's overlay; persist via `save_project`.", .{ args[0], args[0], args[0] }) catch {};
        }

        const text = text_buf.toOwnedSlice() catch return httpErrorStatic();
        json.writeJsonString(w, text) catch {};
        w.writeAll("}}]}") catch {};

        const result = buf.toOwnedSlice() catch return httpErrorStatic();
        const body = json.jsonRpcSuccess(alloc, rpc_id, result) catch return httpErrorStatic();
        return .{ .status = 200, .body = body, .content_type = "application/json", .session_id = session_id };
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    fn resolveSession(self: *Self, context: http.RequestContext, method: []const u8) ![]const u8 {
        self.session_mutex.lockUncancelable(self.io);
        defer self.session_mutex.unlock(self.io);
        if (context.session_id) |sid| {
            if (sid.len > 0) {
                if (self.sessions.contains(sid)) {
                    return sid;
                }
                return error.SessionExpired;
            }
        }
        // Only initialize may create a new session without a header
        if (std.mem.eql(u8, method, "initialize")) {
            return try self.createSessionLocked();
        }
        return error.SessionRequired;
    }

    fn createSessionLocked(self: *Self) ![]const u8 {
        var id: []const u8 = undefined;
        var attempts: usize = 0;
        while (true) : (attempts += 1) {
            if (attempts >= 8) unreachable;
            var random_bytes: [16]u8 = undefined;
            self.io.random(&random_bytes);
            const hex = std.fmt.bytesToHex(random_bytes, .lower);
            id = try std.fmt.allocPrint(self.allocator, "session-{s}", .{&hex});
            if (!self.sessions.contains(id)) break;
            self.allocator.free(id);
        }
        const now = runtime.realMillis(self.io);

        try self.sessions.put(id, .{
            .session = .{
                .id = id,
                .doc_id = 0,
                .created_at = now,
                .last_active = now,
            },
            .initialized = false,
        });

        return id;
    }

    fn touchSession(self: *Self, session_id: []const u8) void {
        self.session_mutex.lockUncancelable(self.io);
        defer self.session_mutex.unlock(self.io);
        if (self.sessions.getPtr(session_id)) |state| {
            state.session.last_active = runtime.realMillis(self.io);
        }
    }

    fn expireSessions(self: *Self) void {
        self.session_mutex.lockUncancelable(self.io);
        defer self.session_mutex.unlock(self.io);
        const now = runtime.realMillis(self.io);
        var it = self.sessions.iterator();
        var to_remove = std.array_list.Managed([]const u8).init(self.allocator);
        defer to_remove.deinit();

        while (it.next()) |entry| {
            const idle = now - entry.value_ptr.session.last_active;
            if (idle > self.session_timeout_ms) {
                to_remove.append(entry.key_ptr.*) catch {};
            }
        }

        for (to_remove.items) |key| {
            _ = self.sessions.remove(key);
        }
    }

    fn httpError(_: *Self, _: Allocator, _: []const u8) http.HttpResponse {
        return .{
            .status = 500,
            .body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\"internal error\"},\"id\":null}",
            .content_type = "application/json",
            .session_id = null,
        };
    }
};

// ============================================================================
// Public API
// ============================================================================

/// Start a Phora MCP server on the given port. Blocks until shutdown.
pub fn serve(allocator: Allocator, io: std.Io, port: u16) !void {
    var server = McpServer.init(allocator, io, port);
    defer server.deinit();
    try server.start(io);
}

/// Start a Phora MCP server with explicit HTTP transport settings.
pub fn serveWithHttpConfig(allocator: Allocator, io: std.Io, config: http.Config) !void {
    var server = McpServer.initWithHttpConfig(allocator, io, config);
    defer server.deinit();
    try server.start(io);
}
