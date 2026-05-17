// Phora — AI-Native Binary Analysis Engine
// CLI entry point: serve, analyze, info, version
// Wires together all components: loaders, decoders, analysis, MCP server.

const std = @import("std");
const types = @import("types.zig");
const server = @import("server.zig");
const macho = @import("loaders/macho.zig");
const elf = @import("loaders/elf.zig");
const pe = @import("loaders/pe.zig");
const json = @import("util/json.zig");
const http = @import("util/http.zig");
const pipeline = @import("analysis/pipeline.zig");

const version_string = "7.15.3";

/// Max binary size: 2GB. The real limit is available RAM — Zig's allocator
/// will fail gracefully if the machine can't handle it.
const max_binary_size: usize = 4 * 1024 * 1024 * 1024;

const FileWriter = struct {
    file: std.Io.File,
    io: std.Io,

    pub fn writeAll(self: FileWriter, bytes: []const u8) !void {
        try self.file.writeStreamingAll(self.io, bytes);
    }

    pub fn writeByte(self: FileWriter, byte: u8) !void {
        try self.writeAll(&.{byte});
    }

    pub fn print(self: FileWriter, comptime fmt: []const u8, args: anytype) !void {
        var stack_buf: [4096]u8 = undefined;
        const rendered = std.fmt.bufPrint(&stack_buf, fmt, args) catch {
            const allocated = try std.fmt.allocPrint(std.heap.page_allocator, fmt, args);
            defer std.heap.page_allocator.free(allocated);
            try self.writeAll(allocated);
            return;
        };
        try self.writeAll(rendered);
    }
};

fn stdoutWriter(io: std.Io) FileWriter {
    return .{ .file = .stdout(), .io = io };
}

fn stderrWriter(io: std.Io) FileWriter {
    return .{ .file = .stderr(), .io = io };
}

fn readLineAlloc(allocator: std.mem.Allocator, reader: *std.Io.Reader, max_len: usize) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    _ = try reader.streamDelimiterLimit(&out.writer, '\n', .limited(max_len));
    const next = reader.peekByte() catch |err| switch (err) {
        error.EndOfStream => {
            if (out.written().len == 0) return error.EndOfStream;
            return out.toOwnedSlice();
        },
        else => |e| return e,
    };
    if (next == '\n') _ = try reader.takeByte();
    return out.toOwnedSlice();
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const io = init.io;

    if (args.len < 2) {
        printUsage(io);
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "serve")) {
        try cmdServe(allocator, io, init.environ_map, args[2..]);
    } else if (std.mem.eql(u8, command, "analyze")) {
        try cmdAnalyze(allocator, io, args[2..]);
    } else if (std.mem.eql(u8, command, "info")) {
        try cmdInfo(allocator, io, args[2..]);
    } else if (std.mem.eql(u8, command, "version")) {
        cmdVersion(io);
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage(io);
    } else {
        const stderr = stderrWriter(io);
        try stderr.print("Unknown command: {s}\n\n", .{command});
        printUsage(io);
        std.process.exit(1);
    }
}

// ============================================================================
// Commands
// ============================================================================

fn cmdStdio(allocator: std.mem.Allocator, io: std.Io) !void {
    const stderr = stderrWriter(io);
    try stderr.print("Phora MCP server v{s} (stdio)\n", .{version_string});

    var mcp = server.McpServer.init(allocator, io, 0);
    defer mcp.deinit();

    var stdin_buf: [8192]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, &stdin_buf);
    const stdout = stdoutWriter(io);

    // Session ID — null on first request, server creates one.
    var session_id: ?[]const u8 = null;

    // Read JSON-RPC messages line by line from stdin
    while (true) {
        const line = readLineAlloc(allocator, &stdin_reader.interface, 4 * 1024 * 1024) catch |err| {
            if (err == error.EndOfStream) break;
            try stderr.print("stdin read error: {s}\n", .{@errorName(err)});
            break;
        };
        defer allocator.free(line);

        if (line.len == 0) continue;

        const response = mcp.processRequest(line, session_id);
        // v7.15.0 B1 pass 2 NOTE (DEFERRED to v7.15.1): originally freed
        // response.body via mcp.allocator here. The HTTP transport hit a
        // concurrent-stress crash with the matching change, so the pass-2
        // arena deinit + body free was deferred. Stdio doesn't see the
        // concurrency hazard but we keep the two transports symmetric.

        // Capture session ID from first response
        if (session_id == null and response.session_id != null) {
            session_id = response.session_id;
        }

        // Notifications return 202 with empty body — don't write anything
        if (response.body.len > 0) {
            // stdio transport: newline is the message delimiter, so strip
            // any literal newlines from the JSON response body.
            const out = try allocator.dupe(u8, response.body);
            defer allocator.free(out);
            for (out) |*c| {
                if (c.* == '\n' or c.* == '\r') c.* = ' ';
            }
            try stdout.writeAll(out);
            try stdout.writeByte('\n');
        }

        // Drain any pending notifications (e.g. tools/list_changed after load_binary)
        // and write each as a separate line to stdout.
        // v7.15.0 B2: drain BOTH the active stdio session AND the stdio sentinel
        // slot (broadcasts always land in the sentinel; per-session events land
        // in the real session id once it's known).
        const sentinel_notifs = mcp.drainNotifications("__stdio__");
        defer if (sentinel_notifs.len > 0) allocator.free(sentinel_notifs);
        for (sentinel_notifs) |notification| {
            defer allocator.free(notification);
            try stdout.writeAll(notification);
            try stdout.writeByte('\n');
        }
        if (session_id) |sid| {
            const session_notifs = mcp.drainNotifications(sid);
            defer if (session_notifs.len > 0) allocator.free(session_notifs);
            for (session_notifs) |notification| {
                defer allocator.free(notification);
                try stdout.writeAll(notification);
                try stdout.writeByte('\n');
            }
        }
    }
}

fn cmdServe(allocator: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map, args: []const []const u8) !void {
    var config: http.Config = .{};
    if (env.get("PHORA_HTTP_TOKEN")) |token| {
        if (token.len > 0) config.token = token;
    }
    var transport: enum { stdio, http } = .stdio;
    var stdio_explicit = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--stdio")) {
            stdio_explicit = true;
        } else if (std.mem.eql(u8, args[i], "--http")) {
            transport = .http;
        } else if (std.mem.eql(u8, args[i], "--port") or std.mem.eql(u8, args[i], "-p")) {
            transport = .http;
            i += 1;
            if (i >= args.len) {
                const stderr = stderrWriter(io);
                try stderr.print("Error: --port requires a value\n", .{});
                std.process.exit(1);
            }
            config.port = std.fmt.parseInt(u16, args[i], 10) catch {
                const stderr = stderrWriter(io);
                try stderr.print("Error: invalid port number '{s}'\n", .{args[i]});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, args[i], "--host")) {
            transport = .http;
            i += 1;
            if (i >= args.len) {
                const stderr = stderrWriter(io);
                try stderr.print("Error: --host requires a value\n", .{});
                std.process.exit(1);
            }
            config.host = normalizeHost(args[i]);
        } else if (std.mem.eql(u8, args[i], "--token")) {
            transport = .http;
            i += 1;
            if (i >= args.len) {
                const stderr = stderrWriter(io);
                try stderr.print("Error: --token requires a value\n", .{});
                std.process.exit(1);
            }
            if (args[i].len == 0) {
                const stderr = stderrWriter(io);
                try stderr.print("Error: --token cannot be empty\n", .{});
                std.process.exit(1);
            }
            config.token = args[i];
        } else if (std.mem.eql(u8, args[i], "--cors-origin")) {
            transport = .http;
            i += 1;
            if (i >= args.len) {
                const stderr = stderrWriter(io);
                try stderr.print("Error: --cors-origin requires a value\n", .{});
                std.process.exit(1);
            }
            config.cors_origin = args[i];
        } else {
            const stderr = stderrWriter(io);
            try stderr.print("Unknown serve option: {s}\n\n", .{args[i]});
            printUsage(io);
            std.process.exit(1);
        }
    }

    if (stdio_explicit and transport == .http) {
        const stderr = stderrWriter(io);
        try stderr.print("Error: --stdio cannot be combined with HTTP options\n", .{});
        std.process.exit(1);
    }

    if (transport == .stdio) {
        return cmdStdio(allocator, io);
    }

    if (!isLoopbackHost(config.host) and config.token == null) {
        const stderr = stderrWriter(io);
        try stderr.print("Error: non-loopback HTTP bind requires PHORA_HTTP_TOKEN or --token\n", .{});
        std.process.exit(1);
    }

    // v7.8.1 H2 hotfix: install fatal-signal handlers so a worker crash
    // (SIGSEGV/SIGBUS/SIGFPE) at least logs a diagnostic to stderr instead of
    // dying silently. The default Zig behaviour for these signals in a
    // ReleaseSmall build is an immediate process exit with no message, which
    // is what made the dyld load_binary regression so hard to triage.
    installCrashLogger() catch |err| {
        const stderr = stderrWriter(io);
        stderr.print("warning: could not install crash logger: {s}\n", .{@errorName(err)}) catch {};
    };

    const stdout = stdoutWriter(io);
    try stdout.print("Phora MCP server v{s}\n", .{version_string});
    try stdout.print("Listening on {s}:{d}\n", .{ config.host, config.port });
    try stdout.print("Transport: Streamable HTTP (JSON-RPC 2.0)\n", .{});
    if (config.token != null) {
        try stdout.print("HTTP auth: bearer token required\n", .{});
    }
    if (config.cors_origin) |origin| {
        try stdout.print("CORS origin: {s}\n", .{origin});
    }
    if (!isLoopbackHost(config.host)) {
        const stderr = stderrWriter(io);
        try stderr.print("WARNING: Phora HTTP is exposed on non-loopback host {s}. Keep the bearer token secret and use only on trusted networks.\n", .{config.host});
    }

    try server.serveWithHttpConfig(allocator, io, config);
}

fn normalizeHost(host: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return "127.0.0.1";
    return host;
}

fn isLoopbackHost(host: []const u8) bool {
    if (std.mem.eql(u8, host, "::1")) return true;
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    return std.mem.eql(u8, host, "127.0.0.1") or std.mem.startsWith(u8, host, "127.");
}

// ============================================================================
// Crash diagnostics (server mode only)
// ============================================================================

fn crashSignalHandler(sig: std.posix.SIG, info: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) void {
    _ = info;
    _ = ctx_ptr;
    const stderr_fd = std.posix.STDERR_FILENO;
    const msg = switch (sig) {
        std.posix.SIG.SEGV => "[phora FATAL] worker hit SIGSEGV (segmentation fault) — dying. The request that triggered this likely involves a large/unusual binary; please file a bug with the binary path and last log lines.\n",
        std.posix.SIG.BUS => "[phora FATAL] worker hit SIGBUS — dying. Often caused by mmap'ing a truncated or non-aligned file.\n",
        std.posix.SIG.FPE => "[phora FATAL] worker hit SIGFPE — dying. Integer division by zero or similar arithmetic fault.\n",
        std.posix.SIG.ILL => "[phora FATAL] worker hit SIGILL — dying. Likely a Zig safety check trip in a Release build, or a malformed instruction stream.\n",
        else => "[phora FATAL] worker hit fatal signal — dying.\n",
    };
    _ = std.c.write(stderr_fd, msg.ptr, msg.len);
    // Re-raise with the default handler so the OS produces a normal exit code
    // and (if enabled) a crash report. We've already logged the diagnostic.
    var act: std.posix.Sigaction = .{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(sig, &act, null);
    _ = std.posix.raise(sig) catch {};
}

fn installCrashLogger() !void {
    var act: std.posix.Sigaction = .{
        .handler = .{ .sigaction = crashSignalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.SIGINFO,
    };
    std.posix.sigaction(std.posix.SIG.SEGV, &act, null);
    std.posix.sigaction(std.posix.SIG.BUS, &act, null);
    std.posix.sigaction(std.posix.SIG.FPE, &act, null);
    std.posix.sigaction(std.posix.SIG.ILL, &act, null);
}

fn cmdAnalyze(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    const stdout = stdoutWriter(io);
    const stderr = stderrWriter(io);

    if (args.len < 1) {
        try stderr.print("Error: analyze requires a file path\n", .{});
        try stderr.print("Usage: phora analyze <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];

    // Read the binary file
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| {
        try stderr.print("Error: cannot open '{s}': {s}\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer file.close(io);

    const stat = try file.stat(io);
    var file_reader = file.reader(io, &.{});
    const data = file_reader.interface.allocRemaining(allocator, .limited(max_binary_size)) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        else => |e| return e,
    };
    defer allocator.free(data);

    // Detect format and load via appropriate loader
    const format = detectFormat(data);
    var doc = loadBinary(allocator, path, data, format) catch |err| {
        try stderr.print("Error: failed to parse '{s}': {s}\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer doc.deinit();

    // Run unified analysis pipeline (lean mode — no instruction storage for CLI)
    var result = pipeline.analyzeLean(allocator, io, &doc, data) catch {
        try stderr.print("Error: analysis failed for '{s}'\n", .{path});
        std.process.exit(1);
    };
    defer result.deinit(allocator);

    const proc_count = result.procedureCount();
    const xref_count = result.xrefCount();

    // Output JSON result
    const w = stdout;
    try w.writeAll("{\n");
    try w.writeAll("  \"success\": true,\n");
    try w.writeAll("  \"path\": ");
    try json.writeJsonString(w, path);
    try w.writeAll(",\n");
    try w.writeAll("  \"format\": ");
    try json.writeJsonString(w, doc.format.toString());
    try w.writeAll(",\n");
    try w.writeAll("  \"arch\": ");
    try json.writeJsonString(w, doc.arch.toString());
    try w.writeAll(",\n");
    try w.print("  \"size\": {d},\n", .{stat.size});
    try w.print("  \"entry_point\": \"0x{x}\",\n", .{doc.entry_point});

    // Segments
    try w.writeAll("  \"segments\": [\n");
    for (doc.segments, 0..) |seg, si| {
        if (si > 0) try w.writeAll(",\n");
        try w.writeAll("    {\"name\": ");
        try json.writeJsonString(w, seg.name);
        try w.print(", \"start\": \"0x{x}\", \"length\": {d}, \"sections\": {d}", .{
            seg.start,
            seg.length,
            seg.sections.len,
        });
        try w.writeAll(", \"permissions\": \"");
        if (seg.permissions.read) try w.writeByte('r') else try w.writeByte('-');
        if (seg.permissions.write) try w.writeByte('w') else try w.writeByte('-');
        if (seg.permissions.execute) try w.writeByte('x') else try w.writeByte('-');
        try w.writeAll("\"}");
    }
    try w.writeAll("\n  ],\n");

    // Statistics
    try w.writeAll("  \"stats\": {\n");
    try w.print("    \"segment_count\": {d},\n", .{doc.segments.len});
    try w.print("    \"procedure_count\": {d},\n", .{proc_count});
    try w.print("    \"string_count\": {d},\n", .{result.stringCount()});
    try w.print("    \"import_count\": {d},\n", .{doc.imports.items.len});
    try w.print("    \"xref_count\": {d},\n", .{xref_count});
    try w.print("    \"lift_success\": {s}\n", .{if (result.lift_success) "true" else "false"});
    try w.writeAll("  },\n");
    try w.writeAll("  \"status\": \"analyzed\"\n");
    try w.writeAll("}\n");
}

fn cmdInfo(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    const stdout = stdoutWriter(io);
    const stderr = stderrWriter(io);

    if (args.len < 1) {
        try stderr.print("Error: info requires a file path\n", .{});
        try stderr.print("Usage: phora info <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];

    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| {
        try stderr.print("Error: cannot open '{s}': {s}\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer file.close(io);

    const stat = try file.stat(io);
    var file_reader = file.reader(io, &.{});
    const data = file_reader.interface.allocRemaining(allocator, .limited(max_binary_size)) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        else => |e| return e,
    };
    defer allocator.free(data);

    // Detect format and load via appropriate loader
    const format = detectFormat(data);
    var doc = loadBinary(allocator, path, data, format) catch {
        // Fallback to basic info if loader fails
        try stdout.print("Phora Binary Info\n", .{});
        try stdout.print("====================\n", .{});
        try stdout.print("Path:     {s}\n", .{path});
        try stdout.print("Size:     {d} bytes\n", .{stat.size});
        try stdout.print("Format:   {s}\n", .{format.toString()});
        if (data.len >= 4) {
            try stdout.print("Magic:    0x{x:0>2}{x:0>2}{x:0>2}{x:0>2}\n", .{ data[0], data[1], data[2], data[3] });
        }
        return;
    };
    defer doc.deinit();

    try stdout.print("Phora Binary Info\n", .{});
    try stdout.print("====================\n", .{});
    try stdout.print("Path:       {s}\n", .{path});
    try stdout.print("Size:       {d} bytes\n", .{stat.size});
    try stdout.print("Format:     {s}\n", .{doc.format.toString()});
    try stdout.print("Arch:       {s}\n", .{doc.arch.toString()});
    try stdout.print("Entry:      0x{x}\n", .{doc.entry_point});

    // Print magic bytes
    if (data.len >= 4) {
        try stdout.print("Magic:      0x{x:0>2}{x:0>2}{x:0>2}{x:0>2}\n", .{ data[0], data[1], data[2], data[3] });
    }

    // Segments
    try stdout.print("\nSegments:   {d}\n", .{doc.segments.len});
    for (doc.segments) |seg| {
        try stdout.print("  {s:16} 0x{x:0>12} - 0x{x:0>12}  ", .{
            seg.name,
            seg.start,
            seg.start + seg.length,
        });
        if (seg.permissions.read) try stdout.writeByte('r') else try stdout.writeByte('-');
        if (seg.permissions.write) try stdout.writeByte('w') else try stdout.writeByte('-');
        if (seg.permissions.execute) try stdout.writeByte('x') else try stdout.writeByte('-');
        try stdout.print("  ({d} sections)\n", .{seg.sections.len});

        for (seg.sections) |sec| {
            try stdout.print("    {s:14} 0x{x:0>12}  {d} bytes\n", .{
                sec.name,
                sec.start,
                sec.length,
            });
        }
    }

    // Imports
    if (doc.imports.items.len > 0) {
        try stdout.print("\nImports:    {d}\n", .{doc.imports.items.len});
        const max_display: usize = 20;
        for (doc.imports.items[0..@min(doc.imports.items.len, max_display)]) |imp| {
            try stdout.print("  0x{x:0>12}  {s}", .{ imp.address, imp.name });
            if (imp.library) |lib| {
                try stdout.print("  ({s})", .{lib});
            }
            try stdout.writeByte('\n');
        }
        if (doc.imports.items.len > max_display) {
            try stdout.print("  ... and {d} more\n", .{doc.imports.items.len - max_display});
        }
    }

    // Procedures from loader
    if (doc.procedures.items.len > 0) {
        try stdout.print("\nProcedures: {d}\n", .{doc.procedures.items.len});
        const max_procs: usize = 20;
        for (doc.procedures.items[0..@min(doc.procedures.items.len, max_procs)]) |proc| {
            try stdout.print("  0x{x:0>12}  {d} bytes", .{ proc.entry, proc.size });
            if (proc.name) |name| {
                try stdout.print("  {s}", .{name});
            }
            try stdout.writeByte('\n');
        }
        if (doc.procedures.items.len > max_procs) {
            try stdout.print("  ... and {d} more\n", .{doc.procedures.items.len - max_procs});
        }
    }
}

fn cmdVersion(io: std.Io) void {
    const stdout = stdoutWriter(io);
    stdout.print("phora {s}\n", .{version_string}) catch {};
}

// ============================================================================
// Helpers
// ============================================================================

fn printUsage(io: std.Io) void {
    const stdout = stdoutWriter(io);
    stdout.print(
        \\Phora — AI-Native Binary Analysis Engine
        \\
        \\Usage: phora <command> [options]
        \\
        \\Commands:
        \\  serve                  Start MCP server on stdin/stdout
        \\  serve --stdio          Start MCP server on stdin/stdout
        \\  serve --http [options] Start MCP server over HTTP on 127.0.0.1:42070
        \\  analyze <path>         One-shot analysis, JSON to stdout
        \\  info <path>            Quick binary overview
        \\  version                Print version info
        \\  help                   Show this message
        \\
        \\HTTP options:
        \\  --host HOST            Bind host (non-loopback requires --token or PHORA_HTTP_TOKEN)
        \\  --port PORT            Bind port
        \\  --token TOKEN          Require Authorization: Bearer TOKEN
        \\  --cors-origin ORIGIN   Emit CORS headers for one explicit origin
        \\
    , .{}) catch {};
}

/// Detect binary format from magic bytes.
fn detectFormat(data: []const u8) types.BinaryFormat {
    if (macho.isMacho(data)) return .macho;
    if (elf.isElf(data)) return .elf;
    if (pe.isPe(data)) return .pe;
    if (data.len >= 4 and data[0] == 'P' and data[1] == 'K' and data[2] == 0x03 and data[3] == 0x04) return .zip;
    if (data.len >= 40 and data[0] == 0x00 and data[1] == 'P' and data[2] == 'B' and data[3] == 'P') return .pbp;
    return .raw;
}

/// Load a binary via the appropriate format-specific loader.
fn loadBinary(allocator: std.mem.Allocator, path: []const u8, data: []const u8, format: types.BinaryFormat) !types.Document {
    const opts = types.LoadOptions{};
    return switch (format) {
        .macho => macho.parse(allocator, 1, path, data, opts) catch |e| return @as(anyerror, e),
        .elf => elf.parse(allocator, 1, path, data, opts) catch |e| return @as(anyerror, e),
        .pe => pe.parse(allocator, 1, path, data, opts) catch |e| return @as(anyerror, e),
        .zip => {
            var doc = types.Document.init(allocator, 1, path, data);
            doc.format = .zip;
            return doc;
        },
        .pbp => {
            // PBP container: extract ELF from section 6 (DATA.PSP)
            // Header: magic(4) + version(4) + 8 section offsets (8 * 4 = 32 bytes)
            // Offsets: [0]=PARAM.SFO [1]=ICON0 [2]=ICON1 [3]=PIC0 [4]=PIC1
            //          [5]=SND0.AT3 [6]=DATA.PSP [7]=DATA.PSAR
            if (data.len < 40) return error.InvalidFormat;
            const elf_offset = std.mem.readInt(u32, data[32..36], .little); // offset[6] = DATA.PSP
            const raw_end = std.mem.readInt(u32, data[36..40], .little); // offset[7] = DATA.PSAR
            // When DATA.PSP and DATA.PSAR share the same offset, DATA.PSP is
            // zero-length in the header but the actual content extends to EOF.
            const elf_end = if (raw_end > elf_offset) raw_end else @as(u32, @intCast(@min(data.len, std.math.maxInt(u32))));
            if (elf_offset >= elf_end or elf_end > data.len) return error.InvalidFormat;
            const elf_data = data[elf_offset..elf_end];
            // Check if extracted data is actually ELF
            if (elf.isElf(elf_data)) {
                return elf.parse(allocator, 1, path, elf_data, opts) catch |e| return @as(anyerror, e);
            }
            // If not ELF (encrypted PBP), fall back to raw
            var doc = types.Document.init(allocator, 1, path, data);
            doc.format = .pbp;
            return doc;
        },
        .psx_exe => {
            // PSX-EXE (PlayStation 1) — handled in detail by tools.zig load_binary
            // path. CLI analyze path keeps a minimal raw-style fallback.
            var doc = types.Document.init(allocator, 1, path, data);
            doc.format = .psx_exe;
            return doc;
        },
        .raw => {
            var doc = types.Document.init(allocator, 1, path, data);
            doc.format = .raw;
            return doc;
        },
    };
}
