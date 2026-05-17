// Phora — String Detector
// Scans data sections for printable ASCII runs >= 4 chars.
// Strict mode: requires null terminator. Relaxed mode: any non-printable byte terminates.

const std = @import("std");
const types = @import("../types.zig");

/// Scan a byte slice for printable ASCII strings >= min_length chars.
/// When relaxed=false (strict), requires null terminator (Mach-O __cstring style).
/// When relaxed=true, any non-printable byte terminates (ELF .rodata, length-prefixed strings).
pub fn detectStrings(
    allocator: std.mem.Allocator,
    data: []const u8,
    base_address: u64,
    min_length: u32,
    relaxed: bool,
) !std.array_list.Managed(types.String) {
    var results = std.array_list.Managed(types.String).init(allocator);
    errdefer results.deinit();

    var i: usize = 0;
    while (i < data.len) {
        // Find start of a printable run
        const run_start = i;
        var run_len: usize = 0;

        while (i < data.len and isPrintableAscii(data[i])) {
            run_len += 1;
            i += 1;
        }

        // Check termination and minimum length
        const terminated = if (i >= data.len)
            false
        else if (relaxed)
            !isPrintableAscii(data[i])
        else
            data[i] == 0;

        if (run_len >= min_length and terminated) {
            try results.append(.{
                .address = base_address + run_start,
                .value = data[run_start .. run_start + run_len],
                .length = @intCast(run_len),
            });
            if (!relaxed) i += 1; // skip null terminator in strict mode
        } else {
            // Not a valid string, advance past whatever we consumed
            if (run_len == 0) {
                i += 1;
            }
        }
    }

    return results;
}

/// Scan all data sections in a document's segments for strings.
pub fn detectAllStrings(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
) !std.array_list.Managed(types.String) {
    var results = std.array_list.Managed(types.String).init(allocator);
    errdefer results.deinit();

    for (doc.segments) |segment| {
        // Skip non-readable segments
        if (!segment.permissions.read) continue;

        // Skip packed runtime segments entirely during load — they can be 100+ MB
        // and take 200+ seconds to scan byte-by-byte. v7.4.2 ships an on-demand
        // byte-grep through `searchPackedSegments` and v7.4.3 surfaces them via
        // the `get_embedded_resources` MCP tool. v7.4.3 F4: now consults the
        // RuntimeAdapter registry instead of hard-coding "__BUN".
        if (isPackedSegment(segment.name)) continue;
        const min_len: u32 = 4;

        for (segment.sections) |section| {
            const section_end = section.file_offset + section.length;
            if (section_end > doc.data.len) continue;
            if (section.file_offset >= doc.data.len) continue;

            // Skip code and non-data sections entirely
            if (isCodeSection(section.name) or isNonDataSection(section.name)) continue;

            const section_data = doc.data[section.file_offset..section_end];

            const relaxed = isKnownStringSection(section.name);
            var section_strings = try detectStrings(
                allocator,
                section_data,
                section.start,
                min_len,
                relaxed,
            );
            defer section_strings.deinit();
            try results.appendSlice(section_strings.items);
        }

        // No gap scanning — Mach-O header/load command strings are metadata,
        // not binary strings. strings(1) doesn't report them, so neither do we.
    }

    return results;
}

/// Scan only __BUN segments with min_length=4 for on-demand bundle string searching.
/// Used by get_strings pattern=X to find short strings in embedded JS bundles
/// that were skipped during load (which uses min_length=15 for __BUN).
pub fn detectBundleStrings(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
) !std.array_list.Managed(types.String) {
    var results = std.array_list.Managed(types.String).init(allocator);
    errdefer results.deinit();

    for (doc.segments) |segment| {
        if (!isPackedSegment(segment.name)) continue;

        for (segment.sections) |section| {
            const section_end = section.file_offset + section.length;
            if (section_end > doc.data.len) continue;
            if (section.file_offset >= doc.data.len) continue;

            const section_data = doc.data[section.file_offset..section_end];
            var section_strings = try detectStrings(allocator, section_data, section.start, 4, false);
            defer section_strings.deinit();
            try results.appendSlice(section_strings.items);
        }
    }

    return results;
}

// ============================================================================
// Packed-segment byte-grep (v7.4.2 F1) — shared between get_strings Phase 2
// and the search type=string/string_refs fallback in handleSearch.
// v7.4.3 F4: refactored to flow through a `RuntimeAdapter` registry so each
// new packed runtime can plug in via one
// `ADAPTERS` entry instead of touching multiple call sites.
// ============================================================================

/// A `RuntimeAdapter` describes how Phora finds and labels content from a
/// specific embedded runtime and its packed resource signals.
///
/// The interface is stable so new adapters can be appended to `ADAPTERS`
/// without touching existing call sites.
pub const RuntimeAdapter = struct {
    /// Lowercase identifier emitted in `runtime` and `runtime_hint` fields
    /// (e.g. "bun", "pyoxidizer").
    name: []const u8,
    /// Detect whether this runtime is present in the document.
    detect: *const fn (doc: *const types.Document) bool,
    /// Predicate for which segment names this runtime claims as packed.
    /// Used by the search fallback (`searchPackedSegments`) to know which
    /// segments to byte-grep on demand.
    is_packed_segment: *const fn (seg_name: []const u8) bool,
    /// Optional: enumerate structured resource entries for `get_embedded_resources`.
    /// If null, the runtime contributes only string-search fallback hits but
    /// no structured resource listings.
    enumerate_resources: ?*const fn (
        allocator: std.mem.Allocator,
        doc: *const types.Document,
    ) anyerror!ResourceList = null,
    /// v7.14.0 B2: optional workflow-cascade redirect. When the adapter
    /// fires, this template tells the LLM where to inspect next (e.g. an
    /// asar archive in Contents/Resources, or a sibling .gguf model file).
    /// `{bundle}` is substituted with the derived bundle root from the load
    /// path (walks up from `Contents/MacOS/<name>` to the `.app/` root); for
    /// non-bundle paths it falls back to the parent directory. Null = no
    /// redirect (some runtimes have nothing to redirect to).
    next_target_template: ?[]const u8 = null,
};

/// A structured embedded resource. Returned by `RuntimeAdapter.enumerate_resources`
/// and surfaced through the `get_embedded_resources` MCP tool.
pub const Resource = struct {
    /// Runtime identifier (matches RuntimeAdapter.name).
    runtime: []const u8,
    /// Synthesized resource name.
    name: []const u8,
    /// Resource kind: "javascript", "python", "binary", "data", ...
    kind: []const u8,
    /// Total size in bytes.
    size: u64,
    /// Virtual address (NOT yet rebase-translated — caller applies delta).
    address: u64,
    /// File offset where the resource bytes start.
    file_offset: u64,
    /// Bounded preview — first ~200 chars of printable bytes for text payloads,
    /// or hex of first 64 bytes for binary. NOT owned by the caller; points
    /// into doc.data.
    preview: []const u8,
    /// How the resource was identified: "segment_scan", "magic_signature",
    /// "symbol_table", ...
    provenance: []const u8,
};

pub const ResourceList = struct {
    items: std.array_list.Managed(Resource),

    pub fn deinit(self: *ResourceList) void {
        self.items.deinit();
    }
};

/// The runtime adapter registry. Add new adapters here.
///
/// v7.13.0 B5: expanded from 1 → 7 adapters (bun + V8 snapshot, asar, J2ObjC,
/// upb, CPython embedded, ggml/llama.cpp). Each new adapter requires ≥2
/// corroborating signals to fire (mitigation per plan risk #4: section name
/// alone is not enough — also needs a magic byte sequence or a known string
/// pattern).
pub const ADAPTERS = [_]RuntimeAdapter{
    bun_adapter,
    v8_snapshot_adapter,
    asar_adapter,
    j2objc_adapter,
    upb_adapter,
    cpython_adapter,
    ggml_adapter,
};

/// Detects a JavaScript bundle stored in a dedicated segment.
const bun_adapter = RuntimeAdapter{
    .name = "bun",
    .detect = bunDetect,
    .is_packed_segment = bunIsPackedSegment,
    .enumerate_resources = bunEnumerateResources,
    .next_target_template = "search type=string_refs pattern='import|export|require' on __BUN segment",
};

fn bunDetect(doc: *const types.Document) bool {
    for (doc.segments) |seg| {
        if (bunIsPackedSegment(seg.name)) return true;
    }
    return false;
}

fn bunIsPackedSegment(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "__BUN");
}

fn bunEnumerateResources(allocator: std.mem.Allocator, doc: *const types.Document) !ResourceList {
    var list = ResourceList{ .items = std.array_list.Managed(Resource).init(allocator) };
    errdefer list.deinit();

    for (doc.segments) |seg| {
        if (!bunIsPackedSegment(seg.name)) continue;
        var total_size: u64 = 0;
        var file_off: u64 = 0;
        var preview: []const u8 = "";

        // Sum section sizes; use the first section's file_offset as the
        // resource start. Build a preview from the first printable run.
        for (seg.sections, 0..) |sec, idx| {
            total_size += sec.length;
            if (idx == 0) {
                file_off = sec.file_offset;
                if (sec.file_offset < doc.data.len) {
                    const sec_end = @min(sec.file_offset + sec.length, doc.data.len);
                    const sec_data = doc.data[sec.file_offset..sec_end];
                    // Find the first run of >= 16 printable chars and take up to 200.
                    var i: usize = 0;
                    while (i < sec_data.len) {
                        const start_i = i;
                        while (i < sec_data.len and isPrintableAscii(sec_data[i])) i += 1;
                        if (i - start_i >= 16) {
                            const end_i = @min(start_i + 200, i);
                            preview = sec_data[start_i..end_i];
                            break;
                        }
                        i += 1;
                    }
                }
            }
        }

        try list.items.append(.{
            .runtime = "bun",
            .name = "bundle",
            .kind = "javascript",
            .size = total_size,
            .address = seg.start,
            .file_offset = file_off,
            .preview = preview,
            .provenance = "segment_scan",
        });
    }

    return list;
}

// ============================================================================
// v7.13.0 B5 — Additional embedded-runtime adapters
// ============================================================================
//
// All six new adapters share one design rule: require ≥2 corroborating signals
// before firing. A bare section-name match would false-positive on any binary
// whose author happened to use the same name; combining (section + magic),
// (section + string family), or (multiple sections) keeps the signal high.
//
// `enumerate_resources` is null for adapters that don't expose discrete
// payload chunks — they still surface in `runtimes_detected[]` so the LLM
// knows the runtime is present.

// ---------- V8 snapshot ------------------------------------------------------

const v8_snapshot_adapter = RuntimeAdapter{
    .name = "v8_snapshot",
    .detect = v8Detect,
    .is_packed_segment = v8IsPackedSegment,
    .enumerate_resources = null,
    .next_target_template = "v8_context_snapshot.bin file alongside binary; Phora cannot deserialize it (v7.15+)",
};

fn v8IsPackedSegment(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "__V8") or
        std.mem.startsWith(u8, name, "__v8") or
        std.mem.eql(u8, name, "v8_context_snapshot");
}

fn v8Detect(doc: *const types.Document) bool {
    var has_section = false;
    var has_string = false;
    for (doc.segments) |seg| {
        if (v8IsPackedSegment(seg.name)) has_section = true;
        for (seg.sections) |sec| {
            if (v8IsPackedSegment(sec.name)) has_section = true;
        }
    }
    // Look for any "v8_context_snapshot.bin" or "V8_*" string ref.
    for (doc.strings.items) |s| {
        if (std.mem.indexOf(u8, s.value, "v8_context_snapshot.bin") != null) {
            has_string = true;
            break;
        }
        if (std.mem.indexOf(u8, s.value, "V8_NATIVES_BLOB") != null or
            std.mem.indexOf(u8, s.value, "v8_snapshot_blob") != null)
        {
            has_string = true;
            break;
        }
    }
    return has_section and has_string;
}

// ---------- asar resource archive -------------------------------------------

const asar_adapter = RuntimeAdapter{
    .name = "asar",
    .detect = asarDetect,
    .is_packed_segment = asarIsPackedSegment,
    .enumerate_resources = null,
    .next_target_template = "{bundle}/Contents/Resources/app.asar OR {bundle}/Contents/Resources/app/.webpack/main",
};

fn asarIsPackedSegment(name: []const u8) bool {
    // No standard segment name — asar archives sit on disk as separate files.
    // The detector still returns hits when the binary embeds an asar header.
    return std.mem.startsWith(u8, name, "__asar") or std.mem.startsWith(u8, name, "__ASAR");
}

fn asarDetect(doc: *const types.Document) bool {
    // ASAR vocabulary appears in Phora itself, so a bare ".asar" string plus a
    // literal `"files":{` constant is not enough. Accept either a real ASAR
    // storage region paired with a path clue, or an archive-shaped manifest.
    return (asarHasPackedRegion(doc) and asarHasPathString(doc)) or
        asarHasPlausibleArchiveManifest(doc);
}

const asar_manifest_marker = "\"files\":{";

fn asarHasPackedRegion(doc: *const types.Document) bool {
    for (doc.segments) |seg| {
        if (asarIsPackedSegment(seg.name)) return true;
        for (seg.sections) |sec| {
            if (asarIsPackedSegment(sec.name)) return true;
        }
    }
    return false;
}

fn asarHasPathString(doc: *const types.Document) bool {
    for (doc.strings.items) |s| {
        if (isLikelyAsarPathString(s.value)) return true;
    }
    return false;
}

fn isLikelyAsarPathString(value: []const u8) bool {
    var start: usize = 0;
    while (std.mem.indexOf(u8, value[start..], ".asar")) |rel| {
        const dot = start + rel;
        const after = dot + ".asar".len;
        defer start = dot + 1;

        if (dot == 0) continue;
        if (!isAsarPathComponentByte(value[dot - 1])) continue;
        if (after < value.len and
            !isAsarPathTerminator(value[after]) and
            !std.mem.startsWith(u8, value[after..], ".unpacked"))
        {
            continue;
        }

        return true;
    }
    return false;
}

fn isAsarPathComponentByte(c: u8) bool {
    return (c >= 'a' and c <= 'z') or
        (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or
        c == '_' or c == '-' or c == '.';
}

fn isAsarPathTerminator(c: u8) bool {
    return c == 0 or
        c == '/' or
        c == '\\' or
        c == '"' or
        c == '\'' or
        c == ' ' or
        c == ')' or
        c == ',' or
        c == ';' or
        c == ':' or
        c == '\n' or
        c == '\t';
}

fn asarHasPlausibleArchiveManifest(doc: *const types.Document) bool {
    for (doc.segments) |seg| {
        if (!seg.permissions.read) continue;
        for (seg.sections) |sec| {
            if (sec.file_offset >= doc.data.len) continue;
            const sec_end = @min(sec.file_offset + sec.length, doc.data.len);
            const sec_data = doc.data[sec.file_offset..sec_end];
            if (asarSectionHasPlausibleManifest(seg.name, sec.name, sec_data)) return true;
        }
    }
    return false;
}

fn asarSectionHasPlausibleManifest(segment_name: []const u8, section_name: []const u8, data: []const u8) bool {
    const scan_len = @min(data.len, 512 * 1024);
    var start: usize = 0;
    while (start < scan_len) {
        const rel = std.mem.indexOf(u8, data[start..scan_len], asar_manifest_marker) orelse break;
        const marker = start + rel;
        if (asarManifestMarkerHasArchiveContext(segment_name, section_name, data, marker)) return true;
        start = marker + 1;
    }
    return false;
}

fn asarManifestMarkerHasArchiveContext(
    segment_name: []const u8,
    section_name: []const u8,
    data: []const u8,
    marker: usize,
) bool {
    const object_start = findAsarManifestObjectStart(data, marker) orelse return false;
    const json_end = printableRunEnd(data, object_start);
    const context_end = @min(json_end, marker + 8192);
    if (context_end <= marker + asar_manifest_marker.len) return false;

    const after_files = data[marker + asar_manifest_marker.len .. context_end];
    const has_file_entry = std.mem.indexOf(u8, after_files, "\":{") != null;
    const has_archive_metadata =
        std.mem.indexOf(u8, after_files, "\"size\":") != null or
        std.mem.indexOf(u8, after_files, "\"offset\":") != null or
        std.mem.indexOf(u8, after_files, "\"unpacked\":") != null or
        std.mem.indexOf(u8, after_files, "\"executable\":") != null or
        std.mem.indexOf(u8, after_files, "\"integrity\":") != null;

    if (!has_file_entry or !has_archive_metadata) return false;
    if (asarHasPicklePrefix(data, object_start, json_end - object_start)) return true;
    if (asarIsPackedSegment(segment_name) or asarIsPackedSegment(section_name)) return true;

    // Compiler-emitted strings commonly live here; without the binary ASAR
    // pickle prefix, treat them as vocabulary rather than archive evidence.
    return !isKnownStringSection(section_name);
}

fn findAsarManifestObjectStart(data: []const u8, marker: usize) ?usize {
    const start = if (marker > 64) marker - 64 else 0;
    var i = marker;
    while (i > start) {
        i -= 1;
        if (data[i] != '{') continue;
        for (data[i + 1 .. marker]) |c| {
            if (c != ' ' and c != '\n' and c != '\t' and c != '\r') break;
        } else {
            return i;
        }
    }
    return null;
}

fn printableRunEnd(data: []const u8, start: usize) usize {
    var end = start;
    while (end < data.len and isPrintableAscii(data[end])) end += 1;
    return end;
}

fn asarHasPicklePrefix(data: []const u8, object_start: usize, json_len: usize) bool {
    const back_offsets = [_]usize{ 8, 12, 16 };
    for (back_offsets) |back| {
        if (object_start < back) continue;
        const first = readU32Le(data, object_start - back);
        const second = readU32Le(data, object_start - back + 4);
        if (asarPickleSizesLookPlausible(first, second, json_len)) return true;
    }
    return false;
}

fn asarPickleSizesLookPlausible(first: u32, second: u32, json_len: usize) bool {
    if (second < asar_manifest_marker.len) return false;
    if (first < second) return false;
    if (first > second + 64) return false;
    return second <= json_len + 8;
}

fn readU32Le(data: []const u8, offset: usize) u32 {
    return @as(u32, data[offset]) |
        (@as(u32, data[offset + 1]) << 8) |
        (@as(u32, data[offset + 2]) << 16) |
        (@as(u32, data[offset + 3]) << 24);
}

test "asar detector ignores analyzer vocabulary in string sections" {
    const allocator = std.testing.allocator;
    const data =
        "Usage mentions {bundle}/Contents/Resources/app.asar and __asar " ++
        "{\"files\":{\"main.js\":{\"size\":42,\"offset\":\"0\"}}}\x00";
    const section = types.Section{
        .name = "__cstring",
        .start = 0x1000,
        .length = data.len,
        .file_offset = 0,
    };
    var sections = [_]types.Section{section};
    const segment = types.Segment{
        .name = "__TEXT",
        .start = 0x1000,
        .length = data.len,
        .sections = sections[0..],
        .permissions = .{ .read = true, .write = false, .execute = false },
        .file_offset = 0,
        .file_size = data.len,
    };
    var segments = [_]types.Segment{segment};
    var strings = std.array_list.Managed(types.String).init(allocator);
    defer strings.deinit();
    try strings.append(.{
        .address = 0x1000,
        .value = "{bundle}/Contents/Resources/app.asar OR {bundle}/Contents/Resources/app/.webpack/main",
        .length = @intCast("{bundle}/Contents/Resources/app.asar OR {bundle}/Contents/Resources/app/.webpack/main".len),
    });
    try strings.append(.{
        .address = 0x1040,
        .value = "{\"files\":{",
        .length = @intCast("{\"files\":{".len),
    });

    const doc = types.Document{
        .id = 1,
        .path = "zig-out/bin/phora",
        .format = .macho,
        .arch = .arm64,
        .entry_point = 0,
        .segments = segments[0..],
        .procedures = std.array_list.Managed(types.Procedure).init(allocator),
        .strings = strings,
        .imports = std.array_list.Managed(types.Import).init(allocator),
        .annotations = std.array_list.Managed(types.Annotation).init(allocator),
        .data = data,
    };

    try std.testing.expect(!asarDetect(&doc));
}

test "asar detector accepts archive-shaped manifest outside string sections" {
    const allocator = std.testing.allocator;
    const data = "{\"files\":{\"main.js\":{\"size\":42,\"offset\":\"0\"}}}\x00";
    const section = types.Section{
        .name = "__archive",
        .start = 0x2000,
        .length = data.len,
        .file_offset = 0,
    };
    var sections = [_]types.Section{section};
    const segment = types.Segment{
        .name = "__DATA",
        .start = 0x2000,
        .length = data.len,
        .sections = sections[0..],
        .permissions = .{ .read = true, .write = false, .execute = false },
        .file_offset = 0,
        .file_size = data.len,
    };
    var segments = [_]types.Segment{segment};

    const doc = types.Document{
        .id = 2,
        .path = "Example.app/Contents/MacOS/Example",
        .format = .macho,
        .arch = .arm64,
        .entry_point = 0,
        .segments = segments[0..],
        .procedures = std.array_list.Managed(types.Procedure).init(allocator),
        .strings = std.array_list.Managed(types.String).init(allocator),
        .imports = std.array_list.Managed(types.Import).init(allocator),
        .annotations = std.array_list.Managed(types.Annotation).init(allocator),
        .data = data,
    };

    try std.testing.expect(asarDetect(&doc));
}

// ---------- J2ObjC (Java→ObjC transpiler runtime) ---------------------------

const j2objc_adapter = RuntimeAdapter{
    .name = "j2objc",
    .detect = j2objcDetect,
    .is_packed_segment = j2objcIsPackedSegment,
    .enumerate_resources = null,
    .next_target_template = "{bundle}/Contents/Resources/<embedded_jar>.jar OR class-dump output (J2ObjC translates Java to Obj-C)",
};

fn j2objcIsPackedSegment(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "__j2objc") or
        std.mem.startsWith(u8, name, "__J2OBJC");
}

fn j2objcDetect(doc: *const types.Document) bool {
    // ≥2 signals: section name AND Java-style "Lcom/" or "Ljava/" string.
    var has_section = false;
    var has_string = false;
    for (doc.segments) |seg| {
        if (j2objcIsPackedSegment(seg.name)) has_section = true;
        for (seg.sections) |sec| {
            if (j2objcIsPackedSegment(sec.name)) has_section = true;
        }
    }
    for (doc.strings.items) |s| {
        if (std.mem.indexOf(u8, s.value, "Lcom/google/") != null or
            std.mem.indexOf(u8, s.value, "Ljava/lang/") != null or
            std.mem.indexOf(u8, s.value, "JreEnsureInitialized") != null or
            std.mem.indexOf(u8, s.value, "j2objc") != null)
        {
            has_string = true;
            break;
        }
    }
    // If only the section is present (test scenario where strings haven't
    // been populated), accept on section + heavy section count.
    if (has_section and !has_string) {
        var section_hits: u32 = 0;
        for (doc.segments) |seg| {
            if (j2objcIsPackedSegment(seg.name)) section_hits += 1;
            for (seg.sections) |sec| {
                if (j2objcIsPackedSegment(sec.name)) section_hits += 1;
            }
        }
        // Two distinct __j2objc* sections is itself two signals.
        if (section_hits >= 2) return true;
    }
    return has_section and has_string;
}

// ---------- upb (micro protobuf runtime) ------------------------------------

const upb_adapter = RuntimeAdapter{
    .name = "upb",
    .detect = upbDetect,
    .is_packed_segment = upbIsPackedSegment,
    .enumerate_resources = null,
    .next_target_template = "search type=string_refs pattern='\\.proto' on doc — schema strings ARE the API surface",
};

fn upbIsPackedSegment(name: []const u8) bool {
    return std.mem.indexOf(u8, name, "upb") != null or
        std.mem.indexOf(u8, name, "__la_upb") != null;
}

fn upbDetect(doc: *const types.Document) bool {
    var has_section = false;
    var has_proto_string = false;
    for (doc.segments) |seg| {
        if (upbIsPackedSegment(seg.name)) has_section = true;
        for (seg.sections) |sec| {
            if (upbIsPackedSegment(sec.name)) has_section = true;
        }
    }
    // Proto-pattern: dot-separated lowercase namespaces with a versioned
    // CamelCase tail like `google.protobuf.FileDescriptorProto` or
    // `google.ai.generativelanguage.v1beta.GenerativeModel`.
    for (doc.strings.items) |s| {
        if (s.length < 12) continue;
        if (std.mem.indexOf(u8, s.value, "google.protobuf.") != null or
            std.mem.indexOf(u8, s.value, "google.ai.") != null or
            std.mem.indexOf(u8, s.value, ".pb.bin") != null or
            std.mem.indexOf(u8, s.value, "upb_MiniTable") != null or
            std.mem.indexOf(u8, s.value, "upb_Message") != null)
        {
            has_proto_string = true;
            break;
        }
    }
    // If only the section is present, also accept on >=2 distinct upb sections.
    if (has_section and !has_proto_string) {
        var section_hits: u32 = 0;
        for (doc.segments) |seg| {
            if (upbIsPackedSegment(seg.name)) section_hits += 1;
            for (seg.sections) |sec| {
                if (upbIsPackedSegment(sec.name)) section_hits += 1;
            }
        }
        if (section_hits >= 2) return true;
    }
    return has_section and has_proto_string;
}

// ---------- CPython embedded interpreter ------------------------------------

const cpython_adapter = RuntimeAdapter{
    .name = "cpython",
    .detect = cpythonDetect,
    .is_packed_segment = cpythonIsPackedSegment,
    .enumerate_resources = null,
    .next_target_template = "{bundle}/Contents/Resources/lib/python*.zip OR .pyc files",
};

fn cpythonIsPackedSegment(_: []const u8) bool {
    // CPython doesn't claim a dedicated segment we can scan separately;
    // detection relies on symbol/string evidence.
    return false;
}

fn cpythonDetect(doc: *const types.Document) bool {
    // Need structural import evidence. Phora embeds analyzer vocabulary such
    // as "Py_Initialize" and "python3." as ordinary strings, so strings alone
    // must never label the binary as CPython.
    var import_hits: u32 = 0;
    var string_hits: u32 = 0;
    var seen_py_init = false;
    var seen_pyimport = false;
    var seen_python_ver = false;
    var seen_py_verify = false;

    for (doc.imports.items) |imp| {
        if (!seen_py_init and (std.mem.indexOf(u8, imp.name, "Py_Initialize") != null)) {
            seen_py_init = true;
            import_hits += 1;
        }
        if (!seen_pyimport and (std.mem.indexOf(u8, imp.name, "_PyImport_") != null or
            std.mem.indexOf(u8, imp.name, "PyImport_") != null))
        {
            seen_pyimport = true;
            import_hits += 1;
        }
        if (!seen_py_verify and (std.mem.indexOf(u8, imp.name, "Py_VerifyVersion") != null or
            std.mem.indexOf(u8, imp.name, "Py_GetVersion") != null))
        {
            seen_py_verify = true;
            import_hits += 1;
        }
    }
    for (doc.strings.items) |s| {
        if (s.length < 8) continue;
        if (!seen_python_ver and std.mem.indexOf(u8, s.value, "python3.") != null) {
            seen_python_ver = true;
            string_hits += 1;
        }
        if (!seen_py_init and std.mem.indexOf(u8, s.value, "Py_Initialize") != null) {
            seen_py_init = true;
            string_hits += 1;
        }
    }
    return import_hits >= 2 or (import_hits >= 1 and string_hits >= 1);
}

test "cpython detector ignores analyzer vocabulary in generic strings" {
    var doc = types.Document.init(std.testing.allocator, 1, "/tmp/phora", &.{});
    defer doc.deinit();
    try doc.strings.append(.{
        .address = 0x1000,
        .value = "Py_Initialize python3.13 lib/python*.zip",
        .length = "Py_Initialize python3.13 lib/python*.zip".len,
    });
    try std.testing.expect(!cpythonDetect(&doc));
}

// ---------- ggml / llama.cpp -------------------------------------------------

const ggml_adapter = RuntimeAdapter{
    .name = "ggml",
    .detect = ggmlDetect,
    .is_packed_segment = ggmlIsPackedSegment,
    .enumerate_resources = null,
    .next_target_template = "{bundle}/Contents/Resources/*.gguf for the embedded model file",
};

fn ggmlIsPackedSegment(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "__GGML") or std.mem.startsWith(u8, name, "__ggml");
}

fn ggmlDetect(doc: *const types.Document) bool {
    var has_section = false;
    var has_string = false;
    for (doc.segments) |seg| {
        if (ggmlIsPackedSegment(seg.name)) has_section = true;
        for (seg.sections) |sec| {
            if (ggmlIsPackedSegment(sec.name)) has_section = true;
        }
    }
    var hits: u32 = 0;
    if (has_section) hits += 1;
    for (doc.strings.items) |s| {
        if (s.length < 4) continue;
        if (std.mem.indexOf(u8, s.value, "gguf_v") != null or
            std.mem.indexOf(u8, s.value, "GGUF") != null or
            std.mem.indexOf(u8, s.value, "llama.cpp") != null or
            std.mem.indexOf(u8, s.value, "ggml_") != null or
            std.mem.indexOf(u8, s.value, "llama_model") != null)
        {
            has_string = true;
            hits += 1;
            break;
        }
    }
    return hits >= 2 and (has_section or has_string);
}

pub fn isPackedSegment(name: []const u8) bool {
    for (ADAPTERS) |adapter| {
        if (adapter.is_packed_segment(name)) return true;
    }
    return false;
}

pub fn hasPackedSegment(doc: *const types.Document) bool {
    for (doc.segments) |seg| {
        if (isPackedSegment(seg.name)) return true;
    }
    return false;
}

/// Detect the runtime present in this document, if any. Returns the first
/// matching adapter's name (e.g. "bun"), or null if no adapter detects.
pub fn detectRuntime(doc: *const types.Document) ?[]const u8 {
    for (ADAPTERS) |adapter| {
        if (adapter.detect(doc)) return adapter.name;
    }
    return null;
}

/// v7.14.0 B2: derive the bundle root from a binary path, used for
/// `next_target_template` `{bundle}` substitution.
///
/// macOS .app layout: <bundle>.app/Contents/MacOS/<binary>. We walk up from
/// the binary path until we find `Contents/MacOS/` and return the parent of
/// `Contents`. For non-bundle paths (e.g. `/bin/ls`, raw blobs, stdin) we
/// return the parent directory, which gives the LLM at least a useful
/// directory to grep around in.
///
/// Returns null when the path is empty or "stdin"/synthetic — caller emits
/// the template with `{bundle}` left as-is so the LLM still gets the hint.
pub fn deriveBundleRoot(path: []const u8) ?[]const u8 {
    if (path.len == 0) return null;
    // Synthetic paths from raw load / dyld_shared_cache: have no bundle.
    if (std.mem.startsWith(u8, path, "dyld_shared_cache:")) return null;
    if (std.mem.startsWith(u8, path, "stdin:")) return null;

    // Look for "/Contents/MacOS/" anywhere in the path; take the substring
    // ending just before "/Contents/...".
    if (std.mem.indexOf(u8, path, "/Contents/MacOS/")) |idx| {
        return path[0..idx];
    }
    if (std.mem.indexOf(u8, path, "/Contents/Frameworks/")) |idx| {
        return path[0..idx];
    }
    // Fallback: parent directory.
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| {
        if (slash == 0) return path[0..1]; // root
        return path[0..slash];
    }
    return null;
}

/// v7.14.0 B2: resolve a `next_target_template` against a load path by
/// substituting `{bundle}` with the derived bundle root. Caller-owned slice
/// allocated with `allocator`. Returns null on OOM or empty template.
pub fn resolveNextTarget(
    allocator: std.mem.Allocator,
    template: []const u8,
    path: []const u8,
) ?[]u8 {
    if (template.len == 0) return null;
    const bundle = deriveBundleRoot(path);
    // If template doesn't contain {bundle}, just dupe.
    if (std.mem.indexOf(u8, template, "{bundle}") == null) {
        return allocator.dupe(u8, template) catch null;
    }
    // If template needs {bundle} but we don't have one, leave the literal so
    // the LLM still sees the hint structure.
    const replacement: []const u8 = bundle orelse "{bundle}";
    var out = std.array_list.Managed(u8).init(allocator);
    var rest: []const u8 = template;
    while (std.mem.indexOf(u8, rest, "{bundle}")) |pos| {
        out.appendSlice(rest[0..pos]) catch return null;
        out.appendSlice(replacement) catch return null;
        rest = rest[pos + "{bundle}".len ..];
    }
    out.appendSlice(rest) catch return null;
    return out.toOwnedSlice() catch null;
}

pub const PackedSearchOptions = struct {
    case_insensitive: bool = false,
    max_results: u32 = 100,
    /// ±N characters of context around the match to include in `excerpt`.
    /// The actual excerpt is also bounded by the surrounding printable run, so
    /// excerpts never include garbage bytes.
    excerpt_radius: usize = 50,
    /// When true, scan EVERY readable segment (not just packed). Used by
    /// get_strings scan=true. When false, only scan packed segments.
    scan_all: bool = false,
};

pub const PackedSearchHit = struct {
    /// Virtual address of the match start (NOT yet rebase-translated —
    /// the caller applies rebase delta).
    address: u64,
    /// Bounded slice into doc.data — trimmed to ±excerpt_radius around the
    /// match AND clamped to the surrounding printable run. Caller MUST NOT
    /// free this slice; it points into doc.data which is owned by the
    /// Document.
    excerpt: []const u8,
    /// Length of the surrounding printable run (the excerpt is a subset).
    full_length: usize,
    /// Segment name where the hit was found (slice into Segment.name —
    /// also not owned by the caller).
    segment_name: []const u8,
};

pub const PackedSearchResults = struct {
    hits: std.array_list.Managed(PackedSearchHit),
    /// Segment names that were actually scanned (matched the prefix filter).
    /// Used to build the `scanned_regions` response field.
    scanned_segments: std.array_list.Managed([]const u8),

    pub fn deinit(self: *PackedSearchResults) void {
        self.hits.deinit();
        self.scanned_segments.deinit();
    }
};

/// Byte-grep over packed segments (or all readable segments when scan_all=true).
/// Returns up to `options.max_results` hits with bounded printable excerpts.
///
/// This is the canonical implementation of the on-demand byte-grep that
/// get_strings Phase 2 uses (tools.zig:5388-5460) and that the v7.4.2 search
/// fallback also uses. The body intentionally mirrors the existing get_strings
/// behavior so the two paths produce consistent results.
pub fn searchPackedSegments(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    pattern: []const u8,
    options: PackedSearchOptions,
) !PackedSearchResults {
    var results = PackedSearchResults{
        .hits = std.array_list.Managed(PackedSearchHit).init(allocator),
        .scanned_segments = std.array_list.Managed([]const u8).init(allocator),
    };
    errdefer results.deinit();

    if (pattern.len == 0) return results;

    seg_loop: for (doc.segments) |segment| {
        const should_scan = options.scan_all or isPackedSegment(segment.name);
        if (!should_scan) continue;
        // Skip code sections in scan_all mode (caller wants strings, not text).
        if (options.scan_all and segment.permissions.execute and !segment.permissions.write) continue;

        try results.scanned_segments.append(segment.name);

        for (segment.sections) |section| {
            if (results.hits.items.len >= options.max_results) break :seg_loop;
            const sec_end = section.file_offset + section.length;
            if (sec_end > doc.data.len) continue;
            if (section.file_offset >= doc.data.len) continue;
            const sec_data = doc.data[section.file_offset..sec_end];

            // Byte-scan for pattern matches (grep-style). Same loop shape as
            // tools.zig:5402-5448 — kept identical so behavior matches.
            var pos: usize = 0;
            while (pos + pattern.len <= sec_data.len) {
                if (results.hits.items.len >= options.max_results) break :seg_loop;

                // Check for pattern match (case-sensitive or insensitive).
                var match = true;
                for (pattern, 0..) |pc, pi| {
                    const dc = sec_data[pos + pi];
                    if (options.case_insensitive) {
                        const pl = if (pc >= 'A' and pc <= 'Z') pc + 32 else pc;
                        const dl = if (dc >= 'A' and dc <= 'Z') dc + 32 else dc;
                        if (pl != dl) {
                            match = false;
                            break;
                        }
                    } else {
                        if (pc != dc) {
                            match = false;
                            break;
                        }
                    }
                }
                if (!match) {
                    pos += 1;
                    continue;
                }

                // Found pattern. Compute the bounded excerpt:
                // walk backward up to excerpt_radius chars OR until non-printable,
                // whichever comes first. Same forward.
                const radius = options.excerpt_radius;
                var ex_start = pos;
                {
                    var back: usize = 0;
                    while (ex_start > 0 and back < radius and isPrintableAscii(sec_data[ex_start - 1])) {
                        ex_start -= 1;
                        back += 1;
                    }
                }
                var ex_end = pos + pattern.len;
                {
                    var fwd: usize = 0;
                    while (ex_end < sec_data.len and fwd < radius and isPrintableAscii(sec_data[ex_end])) {
                        ex_end += 1;
                        fwd += 1;
                    }
                }

                // Compute the FULL printable run for full_length (unbounded by radius).
                var run_start = pos;
                while (run_start > 0 and isPrintableAscii(sec_data[run_start - 1])) run_start -= 1;
                var run_end = pos + pattern.len;
                while (run_end < sec_data.len and isPrintableAscii(sec_data[run_end])) run_end += 1;

                try results.hits.append(.{
                    .address = section.start + pos,
                    .excerpt = sec_data[ex_start..ex_end],
                    .full_length = run_end - run_start,
                    .segment_name = segment.name,
                });

                // Skip past the entire printable run to avoid duplicate matches
                // for the same logical string (the existing get_strings code does
                // the same — see tools.zig:5465).
                pos = run_end + 1;
            }
        }
    }

    return results;
}

fn isPrintableAscii(c: u8) bool {
    return (c >= 0x20 and c <= 0x7E) or c == '\n' or c == '\t';
}

fn isDataSegment(name: []const u8) bool {
    return std.mem.eql(u8, name, "__DATA") or
        std.mem.eql(u8, name, "__DATA_CONST") or
        std.mem.eql(u8, name, "__LINKEDIT") or
        std.mem.eql(u8, name, ".data") or
        std.mem.eql(u8, name, ".rodata");
}

fn isCodeSection(name: []const u8) bool {
    return std.mem.eql(u8, name, "__text") or
        std.mem.eql(u8, name, "__stubs") or
        std.mem.eql(u8, name, "__stub_helper") or
        std.mem.eql(u8, name, "__auth_stubs") or
        std.mem.eql(u8, name, ".text") or
        std.mem.eql(u8, name, ".plt");
}

fn isNonDataSection(name: []const u8) bool {
    return std.mem.eql(u8, name, "__unwind_info") or
        std.mem.eql(u8, name, "__auth_got") or
        std.mem.eql(u8, name, "__got") or
        std.mem.eql(u8, name, "__bss") or
        std.mem.eql(u8, name, ".got") or
        std.mem.eql(u8, name, ".bss") or
        std.mem.eql(u8, name, ".eh_frame");
}

fn isKnownStringSection(name: []const u8) bool {
    return std.mem.eql(u8, name, "__cstring") or
        std.mem.eql(u8, name, "__os_log") or
        std.mem.eql(u8, name, "__cfstring") or
        std.mem.eql(u8, name, "__const") or
        std.mem.eql(u8, name, ".rodata") or
        std.mem.eql(u8, name, ".dynstr") or
        std.mem.eql(u8, name, ".strtab") or
        std.mem.eql(u8, name, ".data.rel.ro") or
        std.mem.eql(u8, name, ".comment");
}

// ============================================================================
// Tests
// ============================================================================

test "detect simple strings (strict)" {
    const allocator = std.testing.allocator;

    // "Hello\0World\0ab\0" — "ab" is too short (< 4 chars)
    const data = "Hello\x00World\x00ab\x00test\x00";
    var result = try detectStrings(allocator, data, 0x1000, 4, false);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), result.items.len);
    try std.testing.expectEqualStrings("Hello", result.items[0].value);
    try std.testing.expectEqual(@as(u64, 0x1000), result.items[0].address);
    try std.testing.expectEqualStrings("World", result.items[1].value);
    try std.testing.expectEqual(@as(u64, 0x1006), result.items[1].address);
    try std.testing.expectEqualStrings("test", result.items[2].value);
    try std.testing.expectEqual(@as(u64, 0x100F), result.items[2].address);
}

test "no strings in binary data" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0x00, 0x01, 0x02, 0xFF, 0xFE, 0x03, 0x80, 0x90 };
    var result = try detectStrings(allocator, &data, 0x2000, 4, false);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "string at end without null terminator is not detected (strict)" {
    const allocator = std.testing.allocator;
    const data = "Hello";
    var result = try detectStrings(allocator, data, 0x3000, 4, false);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "minimum length boundary" {
    const allocator = std.testing.allocator;
    // "abc\0" is 3 chars, "abcd\0" is 4 chars
    const data = "abc\x00abcd\x00";
    var result = try detectStrings(allocator, data, 0x4000, 4, false);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.items.len);
    try std.testing.expectEqualStrings("abcd", result.items[0].value);
}

test "relaxed mode detects non-null-terminated strings" {
    const allocator = std.testing.allocator;
    // ELF .rodata style: strings separated by non-printable bytes (not null)
    const data = "Unity.Core\x01Shader.Load\xFF";
    var result = try detectStrings(allocator, data, 0x5000, 4, true);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqualStrings("Unity.Core", result.items[0].value);
    try std.testing.expectEqualStrings("Shader.Load", result.items[1].value);
}

test "relaxed mode still works with null-terminated strings" {
    const allocator = std.testing.allocator;
    const data = "Hello\x00World\x00";
    var result = try detectStrings(allocator, data, 0x6000, 4, true);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqualStrings("Hello", result.items[0].value);
    try std.testing.expectEqualStrings("World", result.items[1].value);
}

test "asar detection ignores analyzer vocabulary in generic string sections" {
    const allocator = std.testing.allocator;
    const data =
        ".asar\x00" ++
        "__asar\x00" ++
        "{bundle}/Contents/Resources/app.asar OR {bundle}/Contents/Resources/app/.webpack/main\x00" ++
        "{\"files\":{\"fixture.js\":{\"size\":1,\"offset\":\"0\"}}}\x00";

    const section = types.Section{
        .name = "__cstring",
        .start = 0x100000000,
        .length = data.len,
        .file_offset = 0,
    };
    var sections = [_]types.Section{section};

    const segment = types.Segment{
        .name = "__TEXT",
        .start = 0x100000000,
        .length = data.len,
        .sections = sections[0..],
        .permissions = .{ .read = true, .write = false, .execute = false },
        .file_offset = 0,
        .file_size = data.len,
    };
    var segments = [_]types.Segment{segment};

    var doc = types.Document.init(allocator, 1, "synthetic", data);
    defer doc.deinit();
    doc.segments = segments[0..];
    try doc.strings.append(.{ .address = 0x100000000, .value = ".asar", .length = 5 });
    try doc.strings.append(.{ .address = 0x100000006, .value = "__asar", .length = 6 });
    try doc.strings.append(.{
        .address = 0x10000000d,
        .value = "{bundle}/Contents/Resources/app.asar OR {bundle}/Contents/Resources/app/.webpack/main",
        .length = 84,
    });
    try doc.strings.append(.{
        .address = 0x100000062,
        .value = "{\"files\":{\"fixture.js\":{\"size\":1,\"offset\":\"0\"}}}",
        .length = 52,
    });

    try std.testing.expect(detectRuntime(&doc) == null);
}

test "asar detection accepts named ASAR region with archive path" {
    const allocator = std.testing.allocator;
    const data = "embedded asar bytes would live here";

    const section = types.Section{
        .name = "__payload",
        .start = 0x100000000,
        .length = data.len,
        .file_offset = 0,
    };
    var sections = [_]types.Section{section};

    const segment = types.Segment{
        .name = "__ASAR",
        .start = 0x100000000,
        .length = data.len,
        .sections = sections[0..],
        .permissions = .{ .read = true, .write = false, .execute = false },
        .file_offset = 0,
        .file_size = data.len,
    };
    var segments = [_]types.Segment{segment};

    var doc = types.Document.init(allocator, 1, "synthetic", data);
    defer doc.deinit();
    doc.segments = segments[0..];
    try doc.strings.append(.{
        .address = 0x200000000,
        .value = "/tmp/phora-demo/Contents/Resources/app.asar",
        .length = 50,
    });

    const runtime = detectRuntime(&doc) orelse return error.ExpectedAsarRuntime;
    try std.testing.expectEqualStrings("asar", runtime);
}

test "asar detection accepts pickle-backed archive manifest" {
    const allocator = std.testing.allocator;
    const data =
        "\x40\x00\x00\x00\x3c\x00\x00\x00" ++
        "{\"files\":{\"package.json\":{\"size\":42,\"offset\":\"0\"},\"main.js\":{\"size\":7,\"offset\":\"42\"}}}";

    const section = types.Section{
        .name = "__const",
        .start = 0x100000000,
        .length = data.len,
        .file_offset = 0,
    };
    var sections = [_]types.Section{section};

    const segment = types.Segment{
        .name = "__DATA",
        .start = 0x100000000,
        .length = data.len,
        .sections = sections[0..],
        .permissions = .{ .read = true, .write = false, .execute = false },
        .file_offset = 0,
        .file_size = data.len,
    };
    var segments = [_]types.Segment{segment};

    var doc = types.Document.init(allocator, 1, "synthetic", data);
    defer doc.deinit();
    doc.segments = segments[0..];

    const runtime = detectRuntime(&doc) orelse return error.ExpectedAsarRuntime;
    try std.testing.expectEqualStrings("asar", runtime);
}

test "searchPackedSegments finds substring inside __BUN with bounded excerpt" {
    const allocator = std.testing.allocator;

    // Build a synthetic Document with one __BUN section containing some JS-ish bytes.
    // The pattern "bypassPermissions" appears once, surrounded by lots of printable
    // text on both sides.
    const data =
        "var aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=function(){return\x00" ++
        "let mode=opts.bypassPermissions||opts.fallback;return mode;\x00" ++
        "function bbbbbbbbbbbbbbbbb(){return 0}\x00";

    const section = types.Section{
        .name = "__bundle",
        .start = 0x100000000,
        .length = data.len,
        .file_offset = 0,
    };
    var sections = [_]types.Section{section};

    const segment = types.Segment{
        .name = "__BUN",
        .start = 0x100000000,
        .length = data.len,
        .sections = sections[0..],
        .permissions = .{ .read = true, .write = false, .execute = false },
        .file_offset = 0,
        .file_size = data.len,
    };
    var segments = [_]types.Segment{segment};

    const doc = types.Document{
        .id = 1,
        .path = "synthetic",
        .format = .macho,
        .arch = .arm64,
        .entry_point = 0,
        .segments = segments[0..],
        .procedures = std.array_list.Managed(types.Procedure).init(allocator),
        .strings = std.array_list.Managed(types.String).init(allocator),
        .imports = std.array_list.Managed(types.Import).init(allocator),
        .annotations = std.array_list.Managed(types.Annotation).init(allocator),
        .data = data,
    };

    // Case 1: find the pattern with default options.
    var results = try searchPackedSegments(allocator, &doc, "bypassPermissions", .{});
    defer results.deinit();

    try std.testing.expectEqual(@as(usize, 1), results.hits.items.len);
    try std.testing.expectEqual(@as(usize, 1), results.scanned_segments.items.len);
    try std.testing.expectEqualStrings("__BUN", results.scanned_segments.items[0]);

    const hit = results.hits.items[0];
    // Address should be inside the section.
    try std.testing.expect(hit.address >= 0x100000000);
    try std.testing.expect(hit.address < 0x100000000 + data.len);
    // Excerpt must contain the pattern.
    try std.testing.expect(std.mem.indexOf(u8, hit.excerpt, "bypassPermissions") != null);
    // Excerpt must NOT exceed pattern.len + 2*radius (default radius=50).
    try std.testing.expect(hit.excerpt.len <= "bypassPermissions".len + 2 * 50);
    // Excerpt must NOT contain a null byte (the printable-run clamp must hold).
    try std.testing.expect(std.mem.indexOfScalar(u8, hit.excerpt, 0) == null);
}

test "searchPackedSegments returns empty when no packed segment exists" {
    const allocator = std.testing.allocator;

    // Same data, but the segment is named __DATA instead of __BUN.
    const data = "bypassPermissions appears here\x00";
    const section = types.Section{
        .name = "__const",
        .start = 0x100000000,
        .length = data.len,
        .file_offset = 0,
    };
    var sections = [_]types.Section{section};

    const segment = types.Segment{
        .name = "__DATA",
        .start = 0x100000000,
        .length = data.len,
        .sections = sections[0..],
        .permissions = .{ .read = true, .write = false, .execute = false },
        .file_offset = 0,
        .file_size = data.len,
    };
    var segments = [_]types.Segment{segment};

    const doc = types.Document{
        .id = 1,
        .path = "synthetic",
        .format = .macho,
        .arch = .arm64,
        .entry_point = 0,
        .segments = segments[0..],
        .procedures = std.array_list.Managed(types.Procedure).init(allocator),
        .strings = std.array_list.Managed(types.String).init(allocator),
        .imports = std.array_list.Managed(types.Import).init(allocator),
        .annotations = std.array_list.Managed(types.Annotation).init(allocator),
        .data = data,
    };

    var results = try searchPackedSegments(allocator, &doc, "bypassPermissions", .{});
    defer results.deinit();

    // No packed segment → no scan, no hits.
    try std.testing.expectEqual(@as(usize, 0), results.hits.items.len);
    try std.testing.expectEqual(@as(usize, 0), results.scanned_segments.items.len);

    // But scan_all=true should find it.
    var results_all = try searchPackedSegments(allocator, &doc, "bypassPermissions", .{ .scan_all = true });
    defer results_all.deinit();

    try std.testing.expectEqual(@as(usize, 1), results_all.hits.items.len);
    try std.testing.expectEqual(@as(usize, 1), results_all.scanned_segments.items.len);
}

test "searchPackedSegments respects max_results" {
    const allocator = std.testing.allocator;

    // Three matches separated by null terminators (so each is its own printable run).
    const data = "foofoofoo\x00xfoofoofoo\x00yfoofoofoo\x00";
    const section = types.Section{
        .name = "__bundle",
        .start = 0x100000000,
        .length = data.len,
        .file_offset = 0,
    };
    var sections = [_]types.Section{section};

    const segment = types.Segment{
        .name = "__BUN",
        .start = 0x100000000,
        .length = data.len,
        .sections = sections[0..],
        .permissions = .{ .read = true, .write = false, .execute = false },
        .file_offset = 0,
        .file_size = data.len,
    };
    var segments = [_]types.Segment{segment};

    const doc = types.Document{
        .id = 1,
        .path = "synthetic",
        .format = .macho,
        .arch = .arm64,
        .entry_point = 0,
        .segments = segments[0..],
        .procedures = std.array_list.Managed(types.Procedure).init(allocator),
        .strings = std.array_list.Managed(types.String).init(allocator),
        .imports = std.array_list.Managed(types.Import).init(allocator),
        .annotations = std.array_list.Managed(types.Annotation).init(allocator),
        .data = data,
    };

    var results = try searchPackedSegments(allocator, &doc, "foofoo", .{ .max_results = 2 });
    defer results.deinit();
    // 3 distinct printable runs each contain "foofoo" once → cap at 2.
    try std.testing.expectEqual(@as(usize, 2), results.hits.items.len);
}
