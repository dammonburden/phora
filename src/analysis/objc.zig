// Phora — Runtime Metadata Parser
// Parses Mach-O __objc_classlist section to recover class names, method names,
// protocol names, property names, and ivar names.
// Creates named procedures for discovered methods.

const std = @import("std");
const types = @import("../types.zig");
const db_mod = @import("../store/database.zig");

/// Result of ObjC metadata parsing.
pub const ObjcMetadata = struct {
    classes: []ObjcClass,
    protocols: []ObjcProtocol,

    pub fn deinit(self: *ObjcMetadata, allocator: std.mem.Allocator) void {
        for (self.classes) |*cls| cls.deinit(allocator);
        allocator.free(self.classes);
        for (self.protocols) |*proto| proto.deinit(allocator);
        allocator.free(self.protocols);
    }
};

pub const ObjcClass = struct {
    name: []const u8,
    superclass_name: ?[]const u8,
    methods: []ObjcMethod,
    properties: [][]const u8,
    ivars: [][]const u8,

    pub fn deinit(self: *ObjcClass, allocator: std.mem.Allocator) void {
        allocator.free(self.methods);
        allocator.free(self.properties);
        allocator.free(self.ivars);
    }
};

pub const ObjcMethod = struct {
    name: []const u8,
    impl_address: u64,
    /// Formatted as "-[ClassName methodName]" or "+[ClassName methodName]"
    full_name: []const u8,
};

pub const ObjcProtocol = struct {
    name: []const u8,
    methods: [][]const u8,

    pub fn deinit(self: *ObjcProtocol, allocator: std.mem.Allocator) void {
        allocator.free(self.methods);
    }
};

/// Parse ObjC metadata from a loaded document and register results in the database.
pub fn parseObjcMetadata(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    db: *db_mod.Database,
) !ObjcMetadata {
    var classes = std.array_list.Managed(ObjcClass).init(allocator);
    errdefer classes.deinit();
    var protocols = std.array_list.Managed(ObjcProtocol).init(allocator);
    errdefer protocols.deinit();

    // Find relevant sections
    const classlist_section = findSection(doc, "__DATA", "__objc_classlist") orelse
        findSection(doc, "__DATA_CONST", "__objc_classlist");
    const methnames_section = findSection(doc, "__TEXT", "__objc_methnames");
    const protolist_section = findSection(doc, "__DATA", "__objc_protolist") orelse
        findSection(doc, "__DATA_CONST", "__objc_protolist");

    // Parse classes from __objc_classlist
    if (classlist_section) |classlist| {
        const classlist_data = getSectionData(doc.data, classlist) orelse &.{};

        // __objc_classlist is an array of pointers (u64) to class_t structures
        var offset: usize = 0;
        while (offset + 8 <= classlist_data.len) : (offset += 8) {
            const class_ptr = readU64(classlist_data, offset);

            if (parseClass(allocator, doc.data, doc.segments, class_ptr, methnames_section, db)) |cls| {
                try classes.append(cls);
            } else |_| {
                // Skip classes we can't parse
            }
        }
    }

    // Parse protocols from __objc_protolist
    if (protolist_section) |protolist| {
        const protolist_data = getSectionData(doc.data, protolist) orelse &.{};

        var offset: usize = 0;
        while (offset + 8 <= protolist_data.len) : (offset += 8) {
            const proto_ptr = readU64(protolist_data, offset);

            if (parseProtocol(allocator, doc.data, doc.segments, proto_ptr)) |proto| {
                try protocols.append(proto);
            } else |_| {}
        }
    }

    return .{
        .classes = try classes.toOwnedSlice(),
        .protocols = try protocols.toOwnedSlice(),
    };
}

/// Parse a single ObjC class from its class_t pointer.
///
/// class_t layout (simplified, 64-bit):
///   +0:  isa pointer (u64)
///   +8:  superclass pointer (u64)
///   +16: cache (u64)
///   +24: vtable (u64)
///   +32: class_ro_t pointer (u64)  ← bits 0-2 may be flags, mask with ~7
///
/// class_ro_t layout (simplified):
///   +0:  flags (u32)
///   +4:  instanceStart (u32)
///   +8:  instanceSize (u32)
///   +12: reserved (u32)  — 64-bit only
///   +16: ivarLayout (u64)
///   +24: name (u64 pointer to C string)
///   +32: baseMethods (u64 pointer to method_list_t)
///   +40: baseProtocols (u64)
///   +48: ivars (u64 pointer to ivar_list_t)
///   +56: weakIvarLayout (u64)
///   +64: baseProperties (u64 pointer to property_list_t)
fn parseClass(
    allocator: std.mem.Allocator,
    data: []const u8,
    segments: []const types.Segment,
    class_ptr: u64,
    methnames_section: ?types.Section,
    db: *db_mod.Database,
) !ObjcClass {
    const class_offset = vmAddrToFileOffset(segments, class_ptr) orelse return error.InvalidPointer;
    if (class_offset + 40 > data.len) return error.TruncatedData;

    // Read class_ro_t pointer (at offset 32 in class_t)
    const ro_ptr_raw = readU64(data, class_offset + 32);
    const ro_ptr = ro_ptr_raw & ~@as(u64, 7); // mask off flag bits

    const ro_offset = vmAddrToFileOffset(segments, ro_ptr) orelse return error.InvalidPointer;
    if (ro_offset + 72 > data.len) return error.TruncatedData;

    // Read class name
    const name_ptr = readU64(data, ro_offset + 24);
    const class_name = readCString(data, segments, name_ptr) orelse "unknown_class";

    // Read base methods
    var methods = std.array_list.Managed(ObjcMethod).init(allocator);
    errdefer methods.deinit();

    const methods_ptr = readU64(data, ro_offset + 32);
    if (methods_ptr != 0) {
        try parseMethodList(allocator, data, segments, methods_ptr, class_name, methnames_section, &methods, db);
    }

    // Read ivars
    var ivars = std.array_list.Managed([]const u8).init(allocator);
    errdefer ivars.deinit();

    const ivars_ptr = readU64(data, ro_offset + 48);
    if (ivars_ptr != 0) {
        try parseIvarList(data, segments, ivars_ptr, &ivars);
    }

    // Read properties
    var properties = std.array_list.Managed([]const u8).init(allocator);
    errdefer properties.deinit();

    const props_ptr = readU64(data, ro_offset + 64);
    if (props_ptr != 0) {
        try parsePropertyList(data, segments, props_ptr, &properties);
    }

    return .{
        .name = class_name,
        .superclass_name = null,
        .methods = try methods.toOwnedSlice(),
        .properties = try properties.toOwnedSlice(),
        .ivars = try ivars.toOwnedSlice(),
    };
}

/// Parse method_list_t structure.
///
/// method_list_t layout:
///   +0:  flags/entsize (u32) — low bits are entry size, typically 24
///   +4:  count (u32)
///   +8:  methods[count] — each method_t is:
///         +0: name (u64 pointer or selector reference)
///         +8: types (u64 pointer to type encoding string)
///         +16: imp (u64 implementation address)
fn parseMethodList(
    allocator: std.mem.Allocator,
    data: []const u8,
    segments: []const types.Segment,
    list_ptr: u64,
    class_name: []const u8,
    methnames_section: ?types.Section,
    methods: *std.array_list.Managed(ObjcMethod),
    db: *db_mod.Database,
) !void {
    const list_offset = vmAddrToFileOffset(segments, list_ptr) orelse return;
    if (list_offset + 8 > data.len) return;

    const entsize_flags = readU32(data, list_offset);
    const count = readU32(data, list_offset + 4);

    // Entry size: low 16 bits, but handle relative method lists (flag bit 31)
    const is_relative = (entsize_flags & 0x80000000) != 0;
    const entry_size: usize = if (is_relative) 12 else 24; // relative methods are 3x u32

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const method_offset = list_offset + 8 + (i * @as(u32, @intCast(entry_size)));
        if (method_offset + entry_size > data.len) break;

        var method_name: []const u8 = "unknown";
        var impl_addr: u64 = 0;

        if (is_relative) {
            // Relative method list: 3x i32 offsets from the field's address
            const name_rel = readI32(data, method_offset);
            const impl_rel = readI32(data, method_offset + 8);

            // Name offset is relative to a selector reference, which points into __objc_methnames
            const name_ref_addr = list_ptr + 8 + (i * @as(u32, @intCast(entry_size)));
            const name_target = @as(u64, @intCast(@as(i64, @intCast(name_ref_addr)) + name_rel));

            // The name target is a selector ref — read the pointer it contains
            if (vmAddrToFileOffset(segments, name_target)) |name_target_off| {
                if (name_target_off + 8 <= data.len) {
                    const sel_ptr = readU64(data, name_target_off);
                    method_name = readCString(data, segments, sel_ptr) orelse "unknown";
                }
            }

            const impl_field_addr = name_ref_addr + 8;
            impl_addr = @intCast(@as(i64, @intCast(impl_field_addr)) + impl_rel);
        } else {
            // Absolute method list
            const name_ptr = readU64(data, method_offset);
            impl_addr = readU64(data, method_offset + 16);

            // name_ptr may point into __objc_methnames or be a selector ref
            method_name = readCString(data, segments, name_ptr) orelse "unknown";
            if (std.mem.eql(u8, method_name, "unknown") and methnames_section != null) {
                // Try reading as selector reference
                if (vmAddrToFileOffset(segments, name_ptr)) |ref_off| {
                    if (ref_off + 8 <= data.len) {
                        const sel_ptr = readU64(data, ref_off);
                        method_name = readCString(data, segments, sel_ptr) orelse "unknown";
                    }
                }
            }
        }

        // Format as -[ClassName methodName]
        const full_name = std.fmt.allocPrint(allocator, "-[{s} {s}]", .{ class_name, method_name }) catch method_name;

        try methods.append(.{
            .name = method_name,
            .impl_address = impl_addr,
            .full_name = full_name,
        });

        // Register as a procedure and symbol in the database
        if (impl_addr != 0) {
            try db.addProcedure(.{
                .entry = impl_addr,
                .size = 0, // will be determined by procedure detection
                .name = full_name,
            });
            try db.addSymbol(impl_addr, full_name);
        }
    }
}

/// Parse ivar_list_t structure.
///
/// ivar_list_t layout:
///   +0: entsize/count (u32/u32)
///   +8: ivars — each ivar_t is:
///        +0: offset pointer (u64)
///        +8: name (u64)
///        +16: type (u64)
///        +24: alignment_raw (u32)
///        +28: size (u32)
fn parseIvarList(
    data: []const u8,
    segments: []const types.Segment,
    list_ptr: u64,
    ivars: *std.array_list.Managed([]const u8),
) !void {
    const list_offset = vmAddrToFileOffset(segments, list_ptr) orelse return;
    if (list_offset + 8 > data.len) return;

    const count = readU32(data, list_offset + 4);

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const ivar_offset = list_offset + 8 + (i * 32);
        if (ivar_offset + 32 > data.len) break;

        const name_ptr = readU64(data, ivar_offset + 8);
        const name = readCString(data, segments, name_ptr) orelse continue;
        try ivars.append(name);
    }
}

/// Parse property_list_t structure.
///
/// property_list_t layout:
///   +0: entsize/count (u32/u32)
///   +8: properties — each property_t is:
///        +0: name (u64)
///        +8: attributes (u64)
fn parsePropertyList(
    data: []const u8,
    segments: []const types.Segment,
    list_ptr: u64,
    properties: *std.array_list.Managed([]const u8),
) !void {
    const list_offset = vmAddrToFileOffset(segments, list_ptr) orelse return;
    if (list_offset + 8 > data.len) return;

    const count = readU32(data, list_offset + 4);

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const prop_offset = list_offset + 8 + (i * 16);
        if (prop_offset + 16 > data.len) break;

        const name_ptr = readU64(data, prop_offset);
        const name = readCString(data, segments, name_ptr) orelse continue;
        try properties.append(name);
    }
}

/// Parse a protocol_t structure.
///
/// protocol_t layout (simplified):
///   +0:  isa (u64)
///   +8:  mangledName (u64 pointer)
///   +16: protocols (u64)
///   +24: instanceMethods (u64)
///   +32: classMethods (u64)
fn parseProtocol(
    allocator: std.mem.Allocator,
    data: []const u8,
    segments: []const types.Segment,
    proto_ptr: u64,
) !ObjcProtocol {
    const proto_offset = vmAddrToFileOffset(segments, proto_ptr) orelse return error.InvalidPointer;
    if (proto_offset + 40 > data.len) return error.TruncatedData;

    const name_ptr = readU64(data, proto_offset + 8);
    const name = readCString(data, segments, name_ptr) orelse "unknown_protocol";

    // Collect method names from instance and class methods
    var method_names = std.array_list.Managed([]const u8).init(allocator);
    errdefer method_names.deinit();

    const instance_methods_ptr = readU64(data, proto_offset + 24);
    if (instance_methods_ptr != 0) {
        try collectProtocolMethodNames(data, segments, instance_methods_ptr, &method_names);
    }

    const class_methods_ptr = readU64(data, proto_offset + 32);
    if (class_methods_ptr != 0) {
        try collectProtocolMethodNames(data, segments, class_methods_ptr, &method_names);
    }

    return .{
        .name = name,
        .methods = try method_names.toOwnedSlice(),
    };
}

fn collectProtocolMethodNames(
    data: []const u8,
    segments: []const types.Segment,
    list_ptr: u64,
    names: *std.array_list.Managed([]const u8),
) !void {
    const list_offset = vmAddrToFileOffset(segments, list_ptr) orelse return;
    if (list_offset + 8 > data.len) return;

    const count = readU32(data, list_offset + 4);

    // Protocol method descriptions are: name (u64) + types (u64) = 16 bytes each
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const entry_offset = list_offset + 8 + (i * 16);
        if (entry_offset + 16 > data.len) break;

        const name_ptr = readU64(data, entry_offset);
        const name = readCString(data, segments, name_ptr) orelse continue;
        try names.append(name);
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Find a section by segment name and section name.
fn findSection(doc: *const types.Document, segment_name: []const u8, section_name: []const u8) ?types.Section {
    for (doc.segments) |segment| {
        if (!std.mem.eql(u8, segment.name, segment_name)) continue;
        for (segment.sections) |section| {
            if (std.mem.eql(u8, section.name, section_name)) {
                return section;
            }
        }
    }
    return null;
}

/// Get the raw bytes for a section from the file data.
fn getSectionData(data: []const u8, section: types.Section) ?[]const u8 {
    const end = section.file_offset + section.length;
    if (section.file_offset >= data.len) return null;
    return data[section.file_offset..@min(end, data.len)];
}

/// Convert a VM address to a file offset using segment mappings.
fn vmAddrToFileOffset(segments: []const types.Segment, vm_addr: u64) ?usize {
    for (segments) |segment| {
        if (vm_addr >= segment.start and vm_addr < segment.start + segment.length) {
            const offset_in_segment = vm_addr - segment.start;
            return @intCast(segment.file_offset + offset_in_segment);
        }
    }
    return null;
}

/// Read a null-terminated C string from a VM address.
fn readCString(data: []const u8, segments: []const types.Segment, vm_addr: u64) ?[]const u8 {
    const file_offset = vmAddrToFileOffset(segments, vm_addr) orelse return null;
    if (file_offset >= data.len) return null;

    const remaining = data[file_offset..];
    const null_pos = std.mem.indexOfScalar(u8, remaining, 0) orelse return null;
    if (null_pos == 0) return null;
    return remaining[0..null_pos];
}

fn readU32(data: []const u8, offset: usize) u32 {
    if (offset + 4 > data.len) return 0;
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

fn readU64(data: []const u8, offset: usize) u64 {
    if (offset + 8 > data.len) return 0;
    return std.mem.readInt(u64, data[offset..][0..8], .little);
}

fn readI32(data: []const u8, offset: usize) i32 {
    if (offset + 4 > data.len) return 0;
    return std.mem.readInt(i32, data[offset..][0..4], .little);
}

// ============================================================================
// Tests
// ============================================================================

test "findSection returns null for missing section" {
    const allocator = std.testing.allocator;
    var doc = types.Document.init(allocator, 1, "/test", "");
    defer doc.deinit();

    try std.testing.expect(findSection(&doc, "__DATA", "__objc_classlist") == null);
}

test "readCString extracts string" {
    const data = "hello\x00world\x00";
    // We need a segment that maps VM addr 0 → file offset 0
    var sections = [_]types.Section{};
    var segments = [_]types.Segment{.{
        .name = "__TEXT",
        .start = 0,
        .length = data.len,
        .sections = &sections,
        .permissions = .{ .read = true },
        .file_offset = 0,
        .file_size = data.len,
    }};

    try std.testing.expectEqualStrings("hello", readCString(data, &segments, 0).?);
    try std.testing.expectEqualStrings("world", readCString(data, &segments, 6).?);
}

test "vmAddrToFileOffset" {
    var sections = [_]types.Section{};
    var segments = [_]types.Segment{.{
        .name = "__TEXT",
        .start = 0x100000000,
        .length = 0x1000,
        .sections = &sections,
        .permissions = .{ .read = true, .execute = true },
        .file_offset = 0,
        .file_size = 0x1000,
    }};

    try std.testing.expectEqual(@as(?usize, 0x100), vmAddrToFileOffset(&segments, 0x100000100));
    try std.testing.expect(vmAddrToFileOffset(&segments, 0x200000000) == null);
}
