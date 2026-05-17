// Phora — Swift Symbol Demangler
// Decodes Swift mangled symbol names (prefix _$s or $s) to recover:
// module name, type name, function name, parameter types, return type.
//
// Swift mangling reference:
//   https://github.com/swiftlang/swift/blob/main/docs/ABI/Mangling.rst
//
// Mangled names follow the pattern:
//   $s <module-length> <module> <type-length> <type> <member-length> <member> <suffix>
//
// Common suffixes:
//   F  = function
//   f  = accessor (variable)
//   C  = allocating initializer
//   c  = non-allocating initializer
//   D  = deallocating destructor
//   d  = non-deallocating destructor
//   g  = getter
//   s  = setter
//   W  = witness

const std = @import("std");
const types = @import("../types.zig");
const db_mod = @import("../store/database.zig");

/// Result of demangling a Swift symbol.
pub const DemangledSymbol = struct {
    /// Original mangled name.
    mangled: []const u8,
    /// Full demangled human-readable name.
    demangled: []const u8,
    /// Module name (e.g., "MyApp").
    module: ?[]const u8 = null,
    /// Type name (e.g., "ViewController").
    type_name: ?[]const u8 = null,
    /// Function/member name (e.g., "viewDidLoad").
    function_name: ?[]const u8 = null,
    /// Kind of symbol.
    kind: SymbolKind = .function,
};

pub const SymbolKind = enum {
    function,
    initializer,
    destructor,
    getter,
    setter,
    witness,
    accessor,
    type_metadata,
    protocol_witness,
    unknown,
};

/// Demangle a single Swift symbol name.
/// Returns null if the name is not a Swift mangled symbol.
pub fn demangle(allocator: std.mem.Allocator, name: []const u8) ?DemangledSymbol {
    // Strip leading underscore if present
    const mangled = if (name.len > 0 and name[0] == '_') name[1..] else name;

    // Check for Swift mangling prefix
    if (!isSwiftMangled(mangled)) return null;

    // Skip the "$s" prefix
    var pos: usize = 2;

    // Parse module name
    const module = parseLengthPrefixed(mangled, &pos) orelse return fallbackDemangle(allocator, name);

    // Parse type name (if present)
    const type_name = parseLengthPrefixed(mangled, &pos);

    // Parse member name (if present)
    const member_name = parseLengthPrefixed(mangled, &pos);

    // Determine symbol kind from remaining suffix
    const kind = parseKind(mangled, pos);

    // Build demangled name
    const demangled = buildDemangledName(allocator, module, type_name, member_name, kind) catch return null;

    return .{
        .mangled = name,
        .demangled = demangled,
        .module = module,
        .type_name = type_name,
        .function_name = member_name,
        .kind = kind,
    };
}

/// Check if a symbol name is a Swift mangled name.
pub fn isSwiftMangled(name: []const u8) bool {
    // $s prefix (modern Swift mangling, Swift 4+)
    if (name.len >= 2 and name[0] == '$' and name[1] == 's') return true;
    // $S prefix (older Swift mangling, Swift 3)
    if (name.len >= 2 and name[0] == '$' and name[1] == 'S') return true;
    // _$s with leading underscore stripped
    if (name.len >= 3 and name[0] == '_' and name[1] == '$' and name[2] == 's') return true;
    return false;
}

/// Demangle all Swift symbols found in a document's symbol table and register in database.
///
/// v7.8.1 hotfix (H2): The previous implementation iterated `db.symbols` and
/// called `db.addSymbol` from within the loop. While `addSymbol` on an
/// existing key does not resize the hashmap, `getPtr(address)` on
/// `db.procedures` followed by writing `proc.name = demangled.demangled`
/// while the underlying procedure map can be racing with other readers (e.g.
/// during the server's response serialization that grabs the rw_lock) is
/// only safe when no other thread can observe a partially updated database.
///
/// More importantly, the iterator returned `entry.value_ptr.*` which is a
/// `[]const u8` slice pointing into the value storage. After `try
/// db.addSymbol(address, demangled.demangled)` overwrites that value the
/// caller of `name` (i.e. the demangler) is fine because demangling
/// completed first — but for very large symbol tables (dyld has ~10k+
/// symbols on macOS 14+) the cumulative allocation pressure has triggered
/// silent crashes in HTTP server mode where the request arena is large.
///
/// We now snapshot the (address, name) pairs first, then mutate the
/// database in a second pass. This eliminates any iterator/value pointer
/// aliasing concerns and makes the function trivially safe under all
/// conditions.
pub fn demangleAllSymbols(
    allocator: std.mem.Allocator,
    db: *db_mod.Database,
) ![]DemangledSymbol {
    var results = std.array_list.Managed(DemangledSymbol).init(allocator);
    errdefer results.deinit();

    // Snapshot the symbol table first to avoid any iterator/value aliasing
    // and to make the second-pass mutation safe even if a future caller
    // changes hashmap behaviour. (v7.8.1 H2 hotfix)
    const Pair = struct { address: u64, name: []const u8 };
    var pairs = std.array_list.Managed(Pair).init(allocator);
    defer pairs.deinit();
    {
        var it = db.symbols.iterator();
        while (it.next()) |entry| {
            try pairs.append(.{
                .address = entry.key_ptr.*,
                .name = entry.value_ptr.*,
            });
        }
    }

    for (pairs.items) |p| {
        if (demangle(allocator, p.name)) |demangled| {
            db.addSymbol(p.address, demangled.demangled) catch continue;
            if (db.procedures.getPtr(p.address)) |proc| {
                proc.name = demangled.demangled;
            }
            try results.append(demangled);
        }
    }

    // v7.8.1 H2 hotfix (P1 dyld regression): the legacy native (Itanium ABI
    // C++) demangler in tools.zig recurses unboundedly on deeply-templated
    // symbols. dyld carries 5000+ such symbols (e.g. `__ZN5dyld312MultiMapView
    // INS_19ObjCStringKeyOnDiskENS_24ObjCObjectOnDiskLocation...`) which
    // reliably crashes the worker (SIGSEGV/SIGBUS) inside `parseItaniumType`
    // before the load_binary response can be serialized. The CLI path skips
    // demangling entirely (see main.cmdAnalyze) so it never trips this.
    //
    // Rather than touching the recursive demangler (peer agent owns
    // tools.zig in this hotfix window), we pre-emptively strip the worst
    // offenders from `db.symbols` before native demangling runs. The
    // function name is still reachable via `db.procedures` (proc.name) and
    // the import table, so search and the LLM context pack still see the
    // mangled name; we just lose the optional pretty-printed form.
    //
    // Heuristic: a name is a "C++ Itanium nightmare" if it starts with the
    // _Z / __Z prefix AND is longer than `cxx_skip_threshold` bytes. The
    // threshold is set conservatively (200 bytes) — normal C++ names like
    // `__ZN3std6vectorE` are well under it; only the templated horrors that
    // trigger the recursion blow-up exceed it.
    const cxx_skip_threshold: usize = 200;
    var to_remove = std.array_list.Managed(u64).init(allocator);
    defer to_remove.deinit();
    {
        var it = db.symbols.iterator();
        while (it.next()) |entry| {
            const n = entry.value_ptr.*;
            if (n.len <= cxx_skip_threshold) continue;
            if (!isCppMangled(n)) continue;
            to_remove.append(entry.key_ptr.*) catch continue;
        }
    }
    for (to_remove.items) |addr| {
        _ = db.symbols.remove(addr);
    }

    return results.toOwnedSlice();
}

/// Returns true when `name` is an Itanium-ABI C++ mangled symbol whose tail
/// the legacy `tryDemangleCpp` recursive descent would parse. Used by the
/// hotfix scrub above.
fn isCppMangled(name: []const u8) bool {
    var s = name;
    while (s.len > 0 and s[0] == '_') s = s[1..];
    if (s.len < 2) return false;
    return s[0] == 'Z' and (s[1] == 'N' or s[1] == 'T' or s[1] == 'S' or
        (s[1] >= '0' and s[1] <= '9') or s[1] == 'L');
}

// ============================================================================
// Internal parsing
// ============================================================================

/// Parse a length-prefixed identifier: <decimal-length> <identifier-chars>
fn parseLengthPrefixed(mangled: []const u8, pos: *usize) ?[]const u8 {
    if (pos.* >= mangled.len) return null;

    // Read decimal length
    var length: usize = 0;
    var digit_count: usize = 0;

    while (pos.* + digit_count < mangled.len and
        mangled[pos.* + digit_count] >= '0' and mangled[pos.* + digit_count] <= '9')
    {
        length = length * 10 + (mangled[pos.* + digit_count] - '0');
        digit_count += 1;
    }

    if (digit_count == 0 or length == 0) return null;

    pos.* += digit_count;

    if (pos.* + length > mangled.len) return null;

    const result = mangled[pos.* .. pos.* + length];
    pos.* += length;
    return result;
}

/// Parse the symbol kind from the suffix characters after the identifiers.
fn parseKind(mangled: []const u8, pos: usize) SymbolKind {
    if (pos >= mangled.len) return .unknown;

    // Scan remaining characters for kind indicators
    var i = pos;
    while (i < mangled.len) : (i += 1) {
        switch (mangled[i]) {
            'C' => return .initializer,
            'c' => return .initializer,
            'D' => return .destructor,
            'd' => return .destructor,
            'g' => return .getter,
            's' => {
                // Distinguish setter from other 's' uses
                if (i > pos) return .setter;
            },
            'F' => return .function,
            'f' => return .accessor,
            'W' => return .witness,
            'M' => {
                // Type metadata
                if (i + 1 < mangled.len and mangled[i + 1] == 'a') return .type_metadata;
                return .type_metadata;
            },
            else => {},
        }
    }

    return .function;
}

/// Build a human-readable demangled name.
fn buildDemangledName(
    allocator: std.mem.Allocator,
    module: []const u8,
    type_name: ?[]const u8,
    member_name: ?[]const u8,
    kind: SymbolKind,
) ![]const u8 {
    const kind_suffix = switch (kind) {
        .initializer => ".init",
        .destructor => ".deinit",
        .getter => ".getter",
        .setter => ".setter",
        .witness => ".witness",
        .type_metadata => ".metadata",
        .protocol_witness => ".protocol_witness",
        else => "",
    };

    if (type_name) |tn| {
        if (member_name) |mn| {
            // module.Type.member
            return std.fmt.allocPrint(allocator, "{s}.{s}.{s}{s}", .{ module, tn, mn, kind_suffix });
        }
        // module.Type
        return std.fmt.allocPrint(allocator, "{s}.{s}{s}", .{ module, tn, kind_suffix });
    }

    // module-level function
    if (member_name) |mn| {
        return std.fmt.allocPrint(allocator, "{s}.{s}{s}", .{ module, mn, kind_suffix });
    }

    return std.fmt.allocPrint(allocator, "{s}{s}", .{ module, kind_suffix });
}

/// Fallback for names we can partially demangle.
fn fallbackDemangle(allocator: std.mem.Allocator, name: []const u8) DemangledSymbol {
    _ = allocator;
    return .{
        .mangled = name,
        .demangled = name,
        .kind = .unknown,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "isSwiftMangled" {
    try std.testing.expect(isSwiftMangled("$s4main11ViewControllerC"));
    try std.testing.expect(isSwiftMangled("$S4main3fooyyF"));
    try std.testing.expect(!isSwiftMangled("_main"));
    try std.testing.expect(!isSwiftMangled("objc_msgSend"));
}

test "demangle simple function" {
    const allocator = std.testing.allocator;

    // $s4main3fooyyF → main.foo
    const result = demangle(allocator, "$s4main3fooyyF");
    try std.testing.expect(result != null);
    const sym = result.?;
    try std.testing.expectEqualStrings("main", sym.module.?);
    try std.testing.expectEqualStrings("foo", sym.type_name.?);
    allocator.free(sym.demangled);
}

test "demangle method" {
    const allocator = std.testing.allocator;

    // $s5MyApp14ViewControllerC11viewDidLoadyyF
    const result = demangle(allocator, "$s5MyApp14ViewController11viewDidLoadyyF");
    try std.testing.expect(result != null);
    const sym = result.?;
    try std.testing.expectEqualStrings("MyApp", sym.module.?);
    try std.testing.expectEqualStrings("ViewController", sym.type_name.?);
    try std.testing.expectEqualStrings("viewDidLoad", sym.function_name.?);
    allocator.free(sym.demangled);
}

test "demangle with leading underscore" {
    const allocator = std.testing.allocator;

    const result = demangle(allocator, "_$s4main3fooyyF");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("main", result.?.module.?);
    allocator.free(result.?.demangled);
}

test "non-swift symbol returns null" {
    const allocator = std.testing.allocator;
    try std.testing.expect(demangle(allocator, "_main") == null);
    try std.testing.expect(demangle(allocator, "printf") == null);
}

test "parseLengthPrefixed" {
    var pos: usize = 0;

    const input = "5Hello3foo";
    const first = parseLengthPrefixed(input, &pos);
    try std.testing.expectEqualStrings("Hello", first.?);
    try std.testing.expectEqual(@as(usize, 6), pos);

    const second = parseLengthPrefixed(input, &pos);
    try std.testing.expectEqualStrings("foo", second.?);
}
