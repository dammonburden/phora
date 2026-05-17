// Phora — Struct Layout / Type Recovery (W4 of v7.8.0)
// Given a set of lifted IR functions, look for pointer variables that are
// dereferenced at multiple offsets. Infer a struct with fields at those
// offsets. Output typedefs that pseudocode/decompile renderers can emit.
//
// Algorithm:
//   1. Scan load/store/compare statements for [VAR + OFFSET] memory operands.
//   2. Build a per-(function,variable) access set of (offset, width, r/w).
//   3. Cluster accesses into fields (overlapping offsets merge, wider wins).
//   4. Emit a struct per pointer variable with >=2 distinct offsets; merge
//      variables that share the exact same field layout so multiple
//      functions can share a typedef.
//   5. Single-hop cross-function propagation: if F calls G with var V as
//      arg0 and G's arg0 has a recovered struct, V inherits that type.

const std = @import("std");
const types = @import("../types.zig");

// ===========================================================================
// Public types (per spec)
// ===========================================================================

pub const InferredField = struct {
    /// Signed: negative offsets are valid for stack-frame structs (frame_<N>).
    offset: i32,
    /// 1, 2, 4, or 8 bytes.
    width: u8,
    /// e.g. "f_00", "f_08", "f_20"; or "f_n10" for negative-offset frames.
    name: []const u8,
    read_count: u32,
    write_count: u32,
};

pub const InferredStruct = struct {
    /// Name of the struct (e.g. "s_48" meaning a 48-byte struct).
    name: []const u8,
    /// Max observed offset + width.
    size_hint: u32,
    fields: []InferredField,
    /// Variables that Phora thinks are pointers to this struct type.
    /// Keys are "function_entry:variable_name", e.g. "0x1000:arg0".
    pointer_origins: [][]const u8,
};

pub const TypeRecoveryResult = struct {
    structs: []InferredStruct,
    /// Per-function per-variable type assignment:
    /// map key = "funcaddr:varname" -> struct name.
    variable_types: std.StringHashMap([]const u8),
};

// ===========================================================================
// Internal access record
// ===========================================================================

const RawAccess = struct {
    offset: i32,
    width: u8,
    is_read: bool,
    is_write: bool,
};

const ClusteredField = struct {
    offset: i32,
    width: u8,
    read_count: u32,
    write_count: u32,
};

const VarKey = []const u8; // "funcaddr:varname"

const VarInfo = struct {
    func_addr: u64,
    var_name: []const u8,
    accesses: std.array_list.Managed(RawAccess),
    /// Set after clustering.
    fields: []ClusteredField = &.{},
    /// Set after struct emission.
    struct_name: ?[]const u8 = null,
};

// ===========================================================================
// Operand parsing
// ===========================================================================

/// Skip negative offsets unless the variable name is one of these.
/// G2 (v7.8.3): only TRUE stack/frame pointers count. The `local_*` and
/// `stack_*` names from reg_to_var/stack_slot passes are renamed registers
/// or stack-slot identifiers — neither makes sense as a base for negative
/// pointer arithmetic, and including them caused a sign-wrap bug
/// (s_4294967210 absurd structs).
fn isStackLike(name: []const u8) bool {
    return std.mem.eql(u8, name, "stack_ptr") or
        std.mem.eql(u8, name, "frame_ptr") or
        std.mem.eql(u8, name, "sp") or
        std.mem.eql(u8, name, "fp") or
        std.mem.eql(u8, name, "x29");
}

/// Width hint from the full operand string. Returns 0 if no explicit hint.
fn widthFromHint(operand: []const u8) u8 {
    if (std.mem.indexOf(u8, operand, "byte ptr") != null) return 1;
    if (std.mem.indexOf(u8, operand, "word ptr") != null and
        std.mem.indexOf(u8, operand, "dword ptr") == null and
        std.mem.indexOf(u8, operand, "qword ptr") == null) return 2;
    if (std.mem.indexOf(u8, operand, "dword ptr") != null) return 4;
    if (std.mem.indexOf(u8, operand, "qword ptr") != null) return 8;
    return 0;
}

/// Width inferred from a register/variable name. Returns 0 if unknown.
/// ARM64: w0..w30 = 32-bit, x0..x30 = 64-bit, b0=8, h0=16, s0=32, d0=64.
/// x86_64: rax=8, eax=4, ax=2, al/ah=1.
fn widthFromVarName(name: []const u8) u8 {
    if (name.len < 2) return 0;
    const c0 = name[0];
    // ARM64 SIMD/scalar single-letter prefixes followed by digits.
    if ((c0 == 'w' or c0 == 'x' or c0 == 'b' or c0 == 'h' or c0 == 's' or c0 == 'd' or c0 == 'q') and
        std.ascii.isDigit(name[1]))
    {
        // Verify the rest is digits.
        var i: usize = 1;
        while (i < name.len) : (i += 1) {
            if (!std.ascii.isDigit(name[i])) return 0;
        }
        return switch (c0) {
            'b' => 1,
            'h' => 2,
            'w', 's' => 4,
            'x', 'd' => 8,
            'q' => 16, // capped to 8 by caller
            else => 0,
        };
    }
    // x86_64 GPRs: rax/rbx/.../rdi/rsi/r8..r15
    if (c0 == 'r' and name.len >= 2) {
        // r8..r15 with d/w/b suffix
        if (name.len >= 2 and std.ascii.isDigit(name[1])) {
            // r8..r15
            const last = name[name.len - 1];
            return switch (last) {
                'b' => 1,
                'w' => 2,
                'd' => 4,
                else => 8,
            };
        }
        // rax/rcx/rdx/rbx/rsi/rdi/rsp/rbp etc.
        if (name.len == 3) return 8;
    }
    if (c0 == 'e' and name.len == 3) return 4; // eax, ecx ...
    return 0;
}

/// Width hint from the load mnemonic (parsed from a leading hint like "ldrb",
/// "ldrh"). Not always available — we mostly rely on dest name.
fn widthFromLoadMnemonic(op: []const u8) u8 {
    if (std.mem.eql(u8, op, "ldrb") or std.mem.eql(u8, op, "strb")) return 1;
    if (std.mem.eql(u8, op, "ldrh") or std.mem.eql(u8, op, "strh")) return 2;
    if (std.mem.eql(u8, op, "ldrw") or std.mem.eql(u8, op, "strw")) return 4;
    return 0;
}

const ParsedRef = struct {
    var_name: []const u8,
    offset: i64,
};

/// Parse an operand of the form `[VAR + 0x18]`, `[VAR+8]`, `[VAR, #0x10]`,
/// `[VAR]`, `[VAR - 0x4]`. Returns null on no match.
/// Width hint and any qualifying prefixes (`byte ptr`) are not consumed here.
fn parseMemRef(operand: []const u8) ?ParsedRef {
    // Find the opening '['.
    const lb = std.mem.indexOfScalar(u8, operand, '[') orelse return null;
    const rb_rel = std.mem.indexOfScalarPos(u8, operand, lb + 1, ']') orelse return null;
    const inner = std.mem.trim(u8, operand[lb + 1 .. rb_rel], " \t");
    if (inner.len == 0) return null;

    // Variable: from start to first separator (',' '+' '-' or whitespace).
    var name_end: usize = 0;
    while (name_end < inner.len) : (name_end += 1) {
        const c = inner[name_end];
        if (c == ',' or c == '+' or c == '-' or c == ' ' or c == '\t') break;
    }
    if (name_end == 0) return null;
    const var_name = inner[0..name_end];

    // Anything after the name is the offset section. Find a sign.
    var rest = std.mem.trim(u8, inner[name_end..], " \t,");
    if (rest.len == 0) return .{ .var_name = var_name, .offset = 0 };

    var sign: i64 = 1;
    if (rest[0] == '+') {
        rest = std.mem.trim(u8, rest[1..], " \t");
    } else if (rest[0] == '-') {
        sign = -1;
        rest = std.mem.trim(u8, rest[1..], " \t");
    }
    // Optional '#'.
    if (rest.len > 0 and rest[0] == '#') rest = rest[1..];
    // Optional sign after '#'.
    if (rest.len > 0 and rest[0] == '-') {
        sign = -sign;
        rest = rest[1..];
    } else if (rest.len > 0 and rest[0] == '+') {
        rest = rest[1..];
    }
    if (rest.len == 0) return .{ .var_name = var_name, .offset = 0 };

    // Trim any trailing junk after the number (e.g. ", lsl #2").
    var num_end: usize = 0;
    if (rest.len >= 2 and rest[0] == '0' and (rest[1] == 'x' or rest[1] == 'X')) {
        num_end = 2;
        while (num_end < rest.len and std.ascii.isHex(rest[num_end])) : (num_end += 1) {}
    } else {
        while (num_end < rest.len and std.ascii.isDigit(rest[num_end])) : (num_end += 1) {}
    }
    if (num_end == 0) return .{ .var_name = var_name, .offset = 0 };
    const num_str = rest[0..num_end];

    const parsed: u64 = blk: {
        if (num_str.len >= 2 and num_str[0] == '0' and (num_str[1] == 'x' or num_str[1] == 'X')) {
            break :blk std.fmt.parseInt(u64, num_str[2..], 16) catch return .{ .var_name = var_name, .offset = 0 };
        } else {
            break :blk std.fmt.parseInt(u64, num_str, 10) catch return .{ .var_name = var_name, .offset = 0 };
        }
    };
    // G2 (v7.8.3): when the disassembler renders a negative i32 immediate as
    // unsigned hex (e.g. `[arg2 + 0xffffffa2]` for what's really -94), sign-
    // extend it back to a real negative i64 so the negative-offset filter in
    // isOffsetAcceptable can reject it (instead of keeping a 4-billion-offset
    // and emitting absurd structs like `s_4294967210`).
    const normalized: i64 = if (sign > 0 and parsed >= 0x80000000 and parsed <= 0xFFFFFFFF)
        @as(i64, @as(i32, @bitCast(@as(u32, @intCast(parsed)))))
    else
        sign * @as(i64, @bitCast(parsed));
    return .{ .var_name = var_name, .offset = normalized };
}

// ===========================================================================
// Public entry point
// ===========================================================================

pub fn recover(
    allocator: std.mem.Allocator,
    functions: []const types.IRFunction,
) !TypeRecoveryResult {
    // Map varKey -> *VarInfo. Owns the keys (we dupe).
    var var_map = std.StringHashMap(*VarInfo).init(allocator);
    defer var_map.deinit();

    // Backing store of VarInfos so pointers stay stable.
    var var_store = std.array_list.Managed(*VarInfo).init(allocator);
    defer var_store.deinit();

    // 1a. Seed VarInfos for every declared variable (so cross-function
    // propagation can later transfer a type onto e.g. caller's `arg0` even
    // when the caller doesn't dereference it itself).
    for (functions) |func| {
        for (func.variables) |v| {
            _ = try ensureVarInfo(allocator, &var_map, &var_store, func.address, v.name);
        }
    }

    // 1b. Pattern extraction from load/store/compare statements.
    for (functions) |func| {
        for (func.statements) |stmt| {
            try extractFromStatement(allocator, &var_map, &var_store, func.address, stmt);
        }
    }

    // 2. Cluster each variable's accesses into fields.
    for (var_store.items) |info| {
        info.fields = try clusterAccesses(allocator, info.accesses.items);
    }

    // 3. Struct emission. Group variables that share an identical field layout.
    var groups = std.StringHashMap(*StructGroup).init(allocator);
    defer {
        var it = groups.iterator();
        while (it.next()) |e| e.value_ptr.*.members.deinit();
        groups.deinit();
    }
    var group_store = std.array_list.Managed(*StructGroup).init(allocator);
    defer group_store.deinit();

    for (var_store.items) |info| {
        if (info.fields.len < 2) continue; // need >=2 distinct offsets

        // v7.13.0 B6b — suppress fabricated structs that look like raw
        // frame-spill slots. Pre-fix, /bin/mv emitted `s_3616` with 60+
        // single-byte fields covering a 3.5 KB stack frame — that's the
        // function's local register spill area, NOT a real struct. Heuristic:
        // (a) >20 distinct fields, (b) every field is 1 byte wide, (c) byte
        // density >= 90% (offsets densely packed). Combined this catches
        // dense byte-by-byte spill clusters without flagging real wide-field
        // structs (which have 4/8-byte fields).
        if (isLikelySpillCluster(info.fields)) continue;

        const sig = try fieldsSignature(allocator, info.fields);
        const gop = try groups.getOrPut(sig);
        if (!gop.found_existing) {
            const g = try allocator.create(StructGroup);
            g.* = .{
                .signature = sig,
                .fields = info.fields,
                .members = std.array_list.Managed(*VarInfo).init(allocator),
            };
            gop.value_ptr.* = g;
            try group_store.append(g);
        } else {
            // Free the duplicate signature buffer.
            allocator.free(sig);
        }
        try gop.value_ptr.*.members.append(info);
    }

    // Assign struct names. s_<size_hint>; if collision, suffix _b, _c...
    var name_counts = std.StringHashMap(u32).init(allocator);
    defer name_counts.deinit();

    for (group_store.items) |g| {
        const sz = sizeHint(g.fields);
        // v7.9.0: distinguish frame-relative (negative-offset) from
        // pointer-relative (all-positive) structs.
        // v7.12 W8(a): if ANY field has a negative offset, force the
        // frame_<N> name. The previous "all negative" gate was too lax —
        // mixed-sign field sets surfaced as `s_3712.f_nb0`, which makes no
        // sense as a generic struct typedef. A frame-relative struct may
        // include positive offsets too (callee args spilled above frame).
        const any_neg = blk: {
            for (g.fields) |f| if (f.offset < 0) break :blk true;
            break :blk false;
        };
        const base = if (any_neg)
            try std.fmt.allocPrint(allocator, "frame_{d}", .{sz})
        else
            try std.fmt.allocPrint(allocator, "s_{d}", .{sz});
        const gop = try name_counts.getOrPut(base);
        if (!gop.found_existing) {
            gop.value_ptr.* = 1;
            g.struct_name = base;
        } else {
            gop.value_ptr.* += 1;
            const n = gop.value_ptr.*;
            g.struct_name = try std.fmt.allocPrint(allocator, "{s}_{c}", .{ base, @as(u8, 'a' + @as(u8, @intCast(n - 1))) });
            // Don't free `base` here — it's still the key in name_counts.
        }
        for (g.members.items) |m| m.struct_name = g.struct_name;
    }

    // 4. Cross-function propagation (single hop):
    // If function F has a call statement with arg0 = some variable V (or
    // a temp that aliases V), and the callee G has a recovered struct on
    // its arg0, V inherits that struct.
    try propagateAcrossCalls(allocator, functions, var_store.items, var_map);

    // 5. Build the output.
    var structs = try allocator.alloc(InferredStruct, group_store.items.len);
    for (group_store.items, 0..) |g, i| {
        const named_fields = try allocator.alloc(InferredField, g.fields.len);
        for (g.fields, 0..) |f, j| {
            // v7.9.0: negative offsets get `f_n<abs>` so the field name is a
            // valid C identifier (e.g. `f_n20` for offset -0x20).
            const name = if (f.offset < 0)
                try std.fmt.allocPrint(allocator, "f_n{x:0>2}", .{@as(u32, @intCast(-f.offset))})
            else
                try std.fmt.allocPrint(allocator, "f_{x:0>2}", .{@as(u32, @intCast(f.offset))});
            named_fields[j] = .{
                .offset = f.offset,
                .width = f.width,
                .name = name,
                .read_count = f.read_count,
                .write_count = f.write_count,
            };
        }
        var origins = std.array_list.Managed([]const u8).init(allocator);
        for (g.members.items) |m| {
            const key = try std.fmt.allocPrint(allocator, "0x{x}:{s}", .{ m.func_addr, m.var_name });
            try origins.append(key);
        }
        structs[i] = .{
            .name = g.struct_name.?,
            .size_hint = sizeHint(g.fields),
            .fields = named_fields,
            .pointer_origins = try origins.toOwnedSlice(),
        };
    }

    var variable_types = std.StringHashMap([]const u8).init(allocator);
    for (var_store.items) |info| {
        if (info.struct_name) |sn| {
            const key = try std.fmt.allocPrint(allocator, "0x{x}:{s}", .{ info.func_addr, info.var_name });
            try variable_types.put(key, sn);
        }
    }

    return .{
        .structs = structs,
        .variable_types = variable_types,
    };
}

// ===========================================================================
// Pattern extraction
// ===========================================================================

const StructGroup = struct {
    signature: []const u8,
    fields: []ClusteredField,
    members: std.array_list.Managed(*VarInfo),
    struct_name: ?[]const u8 = null,
};

fn extractFromStatement(
    allocator: std.mem.Allocator,
    var_map: *std.StringHashMap(*VarInfo),
    var_store: *std.array_list.Managed(*VarInfo),
    func_addr: u64,
    stmt: types.IRStatement,
) !void {
    switch (stmt.type) {
        .load => {
            // dest = [src] -> read access on src's pointee.
            const mem = stmt.src orelse return;
            const ref = parseMemRef(mem) orelse return;
            if (!isOffsetAcceptable(ref)) return;
            var width = widthFromHint(mem);
            if (width == 0) {
                if (stmt.op) |o| width = widthFromLoadMnemonic(o);
            }
            if (width == 0) {
                if (stmt.dest) |d| width = widthFromVarName(d);
            }
            if (width == 0) width = 8;
            if (width > 8) width = 8;
            try addAccess(allocator, var_map, var_store, func_addr, ref.var_name, .{
                .offset = @as(i32, @intCast(ref.offset)),
                .width = width,
                .is_read = true,
                .is_write = false,
            });
        },
        .store => {
            // [dest] = src -> write access on dest's pointee.
            const mem = stmt.dest orelse return;
            const ref = parseMemRef(mem) orelse return;
            if (!isOffsetAcceptable(ref)) return;
            var width = widthFromHint(mem);
            if (width == 0) {
                if (stmt.op) |o| width = widthFromLoadMnemonic(o);
            }
            if (width == 0) {
                if (stmt.src) |s| width = widthFromVarName(s);
            }
            if (width == 0) width = 8;
            if (width > 8) width = 8;
            try addAccess(allocator, var_map, var_store, func_addr, ref.var_name, .{
                .offset = @intCast(ref.offset),
                .width = width,
                .is_read = false,
                .is_write = true,
            });
        },
        .compare => {
            // Compares can include `[var+off]` on either side.
            inline for (.{ stmt.dest, stmt.src }) |maybe_op| {
                if (maybe_op) |mem| {
                    if (parseMemRef(mem)) |ref| {
                        if (isOffsetAcceptable(ref)) {
                            var width = widthFromHint(mem);
                            if (width == 0) width = 8;
                            try addAccess(allocator, var_map, var_store, func_addr, ref.var_name, .{
                                .offset = @intCast(ref.offset),
                                .width = width,
                                .is_read = true,
                                .is_write = false,
                            });
                        }
                    }
                }
            }
        },
        else => {},
    }
}

fn isOffsetAcceptable(ref: ParsedRef) bool {
    // v7.9.0: re-allow negative offsets for true frame/stack pointers
    // (sp/fp/frame_ptr/x29/stack_ptr). InferredField.offset is now i32, so
    // there's no sign-wrap risk. Bound at -4096 to match the positive cap.
    // We deliberately do NOT broaden isStackLike to include local_*/stack_*
    // synthesized names — those are renamed registers and the v7.8.3 wrap
    // bug originated from accepting negatives on them.
    if (ref.offset < 0) {
        if (!isStackLike(ref.var_name)) return false;
        if (ref.offset <= -4096) return false;
        return true;
    }
    if (ref.offset >= 4096) return false; // likely global, not struct
    return true;
}

fn ensureVarInfo(
    allocator: std.mem.Allocator,
    var_map: *std.StringHashMap(*VarInfo),
    var_store: *std.array_list.Managed(*VarInfo),
    func_addr: u64,
    var_name: []const u8,
) !*VarInfo {
    const key = try std.fmt.allocPrint(allocator, "0x{x}:{s}", .{ func_addr, var_name });
    const gop = try var_map.getOrPut(key);
    if (!gop.found_existing) {
        const info = try allocator.create(VarInfo);
        info.* = .{
            .func_addr = func_addr,
            .var_name = try allocator.dupe(u8, var_name),
            .accesses = std.array_list.Managed(RawAccess).init(allocator),
        };
        gop.value_ptr.* = info;
        try var_store.append(info);
    } else {
        // The key string we just allocated is unused — free it.
        allocator.free(key);
    }
    return gop.value_ptr.*;
}

fn addAccess(
    allocator: std.mem.Allocator,
    var_map: *std.StringHashMap(*VarInfo),
    var_store: *std.array_list.Managed(*VarInfo),
    func_addr: u64,
    var_name: []const u8,
    acc: RawAccess,
) !void {
    const info = try ensureVarInfo(allocator, var_map, var_store, func_addr, var_name);
    try info.accesses.append(acc);
}

// ===========================================================================
// Clustering
// ===========================================================================

/// Sort accesses by offset, then merge accesses at the same offset into one
/// field. When widths differ at the same offset, the wider width wins
/// (represents the canonical field width).
fn clusterAccesses(
    allocator: std.mem.Allocator,
    accesses: []const RawAccess,
) ![]ClusteredField {
    if (accesses.len == 0) return &.{};

    // Copy + sort.
    const copy = try allocator.alloc(RawAccess, accesses.len);
    @memcpy(copy, accesses);
    std.mem.sort(RawAccess, copy, {}, struct {
        fn lt(_: void, a: RawAccess, b: RawAccess) bool {
            if (a.offset != b.offset) return a.offset < b.offset;
            return a.width > b.width; // wider first when offset ties
        }
    }.lt);

    var out = std.array_list.Managed(ClusteredField).init(allocator);
    errdefer out.deinit();

    var current: ClusteredField = .{
        .offset = copy[0].offset,
        .width = copy[0].width,
        .read_count = if (copy[0].is_read) 1 else 0,
        .write_count = if (copy[0].is_write) 1 else 0,
    };

    var i: usize = 1;
    while (i < copy.len) : (i += 1) {
        const a = copy[i];
        if (a.offset == current.offset) {
            // Same offset: fold counts; widen if needed.
            if (a.width > current.width) current.width = a.width;
            if (a.is_read) current.read_count += 1;
            if (a.is_write) current.write_count += 1;
        } else {
            try out.append(current);
            current = .{
                .offset = a.offset,
                .width = a.width,
                .read_count = if (a.is_read) 1 else 0,
                .write_count = if (a.is_write) 1 else 0,
            };
        }
    }
    try out.append(current);
    allocator.free(copy);
    return out.toOwnedSlice();
}

// ===========================================================================
// Struct emission helpers
// ===========================================================================

fn fieldsSignature(allocator: std.mem.Allocator, fields: []const ClusteredField) ![]u8 {
    var buf = std.Io.Writer.Allocating.init(allocator);
    errdefer buf.deinit();
    var w = &buf.writer;
    for (fields) |f| {
        try w.print("{d}:{d};", .{ f.offset, f.width });
    }
    return buf.toOwnedSlice();
}

/// v7.13.0 B6b — heuristic for fabricated spill-slot "structs". Returns true
/// when the field set looks like a dense byte-by-byte stack-spill cluster
/// (compiler-emitted register save area), NOT a real struct.
///
/// Criteria (ALL must hold):
///   - >20 distinct fields (real C structs rarely exceed 20 byte-fields).
///   - Every field is exactly 1 byte wide (real structs almost always have
///     wider members; pure 1-byte arrays would not be inferred as a struct).
///   - Density >= 50%: byte_count / span. Compiler spill clusters are usually
///     contiguous; sparse offsets at 1-byte width are even more clearly noise.
///
/// Field test repro: /bin/mv `s_3616` showed 60+ single-byte fields covering
/// the function's 3.5 KB stack frame. Post-fix, that struct is suppressed.
pub fn isLikelySpillCluster(fields: []const ClusteredField) bool {
    if (fields.len <= 20) return false;
    for (fields) |f| {
        if (f.width != 1) return false;
    }
    // Compute span: max(offset+width) - min(offset).
    var min: i32 = std.math.maxInt(i32);
    var max_end: i32 = std.math.minInt(i32);
    for (fields) |f| {
        if (f.offset < min) min = f.offset;
        const end = f.offset + @as(i32, f.width);
        if (end > max_end) max_end = end;
    }
    const span_i = max_end - min;
    if (span_i <= 0) return false;
    const span: u32 = @intCast(span_i);
    // v7.13.1 A1: relax density threshold and add sparse-large fallback.
    // Real frame-spill patterns are wider-dispersed than register spills (which
    // hit 90%+ density); /bin/mv s_3616 has 60 fields across a 3584-byte span
    // (~1.7% density) and slipped through the prior 50% gate.
    const dense_enough = fields.len * 10 >= span; // ~10% density (was 50%)
    const sparse_large = fields.len >= 40 and span < 8192; // sparse but plenty of fields
    if (!dense_enough and !sparse_large) return false;
    return true;
}

fn sizeHint(fields: []const ClusteredField) u32 {
    // v7.9.0: handle signed offsets. For frame-relative (all-negative)
    // structs, size = -min_offset + max_field_width (the span of the frame
    // region from the most-negative offset to fp+0). For positive structs,
    // size = max(offset+width). For mixed, fall back to magnitude span.
    var min: i32 = std.math.maxInt(i32);
    var max_end: i32 = std.math.minInt(i32);
    var max_w: u8 = 0;
    for (fields) |f| {
        if (f.offset < min) min = f.offset;
        const end = f.offset + @as(i32, f.width);
        if (end > max_end) max_end = end;
        if (f.width > max_w) max_w = f.width;
    }
    if (min >= 0) {
        return @as(u32, @intCast(@max(0, max_end)));
    }
    if (max_end <= 0) {
        // All-negative: frame-region size = -min + max_width
        return @as(u32, @intCast(-min)) + max_w;
    }
    // Mixed sign: use full span.
    const span = max_end - min;
    return @as(u32, @intCast(@max(0, span)));
}

// ===========================================================================
// Cross-function propagation (single hop)
// ===========================================================================

/// For each call statement in F passing var V as arg0, look up the callee G's
/// arg0 in the var_map. If G's arg0 has a recovered struct, transfer it to V
/// (provided V doesn't already have one).
fn propagateAcrossCalls(
    allocator: std.mem.Allocator,
    functions: []const types.IRFunction,
    var_infos: []const *VarInfo,
    var_map: std.StringHashMap(*VarInfo),
) !void {
    _ = allocator;
    _ = var_infos;

    // Build name -> function entry address map.
    var name_to_addr = std.StringHashMap(u64).init(var_map.allocator);
    defer name_to_addr.deinit();
    for (functions) |func| {
        if (func.name) |n| {
            try name_to_addr.put(n, func.address);
        }
    }

    for (functions) |func| {
        for (func.statements) |stmt| {
            if (stmt.type != .call) continue;
            const target = stmt.target orelse continue;
            const args = stmt.args orelse continue;
            if (args.len == 0) continue;

            // Resolve callee address: target is either a function name or "0x..."
            const callee_addr: u64 = blk: {
                if (name_to_addr.get(target)) |a| break :blk a;
                if (std.mem.startsWith(u8, target, "0x")) {
                    break :blk std.fmt.parseInt(u64, target[2..], 16) catch continue;
                }
                continue;
            };

            // Look up callee's arg0.
            const callee_key = try std.fmt.allocPrint(var_map.allocator, "0x{x}:arg0", .{callee_addr});
            defer var_map.allocator.free(callee_key);
            const callee_info = var_map.get(callee_key) orelse continue;
            const callee_struct = callee_info.struct_name orelse continue;

            // Look up caller's arg-0 variable in this call.
            const caller_arg = args[0];
            const caller_key = try std.fmt.allocPrint(var_map.allocator, "0x{x}:{s}", .{ func.address, caller_arg });
            defer var_map.allocator.free(caller_key);
            if (var_map.get(caller_key)) |caller_info| {
                if (caller_info.struct_name == null) {
                    caller_info.struct_name = callee_struct;
                }
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

test "parseMemRef: ARM64 [arg0 + 0x18]" {
    const r = parseMemRef("[arg0 + 0x18]").?;
    try std.testing.expectEqualStrings("arg0", r.var_name);
    try std.testing.expectEqual(@as(i64, 0x18), r.offset);
}

test "parseMemRef: ARM64 [arg0+8]" {
    const r = parseMemRef("[arg0+8]").?;
    try std.testing.expectEqualStrings("arg0", r.var_name);
    try std.testing.expectEqual(@as(i64, 8), r.offset);
}

test "parseMemRef: ARM64 [x0, #0x10]" {
    const r = parseMemRef("[x0, #0x10]").?;
    try std.testing.expectEqualStrings("x0", r.var_name);
    try std.testing.expectEqual(@as(i64, 0x10), r.offset);
}

test "parseMemRef: x86_64 [rdi+0x20]" {
    const r = parseMemRef("[rdi+0x20]").?;
    try std.testing.expectEqualStrings("rdi", r.var_name);
    try std.testing.expectEqual(@as(i64, 0x20), r.offset);
}

test "parseMemRef: dword ptr [rdi+0x20]" {
    const r = parseMemRef("dword ptr [rdi+0x20]").?;
    try std.testing.expectEqualStrings("rdi", r.var_name);
    try std.testing.expectEqual(@as(i64, 0x20), r.offset);
    try std.testing.expectEqual(@as(u8, 4), widthFromHint("dword ptr [rdi+0x20]"));
}

test "parseMemRef: bare [arg0]" {
    const r = parseMemRef("[arg0]").?;
    try std.testing.expectEqualStrings("arg0", r.var_name);
    try std.testing.expectEqual(@as(i64, 0), r.offset);
}

test "parseMemRef: negative [sp - 0x10]" {
    const r = parseMemRef("[sp - 0x10]").?;
    try std.testing.expectEqualStrings("sp", r.var_name);
    try std.testing.expectEqual(@as(i64, -0x10), r.offset);
}

test "G2: parseMemRef sign-extends i32-negative immediates rendered as unsigned hex" {
    // 0xffffffa2 in u32 is -94 in i32. The disassembler may render a -94
    // immediate as the unsigned hex 0xffffffa2; parseMemRef must NOT keep
    // it as a 4-billion offset (which would create absurd structs).
    const r = parseMemRef("[arg2 + 0xffffffa2]").?;
    try std.testing.expectEqualStrings("arg2", r.var_name);
    try std.testing.expectEqual(@as(i64, -94), r.offset);
}

test "G2: parseMemRef leaves small positive offsets alone" {
    const r = parseMemRef("[arg0 + 0x18]").?;
    try std.testing.expectEqualStrings("arg0", r.var_name);
    try std.testing.expectEqual(@as(i64, 0x18), r.offset);
}

test "widthFromVarName" {
    try std.testing.expectEqual(@as(u8, 8), widthFromVarName("x0"));
    try std.testing.expectEqual(@as(u8, 4), widthFromVarName("w19"));
    try std.testing.expectEqual(@as(u8, 8), widthFromVarName("rax"));
    try std.testing.expectEqual(@as(u8, 4), widthFromVarName("eax"));
    try std.testing.expectEqual(@as(u8, 0), widthFromVarName("arg0"));
    try std.testing.expectEqual(@as(u8, 0), widthFromVarName("tmp1"));
}

test "recover: single function with two distinct field accesses" {
    const allocator = std.testing.allocator;

    var stmts = [_]types.IRStatement{
        // x0 = [arg0 + 0x00]
        .{ .type = .load, .address = 0x1000, .dest = "x0", .src = "[arg0 + 0x00]" },
        // [arg0 + 0x08] = x1
        .{ .type = .store, .address = 0x1004, .dest = "[arg0 + 0x08]", .src = "x1" },
        // w2 = [arg0 + 0x10] (32-bit)
        .{ .type = .load, .address = 0x1008, .dest = "w2", .src = "[arg0 + 0x10]" },
        .{ .type = .@"return", .address = 0x100c },
    };
    var vars_list = [_]types.Variable{
        .{ .name = "arg0", .register = "x0" },
    };
    const func = types.IRFunction{
        .address = 0x1000,
        .name = "f1",
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const result = try recover(arena.allocator(), &.{func});

    try std.testing.expectEqual(@as(usize, 1), result.structs.len);
    const s = result.structs[0];
    try std.testing.expectEqual(@as(usize, 3), s.fields.len);
    try std.testing.expectEqual(@as(i32, 0), s.fields[0].offset);
    try std.testing.expectEqual(@as(i32, 8), s.fields[1].offset);
    try std.testing.expectEqual(@as(i32, 0x10), s.fields[2].offset);
    try std.testing.expectEqual(@as(u8, 4), s.fields[2].width); // w2 -> 4 bytes
    try std.testing.expectEqual(@as(u32, 0x10 + 4), s.size_hint);
    try std.testing.expectEqualStrings("s_20", s.name); // 0x14 = 20
    try std.testing.expectEqual(@as(usize, 1), s.pointer_origins.len);
    try std.testing.expectEqualStrings("0x1000:arg0", s.pointer_origins[0]);

    // Field naming: f_<hex offset zero-padded to 2>.
    try std.testing.expectEqualStrings("f_00", s.fields[0].name);
    try std.testing.expectEqualStrings("f_08", s.fields[1].name);
    try std.testing.expectEqualStrings("f_10", s.fields[2].name);

    // read/write counts.
    try std.testing.expectEqual(@as(u32, 1), s.fields[0].read_count);
    try std.testing.expectEqual(@as(u32, 0), s.fields[0].write_count);
    try std.testing.expectEqual(@as(u32, 0), s.fields[1].read_count);
    try std.testing.expectEqual(@as(u32, 1), s.fields[1].write_count);
}

test "recover: two functions with same layout share a struct" {
    const allocator = std.testing.allocator;

    var stmts1 = [_]types.IRStatement{
        .{ .type = .load, .address = 0x1000, .dest = "x0", .src = "[arg0+0]" },
        .{ .type = .load, .address = 0x1004, .dest = "x1", .src = "[arg0+8]" },
    };
    var vars1 = [_]types.Variable{.{ .name = "arg0", .register = "x0" }};
    const f1 = types.IRFunction{
        .address = 0x1000,
        .name = "f1",
        .statements = stmts1[0..],
        .variables = vars1[0..],
    };

    var stmts2 = [_]types.IRStatement{
        .{ .type = .load, .address = 0x2000, .dest = "x0", .src = "[arg0+0]" },
        .{ .type = .load, .address = 0x2004, .dest = "x1", .src = "[arg0+8]" },
    };
    var vars2 = [_]types.Variable{.{ .name = "arg0", .register = "x0" }};
    const f2 = types.IRFunction{
        .address = 0x2000,
        .name = "f2",
        .statements = stmts2[0..],
        .variables = vars2[0..],
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const result = try recover(arena.allocator(), &.{ f1, f2 });

    // Same layout -> a single struct with both functions as origins.
    try std.testing.expectEqual(@as(usize, 1), result.structs.len);
    try std.testing.expectEqual(@as(usize, 2), result.structs[0].pointer_origins.len);
    try std.testing.expectEqualStrings("s_16", result.structs[0].name);
}

test "recover: variable with single offset is not a struct" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .load, .address = 0x3000, .dest = "x0", .src = "[arg0+0]" },
        .{ .type = .load, .address = 0x3004, .dest = "x1", .src = "[arg0+0]" }, // same offset
    };
    var vars_list = [_]types.Variable{.{ .name = "arg0", .register = "x0" }};
    const func = types.IRFunction{
        .address = 0x3000,
        .name = "f3",
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const result = try recover(arena.allocator(), &.{func});
    try std.testing.expectEqual(@as(usize, 0), result.structs.len);
}

test "recover: skips offsets >= 4096 (global, not struct)" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .load, .address = 0x4000, .dest = "x0", .src = "[arg0+0]" },
        .{ .type = .load, .address = 0x4004, .dest = "x1", .src = "[arg0+0x2000]" },
    };
    var vars_list = [_]types.Variable{.{ .name = "arg0", .register = "x0" }};
    const func = types.IRFunction{
        .address = 0x4000,
        .name = "f4",
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const result = try recover(arena.allocator(), &.{func});
    // Only one valid offset survives -> not enough for a struct.
    try std.testing.expectEqual(@as(usize, 0), result.structs.len);
}

test "recover: cross-function propagation transfers struct from callee arg0" {
    const allocator = std.testing.allocator;

    // Callee g: derefs arg0 at 0 and 8.
    var g_stmts = [_]types.IRStatement{
        .{ .type = .load, .address = 0x2000, .dest = "x0", .src = "[arg0+0]" },
        .{ .type = .load, .address = 0x2004, .dest = "x1", .src = "[arg0+8]" },
    };
    var g_vars = [_]types.Variable{.{ .name = "arg0", .register = "x0" }};
    const g = types.IRFunction{
        .address = 0x2000,
        .name = "g",
        .statements = g_stmts[0..],
        .variables = g_vars[0..],
    };

    // Caller f: passes its own arg0 to g, and never derefs its arg0 itself.
    var args = [_][]const u8{"arg0"};
    var f_stmts = [_]types.IRStatement{
        .{ .type = .call, .address = 0x1000, .target = "g", .args = args[0..] },
        .{ .type = .@"return", .address = 0x1004 },
    };
    var f_vars = [_]types.Variable{.{ .name = "arg0", .register = "x0" }};
    const f = types.IRFunction{
        .address = 0x1000,
        .name = "f",
        .statements = f_stmts[0..],
        .variables = f_vars[0..],
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const result = try recover(arena.allocator(), &.{ f, g });

    // g produces a struct.
    try std.testing.expectEqual(@as(usize, 1), result.structs.len);
    const sname = result.structs[0].name;

    // f's arg0 inherits the struct via single-hop propagation.
    const f_type = result.variable_types.get("0x1000:arg0") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expectEqualStrings(sname, f_type);

    // g's arg0 is also typed.
    const g_type = result.variable_types.get("0x2000:arg0").?;
    try std.testing.expectEqualStrings(sname, g_type);
}

test "recover: width promotion when same offset accessed at multiple widths" {
    const allocator = std.testing.allocator;
    var stmts = [_]types.IRStatement{
        .{ .type = .load, .address = 0x5000, .dest = "w0", .src = "[arg0+0]" }, // 4 bytes
        .{ .type = .load, .address = 0x5004, .dest = "x1", .src = "[arg0+0]" }, // 8 bytes — wins
        .{ .type = .load, .address = 0x5008, .dest = "x2", .src = "[arg0+0x10]" },
    };
    var vars_list = [_]types.Variable{.{ .name = "arg0", .register = "x0" }};
    const func = types.IRFunction{
        .address = 0x5000,
        .name = "fwide",
        .statements = stmts[0..],
        .variables = vars_list[0..],
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const result = try recover(arena.allocator(), &.{func});
    try std.testing.expectEqual(@as(usize, 1), result.structs.len);
    try std.testing.expectEqual(@as(u8, 8), result.structs[0].fields[0].width);
    try std.testing.expectEqual(@as(u32, 2), result.structs[0].fields[0].read_count);
}
