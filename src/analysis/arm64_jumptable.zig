// Conservative ARM64 computed-jump recovery. Proofs come from instruction
// encodings and a forward fixed point over reachable control flow, never from
// guessed table lengths or a virtual-address-minus-image-base file offset.
const std = @import("std");
const types = @import("../types.zig");
const arm64 = @import("../arch/arm64.zig");
const jt = @import("jumptable.zig");

const max_entries = 4096;
const Bound = struct { max: u64, full: bool, default: ?u64 = null };
const Table = struct {
    address: u64,
    count: u32,
    width: u8,
    signed: bool,
    wide: bool,
    default: ?u64,
    base: u64 = 0,
};
const Value = union(enum) {
    unknown,
    unknown32,
    constant: u64,
    bound: Bound,
    entry: Table,
    dispatch: Table,
};
const Guard = struct { reg: u5, max: u64, wide: bool, cmp_address: u64 };
const State = struct {
    regs: [31]Value = @splat(.unknown),
    guard: ?Guard = null,
};

/// Return one contiguous, file-backed mapped span. Sections are authoritative
/// when present; segment fallback is restricted to its declared file size.
pub fn mappedBytes(doc: *const types.Document, address: u64, length: u64) ?[]const u8 {
    for (doc.segments) |seg| {
        if (address < seg.start or address - seg.start >= seg.length) continue;
        if (length > seg.length - (address - seg.start)) return null;
        if (seg.sections.len != 0) {
            for (seg.sections) |sec| {
                if (address < sec.start or address - sec.start >= sec.length) continue;
                if (sec.is_zerofill or length > sec.length - (address - sec.start)) return null;
                const off = std.math.add(u64, sec.file_offset, address - sec.start) catch return null;
                if (seg.file_size != 0 and (off < seg.file_offset or off - seg.file_offset > seg.file_size or length > seg.file_size - (off - seg.file_offset))) return null;
                return fileBytes(doc.data, off, length);
            }
            return null;
        }
        const delta = address - seg.start;
        if (delta > seg.file_size or length > seg.file_size - delta or length > seg.length - delta) return null;
        const off = std.math.add(u64, seg.file_offset, delta) catch return null;
        return fileBytes(doc.data, off, length);
    }
    return null;
}

fn fileBytes(data: []const u8, offset: u64, length: u64) ?[]const u8 {
    if (offset > data.len or length > data.len - offset) return null;
    return data[@intCast(offset)..][0..@intCast(length)];
}

fn wordAt(doc: *const types.Document, address: u64, entry: u64, end: u64) ?u32 {
    if (address % 4 != 0 or address < entry or address >= end or end - address < 4) return null;
    const code_end = doc.codeRangeEnd(address) orelse return null;
    if (code_end - address < 4) return null;
    const bytes = mappedBytes(doc, address, 4) orelse return null;
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn readCases(allocator: std.mem.Allocator, doc: *const types.Document, table: Table, entry: u64, end: u64) !?[]jt.JumpTableCase {
    if (table.count == 0 or table.count > max_entries or (table.width != 1 and table.width != 2)) return null;
    var read_only = false;
    for (doc.segments) |segment| {
        if (table.address >= segment.start and table.address - segment.start < segment.length) {
            read_only = segment.permissions.read and !segment.permissions.write;
            break;
        }
    }
    if (!read_only) return null;
    const bytes = mappedBytes(doc, table.address, @as(u64, table.count) * table.width) orelse return null;
    if (table.width == 2 and table.address % 2 != 0) return null;
    const cases = try allocator.alloc(jt.JumpTableCase, table.count);
    errdefer allocator.free(cases);
    for (cases, 0..) |*c, i| {
        const raw: u16 = if (table.width == 1) bytes[i] else std.mem.readInt(u16, bytes[i * 2 ..][0..2], .little);
        const displacement: i128 = if (!table.signed) raw else if (table.width == 1) @as(i8, @bitCast(@as(u8, @intCast(raw)))) else @as(i16, @bitCast(raw));
        const target_wide = @as(i128, table.base) + displacement * 4;
        if (target_wide < 0 or target_wide > std.math.maxInt(u64)) {
            allocator.free(cases);
            return null;
        }
        const target: u64 = @intCast(target_wide);
        const insn = wordAt(doc, target, entry, end) orelse {
            allocator.free(cases);
            return null;
        };
        const decoded = arm64.decode(mappedBytes(doc, target, 4).?, target);
        _ = insn;
        if (std.mem.eql(u8, decoded.mnemonic, "udf") or std.mem.eql(u8, decoded.mnemonic, "unsupported")) {
            allocator.free(cases);
            return null;
        }
        c.* = .{ .value = @intCast(i), .target = target };
    }
    return cases;
}

fn join(a: Value, b: Value) Value {
    if (std.meta.eql(a, b)) return a;
    const ab = asBound(a);
    const bb = asBound(b);
    if (ab != null and bb != null) return .{ .bound = .{ .max = @max(ab.?.max, bb.?.max), .full = ab.?.full and bb.?.full, .default = if (ab.?.default == bb.?.default) ab.?.default else null } };
    if (is32(a) and is32(b)) return .unknown32;
    return .unknown;
}

fn asBound(value: Value) ?Bound {
    return switch (value) {
        .bound => |b| b,
        .constant => |v| .{ .max = v, .full = true },
        else => null,
    };
}

fn is32(value: Value) bool {
    return switch (value) {
        .unknown32 => true,
        .constant => |v| v <= std.math.maxInt(u32),
        .bound => |b| b.full and b.max <= std.math.maxInt(u32),
        else => false,
    };
}

fn propagate(states: *std.AutoHashMap(u64, State), work: *std.array_list.Managed(u64), address: u64, state: State, entry: u64, end: u64) !void {
    if (address < entry or address >= end or address % 4 != 0) return;
    const result = try states.getOrPut(address);
    if (!result.found_existing) {
        result.value_ptr.* = state;
        try work.append(address);
        return;
    }
    var merged = result.value_ptr.*;
    for (&merged.regs, state.regs) |*a, b| a.* = join(a.*, b);
    if (!std.meta.eql(merged.guard, state.guard)) merged.guard = null;
    if (!std.meta.eql(merged, result.value_ptr.*)) {
        result.value_ptr.* = merged;
        try work.append(address);
    }
}

fn regValue(state: State, reg: u5) Value {
    return if (reg == 31) .{ .constant = 0 } else state.regs[reg];
}

fn putReg(state: *State, reg: u5, value: Value) void {
    if (reg != 31) state.regs[reg] = value;
}

fn logicalMask(insn: u32) ?u64 {
    const wide = insn >> 31 != 0;
    const n = (insn >> 22) & 1;
    if (!wide and n != 0) return null;
    const imms = (insn >> 10) & 63;
    const selector = (n << 6) | ((~imms) & 63);
    if (selector < 2) return null;
    const len = 31 - @clz(selector);
    const width: u32 = @as(u32, 1) << @as(u5, @intCast(len));
    const s = imms & (width - 1);
    if (s == width - 1) return null;
    const r = ((insn >> 16) & 63) & (width - 1);
    const mask = @as(u64, std.math.maxInt(u64)) >> @as(u6, @intCast(64 - width));
    var element = (@as(u64, 1) << @as(u6, @intCast(s + 1))) - 1;
    if (r != 0) element = ((element >> @as(u6, @intCast(r))) | (element << @as(u6, @intCast(width - r)))) & mask;
    var value: u64 = 0;
    var shift: u32 = 0;
    while (shift < (if (wide) @as(u32, 64) else 32)) : (shift += width) value |= element << @as(u6, @intCast(shift));
    return value;
}

/// Transfer only precisely modeled values. The generic cases preserve
/// untouched GPRs only for known integer instruction classes; unmodeled
/// instructions invalidate all facts, including flags.
fn transfer(input: State, insn: u32, address: u64, decoded: arm64.DecodedInstruction) State {
    var out = input;
    out.guard = null;
    const rd: u5 = @truncate(insn);
    const rn: u5 = @truncate(insn >> 5);
    const rm: u5 = @truncate(insn >> 16);
    const wide = insn >> 31 != 0;
    if (std.mem.eql(u8, decoded.mnemonic, "udf") or std.mem.eql(u8, decoded.mnemonic, "unsupported")) return .{};
    // ADR and ADRP: signed displacement, checked rather than wrapping.
    if ((insn & 0x1f000000) == 0x10000000) {
        const imm21: u21 = @truncate((((insn >> 5) & 0x7ffff) << 2) | ((insn >> 29) & 3));
        const delta: i128 = @as(i21, @bitCast(imm21));
        const page = insn & 0x80000000 != 0;
        const target = @as(i128, if (page) address & ~@as(u64, 4095) else address) + delta * @as(i128, if (page) 4096 else 1);
        putReg(&out, rd, if (target >= 0 and target <= std.math.maxInt(u64)) .{ .constant = @intCast(target) } else .unknown);
        return out;
    }
    // AND immediate bounds the exact destination, including zero extension.
    if ((insn & 0x7f800000) == 0x12000000) {
        const mask = logicalMask(insn) orelse return .{};
        // Dense compiler dispatch masks are contiguous low bits. A sparse
        // mask does not establish the reported dense table index domain.
        const dense = mask != std.math.maxInt(u64) and (mask & (mask + 1)) == 0;
        putReg(&out, rd, if (dense) .{ .bound = .{ .max = mask, .full = true } } else if (wide) .unknown else .unknown32);
        return out;
    }
    // ADD/SUB immediate. A CMP immediate records the flag-producing register.
    if ((insn & 0x1f000000) == 0x11000000) {
        const immediate: u64 = @as(u64, (insn >> 10) & 4095) << @as(u6, if (insn & 0x00400000 != 0) 12 else 0);
        if ((insn & 0x6000001f) == 0x6000001f and rn != 31) {
            out.guard = .{ .reg = rn, .max = immediate, .wide = wide, .cmp_address = address };
            return out;
        }
        const src = regValue(input, rn);
        var result: Value = if (wide) .unknown else .unknown32;
        if (rn != 31 and src == .constant) {
            const v = if (insn & 0x40000000 == 0) std.math.add(u64, src.constant, immediate) catch null else std.math.sub(u64, src.constant, immediate) catch null;
            if (v) |x| result = .{ .constant = if (wide) x else x & 0xffffffff };
        }
        putReg(&out, rd, result);
        return out;
    }
    // MOV register (ORR Rd,ZR,Rm) with no shift. W writes zero high bits.
    if ((insn & 0x7fe0ffe0) == 0x2a0003e0) {
        var value = regValue(input, rm);
        if (!wide) {
            value = switch (value) {
                .constant => |v| .{ .constant = v & 0xffffffff },
                .bound => |b| .{ .bound = .{ .max = @min(b.max, 0xffffffff), .full = true, .default = b.default } },
                .entry => |t| if (t.signed) .unknown32 else value,
                else => .unknown32,
            };
        }
        putReg(&out, rd, value);
        return out;
    }
    // Integer register-offset byte/halfword load. No signed index extension.
    if ((insn & 0x3f200c00) == 0x38200800 and insn & 0x04000000 == 0) {
        const size = insn >> 30;
        const opc = (insn >> 22) & 3;
        const option = (insn >> 13) & 7;
        const scaled = insn & 0x1000 != 0;
        var result: Value = if (size == 3 or opc == 2) .unknown else .unknown32;
        const base = regValue(input, rn);
        const bound = asBound(regValue(input, rm));
        if (size <= 1 and opc != 0 and rn != 31 and rm != 31 and base == .constant and bound != null and
            (option == 2 or option == 3) and (option == 2 or bound.?.full) and
            (!scaled or size == 1) and (size != 1 or scaled) and bound.?.max < max_entries)
        {
            result = .{ .entry = .{ .address = base.constant, .count = @intCast(bound.?.max + 1), .width = @as(u8, 1) << @as(u3, @intCast(size)), .signed = opc >= 2, .wide = opc == 2, .default = bound.?.default } };
        }
        if (opc != 0) putReg(&out, rd, result);
        return out;
    }
    // ADD Xd,Xbase,Xentry,LSL #2 or Wentry,UXTW/SXTW #2.
    if ((insn & 0xff200000) == 0x8b000000 or (insn & 0xff200000) == 0x8b200000) {
        const base = regValue(input, rn);
        const offset = regValue(input, rm);
        var result: Value = .unknown;
        const extended = insn & 0x00200000 != 0;
        const valid_scale = if (!extended) (insn & 0x00c0fc00) == 0x00000800 else (insn & 0x00c00000) == 0 and ((insn >> 10) & 7) == 2 and ((insn >> 13) & 7 == 2 or (insn >> 13) & 7 == 6);
        if (rn != 31 and rm != 31 and base == .constant and offset == .entry and valid_scale) {
            const t = offset.entry;
            const valid_sign = if (!extended) !t.signed or t.wide else if (((insn >> 13) & 7) == 6) t.signed and !t.wide else !t.signed;
            if (valid_sign) {
                var table = t;
                table.base = base.constant;
                result = .{ .dispatch = table };
            }
        }
        putReg(&out, rd, result);
        return out;
    }
    // Branches do not write tracked registers (calls invalidate everything).
    if (decoded.is_call) return .{};
    if (decoded.is_branch or decoded.is_return) return out;
    if (insn == 0xd503201f or (insn & 0xfffffc1f) == 0xd503241f) return out; // NOP/BTI
    const major = (insn >> 25) & 15;
    if (major == 8 or major == 9 or major == 5 or major == 13) {
        putReg(&out, rd, if (wide) .unknown else .unknown32);
        return out;
    }
    // Integer/SIMD pair load/store: loads write both destinations; writeback
    // also writes the address register. SIMD destinations are not GPRs.
    if ((insn & 0x3a000000) == 0x28000000) {
        if (insn & 0x00400000 != 0 and insn & 0x04000000 == 0) {
            const value: Value = if ((insn >> 30) == 0) .unknown32 else .unknown;
            putReg(&out, rd, value);
            putReg(&out, @truncate(insn >> 10), value);
        }
        const mode = (insn >> 23) & 3;
        if (mode == 1 or mode == 3) putReg(&out, rn, .unknown);
        return out;
    }
    // Ordinary immediate loads/stores, excluding atomic/exclusive encodings.
    if ((insn & 0x3b000000) == 0x39000000 or (insn & 0x3b200000) == 0x38000000) {
        const opc = (insn >> 22) & 3;
        if (opc != 0 and insn & 0x04000000 == 0) putReg(&out, rd, if (insn >> 30 == 3 or opc == 2) .unknown else .unknown32);
        if (insn & 0x01000000 == 0) {
            const mode = (insn >> 10) & 3;
            if (mode == 1 or mode == 3) putReg(&out, rn, .unknown);
        }
        return out;
    }
    return .{};
}

/// Recover only tables proven after convergence. All returned cases are aligned
/// decoded code inside this procedure; any invalid entry rejects the whole table.
/// The result and its case arrays belong to allocator.
pub fn recover(allocator: std.mem.Allocator, doc: *const types.Document, entry: u64, size: u64) ![]jt.JumpTable {
    if (doc.arch != .arm64 or size == 0) return allocator.alloc(jt.JumpTable, 0);
    const end = std.math.add(u64, entry, size) catch return allocator.alloc(jt.JumpTable, 0);
    var states = std.AutoHashMap(u64, State).init(allocator);
    defer states.deinit();
    var work = std.array_list.Managed(u64).init(allocator);
    defer work.deinit();
    try propagate(&states, &work, entry, .{}, entry, end);
    var steps: usize = 0;
    while (work.pop()) |address| {
        steps += 1;
        // A resource limit is a refusal, never a partially proven result.
        if (steps > 200000) return allocator.alloc(jt.JumpTable, 0);
        const insn = wordAt(doc, address, entry, end) orelse continue;
        const decoded = arm64.decode(mappedBytes(doc, address, 4).?, address);
        if (std.mem.eql(u8, decoded.mnemonic, "udf") or std.mem.eql(u8, decoded.mnemonic, "unsupported")) continue;
        const input = states.get(address).?;
        var output = transfer(input, insn, address, decoded);
        if (decoded.is_return) continue;
        if ((insn & 0xfffffc1f) == 0xd61f0000) {
            const reg: u5 = @truncate(insn >> 5);
            const value = regValue(input, reg);
            if (value == .dispatch) {
                const cases = (try readCases(allocator, doc, value.dispatch, entry, end)) orelse continue;
                defer allocator.free(cases);
                for (cases) |c| try propagate(&states, &work, c.target, output, entry, end);
            }
            continue;
        }
        if (decoded.is_branch and !decoded.is_call) {
            if (decoded.branch_target) |target| try propagate(&states, &work, target, output, entry, end);
            if (!decoded.is_conditional_branch) continue;
            // Only the immediate CMP's unsigned out-of-range fallthrough can
            // refine the compared index. Signed branches never imply a bound.
            if ((insn & 0xff000010) == 0x54000000 and input.guard != null and input.guard.?.cmp_address + 4 == address) {
                const cond = insn & 15;
                if (cond == 8 or cond == 2) {
                    const g = input.guard.?;
                    const max = if (cond == 8) g.max else std.math.sub(u64, g.max, 1) catch continue;
                    const prior = regValue(input, g.reg);
                    const prior_bound = asBound(prior);
                    putReg(&output, g.reg, .{ .bound = .{ .max = if (prior_bound) |b| @min(max, b.max) else max, .full = g.wide or is32(prior), .default = decoded.branch_target } });
                }
            }
        }
        try propagate(&states, &work, address + 4, output, entry, end);
    }
    var result = std.array_list.Managed(jt.JumpTable).init(allocator);
    errdefer {
        for (result.items) |table| allocator.free(table.cases);
        result.deinit();
    }
    var it = states.iterator();
    while (it.next()) |node| {
        const address = node.key_ptr.*;
        const insn = wordAt(doc, address, entry, end) orelse continue;
        if ((insn & 0xfffffc1f) != 0xd61f0000) continue;
        const value = regValue(node.value_ptr.*, @truncate(insn >> 5));
        if (value != .dispatch) continue;
        const t = value.dispatch;
        const cases = (try readCases(allocator, doc, t, entry, end)) orelse continue;
        errdefer allocator.free(cases);
        try result.append(.{ .branch_addr = address, .table_addr = t.address, .entry_count = t.count, .entry_width = t.width, .entries_are_absolute = false, .base_addr = t.base, .cases = cases, .default_target = t.default });
    }
    // A reachable unknown indirect jump can reenter any dispatch without
    // passing its guard. Recovery is therefore valid only for a closed graph:
    // every reachable indirect exit must have a fully validated target set.
    // Likewise, an undecoded instruction cannot establish control-flow closure.
    var closed = true;
    var reachable = states.keyIterator();
    while (reachable.next()) |key| {
        const address = key.*;
        _ = wordAt(doc, address, entry, end) orelse {
            closed = false;
            break;
        };
        const decoded = arm64.decode(mappedBytes(doc, address, 4).?, address);
        if (std.mem.eql(u8, decoded.mnemonic, "udf") or std.mem.eql(u8, decoded.mnemonic, "unsupported")) {
            closed = false;
            break;
        }
        if (decoded.is_branch and !decoded.is_call and !decoded.is_return and decoded.branch_target == null) {
            var resolved = false;
            for (result.items) |table| if (table.branch_addr == address) {
                resolved = true;
                break;
            };
            if (!resolved) {
                closed = false;
                break;
            }
        }
    }
    if (!closed) {
        for (result.items) |table| allocator.free(table.cases);
        result.deinit();
        return allocator.alloc(jt.JumpTable, 0);
    }
    std.mem.sort(jt.JumpTable, result.items, {}, struct {
        fn less(_: void, a: jt.JumpTable, b: jt.JumpTable) bool {
            return a.branch_addr < b.branch_addr;
        }
    }.less);
    return result.toOwnedSlice();
}

fn testPut(data: []u8, offset: usize, word: u32) void {
    std.mem.writeInt(u32, data[offset..][0..4], word, .little);
}

fn testAdr(rd: u5, from: u64, to: u64) u32 {
    const displacement: i21 = @intCast(@as(i64, @intCast(to)) - @as(i64, @intCast(from)));
    const imm: u21 = @bitCast(displacement);
    return 0x10000000 | (@as(u32, imm & 3) << 29) | (@as(u32, imm >> 2) << 5) | rd;
}

fn testFixture() [160]u8 {
    var data: [160]u8 = @splat(0);
    @memcpy(data[0x20..][0..4], &[_]u8{ 0, 1, 2, 3 });
    testPut(&data, 0x40, 0x12000403); // and w3,w0,#3
    testPut(&data, 0x44, testAdr(10, 0x1004, 0x3000));
    testPut(&data, 0x48, testAdr(11, 0x1008, 0x1030));
    testPut(&data, 0x4c, 0x3863694c); // ldrb w12,[x10,x3]
    testPut(&data, 0x50, 0x8b0c096b); // add x11,x11,x12,lsl#2
    testPut(&data, 0x54, 0xd61f0160); // br x11
    for (0..4) |i| testPut(&data, 0x70 + i * 4, 0xd65f03c0);
    return data;
}

fn testDocument(data: []const u8, segments: []types.Segment) types.Document {
    var doc = types.Document.init(std.testing.allocator, 0, "test", data);
    doc.segments = segments;
    return doc;
}

test "recovery: mapped ARM64 table discovers case blocks and deduplicates edges" {
    const allocator = std.testing.allocator;
    var data = testFixture();
    data[0x23] = 1; // duplicate destination
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x40, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 4, .file_offset = 0x20, .is_code = false },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x2004, .file_size = data.len, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    var doc = testDocument(&data, &segments);
    defer doc.deinit();
    const tables = try recover(allocator, &doc, 0x1000, 0x40);
    defer jt.freeRecoveredTables(allocator, tables);
    try std.testing.expectEqual(@as(usize, 1), tables.len);
    try std.testing.expectEqual(@as(u64, 0x3000), tables[0].table_addr);
    try std.testing.expectEqual(@as(u32, 4), tables[0].entry_count);
    try std.testing.expectEqual(@as(u64, 0x1030), tables[0].cases[0].target);
    const cfg = @import("cfg.zig");
    const decode = struct {
        fn call(bytes: []const u8, address: u64) cfg.DecodedInstruction {
            return cfg.fromArm64Decoded(arm64.decode(bytes, address), address);
        }
    }.call;
    var result = try cfg.buildCfgWithRecovery(allocator, &doc, 0x40, 0x1000, 0x1000, 0x40, decode);
    defer cfg.freeCfgResult(allocator, &result);
    try std.testing.expectEqual(@as(usize, 4), result.basic_blocks.len);
    try std.testing.expectEqual(@as(usize, 3), result.edges.len);
    try std.testing.expectEqual(@as(usize, 3), result.basic_blocks[0].successors.len);
    for (result.basic_blocks[1..]) |block| try std.testing.expectEqual(@as(usize, 1), block.predecessors.len);
}

test "recovery: signed and unsigned byte and halfword offsets use checked scale four" {
    const allocator = std.testing.allocator;
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x40, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 8, .file_offset = 0x20, .is_code = false },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x2008, .file_size = 160, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    for (0..6) |variant| {
        const half = variant % 2 == 1;
        const signed = variant < 4;
        const extended = variant >= 2 and variant < 4;
        var data = testFixture();
        testPut(&data, 0x48, testAdr(11, 0x1008, if (signed) 0x1038 else 0x1030));
        const load: u32 = if (extended) 0x38e3694c else if (signed) 0x38a3694c else 0x3863694c;
        testPut(&data, 0x4c, load | (if (half) @as(u32, 0x40001000) else 0));
        if (extended) testPut(&data, 0x50, 0x8b2cc96b); // add x11,x11,w12,sxtw#2
        if (half) {
            for (0..4) |i| {
                const offset: i16 = @as(i16, @intCast(i)) - @as(i16, if (signed) 2 else 0);
                std.mem.writeInt(u16, data[0x20 + i * 2 ..][0..2], @bitCast(offset), .little);
            }
        } else if (signed) @memcpy(data[0x20..][0..4], &[_]u8{ 254, 255, 0, 1 });
        var doc = testDocument(&data, &segments);
        defer doc.deinit();
        const tables = try recover(allocator, &doc, 0x1000, 0x40);
        defer jt.freeRecoveredTables(allocator, tables);
        try std.testing.expectEqual(@as(usize, 1), tables.len);
        try std.testing.expectEqual(@as(u8, if (half) 2 else 1), tables[0].entry_width);
        for (tables[0].cases, 0..) |case, i| try std.testing.expectEqual(0x1030 + @as(u64, @intCast(i)) * 4, case.target);
    }
}

test "recovery: rejects unknown bounds wrong flow clobbers truncated nonlocal invalid tables" {
    const allocator = std.testing.allocator;
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x40, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 4, .file_offset = 0x20, .is_code = false },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x2004, .file_size = 160, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    for (0..12) |variant| {
        var data = testFixture();
        sections[1].length = 4;
        sections[1].is_zerofill = false;
        segments[0].permissions.write = false;
        switch (variant) {
            0 => testPut(&data, 0x40, 0xd503201f), // missing mask
            1 => testPut(&data, 0x4c, 0x3864694c), // wrong index
            2 => testPut(&data, 0x48, 0xd280000a), // clobber table base
            3 => testPut(&data, 0x50, 0x8b0d096b), // wrong loaded offset
            4 => testPut(&data, 0x54, 0xd61f0180), // wrong branch register
            5 => sections[1].length = 3, // declared truncated table
            6 => data[0x23] = 255, // nonlocal target
            7 => testPut(&data, 0x70, 0), // invalid target instruction
            8 => sections[1].is_zerofill = true,
            9 => testPut(&data, 0x40, 0x12003c03), // mask #65535: impossible count
            10 => segments[0].permissions.write = true, // runtime-mutable table
            11 => testPut(&data, 0x40, 0x121e0403), // AND W3,W0,#12: sparse mask
            else => unreachable,
        }
        var doc = testDocument(&data, &segments);
        defer doc.deinit();
        const tables = try recover(allocator, &doc, 0x1000, 0x40);
        defer jt.freeRecoveredTables(allocator, tables);
        try std.testing.expectEqual(@as(usize, 0), tables.len);
    }
}

test "recovery: exact unsigned guard index width flags and control flow" {
    const allocator = std.testing.allocator;
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x40, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 4, .file_offset = 0x20, .is_code = false },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x2004, .file_size = 160, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    for (0..9) |variant| {
        var data = testFixture();
        testPut(&data, 0x40, 0xf1000c7f); // cmp x3,#3
        testPut(&data, 0x44, 0x540001c8); // b.hi 0x103c
        testPut(&data, 0x48, testAdr(10, 0x1008, 0x3000));
        testPut(&data, 0x4c, testAdr(11, 0x100c, 0x1030));
        testPut(&data, 0x50, 0x3863694c);
        testPut(&data, 0x54, 0x8b0c096b);
        testPut(&data, 0x58, 0xd61f0160);
        var expected: usize = 0;
        switch (variant) {
            0 => expected = 1,
            1 => { // unsigned HS uses N, not N+1 entries
                testPut(&data, 0x40, 0xf100107f); // cmp x3,#4
                testPut(&data, 0x44, 0x540001c2);
                expected = 1;
            },
            2 => testPut(&data, 0x44, 0x540001cc), // signed GT
            3 => testPut(&data, 0x40, 0xf1000c9f), // cmp different register
            4 => testPut(&data, 0x48, 0x91000463), // clobber bounded index
            5 => testPut(&data, 0x44, 0xd503201f), // no conditional guard
            6 => testPut(&data, 0x40, 0x71000c7f), // W guard cannot bound high X bits
            7 => { // W guard does prove W,UXTW indexing
                testPut(&data, 0x40, 0x71000c7f);
                testPut(&data, 0x50, 0x3863494c);
                expected = 1;
            },
            8 => testPut(&data, 0x44, 0x54000028), // guard target=fallthrough; no bound
            else => unreachable,
        }
        var doc = testDocument(&data, &segments);
        defer doc.deinit();
        const tables = try recover(allocator, &doc, 0x1000, 0x40);
        defer jt.freeRecoveredTables(allocator, tables);
        try std.testing.expectEqual(expected, tables.len);
        if (expected != 0) {
            try std.testing.expectEqual(@as(u32, 4), tables[0].entry_count);
            try std.testing.expectEqual(@as(?u64, 0x103c), tables[0].default_target);
        }
    }
}

test "recovery: joins all reachable inputs and refuses bypassed guard or clobbered table base" {
    const allocator = std.testing.allocator;
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x80, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 4, .file_offset = 0x20, .is_code = false },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x2004, .file_size = 192, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    for (0..3) |variant| {
        const clobber = variant == 1;
        const indirect = variant == 2;
        var data: [192]u8 = @splat(0);
        @memcpy(data[0..160], &testFixture());
        testPut(&data, 0x40, 0x34000180); // cbz w0,0x1030
        testPut(&data, 0x44, 0x12000403); // and w3,w0,#3
        testPut(&data, 0x48, testAdr(10, 0x1008, 0x3000));
        testPut(&data, 0x4c, testAdr(11, 0x100c, 0x1060));
        testPut(&data, 0x50, 0x1400000c); // b0x1040
        testPut(&data, 0x70, if (clobber) 0x12000403 else 0xd503201f); // alternate unbounded path
        testPut(&data, 0x74, testAdr(10, 0x1034, if (clobber) 0x3001 else 0x3000));
        testPut(&data, 0x78, testAdr(11, 0x1038, 0x1060));
        // An unknown X4 may equal 0x1040 and reenter the dispatch with
        // unbounded W3; an unresolved BR is not evidence of an external exit.
        testPut(&data, 0x7c, if (indirect) 0xd61f0080 else 0x14000001);
        testPut(&data, 0x80, 0x3863694c);
        testPut(&data, 0x84, 0x8b0c096b);
        testPut(&data, 0x88, 0xd61f0160);
        for (0..4) |i| testPut(&data, 0xa0 + i * 4, 0xd65f03c0);
        var doc = testDocument(&data, &segments);
        defer doc.deinit();
        const tables = try recover(allocator, &doc, 0x1000, 0x80);
        defer jt.freeRecoveredTables(allocator, tables);
        try std.testing.expectEqual(@as(usize, 0), tables.len);
    }
}

test "recovery: mapped spans reject overflow truncated backing and zerofill" {
    const allocator = std.testing.allocator;
    var data = testFixture();
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x40, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 4, .file_offset = std.math.maxInt(u64) - 1 },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x2004, .file_size = 160, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    var doc = testDocument(&data, &segments);
    defer doc.deinit();
    try std.testing.expect(mappedBytes(&doc, 0x3002, 2) == null);
    sections[1].file_offset = data.len - 2;
    try std.testing.expect(mappedBytes(&doc, 0x3000, 4) == null);
    const tables = try recover(allocator, &doc, std.math.maxInt(u64) - 3, 8);
    defer jt.freeRecoveredTables(allocator, tables);
    try std.testing.expectEqual(@as(usize, 0), tables.len);
    segments[0].sections = &.{};
    segments[0].file_size = 2;
    try std.testing.expect(mappedBytes(&doc, 0x1000, 4) == null);
}

fn allocationCheck(backing: std.mem.Allocator) !void {
    // Disable in-place remapping so allocator reuse cannot change the number
    // of failure points between exhaustive fault-injection runs.
    var no_remap = std.testing.FailingAllocator.init(backing, .{ .resize_fail_index = 0 });
    const allocator = no_remap.allocator();
    var data = testFixture();
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x40, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 4, .file_offset = 0x20, .is_code = false },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x2004, .file_size = data.len, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    var doc = types.Document.init(allocator, 0, "test", &data);
    doc.segments = &segments;
    defer doc.deinit();
    const cfg = @import("cfg.zig");
    const decode = struct {
        fn call(bytes: []const u8, address: u64) cfg.DecodedInstruction {
            return cfg.fromArm64Decoded(arm64.decode(bytes, address), address);
        }
    }.call;
    var result = try cfg.buildCfgWithRecovery(allocator, &doc, 0x40, 0x1000, 0x1000, 0x40, decode);
    defer cfg.freeCfgResult(allocator, &result);
}

test "recovery: releases temporary states cases and partial CFG on every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCheck, .{});
}

test "recovery: relative arithmetic refuses underflow overflow and misaligned halfwords" {
    const allocator = std.testing.allocator;
    var data = testFixture();
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x40, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 4, .file_offset = 0x20, .is_code = false },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x2004, .file_size = data.len, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    var doc = testDocument(&data, &segments);
    defer doc.deinit();
    const overflow = Table{ .address = 0x3000, .count = 4, .width = 1, .signed = false, .wide = false, .default = null, .base = std.math.maxInt(u64) - 1 };
    try std.testing.expect((try readCases(allocator, &doc, overflow, 0x1000, 0x1040)) == null);
    var underflow = overflow;
    underflow.base = 0;
    underflow.signed = true;
    data[0x20] = 255;
    try std.testing.expect((try readCases(allocator, &doc, underflow, 0x1000, 0x1040)) == null);
    var unaligned = overflow;
    unaligned.address = 0x3001;
    unaligned.count = 1;
    unaligned.width = 2;
    try std.testing.expect((try readCases(allocator, &doc, unaligned, 0x1000, 0x1040)) == null);
}

test "recovery: sparse AND mask cannot fabricate dense case values" {
    const allocator = std.testing.allocator;
    var data: [256]u8 = @splat(0);
    @memcpy(data[0..160], &testFixture());
    // The table and all thirteen targets are well formed. Only four indices
    // (0,4,8,12) can result from this mask; a dense thirteen-case report is false.
    testPut(&data, 0x40, 0x121e0403); // AND W3,W0,#12
    testPut(&data, 0x48, testAdr(11, 0x1008, 0x1040));
    for (0..13) |i| {
        data[0x20 + i] = @intCast(i);
        testPut(&data, 0x80 + i * 4, 0xd65f03c0);
    }
    var sections = [_]types.Section{
        .{ .name = "__text", .start = 0x1000, .length = 0x80, .file_offset = 0x40, .is_code = true },
        .{ .name = "__const", .start = 0x3000, .length = 13, .file_offset = 0x20, .is_code = false },
    };
    var segments = [_]types.Segment{.{ .name = "test", .start = 0x1000, .length = 0x200d, .file_size = data.len, .sections = &sections, .permissions = .{ .read = true, .execute = true } }};
    var doc = testDocument(&data, &segments);
    defer doc.deinit();
    const tables = try recover(allocator, &doc, 0x1000, 0x80);
    defer jt.freeRecoveredTables(allocator, tables);
    try std.testing.expectEqual(@as(usize, 0), tables.len);
}
