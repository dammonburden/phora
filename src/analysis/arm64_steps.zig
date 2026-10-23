//! Bounded, encoding-backed local execution steps. This is not SSA: entry
//! values remain parameters supplied by the predecessor on each traversal.
const std = @import("std");
const builtin = @import("builtin");
const arithmetic = @import("arm64_arithmetic.zig");
const bitfield = @import("arm64_bitfield.zig");
const addressing = @import("arm64_addressing.zig");
const pair = @import("arm64_pair.zig");
const assembly = @import("../arch/arm64.zig");
const affine = @import("arm64_affine.zig");

pub const Op = enum { add, sub, and_, or_, xor, movz, movn, movk, extract, lsl, madd, msub, csel, load, store, branch, bcond, cbz, cbnz, tbz, tbnz, ret, nop };
pub const Shift = enum { lsl, lsr, asr, ror };
pub const Effect = struct {
    op: Op,
    width: u7 = 64,
    dst: u5 = 31,
    src: [3]u5 = .{ 31, 31, 31 },
    src_sp: bool = false,
    dst_sp: bool = false,
    immediate: ?u64 = null,
    shift: Shift = .lsl,
    amount: u6 = 0,
    invert_right: bool = false,
    flags: bool = false,
    condition: u4 = 0,
    field_width: u7 = 0,
    signed: bool = false,
    offset: i64 = 0,
    writeback: bool = false,
    pre_index: bool = false,
    // Paired loads write dst and src[2]; stores read src[1] and src[2].
    pair: bool = false,
};

/// Accept only these ordinary scalar encodings. Reserved variants, calls,
/// system ops and unmodeled effects return null and invalidate local state.
pub fn decode(word: u32) ?Effect {
    const width: u7 = if (word >> 31 != 0) 64 else 32;
    const dst: u5 = @truncate(word);
    const rn: u5 = @truncate(word >> 5);
    const rm: u5 = @truncate(word >> 16);
    if (arithmetic.decode(word)) |e| return .{ .op = if (e.subtract) .sub else .add, .width = e.width, .dst = e.destination, .src = .{ e.left, e.right, 31 }, .shift = switch (e.shift) {
        .lsl => .lsl,
        .lsr => .lsr,
        .asr => .asr,
    }, .amount = e.amount, .flags = e.sets_flags };
    if (word & 0x1f800000 == 0x11000000) {
        const flags = word & 0x20000000 != 0;
        return .{ .op = if (word & 0x40000000 != 0) .sub else .add, .width = width, .dst = dst, .src = .{ rn, 31, 31 }, .src_sp = true, .dst_sp = !flags, .flags = flags, .immediate = @as(u64, (word >> 10) & 0xfff) << @as(u6, if (word & 0x400000 != 0) 12 else 0) };
    }
    if (word & 0x1f000000 == 0x0a000000) {
        const amount: u6 = @truncate(word >> 10);
        if (width == 32 and amount >= 32) return null;
        const opc: u2 = @truncate(word >> 29);
        return .{ .op = switch (opc) {
            0, 3 => .and_,
            1 => .or_,
            2 => .xor,
        }, .width = width, .dst = dst, .src = .{ rn, rm, 31 }, .shift = @fromBackingInt(@intCast((word >> 22) & 3)), .amount = amount, .invert_right = word & 0x200000 != 0, .flags = opc == 3 };
    }
    if (word & 0x1f800000 == 0x12800000) {
        const opc: u2 = @truncate(word >> 29);
        const hw: u2 = @truncate(word >> 21);
        if (opc == 1 or (width == 32 and hw >= 2)) return null;
        return .{ .op = switch (opc) {
            0 => .movn,
            2 => .movz,
            3 => .movk,
            else => unreachable,
        }, .width = width, .dst = dst, .src = .{ dst, 31, 31 }, .immediate = @as(u64, (word >> 5) & 0xffff) << @as(u6, @as(u6, hw) * 16), .amount = @as(u6, hw) * 16 };
    }
    if (bitfield.decode(word)) |e| return .{ .op = .extract, .width = e.width, .dst = e.destination, .src = .{ e.source, 31, 31 }, .amount = e.field_lsb, .field_width = e.field_width_bits, .signed = e.extension == .signed };
    // UBFM wrapping forms are modeled only when they encode an exact LSL.
    if (word & 0x7f800000 == 0x53000000 and ((word >> 22) & 1) == (word >> 31)) {
        const r: u6 = @truncate(word >> 16);
        const s: u6 = @truncate(word >> 10);
        if (r < width and s < width and @as(u7, s) + 1 == r) return .{ .op = .lsl, .width = width, .dst = dst, .src = .{ rn, 31, 31 }, .amount = @intCast(width - r) };
    }
    if (word & 0x7fe00000 == 0x1b000000) return .{ .op = if (word & 0x8000 != 0) .msub else .madd, .width = width, .dst = dst, .src = .{ rn, rm, @truncate(word >> 10) } };
    // CSEL only (no CSINC/CSINV/CSNEG).
    if (word & 0x7fe00c00 == 0x1a800000) return .{ .op = .csel, .width = width, .dst = dst, .src = .{ rn, rm, 31 }, .condition = @truncate(word >> 12) };
    if (addressing.decode(word)) |e| return .{ .op = if (e.load) .load else .store, .width = e.width_bits, .dst = e.data, .src = .{ e.base, e.data, 31 }, .src_sp = true, .offset = e.immediate, .writeback = true, .pre_index = e.pre_index };
    if (pair.decode(word)) |e| return .{ .op = if (e.load) .load else .store, .width = e.width_bits, .dst = e.data[0], .src = .{ e.base, e.data[0], e.data[1] }, .src_sp = true, .offset = e.immediate, .writeback = e.writeback, .pre_index = e.pre_index, .pair = true };
    // Scalar unsigned imm12 and unscaled imm9; no signed loads or SIMD.
    if (word & 0x3f000000 == 0x39000000 or word & 0x3f200c00 == 0x38000000) {
        const opc: u2 = @truncate(word >> 22);
        if (opc > 1) return null;
        const transfer: u7 = @as(u7, 8) << @as(u2, @truncate(word >> 30));
        const scaled = word & 0x01000000 != 0;
        return .{ .op = if (opc == 1) .load else .store, .width = transfer, .dst = dst, .src = .{ rn, dst, 31 }, .src_sp = true, .offset = if (scaled) @as(i64, (word >> 10) & 0xfff) * (transfer / 8) else std.math.signExtend(i64, @as(u9, @truncate(word >> 12))) };
    }
    if (word & 0xfc000000 == 0x14000000) return .{ .op = .branch, .offset = std.math.signExtend(i64, @as(u26, @truncate(word))) * 4 };
    if (word & 0xff000010 == 0x54000000) return .{ .op = .bcond, .condition = @truncate(word), .offset = std.math.signExtend(i64, @as(u19, @truncate(word >> 5))) * 4 };
    if (word & 0x7e000000 == 0x34000000) return .{ .op = if (word & 0x01000000 == 0) .cbz else .cbnz, .width = width, .src = .{ dst, 31, 31 }, .offset = std.math.signExtend(i64, @as(u19, @truncate(word >> 5))) * 4 };
    if (word & 0x7e000000 == 0x36000000) return .{ .op = if (word & 0x01000000 == 0) .tbz else .tbnz, .width = width, .src = .{ dst, 31, 31 }, .amount = (@as(u6, @truncate(word >> 19)) & 31) | (@as(u6, @truncate(word >> 26)) & 32), .offset = std.math.signExtend(i64, @as(u14, @truncate(word >> 5))) * 4 };
    if (word & 0xfffffc1f == 0xd65f0000) return .{ .op = .ret, .src = .{ rn, 31, 31 } };
    if (word == 0xd503201f) return .{ .op = .nop };
    return null;
}

pub const Limits = struct { max_steps: usize = 256, max_successors: usize = 64 };
pub const Summary = struct { total_steps: usize, emitted_steps: usize, opaque_steps: usize, partial: bool };
const Version = struct { step: ?u64 = null, width: u7 = 64, is_opaque: bool = false };
const State = struct { regs: [32]Version = @splat(.{}), flags: Version = .{}, block_start: u64 = 0 };

fn source(w: anytype, state: State, reg: u5, width: u7, sp: bool) !void {
    if (reg == 31 and !sp) return w.writeAll("0");
    const v = state.regs[reg];
    const wrap32 = width == 32 and v.width == 64;
    const wrap64 = width == 64 and v.width == 32;
    if (wrap32) try w.writeAll("lo32(");
    if (wrap64) try w.writeAll("zext32(");
    if (reg == 31) try w.writeAll(if (v.width == 32) "wsp" else "sp") else try w.print("{s}{d}", .{ if (v.width == 32) @as([]const u8, "w") else "x", reg });
    if (v.step) |step| try w.print("@{s}0x{x}", .{ if (v.is_opaque) @as([]const u8, "opaque_") else "", step }) else try w.print("@in_0x{x}", .{state.block_start});
    if (wrap32 or wrap64) try w.writeAll(")");
}
fn destination(w: anytype, reg: u5, width: u7, sp: bool, step: u64) !void {
    if (reg == 31 and !sp) return w.writeAll("discard");
    if (reg == 31) try w.print("{s}@0x{x}", .{ if (width == 32) @as([]const u8, "wsp") else "sp", step }) else try w.print("{s}{d}@0x{x}", .{ if (width == 32) @as([]const u8, "w") else "x", reg, step });
}
fn flagsRef(w: anytype, state: State) !void {
    if (state.flags.step) |step| try w.print("NZCV@{s}0x{x}", .{ if (state.flags.is_opaque) @as([]const u8, "opaque_") else "", step }) else try w.print("NZCV@in_0x{x}", .{state.block_start});
}
const predicates = [_][]const u8{ "Z", "!Z", "C", "!C", "N", "!N", "V", "!V", "C&&!Z", "!C||Z", "N==V", "N!=V", "!Z&&N==V", "Z||N!=V", "true", "true" };
fn shifted(w: anytype, state: State, e: Effect) !void {
    if (e.immediate) |imm| return w.print("{d}", .{imm});
    if (e.invert_right) try w.writeAll("not(");
    if (e.amount != 0) try w.print("{s}{d}(", .{ @tagName(e.shift), e.amount });
    try source(w, state, e.src[1], e.width, false);
    if (e.amount != 0) try w.writeAll(")");
    if (e.invert_right) try w.writeAll(")");
}

fn equation(w: anytype, state: State, e: Effect, address: u64, step: u64) !void {
    if (e.pair) {
        // Every RHS uses this same before-state, even when an offset-mode
        // load overwrites its base register. Memory effects stay symbolic.
        const first_offset = if (e.pre_index or !e.writeback) e.offset else 0;
        try pairElement(w, state, e, e.src[1], first_offset, step);
        try w.writeAll("; ");
        try pairElement(w, state, e, e.src[2], first_offset + e.width / 8, step);
        try writebackEquation(w, state, e, step);
        return;
    }
    switch (e.op) {
        .branch, .bcond, .cbz, .cbnz, .tbz, .tbnz => {
            if (e.op != .branch) {
                try w.writeAll("if ");
                if (e.op == .bcond) {
                    try w.print("{s}(", .{predicates[e.condition]});
                    try flagsRef(w, state);
                    try w.writeAll(")");
                } else {
                    if (e.op == .tbz or e.op == .tbnz) try w.print("bit{d}(", .{e.amount});
                    try source(w, state, e.src[0], e.width, false);
                    if (e.op == .tbz or e.op == .tbnz) try w.writeAll(")");
                    try w.writeAll(if (e.op == .cbz or e.op == .tbz) " == 0" else " != 0");
                }
                try w.writeAll(" then ");
            }
            try w.print("goto 0x{x}", .{address +% @as(u64, @bitCast(e.offset))});
            if (e.op != .branch) try w.print(" else goto 0x{x}", .{address + 4});
            return;
        },
        .ret => {
            try w.writeAll("return to ");
            try source(w, state, e.src[0], 64, false);
            return;
        },
        .nop => return w.writeAll("no effect"),
        .store => {
            try w.print("store{d}(address=", .{e.width});
            try source(w, state, e.src[0], 64, true);
            try w.print(" + ({d})) <- low{d}(", .{ if (e.pre_index or !e.writeback) e.offset else 0, e.width });
            try source(w, state, e.src[1], if (e.width == 64) 64 else 32, false);
            try w.writeAll(")");
        },
        else => {
            const result_width: u7 = if (e.op == .load and e.width < 32) 32 else e.width;
            try destination(w, e.dst, result_width, e.dst_sp, step);
            try w.print(" = u{d}(", .{result_width});
            switch (e.op) {
                .add, .sub, .and_, .or_, .xor => {
                    try source(w, state, e.src[0], e.width, e.src_sp);
                    try w.print(" {s} ", .{switch (e.op) {
                        .add => "+",
                        .sub => "-",
                        .and_ => "&",
                        .or_ => "|",
                        .xor => "^",
                        else => unreachable,
                    }});
                    try shifted(w, state, e);
                },
                .movz, .movn => {
                    if (e.op == .movn) try w.writeAll("not(");
                    try w.print("{d}", .{e.immediate.?});
                    if (e.op == .movn) try w.writeAll(")");
                },
                .movk => {
                    try w.print("replace_bits{d}_16(", .{e.amount});
                    try source(w, state, e.src[0], e.width, false);
                    try w.print(", {d})", .{e.immediate.? >> e.amount});
                },
                .extract => {
                    try w.print("{s}_extend{d}(bits{d}_len{d}(", .{ if (e.signed) @as([]const u8, "sign") else "zero", e.width, e.amount, e.field_width });
                    try source(w, state, e.src[0], e.width, false);
                    try w.writeAll("))");
                },
                .lsl => {
                    try w.print("lsl{d}(", .{e.amount});
                    try source(w, state, e.src[0], e.width, false);
                    try w.writeAll(")");
                },
                .madd, .msub => {
                    try source(w, state, e.src[2], e.width, false);
                    try w.writeAll(if (e.op == .madd) " + (" else " - (");
                    try source(w, state, e.src[0], e.width, false);
                    try w.writeAll(" * ");
                    try source(w, state, e.src[1], e.width, false);
                    try w.writeAll(")");
                },
                .csel => {
                    try w.print("select({s}(", .{predicates[e.condition]});
                    try flagsRef(w, state);
                    try w.writeAll("), ");
                    try source(w, state, e.src[0], e.width, false);
                    try w.writeAll(", ");
                    try source(w, state, e.src[1], e.width, false);
                    try w.writeAll(")");
                },
                .load => {
                    try w.print("zero_extend(load{d}(address=", .{e.width});
                    try source(w, state, e.src[0], 64, true);
                    try w.print(" + ({d})))", .{if (e.pre_index or !e.writeback) e.offset else 0});
                },
                else => unreachable,
            }
            try w.writeAll(")");
        },
    }
    try writebackEquation(w, state, e, step);
    if (e.flags) {
        try w.print("; NZCV@0x{x} = {s}{d}_flags(", .{ step, if (e.op == .add) @as([]const u8, "add") else if (e.op == .sub) "sub" else "and", e.width });
        try source(w, state, e.src[0], e.width, e.src_sp);
        try w.writeAll(", ");
        try shifted(w, state, e);
        try w.writeAll(")");
    }
}

fn pairElement(w: anytype, state: State, e: Effect, data: u5, offset: i64, step: u64) !void {
    if (e.op == .load) {
        try destination(w, data, e.width, false, step);
        try w.print(" = u{d}(zero_extend(load{d}(address=", .{ e.width, e.width });
        try source(w, state, e.src[0], 64, true);
        try w.print(" + ({d}))))", .{offset});
    } else {
        try w.print("store{d}(address=", .{e.width});
        try source(w, state, e.src[0], 64, true);
        try w.print(" + ({d})) <- low{d}(", .{ offset, e.width });
        try source(w, state, data, e.width, false);
        try w.writeAll(")");
    }
}

fn writebackEquation(w: anytype, state: State, e: Effect, step: u64) !void {
    if ((e.op == .load or e.op == .store) and e.writeback) {
        try w.writeAll("; ");
        try destination(w, e.src[0], 64, true, step);
        try w.writeAll(" = u64(");
        try source(w, state, e.src[0], 64, true);
        try w.print(" + ({d}))", .{e.offset});
    }
}

fn update(state: *State, e: Effect, step: u64) void {
    switch (e.op) {
        .branch, .bcond, .cbz, .cbnz, .tbz, .tbnz, .ret, .nop, .store => {},
        else => if (e.dst != 31 or e.dst_sp) {
            state.regs[e.dst] = .{ .step = step, .width = if (e.op == .load and e.width < 32) 32 else e.width };
        },
    }
    if (e.pair and e.op == .load and e.src[2] != 31) state.regs[e.src[2]] = .{ .step = step, .width = e.width };
    if ((e.op == .load or e.op == .store) and e.writeback) state.regs[e.src[0]] = .{ .step = step };
    if (e.flags) state.flags = .{ .step = step };
}

/// Emits one JSON object, no allocation. All emitted steps include bytes and
/// addresses. Writer capacity errors propagate; limits never silently omit.
/// The caller supplies exactly one basic block's little-endian instructions.
pub fn writeBlockJson(w: anytype, start: u64, bytes: []const u8, successors: []const u64, limits: Limits) !Summary {
    if (bytes.len % 4 != 0 or start % 4 != 0) return error.UnalignedBlock;
    if (bytes.len > std.math.maxInt(u64) - start) return error.AddressOverflow;
    const total = bytes.len / 4;
    const count = @min(total, @min(limits.max_steps, 4096));
    const edge_count = @min(successors.len, @min(limits.max_successors, 64));
    var state: State = .{ .block_start = start };
    var composition = affine.State.initAt(start);
    var opaque_count: usize = 0;
    try w.print("{{\"model\":\"a64_local_steps_v1\",\"block\":\"0x{x}\",\"entry_rule\":\"@in_0xBLOCK means current incoming state on this block visit, including backedges, never a function initializer. Listed order; RHS before writes. W writes zero-extend X. Equations assume reached/normal completion; reachability past opaque control flow is unknown. Outgoing state supplies successor incoming values. Paired accesses give per-element values/addresses only; memory ordering, atomicity and fault effects are not modeled.\",\"steps\":[", .{start});
    for (0..count) |i| {
        if (i != 0) try w.writeAll(",");
        const raw = bytes[i * 4 ..][0..4];
        const word = std.mem.readInt(u32, raw, .little);
        const address = start + i * 4;
        const display = assembly.decode(raw, address);
        try w.print("{{\"id\":\"0x{x}\",\"address\":\"0x{x}\",\"encoding\":\"0x{x:0>8}\",\"bytes\":\"{x:0>2}{x:0>2}{x:0>2}{x:0>2}\",\"mnemonic\":", .{ address, address, word, raw[0], raw[1], raw[2], raw[3] });
        try std.json.Stringify.encodeJsonString(display.mnemonic, .{}, w);
        try w.writeAll(",\"operands\":");
        try std.json.Stringify.encodeJsonString(display.getOperands(), .{}, w);
        try w.print(",\"assembly_status\":\"{s}\",\"status\":\"{s}\",\"execute\":\"", .{ @tagName(display.decode_status), if (decode(word) != null) @as([]const u8, "modeled_subset") else "opaque_barrier" });
        if (decode(word)) |e| {
            try equation(w, state, e, address, address);
            composition.apply(e, address);
            update(&state, e, address);
        } else {
            try w.writeAll("opaque effects, memory and control flow; all subsequent GPR/SP/NZCV references are unknown until explicitly rewritten");
            state.regs = @splat(.{ .step = address, .is_opaque = true });
            state.flags = .{ .step = address, .is_opaque = true };
            opaque_count += 1;
            composition.applyUnknown(address);
        }
        try w.writeAll("\"}");
    }
    try w.print("],\"total_steps\":{d},\"emitted_steps\":{d},\"omitted_steps\":{d},\"omitted_status\":\"{s}\",\"omitted_start\":\"0x{x}\",\"omitted_bytes\":{d},\"partial\":{},\"successors\":[", .{ total, count, total - count, if (count == total) @as([]const u8, "none") else "step_limit", start + count * 4, (total - count) * 4, count != total or edge_count != successors.len });
    for (successors[0..edge_count], 0..) |target, i| {
        if (i != 0) try w.writeAll(",");
        try w.print("\"0x{x}\"", .{target});
    }
    try w.print("],\"total_successors\":{d},\"opaque_steps\":{d}", .{ successors.len, opaque_count });
    if (count == total and composition.report(8).total_outputs != 0) {
        try w.writeAll(",\"local_modular_composition\":");
        _ = try composition.writeSummaryJson(w, 8);
    } else if (count != total) {
        try w.writeAll(",\"local_modular_composition_status\":\"omitted_step_limit; no outgoing composition inferred\"");
    }
    try w.writeAll("}");
    return .{ .total_steps = total, .emitted_steps = count, .opaque_steps = opaque_count, .partial = count != total or edge_count != successors.len };
}

pub const text_legend = "A64 local execution steps: @in_0xBLOCK means current state arriving at that block on this visit (including backedges), never the function initializer. Listed steps follow instruction order; each equation assumes that instruction is reached and completes normally. Reachability past opaque control flow is unknown. RHS reads occur before any writes of that step. W writes zero-extend into X; u32/u64 wrap; lo32 takes low bits. Shifts operate at operand width (ASR signed, ROR rotates). bitsL_lenN extracts N bits from L; sign_extend sign-extends the field (signed one-bit 1 becomes all ones). select(predicate,true,false). NZCV flags: N=result sign, Z=zero; ADD C=carry/V=signed overflow; SUB C=no borrow/V=signed overflow; logical C=V=0. Edges carry final current state into successor incoming values. Address arithmetic wraps modulo 2^64. Loads/stores describe normal completion only. Paired accesses give per-element values/addresses only; memory ordering, atomicity and fault effects are not modeled. Opaque instructions invalidate all GPR/SP/NZCV provenance; no full semantics or cross-block SSA is claimed.\n";

/// Same bounded view as JSON, with one compact line per instruction. Caller
/// may print text_legend once when combining many blocks.
pub fn writeBlockText(w: anytype, start: u64, bytes: []const u8, successors: []const u64, limits: Limits) !Summary {
    if (bytes.len % 4 != 0 or start % 4 != 0) return error.UnalignedBlock;
    if (bytes.len > std.math.maxInt(u64) - start) return error.AddressOverflow;
    const total = bytes.len / 4;
    const count = @min(total, @min(limits.max_steps, 4096));
    const edge_count = @min(successors.len, @min(limits.max_successors, 64));
    var state: State = .{ .block_start = start };
    var composition = affine.State.initAt(start);
    var opaque_count: usize = 0;
    try w.print("Block 0x{x} (@in_0x{x}=current state on this visit):\n", .{ start, start });
    for (0..count) |i| {
        const raw = bytes[i * 4 ..][0..4];
        const word = std.mem.readInt(u32, raw, .little);
        const address = start + i * 4;
        const display = assembly.decode(raw, address);
        try w.print("  0x{x} [{x:0>2}{x:0>2}{x:0>2}{x:0>2}; word={x:0>8}] {s} {s}: ", .{ address, raw[0], raw[1], raw[2], raw[3], word, display.mnemonic, display.getOperands() });
        if (decode(word)) |e| {
            try equation(w, state, e, address, address);
            composition.apply(e, address);
            update(&state, e, address);
        } else {
            try w.writeAll("OPAQUE effects/memory/control flow barrier: subsequent GPR/SP/NZCV unknown until explicitly rewritten");
            state.regs = @splat(.{ .step = address, .is_opaque = true });
            state.flags = .{ .step = address, .is_opaque = true };
            opaque_count += 1;
            composition.applyUnknown(address);
        }
        try w.writeAll("\n");
    }
    try w.writeAll("  edges (carry current state):");
    for (successors[0..edge_count]) |target| try w.print(" 0x{x}", .{target});
    try w.print("; steps={d}/{d}; opaque={d}; omitted_edges={d}\n", .{ count, total, opaque_count, successors.len - edge_count });
    if (count != total) try w.print("  OMITTED step_limit: {d} steps / {d} bytes starting 0x{x}; no outgoing state inferred beyond omission\n", .{ total - count, (total - count) * 4, start + count * 4 });
    if (count == total) _ = try composition.writeSummaryText(w, 8);
    return .{ .total_steps = total, .emitted_steps = count, .opaque_steps = opaque_count, .partial = count != total or edge_count != successors.len };
}

test "local versions retain current carried operands and each instruction" {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    const words = [_]u32{ 0x3840152d, 0xf100058c, 0x4b0b01ad, 0x0b0b0dab, 0x54ffff81 };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], word, .little);
    const summary = try writeBlockJson(&out.writer, 0x2000, &bytes, &.{ 0x2000, 0x2014 }, .{});
    try std.testing.expectEqual(@as(usize, 0), summary.opaque_steps);
    for ([_][]const u8{ "w13@0x2008 = u32(w13@0x2000 - lo32(x11@in_0x2000))", "w11@0x200c = u32(w13@0x2008 + lsl3(lo32(x11@in_0x2000)))", "!Z(NZCV@0x2004)", "0x200c", "ab0d0b0b" }) |needle| try std.testing.expect(std.mem.indexOf(u8, out.written(), needle) != null);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out.written(), .{});
    defer parsed.deinit();
}

test "reserved variants calls and unknown words are barriers" {
    for ([_]u32{ 0x94000000, 0xd63f0000, 0xd503203f, 0x0b008000, 0x0bc00000, 0x0b200000, 0x52800000 | 0x00400000, 0x32800000, 0x1a800400, 0x5a800000, 0xb9800000, 0x3d400000, 0xf8400c21, 0xffffffff }) |word| try std.testing.expect(decode(word) == null);
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    const bytes = [_]u8{ 0, 0, 0, 0x94, 0x4b, 0x04, 0x02, 0x0b };
    const summary = try writeBlockJson(&out.writer, 0, &bytes, &.{}, .{});
    try std.testing.expectEqual(@as(usize, 1), summary.opaque_steps);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "lo32(x2@opaque_0x0)") != null);
}

test "limits and invalid blocks are explicit and bounded" {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const summary = try writeBlockJson(&writer, 0x1000, &.{ 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5 }, &.{ 4, 8 }, .{ .max_steps = 1, .max_successors = 1 });
    try std.testing.expect(summary.partial);
    try std.testing.expectEqual(@as(usize, 2), summary.total_steps);
    try std.testing.expectEqual(@as(usize, 1), summary.emitted_steps);
    try std.testing.expectError(error.UnalignedBlock, writeBlockJson(&writer, 1, &.{}, &.{}, .{}));
    try std.testing.expectError(error.UnalignedBlock, writeBlockJson(&writer, 0, &.{0}, &.{}, .{}));
    try std.testing.expectError(error.AddressOverflow, writeBlockJson(&writer, 0xfffffffffffffffc, &.{ 0, 0, 0, 0 }, &.{}, .{}));
    var tiny: [2]u8 = undefined;
    var tiny_writer = std.Io.Writer.fixed(&tiny);
    try std.testing.expectError(error.WriteFailed, writeBlockJson(&tiny_writer, 0, &.{}, &.{}, .{}));
}

test "literal boundary fields and register31 roles" {
    try std.testing.expectEqual(@as(?u64, 4096), decode(0x91400400).?.immediate);
    try std.testing.expect(decode(0x910003e0).?.src_sp);
    try std.testing.expect(!decode(0x710003ff).?.dst_sp);
    try std.testing.expectEqual(@as(u6, 63), decode(0x8b00fc00).?.amount);
    try std.testing.expectEqual(@as(u6, 31), decode(0x0b007c00).?.amount);
    try std.testing.expectEqual(@as(i64, -256), decode(0xf8500020).?.offset);
    try std.testing.expectEqual(@as(i64, 32760), decode(0xf97ffc20).?.offset);
    try std.testing.expectEqual(@as(i64, -4), decode(0x17ffffff).?.offset);
    try std.testing.expectEqual(@as(u6, 63), decode(0xb7f80000).?.amount);
    try std.testing.expectEqual(@as(u7, 1), decode(0x1300014c).?.field_width);
    try std.testing.expect(decode(0x1300014c).?.signed);
    try std.testing.expectEqual(@as(u6, 4), decode(0x531c6d2c).?.amount);
}

test "native before-write arithmetic and signed bitfield sanity" {
    if (builtin.cpu.arch != .aarch64) return error.SkipZigTest;
    for ([_]u64{ 0, 1, 2, 0x7fffffff, 0xffffffff }) |acc| {
        const result = asm volatile ("add w11, w2, w2, lsl #1\nsbfm w12, w10, #0, #0\nadd w10, w11, w10\nand w11, w12, w11\neor w2, w11, w10"
            : [out] "={x2}" (-> u64),
            : [acc] "{x2}" (acc),
              [byte] "{x10}" (@as(u64, 5)),
            : .{ .x10 = true, .x11 = true, .x12 = true });
        const triple = arithmetic.decode(0x0b02044b).?.result(acc, acc);
        const mask = bitfield.decode(0x1300014c).?.result(5);
        try std.testing.expectEqual(((triple +% 5) & 0xffffffff) ^ (mask & triple), result);
    }
}

test "independently clang assembled new classes and boundary fields" {
    // clang -target arm64-apple-macos; otool -s __TEXT __text. These
    // literals exercise unrelated registers and both widths, not fixtures.
    const words = [_]u32{ 0x917fffff, 0x713fffff, 0x6a857c83, 0xcae8fce6, 0xd2f579a9, 0x12a2468a, 0xf2cacf0b, 0xd34101ac, 0x1b1045ee, 0x9b14d672, 0x1a98d2f6, 0x397ffff9, 0x7810037a, 0xf84ffffc, 0xb81007fd, 0x54000000, 0xb500001e, 0xb6f8001f, 0xd65f0120 };
    const ops = [_]Op{ .add, .sub, .and_, .xor, .movz, .movn, .movk, .lsl, .madd, .msub, .csel, .load, .store, .load, .store, .bcond, .cbnz, .tbz, .ret };
    for (words, ops) |word, op| try std.testing.expectEqual(op, decode(word).?.op);
    try std.testing.expectEqual(@as(?u64, 4095 * 4096), decode(words[0]).?.immediate);
    try std.testing.expect(decode(words[0]).?.dst_sp);
    try std.testing.expect(decode(words[1]).?.flags);
    try std.testing.expectEqual(Shift.asr, decode(words[2]).?.shift);
    try std.testing.expectEqual(@as(u6, 31), decode(words[2]).?.amount);
    try std.testing.expectEqual(Shift.ror, decode(words[3]).?.shift);
    try std.testing.expect(decode(words[3]).?.invert_right);
    try std.testing.expectEqual(@as(u6, 63), decode(words[3]).?.amount);
    try std.testing.expectEqual(@as(?u64, 0xabcd000000000000), decode(words[4]).?.immediate);
    try std.testing.expectEqual(@as(?u64, 0x12340000), decode(words[5]).?.immediate);
    try std.testing.expectEqual(@as(?u64, 0x567800000000), decode(words[6]).?.immediate);
    try std.testing.expectEqual(@as(u6, 63), decode(words[7]).?.amount);
    try std.testing.expectEqual([3]u5{ 15, 16, 17 }, decode(words[8]).?.src);
    try std.testing.expectEqual([3]u5{ 19, 20, 21 }, decode(words[9]).?.src);
    try std.testing.expectEqual(@as(u4, 13), decode(words[10]).?.condition);
    try std.testing.expectEqual(@as(i64, 4095), decode(words[11]).?.offset);
    try std.testing.expectEqual(@as(u7, 8), decode(words[11]).?.width);
    try std.testing.expectEqual(@as(i64, -256), decode(words[12]).?.offset);
    try std.testing.expectEqual(@as(u7, 16), decode(words[12]).?.width);
    try std.testing.expect(decode(words[13]).?.pre_index);
    try std.testing.expectEqual(@as(i64, 255), decode(words[13]).?.offset);
    try std.testing.expect(!decode(words[14]).?.pre_index);
    try std.testing.expectEqual(@as(i64, -256), decode(words[14]).?.offset);
    try std.testing.expectEqual(@as(u6, 63), decode(words[17]).?.amount);
    try std.testing.expectEqual(@as(u5, 9), decode(words[18]).?.src[0]);
}

test "text preserves aliases, simultaneous writeback and opaque flag provenance" {
    const words = [_]u32{ 0x5280002b, 0x8b0b016c, 0xf8428e61, 0xf8008422, 0xf100058c, 0x00000000, 0x0b02044b, 0x54000001 };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], word, .little);
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    const summary = try writeBlockText(&out.writer, 0x3000, &bytes, &.{ 0x3020, 0x3000 }, .{});
    try std.testing.expectEqual(@as(usize, 1), summary.opaque_steps);
    for ([_][]const u8{
        "x12@0x3004 = u64(zext32(w11@0x3000) + zext32(w11@0x3000))",
        "x1@0x3008 = u64(zero_extend(load64(address=x19@in_0x3000 + (40))))",
        "x19@0x3008 = u64(x19@in_0x3000 + (40))",
        "if !Z(NZCV@opaque_0x3014) then goto 0x301c else goto 0x3020",
    }) |needle| try std.testing.expect(std.mem.indexOf(u8, out.written(), needle) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "store64(address=x1@0x3008 + (0)) <- low64(x2@in_0x3000); x1@0x300c = u64(x1@0x3008 + (8))") != null);
    for (words, 0..) |_, i| {
        var token: [32]u8 = undefined;
        const address = try std.fmt.bufPrint(&token, "0x{x} [", .{0x3000 + i * 4});
        try std.testing.expect(std.mem.indexOf(u8, out.written(), address) != null);
    }
}

test "all reserved writeback overlaps and nonordinary variants stay opaque" {
    for ([_]u32{ 0x38000400, 0x38000c00, 0x78000400, 0x78000c00, 0xb8000400, 0xb8000c00, 0xf8000400, 0xf8000c00 }) |base| {
        for (0..31) |reg| {
            const word = base | @as(u32, @intCast(reg)) | (@as(u32, @intCast(reg)) << 5);
            try std.testing.expect(decode(word) == null);
            try std.testing.expect(decode(word | 0x00400000) == null);
        }
    }
    // SP/ZR is the architecturally permitted overlap exception.
    try std.testing.expect(decode(0xf8400fff) != null);
    for ([_]u32{ 0x54000010, 0x13400000, 0x93400000 ^ 0x00400000, 0x33000000, 0x13010100, 0x531c6820, 0xb8400800, 0xf8206800, 0x9b200000, 0x9ba00000, 0x1a800800, 0x5a800400 }) |word| try std.testing.expect(decode(word) == null);
}

test "decoded modular composition uses before-state and native two-step arithmetic" {
    // sub w4,w3,w2; add w2,w4,w2,lsl#3 -- unrelated register choice.
    var state = affine.State.init();
    state.apply(decode(0x4b020064).?, 0x4000);
    state.apply(decode(0x0b020c82).?, 0x4004);
    const form = state.values[2].form;
    try std.testing.expectEqual(@as(usize, 2), form.len);
    try std.testing.expectEqual(@as(u64, 7), form.terms[1].coefficient);
    const resolver = struct {
        fn value(inputs: [2]u64, atom: affine.Atom) u64 {
            return if (atom.register == 2) inputs[0] else inputs[1];
        }
    }.value;
    for ([_]u64{ 0, 1, 7, 0x7fffffff, 0xffffffff, 0x100000001 }) |carried| for ([_]u64{ 0, 5, 255, 0xffffffff }) |input| {
        const expected = (7 *% carried +% input) & 0xffffffff;
        try std.testing.expectEqual(expected, form.evaluate([2]u64{ carried, input }, resolver));
        if (builtin.cpu.arch == .aarch64) {
            const actual = asm volatile ("sub w4, w3, w2\nadd w2, w4, w2, lsl #3"
                : [out] "={x2}" (-> u64),
                : [left] "{x3}" (input),
                  [right] "{x2}" (carried),
                : .{ .x4 = true });
            try std.testing.expectEqual(actual, form.evaluate([2]u64{ carried, input }, resolver));
        }
    };
}

test "decoded cross-width counterexample and low32 coefficient reduction" {
    var state = affine.State.init();
    state.apply(decode(0x11000401).?, 0x5000); // add w1,w0,#1
    state.apply(decode(0x91002022).?, 0x5004); // add x2,x1,#8
    state.apply(decode(0x91000442).?, 0x5008); // add x2,x2,#1
    const form = state.values[2].form;
    try std.testing.expectEqual(@as(u7, 32), form.terms[0].atom.width);
    try std.testing.expectEqual(@as(?u64, 0x5000), form.terms[0].atom.address);
    const resolver = struct {
        fn value(_: void, a: affine.Atom) u64 {
            return if (a.address == null) 0xffffffff else 0;
        }
    }.value;
    try std.testing.expectEqual(@as(u64, 9), form.evaluate({}, resolver));
    try std.testing.expect(form.evaluate({}, resolver) != 0x100000009);
    if (builtin.cpu.arch == .aarch64) {
        const actual = asm volatile ("add w1,w0,#1\nadd x2,x1,#8\nadd x2,x2,#1"
            : [out] "={x2}" (-> u64),
            : [in] "{x0}" (@as(u64, 0xffffffff)),
            : .{ .x1 = true });
        try std.testing.expectEqual(actual, form.evaluate({}, resolver));
    }
    state = affine.State.init();
    state.apply(decode(0x913ffc01).?, 0x5100); // add x1,x0,#4095
    state.apply(decode(0x0b010422).?, 0x5104); // add w2,w1,w1,lsl#1
    try std.testing.expectEqual(@as(u7, 32), state.values[2].form.width);
    try std.testing.expectEqual(@as(u64, 3), state.values[2].form.terms[0].coefficient);
    try std.testing.expectEqual(@as(u64, 12285), state.values[2].form.constant);
}

test "decoded flags discard SP zero copies writeback and unknown barriers" {
    var state = affine.State.init();
    state.apply(decode(0x910007ff).?, 0x6000); // add sp,sp,#1
    state.apply(decode(0x910007ff).?, 0x6004);
    try std.testing.expectEqual(@as(u64, 2), state.values[31].form.constant);
    state.apply(decode(0xf10007ff).?, 0x6008); // cmp sp,#1; discard destination
    try std.testing.expectEqual(@as(u64, 2), state.values[31].form.constant);
    state.apply(decode(0xaa1f03e0).?, 0x600c); // mov x0,xzr
    try std.testing.expectEqual(@as(usize, 0), state.values[0].form.len);
    state.apply(decode(0xaa1f03e1).?, 0x6010);
    state.apply(decode(0xf8408fff).?, 0x6014); // load XZR,[SP,#8]!; base becomes atom
    try std.testing.expectEqual(@as(usize, 0), state.values[31].form.operations);
    try std.testing.expectEqual(@as(?u64, 0x6014), state.values[31].form.terms[0].atom.address);
    state.applyUnknown(0x6018);
    try std.testing.expectEqual(@as(usize, 0), state.report(8).outputs);
    state.apply(decode(0x91000400).?, 0x601c);
    state.apply(decode(0x91000400).?, 0x6020);
    try std.testing.expect(state.values[0].form.terms[0].atom.is_opaque);
    try std.testing.expectEqual(@as(?u64, 0x6018), state.values[0].form.terms[0].atom.address);
    state.apply(decode(0x8b400400).?, 0x6024); // ADD with LSR#1 cannot compose
    try std.testing.expectEqual(@as(usize, 0), state.values[0].form.operations);
    try std.testing.expectEqual(@as(?u64, 0x6024), state.values[0].form.terms[0].atom.address);
}

test "composition summaries are bounded and absent for omitted instructions" {
    const words = [_]u32{ 0x4b020064, 0x0b020c82, 0xd503201f };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], word, .little);
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    _ = try writeBlockText(&out.writer, 0x4000, &bytes, &.{}, .{});
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "u32(lo32(x3@in_0x4000) + 7*lo32(x2@in_0x4000))") != null);
    out.clearRetainingCapacity();
    _ = try writeBlockText(&out.writer, 0x4000, &bytes, &.{}, .{ .max_steps = 2 });
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "Local modular composition") == null);
    out.clearRetainingCapacity();
    _ = try writeBlockJson(&out.writer, 0x4000, &bytes, &.{}, .{ .max_steps = 0 });
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "omitted_step_limit; no outgoing composition inferred") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"local_modular_composition\":") == null);
    var state = affine.State.init();
    for (0..9) |reg| {
        const e = Effect{ .op = .add, .width = 64, .dst = @intCast(reg), .src = .{ @intCast(reg), 31, 31 }, .immediate = 1 };
        state.apply(e, 100 + reg * 8);
        state.apply(e, 104 + reg * 8);
    }
    try std.testing.expectEqual(@as(usize, 8), state.report(100).outputs);
    try std.testing.expectEqual(@as(usize, 1), state.report(100).omitted_outputs);
    try std.testing.expect(state.report(100).partial);
}

test "incoming register and flag names differ between blocks" {
    const words = [_]u32{ 0x4b020064, 0x0b020c82, 0x54000001 };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], word, .little);
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    _ = try writeBlockText(&out.writer, 0x7000, &bytes, &.{}, .{});
    _ = try writeBlockText(&out.writer, 0x8000, &bytes, &.{}, .{});
    for ([_][]const u8{ "x2@in_0x7000", "x2@in_0x8000", "NZCV@in_0x7000", "NZCV@in_0x8000", "u32(lo32(x3@in_0x7000) + 7*lo32(x2@in_0x7000))", "u32(lo32(x3@in_0x8000) + 7*lo32(x2@in_0x8000))" }) |needle| try std.testing.expect(std.mem.indexOf(u8, out.written(), needle) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "@entry") == null);
}

test "pair equations keep before-write addresses and both data versions" {
    const words = [_]u32{ 0xa984346c, 0xa9bc346c, 0xa9c4346c, 0xa9fc346c, 0xa9418c62, 0x91000464 };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], word, .little);
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    const summary = try writeBlockText(&out.writer, 0x9000, &bytes, &.{}, .{});
    try std.testing.expectEqual(@as(usize, 0), summary.opaque_steps);
    for ([_][]const u8{
        "store64(address=x3@in_0x9000 + (64)) <- low64(x12@in_0x9000); store64(address=x3@in_0x9000 + (72)) <- low64(x13@in_0x9000); x3@0x9000 = u64(x3@in_0x9000 + (64))",
        "store64(address=x3@0x9000 + (-64)) <- low64(x12@in_0x9000); store64(address=x3@0x9000 + (-56)) <- low64(x13@in_0x9000); x3@0x9004 = u64(x3@0x9000 + (-64))",
        "x12@0x9008 = u64(zero_extend(load64(address=x3@0x9004 + (64)))); x13@0x9008 = u64(zero_extend(load64(address=x3@0x9004 + (72)))); x3@0x9008 = u64(x3@0x9004 + (64))",
        "x12@0x900c = u64(zero_extend(load64(address=x3@0x9008 + (-64)))); x13@0x900c = u64(zero_extend(load64(address=x3@0x9008 + (-56)))); x3@0x900c = u64(x3@0x9008 + (-64))",
        "x2@0x9010 = u64(zero_extend(load64(address=x3@0x900c + (24)))); x3@0x9010 = u64(zero_extend(load64(address=x3@0x900c + (32))))",
        "x4@0x9014 = u64(x3@0x9010 + 1)",
    }) |needle| try std.testing.expect(std.mem.indexOf(u8, out.written(), needle) != null);
}

test "pair post index zero extends both W results and keeps SP distinct from ZR" {
    var state: State = .{ .block_start = 0xa000 };
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    // LDP W1,W2,[X3],#8, then read both X registers.
    const load = decode(0x28c10861).?;
    try equation(&out.writer, state, load, 0xa000, 0xa000);
    update(&state, load, 0xa000);
    try std.testing.expectEqual(@as(u7, 32), state.regs[1].width);
    try std.testing.expectEqual(@as(u7, 32), state.regs[2].width);
    try std.testing.expectEqual(@as(?u64, 0xa000), state.regs[3].step);
    try equation(&out.writer, state, .{ .op = .add, .dst = 4, .src = .{ 1, 2, 31 } }, 0xa004, 0xa004);
    for ([_][]const u8{
        "w1@0xa000 = u32(zero_extend(load32(address=x3@in_0xa000 + (0))))",
        "w2@0xa000 = u32(zero_extend(load32(address=x3@in_0xa000 + (4))))",
        "x3@0xa000 = u64(x3@in_0xa000 + (8))",
        "x4@0xa004 = u64(zext32(w1@0xa000) + zext32(w2@0xa000))",
    }) |needle| try std.testing.expect(std.mem.indexOf(u8, out.written(), needle) != null);
    out.clearRetainingCapacity();
    const sp_load = decode(0xa9ff7fe0).?; // LDP X0,XZR,[SP,#-16]!
    try equation(&out.writer, state, sp_load, 0xa008, 0xa008);
    update(&state, sp_load, 0xa008);
    try std.testing.expectEqual(@as(?u64, 0xa008), state.regs[31].step);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "discard = u64(zero_extend(load64(address=sp@in_0xa000 + (-8))))") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "sp@0xa008 = u64(sp@in_0xa000 + (-16))") != null);
    out.clearRetainingCapacity();
    const before_sp = state.regs[31];
    const sp_offset = decode(0xa9407fe1).?; // LDP X1,XZR,[SP] -- no writeback
    try equation(&out.writer, state, sp_offset, 0xa00c, 0xa00c);
    update(&state, sp_offset, 0xa00c);
    try std.testing.expectEqualDeep(before_sp, state.regs[31]);
    const zr_store = decode(0xa9bf7fff).?; // STP XZR,XZR,[SP,#-16]!
    try equation(&out.writer, state, zr_store, 0xa010, 0xa010);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "<- low64(0)") != null);
}

test "unsupported pair forms are explicit JSON opaque barriers" {
    const words = [_]u32{ 0xa9800063, 0xa9400461, 0xad000440, 0xa8000440, 0x69400440, 0xe9400440, 0x91000463 };
    var bytes: [words.len * 4]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], word, .little);
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    const summary = try writeBlockJson(&out.writer, 0xb000, &bytes, &.{}, .{});
    try std.testing.expectEqual(@as(usize, 6), summary.opaque_steps);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"status\":\"opaque_barrier\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "opaque effects, memory and control flow") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "x3@0xb018 = u64(x3@opaque_0xb014 + 1)") != null);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out.written(), .{});
    defer parsed.deinit();
}
