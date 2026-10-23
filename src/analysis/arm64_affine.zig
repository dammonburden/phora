//! Bounded local modular arithmetic composition, not recovered recurrences.
//! The caller supplies an already decoded Effect; there is no decoder here.
const std = @import("std");
pub const max_terms = 8;
pub const max_operations = 128;
pub const max_outputs = 8;

pub const Atom = struct {
    register: u5,
    width: u7,
    address: ?u64 = null,
    /// Meaningful only for incoming atoms (address == null).
    block_start: u64 = 0,
    is_opaque: bool = false,
};
pub const Term = struct { atom: Atom, coefficient: u64 };
pub const Form = struct {
    width: u7,
    constant: u64 = 0,
    terms: [max_terms]Term = undefined,
    len: usize = 0,
    operations: usize = 0,

    pub fn mask(self: Form) u64 {
        return if (self.width == 32) std.math.maxInt(u32) else std.math.maxInt(u64);
    }
    pub fn atom(width: u7, value: Atom) Form {
        var f = Form{ .width = width };
        f.terms[0] = .{ .atom = value, .coefficient = 1 };
        f.len = 1;
        return f;
    }
    /// callback(context, atom) supplies the architectural value of this named
    /// register write/entry. A width32 atom is always zero extended first.
    pub fn evaluate(self: Form, context: anytype, callback: anytype) u64 {
        var value = self.constant;
        for (self.terms[0..self.len]) |term| {
            const raw = callback(context, term.atom);
            const input = if (term.atom.width == 32) raw & std.math.maxInt(u32) else raw;
            value +%= term.coefficient *% input;
        }
        return value & self.mask();
    }
    fn addTerm(self: *Form, term: Term) bool {
        const coefficient = term.coefficient & self.mask();
        if (coefficient == 0) return true;
        for (self.terms[0..self.len], 0..) |old, i| {
            if (std.meta.eql(old.atom, term.atom)) {
                self.terms[i].coefficient = (old.coefficient +% coefficient) & self.mask();
                if (self.terms[i].coefficient == 0) {
                    for (i..self.len - 1) |j| self.terms[j] = self.terms[j + 1];
                    self.len -= 1;
                }
                return true;
            }
        }
        if (self.len == max_terms) return false;
        self.terms[self.len] = .{ .atom = term.atom, .coefficient = coefficient };
        self.len += 1;
        return true;
    }
    pub fn combine(left: Form, right: Form, subtract: bool) ?Form {
        if (left.width != right.width) return null;
        if (left.operations + right.operations + 1 > max_operations) return null;
        var out = Form{ .width = left.width, .constant = (left.constant +% (if (subtract) 0 -% right.constant else right.constant)) & left.mask(), .operations = left.operations + right.operations + 1 };
        for (left.terms[0..left.len]) |term| if (!out.addTerm(term)) return null;
        for (right.terms[0..right.len]) |term| if (!out.addTerm(.{ .atom = term.atom, .coefficient = if (subtract) 0 -% term.coefficient else term.coefficient })) return null;
        return out;
    }
    pub fn shiftLeft(self: Form, amount: u6, instruction: bool) ?Form {
        if (amount >= self.width) return null;
        if (self.operations + @intFromBool(instruction) > max_operations) return null;
        var out = Form{ .width = self.width, .constant = (self.constant << amount) & self.mask(), .operations = self.operations + @intFromBool(instruction) };
        for (self.terms[0..self.len]) |term| if (!out.addTerm(.{ .atom = term.atom, .coefficient = term.coefficient << amount })) return null;
        return out;
    }
    pub fn low32(self: Form) Form {
        var out = Form{ .width = 32, .constant = self.constant & std.math.maxInt(u32), .operations = self.operations };
        for (self.terms[0..self.len]) |term| _ = out.addTerm(term); // at most eight inputs
        return out;
    }
};

pub const Value = struct { form: Form, write_address: ?u64 = null, is_opaque: bool = false };
pub const Report = struct { outputs: usize, total_outputs: usize, omitted_outputs: usize, partial: bool, fallback_writes: usize, unknown_instructions: usize };
pub const State = struct {
    values: [32]Value,
    block_start: u64 = 0,
    fallback_writes: usize = 0,
    unknown_instructions: usize = 0,

    pub fn init() State {
        return initAt(0);
    }
    pub fn initAt(block_start: u64) State {
        var s: State = undefined;
        s.block_start = block_start;
        s.fallback_writes = 0;
        s.unknown_instructions = 0;
        for (0..32) |i| s.values[i] = .{ .form = Form.atom(64, .{ .register = @intCast(i), .width = 64, .block_start = block_start }) };
        return s;
    }
    pub fn source(self: *const State, register: u5, width: u7, sp: bool) Form {
        if (register == 31 and !sp) return .{ .width = width };
        const v = self.values[register];
        if (v.form.width == width) return v.form;
        if (width == 32) return v.form.low32();
        // zext32 of a wrapped sum is not affine in its pre-write sources.
        // Constants are exact; all other W values remain one named atom.
        if (v.form.len == 0) return .{ .width = 64, .constant = v.form.constant };
        return Form.atom(64, .{ .register = register, .width = 32, .address = v.write_address, .block_start = if (v.write_address == null) self.block_start else 0, .is_opaque = v.is_opaque });
    }
    fn fresh(self: *State, register: u5, width: u7, address: u64, sp: bool, is_opaque: bool) void {
        if (register == 31 and !sp) return;
        self.values[register] = .{ .form = Form.atom(width, .{ .register = register, .width = width, .address = address, .is_opaque = is_opaque }), .write_address = address, .is_opaque = is_opaque };
    }
    pub fn applyUnknown(self: *State, address: u64) void {
        for (0..32) |i| self.fresh(@intCast(i), 64, address, true, true);
        self.unknown_instructions += 1;
    }
    /// Effect fields/tags come from arm64_steps.decode. Flags are deliberately
    /// outside this domain. Every source is captured before destination writes.
    pub fn apply(self: *State, e: anytype, address: u64) void {
        switch (e.op) {
            .branch, .bcond, .cbz, .cbnz, .tbz, .tbnz, .ret, .nop => return,
            .load, .store => {
                if (e.op == .load) {
                    self.fresh(e.dst, if (e.width == 64) 64 else 32, address, false, false);
                    if (@hasField(@TypeOf(e), "pair")) {
                        if (e.pair) self.fresh(e.src[2], if (e.width == 64) 64 else 32, address, false, false);
                    }
                }
                if (e.writeback) self.fresh(e.src[0], 64, address, true, false);
                return;
            },
            else => {},
        }
        if (e.dst == 31 and !e.dst_sp) return;
        var out: ?Form = null;
        switch (e.op) {
            .add, .sub => {
                const left = self.source(e.src[0], e.width, e.src_sp);
                var right: ?Form = if (e.immediate) |imm| Form{ .width = e.width, .constant = imm } else self.source(e.src[1], e.width, false);
                if (e.immediate == null and e.amount != 0) right = if (e.shift == .lsl) right.?.shiftLeft(e.amount, false) else null;
                if (right) |r| out = Form.combine(left, r, e.op == .sub);
            },
            .lsl => out = self.source(e.src[0], e.width, false).shiftLeft(e.amount, true),
            .movz, .movn => out = .{ .width = e.width, .constant = (if (e.op == .movn) ~e.immediate.? else e.immediate.?) & (if (e.width == 32) @as(u64, std.math.maxInt(u32)) else std.math.maxInt(u64)) },
            .or_ => if (!e.invert_right and e.amount == 0) {
                if (e.src[0] == 31) out = self.source(e.src[1], e.width, false) else if (e.src[1] == 31) out = self.source(e.src[0], e.width, false);
            },
            else => {},
        }
        if (out) |form| {
            self.values[e.dst] = .{ .form = form, .write_address = address };
        } else {
            self.fresh(e.dst, e.width, address, e.dst_sp, false);
            self.fallback_writes += 1;
        }
    }
    pub fn report(self: *const State, requested: usize) Report {
        var total: usize = 0;
        for (self.values) |v| if (v.write_address != null and v.form.operations >= 2) {
            total += 1;
        };
        const count = @min(total, @min(requested, max_outputs));
        return .{ .outputs = count, .total_outputs = total, .omitted_outputs = total - count, .partial = count != total, .fallback_writes = self.fallback_writes, .unknown_instructions = self.unknown_instructions };
    }
    pub fn writeSummaryText(self: *const State, w: anytype, requested: usize) !Report {
        const r = self.report(requested);
        if (r.total_outputs == 0) return r;
        try w.writeAll("  Local modular composition (covered instructions; assumes reached/normal completion; named atoms are unsolved values):\n");
        var emitted: usize = 0;
        for (self.values, 0..) |v, reg| {
            if (v.write_address == null or v.form.operations < 2) continue;
            if (emitted == r.outputs) break;
            try w.writeAll("    ");
            try writeAtom(w, .{ .register = @intCast(reg), .width = v.form.width, .address = v.write_address }, v.form.width);
            try w.writeAll(" = ");
            try writeForm(w, v.form);
            try w.writeAll("\n");
            emitted += 1;
        }
        try w.print("    outputs={d}/{d}; omitted={d}; partial={}; fresh_atom_fallback_writes={d}; unknown_barriers={d}\n", .{ r.outputs, r.total_outputs, r.omitted_outputs, r.partial, r.fallback_writes, r.unknown_instructions });
        return r;
    }
    pub fn writeSummaryJson(self: *const State, w: anytype, requested: usize) !Report {
        const r = self.report(requested);
        try w.writeAll("{\"model\":\"bounded_local_modular_affine_v1\",\"scope\":\"covered instructions; assumes reached/normal completion; named atoms are unsolved values; no cross-block recurrence inference\",\"outputs\":[");
        var emitted: usize = 0;
        for (self.values, 0..) |v, reg| {
            if (v.write_address == null or v.form.operations < 2) continue;
            if (emitted == r.outputs) break;
            if (emitted != 0) try w.writeAll(",");
            try w.print("{{\"register\":{d},\"width_bits\":{d},\"write_address\":\"0x{x}\",\"expression\":\"", .{ reg, v.form.width, v.write_address.? });
            try writeForm(w, v.form);
            try w.writeAll("\"}");
            emitted += 1;
        }
        try w.print("],\"total_outputs\":{d},\"emitted_outputs\":{d},\"omitted_outputs\":{d},\"partial\":{},\"fresh_atom_fallback_writes\":{d},\"unknown_barriers\":{d},\"term_limit\":8,\"operation_limit\":128}}", .{ r.total_outputs, r.outputs, r.omitted_outputs, r.partial, r.fallback_writes, r.unknown_instructions });
        return r;
    }
};

fn writeAtom(w: anytype, a: Atom, width: u7) !void {
    const low = width == 32 and a.width == 64;
    const ext = width == 64 and a.width == 32;
    if (low) try w.writeAll("lo32(");
    if (ext) try w.writeAll("zext32(");
    if (a.register == 31) try w.writeAll(if (a.width == 32) "wsp" else "sp") else try w.print("{s}{d}", .{ if (a.width == 32) @as([]const u8, "w") else "x", a.register });
    if (a.address) |address| try w.print("@{s}0x{x}", .{ if (a.is_opaque) @as([]const u8, "opaque_") else "", address }) else try w.print("@in_0x{x}", .{a.block_start});
    if (low or ext) try w.writeAll(")");
}
pub fn writeForm(w: anytype, f: Form) !void {
    try w.print("u{d}(", .{f.width});
    var any = false;
    for (f.terms[0..f.len]) |term| {
        const negative = term.coefficient > f.mask() / 2;
        const magnitude = if (negative) (0 -% term.coefficient) & f.mask() else term.coefficient;
        if (any) try w.writeAll(if (negative) " - " else " + ") else if (negative) try w.writeAll("-");
        if (magnitude != 1) try w.print("{d}*", .{magnitude});
        try writeAtom(w, term.atom, f.width);
        any = true;
    }
    if (f.constant != 0 or !any) {
        if (any) try w.writeAll(" + ");
        try w.print("{d}", .{f.constant});
    }
    try w.writeAll(")");
}

test "modular coefficient coalescing cancellation and wrap" {
    const input = Form.atom(32, .{ .register = 0, .width = 64 });
    const byte = Form.atom(32, .{ .register = 4, .width = 32, .address = 20 });
    const sub = Form.combine(byte, input, true).?;
    const out = Form.combine(sub, input.shiftLeft(3, false).?, false).?;
    try std.testing.expectEqual(@as(usize, 2), out.len);
    try std.testing.expectEqual(@as(u64, 7), out.terms[1].coefficient);
    const cancelled = Form.combine(input, input, true).?;
    try std.testing.expectEqual(@as(usize, 0), cancelled.len);
    const overflow = Form.combine(.{ .width = 32, .constant = 0xffffffff }, .{ .width = 32, .constant = 2 }, false).?;
    try std.testing.expectEqual(@as(u64, 1), overflow.constant);
}

test "bounded forms reject excess terms and operation depth" {
    var out = Form{ .width = 64 };
    for (0..max_terms) |i| out = Form.combine(out, Form.atom(64, .{ .register = @intCast(i), .width = 64 }), false).?;
    try std.testing.expect(Form.combine(out, Form.atom(64, .{ .register = 9, .width = 64 }), false) == null);
    out.operations = max_operations;
    try std.testing.expect(out.shiftLeft(1, true) == null);
    try std.testing.expect(Form.combine(out, .{ .width = 64 }, false) == null);
}

test "zero extension of wrapped W form is an atomic write value" {
    var state = State.init();
    state.values[1] = .{ .form = Form.combine(Form.atom(32, .{ .register = 0, .width = 64 }), .{ .width = 32, .constant = 1 }, false).?, .write_address = 100 };
    const ext = state.source(1, 64, false);
    try std.testing.expectEqual(@as(usize, 1), ext.len);
    try std.testing.expectEqual(@as(u5, 1), ext.terms[0].atom.register);
    try std.testing.expectEqual(@as(u7, 32), ext.terms[0].atom.width);
    try std.testing.expectEqual(@as(?u64, 100), ext.terms[0].atom.address);
    const truncated = Form.combine(Form.atom(64, .{ .register = 0, .width = 64 }), .{ .width = 64, .constant = 0x100000001 }, false).?.low32();
    try std.testing.expectEqual(@as(u64, 1), truncated.constant);
    state.applyUnknown(200);
    try std.testing.expectEqual(@as(usize, 0), state.report(8).outputs);
    try std.testing.expect(state.source(1, 32, false).terms[0].atom.is_opaque);
}

test "incoming atom identity is qualified by block without changing evaluation" {
    const a = State.initAt(0x7000);
    const b = State.initAt(0x8000);
    const left = a.source(2, 32, false);
    const right = b.source(2, 32, false);
    try std.testing.expect(!std.meta.eql(left.terms[0].atom, right.terms[0].atom));
    const resolver = struct {
        fn value(_: void, _: Atom) u64 {
            return 0x100000007;
        }
    }.value;
    try std.testing.expectEqual(@as(u64, 7), left.evaluate({}, resolver));
    try std.testing.expectEqual(left.evaluate({}, resolver), right.evaluate({}, resolver));
    try std.testing.expectEqual(@as(u64, 0), State.init().source(2, 64, false).terms[0].atom.block_start);
}
