// Phora — Lifter
// Walks a procedure's basic blocks, transforms each instruction to IR statements.
// Produces structured IR that LLMs can interpret into pseudocode.

const std = @import("std");
const types = @import("../types.zig");
const ir = @import("ir.zig");
const db_mod = @import("../store/database.zig");

// v7.8.0 maturity passes
const pass_const_fold = @import("passes/const_fold.zig");
const pass_dead_store = @import("passes/dead_store.zig");
const pass_reg_to_var = @import("passes/reg_to_var.zig");
const pass_stack_slot = @import("passes/stack_slot.zig");
const pass_call_arg_fixup = @import("passes/call_arg_fixup.zig");
// v7.9.1 maturity pass
const pass_fp_alias = @import("passes/fp_alias.zig");

/// Run the v7.8.0 maturity passes on `func` in the order specified by the
/// W1/W4 design notes:
///   1. call_arg_fixup — needs raw `argN` assigns, so first.
///   2. const_fold     — folds literals (uses string ops on raw operands).
///   3. dead_store     — kills assigns whose dest is overwritten.
///   4. stack_slot     — renames `[sp+N]` → `stack_K` so reg_to_var skips them.
///   5. reg_to_var     — last; renames temporaries that don't escape.
///
/// `allocator` should be a long-lived allocator (typically an arena tied to
/// the IR's lifetime) — const_fold and stack_slot allocate strings that the
/// IR retains. Errors propagate (OOM is the only realistic failure).
pub fn runMaturityPasses(
    allocator: std.mem.Allocator,
    func: *types.IRFunction,
) !void {
    try pass_call_arg_fixup.run(allocator, func);
    try pass_const_fold.run(allocator, func);
    try pass_dead_store.run(allocator, func);
    try pass_stack_slot.run(allocator, func);
    // v7.9.1 Q3: rewrite `[V]` where V aliases fp/sp ± N into direct
    // `[fp ± N]` form. Must run AFTER stack_slot (so we don't compete on
    // the same `[sp+N]` patterns) and BEFORE reg_to_var (so the rewritten
    // bases survive — reg_to_var would otherwise rename `arg0` → `localK`).
    try pass_fp_alias.run(allocator, func);
    try pass_reg_to_var.run(allocator, func);
}

/// Convenience wrapper: lift a procedure and immediately run all maturity
/// passes. Use this from new pipeline code; legacy callers can still call
/// `liftProcedure` directly to skip passes (e.g. lift-only smoke tests).
pub fn liftProcedureMature(
    allocator: std.mem.Allocator,
    proc: *const types.Procedure,
    db: *const db_mod.Database,
) !types.IRFunction {
    var func = try liftProcedure(allocator, proc, db);
    errdefer {
        allocator.free(func.statements);
        allocator.free(func.variables);
    }
    try runMaturityPasses(allocator, &func);
    return func;
}

/// Lift a single procedure to IR.
pub fn liftProcedure(
    allocator: std.mem.Allocator,
    proc: *const types.Procedure,
    db: *const db_mod.Database,
) !types.IRFunction {
    var statements = std.array_list.Managed(types.IRStatement).init(allocator);
    errdefer statements.deinit();

    var variables = std.array_list.Managed(types.Variable).init(allocator);
    errdefer variables.deinit();

    var seen_regs = std.StringHashMap(void).init(allocator);
    defer seen_regs.deinit();

    // Walk each basic block's instructions
    for (proc.basic_blocks) |block| {
        var addr = block.start;
        const block_end = block.start + block.size;

        while (addr < block_end) {
            if (db.getInstruction(addr)) |inst| {
                const stmt = liftInstruction(allocator, inst, proc.entry, db, &seen_regs, &variables) catch {
                    // If we can't lift an instruction, emit a nop
                    try statements.append(ir.nop(addr));
                    addr += inst.size;
                    continue;
                };
                try statements.append(stmt);
                addr += inst.size;
            } else {
                // No instruction at this address, skip 4 bytes (ARM64/MIPS32)
                addr += 4;
            }
        }
    }

    return .{
        .address = proc.entry,
        .name = proc.name,
        .statements = try statements.toOwnedSlice(),
        .variables = try variables.toOwnedSlice(),
    };
}

/// Lift a single instruction to an IR statement.
fn liftInstruction(
    allocator: std.mem.Allocator,
    inst: types.Instruction,
    proc_entry: u64,
    db: *const db_mod.Database,
    seen_regs: *std.StringHashMap(void),
    variables: *std.array_list.Managed(types.Variable),
) !types.IRStatement {
    // v7.15.3 C1.c: dupe inst_operands into the lifter's allocator. The
    // input is a slice into a HashMap bucket (db.instructions) that may be
    // moved by a later addInstruction call. IRStatement fields built from
    // this slice via the various direct-use paths (catch fallbacks, parsing
    // helpers that return the input on failure) would dangle once the
    // bucket moves; the renderer would SIGSEGV in std.mem.indexOfScalar.
    // splitOperands also dupes its tokens via the same allocator.
    const inst_operands = allocator.dupe(u8, inst.operands) catch inst.operands;
    const mnemonic = inst.mnemonic;

    // MOV Xd, Xn — assignment
    if (eqlIgnoreCase(mnemonic, "mov")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            return ir.assign(inst.address, regVar(parts.dest.?), resolveOperand(parts.src1.?, db));
        }
    }

    // ADD/SUB Xd, Xn, op2 — arithmetic assignment (ARM64 + MIPS add/addu/sub/subu)
    if (eqlIgnoreCase(mnemonic, "add") or eqlIgnoreCase(mnemonic, "sub") or
        eqlIgnoreCase(mnemonic, "addu") or eqlIgnoreCase(mnemonic, "subu"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const op = if (eqlIgnoreCase(mnemonic, "add") or eqlIgnoreCase(mnemonic, "addu")) "+" else "-";
            const src_expr = if (parts.src2) |s2|
                formatBinaryOp(allocator, regVar(parts.src1.?), op, resolveOperand(s2, db))
            else
                regVar(parts.src1.?);
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS addiu/addi — immediate add: dest = src + imm
    if (eqlIgnoreCase(mnemonic, "addiu") or eqlIgnoreCase(mnemonic, "addi")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = if (parts.src2) |s2|
                formatBinaryOp(allocator, regVar(parts.src1.?), "+", resolveOperand(s2, db))
            else
                regVar(parts.src1.?);
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS lui — load upper immediate: dest = imm << 16
    if (eqlIgnoreCase(mnemonic, "lui")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = formatBinaryOp(allocator, resolveOperand(parts.src1.?, db), "<< 16", "");
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS mul (3-operand) — multiply: dest = src1 * src2
    if (eqlIgnoreCase(mnemonic, "mul")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = if (parts.src2) |s2|
                formatBinaryOp(allocator, regVar(parts.src1.?), "*", resolveOperand(s2, db))
            else
                inst_operands;
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS bitwise: and/or/xor/nor and immediate variants andi/ori/xori
    if (eqlIgnoreCase(mnemonic, "and") or eqlIgnoreCase(mnemonic, "or") or
        eqlIgnoreCase(mnemonic, "xor") or eqlIgnoreCase(mnemonic, "nor") or
        eqlIgnoreCase(mnemonic, "andi") or eqlIgnoreCase(mnemonic, "ori") or
        eqlIgnoreCase(mnemonic, "xori"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const op = if (eqlIgnoreCase(mnemonic, "and") or eqlIgnoreCase(mnemonic, "andi"))
                "&"
            else if (eqlIgnoreCase(mnemonic, "or") or eqlIgnoreCase(mnemonic, "ori"))
                "|"
            else if (eqlIgnoreCase(mnemonic, "xor") or eqlIgnoreCase(mnemonic, "xori"))
                "^"
            else
                "~|"; // nor
            const src_expr = if (parts.src2) |s2|
                formatBinaryOp(allocator, regVar(parts.src1.?), op, resolveOperand(s2, db))
            else
                regVar(parts.src1.?);
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS shifts: sll/srl/sra (by immediate), sllv/srlv/srav (by register)
    if (eqlIgnoreCase(mnemonic, "sll") or eqlIgnoreCase(mnemonic, "srl") or
        eqlIgnoreCase(mnemonic, "sra") or eqlIgnoreCase(mnemonic, "sllv") or
        eqlIgnoreCase(mnemonic, "srlv") or eqlIgnoreCase(mnemonic, "srav"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const op = if (eqlIgnoreCase(mnemonic, "sll") or eqlIgnoreCase(mnemonic, "sllv"))
                "<<"
            else if (eqlIgnoreCase(mnemonic, "srl") or eqlIgnoreCase(mnemonic, "srlv"))
                ">>"
            else
                ">>a"; // arithmetic right shift
            const src_expr = if (parts.src2) |s2|
                formatBinaryOp(allocator, regVar(parts.src1.?), op, resolveOperand(s2, db))
            else
                regVar(parts.src1.?);
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS slt/sltu/slti/sltiu — set on less than (compare producing a result)
    if (eqlIgnoreCase(mnemonic, "slt") or eqlIgnoreCase(mnemonic, "sltu") or
        eqlIgnoreCase(mnemonic, "slti") or eqlIgnoreCase(mnemonic, "sltiu"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const cmp_op = if (eqlIgnoreCase(mnemonic, "sltu") or eqlIgnoreCase(mnemonic, "sltiu"))
                "<u"
            else
                "<";
            const rhs = if (parts.src2) |s2| resolveOperand(s2, db) else "0";
            // Emit as compare (condition flag) AND assign (result register)
            return ir.compare(inst.address, cmp_op, regVar(parts.src1.?), rhs);
        }
    }

    // MIPS mfhi/mflo — move from HI/LO register
    if (eqlIgnoreCase(mnemonic, "mfhi") or eqlIgnoreCase(mnemonic, "mflo")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src = if (eqlIgnoreCase(mnemonic, "mfhi")) "hi" else "lo";
            return ir.assign(inst.address, regVar(parts.dest.?), src);
        }
    }

    // MIPS mult/multu/div/divu — multiply/divide into HI:LO
    if (eqlIgnoreCase(mnemonic, "mult") or eqlIgnoreCase(mnemonic, "multu") or
        eqlIgnoreCase(mnemonic, "div") or eqlIgnoreCase(mnemonic, "divu"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            const op = if (eqlIgnoreCase(mnemonic, "mult") or eqlIgnoreCase(mnemonic, "multu")) "*" else "/";
            const src_expr = formatBinaryOp(allocator, regVar(parts.dest.?), op, regVar(parts.src1.?));
            return ir.assign(inst.address, "hi:lo", src_expr);
        }
    }

    // MIPS madd/msub — multiply-add/sub into HI:LO accumulator
    if (eqlIgnoreCase(mnemonic, "madd") or eqlIgnoreCase(mnemonic, "msub")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            const op = if (eqlIgnoreCase(mnemonic, "madd")) "+" else "-";
            const mul_expr = formatBinaryOp(allocator, regVar(parts.dest.?), "*", regVar(parts.src1.?));
            const src_expr = formatBinaryOp(allocator, "hi:lo", op, mul_expr);
            return ir.assign(inst.address, "hi:lo", src_expr);
        }
    }

    // MIPS clz/clo — count leading zeros/ones
    if (eqlIgnoreCase(mnemonic, "clz") or eqlIgnoreCase(mnemonic, "clo")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const func = if (eqlIgnoreCase(mnemonic, "clz")) "clz" else "clo";
            const src_expr = std.fmt.allocPrint(allocator, "{s}({s})", .{ func, regVar(parts.src1.?) }) catch inst_operands;
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS movz/movn — conditional move
    if (eqlIgnoreCase(mnemonic, "movz") or eqlIgnoreCase(mnemonic, "movn")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            return ir.assign(inst.address, regVar(parts.dest.?), inst_operands);
        }
    }

    // MIPS load: lw/lb/lbu/lh/lhu/lwl/lwr/lwc1
    if (eqlIgnoreCase(mnemonic, "lw") or eqlIgnoreCase(mnemonic, "lb") or
        eqlIgnoreCase(mnemonic, "lbu") or eqlIgnoreCase(mnemonic, "lh") or
        eqlIgnoreCase(mnemonic, "lhu") or eqlIgnoreCase(mnemonic, "lwl") or
        eqlIgnoreCase(mnemonic, "lwr") or eqlIgnoreCase(mnemonic, "lwc1"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = if (parts.src1) |s| resolveOperand(s, db) else "mem";
            return ir.load(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS store: sw/sb/sh/swl/swr/swc1
    if (eqlIgnoreCase(mnemonic, "sw") or eqlIgnoreCase(mnemonic, "sb") or
        eqlIgnoreCase(mnemonic, "sh") or eqlIgnoreCase(mnemonic, "swl") or
        eqlIgnoreCase(mnemonic, "swr") or eqlIgnoreCase(mnemonic, "swc1"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            const dest_expr = if (parts.src1) |s| resolveOperand(s, db) else "mem";
            return ir.store(inst.address, dest_expr, regVar(parts.dest.?));
        }
    }

    // MIPS branch: beq/bne/blez/bgtz/bltz/bgez + likely variants
    if (eqlIgnoreCase(mnemonic, "beq") or eqlIgnoreCase(mnemonic, "bne") or
        eqlIgnoreCase(mnemonic, "beql") or eqlIgnoreCase(mnemonic, "bnel"))
    {
        // beq/bne rs, rt, target — two-register compare-and-branch
        const parts = splitOperands(allocator, inst_operands);
        const condition = if (eqlIgnoreCase(mnemonic, "beq") or eqlIgnoreCase(mnemonic, "beql")) "eq" else "ne";
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        _ = parts;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    if (eqlIgnoreCase(mnemonic, "blez") or eqlIgnoreCase(mnemonic, "bgtz") or
        eqlIgnoreCase(mnemonic, "bltz") or eqlIgnoreCase(mnemonic, "bgez") or
        eqlIgnoreCase(mnemonic, "blezl") or eqlIgnoreCase(mnemonic, "bgtzl") or
        eqlIgnoreCase(mnemonic, "bltzl") or eqlIgnoreCase(mnemonic, "bgezl"))
    {
        // Single-register branch: rs, target
        const condition = if (eqlIgnoreCase(mnemonic, "blez") or eqlIgnoreCase(mnemonic, "blezl"))
            "le_zero"
        else if (eqlIgnoreCase(mnemonic, "bgtz") or eqlIgnoreCase(mnemonic, "bgtzl"))
            "gt_zero"
        else if (eqlIgnoreCase(mnemonic, "bltz") or eqlIgnoreCase(mnemonic, "bltzl"))
            "lt_zero"
        else
            "ge_zero";
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // MIPS FPU branch: bc1t/bc1f
    if (eqlIgnoreCase(mnemonic, "bc1t") or eqlIgnoreCase(mnemonic, "bc1f")) {
        const condition = if (eqlIgnoreCase(mnemonic, "bc1t")) "fpu_true" else "fpu_false";
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // MIPS jal — jump and link (function call)
    if (eqlIgnoreCase(mnemonic, "jal")) {
        const target_name = resolveCallTarget(inst_operands, db);
        return ir.call(inst.address, target_name, null, "$v0");
    }

    // MIPS jalr — jump and link register (indirect call)
    if (eqlIgnoreCase(mnemonic, "jalr")) {
        const parts = splitOperands(allocator, inst_operands);
        // jalr can be "jalr rd, rs" or just "jalr rs" (rd defaults to $ra)
        const target_name = if (parts.src1) |reg| regVar(reg) else if (parts.dest) |reg| regVar(reg) else "unknown";
        return ir.call(inst.address, target_name, null, "$v0");
    }

    // MIPS jr — jump register (return if $ra, else indirect branch)
    if (eqlIgnoreCase(mnemonic, "jr")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest) |reg| {
            if (eqlIgnoreCase(reg, "$ra")) {
                return ir.ret(inst.address, "$v0");
            }
            // Indirect jump (jump table, etc.)
            const target = parseAddressFromOperands(inst_operands);
            const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
            return ir.branch(inst.address, null, target_offset, null);
        }
        return ir.ret(inst.address, "$v0");
    }

    // MIPS syscall
    if (eqlIgnoreCase(mnemonic, "syscall")) {
        return ir.call(inst.address, "syscall", null, "$v0");
    }

    // MIPS FPU arithmetic: add.s/sub.s/mul.s/div.s → assign
    if (eqlIgnoreCase(mnemonic, "add.s") or eqlIgnoreCase(mnemonic, "sub.s") or
        eqlIgnoreCase(mnemonic, "mul.s") or eqlIgnoreCase(mnemonic, "div.s"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const op = if (eqlIgnoreCase(mnemonic, "add.s"))
                "+"
            else if (eqlIgnoreCase(mnemonic, "sub.s"))
                "-"
            else if (eqlIgnoreCase(mnemonic, "mul.s"))
                "*"
            else
                "/";
            const src_expr = if (parts.src2) |s2|
                formatBinaryOp(allocator, regVar(parts.src1.?), op, regVar(s2))
            else
                regVar(parts.src1.?);
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MIPS FPU compare: c.eq.s/c.lt.s/c.le.s → compare
    if (eqlIgnoreCase(mnemonic, "c.eq.s") or eqlIgnoreCase(mnemonic, "c.lt.s") or
        eqlIgnoreCase(mnemonic, "c.le.s"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            const cmp_op = if (eqlIgnoreCase(mnemonic, "c.eq.s"))
                "=="
            else if (eqlIgnoreCase(mnemonic, "c.lt.s"))
                "<"
            else
                "<=";
            return ir.compare(inst.address, cmp_op, regVar(parts.dest.?), regVar(parts.src1.?));
        }
    }

    // MIPS FPU move/convert: mtc1/mfc1/cvt.s.w/cvt.w.s/trunc.w.s → assign
    if (eqlIgnoreCase(mnemonic, "mtc1") or eqlIgnoreCase(mnemonic, "mfc1") or
        eqlIgnoreCase(mnemonic, "cvt.s.w") or eqlIgnoreCase(mnemonic, "cvt.w.s") or
        eqlIgnoreCase(mnemonic, "trunc.w.s"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = if (parts.src1) |s| regVar(s) else inst_operands;
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // BL target — ARM64 function call
    if (eqlIgnoreCase(mnemonic, "bl")) {
        const target_name = resolveCallTarget(inst_operands, db);
        return ir.call(inst.address, target_name, null, "arg0");
    }

    // BLR Xn — ARM64 indirect function call
    if (eqlIgnoreCase(mnemonic, "blr")) {
        const parts = splitOperands(allocator, inst_operands);
        const target_name = if (parts.dest) |reg| regVar(reg) else "unknown";
        return ir.call(inst.address, target_name, null, "arg0");
    }

    // CMP Xn, op2 — comparison
    if (eqlIgnoreCase(mnemonic, "cmp")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            return ir.compare(inst.address, "cmp", regVar(parts.dest.?), resolveOperand(parts.src1.?, db));
        }
    }

    // CMN Xn, op2 — compare negative
    if (eqlIgnoreCase(mnemonic, "cmn")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            return ir.compare(inst.address, "cmn", regVar(parts.dest.?), resolveOperand(parts.src1.?, db));
        }
    }

    // TST Xn, op2 — test bits
    if (eqlIgnoreCase(mnemonic, "tst")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            return ir.compare(inst.address, "tst", regVar(parts.dest.?), resolveOperand(parts.src1.?, db));
        }
    }

    // B.cond target — conditional branch
    if (mnemonic.len >= 2 and (mnemonic[0] == 'b' or mnemonic[0] == 'B') and mnemonic[1] == '.') {
        const condition = mnemonic[2..]; // eq, ne, lt, gt, etc.
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // B target — unconditional branch
    if (eqlIgnoreCase(mnemonic, "b") and inst_operands.len > 0) {
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, null, target_offset, null);
    }

    // CBZ/CBNZ — compare and branch on zero/nonzero
    if (eqlIgnoreCase(mnemonic, "cbz") or eqlIgnoreCase(mnemonic, "cbnz")) {
        const condition = if (eqlIgnoreCase(mnemonic, "cbz")) "eq_zero" else "ne_zero";
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // TBZ/TBNZ — test bit and branch
    if (eqlIgnoreCase(mnemonic, "tbz") or eqlIgnoreCase(mnemonic, "tbnz")) {
        const condition = if (eqlIgnoreCase(mnemonic, "tbz")) "bit_clear" else "bit_set";
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // RET — return (ARM64)
    if (eqlIgnoreCase(mnemonic, "ret")) {
        return ir.ret(inst.address, "arg0");
    }

    // LDR Xd, [Xn, #imm] — load (ARM64)
    if (eqlIgnoreCase(mnemonic, "ldr") or eqlIgnoreCase(mnemonic, "ldp") or
        eqlIgnoreCase(mnemonic, "ldrb") or eqlIgnoreCase(mnemonic, "ldrh") or
        eqlIgnoreCase(mnemonic, "ldrsw") or eqlIgnoreCase(mnemonic, "ldrsh") or
        eqlIgnoreCase(mnemonic, "ldrsb"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = if (parts.src1) |s| resolveOperand(s, db) else "mem";
            return ir.load(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // STR Xd, [Xn, #imm] — store (ARM64)
    if (eqlIgnoreCase(mnemonic, "str") or eqlIgnoreCase(mnemonic, "stp") or
        eqlIgnoreCase(mnemonic, "strb") or eqlIgnoreCase(mnemonic, "strh"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            const dest_expr = if (parts.src1) |s| resolveOperand(s, db) else "mem";
            return ir.store(inst.address, dest_expr, regVar(parts.dest.?));
        }
    }

    // STP X29, X30, [SP, #-N]! — prologue, treat as store
    if (eqlIgnoreCase(mnemonic, "stp")) {
        return ir.store(inst.address, "stack", "frame_setup");
    }

    // ADRP Xd, page — address computation
    if (eqlIgnoreCase(mnemonic, "adrp") or eqlIgnoreCase(mnemonic, "adr")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = if (parts.src1) |s| resolveOperand(s, db) else "addr";
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // MUL, MADD, etc. — arithmetic (ARM64)
    if (eqlIgnoreCase(mnemonic, "madd") or eqlIgnoreCase(mnemonic, "msub")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            return ir.assign(inst.address, regVar(parts.dest.?), inst_operands);
        }
    }

    // AND/ORR/EOR/LSL/LSR/ASR — bitwise/shift (ARM64)
    if (eqlIgnoreCase(mnemonic, "orr") or eqlIgnoreCase(mnemonic, "eor") or
        eqlIgnoreCase(mnemonic, "lsl") or eqlIgnoreCase(mnemonic, "lsr") or
        eqlIgnoreCase(mnemonic, "asr"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            return ir.assign(inst.address, regVar(parts.dest.?), inst_operands);
        }
    }

    // NOP
    if (eqlIgnoreCase(mnemonic, "nop")) {
        return ir.nop(inst.address);
    }

    // ====================================================================
    // x86_64 specific patterns (2-operand form, Intel syntax)
    // ====================================================================

    // x86_64 XOR reg, reg → zero idiom (most common register-clearing pattern)
    if (eqlIgnoreCase(mnemonic, "xor")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            if (std.ascii.eqlIgnoreCase(parts.dest.?, parts.src1.?)) {
                try trackVariable(seen_regs, variables, parts.dest.?);
                return ir.assign(inst.address, regVar(parts.dest.?), "#0x0");
            }
            // General XOR: dest = dest ^ src
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = formatBinaryOp(allocator, regVar(parts.dest.?), "^", resolveOperand(parts.src1.?, db));
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // x86_64 LEA — address computation (often used for arithmetic)
    if (eqlIgnoreCase(mnemonic, "lea")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            return ir.assign(inst.address, regVar(parts.dest.?), resolveOperand(parts.src1.?, db));
        }
    }

    // x86_64 PUSH reg — store to stack
    if (eqlIgnoreCase(mnemonic, "push")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            return ir.store(inst.address, "stack", regVar(parts.dest.?));
        }
    }

    // x86_64 POP reg — load from stack
    if (eqlIgnoreCase(mnemonic, "pop")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            return ir.load(inst.address, regVar(parts.dest.?), "stack");
        }
    }

    // x86_64 CALL rel32 or CALL [reg] — function call
    if (eqlIgnoreCase(mnemonic, "call")) {
        const target_name = resolveCallTarget(inst_operands, db);
        return ir.call(inst.address, target_name, null, "result");
    }

    // x86_64 RET — already handled above (shared with ARM64)

    // x86_64 JMP — unconditional branch
    if (eqlIgnoreCase(mnemonic, "jmp")) {
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, null, target_offset, null);
    }

    // x86_64 Jcc — conditional branches (je, jne, jl, jle, jg, jge, jb, jbe, ja, jae, js, jns, jo, jno, jp, jnp)
    if (mnemonic.len >= 2 and (mnemonic[0] == 'j' or mnemonic[0] == 'J') and mnemonic[1] != 'm') {
        const condition = mnemonic[1..]; // e, ne, l, le, g, ge, etc.
        const target = parseAddressFromOperands(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // x86_64 TEST — test bits (like TST in ARM)
    if (eqlIgnoreCase(mnemonic, "test")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            return ir.compare(inst.address, "test", regVar(parts.dest.?), resolveOperand(parts.src1.?, db));
        }
    }

    // x86_64 IMUL — signed multiply (2-operand: dest *= src, or 3-operand: dest = src1 * src2)
    if (eqlIgnoreCase(mnemonic, "imul")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            if (parts.src2) |s2| {
                // 3-operand: dest = src1 * src2
                const src_expr = formatBinaryOp(allocator, regVar(parts.src1.?), "*", resolveOperand(s2, db));
                return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
            } else if (parts.src1) |s1| {
                // 2-operand: dest = dest * src
                const src_expr = formatBinaryOp(allocator, regVar(parts.dest.?), "*", resolveOperand(s1, db));
                return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
            }
        }
    }

    // x86_64 LEAVE — equivalent to mov rsp,rbp + pop rbp
    if (eqlIgnoreCase(mnemonic, "leave")) {
        return ir.assign(inst.address, "stack_ptr", "frame_ptr");
    }

    // x86_64 SYSCALL
    if (eqlIgnoreCase(mnemonic, "syscall")) {
        return ir.call(inst.address, "syscall", null, "result");
    }

    // x86_64 INT3 — breakpoint
    if (eqlIgnoreCase(mnemonic, "int3")) {
        return ir.call(inst.address, "breakpoint", null, null);
    }

    // x86_64 2-operand ADD/SUB with memory operand (load+op or store+op)
    // e.g., "add rax, [rbp - 0x40]" or "add [rbp - 0x40], rax"
    if (eqlIgnoreCase(mnemonic, "add") or eqlIgnoreCase(mnemonic, "sub") or
        eqlIgnoreCase(mnemonic, "and") or eqlIgnoreCase(mnemonic, "or") or
        eqlIgnoreCase(mnemonic, "shl") or eqlIgnoreCase(mnemonic, "shr") or
        eqlIgnoreCase(mnemonic, "sar"))
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null and parts.src2 == null) {
            // 2-operand form: dest op= src (x86_64)
            try trackVariable(seen_regs, variables, parts.dest.?);
            const op = if (eqlIgnoreCase(mnemonic, "add")) "+" else if (eqlIgnoreCase(mnemonic, "sub")) "-" else if (eqlIgnoreCase(mnemonic, "and")) "&" else if (eqlIgnoreCase(mnemonic, "or")) "|" else if (eqlIgnoreCase(mnemonic, "shl")) "<<" else if (eqlIgnoreCase(mnemonic, "shr")) ">>" else ">>>"; // sar = arithmetic right shift
            const src_expr = formatBinaryOp(allocator, regVar(parts.dest.?), op, resolveOperand(parts.src1.?, db));
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // x86_64 MOV with memory operand — detect load vs store
    // Already handled by the shared "mov" pattern above for reg-to-reg.
    // This catches: mov [mem], reg (store) and mov reg, [mem] (load)
    if (eqlIgnoreCase(mnemonic, "mov") or eqlIgnoreCase(mnemonic, "movzx") or eqlIgnoreCase(mnemonic, "movsx")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            // If dest contains '[' → store
            if (std.mem.indexOf(u8, parts.dest.?, "[") != null) {
                return ir.store(inst.address, parts.dest.?, regVar(parts.src1.?));
            }
            // If src contains '[' → load
            if (std.mem.indexOf(u8, parts.src1.?, "[") != null) {
                try trackVariable(seen_regs, variables, parts.dest.?);
                return ir.load(inst.address, regVar(parts.dest.?), resolveOperand(parts.src1.?, db));
            }
            // reg-to-reg (already handled by shared mov above, but catch MOVZX/MOVSX)
            try trackVariable(seen_regs, variables, parts.dest.?);
            return ir.assign(inst.address, regVar(parts.dest.?), resolveOperand(parts.src1.?, db));
        }
    }

    // x86_64 NEG/NOT — unary operations
    if (eqlIgnoreCase(mnemonic, "neg") or eqlIgnoreCase(mnemonic, "not")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const prefix = if (eqlIgnoreCase(mnemonic, "neg")) "-" else "~";
            const src_expr = std.fmt.allocPrint(allocator, "{s}{s}", .{ prefix, regVar(parts.dest.?) }) catch inst_operands;
            return ir.assign(inst.address, regVar(parts.dest.?), src_expr);
        }
    }

    // x86_64 CDQ/CQO — sign-extend rax to rdx:rax
    if (eqlIgnoreCase(mnemonic, "cdq") or eqlIgnoreCase(mnemonic, "cqo")) {
        return ir.assign(inst.address, "arg2", "sign_extend(result)");
    }

    // x86_64 UD2 — undefined instruction (unreachable marker)
    if (eqlIgnoreCase(mnemonic, "ud2")) {
        return ir.call(inst.address, "unreachable", null, null);
    }

    // Default: emit as assign with mnemonic info so unknown instructions are visible
    {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null) {
            try trackVariable(seen_regs, variables, parts.dest.?);
            const src_expr = std.fmt.allocPrint(allocator, "{s} {s}", .{ mnemonic, inst_operands }) catch inst_operands;
            return ir.assign(inst.address, ir.registerToVariable(parts.dest.?), src_expr);
        }
        // No destination register: emit assign with "?" dest showing the mnemonic
        const src_expr = std.fmt.allocPrint(allocator, "{s} {s}", .{ mnemonic, inst_operands }) catch mnemonic;
        return ir.assign(inst.address, "?", src_expr);
    }
}

// ============================================================================
// Helpers
// ============================================================================

const OperandParts = struct {
    dest: ?[]const u8 = null,
    src1: ?[]const u8 = null,
    src2: ?[]const u8 = null,
};

/// Split operand string "dest, src1, src2" into components.
/// Works for both ARM64 ("Xd, Xn, op2") and MIPS ("$rd, $rs, $rt").
/// Bracket-enclosed memory references like "[sp, #0x50]" or MIPS "offset($base)" are kept as a single operand.
fn splitOperands(allocator: std.mem.Allocator, operands: []const u8) OperandParts {
    // v7.15.3 C1.c: each returned token is duped into `allocator` so that
    // downstream IRStatement fields (target/src/dest) reference arena-owned
    // memory rather than the input slice. The input typically points into
    // an Instruction.operands_buf field stored in db.instructions; a later
    // addInstruction call (e.g. ensureLiftedIR processing the next proc in a
    // cluster) can rehash the HashMap and move the bucket, leaving the
    // sub-slice dangling. Caching the IRFunction with such slices crashes
    // the renderer with EXC_BAD_ACCESS in std.mem.indexOfScalarPos when it
    // reads IRStatement strings later in the same request.
    var parts = OperandParts{};
    var count: usize = 0;
    var start: usize = 0;
    var bracket_depth: usize = 0;
    var i: usize = 0;

    while (i < operands.len) {
        if (operands[i] == '[' or operands[i] == '(') {
            bracket_depth += 1;
        } else if (operands[i] == ']' or operands[i] == ')') {
            if (bracket_depth > 0) bracket_depth -= 1;
        } else if (bracket_depth == 0 and operands[i] == ',') {
            const tok_raw = std.mem.trim(u8, operands[start..i], " ");
            const token = allocator.dupe(u8, tok_raw) catch tok_raw;
            if (count == 0) {
                parts.dest = token;
            } else if (count == 1) {
                parts.src1 = token;
            } else if (count == 2) {
                parts.src2 = token;
            }
            count += 1;
            i += 1;
            while (i < operands.len and operands[i] == ' ') i += 1;
            start = i;
            continue;
        }
        i += 1;
    }

    if (start < operands.len) {
        const tok_raw = std.mem.trim(u8, operands[start..], " ");
        const token = allocator.dupe(u8, tok_raw) catch tok_raw;
        if (count == 0) {
            parts.dest = token;
        } else if (count == 1) {
            parts.src1 = token;
        } else if (count == 2) {
            parts.src2 = token;
        }
    }

    return parts;
}

/// Resolve an operand to a meaningful name (check for string refs, symbols, etc.).
fn resolveOperand(operand: []const u8, db: *const db_mod.Database) []const u8 {
    // Try to parse as address and look up name
    if (parseAddressFromOperands(operand)) |addr| {
        // Check for string reference
        if (db.getString(addr)) |str| {
            return str.value;
        }
        // Check for symbol name
        if (db.resolveName(addr)) |name| {
            return name;
        }
    }
    // Check if it's a register
    if (isRegister(operand)) {
        return ir.registerToVariable(operand);
    }
    return operand;
}

/// Resolve a call target operand to a function name.
fn resolveCallTarget(operands: []const u8, db: *const db_mod.Database) []const u8 {
    if (parseAddressFromOperands(operands)) |addr| {
        if (db.resolveName(addr)) |name| {
            return name;
        }
    }
    return operands;
}

fn parseAddressFromOperands(operands: []const u8) ?u64 {
    // Look for hex pattern
    if (std.mem.indexOf(u8, operands, "0x")) |idx| {
        const hex_start = idx + 2;
        var hex_end = hex_start;
        while (hex_end < operands.len and isHexDigit(operands[hex_end])) {
            hex_end += 1;
        }
        if (hex_end > hex_start) {
            return std.fmt.parseInt(u64, operands[hex_start..hex_end], 16) catch null;
        }
    }
    return null;
}

/// Compute branch target offset from function entry. Returns null if target
/// is before the entry (external branch).
fn branchOffset(target: u64, proc_entry: u64) ?u32 {
    if (target >= proc_entry) {
        const diff = target - proc_entry;
        if (diff <= std.math.maxInt(u32)) {
            return @intCast(diff);
        }
    }
    return null;
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn isRegister(s: []const u8) bool {
    if (s.len < 2) return false;
    const first = s[0];
    // ARM64: x0-x30, w0-w30
    if ((first == 'x' or first == 'X' or first == 'w' or first == 'W') and
        std.fmt.parseInt(u8, s[1..], 10) != error.InvalidCharacter)
        return true;
    // MIPS: $zero, $at, $v0-$v1, $a0-$a3, $t0-$t9, $s0-$s7, $k0-$k1, $gp, $sp, $fp, $ra, $f0-$f31
    if (first == '$') return true;
    return false;
}

/// Shorthand for ir.registerToVariable — maps register names to readable variable names.
fn regVar(reg: []const u8) []const u8 {
    // Try ARM64 mapping first; if unchanged, try x86_64 mapping.
    const arm_result = ir.registerToVariable(reg);
    if (!std.mem.eql(u8, arm_result, reg)) return arm_result;
    return ir.x86_64RegisterToVariable(reg);
}

/// Format a binary operation as "left op right", e.g. "sp + #0x20".
fn formatBinaryOp(allocator: std.mem.Allocator, left: []const u8, op: []const u8, right: []const u8) []const u8 {
    return std.fmt.allocPrint(allocator, "{s} {s} {s}", .{ left, op, right }) catch {
        return right;
    };
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn trackVariable(
    seen_regs: *std.StringHashMap(void),
    variables: *std.array_list.Managed(types.Variable),
    reg: []const u8,
) !void {
    if (!seen_regs.contains(reg)) {
        // v7.15.2 C1: `reg` typically slices into the current iteration's
        // inst.operands_buf, which goes out of scope on the next getInstruction
        // copy. Dupe into the HashMap's allocator (the lifter's arena) so the
        // key + the Variable's name/register slices stay valid for the
        // lifetime of the IR. Otherwise StringHashMap rehash compares stale
        // keys and trips an assertion.
        const owned = try seen_regs.allocator.dupe(u8, reg);
        try seen_regs.put(owned, {});
        try variables.append(ir.variableFromRegister(owned));
    }
}

/// Lift multiple procedures from a database.
pub fn liftProcedures(
    allocator: std.mem.Allocator,
    addresses: []const u64,
    db: *const db_mod.Database,
) ![]types.IRFunction {
    var results = std.array_list.Managed(types.IRFunction).init(allocator);
    errdefer results.deinit();

    for (addresses) |addr| {
        if (db.getProcedure(addr)) |proc| {
            const ir_func = try liftProcedure(allocator, &proc, db);
            try results.append(ir_func);
        }
    }

    return results.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

test "split operands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parts = splitOperands(arena.allocator(), "x0, x1, #42");
    try std.testing.expectEqualStrings("x0", parts.dest.?);
    try std.testing.expectEqualStrings("x1", parts.src1.?);
    try std.testing.expectEqualStrings("#42", parts.src2.?);
}

test "split single operand" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parts = splitOperands(arena.allocator(), "x0");
    try std.testing.expectEqualStrings("x0", parts.dest.?);
    try std.testing.expect(parts.src1 == null);
}

test "eqlIgnoreCase" {
    try std.testing.expect(eqlIgnoreCase("BL", "bl"));
    try std.testing.expect(eqlIgnoreCase("mov", "MOV"));
    try std.testing.expect(!eqlIgnoreCase("mov", "add"));
}

test "lift ret instruction" {
    const alloc = std.testing.allocator;
    var db = db_mod.Database.init(alloc, std.testing.io);
    defer db.deinit();

    const inst = types.Instruction{
        .address = 0x1000,
        .bytes = &.{ 0xC0, 0x03, 0x5F, 0xD6 },
        .mnemonic = "ret",
        .operands = "",
        .size = 4,
    };

    var seen = std.StringHashMap(void).init(alloc);
    defer seen.deinit();
    var vars = std.array_list.Managed(types.Variable).init(alloc);
    defer vars.deinit();

    const stmt = try liftInstruction(alloc, inst, 0x1000, &db, &seen, &vars);
    try std.testing.expectEqual(types.IRStatementType.@"return", stmt.type);
}
