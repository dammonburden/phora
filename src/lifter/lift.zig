// Phora — Lifter
// Walks a procedure's basic blocks, transforms each instruction to IR statements.
// Produces heuristic structured IR for LLM analysis; not validated instruction semantics.

const std = @import("std");
const types = @import("../types.zig");
const ir = @import("ir.zig");
const db_mod = @import("../store/database.zig");

// v7.8.0 maturity passes
const pass_const_fold = @import("passes/const_fold.zig");
const pass_dead_store = @import("passes/dead_store.zig");
const pass_reg_to_var = @import("passes/reg_to_var.zig");
const pass_stack_slot = @import("passes/stack_slot.zig");
// v7.9.1 maturity pass
const pass_fp_alias = @import("passes/fp_alias.zig");

/// Run the v7.8.0 maturity passes on `func` in the order specified by the
/// W1/W4 design notes:
/// Display aliases such as arg0 do not establish an ABI or a call arity.
/// call_arg_fixup is therefore excluded from this architecture-agnostic path.
/// const_fold, dead_store, stack_slot, fp_alias and reg_to_var preserve the
/// modeled dataflow while explicit call arguments are retained if supplied.
///
/// `allocator` should be a long-lived allocator (typically an arena tied to
/// the IR's lifetime) — const_fold and stack_slot allocate strings that the
/// IR retains. Errors propagate (OOM is the only realistic failure).
pub fn runMaturityPasses(
    allocator: std.mem.Allocator,
    func: *types.IRFunction,
) !void {
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
    return liftProcedureMatureForArch(allocator, proc, db, null);
}

/// Architecture identifies the architectural integer-return candidate only;
/// it does not certify a return type, ABI, or source-language prototype.
pub fn liftProcedureMatureForArch(
    allocator: std.mem.Allocator,
    proc: *const types.Procedure,
    db: *const db_mod.Database,
    arch: ?types.Arch,
) !types.IRFunction {
    var func = try liftProcedureForArch(allocator, proc, db, arch);
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
    return liftProcedureForArch(allocator, proc, db, null);
}

pub fn liftProcedureForArch(
    allocator: std.mem.Allocator,
    proc: *const types.Procedure,
    db: *const db_mod.Database,
    arch: ?types.Arch,
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
                // Allocation failures must not turn a real instruction into NOP.
                var stmt = try liftInstruction(allocator, inst, proc.entry, db, &seen_regs, &variables);
                if (stmt.type == .@"return" and eqlIgnoreCase(inst.mnemonic, "ret")) {
                    stmt.src = if (arch) |a| switch (a) {
                        .x86_64 => "rax",
                        .x86 => "eax",
                        .arm64 => "x0",
                        else => null,
                    } else null;
                    stmt.op = "integer_return_candidate";
                }
                // x86 arithmetic also writes flags. Keep those effects visible
                // even when a later assignment overwrites its scalar result.
                if (arch == .x86_64 or arch == .x86) {
                    if (stmt.type == .assign and x86WritesFlags(inst.mnemonic))
                        stmt.op = "writes_flags";
                }
                // Capture access widths before any presentation changes.
                const evidence = ir.memoryEvidence(inst.mnemonic, inst.operands);
                stmt.memory_width = evidence.width;
                stmt.memory_signedness = evidence.signedness;
                stmt.block_start = addr == block.start;
                if (stmt.type == .branch) {
                    // A condition label alone loses the tested register/bit.
                    // Preserve these operands and even an external target that
                    // cannot be encoded as an unsigned function-relative offset.
                    stmt.op = try allocator.dupe(u8, inst.mnemonic);
                    stmt.src = try allocator.dupe(u8, inst.operands);
                    if (parseBranchTarget(inst.operands)) |target| {
                        stmt.target = try std.fmt.allocPrint(allocator, "0x{x}", .{target});
                    }
                }
                try statements.append(stmt);
                if (inst.size == 0) break;
                addr += inst.size;
            } else {
                // A missing decode is unknown behavior, not a no-op.
                var stmt = ir.opaqueInstruction(addr, "missing_decode", "instruction bytes unavailable");
                stmt.block_start = addr == block.start;
                try statements.append(stmt);
                addr += 4;
            }
        }
    }

    // On-demand callers sometimes provide one linear fallback block. Mark
    // incoming branch targets too, so fallthrough cannot donate a constant or
    // inferred call argument to a join that also has another predecessor.
    var leaders = std.AutoHashMap(u64, void).init(allocator);
    defer leaders.deinit();
    for (statements.items) |stmt| {
        if (stmt.type == .branch) {
            if (stmt.true_block) |off| try leaders.put(proc.entry + off, {});
            if (stmt.false_block) |off| try leaders.put(proc.entry + off, {});
        }
    }
    for (statements.items) |*stmt| {
        if (leaders.contains(stmt.address)) stmt.block_start = true;
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
    const inst_operands = try allocator.dupe(u8, inst.operands);
    const mnemonic = inst.mnemonic;

    // Vector lane operations and scalar FP operations require distinct semantics.
    // Keep their original operands and barrier effects, including q-register
    // transfers: a vector load must never turn into a scalar integer assignment.
    if (ir.hasVectorOrFpOperand(inst_operands))
        return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);

    // One statement cannot represent both destinations of a pair transfer,
    // writeback of its base, or flag/extension effects omitted by the handlers.
    // Keep these instructions intact until a complete model is available.
    if (eqlIgnoreCase(mnemonic, "ldp") or eqlIgnoreCase(mnemonic, "stp") or
        std.mem.indexOfScalar(u8, inst_operands, '!') != null or
        (std.mem.indexOf(u8, inst_operands, "],") != null and
            (std.mem.indexOfScalar(u8, inst_operands, ',') orelse inst_operands.len) < (std.mem.indexOfScalar(u8, inst_operands, '[') orelse 0)) or
        std.mem.indexOf(u8, inst_operands, ", lsl ") != null or
        std.mem.indexOf(u8, inst_operands, ", lsr ") != null or
        std.mem.indexOf(u8, inst_operands, ", asr ") != null or
        std.mem.indexOf(u8, inst_operands, ", uxt") != null or
        std.mem.indexOf(u8, inst_operands, ", sxt") != null)
    {
        return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);
    }

    // A write to the architectural zero register is discarded, but loads or
    // flag-setting instructions can still have effects. Never define `zero`.
    if ((std.mem.startsWith(u8, inst_operands, "xzr,") or std.mem.startsWith(u8, inst_operands, "wzr,")) and
        !eqlIgnoreCase(mnemonic, "str") and !eqlIgnoreCase(mnemonic, "strb") and !eqlIgnoreCase(mnemonic, "strh") and
        !eqlIgnoreCase(mnemonic, "cmp") and !eqlIgnoreCase(mnemonic, "cmn") and !eqlIgnoreCase(mnemonic, "tst"))
    {
        return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);
    }

    // MOV Xd, Xn — assignment
    if (eqlIgnoreCase(mnemonic, "mov")) {
        const parts = splitOperands(allocator, inst_operands);
        if (parts.dest != null and parts.src1 != null) {
            if (std.mem.indexOfScalar(u8, parts.dest.?, '[') != null) {
                return ir.store(inst.address, parts.dest.?, resolveOperand(parts.src1.?, db));
            }
            try trackVariable(seen_regs, variables, parts.dest.?);
            if (std.mem.indexOfScalar(u8, parts.src1.?, '[') != null) {
                return ir.load(inst.address, regVar(parts.dest.?), parts.src1.?);
            }
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
            if (std.mem.indexOfScalar(u8, parts.dest.?, '[') != null) return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);
            const op = if (eqlIgnoreCase(mnemonic, "add") or eqlIgnoreCase(mnemonic, "addu")) "+" else "-";
            const src_expr = if (parts.src2) |s2|
                formatBinaryOp(allocator, regVar(parts.src1.?), op, resolveOperand(s2, db))
            else
                formatBinaryOp(allocator, regVar(parts.dest.?), op, resolveOperand(parts.src1.?, db));
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
            if (std.mem.indexOfScalar(u8, parts.dest.?, '[') != null) return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);
            const src_expr = if (parts.src2) |s2|
                formatBinaryOp(allocator, regVar(parts.src1.?), op, resolveOperand(s2, db))
            else if (eqlIgnoreCase(mnemonic, "xor") and eqlIgnoreCase(parts.dest.?, parts.src1.?))
                "#0x0"
            else
                formatBinaryOp(allocator, regVar(parts.dest.?), op, resolveOperand(parts.src1.?, db));
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

    // AArch64 MADD/MSUB have four register operands and do not touch MIPS
    // HI:LO. Preserve all four operands as unknown effects until represented
    // completely, rather than dropping the multiplier/addend and its reads.
    // The MIPS decoder spells every register with a '$' prefix.
    if ((eqlIgnoreCase(mnemonic, "madd") or eqlIgnoreCase(mnemonic, "msub")) and
        !std.mem.startsWith(u8, inst_operands, "$"))
    {
        return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);
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
        const target = parseBranchTarget(inst_operands);
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
        const target = parseBranchTarget(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // MIPS FPU branch: bc1t/bc1f
    if (eqlIgnoreCase(mnemonic, "bc1t") or eqlIgnoreCase(mnemonic, "bc1f")) {
        const condition = if (eqlIgnoreCase(mnemonic, "bc1t")) "fpu_true" else "fpu_false";
        const target = parseBranchTarget(inst_operands);
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
            const target = parseBranchTarget(inst_operands);
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
        return ir.call(inst.address, target_name, null, null);
    }

    // BLR Xn — ARM64 indirect function call
    if (eqlIgnoreCase(mnemonic, "blr")) {
        const parts = splitOperands(allocator, inst_operands);
        const target_name = if (parts.dest) |reg| regVar(reg) else "unknown";
        return ir.call(inst.address, target_name, null, null);
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
        const target = parseBranchTarget(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // B target — unconditional branch
    if (eqlIgnoreCase(mnemonic, "b") and inst_operands.len > 0) {
        const target = parseBranchTarget(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, null, target_offset, null);
    }

    // CBZ/CBNZ — compare and branch on zero/nonzero
    if (eqlIgnoreCase(mnemonic, "cbz") or eqlIgnoreCase(mnemonic, "cbnz")) {
        const condition = if (eqlIgnoreCase(mnemonic, "cbz")) "eq_zero" else "ne_zero";
        const target = parseBranchTarget(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // TBZ/TBNZ — test bit and branch
    if (eqlIgnoreCase(mnemonic, "tbz") or eqlIgnoreCase(mnemonic, "tbnz")) {
        const condition = if (eqlIgnoreCase(mnemonic, "tbz")) "bit_clear" else "bit_set";
        const target = parseBranchTarget(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, condition, target_offset, null);
    }

    // RET — return (ARM64)
    if (eqlIgnoreCase(mnemonic, "ret")) {
        return ir.ret(inst.address, null);
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
        return ir.call(inst.address, target_name, null, null);
    }

    // x86_64 RET — already handled above (shared with ARM64)

    // x86_64 JMP — unconditional branch
    if (eqlIgnoreCase(mnemonic, "jmp")) {
        const target = parseBranchTarget(inst_operands);
        const target_offset: ?u32 = if (target) |t| branchOffset(t, proc_entry) else null;
        return ir.branch(inst.address, null, target_offset, null);
    }

    // x86_64 Jcc — conditional branches (je, jne, jl, jle, jg, jge, jb, jbe, ja, jae, js, jns, jo, jno, jp, jnp)
    if (mnemonic.len >= 2 and (mnemonic[0] == 'j' or mnemonic[0] == 'J') and mnemonic[1] != 'm') {
        const condition = mnemonic[1..]; // e, ne, l, le, g, ge, etc.
        const target = parseBranchTarget(inst_operands);
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
        return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);
    }

    // x86_64 SYSCALL
    if (eqlIgnoreCase(mnemonic, "syscall")) {
        return ir.call(inst.address, "syscall", null, null);
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
        return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);
    }

    // x86_64 UD2 — undefined instruction (unreachable marker)
    if (eqlIgnoreCase(mnemonic, "ud2")) {
        return ir.call(inst.address, "unreachable", null, null);
    }

    // Unsupported semantics may touch any state. Do not infer a write from
    // operand position, especially for SIMD, stores, and system instructions.
    return ir.opaqueInstruction(inst.address, mnemonic, inst_operands);
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
    if (eqlIgnoreCase(operand, "xzr") or eqlIgnoreCase(operand, "wzr")) return "#0";
    // A memory expression's displacement is not an absolute symbol address.
    if (std.mem.indexOfScalar(u8, operand, '[') != null) return operand;
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
        return regVar(operand);
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
fn parseBranchTarget(operands: []const u8) ?u64 {
    const idx = std.mem.lastIndexOf(u8, operands, "0x") orelse return null;
    return parseAddressFromOperands(operands[idx..]);
}

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

/// Physical names preserve width views and do not assign ABI argument roles.
fn regVar(reg: []const u8) []const u8 {
    if (eqlIgnoreCase(reg, "xzr") or eqlIgnoreCase(reg, "wzr")) return "#0";
    return reg;
}

fn x86WritesFlags(mnemonic: []const u8) bool {
    for ([_][]const u8{ "add", "sub", "and", "or", "xor", "shl", "shr", "sar", "inc", "dec", "neg", "imul" }) |name| {
        if (eqlIgnoreCase(mnemonic, name)) return true;
    }
    return false;
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

test "evidence: opaque SIMD pair and writeback preserve original instruction" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = db_mod.Database.init(std.testing.allocator, std.testing.io);
    defer db.deinit();
    var seen = std.StringHashMap(void).init(a);
    var vars = std.array_list.Managed(types.Variable).init(a);
    const examples = [_]struct { mnemonic: []const u8, operands: []const u8 }{
        .{ .mnemonic = "simd/fp", .operands = "" },
        .{ .mnemonic = "stp", .operands = "x0, x1, [sp, #-0x10]!" },
        .{ .mnemonic = "ldp", .operands = "x0, x1, [x2]" },
        .{ .mnemonic = "ldr", .operands = "x0, [x1], #0x8" },
        .{ .mnemonic = "add", .operands = "x0, x1, x2, lsl #0x3" },
        .{ .mnemonic = "ldr", .operands = "xzr, [x0]" },
        .{ .mnemonic = "unknown", .operands = "x0, x1" },
    };
    for (examples) |ex| {
        const stmt = try liftInstruction(a, .{ .address = 0x1000, .bytes = &.{}, .mnemonic = ex.mnemonic, .operands = ex.operands, .size = 4 }, 0x1000, &db, &seen, &vars);
        try std.testing.expectEqual(types.IRStatementType.@"opaque", stmt.type);
        try std.testing.expect(stmt.dest == null);
        try std.testing.expectEqualStrings(ex.mnemonic, stmt.op.?);
        try std.testing.expectEqualStrings(ex.operands, stmt.src.?);
    }
    const store = try liftInstruction(a, .{ .address = 0x1000, .bytes = &.{}, .mnemonic = "str", .operands = "xzr, [x0]", .size = 4 }, 0x1000, &db, &seen, &vars);
    try std.testing.expectEqual(types.IRStatementType.store, store.type);
    try std.testing.expectEqualStrings("[x0]", store.dest.?);
    try std.testing.expectEqualStrings("#0", store.src.?);
}

test "evidence: maturity passes do not optimize through opaque effects" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var stmts = [_]types.IRStatement{
        ir.assign(0, "arg0", "42"),
        ir.opaqueInstruction(4, "simd/fp", ""),
        ir.assign(8, "saved_x19", "arg0"),
        ir.assign(12, "arg0", "7"),
        ir.call(16, "helper", null, "arg0"),
    };
    var func = types.IRFunction{ .address = 0, .statements = &stmts, .variables = &.{} };
    try runMaturityPasses(arena.allocator(), &func);
    try std.testing.expectEqual(@as(usize, 5), func.statements.len);
    try std.testing.expectEqualStrings("arg0", func.statements[2].src.?);
    try std.testing.expectEqualStrings("saved_x19", func.statements[2].dest.?);
    try std.testing.expectEqual(types.IRStatementType.@"opaque", func.statements[1].type);
    // ABI and arity are unknown here, even with a visible arg0 alias write.
    try std.testing.expect(func.statements[4].args == null);
}

test "evidence: inferred linear blocks split at incoming branches" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var db = db_mod.Database.init(std.testing.allocator, std.testing.io);
    defer db.deinit();
    const insns = [_]struct { mnemonic: []const u8, operands: []const u8 }{
        .{ .mnemonic = "tbz", .operands = "x1, #0x2, 0x100c" },
        .{ .mnemonic = "mov", .operands = "x0, #42" },
        .{ .mnemonic = "nop", .operands = "" },
        .{ .mnemonic = "bl", .operands = "0x2000" },
        .{ .mnemonic = "ret", .operands = "" },
    };
    for (insns, 0..) |inst, i| {
        var stored = types.Instruction{ .address = 0x1000 + i * 4, .bytes = &.{}, .mnemonic = inst.mnemonic, .operands = inst.operands, .size = 4 };
        @memcpy(stored.operands_buf[0..inst.operands.len], inst.operands);
        stored.operands_len = @intCast(inst.operands.len);
        try db.addInstruction(stored);
    }
    var blocks = [_]types.BasicBlock{.{ .start = 0x1000, .size = 20, .instruction_count = 5, .successors = &.{}, .predecessors = &.{}, .terminator = .@"return" }};
    const func = try liftProcedureMatureForArch(arena.allocator(), &.{ .entry = 0x1000, .size = 20, .basic_blocks = &blocks }, &db, .arm64);
    try std.testing.expectEqual(@as(?u32, 12), func.statements[0].true_block);
    try std.testing.expectEqualStrings("x1, #0x2, 0x100c", func.statements[0].src.?);
    try std.testing.expectEqualStrings("0x100c", func.statements[0].target.?);
    try std.testing.expect(func.statements[3].block_start);
    try std.testing.expect(func.statements[3].args == null);
    try std.testing.expectEqualStrings("x0", func.statements[4].src.?);
}

test "evidence: shared handlers preserve memory effects and two operand arithmetic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = db_mod.Database.init(std.testing.allocator, std.testing.io);
    defer db.deinit();
    var seen = std.StringHashMap(void).init(a);
    var vars = std.array_list.Managed(types.Variable).init(a);
    const store = try liftInstruction(a, .{ .address = 0, .bytes = &.{}, .mnemonic = "mov", .operands = "[rax], rbx", .size = 3 }, 0, &db, &seen, &vars);
    try std.testing.expectEqual(types.IRStatementType.store, store.type);
    const load = try liftInstruction(a, .{ .address = 3, .bytes = &.{}, .mnemonic = "mov", .operands = "rax, [rbx]", .size = 3 }, 0, &db, &seen, &vars);
    try std.testing.expectEqual(types.IRStatementType.load, load.type);
    const add = try liftInstruction(a, .{ .address = 6, .bytes = &.{}, .mnemonic = "add", .operands = "rax, rbx", .size = 3 }, 0, &db, &seen, &vars);
    try std.testing.expect(std.mem.indexOf(u8, add.src.?, " + ") != null);
    try std.testing.expect(std.mem.startsWith(u8, add.src.?, "rax + "));
    const xor = try liftInstruction(a, .{ .address = 9, .bytes = &.{}, .mnemonic = "xor", .operands = "eax, eax", .size = 2 }, 0, &db, &seen, &vars);
    try std.testing.expectEqualStrings("#0x0", xor.src.?);
}

test "evidence: ARM64 four operand multiply accumulate cannot use MIPS HI LO model" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = db_mod.Database.init(std.testing.allocator, std.testing.io);
    defer db.deinit();
    var seen = std.StringHashMap(void).init(a);
    var vars = std.array_list.Managed(types.Variable).init(a);
    for ([_][]const u8{ "madd", "msub" }) |mnemonic| {
        const arm_stmt = try liftInstruction(a, .{ .address = 4, .bytes = &.{}, .mnemonic = mnemonic, .operands = "x8, x19, x10, x8", .size = 4 }, 0, &db, &seen, &vars);
        try std.testing.expectEqual(types.IRStatementType.@"opaque", arm_stmt.type);
        try std.testing.expect(arm_stmt.dest == null);
        try std.testing.expectEqualStrings("x8, x19, x10, x8", arm_stmt.src.?);
        var stmts = [_]types.IRStatement{
            ir.assign(0, "tmp1_32", "#0x30"),
            arm_stmt,
            ir.load(8, "tmp1_32", "[x23, #0x78]"),
        };
        var func = types.IRFunction{ .address = 0, .statements = &stmts, .variables = &.{} };
        try runMaturityPasses(a, &func);
        // W10 defines the X10 multiplier's low 32 bits. Its value must remain
        // visible before the four-operand operation, despite the later load.
        try std.testing.expectEqual(@as(usize, 3), func.statements.len);
        try std.testing.expectEqualStrings("#0x30", func.statements[0].src.?);

        const mips_stmt = try liftInstruction(a, .{ .address = 12, .bytes = &.{}, .mnemonic = mnemonic, .operands = "$t0, $t1", .size = 4 }, 0, &db, &seen, &vars);
        try std.testing.expectEqual(types.IRStatementType.assign, mips_stmt.type);
        try std.testing.expectEqualStrings("hi:lo", mips_stmt.dest.?);
        try std.testing.expectEqualStrings(if (std.mem.eql(u8, mnemonic, "madd")) "hi:lo + $t0 * $t1" else "hi:lo - $t0 * $t1", mips_stmt.src.?);
    }
}

test "evidence: mature lift retains original narrow and vector memory widths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var db = db_mod.Database.init(std.testing.allocator, std.testing.io);
    defer db.deinit();
    const instructions = [_]struct { mnemonic: []const u8, operands: []const u8 }{
        .{ .mnemonic = "ldr", .operands = "w0, [x1, #0]" },
        .{ .mnemonic = "ldrsb", .operands = "x2, [x1, #4]" },
        .{ .mnemonic = "ldr", .operands = "q0, [x1, #16]" },
        .{ .mnemonic = "add", .operands = "v0.4s, v1.4s, v2.4s" },
        .{ .mnemonic = "str", .operands = "x0, [x1, #32]" },
    };
    for (instructions, 0..) |inst, i| {
        var stored = types.Instruction{ .address = 0x1000 + i * 4, .bytes = &.{}, .mnemonic = inst.mnemonic, .operands = inst.operands, .size = 4 };
        @memcpy(stored.operands_buf[0..inst.operands.len], inst.operands);
        stored.operands_len = @intCast(inst.operands.len);
        try db.addInstruction(stored);
    }
    var blocks = [_]types.BasicBlock{.{ .start = 0x1000, .size = 20, .instruction_count = 5, .successors = &.{}, .predecessors = &.{}, .terminator = .fallthrough }};
    const func = try liftProcedureMature(arena.allocator(), &.{ .entry = 0x1000, .size = 20, .basic_blocks = &blocks }, &db);
    try std.testing.expectEqual(@as(?u8, 4), func.statements[0].memory_width);
    try std.testing.expectEqualStrings("w0", func.statements[0].dest.?);
    try std.testing.expectEqual(@as(?u8, 1), func.statements[1].memory_width);
    try std.testing.expect(func.statements[1].memory_signedness == .signed);
    try std.testing.expectEqual(@as(?u8, 16), func.statements[2].memory_width);
    try std.testing.expect(func.statements[2].type == .@"opaque");
    try std.testing.expect(func.statements[3].type == .@"opaque");
    try std.testing.expect(func.statements[3].dest == null);
    try std.testing.expectEqualStrings("v0.4s, v1.4s, v2.4s", func.statements[3].src.?);
    try std.testing.expectEqual(@as(?u8, 8), func.statements[4].memory_width);
}

test "evidence: LLVM R05 R06 R07 x86 arithmetic survives mature lifting" {
    // Exact compiler bytes from the three platform fixtures, cross-checked
    // against LLVM. The SysV specimens differ only in their load address.
    const sysv = [_]u8{ 0x55, 0x48, 0x89, 0xe5, 0x4c, 0x01, 0xc7, 0x48, 0x8d, 0x3c, 0x7f, 0x48, 0x8d, 0x04, 0xb6, 0x48, 0x8d, 0x34, 0xd5, 0, 0, 0, 0, 0x48, 0x29, 0xd6, 0x48, 0x31, 0xc6, 0x48, 0x8d, 0x04, 0x89, 0x48, 0x8d, 0x04, 0x41, 0x48, 0x31, 0xf8, 0x48, 0x31, 0xf0, 0x5d, 0xc3 };
    const windows = [_]u8{ 0x55, 0x48, 0x89, 0xe5, 0x48, 0x03, 0x4d, 0x30, 0x48, 0x8d, 0x0c, 0x49, 0x48, 0x8d, 0x04, 0x92, 0x4a, 0x8d, 0x14, 0xc5, 0, 0, 0, 0, 0x4c, 0x29, 0xc2, 0x48, 0x31, 0xc2, 0x4b, 0x8d, 0x04, 0x89, 0x49, 0x8d, 0x04, 0x41, 0x48, 0x31, 0xd0, 0x48, 0x31, 0xc8, 0x5d, 0xc3 };
    const fixtures = [_]struct { entry: u64, bytes: []const u8, first: []const u8 }{
        .{ .entry = 0x1490, .bytes = &sysv, .first = "rdi" },
        .{ .entry = 0x10011b0, .bytes = &sysv, .first = "rdi" },
        .{ .entry = 0x140001000, .bytes = &windows, .first = "rcx" },
    };
    const x86 = @import("../arch/x86_64.zig");
    for (fixtures) |fixture| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var db = db_mod.Database.init(std.testing.allocator, std.testing.io);
        defer db.deinit();
        var off: usize = 0;
        var count: u32 = 0;
        while (off < fixture.bytes.len) {
            const decoded = x86.decode(fixture.bytes[off..], fixture.entry + off);
            var inst = decoded.toInstruction(fixture.entry + off, fixture.bytes[off..]);
            @memcpy(inst.operands_buf[0..inst.operands.len], inst.operands);
            inst.operands_len = @intCast(inst.operands.len);
            try db.addInstruction(inst);
            off += decoded.length;
            count += 1;
        }
        var blocks = [_]types.BasicBlock{.{ .start = fixture.entry, .size = @intCast(fixture.bytes.len), .instruction_count = count, .successors = &.{}, .predecessors = &.{}, .terminator = .@"return" }};
        const proc = types.Procedure{ .entry = fixture.entry, .size = fixture.bytes.len, .basic_blocks = &blocks };
        const func = try liftProcedureMatureForArch(arena.allocator(), &proc, &db, .x86_64);
        // SysV never reads its temporary frame pointer before POP, so that
        // MOV can be removed. Windows reads RBP to fetch its stack operand.
        try std.testing.expectEqual(@as(usize, if (fixture.entry == 0x140001000) 14 else 13), func.statements.len);
        var arithmetic_count: usize = 0;
        var lea_count: usize = 0;
        for (func.statements) |stmt| {
            if (stmt.type == .assign and stmt.address >= fixture.entry + 4) arithmetic_count += 1;
            if (stmt.address == fixture.entry + 4) {
                try std.testing.expectEqualStrings(fixture.first, stmt.dest.?);
                try std.testing.expect(std.mem.indexOf(u8, stmt.src.?, " + ") != null);
            }
            const original = db.getInstruction(stmt.address).?;
            if (eqlIgnoreCase(original.mnemonic, "lea")) {
                lea_count += 1;
                try std.testing.expectEqualStrings(original.operands[0..std.mem.indexOfScalar(u8, original.operands, ',').?], stmt.dest.?);
                try std.testing.expect(std.mem.indexOfScalar(u8, stmt.src.?, '[') != null);
            }
        }
        try std.testing.expectEqual(@as(usize, 10), arithmetic_count);
        try std.testing.expectEqual(@as(usize, 5), lea_count);
        const ret = func.statements[func.statements.len - 1];
        try std.testing.expectEqualStrings("rax", ret.src.?);
        try std.testing.expectEqualStrings("integer_return_candidate", ret.op.?);
        for (func.variables) |v| {
            try std.testing.expectEqualStrings(v.register.?, v.name);
            try std.testing.expect(v.type_name == null);
        }
        const unknown = try liftProcedureMature(arena.allocator(), &proc, &db);
        try std.testing.expect(unknown.statements[unknown.statements.len - 1].src == null);
    }
}

test "evidence: x86 flags survive a scalar overwrite before conditional branch" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var db = db_mod.Database.init(std.testing.allocator, std.testing.io);
    defer db.deinit();
    const operands = [_][]const u8{ "rax, 1", "rax, 0", "0x100c" };
    const mnemonics = [_][]const u8{ "add", "mov", "je" };
    for (operands, mnemonics, 0..) |operand, mnemonic, i| {
        var inst = types.Instruction{ .address = 0x1000 + i * 4, .bytes = &.{}, .mnemonic = mnemonic, .operands = operand, .size = 4 };
        @memcpy(inst.operands_buf[0..operand.len], operand);
        inst.operands_len = @intCast(operand.len);
        try db.addInstruction(inst);
    }
    var blocks = [_]types.BasicBlock{.{ .start = 0x1000, .size = 12, .instruction_count = 3, .successors = &.{}, .predecessors = &.{}, .terminator = .branch }};
    const func = try liftProcedureMatureForArch(arena.allocator(), &.{ .entry = 0x1000, .size = 12, .basic_blocks = &blocks }, &db, .x86_64);
    try std.testing.expectEqual(@as(usize, 3), func.statements.len);
    try std.testing.expectEqualStrings("writes_flags", func.statements[0].op.?);
}
