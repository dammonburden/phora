// Phora — Disassembler
// Linear sweep through code sections using the architecture's decoder.
// Produces Instruction lists and feeds the xref tracker.

const std = @import("std");
const types = @import("../types.zig");
const xref_mod = @import("xref.zig");
const cfg_mod = @import("cfg.zig");
const arm32 = @import("../arch/arm32.zig");
const x86_64 = @import("../arch/x86_64.zig");

/// Architecture-specific decoder interface.
/// The decoder takes raw bytes + address and returns a decoded instruction.
pub const DecoderFn = *const fn (data: []const u8, address: u64) types.Instruction;

/// Disassemble an entire code section via linear sweep.
/// Records cross-references as they are encountered.
pub fn disassembleSection(
    allocator: std.mem.Allocator,
    data: []const u8,
    file_offset: usize,
    section_base: u64,
    section_length: u64,
    decoder: DecoderFn,
    xrefs: *xref_mod.XrefTracker,
    min_insn_size: usize,
) !std.array_list.Managed(types.Instruction) {
    var instructions = std.array_list.Managed(types.Instruction).init(allocator);
    errdefer instructions.deinit();

    const end_offset = file_offset + @as(usize, @intCast(section_length));
    var offset = file_offset;
    var addr = section_base;

    while (offset < end_offset and offset < data.len) {
        const remaining = data[offset..@min(end_offset, data.len)];
        if (remaining.len < min_insn_size) break;

        const inst = decoder(remaining, addr);

        // Extract xrefs from the instruction
        try extractXrefs(inst, xrefs);

        try instructions.append(inst);
        offset += inst.size;
        addr += inst.size;
    }

    return instructions;
}

/// Disassemble all code sections in a document.
/// Falls back to segment-level mapping for ELF binaries with stripped section headers.
pub fn disassembleDocument(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    decoder: DecoderFn,
    xrefs: *xref_mod.XrefTracker,
) !std.array_list.Managed(types.Instruction) {
    var all_instructions = std.array_list.Managed(types.Instruction).init(allocator);
    errdefer all_instructions.deinit();

    for (doc.segments) |segment| {
        if (!segment.permissions.execute) continue;

        var found_code_section = false;
        for (segment.sections) |section| {
            if (!isCodeSection(section.name)) continue;
            found_code_section = true;

            if (section.file_offset >= doc.data.len) continue;

            var section_instructions = try disassembleSection(
                allocator,
                doc.data,
                @intCast(section.file_offset),
                section.start,
                section.length,
                decoder,
                xrefs,
                4, // ARM64 fixed 4-byte instructions
            );
            defer section_instructions.deinit();

            try all_instructions.appendSlice(section_instructions.items);
        }

        // Fallback: no code sections found (stripped ELF). Use segment mapping.
        if (!found_code_section and segment.file_size > 0) {
            if (segment.file_offset < doc.data.len) {
                var seg_instructions = try disassembleSection(
                    allocator,
                    doc.data,
                    @intCast(segment.file_offset),
                    segment.start,
                    segment.file_size,
                    decoder,
                    xrefs,
                    4,
                );
                defer seg_instructions.deinit();

                try all_instructions.appendSlice(seg_instructions.items);
            }
        }
    }

    return all_instructions;
}

/// Disassemble a specific address range.
pub fn disassembleRange(
    allocator: std.mem.Allocator,
    data: []const u8,
    file_offset: usize,
    base_address: u64,
    start: u64,
    length: u64,
    decoder: DecoderFn,
) !std.array_list.Managed(types.Instruction) {
    var instructions = std.array_list.Managed(types.Instruction).init(allocator);
    errdefer instructions.deinit();

    if (start < base_address) return instructions;

    const start_offset = file_offset + @as(usize, @intCast(start - base_address));
    const end_offset = start_offset + @as(usize, @intCast(length));

    var offset = start_offset;
    var addr = start;

    while (offset < end_offset and offset < data.len) {
        const remaining = data[offset..@min(end_offset, data.len)];
        if (remaining.len < 4) break;

        const inst = decoder(remaining, addr);
        try instructions.append(inst);
        offset += inst.size;
        addr += inst.size;
    }

    return instructions;
}

/// Extract cross-references from a decoded instruction.
fn extractXrefs(inst: types.Instruction, xrefs: *xref_mod.XrefTracker) !void {
    extractXrefsFiltered(inst, xrefs, false);
}

/// Extract xrefs with optional calls-only mode (lean mode for CLI).
///
/// v7.4.3 F2 fix: read operand text from `operands_buf[0..operands_len]` rather
/// than `inst.operands`. The `operands` slice is self-referential — it points
/// into the SOURCE struct's `operands_buf`, so when an Instruction is returned
/// from `decodeInstruction` and the caller copies it, `caller.operands` dangles
/// at the original stack location. Using the buffer directly avoids the
/// dangle. This bug silently produced 0 xrefs in the test_integration full
/// path; the MCP-side `disassembleDocumentLean` worked because it operates on
/// raw bytes and never builds Instruction values for xref extraction.
fn extractXrefsFiltered(inst: types.Instruction, xrefs: *xref_mod.XrefTracker, calls_only: bool) void {
    const mnemonic = inst.mnemonic;
    const operands = inst.operands_buf[0..inst.operands_len];

    if (std.mem.eql(u8, mnemonic, "bl") or std.mem.eql(u8, mnemonic, "BL") or
        std.mem.eql(u8, mnemonic, "blr") or std.mem.eql(u8, mnemonic, "BLR"))
    {
        if (parseAddress(operands)) |target| {
            xrefs.addXref(inst.address, target, .call) catch {};
        }
    } else if (!calls_only) {
        if (std.mem.eql(u8, mnemonic, "b") or std.mem.eql(u8, mnemonic, "B")) {
            if (parseAddress(operands)) |target| {
                xrefs.addXref(inst.address, target, .jump) catch {};
            }
        } else if (isBranchMnemonic(mnemonic)) {
            if (parseAddress(operands)) |target| {
                xrefs.addXref(inst.address, target, .jump) catch {};
            }
        } else if (std.mem.eql(u8, mnemonic, "ldr") or std.mem.eql(u8, mnemonic, "LDR")) {
            if (parsePcRelAddress(operands)) |target| {
                xrefs.addXref(inst.address, target, .data_read) catch {};
            }
        } else if (std.mem.eql(u8, mnemonic, "adr") or std.mem.eql(u8, mnemonic, "ADR") or
            std.mem.eql(u8, mnemonic, "adrp") or std.mem.eql(u8, mnemonic, "ADRP"))
        {
            if (parsePcRelAddress(operands)) |target| {
                xrefs.addXref(inst.address, target, .data_read) catch {};
            }
        } else if (std.mem.eql(u8, mnemonic, "str") or std.mem.eql(u8, mnemonic, "STR")) {
            if (parsePcRelAddress(operands)) |target| {
                xrefs.addXref(inst.address, target, .data_write) catch {};
            }
        }
    }
}

/// Lean ARM64 linear sweep over a raw byte range. Extracts BL/B/CBZ/CBNZ/B.cond
/// xrefs and tracks ADRP+ADD pairs for data references.
fn leanSweepArm64(
    data: []const u8,
    start_offset: usize,
    end_offset: usize,
    base_addr: u64,
    xrefs: *xref_mod.XrefTracker,
    data_sections: []const DataSectionBounds,
    adrp_page: *[32]u64,
    adrp_addr: *[32]u64,
    adrp_valid: *[32]bool,
) !usize {
    var insn_count: usize = 0;
    var offset = start_offset;
    var addr = base_addr;

    // Reset ADRP state at region boundary
    adrp_valid.* = [_]bool{false} ** 32;

    while (offset + 4 <= end_offset) {
        const raw = data[offset..][0..4];
        const word = std.mem.readInt(u32, raw, .little);
        const top6 = word >> 26;
        if (top6 == 0b100101 or top6 == 0b000101) {
            // BL (100101) or B (000101)
            const imm26 = word & 0x3FFFFFF;
            const offset_val: i64 = if (imm26 & 0x2000000 != 0)
                @as(i64, @intCast(imm26)) | (@as(i64, -1) << 26)
            else
                @as(i64, @intCast(imm26));
            const target: u64 = @bitCast(@as(i64, @bitCast(addr)) +% (offset_val << 2));
            const xtype: types.XrefType = if (top6 == 0b100101) .call else .jump;
            try xrefs.addXref(addr, target, xtype);
        } else if ((word & 0x7E000000) == 0x34000000) {
            // CBZ/CBNZ
            const imm19 = (word >> 5) & 0x7FFFF;
            const cond_off: i64 = if (imm19 & 0x40000 != 0)
                @as(i64, @intCast(imm19)) | (@as(i64, -1) << 19)
            else
                @as(i64, @intCast(imm19));
            const target: u64 = @bitCast(@as(i64, @bitCast(addr)) +% (cond_off << 2));
            try xrefs.addXref(addr, target, .jump);
        } else if ((word & 0xFF000010) == 0x54000000) {
            // B.cond
            const imm19 = (word >> 5) & 0x7FFFF;
            const cond_off: i64 = if (imm19 & 0x40000 != 0)
                @as(i64, @intCast(imm19)) | (@as(i64, -1) << 19)
            else
                @as(i64, @intCast(imm19));
            const target: u64 = @bitCast(@as(i64, @bitCast(addr)) +% (cond_off << 2));
            try xrefs.addXref(addr, target, .jump);
        } else if (word & 0x9F000000 == 0x90000000) {
            // ADRP
            const rd: u5 = @truncate(word & 0x1F);
            const immlo: u64 = (word >> 29) & 0x3;
            const immhi: u64 = (word >> 5) & 0x7FFFF;
            const imm_raw: u64 = (immhi << 2) | immlo;
            const imm: i64 = if (imm_raw & 0x100000 != 0)
                @as(i64, @intCast(imm_raw)) | (@as(i64, -1) << 21)
            else
                @as(i64, @intCast(imm_raw));
            const pc_page: i64 = @bitCast(addr & ~@as(u64, 0xFFF));
            const page_addr: u64 = @bitCast(pc_page +% (imm << 12));
            adrp_page[rd] = page_addr;
            adrp_addr[rd] = addr;
            adrp_valid[rd] = true;
        } else if (word & 0xFFC00000 == 0x91000000) {
            // ADD immediate (64-bit, no shift)
            const rd: u5 = @truncate(word & 0x1F);
            const rn: u5 = @truncate((word >> 5) & 0x1F);
            const imm12: u64 = (word >> 10) & 0xFFF;
            if (adrp_valid[rn] and rd == rn) {
                if (addr - adrp_addr[rn] <= 32) {
                    const full_addr = adrp_page[rn] + imm12;
                    if (isInDataSection(full_addr, data_sections)) {
                        try xrefs.addXref(addr, full_addr, .data_read);
                    }
                }
            }
        } else if (word & 0xFFC00000 == 0x91400000) {
            // ADD immediate (64-bit, shift=1)
            const rd: u5 = @truncate(word & 0x1F);
            const rn: u5 = @truncate((word >> 5) & 0x1F);
            const imm12: u64 = (word >> 10) & 0xFFF;
            if (adrp_valid[rn] and rd == rn) {
                if (addr - adrp_addr[rn] <= 32) {
                    const full_addr = adrp_page[rn] + (imm12 << 12);
                    if (isInDataSection(full_addr, data_sections)) {
                        try xrefs.addXref(addr, full_addr, .data_read);
                    }
                }
            }
        }
        insn_count += 1;
        offset += 4;
        addr += 4;
    }

    return insn_count;
}

/// Disassemble a document in lean mode — only extract call xrefs, skip instructions.
/// Much lower memory footprint for CLI analysis of large binaries.
pub fn disassembleDocumentLean(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    decoder: DecoderFn,
    xrefs: *xref_mod.XrefTracker,
) !usize {
    _ = allocator;
    _ = decoder;
    var insn_count: usize = 0;

    // Collect data section bounds for ADRP+ADD string reference detection.
    // Any resolved address landing in a readable non-code section is a data ref.
    var data_sections_buf: [64]DataSectionBounds = undefined;
    var data_section_count: usize = 0;
    for (doc.segments) |segment| {
        if (!segment.permissions.read) continue;
        for (segment.sections) |section| {
            if (isCodeSection(section.name)) continue;
            if (section.length == 0) continue;
            if (data_section_count < data_sections_buf.len) {
                data_sections_buf[data_section_count] = .{
                    .start = section.start,
                    .end = section.start + section.length,
                };
                data_section_count += 1;
            }
        }
    }
    const data_sections = data_sections_buf[0..data_section_count];

    // ADRP tracking: last page address computed per register (32 ARM64 GP regs).
    // Each entry stores the page address and the instruction address of the ADRP
    // so we can enforce a proximity window for the matching ADD.
    var adrp_page: [32]u64 = [_]u64{0} ** 32;
    var adrp_addr: [32]u64 = [_]u64{0} ** 32;
    var adrp_valid: [32]bool = [_]bool{false} ** 32;

    for (doc.segments) |segment| {
        if (!segment.permissions.execute) continue;

        // Determine code region(s) to disassemble.
        // For ELF: if no code sections exist (stripped section headers), use the
        // segment's p_offset/p_vaddr mapping directly. This is the authoritative
        // mapping for ELF program headers.
        var found_code_section = false;
        for (segment.sections) |section| {
            if (!isCodeSection(section.name)) continue;
            found_code_section = true;

            const file_off: usize = @intCast(section.file_offset);
            const sect_len: usize = @intCast(section.length);
            const section_end = file_off + sect_len;
            if (file_off >= doc.data.len) continue;

            const end_offset = @min(section_end, doc.data.len);
            insn_count += try leanSweepArm64(doc.data, file_off, end_offset, section.start, xrefs, data_sections, &adrp_page, &adrp_addr, &adrp_valid);
        }

        // Fallback: no code sections found (stripped ELF or unlabeled segments).
        // Use the segment's file_offset (p_offset) and file_size (p_filesz) directly.
        if (!found_code_section and segment.file_size > 0) {
            const file_off: usize = @intCast(segment.file_offset);
            const seg_file_end = file_off + @as(usize, @intCast(segment.file_size));
            if (file_off < doc.data.len) {
                const end_offset = @min(seg_file_end, doc.data.len);
                insn_count += try leanSweepArm64(doc.data, file_off, end_offset, segment.start, xrefs, data_sections, &adrp_page, &adrp_addr, &adrp_valid);
            }
        }
    }

    return insn_count;
}

/// Lean ARM32/Thumb linear sweep over a raw byte range. Extracts BL/B/B.W/B.cond xrefs.
fn leanSweepThumb(
    data: []const u8,
    start_offset: usize,
    end_offset: usize,
    base_addr: u64,
    xrefs: *xref_mod.XrefTracker,
) !usize {
    var insn_count: usize = 0;
    var offset = start_offset;
    var addr = base_addr;

    while (offset + 2 <= end_offset) {
        const hw0 = std.mem.readInt(u16, data[offset..][0..2], .little);
        const top5 = hw0 >> 11;

        if (top5 >= 0b11101) {
            // 32-bit Thumb-2 instruction
            if (offset + 4 > end_offset) break;
            const hw1 = std.mem.readInt(u16, data[offset + 2 ..][0..2], .little);
            const combined: u32 = (@as(u32, hw0) << 16) | @as(u32, hw1);

            // BL: 11110 S imm10 11 J1 1 J2 imm11
            if ((combined & 0xF800D000) == 0xF000D000) {
                const s_bit: u32 = (hw0 >> 10) & 1;
                const imm10: u32 = hw0 & 0x3FF;
                const j1: u32 = (hw1 >> 13) & 1;
                const j2: u32 = (hw1 >> 11) & 1;
                const imm11: u32 = hw1 & 0x7FF;
                const bit_i1 = ~(j1 ^ s_bit) & 1;
                const bit_i2 = ~(j2 ^ s_bit) & 1;
                const imm_raw: u32 = (s_bit << 24) | (bit_i1 << 23) | (bit_i2 << 22) | (imm10 << 12) | (imm11 << 1);
                const offset_val: i32 = if (imm_raw & 0x01000000 != 0)
                    @bitCast(imm_raw | 0xFE000000)
                else
                    @bitCast(imm_raw);
                const target: u64 = @bitCast(@as(i64, @intCast(@as(i64, @bitCast(addr)))) +% @as(i64, offset_val) +% 4);
                try xrefs.addXref(addr, target, .call);
            }
            // B.W (unconditional wide branch encoding T4)
            else if ((combined & 0xF800D000) == 0xF0009000) {
                const s_bit: u32 = (hw0 >> 10) & 1;
                const imm10: u32 = hw0 & 0x3FF;
                const j1: u32 = (hw1 >> 13) & 1;
                const j2: u32 = (hw1 >> 11) & 1;
                const imm11: u32 = hw1 & 0x7FF;
                const bit_i1 = ~(j1 ^ s_bit) & 1;
                const bit_i2 = ~(j2 ^ s_bit) & 1;
                const imm_raw: u32 = (s_bit << 24) | (bit_i1 << 23) | (bit_i2 << 22) | (imm10 << 12) | (imm11 << 1);
                const offset_val: i32 = if (imm_raw & 0x01000000 != 0)
                    @bitCast(imm_raw | 0xFE000000)
                else
                    @bitCast(imm_raw);
                const target: u64 = @bitCast(@as(i64, @intCast(@as(i64, @bitCast(addr)))) +% @as(i64, offset_val) +% 4);
                try xrefs.addXref(addr, target, .jump);
            }

            insn_count += 1;
            offset += 4;
            addr += 4;
        } else {
            // 16-bit Thumb instruction
            if ((hw0 & 0xF800) == 0xE000) {
                const imm11: u32 = hw0 & 0x7FF;
                const offset_val: i32 = if (imm11 & 0x400 != 0)
                    @bitCast((@as(u32, imm11) << 1) | 0xFFFFF000)
                else
                    @bitCast(@as(u32, imm11) << 1);
                const target: u64 = @bitCast(@as(i64, @intCast(@as(i64, @bitCast(addr)))) +% @as(i64, offset_val) +% 4);
                try xrefs.addXref(addr, target, .jump);
            } else if ((hw0 & 0xF000) == 0xD000 and ((hw0 >> 8) & 0xF) < 0xE) {
                const imm8: u32 = hw0 & 0xFF;
                const offset_val: i32 = if (imm8 & 0x80 != 0)
                    @bitCast((@as(u32, imm8) << 1) | 0xFFFFFE00)
                else
                    @bitCast(@as(u32, imm8) << 1);
                const target: u64 = @bitCast(@as(i64, @intCast(@as(i64, @bitCast(addr)))) +% @as(i64, offset_val) +% 4);
                try xrefs.addXref(addr, target, .jump);
            }

            insn_count += 1;
            offset += 2;
            addr += 2;
        }
    }

    return insn_count;
}

/// Lean disassembly for ARM32/Thumb binaries — extract call/jump xrefs only.
/// Variable-length Thumb: 2-byte and 4-byte instructions interleaved.
pub fn disassembleDocumentLean32(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    xrefs: *xref_mod.XrefTracker,
) !usize {
    _ = allocator;
    var insn_count: usize = 0;

    for (doc.segments) |segment| {
        if (!segment.permissions.execute) continue;

        // Try code sections first.
        var found_code_section = false;
        for (segment.sections) |section| {
            if (!isCodeSection(section.name)) continue;
            found_code_section = true;

            const file_off: usize = @intCast(section.file_offset);
            const sect_len: usize = @intCast(section.length);
            const section_end = file_off + sect_len;
            if (file_off >= doc.data.len) continue;

            const end_offset = @min(section_end, doc.data.len);
            insn_count += try leanSweepThumb(doc.data, file_off, end_offset, section.start, xrefs);
        }

        // Fallback: no code sections found (stripped ELF or unlabeled segments).
        // Use the segment's file_offset (p_offset) and file_size (p_filesz) directly.
        if (!found_code_section and segment.file_size > 0) {
            const file_off: usize = @intCast(segment.file_offset);
            const seg_file_end = file_off + @as(usize, @intCast(segment.file_size));
            if (file_off < doc.data.len) {
                const end_offset = @min(seg_file_end, doc.data.len);
                insn_count += try leanSweepThumb(doc.data, file_off, end_offset, segment.start, xrefs);
            }
        }
    }

    return insn_count;
}

/// Lean MIPS32 linear sweep over a raw byte range. Extracts JAL/branch xrefs
/// and tracks LUI+ADDIU/ORI pairs for data references (string_refs).
fn leanSweepMips32(
    data: []const u8,
    start_offset: usize,
    end_offset: usize,
    base_addr: u64,
    xrefs: *xref_mod.XrefTracker,
    data_sections: []const DataSectionBounds,
    lui_value: *[32]u64,
    lui_addr: *[32]u64,
    lui_valid: *[32]bool,
    gp_value: ?u64,
) !usize {
    var insn_count: usize = 0;
    var offset = start_offset;
    var addr = base_addr;

    // Reset LUI state at region boundary
    lui_valid.* = [_]bool{false} ** 32;

    while (offset + 4 <= end_offset) {
        const raw = data[offset..][0..4];
        const insn = std.mem.readInt(u32, raw, .little);
        const opcode = insn >> 26;

        if (opcode == 0x0F) {
            // LUI: rt = imm16 << 16
            const rt: u5 = @truncate((insn >> 16) & 0x1F);
            const imm16: u64 = insn & 0xFFFF;
            if (rt != 0) {
                lui_value[rt] = imm16 << 16;
                lui_addr[rt] = addr;
                lui_valid[rt] = true;
            }
        } else if (opcode == 0x09) {
            // ADDIU: rt = rs + sign_extend(imm16)
            const rs: u5 = @truncate((insn >> 21) & 0x1F);
            const rt: u5 = @truncate((insn >> 16) & 0x1F);
            const imm16_raw: u16 = @truncate(insn & 0xFFFF);
            if (rs == rt and lui_valid[rs] and addr - lui_addr[rs] <= 16) {
                const sign_ext: i64 = @as(i64, @as(i16, @bitCast(imm16_raw)));
                const full_addr: u64 = lui_value[rs] +% @as(u64, @bitCast(sign_ext));
                if (isInDataSection(full_addr, data_sections)) {
                    try xrefs.addXref(addr, full_addr, .data_read);
                }
                lui_valid[rs] = false;
            } else if (rt != 0) {
                // Any write to rt that isn't a LUI invalidates its cache
                lui_valid[rt] = false;
            }
        } else if (opcode == 0x0D) {
            // ORI: rt = rs | zero_extend(imm16)
            const rs: u5 = @truncate((insn >> 21) & 0x1F);
            const rt: u5 = @truncate((insn >> 16) & 0x1F);
            const imm16: u64 = insn & 0xFFFF;
            if (rs == rt and lui_valid[rs] and addr - lui_addr[rs] <= 16) {
                const full_addr: u64 = lui_value[rs] | imm16;
                if (isInDataSection(full_addr, data_sections)) {
                    try xrefs.addXref(addr, full_addr, .data_read);
                }
                lui_valid[rs] = false;
            } else if (rt != 0) {
                lui_valid[rt] = false;
            }
        } else if (opcode == 0x03) {
            // JAL: target = (PC & 0xF0000000) | (instr_index << 2)
            const target: u64 = (addr & 0xF0000000) | (@as(u64, insn & 0x03FFFFFF) << 2);
            try xrefs.addXref(addr, target, .call);
        } else if ((opcode >= 0x04 and opcode <= 0x07) or (opcode >= 0x14 and opcode <= 0x17)) {
            // BEQ, BNE, BLEZ, BGTZ (and their "likely" variants 0x14-0x17)
            const imm16_raw: u16 = @truncate(insn & 0xFFFF);
            const offset_val: i64 = @as(i64, @as(i16, @bitCast(imm16_raw)));
            const target: u64 = @bitCast(@as(i64, @bitCast(addr)) +% 4 +% (offset_val << 2));
            try xrefs.addXref(addr, target, .jump);
        } else if (opcode == 0x01) {
            // REGIMM: BLTZ, BGEZ, BLTZAL, BGEZAL
            const rt_field = (insn >> 16) & 0x1F;
            if (rt_field == 0x00 or rt_field == 0x01 or rt_field == 0x02 or rt_field == 0x03 or rt_field == 0x10 or rt_field == 0x11) {
                const imm16_raw: u16 = @truncate(insn & 0xFFFF);
                const offset_val: i64 = @as(i64, @as(i16, @bitCast(imm16_raw)));
                const target: u64 = @bitCast(@as(i64, @bitCast(addr)) +% 4 +% (offset_val << 2));
                const xtype: types.XrefType = if (rt_field == 0x10 or rt_field == 0x11) .call else .jump;
                try xrefs.addXref(addr, target, xtype);
            }
        } else if (opcode == 0x12) {
            // COP2: check for BC2F/BC2T branches
            const rs = (insn >> 21) & 0x1F;
            if (rs == 0x08) { // BC2
                const imm16_raw: u16 = @truncate(insn & 0xFFFF);
                const offset_val: i64 = @as(i64, @as(i16, @bitCast(imm16_raw)));
                const target: u64 = @bitCast(@as(i64, @bitCast(addr)) +% 4 +% (offset_val << 2));
                try xrefs.addXref(addr, target, .jump);
            }
        } else if (opcode == 0x00) {
            // R-type: destination is rd (bits 15:11)
            const rd: u5 = @truncate((insn >> 11) & 0x1F);
            if (rd != 0) {
                lui_valid[rd] = false;
            }
        } else {
            // Detect $gp-relative data references: lw/sw/lb/lh/lbu/lhu $rt, offset($gp)
            if (gp_value) |gp| {
                const is_load_store = (opcode >= 0x20 and opcode <= 0x26) or // LB,LH,LWL,LW,LBU,LHU,LWR
                    (opcode == 0x28) or (opcode == 0x29) or // SB,SH
                    (opcode == 0x2B) or (opcode == 0x2E) or // SW,SWR
                    (opcode == 0x2A); // SWL
                const rs: u5 = @truncate((insn >> 21) & 0x1F);
                if (is_load_store and rs == 28) { // $gp = register 28
                    const imm16_raw: u16 = @truncate(insn & 0xFFFF);
                    const sign_ext: i64 = @as(i64, @as(i16, @bitCast(imm16_raw)));
                    const full_addr: u64 = gp +% @as(u64, @bitCast(sign_ext));
                    if (isInDataSection(full_addr, data_sections)) {
                        try xrefs.addXref(addr, full_addr, .data_read);
                    }
                }
            }

            // Other I-type instructions: destination is rt (bits 20:16)
            // Loads (0x20-0x26), other arithmetic, etc.
            const rt: u5 = @truncate((insn >> 16) & 0x1F);
            if (rt != 0) {
                lui_valid[rt] = false;
            }
        }

        insn_count += 1;
        offset += 4;
        addr += 4;
    }

    return insn_count;
}

/// Lean disassembly for MIPS32 binaries — extract call/jump xrefs and LUI+ADDIU/ORI data refs.
pub fn disassembleDocumentLeanMips32(
    allocator: std.mem.Allocator,
    doc: *types.Document,
    xrefs: *xref_mod.XrefTracker,
    raw_data: []const u8,
) !void {
    _ = allocator;

    // Collect data section bounds for LUI+ADDIU/ORI data reference detection.
    var data_sections_buf: [64]DataSectionBounds = undefined;
    var data_section_count: usize = 0;
    for (doc.segments) |segment| {
        if (!segment.permissions.read) continue;
        for (segment.sections) |section| {
            if (isCodeSection(section.name)) continue;
            if (section.length == 0) continue;
            if (data_section_count < data_sections_buf.len) {
                data_sections_buf[data_section_count] = .{
                    .start = section.start,
                    .end = section.start + section.length,
                };
                data_section_count += 1;
            }
        }
    }
    const data_sections = data_sections_buf[0..data_section_count];

    // LUI tracking: last upper-immediate value per register (32 MIPS GP regs).
    var lui_value: [32]u64 = [_]u64{0} ** 32;
    var lui_addr: [32]u64 = [_]u64{0} ** 32;
    var lui_valid: [32]bool = [_]bool{false} ** 32;

    for (doc.segments) |segment| {
        if (!segment.permissions.execute) continue;

        var found_code_section = false;
        for (segment.sections) |section| {
            if (!isCodeSection(section.name)) continue;
            found_code_section = true;

            const file_off: usize = @intCast(section.file_offset);
            const sect_len: usize = @intCast(section.length);
            const section_end = file_off + sect_len;
            if (file_off >= raw_data.len) continue;

            const end_offset = @min(section_end, raw_data.len);
            _ = try leanSweepMips32(raw_data, file_off, end_offset, section.start, xrefs, data_sections, &lui_value, &lui_addr, &lui_valid, doc.gp_value);
        }

        // Fallback: no code sections found (stripped ELF).
        if (!found_code_section and segment.file_size > 0) {
            const file_off: usize = @intCast(segment.file_offset);
            const seg_file_end = file_off + @as(usize, @intCast(segment.file_size));
            if (file_off < raw_data.len) {
                const end_offset = @min(seg_file_end, raw_data.len);
                _ = try leanSweepMips32(raw_data, file_off, end_offset, segment.start, xrefs, data_sections, &lui_value, &lui_addr, &lui_valid, doc.gp_value);
            }
        }
    }
}

/// Lean x86_64 linear sweep over a raw byte range. Extracts CALL/JMP/Jcc xrefs
/// and tracks RIP-relative LEA data references.
fn leanSweepX86_64(
    data: []const u8,
    start_offset: usize,
    end_offset: usize,
    base_addr: u64,
    xrefs: *xref_mod.XrefTracker,
    data_sections: []const DataSectionBounds,
) !usize {
    var insn_count: usize = 0;
    var offset = start_offset;
    var addr = base_addr;

    while (offset < end_offset and offset < data.len) {
        const remaining = data[offset..@min(end_offset, data.len)];
        if (remaining.len < 1) break;
        const decoded = x86_64.decode(remaining, addr);

        if (decoded.is_call or decoded.is_branch) {
            if (decoded.branch_target) |target| {
                const xtype: types.XrefType = if (decoded.is_call) .call else .jump;
                try xrefs.addXref(addr, target, xtype);
            }
        }
        // RIP-relative LEA data references
        if (std.mem.eql(u8, decoded.mnemonic, "lea")) {
            if (decoded.branch_target) |target| {
                if (isInDataSection(target, data_sections)) {
                    try xrefs.addXref(addr, target, .data_read);
                }
            }
        }

        insn_count += 1;
        offset += decoded.length;
        addr += decoded.length;
    }
    return insn_count;
}

/// v7.13.0 B1+B2 — Lean x86-32 (i386) linear sweep. PE32 binaries
/// previously routed nowhere — neither x86_64 nor x86 lean sweeps fired, so
/// `procedure_count`, `string_refs`, and call graph were all empty. This is a
/// minimal byte-pattern sweep for the most common x86-32 call/jump/data
/// idioms; deep operand decoding stays the responsibility of the future
/// dedicated x86 decoder.
///
/// Patterns handled:
///   - `e8 disp32`            → CALL rel32           (xref .call)
///   - `e9 disp32`            → JMP rel32            (xref .jump)
///   - `eb disp8`             → JMP rel8             (xref .jump)
///   - `0f 8x disp32`         → Jcc rel32 (long form)(xref .jump)
///   - `7x disp8`             → Jcc rel8             (xref .jump)
///   - `8d /r [imm32]`        → LEA reg, [disp32]    (xref .data_read)
///   - `8b /r [imm32]`        → MOV reg, [disp32]    (xref .data_read)
///   - `c7 /0 [imm32], imm32` → MOV [disp32], imm32  (xref .data_write)
///   - `89 /r [imm32]`        → MOV [disp32], reg    (xref .data_write)
///   - `68 imm32`             → PUSH imm32 (treated as data_read if in-range)
fn leanSweepX86(
    data: []const u8,
    start_offset: usize,
    end_offset: usize,
    base_addr: u64,
    xrefs: *xref_mod.XrefTracker,
    data_sections: []const DataSectionBounds,
) !usize {
    var insn_count: usize = 0;
    var offset = start_offset;
    var addr = base_addr;

    while (offset < end_offset and offset < data.len) {
        if (end_offset - offset < 1) break;
        const op = data[offset];

        // Single-byte branch / call instructions ----------------------------
        if (op == 0xE8 and offset + 5 <= end_offset) {
            // CALL rel32
            const disp = std.mem.readInt(i32, data[offset + 1 ..][0..4], .little);
            const target: u64 = @bitCast(@as(i64, @bitCast(addr + 5)) +% @as(i64, disp));
            try xrefs.addXref(addr, target, .call);
            offset += 5;
            addr += 5;
            insn_count += 1;
            continue;
        }
        if (op == 0xE9 and offset + 5 <= end_offset) {
            // JMP rel32
            const disp = std.mem.readInt(i32, data[offset + 1 ..][0..4], .little);
            const target: u64 = @bitCast(@as(i64, @bitCast(addr + 5)) +% @as(i64, disp));
            try xrefs.addXref(addr, target, .jump);
            offset += 5;
            addr += 5;
            insn_count += 1;
            continue;
        }
        if (op == 0xEB and offset + 2 <= end_offset) {
            // JMP rel8
            const disp = @as(i8, @bitCast(data[offset + 1]));
            const target: u64 = @bitCast(@as(i64, @bitCast(addr + 2)) +% @as(i64, disp));
            try xrefs.addXref(addr, target, .jump);
            offset += 2;
            addr += 2;
            insn_count += 1;
            continue;
        }
        if (op >= 0x70 and op <= 0x7F and offset + 2 <= end_offset) {
            // Short Jcc rel8
            const disp = @as(i8, @bitCast(data[offset + 1]));
            const target: u64 = @bitCast(@as(i64, @bitCast(addr + 2)) +% @as(i64, disp));
            try xrefs.addXref(addr, target, .jump);
            offset += 2;
            addr += 2;
            insn_count += 1;
            continue;
        }
        if (op == 0x0F and offset + 6 <= end_offset) {
            const op2 = data[offset + 1];
            if (op2 >= 0x80 and op2 <= 0x8F) {
                // Long Jcc rel32
                const disp = std.mem.readInt(i32, data[offset + 2 ..][0..4], .little);
                const target: u64 = @bitCast(@as(i64, @bitCast(addr + 6)) +% @as(i64, disp));
                try xrefs.addXref(addr, target, .jump);
                offset += 6;
                addr += 6;
                insn_count += 1;
                continue;
            }
        }

        // Absolute-address loads / stores -----------------------------------
        // 8d /r mod=00 r/m=101 → LEA reg, [disp32]      (5 bytes after prefix)
        // 8b /r mod=00 r/m=101 → MOV reg, [disp32]
        // 89 /r mod=00 r/m=101 → MOV [disp32], reg
        // c7 /0 mod=00 r/m=101 → MOV [disp32], imm32   (10 bytes total)
        if ((op == 0x8D or op == 0x8B or op == 0x89) and offset + 6 <= end_offset) {
            const modrm = data[offset + 1];
            const mod: u8 = (modrm >> 6) & 0x3;
            const rm: u8 = modrm & 0x7;
            if (mod == 0 and rm == 5) {
                const imm = std.mem.readInt(u32, data[offset + 2 ..][0..4], .little);
                const target: u64 = imm;
                const xtype: types.XrefType = if (op == 0x89) .data_write else .data_read;
                if (isInDataSection(target, data_sections)) {
                    try xrefs.addXref(addr, target, xtype);
                }
                offset += 6;
                addr += 6;
                insn_count += 1;
                continue;
            }
        }
        if (op == 0xC7 and offset + 10 <= end_offset) {
            const modrm = data[offset + 1];
            const mod: u8 = (modrm >> 6) & 0x3;
            const rm: u8 = modrm & 0x7;
            const reg: u8 = (modrm >> 3) & 0x7;
            if (mod == 0 and rm == 5 and reg == 0) {
                const imm = std.mem.readInt(u32, data[offset + 2 ..][0..4], .little);
                const target: u64 = imm;
                if (isInDataSection(target, data_sections)) {
                    try xrefs.addXref(addr, target, .data_write);
                }
                offset += 10;
                addr += 10;
                insn_count += 1;
                continue;
            }
        }

        // PUSH imm32 — `68 imm32`. Often used to push a string pointer for
        // `printf`-class calls; treat the immediate as a data_read if it
        // lands in a data section.
        if (op == 0x68 and offset + 5 <= end_offset) {
            const imm = std.mem.readInt(u32, data[offset + 1 ..][0..4], .little);
            const target: u64 = imm;
            if (isInDataSection(target, data_sections)) {
                try xrefs.addXref(addr, target, .data_read);
            }
            offset += 5;
            addr += 5;
            insn_count += 1;
            continue;
        }

        // RET — terminates a procedure (used by detectX86Procedures B2).
        if (op == 0xC3 or op == 0xC2 or op == 0xCB or op == 0xCA) {
            offset += 1;
            addr += 1;
            insn_count += 1;
            continue;
        }

        // Unknown / not-tracked: advance one byte. We don't try to be a full
        // x86 decoder — this lean sweep is intentionally pattern-based.
        offset += 1;
        addr += 1;
        insn_count += 1;
    }

    return insn_count;
}

/// Lean disassembly for x86-32 (i386) PE binaries.
pub fn disassembleDocumentLeanX86(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    xrefs: *xref_mod.XrefTracker,
) !usize {
    _ = allocator;
    var insn_count: usize = 0;

    var data_sections_buf: [64]DataSectionBounds = undefined;
    var data_section_count: usize = 0;
    for (doc.segments) |segment| {
        if (!segment.permissions.read) continue;
        for (segment.sections) |section| {
            if (isCodeSection(section.name)) continue;
            if (section.length == 0) continue;
            if (data_section_count < data_sections_buf.len) {
                data_sections_buf[data_section_count] = .{
                    .start = section.start,
                    .end = section.start + section.length,
                };
                data_section_count += 1;
            }
        }
    }
    const data_sections = data_sections_buf[0..data_section_count];

    for (doc.segments) |segment| {
        if (!segment.permissions.execute) continue;
        var found_code_section = false;
        for (segment.sections) |section| {
            if (!isCodeSection(section.name)) continue;
            found_code_section = true;
            const file_off: usize = @intCast(section.file_offset);
            const sect_len: usize = @intCast(section.length);
            const section_end = file_off + sect_len;
            if (file_off >= doc.data.len) continue;
            const end_offset = @min(section_end, doc.data.len);
            insn_count += try leanSweepX86(doc.data, file_off, end_offset, section.start, xrefs, data_sections);
        }
        if (!found_code_section and segment.file_size > 0) {
            const file_off: usize = @intCast(segment.file_offset);
            const seg_file_end = file_off + @as(usize, @intCast(segment.file_size));
            if (file_off < doc.data.len) {
                const end_offset = @min(seg_file_end, doc.data.len);
                insn_count += try leanSweepX86(doc.data, file_off, end_offset, segment.start, xrefs, data_sections);
            }
        }
    }
    return insn_count;
}

/// Lean disassembly for x86_64 binaries — extract call/jump xrefs and RIP-relative data refs.
pub fn disassembleDocumentLeanX86_64(
    allocator: std.mem.Allocator,
    doc: *const types.Document,
    xrefs: *xref_mod.XrefTracker,
) !usize {
    _ = allocator;
    var insn_count: usize = 0;

    // Collect data section bounds for RIP-relative reference detection
    var data_sections_buf: [64]DataSectionBounds = undefined;
    var data_section_count: usize = 0;
    for (doc.segments) |segment| {
        if (!segment.permissions.read) continue;
        for (segment.sections) |section| {
            if (isCodeSection(section.name)) continue;
            if (section.length == 0) continue;
            if (data_section_count < data_sections_buf.len) {
                data_sections_buf[data_section_count] = .{
                    .start = section.start,
                    .end = section.start + section.length,
                };
                data_section_count += 1;
            }
        }
    }
    const data_sections = data_sections_buf[0..data_section_count];

    for (doc.segments) |segment| {
        if (!segment.permissions.execute) continue;
        var found_code_section = false;
        for (segment.sections) |section| {
            if (!isCodeSection(section.name)) continue;
            found_code_section = true;
            const file_off: usize = @intCast(section.file_offset);
            const sect_len: usize = @intCast(section.length);
            const section_end = file_off + sect_len;
            if (file_off >= doc.data.len) continue;
            const end_offset = @min(section_end, doc.data.len);
            insn_count += try leanSweepX86_64(doc.data, file_off, end_offset, section.start, xrefs, data_sections);
        }
        if (!found_code_section and segment.file_size > 0) {
            const file_off: usize = @intCast(segment.file_offset);
            const seg_file_end = file_off + @as(usize, @intCast(segment.file_size));
            if (file_off < doc.data.len) {
                const end_offset = @min(seg_file_end, doc.data.len);
                insn_count += try leanSweepX86_64(doc.data, file_off, end_offset, segment.start, xrefs, data_sections);
            }
        }
    }
    return insn_count;
}

/// Parse a hex address from operand text (e.g., "#0x100001234" or "0x100001234").
fn parseAddress(operands: []const u8) ?u64 {
    // Look for hex address pattern
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

/// Parse a PC-relative address from operand text.
fn parsePcRelAddress(operands: []const u8) ?u64 {
    return parseAddress(operands);
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn isBranchMnemonic(mnemonic: []const u8) bool {
    if (mnemonic.len < 2) return false;
    // b.eq, b.ne, b.lt, b.gt, etc. — starts with "b." (case-insensitive)
    if ((mnemonic[0] == 'b' or mnemonic[0] == 'B') and mnemonic[1] == '.') return true;
    // cbz, cbnz, tbz, tbnz
    if (std.mem.eql(u8, mnemonic, "cbz") or std.mem.eql(u8, mnemonic, "CBZ")) return true;
    if (std.mem.eql(u8, mnemonic, "cbnz") or std.mem.eql(u8, mnemonic, "CBNZ")) return true;
    if (std.mem.eql(u8, mnemonic, "tbz") or std.mem.eql(u8, mnemonic, "TBZ")) return true;
    if (std.mem.eql(u8, mnemonic, "tbnz") or std.mem.eql(u8, mnemonic, "TBNZ")) return true;
    return false;
}

const DataSectionBounds = struct {
    start: u64,
    end: u64,
};

fn isInDataSection(addr: u64, sections: []const DataSectionBounds) bool {
    for (sections) |sec| {
        if (addr >= sec.start and addr < sec.end) return true;
    }
    return false;
}

fn isCodeSection(name: []const u8) bool {
    return std.mem.eql(u8, name, "__text") or
        std.mem.eql(u8, name, "__stubs") or
        std.mem.eql(u8, name, ".text") or
        std.mem.eql(u8, name, ".plt");
}

// ============================================================================
// Tests
// ============================================================================

test "parse hex address from operands" {
    try std.testing.expectEqual(@as(?u64, 0x100001234), parseAddress("#0x100001234"));
    try std.testing.expectEqual(@as(?u64, 0xDEAD), parseAddress("0xDEAD"));
    try std.testing.expectEqual(@as(?u64, null), parseAddress("x0, x1"));
}

test "branch mnemonic detection" {
    try std.testing.expect(isBranchMnemonic("b.eq"));
    try std.testing.expect(isBranchMnemonic("B.NE"));
    try std.testing.expect(isBranchMnemonic("cbz"));
    try std.testing.expect(isBranchMnemonic("tbnz"));
    try std.testing.expect(!isBranchMnemonic("bl"));
    try std.testing.expect(!isBranchMnemonic("mov"));
}

test "linear sweep with mock decoder" {
    const allocator = std.testing.allocator;
    var xrefs = xref_mod.XrefTracker.init(allocator, std.testing.io);
    defer xrefs.deinit();

    const mock_decoder = struct {
        fn decode(data: []const u8, address: u64) types.Instruction {
            _ = data;
            return types.Instruction{
                .address = address,
                .bytes = &.{ 0, 0, 0, 0 },
                .mnemonic = "nop",
                .operands = "",
                .size = 4,
            };
        }
    }.decode;

    const data = [_]u8{0} ** 16;
    var instructions = try disassembleSection(
        allocator,
        &data,
        0,
        0x1000,
        16,
        mock_decoder,
        &xrefs,
        4,
    );
    defer instructions.deinit();

    try std.testing.expectEqual(@as(usize, 4), instructions.items.len);
    try std.testing.expectEqual(@as(u64, 0x1000), instructions.items[0].address);
    try std.testing.expectEqual(@as(u64, 0x100C), instructions.items[3].address);
}
