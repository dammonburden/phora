// Phora — ELF Binary Parser
// Parses Linux ELF binaries: headers, program headers, section headers,
// symbol tables, string tables, dynamic section.
// Focuses on ELF64 (64-bit) as the common case.

const std = @import("std");
const psp_nids = @import("../psp_nids.zig");
const types = @import("../types.zig");

const Document = types.Document;
const Segment = types.Segment;
const Section = types.Section;
const Import = types.Import;
const Arch = types.Arch;
const BinaryFormat = types.BinaryFormat;
const SegmentPermissions = types.SegmentPermissions;
const LoadOptions = types.LoadOptions;
const Procedure = types.Procedure;

// ============================================================================
// ELF Constants
// ============================================================================

// ELF magic
const ELFMAG: [4]u8 = .{ 0x7f, 'E', 'L', 'F' };

// e_ident indices
const EI_CLASS = 4;
const EI_DATA = 5;
const EI_VERSION = 6;
const EI_OSABI = 7;

// EI_CLASS values
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

// EI_DATA values
const ELFDATA2LSB: u8 = 1; // Little-endian
const ELFDATA2MSB: u8 = 2; // Big-endian

// e_type values
const ET_NONE: u16 = 0;
const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3; // Shared object / PIE
const ET_CORE: u16 = 4;

// e_machine values
const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_MIPS: u16 = 8;
const EM_ARM: u16 = 40;
const EM_AARCH64: u16 = 183;

// Program header types
const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_SHLIB: u32 = 5;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_EH_FRAME: u32 = 0x6474e550;
const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_RELRO: u32 = 0x6474e552;

// Program header flags
const PF_X: u32 = 0x1; // Execute
const PF_W: u32 = 0x2; // Write
const PF_R: u32 = 0x4; // Read

// Section header types
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8; // .bss
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_FINI_ARRAY: u32 = 15;
const SHT_GNU_HASH: u32 = 0x6ffffff6;
const SHT_GNU_VERSYM: u32 = 0x6fffffff;
const SHT_GNU_VERNEED: u32 = 0x6ffffffe;

// Section header flags
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

// Symbol binding (upper 4 bits of st_info)
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

// Symbol type (lower 4 bits of st_info)
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;
const STT_COMMON: u8 = 5;

// Special section indices
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;

// Dynamic section tags
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SONAME: i64 = 14;
const DT_BIND_NOW: i64 = 24;
const DT_FLAGS: i64 = 30;
const DF_BIND_NOW: u64 = 0x8;

// ============================================================================
// ELF On-Disk Structures (extern structs matching binary layout)
// ============================================================================

const Elf64_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64_Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

const Elf64_Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

const Elf64_Sym = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
};

const Elf64_Dyn = extern struct {
    d_tag: i64,
    d_val: u64,
};

// ELF32 on-disk structures

const Elf32_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf32_Phdr = extern struct {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
};

const Elf32_Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u32,
    sh_addr: u32,
    sh_offset: u32,
    sh_size: u32,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u32,
    sh_entsize: u32,
};

const Elf32_Sym = extern struct {
    st_name: u32,
    st_value: u32,
    st_size: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
};

const Elf32_Dyn = extern struct {
    d_tag: i32,
    d_val: u32,
};

// ============================================================================
// Errors
// ============================================================================

pub const ElfError = error{
    NotElf,
    UnsupportedClass,
    UnsupportedEndianness,
    TruncatedHeader,
    TruncatedProgramHeaders,
    TruncatedSectionHeaders,
    InvalidSectionIndex,
    OutOfMemory,
};

// ============================================================================
// Internal parse result (before converting to Document)
// ============================================================================

const ParseResult = struct {
    arch: Arch,
    entry_point: u64,
    segments: std.array_list.Managed(Segment),
    sections_list: std.array_list.Managed(Section),
    symbols: std.array_list.Managed(SymbolEntry),
    imports: std.array_list.Managed(Import),
    needed_libs: std.array_list.Managed([]const u8),
    procedures: std.array_list.Managed(Procedure),
    // Hardening tracking (v7.5.2)
    has_relro: bool = false,
    has_bind_now: bool = false,
    found_symtab: bool = false,

    fn init(allocator: std.mem.Allocator) ParseResult {
        return .{
            .arch = .x86_64,
            .entry_point = 0,
            .segments = std.array_list.Managed(Segment).init(allocator),
            .sections_list = std.array_list.Managed(Section).init(allocator),
            .symbols = std.array_list.Managed(SymbolEntry).init(allocator),
            .imports = std.array_list.Managed(Import).init(allocator),
            .needed_libs = std.array_list.Managed([]const u8).init(allocator),
            .procedures = std.array_list.Managed(Procedure).init(allocator),
        };
    }

    fn deinit(self: *ParseResult) void {
        self.segments.deinit();
        self.sections_list.deinit();
        self.symbols.deinit();
        self.imports.deinit();
        self.needed_libs.deinit();
        self.procedures.deinit();
    }
};

const SymbolEntry = struct {
    name: []const u8,
    value: u64,
    size: u64,
    sym_type: u8, // STT_*
    binding: u8, // STB_*
    section_index: u16,
    is_function: bool,
    is_undefined: bool,
};

// ============================================================================
// Public API
// ============================================================================

/// Parse an ELF binary from raw file data.
/// Returns a populated Document with segments, sections, imports, and procedures.
pub fn parse(allocator: std.mem.Allocator, doc_id: u64, path: []const u8, data: []const u8, options: LoadOptions) ElfError!Document {
    // Minimum size check: ELF32 header is 52 bytes (smallest)
    if (data.len < @sizeOf(Elf32_Ehdr)) return ElfError.TruncatedHeader;

    // Validate ELF magic
    if (data[0] != ELFMAG[0] or data[1] != ELFMAG[1] or
        data[2] != ELFMAG[2] or data[3] != ELFMAG[3])
    {
        return ElfError.NotElf;
    }

    // Check endianness — we only support little-endian for now
    if (data[EI_DATA] != ELFDATA2LSB) return ElfError.UnsupportedEndianness;

    // Dispatch on ELF class
    if (data[EI_CLASS] == ELFCLASS64) {
        if (data.len < @sizeOf(Elf64_Ehdr)) return ElfError.TruncatedHeader;
        return parseElf64(allocator, doc_id, path, data, options);
    } else if (data[EI_CLASS] == ELFCLASS32) {
        return parseElf32(allocator, doc_id, path, data, options);
    } else {
        return ElfError.UnsupportedClass;
    }
}

/// Returns true if the data begins with the ELF magic number.
pub fn isElf(data: []const u8) bool {
    if (data.len < 4) return false;
    return data[0] == ELFMAG[0] and data[1] == ELFMAG[1] and
        data[2] == ELFMAG[2] and data[3] == ELFMAG[3];
}

// ============================================================================
// ELF64 Parsing
// ============================================================================

fn parseElf64(allocator: std.mem.Allocator, doc_id: u64, path: []const u8, data: []const u8, options: LoadOptions) ElfError!Document {
    const ehdr = readEhdr(data);

    var result = ParseResult.init(allocator);
    errdefer result.deinit();

    // Determine architecture
    result.arch = if (options.arch) |a| a else switch (ehdr.e_machine) {
        EM_AARCH64 => Arch.arm64,
        EM_X86_64 => Arch.x86_64,
        EM_MIPS => Arch.mips32,
        else => Arch.x86_64,
    };

    result.entry_point = ehdr.e_entry;

    // Parse section header string table first (needed for section names)
    const shstrtab = getSectionStringTable(data, &ehdr);

    // Parse section headers
    parseSectionHeaders(allocator, data, &ehdr, shstrtab, &result);

    // Parse program headers (creates segments)
    parseProgramHeaders(allocator, data, &ehdr, &result);

    // Parse symbol tables (.symtab and .dynsym)
    parseSymbolTables(allocator, data, &ehdr, &result);

    // Parse dynamic section for DT_NEEDED (shared library dependencies)
    parseDynamicSection(data, &ehdr, &result);

    // Build Document
    var doc = Document.init(allocator, doc_id, path, data);
    doc.format = .elf;
    doc.arch = result.arch;
    doc.entry_point = result.entry_point;
    doc.segments = result.segments.toOwnedSlice() catch return ElfError.OutOfMemory;

    // Hardening fields
    doc.is_pie = (ehdr.e_type == ET_DYN);
    doc.is_stripped = !result.found_symtab;
    doc.has_relro = result.has_relro;
    doc.relro_full = result.has_relro and result.has_bind_now;

    // Transfer needed_libs (DT_NEEDED entries) for cross-binary dependency resolution
    doc.needed_libs = result.needed_libs.toOwnedSlice() catch &.{};

    // Transfer imports
    for (result.imports.items) |imp| {
        doc.imports.append(imp) catch return ElfError.OutOfMemory;
    }

    // Map PLT stub addresses to imports (v7.6.2)
    mapElfPltImports64(data, &ehdr, &doc);

    // Transfer function symbols as procedures
    for (result.symbols.items) |sym| {
        if (sym.is_function and !sym.is_undefined and sym.size > 0) {
            doc.procedures.append(.{
                .entry = sym.value,
                .size = sym.size,
                .name = if (sym.name.len > 0) sym.name else null,
            }) catch return ElfError.OutOfMemory;
        }
    }

    return doc;
}

fn readEhdr(data: []const u8) Elf64_Ehdr {
    return .{
        .e_ident = data[0..16].*,
        .e_type = readU16(data, 16),
        .e_machine = readU16(data, 18),
        .e_version = readU32(data, 20),
        .e_entry = readU64(data, 24),
        .e_phoff = readU64(data, 32),
        .e_shoff = readU64(data, 40),
        .e_flags = readU32(data, 48),
        .e_ehsize = readU16(data, 52),
        .e_phentsize = readU16(data, 54),
        .e_phnum = readU16(data, 56),
        .e_shentsize = readU16(data, 58),
        .e_shnum = readU16(data, 60),
        .e_shstrndx = readU16(data, 62),
    };
}

// ============================================================================
// Section Header Parsing
// ============================================================================

fn getSectionStringTable(data: []const u8, ehdr: *const Elf64_Ehdr) ?[]const u8 {
    if (ehdr.e_shstrndx == 0 or ehdr.e_shstrndx >= ehdr.e_shnum) return null;
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return null;

    const shdr_offset = ehdr.e_shoff + @as(u64, ehdr.e_shstrndx) * @as(u64, ehdr.e_shentsize);
    if (shdr_offset + @sizeOf(Elf64_Shdr) > data.len) return null;

    const sh_offset = readU64(data, @intCast(shdr_offset + 24)); // sh_offset
    const sh_size = readU64(data, @intCast(shdr_offset + 32)); // sh_size

    if (sh_offset + sh_size > data.len) return null;

    return data[@intCast(sh_offset)..@intCast(sh_offset + sh_size)];
}

fn parseSectionHeaders(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf64_Ehdr, shstrtab: ?[]const u8, result: *ParseResult) void {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = ehdr.e_shoff + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf64_Shdr) > data.len) break;

        const shdr = readShdr(data, @intCast(offset));

        // Skip NULL section
        if (shdr.sh_type == SHT_NULL) continue;

        // Track .symtab presence for stripped detection
        if (shdr.sh_type == SHT_SYMTAB) {
            result.found_symtab = true;
        }

        // Get section name from string table
        const name = getSectionName(shstrtab, shdr.sh_name);

        result.sections_list.append(.{
            .name = name,
            .start = shdr.sh_addr,
            .length = shdr.sh_size,
            .file_offset = shdr.sh_offset,
            .alignment = if (shdr.sh_addralign > 0 and shdr.sh_addralign <= 0xFFFFFFFF)
                @intCast(std.math.log2(@as(u64, @max(shdr.sh_addralign, 1))))
            else
                0,
            .is_zerofill = shdr.sh_type == SHT_NOBITS,
        }) catch return;

        _ = allocator;
    }
}

fn readShdr(data: []const u8, offset: usize) Elf64_Shdr {
    return .{
        .sh_name = readU32(data, offset),
        .sh_type = readU32(data, offset + 4),
        .sh_flags = readU64(data, offset + 8),
        .sh_addr = readU64(data, offset + 16),
        .sh_offset = readU64(data, offset + 24),
        .sh_size = readU64(data, offset + 32),
        .sh_link = readU32(data, offset + 40),
        .sh_info = readU32(data, offset + 44),
        .sh_addralign = readU64(data, offset + 48),
        .sh_entsize = readU64(data, offset + 56),
    };
}

fn getSectionName(shstrtab: ?[]const u8, name_offset: u32) []const u8 {
    const strtab = shstrtab orelse return "";
    if (name_offset >= strtab.len) return "";

    const start = strtab[name_offset..];
    const end = std.mem.indexOfScalar(u8, start, 0) orelse start.len;
    return start[0..end];
}

// ============================================================================
// Program Header Parsing (Segments)
// ============================================================================

fn parseProgramHeaders(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf64_Ehdr, result: *ParseResult) void {
    if (ehdr.e_phoff == 0 or ehdr.e_phnum == 0) return;

    var i: u16 = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const offset = ehdr.e_phoff + @as(u64, i) * @as(u64, ehdr.e_phentsize);
        if (offset + @sizeOf(Elf64_Phdr) > data.len) break;

        const phdr = readPhdr(data, @intCast(offset));

        // Detect PT_GNU_RELRO (hardening)
        if (phdr.p_type == PT_GNU_RELRO) {
            result.has_relro = true;
        }

        // Only create segments for PT_LOAD (the actual memory mappings)
        if (phdr.p_type != PT_LOAD) continue;

        const seg_name = segmentName(phdr.p_flags);

        // Find sections that fall within this segment's virtual address range
        var sections = std.array_list.Managed(Section).init(allocator);
        for (result.sections_list.items) |sec| {
            if (sec.start >= phdr.p_vaddr and sec.start < phdr.p_vaddr + phdr.p_memsz) {
                sections.append(sec) catch continue;
            }
        }

        result.segments.append(.{
            .name = seg_name,
            .start = phdr.p_vaddr,
            .length = phdr.p_memsz,
            .file_offset = phdr.p_offset,
            .file_size = phdr.p_filesz,
            .sections = sections.toOwnedSlice() catch &.{},
            .permissions = .{
                .read = (phdr.p_flags & PF_R) != 0,
                .write = (phdr.p_flags & PF_W) != 0,
                .execute = (phdr.p_flags & PF_X) != 0,
            },
        }) catch return;
    }
}

fn readPhdr(data: []const u8, offset: usize) Elf64_Phdr {
    return .{
        .p_type = readU32(data, offset),
        .p_flags = readU32(data, offset + 4),
        .p_offset = readU64(data, offset + 8),
        .p_vaddr = readU64(data, offset + 16),
        .p_paddr = readU64(data, offset + 24),
        .p_filesz = readU64(data, offset + 32),
        .p_memsz = readU64(data, offset + 40),
        .p_align = readU64(data, offset + 48),
    };
}

fn segmentName(flags: u32) []const u8 {
    const r = (flags & PF_R) != 0;
    const w = (flags & PF_W) != 0;
    const x = (flags & PF_X) != 0;

    if (r and x and !w) return "TEXT";
    if (r and w and !x) return "DATA";
    if (r and !w and !x) return "RODATA";
    if (r and w and x) return "RWX";
    return "LOAD";
}

// ============================================================================
// Symbol Table Parsing
// ============================================================================

fn parseSymbolTables(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf64_Ehdr, result: *ParseResult) void {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = ehdr.e_shoff + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf64_Shdr) > data.len) break;

        const shdr = readShdr(data, @intCast(offset));

        if (shdr.sh_type == SHT_SYMTAB or shdr.sh_type == SHT_DYNSYM) {
            parseSymtab(allocator, data, ehdr, &shdr, shdr.sh_type == SHT_DYNSYM, result);
        }
    }
}

fn parseSymtab(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf64_Ehdr, symtab_shdr: *const Elf64_Shdr, is_dynamic: bool, result: *ParseResult) void {
    if (symtab_shdr.sh_entsize == 0) return;
    if (symtab_shdr.sh_offset + symtab_shdr.sh_size > data.len) return;

    // Get the associated string table (sh_link points to it)
    const strtab = getStringTable(data, ehdr, symtab_shdr.sh_link) orelse return;

    const num_syms = symtab_shdr.sh_size / symtab_shdr.sh_entsize;
    var sym_idx: u64 = 0;
    while (sym_idx < num_syms) : (sym_idx += 1) {
        const sym_offset = symtab_shdr.sh_offset + sym_idx * symtab_shdr.sh_entsize;
        if (sym_offset + @sizeOf(Elf64_Sym) > data.len) break;

        const sym = readSym(data, @intCast(sym_offset));

        // Get symbol name
        const name = getStringFromTable(strtab, sym.st_name);
        if (name.len == 0) continue;

        const sym_type = sym.st_info & 0x0f;
        const binding = sym.st_info >> 4;
        const is_undefined = sym.st_shndx == SHN_UNDEF;
        const is_func = sym_type == STT_FUNC;

        const entry = SymbolEntry{
            .name = name,
            .value = sym.st_value,
            .size = sym.st_size,
            .sym_type = sym_type,
            .binding = binding,
            .section_index = sym.st_shndx,
            .is_function = is_func,
            .is_undefined = is_undefined,
        };

        result.symbols.append(entry) catch return;

        // Undefined function symbols from .dynsym are imports
        if (is_dynamic and is_undefined and is_func and name.len > 0) {
            // If exactly one DT_NEEDED lib, assign it as the import's library
            const lib: ?[]const u8 = if (result.needed_libs.items.len == 1)
                result.needed_libs.items[0]
            else
                null;
            result.imports.append(.{
                .address = sym.st_value,
                .name = name,
                .library = lib,
            }) catch return;
        }

        _ = allocator;
    }
}

fn readSym(data: []const u8, offset: usize) Elf64_Sym {
    return .{
        .st_name = readU32(data, offset),
        .st_info = data[offset + 4],
        .st_other = data[offset + 5],
        .st_shndx = readU16(data, offset + 6),
        .st_value = readU64(data, offset + 8),
        .st_size = readU64(data, offset + 16),
    };
}

fn getStringTable(data: []const u8, ehdr: *const Elf64_Ehdr, sh_link: u32) ?[]const u8 {
    if (sh_link == 0 or sh_link >= ehdr.e_shnum) return null;

    const offset = ehdr.e_shoff + @as(u64, sh_link) * @as(u64, ehdr.e_shentsize);
    if (offset + @sizeOf(Elf64_Shdr) > data.len) return null;

    const strtab_shdr = readShdr(data, @intCast(offset));
    if (strtab_shdr.sh_type != SHT_STRTAB) return null;
    if (strtab_shdr.sh_offset + strtab_shdr.sh_size > data.len) return null;

    return data[@intCast(strtab_shdr.sh_offset)..@intCast(strtab_shdr.sh_offset + strtab_shdr.sh_size)];
}

fn getStringFromTable(strtab: []const u8, name_offset: u32) []const u8 {
    if (name_offset >= strtab.len) return "";
    const start = strtab[name_offset..];
    const end = std.mem.indexOfScalar(u8, start, 0) orelse start.len;
    return start[0..end];
}

// ============================================================================
// Dynamic Section Parsing
// ============================================================================

fn parseDynamicSection(data: []const u8, ehdr: *const Elf64_Ehdr, result: *ParseResult) void {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    // Find .dynamic section
    var dyn_shdr: ?Elf64_Shdr = null;
    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = ehdr.e_shoff + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf64_Shdr) > data.len) break;

        const shdr = readShdr(data, @intCast(offset));
        if (shdr.sh_type == SHT_DYNAMIC) {
            dyn_shdr = shdr;
            break;
        }
    }

    const dynamic = dyn_shdr orelse return;
    if (dynamic.sh_offset + dynamic.sh_size > data.len) return;
    if (dynamic.sh_entsize == 0) return;

    // Get the string table linked to the dynamic section
    const dyn_strtab = getStringTable(data, ehdr, dynamic.sh_link);

    // Parse dynamic entries
    const num_entries = dynamic.sh_size / dynamic.sh_entsize;
    var entry_idx: u64 = 0;
    while (entry_idx < num_entries) : (entry_idx += 1) {
        const entry_offset = dynamic.sh_offset + entry_idx * dynamic.sh_entsize;
        if (entry_offset + @sizeOf(Elf64_Dyn) > data.len) break;

        const dyn = readDyn(data, @intCast(entry_offset));

        if (dyn.d_tag == DT_NULL) break;

        if (dyn.d_tag == DT_NEEDED) {
            if (dyn_strtab) |strtab| {
                const lib_name = getStringFromTable(strtab, @intCast(dyn.d_val));
                if (lib_name.len > 0) {
                    result.needed_libs.append(lib_name) catch continue;
                }
            }
        }

        // Detect BIND_NOW for full RELRO
        if (dyn.d_tag == DT_BIND_NOW) {
            result.has_bind_now = true;
        }
        if (dyn.d_tag == DT_FLAGS and (dyn.d_val & DF_BIND_NOW) != 0) {
            result.has_bind_now = true;
        }
    }

    // Associate imports with their libraries based on DT_NEEDED
    // (Simple heuristic: for now, just note the needed libraries exist)
}

fn readDyn(data: []const u8, offset: usize) Elf64_Dyn {
    return .{
        .d_tag = @bitCast(readU64(data, offset)),
        .d_val = readU64(data, offset + 8),
    };
}

// ============================================================================
// ELF32 Parsing
// ============================================================================

fn parseElf32(allocator: std.mem.Allocator, doc_id: u64, path: []const u8, data: []const u8, options: LoadOptions) ElfError!Document {
    const ehdr = readEhdr32(data);

    var result = ParseResult.init(allocator);
    errdefer result.deinit();

    // Determine architecture
    result.arch = if (options.arch) |a| a else switch (ehdr.e_machine) {
        EM_ARM => Arch.arm32,
        EM_386 => Arch.x86,
        EM_MIPS => Arch.mips32,
        else => Arch.x86,
    };

    result.entry_point = @as(u64, ehdr.e_entry);

    // Parse section header string table first (needed for section names)
    const shstrtab = getSectionStringTable32(data, &ehdr);

    // Parse section headers
    parseSectionHeaders32(allocator, data, &ehdr, shstrtab, &result);

    // Parse program headers (creates segments)
    parseProgramHeaders32(allocator, data, &ehdr, &result);

    // Parse symbol tables (.symtab and .dynsym)
    parseSymbolTables32(allocator, data, &ehdr, &result);

    // Parse dynamic section for DT_NEEDED (shared library dependencies)
    parseDynamicSection32(data, &ehdr, &result);

    // Parse PSP import stubs if this is a MIPS binary
    if (ehdr.e_machine == EM_MIPS) {
        parsePspImports(allocator, data, &ehdr, &result);
    }

    // Build Document
    var doc = Document.init(allocator, doc_id, path, data);
    doc.format = .elf;
    doc.arch = result.arch;
    doc.entry_point = result.entry_point;
    doc.segments = result.segments.toOwnedSlice() catch return ElfError.OutOfMemory;

    // Hardening fields
    doc.is_pie = (ehdr.e_type == ET_DYN);
    doc.is_stripped = !result.found_symtab;
    doc.has_relro = result.has_relro;
    doc.relro_full = result.has_relro and result.has_bind_now;

    // Transfer needed_libs (DT_NEEDED entries) for cross-binary dependency resolution
    doc.needed_libs = result.needed_libs.toOwnedSlice() catch &.{};

    // Transfer imports
    for (result.imports.items) |imp| {
        doc.imports.append(imp) catch return ElfError.OutOfMemory;
    }

    // Map PLT stub addresses to imports (v7.6.2)
    mapElfPltImports32(data, &ehdr, &doc);

    // Transfer function symbols as procedures
    for (result.symbols.items) |sym| {
        if (sym.is_function and !sym.is_undefined and sym.size > 0) {
            doc.procedures.append(.{
                .entry = sym.value,
                .size = sym.size,
                .name = if (sym.name.len > 0) sym.name else null,
            }) catch return ElfError.OutOfMemory;
        }
    }

    // Compute MIPS $gp (global pointer) value: .data address + 0x7FF0
    if (doc.arch == .mips32) {
        for (result.sections_list.items) |sec| {
            if (std.mem.eql(u8, sec.name, ".data")) {
                doc.gp_value = sec.start + 0x7FF0;
                break;
            }
        }
    }

    return doc;
}

fn readEhdr32(data: []const u8) Elf32_Ehdr {
    return .{
        .e_ident = data[0..16].*,
        .e_type = readU16(data, 16),
        .e_machine = readU16(data, 18),
        .e_version = readU32(data, 20),
        .e_entry = readU32(data, 24),
        .e_phoff = readU32(data, 28),
        .e_shoff = readU32(data, 32),
        .e_flags = readU32(data, 36),
        .e_ehsize = readU16(data, 40),
        .e_phentsize = readU16(data, 42),
        .e_phnum = readU16(data, 44),
        .e_shentsize = readU16(data, 46),
        .e_shnum = readU16(data, 48),
        .e_shstrndx = readU16(data, 50),
    };
}

fn getSectionStringTable32(data: []const u8, ehdr: *const Elf32_Ehdr) ?[]const u8 {
    if (ehdr.e_shstrndx == 0 or ehdr.e_shstrndx >= ehdr.e_shnum) return null;
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return null;

    const shdr_offset = @as(u64, ehdr.e_shoff) + @as(u64, ehdr.e_shstrndx) * @as(u64, ehdr.e_shentsize);
    if (shdr_offset + @sizeOf(Elf32_Shdr) > data.len) return null;

    const sh_offset = @as(u64, readU32(data, @intCast(shdr_offset + 16))); // sh_offset at +16 in Elf32_Shdr
    const sh_size = @as(u64, readU32(data, @intCast(shdr_offset + 20))); // sh_size at +20

    if (sh_offset + sh_size > data.len) return null;

    return data[@intCast(sh_offset)..@intCast(sh_offset + sh_size)];
}

fn readShdr32(data: []const u8, offset: usize) Elf32_Shdr {
    return .{
        .sh_name = readU32(data, offset),
        .sh_type = readU32(data, offset + 4),
        .sh_flags = readU32(data, offset + 8),
        .sh_addr = readU32(data, offset + 12),
        .sh_offset = readU32(data, offset + 16),
        .sh_size = readU32(data, offset + 20),
        .sh_link = readU32(data, offset + 24),
        .sh_info = readU32(data, offset + 28),
        .sh_addralign = readU32(data, offset + 32),
        .sh_entsize = readU32(data, offset + 36),
    };
}

fn parseSectionHeaders32(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf32_Ehdr, shstrtab: ?[]const u8, result: *ParseResult) void {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = @as(u64, ehdr.e_shoff) + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf32_Shdr) > data.len) break;

        const shdr = readShdr32(data, @intCast(offset));

        // Skip NULL section
        if (shdr.sh_type == SHT_NULL) continue;

        // Track .symtab presence for stripped detection
        if (shdr.sh_type == SHT_SYMTAB) {
            result.found_symtab = true;
        }

        // Get section name from string table
        const name = getSectionName(shstrtab, shdr.sh_name);

        result.sections_list.append(.{
            .name = name,
            .start = @as(u64, shdr.sh_addr),
            .length = @as(u64, shdr.sh_size),
            .file_offset = @as(u64, shdr.sh_offset),
            .alignment = if (shdr.sh_addralign > 0)
                @intCast(std.math.log2(@as(u64, @max(shdr.sh_addralign, 1))))
            else
                0,
            .is_zerofill = shdr.sh_type == SHT_NOBITS,
        }) catch return;

        _ = allocator;
    }
}

fn readPhdr32(data: []const u8, offset: usize) Elf32_Phdr {
    return .{
        .p_type = readU32(data, offset),
        .p_offset = readU32(data, offset + 4),
        .p_vaddr = readU32(data, offset + 8),
        .p_paddr = readU32(data, offset + 12),
        .p_filesz = readU32(data, offset + 16),
        .p_memsz = readU32(data, offset + 20),
        .p_flags = readU32(data, offset + 24),
        .p_align = readU32(data, offset + 28),
    };
}

fn parseProgramHeaders32(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf32_Ehdr, result: *ParseResult) void {
    if (ehdr.e_phoff == 0 or ehdr.e_phnum == 0) return;

    var i: u16 = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const offset = @as(u64, ehdr.e_phoff) + @as(u64, i) * @as(u64, ehdr.e_phentsize);
        if (offset + @sizeOf(Elf32_Phdr) > data.len) break;

        const phdr = readPhdr32(data, @intCast(offset));

        // Detect PT_GNU_RELRO (hardening)
        if (phdr.p_type == PT_GNU_RELRO) {
            result.has_relro = true;
        }

        // Only create segments for PT_LOAD (the actual memory mappings)
        if (phdr.p_type != PT_LOAD) continue;

        const seg_name = segmentName(phdr.p_flags);

        // Find sections that fall within this segment's virtual address range
        var sections = std.array_list.Managed(Section).init(allocator);
        for (result.sections_list.items) |sec| {
            if (sec.start >= @as(u64, phdr.p_vaddr) and sec.start < @as(u64, phdr.p_vaddr) + @as(u64, phdr.p_memsz)) {
                sections.append(sec) catch continue;
            }
        }

        result.segments.append(.{
            .name = seg_name,
            .start = @as(u64, phdr.p_vaddr),
            .length = @as(u64, phdr.p_memsz),
            .file_offset = @as(u64, phdr.p_offset),
            .file_size = @as(u64, phdr.p_filesz),
            .sections = sections.toOwnedSlice() catch &.{},
            .permissions = .{
                .read = (phdr.p_flags & PF_R) != 0,
                .write = (phdr.p_flags & PF_W) != 0,
                .execute = (phdr.p_flags & PF_X) != 0,
            },
        }) catch return;
    }
}

fn readSym32(data: []const u8, offset: usize) Elf32_Sym {
    return .{
        .st_name = readU32(data, offset),
        .st_value = readU32(data, offset + 4),
        .st_size = readU32(data, offset + 8),
        .st_info = data[offset + 12],
        .st_other = data[offset + 13],
        .st_shndx = readU16(data, offset + 14),
    };
}

fn parseSymbolTables32(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf32_Ehdr, result: *ParseResult) void {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = @as(u64, ehdr.e_shoff) + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf32_Shdr) > data.len) break;

        const shdr = readShdr32(data, @intCast(offset));

        if (shdr.sh_type == SHT_SYMTAB or shdr.sh_type == SHT_DYNSYM) {
            parseSymtab32(allocator, data, ehdr, &shdr, shdr.sh_type == SHT_DYNSYM, result);
        }
    }
}

fn parseSymtab32(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf32_Ehdr, symtab_shdr: *const Elf32_Shdr, is_dynamic: bool, result: *ParseResult) void {
    if (symtab_shdr.sh_entsize == 0) return;
    if (@as(u64, symtab_shdr.sh_offset) + @as(u64, symtab_shdr.sh_size) > data.len) return;

    // Get the associated string table (sh_link points to it)
    const strtab = getStringTable32(data, ehdr, symtab_shdr.sh_link) orelse return;

    const num_syms = symtab_shdr.sh_size / symtab_shdr.sh_entsize;
    var sym_idx: u32 = 0;
    while (sym_idx < num_syms) : (sym_idx += 1) {
        const sym_offset = @as(u64, symtab_shdr.sh_offset) + @as(u64, sym_idx) * @as(u64, symtab_shdr.sh_entsize);
        if (sym_offset + @sizeOf(Elf32_Sym) > data.len) break;

        const sym = readSym32(data, @intCast(sym_offset));

        // Get symbol name
        const name = getStringFromTable(strtab, sym.st_name);
        if (name.len == 0) continue;

        const sym_type = sym.st_info & 0x0f;
        const binding = sym.st_info >> 4;
        const is_undefined = sym.st_shndx == SHN_UNDEF;
        const is_func = sym_type == STT_FUNC;

        const entry = SymbolEntry{
            .name = name,
            .value = @as(u64, sym.st_value),
            .size = @as(u64, sym.st_size),
            .sym_type = sym_type,
            .binding = binding,
            .section_index = sym.st_shndx,
            .is_function = is_func,
            .is_undefined = is_undefined,
        };

        result.symbols.append(entry) catch return;

        // Undefined function symbols from .dynsym are imports
        if (is_dynamic and is_undefined and is_func and name.len > 0) {
            // If exactly one DT_NEEDED lib, assign it as the import's library
            const lib: ?[]const u8 = if (result.needed_libs.items.len == 1)
                result.needed_libs.items[0]
            else
                null;
            result.imports.append(.{
                .address = @as(u64, sym.st_value),
                .name = name,
                .library = lib,
            }) catch return;
        }

        _ = allocator;
    }
}

fn getStringTable32(data: []const u8, ehdr: *const Elf32_Ehdr, sh_link: u32) ?[]const u8 {
    if (sh_link == 0 or sh_link >= ehdr.e_shnum) return null;

    const offset = @as(u64, ehdr.e_shoff) + @as(u64, sh_link) * @as(u64, ehdr.e_shentsize);
    if (offset + @sizeOf(Elf32_Shdr) > data.len) return null;

    const strtab_shdr = readShdr32(data, @intCast(offset));
    if (strtab_shdr.sh_type != SHT_STRTAB) return null;
    if (@as(u64, strtab_shdr.sh_offset) + @as(u64, strtab_shdr.sh_size) > data.len) return null;

    return data[strtab_shdr.sh_offset .. strtab_shdr.sh_offset + strtab_shdr.sh_size];
}

fn readDyn32(data: []const u8, offset: usize) Elf32_Dyn {
    return .{
        .d_tag = @bitCast(readU32(data, offset)),
        .d_val = readU32(data, offset + 4),
    };
}

fn parseDynamicSection32(data: []const u8, ehdr: *const Elf32_Ehdr, result: *ParseResult) void {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    // Find .dynamic section
    var dyn_shdr: ?Elf32_Shdr = null;
    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = @as(u64, ehdr.e_shoff) + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf32_Shdr) > data.len) break;

        const shdr = readShdr32(data, @intCast(offset));
        if (shdr.sh_type == SHT_DYNAMIC) {
            dyn_shdr = shdr;
            break;
        }
    }

    const dynamic = dyn_shdr orelse return;
    if (@as(u64, dynamic.sh_offset) + @as(u64, dynamic.sh_size) > data.len) return;
    if (dynamic.sh_entsize == 0) return;

    // Get the string table linked to the dynamic section
    const dyn_strtab = getStringTable32(data, ehdr, dynamic.sh_link);

    // Parse dynamic entries
    const num_entries = dynamic.sh_size / dynamic.sh_entsize;
    var entry_idx: u32 = 0;
    while (entry_idx < num_entries) : (entry_idx += 1) {
        const entry_offset = @as(u64, dynamic.sh_offset) + @as(u64, entry_idx) * @as(u64, dynamic.sh_entsize);
        if (entry_offset + @sizeOf(Elf32_Dyn) > data.len) break;

        const dyn = readDyn32(data, @intCast(entry_offset));

        if (dyn.d_tag == @as(i32, 0)) break; // DT_NULL

        if (dyn.d_tag == @as(i32, 1)) { // DT_NEEDED
            if (dyn_strtab) |strtab| {
                const lib_name = getStringFromTable(strtab, dyn.d_val);
                if (lib_name.len > 0) {
                    result.needed_libs.append(lib_name) catch continue;
                }
            }
        }

        // Detect BIND_NOW for full RELRO
        if (dyn.d_tag == @as(i32, @truncate(DT_BIND_NOW))) {
            result.has_bind_now = true;
        }
        if (dyn.d_tag == @as(i32, @truncate(DT_FLAGS)) and (dyn.d_val & @as(u32, @truncate(DF_BIND_NOW))) != 0) {
            result.has_bind_now = true;
        }
    }
}

// ============================================================================
// PSP Import Stub Parsing
// ============================================================================

const PspSectionInfo = struct {
    addr: u64,
    offset: usize,
    size: usize,
};

/// Find an ELF32 section header by name, returning its virtual address, file offset, and size.
fn findSectionByName(data: []const u8, ehdr: *const Elf32_Ehdr, shstrtab: []const u8, target: []const u8) ?PspSectionInfo {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return null;

    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = @as(u64, ehdr.e_shoff) + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf32_Shdr) > data.len) break;

        const sh_name_idx = readU32(data, @intCast(offset));
        const name = getSectionName(shstrtab, sh_name_idx);

        if (std.mem.eql(u8, name, target)) {
            const sh_addr = readU32(data, @intCast(offset + 12));
            const sh_offset = readU32(data, @intCast(offset + 16));
            const sh_size = readU32(data, @intCast(offset + 20));
            return .{
                .addr = @as(u64, sh_addr),
                .offset = @as(usize, sh_offset),
                .size = @as(usize, sh_size),
            };
        }
    }
    return null;
}

/// Parse PSP import stubs from .lib.stub section.
/// PSP binaries use a custom import mechanism with 20-byte stub table entries
/// that reference NID arrays and stub code instead of standard .dynsym.
fn parsePspImports(allocator: std.mem.Allocator, data: []const u8, ehdr: *const Elf32_Ehdr, result: *ParseResult) void {
    _ = allocator;
    const shstrtab = getSectionStringTable32(data, ehdr) orelse return;

    // Find required sections
    const lib_stub = findSectionByName(data, ehdr, shstrtab, ".lib.stub") orelse return;
    const resident = findSectionByName(data, ehdr, shstrtab, ".rodata.sceResident");
    const nid_sec = findSectionByName(data, ehdr, shstrtab, ".rodata.sceNid");
    // .sceStub.text must exist for stub addresses to be valid
    _ = findSectionByName(data, ehdr, shstrtab, ".sceStub.text") orelse return;

    // .lib.stub entries are 20 bytes each
    if (lib_stub.size < 20) return;
    const entry_count = lib_stub.size / 20;

    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        const entry_off = lib_stub.offset + i * 20;
        if (entry_off + 20 > data.len) break;

        const name_ptr = @as(u64, readU32(data, entry_off));
        // Word at +8: lower u16 is entry size/4, upper u16 is func_count
        const func_count = readU16(data, entry_off + 10);
        const nid_table_ptr = @as(u64, readU32(data, entry_off + 12));
        const stub_table_ptr = @as(u64, readU32(data, entry_off + 16));

        if (func_count == 0) continue;

        // Read library name string by converting virtual address to file offset
        const lib_name = blk: {
            if (resident) |res| {
                if (name_ptr >= res.addr) {
                    const name_file_off = @as(usize, @intCast(name_ptr - res.addr)) + res.offset;
                    if (name_file_off < data.len) {
                        const start = data[name_file_off..];
                        const end = std.mem.indexOfScalar(u8, start, 0) orelse start.len;
                        if (end > 0) break :blk start[0..end];
                    }
                }
            }
            break :blk @as([]const u8, "unknown");
        };

        var j: u16 = 0;
        while (j < func_count) : (j += 1) {
            // Read NID value
            const nid: ?u32 = blk: {
                if (nid_sec) |ns| {
                    if (nid_table_ptr >= ns.addr) {
                        const nid_file_off = @as(usize, @intCast(nid_table_ptr - ns.addr)) + ns.offset + @as(usize, j) * 4;
                        if (nid_file_off + 4 <= data.len) {
                            break :blk readU32(data, nid_file_off);
                        }
                    }
                }
                break :blk null;
            };

            // Resolve NID to human-readable function name if possible
            const resolved_name = if (nid) |n| psp_nids.resolveNid(n) else null;
            const import_name = resolved_name orelse lib_name;

            // Compute stub address (virtual address, not file offset)
            const stub_addr: u64 = stub_table_ptr + @as(u64, j) * 8;

            result.imports.append(.{
                .address = stub_addr,
                .name = import_name,
                .library = lib_name,
                .ordinal = nid,
            }) catch return;
        }
    }
}

// ============================================================================
// PLT Stub → Import Resolution (v7.6.2)
// ============================================================================

/// Compute PLT entry sizes based on architecture.
/// Returns (header_size, entry_size).
fn pltEntrySizes(arch: Arch) struct { header: u64, entry: u64 } {
    return switch (arch) {
        .x86_64 => .{ .header = 16, .entry = 16 },
        .arm64 => .{ .header = 32, .entry = 16 },
        .arm32 => .{ .header = 20, .entry = 12 },
        .mips32 => .{ .header = 32, .entry = 16 },
        else => .{ .header = 16, .entry = 16 },
    };
}

/// Map PLT stub addresses to imports for ELF64 binaries.
/// Scans section headers for .rela.plt/.rel.plt and .plt, then for each
/// relocation entry resolves the symbol name via .dynsym and sets
/// the matching Import's stub_address.
fn mapElfPltImports64(data: []const u8, ehdr: *const Elf64_Ehdr, doc: *Document) void {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    // First pass: find .plt section and .rela.plt/.rel.plt section.
    // Also locate .dynsym and its linked string table for name resolution.
    var plt_addr: u64 = 0;
    var plt_found = false;
    var relplt_offset: u64 = 0;
    var relplt_size: u64 = 0;
    var relplt_entsize: u64 = 0;
    var relplt_type: u32 = 0; // SHT_RELA or SHT_REL
    var relplt_found = false;
    var dynsym_offset: u64 = 0;
    var dynsym_entsize: u64 = 0;
    var dynsym_size: u64 = 0;
    var dynsym_link: u32 = 0; // sh_link points to dynstr
    var dynsym_found = false;

    const shstrtab = getSectionStringTable(data, ehdr) orelse return;

    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = ehdr.e_shoff + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf64_Shdr) > data.len) break;

        const shdr = readShdr(data, @intCast(offset));
        const name = getSectionName(shstrtab, shdr.sh_name);

        if (std.mem.eql(u8, name, ".plt")) {
            plt_addr = shdr.sh_addr;
            plt_found = true;
        } else if (std.mem.eql(u8, name, ".rela.plt") or std.mem.eql(u8, name, ".rel.plt")) {
            relplt_offset = shdr.sh_offset;
            relplt_size = shdr.sh_size;
            relplt_entsize = shdr.sh_entsize;
            relplt_type = shdr.sh_type;
            relplt_found = true;
        } else if (shdr.sh_type == SHT_DYNSYM) {
            dynsym_offset = shdr.sh_offset;
            dynsym_entsize = shdr.sh_entsize;
            dynsym_size = shdr.sh_size;
            dynsym_link = shdr.sh_link;
            dynsym_found = true;
        }
    }

    if (!plt_found or !relplt_found or !dynsym_found) return;
    if (relplt_entsize == 0 or dynsym_entsize == 0) return;
    if (relplt_offset + relplt_size > data.len) return;
    if (dynsym_offset + dynsym_size > data.len) return;

    // Get the dynamic string table for symbol name lookups
    const dynstr = getStringTable(data, ehdr, dynsym_link) orelse return;

    const plt_sizes = pltEntrySizes(doc.arch);
    const is_rela = relplt_type == SHT_RELA;
    const entry_bytes: u64 = if (is_rela) 24 else 16; // Elf64_Rela=24, Elf64_Rel=16
    if (relplt_entsize < entry_bytes) return;

    const num_relocs = relplt_size / relplt_entsize;
    var entry_idx: u64 = 0;
    while (entry_idx < num_relocs) : (entry_idx += 1) {
        const rel_off = relplt_offset + entry_idx * relplt_entsize;
        if (rel_off + entry_bytes > data.len) break;

        // r_info is at offset 8 in both Elf64_Rel and Elf64_Rela
        const r_info = readU64(data, @intCast(rel_off + 8));
        const sym_idx = r_info >> 32;

        // Look up symbol name from .dynsym
        const sym_off = dynsym_offset + sym_idx * dynsym_entsize;
        if (sym_off + @sizeOf(Elf64_Sym) > data.len) continue;

        const st_name = readU32(data, @intCast(sym_off));
        const sym_name = getStringFromTable(dynstr, st_name);
        if (sym_name.len == 0) continue;

        // Compute PLT stub address for this entry
        const stub_addr = plt_addr + plt_sizes.header + entry_idx * plt_sizes.entry;

        // Find matching import and set stub_address
        for (doc.imports.items) |*imp| {
            if (std.mem.eql(u8, imp.name, sym_name)) {
                imp.stub_address = stub_addr;
                break;
            }
        }
    }
}

/// Map PLT stub addresses to imports for ELF32 binaries.
/// Same logic as mapElfPltImports64 but uses 32-bit section headers and relocation entries.
fn mapElfPltImports32(data: []const u8, ehdr: *const Elf32_Ehdr, doc: *Document) void {
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    var plt_addr: u64 = 0;
    var plt_found = false;
    var relplt_offset: u64 = 0;
    var relplt_size: u64 = 0;
    var relplt_entsize: u64 = 0;
    var relplt_type: u32 = 0;
    var relplt_found = false;
    var dynsym_offset: u64 = 0;
    var dynsym_entsize: u64 = 0;
    var dynsym_size: u64 = 0;
    var dynsym_link: u32 = 0;
    var dynsym_found = false;

    const shstrtab = getSectionStringTable32(data, ehdr) orelse return;

    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const offset = @as(u64, ehdr.e_shoff) + @as(u64, i) * @as(u64, ehdr.e_shentsize);
        if (offset + @sizeOf(Elf32_Shdr) > data.len) break;

        const shdr = readShdr32(data, @intCast(offset));
        const name = getSectionName(shstrtab, shdr.sh_name);

        if (std.mem.eql(u8, name, ".plt")) {
            plt_addr = @as(u64, shdr.sh_addr);
            plt_found = true;
        } else if (std.mem.eql(u8, name, ".rela.plt") or std.mem.eql(u8, name, ".rel.plt")) {
            relplt_offset = @as(u64, shdr.sh_offset);
            relplt_size = @as(u64, shdr.sh_size);
            relplt_entsize = @as(u64, shdr.sh_entsize);
            relplt_type = shdr.sh_type;
            relplt_found = true;
        } else if (shdr.sh_type == SHT_DYNSYM) {
            dynsym_offset = @as(u64, shdr.sh_offset);
            dynsym_entsize = @as(u64, shdr.sh_entsize);
            dynsym_size = @as(u64, shdr.sh_size);
            dynsym_link = shdr.sh_link;
            dynsym_found = true;
        }
    }

    if (!plt_found or !relplt_found or !dynsym_found) return;
    if (relplt_entsize == 0 or dynsym_entsize == 0) return;
    if (relplt_offset + relplt_size > data.len) return;
    if (dynsym_offset + dynsym_size > data.len) return;

    // Get the dynamic string table for symbol name lookups
    const dynstr = getStringTable32(data, ehdr, dynsym_link) orelse return;

    const plt_sizes = pltEntrySizes(doc.arch);
    const is_rela = relplt_type == SHT_RELA;
    const entry_bytes: u64 = if (is_rela) 12 else 8; // Elf32_Rela=12, Elf32_Rel=8
    if (relplt_entsize < entry_bytes) return;

    const num_relocs = relplt_size / relplt_entsize;
    var entry_idx: u64 = 0;
    while (entry_idx < num_relocs) : (entry_idx += 1) {
        const rel_off = relplt_offset + entry_idx * relplt_entsize;
        if (rel_off + entry_bytes > data.len) break;

        // r_info is at offset 4 in both Elf32_Rel and Elf32_Rela
        const r_info = readU32(data, @intCast(rel_off + 4));
        const sym_idx = @as(u64, r_info >> 8);

        // Look up symbol name from .dynsym
        const sym_off = dynsym_offset + sym_idx * dynsym_entsize;
        if (sym_off + @sizeOf(Elf32_Sym) > data.len) continue;

        const st_name = readU32(data, @intCast(sym_off));
        const sym_name = getStringFromTable(dynstr, st_name);
        if (sym_name.len == 0) continue;

        // Compute PLT stub address for this entry
        const stub_addr = plt_addr + plt_sizes.header + entry_idx * plt_sizes.entry;

        // Find matching import and set stub_address
        for (doc.imports.items) |*imp| {
            if (std.mem.eql(u8, imp.name, sym_name)) {
                imp.stub_address = stub_addr;
                break;
            }
        }
    }
}

// ============================================================================
// Byte reading helpers (little-endian)
// ============================================================================

fn readU16(data: []const u8, offset: usize) u16 {
    if (offset + 2 > data.len) return 0;
    return std.mem.readInt(u16, data[offset..][0..2], .little);
}

fn readU32(data: []const u8, offset: usize) u32 {
    if (offset + 4 > data.len) return 0;
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

fn readU64(data: []const u8, offset: usize) u64 {
    if (offset + 8 > data.len) return 0;
    return std.mem.readInt(u64, data[offset..][0..8], .little);
}

// ============================================================================
// Tests
// ============================================================================

test "isElf detects magic" {
    const valid: [4]u8 = .{ 0x7f, 'E', 'L', 'F' };
    try std.testing.expect(isElf(&valid));

    const invalid: [4]u8 = .{ 0x7f, 'X', 'L', 'F' };
    try std.testing.expect(!isElf(&invalid));

    const short: [2]u8 = .{ 0x7f, 'E' };
    try std.testing.expect(!isElf(&short));
}

test "readU16 readU32 readU64 little-endian" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    try std.testing.expectEqual(@as(u16, 0x0201), readU16(&data, 0));
    try std.testing.expectEqual(@as(u32, 0x04030201), readU32(&data, 0));
    try std.testing.expectEqual(@as(u64, 0x0807060504030201), readU64(&data, 0));
}

test "readU32 bounds check" {
    const data = [_]u8{ 0x01, 0x02 };
    try std.testing.expectEqual(@as(u32, 0), readU32(&data, 0));
    try std.testing.expectEqual(@as(u64, 0), readU64(&data, 0));
}

test "getStringFromTable" {
    const strtab = "\x00hello\x00world\x00";
    try std.testing.expectEqualStrings("hello", getStringFromTable(strtab, 1));
    try std.testing.expectEqualStrings("world", getStringFromTable(strtab, 7));
    try std.testing.expectEqualStrings("", getStringFromTable(strtab, 0));
    try std.testing.expectEqualStrings("", getStringFromTable(strtab, 100));
}

test "segmentName from flags" {
    try std.testing.expectEqualStrings("TEXT", segmentName(PF_R | PF_X));
    try std.testing.expectEqualStrings("DATA", segmentName(PF_R | PF_W));
    try std.testing.expectEqualStrings("RODATA", segmentName(PF_R));
    try std.testing.expectEqualStrings("RWX", segmentName(PF_R | PF_W | PF_X));
}

test "parse minimal ELF64 header" {
    const allocator = std.testing.allocator;

    // Construct a minimal valid ELF64 binary (just header, no program/section headers)
    var elf_data: [64]u8 = .{0} ** 64;
    // ELF magic
    elf_data[0] = 0x7f;
    elf_data[1] = 'E';
    elf_data[2] = 'L';
    elf_data[3] = 'F';
    elf_data[EI_CLASS] = ELFCLASS64; // 64-bit
    elf_data[EI_DATA] = ELFDATA2LSB; // Little-endian
    elf_data[EI_VERSION] = 1; // Current

    // e_type = ET_EXEC (2)
    std.mem.writeInt(u16, elf_data[16..18], ET_EXEC, .little);
    // e_machine = EM_X86_64 (62)
    std.mem.writeInt(u16, elf_data[18..20], EM_X86_64, .little);
    // e_version = 1
    std.mem.writeInt(u32, elf_data[20..24], 1, .little);
    // e_entry = 0x401000
    std.mem.writeInt(u64, elf_data[24..32], 0x401000, .little);
    // e_ehsize = 64
    std.mem.writeInt(u16, elf_data[52..54], 64, .little);

    var doc = try parse(allocator, 1, "/test/minimal", &elf_data, .{});
    defer doc.deinit();

    try std.testing.expectEqual(BinaryFormat.elf, doc.format);
    try std.testing.expectEqual(Arch.x86_64, doc.arch);
    try std.testing.expectEqual(@as(u64, 0x401000), doc.entry_point);
}

test "parse rejects non-ELF" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xCF, 0xFA, 0xED, 0xFE } ++ [_]u8{0} ** 60;
    const result = parse(allocator, 1, "/test/macho", &data, .{});
    try std.testing.expectError(ElfError.NotElf, result);
}

test "parse minimal ELF32 header" {
    const allocator = std.testing.allocator;

    // Construct a minimal valid ELF32 binary (just header, no program/section headers)
    var elf_data: [52]u8 = .{0} ** 52;
    // ELF magic
    elf_data[0] = 0x7f;
    elf_data[1] = 'E';
    elf_data[2] = 'L';
    elf_data[3] = 'F';
    elf_data[EI_CLASS] = ELFCLASS32; // 32-bit
    elf_data[EI_DATA] = ELFDATA2LSB; // Little-endian
    elf_data[EI_VERSION] = 1; // Current

    // e_type = ET_EXEC (2)
    std.mem.writeInt(u16, elf_data[16..18], ET_EXEC, .little);
    // e_machine = EM_386 (3)
    std.mem.writeInt(u16, elf_data[18..20], EM_386, .little);
    // e_version = 1
    std.mem.writeInt(u32, elf_data[20..24], 1, .little);
    // e_entry = 0x08048000
    std.mem.writeInt(u32, elf_data[24..28], 0x08048000, .little);
    // e_ehsize = 52
    std.mem.writeInt(u16, elf_data[40..42], 52, .little);

    var doc = try parse(allocator, 1, "/test/elf32", &elf_data, .{});
    defer doc.deinit();

    try std.testing.expectEqual(BinaryFormat.elf, doc.format);
    try std.testing.expectEqual(Arch.x86, doc.arch);
    try std.testing.expectEqual(@as(u64, 0x08048000), doc.entry_point);
}

test "parse rejects big-endian" {
    const allocator = std.testing.allocator;
    var data: [64]u8 = .{0} ** 64;
    data[0] = 0x7f;
    data[1] = 'E';
    data[2] = 'L';
    data[3] = 'F';
    data[EI_CLASS] = ELFCLASS64;
    data[EI_DATA] = ELFDATA2MSB;
    const result = parse(allocator, 1, "/test/be", &data, .{});
    try std.testing.expectError(ElfError.UnsupportedEndianness, result);
}
