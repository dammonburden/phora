// Phora — Mach-O Binary Parser
// Parses Mach-O binaries: headers, load commands, segments, sections, symbols.
// Handles FAT/Universal binaries with architecture slice selection.

const std = @import("std");
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
// Mach-O Constants
// ============================================================================

// Magic numbers
const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;
const MH_MAGIC: u32 = 0xFEEDFACE;
const MH_CIGAM: u32 = 0xCEFAEDFE;
const FAT_MAGIC: u32 = 0xCAFEBABE;
const FAT_CIGAM: u32 = 0xBEBAFECA;
const FAT_MAGIC_64: u32 = 0xCAFEBABF;
const FAT_CIGAM_64: u32 = 0xBFBAFECA;

// CPU types
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM64: u32 = 0x0100000C;

// CPU subtypes
const CPU_SUBTYPE_ALL: u32 = 0x00000003;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0x00000000;
const CPU_SUBTYPE_ARM64E: u32 = 0x00000002;

// File types
const MH_OBJECT: u32 = 0x1;
const MH_EXECUTE: u32 = 0x2;
const MH_DYLIB: u32 = 0x6;
const MH_DYLINKER: u32 = 0x7;
const MH_BUNDLE: u32 = 0x8;
const MH_DSYM: u32 = 0xA;

// Header flags
const MH_PIE: u32 = 0x00200000;

// Load command types
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0B;
const LC_LOAD_DYLIB: u32 = 0x0C;
const LC_ID_DYLIB: u32 = 0x0D;
const LC_LOAD_WEAK_DYLIB: u32 = 0x80000018;
const LC_REEXPORT_DYLIB: u32 = 0x8000001F;
const LC_MAIN: u32 = 0x80000028;
const LC_UUID: u32 = 0x1B;
const LC_FUNCTION_STARTS: u32 = 0x26;

// Segment VM protection flags
const VM_PROT_READ: u32 = 0x01;
const VM_PROT_WRITE: u32 = 0x02;
const VM_PROT_EXECUTE: u32 = 0x04;

// Symbol table n_type masks
const N_STAB: u8 = 0xE0;
const N_PEXT: u8 = 0x10;
const N_TYPE: u8 = 0x0E;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x00;
const N_ABS: u8 = 0x02;
const N_SECT: u8 = 0x0E;
const N_INDR: u8 = 0x0A;

// ============================================================================
// Mach-O On-Disk Structures (packed to match binary layout)
// ============================================================================

const MachHeader64 = extern struct {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
};

const LoadCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
};

const SegmentCommand64 = extern struct {
    cmd: u32,
    cmdsize: u32,
    segname: [16]u8,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
    flags: u32,
};

const SectionHeader64 = extern struct {
    sectname: [16]u8,
    segname: [16]u8,
    addr: u64,
    size: u64,
    offset: u32,
    @"align": u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
};

const SymtabCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
};

const DysymtabCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    ilocalsym: u32,
    nlocalsym: u32,
    iextdefsym: u32,
    nextdefsym: u32,
    iundefsym: u32,
    nundefsym: u32,
    tocoff: u32,
    ntoc: u32,
    modtaboff: u32,
    nmodtab: u32,
    extrefsymoff: u32,
    nextrefsyms: u32,
    indirectsymoff: u32,
    nindirectsyms: u32,
    extreloff: u32,
    nextrel: u32,
    locreloff: u32,
    nlocrel: u32,
};

const EntryPointCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    entryoff: u64,
    stacksize: u64,
};

const DylibCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    name_offset: u32,
    timestamp: u32,
    current_version: u32,
    compat_version: u32,
};

const Nlist64 = extern struct {
    n_strx: u32,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
};

const FatHeader = extern struct {
    magic: u32,
    nfat_arch: u32,
};

const FatArch = extern struct {
    cputype: u32,
    cpusubtype: u32,
    offset: u32,
    size: u32,
    @"align": u32,
};

const FatArch64 = extern struct {
    cputype: u32,
    cpusubtype: u32,
    offset: u64,
    size: u64,
    @"align": u32,
    reserved: u32,
};

// ============================================================================
// Error Types
// ============================================================================

pub const MachoError = error{
    InvalidMagic,
    TruncatedHeader,
    TruncatedLoadCommand,
    TruncatedSegment,
    TruncatedSection,
    TruncatedSymtab,
    TruncatedStringTable,
    TruncatedFatHeader,
    InvalidLoadCommand,
    UnsupportedCpuType,
    ArchNotFoundInFat,
    InvalidSymbolIndex,
    OutOfMemory,
    Overflow,
};

// ============================================================================
// Parser State
// ============================================================================

/// Intermediate result from parsing a single Mach-O slice.
const ParseResult = struct {
    arch: Arch,
    entry_point: u64,
    text_vmaddr: u64,
    segments: std.array_list.Managed(Segment),
    symbols: std.array_list.Managed(SymbolEntry),
    imports: std.array_list.Managed(Import),
    dylibs: std.array_list.Managed([]const u8),
    func_starts: std.array_list.Managed(u64),
    // Hardening tracking (v7.5.2)
    nlocalsym: u32 = 0,
    has_dysymtab: bool = false,
    // Indirect symbol table for stub→import mapping
    indirectsymoff: u32 = 0,
    nindirectsyms: u32 = 0,

    fn init(allocator: std.mem.Allocator) ParseResult {
        return .{
            .arch = .arm64,
            .entry_point = 0,
            .text_vmaddr = 0,
            .segments = std.array_list.Managed(Segment).init(allocator),
            .symbols = std.array_list.Managed(SymbolEntry).init(allocator),
            .imports = std.array_list.Managed(Import).init(allocator),
            .dylibs = std.array_list.Managed([]const u8).init(allocator),
            .func_starts = std.array_list.Managed(u64).init(allocator),
        };
    }

    fn deinit(self: *ParseResult) void {
        self.segments.deinit();
        self.symbols.deinit();
        self.imports.deinit();
        self.dylibs.deinit();
        self.func_starts.deinit();
    }
};

/// Internal symbol representation before mapping to Procedure/Import.
const SymbolEntry = struct {
    name: []const u8,
    address: u64,
    section: u8,
    symbol_type: u8,
    is_external: bool,
    is_undefined: bool,
    library_ordinal: u8 = 0, // from GET_LIBRARY_ORDINAL(n_desc)
};

// ============================================================================
// Public API
// ============================================================================

/// Parse a Mach-O binary (or FAT/Universal) from raw file data.
/// Returns a populated Document with segments, sections, imports, and
/// procedure stubs derived from the symbol table.
pub fn parse(allocator: std.mem.Allocator, doc_id: u64, path: []const u8, data: []const u8, options: LoadOptions) MachoError!Document {
    if (data.len < 4) return MachoError.TruncatedHeader;

    const magic = readU32(data, 0);

    // Check for FAT/Universal binary
    if (magic == FAT_MAGIC or magic == FAT_CIGAM or
        magic == FAT_MAGIC_64 or magic == FAT_CIGAM_64)
    {
        return parseFat(allocator, doc_id, path, data, options);
    }

    // Single-architecture Mach-O
    return parseMacho(allocator, doc_id, path, data, 0, data.len, options);
}

/// Returns true if the data begins with a Mach-O or FAT magic number.
pub fn isMacho(data: []const u8) bool {
    if (data.len < 4) return false;
    const magic = readU32(data, 0);
    return magic == MH_MAGIC_64 or magic == MH_CIGAM_64 or
        magic == MH_MAGIC or magic == MH_CIGAM or
        magic == FAT_MAGIC or magic == FAT_CIGAM or
        magic == FAT_MAGIC_64 or magic == FAT_CIGAM_64;
}

// ============================================================================
// FAT/Universal Binary Handling
// ============================================================================

fn parseFat(allocator: std.mem.Allocator, doc_id: u64, path: []const u8, data: []const u8, options: LoadOptions) MachoError!Document {
    if (data.len < @sizeOf(FatHeader)) return MachoError.TruncatedFatHeader;

    const magic = readU32(data, 0);
    const needs_swap = (magic == FAT_CIGAM or magic == FAT_CIGAM_64);
    const is_fat64 = (magic == FAT_MAGIC_64 or magic == FAT_CIGAM_64);

    const nfat_arch_raw = readU32(data, 4);
    const nfat_arch = if (needs_swap) @byteSwap(nfat_arch_raw) else nfat_arch_raw;

    // Determine which architecture the caller wants. Default arm64.
    const desired_cpu = archToCpuType(options.fat_arch orelse options.arch orelse .arm64);

    // v7.4.2 F5: walk all slices once, recording (cputype, offset, size) tuples.
    // Then pick a slice in priority order: exact desired match → any 64-bit
    // slice → fail. The previous logic just took slice[0] as a fallback, which
    // chose unsupported 32-bit slices in mixed-architecture vendor binaries —
    // yielding "failed to parse Mach-O" because parseMacho
    // only supports 64-bit headers.
    const SliceInfo = struct {
        cputype: u32,
        offset: usize,
        size: usize,
    };
    var slices: [16]SliceInfo = undefined;
    var slice_count: usize = 0;

    var offset: usize = @sizeOf(FatHeader);
    var i: u32 = 0;
    while (i < nfat_arch and slice_count < slices.len) : (i += 1) {
        if (is_fat64) {
            if (offset + @sizeOf(FatArch64) > data.len) return MachoError.TruncatedFatHeader;
            const fa = readStruct(FatArch64, data, offset);
            slices[slice_count] = .{
                .cputype = if (needs_swap) @byteSwap(fa.cputype) else fa.cputype,
                .offset = @intCast(if (needs_swap) @byteSwap(fa.offset) else fa.offset),
                .size = @intCast(if (needs_swap) @byteSwap(fa.size) else fa.size),
            };
            slice_count += 1;
            offset += @sizeOf(FatArch64);
        } else {
            if (offset + @sizeOf(FatArch) > data.len) return MachoError.TruncatedFatHeader;
            const fa = readStruct(FatArch, data, offset);
            slices[slice_count] = .{
                .cputype = if (needs_swap) @byteSwap(fa.cputype) else fa.cputype,
                .offset = @intCast(if (needs_swap) @byteSwap(fa.offset) else fa.offset),
                .size = @intCast(if (needs_swap) @byteSwap(fa.size) else fa.size),
            };
            slice_count += 1;
            offset += @sizeOf(FatArch);
        }
    }

    // Pass 1: exact desired arch match.
    for (slices[0..slice_count]) |slc| {
        if (slc.cputype == desired_cpu) {
            return parseMacho(allocator, doc_id, path, data, slc.offset, slc.size, options);
        }
    }

    // Pass 2: any 64-bit slice. The Mach-O CPU_ARCH_ABI64 bit is 0x01000000;
    // any cputype with that bit set is a 64-bit architecture (x86_64, arm64,
    // arm64e, etc.). Prefer arm64 then x86_64 then any 64-bit.
    const ABI64: u32 = 0x01000000;
    // Preferred order: arm64 → x86_64 → any other 64-bit.
    inline for ([_]u32{ CPU_TYPE_ARM64, CPU_TYPE_X86_64 }) |preferred| {
        for (slices[0..slice_count]) |slc| {
            if (slc.cputype == preferred) {
                return parseMacho(allocator, doc_id, path, data, slc.offset, slc.size, options);
            }
        }
    }
    for (slices[0..slice_count]) |slc| {
        if ((slc.cputype & ABI64) != 0) {
            return parseMacho(allocator, doc_id, path, data, slc.offset, slc.size, options);
        }
    }

    // No 64-bit slice in this fat binary — only 32-bit (i386, arm32, etc.)
    // which Phora doesn't support yet (parseMacho is 64-bit only). Return a
    // distinct error so the caller can give the user an actionable message.
    return MachoError.UnsupportedCpuType;
}

// ============================================================================
// Single-Architecture Mach-O Parsing
// ============================================================================

fn parseMacho(
    allocator: std.mem.Allocator,
    doc_id: u64,
    path: []const u8,
    data: []const u8,
    slice_offset: usize,
    slice_size: usize,
    options: LoadOptions,
) MachoError!Document {
    _ = options;
    const slice_end = slice_offset + slice_size;
    if (slice_end > data.len) return MachoError.TruncatedHeader;
    if (slice_size < @sizeOf(MachHeader64)) return MachoError.TruncatedHeader;

    const header = readStruct(MachHeader64, data, slice_offset);

    // Validate magic — we only support 64-bit
    const needs_swap = (header.magic == MH_CIGAM_64);
    if (header.magic != MH_MAGIC_64 and header.magic != MH_CIGAM_64) {
        return MachoError.InvalidMagic;
    }

    const cputype = maybeSwap32(header.cputype, needs_swap);
    const ncmds = maybeSwap32(header.ncmds, needs_swap);
    const sizeofcmds = maybeSwap32(header.sizeofcmds, needs_swap);

    const arch = cpuTypeToArch(cputype) orelse return MachoError.UnsupportedCpuType;

    var result = ParseResult.init(allocator);
    errdefer result.deinit();
    result.arch = arch;

    // Walk load commands
    var cmd_offset = slice_offset + @sizeOf(MachHeader64);
    const cmds_end = cmd_offset + sizeofcmds;
    if (cmds_end > slice_end) return MachoError.TruncatedLoadCommand;

    var cmd_index: u32 = 0;
    while (cmd_index < ncmds) : (cmd_index += 1) {
        if (cmd_offset + @sizeOf(LoadCommand) > cmds_end) break;
        const lc = readStruct(LoadCommand, data, cmd_offset);
        const cmd = maybeSwap32(lc.cmd, needs_swap);
        const cmdsize = maybeSwap32(lc.cmdsize, needs_swap);

        if (cmdsize < @sizeOf(LoadCommand)) return MachoError.InvalidLoadCommand;
        if (cmd_offset + cmdsize > cmds_end) return MachoError.TruncatedLoadCommand;

        switch (cmd) {
            LC_SEGMENT_64 => try parseSegment64(allocator, data, cmd_offset, slice_offset, needs_swap, &result),
            LC_SYMTAB => try parseSymtab(allocator, data, cmd_offset, slice_offset, slice_end, needs_swap, &result),
            LC_MAIN => parseEntryPoint(data, cmd_offset, needs_swap, &result),
            LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_ID_DYLIB => parseDylib(allocator, data, cmd_offset, cmdsize, needs_swap, &result),
            LC_DYSYMTAB => parseDysymtab(data, cmd_offset, needs_swap, &result),
            LC_FUNCTION_STARTS => try parseFunctionStarts(allocator, data, cmd_offset, slice_offset, slice_end, needs_swap, &result),
            else => {},
        }

        cmd_offset += cmdsize;
    }

    // Resolve undefined symbols as imports
    try resolveImports(allocator, &result);

    // Build the Document
    var doc = Document.init(allocator, doc_id, path, data);
    doc.format = .macho;
    doc.arch = result.arch;
    doc.entry_point = result.entry_point;
    doc.segments = result.segments.toOwnedSlice() catch return MachoError.OutOfMemory;

    // Hardening fields
    const flags = maybeSwap32(header.flags, needs_swap);
    // v7.12.1 W3: MH_PIE flag is meaningful only on MH_EXECUTE; for MH_DYLIB /
    // MH_BUNDLE shared images are inherently position-independent, so the flag
    // bit is undefined. Reporting pie:false on a dylib is misleading.
    const filetype = maybeSwap32(header.filetype, needs_swap);
    doc.macho_filetype = filetype;
    if (filetype == MH_EXECUTE) {
        doc.is_pie = (flags & MH_PIE) != 0;
    } else if (filetype == MH_DYLIB or filetype == MH_BUNDLE) {
        doc.is_pie = true; // structural — shared images must be PI
    } else {
        doc.is_pie = false; // MH_OBJECT etc.
    }
    // ARM64e CPU subtype indicates Pointer Authentication (PAC) support
    const cpu_subtype = maybeSwap32(header.cpusubtype, needs_swap) & 0xFF;
    doc.has_pac = (cpu_subtype == CPU_SUBTYPE_ARM64E);
    // Stripped if dysymtab present and nlocalsym == 0 (all symbols are external/undefined)
    doc.is_stripped = result.has_dysymtab and result.nlocalsym == 0;
    // Mach-O doesn't have RELRO — leave defaults (false)

    // Create procedure stubs from defined symbols
    for (result.symbols.items) |sym| {
        if (!sym.is_undefined and sym.section != 0 and sym.address != 0) {
            doc.procedures.append(.{
                .entry = sym.address,
                .size = 0, // Size will be determined by the analysis engine
                .name = sym.name,
            }) catch return MachoError.OutOfMemory;
        }
    }

    // Add LC_FUNCTION_STARTS entries as procedures (linker ground truth).
    // Use a HashSet for O(1) dedup instead of linear scan.
    {
        var proc_set = std.AutoHashMap(u64, void).init(allocator);
        defer proc_set.deinit();
        for (doc.procedures.items) |p| {
            proc_set.put(p.entry, {}) catch {};
        }
        for (result.func_starts.items) |addr| {
            if (!proc_set.contains(addr)) {
                proc_set.put(addr, {}) catch {};
                doc.procedures.append(.{
                    .entry = addr,
                    .size = 0,
                    .name = null,
                }) catch return MachoError.OutOfMemory;
            }
        }
    }

    // Compute procedure sizes by sorting and using next-procedure boundaries.
    // LC_FUNCTION_STARTS and symbol procedures are added with size=0; fix that here.
    {
        const procs = doc.procedures.items;
        if (procs.len > 1) {
            // Sort procedures by entry address
            std.mem.sort(types.Procedure, procs, {}, struct {
                fn lessThan(_: void, a: types.Procedure, b: types.Procedure) bool {
                    return a.entry < b.entry;
                }
            }.lessThan);

            // Set size = next.entry - this.entry for each procedure (only if size is 0)
            for (procs[0 .. procs.len - 1], 0..) |*p, idx| {
                if (p.size == 0) {
                    p.size = procs[idx + 1].entry - p.entry;
                }
            }
            // Last procedure: use a reasonable default size of 64 bytes
            if (procs[procs.len - 1].size == 0) {
                procs[procs.len - 1].size = 64;
            }
        } else if (procs.len == 1) {
            if (procs[0].size == 0) {
                procs[0].size = 64;
            }
        }
    }

    // Copy imports
    for (result.imports.items) |imp| {
        doc.imports.append(imp) catch return MachoError.OutOfMemory;
    }

    // Map stub addresses to imports via the indirect symbol table.
    // Each __auth_stubs/__stubs section has reserved1 = starting index into
    // the indirect symbol table. Each entry is a 4-byte symtab index.
    if (result.has_dysymtab and result.indirectsymoff > 0 and result.nindirectsyms > 0) {
        const isym_off: usize = slice_offset + result.indirectsymoff;
        const isym_count: usize = result.nindirectsyms;

        for (doc.segments) |seg| {
            if (!seg.permissions.execute) continue;
            for (seg.sections) |sec| {
                const is_stubs = std.mem.eql(u8, sec.name, "__auth_stubs") or
                    std.mem.eql(u8, sec.name, "__stubs");
                if (!is_stubs) continue;

                // reserved1 is in the raw section header. We need to read it from the binary.
                // Find the section header for this section by scanning segments.
                const stub_size: u64 = if (std.mem.eql(u8, sec.name, "__auth_stubs")) 16 else 12;
                const n_stubs = sec.length / stub_size;

                // Look up reserved1 from raw data by finding the section header
                const reserved1 = findSectionReserved1(data[slice_offset..slice_end], sec.name, seg.name) orelse continue;

                var stub_idx: usize = 0;
                while (stub_idx < n_stubs) : (stub_idx += 1) {
                    const isym_idx = reserved1 + stub_idx;
                    if (isym_idx >= isym_count) break;
                    const entry_off = isym_off + isym_idx * 4;
                    if (entry_off + 4 > data.len) break;

                    const sym_idx = std.mem.readInt(u32, data[entry_off..][0..4], .little);
                    // Match this symtab index to an import by finding the symbol name
                    if (sym_idx < result.symbols.items.len) {
                        const sym_name = result.symbols.items[sym_idx].name;
                        const stub_addr = sec.start + stub_idx * stub_size;
                        // Find matching import and set its stub_address
                        for (doc.imports.items) |*imp| {
                            if (std.mem.eql(u8, imp.name, sym_name)) {
                                imp.stub_address = stub_addr;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Free intermediate ParseResult arrays (segments was consumed via toOwnedSlice)
    result.symbols.deinit();
    result.imports.deinit();
    result.dylibs.deinit();
    result.func_starts.deinit();

    return doc;
}

// ============================================================================
// Load Command Parsers
// ============================================================================

fn parseSegment64(
    allocator: std.mem.Allocator,
    data: []const u8,
    offset: usize,
    slice_offset: usize,
    needs_swap: bool,
    result: *ParseResult,
) MachoError!void {
    if (offset + @sizeOf(SegmentCommand64) > data.len) return MachoError.TruncatedSegment;

    const seg = readStruct(SegmentCommand64, data, offset);
    const vmaddr = maybeSwap64(seg.vmaddr, needs_swap);
    const vmsize = maybeSwap64(seg.vmsize, needs_swap);
    const fileoff = slice_offset + maybeSwap64(seg.fileoff, needs_swap);
    const filesize = maybeSwap64(seg.filesize, needs_swap);
    const nsects = maybeSwap32(seg.nsects, needs_swap);
    const initprot = maybeSwap32(seg.initprot, needs_swap);
    // Read segment name directly from data buffer to avoid dangling stack pointer
    const segname = readName(data, offset + 8, 16);

    // Track __TEXT vmaddr for LC_MAIN entry point resolution
    if (std.mem.eql(u8, segname, "__TEXT")) {
        result.text_vmaddr = vmaddr;
    }

    // Parse sections within this segment
    var sections = std.array_list.Managed(Section).init(allocator);
    errdefer sections.deinit();

    var sect_offset = offset + @sizeOf(SegmentCommand64);
    var sect_index: u32 = 0;
    while (sect_index < nsects) : (sect_index += 1) {
        if (sect_offset + @sizeOf(SectionHeader64) > data.len) return MachoError.TruncatedSection;

        const sh = readStruct(SectionHeader64, data, sect_offset);
        // Section type is low 8 bits of flags. Zerofill types have no file backing.
        const sh_flags = maybeSwap32(sh.flags, needs_swap);
        const sh_type = sh_flags & 0xFF;
        const is_zf = sh_type == 0x1 // S_ZEROFILL (__bss, __common)
        or sh_type == 0xC // S_GB_ZEROFILL
        or sh_type == 0x11; // S_THREAD_LOCAL_ZEROFILL
        const sect = Section{
            .name = readName(data, sect_offset, 16), // sectname at offset 0 within section header
            .start = maybeSwap64(sh.addr, needs_swap),
            .length = maybeSwap64(sh.size, needs_swap),
            .file_offset = slice_offset + maybeSwap32(sh.offset, needs_swap),
            .alignment = maybeSwap32(sh.@"align", needs_swap),
            .is_zerofill = is_zf,
        };
        sections.append(sect) catch return MachoError.OutOfMemory;
        sect_offset += @sizeOf(SectionHeader64);
    }

    const segment = Segment{
        .name = segname,
        .start = vmaddr,
        .length = vmsize,
        .sections = sections.toOwnedSlice() catch return MachoError.OutOfMemory,
        .permissions = vmProtToPermissions(initprot),
        .file_offset = fileoff,
        .file_size = filesize,
    };
    result.segments.append(segment) catch return MachoError.OutOfMemory;
}

fn parseSymtab(
    _: std.mem.Allocator,
    data: []const u8,
    offset: usize,
    slice_offset: usize,
    _: usize,
    needs_swap: bool,
    result: *ParseResult,
) MachoError!void {
    if (offset + @sizeOf(SymtabCommand) > data.len) return MachoError.TruncatedSymtab;

    const symtab = readStruct(SymtabCommand, data, offset);
    const symoff = maybeSwap32(symtab.symoff, needs_swap);
    const nsyms = maybeSwap32(symtab.nsyms, needs_swap);
    const stroff = maybeSwap32(symtab.stroff, needs_swap);
    const strsize = maybeSwap32(symtab.strsize, needs_swap);

    // symoff/stroff are relative to the start of the Mach-O slice, not the FAT file
    const sym_start: usize = slice_offset + symoff;
    const str_start: usize = slice_offset + stroff;
    const str_end: usize = str_start + strsize;

    if (str_end > data.len) return MachoError.TruncatedStringTable;

    const strtab = data[str_start..str_end];

    var i: u32 = 0;
    while (i < nsyms) : (i += 1) {
        const nlist_offset = sym_start + @as(usize, i) * @sizeOf(Nlist64);
        if (nlist_offset + @sizeOf(Nlist64) > data.len) break;

        const nlist = readStruct(Nlist64, data, nlist_offset);
        const n_strx = maybeSwap32(nlist.n_strx, needs_swap);
        const n_type = nlist.n_type;
        const n_sect = nlist.n_sect;
        const n_desc = maybeSwap16(nlist.n_desc, needs_swap);
        const n_value = maybeSwap64(nlist.n_value, needs_swap);

        // Skip stab debug symbols
        if (n_type & N_STAB != 0) continue;

        // Lookup name in string table
        const name = getStringFromTable(strtab, n_strx);
        if (name.len == 0) continue;

        const type_field = n_type & N_TYPE;
        const is_external = (n_type & N_EXT) != 0;
        const is_undefined = (type_field == N_UNDF);

        const entry = SymbolEntry{
            .name = name,
            .address = n_value,
            .section = n_sect,
            .symbol_type = type_field,
            .is_external = is_external,
            .is_undefined = is_undefined,
            .library_ordinal = @intCast((n_desc >> 8) & 0xFF),
        };
        result.symbols.append(entry) catch return MachoError.OutOfMemory;
    }
}

fn parseEntryPoint(data: []const u8, offset: usize, needs_swap: bool, result: *ParseResult) void {
    if (offset + @sizeOf(EntryPointCommand) > data.len) return;

    const ep = readStruct(EntryPointCommand, data, offset);
    const entryoff = maybeSwap64(ep.entryoff, needs_swap);

    // LC_MAIN specifies offset from __TEXT segment start
    result.entry_point = result.text_vmaddr + entryoff;
}

fn parseDylib(
    _: std.mem.Allocator,
    data: []const u8,
    offset: usize,
    cmdsize: u32,
    needs_swap: bool,
    result: *ParseResult,
) void {
    if (offset + @sizeOf(DylibCommand) > data.len) return;

    const dylib = readStruct(DylibCommand, data, offset);
    const name_offset = maybeSwap32(dylib.name_offset, needs_swap);

    const name_start = offset + name_offset;
    const cmd_end = offset + cmdsize;
    if (name_start >= cmd_end or name_start >= data.len) return;

    const max_end = @min(cmd_end, data.len);
    const name_bytes = data[name_start..max_end];

    // Find null terminator
    var name_len: usize = 0;
    while (name_len < name_bytes.len and name_bytes[name_len] != 0) : (name_len += 1) {}

    if (name_len > 0) {
        result.dylibs.append(name_bytes[0..name_len]) catch return;
    }
}

fn parseDysymtab(data: []const u8, offset: usize, needs_swap: bool, result: *ParseResult) void {
    // We store dysymtab info for future use by the analysis engine.
    // The key fields (iundefsym, nundefsym) help identify which symbols are imports.
    if (offset + @sizeOf(DysymtabCommand) > data.len) return;
    const dysym = readStruct(DysymtabCommand, data, offset);
    result.nlocalsym = maybeSwap32(dysym.nlocalsym, needs_swap);
    result.indirectsymoff = maybeSwap32(dysym.indirectsymoff, needs_swap);
    result.nindirectsyms = maybeSwap32(dysym.nindirectsyms, needs_swap);
    result.has_dysymtab = true;
}

/// Parse LC_FUNCTION_STARTS — the linker's definitive list of function entry points.
/// This is the most accurate function detection possible: the compiler/linker knows
/// Find the reserved1 field of a section header by scanning raw Mach-O load commands.
/// reserved1 is the indirect symbol table starting index for stub/GOT sections.
fn findSectionReserved1(data: []const u8, sect_name: []const u8, seg_name: []const u8) ?usize {
    if (data.len < 32) return null;
    const ncmds = std.mem.readInt(u32, data[16..20], .little);
    var cmd_offset: usize = if (std.mem.readInt(u32, data[0..4], .little) == 0xFEEDFACF) 32 else 28;

    var cmd_idx: usize = 0;
    while (cmd_idx < ncmds and cmd_offset + 8 <= data.len) : (cmd_idx += 1) {
        const cmd = std.mem.readInt(u32, data[cmd_offset..][0..4], .little);
        const cmdsize = std.mem.readInt(u32, data[cmd_offset + 4 ..][0..4], .little);
        if (cmdsize < 8) break;

        // LC_SEGMENT_64 = 0x19
        if (cmd == 0x19 and cmd_offset + 72 <= data.len) {
            const nsects = std.mem.readInt(u32, data[cmd_offset + 64 ..][0..4], .little);
            var sect_off = cmd_offset + 72; // after segment_command_64 header
            var s: usize = 0;
            while (s < nsects and sect_off + @sizeOf(SectionHeader64) <= data.len) : (s += 1) {
                const s_name = trimNullBytes(data[sect_off .. sect_off + 16]);
                const s_seg = trimNullBytes(data[sect_off + 16 .. sect_off + 32]);
                if (std.mem.eql(u8, s_name, sect_name) and std.mem.eql(u8, s_seg, seg_name)) {
                    // reserved1 is at offset 60 within Section64
                    const r1 = std.mem.readInt(u32, data[sect_off + 60 ..][0..4], .little);
                    return @intCast(r1);
                }
                sect_off += @sizeOf(SectionHeader64);
            }
        }
        cmd_offset += cmdsize;
    }
    return null;
}

/// exactly where every function starts. ULEB128-encoded deltas from __text vmaddr.
fn parseFunctionStarts(
    _: std.mem.Allocator,
    data: []const u8,
    offset: usize,
    slice_offset: usize,
    slice_end: usize,
    needs_swap: bool,
    result: *ParseResult,
) !void {
    _ = needs_swap;
    if (offset + 16 > data.len) return;

    const dataoff = std.mem.readInt(u32, data[offset + 8 ..][0..4], .little);
    const datasize = std.mem.readInt(u32, data[offset + 12 ..][0..4], .little);

    // Adjust for FAT binary slice offset
    const abs_off = if (dataoff >= slice_offset and dataoff < slice_end)
        dataoff
    else
        dataoff + @as(u32, @intCast(slice_offset));

    if (abs_off + datasize > data.len) return;
    const fs_data = data[abs_off .. abs_off + datasize];

    // First function is at text_vmaddr (added by caller or entry point)
    var addr = result.text_vmaddr;

    var i: usize = 0;
    while (i < fs_data.len) {
        // Read ULEB128 delta
        var delta: u64 = 0;
        var shift: u6 = 0;
        while (i < fs_data.len) {
            const byte = fs_data[i];
            i += 1;
            delta |= @as(u64, byte & 0x7F) << shift;
            if (shift < 63) {
                shift += 7;
            }
            if (byte < 0x80) break;
        }
        if (delta == 0) break;
        addr += delta;
        result.func_starts.append(addr) catch {};
    }
}

// ============================================================================
// Import Resolution
// ============================================================================

fn resolveImports(_: std.mem.Allocator, result: *ParseResult) MachoError!void {
    for (result.symbols.items) |sym| {
        if (sym.is_undefined and sym.is_external) {
            // Use two-level namespace ordinal to find the correct library.
            // Ordinal 0 = self, ordinal N = dylibs[N-1].
            const library: ?[]const u8 = if (sym.library_ordinal > 0 and sym.library_ordinal <= result.dylibs.items.len)
                result.dylibs.items[sym.library_ordinal - 1]
            else if (result.dylibs.items.len > 0)
                result.dylibs.items[0] // fallback for ordinal 0 or out-of-range
            else
                null;

            result.imports.append(.{
                .address = sym.address,
                .name = sym.name,
                .library = library,
            }) catch return MachoError.OutOfMemory;
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

fn readU32(data: []const u8, offset: usize) u32 {
    if (offset + 4 > data.len) return 0;
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

fn readStruct(comptime T: type, data: []const u8, offset: usize) T {
    const bytes = data[offset..][0..@sizeOf(T)];
    return std.mem.bytesAsValue(T, bytes).*;
}

fn maybeSwap16(val: u16, swap: bool) u16 {
    return if (swap) @byteSwap(val) else val;
}

fn maybeSwap32(val: u32, swap: bool) u32 {
    return if (swap) @byteSwap(val) else val;
}

fn maybeSwap64(val: u64, swap: bool) u64 {
    return if (swap) @byteSwap(val) else val;
}

fn trimNullBytes(name: []const u8) []const u8 {
    var end: usize = name.len;
    while (end > 0 and name[end - 1] == 0) : (end -= 1) {}
    return name[0..end];
}

/// Read a fixed-size name field directly from the data buffer (avoids dangling stack pointer).
fn readName(data: []const u8, offset: usize, comptime len: usize) []const u8 {
    if (offset + len > data.len) return "";
    return trimNullBytes(data[offset..][0..len]);
}

fn getStringFromTable(strtab: []const u8, index: u32) []const u8 {
    const idx: usize = index;
    if (idx >= strtab.len) return "";
    const start = strtab[idx..];
    var len: usize = 0;
    while (len < start.len and start[len] != 0) : (len += 1) {}
    return start[0..len];
}

fn vmProtToPermissions(prot: u32) SegmentPermissions {
    return .{
        .read = (prot & VM_PROT_READ) != 0,
        .write = (prot & VM_PROT_WRITE) != 0,
        .execute = (prot & VM_PROT_EXECUTE) != 0,
    };
}

fn cpuTypeToArch(cputype: u32) ?Arch {
    return switch (cputype) {
        CPU_TYPE_ARM64 => .arm64,
        CPU_TYPE_X86_64 => .x86_64,
        else => null,
    };
}

fn archToCpuType(arch: Arch) u32 {
    return switch (arch) {
        .arm64 => CPU_TYPE_ARM64,
        .x86_64 => CPU_TYPE_X86_64,
        .arm32, .x86, .mips32 => CPU_TYPE_X86_64, // ELF-only archs — fallback
    };
}

// ============================================================================
// Tests
// ============================================================================

test "isMacho detects magic numbers" {
    const valid_64 = [_]u8{ 0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0 };
    try std.testing.expect(isMacho(&valid_64));

    const valid_fat = [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0 };
    try std.testing.expect(isMacho(&valid_fat));

    const invalid = [_]u8{ 0x7F, 0x45, 0x4C, 0x46 }; // ELF
    try std.testing.expect(!isMacho(&invalid));

    const too_short = [_]u8{ 0xCF, 0xFA };
    try std.testing.expect(!isMacho(&too_short));
}

test "trimNullBytes" {
    const name = [_]u8{ '_', '_', 'T', 'E', 'X', 'T', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const trimmed = trimNullBytes(&name);
    try std.testing.expectEqualStrings("__TEXT", trimmed);
}

test "getStringFromTable" {
    const strtab = "\x00_main\x00_printf\x00";
    try std.testing.expectEqualStrings("_main", getStringFromTable(strtab, 1));
    try std.testing.expectEqualStrings("_printf", getStringFromTable(strtab, 7));
    try std.testing.expectEqualStrings("", getStringFromTable(strtab, 0));
    try std.testing.expectEqualStrings("", getStringFromTable(strtab, 100));
}

test "vmProtToPermissions" {
    const rwx = vmProtToPermissions(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    try std.testing.expect(rwx.read);
    try std.testing.expect(rwx.write);
    try std.testing.expect(rwx.execute);

    const rx = vmProtToPermissions(VM_PROT_READ | VM_PROT_EXECUTE);
    try std.testing.expect(rx.read);
    try std.testing.expect(!rx.write);
    try std.testing.expect(rx.execute);

    const none = vmProtToPermissions(0);
    try std.testing.expect(!none.read);
    try std.testing.expect(!none.write);
    try std.testing.expect(!none.execute);
}

test "cpuTypeToArch" {
    try std.testing.expectEqual(Arch.arm64, cpuTypeToArch(CPU_TYPE_ARM64).?);
    try std.testing.expectEqual(Arch.x86_64, cpuTypeToArch(CPU_TYPE_X86_64).?);
    try std.testing.expectEqual(@as(?Arch, null), cpuTypeToArch(0x12345));
}

test "parse rejects truncated data" {
    const short = [_]u8{ 0xCF, 0xFA };
    const err = parse(std.testing.allocator, 1, "/test", &short, .{});
    try std.testing.expectError(MachoError.TruncatedHeader, err);
}

test "parse rejects invalid magic" {
    // 32 bytes of zeros — enough for a header but wrong magic
    var bad_data: [32]u8 = undefined;
    @memset(&bad_data, 0);
    const err = parse(std.testing.allocator, 1, "/test", &bad_data, .{});
    try std.testing.expectError(MachoError.InvalidMagic, err);
}

test "parse /bin/ls (real Mach-O)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const file = std.Io.Dir.openFileAbsolute(io, "/bin/ls", .{}) catch |err| {
        // Skip test if /bin/ls is not available
        std.debug.print("Skipping /bin/ls test: {s}\n", .{@errorName(err)});
        return;
    };
    defer file.close(io);

    var file_reader = file.reader(io, &.{});
    const data = file_reader.interface.allocRemaining(allocator, .limited(10 * 1024 * 1024)) catch return;
    defer allocator.free(data);

    var doc = try parse(allocator, 1, "/bin/ls", data, .{});
    defer {
        // Free owned slices from segments
        for (doc.segments) |seg| {
            allocator.free(seg.sections);
        }
        allocator.free(doc.segments);
        doc.deinit();
    }

    // Verify basic properties
    try std.testing.expectEqual(BinaryFormat.macho, doc.format);
    try std.testing.expect(doc.arch == .arm64 or doc.arch == .x86_64);
    try std.testing.expect(doc.entry_point != 0);

    // Must have segments
    try std.testing.expect(doc.segments.len > 0);

    // Should have __TEXT segment
    var found_text = false;
    for (doc.segments) |seg| {
        if (std.mem.eql(u8, seg.name, "__TEXT")) {
            found_text = true;
            try std.testing.expect(seg.permissions.read);
            try std.testing.expect(seg.permissions.execute);
            // __TEXT should have sections
            try std.testing.expect(seg.sections.len > 0);
            break;
        }
    }
    try std.testing.expect(found_text);

    // Should have __DATA or __DATA_CONST segment
    var found_data = false;
    for (doc.segments) |seg| {
        if (std.mem.eql(u8, seg.name, "__DATA") or
            std.mem.eql(u8, seg.name, "__DATA_CONST"))
        {
            found_data = true;
            break;
        }
    }
    try std.testing.expect(found_data);

    // Should have imports (undefined external symbols) — /bin/ls is stripped
    // so it has many undefined symbols but few defined ones
    try std.testing.expect(doc.imports.items.len > 0);
}
