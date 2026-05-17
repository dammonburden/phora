// Phora — PE Binary Parser
// Parses Windows PE32+ (64-bit) executables: DOS header, COFF header,
// optional header, section headers, import/export tables.

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

// ============================================================================
// PE Constants
// ============================================================================

// DOS header magic
const MZ_MAGIC: u16 = 0x5A4D; // "MZ" little-endian

// PE signature
const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0" little-endian

// Optional header magic
const PE32_MAGIC: u16 = 0x010B;
const PE32PLUS_MAGIC: u16 = 0x020B;

// Machine types
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;

// Section characteristics flags
const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

// Data directory indices
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;

// ============================================================================
// PE On-Disk Structures (extern structs to match binary layout)
// ============================================================================

const DosHeader = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: u32,
};

const CoffHeader = extern struct {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
};

const DataDirectory = extern struct {
    virtual_address: u32,
    size: u32,
};

const OptionalHeader64 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
};

const OptionalHeader32 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
};

const SectionHeader = extern struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
};

const ImportDescriptor = extern struct {
    original_first_thunk: u32, // RVA to ILT (Import Lookup Table)
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32, // RVA to DLL name
    first_thunk: u32, // RVA to IAT (Import Address Table)
};

const ExportDirectory = extern struct {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name_rva: u32,
    ordinal_base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32, // RVA to export address table
    address_of_names: u32, // RVA to name pointer table
    address_of_name_ordinals: u32, // RVA to ordinal table
};

// ============================================================================
// Error Types
// ============================================================================

pub const PeError = error{
    InvalidMagic,
    NotPE,
    TruncatedDosHeader,
    TruncatedPeSignature,
    TruncatedCoffHeader,
    TruncatedOptionalHeader,
    TruncatedSectionHeader,
    TruncatedImportTable,
    TruncatedExportTable,
    UnsupportedMachine,
    InvalidRva,
    OutOfMemory,
    Overflow,
};

// ============================================================================
// Parser State
// ============================================================================

const ParseResult = struct {
    arch: Arch,
    image_base: u64,
    entry_point_rva: u32,
    is_pe32plus: bool,
    sections: std.array_list.Managed(SectionInfo),
    imports: std.array_list.Managed(Import),
    exports: std.array_list.Managed(ExportEntry),
    data_directories: [16]DataDirectory,
    number_of_rva_and_sizes: u32,

    fn init(allocator: std.mem.Allocator) ParseResult {
        return .{
            .arch = .x86_64,
            .image_base = 0,
            .entry_point_rva = 0,
            .is_pe32plus = true,
            .sections = std.array_list.Managed(SectionInfo).init(allocator),
            .imports = std.array_list.Managed(Import).init(allocator),
            .exports = std.array_list.Managed(ExportEntry).init(allocator),
            .data_directories = std.mem.zeroes([16]DataDirectory),
            .number_of_rva_and_sizes = 0,
        };
    }

    fn deinit(self: *ParseResult) void {
        self.sections.deinit();
        self.imports.deinit();
        self.exports.deinit();
    }
};

const SectionInfo = struct {
    name: []const u8,
    virtual_address: u32,
    virtual_size: u32,
    raw_data_offset: u32,
    raw_data_size: u32,
    characteristics: u32,
};

const ExportEntry = struct {
    name: []const u8,
    address: u64,
    ordinal: u32,
};

// ============================================================================
// Public API
// ============================================================================

/// Parse a PE binary from raw file data.
/// Returns a populated Document with segments (from sections), imports, and
/// procedure stubs from exports.
pub fn parse(allocator: std.mem.Allocator, doc_id: u64, path: []const u8, data: []const u8, options: LoadOptions) PeError!Document {
    _ = options;

    if (data.len < @sizeOf(DosHeader)) return PeError.TruncatedDosHeader;

    // Validate DOS header
    const dos = readStruct(DosHeader, data, 0);
    if (dos.e_magic != MZ_MAGIC) return PeError.InvalidMagic;

    // Locate PE header
    const pe_offset: usize = dos.e_lfanew;
    if (pe_offset + 4 > data.len) return PeError.TruncatedPeSignature;

    // Validate PE signature
    const pe_sig = readStruct(u32, data, pe_offset);
    if (pe_sig != PE_SIGNATURE) return PeError.NotPE;

    // Parse COFF header
    const coff_offset = pe_offset + 4;
    if (coff_offset + @sizeOf(CoffHeader) > data.len) return PeError.TruncatedCoffHeader;
    const coff = readStruct(CoffHeader, data, coff_offset);

    var result = ParseResult.init(allocator);
    errdefer result.deinit();

    result.arch = machineToArch(coff.machine) orelse return PeError.UnsupportedMachine;

    // Parse optional header
    const opt_offset = coff_offset + @sizeOf(CoffHeader);
    if (opt_offset + 2 > data.len) return PeError.TruncatedOptionalHeader;
    const opt_magic = readStruct(u16, data, opt_offset);

    if (opt_magic == PE32PLUS_MAGIC) {
        if (opt_offset + @sizeOf(OptionalHeader64) > data.len) return PeError.TruncatedOptionalHeader;
        const opt = readStruct(OptionalHeader64, data, opt_offset);
        result.is_pe32plus = true;
        result.image_base = opt.image_base;
        result.entry_point_rva = opt.address_of_entry_point;
        result.number_of_rva_and_sizes = opt.number_of_rva_and_sizes;

        // Read data directories
        const dd_offset = opt_offset + @sizeOf(OptionalHeader64);
        const dd_count = @min(opt.number_of_rva_and_sizes, 16);
        var i: usize = 0;
        while (i < dd_count) : (i += 1) {
            const ddo = dd_offset + i * @sizeOf(DataDirectory);
            if (ddo + @sizeOf(DataDirectory) > data.len) break;
            result.data_directories[i] = readStruct(DataDirectory, data, ddo);
        }
    } else if (opt_magic == PE32_MAGIC) {
        if (opt_offset + @sizeOf(OptionalHeader32) > data.len) return PeError.TruncatedOptionalHeader;
        const opt = readStruct(OptionalHeader32, data, opt_offset);
        result.is_pe32plus = false;
        result.image_base = opt.image_base;
        result.entry_point_rva = opt.address_of_entry_point;
        result.number_of_rva_and_sizes = opt.number_of_rva_and_sizes;

        // Read data directories
        const dd_offset = opt_offset + @sizeOf(OptionalHeader32);
        const dd_count = @min(opt.number_of_rva_and_sizes, 16);
        var i: usize = 0;
        while (i < dd_count) : (i += 1) {
            const ddo = dd_offset + i * @sizeOf(DataDirectory);
            if (ddo + @sizeOf(DataDirectory) > data.len) break;
            result.data_directories[i] = readStruct(DataDirectory, data, ddo);
        }
    } else {
        return PeError.TruncatedOptionalHeader;
    }

    // Parse section headers
    const sections_offset = opt_offset + coff.size_of_optional_header;
    try parseSections(data, sections_offset, coff.number_of_sections, &result);

    // Parse import table
    parseImports(allocator, data, &result) catch {};

    // Parse export table
    parseExports(allocator, data, &result) catch {};

    // Build the Document
    var doc = Document.init(allocator, doc_id, path, data);
    doc.format = .pe;
    doc.arch = result.arch;
    doc.entry_point = result.image_base + result.entry_point_rva;

    // Convert sections to segments (PE sections map to Phora segments)
    var segments = std.array_list.Managed(Segment).init(allocator);
    errdefer segments.deinit();

    for (result.sections.items) |sect| {
        // Each PE section becomes a segment with a single section inside
        var inner_sections = std.array_list.Managed(Section).init(allocator);
        errdefer inner_sections.deinit();

        inner_sections.append(.{
            .name = sect.name,
            .start = result.image_base + sect.virtual_address,
            .length = sect.virtual_size,
            .file_offset = sect.raw_data_offset,
        }) catch return PeError.OutOfMemory;

        segments.append(.{
            .name = sect.name,
            .start = result.image_base + sect.virtual_address,
            .length = sect.virtual_size,
            .sections = inner_sections.toOwnedSlice() catch return PeError.OutOfMemory,
            .permissions = characteristicsToPermissions(sect.characteristics),
            .file_offset = sect.raw_data_offset,
            .file_size = sect.raw_data_size,
        }) catch return PeError.OutOfMemory;
    }

    doc.segments = segments.toOwnedSlice() catch return PeError.OutOfMemory;

    // Copy imports
    for (result.imports.items) |imp| {
        doc.imports.append(imp) catch return PeError.OutOfMemory;
    }

    // Create procedure stubs from exports
    for (result.exports.items) |exp| {
        doc.procedures.append(.{
            .entry = exp.address,
            .size = 0,
            .name = exp.name,
        }) catch return PeError.OutOfMemory;
    }

    // Free intermediate result arrays
    result.sections.deinit();
    result.imports.deinit();
    result.exports.deinit();

    return doc;
}

/// Returns true if the data begins with "MZ" (DOS header magic).
pub fn isPe(data: []const u8) bool {
    if (data.len < 2) return false;
    return std.mem.readInt(u16, data[0..2], .little) == MZ_MAGIC;
}

// ============================================================================
// Section Parsing
// ============================================================================

fn parseSections(data: []const u8, offset: usize, count: u16, result: *ParseResult) PeError!void {
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const sect_offset = offset + @as(usize, i) * @sizeOf(SectionHeader);
        if (sect_offset + @sizeOf(SectionHeader) > data.len) return PeError.TruncatedSectionHeader;

        const sh = readStruct(SectionHeader, data, sect_offset);

        // Read name directly from data buffer to avoid dangling stack pointer
        const name = readSectionName(data, sect_offset);

        result.sections.append(.{
            .name = name,
            .virtual_address = sh.virtual_address,
            .virtual_size = sh.virtual_size,
            .raw_data_offset = sh.pointer_to_raw_data,
            .raw_data_size = sh.size_of_raw_data,
            .characteristics = sh.characteristics,
        }) catch return PeError.OutOfMemory;
    }
}

// ============================================================================
// Import Table Parsing
// ============================================================================

fn parseImports(allocator: std.mem.Allocator, data: []const u8, result: *ParseResult) PeError!void {
    if (result.number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return;

    const import_dd = result.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dd.virtual_address == 0 or import_dd.size == 0) return;

    const import_offset = rvaToFileOffset(import_dd.virtual_address, result) orelse return;

    // Walk import descriptors (null-terminated array)
    var desc_offset = import_offset;
    while (desc_offset + @sizeOf(ImportDescriptor) <= data.len) {
        const desc = readStruct(ImportDescriptor, data, desc_offset);

        // Null terminator: all fields zero
        if (desc.original_first_thunk == 0 and desc.first_thunk == 0) break;

        // Get DLL name
        const dll_name_offset = rvaToFileOffset(desc.name_rva, result) orelse {
            desc_offset += @sizeOf(ImportDescriptor);
            continue;
        };
        const dll_name = readNullTermString(data, dll_name_offset);

        // Walk the Import Lookup Table (ILT) or fall back to IAT
        const ilt_rva = if (desc.original_first_thunk != 0) desc.original_first_thunk else desc.first_thunk;
        const ilt_offset = rvaToFileOffset(ilt_rva, result) orelse {
            desc_offset += @sizeOf(ImportDescriptor);
            continue;
        };

        // Walk ILT entries
        var ilt_entry_offset = ilt_offset;
        var iat_rva = desc.first_thunk;

        if (result.is_pe32plus) {
            // 64-bit: ILT entries are 8 bytes
            while (ilt_entry_offset + 8 <= data.len) {
                const entry = std.mem.readInt(u64, data[ilt_entry_offset..][0..8], .little);
                if (entry == 0) break;

                const is_ordinal = (entry & (1 << 63)) != 0;
                if (!is_ordinal) {
                    // Hint/Name table RVA (bits 30:0)
                    const hint_rva: u32 = @truncate(entry & 0x7FFFFFFF);
                    const hint_offset = rvaToFileOffset(hint_rva, result);
                    if (hint_offset) |ho| {
                        // Skip 2-byte hint, read name
                        if (ho + 2 < data.len) {
                            const func_name = readNullTermString(data, ho + 2);
                            if (func_name.len > 0) {
                                result.imports.append(.{
                                    .address = result.image_base + iat_rva,
                                    .name = func_name,
                                    .library = dll_name,
                                }) catch return PeError.OutOfMemory;
                            }
                        }
                    }
                } else {
                    // Import by ordinal
                    const ordinal: u16 = @truncate(entry & 0xFFFF);
                    _ = ordinal;
                    _ = allocator;
                    // We skip ordinal-only imports since they have no name
                }

                ilt_entry_offset += 8;
                iat_rva += 8;
            }
        } else {
            // 32-bit: ILT entries are 4 bytes
            while (ilt_entry_offset + 4 <= data.len) {
                const entry = std.mem.readInt(u32, data[ilt_entry_offset..][0..4], .little);
                if (entry == 0) break;

                const is_ordinal = (entry & (1 << 31)) != 0;
                if (!is_ordinal) {
                    const hint_rva: u32 = entry & 0x7FFFFFFF;
                    const hint_offset = rvaToFileOffset(hint_rva, result);
                    if (hint_offset) |ho| {
                        if (ho + 2 < data.len) {
                            const func_name = readNullTermString(data, ho + 2);
                            if (func_name.len > 0) {
                                result.imports.append(.{
                                    .address = result.image_base + iat_rva,
                                    .name = func_name,
                                    .library = dll_name,
                                }) catch return PeError.OutOfMemory;
                            }
                        }
                    }
                }

                ilt_entry_offset += 4;
                iat_rva += 4;
            }
        }

        desc_offset += @sizeOf(ImportDescriptor);
    }
}

// ============================================================================
// Export Table Parsing
// ============================================================================

fn parseExports(_: std.mem.Allocator, data: []const u8, result: *ParseResult) PeError!void {
    if (result.number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return;

    const export_dd = result.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dd.virtual_address == 0 or export_dd.size == 0) return;

    const export_offset = rvaToFileOffset(export_dd.virtual_address, result) orelse return;
    if (export_offset + @sizeOf(ExportDirectory) > data.len) return;

    const exp_dir = readStruct(ExportDirectory, data, export_offset);
    const num_names = exp_dir.number_of_names;
    if (num_names == 0) return;

    // Get arrays
    const names_offset = rvaToFileOffset(exp_dir.address_of_names, result) orelse return;
    const ordinals_offset = rvaToFileOffset(exp_dir.address_of_name_ordinals, result) orelse return;
    const functions_offset = rvaToFileOffset(exp_dir.address_of_functions, result) orelse return;

    var i: u32 = 0;
    while (i < num_names) : (i += 1) {
        // Read name RVA from name pointer table
        const name_rva_offset = names_offset + @as(usize, i) * 4;
        if (name_rva_offset + 4 > data.len) break;
        const name_rva = std.mem.readInt(u32, data[name_rva_offset..][0..4], .little);

        // Read ordinal
        const ord_offset = ordinals_offset + @as(usize, i) * 2;
        if (ord_offset + 2 > data.len) break;
        const ordinal_index = std.mem.readInt(u16, data[ord_offset..][0..2], .little);

        // Read function RVA from export address table
        const func_rva_offset = functions_offset + @as(usize, ordinal_index) * 4;
        if (func_rva_offset + 4 > data.len) break;
        const func_rva = std.mem.readInt(u32, data[func_rva_offset..][0..4], .little);

        // Resolve name
        const name_offset = rvaToFileOffset(name_rva, result) orelse continue;
        const func_name = readNullTermString(data, name_offset);
        if (func_name.len == 0) continue;

        // Check for forwarder (function RVA points within export directory)
        const is_forwarder = func_rva >= export_dd.virtual_address and
            func_rva < export_dd.virtual_address + export_dd.size;
        if (is_forwarder) continue;

        result.exports.append(.{
            .name = func_name,
            .address = result.image_base + func_rva,
            .ordinal = exp_dir.ordinal_base + ordinal_index,
        }) catch return PeError.OutOfMemory;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

fn readStruct(comptime T: type, data: []const u8, offset: usize) T {
    const bytes = data[offset..][0..@sizeOf(T)];
    return std.mem.bytesAsValue(T, bytes).*;
}

/// Convert an RVA (Relative Virtual Address) to a file offset using the section table.
fn rvaToFileOffset(rva: u32, result: *const ParseResult) ?usize {
    for (result.sections.items) |sect| {
        if (rva >= sect.virtual_address and rva < sect.virtual_address + @max(sect.virtual_size, sect.raw_data_size)) {
            const offset_in_section = rva - sect.virtual_address;
            return sect.raw_data_offset + offset_in_section;
        }
    }
    return null;
}

/// Read a null-terminated string from the data buffer.
fn readNullTermString(data: []const u8, offset: usize) []const u8 {
    if (offset >= data.len) return "";
    const start = data[offset..];
    var len: usize = 0;
    while (len < start.len and start[len] != 0) : (len += 1) {}
    return start[0..len];
}

/// Read section name from data buffer (8 bytes, null-padded).
fn readSectionName(data: []const u8, offset: usize) []const u8 {
    if (offset + 8 > data.len) return "";
    const raw = data[offset..][0..8];
    var end: usize = 8;
    while (end > 0 and raw[end - 1] == 0) : (end -= 1) {}
    return raw[0..end];
}

fn machineToArch(machine: u16) ?Arch {
    return switch (machine) {
        IMAGE_FILE_MACHINE_AMD64 => .x86_64,
        IMAGE_FILE_MACHINE_ARM64 => .arm64,
        IMAGE_FILE_MACHINE_I386 => .x86,
        IMAGE_FILE_MACHINE_ARMNT => .arm32,
        else => null,
    };
}

fn characteristicsToPermissions(chars: u32) SegmentPermissions {
    return .{
        .read = (chars & IMAGE_SCN_MEM_READ) != 0,
        .write = (chars & IMAGE_SCN_MEM_WRITE) != 0,
        .execute = (chars & IMAGE_SCN_MEM_EXECUTE) != 0,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "isPe detects MZ magic" {
    const valid = [_]u8{ 'M', 'Z', 0x90, 0x00 };
    try std.testing.expect(isPe(&valid));

    const invalid = [_]u8{ 0x7F, 'E', 'L', 'F' }; // ELF
    try std.testing.expect(!isPe(&invalid));

    const too_short = [_]u8{'M'};
    try std.testing.expect(!isPe(&too_short));
}

test "readSectionName" {
    const name = [_]u8{ '.', 't', 'e', 'x', 't', 0, 0, 0, 0xFF, 0xFF };
    try std.testing.expectEqualStrings(".text", readSectionName(&name, 0));

    const full = [_]u8{ '.', 'r', 'e', 'l', 'o', 'c', 0, 0 };
    try std.testing.expectEqualStrings(".reloc", readSectionName(&full, 0));
}

test "readNullTermString" {
    const data = "kernel32.dll\x00user32.dll\x00";
    try std.testing.expectEqualStrings("kernel32.dll", readNullTermString(data, 0));
    try std.testing.expectEqualStrings("user32.dll", readNullTermString(data, 13));
    try std.testing.expectEqualStrings("", readNullTermString(data, 100));
}

test "machineToArch" {
    try std.testing.expectEqual(Arch.x86_64, machineToArch(IMAGE_FILE_MACHINE_AMD64).?);
    try std.testing.expectEqual(Arch.arm64, machineToArch(IMAGE_FILE_MACHINE_ARM64).?);
    try std.testing.expectEqual(Arch.x86, machineToArch(IMAGE_FILE_MACHINE_I386).?);
    try std.testing.expectEqual(Arch.arm32, machineToArch(IMAGE_FILE_MACHINE_ARMNT).?);
    try std.testing.expectEqual(@as(?Arch, null), machineToArch(0x1234));
}

test "characteristicsToPermissions" {
    const rx = characteristicsToPermissions(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
    try std.testing.expect(rx.read);
    try std.testing.expect(!rx.write);
    try std.testing.expect(rx.execute);

    const rw = characteristicsToPermissions(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    try std.testing.expect(rw.read);
    try std.testing.expect(rw.write);
    try std.testing.expect(!rw.execute);
}

test "parse rejects truncated data" {
    const short = [_]u8{ 'M', 'Z' };
    const err = parse(std.testing.allocator, 1, "/test.exe", &short, .{});
    try std.testing.expectError(PeError.TruncatedDosHeader, err);
}

test "parse rejects non-MZ magic" {
    var bad_data: [64]u8 = undefined;
    @memset(&bad_data, 0);
    bad_data[0] = 0x7F;
    bad_data[1] = 'E';
    const err = parse(std.testing.allocator, 1, "/test.exe", &bad_data, .{});
    try std.testing.expectError(PeError.InvalidMagic, err);
}

test "parse minimal PE64 header" {
    // Build a minimal valid PE64 binary in memory
    const allocator = std.testing.allocator;
    _ = allocator;

    var pe_data: [512]u8 = undefined;
    @memset(&pe_data, 0);

    // DOS header
    pe_data[0] = 'M';
    pe_data[1] = 'Z';
    // e_lfanew at offset 0x3C = 64 (point to PE signature)
    std.mem.writeInt(u32, pe_data[0x3C..0x40], 64, .little);

    // PE signature at offset 64
    std.mem.writeInt(u32, pe_data[64..68], PE_SIGNATURE, .little);

    // COFF header at offset 68
    std.mem.writeInt(u16, pe_data[68..70], IMAGE_FILE_MACHINE_AMD64, .little); // machine
    std.mem.writeInt(u16, pe_data[70..72], 1, .little); // number_of_sections
    std.mem.writeInt(u16, pe_data[84..86], @sizeOf(OptionalHeader64) + 2 * @sizeOf(DataDirectory), .little); // size_of_optional_header

    // Optional header at offset 88
    const opt_off: usize = 88;
    std.mem.writeInt(u16, pe_data[opt_off..][0..2], PE32PLUS_MAGIC, .little); // magic
    std.mem.writeInt(u32, pe_data[opt_off + 16 ..][0..4], 0x1000, .little); // address_of_entry_point
    std.mem.writeInt(u64, pe_data[opt_off + 24 ..][0..8], 0x140000000, .little); // image_base
    std.mem.writeInt(u32, pe_data[opt_off + 108 ..][0..4], 2, .little); // number_of_rva_and_sizes

    // Section header after optional header + data directories
    const sect_off = opt_off + @sizeOf(OptionalHeader64) + 2 * @sizeOf(DataDirectory);
    pe_data[sect_off] = '.';
    pe_data[sect_off + 1] = 't';
    pe_data[sect_off + 2] = 'e';
    pe_data[sect_off + 3] = 'x';
    pe_data[sect_off + 4] = 't';
    std.mem.writeInt(u32, pe_data[sect_off + 8 ..][0..4], 0x100, .little); // virtual_size
    std.mem.writeInt(u32, pe_data[sect_off + 12 ..][0..4], 0x1000, .little); // virtual_address
    std.mem.writeInt(u32, pe_data[sect_off + 16 ..][0..4], 0x200, .little); // size_of_raw_data
    std.mem.writeInt(u32, pe_data[sect_off + 20 ..][0..4], 0x200, .little); // pointer_to_raw_data
    std.mem.writeInt(u32, pe_data[sect_off + 36 ..][0..4], IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE, .little);

    var doc = try parse(std.testing.allocator, 1, "/test.exe", &pe_data, .{});
    defer {
        for (doc.segments) |seg| {
            std.testing.allocator.free(seg.sections);
        }
        std.testing.allocator.free(doc.segments);
        doc.deinit();
    }

    try std.testing.expectEqual(BinaryFormat.pe, doc.format);
    try std.testing.expectEqual(Arch.x86_64, doc.arch);
    try std.testing.expectEqual(@as(u64, 0x140001000), doc.entry_point);
    try std.testing.expectEqual(@as(usize, 1), doc.segments.len);
    try std.testing.expectEqualStrings(".text", doc.segments[0].name);
    try std.testing.expect(doc.segments[0].permissions.read);
    try std.testing.expect(doc.segments[0].permissions.execute);
    try std.testing.expect(!doc.segments[0].permissions.write);
}
