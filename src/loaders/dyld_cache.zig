// Phora — dyld_shared_cache image extractor (v7.13.0 B8 + v7.14.0 B1)
//
// Recent system releases may ship no standalone framework bodies — every
// `/System/Library/Frameworks/X.framework/Versions/A/X` lives only inside the
// `dyld_shared_cache_arm64e` blob. Without this loader Phora cannot analyze
// any system framework on affected systems.
//
// Strategy (v7.14.0 packed-extraction rewrite):
//   1) `loadImage(allocator, image_name)` opens the canonical cache path and
//      parses just enough of the header to find the named image.
//   2) For the named image, we walk LC_SEGMENT_64 commands and collect each
//      segment's (orig_vmaddr, orig_fileoff_in_cache, vmsize, filesize).
//      __LINKEDIT and __PAGEZERO are handled separately (LINKEDIT is shared
//      across all dyld-cache images and lives in its own mapping region).
//   3) We allocate a packed output buffer and copy each segment's bytes
//      contiguously, tracking new file offsets.
//   4) We REWRITE every LC_SEGMENT_64 command to make `vmaddr` image-local
//      (chosen base 0x100000000 for __TEXT) and `fileoff` match the new
//      packed layout. Every embedded SectionHeader64 also gets `addr` and
//      `offset` rewritten the same way.
//   5) We REWRITE every LC_SYMTAB / LC_DYSYMTAB / LC_FUNCTION_STARTS /
//      LC_DATA_IN_CODE offset to point into our new packed __LINKEDIT (we
//      pack the relevant LINKEDIT bytes contiguously as the last segment).
//   6) The resulting buffer is handed to `macho.parse` exactly like a
//      regular file.
//
// Trade-off (v7.14.0): LC_DYLD_CHAINED_FIXUPS / LC_DYLD_EXPORTS_TRIE point
// into the original cache. We rewrite the offsets if the data lives in
// LINKEDIT and we packed it; otherwise we zero out the count so downstream
// parsers skip the chunk gracefully. Decompile still works for code; data
// references that depend on chained-fixup binding may show as raw cache
// addresses. macOS 14+ chained-fixups full handling is a v7.15+ item.
//
// Limits:
//   - Only macOS 14+ format (`dyld_v1` magic).
//   - Subcaches (split cache files .01, .02, ...) are NOT followed for image
//     bytes that span files — those segments are skipped (zero-filled in
//     output) but the load proceeds. Most small/medium frameworks fit in
//     the main cache.

const std = @import("std");
pub const DyldCacheError = error{
    UnknownCachePath,
    UnsupportedMagic,
    TruncatedHeader,
    ImagesTableNotFound,
    ImageNotFound,
    ImageSpansSubcaches,
    Truncated,
    OutOfMemory,
    OpenFailed,
    ReadFailed,
};

/// Result of extracting a named image from the dyld shared cache.
/// `data` is owned by the caller and must be freed via `allocator.free`.
pub const ExtractedImage = struct {
    /// Synthesized path: `dyld_shared_cache:<image_name>`. Caller may pass
    /// this through to the document for round-trip identification.
    path: []const u8,
    /// Mach-O bytes of the extracted image (caller-owned).
    data: []u8,
};

// ----------------------------------------------------------------------------
// Cache header / table structures.
// We read header fields by absolute byte offset (mappingOffset @0x10 / 0x14;
// imagesOffsetOld @0x18 / 0x1C; modern imagesOffset @0x1C0 / 0x1C4 verified
// empirically against current cache files) instead of mirroring the
// full external struct, because the tail of the header has grown across OS
// versions and field ordering between iOS releases is brittle.
// ----------------------------------------------------------------------------

const CacheImageInfo = extern struct {
    address: u64, // image's virtual address inside the cache
    modTime: u64,
    inode: u64,
    pathFileOffset: u32,
    pad: u32,
};

const CacheMappingInfo = extern struct {
    address: u64,
    size: u64,
    fileOffset: u64,
    maxProt: u32,
    initProt: u32,
};

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

/// Default cache paths for current system-cache layouts.
const CACHE_PATHS = [_][]const u8{
    "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
    "/System/Library/dyld/dyld_shared_cache_arm64e",
};

// Mach-O load command constants (subset we need for rewriting).
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0B;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x80000033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x80000034;

/// Internal: per-segment info collected during the size pass.
const SegInfo = struct {
    name: [16]u8,
    lc_offset: usize, // byte offset of this LC_SEGMENT_64 inside the load commands
    cmdsize: u32,
    orig_vmaddr: u64,
    orig_fileoff: u64,
    vmsize: u64,
    filesize: u64,
    new_vmaddr: u64,
    new_fileoff: u64,
    new_filesize: u64,
    nsects: u32,
    is_pagezero: bool,
    is_linkedit: bool,
};

/// Internal: a LINKEDIT chunk we copy into our packed __LINKEDIT segment.
/// Each chunk records its old-cache file offset, its size, and the new
/// in-image file offset that the rewritten load command will point at.
const LinkChunk = struct {
    /// Source file offset in the cache (pre-rewrite).
    src_fileoff: u64,
    /// Length in bytes.
    len: u64,
    /// New file offset in the packed image (set after layout).
    new_fileoff: u64 = 0,
    /// Pointer to the u32 field inside lc_buf that holds the offset to be
    /// rewritten. Null = no rewrite (e.g. chunk dropped because it spans
    /// subcache).
    field_lc_offset: usize,
    /// True when the field couldn't be resolved → zero out the count too.
    drop: bool = false,
    /// When `drop` is true and the count field is non-null, we zero it.
    count_field_lc_offset: ?usize = null,
};

/// Hard cap on individual LINKEDIT chunk size. dyld_shared_cache shares
/// the global string table across all dylib images (~400 MB on macOS 15);
/// we can't pack that whole thing per image. 16 MiB covers per-image
/// chained-fixups and most exports tries; anything larger is the shared
/// string table and gets dropped (Phora falls back to LC_FUNCTION_STARTS
/// for procedure detection — symbol naming is best-effort).
const MAX_CHUNK_BYTES: u64 = 16 * 1024 * 1024;

/// Extract the named image from the system dyld shared cache.
pub fn loadImage(allocator: std.mem.Allocator, io: std.Io, image_name: []const u8) DyldCacheError!ExtractedImage {
    // Resolve the cache file path.
    const cache_path: []const u8 = blk: {
        for (CACHE_PATHS) |p| {
            if (std.Io.Dir.openFileAbsolute(io, p, .{})) |f| {
                f.close(io);
                break :blk p;
            } else |_| {}
        }
        return DyldCacheError.UnknownCachePath;
    };

    const file = std.Io.Dir.openFileAbsolute(io, cache_path, .{}) catch return DyldCacheError.OpenFailed;
    defer file.close(io);
    const file_size = (file.stat(io) catch return DyldCacheError.ReadFailed).size;

    // Read 1 KiB header prefix.
    var header_buf: [1024]u8 = undefined;
    const header_n = file.readPositionalAll(io, &header_buf, 0) catch return DyldCacheError.ReadFailed;
    if (header_n < 0x200) return DyldCacheError.TruncatedHeader;

    // Magic check: "dyld_v1" prefix.
    if (!std.mem.startsWith(u8, &header_buf, "dyld_v1")) return DyldCacheError.UnsupportedMagic;

    // Read fixed-position early fields.
    const mapping_offset = std.mem.readInt(u32, header_buf[0x10..0x14], .little);
    const mapping_count = std.mem.readInt(u32, header_buf[0x14..0x18], .little);
    const images_offset_old = std.mem.readInt(u32, header_buf[0x18..0x1C], .little);
    const images_count_old = std.mem.readInt(u32, header_buf[0x1C..0x20], .little);

    const images_offset_new = std.mem.readInt(u32, header_buf[0x1C0..0x1C4], .little);
    const images_count_new = std.mem.readInt(u32, header_buf[0x1C4..0x1C8], .little);

    const images_offset: u64 = if (images_offset_new != 0) images_offset_new else images_offset_old;
    const images_count: u32 = if (images_offset_new != 0) images_count_new else images_count_old;
    if (images_offset == 0 or images_count == 0) return DyldCacheError.ImagesTableNotFound;

    // Read mappings table.
    const mappings_total = @as(u64, mapping_count) * @sizeOf(CacheMappingInfo);
    if (mapping_count == 0 or mappings_total > 16 * @sizeOf(CacheMappingInfo)) return DyldCacheError.TruncatedHeader;
    const mappings_buf = allocator.alloc(u8, @intCast(mappings_total)) catch return DyldCacheError.OutOfMemory;
    defer allocator.free(mappings_buf);
    if ((file.readPositionalAll(io, mappings_buf, mapping_offset) catch return DyldCacheError.ReadFailed) != mappings_buf.len)
        return DyldCacheError.ReadFailed;
    const mappings: []const CacheMappingInfo = @as([*]const CacheMappingInfo, @ptrCast(@alignCast(mappings_buf.ptr)))[0..mapping_count];

    // Read images table.
    const images_total = @as(u64, images_count) * @sizeOf(CacheImageInfo);
    if (images_total > 64 * 1024 * @sizeOf(CacheImageInfo)) return DyldCacheError.TruncatedHeader;
    const images_buf = allocator.alloc(u8, @intCast(images_total)) catch return DyldCacheError.OutOfMemory;
    defer allocator.free(images_buf);
    if ((file.readPositionalAll(io, images_buf, images_offset) catch return DyldCacheError.ReadFailed) != images_buf.len)
        return DyldCacheError.ReadFailed;
    const images: []const CacheImageInfo = @as([*]const CacheImageInfo, @ptrCast(@alignCast(images_buf.ptr)))[0..images_count];

    // Find the requested image by name.
    var found: ?CacheImageInfo = null;
    for (images) |info| {
        var path_buf: [1024]u8 = undefined;
        const n = file.readPositionalAll(io, &path_buf, info.pathFileOffset) catch 0;
        if (n == 0) continue;
        const path_end = std.mem.indexOfScalar(u8, path_buf[0..n], 0) orelse continue;
        const path = path_buf[0..path_end];

        if (matchesImageName(path, image_name)) {
            found = info;
            break;
        }
    }
    const img_info = found orelse return DyldCacheError.ImageNotFound;

    // Translate the image VA to a file offset in the cache.
    const img_file_offset = translateVAToFileOffset(img_info.address, mappings) orelse return DyldCacheError.ImageNotFound;

    // Read Mach-O header.
    var mh_buf: [32]u8 = undefined;
    const mh_n = file.readPositionalAll(io, &mh_buf, img_file_offset) catch return DyldCacheError.ReadFailed;
    if (mh_n < 32) return DyldCacheError.Truncated;
    const magic_le = std.mem.readInt(u32, mh_buf[0..4], .little);
    if (magic_le != 0xFEEDFACF and magic_le != 0xCFFAEDFE) return DyldCacheError.UnsupportedMagic;

    const ncmds = std.mem.readInt(u32, mh_buf[16..20], .little);
    const sizeofcmds = std.mem.readInt(u32, mh_buf[20..24], .little);
    const lc_total: usize = 32 + @as(usize, sizeofcmds);
    if (lc_total > 256 * 1024) return DyldCacheError.TruncatedHeader;

    const lc_buf = allocator.alloc(u8, lc_total) catch return DyldCacheError.OutOfMemory;
    defer allocator.free(lc_buf);
    if ((file.readPositionalAll(io, lc_buf, img_file_offset) catch return DyldCacheError.ReadFailed) != lc_total) return DyldCacheError.Truncated;

    // ------------------------------------------------------------------------
    // Pass 1: walk LC_SEGMENT_64 commands and collect SegInfo for each.
    // ------------------------------------------------------------------------
    var segs = std.array_list.Managed(SegInfo).init(allocator);
    defer segs.deinit();

    var off: usize = 32;
    var idx: u32 = 0;
    while (idx < ncmds and off + 8 <= lc_buf.len) : (idx += 1) {
        const cmd = std.mem.readInt(u32, lc_buf[off..][0..4], .little);
        const cmdsize = std.mem.readInt(u32, lc_buf[off + 4 ..][0..4], .little);
        if (cmdsize == 0 or off + cmdsize > lc_buf.len) break;
        if (cmd == LC_SEGMENT_64 and cmdsize >= 72) {
            var name_arr: [16]u8 = [_]u8{0} ** 16;
            @memcpy(&name_arr, lc_buf[off + 8 ..][0..16]);
            const vmaddr = std.mem.readInt(u64, lc_buf[off + 24 ..][0..8], .little);
            const vmsize = std.mem.readInt(u64, lc_buf[off + 32 ..][0..8], .little);
            const fileoff = std.mem.readInt(u64, lc_buf[off + 40 ..][0..8], .little);
            const filesize = std.mem.readInt(u64, lc_buf[off + 48 ..][0..8], .little);
            const nsects = std.mem.readInt(u32, lc_buf[off + 64 ..][0..4], .little);

            const is_pz = std.mem.startsWith(u8, &name_arr, "__PAGEZERO");
            const is_le = std.mem.startsWith(u8, &name_arr, "__LINKEDIT");

            segs.append(.{
                .name = name_arr,
                .lc_offset = off,
                .cmdsize = cmdsize,
                .orig_vmaddr = vmaddr,
                .orig_fileoff = fileoff,
                .vmsize = vmsize,
                .filesize = filesize,
                .new_vmaddr = 0,
                .new_fileoff = 0,
                .new_filesize = 0,
                .nsects = nsects,
                .is_pagezero = is_pz,
                .is_linkedit = is_le,
            }) catch return DyldCacheError.OutOfMemory;
        }
        off += cmdsize;
    }
    if (segs.items.len == 0) return DyldCacheError.Truncated;

    // ------------------------------------------------------------------------
    // Pass 2: collect the LINKEDIT chunks referenced by LC_SYMTAB,
    // LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
    // LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE. Each chunk's source
    // bytes live in the cache's __LINKEDIT mapping (a separate region from
    // __TEXT/__DATA). We rewrite their offset fields to point at our new
    // packed __LINKEDIT segment.
    // ------------------------------------------------------------------------
    var chunks = std.array_list.Managed(LinkChunk).init(allocator);
    defer chunks.deinit();

    // Pre-pass: locate DYSYMTAB so we can compute the per-image symbol slice.
    // In dyld_shared_cache the SYMTAB cmd's nsyms/strsize describe the WHOLE
    // shared symbol/string tables (~400 MB across all dylibs). DYSYMTAB
    // ilocalsym/nlocalsym/iextdefsym/nextdefsym/iundefsym/nundefsym tell us
    // just THIS image's slice — typically a few thousand symbols.
    var dysym_off: ?usize = null;
    {
        var poff: usize = 32;
        var pidx: u32 = 0;
        while (pidx < ncmds and poff + 8 <= lc_buf.len) : (pidx += 1) {
            const cmd = std.mem.readInt(u32, lc_buf[poff..][0..4], .little);
            const cmdsize = std.mem.readInt(u32, lc_buf[poff + 4 ..][0..4], .little);
            if (cmdsize == 0 or poff + cmdsize > lc_buf.len) break;
            if (cmd == LC_DYSYMTAB and cmdsize >= 80) {
                dysym_off = poff;
                break;
            }
            poff += cmdsize;
        }
    }

    // Compute per-image symbol slice from DYSYMTAB if present.
    // Returns (start_index_within_symtab, count) — the chunk we'll pack and
    // the new symoff/nsyms we'll write into LC_SYMTAB.
    const PerImageSymRange = struct { start: u32, count: u32 };
    const sym_range: ?PerImageSymRange = blk: {
        const d = dysym_off orelse break :blk null;
        const ilocal = std.mem.readInt(u32, lc_buf[d + 8 ..][0..4], .little);
        const nlocal = std.mem.readInt(u32, lc_buf[d + 12 ..][0..4], .little);
        const iext = std.mem.readInt(u32, lc_buf[d + 16 ..][0..4], .little);
        const next = std.mem.readInt(u32, lc_buf[d + 20 ..][0..4], .little);
        const iundef = std.mem.readInt(u32, lc_buf[d + 24 ..][0..4], .little);
        const nundef = std.mem.readInt(u32, lc_buf[d + 28 ..][0..4], .little);
        const start: u32 = @min(ilocal, @min(iext, iundef));
        const last_end: u32 = @max(ilocal + nlocal, @max(iext + next, iundef + nundef));
        const count: u32 = if (last_end > start) last_end - start else 0;
        break :blk .{ .start = start, .count = count };
    };

    off = 32;
    idx = 0;
    while (idx < ncmds and off + 8 <= lc_buf.len) : (idx += 1) {
        const cmd = std.mem.readInt(u32, lc_buf[off..][0..4], .little);
        const cmdsize = std.mem.readInt(u32, lc_buf[off + 4 ..][0..4], .little);
        if (cmdsize == 0 or off + cmdsize > lc_buf.len) break;
        switch (cmd) {
            LC_SYMTAB => if (cmdsize >= 24) {
                const symoff = std.mem.readInt(u32, lc_buf[off + 8 ..][0..4], .little);
                const nsyms = std.mem.readInt(u32, lc_buf[off + 12 ..][0..4], .little);
                const stroff = std.mem.readInt(u32, lc_buf[off + 16 ..][0..4], .little);
                const strsize = std.mem.readInt(u32, lc_buf[off + 20 ..][0..4], .little);
                _ = nsyms;
                // Symbol table: only pack the per-image slice (computed from
                // DYSYMTAB). If we have no DYSYMTAB, we have to drop symbols
                // entirely — the whole shared symbol table is too large.
                if (sym_range) |sr| {
                    if (sr.count > 0 and symoff > 0) {
                        const slice_off: u64 = @as(u64, symoff) + @as(u64, sr.start) * 16;
                        const slice_len: u64 = @as(u64, sr.count) * 16;
                        chunks.append(.{
                            .src_fileoff = slice_off,
                            .len = slice_len,
                            .field_lc_offset = off + 8,
                        }) catch return DyldCacheError.OutOfMemory;
                        // Rewrite nsyms now (rewrite-pass only updates the
                        // offset field, not the count).
                        std.mem.writeInt(u32, lc_buf[off + 12 ..][0..4], sr.count, .little);
                    } else {
                        // Zero out symtab: no per-image slice resolvable.
                        std.mem.writeInt(u32, lc_buf[off + 8 ..][0..4], 0, .little);
                        std.mem.writeInt(u32, lc_buf[off + 12 ..][0..4], 0, .little);
                    }
                } else {
                    std.mem.writeInt(u32, lc_buf[off + 8 ..][0..4], 0, .little);
                    std.mem.writeInt(u32, lc_buf[off + 12 ..][0..4], 0, .little);
                }
                // String table: cap to MAX_CHUNK_BYTES. Some shared string
                // tables are hundreds of MB; we drop those. Smaller dylibs
                // often have <1 MB and we keep them. When dropped, the
                // SYMTAB-pointed strings dangle — we also zero strsize so
                // downstream parsers skip the lookup.
                if (strsize > 0 and stroff > 0 and strsize <= MAX_CHUNK_BYTES) {
                    chunks.append(.{
                        .src_fileoff = stroff,
                        .len = strsize,
                        .field_lc_offset = off + 16,
                        .count_field_lc_offset = off + 20,
                    }) catch return DyldCacheError.OutOfMemory;
                } else {
                    // Drop string table.
                    std.mem.writeInt(u32, lc_buf[off + 16 ..][0..4], 0, .little);
                    std.mem.writeInt(u32, lc_buf[off + 20 ..][0..4], 0, .little);
                    // If we drop strings we also have to drop symbols (their
                    // names would all be invalid offsets).
                    std.mem.writeInt(u32, lc_buf[off + 8 ..][0..4], 0, .little);
                    std.mem.writeInt(u32, lc_buf[off + 12 ..][0..4], 0, .little);
                    // And drop any chunk we just queued for the symbol slice
                    // (it lives at the tail of `chunks` because we push then
                    // string-cap right after).
                    if (chunks.items.len > 0) {
                        const last = &chunks.items[chunks.items.len - 1];
                        if (last.field_lc_offset == off + 8) {
                            _ = chunks.pop();
                        }
                    }
                }
            },
            LC_DYSYMTAB => if (cmdsize >= 80) {
                const indirectsymoff = std.mem.readInt(u32, lc_buf[off + 56 ..][0..4], .little);
                const nindirectsyms = std.mem.readInt(u32, lc_buf[off + 60 ..][0..4], .little);
                if (nindirectsyms > 0 and indirectsymoff > 0 and @as(u64, nindirectsyms) * 4 <= MAX_CHUNK_BYTES) {
                    chunks.append(.{
                        .src_fileoff = indirectsymoff,
                        .len = @as(u64, nindirectsyms) * 4,
                        .field_lc_offset = off + 56,
                        .count_field_lc_offset = off + 60,
                    }) catch return DyldCacheError.OutOfMemory;
                } else {
                    // Drop indirect symbols.
                    std.mem.writeInt(u32, lc_buf[off + 56 ..][0..4], 0, .little);
                    std.mem.writeInt(u32, lc_buf[off + 60 ..][0..4], 0, .little);
                }
                // After packing the per-image symbol slice the original
                // ilocalsym/iextdefsym/iundefsym indices need to be rebased
                // to 0..count (we packed starting at 0). Update those fields.
                if (sym_range) |sr| {
                    const ilocal = std.mem.readInt(u32, lc_buf[off + 8 ..][0..4], .little);
                    const iext = std.mem.readInt(u32, lc_buf[off + 16 ..][0..4], .little);
                    const iundef = std.mem.readInt(u32, lc_buf[off + 24 ..][0..4], .little);
                    if (ilocal >= sr.start) std.mem.writeInt(u32, lc_buf[off + 8 ..][0..4], ilocal - sr.start, .little);
                    if (iext >= sr.start) std.mem.writeInt(u32, lc_buf[off + 16 ..][0..4], iext - sr.start, .little);
                    if (iundef >= sr.start) std.mem.writeInt(u32, lc_buf[off + 24 ..][0..4], iundef - sr.start, .little);
                }
            },
            LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLD_EXPORTS_TRIE, LC_DYLD_CHAINED_FIXUPS => if (cmdsize >= 16) {
                // linkedit_data_command: off+8 = dataoff, off+12 = datasize.
                const dataoff = std.mem.readInt(u32, lc_buf[off + 8 ..][0..4], .little);
                const datasize = std.mem.readInt(u32, lc_buf[off + 12 ..][0..4], .little);
                if (datasize > 0 and dataoff > 0 and datasize <= MAX_CHUNK_BYTES) {
                    chunks.append(.{
                        .src_fileoff = dataoff,
                        .len = datasize,
                        .field_lc_offset = off + 8,
                        .count_field_lc_offset = off + 12,
                    }) catch return DyldCacheError.OutOfMemory;
                } else if (datasize > MAX_CHUNK_BYTES) {
                    // Too large (probably chained-fixups for shared libs);
                    // zero the offset+count so downstream parsers skip it.
                    std.mem.writeInt(u32, lc_buf[off + 8 ..][0..4], 0, .little);
                    std.mem.writeInt(u32, lc_buf[off + 12 ..][0..4], 0, .little);
                }
            },
            LC_DYLD_INFO, LC_DYLD_INFO_ONLY => if (cmdsize >= 48) {
                // dyld_info_command: 5 (offset, size) pairs starting at off+8.
                // rebase, bind, weak_bind, lazy_bind, export.
                var k: usize = 0;
                while (k < 5) : (k += 1) {
                    const fld = off + 8 + k * 8;
                    const ofs = std.mem.readInt(u32, lc_buf[fld..][0..4], .little);
                    const sz = std.mem.readInt(u32, lc_buf[fld + 4 ..][0..4], .little);
                    if (sz > 0 and ofs > 0 and sz <= MAX_CHUNK_BYTES) {
                        chunks.append(.{
                            .src_fileoff = ofs,
                            .len = sz,
                            .field_lc_offset = fld,
                            .count_field_lc_offset = fld + 4,
                        }) catch return DyldCacheError.OutOfMemory;
                    } else if (sz > MAX_CHUNK_BYTES) {
                        std.mem.writeInt(u32, lc_buf[fld..][0..4], 0, .little);
                        std.mem.writeInt(u32, lc_buf[fld + 4 ..][0..4], 0, .little);
                    }
                }
            },
            else => {},
        }
        off += cmdsize;
    }

    // ------------------------------------------------------------------------
    // Pass 3: lay out the packed image. Strategy:
    //   * Choose new_image_base = 0x100000000 (the canonical __TEXT base).
    //   * Skip __PAGEZERO from the file (it has no on-disk bytes) but keep
    //     its load command (rewritten).
    //   * Pack __TEXT first at file offset 0 (so the Mach-O header sits
    //     inside __TEXT's first page like a normal binary).
    //   * Pack other non-LINKEDIT segments contiguously after, page-aligned.
    //   * Pack a __LINKEDIT segment last that holds all collected chunks.
    //
    // For each segment we determine the source file offset in the cache by
    // either using its orig_fileoff (if non-zero AND in main cache) or
    // translating its orig_vmaddr through the mappings table.
    // ------------------------------------------------------------------------
    const PAGE: u64 = 0x4000; // 16 KiB page (arm64 macOS)
    var cur_fileoff: u64 = 0;
    var cur_vmaddr: u64 = 0x100000000;

    // First pass through segs to assign new offsets/addrs for non-PAGEZERO,
    // non-LINKEDIT segments. We always lay out in source order. __TEXT is
    // expected to be the first segment in well-formed Mach-O dylibs.
    for (segs.items) |*s| {
        if (s.is_pagezero) {
            // PAGEZERO occupies vm-space at 0x0 with no file bytes. Keep its
            // load command pristine (vmaddr=0, fileoff=0, filesize=0).
            s.new_vmaddr = 0;
            s.new_fileoff = 0;
            s.new_filesize = 0;
            continue;
        }
        if (s.is_linkedit) continue; // handled below

        // Page-align the file offset (and vmaddr).
        cur_fileoff = (cur_fileoff + PAGE - 1) & ~(PAGE - 1);
        cur_vmaddr = (cur_vmaddr + PAGE - 1) & ~(PAGE - 1);

        s.new_fileoff = cur_fileoff;
        s.new_vmaddr = cur_vmaddr;
        s.new_filesize = s.filesize;

        cur_fileoff += s.filesize;
        cur_vmaddr += @max(s.vmsize, s.filesize);
    }

    // Now lay out __LINKEDIT as a packed concatenation of chunks. Sort chunks
    // by their source offset to preserve locality and merge adjacent regions.
    // Even simpler: just concatenate, and remember each chunk's new offset.
    cur_fileoff = (cur_fileoff + PAGE - 1) & ~(PAGE - 1);
    cur_vmaddr = (cur_vmaddr + PAGE - 1) & ~(PAGE - 1);
    const linkedit_new_fileoff = cur_fileoff;
    const linkedit_new_vmaddr = cur_vmaddr;
    var linkedit_size: u64 = 0;

    // Validate each chunk lives in the main cache file. Drop ones that don't.
    for (chunks.items) |*c| {
        if (c.src_fileoff + c.len > file_size) {
            // Chunk lies in a subcache file — drop it (zero count). Without
            // the symbol table the resulting image is still parseable but
            // procedure detection falls back to instruction scanning.
            c.drop = true;
        }
    }
    // Assign new offsets contiguously, 8-byte aligned.
    for (chunks.items) |*c| {
        if (c.drop) continue;
        const aligned = (linkedit_size + 7) & ~@as(u64, 7);
        c.new_fileoff = linkedit_new_fileoff + aligned;
        linkedit_size = aligned + c.len;
    }
    // Update LINKEDIT segment size.
    var linkedit_seg: ?*SegInfo = null;
    for (segs.items) |*s| {
        if (s.is_linkedit) {
            linkedit_seg = s;
            break;
        }
    }
    if (linkedit_seg) |le| {
        le.new_fileoff = linkedit_new_fileoff;
        le.new_vmaddr = linkedit_new_vmaddr;
        le.new_filesize = linkedit_size;
        // Page-align the in-memory segment span to match what the rest of
        // the loader expects.
        const aligned_size = (linkedit_size + PAGE - 1) & ~(PAGE - 1);
        le.vmsize = @max(aligned_size, PAGE);
        le.filesize = linkedit_size;
        cur_fileoff = linkedit_new_fileoff + linkedit_size;
        cur_vmaddr = linkedit_new_vmaddr + le.vmsize;
    } else if (linkedit_size > 0) {
        // Image had no __LINKEDIT segment but referenced LINKEDIT data — that
        // would be malformed. Drop the chunks.
        for (chunks.items) |*c| c.drop = true;
        linkedit_size = 0;
    }

    // Sanity bound — refuse images > 200 MiB. Most system frameworks fit
    // well under 50 MiB even after packing; libSystem-class megaliths are
    // an exception we don't try to load.
    const total_size = cur_fileoff;
    if (total_size > 200 * 1024 * 1024) return DyldCacheError.Truncated;
    if (total_size == 0) return DyldCacheError.Truncated;

    // ------------------------------------------------------------------------
    // Pass 4: allocate output buffer, copy the (still-unmodified) header +
    // load commands into __TEXT[0..lc_total], then copy each segment's bytes
    // to its new file offset, and finally copy LINKEDIT chunks.
    // ------------------------------------------------------------------------
    const out = allocator.alloc(u8, @intCast(total_size)) catch return DyldCacheError.OutOfMemory;
    errdefer allocator.free(out);
    @memset(out, 0);

    // IMPORTANT ORDER: copy segment bytes FIRST, then overwrite the header
    // region with our (modified) lc_buf. The header sits inside __TEXT at
    // file offset 0, so the source __TEXT copy would otherwise stomp our
    // rewritten LC_SYMTAB / LC_SEGMENT_64 / etc. fields.

    // Copy each packed segment's bytes from the cache.
    for (segs.items) |s| {
        if (s.is_pagezero) continue;
        if (s.is_linkedit) continue; // copied via chunks below
        if (s.new_filesize == 0) continue;

        // Source file offset in cache: prefer translating vmaddr (works even
        // if orig_fileoff is in a different mapping). For __TEXT in a normal
        // dylib these resolve to the same place.
        const src = translateVAToFileOffset(s.orig_vmaddr, mappings) orelse continue;
        if (src + s.new_filesize > file_size) continue; // subcache — skip
        if (s.new_fileoff + s.new_filesize > out.len) continue;
        const dst = out[@intCast(s.new_fileoff)..@intCast(s.new_fileoff + s.new_filesize)];
        _ = file.readPositionalAll(io, dst, src) catch 0;
    }

    // Now overwrite the header / load command region with our modified
    // lc_buf. (The pass-2 chunk-collection code wrote zero/cap rewrites
    // into lc_buf; pass 5 below will further rewrite vmaddr/fileoff fields
    // directly in `out`.)
    @memcpy(out[0..lc_buf.len], lc_buf);

    // Copy LINKEDIT chunks.
    for (chunks.items) |c| {
        if (c.drop) continue;
        if (c.new_fileoff + c.len > out.len) continue;
        if (c.src_fileoff + c.len > file_size) continue;
        const dst = out[@intCast(c.new_fileoff)..@intCast(c.new_fileoff + c.len)];
        _ = file.readPositionalAll(io, dst, c.src_fileoff) catch 0;
    }

    // ------------------------------------------------------------------------
    // Pass 5: rewrite load commands in `out`. We modify the *output* buffer
    // because that's what `macho.parse` will see. Per-segment vmaddr/fileoff,
    // and per-section addr/offset for embedded SectionHeader64. Also rewrite
    // LINKEDIT-pointing offset fields and zero counts for dropped chunks.
    // ------------------------------------------------------------------------
    for (segs.items) |s| {
        // SegmentCommand64 layout: cmd(0), cmdsize(4), segname[16](8),
        // vmaddr(24), vmsize(32), fileoff(40), filesize(48), maxprot(56),
        // initprot(60), nsects(64), flags(68). Sections start at off+72.
        const seg_lc = s.lc_offset;
        std.mem.writeInt(u64, out[seg_lc + 24 ..][0..8], s.new_vmaddr, .little);
        if (s.is_pagezero) {
            std.mem.writeInt(u64, out[seg_lc + 32 ..][0..8], s.vmsize, .little);
        } else {
            // Vmsize stays as orig (page-aligned). Filesize = new_filesize.
            std.mem.writeInt(u64, out[seg_lc + 32 ..][0..8], s.vmsize, .little);
        }
        std.mem.writeInt(u64, out[seg_lc + 40 ..][0..8], s.new_fileoff, .little);
        std.mem.writeInt(u64, out[seg_lc + 48 ..][0..8], s.new_filesize, .little);

        // Rewrite each section's addr and offset (delta from segment).
        const va_delta_pos = s.new_vmaddr >= s.orig_vmaddr;
        const va_delta = if (va_delta_pos) s.new_vmaddr - s.orig_vmaddr else s.orig_vmaddr - s.new_vmaddr;
        const fo_delta_pos = s.new_fileoff >= s.orig_fileoff;
        const fo_delta = if (fo_delta_pos) s.new_fileoff - s.orig_fileoff else s.orig_fileoff - s.new_fileoff;

        const sec_size: usize = 80; // sizeof SectionHeader64
        var sec_idx: u32 = 0;
        while (sec_idx < s.nsects) : (sec_idx += 1) {
            const sec_off = seg_lc + 72 + @as(usize, sec_idx) * sec_size;
            if (sec_off + sec_size > out.len) break;
            // SectionHeader64: sectname[16](0), segname[16](16), addr(32),
            // size(40), offset(48), align(52), reloff(56), nreloc(60),
            // flags(64), reserved1(68), reserved2(72), reserved3(76).
            const old_addr = std.mem.readInt(u64, out[sec_off + 32 ..][0..8], .little);
            const old_offset = std.mem.readInt(u32, out[sec_off + 48 ..][0..4], .little);
            const new_addr: u64 = if (va_delta_pos) old_addr + va_delta else old_addr - va_delta;
            std.mem.writeInt(u64, out[sec_off + 32 ..][0..8], new_addr, .little);
            // Section file offset only matters when it's nonzero (BSS sections
            // legitimately have offset=0). __PAGEZERO has no sections.
            if (old_offset != 0) {
                const new_offset_u64: u64 = if (fo_delta_pos) @as(u64, old_offset) + fo_delta else @as(u64, old_offset) - fo_delta;
                const new_offset: u32 = @intCast(@min(new_offset_u64, std.math.maxInt(u32)));
                std.mem.writeInt(u32, out[sec_off + 48 ..][0..4], new_offset, .little);
            }
            // Zero out reloff/nreloc — we didn't pack relocations.
            std.mem.writeInt(u32, out[sec_off + 56 ..][0..4], 0, .little);
            std.mem.writeInt(u32, out[sec_off + 60 ..][0..4], 0, .little);
        }
    }

    // Rewrite LINKEDIT-pointing offset fields. For dropped chunks, zero out
    // both the offset and the count so downstream parsers skip them.
    for (chunks.items) |c| {
        if (c.drop) {
            std.mem.writeInt(u32, out[c.field_lc_offset..][0..4], 0, .little);
            if (c.count_field_lc_offset) |cf| {
                std.mem.writeInt(u32, out[cf..][0..4], 0, .little);
            }
            continue;
        }
        const new32: u32 = @intCast(@min(c.new_fileoff, std.math.maxInt(u32)));
        std.mem.writeInt(u32, out[c.field_lc_offset..][0..4], new32, .little);
    }

    const synth_path = std.fmt.allocPrint(allocator, "dyld_shared_cache:{s}", .{image_name}) catch
        return DyldCacheError.OutOfMemory;
    return .{ .path = synth_path, .data = out };
}

fn translateVAToFileOffset(va: u64, mappings: []const CacheMappingInfo) ?u64 {
    for (mappings) |m| {
        if (va >= m.address and va < m.address + m.size) {
            return m.fileOffset + (va - m.address);
        }
    }
    return null;
}

/// True when `image_path` matches the requested name, accepting either the
/// basename or the full install path.
fn matchesImageName(image_path: []const u8, requested: []const u8) bool {
    // Exact full-path match.
    if (std.mem.eql(u8, image_path, requested)) return true;
    // Basename match.
    if (std.mem.lastIndexOfScalar(u8, image_path, '/')) |slash| {
        const basename = image_path[slash + 1 ..];
        if (std.mem.eql(u8, basename, requested)) return true;
    }
    // Framework heuristic: requested image names must match a full path component.
    //
    // v7.15.1 A3: previously this used a substring search, which could match
    // one framework name inside another. Require a leading '/' before the
    // framework token so only exact path components match.
    var fw_buf: [256]u8 = undefined;
    if (requested.len + 13 < fw_buf.len) {
        const fw = std.fmt.bufPrint(&fw_buf, "/{s}.framework", .{requested}) catch return false;
        if (std.mem.indexOf(u8, image_path, fw) != null and std.mem.endsWith(u8, image_path, requested)) {
            return true;
        }
    }
    return false;
}
