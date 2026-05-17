// Phora — Analysis engine, lifter, and loader test runner
// Imports all modules to run their embedded tests.

comptime {
    _ = @import("analysis/strings.zig");
    _ = @import("analysis/xref.zig");
    _ = @import("analysis/procedures.zig");
    _ = @import("analysis/cfg.zig");
    _ = @import("analysis/disassembler.zig");
    _ = @import("analysis/pipeline.zig");
    _ = @import("analysis/objc.zig");
    _ = @import("analysis/swift.zig");
    _ = @import("arch/arm64.zig");
    _ = @import("arch/arm32.zig");
    _ = @import("arch/x86_64.zig");
    _ = @import("arch/mips32.zig");
    _ = @import("store/database.zig");
    _ = @import("lifter/ir.zig");
    _ = @import("lifter/lift.zig");
    _ = @import("lifter/patterns.zig");
    _ = @import("loaders/macho.zig");
    _ = @import("loaders/elf.zig");
    _ = @import("loaders/pe.zig");
    _ = @import("util/json.zig");
}
