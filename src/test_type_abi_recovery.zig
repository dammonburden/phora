comptime {
    _ = @import("analysis/abi.zig");
    _ = @import("analysis/types.zig");
    _ = @import("lifter/lift.zig");
    _ = @import("lifter/passes/call_arg_fixup.zig");
    _ = @import("lifter/passes/reg_to_var.zig");
}
