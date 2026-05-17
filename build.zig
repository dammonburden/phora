const std = @import("std");

fn zigModule(
    b: *std.Build,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    strip: bool,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = target,
        .optimize = optimize,
        .strip = strip,
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main executable
    // Binary size constraint: ≤ 2,097,152 bytes (2.0 MiB).
    // Verify after build: stat -f%z zig-out/bin/phora
    const exe = b.addExecutable(.{
        .name = "phora",
        .root_module = zigModule(b, "src/main.zig", target, .ReleaseSmall, true),
    });
    exe.link_gc_sections = true;

    // Post-link: strip local symbols to shrink LINKEDIT (~134KB savings).
    // Zig's .strip=true removes debug info but keeps local symbol table entries.
    // macOS `strip -x` removes those while keeping exported/dynamic symbols.
    const strip_cmd = b.addSystemCommand(&.{ "strip", "-x" });
    strip_cmd.addArtifactArg(exe);

    // Install the stripped binary
    const install = b.addInstallArtifact(exe, .{});
    install.step.dependOn(&strip_cmd.step);
    b.getInstallStep().dependOn(&install.step);

    // Post-build size gate: fail if binary exceeds 2 MiB (2,097,152 bytes)
    const size_check = b.addSystemCommand(&.{
        "sh", "-c",
        "SIZE=$(stat -f%z zig-out/bin/phora) && " ++
            "if [ \"$SIZE\" -gt 2097152 ]; then " ++
            "echo \"BUILD FAILED: binary is $SIZE bytes (max 2097152)\"; exit 1; " ++
            "else echo \"Binary size OK: $SIZE bytes\"; fi",
    });
    size_check.step.dependOn(&install.step);
    b.getInstallStep().dependOn(&size_check.step);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run phora");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const unit_tests = b.addTest(.{
        .root_module = zigModule(b, "src/main.zig", target, optimize, false),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Types library test
    const types_tests = b.addTest(.{
        .root_module = zigModule(b, "src/types.zig", target, optimize, false),
    });
    const run_types_tests = b.addRunArtifact(types_tests);
    test_step.dependOn(&run_types_tests.step);

    // Analysis engine, loader, arch decoder, and lifter tests.
    // These modules use relative imports (../types.zig etc.) so we need to
    // create a test runner that imports them from the src/ root.
    const test_runner = b.addTest(.{
        .root_module = zigModule(b, "src/test_analysis.zig", target, optimize, false),
    });
    const run_analysis_tests = b.addRunArtifact(test_runner);
    test_step.dependOn(&run_analysis_tests.step);

    // Integration test
    const integration_tests = b.addTest(.{
        .root_module = zigModule(b, "src/test_integration.zig", target, optimize, false),
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_step = b.step("test-integration", "Run integration tests");
    integration_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    // ReleaseSafe gate. This compiles and tests with runtime safety enabled
    // without changing the installed ReleaseSmall binary.
    const safe_exe = b.addExecutable(.{
        .name = "phora-check-safe",
        .root_module = zigModule(b, "src/main.zig", target, .ReleaseSafe, false),
    });

    const check_safe_step = b.step("check-safe", "Build and test Phora in ReleaseSafe");
    check_safe_step.dependOn(&safe_exe.step);

    const safe_unit_tests = b.addTest(.{
        .root_module = zigModule(b, "src/main.zig", target, .ReleaseSafe, false),
    });
    const run_safe_unit_tests = b.addRunArtifact(safe_unit_tests);
    check_safe_step.dependOn(&run_safe_unit_tests.step);

    const safe_types_tests = b.addTest(.{
        .root_module = zigModule(b, "src/types.zig", target, .ReleaseSafe, false),
    });
    const run_safe_types_tests = b.addRunArtifact(safe_types_tests);
    check_safe_step.dependOn(&run_safe_types_tests.step);

    const safe_analysis_tests = b.addTest(.{
        .root_module = zigModule(b, "src/test_analysis.zig", target, .ReleaseSafe, false),
    });
    const run_safe_analysis_tests = b.addRunArtifact(safe_analysis_tests);
    check_safe_step.dependOn(&run_safe_analysis_tests.step);

    const safe_integration_tests = b.addTest(.{
        .root_module = zigModule(b, "src/test_integration.zig", target, .ReleaseSafe, false),
    });
    const run_safe_integration_tests = b.addRunArtifact(safe_integration_tests);
    check_safe_step.dependOn(&run_safe_integration_tests.step);

    const verify_step = b.step("verify", "Run build, tests, benchmark smoke, size gate, and safe export audit");
    verify_step.dependOn(b.getInstallStep());
    verify_step.dependOn(test_step);
    verify_step.dependOn(check_safe_step);

    const verify_zig = b.addSystemCommand(&.{ "sh", "-c", "test \"$(zig version)\" = \"0.16.0\"" });
    verify_step.dependOn(&verify_zig.step);

    const verify_native = b.addSystemCommand(&.{
        "sh", "-c",
        "set -eu; " ++
            "! rg 'compat\\.zig|@import\\(.*compat|compat\\.' src >/dev/null; " ++
            "out=$(rg -n 'std\\.c\\.(open|read|write|lseek|fstat|gettimeofday|unlink)|std\\.Thread\\.spawn' src || true); " ++
            "printf '%s\\n' \"$out\" | grep -Ev '^$|^src/main\\.zig:[0-9]+:    _ = std\\.c\\.write\\(stderr_fd, msg\\.ptr, msg\\.len\\);$' >/dev/null && exit 1 || exit 0",
    });
    verify_step.dependOn(&verify_native.step);

    const verify_bench_dry = b.addSystemCommand(&.{ "python3", "scripts/bench-phora.py", "--dry-run", "--no-build" });
    verify_bench_dry.step.dependOn(b.getInstallStep());
    verify_step.dependOn(&verify_bench_dry.step);

    const verify_bench_strict = b.addSystemCommand(&.{ "python3", "scripts/bench-phora.py", "--case", "phora-self-context", "--strict", "--repeat", "1", "--no-build" });
    verify_bench_strict.step.dependOn(b.getInstallStep());
    verify_step.dependOn(&verify_bench_strict.step);

    const verify_safe_export = b.addSystemCommand(&.{
        "sh", "-c",
        "set -eu; " ++
            "tmp=$(mktemp -d \"${TMPDIR:-/tmp}/phora-verify-export.XXXXXX\"); " ++
            "trap 'rm -rf \"$tmp\"' EXIT; " ++
            "scripts/github-safe-publish.sh --export-dir \"$tmp\" >/tmp/phora-verify-safe-publish.log; " ++
            "test -f \"$tmp/benchmarks/cases.json\"; " ++
            "test -f \"$tmp/scripts/bench-phora.py\"; " ++
            "test ! -e \"$tmp/benchmark-results\"; " ++
            "test ! -e \"$tmp/benchmarks/results\"",
    });
    verify_safe_export.step.dependOn(b.getInstallStep());
    verify_step.dependOn(&verify_safe_export.step);
}
