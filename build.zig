const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Core module shared between the installable library and the test step.
    const lib_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const static_lib = b.addLibrary(.{
        .name = "mosaic",
        .root_module = lib_module,
        .linkage = .static,
    });

    const install_lib = b.addInstallArtifact(static_lib, .{});
    b.getInstallStep().dependOn(&install_lib.step);

    const tests = b.addTest(.{
        .root_module = lib_module,
    });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}
