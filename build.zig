const std = @import("std");

/// Discover every `.zig` file under `dir_path` and schedule it with `zig test`.
///
/// Zig only executes tests for the specific root file you hand to `addTest`. By
/// crawling the tree ourselves we guarantee that `zig build test` (and CI) runs
/// the tests for every module in the repository, so new files can never slip
/// through unnoticed.
fn addZigTestsForDir(
    b: *std.Build,
    step: *std.Build.Step,
    dir_path: []const u8,
    target: anytype,
    optimize: std.builtin.OptimizeMode,
) !void {
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;

        switch (entry.kind) {
            .directory => {
                const sub_path = try std.fmt.allocPrint(b.allocator, "{s}/{s}", .{ dir_path, entry.name });
                try addZigTestsForDir(b, step, sub_path, target, optimize);
            },
            .file => if (std.mem.endsWith(u8, entry.name, ".zig")) {
                const file_path = try std.fmt.allocPrint(b.allocator, "{s}/{s}", .{ dir_path, entry.name });
                const module = b.createModule(.{
                    .root_source_file = b.path(file_path),
                    .target = target,
                    .optimize = optimize,
                });
                const test_exe = b.addTest(.{
                    .root_module = module,
                });
                step.dependOn(&test_exe.step);
            },
            else => {},
        }
    }
}

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

    const test_step = b.step("test", "Run all Zig tests");
    addZigTestsForDir(b, test_step, "src", target, optimize) catch |err| {
        std.debug.panic("failed to enumerate tests: {s}", .{@errorName(err)});
    };
}
