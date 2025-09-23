const std = @import("std");

/// Discover every `.zig` file under `dir_path` and schedule it with `zig test`.
///
/// Zig only executes tests for the specific root file you hand to `addTest`. By
/// crawling the tree ourselves we guarantee that `zig build test` (and CI) runs
/// the tests for every module in the repository, so new files can never slip
/// through unnoticed.
const ModuleImport = struct {
    name: []const u8,
    module: *std.Build.Module,
};

fn addZigTestsForDir(
    b: *std.Build,
    step: *std.Build.Step,
    dir_path: []const u8,
    target: anytype,
    optimize: std.builtin.OptimizeMode,
    extra_imports: []const ModuleImport,
) !void {
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;

        switch (entry.kind) {
            .directory => {
                if (std.mem.eql(u8, entry.name, "vendor")) continue;
                const sub_path = try std.fmt.allocPrint(b.allocator, "{s}/{s}", .{ dir_path, entry.name });
                try addZigTestsForDir(b, step, sub_path, target, optimize, extra_imports);
            },
            .file => if (std.mem.endsWith(u8, entry.name, ".zig")) {
                const file_path = try std.fmt.allocPrint(b.allocator, "{s}/{s}", .{ dir_path, entry.name });
                const module = b.createModule(.{
                    .root_source_file = b.path(file_path),
                    .target = target,
                    .optimize = optimize,
                });
                for (extra_imports) |imp| {
                    module.addImport(imp.name, imp.module);
                }
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

    const lmdb_dep = b.dependency("lmdb", .{});
    const lmdb_module = b.createModule(.{
        .root_source_file = b.path("src/lmdb.zig"),
        .target = target,
        .optimize = optimize,
    });
    lmdb_module.addIncludePath(lmdb_dep.path("libraries/liblmdb"));
    lmdb_module.addCSourceFiles(.{
        .root = lmdb_dep.path("libraries/liblmdb"),
        .files = &.{ "mdb.c", "midl.c" },
    });
    lmdb_module.link_libc = true;

    const websocket_dep = b.dependency("websocket", .{ .target = target, .optimize = optimize });
    const websocket_module = websocket_dep.module("websocket");

    // Core module shared between the installable library and the test step.
    const lib_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib_imports = [_]ModuleImport{
        .{ .name = "lmdb", .module = lmdb_module },
        .{ .name = "websocket", .module = websocket_module },
    };

    for (lib_imports) |imp| {
        lib_module.addImport(imp.name, imp.module);
    }

    const static_lib = b.addLibrary(.{
        .name = "mosaic",
        .root_module = lib_module,
        .linkage = .static,
    });

    const install_lib = b.addInstallArtifact(static_lib, .{});
    b.getInstallStep().dependOn(&install_lib.step);

    const ws_transport_module = b.createModule(.{
        .root_source_file = b.path("src/transport/websocket_mosaic.zig"),
        .target = target,
        .optimize = optimize,
    });
    const ws_server_module = b.createModule(.{
        .root_source_file = b.path("src/transport/websocket_server.zig"),
        .target = target,
        .optimize = optimize,
    });
    ws_server_module.addImport("mosaic", lib_module);
    ws_server_module.addImport("websocket", websocket_module);
    ws_transport_module.addImport("mosaic", lib_module);
    ws_transport_module.addImport("websocket", websocket_module);
    ws_transport_module.addImport("websocket_server", ws_server_module);

    const cli_exe = b.addExecutable(.{
        .name = "mo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    cli_exe.root_module.addImport("mosaic", lib_module);
    cli_exe.root_module.addImport("websocket_transport", ws_transport_module);
    cli_exe.root_module.addImport("websocket_server", ws_server_module);
    cli_exe.linkLibrary(static_lib);

    const install_cli = b.addInstallArtifact(cli_exe, .{});
    b.getInstallStep().dependOn(&install_cli.step);

    const run_cli = b.addRunArtifact(cli_exe);
    if (b.args) |args| run_cli.addArgs(args);
    const cli_step = b.step("cli", "Run the Mosaic CLI");
    cli_step.dependOn(&run_cli.step);

    const test_step = b.step("test", "Run all Zig tests");
    const shared_imports = [_]ModuleImport{
        .{ .name = "lmdb", .module = lmdb_module },
        .{ .name = "websocket", .module = websocket_module },
        .{ .name = "mosaic", .module = lib_module },
        .{ .name = "websocket_transport", .module = ws_transport_module },
        .{ .name = "websocket_server", .module = ws_server_module },
    };

    addZigTestsForDir(b, test_step, "src", target, optimize, shared_imports[0..]) catch |err| {
        std.debug.panic("failed to enumerate tests: {s}", .{@errorName(err)});
    };
}
