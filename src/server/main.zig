const std = @import("std");
const mosaic = @import("mosaic");
const protocol = mosaic.protocol;
const ws_server_mod = @import("websocket_server");

const FileWriteError = std.fs.File.WriteError;
fn fileWriteAll(file: std.fs.File, bytes: []const u8) FileWriteError!usize {
    try file.writeAll(bytes);
    return bytes.len;
}
const FileWriter = std.io.GenericWriter(std.fs.File, FileWriteError, fileWriteAll);

fn stdoutWriter() FileWriter {
    return .{ .context = std.fs.File.stdout() };
}

fn stderrWriter() FileWriter {
    return .{ .context = std.fs.File.stderr() };
}

const usage = "Usage:\n  mos [--host HOST] [--port PORT] [--versions V] [--features F] [--subprotocol S]\n";

fn zSlice(z: [:0]const u8) []const u8 {
    const ptr: [*:0]const u8 = @ptrCast(z.ptr);
    return std.mem.span(ptr);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) std.debug.print("warning: leaked memory\n", .{});
    const allocator = gpa.allocator();

    const args_raw = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args_raw);

    const default_host = "127.0.0.1";
    var host_nt: [:0]const u8 = default_host;
    var port: u16 = 8081;
    var versions: []const u8 = "0";
    var features: []const u8 = "chat";
    var subprotocol: []const u8 = "mosaic2025";

    var idx: usize = 1;
    while (idx < args_raw.len) : (idx += 1) {
        const arg = zSlice(args_raw[idx]);
        if (std.mem.eql(u8, arg, "--host")) {
            idx += 1;
            if (idx >= args_raw.len) return error.InvalidArguments;
            host_nt = args_raw[idx];
        } else if (std.mem.eql(u8, arg, "--port")) {
            idx += 1;
            if (idx >= args_raw.len) return error.InvalidArguments;
            const port_text = zSlice(args_raw[idx]);
            port = try std.fmt.parseUnsigned(u16, port_text, 10);
        } else if (std.mem.eql(u8, arg, "--versions")) {
            idx += 1;
            if (idx >= args_raw.len) return error.InvalidArguments;
            versions = zSlice(args_raw[idx]);
        } else if (std.mem.eql(u8, arg, "--features")) {
            idx += 1;
            if (idx >= args_raw.len) return error.InvalidArguments;
            features = zSlice(args_raw[idx]);
        } else if (std.mem.eql(u8, arg, "--subprotocol")) {
            idx += 1;
            if (idx >= args_raw.len) return error.InvalidArguments;
            subprotocol = zSlice(args_raw[idx]);
        } else if (std.mem.eql(u8, arg, "--help")) {
            const stdout = stdoutWriter();
            try stdout.writeAll(usage);
            return;
        } else {
            const stderr = stderrWriter();
            try stderr.writeAll(usage);
            return error.InvalidArguments;
        }
    }

    var apps: [0]u32 = .{};
    const config = ws_server_mod.Config{
        .expect = .{
            .versions = versions,
            .features = features,
            .authenticate_as = null,
            .server_auth_nonce = null,
            .subprotocol = subprotocol,
        },
        .response = .{
            .version = "0",
            .features_accepted = features,
            .client_auth_nonce = null,
            .hello_ack_result = protocol.ResultCode.success,
            .hello_ack_max_version = 0,
            .hello_ack_applications = apps[0..],
            .submission_result_prefix = null,
            .server_secret_seed = null,
        },
    };

    const host_slice = std.mem.sliceTo(host_nt, 0);
    var server = if (port == 0)
        try ws_server_mod.start(allocator, config)
    else
        try ws_server_mod.startAt(allocator, config, host_slice, port);
    defer server.ensureStopped();

    const actual_port = server.port();
    var stdout = stdoutWriter();
    try std.fmt.format(stdout, "mos listening on {s}:{d}\n", .{ host_slice, actual_port });
    try stdout.writeAll("Press Ctrl+C to stop.\n");

    while (true) {
        std.Thread.sleep(1_000_000_000);
    }
}
