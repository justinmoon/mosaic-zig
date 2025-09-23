const std = @import("std");
const app = @import("app.zig");
const mosaic = @import("mosaic");
const crypto = mosaic.crypto;
const printable = mosaic.printable;
const Allocator = std.mem.Allocator;

const default_host = "mosaic.justinmoon.com";
const default_path = "/";
const default_versions = "0";
const default_features = "chat";
const default_port: u16 = 443;
const default_tls = true;

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

pub fn main() void {
    run() catch |err| {
        const stderr = stderrWriter();
        std.fmt.format(stderr, "error: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}

fn run() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) std.debug.print("warning: leaked memory\n", .{});
    const allocator = gpa.allocator();

    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();

    const raw_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_args);

    var args_list = std.ArrayList([]const u8){};
    defer args_list.deinit(allocator);
    var raw_index: usize = 1;
    while (raw_index < raw_args.len) : (raw_index += 1) {
        const trimmed = std.mem.sliceTo(raw_args[raw_index], 0);
        try args_list.append(allocator, trimmed);
    }
    const args = args_list.items;

    if (args.len == 0) {
        const stderr = stderrWriter();
        try printUsage(stderr);
        return;
    }

    var idx: usize = 0;

    var storage_path_opt = env.get("MOSAIC_STATE_DIR");
    var server_host: []const u8 = env.get("MOSAIC_SERVER_HOST") orelse default_host;
    var server_path: []const u8 = env.get("MOSAIC_SERVER_PATH") orelse default_path;
    var server_versions: []const u8 = env.get("MOSAIC_CLIENT_VERSIONS") orelse default_versions;
    var server_features: []const u8 = env.get("MOSAIC_CLIENT_FEATURES") orelse default_features;
    var server_port: u16 = default_port;
    if (env.get("MOSAIC_SERVER_PORT")) |port_text| {
        server_port = try parsePort(port_text);
    }
    var use_tls = default_tls;
    if (env.get("MOSAIC_SERVER_TLS")) |tls_text| {
        use_tls = !std.mem.eql(u8, tls_text, "0");
    }

    while (idx < args.len) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--")) {
            idx += 1;
            break;
        }
        if (arg.len == 0 or arg[0] != '-') break;
        idx += 1;

        if (std.mem.eql(u8, arg, "--storage")) {
            if (idx >= args.len) return error.InvalidArguments;
            storage_path_opt = args[idx];
            idx += 1;
        } else if (std.mem.eql(u8, arg, "--server")) {
            if (idx >= args.len) return error.InvalidArguments;
            server_host = args[idx];
            idx += 1;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (idx >= args.len) return error.InvalidArguments;
            server_port = try parsePort(args[idx]);
            idx += 1;
        } else if (std.mem.eql(u8, arg, "--path")) {
            if (idx >= args.len) return error.InvalidArguments;
            server_path = args[idx];
            idx += 1;
        } else if (std.mem.eql(u8, arg, "--versions")) {
            if (idx >= args.len) return error.InvalidArguments;
            server_versions = args[idx];
            idx += 1;
        } else if (std.mem.eql(u8, arg, "--features")) {
            if (idx >= args.len) return error.InvalidArguments;
            server_features = args[idx];
            idx += 1;
        } else if (std.mem.eql(u8, arg, "--no-tls") or std.mem.eql(u8, arg, "--insecure")) {
            use_tls = false;
        } else if (std.mem.eql(u8, arg, "--tls")) {
            use_tls = true;
        } else {
            return error.InvalidArguments;
        }
    }

    if (idx >= args.len) {
        const stderr = stderrWriter();
        try printUsage(stderr);
        return;
    }

    const command = args[idx];
    idx += 1;

    if (std.mem.eql(u8, command, "help")) {
        const stdout = stdoutWriter();
        try printUsage(stdout);
        return;
    }

    if (std.mem.eql(u8, command, "keygen")) {
        try handleKeygen(allocator, &env);
        return;
    }

    var credentials = try loadCredentials(allocator, &env);

    const storage_path = try resolveStoragePath(allocator, &env, storage_path_opt);
    defer allocator.free(storage_path);

    var app_instance = app.App{
        .allocator = allocator,
        .connect = .{
            .host = server_host,
            .port = server_port,
            .path = server_path,
            .tls = use_tls,
            .versions = server_versions,
            .features = server_features,
            .expected_subprotocol = "mosaic2025",
        },
        .storage_config = .{ .path = storage_path, .map_size = 64 * 1024 * 1024 },
        .credentials = credentials,
        .storage = null,
    };
    defer app_instance.deinit();
    credentials = undefined;

    if (std.mem.eql(u8, command, "publish")) {
        try handlePublish(allocator, &app_instance, args, &idx);
    } else if (std.mem.eql(u8, command, "timeline")) {
        try handleTimeline(allocator, &app_instance, args, &idx);
    } else {
        return error.UnsupportedCommand;
    }
}

fn handlePublish(allocator: Allocator, app_instance: *app.App, args: []const []const u8, idx_ptr: *usize) !void {
    var text_opt: ?[]const u8 = null;
    var text_buffer: ?[]u8 = null;
    const max_stdin: usize = 1 << 20;

    var idx = idx_ptr.*;
    while (idx < args.len) {
        const arg = args[idx];
        idx += 1;
        if (std.mem.eql(u8, arg, "--text")) {
            if (idx >= args.len) return error.InvalidArguments;
            text_opt = args[idx];
            idx += 1;
        } else if (std.mem.eql(u8, arg, "--stdin")) {
            if (text_buffer != null or text_opt != null) return error.InvalidArguments;
            text_buffer = try std.fs.File.stdin().readToEndAlloc(allocator, max_stdin);
            text_opt = text_buffer;
        } else {
            return error.InvalidArguments;
        }
    }
    idx_ptr.* = idx;

    const text = text_opt orelse return error.MissingText;

    defer if (text_buffer) |buf| allocator.free(buf);

    const stdout = stdoutWriter();
    try app_instance.publish(stdout, .{ .text = text });
}

fn handleTimeline(allocator: Allocator, app_instance: *app.App, args: []const []const u8, idx_ptr: *usize) !void {
    var limit: usize = 10;
    var reference_texts = std.ArrayList([]const u8){};
    defer reference_texts.deinit(allocator);

    var idx = idx_ptr.*;
    while (idx < args.len) {
        const arg = args[idx];
        idx += 1;
        if (std.mem.eql(u8, arg, "--limit")) {
            if (idx >= args.len) return error.InvalidArguments;
            limit = try parseUnsigned(args[idx]);
            idx += 1;
        } else if (std.mem.eql(u8, arg, "--reference")) {
            if (idx >= args.len) return error.InvalidArguments;
            try reference_texts.append(allocator, args[idx]);
            idx += 1;
        } else {
            return error.InvalidArguments;
        }
    }
    idx_ptr.* = idx;

    const references = try app.parseReferences(allocator, reference_texts.items);
    defer allocator.free(references);

    const stdout = stdoutWriter();
    try app_instance.timeline(stdout, .{ .limit = limit, .references = references });
}

fn handleKeygen(allocator: Allocator, env: *std.process.EnvMap) !void {
    var seed: [crypto.Ed25519Blake3.seed_length]u8 = undefined;
    std.crypto.random.bytes(&seed);

    const key_pair = try crypto.Ed25519Blake3.KeyPair.fromSeed(seed);
    const secret_text = printable.encodeSecretKey(seed);
    const public_text = printable.encodeUserPublicKey(key_pair.publicKeyBytes());

    const secret_path = try resolveSecretPath(allocator, env);
    defer allocator.free(secret_path);

    if (std.fs.path.dirname(secret_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    if (std.fs.cwd().access(secret_path, .{})) {
        const stdout = stdoutWriter();
        try std.fmt.format(stdout, "mosec already exists at {s}\n", .{secret_path});
        try std.fmt.format(stdout, "Use MOSEC env var to override or remove the file to generate anew.\n", .{});
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    var file = try std.fs.cwd().createFile(secret_path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    try file.writeAll(secret_text[0..]);
    try file.writeAll("\n");

    @memset(seed[0..], 0);

    const stdout = stdoutWriter();
    try std.fmt.format(stdout, "saved mosec0 to {s}\n", .{secret_path});
    try std.fmt.format(stdout, "mosec0: {s}\n", .{secret_text});
    try std.fmt.format(stdout, "mopub0: {s}\n", .{public_text});
}

fn parsePort(text: []const u8) !u16 {
    const value = try std.fmt.parseUnsigned(u16, text, 10);
    if (value == 0) return error.InvalidPort;
    return value;
}

fn parseUnsigned(text: []const u8) !usize {
    return try std.fmt.parseUnsigned(usize, text, 10);
}

fn resolveStoragePath(allocator: Allocator, env: *std.process.EnvMap, input: ?[]const u8) ![]u8 {
    if (input) |path_text| {
        return try resolvePath(allocator, env, path_text);
    }
    const home = env.get("HOME") orelse return error.MissingHome;
    return try std.fmt.allocPrint(allocator, "{s}/.local/share/mosaic-cli", .{home});
}

fn resolvePath(allocator: Allocator, env: *std.process.EnvMap, path_text: []const u8) ![]u8 {
    if (path_text.len != 0 and path_text[0] == '~') {
        const home = env.get("HOME") orelse return error.MissingHome;
        return try std.fmt.allocPrint(allocator, "{s}{s}", .{ home, path_text[1..] });
    }
    if (std.fs.path.isAbsolute(path_text)) {
        return try allocator.dupe(u8, path_text);
    }
    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);
    return try std.fs.path.join(allocator, &.{ cwd_path, path_text });
}

fn loadCredentials(allocator: Allocator, env: *std.process.EnvMap) !app.Credentials {
    if (env.get("MOSEC")) |secret_env| {
        const env_slice = std.mem.sliceTo(secret_env, 0);
        const trimmed = std.mem.trim(u8, env_slice, " \t\r\n");
        if (trimmed.len == 0) return error.MissingCredentials;
        return credentialsFromSecret(allocator, trimmed);
    }

    const secret_path = try resolveSecretPath(allocator, env);
    defer allocator.free(secret_path);

    var file = std.fs.cwd().openFile(secret_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.MissingCredentials,
        else => return err,
    };
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 8 * 1024);
    defer allocator.free(contents);

    const trimmed = std.mem.trim(u8, contents, " \t\r\n");
    if (trimmed.len == 0) return error.MissingCredentials;
    return credentialsFromSecret(allocator, trimmed);
}

fn credentialsFromSecret(allocator: Allocator, secret_text: []const u8) !app.Credentials {
    var seed = try printable.decodeSecretKey(secret_text);
    defer @memset(seed[0..], 0);
    const key_pair = try crypto.Ed25519Blake3.KeyPair.fromSeed(seed);
    const public_text = printable.encodeUserPublicKey(key_pair.publicKeyBytes());
    return app.Credentials.init(allocator, public_text[0..], secret_text);
}

fn resolveSecretPath(allocator: Allocator, env: *std.process.EnvMap) ![]u8 {
    if (env.get("MOSAIC_SECRET_PATH")) |raw| {
        return try resolvePath(allocator, env, raw);
    }
    const home = env.get("HOME") orelse return error.MissingHome;
    return try std.fmt.allocPrint(allocator, "{s}/.config/mosaic/mosec.key", .{home});
}

fn printUsage(writer: anytype) !void {
    try std.fmt.format(writer, "Usage:\n  mo keygen\n  mo publish --text <message>\n  mo publish --stdin\n  mo timeline [--limit N] [--reference moref0...]\n\nCommon options:\n  --server <host>        Override server host\n  --port <port>          Override server port\n  --no-tls               Disable TLS for local testing\n  --storage <path>       Override storage directory\n", .{});
}
