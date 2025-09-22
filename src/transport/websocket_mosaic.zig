const std = @import("std");
const websocket = @import("websocket");
const ascii = std.ascii;

pub const ConnectOptions = struct {
    port: u16,
    path: []const u8 = "/",
    tls: bool = true,
    timeout_ms: u32 = 5_000,
    expected_subprotocol: []const u8 = "mosaic2025",
    versions: []const u8 = "0",
    features: []const u8 = "",
    authenticate_as: ?[]const u8 = null,
    server_auth_nonce: ?[]const u8 = null,
    ca_bundle: ?std.crypto.Certificate.Bundle = null,
    host_header: ?[]const u8 = null,
    extra_headers: ?[]const u8 = null,
};

pub const Connection = struct {
    client: websocket.Client,
    handshake: websocket.Client.HandshakeResult,

    pub fn deinit(self: *Connection) void {
        self.handshake.deinit();
        self.client.deinit();
    }

    pub fn helloAck(self: *Connection) !HelloAck {
        return parseHelloAck(&self.handshake);
    }
};

pub const HelloAck = struct {
    subprotocol: ?[]const u8,
    version: []const u8,
    features_accepted: ?[]const u8 = null,
    server_authentication: ?[]const u8 = null,
    client_authenticate_nonce: ?[]const u8 = null,
    service_url: ?[]const u8 = null,
};

pub const HelloAckError = error{
    MissingServerVersion,
};

pub fn connect(
    allocator: std.mem.Allocator,
    host: []const u8,
    options: ConnectOptions,
) !Connection {
    var client = try websocket.Client.init(allocator, .{
        .host = host,
        .port = options.port,
        .tls = options.tls,
        .ca_bundle = options.ca_bundle,
    });
    errdefer client.deinit();

    const host_header = options.host_header orelse host;
    const headers = try buildHandshakeHeaders(allocator, host_header, options);
    defer allocator.free(headers);

    var handshake = try client.handshake(options.path, .{
        .timeout_ms = options.timeout_ms,
        .headers = headers,
        .expected_subprotocol = options.expected_subprotocol,
    });
    errdefer handshake.deinit();

    return .{
        .client = client,
        .handshake = handshake,
    };
}

fn buildHandshakeHeaders(
    allocator: std.mem.Allocator,
    host_header: []const u8,
    options: ConnectOptions,
) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(allocator);

    var writer_ctx = ArrayListWriter{ .list = &list, .allocator = allocator };
    var writer = ListWriter{ .context = &writer_ctx };

    try std.fmt.format(writer, "Host: {s}:{d}\r\n", .{ host_header, options.port });
    try std.fmt.format(writer, "Sec-WebSocket-Protocol: {s}\r\n", .{options.expected_subprotocol});
    try std.fmt.format(writer, "X-Mosaic-Versions: {s}\r\n", .{options.versions});
    try std.fmt.format(writer, "X-Mosaic-Features: {s}\r\n", .{options.features});

    if (options.authenticate_as) |auth| {
        try std.fmt.format(writer, "X-Mosaic-Authenticate-As: {s}\r\n", .{auth});
    }

    if (options.server_auth_nonce) |nonce| {
        try std.fmt.format(writer, "X-Mosaic-Server-Authenticate-Nonce: {s}\r\n", .{nonce});
    }

    if (options.extra_headers) |extra| {
        try writer.writeAll(extra);
        if (!std.mem.endsWith(u8, extra, "\r\n")) {
            try writer.writeAll("\r\n");
        }
    }

    return try list.toOwnedSlice(allocator);
}

const ArrayListWriter = struct {
    list: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
};

fn listWrite(ctx: *ArrayListWriter, bytes: []const u8) error{OutOfMemory}!usize {
    try ctx.list.appendSlice(ctx.allocator, bytes);
    return bytes.len;
}

const ListWriter = std.io.GenericWriter(*ArrayListWriter, error{OutOfMemory}, listWrite);

pub fn parseHelloAck(handshake: *const websocket.Client.HandshakeResult) HelloAckError!HelloAck {
    const version = handshake.get("x-mosaic-version") orelse return error.MissingServerVersion;

    return .{
        .subprotocol = handshake.get("sec-websocket-protocol"),
        .version = version,
        .features_accepted = handshake.get("x-mosaic-features-accepted"),
        .server_authentication = handshake.get("x-mosaic-server-authentication"),
        .client_authenticate_nonce = handshake.get("x-mosaic-client-authenticate-nonce"),
        .service_url = handshake.get("x-mosaic-service-url"),
    };
}

const testing = std.testing;

test "buildHandshakeHeaders emits required Mosaic headers" {
    var alloc = testing.allocator;
    const options = ConnectOptions{
        .port = 443,
        .versions = "0,1",
        .features = "chat,contacts",
        .authenticate_as = "mopub0:abc",
        .server_auth_nonce = "nonce123",
    };
    const headers = try buildHandshakeHeaders(alloc, "example.com", options);
    defer alloc.free(headers);

    try testing.expect(std.mem.containsAtLeast(u8, headers, 1, "Host: example.com:443\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, headers, 1, "Sec-WebSocket-Protocol: mosaic2025\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, headers, 1, "X-Mosaic-Versions: 0,1\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, headers, 1, "X-Mosaic-Features: chat,contacts\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, headers, 1, "X-Mosaic-Authenticate-As: mopub0:abc\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, headers, 1, "X-Mosaic-Server-Authenticate-Nonce: nonce123\r\n"));
}

test "parseHelloAck extracts Mosaic headers" {
    var alloc = testing.allocator;
    var headers = std.ArrayListUnmanaged(websocket.Client.HandshakeHeader){};

    try headers.append(alloc, .{ .name = try alloc.dupe(u8, "sec-websocket-protocol"), .value = try alloc.dupe(u8, "mosaic2025") });
    try headers.append(alloc, .{ .name = try alloc.dupe(u8, "x-mosaic-version"), .value = try alloc.dupe(u8, "0") });
    try headers.append(alloc, .{ .name = try alloc.dupe(u8, "x-mosaic-features-accepted"), .value = try alloc.dupe(u8, "chat") });
    try headers.append(alloc, .{ .name = try alloc.dupe(u8, "x-mosaic-server-authentication"), .value = try alloc.dupe(u8, "sig") });
    try headers.append(alloc, .{ .name = try alloc.dupe(u8, "x-mosaic-client-authenticate-nonce"), .value = try alloc.dupe(u8, "nonce") });

    var result = websocket.Client.HandshakeResult{
        .compression = false,
        .headers = headers,
        .allocator = alloc,
    };
    defer result.deinit();

    const hello = try parseHelloAck(&result);
    try testing.expectEqualStrings("mosaic2025", hello.subprotocol.?);
    try testing.expectEqualStrings("0", hello.version);
    try testing.expectEqualStrings("chat", hello.features_accepted.?);
    try testing.expectEqualStrings("sig", hello.server_authentication.?);
    try testing.expectEqualStrings("nonce", hello.client_authenticate_nonce.?);
    try testing.expect(hello.service_url == null);
}

const ExpectHeaders = struct {
    versions: []const u8,
    features: []const u8,
    subprotocol: []const u8 = "mosaic2025",
};

const ServerResult = struct {
    saw_versions: bool = false,
    saw_features: bool = false,
    saw_subprotocol: bool = false,
};

const ServerContext = struct {
    server: *std.net.Server,
    expect: ExpectHeaders,
    result: ServerResult = .{},
    err: ?anyerror = null,
};

fn serverThread(ctx: *ServerContext) void {
    ctx.result = .{};
    ctx.err = null;
    const res = runMockServer(ctx.server, ctx.expect) catch |err| {
        ctx.err = err;
        return;
    };
    ctx.result = res;
}

fn runMockServer(server: *std.net.Server, expect: ExpectHeaders) !ServerResult {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var connection = try server.accept();
    defer connection.stream.close();

    var buffer = std.ArrayListUnmanaged(u8){};
    defer buffer.deinit(arena.allocator());

    var tmp: [512]u8 = undefined;
    while (true) {
        const read_len = try connection.stream.read(&tmp);
        if (read_len == 0) return error.ConnectionClosedEarly;
        try buffer.appendSlice(arena.allocator(), tmp[0..read_len]);
        if (std.mem.indexOf(u8, buffer.items, "\r\n\r\n")) |_| break;
    }

    var saw_versions = false;
    var saw_features = false;
    var saw_subprotocol = false;
    var sec_key: ?[]const u8 = null;

    var lines = std.mem.splitSequence(u8, buffer.items, "\r\n");
    _ = lines.next() orelse return error.InvalidHandshakeRequest;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon_index = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon_index], &ascii.whitespace);
        const value = std.mem.trim(u8, line[colon_index + 1 ..], &ascii.whitespace);

        if (ascii.eqlIgnoreCase(name, "sec-websocket-key")) {
            sec_key = value;
        } else if (ascii.eqlIgnoreCase(name, "sec-websocket-protocol")) {
            saw_subprotocol = ascii.eqlIgnoreCase(value, expect.subprotocol);
        } else if (ascii.eqlIgnoreCase(name, "x-mosaic-versions")) {
            saw_versions = std.mem.eql(u8, value, expect.versions);
        } else if (ascii.eqlIgnoreCase(name, "x-mosaic-features")) {
            saw_features = std.mem.eql(u8, value, expect.features);
        }
    }

    const websocket_key = sec_key orelse return error.MissingWebSocketKey;
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(websocket_key);
    sha.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha.final(&digest);

    var accept_buf: [28]u8 = undefined;
    const accept_value = std.base64.standard.Encoder.encode(&accept_buf, &digest);

    var response_builder = std.ArrayListUnmanaged(u8){};
    defer response_builder.deinit(arena.allocator());
    var response_writer_ctx = ArrayListWriter{ .list = &response_builder, .allocator = arena.allocator() };
    const response_writer = ListWriter{ .context = &response_writer_ctx };

    try std.fmt.format(
        response_writer,
        "HTTP/1.1 101 Switching Protocol\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\nSec-WebSocket-Protocol: {s}\r\n" ++
            "X-Mosaic-Version: 0\r\nX-Mosaic-Features-Accepted: chat\r\nX-Mosaic-Server-Authentication: sig\r\n" ++
            "X-Mosaic-Client-Authenticate-Nonce: nonce\r\n\r\n",
        .{ accept_value, expect.subprotocol },
    );

    try connection.stream.writeAll(response_builder.items);

    return ServerResult{
        .saw_versions = saw_versions,
        .saw_features = saw_features,
        .saw_subprotocol = saw_subprotocol,
    };
}

test "websocket mosaic handshake demo" {
    var address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    const port = server.listen_address.in.getPort();
    const expect = ExpectHeaders{ .versions = "0,1", .features = "chat" };

    var ctx = ServerContext{ .server = &server, .expect = expect };
    const thread = try std.Thread.spawn(.{}, serverThread, .{&ctx});

    var conn = try connect(std.testing.allocator, "127.0.0.1", .{
        .port = port,
        .versions = expect.versions,
        .features = expect.features,
        .host_header = "127.0.0.1",
    });
    defer conn.deinit();

    const hello = try conn.helloAck();
    try std.testing.expectEqualStrings("0", hello.version);
    try std.testing.expectEqualStrings("chat", hello.features_accepted.?);
    try std.testing.expectEqualStrings("sig", hello.server_authentication.?);
    try std.testing.expectEqualStrings("nonce", hello.client_authenticate_nonce.?);

    thread.join();
    if (ctx.err) |err| return err;
    const server_result = ctx.result;
    try std.testing.expect(server_result.saw_versions);
    try std.testing.expect(server_result.saw_features);
    try std.testing.expect(server_result.saw_subprotocol);
}
