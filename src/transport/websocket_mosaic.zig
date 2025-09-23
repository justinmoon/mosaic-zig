const std = @import("std");
const websocket = @import("websocket");
const mosaic = @import("mosaic");
const protocol = mosaic.protocol;
const Ed25519Blake3 = mosaic.Ed25519Blake3;
const printable = mosaic.printable;
const base64 = std.base64;
const mock_server = @import("websocket_server.zig");
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
    authenticate_secret: ?[]const u8 = null,
    server_auth_nonce: ?[]const u8 = null,
    ca_bundle: ?std.crypto.Certificate.Bundle = null,
    host_header: ?[]const u8 = null,
    extra_headers: ?[]const u8 = null,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    client: websocket.Client,
    handshake: websocket.Client.HandshakeResult,
    hello_state: HelloState,

    pub fn deinit(self: *Connection) void {
        self.hello_state.deinit(self.allocator);
        self.handshake.deinit();
        self.client.deinit();
    }

    pub fn helloAck(self: *Connection) !HelloAck {
        return self.hello_state.headers;
    }

    pub fn helloState(self: *const Connection) *const HelloState {
        return &self.hello_state;
    }

    fn requiresHelloAuth(self: *const Connection) bool {
        return self.hello_state.requiresHelloAuth();
    }

    pub fn sendMessage(self: *Connection, message: *const protocol.Message) !void {
        const bytes = try protocol.encodeMessage(self.allocator, message.*);
        defer self.allocator.free(bytes);
        try self.client.writeBin(bytes);
    }

    pub fn recvMessage(self: *Connection) !protocol.Message {
        while (true) {
            const ws_message = try self.client.read() orelse continue;
            defer self.client.done(ws_message);

            switch (ws_message.type) {
                .binary => {
                    const decoded = try protocol.decodeMessage(self.allocator, ws_message.data);
                    if (decoded.messageType() == protocol.MessageType.hello_ack) {
                        try self.hello_state.setHelloAck(self.allocator, decoded.hello_ack);
                    }
                    return decoded;
                },
                .ping => {
                    const payload = try self.allocator.dupe(u8, ws_message.data);
                    defer self.allocator.free(payload);
                    try self.client.writePong(payload);
                    continue;
                },
                .pong => continue,
                .close => return error.ConnectionClosed,
                .text => return error.UnexpectedTextFrame,
            }
        }
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

pub const HelloState = struct {
    headers: HelloAck,
    authenticate_as: ?[]u8 = null,
    hello_auth_sent: bool = false,
    ack_frame: ?AckFrame = null,
    auth: ?*ClientAuth = null,

    const AckFrame = struct {
        result: protocol.ResultCode,
        max_version: u8,
        applications: []u32,
    };

    const ClientAuth = struct {
        key_pair: Ed25519Blake3.KeyPair,
    };

    fn init(
        allocator: std.mem.Allocator,
        handshake_ack: HelloAck,
        options: ConnectOptions,
    ) !HelloState {
        var auth_copy: ?[]u8 = null;
        if (options.authenticate_as) |auth| {
            auth_copy = try allocator.dupe(u8, auth);
        }

        var auth_state: ?*ClientAuth = null;

        if (handshake_ack.client_authenticate_nonce != null) {
            if (options.authenticate_secret == null) {
                if (auth_copy) |copy| allocator.free(copy);
                return error.HelloAuthMissingSecret;
            }
            if (options.authenticate_as == null) {
                if (auth_copy) |copy| allocator.free(copy);
                return error.HelloAuthMissingPublicKey;
            }
        }

        if (options.authenticate_secret) |secret_text| {
            if (options.authenticate_as == null) {
                if (auth_copy) |copy| allocator.free(copy);
                return error.HelloAuthMissingPublicKey;
            }

            var seed = try printable.decodeSecretKey(secret_text);
            defer @memset(seed[0..], 0);

            var key_pair = try Ed25519Blake3.KeyPair.fromSeed(seed);
            const derived_public = key_pair.publicKeyBytes();
            const expected_public = try printable.decodeUserPublicKey(options.authenticate_as.?);
            if (!std.mem.eql(u8, derived_public[0..], expected_public[0..])) {
                zeroKeyPair(&key_pair);
                if (auth_copy) |copy| allocator.free(copy);
                return error.HelloAuthPublicMismatch;
            }

            const auth_ptr = try allocator.create(ClientAuth);
            errdefer allocator.destroy(auth_ptr);
            auth_ptr.* = .{ .key_pair = key_pair };
            auth_state = auth_ptr;
        }

        return HelloState{
            .headers = handshake_ack,
            .authenticate_as = auth_copy,
            .auth = auth_state,
        };
    }

    fn deinit(self: *HelloState, allocator: std.mem.Allocator) void {
        if (self.ack_frame) |*ack| {
            allocator.free(ack.applications);
            self.ack_frame = null;
        }
        if (self.authenticate_as) |auth| {
            allocator.free(auth);
            self.authenticate_as = null;
        }
        if (self.auth) |auth_ptr| {
            zeroKeyPair(&auth_ptr.key_pair);
            allocator.destroy(auth_ptr);
            self.auth = null;
        }
    }

    fn setHelloAck(self: *HelloState, allocator: std.mem.Allocator, ack: protocol.HelloAck) !void {
        const apps = try allocator.alloc(u32, ack.applications.len);
        std.mem.copyForwards(u32, apps, ack.applications);

        const new_frame = AckFrame{
            .result = ack.result,
            .max_version = ack.max_version,
            .applications = apps,
        };

        if (self.ack_frame) |*existing| {
            allocator.free(existing.applications);
        }
        self.ack_frame = new_frame;
    }

    fn requiresHelloAuth(self: *const HelloState) bool {
        return self.headers.client_authenticate_nonce != null and !self.hello_auth_sent;
    }
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

    const handshake_headers = try parseHelloAck(&handshake);
    var connection = Connection{
        .allocator = allocator,
        .client = client,
        .handshake = handshake,
        .hello_state = undefined,
    };
    connection.hello_state = try HelloState.init(allocator, handshake_headers, options);
    errdefer connection.deinit();

    if (connection.requiresHelloAuth()) {
        try sendHelloAuth(&connection);
    }

    return connection;
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

fn zeroKeyPair(key_pair: *Ed25519Blake3.KeyPair) void {
    @memset(key_pair.inner.secret_key.bytes[0..], 0);
    @memset(key_pair.inner.public_key.bytes[0..], 0);
}

fn writeHelloAuthFrame(self: *Connection, payload: []const u8) !void {
    const type_byte: u8 = 0x11;
    const header_len = 8;
    const total_len = header_len + payload.len;
    const len_u32 = std.math.cast(u32, total_len) orelse return error.HelloAuthTooLong;

    var frame = try self.allocator.alloc(u8, total_len);
    defer self.allocator.free(frame);

    frame[0] = type_byte;
    frame[1] = 0;
    frame[2] = 0;
    frame[3] = 0;
    std.mem.writeInt(u32, frame[4..8], len_u32, .little);
    std.mem.copyForwards(u8, frame[8..], payload);

    try self.client.writeBin(frame);
}

fn encodeHelloAuthPayload(self: *Connection) ![]u8 {
    const nonce = self.hello_state.headers.client_authenticate_nonce orelse return error.HelloAuthMissingChallenge;
    if (nonce.len == 0) return error.HelloAuthMissingChallenge;

    const auth = self.hello_state.auth orelse return error.HelloAuthMissingSecret;
    const signature = try auth.key_pair.sign(nonce);

    const payload = try self.allocator.alloc(u8, signature.len);
    std.mem.copyForwards(u8, payload, signature[0..]);
    return payload;
}

fn sendHelloAuth(self: *Connection) !void {
    if (!self.requiresHelloAuth()) return;
    const payload = try encodeHelloAuthPayload(self);
    defer self.allocator.free(payload);
    try writeHelloAuthFrame(self, payload);
    self.hello_state.hello_auth_sent = true;
}

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

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

test "websocket mosaic handshake demo" {
    const allocator = std.testing.allocator;

    const client_secret_text = "mosec06ayb687prmw8abtuum9bps5hjmfz5ffyft3b4jeznn3htppf3kto";
    var client_seed = try printable.decodeSecretKey(client_secret_text);
    var client_kp = try Ed25519Blake3.KeyPair.fromSeed(client_seed);
    const public_bytes = client_kp.publicKeyBytes();
    var public_text = printable.encodeUserPublicKey(public_bytes);
    defer zeroKeyPair(&client_kp);
    @memset(client_seed[0..], 0);

    const server_secret_text = "mosec06ayb687prmw8abtuum9bps5hjmfz5ffyft3b4jeznn3htppf3kto";
    var server_seed = try printable.decodeSecretKey(server_secret_text);
    var server_kp = try Ed25519Blake3.KeyPair.fromSeed(server_seed);
    const server_nonce = "nonce123";
    const server_signature = try server_kp.sign(server_nonce);
    var server_auth_buf: [base64.standard.Encoder.calcSize(server_signature.len)]u8 = undefined;
    const expected_server_auth = base64.standard.Encoder.encode(&server_auth_buf, server_signature[0..]);
    defer zeroKeyPair(&server_kp);

    const apps = [_]u32{0};
    var submission_prefix = [_]u8{0} ** 32;
    submission_prefix[0] = 0x01;

    var server = try mock_server.start(allocator, .{
        .expect = .{
            .versions = "0,1",
            .features = "chat",
            .authenticate_as = public_text[0..],
            .server_auth_nonce = server_nonce,
        },
        .response = .{
            .version = "0",
            .features_accepted = "chat",
            .client_auth_nonce = "client-nonce",
            .hello_ack_result = protocol.ResultCode.success,
            .hello_ack_max_version = 0,
            .hello_ack_applications = apps[0..],
            .submission_result_prefix = submission_prefix,
            .server_secret_seed = server_seed,
        },
    });
    var server_joined = false;
    defer if (!server_joined) server.ensureStopped();
    @memset(server_seed[0..], 0);

    var conn = try connect(allocator, "127.0.0.1", .{
        .port = server.port(),
        .versions = "0,1",
        .features = "chat",
        .host_header = "127.0.0.1",
        .authenticate_as = public_text[0..],
        .authenticate_secret = client_secret_text,
        .server_auth_nonce = server_nonce,
    });
    defer conn.deinit();

    const hello = try conn.helloAck();
    try std.testing.expectEqualStrings("0", hello.version);
    try std.testing.expectEqualStrings("chat", hello.features_accepted.?);
    try std.testing.expectEqualStrings(expected_server_auth, hello.server_authentication.?);
    try std.testing.expectEqualStrings("client-nonce", hello.client_authenticate_nonce.?);

    try std.testing.expect(conn.helloState().hello_auth_sent);
    try std.testing.expect(conn.helloState().authenticate_as != null);
    try std.testing.expectEqualStrings(public_text[0..], conn.helloState().authenticate_as.?);
    try std.testing.expect(conn.helloState().ack_frame == null);

    var first = try conn.recvMessage();
    defer first.deinit(allocator);
    try std.testing.expectEqual(protocol.MessageType.hello_ack, first.messageType());
    const ack_summary = conn.helloState().ack_frame.?;
    try std.testing.expectEqual(protocol.ResultCode.success, ack_summary.result);
    try std.testing.expectEqual(@as(u8, 0), ack_summary.max_version);
    try std.testing.expectEqual(@as(usize, 1), ack_summary.applications.len);
    try std.testing.expectEqual(@as(u32, 0), ack_summary.applications[0]);

    const vectors_json = try std.fs.cwd().readFileAlloc(allocator, "testdata/test_vectors.json", 1 << 20);
    defer allocator.free(vectors_json);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vectors_json, .{});
    defer parsed.deinit();

    const record_hex = parsed.value.object.get("record").?.object.get("record_hex").?.string;
    const record_bytes_const = try hexToBytesAlloc(allocator, record_hex);
    defer allocator.free(record_bytes_const);

    const submission_bytes = try allocator.alloc(u8, record_bytes_const.len);
    @memcpy(submission_bytes, record_bytes_const);
    const submission_record = try protocol.Record.fromBytes(record_bytes_const);

    const submission_message = protocol.Message{ .submission = .{
        .record_bytes = submission_bytes,
        .record = submission_record,
    } };
    try conn.sendMessage(&submission_message);
    allocator.free(submission_bytes);

    var submission_result_msg = try conn.recvMessage();
    defer submission_result_msg.deinit(allocator);
    try std.testing.expectEqual(protocol.MessageType.submission_result, submission_result_msg.messageType());
    const submission_result = submission_result_msg.submission_result;
    try std.testing.expectEqual(protocol.ResultCode.accepted, submission_result.result);

    var record_id: [48]u8 = undefined;
    @memcpy(record_id[0..], record_bytes_const[0..48]);

    var references = try allocator.alloc(protocol.Reference, 1);
    defer allocator.free(references);
    references[0] = .{ .bytes = record_id };

    const get_message = protocol.Message{ .get = .{
        .query_id = protocol.QueryId.fromInt(0x1234),
        .references = references,
    } };
    try conn.sendMessage(&get_message);

    var record_response = try conn.recvMessage();
    defer record_response.deinit(allocator);
    try std.testing.expectEqual(protocol.MessageType.record, record_response.messageType());
    const record_msg = record_response.record;
    try std.testing.expectEqual(@as(u16, 0x1234), record_msg.query_id.toInt());
    try std.testing.expectEqualSlices(u8, record_bytes_const, record_msg.record_bytes);

    server_joined = true;
    const server_result = try server.wait();
    try std.testing.expect(server_result.saw_versions);
    try std.testing.expect(server_result.saw_features);
    try std.testing.expect(server_result.saw_subprotocol);
    try std.testing.expect(server_result.saw_authenticate_as);
    try std.testing.expect(server_result.saw_server_nonce);
    try std.testing.expect(server_result.hello_auth_seen);
    try std.testing.expect(server_result.hello_auth_valid);
}
