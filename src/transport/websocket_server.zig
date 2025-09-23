const std = @import("std");
const mosaic = @import("mosaic");
const protocol = mosaic.protocol;
const Ed25519Blake3 = mosaic.Ed25519Blake3;
const printable = mosaic.printable;
const ascii = std.ascii;

const ServerError = error{
    InvalidHandshakeRequest,
    ConnectionClosedEarly,
    MissingWebSocketKey,
    InvalidAuthenticateHeader,
    MissingAuthenticateHeader,
    MissingHelloAuthPayload,
    UnexpectedOpCode,
    UnmaskedFrame,
    FrameTooLarge,
    InvalidHelloAuthPayload,
};

pub const ExpectHeaders = struct {
    versions: []const u8,
    features: []const u8,
    subprotocol: []const u8 = "mosaic2025",
    authenticate_as: ?[]const u8 = null,
    server_auth_nonce: ?[]const u8 = null,
};

pub const ResponseConfig = struct {
    version: []const u8,
    features_accepted: []const u8,
    server_authentication: []const u8,
    client_auth_nonce: []const u8,
    hello_ack_result: protocol.ResultCode = .success,
    hello_ack_max_version: u8,
    hello_ack_applications: []const u32,
    submission_result_prefix: ?[32]u8 = null,
};

pub const Config = struct {
    expect: ExpectHeaders,
    response: ResponseConfig,
};

pub const ServerResult = struct {
    saw_versions: bool = false,
    saw_features: bool = false,
    saw_subprotocol: bool = false,
    saw_authenticate_as: bool = false,
    saw_server_nonce: bool = false,
    hello_auth_seen: bool = false,
    hello_auth_valid: bool = false,
};

const ServerContext = struct {
    server: std.net.Server,
    config: Config,
    result: ServerResult = .{},
    err: ?anyerror = null,
    port: u16,
};

pub const Server = struct {
    ctx: ?*ServerContext,
    thread: std.Thread,
    allocator: std.mem.Allocator,

    pub fn port(self: *const Server) u16 {
        return self.ctx.?.port;
    }

    pub fn wait(self: *Server) !ServerResult {
        const ctx_ptr = self.ctx orelse return error.AlreadyJoined;
        self.thread.join();
        self.ctx = null;
        defer self.allocator.destroy(ctx_ptr);
        if (ctx_ptr.err) |err| {
            return err;
        }
        return ctx_ptr.result;
    }

    pub fn ensureStopped(self: *Server) void {
        if (self.ctx != null) {
            _ = self.wait() catch {};
        }
    }
};

pub fn start(allocator: std.mem.Allocator, config: Config) !Server {
    var address = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try address.listen(.{ .reuse_address = true });
    const port = server.listen_address.in.getPort();

    const ctx = try allocator.create(ServerContext);
    ctx.* = .{
        .server = server,
        .config = config,
        .port = port,
    };

    const thread = try std.Thread.spawn(.{}, serverThread, .{ctx});

    return .{
        .ctx = ctx,
        .thread = thread,
        .allocator = allocator,
    };
}

fn serverThread(ctx: *ServerContext) void {
    ctx.result = .{};
    ctx.err = null;
    runServer(ctx) catch |err| {
        ctx.err = err;
        return;
    };
}

fn runServer(ctx: *ServerContext) !void {
    defer ctx.server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var connection = try ctx.server.accept();
    defer connection.stream.close();

    var buffer = std.ArrayListUnmanaged(u8){};
    defer buffer.deinit(arena.allocator());

    var tmp: [1024]u8 = undefined;
    while (true) {
        const read_len = try connection.stream.read(&tmp);
        if (read_len == 0) return ServerError.ConnectionClosedEarly;
        try buffer.appendSlice(arena.allocator(), tmp[0..read_len]);
        if (std.mem.indexOf(u8, buffer.items, "\r\n\r\n")) |_| break;
    }

    const request = buffer.items;
    const headers_end = std.mem.indexOfPos(u8, request, 0, "\r\n\r\n") orelse return ServerError.InvalidHandshakeRequest;
    const header_bytes = request[0..headers_end];

    var lines = std.mem.splitSequence(u8, header_bytes, "\r\n");
    const request_line = lines.next() orelse return ServerError.InvalidHandshakeRequest;
    const expect = ctx.config.expect;

    var saw_versions = false;
    var saw_features = false;
    var saw_subprotocol = false;
    var saw_authenticate_as = false;
    var saw_server_nonce = false;
    var sec_key: ?[]const u8 = null;
    var authenticate_as_bytes: ?[32]u8 = null;

    // Validate request line
    if (!std.mem.startsWith(u8, request_line, "GET ")) return ServerError.InvalidHandshakeRequest;

    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon_index = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const raw_name = line[0..colon_index];
        var lowered = try arena.allocator().alloc(u8, raw_name.len);
        for (raw_name, 0..) |ch, idx| {
            lowered[idx] = std.ascii.toLower(ch);
        }
        const name = std.mem.trim(u8, lowered, &ascii.whitespace);
        const value = std.mem.trim(u8, line[colon_index + 1 ..], &ascii.whitespace);

        if (std.mem.eql(u8, name, "sec-websocket-key")) {
            sec_key = value;
        } else if (std.mem.eql(u8, name, "sec-websocket-protocol")) {
            saw_subprotocol = std.mem.eql(u8, value, expect.subprotocol);
        } else if (std.mem.eql(u8, name, "x-mosaic-versions")) {
            saw_versions = std.mem.eql(u8, value, expect.versions);
        } else if (std.mem.eql(u8, name, "x-mosaic-features")) {
            saw_features = std.mem.eql(u8, value, expect.features);
        } else if (std.mem.eql(u8, name, "x-mosaic-authenticate-as")) {
            if (expect.authenticate_as) |expected| {
                saw_authenticate_as = std.mem.eql(u8, value, expected);
                authenticate_as_bytes = printable.decodeUserPublicKey(value) catch return ServerError.InvalidAuthenticateHeader;
            }
        } else if (std.mem.eql(u8, name, "x-mosaic-server-authenticate-nonce")) {
            if (expect.server_auth_nonce) |nonce| {
                saw_server_nonce = std.mem.eql(u8, value, nonce);
            }
        }
    }

    ctx.result.saw_versions = saw_versions;
    ctx.result.saw_features = saw_features;
    ctx.result.saw_subprotocol = saw_subprotocol;
    ctx.result.saw_authenticate_as = saw_authenticate_as;
    ctx.result.saw_server_nonce = saw_server_nonce;

    const websocket_key = sec_key orelse return ServerError.MissingWebSocketKey;
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

    const res = ctx.config.response;
    try std.fmt.format(
        response_writer,
        "HTTP/1.1 101 Switching Protocol\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\nSec-WebSocket-Protocol: {s}\r\n" ++
            "X-Mosaic-Version: {s}\r\nX-Mosaic-Features-Accepted: {s}\r\nX-Mosaic-Server-Authentication: {s}\r\n" ++
            "X-Mosaic-Client-Authenticate-Nonce: {s}\r\n\r\n",
        .{ accept_value, expect.subprotocol, res.version, res.features_accepted, res.server_authentication, res.client_auth_nonce },
    );

    try connection.stream.writeAll(response_builder.items);

    const apps_copy = try arena.allocator().alloc(u32, res.hello_ack_applications.len);
    @memcpy(apps_copy[0..], res.hello_ack_applications);
    const hello_ack_msg = protocol.Message{ .hello_ack = .{
        .result = res.hello_ack_result,
        .max_version = res.hello_ack_max_version,
        .applications = apps_copy,
    } };
    const hello_ack_payload = try protocol.encodeMessage(arena.allocator(), hello_ack_msg);
    defer arena.allocator().free(hello_ack_payload);
    try writeServerBinaryFrame(&connection.stream, hello_ack_payload);

    const hello_auth_payload = try readClientBinaryFrame(arena.allocator(), &connection.stream);
    defer arena.allocator().free(hello_auth_payload);

    ctx.result.hello_auth_seen = hello_auth_payload.len != 0;

    if (res.client_auth_nonce.len != 0 and (expect.authenticate_as != null)) {
        if (hello_auth_payload.len == 0) return ServerError.MissingHelloAuthPayload;
        const signature_slice = try parseHelloAuthPayload(hello_auth_payload);
        var signature: [Ed25519Blake3.signature_length]u8 = undefined;
        std.mem.copyForwards(u8, signature[0..], signature_slice);
        const pubkey = authenticate_as_bytes orelse return ServerError.MissingAuthenticateHeader;
        try Ed25519Blake3.verify(res.client_auth_nonce, signature, pubkey);
        ctx.result.hello_auth_valid = true;
    }

    if (res.submission_result_prefix) |prefix| {
        const submission_msg = protocol.Message{ .submission_result = .{
            .result = protocol.ResultCode.accepted,
            .id_prefix = prefix,
        } };
        const submission_payload = try protocol.encodeMessage(arena.allocator(), submission_msg);
        defer arena.allocator().free(submission_payload);
        try writeServerBinaryFrame(&connection.stream, submission_payload);
    }
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

fn writeServerBinaryFrame(stream: *std.net.Stream, payload: []const u8) !void {
    std.debug.assert(payload.len < 126);
    var header = [_]u8{ 0x82, @intCast(payload.len) };
    try stream.writeAll(header[0..]);
    if (payload.len != 0) try stream.writeAll(payload);
}

fn readExact(stream: *std.net.Stream, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const read_bytes = try stream.read(buf[offset..]);
        if (read_bytes == 0) return ServerError.ConnectionClosedEarly;
        offset += read_bytes;
    }
}

fn readClientBinaryFrame(allocator: std.mem.Allocator, stream: *std.net.Stream) ![]u8 {
    var header: [2]u8 = undefined;
    try readExact(stream, header[0..]);

    if ((header[0] & 0x0F) != 0x2) return ServerError.UnexpectedOpCode;
    if ((header[1] & 0x80) == 0) return ServerError.UnmaskedFrame;

    var payload_len: usize = header[1] & 0x7F;
    if (payload_len == 126) {
        var extended: [2]u8 = undefined;
        try readExact(stream, extended[0..]);
        payload_len = (@as(usize, extended[0]) << 8) | extended[1];
    } else if (payload_len == 127) {
        return ServerError.FrameTooLarge;
    }

    var mask: [4]u8 = undefined;
    try readExact(stream, mask[0..]);

    var payload = try allocator.alloc(u8, payload_len);
    if (payload_len != 0) {
        try readExact(stream, payload);
        var i: usize = 0;
        while (i < payload_len) : (i += 1) {
            payload[i] ^= mask[i % 4];
        }
    }

    return payload;
}

fn parseHelloAuthPayload(payload: []const u8) ![]const u8 {
    if (payload.len != Ed25519Blake3.signature_length) {
        return ServerError.InvalidHelloAuthPayload;
    }
    return payload;
}
