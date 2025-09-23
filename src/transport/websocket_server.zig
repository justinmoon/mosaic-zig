const std = @import("std");
const websocket = @import("websocket");
const mosaic = @import("mosaic");
const protocol = mosaic.protocol;
const printable = mosaic.printable;
const Ed25519Blake3 = mosaic.Ed25519Blake3;

pub const ExpectHeaders = struct {
    versions: []const u8,
    features: []const u8,
    authenticate_as: ?[]const u8 = null,
    server_auth_nonce: ?[]const u8 = null,
    subprotocol: []const u8 = "mosaic2025",
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

const ServerError = error{
    MissingHeader,
    InvalidHeader,
    MissingAuthenticateHeader,
    InvalidAuthenticateHeader,
    MissingHelloAuthPayload,
    InvalidHelloAuthPayload,
};

const HandlerState = struct {
    allocator: std.mem.Allocator,
    config: Config,
    result: ServerResult = .{},
    expect_public_key: ?[32]u8,
    records: std.AutoHashMap([48]u8, []u8),
    mutex: std.Thread.Mutex = .{},

    fn init(allocator: std.mem.Allocator, config: Config) !*HandlerState {
        const state = try allocator.create(HandlerState);
        errdefer allocator.destroy(state);

        var expect_public: ?[32]u8 = null;
        if (config.expect.authenticate_as) |text| {
            const decoded = printable.decodeUserPublicKey(text) catch return ServerError.InvalidAuthenticateHeader;
            expect_public = decoded;
        }

        state.* = .{
            .allocator = allocator,
            .config = config,
            .result = .{},
            .expect_public_key = expect_public,
            .records = std.AutoHashMap([48]u8, []u8).init(allocator),
        };
        return state;
    }

    fn deinit(self: *HandlerState) void {
        var it = self.records.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.records.deinit();
    }

    fn noteHandshake(self: *HandlerState, result: ServerResult) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.result = result;
    }

    fn noteHelloAuth(self: *HandlerState, valid: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.result.hello_auth_seen = true;
        self.result.hello_auth_valid = valid;
    }
};

const Handler = struct {
    state: *HandlerState,
    conn: *websocket.server.Conn,
    authenticated: bool = false,
    expect_hello_auth: bool,

    pub fn init(handshake: *const websocket.server.Handshake, conn: *websocket.server.Conn, state: *HandlerState) !Handler {
        const expect = state.config.expect;
        var result = ServerResult{};

        const versions = handshake.headers.get("x-mosaic-versions") orelse return ServerError.MissingHeader;
        result.saw_versions = std.mem.eql(u8, versions, expect.versions);
        if (!result.saw_versions) return ServerError.InvalidHeader;

        const features = handshake.headers.get("x-mosaic-features") orelse return ServerError.MissingHeader;
        result.saw_features = std.mem.eql(u8, features, expect.features);
        if (!result.saw_features) return ServerError.InvalidHeader;

        const subprotocol = handshake.headers.get("sec-websocket-protocol") orelse return ServerError.MissingHeader;
        result.saw_subprotocol = std.mem.eql(u8, subprotocol, expect.subprotocol);
        if (!result.saw_subprotocol) return ServerError.InvalidHeader;

        if (expect.server_auth_nonce) |nonce| {
            const header = handshake.headers.get("x-mosaic-server-authenticate-nonce") orelse return ServerError.MissingHeader;
            result.saw_server_nonce = std.mem.eql(u8, header, nonce);
            if (!result.saw_server_nonce) return ServerError.InvalidHeader;
        } else {
            result.saw_server_nonce = true;
        }

        if (expect.authenticate_as) |expected| {
            const header = handshake.headers.get("x-mosaic-authenticate-as") orelse return ServerError.MissingAuthenticateHeader;
            result.saw_authenticate_as = std.mem.eql(u8, header, expected);
            if (!result.saw_authenticate_as) return ServerError.InvalidAuthenticateHeader;
            const decoded = printable.decodeUserPublicKey(header) catch return ServerError.InvalidAuthenticateHeader;
            state.expect_public_key = decoded;
        } else {
            result.saw_authenticate_as = true;
        }

        // Populate response headers
        handshake.res_headers.add("Sec-WebSocket-Protocol", expect.subprotocol);
        handshake.res_headers.add("X-Mosaic-Version", state.config.response.version);
        handshake.res_headers.add("X-Mosaic-Features-Accepted", state.config.response.features_accepted);
        handshake.res_headers.add("X-Mosaic-Server-Authentication", state.config.response.server_authentication);
        handshake.res_headers.add("X-Mosaic-Client-Authenticate-Nonce", state.config.response.client_auth_nonce);

        state.noteHandshake(result);

        return Handler{
            .state = state,
            .conn = conn,
            .expect_hello_auth = state.config.response.client_auth_nonce.len != 0,
        };
    }

    pub fn afterInit(self: *Handler, _: *HandlerState) !void {
        try self.sendHelloAck();
    }

    pub fn clientMessage(self: *Handler, allocator: std.mem.Allocator, data: []const u8) !void {
        if (data.len == 0) return;
        const msg_type = data[0];
        if (msg_type == 0x11) {
            try self.handleHelloAuth(data);
            return;
        }

        var message = try protocol.decodeMessage(allocator, data);
        defer message.deinit(allocator);

        switch (message) {
            .submission => |submission| try self.handleSubmission(submission),
            .get => |get| try self.handleGet(get),
            else => {},
        }
    }

    fn sendHelloAck(self: *Handler) !void {
        const res = self.state.config.response;
        const allocator = self.state.allocator;
        var apps = try allocator.alloc(u32, res.hello_ack_applications.len);
        defer allocator.free(apps);
        @memcpy(apps[0..], res.hello_ack_applications);

        const message = protocol.Message{ .hello_ack = .{
            .result = res.hello_ack_result,
            .max_version = res.hello_ack_max_version,
            .applications = apps,
        } };

        const encoded = try protocol.encodeMessage(allocator, message);
        defer allocator.free(encoded);
        try self.conn.writeFrame(.binary, encoded);
    }

    fn handleHelloAuth(self: *Handler, payload: []const u8) !void {
        if (!self.expect_hello_auth) {
            self.state.noteHelloAuth(false);
            return;
        }
        if (payload.len != 8 + Ed25519Blake3.signature_length) {
            self.state.noteHelloAuth(false);
            return ServerError.InvalidHelloAuthPayload;
        }
        const nonce = self.state.config.response.client_auth_nonce;
        if (nonce.len == 0) {
            self.state.noteHelloAuth(false);
            return ServerError.InvalidHelloAuthPayload;
        }

        const signature = payload[8..];
        const public_key = self.state.expect_public_key orelse return ServerError.MissingAuthenticateHeader;
        var sig: [Ed25519Blake3.signature_length]u8 = undefined;
        @memcpy(sig[0..], signature);
        try Ed25519Blake3.verify(nonce, sig, public_key);
        self.state.noteHelloAuth(true);
        self.authenticated = true;
    }

    fn handleSubmission(self: *Handler, submission: protocol.Submission) !void {
        if (self.expect_hello_auth and !self.authenticated) {
            return;
        }
        const allocator = self.state.allocator;
        const record_bytes = submission.record_bytes;
        var copy = try allocator.alloc(u8, record_bytes.len);
        @memcpy(copy, record_bytes);

        var id: [48]u8 = undefined;
        @memcpy(id[0..], copy[0..48]);

        {
            self.state.mutex.lock();
            defer self.state.mutex.unlock();
            if (try self.state.records.fetchPut(id, copy)) |older| {
                allocator.free(older.value);
            }
        }

        var prefix = [_]u8{0} ** 32;
        @memcpy(prefix[0..], copy[0..32]);
        const message = protocol.Message{ .submission_result = .{
            .result = protocol.ResultCode.accepted,
            .id_prefix = prefix,
        } };
        const encoded = try protocol.encodeMessage(allocator, message);
        defer allocator.free(encoded);
        try self.conn.writeFrame(.binary, encoded);
    }

    fn handleGet(self: *Handler, get: protocol.Get) !void {
        var i: usize = 0;
        while (i < get.references.len) : (i += 1) {
            const key = get.references[i].bytes;
            var record_slice_opt: ?[]u8 = null;
            {
                self.state.mutex.lock();
                defer self.state.mutex.unlock();
                if (self.state.records.get(key)) |value| {
                    record_slice_opt = value;
                }
            }
            const record_slice = record_slice_opt orelse continue;
            const record = protocol.Record.fromBytes(record_slice) catch continue;
            const message = protocol.Message{ .record = .{
                .query_id = get.query_id,
                .record_bytes = record_slice,
                .record = record,
            } };
            const encoded = try protocol.encodeMessage(self.state.allocator, message);
            defer self.state.allocator.free(encoded);
            try self.conn.writeFrame(.binary, encoded);
        }
    }
};

const WsServer = websocket.server.Server(Handler);

fn findOpenPort() !u16 {
    var address = try std.net.Address.parseIp("127.0.0.1", 0);
    var temp = try address.listen(.{ .reuse_address = true });
    defer temp.deinit();
    return temp.listen_address.in.getPort();
}

pub const Server = struct {
    allocator: std.mem.Allocator,
    state: ?*HandlerState,
    ws_server: ?*WsServer,
    thread: std.Thread,
    port_value: u16,

    pub fn port(self: *const Server) u16 {
        return self.port_value;
    }

    pub fn stop(self: *Server) void {
        if (self.ws_server) |srv| srv.stop();
    }

    pub fn wait(self: *Server) !ServerResult {
        var result: ServerResult = .{};
        if (self.state) |state_ptr| {
            result = state_ptr.result;
        }
        defer self.cleanup();
        self.stop();
        self.thread.join();
        return result;
    }

    pub fn ensureStopped(self: *Server) void {
        _ = self.wait() catch {};
    }

    fn cleanup(self: *Server) void {
        if (self.ws_server) |srv| {
            srv.deinit();
            self.allocator.destroy(srv);
            self.ws_server = null;
        }
        if (self.state) |state_ptr| {
            state_ptr.deinit();
            self.allocator.destroy(state_ptr);
            self.state = null;
        }
    }
};

pub fn start(allocator: std.mem.Allocator, config: Config) !Server {
    var state = try HandlerState.init(allocator, config);
    errdefer {
        state.deinit();
        allocator.destroy(state);
    }

    const port = try findOpenPort();

    const ws_ptr = try allocator.create(WsServer);
    errdefer allocator.destroy(ws_ptr);
    ws_ptr.* = try WsServer.init(allocator, .{
        .port = port,
        .address = "127.0.0.1",
        .worker_count = 1,
    });

    const thread = try ws_ptr.listenInNewThread(state);

    return Server{
        .allocator = allocator,
        .state = state,
        .ws_server = ws_ptr,
        .thread = thread,
        .port_value = port,
    };
}
