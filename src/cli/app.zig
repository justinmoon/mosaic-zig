const std = @import("std");
const mosaic = @import("mosaic");
const protocol = mosaic.protocol;
const record_ns = mosaic.record;
const record_builder = mosaic.record_builder;
const timestamp_ns = mosaic.timestamp;
const printable = mosaic.printable;
const crypto = mosaic.crypto;
const storage_ns = mosaic.storage;
const transport = @import("websocket_transport");
const mock_server = @import("websocket_server");

const Allocator = std.mem.Allocator;

pub const Credentials = struct {
    allocator: Allocator,
    mopub_text: []const u8,
    mosec_text: []const u8,
    public_key: [32]u8,
    key_pair: crypto.Ed25519Blake3.KeyPair,

    pub fn init(allocator: Allocator, mopub_text: []const u8, mosec_text: []const u8) !Credentials {
        const public_key = try printable.decodeUserPublicKey(mopub_text);

        var secret_seed = try printable.decodeSecretKey(mosec_text);
        defer @memset(secret_seed[0..], 0);
        const key_pair = try crypto.Ed25519Blake3.KeyPair.fromSeed(secret_seed);

        const mopub_copy = try allocator.dupe(u8, mopub_text);
        errdefer allocator.free(mopub_copy);
        const mosec_copy = try allocator.dupe(u8, mosec_text);
        errdefer allocator.free(mosec_copy);

        return .{
            .allocator = allocator,
            .mopub_text = mopub_copy,
            .mosec_text = mosec_copy,
            .public_key = public_key,
            .key_pair = key_pair,
        };
    }

    pub fn deinit(self: *Credentials) void {
        self.allocator.free(self.mopub_text);
        self.allocator.free(self.mosec_text);
        self.* = undefined;
    }
};

pub const ConnectConfig = struct {
    host: []const u8,
    port: u16,
    path: []const u8 = "/",
    tls: bool = true,
    versions: []const u8 = "0",
    features: []const u8 = "chat",
    timeout_ms: u32 = 5_000,
    expected_subprotocol: []const u8 = "mosaic2025",
};

pub const StorageConfig = struct {
    path: []const u8,
    map_size: usize = 64 * 1024 * 1024,
};

pub const PublishOptions = struct {
    text: []const u8,
    timestamp_override: ?timestamp_ns.Timestamp = null,
};

pub const TimelineOptions = struct {
    limit: usize = 10,
    references: []const protocol.Reference = &[_]protocol.Reference{},
};

pub const App = struct {
    allocator: Allocator,
    connect: ConnectConfig,
    storage_config: StorageConfig,
    credentials: Credentials,
    storage: ?storage_ns.Storage = null,

    pub fn init(self: *App) !void {
        if (self.storage != null) return;
        const storage = try storage_ns.Storage.init(self.allocator, .{
            .path = self.storage_config.path,
            .map_size = self.storage_config.map_size,
        });
        self.storage = storage;
    }

    pub fn deinit(self: *App) void {
        if (self.storage) |*store| {
            store.deinit();
            self.storage = null;
        }
        self.credentials.deinit();
    }

    pub fn publish(self: *App, writer: anytype, options: PublishOptions) !void {
        try self.ensureStorage();
        if (options.text.len == 0) return error.MissingText;

        const timestamp = options.timestamp_override orelse try currentTimestamp();
        const record_buf = try record_builder.buildMicroblogRecord(self.allocator, .{
            .timestamp = timestamp,
            .signing_key = self.credentials.key_pair,
            .author_public_key = self.credentials.public_key,
            .payload = options.text,
            .tags = &[_]record_builder.TagInput{},
            .address_nonce = null,
        });
        defer self.allocator.free(record_buf);

        var conn = try self.connectToServer();
        defer conn.deinit();
        try sendHello(&conn);
        try awaitHelloAck(self.allocator, &conn);

        try sendSubmission(&conn, record_buf);
        const result = try awaitSubmissionResult(self.allocator, &conn);
        if (result.result != protocol.ResultCode.accepted and result.result != protocol.ResultCode.success) {
            return error.PublishRejected;
        }

        const storage_ptr = if (self.storage) |*store| store else return error.StorageUnavailable;
        try storage_ptr.put(record_buf);

        var id_bytes: [48]u8 = undefined;
        std.mem.copyForwards(u8, id_bytes[0..], record_buf[0..48]);
        const id_text = printable.encodeReference(id_bytes);
        try std.fmt.format(writer, "published {s}\n", .{id_text});
    }

    pub fn timeline(self: *App, writer: anytype, options: TimelineOptions) !void {
        try self.ensureStorage();
        const storage_ptr = if (self.storage) |*store| store else return error.StorageUnavailable;

        var conn = try self.connectToServer();
        defer conn.deinit();
        try sendHello(&conn);
        try awaitHelloAck(self.allocator, &conn);

        if (options.references.len != 0) {
            try sendGet(&conn, options.references);
            try harvestRecords(self.allocator, &conn, storage_ptr);
        }

        const max_ts = @as(u64, @intCast(timestamp_ns.Timestamp.max.asNanoseconds()));
        var records = try storage_ptr.getByTimestamp(self.allocator, 0, max_ts, options.limit);
        defer records.deinit();

        for (records.items) |item| {
            const record = try record_ns.Record.fromBytes(item.bytes);
            const ts_value = @as(i64, @intCast(record.timestamp()));
            const ts = timestamp_ns.Timestamp{ .value = ts_value };
            const unix = ts.toUnixTime();
            const payload = record.payload();
            try std.fmt.format(writer, "{d}.{d:0>9}: {s}\n", .{ unix.seconds, unix.nanoseconds, payload });
        }
    }

    fn ensureStorage(self: *App) !void {
        if (self.storage == null) {
            try self.init();
        }
    }

    fn connectToServer(self: *App) !transport.Connection {
        return try transport.connect(self.allocator, self.connect.host, .{
            .port = self.connect.port,
            .path = self.connect.path,
            .tls = self.connect.tls,
            .timeout_ms = self.connect.timeout_ms,
            .expected_subprotocol = self.connect.expected_subprotocol,
            .versions = self.connect.versions,
            .features = self.connect.features,
            .authenticate_as = self.credentials.mopub_text,
            .authenticate_secret = self.credentials.mosec_text,
        });
    }
};

pub const AppError = error{
    MissingText,
    PublishRejected,
    StorageUnavailable,
};

fn sendHello(conn: *transport.Connection) !void {
    var apps = [_]u32{0};
    const hello = protocol.Message{ .hello = .{
        .max_version = 0,
        .applications = apps[0..],
    } };
    try conn.sendMessage(&hello);
}

fn awaitHelloAck(allocator: Allocator, conn: *transport.Connection) !void {
    while (true) {
        var msg = try conn.recvMessage();
        defer msg.deinit(allocator);
        switch (msg) {
            .hello_ack => return,
            else => continue,
        }
    }
}

fn sendSubmission(conn: *transport.Connection, record_bytes: []u8) !void {
    const record = try record_ns.Record.fromBytes(record_bytes);
    const submission = protocol.Message{ .submission = .{
        .record_bytes = record_bytes,
        .record = record,
    } };
    try conn.sendMessage(&submission);
}

fn awaitSubmissionResult(allocator: Allocator, conn: *transport.Connection) !protocol.SubmissionResult {
    while (true) {
        var msg = try conn.recvMessage();
        defer msg.deinit(allocator);
        switch (msg) {
            .submission_result => |result| return result,
            else => continue,
        }
    }
}

fn sendGet(conn: *transport.Connection, references: []const protocol.Reference) !void {
    const refs_mut = @constCast(references);
    const get_msg = protocol.Message{ .get = .{
        .query_id = protocol.QueryId.fromInt(1),
        .references = refs_mut,
    } };
    try conn.sendMessage(&get_msg);
}

fn harvestRecords(allocator: Allocator, conn: *transport.Connection, storage: *storage_ns.Storage) !void {
    while (true) {
        var msg = conn.recvMessage() catch |err| {
            if (err == error.ConnectionClosed) break;
            return err;
        };
        defer msg.deinit(allocator);
        switch (msg) {
            .record => |record_msg| {
                try storage.put(record_msg.record_bytes);
                continue;
            },
            .submission_result => continue,
            .hello_ack => continue,
            else => break,
        }
    }
}

fn currentTimestamp() !timestamp_ns.Timestamp {
    const ms_i128 = std.time.milliTimestamp();
    const seconds = @as(u64, @intCast(@divTrunc(ms_i128, 1000)));
    const rem_ms = @rem(ms_i128, 1000);
    const nanos = @as(u32, @intCast(rem_ms * 1_000_000));
    return timestamp_ns.Timestamp.fromUnixTime(seconds, nanos);
}

pub fn parseReferences(allocator: Allocator, texts: [][]const u8) ![]protocol.Reference {
    const refs = try allocator.alloc(protocol.Reference, texts.len);
    errdefer allocator.free(refs);
    for (texts, 0..) |text, idx| {
        const raw = try printable.decodeReference(text);
        refs[idx] = .{ .bytes = raw };
    }
    return refs;
}

test "publish and timeline happy path" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("db");
    const db_path = try tmp.dir.realpathAlloc(allocator, "db");
    defer allocator.free(db_path);

    const mopub_example = "mopub03ctpjer5jfkd49rxe4767hk9ij6f8sdtryjnnru1bpwxhcykk54o";
    const mosec_example = "mosec06ayb687prmw8abtuum9bps5hjmfz5ffyft3b4jeznn3htppf3kto";

    var credentials = try Credentials.init(allocator, mopub_example, mosec_example);
    defer credentials = undefined;

    const override_ts = try timestamp_ns.Timestamp.fromNanoseconds(1_705_554_321_098_765_432);
    const payload = "integration test note";

    const preview_record = try record_builder.buildMicroblogRecord(allocator, .{
        .timestamp = override_ts,
        .signing_key = credentials.key_pair,
        .author_public_key = credentials.public_key,
        .payload = payload,
        .tags = &[_]record_builder.TagInput{},
        .address_nonce = null,
    });
    defer allocator.free(preview_record);

    var reference_bytes: [48]u8 = undefined;
    std.mem.copyForwards(u8, reference_bytes[0..], preview_record[0..48]);
    const reference_text = printable.encodeReference(reference_bytes);

    var apps_buf = [_]u32{0};
    var server = try mock_server.start(allocator, .{
        .expect = .{
            .versions = "0,1",
            .features = "chat",
            .authenticate_as = mopub_example,
        },
        .response = .{
            .version = "0",
            .features_accepted = "chat",
            .client_auth_nonce = "client-nonce",
            .hello_ack_result = protocol.ResultCode.success,
            .hello_ack_max_version = 0,
            .hello_ack_applications = apps_buf[0..],
        },
    });
    defer server.ensureStopped();

    var app = App{
        .allocator = allocator,
        .connect = .{
            .host = "127.0.0.1",
            .port = server.port(),
            .path = "/",
            .tls = false,
            .versions = "0,1",
            .features = "chat",
            .expected_subprotocol = "mosaic2025",
        },
        .storage_config = .{ .path = db_path, .map_size = 8 * 1024 * 1024 },
        .credentials = credentials,
        .storage = null,
    };
    defer app.deinit();

    var publish_output = std.ArrayList(u8){};
    defer publish_output.deinit(allocator);
    try app.publish(publish_output.writer(allocator), .{ .text = payload, .timestamp_override = override_ts });
    try std.testing.expect(std.mem.containsAtLeast(u8, publish_output.items, 1, "published"));
    try std.testing.expect(std.mem.containsAtLeast(u8, publish_output.items, 1, reference_text[0..]));

    const references_slice = try allocator.alloc([]const u8, 1);
    defer allocator.free(references_slice);
    references_slice[0] = reference_text[0..];
    const references = try parseReferences(allocator, references_slice);
    defer allocator.free(@constCast(references));

    var timeline_output = std.ArrayList(u8){};
    defer timeline_output.deinit(allocator);
    try app.timeline(timeline_output.writer(allocator), .{ .limit = 5, .references = references });
    try std.testing.expect(std.mem.containsAtLeast(u8, timeline_output.items, 1, payload));

    const server_result = try server.wait();
    try std.testing.expect(server_result.saw_versions);
    try std.testing.expect(server_result.saw_features);
    try std.testing.expect(server_result.saw_subprotocol);
    try std.testing.expect(server_result.saw_authenticate_as);
    try std.testing.expect(server_result.hello_auth_seen);
    try std.testing.expect(server_result.hello_auth_valid);
}
