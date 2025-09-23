const std = @import("std");
const lmdb = @import("lmdb");
const record_mod = @import("record.zig");

const Record = record_mod.Record;
const RecordError = record_mod.RecordError;

const ID_LEN = 48;
const ADDRESS_OFFSET = 48;
const ADDRESS_LEN = 48;
const TIMESTAMP_BYTES = 8;
const KIND_BYTES = 8;
const MAX_TIMESTAMP: u64 = 0x7fffffffffffffff;

const DB_RECORDS = "records";
const DB_ADDRESS = "idx_address";
const DB_KIND = "idx_kind";
const DB_TIMESTAMP = "idx_timestamp";

pub const Error = RecordError || lmdb.Error || std.mem.Allocator.Error || std.fs.Dir.MakeError || std.fs.Dir.StatFileError || error{
    InvalidKeyLength,
    DataCorruption,
};

pub const Storage = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    env: lmdb.Environment,

    pub const Options = struct {
        path: []const u8,
        map_size: usize = 64 * 1024 * 1024,
    };

    pub fn init(allocator: std.mem.Allocator, options: Options) Error!Self {
        try std.fs.cwd().makePath(options.path);
        var path_z = try allocator.allocSentinel(u8, options.path.len, 0);
        defer allocator.free(path_z);
        std.mem.copyForwards(u8, path_z[0..options.path.len], options.path);

        var env = try lmdb.Environment.init(path_z, .{
            .map_size = options.map_size,
            .max_dbs = 8,
            .max_readers = 128,
        });
        errdefer env.deinit();

        var storage = Self{
            .allocator = allocator,
            .env = env,
        };

        try storage.ensureDbs();
        return storage;
    }

    pub fn deinit(self: *Self) void {
        self.env.deinit();
        self.* = undefined;
    }

    pub fn put(self: *Self, record_bytes: []const u8) Error!void {
        const rec = try Record.fromBytes(record_bytes);
        var txn = try self.env.transaction(.{ .mode = .ReadWrite });
        errdefer txn.abort();

        var records_db = try txn.database(DB_RECORDS, .{ .create = true });
        var address_db = try txn.database(DB_ADDRESS, .{ .create = true });
        var kind_db = try txn.database(DB_KIND, .{ .create = true });
        var timestamp_db = try txn.database(DB_TIMESTAMP, .{ .create = true });

        const id_slice = rec.bytes[0..ID_LEN];

        if (try records_db.get(id_slice)) |existing_bytes| {
            const owned = try self.allocator.dupe(u8, existing_bytes);
            defer self.allocator.free(owned);
            const existing_rec = try Record.fromBytes(owned);
            try self.deindexRecord(&txn, existing_rec, &address_db, &kind_db, &timestamp_db);
        }

        try records_db.set(id_slice, record_bytes);
        try self.indexRecord(&txn, rec, &address_db, &kind_db, &timestamp_db);

        try txn.commit();
    }

    pub fn getById(self: *Self, allocator: std.mem.Allocator, id: []const u8) Error!?[]u8 {
        if (id.len != ID_LEN) return error.InvalidKeyLength;
        var txn = try self.env.transaction(.{ .mode = .ReadOnly });
        defer txn.abort();

        const records_db = try txn.database(DB_RECORDS, .{});
        if (try records_db.get(id)) |value| {
            return try allocator.dupe(u8, value);
        }
        return null;
    }

    pub fn delete(self: *Self, id: []const u8) Error!bool {
        if (id.len != ID_LEN) return error.InvalidKeyLength;
        var txn = try self.env.transaction(.{ .mode = .ReadWrite });
        errdefer txn.abort();

        var records_db = try txn.database(DB_RECORDS, .{});
        var address_db = try txn.database(DB_ADDRESS, .{});
        var kind_db = try txn.database(DB_KIND, .{});
        var timestamp_db = try txn.database(DB_TIMESTAMP, .{});

        const existing = try records_db.get(id) orelse return false;
        const owned = try self.allocator.dupe(u8, existing);
        defer self.allocator.free(owned);
        const existing_rec = try Record.fromBytes(owned);

        try self.deindexRecord(&txn, existing_rec, &address_db, &kind_db, &timestamp_db);
        try records_db.delete(id);
        try txn.commit();
        return true;
    }

    pub fn getByAddress(
        self: *Self,
        allocator: std.mem.Allocator,
        address: []const u8,
        limit: usize,
    ) Error!RecordList {
        if (address.len != ADDRESS_LEN) return error.InvalidKeyLength;
        if (limit == 0) return RecordList.empty(allocator);

        var txn = try self.env.transaction(.{ .mode = .ReadOnly });
        defer txn.abort();

        const address_db = try txn.database(DB_ADDRESS, .{});
        const records_db = try txn.database(DB_RECORDS, .{});

        var cursor = try address_db.cursor();
        defer cursor.deinit();

        var results = RecordListBuilder.init(allocator);
        errdefer results.deinit();

        var search_key: [ADDRESS_LEN + TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.copyForwards(u8, search_key[0..ADDRESS_LEN], address);
        @memset(search_key[ADDRESS_LEN .. ADDRESS_LEN + TIMESTAMP_BYTES], 0);
        @memset(search_key[ADDRESS_LEN + TIMESTAMP_BYTES ..], 0);

        var current = try cursor.seek(search_key[0..]);
        while (current) |key| {
            if (!std.mem.eql(u8, key[0..ADDRESS_LEN], address)) break;
            const record_id = try cursor.getCurrentValue();
            const owned_record = try copyRecord(allocator, records_db, record_id);
            try results.append(owned_record);
            if (results.len() >= limit) break;
            current = try cursor.goToNext();
        }

        return results.toList();
    }

    pub fn getByKind(
        self: *Self,
        allocator: std.mem.Allocator,
        kind: u64,
        since: u64,
        until: u64,
        limit: usize,
    ) Error!RecordList {
        if (limit == 0 or since > until) return RecordList.empty(allocator);

        var txn = try self.env.transaction(.{ .mode = .ReadOnly });
        defer txn.abort();

        const kind_db = try txn.database(DB_KIND, .{});
        const records_db = try txn.database(DB_RECORDS, .{});

        var cursor = try kind_db.cursor();
        defer cursor.deinit();

        var results = RecordListBuilder.init(allocator);
        errdefer results.deinit();

        var search_key: [KIND_BYTES + TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.writeInt(u64, search_key[0..KIND_BYTES], kind, .big);
        std.mem.writeInt(u64, search_key[KIND_BYTES .. KIND_BYTES + TIMESTAMP_BYTES], invertTimestamp(until), .big);
        @memset(search_key[KIND_BYTES + TIMESTAMP_BYTES ..], 0);

        var current = try cursor.seek(search_key[0..]);
        while (current) |key| {
            if (!std.mem.eql(u8, key[0..KIND_BYTES], search_key[0..KIND_BYTES])) break;
            const stored_ts = std.mem.readInt(u64, key[KIND_BYTES .. KIND_BYTES + TIMESTAMP_BYTES], .big);
            const actual_ts = invertTimestamp(stored_ts);
            if (actual_ts < since) break;
            const record_id = try cursor.getCurrentValue();
            const owned_record = try copyRecord(allocator, records_db, record_id);
            try results.append(owned_record);
            if (results.len() >= limit) break;
            current = try cursor.goToNext();
        }

        return results.toList();
    }

    pub fn getByTimestamp(
        self: *Self,
        allocator: std.mem.Allocator,
        since: u64,
        until: u64,
        limit: usize,
    ) Error!RecordList {
        if (limit == 0 or since > until) return RecordList.empty(allocator);

        var txn = try self.env.transaction(.{ .mode = .ReadOnly });
        defer txn.abort();

        const timestamp_db = try txn.database(DB_TIMESTAMP, .{});
        const records_db = try txn.database(DB_RECORDS, .{});

        var cursor = try timestamp_db.cursor();
        defer cursor.deinit();

        var results = RecordListBuilder.init(allocator);
        errdefer results.deinit();

        var search_key: [TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.writeInt(u64, search_key[0..TIMESTAMP_BYTES], invertTimestamp(until), .big);
        @memset(search_key[TIMESTAMP_BYTES..], 0);

        var current = try cursor.seek(search_key[0..]);
        while (current) |key| {
            const stored_ts = std.mem.readInt(u64, key[0..TIMESTAMP_BYTES], .big);
            const actual_ts = invertTimestamp(stored_ts);
            if (actual_ts < since) break;
            const record_id = try cursor.getCurrentValue();
            const owned_record = try copyRecord(allocator, records_db, record_id);
            try results.append(owned_record);
            if (results.len() >= limit) break;
            current = try cursor.goToNext();
        }

        return results.toList();
    }

    fn ensureDbs(self: *Self) Error!void {
        var txn = try self.env.transaction(.{ .mode = .ReadWrite });
        errdefer txn.abort();
        _ = try txn.database(DB_RECORDS, .{ .create = true });
        _ = try txn.database(DB_ADDRESS, .{ .create = true });
        _ = try txn.database(DB_KIND, .{ .create = true });
        _ = try txn.database(DB_TIMESTAMP, .{ .create = true });
        try txn.commit();
    }

    fn indexRecord(
        self: *Self,
        txn: *lmdb.Transaction,
        rec: Record,
        address_db: *lmdb.Database,
        kind_db: *lmdb.Database,
        timestamp_db: *lmdb.Database,
    ) Error!void {
        _ = self;
        _ = txn;
        const id_slice = rec.bytes[0..ID_LEN];
        const timestamp = rec.timestamp();

        var ts_key: [TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.writeInt(u64, ts_key[0..TIMESTAMP_BYTES], invertTimestamp(timestamp), .big);
        std.mem.copyForwards(u8, ts_key[TIMESTAMP_BYTES..], id_slice);
        try timestamp_db.set(ts_key[0..], id_slice);

        var address_key: [ADDRESS_LEN + TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.copyForwards(u8, address_key[0..ADDRESS_LEN], rec.bytes[ADDRESS_OFFSET .. ADDRESS_OFFSET + ADDRESS_LEN]);
        std.mem.writeInt(u64, address_key[ADDRESS_LEN .. ADDRESS_LEN + TIMESTAMP_BYTES], invertTimestamp(timestamp), .big);
        std.mem.copyForwards(u8, address_key[ADDRESS_LEN + TIMESTAMP_BYTES ..], id_slice);
        try address_db.set(address_key[0..], id_slice);

        var kind_key: [KIND_BYTES + TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.writeInt(u64, kind_key[0..KIND_BYTES], rec.kind(), .big);
        std.mem.writeInt(u64, kind_key[KIND_BYTES .. KIND_BYTES + TIMESTAMP_BYTES], invertTimestamp(timestamp), .big);
        std.mem.copyForwards(u8, kind_key[KIND_BYTES + TIMESTAMP_BYTES ..], id_slice);
        try kind_db.set(kind_key[0..], id_slice);
    }

    fn deindexRecord(
        self: *Self,
        txn: *lmdb.Transaction,
        rec: Record,
        address_db: *lmdb.Database,
        kind_db: *lmdb.Database,
        timestamp_db: *lmdb.Database,
    ) Error!void {
        _ = self;
        _ = txn;
        const id_slice = rec.bytes[0..ID_LEN];
        const timestamp = rec.timestamp();

        var ts_key: [TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.writeInt(u64, ts_key[0..TIMESTAMP_BYTES], invertTimestamp(timestamp), .big);
        std.mem.copyForwards(u8, ts_key[TIMESTAMP_BYTES..], id_slice);
        try timestamp_db.delete(ts_key[0..]);

        var address_key: [ADDRESS_LEN + TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.copyForwards(u8, address_key[0..ADDRESS_LEN], rec.bytes[ADDRESS_OFFSET .. ADDRESS_OFFSET + ADDRESS_LEN]);
        std.mem.writeInt(u64, address_key[ADDRESS_LEN .. ADDRESS_LEN + TIMESTAMP_BYTES], invertTimestamp(timestamp), .big);
        std.mem.copyForwards(u8, address_key[ADDRESS_LEN + TIMESTAMP_BYTES ..], id_slice);
        try address_db.delete(address_key[0..]);

        var kind_key: [KIND_BYTES + TIMESTAMP_BYTES + ID_LEN]u8 = undefined;
        std.mem.writeInt(u64, kind_key[0..KIND_BYTES], rec.kind(), .big);
        std.mem.writeInt(u64, kind_key[KIND_BYTES .. KIND_BYTES + TIMESTAMP_BYTES], invertTimestamp(timestamp), .big);
        std.mem.copyForwards(u8, kind_key[KIND_BYTES + TIMESTAMP_BYTES ..], id_slice);
        try kind_db.delete(kind_key[0..]);
    }
};

pub const OwnedRecord = struct {
    bytes: []u8,

    pub fn slice(self: OwnedRecord) []const u8 {
        return self.bytes;
    }
};

pub const RecordList = struct {
    allocator: std.mem.Allocator,
    items: []OwnedRecord,

    pub fn empty(allocator: std.mem.Allocator) RecordList {
        return .{ .allocator = allocator, .items = &[_]OwnedRecord{} };
    }

    pub fn deinit(self: RecordList) void {
        for (self.items) |item| {
            self.allocator.free(item.bytes);
        }
        if (self.items.len > 0) self.allocator.free(self.items);
    }
};

const RecordListBuilder = struct {
    allocator: std.mem.Allocator,
    list: std.ArrayList(OwnedRecord),

    fn init(allocator: std.mem.Allocator) RecordListBuilder {
        return .{ .allocator = allocator, .list = .{} };
    }

    fn append(self: *RecordListBuilder, bytes: []u8) !void {
        try self.list.append(self.allocator, .{ .bytes = bytes });
    }

    fn len(self: RecordListBuilder) usize {
        return self.list.items.len;
    }

    fn toList(self: *RecordListBuilder) !RecordList {
        const items = try self.list.toOwnedSlice(self.allocator);
        return .{ .allocator = self.allocator, .items = items };
    }

    fn deinit(self: *RecordListBuilder) void {
        for (self.list.items) |item| {
            self.allocator.free(item.bytes);
        }
        self.list.deinit(self.allocator);
    }
};

fn copyRecord(allocator: std.mem.Allocator, db: lmdb.Database, id: []const u8) Error![]u8 {
    const value = try db.get(id) orelse return error.DataCorruption;
    return allocator.dupe(u8, value);
}

inline fn invertTimestamp(timestamp: u64) u64 {
    std.debug.assert(timestamp <= MAX_TIMESTAMP);
    return MAX_TIMESTAMP - timestamp;
}

test "storage put and fetch by id" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("db");
    const db_path = try tmp.dir.realpathAlloc(allocator, "db");
    defer allocator.free(db_path);

    var storage = try Storage.init(allocator, .{ .path = db_path });
    defer storage.deinit();

    const record_bytes = try loadTestRecord(allocator);
    defer allocator.free(record_bytes);

    try storage.put(record_bytes);

    const maybe = try storage.getById(allocator, record_bytes[0..ID_LEN]);
    defer if (maybe) |value| allocator.free(value);
    try std.testing.expect(maybe != null);
    try std.testing.expectEqualSlices(u8, record_bytes, maybe.?);
}

test "storage indexes by address kind timestamp" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("db");
    const db_path = try tmp.dir.realpathAlloc(allocator, "db");
    defer allocator.free(db_path);

    var storage = try Storage.init(allocator, .{ .path = db_path });
    defer storage.deinit();

    const record_bytes = try loadTestRecord(allocator);
    defer allocator.free(record_bytes);
    const rec = try Record.fromBytes(record_bytes);

    try storage.put(record_bytes);

    var by_address = try storage.getByAddress(allocator, rec.bytes[ADDRESS_OFFSET .. ADDRESS_OFFSET + ADDRESS_LEN], 5);
    defer by_address.deinit();
    try std.testing.expectEqual(@as(usize, 1), by_address.items.len);
    try std.testing.expectEqualSlices(u8, record_bytes, by_address.items[0].bytes);

    var by_kind = try storage.getByKind(allocator, rec.kind(), rec.timestamp(), rec.timestamp(), 5);
    defer by_kind.deinit();
    try std.testing.expectEqual(@as(usize, 1), by_kind.items.len);
    try std.testing.expectEqualSlices(u8, record_bytes, by_kind.items[0].bytes);

    var by_timestamp = try storage.getByTimestamp(allocator, rec.timestamp(), rec.timestamp(), 5);
    defer by_timestamp.deinit();
    try std.testing.expectEqual(@as(usize, 1), by_timestamp.items.len);
    try std.testing.expectEqualSlices(u8, record_bytes, by_timestamp.items[0].bytes);
}

test "storage delete removes indexes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("db");
    const db_path = try tmp.dir.realpathAlloc(allocator, "db");
    defer allocator.free(db_path);

    var storage = try Storage.init(allocator, .{ .path = db_path });
    defer storage.deinit();

    const record_bytes = try loadTestRecord(allocator);
    defer allocator.free(record_bytes);

    try storage.put(record_bytes);
    const deleted = try storage.delete(record_bytes[0..ID_LEN]);
    try std.testing.expect(deleted);

    const maybe = try storage.getById(allocator, record_bytes[0..ID_LEN]);
    defer if (maybe) |value| allocator.free(value);
    try std.testing.expect(maybe == null);
}

test "storage queries return newest records first" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("db");
    const db_path = try tmp.dir.realpathAlloc(allocator, "db");
    defer allocator.free(db_path);

    var storage = try Storage.init(allocator, .{ .path = db_path });
    defer storage.deinit();

    const record_hexes = [_][]const u8{
        "000000630001001cabddc2ef3be7fe4ab2948aa0c343fcf602d0367c26f7fba0857630265ee1e10439a28158e933e502f1e0a99173564931000000630001001c8bb8fc870c6fe2495464f31c5000201c05a42c08e5c19c542cab41613e71e3998bb8fc870c6fe2495464f31c5000201c05a42c08e5c19c542cab41613e71e399000000630001001c0000000000000000000040000b00000068656c6c6f20776f726c640000000000e0536c568c38f2e14d31caa086cc1700dcb280c2d502d5ec313870e3d5713b5e4d79f4e0492c95ef9187f1287f3677911c9790a81b052345fe219827dcf16406",
        "000000630010425ca583635b9f310d30c676c68d01e9d07aeb6ab794a392f19cd8ac5f43241bd60619269e3a97139518f1e0a99173564931000000630001001c8bb8fc870c6fe2495464f31c5000201c05a42c08e5c19c542cab41613e71e3998bb8fc870c6fe2495464f31c5000201c05a42c08e5c19c542cab41613e71e399000000630010425c0000000000000000000040000d0000006e65776572207061796c6f616400000029fc29549ea6a2d727a8639aaf7096c868564c7a03c705fd6cf5133921de70c3e3eceed73eee2a608597db92a0649ecce0a7266ed54e10eb6a341595e5c3a707",
        "00000063001f849c7f26a75a8640c7724af3339d2de60d5bd023f468b6eda8011d41bad384a3c8f9e4cdb4af397fe312f1e0a99173564931000000630001001c8bb8fc870c6fe2495464f31c5000201c05a42c08e5c19c542cab41613e71e3998bb8fc870c6fe2495464f31c5000201c05a42c08e5c19c542cab41613e71e39900000063001f849c0000000000000000000040000e0000006e6577657374207061796c6f6164000081ac5df4ea86612e7e81afafb575cee0eb375500f601d425fbffbf0033721b7b515784cc45c76216e316c9fee71896275aa7f0f8f87aaf88e470fed1c86be00b",
    };

    var record_bytes: [record_hexes.len][]u8 = undefined;
    defer {
        for (record_bytes) |bytes| {
            allocator.free(bytes);
        }
    }

    inline for (record_hexes, 0..) |hex, idx| {
        const bytes = try hexToBytesAlloc(allocator, hex);
        record_bytes[idx] = bytes;
        try storage.put(bytes);
    }

    const rec0 = try Record.fromBytes(record_bytes[0]);
    const rec2 = try Record.fromBytes(record_bytes[2]);

    var by_address = try storage.getByAddress(
        allocator,
        rec0.bytes[ADDRESS_OFFSET .. ADDRESS_OFFSET + ADDRESS_LEN],
        3,
    );
    defer by_address.deinit();
    try std.testing.expectEqual(@as(usize, 3), by_address.items.len);
    try std.testing.expectEqualSlices(u8, record_bytes[2], by_address.items[0].bytes);
    try std.testing.expectEqualSlices(u8, record_bytes[1], by_address.items[1].bytes);
    try std.testing.expectEqualSlices(u8, record_bytes[0], by_address.items[2].bytes);

    var by_kind = try storage.getByKind(
        allocator,
        rec0.kind(),
        rec0.timestamp(),
        rec2.timestamp(),
        3,
    );
    defer by_kind.deinit();
    try std.testing.expectEqual(@as(usize, 3), by_kind.items.len);
    try std.testing.expectEqualSlices(u8, record_bytes[2], by_kind.items[0].bytes);
    try std.testing.expectEqualSlices(u8, record_bytes[1], by_kind.items[1].bytes);
    try std.testing.expectEqualSlices(u8, record_bytes[0], by_kind.items[2].bytes);

    var by_timestamp = try storage.getByTimestamp(
        allocator,
        rec0.timestamp(),
        rec2.timestamp(),
        3,
    );
    defer by_timestamp.deinit();
    try std.testing.expectEqual(@as(usize, 3), by_timestamp.items.len);
    try std.testing.expectEqualSlices(u8, record_bytes[2], by_timestamp.items[0].bytes);
    try std.testing.expectEqualSlices(u8, record_bytes[1], by_timestamp.items[1].bytes);
    try std.testing.expectEqualSlices(u8, record_bytes[0], by_timestamp.items[2].bytes);
}

fn loadTestRecord(allocator: std.mem.Allocator) ![]u8 {
    const json_bytes = try std.fs.cwd().readFileAlloc(allocator, "testdata/test_vectors.json", 1 << 20);
    defer allocator.free(json_bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    defer parsed.deinit();

    const record_hex_value = parsed.value.object.get("record").?.object.get("record_hex").?;
    const record_hex = record_hex_value.string;
    return hexToBytesAlloc(allocator, record_hex);
}

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidKeyLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}
