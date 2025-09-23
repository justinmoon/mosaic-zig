const std = @import("std");
const record_mod = @import("record.zig");

pub const Record = record_mod.Record;
pub const RecordError = record_mod.RecordError;

pub const MessageType = enum(u8) {
    hello = 0x10,
    hello_ack = 0x90,
    get = 0x01,
    submission = 0x05,
    record = 0x80,
    submission_result = 0x83,

    pub fn fromByte(byte: u8) !MessageType {
        return switch (byte) {
            0x10 => .hello,
            0x90 => .hello_ack,
            0x01 => .get,
            0x05 => .submission,
            0x80 => .record,
            0x83 => .submission_result,
            else => error.UnknownMessageType,
        };
    }
};

pub const ResultCode = enum(u8) {
    undefined = 0,
    success = 1,
    accepted = 2,
    duplicate = 3,
    no_consumers = 4,
    not_found = 16,
    requires_authentication = 32,
    unauthorized = 33,
    invalid = 36,
    too_open = 37,
    too_large = 38,
    too_fast = 39,
    ip_temp_banned = 48,
    ip_perm_banned = 49,
    pubkey_temp_banned = 50,
    pubkey_perm_banned = 51,
    shutting_down = 64,
    temporary_error = 65,
    persistent_error = 66,
    general_error = 67,

    pub fn fromByte(byte: u8) !ResultCode {
        const code = std.meta.intToEnum(ResultCode, byte) catch return error.UnknownResultCode;
        if (code == .undefined) return error.InvalidResultCode;
        return code;
    }
};

pub const MessageError = error{
    TooShort,
    LengthMismatch,
    ReservedBitsSet,
    InvalidApplicationBytes,
    InvalidReferenceLength,
    InvalidIdPrefix,
    MessageTooLong,
    UnknownMessageType,
    UnknownResultCode,
    InvalidResultCode,
} || RecordError || std.mem.Allocator.Error;

pub const Reference = struct {
    bytes: [48]u8,

    pub fn isId(self: Reference) bool {
        return (self.bytes[0] & 0x80) == 0;
    }

    pub fn isAddress(self: Reference) bool {
        return !self.isId();
    }
};

pub const QueryId = struct {
    bytes: [2]u8,

    pub fn init(raw: [2]u8) QueryId {
        return QueryId{ .bytes = raw };
    }

    pub fn fromInt(value: u16) QueryId {
        var raw: [2]u8 = undefined;
        std.mem.writeInt(u16, raw[0..], value, .little);
        return QueryId{ .bytes = raw };
    }

    pub fn toInt(self: QueryId) u16 {
        return std.mem.readInt(u16, self.bytes[0..], .little);
    }
};

pub const Hello = struct {
    max_version: u8,
    applications: []u32,

    pub fn deinit(self: *Hello, allocator: std.mem.Allocator) void {
        if (self.applications.len != 0) allocator.free(self.applications);
    }
};

pub const HelloAck = struct {
    result: ResultCode,
    max_version: u8,
    applications: []u32,

    pub fn deinit(self: *HelloAck, allocator: std.mem.Allocator) void {
        if (self.applications.len != 0) allocator.free(self.applications);
    }
};

pub const Get = struct {
    query_id: QueryId,
    references: []Reference,

    pub fn deinit(self: *Get, allocator: std.mem.Allocator) void {
        if (self.references.len != 0) allocator.free(self.references);
    }
};

pub const Submission = struct {
    record_bytes: []u8,
    record: Record,

    pub fn deinit(self: *Submission, allocator: std.mem.Allocator) void {
        if (self.record_bytes.len != 0) allocator.free(self.record_bytes);
    }
};

pub const RecordMessage = struct {
    query_id: QueryId,
    record_bytes: []u8,
    record: Record,

    pub fn deinit(self: *RecordMessage, allocator: std.mem.Allocator) void {
        if (self.record_bytes.len != 0) allocator.free(self.record_bytes);
    }
};

pub const SubmissionResult = struct {
    result: ResultCode,
    id_prefix: [32]u8,
};

fn readU32le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 4);
    return @as(u32, bytes[0]) | (@as(u32, bytes[1]) << 8) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 24);
}

fn writeU32le(dest: []u8, value: u32) void {
    std.debug.assert(dest.len == 4);
    dest[0] = @truncate(value);
    dest[1] = @truncate(value >> 8);
    dest[2] = @truncate(value >> 16);
    dest[3] = @truncate(value >> 24);
}

pub const Message = union(enum) {
    hello: Hello,
    hello_ack: HelloAck,
    get: Get,
    submission: Submission,
    record: RecordMessage,
    submission_result: SubmissionResult,

    pub fn messageType(self: Message) MessageType {
        return switch (self) {
            .hello => .hello,
            .hello_ack => .hello_ack,
            .get => .get,
            .submission => .submission,
            .record => .record,
            .submission_result => .submission_result,
        };
    }

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .hello => |*msg| msg.deinit(allocator),
            .hello_ack => |*msg| msg.deinit(allocator),
            .get => |*msg| msg.deinit(allocator),
            .submission => |*msg| msg.deinit(allocator),
            .record => |*msg| msg.deinit(allocator),
            .submission_result => {},
        }
    }
};

pub fn decodeMessage(allocator: std.mem.Allocator, bytes: []const u8) MessageError!Message {
    if (bytes.len < 8) return error.TooShort;

    const encoded_len = readU32le(bytes[4..8]);
    const total_len: usize = @intCast(encoded_len);
    if (total_len != bytes.len) return error.LengthMismatch;

    const msg_type = try MessageType.fromByte(bytes[0]);

    return switch (msg_type) {
        .hello => try decodeHello(allocator, bytes),
        .hello_ack => try decodeHelloAck(allocator, bytes),
        .get => try decodeGet(allocator, bytes),
        .submission => try decodeSubmission(allocator, bytes),
        .record => try decodeRecord(allocator, bytes),
        .submission_result => try decodeSubmissionResult(bytes),
    };
}

fn decodeHello(allocator: std.mem.Allocator, bytes: []const u8) MessageError!Message {
    if (bytes[1] != 0 or bytes[2] != 0) return error.ReservedBitsSet;
    const payload_len = bytes.len - 8;
    if (payload_len % 4 != 0) return error.InvalidApplicationBytes;
    const count = payload_len / 4;
    var applications = try allocator.alloc(u32, count);
    errdefer if (applications.len != 0) allocator.free(applications);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const start = 8 + i * 4;
        applications[i] = readU32le(bytes[start .. start + 4]);
    }

    return Message{ .hello = .{
        .max_version = bytes[3],
        .applications = applications,
    } };
}

fn decodeHelloAck(allocator: std.mem.Allocator, bytes: []const u8) MessageError!Message {
    const result = try ResultCode.fromByte(bytes[1]);
    if (bytes[2] != 0) return error.ReservedBitsSet;
    const payload_len = bytes.len - 8;
    if (payload_len % 4 != 0) return error.InvalidApplicationBytes;
    const count = payload_len / 4;
    var applications = try allocator.alloc(u32, count);
    errdefer if (applications.len != 0) allocator.free(applications);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const start = 8 + i * 4;
        applications[i] = readU32le(bytes[start .. start + 4]);
    }

    return Message{ .hello_ack = .{
        .result = result,
        .max_version = bytes[3],
        .applications = applications,
    } };
}

fn decodeGet(allocator: std.mem.Allocator, bytes: []const u8) MessageError!Message {
    if (bytes[1] != 0) return error.ReservedBitsSet;
    const payload_len = bytes.len - 8;
    if (payload_len % 48 != 0) return error.InvalidReferenceLength;
    const count = payload_len / 48;
    var references = try allocator.alloc(Reference, count);
    errdefer if (references.len != 0) allocator.free(references);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const start = 8 + i * 48;
        std.mem.copyForwards(u8, references[i].bytes[0..], bytes[start .. start + 48]);
    }

    const query_id = QueryId.init(.{ bytes[2], bytes[3] });
    return Message{ .get = .{
        .query_id = query_id,
        .references = references,
    } };
}

fn decodeSubmission(allocator: std.mem.Allocator, bytes: []const u8) MessageError!Message {
    if (bytes[1] != 0 or bytes[2] != 0 or bytes[3] != 0) return error.ReservedBitsSet;
    const payload_len = bytes.len - 8;
    const record_bytes = try allocator.alloc(u8, payload_len);
    errdefer if (record_bytes.len != 0) allocator.free(record_bytes);
    std.mem.copyForwards(u8, record_bytes, bytes[8..]);
    const rec = try record_mod.Record.fromBytes(record_bytes);
    return Message{ .submission = .{
        .record_bytes = record_bytes,
        .record = rec,
    } };
}

fn decodeRecord(allocator: std.mem.Allocator, bytes: []const u8) MessageError!Message {
    if (bytes[1] != 0) return error.ReservedBitsSet;
    const payload_len = bytes.len - 8;
    const record_bytes = try allocator.alloc(u8, payload_len);
    errdefer if (record_bytes.len != 0) allocator.free(record_bytes);
    std.mem.copyForwards(u8, record_bytes, bytes[8..]);
    const rec = try record_mod.Record.fromBytes(record_bytes);
    const query_id = QueryId.init(.{ bytes[2], bytes[3] });
    return Message{ .record = .{
        .query_id = query_id,
        .record_bytes = record_bytes,
        .record = rec,
    } };
}

fn decodeSubmissionResult(bytes: []const u8) MessageError!Message {
    const result = try ResultCode.fromByte(bytes[1]);
    if (bytes[2] != 0 or bytes[3] != 0) return error.ReservedBitsSet;
    if (bytes.len != 40) return error.LengthMismatch;

    var id_prefix: [32]u8 = undefined;
    std.mem.copyForwards(u8, id_prefix[0..], bytes[8..40]);
    if ((id_prefix[0] & 0x80) != 0) return error.InvalidIdPrefix;

    return Message{ .submission_result = .{
        .result = result,
        .id_prefix = id_prefix,
    } };
}

pub fn encodeMessage(allocator: std.mem.Allocator, message: Message) MessageError![]u8 {
    return switch (message) {
        .hello => |hello| try encodeHello(allocator, hello),
        .hello_ack => |hello_ack| try encodeHelloAck(allocator, hello_ack),
        .get => |get| try encodeGet(allocator, get),
        .submission => |submission| try encodeSubmission(allocator, submission),
        .record => |record_msg| try encodeRecordMsg(allocator, record_msg),
        .submission_result => |result| try encodeSubmissionResult(allocator, result),
    };
}

fn encodeHello(allocator: std.mem.Allocator, hello: Hello) MessageError![]u8 {
    const payload_bytes = std.math.mul(usize, hello.applications.len, 4) catch return error.MessageTooLong;
    const total_len = 8 + payload_bytes;
    const len_u32 = std.math.cast(u32, total_len) orelse return error.MessageTooLong;

    var out = try allocator.alloc(u8, total_len);
    out[0] = @intFromEnum(MessageType.hello);
    out[1] = 0;
    out[2] = 0;
    out[3] = hello.max_version;
    writeU32le(out[4..8], len_u32);

    var i: usize = 0;
    while (i < hello.applications.len) : (i += 1) {
        const start = 8 + i * 4;
        writeU32le(out[start .. start + 4], hello.applications[i]);
    }

    return out;
}

fn encodeHelloAck(allocator: std.mem.Allocator, hello_ack: HelloAck) MessageError![]u8 {
    const payload_bytes = std.math.mul(usize, hello_ack.applications.len, 4) catch return error.MessageTooLong;
    const total_len = 8 + payload_bytes;
    const len_u32 = std.math.cast(u32, total_len) orelse return error.MessageTooLong;

    var out = try allocator.alloc(u8, total_len);
    out[0] = @intFromEnum(MessageType.hello_ack);
    out[1] = @intFromEnum(hello_ack.result);
    out[2] = 0;
    out[3] = hello_ack.max_version;
    writeU32le(out[4..8], len_u32);

    var i: usize = 0;
    while (i < hello_ack.applications.len) : (i += 1) {
        const start = 8 + i * 4;
        writeU32le(out[start .. start + 4], hello_ack.applications[i]);
    }

    return out;
}

fn encodeGet(allocator: std.mem.Allocator, get: Get) MessageError![]u8 {
    const payload_bytes = std.math.mul(usize, get.references.len, 48) catch return error.MessageTooLong;
    const total_len = 8 + payload_bytes;
    const len_u32 = std.math.cast(u32, total_len) orelse return error.MessageTooLong;

    var out = try allocator.alloc(u8, total_len);
    out[0] = @intFromEnum(MessageType.get);
    out[1] = 0;
    std.mem.copyForwards(u8, out[2..4], get.query_id.bytes[0..]);
    writeU32le(out[4..8], len_u32);

    var i: usize = 0;
    while (i < get.references.len) : (i += 1) {
        const start = 8 + i * 48;
        std.mem.copyForwards(u8, out[start .. start + 48], get.references[i].bytes[0..]);
    }

    return out;
}

fn encodeSubmission(allocator: std.mem.Allocator, submission: Submission) MessageError![]u8 {
    const total_len = 8 + submission.record_bytes.len;
    const len_u32 = std.math.cast(u32, total_len) orelse return error.MessageTooLong;

    var out = try allocator.alloc(u8, total_len);
    out[0] = @intFromEnum(MessageType.submission);
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    writeU32le(out[4..8], len_u32);
    std.mem.copyForwards(u8, out[8..], submission.record_bytes);
    return out;
}

fn encodeRecordMsg(allocator: std.mem.Allocator, record_msg: RecordMessage) MessageError![]u8 {
    const total_len = 8 + record_msg.record_bytes.len;
    const len_u32 = std.math.cast(u32, total_len) orelse return error.MessageTooLong;

    var out = try allocator.alloc(u8, total_len);
    out[0] = @intFromEnum(MessageType.record);
    out[1] = 0;
    std.mem.copyForwards(u8, out[2..4], record_msg.query_id.bytes[0..]);
    writeU32le(out[4..8], len_u32);
    std.mem.copyForwards(u8, out[8..], record_msg.record_bytes);
    return out;
}

fn encodeSubmissionResult(allocator: std.mem.Allocator, result: SubmissionResult) MessageError![]u8 {
    const total_len: usize = 40;
    const len_u32 = std.math.cast(u32, total_len) orelse return error.MessageTooLong;

    var out = try allocator.alloc(u8, total_len);
    out[0] = @intFromEnum(MessageType.submission_result);
    out[1] = @intFromEnum(result.result);
    out[2] = 0;
    out[3] = 0;
    writeU32le(out[4..8], len_u32);
    std.mem.copyForwards(u8, out[8..40], result.id_prefix[0..]);
    return out;
}

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn loadProtocolFrame(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
    const frames_json = try std.fs.cwd().readFileAlloc(allocator, "testdata/protocol_frames.json", 1 << 20);
    defer allocator.free(frames_json);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, frames_json, .{});
    defer parsed.deinit();

    const hex = parsed.value.object.get(key).?.string;
    const bytes = try hexToBytesAlloc(allocator, hex);
    errdefer allocator.free(bytes);
    return bytes;
}

test "protocol framing round trips golden frames" {
    const gpa = std.testing.allocator;
    const frames_json = try std.fs.cwd().readFileAlloc(gpa, "testdata/protocol_frames.json", 1 << 20);
    defer gpa.free(frames_json);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, frames_json, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;

    const record_json = try std.fs.cwd().readFileAlloc(gpa, "testdata/test_vectors.json", 1 << 20);
    defer gpa.free(record_json);
    var record_parsed = try std.json.parseFromSlice(std.json.Value, gpa, record_json, .{});
    defer record_parsed.deinit();
    const record_hex = record_parsed.value.object.get("record").?.object.get("record_hex").?.string;
    const record_bytes = try hexToBytesAlloc(gpa, record_hex);
    defer gpa.free(record_bytes);

    const expected_id = record_bytes[0..48];
    const expected_address = record_bytes[48..96];
    var expected_id_prefix: [32]u8 = undefined;
    std.mem.copyForwards(u8, expected_id_prefix[0..], record_bytes[0..32]);

    const hello_hex = obj.get("hello").?.string;
    const hello_bytes = try hexToBytesAlloc(gpa, hello_hex);
    defer gpa.free(hello_bytes);
    var hello_msg = try decodeMessage(gpa, hello_bytes);
    defer hello_msg.deinit(gpa);
    try std.testing.expectEqual(MessageType.hello, hello_msg.messageType());
    const hello = hello_msg.hello;
    try std.testing.expectEqual(@as(u8, 5), hello.max_version);
    try std.testing.expectEqual(@as(usize, 3), hello.applications.len);
    try std.testing.expectEqual(@as(u32, 0), hello.applications[0]);
    try std.testing.expectEqual(@as(u32, 1), hello.applications[1]);
    try std.testing.expectEqual(@as(u32, 99), hello.applications[2]);
    const hello_encoded = try encodeMessage(gpa, hello_msg);
    defer gpa.free(hello_encoded);
    try std.testing.expectEqualSlices(u8, hello_bytes, hello_encoded);

    const hello_ack_hex = obj.get("hello_ack").?.string;
    const hello_ack_bytes = try hexToBytesAlloc(gpa, hello_ack_hex);
    defer gpa.free(hello_ack_bytes);
    var hello_ack_msg = try decodeMessage(gpa, hello_ack_bytes);
    defer hello_ack_msg.deinit(gpa);
    try std.testing.expectEqual(MessageType.hello_ack, hello_ack_msg.messageType());
    const hello_ack = hello_ack_msg.hello_ack;
    try std.testing.expectEqual(ResultCode.success, hello_ack.result);
    try std.testing.expectEqual(@as(u8, 5), hello_ack.max_version);
    try std.testing.expectEqual(@as(usize, 2), hello_ack.applications.len);
    try std.testing.expectEqual(@as(u32, 0), hello_ack.applications[0]);
    try std.testing.expectEqual(@as(u32, 1), hello_ack.applications[1]);
    const hello_ack_encoded = try encodeMessage(gpa, hello_ack_msg);
    defer gpa.free(hello_ack_encoded);
    try std.testing.expectEqualSlices(u8, hello_ack_bytes, hello_ack_encoded);

    const get_hex = obj.get("get").?.string;
    const get_bytes = try hexToBytesAlloc(gpa, get_hex);
    defer gpa.free(get_bytes);
    var get_msg = try decodeMessage(gpa, get_bytes);
    defer get_msg.deinit(gpa);
    try std.testing.expectEqual(MessageType.get, get_msg.messageType());
    const get = get_msg.get;
    try std.testing.expectEqual(@as(u16, 0x1234), get.query_id.toInt());
    try std.testing.expectEqual(@as(usize, 2), get.references.len);
    try std.testing.expectEqualSlices(u8, expected_id, get.references[0].bytes[0..]);
    try std.testing.expectEqualSlices(u8, expected_address, get.references[1].bytes[0..]);
    const get_encoded = try encodeMessage(gpa, get_msg);
    defer gpa.free(get_encoded);
    try std.testing.expectEqualSlices(u8, get_bytes, get_encoded);

    const submission_hex = obj.get("submission").?.string;
    const submission_bytes = try hexToBytesAlloc(gpa, submission_hex);
    defer gpa.free(submission_bytes);
    var submission_msg = try decodeMessage(gpa, submission_bytes);
    defer submission_msg.deinit(gpa);
    try std.testing.expectEqual(MessageType.submission, submission_msg.messageType());
    const submission = submission_msg.submission;
    try std.testing.expectEqualSlices(u8, record_bytes, submission.record_bytes);
    const submission_encoded = try encodeMessage(gpa, submission_msg);
    defer gpa.free(submission_encoded);
    try std.testing.expectEqualSlices(u8, submission_bytes, submission_encoded);

    const record_hex_msg = obj.get("record").?.string;
    const record_bytes_msg = try hexToBytesAlloc(gpa, record_hex_msg);
    defer gpa.free(record_bytes_msg);
    var record_msg_union = try decodeMessage(gpa, record_bytes_msg);
    defer record_msg_union.deinit(gpa);
    try std.testing.expectEqual(MessageType.record, record_msg_union.messageType());
    const record_msg = record_msg_union.record;
    try std.testing.expectEqual(@as(u16, 0x1234), record_msg.query_id.toInt());
    try std.testing.expectEqualSlices(u8, record_bytes, record_msg.record_bytes);
    const record_encoded = try encodeMessage(gpa, record_msg_union);
    defer gpa.free(record_encoded);
    try std.testing.expectEqualSlices(u8, record_bytes_msg, record_encoded);

    const submission_result_hex = obj.get("submission_result").?.string;
    const submission_result_bytes = try hexToBytesAlloc(gpa, submission_result_hex);
    defer gpa.free(submission_result_bytes);
    var submission_result_msg = try decodeMessage(gpa, submission_result_bytes);
    defer submission_result_msg.deinit(gpa);
    try std.testing.expectEqual(MessageType.submission_result, submission_result_msg.messageType());
    const submission_result = submission_result_msg.submission_result;
    try std.testing.expectEqual(ResultCode.accepted, submission_result.result);
    try std.testing.expectEqualSlices(u8, expected_id_prefix[0..], submission_result.id_prefix[0..]);
    const submission_result_encoded = try encodeMessage(gpa, submission_result_msg);
    defer gpa.free(submission_result_encoded);
    try std.testing.expectEqualSlices(u8, submission_result_bytes, submission_result_encoded);
}

test "protocol decode rejects reserved bits in hello" {
    const gpa = std.testing.allocator;
    const hello_bytes = try loadProtocolFrame(gpa, "hello");
    defer gpa.free(hello_bytes);

    var mutated = try gpa.dupe(u8, hello_bytes);
    defer gpa.free(mutated);
    mutated[1] = 0x01;
    try std.testing.expectError(error.ReservedBitsSet, decodeMessage(gpa, mutated));
}

test "protocol decode rejects invalid application word count" {
    const gpa = std.testing.allocator;
    const hello_bytes = try loadProtocolFrame(gpa, "hello");
    defer gpa.free(hello_bytes);

    const new_len = hello_bytes.len - 2;
    var truncated = try gpa.alloc(u8, new_len);
    defer gpa.free(truncated);
    std.mem.copyForwards(u8, truncated, hello_bytes[0..new_len]);
    writeU32le(truncated[4..8], @intCast(new_len));
    try std.testing.expectError(error.InvalidApplicationBytes, decodeMessage(gpa, truncated));
}

test "protocol decode rejects invalid get reference length" {
    const gpa = std.testing.allocator;
    const get_bytes = try loadProtocolFrame(gpa, "get");
    defer gpa.free(get_bytes);

    const new_len = get_bytes.len - 1;
    var truncated = try gpa.alloc(u8, new_len);
    defer gpa.free(truncated);
    std.mem.copyForwards(u8, truncated, get_bytes[0..new_len]);
    writeU32le(truncated[4..8], @intCast(new_len));
    try std.testing.expectError(error.InvalidReferenceLength, decodeMessage(gpa, truncated));
}

test "protocol decode rejects submission_result reserved bits" {
    const gpa = std.testing.allocator;
    const result_bytes = try loadProtocolFrame(gpa, "submission_result");
    defer gpa.free(result_bytes);

    var mutated = try gpa.dupe(u8, result_bytes);
    defer gpa.free(mutated);
    mutated[2] = 0x01;
    try std.testing.expectError(error.ReservedBitsSet, decodeMessage(gpa, mutated));
}

test "protocol decode rejects submission_result id prefix with high bit" {
    const gpa = std.testing.allocator;
    const result_bytes = try loadProtocolFrame(gpa, "submission_result");
    defer gpa.free(result_bytes);

    var mutated = try gpa.dupe(u8, result_bytes);
    defer gpa.free(mutated);
    mutated[8] |= 0x80;
    try std.testing.expectError(error.InvalidIdPrefix, decodeMessage(gpa, mutated));
}

test "protocol decode rejects invalid result codes" {
    const gpa = std.testing.allocator;
    const hello_ack_bytes = try loadProtocolFrame(gpa, "hello_ack");
    defer gpa.free(hello_ack_bytes);

    var unknown = try gpa.dupe(u8, hello_ack_bytes);
    defer gpa.free(unknown);
    unknown[1] = 0xFF;
    try std.testing.expectError(error.UnknownResultCode, decodeMessage(gpa, unknown));

    var zero = try gpa.dupe(u8, hello_ack_bytes);
    defer gpa.free(zero);
    zero[1] = 0x00;
    try std.testing.expectError(error.InvalidResultCode, decodeMessage(gpa, zero));
}
