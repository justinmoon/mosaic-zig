const std = @import("std");
const z32 = @import("z32.zig");

pub const Error = error{
    InvalidPrefix,
    InvalidLength,
    InvalidChecksum,
} || z32.DecodeError;

fn encodedLen(comptime payload_len: usize) comptime_int {
    return if (payload_len == 0) 0 else (payload_len * 8 + 4) / 5;
}

fn decodeCapacity(comptime payload_len: usize) comptime_int {
    const encoded = encodedLen(payload_len);
    return if (encoded == 0) 0 else (encoded * 5 + 7) / 8;
}

fn decodeFixed(
    comptime prefix: []const u8,
    comptime payload_len: usize,
    text: []const u8,
) Error![payload_len]u8 {
    if (!std.mem.startsWith(u8, text, prefix)) {
        return error.InvalidPrefix;
    }

    const encoded = text[prefix.len..];
    const expected_len = encodedLen(payload_len);
    if (encoded.len != expected_len) {
        return error.InvalidLength;
    }

    const capacity = decodeCapacity(payload_len);
    var raw: [capacity]u8 = undefined;
    const decoded_len = try z32.decodeInto(raw[0..], encoded, null);
    if (decoded_len != payload_len) {
        return error.InvalidLength;
    }

    var out: [payload_len]u8 = undefined;
    @memcpy(out[0..], raw[0..payload_len]);

    // Re-encode to guard against silent truncation or mixed-case copies.
    var canonical: [expected_len]u8 = undefined;
    const rendered = z32.encodeInto(canonical[0..], out[0..]);
    if (!std.mem.eql(u8, rendered, encoded)) {
        return error.InvalidChecksum;
    }

    return out;
}

fn encodeFixed(
    comptime prefix: []const u8,
    comptime payload_len: usize,
    bytes: [payload_len]u8,
) [prefix.len + encodedLen(payload_len)]u8 {
    const encoded_len = encodedLen(payload_len);
    var out: [prefix.len + encoded_len]u8 = undefined;
    @memcpy(out[0..prefix.len], prefix);
    const encoded = z32.encodeInto(out[prefix.len..], bytes[0..]);
    std.debug.assert(encoded.len == encoded_len);
    return out;
}

pub fn decodeUserPublicKey(text: []const u8) Error![32]u8 {
    return decodeFixed("mopub0", 32, text);
}

pub fn encodeUserPublicKey(bytes: [32]u8) [58]u8 {
    return encodeFixed("mopub0", 32, bytes);
}

pub fn decodeServerPublicKey(text: []const u8) Error![32]u8 {
    return decodeFixed("mosrv0", 32, text);
}

pub fn encodeServerPublicKey(bytes: [32]u8) [58]u8 {
    return encodeFixed("mosrv0", 32, bytes);
}

pub fn decodeSecretKey(text: []const u8) Error![32]u8 {
    return decodeFixed("mosec0", 32, text);
}

pub fn encodeSecretKey(bytes: [32]u8) [58]u8 {
    return encodeFixed("mosec0", 32, bytes);
}

pub fn decodeReference(text: []const u8) Error![48]u8 {
    return decodeFixed("moref0", 48, text);
}

pub fn encodeReference(bytes: [48]u8) [83]u8 {
    return encodeFixed("moref0", 48, bytes);
}

const mopub_example = "mopub03ctpjer5jfkd49rxe4767hk9ij6f8sdtryjnnru1bpwxhcykk54o";
const mosrv_example = "mosrv0naeu8zzpu4g9g8jwqkpsrxoje5gwtwzh7bxzkek51mkwbe7x3oqo";
const mosec_example = "mosec06ayb687prmw8abtuum9bps5hjmfz5ffyft3b4jeznn3htppf3kto";
const moref_example = "moref0yyyyyaayyryb3k67amzuz396jk3jjniyapb937on4y58ajzz9qoek7tor3xqdaer8gtens8jgx1or";

const mopub_bytes = [32]u8{
    203, 34,  212, 160, 155, 73,  84, 61,
    124, 143, 70,  187, 238, 241, 95, 170,
    124, 83,  216, 113, 32,  18,  33, 18,
    114, 11,  104, 254, 48,  10,  86, 245,
};

const mosrv_bytes = [32]u8{
    22,  17,  51,  222, 237, 158, 141, 243,
    29,  52,  114, 155, 98,  62,  9,   70,
    205, 72,  210, 252, 232, 95,  117, 33,
    91,  146, 213, 64,  163, 175, 204, 29,
};

const mosec_bytes = [32]u8{
    246, 0,   31,  31,  173, 34,  232, 124,
    6,   51,  154, 254, 22,  219, 124, 74,
    203, 125, 148, 160, 44,  114, 29,  37,
    23,  16,  179, 200, 181, 165, 202, 163,
};

const moref_bytes = [48]u8{
    0,   0,   0,   99,  0,   1,   0,   28,
    171, 221, 194, 239, 59,  231, 254, 74,
    178, 148, 138, 160, 195, 67,  252, 246,
    2,   208, 54,  124, 38,  247, 251, 160,
    133, 118, 48,  38,  94,  225, 225, 4,
    57,  162, 129, 88,  233, 51,  229, 2,
};

test "decode mopub0 public key" {
    const decoded = try decodeUserPublicKey(mopub_example);
    try std.testing.expectEqualSlices(u8, mopub_bytes[0..], decoded[0..]);
}

test "encode mopub0 public key" {
    const encoded = encodeUserPublicKey(mopub_bytes);
    try std.testing.expectEqualSlices(u8, mopub_example, encoded[0..]);
}

test "decode mosrv0 public key" {
    const decoded = try decodeServerPublicKey(mosrv_example);
    try std.testing.expectEqualSlices(u8, mosrv_bytes[0..], decoded[0..]);
}

test "encode mosrv0 public key" {
    const encoded = encodeServerPublicKey(mosrv_bytes);
    try std.testing.expectEqualSlices(u8, mosrv_example, encoded[0..]);
}

test "decode mosec0 secret key" {
    const decoded = try decodeSecretKey(mosec_example);
    try std.testing.expectEqualSlices(u8, mosec_bytes[0..], decoded[0..]);
}

test "encode mosec0 secret key" {
    const encoded = encodeSecretKey(mosec_bytes);
    try std.testing.expectEqualSlices(u8, mosec_example, encoded[0..]);
}

test "decode moref0 reference" {
    const decoded = try decodeReference(moref_example);
    try std.testing.expectEqualSlices(u8, moref_bytes[0..], decoded[0..]);
}

test "encode moref0 reference" {
    const encoded = encodeReference(moref_bytes);
    try std.testing.expectEqualSlices(u8, moref_example, encoded[0..]);
}

test "invalid prefix rejected" {
    var buf: [mopub_example.len]u8 = undefined;
    @memcpy(buf[0.."mosrv0".len], "mosrv0");
    @memcpy(buf["mosrv0".len..], mopub_example["mopub0".len..]);
    try std.testing.expectError(error.InvalidPrefix, decodeUserPublicKey(buf[0..]));
}

test "truncated payload rejected" {
    try std.testing.expectError(error.InvalidLength, decodeUserPublicKey(mopub_example[0 .. mopub_example.len - 1]));
}
