const std = @import("std");
const ed25519_mod = @import("crypto.zig");
const Ed25519 = @import("vendor/ed25519.zig").Ed25519;

pub const MAX_RECORD_SIZE: usize = 1_048_576;
pub const HEADER_LEN: usize = 152;

const HASHABLE_START: usize = 48;
const ADDR_NONCE_OFFSET: usize = 48;
const ID_HASH_OFFSET: usize = 8;
const ID_TIMESTAMP_OFFSET: usize = 0;
const TIMESTAMP_OFFSET: usize = 128;
const SIGNING_KEY_OFFSET: usize = 96;
const AUTHOR_KEY_OFFSET: usize = 64;
const FLAGS_OFFSET: usize = 136;
const LEN_T_OFFSET: usize = 144;
const LEN_S_OFFSET: usize = 146;
const LEN_P_OFFSET: usize = 148;

inline fn paddedLen(len: usize) usize {
    return (len + 7) & ~@as(usize, 7);
}

inline fn readLittle(comptime T: type, bytes: []const u8, offset: usize) T {
    const len = @sizeOf(T);
    return std.mem.readInt(T, bytes[offset .. offset + len], .little);
}

inline fn readBig(comptime T: type, bytes: []const u8, offset: usize) T {
    const len = @sizeOf(T);
    return std.mem.readInt(T, bytes[offset .. offset + len], .big);
}

pub const RecordError = error{
    TooShort,
    TooLong,
    LengthMismatch,
    SignatureLengthMismatch,
    ReservedFlagsSet,
    UnsupportedSignatureScheme,
    InvalidSigningKey,
    InvalidAuthorKey,
    InvalidAddressNonce,
    InvalidIdTimestampMsb,
    HashMismatch,
    TimestampMismatch,
    SignatureVerificationFailed,
};

pub const Record = struct {
    bytes: []const u8,
    len_t: usize,
    len_t_padded: usize,
    len_p: usize,
    len_p_padded: usize,
    len_s: usize,
    len_s_padded: usize,

    pub fn fromBytes(bytes: []const u8) RecordError!Record {
        if (bytes.len < HEADER_LEN) return error.TooShort;

        const len_t = readLittle(u16, bytes, LEN_T_OFFSET);
        const len_s = readLittle(u16, bytes, LEN_S_OFFSET);
        const len_p = readLittle(u32, bytes, LEN_P_OFFSET);

        const len_t_usize = len_t;
        const len_s_usize = len_s;
        const len_p_usize = len_p;

        const len_t_padded = paddedLen(len_t_usize);
        const len_s_padded = paddedLen(len_s_usize);
        const len_p_padded = paddedLen(len_p_usize);

        const expected_len = HEADER_LEN + len_t_padded + len_p_padded + len_s_padded;
        if (expected_len != bytes.len) return error.LengthMismatch;
        if (expected_len > MAX_RECORD_SIZE) return error.TooLong;

        if (len_s_usize != Ed25519.Signature.encoded_length)
            return error.SignatureLengthMismatch;

        const flags = readLittle(u64, bytes, FLAGS_OFFSET);
        try validateFlags(flags);

        if ((bytes[ADDR_NONCE_OFFSET] & 0x80) == 0) return error.InvalidAddressNonce;
        if ((bytes[ID_TIMESTAMP_OFFSET] & 0x80) != 0) return error.InvalidIdTimestampMsb;

        var signing_key_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
        std.mem.copyForwards(u8, &signing_key_bytes, bytes[SIGNING_KEY_OFFSET .. SIGNING_KEY_OFFSET + signing_key_bytes.len]);
        const signing_key = Ed25519.PublicKey.fromBytes(signing_key_bytes) catch return error.InvalidSigningKey;

        var author_key_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
        std.mem.copyForwards(u8, &author_key_bytes, bytes[AUTHOR_KEY_OFFSET .. AUTHOR_KEY_OFFSET + author_key_bytes.len]);
        _ = Ed25519.PublicKey.fromBytes(author_key_bytes) catch return error.InvalidAuthorKey;

        const hash_end = HEADER_LEN + len_t_padded + len_p_padded;
        const true_hash = computeTrueHash(bytes, hash_end);
        if (!std.mem.eql(u8, true_hash[0..40], bytes[ID_HASH_OFFSET .. ID_HASH_OFFSET + 40]))
            return error.HashMismatch;

        if (!std.mem.eql(u8, bytes[ID_TIMESTAMP_OFFSET .. ID_TIMESTAMP_OFFSET + 8], bytes[TIMESTAMP_OFFSET .. TIMESTAMP_OFFSET + 8]))
            return error.TimestampMismatch;

        const sig_start = hash_end;
        var signature_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
        std.mem.copyForwards(u8, &signature_bytes, bytes[sig_start .. sig_start + signature_bytes.len]);
        const signature = Ed25519.Signature.fromBytes(signature_bytes);
        signature.verifyPrehashed(true_hash[0..], signing_key, ed25519_mod.mosaic_context) catch return error.SignatureVerificationFailed;

        return Record{
            .bytes = bytes,
            .len_t = len_t_usize,
            .len_t_padded = len_t_padded,
            .len_p = len_p_usize,
            .len_p_padded = len_p_padded,
            .len_s = len_s_usize,
            .len_s_padded = len_s_padded,
        };
    }

    pub fn data(self: Record) []const u8 {
        return self.bytes;
    }

    pub fn hash(self: Record) [64]u8 {
        return computeTrueHash(self.bytes, HEADER_LEN + self.len_t_padded + self.len_p_padded);
    }

    pub fn timestamp(self: Record) u64 {
        return readBig(u64, self.bytes, TIMESTAMP_OFFSET);
    }

    pub fn idTimestamp(self: Record) u64 {
        return readBig(u64, self.bytes, ID_TIMESTAMP_OFFSET);
    }

    pub fn payload(self: Record) []const u8 {
        const start = HEADER_LEN + self.len_t_padded;
        return self.bytes[start .. start + self.len_p];
    }

    pub fn tags(self: Record) []const u8 {
        return self.bytes[HEADER_LEN .. HEADER_LEN + self.len_t];
    }

    pub fn kind(self: Record) u64 {
        return readBig(u64, self.bytes, 56);
    }

    pub fn signingPublicKey(self: Record) [Ed25519.PublicKey.encoded_length]u8 {
        var out: [Ed25519.PublicKey.encoded_length]u8 = undefined;
        std.mem.copyForwards(u8, &out, self.bytes[SIGNING_KEY_OFFSET .. SIGNING_KEY_OFFSET + out.len]);
        return out;
    }

    pub fn authorPublicKey(self: Record) [Ed25519.PublicKey.encoded_length]u8 {
        var out: [Ed25519.PublicKey.encoded_length]u8 = undefined;
        std.mem.copyForwards(u8, &out, self.bytes[AUTHOR_KEY_OFFSET .. AUTHOR_KEY_OFFSET + out.len]);
        return out;
    }
};

fn computeTrueHash(bytes: []const u8, end_index: usize) [64]u8 {
    var out: [64]u8 = undefined;
    var blake = std.crypto.hash.Blake3.init(.{});
    blake.update(bytes[HASHABLE_START..end_index]);
    blake.final(out[0..]);
    return out;
}

fn validateFlags(flags: u64) RecordError!void {
    const flag0: u8 = @truncate(flags);
    const allowed_flag0_mask: u8 = 0x01 | 0x04 | 0x40 | 0x80;
    if ((flag0 & ~allowed_flag0_mask) != 0) return error.ReservedFlagsSet;
    const scheme_bits = (flag0 >> 6) & 0b11;
    if (scheme_bits != 0) return error.UnsupportedSignatureScheme;

    const flag1: u8 = @truncate(flags >> 8);
    const flag2: u8 = @truncate(flags >> 16);
    if (flag1 != 0 or flag2 != 0) return error.ReservedFlagsSet;
}

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

test "record validator accepts known record" {
    const gpa = std.testing.allocator;
    const json_bytes = try std.fs.cwd().readFileAlloc(gpa, "testdata/test_vectors.json", 1 << 20);
    defer gpa.free(json_bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, json_bytes, .{});
    defer parsed.deinit();

    const record_hex_value = parsed.value.object.get("record").?.object.get("record_hex").?;
    const record_hex = record_hex_value.string;

    const record_bytes = try hexToBytesAlloc(gpa, record_hex);
    defer gpa.free(record_bytes);

    const rec = try Record.fromBytes(record_bytes);
    try std.testing.expectEqual(@as(usize, 0), rec.len_t);
    try std.testing.expectEqual(@as(usize, rec.payload().len), rec.len_p);
    try std.testing.expectEqual(@as(u64, 0x0000_0063_0001_001c), rec.kind());
    try std.testing.expectEqual(@as(u64, 1_703_082_432_123_456_789), rec.timestamp());

    var tampered_sig = try gpa.dupe(u8, record_bytes);
    defer gpa.free(tampered_sig);
    tampered_sig[tampered_sig.len - 1] ^= 0x01;
    try std.testing.expectError(error.SignatureVerificationFailed, Record.fromBytes(tampered_sig));

    var tampered_payload = try gpa.dupe(u8, record_bytes);
    defer gpa.free(tampered_payload);
    const payload_index = HEADER_LEN + paddedLen(rec.len_t);
    tampered_payload[payload_index] ^= 0x01;
    try std.testing.expectError(error.HashMismatch, Record.fromBytes(tampered_payload));
}
