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
const KIND_OFFSET: usize = 56;
const SIGNING_KEY_OFFSET: usize = 96;
const AUTHOR_KEY_OFFSET: usize = 64;
const FLAGS_OFFSET: usize = 136;
const LEN_T_OFFSET: usize = 144;
const LEN_S_OFFSET: usize = 146;
const LEN_P_OFFSET: usize = 148;

pub inline fn paddedLen(len: usize) usize {
    return (len + 7) & ~@as(usize, 7);
}

pub const RecordLayout = struct {
    pub const hashable_start = HASHABLE_START;
    pub const id_timestamp_offset = ID_TIMESTAMP_OFFSET;
    pub const id_hash_offset = ID_HASH_OFFSET;
    pub const address_nonce_offset = ADDR_NONCE_OFFSET;
    pub const kind_offset = KIND_OFFSET;
    pub const author_key_offset = AUTHOR_KEY_OFFSET;
    pub const signing_key_offset = SIGNING_KEY_OFFSET;
    pub const timestamp_offset = TIMESTAMP_OFFSET;
    pub const len_t_offset = LEN_T_OFFSET;
    pub const len_s_offset = LEN_S_OFFSET;
    pub const len_p_offset = LEN_P_OFFSET;
    pub const header_len = HEADER_LEN;
};

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
    const allowed_mask: u64 = 0x01 | 0x04 | 0x40 | 0x80;
    if ((flags & ~allowed_mask) != 0) return error.ReservedFlagsSet;

    const scheme_bits = (flags >> 6) & 0b11;
    if (scheme_bits != 0) return error.UnsupportedSignatureScheme;
}

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn loadRecordFixture(allocator: std.mem.Allocator) ![]u8 {
    const json_bytes = try std.fs.cwd().readFileAlloc(allocator, "testdata/test_vectors.json", 1 << 20);
    defer allocator.free(json_bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    defer parsed.deinit();

    const record_hex_value = parsed.value.object.get("record").?.object.get("record_hex").?;
    const record_hex = record_hex_value.string;
    const record_bytes = try hexToBytesAlloc(allocator, record_hex);
    errdefer allocator.free(record_bytes);
    return record_bytes;
}

test "record validator accepts known record" {
    const gpa = std.testing.allocator;
    const record_bytes = try loadRecordFixture(gpa);
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

test "record validator rejects reserved flag bits" {
    const gpa = std.testing.allocator;
    const record_bytes = try loadRecordFixture(gpa);
    defer gpa.free(record_bytes);

    var mutated = try gpa.dupe(u8, record_bytes);
    defer gpa.free(mutated);
    mutated[FLAGS_OFFSET + 3] ^= 0x01;
    try std.testing.expectError(error.ReservedFlagsSet, Record.fromBytes(mutated));
}

test "record validator rejects unsupported signature scheme" {
    const gpa = std.testing.allocator;
    const record_bytes = try loadRecordFixture(gpa);
    defer gpa.free(record_bytes);

    var mutated = try gpa.dupe(u8, record_bytes);
    defer gpa.free(mutated);
    mutated[FLAGS_OFFSET] |= 0x40;
    try std.testing.expectError(error.UnsupportedSignatureScheme, Record.fromBytes(mutated));
}

test "record validator catches header length mismatch" {
    const gpa = std.testing.allocator;
    const record_bytes = try loadRecordFixture(gpa);
    defer gpa.free(record_bytes);

    var mutated = try gpa.dupe(u8, record_bytes);
    defer gpa.free(mutated);
    std.mem.writeInt(u16, mutated[LEN_T_OFFSET .. LEN_T_OFFSET + 2], 8, .little);
    try std.testing.expectError(error.LengthMismatch, Record.fromBytes(mutated));
}

test "record validator rejects unexpected signature length" {
    const gpa = std.testing.allocator;
    const record_bytes = try loadRecordFixture(gpa);
    defer gpa.free(record_bytes);

    const truncated_len = record_bytes.len - Ed25519.Signature.encoded_length;
    var truncated = try gpa.alloc(u8, truncated_len);
    defer gpa.free(truncated);
    std.mem.copyForwards(u8, truncated, record_bytes[0..truncated_len]);
    std.mem.writeInt(u16, truncated[LEN_S_OFFSET .. LEN_S_OFFSET + 2], 0, .little);
    try std.testing.expectError(error.SignatureLengthMismatch, Record.fromBytes(truncated));
}

test "validateFlags accepts zstd/from_author combinations" {
    try validateFlags(0x00);
    try validateFlags(0x01);
    try validateFlags(0x04);
    try validateFlags(0x05);
    try std.testing.expectError(error.UnsupportedSignatureScheme, validateFlags(0x40));
    try std.testing.expectError(error.ReservedFlagsSet, validateFlags(0x100));
}
