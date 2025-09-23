const std = @import("std");
const crypto = @import("crypto.zig");
const record_mod = @import("record.zig");
const timestamp_mod = @import("timestamp.zig");
const Ed25519 = @import("vendor/ed25519.zig").Ed25519;

pub const microblog_kind: u64 = 0x0000_0001_0001_001c;

const layout = record_mod.RecordLayout;
const HEADER_LEN = record_mod.HEADER_LEN;
const MAX_RECORD_SIZE = record_mod.MAX_RECORD_SIZE;
const MICROBLOG_NONCE_CONTEXT = "MOSAIC_MICROBLOG_V1";

pub const TagInput = struct {
    typ: u16,
    value: []const u8,
};

pub const MicroblogParams = struct {
    timestamp: timestamp_mod.Timestamp,
    signing_key: crypto.Ed25519Blake3.KeyPair,
    author_public_key: [Ed25519.PublicKey.encoded_length]u8,
    payload: []const u8,
    tags: []const TagInput,
    address_nonce: ?[8]u8 = null,
};

pub const BuildError = error{
    InvalidUtf8Payload,
    TagValueTooLong,
    TagsTooLarge,
    PayloadTooLarge,
    RecordTooLarge,
    InvalidNonce,
} || std.mem.Allocator.Error || crypto.SignError || record_mod.RecordError;

pub fn buildMicroblogRecord(allocator: std.mem.Allocator, params: MicroblogParams) BuildError![]u8 {
    if (!std.unicode.utf8ValidateSlice(params.payload))
        return error.InvalidUtf8Payload;

    const tags_bytes = try encodeTags(allocator, params.tags);
    defer allocator.free(tags_bytes);

    const len_t = tags_bytes.len;
    const len_p = params.payload.len;
    if (len_p > std.math.maxInt(u32)) return error.PayloadTooLarge;

    const len_s = Ed25519.Signature.encoded_length;
    const len_t_padded = record_mod.paddedLen(len_t);
    const len_p_padded = record_mod.paddedLen(len_p);
    const len_s_padded = record_mod.paddedLen(len_s);

    const total_len = HEADER_LEN + len_t_padded + len_p_padded + len_s_padded;
    if (total_len > MAX_RECORD_SIZE) return error.RecordTooLarge;

    var buffer = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buffer);
    @memset(buffer, 0);

    const timestamp_bytes = params.timestamp.toBytes();
    std.mem.copyForwards(u8, buffer[layout.id_timestamp_offset .. layout.id_timestamp_offset + 8], timestamp_bytes[0..]);
    std.mem.copyForwards(u8, buffer[layout.timestamp_offset .. layout.timestamp_offset + 8], timestamp_bytes[0..]);

    var address_nonce: [8]u8 = undefined;
    if (params.address_nonce) |override| {
        if ((override[0] & 0x80) == 0) return error.InvalidNonce;
        address_nonce = override;
    } else {
        address_nonce = deriveNonce(params.author_public_key, timestamp_bytes, params.payload, tags_bytes);
    }
    std.mem.copyForwards(u8, buffer[layout.address_nonce_offset .. layout.address_nonce_offset + 8], address_nonce[0..]);

    const kind_ptr = @as(*[8]u8, @ptrCast(buffer.ptr + layout.kind_offset));
    std.mem.writeInt(u64, kind_ptr, microblog_kind, .big);
    std.mem.copyForwards(u8, buffer[layout.author_key_offset .. layout.author_key_offset + params.author_public_key.len], params.author_public_key[0..]);
    const signing_public = params.signing_key.publicKeyBytes();
    std.mem.copyForwards(u8, buffer[layout.signing_key_offset .. layout.signing_key_offset + signing_public.len], signing_public[0..]);

    const len_t_ptr = @as(*[2]u8, @ptrCast(buffer.ptr + layout.len_t_offset));
    std.mem.writeInt(u16, len_t_ptr, @as(u16, @intCast(len_t)), .little);
    const len_s_ptr = @as(*[2]u8, @ptrCast(buffer.ptr + layout.len_s_offset));
    std.mem.writeInt(u16, len_s_ptr, @as(u16, @intCast(len_s)), .little);
    const len_p_ptr = @as(*[4]u8, @ptrCast(buffer.ptr + layout.len_p_offset));
    std.mem.writeInt(u32, len_p_ptr, @as(u32, @intCast(len_p)), .little);

    std.mem.copyForwards(u8, buffer[HEADER_LEN .. HEADER_LEN + len_t], tags_bytes);
    const payload_offset = HEADER_LEN + len_t_padded;
    std.mem.copyForwards(u8, buffer[payload_offset .. payload_offset + len_p], params.payload);

    const hash_end = HEADER_LEN + len_t_padded + len_p_padded;
    var true_hash: [64]u8 = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(buffer[layout.hashable_start..hash_end]);
    hasher.final(true_hash[0..]);
    std.mem.copyForwards(u8, buffer[layout.id_hash_offset .. layout.id_hash_offset + 40], true_hash[0..40]);

    const signature = try params.signing_key.sign(buffer[layout.hashable_start..hash_end]);
    const signature_offset = hash_end;
    std.mem.copyForwards(u8, buffer[signature_offset .. signature_offset + signature.len], signature[0..]);

    const verify_slice: []const u8 = buffer;
    _ = try record_mod.Record.fromBytes(verify_slice);

    return buffer;
}

fn encodeTags(allocator: std.mem.Allocator, tags: []const TagInput) BuildError![]u8 {
    var total: usize = 0;
    for (tags) |tag| {
        if (tag.value.len > 65_532) return error.TagValueTooLong;
        const entry_len = 4 + tag.value.len;
        if (entry_len > std.math.maxInt(u16)) return error.TagValueTooLong;
        total += entry_len;
        if (total > std.math.maxInt(u16)) return error.TagsTooLarge;
    }

    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    var offset: usize = 0;
    for (tags) |tag| {
        const entry_len = 4 + tag.value.len;
        const len_ptr = @as(*[2]u8, @ptrCast(buf.ptr + offset));
        std.mem.writeInt(u16, len_ptr, @as(u16, @intCast(entry_len)), .little);
        const typ_ptr = @as(*[2]u8, @ptrCast(buf.ptr + offset + 2));
        std.mem.writeInt(u16, typ_ptr, tag.typ, .little);
        std.mem.copyForwards(u8, buf[offset + 4 .. offset + entry_len], tag.value);
        offset += entry_len;
    }

    return buf;
}

fn deriveNonce(
    author_public_key: [Ed25519.PublicKey.encoded_length]u8,
    timestamp_bytes: [8]u8,
    payload: []const u8,
    tags_bytes: []const u8,
) [8]u8 {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(MICROBLOG_NONCE_CONTEXT);
    hasher.update(author_public_key[0..]);
    hasher.update(timestamp_bytes[0..]);
    hasher.update(payload);
    hasher.update(tags_bytes);

    var full: [32]u8 = undefined;
    hasher.final(full[0..]);

    var nonce: [8]u8 = undefined;
    std.mem.copyForwards(u8, nonce[0..], full[0..8]);
    nonce[0] |= 0x80;
    return nonce;
}

const HexError = error{
    InvalidLength,
    InvalidCharacter,
};

fn hexToFixedArray(comptime N: usize, hex: []const u8) HexError![N]u8 {
    if (hex.len != N * 2) return error.InvalidLength;
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(out[0..], hex) catch |err| switch (err) {
        error.InvalidLength => unreachable,
        error.InvalidCharacter => return error.InvalidCharacter,
        error.NoSpaceLeft => unreachable,
    };
    return out;
}

fn hexToSlice(allocator: std.mem.Allocator, hex: []const u8) (HexError || std.mem.Allocator.Error)![]u8 {
    if (hex.len % 2 != 0) return error.InvalidLength;
    const buf = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(buf);
    _ = std.fmt.hexToBytes(buf, hex) catch |err| switch (err) {
        error.InvalidLength => unreachable,
        error.InvalidCharacter => return error.InvalidCharacter,
        error.NoSpaceLeft => unreachable,
    };
    return buf;
}

test "build microblog record matches reference" {
    const gpa = std.testing.allocator;
    const json_bytes = try std.fs.cwd().readFileAlloc(gpa, "testdata/test_vectors.json", 1 << 20);
    defer gpa.free(json_bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, json_bytes, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const microblog_value = root.object.get("microblog").?;
    const microblog_obj = microblog_value.object;

    const signing_seed_hex = microblog_obj.get("signing_seed_hex").?.string;
    const signing_seed = try hexToFixedArray(crypto.Ed25519Blake3.seed_length, signing_seed_hex);
    const signing_key = try crypto.Ed25519Blake3.KeyPair.fromSeed(signing_seed);

    const author_seed_hex = microblog_obj.get("author_seed_hex").?.string;
    const author_seed = try hexToFixedArray(crypto.Ed25519Blake3.seed_length, author_seed_hex);
    const author_keypair = try crypto.Ed25519Blake3.KeyPair.fromSeed(author_seed);
    const author_public = author_keypair.publicKeyBytes();

    const timestamp_ns = microblog_obj.get("timestamp_ns").?.integer;
    const timestamp = try timestamp_mod.Timestamp.fromNanoseconds(timestamp_ns);

    const payload = microblog_obj.get("payload_utf8").?.string;

    const tags_array = microblog_obj.get("tags").?.array;
    var tag_inputs = std.ArrayListUnmanaged(TagInput){};
    defer tag_inputs.deinit(gpa);
    var tag_values = std.ArrayListUnmanaged([]u8){};
    defer {
        for (tag_values.items) |value| gpa.free(value);
        tag_values.deinit(gpa);
    }

    for (tags_array.items) |tag_value| {
        const tag_obj = tag_value.object;
        const typ_int = tag_obj.get("typ").?.integer;
        const value_hex = tag_obj.get("value_hex").?.string;
        const value_bytes = try hexToSlice(gpa, value_hex);
        try tag_values.append(gpa, value_bytes);
        try tag_inputs.append(gpa, .{
            .typ = @as(u16, @intCast(typ_int)),
            .value = value_bytes,
        });
    }

    const params = MicroblogParams{
        .timestamp = timestamp,
        .signing_key = signing_key,
        .author_public_key = author_public,
        .payload = payload,
        .tags = tag_inputs.items,
    };

    const record_bytes = try buildMicroblogRecord(gpa, params);
    defer gpa.free(record_bytes);

    const expected_record_hex = microblog_obj.get("record_hex").?.string;
    const expected_record_bytes = try hexToSlice(gpa, expected_record_hex);
    defer gpa.free(expected_record_bytes);
    try std.testing.expectEqual(expected_record_bytes.len, record_bytes.len);
    try std.testing.expectEqualSlices(u8, expected_record_bytes, record_bytes);

    const record = try record_mod.Record.fromBytes(record_bytes);

    const expected_len = @as(usize, @intCast(microblog_obj.get("record_len").?.integer));
    try std.testing.expectEqual(expected_len, record_bytes.len);

    const expected_payload = payload;
    try std.testing.expectEqualSlices(u8, expected_payload, record.payload());

    const expected_tags_encoded = try encodeTags(gpa, tag_inputs.items);
    defer gpa.free(expected_tags_encoded);
    try std.testing.expectEqualSlices(u8, expected_tags_encoded, record.tags());

    const expected_true_hash_hex = microblog_obj.get("true_hash_hex").?.string;
    const expected_true_hash = try hexToFixedArray(64, expected_true_hash_hex);
    const actual_hash = record.hash();
    try std.testing.expectEqualSlices(u8, expected_true_hash[0..], actual_hash[0..]);

    const expected_nonce_hex = microblog_obj.get("nonce_hex").?.string;
    const expected_nonce = try hexToFixedArray(8, expected_nonce_hex);
    const actual_nonce_slice = record.data()[layout.address_nonce_offset .. layout.address_nonce_offset + 8];
    try std.testing.expectEqualSlices(u8, expected_nonce[0..], actual_nonce_slice);

    const expected_signing_public_hex = microblog_obj.get("signing_public_key_hex").?.string;
    const expected_signing_public = try hexToFixedArray(Ed25519.PublicKey.encoded_length, expected_signing_public_hex);
    try std.testing.expectEqual(expected_signing_public, record.signingPublicKey());

    const expected_author_public_hex = microblog_obj.get("author_public_key_hex").?.string;
    const expected_author_public = try hexToFixedArray(Ed25519.PublicKey.encoded_length, expected_author_public_hex);
    try std.testing.expectEqualSlices(u8, expected_author_public[0..], record.authorPublicKey()[0..]);
}

test "build microblog record rejects invalid utf8" {
    const gpa = std.testing.allocator;
    const timestamp = try timestamp_mod.Timestamp.fromNanoseconds(123);
    const seed = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
    const signing_key = try crypto.Ed25519Blake3.KeyPair.fromSeed(seed);
    const author_public = signing_key.publicKeyBytes();
    const bad_payload = [_]u8{0xFF};
    const params = MicroblogParams{
        .timestamp = timestamp,
        .signing_key = signing_key,
        .author_public_key = author_public,
        .payload = bad_payload[0..],
        .tags = &.{},
    };
    try std.testing.expectError(error.InvalidUtf8Payload, buildMicroblogRecord(gpa, params));
}

test "build microblog record enforces tag limits" {
    const gpa = std.testing.allocator;
    const timestamp = try timestamp_mod.Timestamp.fromNanoseconds(456);
    const seed = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30 };
    const signing_key = try crypto.Ed25519Blake3.KeyPair.fromSeed(seed);
    const author_public = signing_key.publicKeyBytes();

    const big_value = try gpa.alloc(u8, 65_533);
    defer gpa.free(big_value);
    @memset(big_value, 0x42);

    const oversize_tag = [_]TagInput{.{ .typ = 1, .value = big_value }};
    const params = MicroblogParams{
        .timestamp = timestamp,
        .signing_key = signing_key,
        .author_public_key = author_public,
        .payload = "ok",
        .tags = &oversize_tag,
    };
    try std.testing.expectError(error.TagValueTooLong, buildMicroblogRecord(gpa, params));
}

test "build microblog record validates override nonce" {
    const gpa = std.testing.allocator;
    const timestamp = try timestamp_mod.Timestamp.fromNanoseconds(789);
    const seed = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40 };
    const signing_key = try crypto.Ed25519Blake3.KeyPair.fromSeed(seed);
    const author_public = signing_key.publicKeyBytes();

    const bad_nonce = [8]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const params = MicroblogParams{
        .timestamp = timestamp,
        .signing_key = signing_key,
        .author_public_key = author_public,
        .payload = "ok",
        .tags = &.{},
        .address_nonce = bad_nonce,
    };
    try std.testing.expectError(error.InvalidNonce, buildMicroblogRecord(gpa, params));
}
