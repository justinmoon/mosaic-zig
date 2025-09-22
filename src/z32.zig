const std = @import("std");

pub const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";
const invalid_marker: u8 = 0xFF;

fn initDecodeTable() [256]u8 {
    var table = [_]u8{invalid_marker} ** 256;
    var i: usize = 0;
    while (i < alphabet.len) : (i += 1) {
        const code = alphabet[i];
        table[@intCast(code)] = @intCast(i);
    }
    return table;
}

const decode_table = initDecodeTable();

pub const DecodeError = error{InvalidCharacter} || std.mem.Allocator.Error;

pub const InvalidCharacter = struct {
    index: usize,
    byte: u8,
};

pub fn encodedLength(byte_count: usize) usize {
    if (byte_count == 0) return 0;
    return (byte_count * 8 + 4) / 5;
}

pub fn encodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out_len = encodedLength(bytes.len);
    const out = try allocator.alloc(u8, out_len);
    _ = encodeInto(out, bytes);
    return out;
}

pub fn encodeInto(out: []u8, bytes: []const u8) []u8 {
    std.debug.assert(out.len >= encodedLength(bytes.len));

    if (bytes.len == 0) return out[0..0];

    const total_bits = bytes.len * 8;
    var p: usize = 0;
    var out_index: usize = 0;

    while (p < total_bits) : (p += 5) {
        const i = p >> 3;
        const j = p & 7;
        var value: u8 = undefined;
        const current: u16 = @as(u16, bytes[i]);

        if (j <= 3) {
            const shift_amount: u4 = @intCast(3 - j);
            value = @intCast((current >> shift_amount) & 0b11111);
        } else {
            const offset: u4 = @intCast(j - 3);
            var bits = (current << offset) & 0b11111;
            if (i < bytes.len - 1) {
                const next: u16 = @as(u16, bytes[i + 1]);
                const back_shift: u4 = @intCast(8 - offset);
                bits |= next >> back_shift;
            }
            value = @intCast(bits & 0b11111);
        }

        out[out_index] = alphabet[@intCast(value)];
        out_index += 1;
    }

    return out[0..out_index];
}

pub fn decodeAlloc(allocator: std.mem.Allocator, input: []const u8, invalid: ?*InvalidCharacter) DecodeError![]u8 {
    const capacity = if (input.len == 0) 0 else (input.len * 5 + 7) / 8;
    const out = try allocator.alloc(u8, capacity);
    errdefer allocator.free(out);
    const used = try decodeInto(out, input, invalid);
    if (used == out.len) return out;
    return try allocator.realloc(out, used);
}

pub fn decodeInto(out: []u8, input: []const u8, invalid: ?*InvalidCharacter) DecodeError!usize {
    std.debug.assert(out.len >= if (input.len == 0) 0 else (input.len * 5 + 7) / 8);

    if (input.len == 0) return 0;

    var position_bits: usize = 0;
    var position_string: usize = 0;
    const r = input.len & 7;
    const q = (input.len - r) / 8;

    var block: usize = 0;
    while (block < q) : (block += 1) {
        const a = try quintet(input, position_string + 0, invalid);
        const b = try quintet(input, position_string + 1, invalid);
        const c = try quintet(input, position_string + 2, invalid);
        const d = try quintet(input, position_string + 3, invalid);
        const e = try quintet(input, position_string + 4, invalid);
        const f = try quintet(input, position_string + 5, invalid);
        const g = try quintet(input, position_string + 6, invalid);
        const h = try quintet(input, position_string + 7, invalid);

        out[position_bits + 0] = (a << 3) | (b >> 2);
        out[position_bits + 1] = ((b & 0b11) << 6) | (c << 1) | (d >> 4);
        out[position_bits + 2] = ((d & 0b1111) << 4) | (e >> 1);
        out[position_bits + 3] = ((e & 0b1) << 7) | (f << 2) | (g >> 3);
        out[position_bits + 4] = ((g & 0b111) << 5) | h;

        position_bits += 5;
        position_string += 8;
    }

    if (r == 0) return position_bits;

    const a = try quintet(input, position_string + 0, invalid);
    const b = try quintet(input, position_string + 1, invalid);
    out[position_bits] = (a << 3) | (b >> 2);

    if (r <= 2) return position_bits + 1;

    const c = try quintet(input, position_string + 2, invalid);
    const d = try quintet(input, position_string + 3, invalid);
    out[position_bits + 1] = ((b & 0b11) << 6) | (c << 1) | (d >> 4);

    if (r <= 4) return position_bits + 2;

    const e = try quintet(input, position_string + 4, invalid);
    out[position_bits + 2] = ((d & 0b1111) << 4) | (e >> 1);

    if (r <= 5) return position_bits + 3;

    const f = try quintet(input, position_string + 5, invalid);
    const g = try quintet(input, position_string + 6, invalid);
    out[position_bits + 3] = ((e & 0b1) << 7) | (f << 2) | (g >> 3);

    if (r <= 7) return position_bits + 4;

    const h = try quintet(input, position_string + 7, invalid);
    out[position_bits + 4] = ((g & 0b111) << 5) | h;

    return position_bits + 5;
}

fn quintet(input: []const u8, position: usize, invalid: ?*InvalidCharacter) DecodeError!u8 {
    if (position >= input.len) return 0;

    const byte = input[position];
    const index = decode_table[@intCast(byte)];
    if (index == invalid_marker) {
        if (invalid) |ptr| ptr.* = .{ .index = position, .byte = byte };
        return error.InvalidCharacter;
    }

    return index;
}
const test_vectors = [_]struct {
    zbase32: []const u8,
    bytes: []const u8,
    encoded: []const u8,
}{
    .{ .zbase32 = "", .bytes = &[_]u8{}, .encoded = "" },
    .{ .zbase32 = "y", .bytes = &[_]u8{0}, .encoded = "yy" },
    .{ .zbase32 = "9", .bytes = &[_]u8{248}, .encoded = "9y" },
    .{ .zbase32 = "com", .bytes = &[_]u8{ 100, 22 }, .encoded = "comy" },
    .{ .zbase32 = "yh", .bytes = &[_]u8{7}, .encoded = "yh" },
    .{ .zbase32 = "6n9hq", .bytes = &[_]u8{ 240, 191, 199 }, .encoded = "6n9hq" },
    .{ .zbase32 = "4t7ye", .bytes = &[_]u8{ 212, 122, 4 }, .encoded = "4t7ye" },
    .{
        .zbase32 = "yoearcwhngkq1s46",
        .bytes = &[_]u8{ 4, 17, 130, 50, 156, 17, 148, 233, 91, 94 },
        .encoded = "yoearcwhngkq1s46",
    },
    .{
        .zbase32 = "ybndrfg8ejkmcpqxot1uwisza345h769",
        .bytes = &[_]u8{
            0, 68, 50, 20, 199, 66, 84, 182, 53, 207, 132, 101, 58, 86, 215, 198, 117, 190, 119, 223,
        },
        .encoded = "ybndrfg8ejkmcpqxot1uwisza345h769",
    },
};

test "z32 basic round trip" {
    const allocator = std.testing.allocator;
    const input = "The quick brown fox jumps over the lazy dog. \xF0\x9F\x91\x80";
    const expected = "ktwgkedtqiwsg43ycj3g675qrbug66bypj4s4hdurbzzc3m1rb4go3jyptozw6jyctzsqmty6nx3dyy";

    const encoded = try encodeAlloc(allocator, input);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, expected, encoded);

    const decoded = try decodeAlloc(allocator, encoded, null);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, input, decoded);
}

test "z32 random payload length" {
    const allocator = std.testing.allocator;
    var random_bytes = [_]u8{0} ** 32;
    var prng = std.Random.DefaultPrng.init(0x12345678);
    prng.random().bytes(random_bytes[0..]);

    const encoded = try encodeAlloc(allocator, random_bytes[0..]);
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(usize, 52), encoded.len);
}

test "z32 public key vector" {
    const allocator = std.testing.allocator;
    const text = "6ropkm1nz98qqwnotqz1tryk3mrfiw9u16iwzp1usci6kbqdfwho";
    const key = [_]u8{
        241, 32, 213, 46,  66,  191, 206, 231, 80, 80,  139, 175, 40, 144, 10, 202,
        200, 90, 211, 243, 151, 171, 75,  182, 83, 179, 43,  229, 5,  195, 45, 57,
    };

    const encoded = try encodeAlloc(allocator, key[0..]);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, text, encoded);

    const decoded = try decodeAlloc(allocator, text, null);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, key[0..], decoded);

    const roundtrip = try decodeAlloc(allocator, encoded, null);
    defer allocator.free(roundtrip);
    try std.testing.expectEqualSlices(u8, key[0..], roundtrip);
}

test "z32 encode fixtures" {
    const allocator = std.testing.allocator;
    for (test_vectors) |vector| {
        const encoded = try encodeAlloc(allocator, vector.bytes);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, vector.encoded, encoded);
    }
}

test "z32 decode fixtures" {
    const allocator = std.testing.allocator;
    for (test_vectors) |vector| {
        const decoded = try decodeAlloc(allocator, vector.zbase32, null);
        defer allocator.free(decoded);
        try std.testing.expectEqualSlices(u8, vector.bytes, decoded);
    }
}

test "z32 invalid inputs" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        text: []const u8,
        index: usize,
    }{
        .{ .text = "!!!", .index = 0 },
        .{ .text = "~~~", .index = 0 },
        .{ .text = "l", .index = 0 },
        .{ .text = "I1I1I1", .index = 0 },
        .{ .text = "ybndrfg8ejkmcpqxot1uwisza345H769", .index = 28 },
        .{ .text = "bn\xE2\x84\x95e", .index = 2 },
        .{ .text = "uv", .index = 1 },
    };

    for (cases) |case| {
        var detail: InvalidCharacter = undefined;
        const result = decodeAlloc(allocator, case.text, &detail);
        if (result) |decoded| {
            defer allocator.free(decoded);
            std.debug.panic("expected error for input '{s}'", .{case.text});
        } else |err| {
            switch (err) {
                error.InvalidCharacter => {
                    try std.testing.expectEqual(case.index, detail.index);
                    try std.testing.expectEqual(case.text[detail.index], detail.byte);
                },
                error.OutOfMemory => std.debug.panic("unexpected allocator failure", .{}),
            }
        }
    }
}
