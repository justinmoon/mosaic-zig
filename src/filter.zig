const std = @import("std");

pub const DecodeError = error{
    TooShort,
    InvalidLength,
    Truncated,
    ZeroElement,
    ElementOverflow,
    UnexpectedPayloadSize,
    InvalidKeyLength,
    InvalidKindLength,
    InvalidTimestampLength,
    InvalidTagLength,
    InvalidTagPadding,
} || std.mem.Allocator.Error;

pub const EncodeError = error{FilterTooLarge} || DecodeError;

pub const Filter = struct {
    elements: []Element,

    pub fn deinit(self: Filter, allocator: std.mem.Allocator) void {
        for (self.elements) |elem| deinitElement(elem, allocator);
        if (self.elements.len != 0) allocator.free(self.elements);
    }

    pub fn encode(self: Filter, allocator: std.mem.Allocator) EncodeError![]u8 {
        var builder = std.array_list.Managed(u8).init(allocator);
        errdefer builder.deinit();

        // Reserve space for the 8-byte filter header up front.
        try builder.appendSlice(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 });

        for (self.elements) |elem| {
            switch (elem) {
                .author_keys => |keys| try encodeKeyList(&builder, 0x01, keys),
                .signing_keys => |keys| try encodeKeyList(&builder, 0x02, keys),
                .kinds => |kinds| try encodeKinds(&builder, kinds),
                .timestamps => |stamps| try encodeTimestamps(&builder, stamps),
                .included_tags => |tags| try encodeTags(&builder, 0x05, tags),
                .excluded_tags => |tags| try encodeTags(&builder, 0x85, tags),
                .since => |value| try encodeSingleTimestamp(&builder, 0x80, value),
                .until => |value| try encodeSingleTimestamp(&builder, 0x81, value),
                .received_since => |value| try encodeSingleTimestamp(&builder, 0x82, value),
                .received_until => |value| try encodeSingleTimestamp(&builder, 0x83, value),
                .exclude => |prefixes| try encodeExclude(&builder, prefixes),
                .unknown => |unk| try builder.appendSlice(unk.bytes),
            }
        }

        const total_len = builder.items.len;
        if (total_len > std.math.maxInt(u16)) return error.FilterTooLarge;
        const len_bytes = std.mem.toBytes(@as(u16, @intCast(total_len)));
        builder.items[0] = len_bytes[0];
        builder.items[1] = len_bytes[1];

        return builder.toOwnedSlice();
    }
};

pub const Element = union(enum) {
    author_keys: [][]u8,
    signing_keys: [][]u8,
    kinds: []u64,
    timestamps: []i64,
    included_tags: []Tag,
    excluded_tags: []Tag,
    since: i64,
    until: i64,
    received_since: i64,
    received_until: i64,
    exclude: [][]u8,
    unknown: UnknownElement,
};

pub const Tag = struct {
    typ: u16,
    value: []u8,
};

pub const UnknownElement = struct {
    bytes: []u8,
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!Filter {
    if (bytes.len < 8) return error.TooShort;
    const declared_len = std.mem.readInt(u16, bytes[0..2], .little);
    if (declared_len % 8 != 0) return error.InvalidLength;
    if (declared_len > bytes.len) return error.Truncated;

    var elements = std.array_list.Managed(Element).init(allocator);
    errdefer {
        for (elements.items) |elem| deinitElement(elem, allocator);
        elements.deinit();
    }

    var offset: usize = 8;
    while (offset < declared_len) {
        if (declared_len - offset < 2) return error.Truncated;
        const type_byte = bytes[offset];
        const word_len = bytes[offset + 1];
        if (word_len == 0) return error.ZeroElement;
        const element_len = @as(usize, word_len) * 8;
        if (element_len < 8) return error.UnexpectedPayloadSize;
        if (offset + element_len > declared_len) return error.Truncated;

        const element_bytes = bytes[offset .. offset + element_len];
        const payload = element_bytes[8..];

        const elem = switch (type_byte) {
            0x01 => try parseKeyList(allocator, payload, true),
            0x02 => try parseKeyList(allocator, payload, false),
            0x03 => try parseKinds(allocator, payload),
            0x04 => try parseTimestamps(allocator, payload),
            0x05 => try parseTagsElement(allocator, payload, false),
            0x80 => try parseSingleTimestamp(payload, .since),
            0x81 => try parseSingleTimestamp(payload, .until),
            0x82 => try parseSingleTimestamp(payload, .received_since),
            0x83 => try parseSingleTimestamp(payload, .received_until),
            0x84 => try parseExclude(allocator, payload),
            0x85 => try parseTagsElement(allocator, payload, true),
            else => blk: {
                const copy = try allocator.dupe(u8, element_bytes);
                break :blk Element{ .unknown = .{ .bytes = copy } };
            },
        };

        try elements.append(elem);
        offset += element_len;
    }

    const owned = try elements.toOwnedSlice();
    elements.deinit();
    return Filter{ .elements = owned };
}

fn parseKeyList(allocator: std.mem.Allocator, payload: []const u8, is_author: bool) DecodeError!Element {
    if (payload.len % 32 != 0) return error.InvalidKeyLength;
    const count = payload.len / 32;
    var list = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const key_bytes = payload[idx * 32 .. idx * 32 + 32];
        const copy = try allocator.dupe(u8, key_bytes);
        try list.append(copy);
    }

    const owned = try list.toOwnedSlice();
    list.deinit();
    return if (is_author)
        Element{ .author_keys = owned }
    else
        Element{ .signing_keys = owned };
}

fn parseKinds(allocator: std.mem.Allocator, payload: []const u8) DecodeError!Element {
    if (payload.len % 8 != 0) return error.InvalidKindLength;
    const count = payload.len / 8;
    var list = std.array_list.Managed(u64).init(allocator);
    errdefer list.deinit();

    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const kind = readIntBig(u64, payload[idx * 8 .. idx * 8 + 8]);
        try list.append(kind);
    }

    const owned = try list.toOwnedSlice();
    list.deinit();
    return Element{ .kinds = owned };
}

fn parseTimestamps(allocator: std.mem.Allocator, payload: []const u8) DecodeError!Element {
    if (payload.len % 8 != 0) return error.InvalidTimestampLength;
    const count = payload.len / 8;
    var list = std.array_list.Managed(i64).init(allocator);
    errdefer list.deinit();

    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const value = readIntBig(i64, payload[idx * 8 .. idx * 8 + 8]);
        try list.append(value);
    }

    const owned = try list.toOwnedSlice();
    list.deinit();
    return Element{ .timestamps = owned };
}

fn parseSingleTimestamp(payload: []const u8, which: std.meta.Tag(Element)) DecodeError!Element {
    if (payload.len != 8) return error.UnexpectedPayloadSize;
    const value = readIntBig(i64, payload);
    return switch (which) {
        .since => Element{ .since = value },
        .until => Element{ .until = value },
        .received_since => Element{ .received_since = value },
        .received_until => Element{ .received_until = value },
        else => unreachable,
    };
}

fn parseExclude(allocator: std.mem.Allocator, payload: []const u8) DecodeError!Element {
    if (payload.len % 32 != 0) return error.UnexpectedPayloadSize;
    const count = payload.len / 32;
    var list = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const slice = payload[idx * 32 .. idx * 32 + 32];
        const copy = try allocator.dupe(u8, slice);
        try list.append(copy);
    }

    const owned = try list.toOwnedSlice();
    list.deinit();
    return Element{ .exclude = owned };
}

fn parseTagsElement(
    allocator: std.mem.Allocator,
    payload: []const u8,
    excluded: bool,
) DecodeError!Element {
    var tags = std.array_list.Managed(Tag).init(allocator);
    errdefer {
        for (tags.items) |tag| allocator.free(tag.value);
        tags.deinit();
    }

    var offset: usize = 0;
    while (offset < payload.len) {
        if (payload.len - offset < 2) {
            if (!allZeros(payload[offset..])) return error.InvalidTagPadding;
            break;
        }

        const tag_len = readIntLittle(u16, payload[offset .. offset + 2]);

        if (tag_len == 0) {
            if (!allZeros(payload[offset..])) return error.InvalidTagPadding;
            break;
        }

        if (tag_len < 4) return error.InvalidTagLength;
        if (offset + tag_len > payload.len) return error.InvalidTagLength;

        const typ = readIntLittle(u16, payload[offset + 2 .. offset + 4]);
        const value_slice = payload[offset + 4 .. offset + tag_len];
        const copy = try allocator.dupe(u8, value_slice);
        try tags.append(.{ .typ = typ, .value = copy });

        offset += tag_len;
    }

    if (offset < payload.len and !allZeros(payload[offset..])) {
        return error.InvalidTagPadding;
    }

    const owned = try tags.toOwnedSlice();
    tags.deinit();
    return if (excluded)
        Element{ .excluded_tags = owned }
    else
        Element{ .included_tags = owned };
}

fn deinitElement(element: Element, allocator: std.mem.Allocator) void {
    switch (element) {
        .author_keys => |keys| freeSlices(allocator, keys),
        .signing_keys => |keys| freeSlices(allocator, keys),
        .kinds => |items| if (items.len != 0) allocator.free(items),
        .timestamps => |items| if (items.len != 0) allocator.free(items),
        .included_tags => |tags| freeTags(allocator, tags),
        .excluded_tags => |tags| freeTags(allocator, tags),
        .since => {},
        .until => {},
        .received_since => {},
        .received_until => {},
        .exclude => |prefixes| freeSlices(allocator, prefixes),
        .unknown => |unk| if (unk.bytes.len != 0) allocator.free(unk.bytes),
    }
}

fn freeSlices(allocator: std.mem.Allocator, slices: [][]u8) void {
    for (slices) |slice| if (slice.len != 0) allocator.free(slice);
    if (slices.len != 0) allocator.free(slices);
}

fn freeTags(allocator: std.mem.Allocator, tags: []Tag) void {
    for (tags) |tag| if (tag.value.len != 0) allocator.free(tag.value);
    if (tags.len != 0) allocator.free(tags);
}

fn encodeKeyList(builder: *std.array_list.Managed(u8), type_byte: u8, keys: [][]u8) EncodeError!void {
    const payload_len = 32 * keys.len;
    const word_len = 1 + payload_len / 8;
    try appendHeader(builder, type_byte, word_len);
    for (keys) |key| {
        if (key.len != 32) return error.InvalidKeyLength;
        try builder.appendSlice(key);
    }
}

fn encodeKinds(builder: *std.array_list.Managed(u8), kinds: []const u64) EncodeError!void {
    const payload_len = 8 * kinds.len;
    const word_len = 1 + payload_len / 8;
    try appendHeader(builder, 0x03, word_len);
    var buf: [8]u8 = undefined;
    for (kinds) |kind| {
        std.mem.writeInt(u64, &buf, kind, .big);
        try builder.appendSlice(&buf);
    }
}

fn encodeTimestamps(builder: *std.array_list.Managed(u8), timestamps: []const i64) EncodeError!void {
    const payload_len = 8 * timestamps.len;
    const word_len = 1 + payload_len / 8;
    try appendHeader(builder, 0x04, word_len);
    var buf: [8]u8 = undefined;
    for (timestamps) |value| {
        std.mem.writeInt(i64, &buf, value, .big);
        try builder.appendSlice(&buf);
    }
}

fn encodeSingleTimestamp(builder: *std.array_list.Managed(u8), type_byte: u8, ts: i64) EncodeError!void {
    try appendHeader(builder, type_byte, 2);
    var buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &buf, ts, .big);
    try builder.appendSlice(&buf);
}

fn encodeExclude(builder: *std.array_list.Managed(u8), prefixes: [][]u8) EncodeError!void {
    const payload_len = 32 * prefixes.len;
    const word_len = 1 + payload_len / 8;
    try appendHeader(builder, 0x84, word_len);
    for (prefixes) |p| {
        if (p.len != 32) return error.UnexpectedPayloadSize;
        try builder.appendSlice(p);
    }
}

fn encodeTags(builder: *std.array_list.Managed(u8), type_byte: u8, tags: []const Tag) EncodeError!void {
    var payload_len: usize = 0;
    for (tags) |tag| payload_len += 4 + tag.value.len;
    const padded_len = paddedLen(payload_len);
    const word_len = 1 + padded_len / 8;
    try appendHeader(builder, type_byte, word_len);

    var header_buf: [4]u8 = undefined;
    for (tags) |tag| {
        const total = 4 + tag.value.len;
        if (total > std.math.maxInt(u16)) return error.InvalidTagLength;
        header_buf[0] = @intCast(total & 0xFF);
        header_buf[1] = @intCast((total >> 8) & 0xFF);
        header_buf[2] = @intCast(tag.typ & 0xFF);
        header_buf[3] = @intCast((tag.typ >> 8) & 0xFF);
        try builder.appendSlice(&header_buf);
        try builder.appendSlice(tag.value);
    }

    const pad_len = padded_len - payload_len;
    if (pad_len > 0) {
        const zeros = [_]u8{ 0, 0, 0, 0, 0, 0, 0 };
        try builder.appendSlice(zeros[0..pad_len]);
    }
}

fn appendHeader(builder: *std.array_list.Managed(u8), type_byte: u8, word_len: usize) EncodeError!void {
    if (word_len == 0 or word_len > std.math.maxInt(u8)) return error.ElementOverflow;
    try builder.append(type_byte);
    try builder.append(@intCast(word_len));
    try builder.appendSlice(&[_]u8{ 0, 0, 0, 0, 0, 0 });
}

fn paddedLen(len: usize) usize {
    return (len + 7) & ~@as(usize, 7);
}

fn allZeros(bytes: []const u8) bool {
    for (bytes) |b| if (b != 0) return false;
    return true;
}

fn readIntBig(comptime T: type, bytes: []const u8) T {
    std.debug.assert(bytes.len == @sizeOf(T));
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.copyForwards(u8, &buf, bytes);
    return std.mem.readInt(T, &buf, .big);
}

fn readIntLittle(comptime T: type, bytes: []const u8) T {
    std.debug.assert(bytes.len == @sizeOf(T));
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.copyForwards(u8, &buf, bytes);
    return std.mem.readInt(T, &buf, .little);
}

const testing = std.testing;

fn loadFixture(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "test-vectors/filters/{s}.bin", .{name});
    defer allocator.free(path);
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, std.math.maxInt(usize));
}

fn expectRoundTrip(allocator: std.mem.Allocator, name: []const u8) !Filter {
    const bytes = try loadFixture(allocator, name);
    defer allocator.free(bytes);

    const filter = try decode(allocator, bytes);
    const encoded = try filter.encode(allocator);
    defer allocator.free(encoded);
    try testing.expectEqualSlices(u8, bytes, encoded);
    return filter;
}

fn assertAuthorKinds(filter: Filter) !void {
    try testing.expectEqual(@as(usize, 2), filter.elements.len);
    const first = filter.elements[0];
    const second = filter.elements[1];
    switch (first) {
        .author_keys => |keys| try testing.expectEqual(@as(usize, 2), keys.len),
        else => return testing.expect(false),
    }
    switch (second) {
        .kinds => |kinds| {
            try testing.expectEqual(@as(usize, 2), kinds.len);
            try testing.expectEqual(kinds[0], 0x0000_0001_0001_001c);
            try testing.expectEqual(kinds[1], 0x0000_0001_0002_001c);
        },
        else => return testing.expect(false),
    }
}

test "decode author_kinds" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var filter = try expectRoundTrip(allocator, "author_kinds");
    defer filter.deinit(allocator);
    try assertAuthorKinds(filter);
}

test "decode include_tags" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var filter = try expectRoundTrip(allocator, "include_tags");
    defer filter.deinit(allocator);

    try testing.expect(filter.elements.len > 0);
    switch (filter.elements[0]) {
        .included_tags => |tags| {
            try testing.expectEqual(@as(usize, 2), tags.len);
            try testing.expectEqual(@as(u16, 0x01), tags[0].typ);
            try testing.expectEqual(@as(u16, 0x24), tags[1].typ);
        },
        else => return testing.expect(false),
    }
}

test "decode since/until order preserved" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var filter = try expectRoundTrip(allocator, "since_until");
    defer filter.deinit(allocator);

    try testing.expectEqual(@as(usize, 2), filter.elements.len);
    try testing.expect(switch (filter.elements[0]) {
        .since => true,
        else => false,
    });
    try testing.expect(switch (filter.elements[1]) {
        .until => true,
        else => false,
    });
}

test "roundtrip all fixtures" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const names = [_][]const u8{
        "author_kinds",
        "signing_keys",
        "timestamps",
        "since_until",
        "received",
        "include_tags",
        "exclude_tags",
        "exclude_ids",
        "mixed",
    };

    for (names) |name| {
        var filter = try expectRoundTrip(allocator, name);
        filter.deinit(allocator);
    }
}
