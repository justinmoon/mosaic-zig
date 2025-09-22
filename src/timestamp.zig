const std = @import("std");

/// The largest timestamp representable in nanoseconds.
pub const max_nanoseconds: i64 = std.math.maxInt(i64);
/// Last unixtime that is covered by the embedded leap-second table.
pub const leap_seconds_expire: u64 = 1_766_880_000;

const ntp_time_unixtime_offset: u64 = 2_208_988_800;
const max_nanoseconds_u128: u128 = (@as(u128, 1) << 63) - 1;

/// Errors that can be raised while working with Mosaic timestamps.
pub const TimestampError = error{
    TimeOutOfRange,
    SubsecondOutOfRange,
    BeyondLeapSecondData,
};

/// Unixtime seconds/nanoseconds pair.
pub const UnixTime = struct {
    seconds: u64,
    nanoseconds: u32,
};

/// Timestamp counts the number of nanoseconds elapsed since the UNIX epoch,
/// including leap seconds.
pub const Timestamp = struct {
    value: i64,

    pub const zero = Timestamp{ .value = 0 };
    pub const min = Timestamp{ .value = 0 };
    pub const max = Timestamp{ .value = max_nanoseconds };

    /// Construct a timestamp from raw nanoseconds.
    pub fn fromNanoseconds(nanos: i64) TimestampError!Timestamp {
        if (nanos < 0) return TimestampError.TimeOutOfRange;
        return Timestamp{ .value = nanos };
    }

    /// Access the underlying nanoseconds.
    pub fn asNanoseconds(self: Timestamp) i64 {
        return self.value;
    }

    /// Convert a unixtime pair to a Mosaic timestamp.
    pub fn fromUnixTime(seconds: u64, subsec_nanoseconds: u32) TimestampError!Timestamp {
        if (subsec_nanoseconds > 999_999_999) return TimestampError.SubsecondOutOfRange;
        if (seconds > leap_seconds_expire) return TimestampError.BeyondLeapSecondData;

        const leaps = countLeapSecondsBeforeUnix(seconds);
        const adjusted_seconds = @as(u128, seconds) + @as(u128, leaps);
        const total_nanoseconds = adjusted_seconds * 1_000_000_000 + @as(u128, subsec_nanoseconds);

        if (total_nanoseconds > max_nanoseconds_u128) return TimestampError.TimeOutOfRange;

        return Timestamp{ .value = @as(i64, @intCast(total_nanoseconds)) };
    }

    /// Convert this timestamp back to a unixtime pair.
    pub fn toUnixTime(self: Timestamp) UnixTime {
        const total_nanoseconds = @as(u64, @intCast(self.value));
        const unadjusted_seconds = total_nanoseconds / 1_000_000_000;
        const nanoseconds = total_nanoseconds % 1_000_000_000;

        const leaps = countLeapSecondsBeforeUnadjusted(unadjusted_seconds);
        const seconds = unadjusted_seconds - leaps;

        return UnixTime{
            .seconds = seconds,
            .nanoseconds = @as(u32, @intCast(nanoseconds)),
        };
    }

    /// Encode as big-endian bytes.
    pub fn toBytes(self: Timestamp) [8]u8 {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(i64, bytes[0..], self.value, .big);
        return bytes;
    }

    /// Decode from big-endian bytes.
    pub fn fromBytes(bytes: [8]u8) TimestampError!Timestamp {
        const value = std.mem.readInt(i64, bytes[0..], .big);
        if (value < 0) return TimestampError.TimeOutOfRange;
        return Timestamp{ .value = value };
    }

    /// Encode for reverse-lexicographic ordering.
    pub fn toInverseBytes(self: Timestamp) [8]u8 {
        const inverted = max_nanoseconds - self.value;
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(i64, bytes[0..], inverted, .big);
        return bytes;
    }

    /// Decode from inverse-ordered bytes.
    pub fn fromInverseBytes(bytes: [8]u8) TimestampError!Timestamp {
        const inverted = std.mem.readInt(i64, bytes[0..], .big);
        if (inverted < 0) return TimestampError.TimeOutOfRange;
        return Timestamp{ .value = max_nanoseconds - inverted };
    }
};

fn countLeapSecondsBeforeUnix(seconds: u64) u64 {
    var count: u64 = 0;
    for (ianaNtpLeapSeconds()) |ntp| {
        const unix = ntp - ntp_time_unixtime_offset;
        if (unix < seconds) {
            count += 1;
        } else {
            break;
        }
    }
    return count;
}

fn countLeapSecondsBeforeUnadjusted(unadjusted_seconds: u64) u64 {
    var count: u64 = 0;
    for (ianaNtpLeapSeconds(), 0..) |ntp, idx| {
        const unix = ntp - ntp_time_unixtime_offset;
        const threshold = unix + 1 + idx;
        if (threshold < unadjusted_seconds) {
            count += 1;
        } else {
            break;
        }
    }
    return count;
}

fn ianaNtpLeapSeconds() []const u64 {
    return &.{
        2_272_060_800,
        2_287_785_600,
        2_303_683_200,
        2_335_219_200,
        2_366_755_200,
        2_398_291_200,
        2_429_913_600,
        2_461_449_600,
        2_492_985_600,
        2_524_521_600,
        2_571_782_400,
        2_603_318_400,
        2_634_854_400,
        2_698_012_800,
        2_776_982_400,
        2_840_140_800,
        2_871_676_800,
        2_918_937_600,
        2_950_473_600,
        2_982_009_600,
        3_029_443_200,
        3_076_704_000,
        3_124_137_600,
        3_345_062_400,
        3_439_756_800,
        3_550_089_600,
        3_644_697_600,
        3_692_217_600,
    };
}

test "timestamp from unixtime applies leap seconds" {
    var ts = try Timestamp.fromUnixTime(500_000_000, 987_000_000);
    try std.testing.expectEqual(@as(i64, 500_000_014_987_000_000), ts.asNanoseconds());

    ts = try Timestamp.fromUnixTime(1_732_950_200, 100_000_000);
    try std.testing.expectEqual(@as(i64, 1_732_950_228_100_000_000), ts.asNanoseconds());

    const bytes = ts.toBytes();
    const roundtrip = try Timestamp.fromBytes(bytes);
    try std.testing.expectEqual(ts, roundtrip);

    const inverse = ts.toInverseBytes();
    const from_inverse = try Timestamp.fromInverseBytes(inverse);
    try std.testing.expectEqual(ts, from_inverse);
}

test "timestamp unixtime conversions around leap second" {
    var seconds: u64 = 126_230_390;
    while (seconds < 126_230_410) : (seconds += 1) {
        const ts = try Timestamp.fromUnixTime(seconds, 500_000_000);
        const unix = ts.toUnixTime();
        try std.testing.expectEqual(seconds, unix.seconds);
        try std.testing.expectEqual(@as(u32, 500_000_000), unix.nanoseconds);
    }
}

test "timestamp error handling" {
    try std.testing.expectError(TimestampError.SubsecondOutOfRange, Timestamp.fromUnixTime(0, 1_000_000_000));
    try std.testing.expectError(TimestampError.BeyondLeapSecondData, Timestamp.fromUnixTime(leap_seconds_expire + 1, 0));

    var neg: [8]u8 = undefined;
    std.mem.writeInt(i64, neg[0..], -1, .big);
    try std.testing.expectError(TimestampError.TimeOutOfRange, Timestamp.fromBytes(neg));
    try std.testing.expectError(TimestampError.TimeOutOfRange, Timestamp.fromInverseBytes(neg));
}
