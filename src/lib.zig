const std = @import("std");

/// Returns the canonical greeting used by Mosaic Zig clients.
pub fn greeting() []const u8 {
    return "Hello, mosaic!";
}

test "greeting message" {
    try std.testing.expectEqualStrings("Hello, mosaic!", greeting());
}
