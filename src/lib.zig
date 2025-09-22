const std = @import("std");
const Ed25519 = @import("crypto/vendor/ed25519.zig").Ed25519;

pub const z32 = @import("z32.zig");

pub const mosaic_context: []const u8 = "Mosaic";

pub const timestamp = @import("timestamp.zig");
pub const Timestamp = timestamp.Timestamp;
pub const TimestampError = timestamp.TimestampError;
pub const UnixTime = timestamp.UnixTime;

fn errorSetOf(comptime func: anytype) type {
    const info = @typeInfo(@TypeOf(func));
    return switch (info) {
        .@"fn" => |fn_info| blk: {
            const ret_type = fn_info.return_type orelse @compileError("function has no return type");
            break :blk switch (@typeInfo(ret_type)) {
                .error_union => |eu| eu.error_set,
                else => @compileError("function does not return an error union"),
            };
        },
        else => @compileError("expected function type"),
    };
}

const SignPrehashedError = errorSetOf(Ed25519.KeyPair.signPrehashed);
const VerifyPrehashedError = errorSetOf(Ed25519.Signature.verifyPrehashed);
const GenerateDeterministicError = errorSetOf(Ed25519.KeyPair.generateDeterministic);

/// Error type returned by Mosaic signing helpers.
pub const SignError = error{MessageTooShort} || SignPrehashedError;
/// Error type returned by Mosaic verification helpers.
pub const VerifyError = VerifyPrehashedError;
/// Error type returned when deriving a key pair from a seed.
pub const KeyGenError = GenerateDeterministicError;

pub const Ed25519Blake3 = struct {
    pub const seed_length = Ed25519.KeyPair.seed_length;
    pub const public_key_length = Ed25519.PublicKey.encoded_length;
    pub const signature_length = Ed25519.Signature.encoded_length;
    pub const secret_key_length = Ed25519.SecretKey.encoded_length;

    pub const KeyPair = struct {
        inner: Ed25519.KeyPair,

        pub fn fromSeed(seed: [seed_length]u8) KeyGenError!KeyPair {
            return KeyPair{ .inner = try Ed25519.KeyPair.generateDeterministic(seed) };
        }

        pub fn publicKeyBytes(self: KeyPair) [public_key_length]u8 {
            return self.inner.public_key.toBytes();
        }

        pub fn secretKeyBytes(self: KeyPair) [secret_key_length]u8 {
            return self.inner.secret_key.toBytes();
        }

        pub fn sign(self: KeyPair, message: []const u8) SignError![signature_length]u8 {
            if (message.len == 0) return error.MessageTooShort;
            var prehash = blake3Prehash(message);
            const signature = try Ed25519.KeyPair.signPrehashed(self.inner, prehash[0..], mosaic_context, null);
            return signature.toBytes();
        }
    };

    pub fn verify(message: []const u8, signature_bytes: [signature_length]u8, public_key_bytes: [public_key_length]u8) VerifyError!void {
        var prehash = blake3Prehash(message);
        const public_key = try Ed25519.PublicKey.fromBytes(public_key_bytes);
        const signature = Ed25519.Signature.fromBytes(signature_bytes);
        try signature.verifyPrehashed(prehash[0..], public_key, mosaic_context);
    }
};

fn blake3Prehash(message: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    var blake = std.crypto.hash.Blake3.init(.{});
    blake.update(message);
    blake.final(out[0..]);
    return out;
}

test "ed25519-blake3 sign + verify matches mosaic-core" {
    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    const expected_public = [_]u8{
        0x03, 0xA1, 0x07, 0xBF, 0xF3, 0xCE, 0x10, 0xBE,
        0x1D, 0x70, 0xDD, 0x18, 0xE7, 0x4B, 0xC0, 0x99,
        0x67, 0xE4, 0xD6, 0x30, 0x9B, 0xA5, 0x0D, 0x5F,
        0x1D, 0xDC, 0x86, 0x64, 0x12, 0x55, 0x31, 0xB8,
    };
    const message = "zig-mosaic test vector message";
    const expected_signature = [_]u8{
        0x1F, 0x2E, 0xCF, 0x5B, 0xE8, 0x60, 0x82, 0x63,
        0xEA, 0x0D, 0xED, 0xB7, 0x52, 0x4C, 0xF8, 0x72,
        0xDF, 0x16, 0xF2, 0x91, 0x7A, 0x03, 0x82, 0x18,
        0xE1, 0xE2, 0x20, 0x69, 0x88, 0xE6, 0x3C, 0xF9,
        0x96, 0xB1, 0x45, 0xD7, 0x0D, 0x72, 0x07, 0x40,
        0xC5, 0x54, 0x4C, 0x93, 0x42, 0xB4, 0x91, 0xDC,
        0x56, 0x38, 0x8C, 0x9C, 0x2F, 0xD3, 0x48, 0x35,
        0xFE, 0xD2, 0xBA, 0x9B, 0xB5, 0x55, 0xAF, 0x02,
    };

    const kp = try Ed25519Blake3.KeyPair.fromSeed(seed);
    try std.testing.expectEqualSlices(u8, &expected_public, &kp.publicKeyBytes());

    const sig = try kp.sign(message);
    try std.testing.expectEqualSlices(u8, &expected_signature, &sig);

    try Ed25519Blake3.verify(message, sig, expected_public);

    var bad_sig = expected_signature;
    bad_sig[0] ^= 0x01;
    try std.testing.expectError(error.SignatureVerificationFailed, Ed25519Blake3.verify(message, bad_sig, expected_public));
}
