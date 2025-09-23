# Spec Notes – Spec Fidelity / Fixture Sync

## Record flag field is strictly 64 bits wide
- Location: `mosaic-spec/docs/records.md` (Flags section), `mosaic-core/src/record/mod.rs`.
- Observation: The spec calls out `ZSTD` (bit 0) and `FROM_AUTHOR` (bit 2) but does not state that *all other* bits in the 64-bit little-endian field must be zero. Rust rejects any non-zero high byte before signature verification.
- Impact: Interop would break if implementations accept extra feature bits: the Zig validator now matches Rust by rejecting anything outside `{ZSTD, FROM_AUTHOR}` and still treating Ed25519 as the only supported signature scheme (bits 6–7 must remain 0).
- Follow-up: Clarify the allowed mask explicitly in the spec and note that alternative signature schemes are currently undefined.

## Signature length header must always read 64
- Location: `mosaic-spec/docs/records.md` (Layout table), `mosaic-core/src/record/mod.rs`.
- Observation: The spec implies fixed-size Ed25519 signatures, but never states that `LenS` must equal 64. When an adversary tampers with `LenS`, Rust fails the record before verifying the signature.
- Impact: Without that rule, validators could accept truncated records. Zig now enforces the same 64-byte requirement prior to hash/signature validation.
- Follow-up: Spell out that `LenS` is fixed at 64 (and still padded to 64) until new signature schemes are introduced.

## Header length fields cover padded regions
- Location: `mosaic-spec/docs/records.md` (Tags/Payload description).
- Observation: The spec documents padding but does not emphasise that the `LenT`, `LenP`, and `LenS` values drive the full padded-length calculation; malformed records can shrink these values while leaving trailing bytes in place.
- Impact: Zig now mirrors Rust by rejecting mismatches between declared padded lengths and the actual buffer length.
- Follow-up: Add a sentence making the padding rule explicit (“total length = 152 + padded(LenT) + padded(LenP) + padded(LenS)”).

## Protocol headers reserve every metadata byte
- Location: `mosaic-spec/docs/messages.md` (§Hello, §Hello Ack, §Get, §Submission Result).
- Observation: The diagrams mark certain bytes as reserved, but not all error paths are called out. Rust rejects frames where Hello/HelloAck reserved bytes are non-zero, where the application list is not 4-byte aligned, or where Get carries references that are not multiples of 48 bytes. Submission Result also requires bytes 2–3 to stay zero and the returned ID prefix to have its high bit clear.
- Impact: Zig now exercises these checks and will fail fast when the framing is malformed.
- Follow-up: Expand the spec to mention the alignment rules and explicitly mark the reserved fields as “MUST be zero” with validation consequences.

## Result code zero is invalid everywhere
- Location: `mosaic-spec/docs/messages.md` (§Result Codes), `mosaic-core/src/protocol/result_code.rs`.
- Observation: The enumeration assigns 0 to `Undefined`, and Rust raises `InvalidResultCode` if a frame uses it. The spec lists 0 but never states it is forbidden in the wire format.
- Impact: The Zig decoder now returns an error when it encounters 0, matching Rust.
- Follow-up: Document that result code 0 is reserved and that senders MUST choose one of the defined non-zero codes.
