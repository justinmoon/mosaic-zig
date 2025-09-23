# Spec Notes

## Microblog Record Builder assumptions

- The microblog helper derives address nonces by hashing `"MOSAIC_MICROBLOG_V1" || author_pubkey || timestamp_bytes || payload || encoded_tags` with BLAKE3 and forcing the MSB. The spec does not yet define a canonical nonce strategy for kind `0x0000_0001_0001_001c`, so we document this project-side convention.
- Record flags remain zero (no compression or auth hints) and the builder enforces UTF-8 payloads before signing.
- Callers must supply fully encoded tag bodies (type-specific layout, offsets, etc.) because the helper copies tag bytes directly into the record without inspection.
