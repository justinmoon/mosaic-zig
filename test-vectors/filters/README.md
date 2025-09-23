# Mosaic Filter Fixtures

These binary fixtures are exported from `mosaic-core` using the helper in
`test-vectors/src/bin/export_filters.rs`. Each file is a serialized Mosaic
filter containing one or more filter elements:

- `author_kinds.bin` – AUTHOR_KEYS + KINDS
- `signing_keys.bin` – SIGNING_KEYS
- `timestamps.bin` – TIMESTAMPS element with two entries
- `since_until.bin` – SINCE followed by UNTIL
- `received.bin` – RECEIVED_SINCE followed by RECEIVED_UNTIL
- `include_tags.bin` – INCLUDED_TAGS with a notify pubkey and URL tag
- `exclude_tags.bin` – EXCLUDED_TAGS mirroring the include set
- `exclude_ids.bin` – EXCLUDE prefix list for two IDs
- `mixed.bin` – Mixed elements (author/signing/kind/since/tag)

Regenerate fixtures via:

```
cargo run --quiet --bin export_filters --manifest-path test-vectors/Cargo.toml
```
