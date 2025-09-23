use mosaic_core::{
    Kind, OwnedRecord, OwnedTag, RecordAddressData, RecordFlags, RecordParts, RecordSigningData,
    SecretKey, Timestamp, EMPTY_TAG_SET,
};

pub fn sample_seed() -> [u8; 32] {
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ]
}

pub fn sample_message() -> &'static [u8] {
    b"zig-mosaic test vector message"
}

pub fn sample_secret_key() -> SecretKey {
    SecretKey::from_bytes(&sample_seed())
}

pub fn sample_timestamp() -> Result<Timestamp, mosaic_core::Error> {
    Timestamp::from_nanoseconds(1_703_082_432_123_456_789)
}

pub fn sample_payload() -> &'static [u8] {
    b"record validator payload"
}

pub fn sample_record() -> Result<OwnedRecord, mosaic_core::Error> {
    let secret = sample_secret_key();
    let public = secret.public();
    let timestamp = sample_timestamp()?;
    let payload = sample_payload();

    let signing_data = RecordSigningData::SecretKey(secret.clone());
    let address_data = RecordAddressData::Deterministic(
        public,
        Kind::EXAMPLE,
        vec![0x80, 0x14, 0x22, 0x00, 0x00, 0x00, 0x00, 0x01],
    );

    OwnedRecord::new(&RecordParts {
        signing_data,
        address_data,
        timestamp,
        flags: RecordFlags::empty(),
        tag_set: &*EMPTY_TAG_SET,
        payload,
    })
}

pub fn microblog_signing_seed() -> [u8; 32] {
    [
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61,
    ]
}

pub fn microblog_author_seed() -> [u8; 32] {
    [
        0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91,
    ]
}

pub fn microblog_payload() -> &'static str {
    "Hello Mosaic! Visit https://example.com/microblog #vibes"
}

pub fn microblog_tags(author_public: &mosaic_core::PublicKey) -> Vec<OwnedTag> {
    let mut tags = Vec::new();
    tags.push(OwnedTag::new_notify_public_key(author_public));
    tags.push(OwnedTag::new_content_segment_url(
        "https://example.com/microblog",
        18,
    ));
    tags
}

pub fn microblog_timestamp() -> Result<Timestamp, mosaic_core::Error> {
    Timestamp::from_nanoseconds(1_705_554_321_098_765_432)
}
