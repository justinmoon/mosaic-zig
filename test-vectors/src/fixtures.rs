use mosaic_core::{
    Kind, OwnedRecord, RecordAddressData, RecordFlags, RecordParts, RecordSigningData, SecretKey,
    Timestamp, EMPTY_TAG_SET,
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
