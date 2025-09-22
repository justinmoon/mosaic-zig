use mosaic_core::{
    Kind, OwnedRecord, PublicKey, RecordAddressData, RecordFlags, RecordParts, RecordSigningData,
    SecretKey, Timestamp, EMPTY_TAG_SET,
};
use serde::Serialize;

#[derive(Serialize)]
struct SigningVector {
    seed_hex: String,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
}

#[derive(Serialize)]
struct RecordVector {
    record_hex: String,
    record_len: usize,
    timestamp_ns: i64,
    kind_u64_hex: String,
    payload_hex: String,
    author_public_key_hex: String,
    signing_public_key_hex: String,
}

#[derive(Serialize)]
struct OutputVectors {
    signing: SigningVector,
    record: RecordVector,
}

fn main() -> Result<(), mosaic_core::Error> {
    let seed: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    let message = b"zig-mosaic test vector message";

    let secret = SecretKey::from_bytes(&seed);
    let public = secret.public();
    let signature = secret.sign_data(message)?;

    let signing = SigningVector {
        seed_hex: hex::encode(seed),
        public_key_hex: hex::encode(public.as_bytes()),
        message_hex: hex::encode(message),
        signature_hex: hex::encode(signature.to_bytes()),
    };

    let timestamp = Timestamp::from_nanoseconds(1_703_082_432_123_456_789)?;
    let payload: &[u8] = b"record validator payload";
    let author_public_key: PublicKey = public;
    let signing_data = RecordSigningData::SecretKey(secret.clone());
    let address_data = RecordAddressData::Deterministic(
        author_public_key,
        Kind::EXAMPLE,
        vec![0x80, 0x14, 0x22, 0x00, 0x00, 0x00, 0x00, 0x01],
    );

    let record = OwnedRecord::new(&RecordParts {
        signing_data,
        address_data,
        timestamp,
        flags: RecordFlags::empty(),
        tag_set: &*EMPTY_TAG_SET,
        payload,
    })?;

    let record_slice = record.as_bytes();
    let record_vector = RecordVector {
        record_hex: hex::encode(record_slice),
        record_len: record_slice.len(),
        timestamp_ns: timestamp.as_nanoseconds(),
        kind_u64_hex: format!("{:016x}", Kind::EXAMPLE.to_u64()),
        payload_hex: hex::encode(payload),
        author_public_key_hex: hex::encode(author_public_key.as_bytes()),
        signing_public_key_hex: hex::encode(record.signing_public_key().as_bytes()),
    };

    let output = OutputVectors {
        signing,
        record: record_vector,
    };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    Ok(())
}
