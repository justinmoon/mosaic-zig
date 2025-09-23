mod fixtures;

use fixtures::{sample_message, sample_payload, sample_record, sample_seed, sample_timestamp};
use mosaic_core::{OwnedRecord, PublicKey, SecretKey};
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
    let seed = sample_seed();
    let secret: SecretKey = SecretKey::from_bytes(&seed);
    let public: PublicKey = secret.public();
    let message = sample_message();
    let signature = secret.sign_data(message)?;

    let signing = SigningVector {
        seed_hex: hex::encode(seed),
        public_key_hex: hex::encode(public.as_bytes()),
        message_hex: hex::encode(message),
        signature_hex: hex::encode(signature.to_bytes()),
    };

    let record_owned: OwnedRecord = sample_record()?;
    let record_slice = record_owned.as_bytes();
    let timestamp = sample_timestamp()?.as_nanoseconds();
    let payload = sample_payload();
    let author_public_key: PublicKey = public;
    let record_vector = RecordVector {
        record_hex: hex::encode(record_slice),
        record_len: record_slice.len(),
        timestamp_ns: timestamp,
        kind_u64_hex: format!("{:016x}", record_owned.kind().to_u64()),
        payload_hex: hex::encode(payload),
        author_public_key_hex: hex::encode(author_public_key.as_bytes()),
        signing_public_key_hex: hex::encode(record_owned.signing_public_key().as_bytes()),
    };

    let output = OutputVectors {
        signing,
        record: record_vector,
    };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    Ok(())
}
