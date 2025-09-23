mod fixtures;

use fixtures::{
    microblog_author_seed, microblog_payload, microblog_signing_seed, microblog_tags,
    microblog_timestamp, sample_message, sample_payload, sample_record, sample_seed,
    sample_timestamp,
};
use mosaic_core::{
    Kind, OwnedRecord, OwnedTagSet, PublicKey, RecordAddressData, RecordFlags, RecordParts,
    RecordSigningData, SecretKey,
};
use serde::Serialize;
use std::convert::TryInto;

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
    microblog: MicroblogVector,
}

#[derive(Serialize)]
struct TagFixture {
    typ: u16,
    value_hex: String,
    encoded_hex: String,
}

#[derive(Serialize)]
struct MicroblogVector {
    signing_seed_hex: String,
    signing_public_key_hex: String,
    author_seed_hex: String,
    author_public_key_hex: String,
    timestamp_ns: i64,
    payload_utf8: String,
    tags: Vec<TagFixture>,
    nonce_key_hex: String,
    nonce_hex: String,
    record_hex: String,
    record_len: usize,
    true_hash_hex: String,
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

    let micro_signing_seed = microblog_signing_seed();
    let micro_signing_secret: SecretKey = SecretKey::from_bytes(&micro_signing_seed);
    let micro_signing_public: PublicKey = micro_signing_secret.public();
    let micro_author_seed = microblog_author_seed();
    let micro_author_secret: SecretKey = SecretKey::from_bytes(&micro_author_seed);
    let micro_author_public: PublicKey = micro_author_secret.public();
    let micro_payload = microblog_payload();
    let micro_timestamp = microblog_timestamp()?;

    let owned_tags = microblog_tags(&micro_author_public);
    let mut tag_set = OwnedTagSet::new();
    let mut tag_fixtures = Vec::with_capacity(owned_tags.len());
    for tag in &owned_tags {
        tag_set.add_tag(tag);
        let encoded_bytes = tag.as_bytes();
        let typ = u16::from_le_bytes(encoded_bytes[2..4].try_into().unwrap());
        tag_fixtures.push(TagFixture {
            typ,
            value_hex: hex::encode(tag.data_bytes()),
            encoded_hex: hex::encode(encoded_bytes),
        });
    }

    let mut nonce_key: Vec<u8> = Vec::new();
    nonce_key.extend_from_slice(b"MOSAIC_MICROBLOG_V1");
    nonce_key.extend_from_slice(micro_author_public.as_bytes());
    nonce_key.extend_from_slice(&micro_timestamp.to_bytes());
    nonce_key.extend_from_slice(micro_payload.as_bytes());
    nonce_key.extend_from_slice(tag_set.as_bytes());

    let micro_record_owned: OwnedRecord = OwnedRecord::new(&RecordParts {
        signing_data: RecordSigningData::SecretKey(micro_signing_secret.clone()),
        address_data: RecordAddressData::Deterministic(
            micro_author_public,
            Kind::MICROBLOG_ROOT,
            nonce_key.clone(),
        ),
        timestamp: micro_timestamp,
        flags: RecordFlags::empty(),
        tag_set: &tag_set,
        payload: micro_payload.as_bytes(),
    })?;
    let micro_record_bytes = micro_record_owned.as_bytes();
    let micro_address = micro_record_owned.address();
    let micro_nonce = *micro_address.nonce();
    let micro_full_hash = micro_record_owned.full_hash();

    let microblog = MicroblogVector {
        signing_seed_hex: hex::encode(micro_signing_seed),
        signing_public_key_hex: hex::encode(micro_signing_public.as_bytes()),
        author_seed_hex: hex::encode(micro_author_seed),
        author_public_key_hex: hex::encode(micro_author_public.as_bytes()),
        timestamp_ns: micro_timestamp.as_nanoseconds(),
        payload_utf8: micro_payload.to_string(),
        tags: tag_fixtures,
        nonce_key_hex: hex::encode(&nonce_key),
        nonce_hex: hex::encode(micro_nonce),
        record_hex: hex::encode(micro_record_bytes),
        record_len: micro_record_bytes.len(),
        true_hash_hex: hex::encode(micro_full_hash),
    };

    let output = OutputVectors {
        signing,
        record: record_vector,
        microblog,
    };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    Ok(())
}
