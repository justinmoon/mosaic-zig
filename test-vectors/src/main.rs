use mosaic_core::{SecretKey, Error};
use serde::Serialize;

#[derive(Serialize)]
struct TestVector {
    seed_hex: String,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
}

fn main() -> Result<(), Error> {
    // Deterministic seed chosen for reproducibility.
    let seed: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];

    let message = b"zig-mosaic test vector message";

    let secret = SecretKey::from_bytes(&seed);
    let public = secret.public();
    let signature = secret.sign_data(message)?;

    let vector = TestVector {
        seed_hex: hex::encode(seed),
        public_key_hex: hex::encode(public.as_bytes()),
        message_hex: hex::encode(message),
        signature_hex: hex::encode(signature.to_bytes()),
    };

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
    Ok(())
}
