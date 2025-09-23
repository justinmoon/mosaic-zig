#[path = "../fixtures.rs"]
#[allow(dead_code)]
mod fixtures;

use fixtures::sample_record;
use mosaic_core::{Message, QueryId, Reference, ResultCode};
use serde::Serialize;

#[derive(Serialize)]
struct FramesOutput {
    hello: String,
    hello_ack: String,
    get: String,
    submission: String,
    record: String,
    submission_result: String,
}

fn main() -> Result<(), mosaic_core::Error> {
    let record_owned = sample_record()?;
    let record = record_owned.as_ref();
    let id = record.id();
    let address = record.address();

    let id_ref = Reference::from_bytes(id.as_bytes())?;
    let addr_ref = Reference::from_bytes(address.as_bytes())?;
    let references = [&id_ref, &addr_ref];

    let query_id = QueryId::from_bytes([0x34, 0x12]);

    let hello = Message::new_hello(5, &[0, 1, 99])?;
    let hello_ack = Message::new_hello_ack(ResultCode::Success, 5, &[0, 1])?;
    let get = Message::new_get(query_id, &references)?;
    let submission = Message::new_submission(record)?;
    let record_msg = Message::new_record(query_id, record)?;
    let submission_result = Message::new_submission_result(id, ResultCode::Accepted);

    let output = FramesOutput {
        hello: hex::encode(hello.as_bytes()),
        hello_ack: hex::encode(hello_ack.as_bytes()),
        get: hex::encode(get.as_bytes()),
        submission: hex::encode(submission.as_bytes()),
        record: hex::encode(record_msg.as_bytes()),
        submission_result: hex::encode(submission_result.as_bytes()),
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    Ok(())
}
