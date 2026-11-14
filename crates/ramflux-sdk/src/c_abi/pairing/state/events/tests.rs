// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public daemon progress reaches the ABI queue without another pairing call or private callback.
use super::*;
use crate::platform::listener::BusListener as _;
use ramflux_protocol::custody::pairing::{
    full_transfer::U64,
    local_dto::{FullStatus, FullStatusStage, FullTailStatus, LocalResult, Outcome},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn result(id: u8, durable: u64) -> LocalResult {
    LocalResult {
        schema: "ramflux.pairing.LocalResult.v2".into(),
        version: 2,
        outcome: Outcome::FullStatus {
            value: Box::new(FullStatus {
                attachment_absent: U64(0),
                bytes_durable: U64(durable),
                bytes_total: U64(100),
                cut: U64(1),
                generation: 2,
                lease_expires_at: 604_900,
                operation_id: ramflux_protocol::encode_base64url([id; 32]),
                result: None,
                role: "responder".into(),
                stage: FullStatusStage::Streaming,
                tail_status: FullTailStatus::None,
            }),
        },
    }
}
fn poll(state: &State) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    state.poll().map_err(|error| error.message.into())
}
#[tokio::test]
async fn pairing_abi_receives_async_public_progress_and_discards_another_operation() -> TestResult {
    crate::bus::credentials::contract_tests::deadline(run()).await
}
async fn run() -> TestResult {
    let root = tempfile::tempdir()?;
    let socket = root.path().join("events.sock");
    let listener = crate::platform::listener::bind(&socket)?;
    let state = State::new(
        root.path().to_path_buf(),
        Some(socket.to_str().ok_or("test: socket UTF8")?.into()),
        Some("account".into()),
    )
    .map_err(|error| error.message)?;
    *state.event_account.lock().map_err(|_| "test: account lock")? = Some("account".into());
    state.remember(&result(1, 0)).map_err(|error| error.message)?;
    let mut stream = listener.accept().await?;
    let request = crate::bus::io::read_local_bus_frame(&mut stream).await?;
    assert_eq!(
        request.method, "subscription.open",
        "test: event reader issued a pairing operation"
    );
    assert_eq!(
        request.account_id.as_deref(),
        Some("account"),
        "test: event reader crossed accounts"
    );
    crate::bus::io::write_local_bus_frame(
        &mut stream,
        &crate::bus::io::local_bus_response(&request, serde_json::json!({"subscribed":true})),
    )
    .await?;
    for (sequence, value) in [(1, result(9, 99)), (2, result(1, 75))] {
        let Outcome::FullStatus { value } = value.outcome else {
            return Err("test: full status missing".into());
        };
        let event = LocalEvent::FullStatus {
            schema: "ramflux.pairing.LocalEvent.v2".into(),
            version: 2,
            outcome: FullStatusEvent::FullStatus { value },
        };
        let mut frame = crate::bus::io::local_bus_event(
            &request,
            "account",
            "device",
            crate::custody::pairing::PAIRING_EVENT_TOPIC,
            serde_json::to_value(event)?,
        );
        frame.seq = Some(sequence);
        crate::bus::io::write_local_bus_frame(&mut stream, &frame).await?;
    }
    drop(stream);
    loop {
        let finished = state
            .event_reader
            .lock()
            .map_err(|_| "test: reader lock")?
            .as_ref()
            .is_some_and(|reader| reader.join.is_finished());
        if finished {
            break;
        }
        tokio::task::yield_now().await;
    }
    let first = LocalEvent::from_wire_bytes(&poll(&state)?)?;
    let next = LocalEvent::from_wire_bytes(&poll(&state)?)?;
    let LocalEvent::FullStatus { outcome: FullStatusEvent::FullStatus { value: initial }, .. } =
        first
    else {
        return Err("test: initial event missing".into());
    };
    let LocalEvent::FullStatus { outcome: FullStatusEvent::FullStatus { value: progress }, .. } =
        next
    else {
        return Err("test: async event missing".into());
    };
    assert_eq!(initial.bytes_durable.0, 0, "test: direct result snapshot changed");
    assert_eq!(
        progress.bytes_durable.0, 75,
        "test: daemon progress was not delivered independently"
    );
    assert_eq!(
        progress.operation_id, initial.operation_id,
        "test: foreign operation entered ABI queue"
    );
    assert!(poll(&state)?.is_empty(), "test: event reader queued a foreign or duplicate display");
    state.close();
    Ok(())
}
