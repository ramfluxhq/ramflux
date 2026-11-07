// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `capable_client_frame_codecs`: constructors and encoding of the negotiated client frames.
//!
//! Oracle: every encoded frame must equal a literal golden byte string and decode under
//! `ramflux_node_core::SessionPushClientFrame` (`deny_unknown_fields`) with each decoded
//! field equal to the source values that went into the SDK constructor (distinct sentinels).
use super::{CapableClientFrame, ClientFrameError};
use crate::GatewayResumeFrame;
use ramflux_node_core as n;
use serde_json::{Value, json};

const E: &str = "0123456789abcdef0123456789abcdef";

fn ack_json() -> Value {
    json!({
        "schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1",
        "signing_key_id":"dev-key","signature_alg":"ed25519","signature":"sig-ack",
        "ack_id":"ack-7","envelope_id":"env-7","receiver_device_id":"device-7",
        "received_at":1234,"cursor_after":"cursor-7"
    })
}

fn nack_json() -> Value {
    json!({
        "schema":"ramflux.nack.v1","version":1,"domain":"ramflux.nack.v1",
        "signing_key_id":"dev-key","signature_alg":"ed25519","signature":"sig-nack",
        "nack_id":"nack-8","envelope_id":"env-8","receiver_device_id":"device-8",
        "reason":"expired","received_at":5678,"retry_after":9,"proof_hash":"proof-8",
        "new_home_node_hint":"hint-8"
    })
}

fn resume_frame(limit: usize) -> GatewayResumeFrame {
    GatewayResumeFrame {
        target_delivery_id: "target-r".into(),
        after_inbox_seq: 5,
        limit,
        resume_token: "token-r".into(),
    }
}

fn decode(bytes: &[u8]) -> n::SessionPushClientFrame {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn capable_client_frame_codecs() {
    // (p1) resume: golden bytes, and node-core decodes every field to the source values.
    let resume = CapableClientFrame::resume(E, resume_frame(17)).unwrap().encode().unwrap();
    assert_eq!(
        std::str::from_utf8(&resume).unwrap(),
        concat!(
            r#"{"frame_type":"resume","resume":{"target_delivery_id":"target-r","#,
            r#""after_inbox_seq":5,"limit":17,"resume_token":"token-r"},"#,
            r#""incarnation_id":"0123456789abcdef0123456789abcdef"}"#
        )
    );
    match decode(&resume) {
        n::SessionPushClientFrame::Resume { resume, incarnation_id } => {
            assert_eq!(incarnation_id, E);
            assert_eq!(resume.target_delivery_id, "target-r");
            assert_eq!(resume.after_inbox_seq, 5);
            assert_eq!(resume.limit, 17);
            assert_eq!(resume.resume_token, "token-r");
        }
        other => panic!("not a resume: {other:?}"),
    }
    // (p5) resume(limit=1) is accepted: the inclusive lower endpoint.
    assert!(CapableClientFrame::resume(E, resume_frame(1)).is_ok());

    // (p1) fetch_entry, with (p4) seq = 1 as the inclusive endpoint.
    let fetch = CapableClientFrame::fetch_entry(E, 9).unwrap().encode().unwrap();
    assert_eq!(
        std::str::from_utf8(&fetch).unwrap(),
        r#"{"frame_type":"fetch_entry","incarnation_id":"0123456789abcdef0123456789abcdef","inbox_seq":9}"#
    );
    match decode(&fetch) {
        n::SessionPushClientFrame::FetchEntry { incarnation_id, inbox_seq } => {
            assert_eq!((incarnation_id.as_str(), inbox_seq), (E, 9));
        }
        other => panic!("not a fetch_entry: {other:?}"),
    }
    assert!(CapableClientFrame::fetch_entry(E, 1).is_ok());

    // (p1) ack_batch with distinct strictly increasing sentinels.
    let batch = CapableClientFrame::ack_batch(E, vec![3, 5, 8, 13]).unwrap().encode().unwrap();
    assert_eq!(
        std::str::from_utf8(&batch).unwrap(),
        r#"{"frame_type":"ack_batch","incarnation_id":"0123456789abcdef0123456789abcdef","inbox_seqs":[3,5,8,13]}"#
    );
    match decode(&batch) {
        n::SessionPushClientFrame::AckBatch { incarnation_id, inbox_seqs } => {
            assert_eq!(incarnation_id, E);
            assert_eq!(inbox_seqs, [3, 5, 8, 13]);
        }
        other => panic!("not an ack_batch: {other:?}"),
    }
    // (p2) length 1 and (p3) length 64 are the inclusive endpoints.
    assert!(CapableClientFrame::ack_batch(E, vec![1]).is_ok());
    assert!(CapableClientFrame::ack_batch(E, (1..=64).collect()).is_ok());

    // (p1) ack and nack: the frame equals the node-core encoding and the literal Value, and
    // node-core decodes each field to the source values.
    let ack = serde_json::from_value(ack_json()).unwrap();
    let ack_bytes = CapableClientFrame::ack(E, ack).unwrap().encode().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&ack_bytes).unwrap(),
        json!({"frame_type":"ack","incarnation_id":E,"ack":ack_json()})
    );
    match decode(&ack_bytes) {
        n::SessionPushClientFrame::Ack { incarnation_id, ack } => {
            assert_eq!(incarnation_id, E);
            assert_eq!(serde_json::to_value(&ack).unwrap(), ack_json());
            assert_eq!(
                serde_json::to_vec(&n::SessionPushClientFrame::Ack { incarnation_id, ack })
                    .unwrap(),
                ack_bytes
            );
        }
        other => panic!("not an ack: {other:?}"),
    }
    let nack = serde_json::from_value(nack_json()).unwrap();
    let nack_bytes = CapableClientFrame::nack(E, nack).unwrap().encode().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&nack_bytes).unwrap(),
        json!({"frame_type":"nack","incarnation_id":E,"nack":nack_json()})
    );
    match decode(&nack_bytes) {
        n::SessionPushClientFrame::Nack { incarnation_id, nack } => {
            assert_eq!(incarnation_id, E);
            assert_eq!(serde_json::to_value(&nack).unwrap(), nack_json());
            assert_eq!(
                serde_json::to_vec(&n::SessionPushClientFrame::Nack { incarnation_id, nack })
                    .unwrap(),
                nack_bytes
            );
        }
        other => panic!("not a nack: {other:?}"),
    }

    refusal_rows();
}

fn refusal_rows() {
    let batch = |seqs: Vec<u64>| CapableClientFrame::ack_batch(E, seqs).map(|_| ());
    let err = |result: Result<(), ClientFrameError>| result.unwrap_err();
    // (r1) empty seqs, (r2) 65 seqs: the length bounds, one operand each.
    assert_eq!(err(batch(vec![])), ClientFrameError::BatchLength);
    assert_eq!(err(batch((1..=65).collect())), ClientFrameError::BatchLength);
    // (r3) a zero element.
    assert_eq!(err(batch(vec![0])), ClientFrameError::BatchZeroSeq);
    // (r4) equal neighbours, (r5) descending first pair, (r6) descending later.
    assert_eq!(err(batch(vec![2, 2])), ClientFrameError::BatchOrder);
    assert_eq!(err(batch(vec![3, 2])), ClientFrameError::BatchOrder);
    assert_eq!(err(batch(vec![1, 3, 2])), ClientFrameError::BatchOrder);
    // (r7) fetch_entry(seq=0); (r9) resume(limit=0).
    assert_eq!(
        err(CapableClientFrame::fetch_entry(E, 0).map(|_| ())),
        ClientFrameError::FetchSeqZero
    );
    assert_eq!(
        err(CapableClientFrame::resume(E, resume_frame(0)).map(|_| ())),
        ClientFrameError::ResumeLimitZero
    );
    // (r8) a bad E on each of the five constructors, one row each (31, 33 chars, `g`, `A`).
    let bad = [
        &E[..31],
        "0123456789abcdef0123456789abcdef0",
        "g123456789abcdef0123456789abcdef",
        "A123456789abcdef0123456789abcdef",
    ];
    let ack = || serde_json::from_value(ack_json()).unwrap();
    let nack = || serde_json::from_value(nack_json()).unwrap();
    for id in bad {
        let results = [
            CapableClientFrame::resume(id, resume_frame(1)).map(|_| ()),
            CapableClientFrame::fetch_entry(id, 1).map(|_| ()),
            CapableClientFrame::ack_batch(id, vec![1]).map(|_| ()),
            CapableClientFrame::ack(id, ack()).map(|_| ()),
            CapableClientFrame::nack(id, nack()).map(|_| ()),
        ];
        for (index, result) in results.into_iter().enumerate() {
            assert_eq!(
                err(result),
                ClientFrameError::InvalidIncarnation,
                "constructor {index} with {id:?}"
            );
        }
    }
}
