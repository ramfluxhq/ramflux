// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `capable_point_and_ack_exact_reply_sets`: `fetch_entry`, `ack_batch`, the Push `ack()`
//! adapter and the legacy `cursor()` on a negotiated session.
//!
//! Oracle: node-core builds every reply from distinct non-default values (both producer
//! orders for the positives). Every refusal starts from a valid reply and changes one field;
//! every unexpected reply kind is one isolated row.
use super::resume_tests::{Gateway, Sent, eid, forwarded, nack, node_record, session, typed};
use super::routing_tests::{E, envelope, push};
use super::split_tests::legacy_unexpected_kinds;
use super::{AckOutcome, AckResult, EntryGoneReason, PageEntryRecord, PushNackReason, SessionMode};
use crate::SdkError;
use crate::bus::connection_manager::DisconnectReason;
use crate::gateway::push_point::{BatchReply, PointReply};
use crate::gateway::{
    GatewayCursor, GatewayInboxEntry, GatewayQuicEndpointConfig, GatewaySessionConfig,
    GatewaySessionEngine,
};
use n::SessionPushServerFrame as F;
use ramflux_node_core as n;
use ramflux_transport::GatewaySessionTransport;
use serde_json::{Value, json};
use std::sync::Arc;

const UNEXPECTED: &str =
    "unexpected gateway frame: unexpected capable reply while awaiting a point reply";
const FOREIGN_E: &str = "unexpected gateway frame: reply with a foreign incarnation";
const FOREIGN_NACK: &str = "unexpected gateway frame: capable nack with a foreign incarnation";
const OUTSIDE: &str = "unexpected gateway frame: capable reply outside a capable wait";
/// The complete signed capable ack frame as written on the wire (fixed keys and clock).
const PUSH_ACK_GOLDEN: &str = r#"{"frame_type":"ack","incarnation_id":"0123456789abcdef0123456789abcdef","ack":{"schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1","ext":{"inbox_seq":21,"receiver_root_commitment":"PFJFQemtHUtFOLU60gf6Yf5aT4KG6otCZTo80YGOkiE"},"signing_key_id":"device:point-device","signature_alg":"ed25519","signature":"yYsjuPmCClkwxVK9LrOAly6ZontmeKwpUiLTUY3fF_QEdPrmTrqWKmYuEFp9rRXQuDVg_9xAzZPLwIQEdtEwDg","ack_id":"ack_env-route_point-device","envelope_id":"env-route","receiver_device_id":"point-device","received_at":1}}"#;

/// The complete legacy ack frame as written on the wire.
const LEGACY_ACK_GOLDEN: &str = r#"{"frame_type":"ack","ack":{"schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1","ext":{"inbox_seq":21,"receiver_root_commitment":"PFJFQemtHUtFOLU60gf6Yf5aT4KG6otCZTo80YGOkiE"},"signing_key_id":"device:point-device","signature_alg":"ed25519","signature":"yYsjuPmCClkwxVK9LrOAly6ZontmeKwpUiLTUY3fF_QEdPrmTrqWKmYuEFp9rRXQuDVg_9xAzZPLwIQEdtEwDg","ack_id":"ack_env-route_point-device","envelope_id":"env-route","receiver_device_id":"point-device","received_at":1}}"#;

fn node_cursor(target: &str) -> n::InboxCursorResponse {
    n::InboxCursorResponse {
        target_delivery_id: target.into(),
        inbox_seq: 30,
        last_envelope_id: Some("last-30".into()),
        acked_envelope_ids: vec!["acked-a".into(), "acked-b".into()],
        nacked_envelope_ids: [("nacked-30".to_owned(), ramflux_protocol::NackReason::Expired)]
            .into_iter()
            .collect(),
    }
}

fn sdk_cursor() -> GatewayCursor {
    GatewayCursor {
        target_delivery_id: "target-route".into(),
        inbox_seq: 30,
        last_envelope_id: Some("last-30".into()),
        acked_envelope_ids: vec!["acked-a".into(), "acked-b".into()],
        nacked_envelope_ids: [("nacked-30".to_owned(), ramflux_protocol::NackReason::Expired)]
            .into_iter()
            .collect(),
    }
}

fn entry_frame(seq: u64) -> F {
    F::Entry { incarnation_id: E.into(), record: Box::new(node_record(seq, 9_001)) }
}

fn too_large(seq: u64) -> F {
    F::EntryTooLarge { incarnation_id: E.into(), inbox_seq: seq, retain_until: 9_002 }
}

fn gone(seq: u64, observed: u64) -> F {
    F::EntryGone {
        incarnation_id: E.into(),
        inbox_seq: seq,
        observed_issued_inbox_seq: observed,
        reason: n::EntryGoneReason::AckWindowOverflow,
    }
}

fn batch_frame(seqs: &[u64]) -> F {
    F::AckBatch {
        incarnation_id: E.into(),
        cursor: node_cursor("target-route"),
        results: seqs
            .iter()
            .map(|seq| n::SessionAckResult {
                inbox_seq: *seq,
                outcome: n::SessionAckOutcome::Acked,
                reason: None,
            })
            .collect(),
    }
}

fn ack_frame() -> F {
    F::Ack { incarnation_id: E.into(), cursor: node_cursor("target-route") }
}

/// One valid frame of each of the nine capable reply kinds, keyed to this session.
fn all_kinds() -> Vec<(&'static str, Vec<u8>)> {
    let page = F::ResumePage {
        target_delivery_id: "target-route".into(),
        incarnation_id: E.into(),
        after_inbox_seq: 7,
        covered_through_seq: 17,
        issued_inbox_seq: 19,
        settled_through_seq: 5,
        entries: vec![],
        known_losses: vec![],
        oversize_next: None,
        more: false,
    };
    vec![
        (
            "submit_accepted",
            typed(&F::SubmitAccepted {
                incarnation_id: E.into(),
                envelope_id: "env-route".into(),
                target_delivery_id: "target-route".into(),
                inbox_seq: 3,
            }),
        ),
        ("resume_page", typed(&page)),
        ("entry", typed(&entry_frame(7))),
        ("entry_too_large", typed(&too_large(7))),
        ("entry_gone", typed(&gone(7, 7))),
        ("ack_batch", typed(&batch_frame(&[1]))),
        ("ack", typed(&ack_frame())),
        (
            "cursor",
            typed(&F::Cursor {
                incarnation_id: E.into(),
                cursor: Some(node_cursor("target-route")),
            }),
        ),
        ("nack", nack(n::SessionPushNackReason::Busy, Some(E.into()))),
    ]
}

/// A signed engine on the given transport.
pub(super) fn signed_on(
    mode: SessionMode,
    stream: Box<dyn GatewaySessionTransport + Send>,
) -> GatewaySessionEngine {
    let root = ramflux_crypto::create_identity_root("point-principal", [0x71; 32]);
    let branch =
        ramflux_crypto::create_device_branch("point-principal", "point-device", 1, [0x72; 32]);
    let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse().unwrap(),
        gateway_addr: "127.0.0.1:443".parse().unwrap(),
        server_name: "localhost".into(),
        ca_cert: "test-ca.pem".into(),
        principal_id: "point-principal".into(),
        device_id: "point-device".into(),
        target_delivery_id: "target-route".into(),
        prekey_http_url: None,
    })
    .with_owned_device(&root, branch)
    .unwrap();
    let mut engine = GatewaySessionEngine::with_test_transport(config, stream);
    engine.mode = mode;
    engine
}

/// A signed engine that records what it writes.
pub(super) fn signed(mode: SessionMode, frames: Vec<Vec<u8>>) -> (GatewaySessionEngine, Sent) {
    let sent: Sent = Arc::default();
    let stream: Box<dyn GatewaySessionTransport + Send> =
        Box::new(Gateway { frames: frames.into(), sent: Arc::clone(&sent) });
    (signed_on(mode, stream), sent)
}

/// An ack for entry 21, carrying the `ext.inbox_seq` the gateway requires (a missing or zero
/// value is nacked `invalid_seq`, `session_push.rs` input admission).
fn ack_of(engine: &GatewaySessionEngine) -> ramflux_protocol::Ack {
    let mut ack =
        crate::dm::gateway_ack("env-route", engine.config.source_identity.as_ref().unwrap(), 1);
    ack.ext.ext.insert("inbox_seq".into(), json!(21));
    ack
}

/// The gateway's admission predicate for a client `ack`, restated independently.
fn gateway_admits_ack(bytes: &[u8]) -> bool {
    match serde_json::from_slice::<n::SessionPushClientFrame>(bytes) {
        Ok(n::SessionPushClientFrame::Ack { incarnation_id, ack }) => {
            incarnation_id == E
                && ack.ext.ext.get("inbox_seq").is_some_and(|v| v.as_u64().is_some_and(|s| s > 0))
        }
        _ => false,
    }
}

fn retired_with<T: std::fmt::Debug>(
    result: Result<T, SdkError>,
    engine: &GatewaySessionEngine,
    message: &str,
    what: &str,
) {
    match result {
        Err(SdkError::GatewaySessionRejected(got)) => assert_eq!(got, message, "{what}"),
        other => panic!("{what}: expected {message:?}, got {other:?}"),
    }
    assert!(
        matches!(engine.terminal_reason, Some(DisconnectReason::UnexpectedReply)),
        "{what}: terminal reason"
    );
}

fn golden_fetch(seq: u64) -> Vec<u8> {
    format!(r#"{{"frame_type":"fetch_entry","incarnation_id":"{E}","inbox_seq":{seq}}}"#)
        .into_bytes()
}

fn golden_batch(seqs: &[u64]) -> Vec<u8> {
    let list = seqs.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
    format!(r#"{{"frame_type":"ack_batch","incarnation_id":"{E}","inbox_seqs":[{list}]}}"#)
        .into_bytes()
}

fn value_of(frame: &F) -> Value {
    serde_json::to_value(frame).unwrap()
}

fn mutate(frame: &F, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value = value_of(frame);
    edit(&mut value);
    forwarded(&value)
}

async fn fetch(
    frames: Vec<Vec<u8>>,
    seq: u64,
) -> (Result<PointReply, SdkError>, GatewaySessionEngine) {
    let (mut engine, _) = session(push(), frames);
    let result = engine.fetch_entry(seq).await;
    (result, engine)
}

async fn batch(
    frames: Vec<Vec<u8>>,
    seqs: Vec<u64>,
) -> (Result<BatchReply, SdkError>, GatewaySessionEngine) {
    let (mut engine, _) = session(push(), frames);
    let result = engine.ack_batch(seqs).await;
    (result, engine)
}

async fn single(frames: Vec<Vec<u8>>) -> (Result<GatewayCursor, SdkError>, GatewaySessionEngine) {
    let (mut engine, _) = signed(push(), frames);
    let ack = ack_of(&engine);
    let result = engine.ack(ack).await;
    (result, engine)
}

fn sdk_record(seq: u64) -> PageEntryRecord {
    PageEntryRecord {
        entry: GatewayInboxEntry {
            forwarded: false,
            inbox_seq: seq,
            target_delivery_id: "target-route".into(),
            envelope: envelope(),
        },
        retain_until: 9_001,
    }
}

fn expected_results(seqs: &[u64]) -> Vec<AckResult> {
    seqs.iter()
        .map(|seq| AckResult { inbox_seq: *seq, outcome: AckOutcome::Acked, reason: None })
        .collect()
}

#[tokio::test]
async fn capable_point_and_ack_exact_reply_sets() {
    // (p1) entry, (p2) entry_too_large, (p3) entry_gone with observed == seq (inclusive), from
    // both producer orders; the request bytes are the golden.
    let cases: [(F, PointReply); 3] = [
        (entry_frame(7), PointReply::Entry(Box::new(sdk_record(7)))),
        (too_large(7), PointReply::TooLarge { retain_until: 9_002 }),
        (
            gone(7, 7),
            PointReply::Gone {
                observed_issued_inbox_seq: 7,
                reason: EntryGoneReason::AckWindowOverflow,
            },
        ),
    ];
    for (frame, expected) in cases {
        assert_ne!(typed(&frame), forwarded(&value_of(&frame)), "two producer orders");
        for bytes in [typed(&frame), forwarded(&value_of(&frame))] {
            let (mut engine, sent) = session(push(), vec![bytes]);
            assert_eq!(engine.fetch_entry(7).await.unwrap(), expected);
            assert_eq!(*sent.lock().unwrap(), vec![golden_fetch(7)]);
            assert!(engine.terminal_reason.is_none());
        }
    }
    // Sequence bounds: 1 and the largest interoperable JSON integer are sent; 0 is refused.
    for seq in [1, ramflux_protocol::MAX_SAFE_JSON_INTEGER] {
        let (mut engine, sent) = session(push(), vec![typed(&entry_frame(seq))]);
        assert_eq!(
            engine.fetch_entry(seq).await.unwrap(),
            PointReply::Entry(Box::new(sdk_record(seq)))
        );
        assert_eq!(*sent.lock().unwrap(), vec![golden_fetch(seq)]);
    }
    let (mut engine, sent) = session(push(), vec![typed(&entry_frame(1))]);
    let refused = engine.fetch_entry(0).await;
    assert!(matches!(&refused, Err(SdkError::GatewaySessionRejected(m))
        if m == "fetch_entry refused locally: the sequence is zero"));
    assert!(sent.lock().unwrap().is_empty() && engine.wire_writes == 0);

    // (p4) one sequence, (p5) 64 sequences (inclusive upper bound); 0 and 65 are refused
    // locally before any write.
    for count in [1_u64, 64] {
        let seqs: Vec<u64> = (1..=count).collect();
        let (mut engine, sent) = session(push(), vec![typed(&batch_frame(&seqs))]);
        assert_eq!(
            engine.ack_batch(seqs.clone()).await.unwrap(),
            BatchReply::Done { cursor: sdk_cursor(), results: expected_results(&seqs) }
        );
        assert_eq!(*sent.lock().unwrap(), vec![golden_batch(&seqs)]);
    }
    for (seqs, why) in [
        (vec![], "the batch length is outside 1..=64"),
        ((1..=65).collect::<Vec<u64>>(), "the batch length is outside 1..=64"),
        (vec![0], "a batch sequence is zero"),
        (vec![2, 2], "the batch is not strictly ascending"),
        (vec![3, 2], "the batch is not strictly ascending"),
    ] {
        let (mut engine, sent) = session(push(), vec![typed(&batch_frame(&[1]))]);
        let refused = engine.ack_batch(seqs).await;
        assert!(matches!(&refused, Err(SdkError::GatewaySessionRejected(m))
            if *m == format!("ack_batch refused locally: {why}")));
        assert!(sent.lock().unwrap().is_empty() && engine.wire_writes == 0);
    }

    // (p12) results in request order, all five outcome alternatives once across a 5-seq batch.
    let outcomes = [
        (n::SessionAckOutcome::Acked, AckOutcome::Acked, None),
        (n::SessionAckOutcome::AlreadySettled, AckOutcome::AlreadySettled, None),
        (n::SessionAckOutcome::NotFound, AckOutcome::NotFound, None),
        (n::SessionAckOutcome::InvalidSeq, AckOutcome::InvalidSeq, None),
        (n::SessionAckOutcome::Rejected, AckOutcome::Rejected, Some("ack_backpressure_retry")),
    ];
    let seqs = [11_u64, 12, 13, 14, 15];
    let frame = F::AckBatch {
        incarnation_id: E.into(),
        cursor: node_cursor("target-route"),
        results: seqs
            .iter()
            .zip(&outcomes)
            .map(|(seq, (wire, _, reason))| n::SessionAckResult {
                inbox_seq: *seq,
                outcome: *wire,
                reason: reason.map(Into::into),
            })
            .collect(),
    };
    let want: Vec<AckResult> = seqs
        .iter()
        .zip(&outcomes)
        .map(|(seq, (_, sdk, reason))| AckResult {
            inbox_seq: *seq,
            outcome: *sdk,
            reason: reason.map(Into::into),
        })
        .collect();
    for bytes in [typed(&frame), forwarded(&value_of(&frame))] {
        let (mut engine, _) = session(push(), vec![bytes]);
        assert_eq!(
            engine.ack_batch(seqs.to_vec()).await.unwrap(),
            BatchReply::Done { cursor: sdk_cursor(), results: want.clone() }
        );
    }

    // (p9)/(p10) a matching-E nack on fetch_entry and ack_batch is a typed refusal; the
    // session stays alive and serves the next reply.
    let busy = || nack(n::SessionPushNackReason::Busy, Some(E.into()));
    let (mut engine, _) = session(push(), vec![busy(), typed(&entry_frame(7))]);
    assert_eq!(engine.fetch_entry(7).await.unwrap(), PointReply::Refused(PushNackReason::Busy));
    assert!(engine.terminal_reason.is_none());
    assert!(matches!(engine.fetch_entry(7).await.unwrap(), PointReply::Entry(_)));
    let (mut engine, _) = session(push(), vec![busy(), typed(&batch_frame(&[1]))]);
    assert_eq!(engine.ack_batch(vec![1]).await.unwrap(), BatchReply::Refused(PushNackReason::Busy));
    assert!(engine.terminal_reason.is_none());
    assert!(matches!(engine.ack_batch(vec![1]).await.unwrap(), BatchReply::Done { .. }));

    // (p6) Push ack() adapts the capable ack to a GatewayCursor, sends one capable ack, and
    // records the cursor; (p11) a matching-E nack is a refusal with the session alive.
    for bytes in [typed(&ack_frame()), forwarded(&value_of(&ack_frame()))] {
        let clock = crate::time::FixedClock::set(1_700_000_000);
        let (mut engine, sent) = signed(push(), vec![bytes]);
        let ack = ack_of(&engine);
        assert_eq!(engine.ack(ack).await.unwrap(), sdk_cursor());
        drop(clock);
        assert_eq!(engine.config.last_seen_inbox_seq, 30);
        let written = sent.lock().unwrap().clone();
        assert_eq!(written.len(), 1);
        let wire: Value = serde_json::from_slice(&written[0]).unwrap();
        assert_eq!(wire["frame_type"], "ack");
        assert_eq!(wire["incarnation_id"], E);
        assert_eq!(wire["ack"]["envelope_id"], "env-route");
        assert!(wire["ack"]["signature"].is_string());
        assert_eq!(wire["ack"]["ext"]["inbox_seq"], 21);
        assert!(gateway_admits_ack(&written[0]), "the gateway would admit this ack");
        // The complete signed capable ACK as an independent literal, and decode then encode
        // (through the node-core type) is the identity.
        assert_eq!(String::from_utf8(written[0].clone()).unwrap(), PUSH_ACK_GOLDEN);
        let decoded: n::SessionPushClientFrame = serde_json::from_slice(&written[0]).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), written[0]);
    }
    let (mut engine, _) = signed(push(), vec![busy()]);
    let ack = ack_of(&engine);
    assert!(
        matches!(engine.ack(ack).await, Err(SdkError::GatewaySessionRejected(m)) if m == "busy")
    );
    assert!(engine.terminal_reason.is_none());

    // (p7) Push cursor() sends the legacy frame and accepts a keyless legacy cursor.
    let (mut engine, sent) =
        session(push(), vec![forwarded(&json!({"frame_type":"cursor","cursor":null}))]);
    assert_eq!(engine.cursor().await.unwrap(), None);
    assert_eq!(
        *sent.lock().unwrap(),
        vec![br#"{"frame_type":"cursor","target_delivery_id":"target-route"}"#.to_vec()]
    );
    // A keyless legacy nack is an accepted reply: an error, session alive.
    let keyless = forwarded(&json!({"frame_type":"nack","reason":"idempotency_conflict"}));
    let (mut engine, _) = session(push(), vec![keyless]);
    assert!(
        matches!(engine.cursor().await, Err(SdkError::GatewaySessionRejected(m)) if m == "idempotency_conflict")
    );
    assert!(engine.terminal_reason.is_none());

    // (p8) Legacy ack() writes the frozen legacy bytes: the original capture equals the
    // complete golden (the Ed25519 signature is deterministic for the fixed keys).
    let cursor = json!({"target_delivery_id":"target-route","inbox_seq":30,"last_envelope_id":null,
        "acked_envelope_ids":[],"nacked_envelope_ids":{}});
    let replies = vec![
        forwarded(&json!({"frame_type":"ack","cursor":cursor})),
        forwarded(&json!({"frame_type":"cursor","cursor":null})),
    ];
    let (mut engine, sent) = signed(SessionMode::Legacy, replies);
    let ack = ack_of(&engine);
    assert_eq!(engine.ack(ack).await.unwrap().inbox_seq, 30);
    let written = sent.lock().unwrap().clone();
    assert_eq!(written.len(), 1);
    assert_eq!(String::from_utf8(written[0].clone()).unwrap(), LEGACY_ACK_GOLDEN);
    let decoded: crate::gateway::GatewayClientFrame = serde_json::from_slice(&written[0]).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), written[0]);

    refusal_rows().await;
    set_rows().await;
}

async fn refusal_rows() {
    // (r1)-(r4) fetch_entry and ack_batch on Legacy and on Compat: refused locally, no write.
    for mode in [SessionMode::Legacy, SessionMode::Compat] {
        let (mut engine, sent) = session(mode.clone(), vec![typed(&entry_frame(7))]);
        let result = engine.fetch_entry(7).await;
        assert!(matches!(&result, Err(SdkError::GatewaySessionRejected(m))
            if m == "fetch_entry refused locally: the session is not negotiated"));
        assert!(sent.lock().unwrap().is_empty() && engine.wire_writes == 0);
        assert!(engine.terminal_reason.is_none());
        let (mut engine, sent) = session(mode, vec![typed(&batch_frame(&[1]))]);
        let result = engine.ack_batch(vec![1]).await;
        assert!(matches!(&result, Err(SdkError::GatewaySessionRejected(m))
            if m == "ack_batch refused locally: the session is not negotiated"));
        assert!(sent.lock().unwrap().is_empty() && engine.wire_writes == 0);
        assert!(engine.terminal_reason.is_none());
    }

    // The unmutated replies are valid; each row below changes exactly one field.
    assert!(fetch(vec![typed(&entry_frame(7))], 7).await.0.is_ok());
    assert!(fetch(vec![typed(&too_large(7))], 7).await.0.is_ok());
    assert!(fetch(vec![typed(&gone(7, 7))], 7).await.0.is_ok());
    assert!(batch(vec![typed(&batch_frame(&[1, 2, 3]))], vec![1, 2, 3]).await.0.is_ok());
    assert!(single(vec![typed(&ack_frame())]).await.0.is_ok());

    let other_e = json!(eid(0xff));
    // (r5)-(r7) foreign E on entry, entry_too_large, entry_gone; (r18) on ack_batch; (r19) on ack.
    for (row, frame) in [("r5", entry_frame(7)), ("r6", too_large(7)), ("r7", gone(7, 7))] {
        let bytes = mutate(&frame, |v| v["incarnation_id"] = other_e.clone());
        let (result, engine) = fetch(vec![bytes], 7).await;
        retired_with(result, &engine, FOREIGN_E, row);
    }
    let bytes = mutate(&batch_frame(&[1, 2, 3]), |v| v["incarnation_id"] = other_e.clone());
    let (result, engine) = batch(vec![bytes], vec![1, 2, 3]).await;
    retired_with(result, &engine, FOREIGN_E, "r18");
    let bytes = mutate(&ack_frame(), |v| v["incarnation_id"] = other_e.clone());
    let (result, engine) = single(vec![bytes]).await;
    retired_with(result, &engine, FOREIGN_E, "r19");

    // (r8) entry with the wrong seq (both directions), (r9) wrong target, (r10) too_large
    // wrong seq, (r11) gone wrong seq, (r12) gone observed = seq - 1.
    for (row, seq) in [("r8-", 6), ("r8+", 8)] {
        let (result, engine) = fetch(vec![typed(&entry_frame(seq))], 7).await;
        retired_with(
            result,
            &engine,
            "unexpected gateway frame: entry for a different sequence",
            row,
        );
    }
    let bytes = mutate(&entry_frame(7), |v| {
        v["record"]["entry"]["target_delivery_id"] = json!("target-other");
    });
    let (result, engine) = fetch(vec![bytes], 7).await;
    retired_with(result, &engine, "unexpected gateway frame: entry for a different target", "r9");
    for (row, seq) in [("r10-", 6), ("r10+", 8)] {
        let (result, engine) = fetch(vec![typed(&too_large(seq))], 7).await;
        retired_with(
            result,
            &engine,
            "unexpected gateway frame: entry_too_large for a different sequence",
            row,
        );
    }
    for (row, seq) in [("r11-", 6), ("r11+", 8)] {
        let (result, engine) = fetch(vec![typed(&gone(seq, 9))], 7).await;
        retired_with(
            result,
            &engine,
            "unexpected gateway frame: entry_gone for a different sequence",
            row,
        );
    }
    let (result, engine) = fetch(vec![typed(&gone(7, 6))], 7).await;
    retired_with(
        result,
        &engine,
        "unexpected gateway frame: entry_gone observed below the requested sequence",
        "r12",
    );

    // (r17) batch cursor target, (r20) single-ACK cursor target.
    let bytes = mutate(&batch_frame(&[1, 2, 3]), |v| {
        v["cursor"]["target_delivery_id"] = json!("target-other");
    });
    let (result, engine) = batch(vec![bytes], vec![1, 2, 3]).await;
    retired_with(
        result,
        &engine,
        "unexpected gateway frame: ack_batch cursor for a different target",
        "r17",
    );
    let bytes = mutate(&ack_frame(), |v| v["cursor"]["target_delivery_id"] = json!("target-other"));
    let (result, engine) = single(vec![bytes]).await;
    retired_with(
        result,
        &engine,
        "unexpected gateway frame: ack cursor for a different target",
        "r20",
    );
    // (r21) a single ACK reply that carries `results` is malformed (no fallback).
    let bytes = mutate(&ack_frame(), |v| v["results"] = json!([]));
    let (result, engine) = single(vec![bytes]).await;
    assert!(matches!(result, Err(SdkError::Protocol(ramflux_protocol::ProtocolError::IJson(_)))));
    assert!(matches!(engine.terminal_reason, Some(DisconnectReason::Transport)), "r21");

    // (r13)-(r16) the result list against the requested [1, 2, 3].
    let mismatch =
        "unexpected gateway frame: ack_batch results do not match the requested sequences";
    for (row, results) in [
        ("r13 missing", vec![1, 2]),
        ("r14 extra", vec![1, 2, 3, 4]),
        ("r15 duplicated", vec![1, 2, 2]),
        ("r16 out of order", vec![1, 3, 2]),
        ("r16 wrong seq", vec![1, 2, 4]),
    ] {
        let (result, engine) = batch(vec![typed(&batch_frame(&results))], vec![1, 2, 3]).await;
        retired_with(result, &engine, mismatch, row);
    }

    // (r22)-(r24) a nack with a foreign E on fetch_entry, ack_batch and Push ack().
    let foreign = || nack(n::SessionPushNackReason::Busy, Some(eid(0xff)));
    let (result, engine) = fetch(vec![foreign()], 7).await;
    retired_with(result, &engine, FOREIGN_NACK, "r22");
    let (result, engine) = batch(vec![foreign()], vec![1]).await;
    retired_with(result, &engine, FOREIGN_NACK, "r23");
    let (result, engine) = single(vec![foreign()]).await;
    retired_with(result, &engine, FOREIGN_NACK, "r24");
}

/// Legacy frames that are replies of some kind, with their exact retirement text.
fn legacy_rows() -> Vec<(&'static str, Value, String)> {
    let mut rows = legacy_unexpected_kinds();
    rows.push((
        "forward_ack",
        json!({"frame_type":"forward_ack","ack":{
            "envelope_id":"env-route","target_delivery_id":"target-route","inbox_seq":9}}),
        "unexpected gateway reply: ForwardAck".into(),
    ));
    rows.push((
        "nack",
        json!({"frame_type":"nack","reason":"idempotency_conflict"}),
        "unexpected gateway reply: Nack".into(),
    ));
    assert_eq!(rows.len(), 15);
    rows
}

async fn set_rows() {
    let capable = all_kinds();
    assert_eq!(capable.len(), 9);
    let legacy = legacy_rows();

    // (r25)-(r29) fetch_entry: 5 unexpected capable kinds, 15 legacy.
    let accepted = ["entry", "entry_too_large", "entry_gone", "nack"];
    let mut count = 0;
    for (name, bytes) in &capable {
        if accepted.contains(name) {
            continue;
        }
        count += 1;
        let (result, engine) = fetch(vec![bytes.clone()], 7).await;
        retired_with(result, &engine, UNEXPECTED, &format!("fetch {name}"));
    }
    assert_eq!(count, 5);
    for (name, wire, message) in &legacy {
        let (result, engine) = fetch(vec![forwarded(wire)], 7).await;
        retired_with(result, &engine, message, &format!("fetch legacy {name}"));
    }

    // (r30)-(r36) ack_batch: 7 unexpected capable kinds, 15 legacy.
    let accepted = ["ack_batch", "nack"];
    let mut count = 0;
    for (name, bytes) in &capable {
        if accepted.contains(name) {
            continue;
        }
        count += 1;
        let (result, engine) = batch(vec![bytes.clone()], vec![1]).await;
        retired_with(result, &engine, UNEXPECTED, &format!("batch {name}"));
    }
    assert_eq!(count, 7);
    for (name, wire, message) in &legacy {
        let (result, engine) = batch(vec![forwarded(wire)], vec![1]).await;
        retired_with(result, &engine, message, &format!("batch legacy {name}"));
    }

    // (r37)-(r43) Push ack(): 7 unexpected capable kinds, 15 legacy.
    let accepted = ["ack", "nack"];
    let mut count = 0;
    for (name, bytes) in &capable {
        if accepted.contains(name) {
            continue;
        }
        count += 1;
        let (result, engine) = single(vec![bytes.clone()]).await;
        retired_with(result, &engine, UNEXPECTED, &format!("ack {name}"));
    }
    assert_eq!(count, 7);
    for (name, wire, message) in &legacy {
        let (result, engine) = single(vec![forwarded(wire)]).await;
        retired_with(result, &engine, message, &format!("ack legacy {name}"));
    }

    // (r44)-(r52) Push cursor(): all 9 capable kinds are unexpected (it is a legacy
    // operation), and 13 legacy kinds (everything but the keyless cursor and nack).
    for (name, bytes) in &capable {
        let (mut engine, _) = session(push(), vec![bytes.clone()]);
        let result = engine.cursor().await;
        retired_with(result, &engine, OUTSIDE, &format!("cursor {name}"));
    }
    let mut count = 0;
    for (name, wire, message) in &legacy {
        if matches!(*name, "cursor" | "nack") {
            continue;
        }
        count += 1;
        let (mut engine, _) = session(push(), vec![forwarded(wire)]);
        let result = engine.cursor().await;
        retired_with(result, &engine, message, &format!("cursor legacy {name}"));
    }
    assert_eq!(count, 13);
}
