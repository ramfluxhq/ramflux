// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `capable_resume_page_exact_reply`: the `resume_page` operation and its adapters.
//!
//! Oracle: node-core builds every page from distinct non-default values, in both producer
//! orders (struct order and sorted `Value` order). The whole decoded reply is compared with
//! an explicitly constructed expected value. Every refusal starts from a valid page and
//! changes one field.
use super::routing_tests::{E, capable_deliver, envelope, push};
use super::split_tests::legacy_unexpected_kinds;
use super::{KnownLoss, PageEntryRecord, PageReason, PushMeta, PushNackReason, SessionMode};
use crate::SdkError;
use crate::bus::connection_manager::DisconnectReason;
use crate::gateway::push_resume::{PageReply, ResumePage};
use crate::gateway::{
    GatewayInboxEntry, GatewayQuicEndpointConfig, GatewaySessionConfig, GatewaySessionEngine,
};
use n::SessionPushServerFrame as F;
use ramflux_node_core as n;
use ramflux_transport::{
    GatewaySessionFrameSink, GatewaySessionFrameSource, GatewaySessionTransport, TransportError,
};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;
pub(super) type Sent = Arc<Mutex<Vec<Vec<u8>>>>;

/// Serves the scripted frames in order and records every client frame.
pub(super) struct Gateway {
    pub(super) frames: VecDeque<Vec<u8>>,
    pub(super) sent: Sent,
}

impl GatewaySessionFrameSink for Gateway {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(frame.to_vec());
            Ok(())
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for Gateway {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        let frame = self.frames.pop_front();
        Box::pin(async move {
            if let Some(frame) = frame { Ok(frame) } else { std::future::pending().await }
        })
    }
}

pub(super) fn session(mode: SessionMode, frames: Vec<Vec<u8>>) -> (GatewaySessionEngine, Sent) {
    let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse().unwrap(),
        gateway_addr: "127.0.0.1:443".parse().unwrap(),
        server_name: "localhost".into(),
        ca_cert: "test-ca.pem".into(),
        principal_id: "route-principal".into(),
        device_id: "route-device".into(),
        target_delivery_id: "target-route".into(),
        prekey_http_url: None,
    });
    let sent: Sent = Arc::default();
    let stream: Box<dyn GatewaySessionTransport + Send> =
        Box::new(Gateway { frames: frames.into(), sent: Arc::clone(&sent) });
    let mut engine = GatewaySessionEngine::with_test_transport(config, stream);
    engine.mode = mode;
    (engine, sent)
}

pub(super) fn eid(first: u8) -> String {
    format!("{first:02x}{}", &E[2..])
}

pub(super) fn node_record(seq: u64, retain_until: i64) -> n::PageEntryRecord {
    n::PageEntryRecord {
        entry: n::InboxEntry {
            inbox_seq: seq,
            target_delivery_id: "target-route".into(),
            envelope: envelope(),
        },
        retain_until,
    }
}

fn sdk_record(seq: u64, retain_until: i64) -> PageEntryRecord {
    PageEntryRecord {
        entry: GatewayInboxEntry {
            forwarded: false,
            inbox_seq: seq,
            target_delivery_id: "target-route".into(),
            envelope: envelope(),
        },
        retain_until,
    }
}

/// The node-core page for a request after `after`, with distinct non-default values.
fn page(after: u64) -> F {
    F::ResumePage {
        target_delivery_id: "target-route".into(),
        incarnation_id: E.into(),
        after_inbox_seq: after,
        covered_through_seq: 17,
        issued_inbox_seq: 19,
        settled_through_seq: 5,
        entries: vec![node_record(21, 3_333), node_record(22, 4_444)],
        known_losses: vec![n::KnownLoss { from_seq: 6, to_seq: 7, reason: n::PageReason::Expired }],
        oversize_next: Some(23),
        more: true,
    }
}

fn expected(after: u64) -> PageReply {
    PageReply::Page(Box::new(ResumePage {
        after_inbox_seq: after,
        covered_through_seq: 17,
        issued_inbox_seq: 19,
        settled_through_seq: 5,
        entries: vec![sdk_record(21, 3_333), sdk_record(22, 4_444)],
        known_losses: vec![KnownLoss { from_seq: 6, to_seq: 7, reason: PageReason::Expired }],
        oversize_next: Some(23),
        more: true,
    }))
}

/// Producer order (i): node-core struct order.
pub(super) fn typed(frame: &F) -> Vec<u8> {
    serde_json::to_vec(frame).unwrap()
}

/// Producer order (ii): sorted-key `Value` order, as forwarded router JSON.
pub(super) fn forwarded(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

pub(super) fn nack(reason: n::SessionPushNackReason, key: Option<String>) -> Vec<u8> {
    typed(&F::Nack { reason, incarnation_id: key })
}

/// The golden bytes of the capable resume frame for `(after, limit)`.
fn golden(after: u64, limit: usize) -> Vec<u8> {
    format!(
        r#"{{"frame_type":"resume","resume":{{"target_delivery_id":"target-route","after_inbox_seq":{after},"limit":{limit},"resume_token":"test-resume"}},"incarnation_id":"{E}"}}"#
    )
    .into_bytes()
}

fn assert_retired(
    result: Result<PageReply, SdkError>,
    engine: &GatewaySessionEngine,
    message: &str,
    what: &str,
) {
    match result {
        Err(SdkError::GatewaySessionRejected(got)) => assert_eq!(got, message, "{what}"),
        other => panic!("{what}: expected a retirement ({message}), got {other:?}"),
    }
    assert!(
        matches!(engine.terminal_reason, Some(DisconnectReason::UnexpectedReply)),
        "{what}: terminal reason"
    );
}

async fn ask(
    frames: Vec<Vec<u8>>,
    after: u64,
) -> (Result<PageReply, SdkError>, GatewaySessionEngine) {
    let (mut engine, _) = session(push(), frames);
    let result = engine.resume_page(after, 64).await;
    (result, engine)
}

/// A Push session that already buffered the capable deliver `71` (envelope `env-pushed`) and
/// will answer the request with the page after `7`.
fn buffered() -> GatewaySessionEngine {
    let (mut engine, _) = session(push(), vec![typed(&page(7))]);
    let mut pushed = envelope();
    pushed.envelope_id = "env-pushed".into();
    engine.last_frame_bytes = 1;
    engine.buffer_delivery(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 71,
        target_delivery_id: "target-route".into(),
        envelope: pushed,
    });
    engine
}

fn seqs(entries: &[GatewayInboxEntry]) -> Vec<u64> {
    entries.iter().map(|entry| entry.inbox_seq).collect()
}

#[tokio::test]
async fn capable_resume_page_exact_reply() {
    // Oracle: node-core produces exactly the golden request bytes.
    let resume: n::GatewayResumeFrame = serde_json::from_value(json!({
        "target_delivery_id":"target-route","after_inbox_seq":7,"limit":64,
        "resume_token":"test-resume"}))
    .unwrap();
    let node_bytes =
        serde_json::to_vec(&n::SessionPushClientFrame::Resume { resume, incarnation_id: E.into() })
            .unwrap();
    assert_eq!(node_bytes, golden(7, 64), "node-core still produces the golden bytes");

    // (p1) a page round-trips from both producer orders; the request bytes are the golden.
    let value = serde_json::to_value(page(7)).unwrap();
    assert_ne!(typed(&page(7)), forwarded(&value), "two producer orders");
    for (order, bytes) in [("typed", typed(&page(7))), ("forwarded", forwarded(&value))] {
        let (mut engine, sent) = session(push(), vec![bytes]);
        assert_eq!(engine.resume_page(7, 64).await.unwrap(), expected(7), "{order}");
        assert_eq!(*sent.lock().unwrap(), vec![golden(7, 64)], "{order}");
        assert!(engine.terminal_reason.is_none());
    }

    // (p2) a capable nack with the matching E is a typed refusal; the session stays alive and
    // serves the next page.
    let (mut engine, _) = session(
        push(),
        vec![nack(n::SessionPushNackReason::Busy, Some(E.into())), typed(&page(7))],
    );
    assert_eq!(engine.resume_page(7, 64).await.unwrap(), PageReply::Refused(PushNackReason::Busy));
    assert!(engine.terminal_reason.is_none());
    assert_eq!(engine.resume_page(7, 64).await.unwrap(), expected(7));

    // (p3) Push `resume_after` returns the buffered deliver first, then the adapted page
    // entries; `resume_authoritative_after` returns the page only and drops the buffer.
    let mut engine = buffered();
    assert_eq!(seqs(&engine.resume_after(7, 64).await.unwrap()), [71, 21]);
    assert!(engine.pending_deliveries.is_empty());
    let mut engine = buffered();
    assert_eq!(seqs(&engine.resume_authoritative_after(7, 64).await.unwrap()), [21]);
    assert!(engine.pending_deliveries.is_empty(), "the authoritative path drops pushed entries");
    // The adapters surface a keyed refusal as the reason text and keep the session alive.
    for authoritative in [false, true] {
        let (mut engine, _) =
            session(push(), vec![nack(n::SessionPushNackReason::CursorAhead, Some(E.into()))]);
        let result = if authoritative {
            engine.resume_authoritative_after(7, 64).await
        } else {
            engine.resume_after(7, 64).await
        };
        assert!(matches!(&result, Err(SdkError::GatewaySessionRejected(m)) if m == "cursor_ahead"));
        assert!(engine.terminal_reason.is_none());
    }

    // (p3b) a refusal must not consume buffered deliveries: a locally refused resume
    // (limit 0) and a matching-E Busy refusal both leave the queue, its push metadata and
    // its byte accounting intact, on both public entry points.
    for authoritative in [false, true] {
        for busy in [false, true] {
            let frames = if busy {
                vec![nack(n::SessionPushNackReason::Busy, Some(E.into()))]
            } else {
                vec![]
            };
            let (mut engine, sent) = session(push(), frames);
            let meta = PushMeta { incarnation_id: super::routing_tests::id(), retain_until: 5_555 };
            engine.last_frame_bytes = 7;
            engine.buffer_capable_delivery(
                GatewayInboxEntry {
                    forwarded: false,
                    inbox_seq: 71,
                    target_delivery_id: "target-route".into(),
                    envelope: envelope(),
                },
                meta.clone(),
            );
            let limit = if busy { 64 } else { 0 };
            let result = if authoritative {
                engine.resume_authoritative_after(7, limit).await
            } else {
                engine.resume_after(7, limit).await
            };
            let want = if busy { "busy" } else { "resume_page refused locally: the limit is zero" };
            assert!(
                matches!(&result, Err(SdkError::GatewaySessionRejected(m)) if m == want),
                "auth={authoritative} busy={busy}: {result:?}"
            );
            assert!(engine.terminal_reason.is_none());
            assert_eq!(sent.lock().unwrap().is_empty(), !busy, "a write happens only for busy");
            assert_eq!(engine.pending_deliveries.len(), 1, "auth={authoritative} busy={busy}");
            assert_eq!(engine.buffered_bytes, 7, "auth={authoritative} busy={busy}");
            let kept = engine.take_pending_capable();
            assert_eq!(kept[0].0.inbox_seq, 71);
            assert_eq!(kept[0].1, Some(meta));
        }
    }

    // (p4) Legacy `resume_after` and `resume_authoritative_after` write the frozen legacy
    // bytes and are unchanged.
    let legacy_bytes = br#"{"frame_type":"resume","resume":{"target_delivery_id":"target-route","after_inbox_seq":7,"limit":64,"resume_token":"test-resume"}}"#.to_vec();
    for authoritative in [false, true] {
        let reply = forwarded(&json!({"frame_type":"resume","entries":[]}));
        let (mut engine, sent) = session(SessionMode::Legacy, vec![reply]);
        let result = if authoritative {
            engine.resume_authoritative_after(7, 64).await
        } else {
            engine.resume_after(7, 64).await
        };
        assert_eq!(result.unwrap(), Vec::<GatewayInboxEntry>::new());
        assert_eq!(*sent.lock().unwrap(), vec![legacy_bytes.clone()]);
    }

    // (p5) a capable deliver arriving mid-wait is buffered with its metadata and the wait
    // completes.
    let (mut engine, _) = session(push(), vec![forwarded(&capable_deliver()), typed(&page(7))]);
    assert_eq!(engine.resume_page(7, 64).await.unwrap(), expected(7));
    let pending = engine.take_pending_capable();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0.inbox_seq, 71);

    // (p6) bounds, inclusive at both ends: limit 1 and the cursor extremes are sent and
    // echoed; limit 0 is refused before any write.
    for (after, limit) in [(0, 1), (u64::MAX, 1), (u64::MAX, 256)] {
        let (mut engine, sent) = session(push(), vec![typed(&page(after))]);
        assert_eq!(engine.resume_page(after, limit).await.unwrap(), expected(after));
        assert_eq!(*sent.lock().unwrap(), vec![golden(after, limit)]);
    }
    let (mut engine, sent) = session(push(), vec![typed(&page(7))]);
    let refused = engine.resume_page(7, 0).await;
    assert!(matches!(&refused, Err(SdkError::GatewaySessionRejected(m))
            if m == "resume_page refused locally: the limit is zero"));
    assert!(sent.lock().unwrap().is_empty() && engine.wire_writes == 0);
    assert!(engine.terminal_reason.is_none());

    isolated_rows().await;
}

async fn isolated_rows() {
    // (r1) Legacy and (r2) Compat: refused locally, `wire_writes` unchanged, no retirement.
    for mode in [SessionMode::Legacy, SessionMode::Compat] {
        let (mut engine, sent) = session(mode, vec![typed(&page(7))]);
        let result = engine.resume_page(7, 64).await;
        assert!(matches!(&result, Err(SdkError::GatewaySessionRejected(m))
                if m == "resume_page refused locally: the session is not negotiated"));
        assert!(sent.lock().unwrap().is_empty() && engine.wire_writes == 0);
        assert!(engine.terminal_reason.is_none());
    }

    // The unmutated page is valid; each row below changes exactly one field.
    let (valid, _) = ask(vec![typed(&page(7))], 7).await;
    assert_eq!(valid.unwrap(), expected(7));
    let base = serde_json::to_value(page(7)).unwrap();
    let mutated = |key: &str, to: Value| {
        let mut value = base.clone();
        value[key] = to;
        forwarded(&value)
    };
    // (r3) reply E differs, (r4) target differs, (r5) cursor differs in both directions.
    let rows = [
        (
            "r3",
            mutated("incarnation_id", json!(eid(0xff))),
            "resume_page with a foreign incarnation",
        ),
        (
            "r4",
            mutated("target_delivery_id", json!("target-other")),
            "resume_page for a different target",
        ),
        ("r5-", mutated("after_inbox_seq", json!(6)), "resume_page for a different cursor"),
        ("r5+", mutated("after_inbox_seq", json!(8)), "resume_page for a different cursor"),
    ];
    for (row, bytes, why) in rows {
        let (result, engine) = ask(vec![bytes], 7).await;
        assert_retired(result, &engine, &format!("unexpected gateway frame: {why}"), row);
    }
    // (r29) a page entry whose target is not T.
    let mut elsewhere = base.clone();
    elsewhere["entries"][1]["entry"]["target_delivery_id"] = json!("target-other");
    let (result, engine) = ask(vec![forwarded(&elsewhere)], 7).await;
    assert_retired(
        result,
        &engine,
        "unexpected gateway frame: resume_page entry for a different target",
        "r29",
    );

    // (r6) a capable nack with a foreign E.
    let (result, engine) =
        ask(vec![nack(n::SessionPushNackReason::Busy, Some(eid(0xff)))], 7).await;
    assert_retired(
        result,
        &engine,
        "unexpected gateway frame: capable nack with a foreign incarnation",
        "r6",
    );
    // (r7) a legacy keyless nack during the wait.
    let keyless = forwarded(&json!({"frame_type":"nack","reason":"idempotency_conflict"}));
    let (result, engine) = ask(vec![keyless], 7).await;
    assert_retired(result, &engine, "unexpected gateway reply: Nack", "r7");

    // (r8)-(r14) each other capable reply kind.
    let cursor = n::InboxCursorResponse {
        target_delivery_id: "target-route".into(),
        inbox_seq: 1,
        last_envelope_id: None,
        acked_envelope_ids: vec![],
        nacked_envelope_ids: std::collections::BTreeMap::default(),
    };
    let others = [
        (
            "submit_accepted",
            F::SubmitAccepted {
                incarnation_id: E.into(),
                envelope_id: "env-route".into(),
                target_delivery_id: "target-route".into(),
                inbox_seq: 3,
            },
        ),
        ("entry", F::Entry { incarnation_id: E.into(), record: Box::new(node_record(21, 1)) }),
        (
            "entry_too_large",
            F::EntryTooLarge { incarnation_id: E.into(), inbox_seq: 1, retain_until: 1 },
        ),
        (
            "entry_gone",
            F::EntryGone {
                incarnation_id: E.into(),
                inbox_seq: 1,
                observed_issued_inbox_seq: 1,
                reason: n::EntryGoneReason::Expired,
            },
        ),
        (
            "ack_batch",
            F::AckBatch { incarnation_id: E.into(), cursor: cursor.clone(), results: vec![] },
        ),
        ("ack", F::Ack { incarnation_id: E.into(), cursor: cursor.clone() }),
        ("cursor", F::Cursor { incarnation_id: E.into(), cursor: Some(cursor) }),
    ];
    assert_eq!(others.len(), 7);
    for (name, frame) in others {
        let (result, engine) = ask(vec![typed(&frame)], 7).await;
        assert_retired(
            result,
            &engine,
            "unexpected gateway frame: unexpected capable reply while awaiting a page",
            name,
        );
    }

    // (r15)-(r28) each legacy reply kind: the 13 of the submit table plus `forward_ack`.
    let mut legacy = legacy_unexpected_kinds();
    legacy.push((
        "forward_ack",
        json!({"frame_type":"forward_ack","ack":{
            "envelope_id":"env-route","target_delivery_id":"target-route","inbox_seq":9}}),
        "unexpected gateway reply: ForwardAck".into(),
    ));
    assert_eq!(legacy.len(), 14);
    for (name, wire, message) in legacy {
        let (result, engine) = ask(vec![forwarded(&wire)], 7).await;
        match result {
            Err(SdkError::GatewaySessionRejected(got)) => assert_eq!(got, message, "{name}"),
            other => panic!("{name}: expected {message:?}, got {other:?}"),
        }
        assert!(
            matches!(engine.terminal_reason, Some(DisconnectReason::UnexpectedReply)),
            "{name}"
        );
    }
}
