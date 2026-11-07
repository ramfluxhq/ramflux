// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `push_reader_routes_shared_and_capable_frames`: the raw-byte routing table.
//!
//! Capable vectors come from node-core typed frames. Every row runs through the real reader
//! (`read_reply`/`idle_read`) on a scripted transport, or through `route` for the decoder choice.
use super::{
    CapableServerFrame as C, IncarnationId, PushNackReason, ResyncReason, RouteError, Routed,
    SessionMode, route,
};
use crate::SdkError;
use crate::bus::connection_manager::DisconnectReason;
use crate::gateway::frame_dispatch::ExpectedReply;
use crate::gateway::{
    GatewayQuicEndpointConfig, GatewayServerFrame, GatewaySessionConfig, GatewaySessionEngine,
};
use ramflux_node_core as n;
use ramflux_transport::{
    GatewaySessionFrameSink, GatewaySessionFrameSource, GatewaySessionTransport, TransportError,
};
use serde_json::{Value, json};
use std::collections::VecDeque;

const E: &str = "0123456789abcdef0123456789abcdef";

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;

/// Serves the scripted frames in order, then idles.
struct Script(VecDeque<Vec<u8>>);

impl GatewaySessionFrameSink for Script {
    fn send_frame<'a>(&'a mut self, _frame: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for Script {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        let frame = self.0.pop_front();
        Box::pin(async move {
            if let Some(frame) = frame { Ok(frame) } else { std::future::pending().await }
        })
    }
}

fn id() -> IncarnationId {
    IncarnationId::try_from(E.to_owned()).unwrap()
}

fn push() -> SessionMode {
    SessionMode::Push { incarnation: id() }
}

fn scripted(mode: SessionMode, frames: Vec<Value>) -> GatewaySessionEngine {
    let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse().unwrap(),
        gateway_addr: "127.0.0.1:443".parse().unwrap(),
        server_name: "localhost".into(),
        ca_cert: "test-ca.pem".into(),
        principal_id: "route-principal".into(),
        device_id: "route-device".into(),
        target_delivery_id: "route-target".into(),
        prekey_http_url: None,
    });
    let script: Vec<Vec<u8>> =
        frames.into_iter().map(|f| serde_json::to_vec(&f).unwrap()).collect();
    let stream: Box<dyn GatewaySessionTransport + Send> = Box::new(Script(script.into()));
    let mut engine = GatewaySessionEngine::with_test_transport(config, stream);
    engine.mode = mode;
    engine
}

fn envelope() -> ramflux_protocol::Envelope {
    serde_json::from_value(json!({
        "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
        "signing_key_id":"dev","signature_alg":"ed25519","signature":"fixture",
        "envelope_id":"env-route","source_principal_id":"p","source_device_id":"d",
        "target_delivery_id":"target-route","delivery_class":"opaque_event",
        "priority":"normal","ttl":600,"created_at":1,"encrypted_payload":"opaque",
        "payload_hash":"hash-route"
    }))
    .unwrap()
}

fn node_entry() -> n::InboxEntry {
    n::InboxEntry { inbox_seq: 71, target_delivery_id: "target-route".into(), envelope: envelope() }
}

fn capable(frame: &n::SessionPushServerFrame) -> Value {
    serde_json::to_value(frame).unwrap()
}

fn capable_deliver() -> Value {
    capable(&n::SessionPushServerFrame::Deliver {
        entry: node_entry(),
        incarnation_id: E.into(),
        retain_until: 7_777,
    })
}

fn capable_resync() -> Value {
    capable(&n::SessionPushServerFrame::Resync {
        incarnation_id: E.into(),
        target_delivery_id: "target-route".into(),
        after_inbox_seq: 72,
        reason: n::SessionPushResyncReason::QueueFull,
    })
}

fn capable_nack(incarnation_id: Option<&str>) -> Value {
    capable(&n::SessionPushServerFrame::Nack {
        reason: n::SessionPushNackReason::Busy,
        incarnation_id: incarnation_id.map(Into::into),
    })
}

fn legacy_nack(reason: &str) -> Value {
    json!({"frame_type":"nack","reason":reason})
}

fn heartbeat() -> Value {
    json!({"frame_type":"heartbeat","now":5})
}

fn legacy_deliver() -> Value {
    json!({"frame_type":"deliver","entry":{
        "inbox_seq":71,"target_delivery_id":"target-route","envelope":envelope()}})
}

/// Reads one legacy reply through the real reader.
async fn read(engine: &mut GatewaySessionEngine) -> Result<GatewayServerFrame, SdkError> {
    engine.read_reply(ExpectedReply::Heartbeat).await
}

fn retired(result: Result<GatewayServerFrame, SdkError>, engine: &GatewaySessionEngine, why: &str) {
    match result {
        Err(SdkError::GatewaySessionRejected(message)) => {
            assert_eq!(message, format!("unexpected gateway frame: {why}"));
        }
        other => panic!("expected a retirement ({why}), got {other:?}"),
    }
    assert!(matches!(engine.terminal_reason, Some(DisconnectReason::UnexpectedReply)));
    assert!(engine.capable_events.is_empty(), "a refused frame must not queue an event");
}

#[tokio::test]
async fn push_reader_routes_shared_and_capable_frames() {
    // (p1)-(p3) keyless legacy nacks decode as legacy Nack in Push mode.
    for reason in ["aborted_retry_safe", "capacity_retry_after", "idempotency_conflict"] {
        let mut engine = scripted(push(), vec![legacy_nack(reason)]);
        let frame = read(&mut engine).await.unwrap();
        assert_eq!(frame, GatewayServerFrame::Nack { reason: reason.into() });
    }
    // (p4) legacy heartbeat reply.
    let mut engine = scripted(push(), vec![heartbeat()]);
    assert_eq!(read(&mut engine).await.unwrap(), GatewayServerFrame::Heartbeat { now: 5 });
    // (p5) drain and (p6) close give the terminal outcome.
    let mut engine =
        scripted(push(), vec![json!({"frame_type":"drain","session_id":"s","reason":"r"})]);
    assert!(read(&mut engine).await.is_err());
    assert!(matches!(engine.terminal_reason, Some(DisconnectReason::Drain)));
    let mut engine = scripted(push(), vec![json!({"frame_type":"close","reason":"r"})]);
    assert!(read(&mut engine).await.is_err());
    assert!(matches!(engine.terminal_reason, Some(DisconnectReason::Close)));
    // (p7) in_band_wake is an event; the reply behind it is still returned.
    let wake = json!({"frame_type":"in_band_wake","target_delivery_id":"t","delivery_class":"opaque_event"});
    let mut engine = scripted(push(), vec![wake, heartbeat()]);
    assert_eq!(read(&mut engine).await.unwrap(), GatewayServerFrame::Heartbeat { now: 5 });
    // (p8) keyless legacy cursor reply.
    let mut engine = scripted(push(), vec![json!({"frame_type":"cursor","cursor":null})]);
    let frame = engine.read_reply(ExpectedReply::Cursor).await.unwrap();
    assert_eq!(frame, GatewayServerFrame::Cursor { cursor: None });

    // (p9)/(p10) capable nack with a null E and with an E choose the capable decoder.
    for (key, expected) in [(None, None), (Some(E), Some(id()))] {
        let bytes = serde_json::to_vec(&capable_nack(key)).unwrap();
        match route(&bytes, &push()).unwrap() {
            Routed::Capable(frame) => match *frame {
                C::Nack { reason, incarnation_id } => {
                    assert_eq!(reason, PushNackReason::Busy);
                    assert_eq!(incarnation_id, expected);
                }
                other => panic!("not a capable nack: {other:?}"),
            },
            Routed::Legacy(other) => panic!("not capable: {other:?}"),
        }
    }

    // (p11)/(p12) capable events reach the queue while a legacy heartbeat wait is active, in
    // order, and the heartbeat still completes.
    let mut engine = scripted(push(), vec![capable_deliver(), capable_resync(), heartbeat()]);
    assert_eq!(read(&mut engine).await.unwrap(), GatewayServerFrame::Heartbeat { now: 5 });
    assert_eq!(engine.capable_events.len(), 2);
    match &engine.capable_events[0] {
        C::Deliver { entry, incarnation_id, retain_until } => {
            assert_eq!(entry.inbox_seq, 71);
            assert_eq!(incarnation_id, &id());
            assert_eq!(*retain_until, 7_777);
        }
        other => panic!("not a deliver: {other:?}"),
    }
    match &engine.capable_events[1] {
        C::Resync { target_delivery_id, after_inbox_seq, reason, .. } => {
            assert_eq!(target_delivery_id, "target-route");
            assert_eq!(*after_inbox_seq, 72);
            assert_eq!(*reason, ResyncReason::QueueFull);
        }
        other => panic!("not a resync: {other:?}"),
    }

    // (p13) Legacy mode: every legacy vector decodes byte-for-byte as before routing.
    let vectors = [
        heartbeat(),
        legacy_nack("aborted_retry_safe"),
        legacy_deliver(),
        json!({"frame_type":"cursor","cursor":null}),
        json!({"frame_type":"forward_ack","ack":{
            "envelope_id":"env-route","target_delivery_id":"target-route","inbox_seq":9}}),
        json!({"frame_type":"resume","entries":[]}),
    ];
    for vector in vectors {
        let bytes = serde_json::to_vec(&vector).unwrap();
        let direct: GatewayServerFrame = serde_json::from_slice(&bytes).unwrap();
        for mode in [SessionMode::Legacy, SessionMode::Compat] {
            match route(&bytes, &mode).unwrap() {
                Routed::Legacy(frame) => assert_eq!(*frame, direct),
                Routed::Capable(other) => panic!("not legacy: {other:?}"),
            }
        }
    }

    refusal_rows().await;
}

async fn refusal_rows() {
    // (r1) a malformed capable deliver (missing retain_until) retires and is NOT read as a
    // legacy Deliver.
    let mut malformed = capable_deliver();
    malformed.as_object_mut().unwrap().remove("retain_until");
    let mut engine = scripted(push(), vec![malformed]);
    let result = read(&mut engine).await;
    retired(result, &engine, "malformed capable frame");
    // (r2) Push deliver without the key, (r3) Push ack without the key.
    let mut engine = engine_of(push(), legacy_deliver());
    let result = read(&mut engine).await;
    retired(result, &engine, "keyless shape in a push session");
    let mut engine = engine_of(
        push(),
        json!({"frame_type":"ack","cursor":{
        "target_delivery_id":"t","inbox_seq":1,"last_envelope_id":null,
        "acked_envelope_ids":[],"nacked_envelope_ids":{}}}),
    );
    let result = read(&mut engine).await;
    retired(result, &engine, "keyless shape in a push session");
    // (r4) Push legacy resume.
    let mut engine = engine_of(push(), json!({"frame_type":"resume","entries":[]}));
    let result = read(&mut engine).await;
    retired(result, &engine, "legacy resume in a push session");
    // (r5) a capable resume_page during a legacy heartbeat wait.
    let page = capable(&n::SessionPushServerFrame::ResumePage {
        target_delivery_id: "target-route".into(),
        incarnation_id: E.into(),
        after_inbox_seq: 1,
        covered_through_seq: 2,
        issued_inbox_seq: 2,
        settled_through_seq: 0,
        entries: vec![],
        known_losses: vec![],
        oversize_next: None,
        more: false,
    });
    let mut engine = engine_of(push(), page.clone());
    let result = read(&mut engine).await;
    retired(result, &engine, "capable reply outside a capable wait");
    // (r6) a Legacy session receives resume_page, (r7) a keyed nack, (r8) a Compat session
    // receives submit_accepted.
    let mut engine = engine_of(SessionMode::Legacy, page);
    let result = read(&mut engine).await;
    retired(result, &engine, "capable frame on an unnegotiated session");
    let mut engine = engine_of(SessionMode::Legacy, capable_nack(Some(E)));
    let result = read(&mut engine).await;
    retired(result, &engine, "capable frame on an unnegotiated session");
    let accepted = capable(&n::SessionPushServerFrame::SubmitAccepted {
        incarnation_id: E.into(),
        envelope_id: "env-route".into(),
        target_delivery_id: "target-route".into(),
        inbox_seq: 3,
    });
    let mut engine = engine_of(SessionMode::Compat, accepted);
    let result = read(&mut engine).await;
    retired(result, &engine, "capable frame on an unnegotiated session");
    // (r9) a capable nack with an unknown reason: closed enum, no legacy fallback.
    let mut unknown = capable_nack(Some(E));
    unknown["reason"] = json!("zz");
    let mut engine = engine_of(push(), unknown);
    let result = read(&mut engine).await;
    retired(result, &engine, "malformed capable frame");
    // (r10) a keyed nack whose E has 31 characters: retired, no fallback to the keyless shape.
    let mut short = capable_nack(Some(E));
    short["incarnation_id"] = json!(&E[..31]);
    let mut engine = engine_of(push(), short);
    let result = read(&mut engine).await;
    retired(result, &engine, "malformed capable frame");
    // (r11) a keyed cursor during an idle read (no outstanding request).
    let keyed_cursor =
        capable(&n::SessionPushServerFrame::Cursor { incarnation_id: E.into(), cursor: None });
    let mut engine = engine_of(push(), keyed_cursor);
    let result = engine.idle_read().await.map(|()| GatewayServerFrame::Heartbeat { now: 0 });
    retired(result, &engine, "capable reply outside a capable wait");
    // A capable decode failure is a RouteError::Capable, never Legacy.
    let bytes = serde_json::to_vec(&capable_deliver_missing()).unwrap();
    assert!(matches!(route(&bytes, &push()), Err(RouteError::Capable(_))));
}

fn engine_of(mode: SessionMode, frame: Value) -> GatewaySessionEngine {
    scripted(mode, vec![frame])
}

fn capable_deliver_missing() -> Value {
    let mut value = capable_deliver();
    value.as_object_mut().unwrap().remove("retain_until");
    value
}
