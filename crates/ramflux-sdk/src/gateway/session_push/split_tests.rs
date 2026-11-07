// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `capable_reply_event_split`: on a Push session the submit reply is `submit_accepted` and the
//! recipient `deliver` is an event, even for the sender's own target.
//!
//! Capable frames come from node-core typed values; the engine signs and writes a real submit.
use super::carrier_tests::attach_host;
use super::routing_tests::{E, capable_deliver, envelope, id, push};
use super::{PushMeta, SessionMode};
use crate::SdkError;
use crate::bus::connection_manager::DisconnectReason;
use crate::bus::connection_manager::subscriptions::SessionEvent;
use crate::gateway::frame_dispatch::{ExpectedReply, FrameKind};
use crate::gateway::{
    GatewayClientFrame, GatewayInboxEntry, GatewayQuicEndpointConfig, GatewaySessionConfig,
    GatewaySessionEngine,
};
use n::SessionPushServerFrame as F;
use ramflux_node_core as n;
use ramflux_transport::{
    GatewaySessionFrameSink, GatewaySessionFrameSource, GatewaySessionTransport, TransportError,
};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;
type Sent = Arc<Mutex<Vec<Vec<u8>>>>;

/// Serves the scripted frames in order and records every client frame.
struct Gateway {
    frames: VecDeque<Vec<u8>>,
    sent: Sent,
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

fn scripted(mode: SessionMode, frames: Vec<Value>) -> (GatewaySessionEngine, Sent) {
    let root = ramflux_crypto::create_identity_root("split-principal", [0x61; 32]);
    let branch =
        ramflux_crypto::create_device_branch("split-principal", "split-device", 1, [0x62; 32]);
    let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse().unwrap(),
        gateway_addr: "127.0.0.1:443".parse().unwrap(),
        server_name: "localhost".into(),
        ca_cert: "test-ca.pem".into(),
        principal_id: "split-principal".into(),
        device_id: "split-device".into(),
        target_delivery_id: "target-route".into(),
        prekey_http_url: None,
    })
    .with_owned_device(&root, branch)
    .unwrap();
    let sent: Sent = Arc::default();
    let frames = frames.into_iter().map(|f| serde_json::to_vec(&f).unwrap()).collect();
    let stream: Box<dyn GatewaySessionTransport + Send> =
        Box::new(Gateway { frames, sent: Arc::clone(&sent) });
    let mut engine = GatewaySessionEngine::with_test_transport(config, stream);
    engine.mode = mode;
    (engine, sent)
}

/// The submitted envelope: id `env-route`, to `target`.
fn submitted(target: &str) -> ramflux_protocol::Envelope {
    let mut value = serde_json::to_value(envelope()).unwrap();
    value["target_delivery_id"] = json!(target);
    serde_json::from_value(value).unwrap()
}

fn accepted(mutate: impl FnOnce(&mut Value)) -> Value {
    let mut value = serde_json::to_value(n::SessionPushServerFrame::SubmitAccepted {
        incarnation_id: E.into(),
        envelope_id: "env-route".into(),
        target_delivery_id: "target-route".into(),
        inbox_seq: 55,
    })
    .unwrap();
    mutate(&mut value);
    value
}

fn heartbeat() -> Value {
    json!({"frame_type":"heartbeat","now":5})
}

fn refused(result: Result<GatewayInboxEntry, SdkError>, engine: &GatewaySessionEngine, why: &str) {
    match result {
        Err(SdkError::GatewaySessionRejected(message)) => assert_eq!(message, why),
        other => panic!("expected a retirement ({why}), got {other:?}"),
    }
    assert!(matches!(engine.terminal_reason, Some(DisconnectReason::UnexpectedReply)));
}

fn frame(wire: &n::SessionPushServerFrame) -> Value {
    serde_json::to_value(wire).unwrap()
}

/// The complete legacy submit frame as written on the wire (fixed clock, fixed keys).
const LEGACY_SUBMIT_GOLDEN: &str = r#"{"frame_type":"submit","submit":{"signed_request":{"schema":"ramflux.signed_request.v1","version":1,"domain":"ramflux.signed_request.v1","signing_key_id":"device:split-device","signature_alg":"ed25519","signature":"dFFLNuZtJZETgi9GVSVFxbzLxJwRUSsBRvxRnwiWPgW6e-8RbTxpN8GU53tBBm9enkYk41CZ75oFRYq2lnSKBg","source_device_id":"split-device","request_id":"req_sdk_test-session_0","method":"POST","path":"/gateway/session/submit","device_proof_hash":"already_authed","body_hash":"ciw0_tgfF9AZeUGAVif6x7pPGdBOxV0yhGiAVebx3Y0","nonce":"Ve-x2xgmgbFpMX-MvNzQkI-YrW1rl-G_veTPkY-MA-4","created_at":1700000000,"expires_at":1700000300},"envelope":{"schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1","signing_key_id":"dev","signature_alg":"ed25519","signature":"fixture","envelope_id":"env-route","source_principal_id":"p","source_device_id":"d","target_delivery_id":"target-route","delivery_class":"opaque_event","priority":"normal","ttl":600,"created_at":1,"encrypted_payload":"opaque","payload_hash":"hash-route"}}}"#;

#[tokio::test]
async fn capable_reply_event_split() {
    // (p1) Push self-target submit: the result comes from `submit_accepted`; the recipient
    // deliver is captured exactly once by the carrier and the subscriber, in either order.
    for deliver_first in [true, false] {
        let mut frames = vec![capable_deliver(), accepted(|_| {}), heartbeat()];
        if !deliver_first {
            frames.swap(0, 1);
        }
        let (mut engine, _) = scripted(push(), frames);
        let (hub, _) = attach_host(&mut engine);
        let mut seen = hub.subscribe([FrameKind::Deliver, FrameKind::Heartbeat]);
        let entry = engine.submit_envelope(submitted("target-route")).await.unwrap();
        assert_eq!((entry.forwarded, entry.inbox_seq), (false, 55));
        assert_eq!(entry.envelope, submitted("target-route"));
        engine.read_reply(ExpectedReply::Heartbeat).await.ok();
        hub.publish(crate::GatewayServerFrame::Heartbeat { now: 5 });
        let pending = engine.take_pending_capable();
        assert_eq!(pending.len(), 1, "deliver_first={deliver_first}");
        assert_eq!(pending[0].0.inbox_seq, 71);
        assert_eq!(pending[0].1, Some(PushMeta { incarnation_id: id(), retain_until: 7_777 }));
        let first = tokio::time::timeout(Duration::from_secs(10), seen.recv()).await.unwrap();
        assert!(
            matches!(&first, Some(SessionEvent::Capable { event, .. })
                if matches!(&**event, super::CapableEvent::Deliver { retain_until: 7_777, .. })),
            "the subscriber sees the deliver first: {first:?}"
        );
        let second = tokio::time::timeout(Duration::from_secs(10), seen.recv()).await.unwrap();
        assert!(
            matches!(second, Some(SessionEvent::Frame { .. })),
            "the deliver reached the subscriber exactly once"
        );
    }

    // (p2) Push submit to another target: submit_accepted adapted, no deliver expected.
    let (mut engine, _) =
        scripted(push(), vec![accepted(|v| v["target_delivery_id"] = json!("other-target"))]);
    let entry = engine.submit_envelope(submitted("other-target")).await.unwrap();
    assert_eq!(
        (entry.forwarded, entry.inbox_seq, entry.target_delivery_id.as_str()),
        (false, 55, "other-target")
    );
    assert!(engine.pending_deliveries.is_empty());

    // (p3) Legacy wire: the matching deliver is the reply, consumed once and not buffered; the
    // written submit is a plain legacy submit frame carrying the envelope.
    let legacy = json!({"frame_type":"deliver","entry":{
        "inbox_seq":71,"target_delivery_id":"target-route","envelope":envelope()}});
    let clock = crate::time::FixedClock::set(1_700_000_000);
    let (mut engine, sent) = scripted(SessionMode::Legacy, vec![legacy]);
    let entry = engine.submit_envelope(submitted("target-route")).await.unwrap();
    drop(clock);
    assert_eq!((entry.forwarded, entry.inbox_seq), (false, 71));
    assert!(engine.pending_deliveries.is_empty(), "the reply is not duplicated");
    let written = sent.lock().unwrap().clone();
    assert_eq!(written.len(), 1);
    match serde_json::from_slice::<GatewayClientFrame>(&written[0]).unwrap() {
        GatewayClientFrame::Submit { submit } => {
            assert_eq!(submit.envelope, submitted("target-route"));
        }
        other => panic!("not a submit: {other:?}"),
    }
    // Exact legacy bytes: the captured original bytes equal the frozen golden, and decoding
    // then encoding them is the identity (no normalization of the capture).
    assert_eq!(String::from_utf8(written[0].clone()).unwrap(), LEGACY_SUBMIT_GOLDEN);
    let decoded: GatewayClientFrame = serde_json::from_slice(&written[0]).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), written[0]);

    // (p4) Push legacy ForwardAck matching: the forwarded result.
    let ack = json!({"frame_type":"forward_ack","ack":{
        "envelope_id":"env-route","target_delivery_id":"target-route","inbox_seq":9}});
    let (mut engine, _) = scripted(push(), vec![ack]);
    let entry = engine.submit_envelope(submitted("target-route")).await.unwrap();
    assert_eq!((entry.forwarded, entry.inbox_seq), (true, 9));

    // (p4b) boundary: a matching ForwardAck with inbox_seq 1 succeeds.
    let ack = json!({"frame_type":"forward_ack","ack":{
        "envelope_id":"env-route","target_delivery_id":"target-route","inbox_seq":1}});
    let (mut engine, _) = scripted(push(), vec![ack]);
    let entry = engine.submit_envelope(submitted("target-route")).await.unwrap();
    assert_eq!((entry.forwarded, entry.inbox_seq), (true, 1));
    // (p4c)/(p4d) isolated single-field mismatches of the same valid ack, exact errors.
    for (env, target, text) in [
        ("env-other", "target-route", "env-other target target-route"),
        ("env-route", "target-other", "env-route target target-other"),
    ] {
        let ack = json!({"frame_type":"forward_ack","ack":{
            "envelope_id":env,"target_delivery_id":target,"inbox_seq":1}});
        let (mut engine, _) = scripted(push(), vec![ack]);
        match engine.submit_envelope(submitted("target-route")).await {
            Err(SdkError::GatewaySessionRejected(message)) => {
                assert_eq!(
                    message,
                    format!("forward acknowledgement mismatch for envelope {text}")
                );
            }
            other => panic!("expected a mismatch refusal, got {other:?}"),
        }
    }

    // (p5) a keyless legacy nack is a submit error and the session stays alive.
    let (mut engine, _) =
        scripted(push(), vec![json!({"frame_type":"nack","reason":"rejected_security"})]);
    match engine.submit_envelope(submitted("target-route")).await {
        Err(SdkError::GatewaySessionRejected(reason)) => assert_eq!(reason, "rejected_security"),
        other => panic!("expected the refusal reason, got {other:?}"),
    }
    assert!(engine.terminal_reason.is_none(), "the session stays alive");

    refusal_rows().await;
}

async fn refusal_rows() {
    let submit_refused = |frames: Vec<Value>| async move {
        let (mut engine, _) = scripted(push(), frames);
        let result = engine.submit_envelope(submitted("target-route")).await;
        (result, engine)
    };
    // (r1) mismatched envelope id, (r2) mismatched target, (r3) inbox_seq 0, (r4) foreign E.
    let cases: [(&str, Value, &str); 4] = [
        (
            "r1",
            accepted(|v| v["envelope_id"] = json!("env-other")),
            "unexpected gateway frame: submit_accepted for a different envelope",
        ),
        (
            "r2",
            accepted(|v| v["target_delivery_id"] = json!("target-other")),
            "unexpected gateway frame: submit_accepted for a different target",
        ),
        (
            "r3",
            accepted(|v| v["inbox_seq"] = json!(0)),
            "unexpected gateway frame: submit_accepted without an inbox sequence",
        ),
        (
            "r4",
            accepted(|v| v["incarnation_id"] = json!(format!("ff{}", &E[2..]))),
            "unexpected gateway frame: submit_accepted with a foreign incarnation",
        ),
    ];
    for (row, wire, why) in cases {
        let (result, engine) = submit_refused(vec![wire]).await;
        let _ = row;
        refused(result, &engine, why);
    }
    // (r5) a deliver with a foreign E, (r6) a deliver whose target is not T.
    let mut foreign = capable_deliver();
    foreign["incarnation_id"] = json!(format!("ff{}", &E[2..]));
    let (result, engine) = submit_refused(vec![foreign]).await;
    refused(result, &engine, "unexpected gateway frame: capable event with a foreign incarnation");
    let mut elsewhere = capable_deliver();
    elsewhere["entry"]["target_delivery_id"] = json!("target-other");
    let (result, engine) = submit_refused(vec![elsewhere]).await;
    refused(result, &engine, "unexpected gateway frame: capable deliver for a foreign target");

    // (r7) each capable reply kind other than submit_accepted while awaiting the submit.
    let record = n::PageEntryRecord {
        entry: n::InboxEntry {
            inbox_seq: 71,
            target_delivery_id: "target-route".into(),
            envelope: envelope(),
        },
        retain_until: 1,
    };
    let cursor = n::InboxCursorResponse {
        target_delivery_id: "target-route".into(),
        inbox_seq: 1,
        last_envelope_id: None,
        acked_envelope_ids: vec![],
        nacked_envelope_ids: std::collections::BTreeMap::default(),
    };
    let replies = [
        F::ResumePage {
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
        },
        F::Entry { incarnation_id: E.into(), record: Box::new(record) },
        F::EntryTooLarge { incarnation_id: E.into(), inbox_seq: 1, retain_until: 1 },
        F::EntryGone {
            incarnation_id: E.into(),
            inbox_seq: 1,
            observed_issued_inbox_seq: 1,
            reason: n::EntryGoneReason::Expired,
        },
        F::AckBatch { incarnation_id: E.into(), cursor: cursor.clone(), results: vec![] },
        F::Ack { incarnation_id: E.into(), cursor: cursor.clone() },
        F::Cursor { incarnation_id: E.into(), cursor: Some(cursor) },
        F::Nack { reason: n::SessionPushNackReason::Busy, incarnation_id: Some(E.into()) },
    ];
    for reply in replies {
        let (result, engine) = submit_refused(vec![frame(&reply)]).await;
        refused(
            result,
            &engine,
            "unexpected gateway frame: unexpected capable reply while awaiting a submit",
        );
    }

    // (r8)-(r20) the 13 unexpected legacy kinds, each awaited during a Push submit.
    let unexpected = legacy_unexpected_kinds();
    assert_eq!(unexpected.len(), 13);
    for (name, wire, message) in unexpected {
        let (result, engine) = submit_refused(vec![wire]).await;
        assert!(
            matches!(&result, Err(SdkError::GatewaySessionRejected(m)) if m == &message),
            "{name}: expected {message:?}, got {result:?}"
        );
        assert!(
            matches!(engine.terminal_reason, Some(DisconnectReason::UnexpectedReply)),
            "{name}"
        );
    }
}

/// Every legacy reply kind outside the submit set, with the exact retirement it must give.
pub(super) fn legacy_unexpected_kinds() -> Vec<(&'static str, Value, String)> {
    let reply = |kind: &str| format!("unexpected gateway reply: {kind}");
    let keyless = |why: &str| format!("unexpected gateway frame: {why}");
    let cursor = json!({"target_delivery_id":"t","inbox_seq":1,"last_envelope_id":null,
        "acked_envelope_ids":[],"nacked_envelope_ids":{}});
    let issuer = json!({"schema":"s","version":1,"cert_id":"c","node_id":"n",
        "gateway_instance_id":"g","attestation_public_key":"k","attestation_key_id":"i",
        "not_before":1,"not_after":2,"issued_at":1,"node_root_signing_key_id":"r",
        "node_root_signature":"x","revoked_at":null});
    vec![
        (
            "voice_lease",
            json!({"frame_type":"voice_lease","response":{"result":"status","status":{"expires_at":9}}}),
            reply("VoiceLease"),
        ),
        (
            "own_device_fanout",
            json!({"frame_type":"own_device_fanout","response":{
                "principal_id":"p","source_device_id":"d","delivered":[]}}),
            reply("OwnDeviceFanout"),
        ),
        (
            "identity_registered",
            json!({"frame_type":"identity_registered","response":{
                "principal_id":"p","device_id":"d","device_epoch":1,"target_delivery_id":"t",
                "session_bound":true,"registration_trust_tier":"tier"}}),
            reply("IdentityRegistered"),
        ),
        (
            "identity_registration_rejected",
            json!({"frame_type":"identity_registration_rejected","reason_code":"capacity"}),
            reply("IdentityRegistrationRejected"),
        ),
        (
            "principal_manifest",
            json!({"frame_type":"principal_manifest","response":{"manifest":null,"reason_code":null}}),
            reply("PrincipalManifest"),
        ),
        (
            "prekey_published",
            json!({"frame_type":"prekey_published","response":{
                "device_id":"d","bundle":null,"principal_commitment":"c"}}),
            reply("PrekeyPublished"),
        ),
        (
            "prekey",
            json!({"frame_type":"prekey","response":{
                "device_id":"d","bundle":null,"principal_commitment":"c"}}),
            reply("Prekey"),
        ),
        (
            "relay_token_issued",
            json!({"frame_type":"relay_token_issued","response":{"relay_token":{
                "token_id":"t","object_id":"o","manifest_hash":"m","chunk_id":"c",
                "recipient_device_hash":"h","owner_signing_key_id":"k","owner_public_key":"p",
                "issuer_service":"s","capabilities":["put"],"delete_after_ack":false,
                "issued_at":1,"expires_at":2,"nonce":"n","mac":"m"}}}),
            reply("RelayTokenIssued"),
        ),
        (
            "relay_token_v3_issued",
            json!({"frame_type":"relay_token_v3_issued","response":{"relay_token":{
                "token_version":3,"token_id":"t","requester_device_id":"d",
                "requester_device_hash":"h","requester_public_key":"k","requester_device_epoch":1,
                "owner_signing_key_id":"k","owner_public_key":"p","owner_home_node_id":"n",
                "owner_principal_id":"o","owner_device_epoch":1,"issuer_node_id":"i",
                "gateway_instance_id":"g","issuer_certificate_id":"c","attestation_key_id":"a",
                "issuer_certificate":issuer,"audience_service":"s","audience_node_id":"n",
                "relay_instance_id":null,"object_id":"o","manifest_hash":"m","chunk_id":"c",
                "capabilities":["put"],"authorization_kind":"owner_session",
                "authorization_binding_hash":"b","delete_after_ack":false,"issued_at":1,
                "expires_at":2,"nonce":"n","issuer_signature":"s"}}}),
            reply("RelayTokenV3Issued"),
        ),
        (
            "ack",
            json!({"frame_type":"ack","cursor":cursor}),
            keyless("keyless shape in a push session"),
        ),
        ("cursor", json!({"frame_type":"cursor","cursor":null}), reply("Cursor")),
        (
            "resume",
            json!({"frame_type":"resume","entries":[]}),
            keyless("legacy resume in a push session"),
        ),
        ("heartbeat", heartbeat(), reply("Heartbeat")),
    ]
}
