// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `capable_negotiation_requires_signed_advertisement_and_echo`.
//!
//! Establishment bytes come from node-core (the typed frames the gateway writes). The engine
//! connects through `TEST_CONNECT_OPENER`; the device proof it signs is captured from the wire
//! and its signature is verified, so the scope under test is the scope that was signed.
use super::{IncarnationId, SessionMode};
use crate::SdkError;
use crate::gateway::engine::TEST_CONNECT_OPENER;
use crate::gateway::transport_opener::{OpenFuture, TransportOpener};
use crate::gateway::{
    GatewayQuicEndpointConfig, GatewaySessionClientTransport, GatewaySessionConfig,
    GatewaySessionEngine, GatewaySessionTransportKind,
};
use ramflux_node_core as n;
use ramflux_transport::{
    GatewaySessionFrameSink, GatewaySessionFrameSource, GatewaySessionTransport, TransportError,
};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PUSH: &str = ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY;
const E: &str = "0123456789abcdef0123456789abcdef";

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;
type Sent = Arc<Mutex<Vec<Value>>>;
/// Breaks one field of a push establishment.
type MalformEcho = fn(&mut Value);

/// Serves one establishment frame, records every client frame, then idles.
struct Gateway {
    establishment: Option<Vec<u8>>,
    sent: Sent,
}

impl GatewaySessionFrameSink for Gateway {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            let value = serde_json::from_slice(frame)
                .map_err(|error| TransportError::Quic(error.to_string()))?;
            self.sent.lock().unwrap().push(value);
            Ok(())
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for Gateway {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        let frame = self.establishment.take();
        Box::pin(async move {
            if let Some(frame) = frame { Ok(frame) } else { std::future::pending().await }
        })
    }
}

/// One scripted establishment per connect; reconnects take the next one.
struct Opener {
    script: Mutex<VecDeque<Vec<u8>>>,
    sent: Sent,
}

impl TransportOpener for Opener {
    fn open(&self, _config: GatewaySessionConfig, _timeout: Duration) -> OpenFuture<'_> {
        let establishment = self.script.lock().unwrap().pop_front();
        let sent = Arc::clone(&self.sent);
        Box::pin(async move {
            let gateway: Box<dyn GatewaySessionTransport + Send> =
                Box::new(Gateway { establishment, sent });
            Ok((
                GatewaySessionClientTransport::Injected,
                gateway,
                GatewaySessionTransportKind::Quic,
            ))
        })
    }
}

fn branch() -> ramflux_crypto::DeviceBranch {
    ramflux_crypto::create_device_branch("neg-principal", "neg-device", 1, [0x52; 32])
}

fn config(advertise: bool, scope: &[&str]) -> GatewaySessionConfig {
    let root = ramflux_crypto::create_identity_root("neg-principal", [0x51; 32]);
    let mut config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse().unwrap(),
        gateway_addr: "127.0.0.1:443".parse().unwrap(),
        server_name: "localhost".into(),
        ca_cert: "test-ca.pem".into(),
        principal_id: "neg-principal".into(),
        device_id: "neg-device".into(),
        target_delivery_id: "neg-target".into(),
        prekey_http_url: None,
    })
    .with_owned_device(&root, branch())
    .unwrap()
    .with_session_push_advertise(advertise);
    config.capability_scope = scope.iter().map(|s| (*s).to_owned()).collect();
    config
}

/// An unmodified constructor: nothing sets the advertise switch.
fn default_config() -> GatewaySessionConfig {
    let root = ramflux_crypto::create_identity_root("neg-principal", [0x51; 32]);
    GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse().unwrap(),
        gateway_addr: "127.0.0.1:443".parse().unwrap(),
        server_name: "localhost".into(),
        ca_cert: "test-ca.pem".into(),
        principal_id: "neg-principal".into(),
        device_id: "neg-device".into(),
        target_delivery_id: "neg-target".into(),
        prekey_http_url: None,
    })
    .with_owned_device(&root, branch())
    .unwrap()
}

fn session() -> n::GatewaySessionEstablishedFrame {
    n::GatewaySessionEstablishedFrame {
        call_session_generation: None,
        session_id: "neg-session".into(),
        gateway_id: "neg-gateway".into(),
        accepted_cursor: None,
        resume_token: "neg-token".into(),
        resume_window_seconds: 60,
    }
}

/// The typed push establishment the gateway writes.
fn push_frame(capabilities: Vec<String>, id: &str) -> Value {
    serde_json::to_value(n::SessionPushServerFrame::SessionEstablished {
        session: n::SessionPushEstablishedFrame {
            session: session(),
            capabilities,
            inbox_incarnation_id: id.into(),
        },
    })
    .unwrap()
}

/// The legacy establishment: no `capabilities`, no incarnation.
fn legacy_frame() -> Value {
    serde_json::to_value(n::GatewayServerFrame::SessionEstablished { session: session() }).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

async fn connect(
    config: GatewaySessionConfig,
    script: Vec<Vec<u8>>,
) -> (Result<GatewaySessionEngine, SdkError>, Sent, Arc<Opener>) {
    let sent: Sent = Arc::default();
    let opener = Arc::new(Opener { script: Mutex::new(script.into()), sent: Arc::clone(&sent) });
    let dyn_opener: Arc<dyn TransportOpener> = Arc::clone(&opener) as Arc<dyn TransportOpener>;
    let result =
        TEST_CONNECT_OPENER.scope(dyn_opener, GatewaySessionEngine::connect_at(config, None)).await;
    (result, sent, opener)
}

/// The signed device proof from the `auth` frame the engine wrote.
fn proof(sent: &Sent) -> ramflux_protocol::DeviceProof {
    let sent = sent.lock().unwrap();
    let auth = sent.iter().find(|frame| frame["frame_type"] == "auth").expect("auth frame");
    serde_json::from_value(auth["auth"]["device_proof"].clone()).unwrap()
}

fn verifies(proof: &ramflux_protocol::DeviceProof) -> bool {
    let public =
        ramflux_protocol::encode_base64url(branch().signing_key.verifying_key().to_bytes());
    let canonical = ramflux_protocol::signed_bytes(proof).unwrap();
    ramflux_crypto::verify_canonical_signature(&canonical, &proof.signed.signature, &public).is_ok()
}

fn count(scope: &[String], capability: &str) -> usize {
    scope.iter().filter(|c| c.as_str() == capability).count()
}

fn refusal(result: Result<GatewaySessionEngine, SdkError>, why: &str) {
    match result {
        Err(SdkError::GatewaySessionRejected(message)) => {
            assert_eq!(message, format!("session push negotiation refused: {why}"));
        }
        Err(other) => panic!("expected a negotiation refusal ({why}), got {other:?}"),
        Ok(engine) => panic!("expected a negotiation refusal ({why}), got mode {:?}", engine.mode),
    }
}

fn id(text: &str) -> IncarnationId {
    IncarnationId::try_from(text.to_owned()).unwrap()
}

#[tokio::test]
async fn capable_negotiation_requires_signed_advertisement_and_echo() {
    let echo_ok = bytes(&push_frame(vec![PUSH.into(), "gateway.ephemeral.v1".into()], E));

    // (p1) on + echo + valid E gives Push(E); the capability is in the signed scope, once, and
    // the device proof verifies.
    let (result, sent, _) =
        connect(config(true, &["gateway.session"]), vec![echo_ok.clone()]).await;
    let engine = result.unwrap();
    assert_eq!(engine.mode, SessionMode::Push { incarnation: id(E) });
    assert!(engine.ephemeral_negotiated, "the runtime must record the ephemeral echo");
    let signed = proof(&sent);
    assert_eq!(signed.capability_scope, ["gateway.session", PUSH, "gateway.ephemeral.v1"]);
    assert!(verifies(&signed));

    let (push_only, _, _) =
        connect(config(true, &["gateway.session"]), vec![bytes(&push_frame(vec![PUSH.into()], E))])
            .await;
    assert!(push_only.is_ok(), "an old gateway push-only echo must remain usable");
    if let Ok(engine) = push_only {
        assert_eq!(engine.mode, SessionMode::Push { incarnation: id(E) });
        assert!(!engine.ephemeral_negotiated, "missing ephemeral echo stays local unsupported");
    }

    // (p6) reconnect after Push, the gateway sending no echo, renegotiates to Compat.
    let mut engine = engine;
    let sent: Sent = Arc::default();
    let opener: Arc<dyn TransportOpener> =
        Arc::new(Opener { script: Mutex::new(VecDeque::from([bytes(&legacy_frame())])), sent });
    TEST_CONNECT_OPENER.scope(opener, engine.reconnect(0)).await.unwrap();
    assert_eq!(engine.mode, SessionMode::Compat);

    // (p2) on + no `capabilities` key gives Compat. (p3) on + `capabilities: []` gives Compat.
    let (result, _, _) =
        connect(config(true, &["gateway.session"]), vec![bytes(&legacy_frame())]).await;
    assert_eq!(result.unwrap().mode, SessionMode::Compat);
    let mut empty = legacy_frame();
    empty["session"]["capabilities"] = json!([]);
    let (result, _, _) = connect(config(true, &["gateway.session"]), vec![bytes(&empty)]).await;
    assert_eq!(result.unwrap().mode, SessionMode::Compat);

    // (p4) off: the signed scope lacks the capability and the mode is Legacy.
    let (result, sent, _) =
        connect(config(false, &["gateway.session"]), vec![bytes(&legacy_frame())]).await;
    assert_eq!(result.unwrap().mode, SessionMode::Legacy);
    let signed = proof(&sent);
    assert_eq!(count(&signed.capability_scope, PUSH), 0);
    assert!(verifies(&signed));

    // (p5) on + a caller scope that already holds it: it appears exactly once.
    let (result, sent, _) = connect(
        config(true, &["gateway.session", PUSH, "gateway.ephemeral.v1"]),
        vec![echo_ok.clone()],
    )
    .await;
    result.unwrap();
    assert_eq!(count(&proof(&sent).capability_scope, PUSH), 1);
    assert_eq!(count(&proof(&sent).capability_scope, "gateway.ephemeral.v1"), 1);

    // (r1) off + a caller scope that holds it: it is stripped, asserted on the signed proof.
    let (result, sent, _) = connect(
        config(false, &["gateway.session", PUSH, "gateway.ephemeral.v1"]),
        vec![bytes(&legacy_frame())],
    )
    .await;
    result.unwrap();
    let signed = proof(&sent);
    assert_eq!(signed.capability_scope, ["gateway.session"]);
    assert!(verifies(&signed));

    // (r2) off + echo.
    let (result, _, _) = connect(config(false, &["gateway.session"]), vec![echo_ok.clone()]).await;
    refusal(result, "echo names a capability that was not advertised");

    // (r3) on + echo + `inbox_incarnation_id` missing.
    let mut missing = push_frame(vec![PUSH.into()], E);
    missing["session"].as_object_mut().unwrap().remove("inbox_incarnation_id");
    let (result, _, _) = connect(config(true, &["gateway.session"]), vec![bytes(&missing)]).await;
    refusal(result, "echo without an inbox incarnation");

    // (r4) 31-character E, (r5) uppercase E.
    for (row, bad) in [("r4", &E[..31]), ("r5", "ABCDEF0123456789ABCDEF0123456789")] {
        let frame = bytes(&push_frame(vec![PUSH.into()], bad));
        let (result, _, _) = connect(config(true, &["gateway.session"]), vec![frame]).await;
        let _ = row;
        refusal(result, "invalid inbox incarnation");
    }

    // (r6) no echo but `inbox_incarnation_id` present.
    let mut orphan = legacy_frame();
    orphan["session"]["inbox_incarnation_id"] = json!(E);
    let (result, _, _) = connect(config(true, &["gateway.session"]), vec![bytes(&orphan)]).await;
    refusal(result, "incarnation without an echoed capability");

    // (r7) an echo naming a capability that was not advertised.
    let frame = bytes(&push_frame(vec!["gateway.ephemeral.v1".into()], E));
    let (result, _, _) = connect(config(true, &["gateway.session"]), vec![frame]).await;
    refusal(result, "echo names a capability that was not advertised");

    // (r8) tampering the scope after signing makes the proof fail verification.
    let (result, sent, _) =
        connect(config(true, &["gateway.session"]), vec![echo_ok.clone()]).await;
    result.unwrap();
    let mut tampered = proof(&sent);
    assert!(verifies(&tampered));
    tampered.capability_scope.push("gateway.ephemeral.v1".into());
    assert!(!verifies(&tampered));
    // Default-off is pinned: an unmodified constructor does not advertise, negotiates Legacy
    // and keeps the capability out of the signed scope.
    let unmodified = default_config();
    assert!(!unmodified.session_push_advertise);
    let (result, sent, _) = connect(unmodified, vec![bytes(&legacy_frame())]).await;
    assert_eq!(result.unwrap().mode, SessionMode::Legacy);
    let signed = proof(&sent);
    assert_eq!(count(&signed.capability_scope, PUSH), 0);
    assert!(verifies(&signed));

    // The establishment in node-core struct order (producer order i), not only the sorted
    // `Value` order: Push when advertised, Compat for the legacy typed frame.
    let typed_push = serde_json::to_vec(&n::SessionPushServerFrame::SessionEstablished {
        session: n::SessionPushEstablishedFrame {
            session: session(),
            capabilities: vec![PUSH.into()],
            inbox_incarnation_id: E.into(),
        },
    })
    .unwrap();
    assert_ne!(typed_push, echo_ok, "the two producer orders differ on the wire");
    let (result, _, _) = connect(config(true, &["gateway.session"]), vec![typed_push]).await;
    assert_eq!(result.unwrap().mode, SessionMode::Push { incarnation: id(E) });
    let typed_legacy =
        serde_json::to_vec(&n::GatewayServerFrame::SessionEstablished { session: session() })
            .unwrap();
    let (result, _, _) = connect(config(true, &["gateway.session"]), vec![typed_legacy]).await;
    assert_eq!(result.unwrap().mode, SessionMode::Compat);

    // Malformed echo, one wrong JSON type per row: the capability container, a capability
    // element and the incarnation. Each is the same exact refusal.
    let malformed: [(&str, MalformEcho); 3] = [
        ("capabilities is a string", |v| v["session"]["capabilities"] = json!("x")),
        ("a capability element is a number", |v| v["session"]["capabilities"] = json!([1])),
        ("the incarnation is a number", |v| v["session"]["inbox_incarnation_id"] = json!(5)),
    ];
    for (row, mutate) in malformed {
        let mut frame = push_frame(vec![PUSH.into()], E);
        mutate(&mut frame);
        let (result, _, _) = connect(config(true, &["gateway.session"]), vec![bytes(&frame)]).await;
        match result {
            Err(SdkError::GatewaySessionRejected(message)) => {
                assert_eq!(message, "session push negotiation refused: echo is malformed", "{row}");
            }
            Err(other) => panic!("{row}: {other:?}"),
            Ok(engine) => panic!("{row}: accepted as {:?}", engine.mode),
        }
    }
}
