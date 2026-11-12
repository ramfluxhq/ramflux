// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The exchange against a scripted node. Every refusal case also proves nothing was signed.

use std::cell::Cell;

use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::custody::{DeviceRef, Envelope, signing_bytes};
use ramflux_protocol::{domain, encode_base64url};
use serde_json::{Value, json};

use super::*;
use crate::wire::{WEB_ORIGIN_BINDING_SCHEMA, WebOpenFrame};

const NOW: u64 = 1_794_500_010;
const ORIGIN: &str = "https://app.example.org";
const LISTENER: &str = "wss://gw.example.org/v1/session";

struct Authority {
    key: SigningKey,
    signatures: Cell<u32>,
    transport_kind: &'static str,
}

impl SessionAuthority for Authority {
    fn sign_branch_proof(&self, transcript: &[u8]) -> Result<[u8; 64], WebError> {
        self.signatures.set(self.signatures.get() + 1);
        Ok(self.key.sign(transcript).to_bytes())
    }

    fn open_and_auth(&self, _: &Value, _: u64) -> Result<(WebOpenFrame, Value), WebError> {
        Ok((
            WebOpenFrame {
                protocol_version: "1".to_owned(),
                transport_kind: self.transport_kind.to_owned(),
                client_instance_id: "tab".to_owned(),
                device_id: "web-1".to_owned(),
                target_delivery_id: "delivery".to_owned(),
                stream_nonce: "nonce".to_owned(),
                previous_session_id: None,
                resume_token_hash: None,
                last_seen_inbox_seq: None,
                max_inflight_downstream: 16,
                max_inflight_upstream: 4,
                pre_auth_cookie: None,
                pre_auth_now: None,
                source_ip_hash: None,
            },
            json!({"signed_request": {}, "device_proof": {}}),
        ))
    }
}

fn authority() -> Authority {
    Authority {
        key: SigningKey::from_bytes(&[3_u8; 32]),
        signatures: Cell::new(0),
        transport_kind: "websocket",
    }
}

fn node_key() -> SigningKey {
    SigningKey::from_bytes(&[9_u8; 32])
}

fn device_ref() -> DeviceRef {
    DeviceRef {
        account_anchor: encode_base64url([1_u8; 32]),
        device_id: "web-1".to_owned(),
        device_epoch: 1,
    }
}

fn pins() -> WebLinkPins {
    WebLinkPins {
        listener_url: LISTENER.to_owned(),
        origin: ORIGIN.to_owned(),
        node_id: "node-a".to_owned(),
        node_signing_public_key: encode_base64url(node_key().verifying_key().to_bytes()),
        device_ref: device_ref(),
        certificate_hash: encode_base64url([4_u8; 32]),
        record_hash: encode_base64url([5_u8; 32]),
    }
}

fn node_identity(origins: &[&str]) -> Vec<u8> {
    let body = json!({
        "schema": "ramflux.identity.node_record.v1",
        "version": 1,
        "node_id": "node-a",
        "node_signing_public_key": encode_base64url(node_key().verifying_key().to_bytes()),
        "client_tls_certificate_sha256": null,
        "epoch": 1,
        "previous_record_hash": null,
        "issued_at": NOW - 100,
        "receipt_keys": [],
        "revoked_receipt_key_ids": [],
        "proxy_keys": [],
        "revoked_proxy_key_ids": [],
        "channel_binding_modes": ["direct_exporter", "web_origin_bound"],
        "web_listeners": [{"url": LISTENER, "origins": origins}],
    });
    let transcript = signing_bytes(domain::CUSTODY_NODE_RECORD, &body).unwrap_or_default();
    let signature = encode_base64url(node_key().sign(&transcript).to_bytes());
    serde_json::to_vec(&json!({
        "frame_type": "node_identity",
        "record": Envelope { body, signature },
        "audience": "node-a",
        "binding_mode": "web_origin_bound",
        "proxy_key_custody": null,
    }))
    .unwrap_or_default()
}

fn web_binding(origin: &str, listener: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "frame_type": "web_binding",
        "context": {
            "schema": WEB_ORIGIN_BINDING_SCHEMA,
            "version": 1,
            "node_id": "node-a",
            "listener_url": listener,
            "origin": origin,
            "transport_kind": "websocket",
            "gateway_nonce": encode_base64url([6_u8; 32]),
            "issued_at": NOW - 10,
            "expires_at": NOW + 290,
        },
    }))
    .unwrap_or_default()
}

fn challenge(mode: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "frame_type": "challenge",
        "challenge": {
            "challenge_nonce": encode_base64url([2_u8; 32]),
            "action_hash": encode_base64url([8_u8; 32]),
            "audience": "node-a",
            "binding_mode": mode,
            "issued_at": NOW - 5,
            "expires_at": NOW + 120,
        },
    }))
    .unwrap_or_default()
}

fn custody_session() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "frame_type": "session_established",
        "session": {
            "session_id": "custody-1",
            "device_ref": device_ref(),
            "target_delivery_id": "delivery",
            "record_hash": encode_base64url([5_u8; 32]),
            "proof_hash": encode_base64url([0_u8; 32]),
            "binding_mode": "web_origin_bound",
            "expires_at": NOW + 300,
        },
    }))
    .unwrap_or_default()
}

fn opened() -> WebHandshake {
    let mut handshake = WebHandshake::new(pins()).unwrap_or_else(|_| unreachable!());
    assert!(handshake.on_open("ramflux.gateway_session.v1", "").is_ok());
    handshake
}

fn feed(handshake: &mut WebHandshake, authority: &Authority, bytes: &[u8]) -> Result<HandshakeStep, WebError> {
    handshake.on_message(bytes, NOW, [0x11; 32], authority)
}

#[test]
fn completes_the_exchange_and_signs_exactly_once() {
    let authority = authority();
    let mut handshake = opened();
    assert_eq!(feed(&mut handshake, &authority, &node_identity(&[ORIGIN])), Ok(HandshakeStep::Send(vec![])));
    assert!(matches!(feed(&mut handshake, &authority, &web_binding(ORIGIN, LISTENER)), Ok(HandshakeStep::Send(f)) if f.len() == 1));
    let Ok(HandshakeStep::Send(frames)) = feed(&mut handshake, &authority, &challenge("web_origin_bound")) else {
        unreachable!("the proof is produced")
    };
    let prove: Value = serde_json::from_slice(&frames[0]).unwrap_or_default();
    assert_eq!(prove["frame_type"], "prove");
    assert_eq!(prove["proof"]["body"]["binding_mode"], "web_origin_bound");
    assert_eq!(prove["proof"]["body"]["expires_at"], NOW + 120);
    assert_eq!(authority.signatures.get(), 1);
    let Ok(HandshakeStep::Send(frames)) = feed(&mut handshake, &authority, &custody_session()) else {
        unreachable!("handoff, open and auth are produced")
    };
    let kinds: Vec<Value> = frames
        .iter()
        .map(|f| serde_json::from_slice::<Value>(f).unwrap_or_default()["frame_type"].clone())
        .collect();
    assert_eq!(kinds, vec![json!("gateway_handoff"), json!("open"), json!("auth")]);
    let established = br#"{"frame_type":"session_established","session":{"session_id":"g","carrier":"websocket"}}"#;
    assert!(matches!(feed(&mut handshake, &authority, established), Ok(HandshakeStep::Established { .. })));
    assert_eq!(handshake.phase(), HandshakePhase::Established);
    assert_eq!(handshake.inbound_cap(), 1_048_576);
}

#[test]
fn refuses_a_wrong_subprotocol_or_any_extension() {
    let mut handshake = WebHandshake::new(pins()).unwrap_or_else(|_| unreachable!());
    assert!(handshake.on_open("", "").is_err());
    let mut handshake = WebHandshake::new(pins()).unwrap_or_else(|_| unreachable!());
    assert!(handshake.on_open("ramflux.gateway_session.v1", "permessage-deflate").is_err());
}

#[test]
fn refuses_a_context_for_another_origin_without_signing() {
    let authority = authority();
    let mut handshake = opened();
    assert!(feed(&mut handshake, &authority, &node_identity(&[ORIGIN])).is_ok());
    let result = feed(&mut handshake, &authority, &web_binding("https://evil.example.org", LISTENER));
    assert!(matches!(result, Err(WebError::Binding(_))));
    assert_eq!(authority.signatures.get(), 0);
    assert_eq!(handshake.phase(), HandshakePhase::Failed);
}

#[test]
fn refuses_a_context_for_another_listener_without_signing() {
    let authority = authority();
    let mut handshake = opened();
    assert!(feed(&mut handshake, &authority, &node_identity(&[ORIGIN])).is_ok());
    let result =
        feed(&mut handshake, &authority, &web_binding(ORIGIN, "wss://gw2.example.org/v1/session"));
    assert!(matches!(result, Err(WebError::Binding(_))));
    assert_eq!(authority.signatures.get(), 0);
}

#[test]
fn refuses_a_node_record_that_does_not_list_this_origin() {
    let authority = authority();
    let mut handshake = opened();
    let result = feed(&mut handshake, &authority, &node_identity(&["https://other.example.org"]));
    assert!(matches!(result, Err(WebError::Binding(_))));
}

#[test]
fn refuses_a_node_record_signed_by_another_key() {
    let authority = authority();
    let mut handshake = opened();
    let mut frame: Value = serde_json::from_slice(&node_identity(&[ORIGIN])).unwrap_or_default();
    frame["record"]["signature"] = json!(encode_base64url([0_u8; 64]));
    let bytes = serde_json::to_vec(&frame).unwrap_or_default();
    assert!(matches!(feed(&mut handshake, &authority, &bytes), Err(WebError::Binding(_))));
}

#[test]
fn refuses_a_challenge_in_another_binding_mode_without_signing() {
    let authority = authority();
    let mut handshake = opened();
    assert!(feed(&mut handshake, &authority, &node_identity(&[ORIGIN])).is_ok());
    assert!(feed(&mut handshake, &authority, &web_binding(ORIGIN, LISTENER)).is_ok());
    let result = feed(&mut handshake, &authority, &challenge("no_channel_binding"));
    assert!(matches!(result, Err(WebError::Binding(_))));
    assert_eq!(authority.signatures.get(), 0);
}

#[test]
fn refuses_an_open_that_is_not_websocket() {
    let mut authority = authority();
    authority.transport_kind = "quic";
    let mut handshake = opened();
    assert!(feed(&mut handshake, &authority, &node_identity(&[ORIGIN])).is_ok());
    assert!(feed(&mut handshake, &authority, &web_binding(ORIGIN, LISTENER)).is_ok());
    assert!(feed(&mut handshake, &authority, &challenge("web_origin_bound")).is_ok());
    assert!(matches!(feed(&mut handshake, &authority, &custody_session()), Err(WebError::Protocol(_))));
}

#[test]
fn refuses_an_out_of_state_or_oversized_frame() {
    let authority = authority();
    let mut handshake = opened();
    assert!(feed(&mut handshake, &authority, &challenge("web_origin_bound")).is_err());
    let mut handshake = opened();
    let oversized = vec![b' '; 65_537];
    assert!(matches!(feed(&mut handshake, &authority, &oversized), Err(WebError::Protocol(_))));
}

#[test]
fn a_first_time_device_registers_its_prekeys_before_open_session() {
    let authority = authority();
    let mut handshake = WebHandshake::new(pins())
        .unwrap_or_else(|_| unreachable!())
        .with_first_registration(json!({"signed_prekey": "p"}));
    assert!(handshake.on_open("ramflux.gateway_session.v1", "").is_ok());
    assert!(feed(&mut handshake, &authority, &node_identity(&[ORIGIN])).is_ok());
    let Ok(HandshakeStep::Send(frames)) = feed(&mut handshake, &authority, &web_binding(ORIGIN, LISTENER))
    else {
        unreachable!("the registration challenge is requested")
    };
    let first: Value = serde_json::from_slice(&frames[0]).unwrap_or_default();
    assert_eq!(first["action"]["operation"], "register");
    assert!(feed(&mut handshake, &authority, &challenge("web_origin_bound")).is_ok());
    let registered = serde_json::to_vec(&json!({
        "frame_type": "registered",
        "device_ref": device_ref(),
        "target_delivery_id": "delivery-9",
    }))
    .unwrap_or_default();
    let Ok(HandshakeStep::Send(frames)) = feed(&mut handshake, &authority, &registered) else {
        unreachable!("open_session follows registration")
    };
    let next: Value = serde_json::from_slice(&frames[0]).unwrap_or_default();
    assert_eq!(next["action"]["operation"], "open_session");
    assert_eq!(handshake.registered_delivery_id(), Some("delivery-9"));
    assert_eq!(authority.signatures.get(), 1);
}

#[test]
fn a_wrong_local_clock_is_reported_as_a_clock_error() {
    let authority = authority();
    let mut handshake = opened();
    assert!(feed(&mut handshake, &authority, &node_identity(&[ORIGIN])).is_ok());
    let result = handshake.on_message(&web_binding(ORIGIN, LISTENER), NOW + 4000, [0; 32], &authority);
    assert_eq!(result, Err(WebError::Clock));
}
