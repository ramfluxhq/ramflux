// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission, authorization lifetime and opaque routing regressions.
#![allow(clippy::expect_used)]
use super::*;
fn scope(id: u8) -> VoiceAllocationRequest {
    VoiceAllocationRequest {
        call_id: ramflux_protocol::encode_base64url([id; 16]),
        caller: CallEndpoint {
            principal_id: "alice".into(),
            root_public_key: ramflux_protocol::encode_base64url([1; 32]),
            device_id: "device".into(),
        },
        callee: CallEndpoint {
            principal_id: "bob".into(),
            root_public_key: ramflux_protocol::encode_base64url([2; 32]),
            device_id: "device".into(),
        },
    }
}
#[test]
fn voice_learned_sources_are_opaque_and_keepalive_cannot_renew_lease() {
    let mut state = VoiceRelayState::default();
    let scope = scope(1);
    let a = state.allocate("node", &scope, "relay:9000", 100).expect("allocate");
    let sender_addr = "8.8.8.8:10000".parse().expect("address");
    let receiver_addr = "1.1.1.1:20000".parse().expect("address");
    let bind = encode_voice_datagram(&a.callee_token, &[]).expect("frame");
    assert!(state.route(&bind, receiver_addr, 100, false).expect("bind").is_none());
    let packet = encode_voice_datagram(&a.caller_token, b"opaque ciphertext").expect("frame");
    assert_eq!(
        state.route(&packet, sender_addr, 101, false).expect("route"),
        Some((receiver_addr, &b"opaque ciphertext"[..]))
    );
    let packet = encode_voice_datagram(&a.callee_token, b"reverse ciphertext").expect("frame");
    assert_eq!(
        state.route(&packet, receiver_addr, 102, false).expect("route"),
        Some((sender_addr, &b"reverse ciphertext"[..]))
    );
    assert!(state.route(&bind, receiver_addr, 159, false).expect("keepalive").is_none());
    assert!(state.route(&bind, receiver_addr, 160, false).is_err());
    assert!(state.tokens.is_empty());
}
#[test]
fn voice_exact_scope_and_authenticated_owner_control_renewal_and_release() {
    let mut state = VoiceRelayState::default();
    let s = scope(2);
    let a = state.allocate("node", &s, "relay:9000", 100).expect("allocate");
    assert_eq!(a, state.allocate("node", &s, "relay:9000", 101).expect("idempotent"));
    let mut changed = s.clone();
    changed.callee.root_public_key = ramflux_protocol::encode_base64url([3; 32]);
    assert!(state.allocate("node", &changed, "relay:9000", 100).is_err());
    assert!(state.renew("other-node", &s, 120).is_err());
    assert!(state.renew("node", &changed, 120).is_err());
    assert!(state.release("node", &changed).is_err());
    assert_eq!(state.renew("node", &s, 120).expect("renew"), 180);
    let p = encode_voice_datagram(&a.caller_token, &[]).expect("packet");
    assert!(state.route(&p, "8.8.8.8:1234".parse().expect("source"), 160, false).is_ok());
    state.release("node", &s).expect("release");
    state.release("node", &s).expect("idempotent");
    assert!(state.route(&p, "8.8.8.8:1234".parse().expect("source"), 161, false).is_err());
}
#[test]
fn voice_capacity_counts_root_qualified_accounts_and_forbids_private_sources() {
    let mut state = VoiceRelayState::default();
    for id in [1, 2] {
        state.allocate("node", &scope(id), "relay:9000", 100).expect("allocate");
    }
    assert!(state.allocate("node", &scope(3), "relay:9000", 100).is_err());
    let a = state.allocate("node", &scope(1), "relay:9000", 100).expect("existing survives cap");
    let packet = encode_voice_datagram(&a.caller_token, &[]).expect("packet");
    assert!(state.route(&packet, "127.0.0.1:1234".parse().expect("addr"), 100, false).is_err());
    assert!(state.route(&packet, "127.0.0.1:1234".parse().expect("addr"), 100, true).is_ok());
    let mut other = scope(3);
    other.caller.root_public_key = ramflux_protocol::encode_base64url([3; 32]);
    other.callee.root_public_key = ramflux_protocol::encode_base64url([4; 32]);
    assert!(state.allocate("node", &other, "relay:9000", 100).is_ok());
    assert!(state.allocate("node", &scope(4), "relay:9000", 160).is_ok());
}
#[test]
fn voice_framing_bandwidth_and_unknown_credentials_fail_closed() {
    let mut state = VoiceRelayState::default();
    let a = state.allocate("node", &scope(1), "relay:9000", 100).expect("allocate");
    let source = "8.8.8.8:1234".parse().expect("source");
    assert!(state.route(&[0; 3], source, 100, false).is_err());
    let bad =
        encode_voice_datagram(&ramflux_protocol::encode_base64url([0; 32]), &[]).expect("bad");
    assert!(state.route(&bad, source, 100, false).is_err());
    let packet = encode_voice_datagram(&a.caller_token, &[0; 1400]).expect("packet");
    for _ in 0..91 {
        state.route(&packet, source, 100, false).expect("within bandwidth");
    }
    assert!(state.route(&packet, source, 100, false).is_err());
    assert!(state.route(&packet, source, 101, false).is_ok());
    assert!(state.route(&packet, source, 100, false).is_err());
}
