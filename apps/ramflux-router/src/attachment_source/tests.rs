// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use ramflux_protocol::large_attachment::{ForwardAttestation, QualifiedOwner};
use serde_json::json;
use std::cell::RefCell;

const NOW: u64 = 1_700_000_000;

struct Fake {
    verdict: Result<HomeVerdict, RenewalRefusal>,
    relayed: RefCell<Vec<(String, Value)>>,
    verdicts: RefCell<Vec<(String, String)>>,
}
impl Fake {
    fn new(node: &str) -> Self {
        Self {
            verdict: Ok(verdict(node)),
            relayed: RefCell::default(),
            verdicts: RefCell::default(),
        }
    }
    fn untouched(&self) -> bool {
        self.relayed.borrow().is_empty() && self.verdicts.borrow().is_empty()
    }
}
impl SourceBackend for Fake {
    fn now(&self) -> u64 {
        NOW
    }
    fn verdict(&self, anchor: &str, peer: &str, _: u64) -> Result<HomeVerdict, RenewalRefusal> {
        self.verdicts.borrow_mut().push((anchor.into(), peer.into()));
        self.verdict.clone()
    }
    fn relay(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, RenewalRefusal> {
        self.relayed.borrow_mut().push((path.into(), serde_json::from_slice(&body).unwrap()));
        Ok(b"{\"relayed\":true}".to_vec())
    }
}
fn verdict(node: &str) -> HomeVerdict {
    HomeVerdict {
        account_anchor: "anchor-1".into(),
        home_node: node.into(),
        home_node_key: [7; 32],
        home_epoch: 2,
        home_record_hash: [9; 32],
        checked_at: NOW,
    }
}
fn challenge(peer: &str, home: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "kind": "challenge",
        "peer_node": peer,
        "request": {
            "capability": [1], "target_operation": [2],
            "requester": {"account_anchor": "anchor-1", "device_id": "d", "device_epoch": 1,
                "signing_public_key": vec![0; 32], "home_node_id": home},
            "home_node": "client-claim", "peer_node": "client-claim",
            "home_verdict": {"client": "supplied"}
        }
    }))
    .unwrap()
}
fn forward(peer: &str, home: &str) -> Vec<u8> {
    let w = ForwardAttestation {
        requester: QualifiedOwner {
            account_anchor: "anchor-1".into(),
            device_id: "d".into(),
            device_epoch: 1,
            signing_public_key: [0; 32],
            home_node_id: home.into(),
        },
        grant_hash: [1; 32],
        grant_id: [2; 32],
        grant_epoch: 1,
        source_issuer: "issuer".into(),
        home_issuer: home.into(),
        challenge: [3; 32],
        operation_hash: [4; 32],
        issued_at: NOW,
        expires_at: NOW + 30,
    };
    serde_json::to_vec(&json!({
        "kind": "forward",
        "peer_node": peer,
        "request": {"attestation": w.canonical_bytes().unwrap(), "peer_node": "client-claim"}
    }))
    .unwrap()
}
fn refusal(reply: &SourceReply) -> Value {
    assert_eq!(reply.status, "200 OK");
    serde_json::from_slice(&reply.body).unwrap()
}

#[test]
fn source_route_admits_federation_peer_only() {
    let backend = Fake::new("node-b");
    let body = challenge("node-b", "node-b");
    for peer in [
        "ramflux-gateway",
        "ramflux-relay",
        "ramflux-notify",
        "ramflux-retention",
        "ramflux-router",
        "",
    ] {
        let reply = route(peer, &body, Some(&backend));
        assert_eq!(
            reply,
            text("403 Forbidden", "attachment source requires federation identity"),
            "{peer}"
        );
    }
    assert!(backend.untouched());
    let ok = route(FEDERATION_SERVICE_ID, &body, Some(&backend));
    assert_eq!(ok, SourceReply { status: "200 OK", body: b"{\"relayed\":true}".to_vec() });
}

#[test]
fn dormant_without_a_backend() {
    let reply = route(FEDERATION_SERVICE_ID, &challenge("node-b", "node-b"), None);
    assert_eq!(reply, text("503 Service Unavailable", "attachment source is not configured"));
    // The peer check still comes first.
    assert_eq!(route("ramflux-gateway", b"{}", None).status, "403 Forbidden");
}

#[test]
fn challenge_gets_the_stamped_peer_and_the_router_verdict() {
    let backend = Fake::new("node-b");
    route(FEDERATION_SERVICE_ID, &challenge("node-b", "node-b"), Some(&backend));
    assert_eq!(*backend.verdicts.borrow(), vec![("anchor-1".to_owned(), "node-b".to_owned())]);
    let relayed = backend.relayed.borrow();
    assert_eq!(relayed.len(), 1);
    let (path, sent) = &relayed[0];
    assert_eq!(path, RELAY_CHALLENGE_PATH);
    // Client-claimed peer, home node and verdict are overwritten, never trusted.
    assert_eq!(sent["peer_node"], "node-b");
    assert_eq!(sent["home_node"], "node-b");
    assert_eq!(sent["home_verdict"], serde_json::to_value(verdict("node-b")).unwrap());
}

#[test]
fn forward_reads_the_requester_from_w_and_stamps_peer_and_verdict() {
    let backend = Fake::new("node-b");
    route(FEDERATION_SERVICE_ID, &forward("node-b", "node-b"), Some(&backend));
    let relayed = backend.relayed.borrow();
    assert_eq!(relayed[0].0, RELAY_RENEW_PATH);
    assert_eq!(relayed[0].1["peer_node"], "node-b");
    assert_eq!(relayed[0].1["home_verdict"], serde_json::to_value(verdict("node-b")).unwrap());
}

#[test]
fn every_home_equality_is_refused_in_isolation_without_a_relay_call() {
    // peer_node differs from the requester's home node.
    let backend = Fake::new("node-b");
    let reply = route(FEDERATION_SERVICE_ID, &challenge("node-c", "node-b"), Some(&backend));
    assert_eq!(refusal(&reply), json!({"Refused": {"code": "home_mismatch"}}));
    assert!(backend.relayed.borrow().is_empty());
    // The verdict names another home than peer_node.
    let backend = Fake::new("node-d");
    let reply = route(FEDERATION_SERVICE_ID, &forward("node-b", "node-b"), Some(&backend));
    assert_eq!(refusal(&reply), json!({"Refused": {"code": "home_mismatch"}}));
    assert!(backend.relayed.borrow().is_empty());
    // The verdict is for another anchor.
    let mut backend = Fake::new("node-b");
    backend.verdict = Ok(HomeVerdict { account_anchor: "anchor-2".into(), ..verdict("node-b") });
    let reply = route(FEDERATION_SERVICE_ID, &challenge("node-b", "node-b"), Some(&backend));
    assert_eq!(refusal(&reply), json!({"Refused": {"code": "home_mismatch"}}));
    assert!(backend.relayed.borrow().is_empty());
}

#[test]
fn verdict_refusals_and_malformed_bodies_are_typed() {
    let mut backend = Fake::new("node-b");
    backend.verdict = Err(RenewalRefusal::HomeTrustUnavailable);
    let reply = route(FEDERATION_SERVICE_ID, &challenge("node-b", "node-b"), Some(&backend));
    assert_eq!(refusal(&reply), json!({"Refused": {"code": "home_trust_unavailable"}}));
    assert!(backend.relayed.borrow().is_empty());
    let backend = Fake::new("node-b");
    for body in [
        &b"not json"[..],
        br#"{"kind":"other"}"#,
        br#"{"kind":"challenge","peer_node":"x","request":{}}"#,
    ] {
        let reply = route(FEDERATION_SERVICE_ID, body, Some(&backend));
        assert_eq!(refusal(&reply), json!({"Refused": {"code": "invalid"}}));
    }
    assert!(backend.untouched());
    // Inclusive size bound: the cap itself is parsed, one byte more is refused.
    let at_cap = vec![b' '; MAX_BODY];
    let over = vec![b' '; MAX_BODY + 1];
    assert_eq!(
        refusal(&route(FEDERATION_SERVICE_ID, &at_cap, Some(&backend))),
        json!({"Refused": {"code": "invalid"}})
    );
    assert_eq!(
        route(FEDERATION_SERVICE_ID, &over, Some(&backend)),
        text("413 Payload Too Large", "body")
    );
}
