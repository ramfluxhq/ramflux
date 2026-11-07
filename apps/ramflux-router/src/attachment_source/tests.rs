// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use ramflux_protocol::large_attachment::{ForwardAttestation, QualifiedOwner};
use serde_json::json;
use std::cell::RefCell;
use std::time::Instant;

const NOW: u64 = 1_700_000_000;

fn far() -> Instant {
    Instant::now() + ROUTE_BUDGET
}

struct Fake {
    verdict: Result<HomeVerdict, RenewalRefusal>,
    relayed: RefCell<Vec<(String, Value)>>,
    verdicts: RefCell<Vec<(String, String)>>,
    deadlines: RefCell<Vec<Instant>>,
}
impl Fake {
    fn new(node: &str) -> Self {
        Self {
            verdict: Ok(verdict(node)),
            relayed: RefCell::default(),
            verdicts: RefCell::default(),
            deadlines: RefCell::default(),
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
    fn verdict(
        &self,
        anchor: &str,
        peer: &str,
        _: u64,
        deadline: Instant,
    ) -> Result<HomeVerdict, RenewalRefusal> {
        self.deadlines.borrow_mut().push(deadline);
        self.verdicts.borrow_mut().push((anchor.into(), peer.into()));
        self.verdict.clone()
    }
    fn relay(
        &self,
        path: &str,
        body: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal> {
        self.deadlines.borrow_mut().push(deadline);
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
        let reply = route(peer, &body, Some(&backend), far());
        assert_eq!(
            reply,
            text("403 Forbidden", "attachment source requires federation identity"),
            "{peer}"
        );
    }
    assert!(backend.untouched());
    let ok = route(FEDERATION_SERVICE_ID, &body, Some(&backend), far());
    assert_eq!(ok, SourceReply { status: "200 OK", body: b"{\"relayed\":true}".to_vec() });
}

#[test]
fn dormant_without_a_backend() {
    let reply = route(FEDERATION_SERVICE_ID, &challenge("node-b", "node-b"), None, far());
    assert_eq!(reply, text("503 Service Unavailable", "attachment source is not configured"));
    // The peer check still comes first.
    assert_eq!(route("ramflux-gateway", b"{}", None, far()).status, "403 Forbidden");
}

#[test]
fn challenge_gets_the_stamped_peer_and_the_router_verdict() {
    let backend = Fake::new("node-b");
    route(FEDERATION_SERVICE_ID, &challenge("node-b", "node-b"), Some(&backend), far());
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
    route(FEDERATION_SERVICE_ID, &forward("node-b", "node-b"), Some(&backend), far());
    let relayed = backend.relayed.borrow();
    assert_eq!(relayed[0].0, RELAY_RENEW_PATH);
    assert_eq!(relayed[0].1["peer_node"], "node-b");
    assert_eq!(relayed[0].1["home_verdict"], serde_json::to_value(verdict("node-b")).unwrap());
}

fn mismatch() -> Value {
    json!({"Refused": {"code": "home_mismatch"}})
}
fn invalid() -> Value {
    json!({"Refused": {"code": "invalid"}})
}
fn run(backend: &Fake, body: &[u8]) -> SourceReply {
    route(FEDERATION_SERVICE_ID, body, Some(backend), far())
}
fn verdict_for(node: &str, anchor: &str) -> Fake {
    let mut f = Fake::new(node);
    f.verdict = Ok(HomeVerdict { account_anchor: anchor.into(), ..verdict(node) });
    f
}

/// One equality violated per row, for both envelope kinds. The three equalities are
/// verdict.home == peer, peer == requester home, and verdict.anchor == requester anchor.
#[test]
fn every_home_equality_is_refused_in_isolation_without_a_relay_call() {
    type Build = fn(&str, &str) -> Vec<u8>;
    for (kind, build) in [("challenge", challenge as Build), ("forward", forward as Build)] {
        // verdict names C; peer = requester home = B.
        let backend = verdict_for("node-c", "anchor-1");
        assert_eq!(refusal(&run(&backend, &build("node-b", "node-b"))), mismatch(), "{kind}");
        assert!(backend.relayed.borrow().is_empty());
        // verdict = peer = C; requester home = B (the other half of the same pair).
        let backend = verdict_for("node-c", "anchor-1");
        assert_eq!(refusal(&run(&backend, &build("node-c", "node-b"))), mismatch(), "{kind}");
        assert!(backend.relayed.borrow().is_empty());
        // verdict = requester home = B; peer = C.
        let backend = verdict_for("node-b", "anchor-1");
        assert_eq!(refusal(&run(&backend, &build("node-c", "node-b"))), mismatch(), "{kind}");
        assert!(backend.relayed.borrow().is_empty());
        // Only the anchor differs.
        let backend = verdict_for("node-b", "anchor-2");
        assert_eq!(refusal(&run(&backend, &build("node-b", "node-b"))), mismatch(), "{kind}");
        assert!(backend.relayed.borrow().is_empty());
        // All equal: relayed exactly once.
        let backend = verdict_for("node-b", "anchor-1");
        run(&backend, &build("node-b", "node-b"));
        assert_eq!(backend.relayed.borrow().len(), 1, "{kind}");
    }
}

#[test]
fn verdict_refusals_and_malformed_bodies_are_typed() {
    let mut backend = Fake::new("node-b");
    backend.verdict = Err(RenewalRefusal::HomeTrustUnavailable);
    let reply = run(&backend, &challenge("node-b", "node-b"));
    assert_eq!(refusal(&reply), json!({"Refused": {"code": "home_trust_unavailable"}}));
    assert!(backend.relayed.borrow().is_empty());
    let backend = Fake::new("node-b");
    let bad: Vec<(&str, Vec<u8>)> = vec![
        ("not json", b"not json".to_vec()),
        ("unknown kind", br#"{"kind":"other"}"#.to_vec()),
        ("no requester", br#"{"kind":"challenge","peer_node":"x","request":{}}"#.to_vec()),
        (
            "no anchor",
            br#"{"kind":"challenge","peer_node":"x","request":{"requester":{"home_node_id":"x"}}}"#
                .to_vec(),
        ),
        (
            "no home",
            br#"{"kind":"challenge","peer_node":"x","request":{"requester":{"account_anchor":"a"}}}"#
                .to_vec(),
        ),
        ("request not an object", br#"{"kind":"challenge","peer_node":"x","request":[]}"#.to_vec()),
        ("forward without W", br#"{"kind":"forward","peer_node":"x","request":{}}"#.to_vec()),
        (
            "W not bytes",
            br#"{"kind":"forward","peer_node":"x","request":{"attestation":"abc"}}"#.to_vec(),
        ),
        (
            "W undecodable",
            br#"{"kind":"forward","peer_node":"x","request":{"attestation":[1,2,3]}}"#.to_vec(),
        ),
    ];
    for (name, body) in &bad {
        assert_eq!(refusal(&run(&backend, body)), invalid(), "{name}");
    }
    assert!(backend.untouched());
}

fn padded(mut body: Vec<u8>, total: usize) -> Vec<u8> {
    assert!(body.len() <= total);
    body.resize(total, b' ');
    body
}

#[test]
fn sixteen_kib_wire_cap_is_exact_at_the_router_gate() {
    let backend = Fake::new("node-b");
    let base = challenge("node-b", "node-b");
    let at_cap = padded(base.clone(), MAX_BODY);
    assert_eq!(at_cap.len(), 16384);
    let ok = run(&backend, &at_cap);
    assert_eq!(ok.body, b"{\"relayed\":true}".to_vec());
    let over = padded(base, MAX_BODY + 1);
    assert_eq!(run(&backend, &over), text("413 Payload Too Large", "body"));
    assert_eq!(backend.relayed.borrow().len(), 1);
}

#[test]
fn an_outgoing_body_over_the_cap_is_refused_without_a_relay_call() {
    let backend = Fake::new("node-b");
    // The largest challenge that still passes the inbound gate: the stamped verdict then
    // pushes the forwarded body past 16 KiB.
    let mut n = 1;
    let body = loop {
        let mut v: Value = serde_json::from_slice(&challenge("node-b", "node-b")).unwrap();
        v["request"]["capability"] = json!(vec![1u8; n]);
        let b = serde_json::to_vec(&v).unwrap();
        if b.len() + 2 > MAX_BODY {
            break b;
        }
        n += 1;
    };
    assert!(body.len() <= MAX_BODY && body.len() + 2 > MAX_BODY);
    assert_eq!(refusal(&run(&backend, &body)), invalid());
    assert!(backend.relayed.borrow().is_empty());
}

#[test]
fn the_shared_route_budget_reaches_every_backend_call_and_expiry_is_busy() {
    // An elapsed budget stops the route before any backend call.
    let backend = Fake::new("node-b");
    let past = Instant::now().checked_sub(std::time::Duration::from_millis(1)).unwrap();
    let reply = route(FEDERATION_SERVICE_ID, &challenge("node-b", "node-b"), Some(&backend), past);
    assert_eq!(refusal(&reply), json!({"Refused": {"code": "busy"}}));
    assert!(backend.untouched());
    // A live budget is the very deadline each hop receives, verdict first, relay second.
    let backend = Fake::new("node-b");
    let deadline = far();
    route(FEDERATION_SERVICE_ID, &forward("node-b", "node-b"), Some(&backend), deadline);
    assert_eq!(*backend.deadlines.borrow(), vec![deadline, deadline]);
    // The whole route budget is the protocol's ten seconds.
    assert_eq!(ROUTE_BUDGET, std::time::Duration::from_secs(10));
}
