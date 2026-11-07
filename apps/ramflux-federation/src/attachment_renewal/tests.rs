// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use serde_json::json;
use std::cell::RefCell;
use std::time::Duration;

struct Fake {
    posted: RefCell<Vec<(String, Value)>>,
    reply: Result<Vec<u8>, RenewalRefusal>,
}
impl Fake {
    fn ok() -> Self {
        Self { posted: RefCell::default(), reply: Ok(b"{\"relayed\":true}".to_vec()) }
    }
}
impl Forwarder for Fake {
    fn post(
        &self,
        _: &str,
        path: &str,
        body: Vec<u8>,
        _: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal> {
        self.posted
            .borrow_mut()
            .push((path.into(), serde_json::from_slice(&body).unwrap_or(Value::Null)));
        self.reply.clone()
    }
}
fn far() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
type InboundRow<'a> = (&'a str, Option<&'a str>, Vec<u8>, PeerView, Value);
const FED_B: Option<&str> = Some("spiffe://node-b/ramflux-federation");
fn view() -> PeerView {
    PeerView { advertised: true, admitted: true, negotiated: true }
}
fn body(home: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"kind":"challenge","home_node":home,"request":{"x":1}}))
        .unwrap_or_default()
}
fn code(reply: &Reply) -> Value {
    assert_eq!(reply.status, "200 OK");
    serde_json::from_slice::<Value>(&reply.body).unwrap_or(Value::Null)
}

#[test]
fn inbound_peer_stamps_the_tls_node_and_forwards_only_to_the_local_router() {
    let router = Fake::ok();
    let reply = inbound_peer(FED_B, &body("node-b"), &view(), &router, far());
    assert_eq!(reply.body, b"{\"relayed\":true}".to_vec());
    let posted = router.posted.borrow();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].0, ROUTER_SOURCE_PATH);
    assert_eq!(posted[0].1["peer_node"], "node-b");
    assert_eq!(posted[0].1["kind"], "challenge");
}

#[test]
fn inbound_refusals_are_isolated_and_never_reach_the_router() {
    let rows: Vec<InboundRow<'_>> = vec![
        (
            "not advertised",
            FED_B,
            body("node-b"),
            PeerView { advertised: false, ..view() },
            json!({"Refused":{"code":"capability_unavailable"}}),
        ),
        (
            "unadmitted",
            FED_B,
            body("node-b"),
            PeerView { admitted: false, ..view() },
            json!({"Refused":{"code":"source_unknown"}}),
        ),
        (
            "not negotiated",
            FED_B,
            body("node-b"),
            PeerView { negotiated: false, ..view() },
            json!({"Refused":{"code":"capability_unavailable"}}),
        ),
        // C's TLS identity claiming home B.
        (
            "tls != home",
            Some("spiffe://node-c/ramflux-federation"),
            body("node-b"),
            view(),
            json!({"Refused":{"code":"home_mismatch"}}),
        ),
        ("malformed", FED_B, b"not json".to_vec(), view(), json!({"Refused":{"code":"invalid"}})),
        (
            "unknown kind",
            FED_B,
            br#"{"kind":"x","home_node":"node-b","request":{}}"#.to_vec(),
            view(),
            json!({"Refused":{"code":"invalid"}}),
        ),
        (
            "unknown member",
            FED_B,
            br#"{"kind":"challenge","home_node":"node-b","request":{},"z":1}"#.to_vec(),
            view(),
            json!({"Refused":{"code":"invalid"}}),
        ),
    ];
    for (name, uri, bytes, v, expected) in rows {
        let router = Fake::ok();
        let reply = inbound_peer(uri, &bytes, &v, &router, far());
        assert_eq!(code(&reply), expected, "{name}");
        assert!(router.posted.borrow().is_empty(), "{name}");
    }
}

#[test]
fn only_a_federation_identity_reaches_the_body_and_the_cap_is_exact() {
    for uri in [
        None,
        Some("not-spiffe"),
        Some("spiffe://node-b/ramflux-gateway"),
        Some("spiffe://node-b/ramflux-router"),
        Some("spiffe://node-b/ramflux-relay"),
    ] {
        let router = Fake::ok();
        // Even an undecodable, oversized body gets the same 403: identity comes first.
        for bytes in [body("node-b"), vec![b'x'; MAX_BODY + 1]] {
            let reply = inbound_peer(uri, &bytes, &view(), &router, far());
            assert_eq!(reply.status, "403 Forbidden", "{uri:?}");
        }
        assert!(router.posted.borrow().is_empty());
    }
    let router = Fake::ok();
    let mut at_cap = body("node-b");
    at_cap.resize(MAX_BODY, b' ');
    assert_eq!(inbound_peer(FED_B, &at_cap, &view(), &router, far()).status, "200 OK");
    assert_eq!(router.posted.borrow().len(), 1);
    at_cap.push(b' ');
    assert_eq!(
        inbound_peer(FED_B, &at_cap, &view(), &router, far()).status,
        "413 Payload Too Large"
    );
    assert_eq!(router.posted.borrow().len(), 1);
}

#[test]
fn an_elapsed_budget_is_busy_before_any_hop() {
    let router = Fake::ok();
    let past = Instant::now().checked_sub(Duration::from_millis(1)).unwrap_or_else(Instant::now);
    let reply = inbound_peer(FED_B, &body("node-b"), &view(), &router, past);
    assert_eq!(code(&reply), json!({"Refused":{"code":"busy"}}));
    assert!(router.posted.borrow().is_empty());
}

fn local_body(token: &str, source: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"admin_token":token,"source_node":source,"kind":"forward","request":{"y":2}}),
    )
    .unwrap_or_default()
}

#[test]
fn local_hop_requires_the_admin_token_and_an_admitted_negotiated_peer() -> Result<(), NodeCoreError>
{
    let peer = Fake::ok();
    let all = |_: &str| view();
    // Wrong or missing token: no outbound call.
    assert!(
        local_peer(Some("tok"), &local_body("bad", "node-a"), "node-b", &all, &peer, far())
            .is_err()
    );
    assert!(local_peer(None, &local_body("tok", "node-a"), "node-b", &all, &peer, far()).is_err());
    assert!(peer.posted.borrow().is_empty());
    // Peer-state rows, one false at a time.
    let rows: Vec<(&str, PeerView, Value)> = vec![
        (
            "not advertised",
            PeerView { advertised: false, ..view() },
            json!({"Refused":{"code":"capability_unavailable"}}),
        ),
        (
            "unadmitted",
            PeerView { admitted: false, ..view() },
            json!({"Refused":{"code":"source_unknown"}}),
        ),
        (
            "not negotiated",
            PeerView { negotiated: false, ..view() },
            json!({"Refused":{"code":"capability_unavailable"}}),
        ),
    ];
    for (name, v, expected) in rows {
        let peer = Fake::ok();
        let one = move |_: &str| PeerView {
            advertised: v.advertised,
            admitted: v.admitted,
            negotiated: v.negotiated,
        };
        let reply =
            local_peer(Some("tok"), &local_body("tok", "node-a"), "node-b", &one, &peer, far())?;
        assert_eq!(code(&reply), expected, "{name}");
        assert!(peer.posted.borrow().is_empty(), "{name}");
    }
    // Valid: posts the peer envelope with this node as home to the peer path only.
    let reply =
        local_peer(Some("tok"), &local_body("tok", "node-a"), "node-b", &all, &peer, far())?;
    assert_eq!(reply.body, b"{\"relayed\":true}".to_vec());
    let posted = peer.posted.borrow();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].0, PEER_PATH);
    assert_eq!(posted[0].1["home_node"], "node-b");
    assert_eq!(posted[0].1["kind"], "forward");
    // A hop refusal is passed on typed, never retried or redirected.
    let failing = Fake { posted: RefCell::default(), reply: Err(RenewalRefusal::Busy) };
    let reply =
        local_peer(Some("tok"), &local_body("tok", "node-a"), "node-b", &all, &failing, far())?;
    assert_eq!(code(&reply), json!({"Refused":{"code":"busy"}}));
    assert_eq!(failing.posted.borrow().len(), 1);
    Ok(())
}
