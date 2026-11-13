// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use serde_json::json;
use std::cell::RefCell;
use std::time::Duration;

struct Fake {
    posted: RefCell<Vec<(String, Value)>>,
    deadlines: RefCell<Vec<Instant>>,
    reply: Result<Vec<u8>, RenewalRefusal>,
}
impl Fake {
    fn ok() -> Self {
        Self {
            posted: RefCell::default(),
            deadlines: RefCell::default(),
            reply: Ok(b"{\"relayed\":true}".to_vec()),
        }
    }
}
impl Forwarder for Fake {
    fn post(
        &self,
        _: &str,
        path: &str,
        body: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal> {
        self.deadlines.borrow_mut().push(deadline);
        self.posted
            .borrow_mut()
            .push((path.into(), serde_json::from_slice(&body).unwrap_or(Value::Null)));
        self.reply.clone()
    }
}
static ALLOW: &(dyn Fn(Instant) -> Result<(), RenewalRefusal> + Sync) = &|_| Ok(());
type InboundRow<'a> = (&'a str, Option<&'a str>, Vec<u8>, PeerView, Value);
const FED_B: Option<&str> = Some("spiffe://node-b/ramflux-federation");
fn view() -> PeerView {
    PeerView { advertised: true, admitted: true, negotiated: true }
}
fn body(home: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"kind":"challenge","home_node":home,"budget_ms":10_000,"request":{"x":1}}),
    )
    .unwrap_or_default()
}
fn code(reply: &Reply) -> Value {
    assert_eq!(reply.status, "200 OK");
    serde_json::from_slice::<Value>(&reply.body).unwrap_or(Value::Null)
}

#[test]
fn inbound_peer_stamps_the_tls_node_and_forwards_only_to_the_local_router() {
    let router = Fake::ok();
    let reply = inbound_peer(FED_B, &body("node-b"), &view(), &router, Instant::now(), ALLOW);
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
            br#"{"kind":"x","home_node":"node-b","budget_ms":10000,"request":{}}"#.to_vec(),
            view(),
            json!({"Refused":{"code":"invalid"}}),
        ),
        (
            "unknown member",
            FED_B,
            br#"{"kind":"challenge","home_node":"node-b","budget_ms":10000,"request":{},"z":1}"#
                .to_vec(),
            view(),
            json!({"Refused":{"code":"invalid"}}),
        ),
    ];
    for (name, uri, bytes, v, expected) in rows {
        let router = Fake::ok();
        let reply = inbound_peer(uri, &bytes, &v, &router, Instant::now(), ALLOW);
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
            let reply = inbound_peer(uri, &bytes, &view(), &router, Instant::now(), ALLOW);
            assert_eq!(reply.status, "403 Forbidden", "{uri:?}");
        }
        assert!(router.posted.borrow().is_empty());
    }
    let router = Fake::ok();
    let mut at_cap = body("node-b");
    at_cap.resize(MAX_BODY, b' ');
    assert_eq!(
        inbound_peer(FED_B, &at_cap, &view(), &router, Instant::now(), ALLOW).status,
        "200 OK"
    );
    assert_eq!(router.posted.borrow().len(), 1);
    at_cap.push(b' ');
    assert_eq!(
        inbound_peer(FED_B, &at_cap, &view(), &router, Instant::now(), ALLOW).status,
        "413 Payload Too Large"
    );
    assert_eq!(router.posted.borrow().len(), 1);
}

fn budgeted(body: &[u8], budget_ms: u64) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    v["budget_ms"] = json!(budget_ms);
    serde_json::to_vec(&v).unwrap_or_default()
}

#[test]
fn the_carried_budget_is_validated_and_constrains_every_downstream_step() {
    // 0 and anything over the ten-second ceiling are malformed; 1 and 10000 are accepted.
    for (budget, ok) in [(0, false), (1, true), (10_000, true), (10_001, false)] {
        let router = Fake::ok();
        let reply = inbound_peer(
            FED_B,
            &budgeted(&body("node-b"), budget),
            &view(),
            &router,
            // Received "in the future" so a 1 ms budget cannot lapse while the test runs.
            Instant::now() + Duration::from_secs(3_600),
            ALLOW,
        );
        if ok {
            assert_eq!(router.posted.borrow().len(), 1, "{budget}");
        } else {
            assert_eq!(code(&reply), json!({"Refused":{"code":"invalid"}}), "{budget}");
            assert!(router.posted.borrow().is_empty(), "{budget}");
        }
    }
    // The deadline is the receive time plus the carried budget: the listener is told to
    // tighten to exactly that instant, the router gets exactly that deadline and only the
    // remainder as its own budget.
    let router = Fake::ok();
    let received = Instant::now();
    let told = std::cell::Cell::new(None);
    let reply =
        inbound_peer(FED_B, &budgeted(&body("node-b"), 2_000), &view(), &router, received, &|d| {
            told.set(Some(d));
            Ok(())
        });
    assert_eq!(reply.status, "200 OK");
    let expected = received + Duration::from_millis(2_000);
    assert_eq!(told.get(), Some(expected));
    assert_eq!(router.deadlines.borrow()[0], expected);
    let carried = router.posted.borrow()[0].1["budget_ms"].as_u64().unwrap_or(0);
    assert!((1..=2_000).contains(&carried), "{carried}");
    // A budget that has already run out when work would start stops before any hop...
    let router = Fake::ok();
    let long_ago = Instant::now().checked_sub(Duration::from_secs(20)).unwrap_or_else(Instant::now);
    let reply = inbound_peer(FED_B, &body("node-b"), &view(), &router, long_ago, ALLOW);
    assert_eq!(code(&reply), json!({"Refused":{"code":"busy"}}));
    assert!(router.posted.borrow().is_empty());
    // ...and so does a listener that cannot tighten its own deadline.
    let router = Fake::ok();
    let reply = inbound_peer(FED_B, &body("node-b"), &view(), &router, Instant::now(), &|_| {
        Err(RenewalRefusal::Busy)
    });
    assert_eq!(code(&reply), json!({"Refused":{"code":"busy"}}));
    assert!(router.posted.borrow().is_empty());
}

fn local_body(token: &str, source: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"admin_token":token,"source_node":source,"kind":"forward","budget_ms":10_000,"request":{"y":2}}),
    )
    .unwrap_or_default()
}

#[test]
fn local_hop_requires_the_admin_token_and_an_admitted_negotiated_peer() -> Result<(), NodeCoreError>
{
    let peer = Fake::ok();
    let all = |_: &str| view();
    // Wrong or missing token: no outbound call.
    let bad = local_peer(
        Some("tok"),
        &local_body("bad", "node-a"),
        "node-b",
        &all,
        &peer,
        Instant::now(),
    );
    assert!(
        matches!(&bad, Err(NodeCoreError::ItestHttp(m)) if m == "federation admin authentication failed"),
        "{bad:?}"
    );
    let unset =
        local_peer(None, &local_body("tok", "node-a"), "node-b", &all, &peer, Instant::now());
    assert!(
        matches!(&unset, Err(NodeCoreError::ItestHttp(m)) if m == "federation admin token is not configured"),
        "{unset:?}"
    );
    let malformed = local_peer(Some("tok"), b"not json", "node-b", &all, &peer, Instant::now());
    assert!(
        matches!(&malformed, Err(NodeCoreError::ItestHttp(m)) if m == "invalid attachment renewal request"),
        "{malformed:?}"
    );
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
        let reply = local_peer(
            Some("tok"),
            &local_body("tok", "node-a"),
            "node-b",
            &one,
            &peer,
            Instant::now(),
        )?;
        assert_eq!(code(&reply), expected, "{name}");
        assert!(peer.posted.borrow().is_empty(), "{name}");
    }
    // Valid: posts the peer envelope with this node as home to the peer path only.
    let reply = local_peer(
        Some("tok"),
        &local_body("tok", "node-a"),
        "node-b",
        &all,
        &peer,
        Instant::now(),
    )?;
    assert_eq!(reply.body, b"{\"relayed\":true}".to_vec());
    let posted = peer.posted.borrow();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].0, PEER_PATH);
    assert_eq!(posted[0].1["home_node"], "node-b");
    assert_eq!(posted[0].1["kind"], "forward");
    // A hop refusal is passed on typed, never retried or redirected.
    let failing = Fake {
        posted: RefCell::default(),
        deadlines: RefCell::default(),
        reply: Err(RenewalRefusal::Busy),
    };
    let reply = local_peer(
        Some("tok"),
        &local_body("tok", "node-a"),
        "node-b",
        &all,
        &failing,
        Instant::now(),
    )?;
    assert_eq!(code(&reply), json!({"Refused":{"code":"busy"}}));
    assert_eq!(failing.posted.borrow().len(), 1);
    Ok(())
}

#[test]
fn pin_lookup_is_empty_unless_advertised_and_unadmitted_nodes_are_source_unknown()
-> Result<(), NodeCoreError> {
    let state =
        crate::SharedFederationTrustState::new(ramflux_node_core::FederationTrustState::new());
    let path = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-fed-pin-answer-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
    let store = ramflux_node_core::FederationRedbStore::open(&path)?;
    // Not advertised: nothing is exposed, whatever the peer is.
    assert_eq!(
        pin_answer_for(&state, &store, false, "node-a")?,
        ramflux_node_core::PinAnswer::Unavailable
    );
    // Advertised, but this node has never admitted the peer.
    assert_eq!(
        pin_answer_for(&state, &store, true, "node-a")?,
        ramflux_node_core::PinAnswer::SourceUnknown
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Hang guard: the accept and every read fail loudly after ten seconds instead of blocking.
fn accept_within(listener: &std::net::TcpListener) -> std::io::Result<std::net::TcpStream> {
    let give_up = Instant::now() + Duration::from_secs(10);
    listener.set_nonblocking(true)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(10)))?;
                return Ok(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < give_up, "no connection within 10 s");
                std::thread::yield_now();
            }
            Err(error) => return Err(error),
        }
    }
}

#[test]
fn the_listener_cap_is_16_kib_on_the_declared_length_over_a_real_socket() -> std::io::Result<()> {
    use std::io::Write;
    let cap = crate::mesh::mesh_body_cap("POST", PEER_PATH);
    assert_eq!(cap, MAX_BODY);
    assert_eq!(MAX_BODY, 16384);
    assert!(crate::mesh::mesh_body_cap("POST", "/v3/home-migration/peer") > MAX_BODY);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let head = |n: usize| format!("POST {PEER_PATH} HTTP/1.1\r\nContent-Length: {n}\r\n\r\n");
    // 16384: the full body is read as received.
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut s = std::net::TcpStream::connect(addr)?;
        s.write_all(head(16384).as_bytes())?;
        s.write_all(&vec![b' '; 16384])?;
        s.shutdown(std::net::Shutdown::Write)
    });
    let mut stream = accept_within(&listener)?;
    let ok = ramflux_transport::read_bounded_mesh_http_request_by_path(
        &mut stream,
        &crate::mesh::mesh_body_cap,
    );
    writer.join().map_err(|_| std::io::Error::other("writer panicked"))??;
    assert_eq!(ok.map(|r| r.map(|r| r.body.len())).ok().flatten(), Some(16384));
    // 16385 is refused on the declared length; the client never sends a body byte.
    let writer = std::thread::spawn(move || -> std::io::Result<std::net::TcpStream> {
        let mut s = std::net::TcpStream::connect(addr)?;
        s.write_all(head(16385).as_bytes())?;
        Ok(s)
    });
    let mut stream = accept_within(&listener)?;
    let refused = ramflux_transport::read_bounded_mesh_http_request_by_path(
        &mut stream,
        &crate::mesh::mesh_body_cap,
    );
    let _held = writer.join().map_err(|_| std::io::Error::other("writer panicked"))??;
    assert!(
        matches!(&refused, Err(ramflux_transport::TransportError::Http(m)) if m == "mesh body exceeds budget"),
        "{refused:?}"
    );
    Ok(())
}

#[test]
fn the_local_hop_carries_only_the_remainder_and_stops_at_the_originating_deadline()
-> Result<(), NodeCoreError> {
    let all = |_: &str| view();
    let with = |budget: u64| -> Vec<u8> {
        let mut v: Value =
            serde_json::from_slice(&local_body("tok", "node-a")).unwrap_or(Value::Null);
        v["budget_ms"] = json!(budget);
        serde_json::to_vec(&v).unwrap_or_default()
    };
    // Ends of the accepted range, and the malformed ones (typed, nothing posted).
    for (budget, ok) in [(0, false), (1, true), (10_000, true), (10_001, false)] {
        let peer = Fake::ok();
        let future = Instant::now() + Duration::from_secs(3_600);
        let reply = local_peer(Some("tok"), &with(budget), "node-b", &all, &peer, future)?;
        if ok {
            assert_eq!(peer.posted.borrow().len(), 1, "{budget}");
        } else {
            assert_eq!(code(&reply), json!({"Refused":{"code":"invalid"}}), "{budget}");
            assert!(peer.posted.borrow().is_empty(), "{budget}");
        }
    }
    // The peer is posted exactly the originating deadline and a remainder of that budget.
    let peer = Fake::ok();
    let received = Instant::now();
    local_peer(Some("tok"), &with(3_000), "node-b", &all, &peer, received)?;
    assert_eq!(peer.deadlines.borrow()[0], received + Duration::from_millis(3_000));
    let carried = peer.posted.borrow()[0].1["budget_ms"].as_u64().unwrap_or(0);
    assert!((1..=3_000).contains(&carried), "{carried}");
    // Already past the originating deadline: busy, no hop.
    let peer = Fake::ok();
    let long_ago = Instant::now().checked_sub(Duration::from_secs(20)).unwrap_or_else(Instant::now);
    let reply = local_peer(Some("tok"), &with(10_000), "node-b", &all, &peer, long_ago)?;
    assert_eq!(code(&reply), json!({"Refused":{"code":"busy"}}));
    assert!(peer.posted.borrow().is_empty());
    Ok(())
}
