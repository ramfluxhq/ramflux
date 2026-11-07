// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! The relay authority admits the source router only (P25 N5b).
use super::*;
use crate::attachment_authority::listener::{
    AuthorityListener, AuthorityListenerConfig, CHALLENGE_PATH, ChallengeMintRequest,
    ChallengeReply, Handled, Incoming, MAX_WIRE_BODY, RENEW_PATH, RequesterWire,
};

const ROUTER: &str = "spiffe://node-a/ramflux-router";

fn wire(e: &Env) -> ChallengeMintRequest {
    let g = e.g();
    let r = &g.grantee;
    ChallengeMintRequest {
        capability: e.cap.clone(),
        target_operation: e.target().canonical_bytes().unwrap(),
        requester: RequesterWire {
            account_anchor: r.account_anchor.clone(),
            device_id: r.device_id.clone(),
            device_epoch: r.device_epoch,
            signing_public_key: r.signing_public_key,
            home_node_id: r.home_node_id.clone(),
        },
        home_node: r.home_node_id.clone(),
        peer_node: r.home_node_id.clone(),
        home_verdict: Some(e.verdict()),
    }
}
fn call(
    e: &Env,
    peer: Option<&str>,
    path: &str,
    body: &[u8],
) -> (Result<Handled, IssueError>, VecSink) {
    let listener = AuthorityListener::new(&e.issuer);
    let mut sink = VecSink::default();
    let now = e.now;
    let out = listener.handle(
        &Incoming { peer_spiffe_uri: peer, method: "POST", path, body },
        &|| now,
        &mut sink,
        &IssueHooks::none(),
    );
    (out, sink)
}
fn challenge_of(handled: Handled) -> [u8; 32] {
    match handled {
        Handled::Challenge(ChallengeReply::Minted { challenge, .. }) => challenge,
        other => panic!("expected a minted challenge, got {other:?}"),
    }
}
fn refused_challenge(e: &Env, request: &ChallengeMintRequest) -> RenewalRefusal {
    let body = serde_json::to_vec(request).unwrap();
    match call(e, Some(ROUTER), CHALLENGE_PATH, &body).0.unwrap() {
        Handled::Challenge(ChallengeReply::Refused { code }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn large_relay_authority_admits_router_peer_only() {
    let e = Env::new("listener-peer");
    let body = serde_json::to_vec(&wire(&e)).unwrap();
    // Router peer: challenge, then the full renewal, both through the listener.
    let challenge = challenge_of(call(&e, Some(ROUTER), CHALLENGE_PATH, &body).0.unwrap());
    let request = e.build(e.g(), &e.cap, &e.target(), challenge, 7);
    let renew = serde_json::to_vec(&request).unwrap();
    let (out, sink) = call(&e, Some(ROUTER), RENEW_PATH, &renew);
    assert_eq!(out.unwrap(), Handled::Renew(Outcome::Issued));
    assert!(matches!(
        serde_json::from_slice::<RenewAdmitResponse>(&sink.bytes).unwrap(),
        RenewAdmitResponse::Issued { .. }
    ));

    // Every other identity is refused on both routes before the body is read, and
    // nothing is written or consumed: the same challenge and nonce still work.
    let fresh = Env::new("listener-peer-negative");
    let body = serde_json::to_vec(&wire(&fresh)).unwrap();
    let challenge = challenge_of(call(&fresh, Some(ROUTER), CHALLENGE_PATH, &body).0.unwrap());
    let renew =
        serde_json::to_vec(&fresh.build(fresh.g(), &fresh.cap, &fresh.target(), challenge, 7))
            .unwrap();
    let wrong = [
        Some("spiffe://node-a/ramflux-gateway"),
        Some("spiffe://node-a/ramflux-federation"),
        // The service matrix admits retention to the relay; the listener must not.
        Some("spiffe://node-a/ramflux-retention"),
        Some("spiffe://node-a/ramflux-notify"),
        Some("https://node-a/ramflux-router"),
        None,
    ];
    for peer in wrong {
        for (path, payload) in [(CHALLENGE_PATH, &body), (RENEW_PATH, &renew)] {
            let (out, sink) = call(&fresh, peer, path, payload);
            assert_eq!(
                out.unwrap(),
                Handled::Rejected {
                    status: "403 Forbidden",
                    reason: "attachment authority requires the router identity"
                },
                "{peer:?} {path}"
            );
            assert!(sink.bytes.is_empty() && !sink.reset);
        }
    }
    let (out, _) = call(&fresh, Some(ROUTER), RENEW_PATH, &renew);
    assert_eq!(out.unwrap(), Handled::Renew(Outcome::Issued));
}

#[test]
fn authority_listener_is_off_without_a_bind_address() {
    assert!(!AuthorityListenerConfig::default().enabled());
    assert!(AuthorityListenerConfig { bind_addr: Some("127.0.0.1:0".into()) }.enabled());
}

#[test]
fn missing_verdict_is_home_trust_unavailable_on_both_routes() {
    let e = Env::new("listener-missing");
    let mut request = wire(&e);
    request.home_verdict = None;
    assert_eq!(refused_challenge(&e, &request), RenewalRefusal::HomeTrustUnavailable);
    // A body with no `home_verdict` key at all, and an explicit null.
    let mut v = serde_json::to_value(wire(&e)).unwrap();
    v.as_object_mut().unwrap().remove("home_verdict");
    let body = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        call(&e, Some(ROUTER), CHALLENGE_PATH, &body).0.unwrap(),
        Handled::Challenge(ChallengeReply::Refused { code: RenewalRefusal::HomeTrustUnavailable })
    ));
    let challenge = e.mint(e.g(), &e.cap, &e.target());
    let renewal = e.build(e.g(), &e.cap, &e.target(), challenge, 7);
    for strip in [true, false] {
        let mut v = serde_json::to_value(&renewal).unwrap();
        if strip {
            v.as_object_mut().unwrap().remove("home_verdict");
        } else {
            v["home_verdict"] = serde_json::Value::Null;
        }
        let (out, sink) = call(&e, Some(ROUTER), RENEW_PATH, &serde_json::to_vec(&v).unwrap());
        assert_eq!(
            out.unwrap(),
            Handled::Renew(Outcome::Refused(RenewalRefusal::HomeTrustUnavailable))
        );
        assert!(matches!(
            serde_json::from_slice::<RenewAdmitResponse>(&sink.bytes).unwrap(),
            RenewAdmitResponse::Refused { code: RenewalRefusal::HomeTrustUnavailable }
        ));
    }
    // The refusals consumed nothing: the same renewal is still issued.
    assert!(e.run(&renewal).is_ok());
}

#[test]
fn stale_verdict_is_refused_at_exactly_sixty_one_seconds() {
    let e = Env::new("listener-stale");
    let mut request = wire(&e);
    // Inclusive boundary: age 60 is accepted.
    request.home_verdict.as_mut().unwrap().checked_at = e.now - 60;
    let body = serde_json::to_vec(&request).unwrap();
    challenge_of(call(&e, Some(ROUTER), CHALLENGE_PATH, &body).0.unwrap());
    request.home_verdict.as_mut().unwrap().checked_at = e.now - 61;
    assert_eq!(refused_challenge(&e, &request), RenewalRefusal::HomeTrustUnavailable);
    // The same bound holds on the renew route.
    let challenge = e.mint(e.g(), &e.cap, &e.target());
    let mut renewal = e.build(e.g(), &e.cap, &e.target(), challenge, 7);
    renewal.home_verdict.checked_at = e.now - 61;
    let (out, _) = call(&e, Some(ROUTER), RENEW_PATH, &serde_json::to_vec(&renewal).unwrap());
    assert_eq!(
        out.unwrap(),
        Handled::Renew(Outcome::Refused(RenewalRefusal::HomeTrustUnavailable))
    );
}

#[test]
fn peer_node_other_than_the_home_node_is_refused() {
    let e = Env::new("listener-peer-node");
    let mut request = wire(&e);
    request.peer_node = "node-c".into();
    assert_eq!(refused_challenge(&e, &request), RenewalRefusal::HomeMismatch);
    let challenge = e.mint(e.g(), &e.cap, &e.target());
    let mut renewal = e.build(e.g(), &e.cap, &e.target(), challenge, 7);
    renewal.peer_node = "node-c".into();
    let (out, _) = call(&e, Some(ROUTER), RENEW_PATH, &serde_json::to_vec(&renewal).unwrap());
    assert_eq!(out.unwrap(), Handled::Renew(Outcome::Refused(RenewalRefusal::HomeMismatch)));
}

fn get(e: &Env, path: &str, method: &str) -> Handled {
    let listener = AuthorityListener::new(&e.issuer);
    let mut sink = VecSink::default();
    let now = e.now;
    listener
        .handle(
            &Incoming { peer_spiffe_uri: Some(ROUTER), method, path, body: b"{}" },
            &|| now,
            &mut sink,
            &IssueHooks::none(),
        )
        .unwrap()
}

#[test]
fn method_and_path_predicates_are_each_refused_in_isolation() {
    let e = Env::new("listener-routes");
    let not_found = Handled::Rejected { status: "404 Not Found", reason: "unknown route" };
    // Right path, wrong method (both routes).
    assert_eq!(get(&e, CHALLENGE_PATH, "GET"), not_found);
    assert_eq!(get(&e, RENEW_PATH, "GET"), not_found);
    // Right method, wrong path.
    assert_eq!(get(&e, "/s9/attachment-authority/other", "POST"), not_found);
    assert_eq!(get(&e, "", "POST"), not_found);
}

#[test]
fn the_sixteen_kib_wire_cap_is_exact_on_both_routes() {
    let e = Env::new("listener-cap");
    // 16384 bytes is parsed (a blank body is malformed, not oversized); 16385 is refused.
    let at_cap = vec![b' '; MAX_WIRE_BODY];
    let over = vec![b' '; MAX_WIRE_BODY + 1];
    assert_eq!(MAX_WIRE_BODY, 16384);
    assert!(matches!(
        call(&e, Some(ROUTER), CHALLENGE_PATH, &at_cap).0.unwrap(),
        Handled::Challenge(ChallengeReply::Refused { code: RenewalRefusal::Invalid })
    ));
    assert_eq!(
        call(&e, Some(ROUTER), RENEW_PATH, &at_cap).0.unwrap(),
        Handled::Renew(Outcome::Refused(RenewalRefusal::Invalid))
    );
    for path in [CHALLENGE_PATH, RENEW_PATH] {
        assert_eq!(
            call(&e, Some(ROUTER), path, &over).0.unwrap(),
            Handled::Rejected { status: "413 Payload Too Large", reason: "body" }
        );
    }
    // A real request padded to exactly 16384 bytes is served, not merely parsed.
    let mut body = serde_json::to_vec(&wire(&e)).unwrap();
    assert!(body.len() <= MAX_WIRE_BODY);
    body.resize(MAX_WIRE_BODY, b' ');
    assert!(matches!(
        call(&e, Some(ROUTER), CHALLENGE_PATH, &body).0.unwrap(),
        Handled::Challenge(ChallengeReply::Minted { .. })
    ));
}
