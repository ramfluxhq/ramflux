// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::large_attachment::{ScopedAttachmentGrant, VerifiedScopedGrant};
use serde_json::json;
use std::cell::RefCell;

const SOURCE: &str = "node-owner";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn grant(case: usize) -> VerifiedScopedGrant {
    let j: Value = serde_json::from_str(include_str!(
        "../../../../crates/ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    let c = &j["cases"][case];
    let g = unhex(c["grant_unsigned_hex"].as_str().unwrap());
    let mut signed = b"RFC1".to_vec();
    signed.extend(u32::try_from(g.len()).unwrap().to_be_bytes());
    signed.extend(&g);
    signed.extend(64_u32.to_be_bytes());
    signed.extend(unhex(c["grant_signature_hex"].as_str().unwrap()));
    ScopedAttachmentGrant::decode_signed(&signed).unwrap()
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn receipt(
    g: &VerifiedScopedGrant,
    generation: u64,
    expires_at: u64,
) -> AttachmentRegistrationReceipt {
    AttachmentRegistrationReceipt {
        grant_hash: g.grant().hash().unwrap(),
        grant_epoch: g.grant().epoch,
        source_authority: SOURCE.into(),
        authority_generation: generation,
        expires_at,
    }
}
fn capability(
    g: &VerifiedScopedGrant,
    generation: u64,
    expires_at: u64,
    signer: &SigningKey,
) -> Vec<u8> {
    let r = receipt(g, generation, expires_at);
    let sig = signer.sign(&r.signing_bytes().unwrap()).to_bytes();
    r.capability(g, &sig, &signer.verifying_key().to_bytes()).unwrap()
}
/// Length of the `RFC1 || LP(G) || LP(sig)` prefix.
fn prefix_len(cap: &[u8]) -> usize {
    8 + usize::try_from(u32::from_be_bytes(cap[4..8].try_into().unwrap())).unwrap() + 4 + 64
}

struct Fake {
    pin: Result<AuthorityPin, RenewalRefusal>,
    now: u64,
    calls: RefCell<Vec<String>>,
    forwarded: RefCell<Vec<Value>>,
    deadlines: RefCell<Vec<Instant>>,
}
impl Fake {
    fn new(pin: Result<AuthorityPin, RenewalRefusal>, now: u64) -> Self {
        Self {
            pin,
            now,
            calls: RefCell::default(),
            forwarded: RefCell::default(),
            deadlines: RefCell::default(),
        }
    }
}
impl HomeBackend for Fake {
    fn now(&self) -> u64 {
        self.now
    }
    fn pin(&self, node: &str, deadline: Instant) -> Result<AuthorityPin, RenewalRefusal> {
        self.calls.borrow_mut().push(format!("pin:{node}"));
        self.deadlines.borrow_mut().push(deadline);
        self.pin
    }
    fn federation(
        &self,
        node: &str,
        kind: Kind,
        request: Value,
        deadline: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal> {
        self.calls.borrow_mut().push(format!("federation:{node}:{kind:?}"));
        self.deadlines.borrow_mut().push(deadline);
        self.forwarded.borrow_mut().push(request);
        Ok(b"{\"routed\":true}".to_vec())
    }
}
fn far() -> Instant {
    Instant::now() + ROUTE_BUDGET
}
fn pin_of(signer: &SigningKey, generation: u64) -> AuthorityPin {
    AuthorityPin { generation, key: signer.verifying_key().to_bytes() }
}
fn envelope(kind: Kind, cap: &[u8]) -> (&'static str, Vec<u8>) {
    match kind {
        Kind::Challenge => (
            CHALLENGE_PATH,
            serde_json::to_vec(
                &json!({"capability": cap, "target_operation": [1], "home_node": "node-b"}),
            )
            .unwrap(),
        ),
        Kind::Forward => {
            (FORWARD_PATH, serde_json::to_vec(&json!({"grant": cap, "operation": [1]})).unwrap())
        }
    }
}
fn code(reply: &HomeReply) -> Value {
    assert_eq!(reply.status, "200 OK");
    serde_json::from_slice(&reply.body).unwrap()
}
fn refusal(name: &str) -> Value {
    json!({"Refused": {"code": name}})
}
const KINDS: [Kind; 2] = [Kind::Challenge, Kind::Forward];

#[test]
fn large_home_router_routes_only_by_verified_receipt() {
    let g = grant(0);
    let signer = key(0x60);
    let issued = g.grant().issued_at;
    let now = issued + 1;
    assert!(g.grant().expires_at > issued + 20);
    let good = capability(&g, 3, g.grant().expires_at, &signer);
    let other = grant(1);
    let other_cap = capability(&other, 3, other.grant().expires_at, &signer);
    let substituted = [&good[..prefix_len(&good)], &other_cap[prefix_len(&other_cap)..]].concat();
    let short_lived = capability(&g, 3, issued + 10, &signer);
    let foreign_signer = capability(&g, 3, g.grant().expires_at, &key(0x61));

    for kind in KINDS {
        // Positive: the receipt names the source, the pin verifies it, only that peer is called.
        let backend = Fake::new(Ok(pin_of(&signer, 3)), now);
        let (path, body) = envelope(kind, &good);
        let reply = route(GATEWAY_SERVICE_ID, path, &body, Some(&backend), far());
        assert_eq!(reply.body, b"{\"routed\":true}".to_vec(), "{kind:?}");
        assert_eq!(
            *backend.calls.borrow(),
            vec![format!("pin:{SOURCE}"), format!("federation:{SOURCE}:{kind:?}")]
        );
        // The request reaches the federation byte-for-byte as parsed from the envelope.
        assert_eq!(backend.forwarded.borrow()[0], serde_json::from_slice::<Value>(&body).unwrap());

        // Each negative is one defect from the valid state, with the exact refusal, and
        // never a federation call (the trait has no gateway-peer, mint or store method).
        let grant_only = g.signed_bytes().unwrap();
        let rows: Vec<(&str, Vec<u8>, Fake, &str, usize)> = vec![
            (
                "receipt missing",
                grant_only,
                Fake::new(Ok(pin_of(&signer, 3)), now),
                "capability_invalid",
                0,
            ),
            (
                "garbage capability",
                vec![1, 2, 3],
                Fake::new(Ok(pin_of(&signer, 3)), now),
                "capability_invalid",
                0,
            ),
            (
                "receipt for another Hgrant",
                substituted.clone(),
                Fake::new(Ok(pin_of(&signer, 3)), now),
                "capability_invalid",
                1,
            ),
            (
                "expired receipt",
                short_lived.clone(),
                Fake::new(Ok(pin_of(&signer, 3)), issued + 10),
                "capability_invalid",
                1,
            ),
            (
                "receipt signed by another key",
                foreign_signer.clone(),
                Fake::new(Ok(pin_of(&signer, 3)), now),
                "capability_invalid",
                1,
            ),
            (
                "wrong source",
                good.clone(),
                Fake::new(Err(RenewalRefusal::SourceUnknown), now),
                "source_unknown",
                1,
            ),
            (
                "generation differs from the pin",
                good.clone(),
                Fake::new(Ok(pin_of(&signer, 4)), now),
                "authority_generation_mismatch",
                1,
            ),
            (
                "pin withdrawn",
                good.clone(),
                Fake::new(Err(RenewalRefusal::CapabilityUnavailable), now),
                "capability_unavailable",
                1,
            ),
        ];
        for (name, cap, backend, expected, pins) in rows {
            let (path, body) = envelope(kind, &cap);
            let reply = route(GATEWAY_SERVICE_ID, path, &body, Some(&backend), far());
            assert_eq!(code(&reply), refusal(expected), "{kind:?} {name}");
            let calls = backend.calls.borrow();
            assert_eq!(calls.len(), pins, "{kind:?} {name}: {calls:?}");
            assert!(calls.iter().all(|c| c.starts_with("pin:")), "{kind:?} {name}");
            assert!(backend.forwarded.borrow().is_empty(), "{kind:?} {name}");
        }
    }
}

#[test]
fn expiry_is_decided_only_by_the_receipt_at_its_inclusive_boundary() {
    let g = grant(0);
    let signer = key(0x60);
    let cap = capability(&g, 3, g.grant().issued_at + 10, &signer);
    for (now, routed) in [(g.grant().issued_at + 9, true), (g.grant().issued_at + 10, false)] {
        let backend = Fake::new(Ok(pin_of(&signer, 3)), now);
        let (path, body) = envelope(Kind::Forward, &cap);
        let reply = route(GATEWAY_SERVICE_ID, path, &body, Some(&backend), far());
        assert_eq!(backend.forwarded.borrow().len(), usize::from(routed), "{now}");
        if !routed {
            assert_eq!(code(&reply), refusal("capability_invalid"));
        }
    }
}

#[test]
fn envelope_fields_peer_path_size_and_budget_are_refused_in_isolation() {
    let g = grant(0);
    let signer = key(0x60);
    let good = capability(&g, 3, g.grant().expires_at, &signer);
    let now = g.grant().issued_at + 1;
    // Only the gateway may call; every other service is refused before the body.
    for peer in ["ramflux-federation", "ramflux-relay", "ramflux-notify", "ramflux-router", ""] {
        let backend = Fake::new(Ok(pin_of(&signer, 3)), now);
        let (path, body) = envelope(Kind::Challenge, &good);
        let reply = route(peer, path, &body, Some(&backend), far());
        assert_eq!(
            reply,
            text("403 Forbidden", "attachment renewal requires gateway identity"),
            "{peer}"
        );
        assert!(backend.calls.borrow().is_empty());
    }
    let backend = Fake::new(Ok(pin_of(&signer, 3)), now);
    let (_, body) = envelope(Kind::Challenge, &good);
    assert_eq!(
        route(GATEWAY_SERVICE_ID, "/s9/attachments/renew/other", &body, Some(&backend), far())
            .status,
        "404 Not Found"
    );
    // Dormant without a backend; the identity check still comes first.
    assert_eq!(
        route(GATEWAY_SERVICE_ID, CHALLENGE_PATH, &body, None, far()).status,
        "503 Service Unavailable"
    );
    assert_eq!(route("ramflux-relay", CHALLENGE_PATH, &body, None, far()).status, "403 Forbidden");
    // Envelope: not JSON, field absent, field not bytes.
    for (name, bad, expected) in [
        ("not json", b"nope".to_vec(), "invalid"),
        ("capability absent", br#"{"target_operation":[1]}"#.to_vec(), "capability_invalid"),
        ("capability not bytes", br#"{"capability":"abc"}"#.to_vec(), "capability_invalid"),
    ] {
        let reply = route(GATEWAY_SERVICE_ID, CHALLENGE_PATH, &bad, Some(&backend), far());
        assert_eq!(code(&reply), refusal(expected), "{name}");
    }
    // A forward envelope carries the capability in `grant`, a challenge in `capability`.
    let cross = serde_json::to_vec(&json!({"grant": good})).unwrap();
    assert_eq!(
        code(&route(GATEWAY_SERVICE_ID, CHALLENGE_PATH, &cross, Some(&backend), far())),
        refusal("capability_invalid")
    );
    assert!(backend.calls.borrow().is_empty());
    // Exact 16 KiB cap: 16384 is parsed, 16385 is refused.
    let mut at_cap = body.clone();
    at_cap.resize(MAX_BODY, b' ');
    assert_eq!(
        route(GATEWAY_SERVICE_ID, CHALLENGE_PATH, &at_cap, Some(&backend), far()).status,
        "200 OK"
    );
    assert_eq!(backend.forwarded.borrow().len(), 1);
    at_cap.push(b' ');
    assert_eq!(
        route(GATEWAY_SERVICE_ID, CHALLENGE_PATH, &at_cap, Some(&backend), far()).status,
        "413 Payload Too Large"
    );
    assert_eq!(backend.forwarded.borrow().len(), 1);
}

#[test]
fn the_route_budget_reaches_both_hops_and_an_elapsed_budget_is_busy() {
    let g = grant(0);
    let signer = key(0x60);
    let good = capability(&g, 3, g.grant().expires_at, &signer);
    let now = g.grant().issued_at + 1;
    let (path, body) = envelope(Kind::Forward, &good);
    let backend = Fake::new(Ok(pin_of(&signer, 3)), now);
    let deadline = far();
    route(GATEWAY_SERVICE_ID, path, &body, Some(&backend), deadline);
    assert_eq!(*backend.deadlines.borrow(), vec![deadline, deadline]);
    let backend = Fake::new(Ok(pin_of(&signer, 3)), now);
    let past = Instant::now().checked_sub(Duration::from_millis(1)).unwrap();
    let reply = route(GATEWAY_SERVICE_ID, path, &body, Some(&backend), past);
    assert_eq!(code(&reply), refusal("busy"));
    assert!(backend.calls.borrow().is_empty());
    assert_eq!(ROUTE_BUDGET, Duration::from_secs(10));
}
