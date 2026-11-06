// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Isolated exact-error rows: every operand of the relay validation chain, one change each.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::type_complexity
)]
use super::*;

fn total(r: &RenewAdmitRequest) -> usize {
    r.operation.len()
        + r.body.len()
        + r.attestation.len()
        + r.home_signature.len()
        + r.proof.len()
        + r.requester_signature.len()
        + r.grant.len()
}

#[test]
fn every_validation_operand_is_refused_in_isolation_and_nothing_is_consumed() {
    let e = Env::new("rows");
    let t = e.target();
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    let request = RenewalRequest::new(&t, ISSUER, [0xb2; 32]).unwrap();
    let now = e.now;
    let mut rows: Vec<(String, RenewAdmitRequest, RenewalRefusal)> = Vec::new();
    let mut add = |name: &str, r: RenewAdmitRequest, want: RenewalRefusal| {
        rows.push((name.into(), r, want));
    };

    // Whole-request cap, inclusive: exactly 16 KiB reaches parsing, one more byte is Invalid.
    let mut at_cap = good.clone();
    at_cap.operation.resize(at_cap.operation.len() + (16 * 1024 - total(&good)), 0);
    assert_eq!(total(&at_cap), 16 * 1024);
    add("cap", at_cap.clone(), RenewalRefusal::TargetInvalid);
    at_cap.operation.push(0);
    add("cap+1", at_cap, RenewalRefusal::Invalid);

    // Capability.
    let mut r = good.clone();
    r.grant.truncate(r.grant.len() - 1);
    add("capability truncated", r, RenewalRefusal::CapabilityInvalid);
    let g = e.g();
    let receipt = AttachmentRegistrationReceipt {
        grant_hash: g.hash().unwrap(),
        grant_epoch: g.epoch,
        source_authority: "node-owner".into(),
        authority_generation: 3,
        expires_at: g.expires_at - 1,
    };
    let signer = e.f.source_signer();
    let sig = signer.sign(&receipt.signing_bytes().unwrap()).to_bytes();
    let forged = receipt.capability(&e.f.grant, &sig, &signer.verifying_key().to_bytes()).unwrap();
    assert_ne!(forged, e.cap);
    let mut r = good.clone();
    r.grant = forged;
    add("capability != registered row", r, RenewalRefusal::CapabilityInvalid);

    // Orenew / Otarget.
    let other_issuer = RenewalRequest::new(&t, "https://other-issuer.example", [0xb2; 32]).unwrap();
    add(
        "orenew audience",
        e.forge(e.g(), &e.cap, &other_issuer, challenge, 1, &Tweak::none()),
        RenewalRefusal::TargetInvalid,
    );
    let mut gen4 = t.clone();
    gen4.authority_generation = 4;
    let req4 = RenewalRequest::new(&gen4, ISSUER, [0xb2; 32]).unwrap();
    add(
        "authority generation",
        e.forge(e.g(), &e.cap, &req4, challenge, 1, &Tweak::none()),
        RenewalRefusal::AuthorityGenerationMismatch,
    );
    let narrow = e.f.register_edited(|g| {
        g.grant_id = [0x78; 32];
        g.rights = 1 | 8;
    });
    let narrow_cap = capability(&e.f, [0x78; 32]);
    let head = operation(narrow.grant(), 2, 0);
    let head_req = RenewalRequest::new(&head, ISSUER, [0xb2; 32]).unwrap();
    add(
        "rights",
        e.forge(narrow.grant(), &narrow_cap, &head_req, [7; 32], 1, &Tweak::none()),
        RenewalRefusal::RightsInsufficient,
    );
    let mut r = good.clone();
    r.attestation = vec![1, 2, 3];
    add("w decode", r, RenewalRefusal::Invalid);

    // Home binding: one operand at a time.
    let mut r = good.clone();
    r.peer_node = "node-c".into();
    add("peer", r, RenewalRefusal::HomeMismatch);
    let mut r = good.clone();
    r.home_verdict.home_node = "node-x".into();
    add("verdict home", r, RenewalRefusal::HomeMismatch);
    let mut r = e.forge(
        e.g(),
        &e.cap,
        &request,
        challenge,
        1,
        &Tweak {
            w: &|w| {
                w.requester.home_node_id = "node-x".into();
                w.home_issuer = "node-x".into();
            },
            ..Tweak::none()
        },
    );
    r.home_verdict.home_node = "node-x".into();
    add("grantee home", r, RenewalRefusal::HomeMismatch);
    let mut r = e.forge(
        e.g(),
        &e.cap,
        &request,
        challenge,
        1,
        &Tweak { w: &|w| w.requester.account_anchor = "other".into(), ..Tweak::none() },
    );
    r.home_verdict.account_anchor = e.g().grantee.account_anchor.clone();
    add("anchor", r, RenewalRefusal::HomeMismatch);
    for (name, at) in [("verdict stale", now - 61), ("verdict future", now + 6)] {
        let mut r = good.clone();
        r.home_verdict.checked_at = at;
        add(name, r, RenewalRefusal::HomeTrustUnavailable);
    }
    let mut r = good.clone();
    r.home_verdict.home_node_key =
        (0..=255_u8).map(|b| [b; 32]).find(|k| VerifyingKey::from_bytes(k).is_err()).unwrap();
    add("verdict key", r, RenewalRefusal::HomeTrustUnavailable);

    // W signature.
    let mut r = good.clone();
    r.home_signature[0] ^= 1;
    add("w signature bit", r, RenewalRefusal::HomeMismatch);
    let other = SigningKey::from_bytes(&[0x99; 32]);
    add(
        "w signer",
        e.forge(e.g(), &e.cap, &request, challenge, 1, &Tweak { home: other, ..Tweak::none() }),
        RenewalRefusal::HomeMismatch,
    );
    let mut r = good.clone();
    r.home_signature.pop();
    add("w signature length", r, RenewalRefusal::Invalid);

    // W binding, re-signed so only the named field is wrong.
    type WEdit = fn(&mut ForwardAttestation);
    let w_rows: [(&str, WEdit, RenewalRefusal); 9] = [
        ("w grant_hash", |w| w.grant_hash[0] ^= 1, RenewalRefusal::ChallengeMismatch),
        ("w grant_id", |w| w.grant_id[0] ^= 1, RenewalRefusal::ChallengeMismatch),
        ("w grant_epoch", |w| w.grant_epoch += 1, RenewalRefusal::ChallengeMismatch),
        (
            "w source_issuer",
            |w| w.source_issuer = "https://x.example".into(),
            RenewalRefusal::ChallengeMismatch,
        ),
        ("w operation_hash", |w| w.operation_hash[0] ^= 1, RenewalRefusal::ChallengeMismatch),
        (
            "w requester device",
            |w| w.requester.device_id = "other".into(),
            RenewalRefusal::ChallengeMismatch,
        ),
        ("w future", |w| w.issued_at += 6, RenewalRefusal::Expired),
        (
            "w expired",
            |w| (w.issued_at, w.expires_at) = (w.issued_at - 35, w.issued_at - 5),
            RenewalRefusal::Expired,
        ),
        ("w lifetime", |w| w.expires_at = w.issued_at, RenewalRefusal::Invalid),
    ];
    // The last row cannot be encoded by the canonical writer: it is covered by a raw tamper.
    for (name, edit, want) in &w_rows[..8] {
        let tweak = Tweak { w: edit, ..Tweak::none() };
        add(name, e.forge(e.g(), &e.cap, &request, challenge, 1, &tweak), *want);
    }
    let mut r = good.clone();
    let len = r.attestation.len();
    r.attestation[len - 16..len - 8].copy_from_slice(&now.to_be_bytes());
    r.attestation[len - 8..].copy_from_slice(&now.to_be_bytes());
    add("w lifetime", r, RenewalRefusal::Invalid);

    // Prenew binding and signature.
    type PEdit = fn(&mut RequesterPop);
    let p_rows: [(&str, PEdit, RenewalRefusal); 5] = [
        ("p operation_hash", |p| p.operation_hash[0] ^= 1, RenewalRefusal::Invalid),
        ("p requester_digest", |p| p.requester_digest[0] ^= 1, RenewalRefusal::Invalid),
        ("p forward_digest", |p| p.forward_digest[0] ^= 1, RenewalRefusal::Invalid),
        (
            "p before W",
            |p| (p.issued_at, p.expires_at) = (p.issued_at - 1, p.expires_at - 1),
            RenewalRefusal::Expired,
        ),
        ("p future", |p| p.issued_at += 6, RenewalRefusal::Expired),
    ];
    for (name, edit, want) in p_rows {
        let tweak = Tweak { p: &edit, ..Tweak::none() };
        add(name, e.forge(e.g(), &e.cap, &request, challenge, 1, &tweak), want);
    }
    let tweak = Tweak { w: &|w| w.expires_at = w.issued_at + 20, ..Tweak::none() };
    add(
        "p after W",
        e.forge(e.g(), &e.cap, &request, challenge, 1, &tweak),
        RenewalRefusal::Expired,
    );
    add(
        "p signer",
        e.forge(
            e.g(),
            &e.cap,
            &request,
            challenge,
            1,
            &Tweak { grantee: SigningKey::from_bytes(&[0x98; 32]), ..Tweak::none() },
        ),
        RenewalRefusal::Invalid,
    );
    let mut r = good.clone();
    // Same signer, wrong preimage: the raw proof without the domain prefix.
    r.requester_signature = grantee_key().sign(&r.proof).to_bytes().to_vec();
    add("p preimage", r, RenewalRefusal::Invalid);
    let mut r = good.clone();
    r.requester_signature.pop();
    add("p signature length", r, RenewalRefusal::Invalid);

    for (name, r, want) in &rows {
        assert_eq!(e.refused(r), *want, "row {name}");
    }

    // No refusal above consumed the challenge or nonce: the genuine request issues.
    let token = e.run(&good).unwrap();
    let key = e.f.source_signer().verifying_key().to_bytes();
    let verified = AttachmentToken::decode_signed(&token, &key).unwrap();
    assert_eq!(verified.token().target_hash, t.hash().unwrap());
    assert_eq!(verified.token().requester_digest, requester_digest(&g.grantee).unwrap());
    assert_eq!((verified.token().issued_at, verified.token().expires_at), (now, now + 300));
}

#[test]
fn inclusive_time_bounds_are_accepted() {
    let e = Env::new("positives");
    let t = e.target();
    let request = RenewalRequest::new(&t, ISSUER, [0xb2; 32]).unwrap();
    let now = e.now;
    // Each positive has its own challenge and nonce (four per requester is the cap).
    let positives: [(&str, Box<dyn Fn(&mut RenewAdmitRequest)>, Tweak<'_>); 4] = [
        (
            "w +5 s",
            Box::new(|_| {}),
            Tweak { w: &|w| w.issued_at += 5, p: &|p| p.issued_at += 5, ..Tweak::none() },
        ),
        ("p +5 s", Box::new(|_| {}), Tweak { p: &|p| p.issued_at += 5, ..Tweak::none() }),
        ("verdict 60 s", Box::new(|r| r.home_verdict.checked_at = now - 60), Tweak::none()),
        ("verdict +5 s", Box::new(|r| r.home_verdict.checked_at = now + 5), Tweak::none()),
    ];
    for (n, (name, edit, tweak)) in (10_u8..).zip(positives) {
        let c = e.mint(e.g(), &e.cap, &t);
        let mut r = e.forge(e.g(), &e.cap, &request, c, n, &tweak);
        edit(&mut r);
        assert!(e.run(&r).is_ok(), "positive {name}");
    }
}
