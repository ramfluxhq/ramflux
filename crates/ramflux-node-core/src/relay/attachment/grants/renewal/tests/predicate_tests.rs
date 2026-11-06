// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! One isolated, exact-error row per predicate operand of the renewal admission.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use std::cell::Cell;

fn tamper(e: &Env, byte: u8, f: impl FnOnce(&mut ChallengeRow)) {
    let tx = e.f.registry.ledger.db.begin_write().unwrap();
    {
        let mut t = tx.open_table(CHALLENGES).unwrap();
        let mut row: ChallengeRow = {
            let v = t.get([byte; 32].as_slice()).unwrap().unwrap();
            decode(v.value()).unwrap()
        };
        f(&mut row);
        t.insert([byte; 32].as_slice(), encode(&row).unwrap().as_slice()).unwrap();
    }
    tx.commit().unwrap();
}
fn consumed(e: &Env, byte: u8) -> bool {
    let tx = e.f.registry.ledger.db.begin_write().unwrap();
    let t = tx.open_table(CHALLENGES).unwrap();
    let v = t.get([byte; 32].as_slice()).unwrap().unwrap();
    decode::<ChallengeRow>(v.value()).unwrap().consumed
}
fn nonce_used(e: &Env, n: u8) -> bool {
    let tx = e.f.registry.ledger.db.begin_write().unwrap();
    replay::nonce_consumed(&tx, "node-a", &e.g().grantee, &[n; 32]).unwrap()
}
/// Admission with every time input explicit. Returns the result and clock used inside.
#[derive(Clone, Copy)]
struct Times {
    w_issued: u64,
    w_expires: u64,
    p_issued: u64,
    p_expires: u64,
    verdict: u64,
    /// Clock read before the transaction, and inside it.
    before: u64,
    inside: u64,
}
fn try_admit(
    e: &Env,
    ch: u8,
    n: u8,
    t: &AttachmentOperation,
    x: Times,
) -> Result<(), RenewalRefusal> {
    let proof =
        AttachmentReplayProof { nonce: [n; 32], issued_at: x.p_issued, expires_at: x.p_expires };
    let mut adm = e.admission(ch, t, &proof, x.w_expires);
    adm.w_issued_at = x.w_issued;
    adm.verdict_checked_at = x.verdict;
    let calls = Cell::new(0);
    let clock = || {
        calls.set(calls.get() + 1);
        if calls.get() == 1 { x.before } else { x.inside }
    };
    e.f.registry.admit_renewal_after_authentication(&adm, &clock).map(drop)
}
fn base(now: u64) -> Times {
    Times {
        w_issued: now,
        w_expires: now + 30,
        p_issued: now,
        p_expires: now + 30,
        verdict: now,
        before: now,
        inside: now,
    }
}

#[test]
fn admission_revalidates_every_freshness_input_at_the_in_transaction_clock() {
    let e = Env::new("fresh");
    let (t, now) = (e.target(16), e.now);
    for c in 1..=12 {
        e.mint(c, &t, now).unwrap();
    }
    let rows: [(u8, Times, RenewalRefusal); 5] = [
        // Validated at expiry-1, resumed at expiry+1: the challenge has expired.
        (
            1,
            Times { before: now + 29, inside: now + 31, ..base(now) },
            RenewalRefusal::ChallengeExpired,
        ),
        // W alone expires (challenge, proof and verdict stay fresh).
        (
            2,
            Times { w_expires: now + 10, before: now + 9, inside: now + 11, ..base(now) },
            RenewalRefusal::Expired,
        ),
        // Prenew alone expires.
        (
            3,
            Times { p_expires: now + 10, before: now + 9, inside: now + 11, ..base(now) },
            RenewalRefusal::Expired,
        ),
        // Verdict alone ages past 60 s.
        (
            4,
            Times { verdict: now - 59, before: now, inside: now + 2, ..base(now) },
            RenewalRefusal::HomeTrustUnavailable,
        ),
        // Future verdict beyond the +5 s tolerance.
        (5, Times { verdict: now + 6, ..base(now) }, RenewalRefusal::HomeTrustUnavailable),
    ];
    for (n, (ch, x, want)) in (1_u8..).zip(rows) {
        assert_eq!(refusal(try_admit(&e, ch, n, &t, x).map(|()| 0)), want, "row {ch}");
        assert!(!consumed(&e, ch) && !nonce_used(&e, n), "row {ch} consumed state");
    }
    // Future W and Prenew issue times beyond +5 s.
    let x = Times { w_issued: now + 6, ..base(now) };
    assert_eq!(refusal(try_admit(&e, 6, 6, &t, x).map(|()| 0)), RenewalRefusal::Expired);
    let x = Times { p_issued: now + 6, p_expires: now + 30, ..base(now) };
    assert_eq!(refusal(try_admit(&e, 6, 6, &t, x).map(|()| 0)), RenewalRefusal::Expired);
    assert!(!consumed(&e, 6) && !nonce_used(&e, 6));
    // Inclusive positives: +5 s future issue times, a 60 s old verdict, +5 s future verdict.
    assert_eq!(try_admit(&e, 7, 7, &t, Times { w_issued: now + 5, ..base(now) }), Ok(()));
    assert_eq!(try_admit(&e, 8, 8, &t, Times { p_issued: now + 5, ..base(now) }), Ok(()));
    assert_eq!(try_admit(&e, 9, 9, &t, Times { verdict: now - 60, ..base(now) }), Ok(()));
    assert_eq!(try_admit(&e, 10, 10, &t, Times { verdict: now + 5, ..base(now) }), Ok(()));
    // Last second of each lifetime still admits.
    let x = Times { before: now + 29, inside: now + 29, ..base(now) };
    assert_eq!(try_admit(&e, 11, 11, &t, x), Ok(()));
}

#[test]
fn consumed_request_is_replay_before_retirement_and_lease_saturation() {
    let e = Env::new("precedence");
    let (t, now) = (e.target(16), e.now);
    e.mint(1, &t, now).unwrap();
    drop(e.admit(1, &t, 1, now).unwrap());
    // Saturated lease table: a fresh nonce is Busy, the consumed one stays Replay.
    let held: Vec<_> = (0..32)
        .map(|_| e.f.registry.lease_after_operation_admission(&e.f.grant, 1, now).unwrap())
        .collect();
    e.mint(2, &t, now).unwrap();
    assert_eq!(refusal(e.admit(2, &t, 2, now)), RenewalRefusal::Busy);
    assert_eq!(refusal(e.admit(1, &t, 1, now)), RenewalRefusal::Replay);
    drop(held);
    // The refused fresh nonce was not consumed.
    drop(e.admit(2, &t, 2, now).unwrap());
    // After retirement the consumed request is still Replay; a fresh one is GrantNotActive.
    assert_eq!(e.f.retire(&e.f.request()).unwrap(), RetirementOutcome::Retired);
    assert_eq!(refusal(e.admit(1, &t, 1, now)), RenewalRefusal::Replay);
    assert_eq!(refusal(e.admit(2, &t, 3, now)), RenewalRefusal::GrantNotActive);
}

#[test]
fn challenge_row_bindings_are_each_checked_in_isolation() {
    type Edit = fn(&mut ChallengeRow);
    let e = Env::new("rows");
    let (t, now) = (e.target(16), e.now);
    let rows: [(&str, Edit, RenewalRefusal); 9] = [
        ("grant_id", |r| r.grant_id[0] ^= 1, RenewalRefusal::ChallengeMismatch),
        ("grant_epoch", |r| r.grant_epoch += 1, RenewalRefusal::ChallengeMismatch),
        ("grant_hash", |r| r.grant_hash[0] ^= 1, RenewalRefusal::ChallengeMismatch),
        ("target_hash", |r| r.target_hash[0] ^= 1, RenewalRefusal::ChallengeMismatch),
        ("requester", |r| r.requester[0] ^= 1, RenewalRefusal::ChallengeMismatch),
        ("home_node", |r| r.home_node = "node-x".into(), RenewalRefusal::ChallengeMismatch),
        ("home_epoch", |r| r.home_epoch += 1, RenewalRefusal::ChallengeMismatch),
        ("expires_at", |r| r.expires_at -= 1, RenewalRefusal::ChallengeMismatch),
        ("generation", |r| r.authority_generation = 3, RenewalRefusal::AuthorityGenerationMismatch),
    ];
    for (i, (name, edit, want)) in (1_u8..).zip(rows) {
        e.mint(i, &t, now).unwrap();
        tamper(&e, i, edit);
        assert_eq!(refusal(e.admit(i, &t, i, now)), want, "{name}");
        assert!(!consumed(&e, i) && !nonce_used(&e, i), "{name} consumed state");
    }
    // Control: an untouched row admits, and the same tamper-free path is positive.
    e.mint(20, &t, now).unwrap();
    drop(e.admit(20, &t, 20, now).unwrap());
}

fn edited(
    e: &Env,
    id: u8,
    edit: impl FnOnce(&mut ScopedAttachmentGrant),
) -> (VerifiedScopedGrant, Vec<u8>) {
    let g = e.f.register_edited(|g| {
        g.grant_id = [id; 32];
        edit(g);
    });
    let cap = capability(&e.f.registry, [id; 32]);
    (g, cap)
}
fn next_id() -> u8 {
    static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(100);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
fn mint_for(
    e: &Env,
    cap: &[u8],
    op: &AttachmentOperation,
    at: u64,
) -> Result<RenewalChallenge, RenewalRefusal> {
    let bytes = op.canonical_bytes().unwrap();
    let verdict = HomeVerdict { checked_at: at, ..e.verdict(at) };
    e.f.registry.mint_with(
        &e.policy,
        &e.mint_req(&bytes, &verdict, cap),
        [next_id(); 32],
        at,
        wide(),
    )
}

#[test]
fn target_operands_rights_and_time_are_each_checked_in_isolation() {
    let e = Env::new("target");
    let (t, now) = (e.target(16), e.now);
    let g = e.g().clone();
    let hex_of = |b: &[u8; 32]| hex(b);
    let mut rows: Vec<(&str, AttachmentOperation, RenewalRefusal)> = Vec::new();
    let mut o = t.clone();
    o.audience = "https://other.example".into();
    rows.push(("audience", o, RenewalRefusal::TargetInvalid));
    let mut o = t.clone();
    o.object_id[0] ^= 1;
    o.path = o.path.replace(&hex_of(&g.object_id), &hex_of(&o.object_id));
    rows.push(("object", o, RenewalRefusal::TargetInvalid));
    let mut o = t.clone();
    o.manifest_hash[0] ^= 1;
    o.path = o.path.replace(&hex_of(&g.manifest_hash), &hex_of(&o.manifest_hash));
    rows.push(("manifest", o, RenewalRefusal::TargetInvalid));
    let mut o = t.clone();
    o.grant_id[0] ^= 1;
    rows.push(("grant", o, RenewalRefusal::TargetInvalid));
    let mut o = t.clone();
    o.grant_epoch += 1;
    rows.push(("epoch", o, RenewalRefusal::TargetInvalid));
    let mut o = t.clone();
    o.authority_generation = 3;
    rows.push(("generation", o, RenewalRefusal::AuthorityGenerationMismatch));
    let mut o = t.clone();
    (o.op, o.method, o.path, o.length) = (8, "POST".into(), "/s9/attachments/renew".into(), 0);
    rows.push(("renew-as-target", o, RenewalRefusal::TargetInvalid));
    let mut o = t.clone();
    o.payload_generation = 2;
    rows.push(("payload", o, RenewalRefusal::PayloadGenerationMismatch));
    for (name, op, want) in rows {
        assert_eq!(refusal(mint_for(&e, &e.cap, &op, now)), want, "{name}");
    }
    // Rights: both Renew and the target right are required, each missing alone refused.
    let (ren_only, cap_a) = edited(&e, 0x61, |g| g.rights = 8);
    let get = operation(ren_only.grant(), 1, 16);
    assert_eq!(refusal(mint_for(&e, &cap_a, &get, now)), RenewalRefusal::RightsInsufficient);
    let (get_only, cap_b) = edited(&e, 0x62, |g| g.rights = 1);
    let get = operation(get_only.grant(), 1, 16);
    assert_eq!(refusal(mint_for(&e, &cap_b, &get, now)), RenewalRefusal::RightsInsufficient);
    let (both, cap_c) = edited(&e, 0x63, |g| g.rights = 9);
    let get = operation(both.grant(), 1, 16);
    assert!(mint_for(&e, &cap_c, &get, now).is_ok());
    // Time: a grant issued exactly 5 s ahead is accepted; the last second before expiry too.
    let (ahead, cap_d) = edited(&e, 0x64, |g| g.issued_at = now + 5);
    assert!(mint_for(&e, &cap_d, &operation(ahead.grant(), 1, 16), now).is_ok());
    let (short, cap_e) = edited(&e, 0x65, |g| g.expires_at = now + 100);
    let op = operation(short.grant(), 1, 16);
    let tx_last = now + 99;
    assert!(mint_for(&e, &cap_e, &op, tx_last).is_ok());
    assert_eq!(refusal(mint_for(&e, &cap_e, &op, now + 100)), RenewalRefusal::CapabilityInvalid);
    // Registered row removed: the capability no longer matches any row.
    let tx = e.f.registry.ledger.db.begin_write().unwrap();
    tx.open_table(GRANTS).unwrap().remove(g.grant_id.as_slice()).unwrap();
    tx.commit().unwrap();
    assert_eq!(refusal(mint_for(&e, &e.cap, &t, now)), RenewalRefusal::CapabilityInvalid);
}

#[test]
fn mint_home_and_verdict_operands_are_each_checked_in_isolation() {
    let e = Env::new("home");
    let (t, now) = (e.target(16), e.now);
    let op = t.canonical_bytes().unwrap();
    let go = |req: &ChallengeMint<'_>| e.f.registry.mint_with(&e.policy, req, [1; 32], now, wide());
    let v = e.verdict(now);
    // Only the grantee home differs from three agreeing values.
    let mut v1 = v.clone();
    v1.home_node = "node-x".into();
    let mut req = e.mint_req(&op, &v1, &e.cap);
    (req.home_node, req.peer_node) = ("node-x", "node-x");
    assert_eq!(refusal(go(&req)), RenewalRefusal::HomeMismatch);
    // Only the requester device epoch / key differ: the whole qualified identity is compared.
    let mut stranger = e.g().grantee.clone();
    stranger.device_epoch += 1;
    let mut req = e.mint_req(&op, &v, &e.cap);
    req.requester = &stranger;
    assert_eq!(refusal(go(&req)), RenewalRefusal::ChallengeMismatch);
    let mut stranger = e.g().grantee.clone();
    stranger.signing_public_key[0] ^= 1;
    let mut req = e.mint_req(&op, &v, &e.cap);
    req.requester = &stranger;
    assert_eq!(refusal(go(&req)), RenewalRefusal::ChallengeMismatch);
    // Verdict freshness: +5 s future is accepted, +6 s is not.
    let mut ahead = e.verdict(now);
    ahead.checked_at = now + 6;
    assert_eq!(refusal(go(&e.mint_req(&op, &ahead, &e.cap))), RenewalRefusal::HomeTrustUnavailable);
    ahead.checked_at = now + 5;
    assert!(go(&e.mint_req(&op, &ahead, &e.cap)).is_ok());
}

#[test]
fn every_refusal_has_a_stable_unique_mapping() {
    let mut codes = std::collections::BTreeSet::new();
    for (i, r) in RenewalRefusal::ALL.into_iter().enumerate() {
        assert_eq!(r.ordinal(), i);
        assert!(codes.insert(r.wire_code()), "duplicate {}", r.wire_code());
        assert!((400..=599).contains(&r.http_status()));
        // Status class agrees with the retry class: only 429/503 are retryable.
        assert_eq!(r.retryable(), matches!(r.http_status(), 429 | 503), "{}", r.wire_code());
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<RenewalRefusal>(&json).unwrap(), r);
    }
    assert_eq!(codes.len(), RenewalRefusal::COUNT);
    assert!(!RenewalRefusal::Storage.retryable());
    assert!(RenewalRefusal::Busy.retryable());
}
