// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use redb::{ReadableDatabase, ReadableTableMetadata};

fn rows(e: &Env) -> u64 {
    let tx = e.f.registry.ledger.db.begin_read().unwrap();
    tx.open_table(CHALLENGES).unwrap().len().unwrap()
}
fn insert_raw(e: &Env, n: u64, expires_at: u64) {
    let tx = e.f.registry.ledger.db.begin_write().unwrap();
    {
        let mut table = tx.open_table(CHALLENGES).unwrap();
        let mut id = [9_u8; 32];
        id[..8].copy_from_slice(&n.to_be_bytes());
        let row = ChallengeRow {
            grant_id: [1; 32],
            grant_epoch: 1,
            grant_hash: [2; 32],
            target_hash: [3; 32],
            requester: [4; 32],
            home_node: "node-x".into(),
            home_epoch: 1,
            authority_generation: 4,
            expires_at,
            consumed: false,
        };
        table.insert(id.as_slice(), encode(&row).unwrap().as_slice()).unwrap();
    }
    tx.commit().unwrap();
}

#[test]
fn renewal_challenge_mint_refuses_every_substitution_without_inserting() {
    let e = Env::new("mint");
    let (t, now) = (e.target(16), e.now);
    let op = t.canonical_bytes().unwrap();
    let mint =
        |req: &ChallengeMint<'_>| e.f.registry.mint_with(&e.policy, req, [1; 32], now, wide());
    let verdict = e.verdict(now);
    let good = e.mint_req(&op, &verdict, &e.cap);
    // Inclusive freshness boundary: exactly 60 s old is accepted, 61 s is not.
    let edge = e.verdict(now - 60);
    assert!(mint(&e.mint_req(&op, &edge, &e.cap)).is_ok());
    assert_eq!(rows(&e), 1);
    let before = rows(&e);
    let stale = e.verdict(now - 61);
    assert_eq!(
        refusal(mint(&e.mint_req(&op, &stale, &e.cap))),
        RenewalRefusal::HomeTrustUnavailable
    );
    let mut v = e.verdict(now);
    v.home_node_key = (0..=255_u8)
        .map(|b| [b; 32])
        .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
        .unwrap();
    assert_eq!(refusal(mint(&e.mint_req(&op, &v, &e.cap))), RenewalRefusal::HomeTrustUnavailable);
    let mut v = e.verdict(now);
    v.account_anchor = "someone-else".into();
    assert_eq!(refusal(mint(&e.mint_req(&op, &v, &e.cap))), RenewalRefusal::HomeMismatch);
    let mut v = e.verdict(now);
    v.home_node = "node-c".into();
    assert_eq!(refusal(mint(&e.mint_req(&op, &v, &e.cap))), RenewalRefusal::HomeMismatch);
    let mut req = e.mint_req(&op, &verdict, &e.cap);
    req.peer_node = "node-c";
    assert_eq!(refusal(mint(&req)), RenewalRefusal::HomeMismatch);
    let stranger = QualifiedOwner { device_id: "other".into(), ..e.g().grantee.clone() };
    let mut req = e.mint_req(&op, &verdict, &e.cap);
    req.requester = &stranger;
    assert_eq!(refusal(mint(&req)), RenewalRefusal::ChallengeMismatch);
    assert_eq!(
        refusal(mint(&e.mint_req(&op, &verdict, &e.cap[..e.cap.len() - 1]))),
        RenewalRefusal::CapabilityInvalid
    );
    assert_eq!(
        refusal(mint(&e.mint_req(b"garbage", &verdict, &e.cap))),
        RenewalRefusal::TargetInvalid
    );
    let mut other = t.clone();
    other.audience = "https://other-relay.example".into();
    let bytes = other.canonical_bytes().unwrap();
    assert_eq!(refusal(mint(&e.mint_req(&bytes, &verdict, &e.cap))), RenewalRefusal::TargetInvalid);
    let mut other = t.clone();
    other.authority_generation = 3;
    let bytes = other.canonical_bytes().unwrap();
    assert_eq!(
        refusal(mint(&e.mint_req(&bytes, &verdict, &e.cap))),
        RenewalRefusal::AuthorityGenerationMismatch
    );
    let mut other = t.clone();
    other.payload_generation = 2;
    let bytes = other.canonical_bytes().unwrap();
    assert_eq!(
        refusal(mint(&e.mint_req(&bytes, &verdict, &e.cap))),
        RenewalRefusal::PayloadGenerationMismatch
    );
    // Renew alone is not enough: the target's own right is required as well.
    let narrow = e.f.register_edited(|g| {
        g.grant_id = [0x78; 32];
        g.rights = 1 | 8;
    });
    let narrow_cap = capability(&e.f.registry, narrow.grant().grant_id);
    let mut head = operation(narrow.grant(), 2, 0);
    head.operation_id = [0xa1; 32];
    let bytes = head.canonical_bytes().unwrap();
    assert_eq!(
        refusal(mint(&e.mint_req(&bytes, &verdict, &narrow_cap))),
        RenewalRefusal::RightsInsufficient
    );
    assert_eq!(rows(&e), before);
    assert!(
        e.f.registry.mint_with(&e.policy, &good, [2; 32], now, wide()).is_ok()
            && rows(&e) == before + 1
    );
    // A retired grant never mints.
    assert_eq!(e.f.retire(&e.f.request()).unwrap(), RetirementOutcome::Retired);
    assert_eq!(refusal(mint(&e.mint_req(&op, &verdict, &e.cap))), RenewalRefusal::GrantNotActive);
}

#[test]
fn renewal_challenge_caps_gc_and_clock_fail_closed() {
    let e = Env::new("caps");
    let (t, now) = (e.target(16), e.now);
    assert_eq!(
        (Caps::default().global, Caps::default().per_home, Caps::default().per_requester),
        (4096, 64, 4)
    );
    let op = t.canonical_bytes().unwrap();
    let verdict = e.verdict(now);
    let req = e.mint_req(&op, &verdict, &e.cap);
    let go = |c: u8, caps: Caps| e.f.registry.mint_with(&e.policy, &req, [c; 32], now, caps);
    // 4 per requester digest, the fifth is refused with no row inserted.
    for c in 1..=4 {
        go(c, Caps::default()).unwrap();
    }
    assert_eq!(refusal(go(5, Caps::default())), RenewalRefusal::ReplayProtectionCapacity);
    assert_eq!(rows(&e), 4);
    // Per-home and global caps, with small injected limits.
    assert_eq!(
        refusal(go(6, Caps { global: 4096, per_home: 4, per_requester: 100 })),
        RenewalRefusal::ReplayProtectionCapacity
    );
    assert_eq!(
        refusal(go(6, Caps { global: 4, per_home: 64, per_requester: 100 })),
        RenewalRefusal::ReplayProtectionCapacity
    );
    assert!(go(6, Caps { global: 5, per_home: 5, per_requester: 100 }).is_ok());
    assert_eq!(rows(&e), 5);
    // GC removes at most 64 rows per turn, only after expiry plus 5 s skew.
    for n in 0..70 {
        insert_raw(&e, n, now + 10);
    }
    assert_eq!(rows(&e), 75);
    assert_eq!(e.f.registry.gc_renewal_challenges(now + 14, 64), Ok(0));
    assert_eq!(e.f.registry.gc_renewal_challenges(now + 15, 64), Ok(64));
    assert_eq!(e.f.registry.gc_renewal_challenges(now + 15, 64), Ok(6));
    assert_eq!(rows(&e), 5);
    assert_eq!(e.f.registry.gc_renewal_challenges(now + 15, 0), Err(RenewalRefusal::Invalid));
    assert_eq!(e.f.registry.gc_renewal_challenges(now + 15, 65), Err(RenewalRefusal::Invalid));
    // Clock rollback beyond the fence is ClockUncertain and changes nothing.
    assert_eq!(
        e.f.registry.gc_renewal_challenges(now - 100, 64),
        Err(RenewalRefusal::ClockUncertain)
    );
    assert_eq!(rows(&e), 5);
}
