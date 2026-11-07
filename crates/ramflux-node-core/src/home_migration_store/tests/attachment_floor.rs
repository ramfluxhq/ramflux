// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The attachment home floor survives restart and refuses superseded or forked chains.
use super::*;
use crate::relay::attachment::RenewalRefusal;

const T: u64 = 1_700_000_200;

fn evidence(epoch: u64, key_seed: u8) -> TestResult<RecordEvidence> {
    let mut ev: RecordEvidence = serde_json::from_value(fixture()?["genesis"].clone())?;
    let HomeRecord::Genesis { genesis } = &mut ev.record else {
        return Err("fixture is a genesis".into());
    };
    genesis.body.home_epoch = epoch;
    genesis.body.home_node_key = public(key_seed);
    Ok(ev)
}
fn anchor(ev: &RecordEvidence) -> String {
    ev.record.account_anchor().to_owned()
}
fn hash_of(ev: &RecordEvidence) -> TestResult<String> {
    Ok(record_hash(&ev.record)?)
}
fn resolved(ev: &RecordEvidence) -> impl FnOnce() -> Result<ResolveResult, RenewalRefusal> {
    let result = ResolveResult { home: ev.clone(), predecessors: vec![] };
    move || Ok(result)
}

#[test]
fn large_home_floor_refuses_superseded_chain_after_restart() -> TestResult {
    let mut a = TestNode::new("A", 8, true)?;
    let old = evidence(5, 11)?;
    let new = evidence(6, 12)?;
    let anchor = anchor(&old);
    let verdicts = AttachmentHomeVerdicts::new();
    // B's epoch-5 chain is accepted before the successor is seen.
    let first = verdicts.verdict(a.store()?, &anchor, T, resolved(&old))?;
    assert_eq!(first.home_epoch, 5);
    assert_eq!(verdicts.cached(), 1);
    // Observing the successor advances the floor and evicts the cached verdict.
    assert_eq!(
        verdicts.observe(a.store()?, &anchor, 6, &hash_of(&new)?, T + 1)?,
        FloorObservation::Advanced
    );
    assert_eq!(verdicts.cached(), 0);
    // Restart the router store: the memory cache is gone, the floor must be durable.
    a.restart()?;
    let fresh = AttachmentHomeVerdicts::new();
    assert_eq!(
        fresh.verdict(a.store()?, &anchor, T + 2, resolved(&old)),
        Err(RenewalRefusal::HomeMismatch)
    );
    assert_eq!(a.store()?.attachment_home_floor(&anchor)?.map(|f| f.epoch), Some(6));
    // Inclusive boundary: the floor epoch itself with the floor hash is accepted.
    let ok = fresh.verdict(a.store()?, &anchor, T + 3, resolved(&new))?;
    assert_eq!((ok.home_epoch, ok.home_node.as_str()), (6, new.record.home().0));
    Ok(())
}

#[test]
fn same_epoch_with_different_hash_is_a_fork() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let one = evidence(5, 11)?;
    let fork = evidence(5, 12)?;
    let anchor = anchor(&one);
    let verdicts = AttachmentHomeVerdicts::new();
    verdicts.verdict(a.store()?, &anchor, T, resolved(&one))?;
    assert_eq!(
        a.store()?.observe_attachment_home(&anchor, 5, &hash_of(&fork)?, T),
        Err(RenewalRefusal::HomeMismatch)
    );
    assert_eq!(
        AttachmentHomeVerdicts::new().verdict(a.store()?, &anchor, T, resolved(&fork)),
        Err(RenewalRefusal::HomeMismatch)
    );
    // The refusals left the floor on the first hash.
    assert_eq!(
        a.store()?.attachment_home_floor(&anchor)?.map(|f| f.record_hash),
        Some(hash_of(&one)?)
    );
    Ok(())
}

#[test]
fn floor_never_moves_backwards() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let ev = evidence(7, 11)?;
    let anchor = anchor(&ev);
    let store = a.store()?;
    assert_eq!(
        store.observe_attachment_home(&anchor, 7, &hash_of(&ev)?, T)?,
        FloorObservation::Advanced
    );
    assert_eq!(
        store.observe_attachment_home(&anchor, 7, &hash_of(&ev)?, T + 9)?,
        FloorObservation::Unchanged
    );
    assert_eq!(
        store.observe_attachment_home(&anchor, 6, &hash(1), T + 9)?,
        FloorObservation::Unchanged
    );
    assert_eq!(
        store.attachment_home_floor(&anchor)?,
        Some(HomeFloor { epoch: 7, record_hash: hash_of(&ev)?, observed_at: T })
    );
    Ok(())
}

#[test]
fn full_floor_refuses_new_anchors_but_advances_existing_ones() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let store = a.store()?;
    // Inclusive boundary at a cap of 3: anchors 1..=3 are admitted, anchor 4 is refused.
    for n in 1..=3u8 {
        assert_eq!(
            store.observe_attachment_home_capped(&format!("a{n}"), 1, &hash(n), T, 3)?,
            FloorObservation::Advanced
        );
    }
    assert_eq!(
        store.observe_attachment_home_capped("a4", 1, &hash(4), T, 3),
        Err(RenewalRefusal::HomeTrustUnavailable)
    );
    assert_eq!(store.attachment_home_floor("a4")?, None);
    // An existing anchor needs no slot.
    assert_eq!(
        store.observe_attachment_home_capped("a2", 2, &hash(9), T, 3)?,
        FloorObservation::Advanced
    );
    assert_eq!(store.attachment_home_floor("a2")?.map(|f| f.epoch), Some(2));
    Ok(())
}

#[test]
fn verdict_cache_is_bounded_and_expires_after_sixty_seconds() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let ev = evidence(5, 11)?;
    let anchor = anchor(&ev);
    let verdicts = AttachmentHomeVerdicts::new();
    let first = verdicts.verdict(a.store()?, &anchor, T, resolved(&ev))?;
    let never = || -> Result<ResolveResult, RenewalRefusal> { Err(RenewalRefusal::Invalid) };
    // Age 60 is a hit (inclusive); the resolver is not consulted.
    assert_eq!(verdicts.verdict(a.store()?, &anchor, T + 60, never)?, first);
    // Age 61 is a miss: the resolver runs and its refusal surfaces.
    assert_eq!(verdicts.verdict(a.store()?, &anchor, T + 61, never), Err(RenewalRefusal::Invalid));
    // Bounded at 256 entries; the oldest entry is evicted first.
    for n in 0..=MAX_CACHED_VERDICTS as u64 {
        let mut v = first.clone();
        v.account_anchor = format!("c{n}");
        v.checked_at = T + 100 + n % 50;
        verdicts.insert(&hash(1), &v, T + 150)?;
    }
    assert_eq!(verdicts.cached(), MAX_CACHED_VERDICTS);
    Ok(())
}
