// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The attachment home floor survives restart and refuses superseded or forked chains.
#![allow(clippy::unwrap_used)]
use super::super::attachment_floor::FloorWrite;
use super::*;
use crate::relay::attachment::RenewalRefusal;
use std::sync::Arc;

const T: u64 = 1_700_000_200;
type Advance = fn(&RouterRedbStore, &RecordEvidence);

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
fn capped<'a>(anchor: &'a str, epoch: u64, hash: &'a str, max: usize) -> FloorWrite<'a> {
    FloorWrite { max_anchors: max, ..FloorWrite::new(anchor, epoch, hash, T, false) }
}
fn set_hook(
    store: &RouterRedbStore,
    hook: impl Fn(&RouterRedbStore, &'static str) + Send + Sync + 'static,
) {
    *store.attachment_verdict_hook.lock().unwrap() = Some(Arc::new(hook));
}

#[test]
fn large_home_floor_refuses_superseded_chain_after_restart() -> TestResult {
    let mut a = TestNode::new("A", 8, true)?;
    let old = evidence(5, 11)?;
    let new = evidence(6, 12)?;
    let anchor = anchor(&old);
    let first = a.store()?.attachment_home_verdict(&anchor, T, resolved(&old))?;
    assert_eq!(first.home_epoch, 5);
    assert_eq!(a.store()?.attachment_cached_verdicts(), 1);
    // Observing the successor advances the floor and evicts the cached verdict.
    assert_eq!(
        a.store()?.observe_attachment_home(&anchor, 6, &hash_of(&new)?, T + 1)?,
        FloorObservation::Advanced
    );
    assert_eq!(a.store()?.attachment_cached_verdicts(), 0);
    // Restart the router store: the memory cache is gone, the floor must be durable.
    a.restart()?;
    assert_eq!(a.store()?.attachment_cached_verdicts(), 0);
    assert_eq!(
        a.store()?.attachment_home_verdict(&anchor, T + 2, resolved(&old)),
        Err(RenewalRefusal::HomeMismatch)
    );
    assert_eq!(a.store()?.attachment_home_floor(&anchor)?.map(|f| f.epoch), Some(6));
    // Inclusive boundary: the floor epoch itself with the floor hash is accepted.
    let ok = a.store()?.attachment_home_verdict(&anchor, T + 3, resolved(&new))?;
    assert_eq!((ok.home_epoch, ok.home_node.as_str()), (6, new.record.home().0));
    Ok(())
}

#[test]
fn real_migration_chain_floor_refuses_the_superseded_genesis_after_restart() -> TestResult {
    // A real attested genesis, then a real committed successor on the source. Both are
    // persisted as heads, and each head write advances the floor in its own transaction.
    let mut s = Scenario::prepared()?;
    let genesis = s.base.evidence().clone();
    let anchor = s.anchor.clone();
    assert_eq!(s.a.store()?.attachment_home_floor(&anchor)?.map(|f| f.epoch), Some(0));
    let op = s.seal()?;
    let committed = s.commit(&op)?;
    assert_eq!(committed.record.epoch(), 1);
    s.a.restart()?;
    assert_eq!(s.a.store()?.attachment_home_floor(&anchor)?.map(|f| f.epoch), Some(1));
    assert_eq!(
        s.a.store()?.attachment_home_verdict(&anchor, NOW + 3, resolved(&genesis)),
        Err(RenewalRefusal::HomeMismatch)
    );
    let ok = s.a.store()?.attachment_home_verdict(&anchor, NOW + 3, resolved(&committed))?;
    assert_eq!((ok.home_epoch, ok.home_node.as_str()), (1, "B"));
    Ok(())
}

#[test]
fn resolver_results_are_persisted_to_the_floor() -> TestResult {
    let s = Scenario::prepared()?;
    let anchor = s.anchor.clone();
    // Drop the floor row the head write made, so only the resolver hook can restore it.
    let tx = s.a.store()?.begin_write()?;
    tx.delete_table(redb::TableDefinition::<&str, &[u8]>::new("attachment_home_floor_v1"))?;
    crate::home_migration_store::commit_transition(s.a.store()?, tx)?;
    assert_eq!(s.a.store()?.attachment_home_floor(&anchor)?, None);
    let service = crate::HomeMigrationService::new(Arc::new(s.a.node.clone()), Arc::new(NoMesh));
    let payload = ramflux_protocol::home_migration::ResolvePayload {
        target_anchor: anchor.clone(),
        after_home_hash: None,
        limit: 8,
        old_node_hint: None,
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let result = service.latest_migration_home_at(s.a.store()?, NOW, deadline, &payload, "id")?;
    assert_eq!(
        s.a.store()?.attachment_home_floor(&anchor)?.map(|f| (f.epoch, f.record_hash)),
        Some((0, hash_of(&result.home)?))
    );
    Ok(())
}
struct NoMesh;
impl crate::HomeMigrationMesh for NoMesh {
    fn peer_key(&self, _: &str, _: std::time::Instant) -> Result<String, crate::NodeCoreError> {
        Err(crate::NodeCoreError::HomeMigration(Refusal::PeeringUnavailable))
    }
}

#[test]
fn same_epoch_with_different_hash_is_a_fork() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let one = evidence(5, 11)?;
    let fork = evidence(5, 12)?;
    let anchor = anchor(&one);
    a.store()?.attachment_home_verdict(&anchor, T, resolved(&one))?;
    for observe in [true, false] {
        let out = if observe {
            a.store()?.observe_attachment_home(&anchor, 5, &hash_of(&fork)?, T)
        } else {
            a.store()?.admit_attachment_home(&anchor, 5, &hash_of(&fork)?, T)
        };
        assert_eq!(out, Err(RenewalRefusal::HomeMismatch));
    }
    assert_eq!(
        a.store()?.attachment_home_verdict(&anchor, T + 61, resolved(&fork)),
        Err(RenewalRefusal::HomeMismatch)
    );
    assert_eq!(
        a.store()?.attachment_home_floor(&anchor)?.map(|f| f.record_hash),
        Some(hash_of(&one)?)
    );
    Ok(())
}

#[test]
fn observe_is_a_noop_below_the_floor_and_admit_refuses_it() -> TestResult {
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
        store.admit_attachment_home(&anchor, 6, &hash(1), T + 9),
        Err(RenewalRefusal::HomeMismatch)
    );
    assert_eq!(
        store.admit_attachment_home(&anchor, 7, &hash_of(&ev)?, T + 9)?,
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
            store.floor_commit(&capped(&format!("a{n}"), 1, &hash(n), 3))?.0,
            FloorObservation::Advanced
        );
    }
    assert_eq!(
        store.floor_commit(&capped("a4", 1, &hash(4), 3)).map(|r| r.0),
        Err(RenewalRefusal::HomeTrustUnavailable)
    );
    assert_eq!(store.attachment_home_floor("a4")?, None);
    // An existing anchor needs no slot.
    assert_eq!(store.floor_commit(&capped("a2", 2, &hash(9), 3))?.0, FloorObservation::Advanced);
    assert_eq!(store.attachment_home_floor("a2")?.map(|f| f.epoch), Some(2));
    Ok(())
}

#[test]
fn verdict_for_another_anchor_or_an_unusable_key_is_refused_in_isolation() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let ev = evidence(5, 11)?;
    // The resolver returned a head for a different anchor than the one asked about.
    assert_eq!(
        a.store()?.attachment_home_verdict("other-anchor", T, resolved(&ev)),
        Err(RenewalRefusal::HomeMismatch)
    );
    // A node key that is not 32 bytes cannot verify W.
    let mut bad = evidence(5, 11)?;
    let HomeRecord::Genesis { genesis } = &mut bad.record else {
        return Err("genesis".into());
    };
    genesis.body.home_node_key = "short".into();
    assert_eq!(
        a.store()?.attachment_home_verdict(&anchor(&bad), T, resolved(&bad)),
        Err(RenewalRefusal::HomeTrustUnavailable)
    );
    assert_eq!(a.store()?.attachment_home_floor(&anchor(&bad))?, None);
    // A resolver refusal passes through unchanged.
    assert_eq!(
        a.store()?.attachment_home_verdict(&anchor(&ev), T, || Err(RenewalRefusal::Busy)),
        Err(RenewalRefusal::Busy)
    );
    Ok(())
}

#[test]
fn cache_hit_is_revalidated_against_a_floor_advanced_by_another_writer() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let old = evidence(5, 11)?;
    let new = evidence(6, 12)?;
    let anchor = anchor(&old);
    let store = a.store()?;
    store.attachment_home_verdict(&anchor, T, resolved(&old))?;
    // A different writer (a head save, which has no handle on this cache) advances it.
    let tx = store.begin_write()?;
    save_head(&tx, &new)?;
    commit_transition(store, tx)?;
    assert_eq!(store.attachment_cached_verdicts(), 1);
    // The cached epoch-5 verdict must not be served: the hit is checked against the floor
    // and falls through to the resolver, which here yields the epoch-6 head.
    let fresh = store.attachment_home_verdict(&anchor, T + 1, resolved(&new))?;
    assert_eq!(fresh.home_epoch, 6);
    assert_eq!(store.attachment_cached_verdicts(), 1);
    // And if the resolver only knows the old head, the answer is a refusal, not the cache.
    assert_eq!(
        store.attachment_home_verdict(&anchor, T + 70, resolved(&old)),
        Err(RenewalRefusal::HomeMismatch)
    );
    Ok(())
}

#[test]
fn an_advance_between_resolve_and_admit_never_publishes_the_older_verdict() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let old = evidence(5, 11)?;
    let new = evidence(6, 12)?;
    let anchor = anchor(&old);
    let store = a.store()?;
    let (h, k) = (hash_of(&new)?, anchor.clone());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    set_hook(store, move |store, point| {
        log.lock().unwrap().push(point);
        if point == "before_admit" {
            store.observe_attachment_home(&k, 6, &h, T).unwrap();
        }
    });
    assert_eq!(
        store.attachment_home_verdict(&anchor, T, resolved(&old)),
        Err(RenewalRefusal::HomeMismatch)
    );
    assert_eq!(store.attachment_cached_verdicts(), 0);
    assert_eq!(*seen.lock().unwrap(), vec!["before_admit"]);
    Ok(())
}

#[test]
fn an_advance_between_admit_and_publish_is_detected_and_retried_to_a_refusal() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let old = evidence(5, 11)?;
    let new = evidence(6, 12)?;
    let anchor = anchor(&old);
    let store = a.store()?;
    let (h, k) = (hash_of(&new)?, anchor.clone());
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let once = Arc::clone(&fired);
    set_hook(store, move |store, point| {
        if point == "before_publish" && !once.swap(true, std::sync::atomic::Ordering::SeqCst) {
            store.observe_attachment_home(&k, 6, &h, T).unwrap();
        }
    });
    // The advance lands after admit committed epoch 5 but before publication: the
    // generation moved, so the verdict is not published; the retry's admit refuses it.
    assert_eq!(
        store.attachment_home_verdict(&anchor, T, resolved(&old)),
        Err(RenewalRefusal::HomeMismatch)
    );
    assert_eq!(store.attachment_cached_verdicts(), 0);
    Ok(())
}

#[test]
fn verdict_cache_is_bounded_and_expires_after_sixty_seconds() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let ev = evidence(5, 11)?;
    let anchor = anchor(&ev);
    let store = a.store()?;
    let first = store.attachment_home_verdict(&anchor, T, resolved(&ev))?;
    let never = || -> Result<ResolveResult, RenewalRefusal> { Err(RenewalRefusal::Invalid) };
    // Age 60 is a hit (inclusive); the resolver is not consulted.
    assert_eq!(store.attachment_home_verdict(&anchor, T + 60, never)?, first);
    // Age 61 is a miss: the resolver runs and its refusal surfaces.
    assert_eq!(store.attachment_home_verdict(&anchor, T + 61, never), Err(RenewalRefusal::Invalid));
    // Bounded at 256 entries; the oldest entry is evicted first.
    for n in 0..=MAX_CACHED_VERDICTS as u64 {
        let mut v = first.clone();
        v.account_anchor = format!("c{n}");
        v.checked_at = T + 100 + n % 50;
        store.cache_insert_for_test(&hash(1), &v);
    }
    // Publication trims to the bound.
    let other = evidence(9, 13)?;
    store.attachment_home_verdict(&anchor, T + 150, resolved(&other))?;
    assert_eq!(store.attachment_cached_verdicts(), MAX_CACHED_VERDICTS);
    Ok(())
}

#[test]
fn every_floor_writer_is_ordered_against_publication() -> TestResult {
    let old = evidence(5, 11)?;
    let new = evidence(6, 12)?;
    let anchor = anchor(&old);
    // One row per writer: the head-save transaction (no handle on the cache), the
    // resolver hook, and the store-level observe/admit paths.
    let writers: Vec<(&str, Advance)> = vec![
        ("save_head", |store, ev| {
            let tx = store.begin_write().unwrap();
            save_head(&tx, ev).unwrap();
            commit_transition(store, tx).unwrap();
        }),
        ("resolver hook", |store, ev| {
            let result = ResolveResult { home: ev.clone(), predecessors: vec![] };
            store.observe_attachment_resolved(&result, T).unwrap();
        }),
        ("observe_attachment_evidence", |store, ev| {
            store.observe_attachment_evidence(ev, T).unwrap();
        }),
        ("admit_attachment_home", |store, ev| {
            let hash = record_hash(&ev.record).unwrap();
            store
                .admit_attachment_home(ev.record.account_anchor(), ev.record.epoch(), &hash, T)
                .unwrap();
        }),
    ];
    for (name, advance) in writers {
        let a = TestNode::new("A", 8, true)?;
        let store = a.store()?;
        let successor = new.clone();
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let once = Arc::clone(&fired);
        set_hook(store, move |store, point| {
            if point == "before_publish" && !once.swap(true, std::sync::atomic::Ordering::SeqCst) {
                advance(store, &successor);
            }
        });
        // The writer commits after admit and before publication: epoch 5 must not be
        // returned or cached.
        assert_eq!(
            store.attachment_home_verdict(&anchor, T, resolved(&old)),
            Err(RenewalRefusal::HomeMismatch),
            "{name}"
        );
        assert_eq!(store.attachment_cached_verdicts(), 0, "{name}");
        assert_eq!(store.attachment_home_floor(&anchor)?.map(|f| f.epoch), Some(6), "{name}");
    }
    Ok(())
}
