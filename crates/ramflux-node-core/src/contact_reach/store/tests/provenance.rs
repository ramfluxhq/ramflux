// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real management writer, native advance/reopen and immutable owner snapshot proof reads.
use super::*;
use crate::contact_reach::{ReachService, ReachSession};
use ramflux_protocol::contact_reach::{ProvenanceAuthority, Request, verify_pages};
fn request(operation: Operation) -> Request {
    Request {
        request_id: digest(98),
        session_id: "native-session".into(),
        session_generation: 1,
        remaining_ms: 10_000,
        operation,
    }
}
pub(super) fn call(
    service: &ReachService,
    store: &RouterRedbStore,
    f: &Fixture,
    operation: Operation,
    now: u64,
) -> OperationResult {
    service
        .owner(
            store,
            ReachSession { actor: &f.actor, id: "native-session", generation: 1 },
            &request(operation),
            now,
        )
        .result
}
#[test]
fn cr_retained_signer_owner_read_survives_native_advance_and_reopen() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("retained-owner.redb");
    let (store, mut f) = initialize(&path)?;
    let node = costs::issuer(&store, &f)?;
    f.home = {
        let tx = store.begin_write()?;
        ramflux_protocol::home_migration::record_hash(&home(&tx, &f.root)?.record)?
    };
    let operation = policy(&f, 90, 0, ReachMode::ContactsOnly)?;
    store.reach_owner_commit(owner(&f), &operation, NOW)?;
    let later = NOW + 604_800 + 901;
    let renewed = groups::renewed_primary(&f, later)?;
    let tx = store.begin_write()?;
    let mut state = account(&tx, &f.root)?;
    state.pins.observe(&renewed)?;
    state.publication.record = renewed.envelope().clone();
    tx.open_table(CUSTODY)?.insert(f.root.as_str(), encoded(&state)?.as_slice())?;
    tx.commit()?;
    store.prune_custody_history(later)?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    assert!(
        store
            .custody_historical_publication(
                &f.root,
                &custody::object_hash(f.authority.envelope())?,
                later
            )?
            .is_none(),
        "owner provenance cannot depend on the public delayed-contact history"
    );
    let service = ReachService::new(node)?;
    let result = call(
        &service,
        &store,
        &f,
        Operation::ReachState { known_revision: 1, snapshot_id: None, page: 0 },
        later,
    );
    let OperationResult::ReachState { manifest, page } = result else {
        return Err(format!("state owner result: {result:?}").into());
    };
    verify_pages(&manifest.body, std::slice::from_ref(&page))?;
    let selected = page.signers.first().ok_or("retained policy reference")?;
    let read = Operation::ReachProvenance {
        snapshot_id: manifest.body.snapshot_id.clone(),
        proof_hash: selected.proof_hash.clone(),
    };
    let result = call(&service, &store, &f, read.clone(), later);
    let OperationResult::ReachProvenance {
        manifest: returned,
        proof_hash,
        authority,
        custodian_history,
    } = result
    else {
        return Err(format!("proof owner result: {result:?}").into());
    };
    assert_eq!(
        returned, manifest,
        "proof reads retain the byte-identical immutable snapshot manifest"
    );
    let proof = ProvenanceAuthority { proof_hash, authority: *authority, custodian_history };
    let Operation::Policy { update } = operation else {
        return Err("original policy".into());
    };
    ramflux_crypto::contact_reach::verify_historical_policy(&update, &proof)?;
    assert_eq!(
        proof.authority.publication.record,
        *f.authority.envelope(),
        "a later current publication cannot substitute for original recipient signer evidence"
    );
    let mut swapped = proof.clone();
    swapped.authority.publication.record = renewed.envelope().clone();
    assert!(
        ramflux_crypto::contact_reach::verify_historical_policy(&update, &swapped).is_err(),
        "current-key substitution must fail the original content address"
    );
    owner_refusals(&service, &store, &f, &manifest, read, later);
    Ok(())
}

#[test]
fn cr_current_native_advance_waits_for_durable_reach_adoption() -> TestResult {
    use super::super::provenance::{adopt_current, require_ready};
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("reach-adoption.redb"))?;
    store.reach_owner_commit(owner(&f), &policy(&f, 89, 0, ReachMode::ContactsOnly)?, NOW)?;
    {
        let tx = store.begin_write()?;
        require_ready(&store, &tx, &f.root, &load(&tx, &f.root)?, NOW)?;
    }
    let renewed = groups::renewed_primary(&f, NOW + 3601)?;
    {
        let tx = store.begin_write()?;
        let mut native = account(&tx, &f.root)?;
        native.pins.observe(&renewed)?;
        native.publication.record = renewed.envelope().clone();
        tx.open_table(CUSTODY)?.insert(f.root.as_str(), encoded(&native)?.as_slice())?;
        tx.commit()?;
    }
    {
        let tx = store.begin_write()?;
        let state = load(&tx, &f.root)?;
        assert!(require_ready(&store, &tx, &f.root, &state, NOW + 1).is_err());
        adopt_current(&store, &tx, &f.root, NOW + 1)?;
        require_ready(&store, &tx, &f.root, &state, NOW + 1)?;
        // Dropping the transaction must drop the attempted adoption too.
    }
    {
        let tx = store.begin_write()?;
        assert!(require_ready(&store, &tx, &f.root, &load(&tx, &f.root)?, NOW + 1).is_err());
        adopt_current(&store, &tx, &f.root, NOW + 1)?;
        tx.commit()?;
    }
    let tx = store.begin_write()?;
    require_ready(&store, &tx, &f.root, &load(&tx, &f.root)?, NOW + 1)?;
    assert_eq!(load(&tx, &f.root)?.revision, 1, "adoption never rewrites historical state");
    Ok(())
}

fn owner_refusals(
    service: &ReachService,
    store: &RouterRedbStore,
    f: &Fixture,
    manifest: &Signed<ramflux_protocol::contact_reach::StateManifest>,
    read: Operation,
    later: u64,
) {
    let other = service
        .owner(
            store,
            ReachSession { actor: &f.actor, id: "another-session", generation: 1 },
            &Request { session_id: "another-session".into(), ..request(read.clone()) },
            later,
        )
        .result;
    assert!(
        matches!(other, OperationResult::Error { reason: Reason::ForeignReadRefused, .. }),
        "same-device different-session reads cannot borrow snapshot ownership"
    );
    assert!(
        matches!(
            call(
                service,
                store,
                f,
                Operation::ReachProvenance {
                    snapshot_id: manifest.body.snapshot_id.clone(),
                    proof_hash: digest(99)
                },
                later
            ),
            OperationResult::Error { reason: Reason::ForeignSnapshotInvalid, .. }
        ),
        "an arbitrary hash cannot become a historical key lookup"
    );
    assert!(
        matches!(
            call(service, store, f, read, later + 60),
            OperationResult::Error { reason: Reason::ForeignSnapshotExpired, .. }
        ),
        "snapshot expiry removes transfer authority without deleting durable provenance"
    );
}
