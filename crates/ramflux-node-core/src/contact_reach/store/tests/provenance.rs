// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real management writer, native advance/reopen and immutable owner snapshot proof reads.
use super::*;
use crate::contact_reach::{ReachService, ReachSession};
use ramflux_protocol::contact_reach::{ProvenanceAuthority, Request, verify_pages};

fn retained(
    store: &RouterRedbStore,
    root: &str,
    reference: &ramflux_protocol::contact_reach::SignerReference,
    proof: bool,
) -> TestResult<bool> {
    use redb::ReadableDatabase;
    let tx = store.migration_db().begin_read()?;
    let table = tx.open_table(redb::TableDefinition::<&str, &[u8]>::new(if proof {
        "contact_reach_provenance_v1"
    } else {
        "contact_reach_signer_references_v1"
    }))?;
    let selector = if proof {
        reference.proof_hash.clone()
    } else {
        serde_json::to_string(&(reference.object_kind, &reference.object_hash))?
    };
    let present = table.get(key(root, &selector)?.as_str())?.is_some();
    Ok(present)
}

#[test]
fn cr_owner_proof_collection_waits_for_snapshot_leases_and_preserves_current_head() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("owner-proof-collection.redb");
    let (store, mut f) = initialize(&path)?;
    let node = costs::issuer(&store, &f)?;
    {
        let tx = store.begin_write()?;
        f.home = ramflux_protocol::home_migration::record_hash(&home(&tx, &f.root)?.record)?;
    }
    store.reach_owner_commit(owner(&f), &policy(&f, 110, 0, ReachMode::ContactsOnly)?, NOW)?;
    let service = ReachService::new(node)?;
    let read = Operation::ReachState { known_revision: 0, snapshot_id: None, page: 0 };
    let OperationResult::ReachState { manifest, page } =
        call(&service, &store, &f, read.clone(), NOW)
    else {
        return Err("first immutable snapshot".into());
    };
    let old = page.signers.first().ok_or("original policy signer")?.clone();
    let mut body = f.authority.envelope().body.clone();
    body.device_set_epoch += 1;
    body.previous_record_hash = Some(custody::object_hash(f.authority.envelope())?);
    body.issued_at = NOW + 1;
    let record = f.key.sign_record(body)?;
    f.authority = ramflux_crypto::custody::verify_record(&record, NOW + 1, None, None)?;
    let tx = store.begin_write()?;
    let mut account = account(&tx, &f.root)?;
    account.pins.observe(&f.authority)?;
    account.publication.record = record;
    tx.open_table(CUSTODY)?.insert(f.root.as_str(), encoded(&account)?.as_slice())?;
    tx.commit()?;
    store.reach_owner_commit(
        owner(&f),
        &policy_at(&f, 111, 1, ReachMode::ContactsOnly, NOW + 2)?,
        NOW + 2,
    )?;
    assert!(
        matches!(
            call(&service, &store, &f, read.clone(), NOW + 3),
            OperationResult::ReachState { .. }
        ),
        "a second snapshot must retain the earlier lease's complete proof closure"
    );
    assert!(retained(&store, &f.root, &old, false)?, "an active lease pins superseded selectors");
    assert!(retained(&store, &f.root, &old, true)?, "an active lease pins superseded proof bytes");
    let proof_read = Operation::ReachProvenance {
        snapshot_id: manifest.body.snapshot_id.clone(),
        proof_hash: old.proof_hash.clone(),
    };
    assert!(
        matches!(call(&service, &store, &f, proof_read.clone(), NOW + 4), OperationResult::ReachProvenance { manifest: returned, .. } if returned == manifest),
        "a native head advance must not substitute the original immutable proof read"
    );
    let OperationResult::ReachState { page, .. } = call(&service, &store, &f, read, NOW + 64)
    else {
        return Err("fresh snapshot after both leases expired".into());
    };
    let current = page.signers.first().ok_or("current policy signer")?;
    assert!(!retained(&store, &f.root, &old, false)?, "expired leases release obsolete selectors");
    assert!(
        !retained(&store, &f.root, &old, true)?,
        "unreferenced old native tuples can now be collected"
    );
    assert!(retained(&store, &f.root, current, true)?, "the current admitted tuple remains pinned");
    assert!(
        matches!(
            call(&service, &store, &f, proof_read, NOW + 64),
            OperationResult::Error { reason: Reason::ForeignSnapshotExpired, .. }
        ),
        "expired snapshot selectors cannot become a general historical lookup"
    );
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    assert!(!retained(&store, &f.root, &old, true)?, "collection survives reopening");
    assert!(
        retained(&store, &f.root, current, true)?,
        "reopening preserves the live original proof"
    );
    Ok(())
}
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
