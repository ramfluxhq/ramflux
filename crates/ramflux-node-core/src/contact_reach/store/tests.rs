// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real redb writer/reopen and current-key CAS tests using immutable signed authority fixtures.
use super::*;
use ramflux_crypto::custody::{SelfSigningKey, VerifiedRecord};
use ramflux_protocol::contact_reach::{DECLINE_COOLDOWN, ReachMode, ReachPolicy};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_100;
fn digest(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
struct Fixture {
    root: String,
    actor: DeviceRef,
    authority: VerifiedRecord,
    key: SelfSigningKey,
    home: String,
}
fn initialize(path: &std::path::Path) -> TestResult<(RouterRedbStore, Fixture)> {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let record = serde_json::from_value(vector.get("record").ok_or("record")?.clone())?;
    let verified = ramflux_crypto::custody::verify_record(&record, NOW, None, None)?;
    let mut pins = ramflux_crypto::custody::AuthorityPins::default();
    pins.observe(&verified)?;
    let publication = crate::CustodyPublication { record, compacted_ids: None };
    let home: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    let home: ramflux_protocol::home_migration::RecordEvidence =
        serde_json::from_value(home.get("genesis").ok_or("genesis")?.clone())?;
    let store = RouterRedbStore::open_without_wal(path)?;
    let root = verified.envelope().body.account_anchor.clone();
    let tx = store.begin_write()?;
    tx.open_table(CUSTODY)?
        .insert(root.as_str(), encoded(&CustodyAccountState { publication, pins })?.as_slice())?;
    tx.open_table(HEADS)?.insert(root.as_str(), encoded(&home)?.as_slice())?;
    tx.commit()?;
    let fixture = Fixture {
        root,
        actor: verified.envelope().body.master_certificate.body.primary_device_ref.clone(),
        authority: verified,
        key: SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32])),
        home: ramflux_protocol::home_migration::record_hash(&home.record)?,
    };
    Ok((store, fixture))
}
fn policy(f: &Fixture, id: u8, revision: u64, mode: ReachMode) -> TestResult<Operation> {
    Ok(Operation::Policy {
        update: f.key.sign_reach_policy(
            ReachPolicy {
                version: 1,
                operation_id: digest(id),
                account_anchor: f.root.clone(),
                home_head_hash: f.home.clone(),
                expected_revision: revision,
                revision: revision + 1,
                mode,
                authority_head_hash: custody::object_hash(f.authority.envelope())?,
                master_certificate_hash: custody::object_hash(
                    &f.authority.envelope().body.master_certificate,
                )?,
                actor: f.actor.clone(),
                issued_at: NOW,
                expires_at: NOW + 300,
            },
            &f.authority,
            NOW,
        )?,
    })
}
fn owner(f: &Fixture) -> ReachOwner<'_> {
    ReachOwner { recipient_root: &f.root, actor: &f.actor }
}

#[test]
fn cr_home_policy_cas_exact_retry_and_closed_default_survive_reopen() -> TestResult {
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("home.redb");
    let (store, f) = initialize(&path)?;
    let open = policy(&f, 10, 0, ReachMode::Open)?;
    assert!(
        store.reach_owner_commit(owner(&f), &open, NOW).is_err(),
        "setup must explicitly install contacts_only revision one"
    );
    assert!(store.reach_account(&f.root)?.is_none(), "refused setup cannot leave partial state");
    let first = policy(&f, 11, 0, ReachMode::ContactsOnly)?;
    let result = store.reach_owner_commit(owner(&f), &first, NOW)?;
    assert_eq!(
        store.reach_owner_commit(owner(&f), &first, NOW + 301)?,
        result,
        "identical retry returns original committed result after submission expiry"
    );
    let changed = policy(&f, 11, 0, ReachMode::Open)?;
    assert!(
        matches!(
            store.reach_owner_commit(owner(&f), &changed, NOW),
            Err(super::super::ReachError::Refused(Reason::IdempotencyConflict))
        ),
        "changed bytes under the same operation id must conflict"
    );
    let next = policy(&f, 12, 1, ReachMode::Open)?;
    store.reach_owner_commit(owner(&f), &next, NOW)?;
    let stale = policy(&f, 13, 1, ReachMode::ContactsOnly)?;
    assert!(
        matches!(
            store.reach_owner_commit(owner(&f), &stale, NOW),
            Err(super::super::ReachError::Revision(2))
        ),
        "stale policy CAS cannot overwrite a newer decision"
    );
    drop(store);
    let reopened = RouterRedbStore::open_without_wal(&path)?;
    let saved = reopened.reach_account(&f.root)?.ok_or("state")?;
    assert_eq!(saved.policy_revision(), 2, "policy revision must survive reopen");
    assert_eq!(
        saved.policy.ok_or("policy")?.body.mode,
        ReachMode::Open,
        "reopen cannot reset the committed policy"
    );
    Ok(())
}

#[test]
fn cr_primary_denial_is_durable_and_unblock_restores_no_grant() -> TestResult {
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("home.redb");
    let (store, f) = initialize(&path)?;
    store.reach_owner_commit(owner(&f), &policy(&f, 20, 0, ReachMode::ContactsOnly)?, NOW)?;
    let peer = digest(41);
    let make = |id, revision, decision| -> TestResult<Operation> {
        Ok(Operation::Admission {
            update: f.key.sign_reach_admission(
                Admission {
                    version: 2,
                    operation_id: digest(id),
                    recipient_root: f.root.clone(),
                    home_head_hash: f.home.clone(),
                    expected_revision: revision,
                    subject: Subject::Friendship { root: peer.clone() },
                    decision,
                    permissions: None,
                    grant_until: None,
                    authority_head_hash: custody::object_hash(f.authority.envelope())?,
                    master_certificate_hash: custody::object_hash(
                        &f.authority.envelope().body.master_certificate,
                    )?,
                    actor: f.actor.clone(),
                    notice_hash: None,
                    evidence_hash: None,
                    issued_at: NOW,
                    expires_at: NOW + 300,
                },
                &f.authority,
                NOW,
            )?,
            peer_evidence: None,
            notice: None,
        })
    };
    store.reach_owner_commit(owner(&f), &make(21, 0, Decision::Block)?, NOW)?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    assert!(
        store
            .reach_account(&f.root)?
            .ok_or("state")?
            .check_denials(&peer, "foreign.example", NOW + 1)
            .is_err(),
        "a block must survive the receiving-home restart"
    );
    store.reach_owner_commit(owner(&f), &make(22, 1, Decision::Unblock)?, NOW + 2)?;
    let state = store.reach_account(&f.root)?.ok_or("state")?;
    state.check_denials(&peer, "foreign.example", NOW + 2)?;
    assert!(
        state.grants.is_empty(),
        "unblock must never recreate friendship or conversation grants"
    );
    store.reach_owner_commit(owner(&f), &make(23, 2, Decision::Decline)?, NOW + 3)?;
    let state = store.reach_account(&f.root)?.ok_or("state")?;
    assert!(
        state.check_denials(&peer, "foreign.example", NOW + 3 + DECLINE_COOLDOWN - 1).is_err(),
        "decline cooldown must last a full day from home commit"
    );
    state.check_denials(&peer, "foreign.example", NOW + 3 + DECLINE_COOLDOWN)?;
    Ok(())
}

mod costs;
mod groups;

mod provenance;
