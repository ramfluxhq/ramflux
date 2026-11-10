// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named P09 publication tests. Real `AccountDb`, real authority files, real node persist.
use super::{
    HeadKind, HeadWrite, NodeHeadPersist, PublishedHead, acknowledge_as_responder, publish_head,
};
use crate::SdkError;
use crate::client::native_test_support::Fixture;
use crate::custody::load_account;
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_node_core::{CustodyPublication, RouterCore, RouterRedbStore};
use ramflux_protocol::custody::{Device, DeviceRef, Envelope, Publication, object_hash};
use ramflux_protocol::encode_base64url;
use ramflux_storage::{AccountDb, AccountDbKey, AccountIndex, HeadRow};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct RouterPersist {
    router: RouterCore,
    store: RouterRedbStore,
}

impl RouterPersist {
    fn open(dir: &Path) -> TestResult<Arc<Self>> {
        let path = dir.join("router.redb");
        let store = RouterRedbStore::open_without_wal(&path)?;
        let router = RouterCore::new();
        store.bootstrap_router(&router)?;
        Ok(Arc::new(Self { router, store }))
    }
}

impl NodeHeadPersist for RouterPersist {
    fn persist_head(&self, publication: &Publication, now: u64) -> Result<String, SdkError> {
        let body = CustodyPublication {
            record: publication.record.clone(),
            compacted_ids: publication.compacted_ids.clone(),
        };
        let published = self
            .router
            .publish_custody_record(&body, now, &self.store)
            .map_err(|error| SdkError::LocalBus(error.to_string()))?;
        object_hash(&published).map_err(SdkError::from)
    }
}

impl NodeHeadPersist for Arc<RouterPersist> {
    fn persist_head(&self, publication: &Publication, now: u64) -> Result<String, SdkError> {
        self.as_ref().persist_head(publication, now)
    }
}

struct LossyPersist {
    inner: Arc<RouterPersist>,
    fail_once: AtomicBool,
}

impl NodeHeadPersist for LossyPersist {
    fn persist_head(&self, publication: &Publication, now: u64) -> Result<String, SdkError> {
        let hash = self.inner.persist_head(publication, now)?;
        if self.fail_once.swap(false, Ordering::SeqCst) {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        Ok(hash)
    }
}

struct Harness {
    id: String,
    fixture: Fixture,
    db: Mutex<AccountDb>,
    persist: Arc<RouterPersist>,
    _db_root: tempfile::TempDir,
    _router_root: tempfile::TempDir,
}

impl Harness {
    async fn open(id: &str) -> TestResult<Self> {
        let fixture = Fixture::new(id).await?;
        let db_root = tempfile::tempdir()?;
        let index = AccountIndex::open(db_root.path())?;
        index.create_account(id, "principal")?;
        let key = AccountDbKey::derive(id, b"pair01-p09-journal");
        let db = Mutex::new(AccountDb::open(&index, id, &key)?);
        let router_root = tempfile::tempdir()?;
        let persist = RouterPersist::open(router_root.path())?;
        Ok(Self {
            id: id.into(),
            fixture,
            db,
            persist,
            _db_root: db_root,
            _router_root: router_root,
        })
    }

    fn root(&self) -> &Path {
        &self.fixture.root.0
    }

    fn now() -> TestResult<u64> {
        Ok(crate::custody::network_now()?)
    }

    fn account(&self, now: u64) -> TestResult<crate::custody::BornAccount> {
        Ok(load_account(self.root(), &self.id, now)?)
    }

    fn primary(&self, now: u64) -> TestResult<SelfSigningKey> {
        let account = self.account(now)?;
        Ok(self.fixture.vault.primary_for_public_key(
            &account.record().body.master_certificate.body.self_signing_public_key,
        )?)
    }

    fn publisher(&self, now: u64) -> TestResult<DeviceRef> {
        Ok(self.account(now)?.record().body.master_certificate.body.primary_device_ref.clone())
    }

    fn vault_refs(&self, now: u64) -> TestResult<(String, String)> {
        let account = self.account(now)?;
        Ok((account.branch_vault_ref().to_owned(), account.primary_vault_ref().to_owned()))
    }
}

fn b32() -> TestResult<String> {
    Ok(encode_base64url(ramflux_crypto::random_32()?))
}

fn certify(
    harness: &Harness,
    device_id: &str,
    now: u64,
) -> TestResult<(DeviceRef, Envelope<ramflux_protocol::custody::BranchCertificate>)> {
    let account = harness.account(now)?;
    let primary = harness.primary(now)?;
    let branch = ramflux_crypto::create_device_branch(
        &account.record().body.principal_id,
        device_id,
        1,
        ramflux_crypto::random_32()?,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(ramflux_crypto::random_32()?);
    let mut certificate = account
        .record()
        .body
        .devices
        .iter()
        .find_map(|device| device.branch_certificate.as_ref().map(|envelope| envelope.body.clone()))
        .ok_or("certificate")?;
    certificate.device_id = device_id.into();
    certificate.device_epoch = 1;
    certificate.branch_signing_public_key =
        encode_base64url(branch.signing_key.verifying_key().to_bytes());
    certificate.agreement_identity_public_key = encode_base64url(agreement.public);
    certificate.cert_id = encode_base64url(ramflux_crypto::random_32()?);
    let certified = primary.certify_branch(certificate)?;
    let reference = DeviceRef {
        account_anchor: account.record().body.account_anchor.clone(),
        device_id: device_id.into(),
        device_epoch: 1,
    };
    Ok((reference, certified))
}

fn enroll_write(
    harness: &Harness,
    device_id: &str,
    now: u64,
) -> TestResult<(HeadWrite, DeviceRef)> {
    let publisher = harness.publisher(now)?;
    let (recipient, certificate) = certify(harness, device_id, now)?;
    let (branch_vault_ref, primary_vault_ref) = harness.vault_refs(now)?;
    Ok((
        HeadWrite {
            account_id: harness.id.clone(),
            operation_id: b32()?,
            invitation_id: Some(b32()?),
            generation: 1,
            issuer_seq: 1,
            local_seq: 1,
            kind: HeadKind::Enroll,
            publisher_ref: publisher.clone(),
            local_ref: publisher,
            recipient_ref: Some(recipient.clone()),
            revoked_id: None,
            certificate: Some(certificate),
            display_name: None,
            now,
            branch_vault_ref,
            data_vault_ref: "data".into(),
            primary_vault_ref: Some(primary_vault_ref),
        },
        recipient,
    ))
}

fn profile_write(harness: &Harness, name: &str, now: u64) -> TestResult<HeadWrite> {
    let publisher = harness.publisher(now)?;
    let (branch_vault_ref, primary_vault_ref) = harness.vault_refs(now)?;
    Ok(HeadWrite {
        account_id: harness.id.clone(),
        operation_id: b32()?,
        invitation_id: None,
        generation: 1,
        issuer_seq: 1,
        local_seq: 1,
        kind: HeadKind::Profile,
        publisher_ref: publisher.clone(),
        local_ref: publisher,
        recipient_ref: None,
        revoked_id: None,
        certificate: None,
        display_name: Some(name.into()),
        now,
        branch_vault_ref,
        data_vault_ref: "data".into(),
        primary_vault_ref: Some(primary_vault_ref),
    })
}

fn revoke_write(harness: &Harness, device_id: &str, now: u64) -> TestResult<HeadWrite> {
    let publisher = harness.publisher(now)?;
    let (branch_vault_ref, primary_vault_ref) = harness.vault_refs(now)?;
    Ok(HeadWrite {
        account_id: harness.id.clone(),
        operation_id: b32()?,
        invitation_id: None,
        generation: 1,
        issuer_seq: 1,
        local_seq: 1,
        kind: HeadKind::Revoke,
        publisher_ref: publisher.clone(),
        local_ref: publisher,
        recipient_ref: None,
        revoked_id: Some(device_id.into()),
        certificate: None,
        display_name: None,
        now,
        branch_vault_ref,
        data_vault_ref: "data".into(),
        primary_vault_ref: Some(primary_vault_ref),
    })
}

fn persist_current(harness: &Harness, now: u64) -> TestResult<String> {
    let account = harness.account(now)?;
    let publication = Publication { record: account.record().clone(), compacted_ids: None };
    Ok(harness.persist.persist_head(&publication, now)?)
}

fn enroll_sibling(harness: &Harness, now: u64) -> TestResult<Vec<Device>> {
    let account = harness.account(now)?;
    let primary = harness.primary(now)?;
    let (_ref, certificate) = certify(harness, "sibling", now)?;
    let record = primary.enroll_device(account.verified(), certificate, now)?;
    let authority = ramflux_protocol::custody::CustodyAuthority {
        publication: Publication { record: record.clone(), compacted_ids: None },
        custodian_publication: None,
    };
    crate::custody::accept_publication(harness.root(), &harness.id, &authority, now)?;
    persist_current(harness, now)?;
    Ok(load_account(harness.root(), &harness.id, now)?.record().body.devices.clone())
}

#[tokio::test]
async fn pairing_enroll_preserves_every_existing_device() -> TestResult {
    let harness = Harness::open("p09enroll").await?;
    let now = Harness::now()?;
    persist_current(&harness, now)?;
    let before = enroll_sibling(&harness, now)?;
    let (mut write, recipient) = enroll_write(&harness, "joined", now.saturating_add(1))?;
    let lossy =
        LossyPersist { inner: Arc::clone(&harness.persist), fail_once: AtomicBool::new(true) };
    match publish_head(&harness.db, harness.root(), harness.fixture.vault.as_ref(), &write, &lossy)
    {
        Err(SdkError::PairingCode("PublicationPending")) => {}
        other => return Err(format!("expected response loss, got {other:?}").into()),
    }
    write.now = now.saturating_add(2);
    let published =
        publish_head(&harness.db, harness.root(), harness.fixture.vault.as_ref(), &write, &lossy)?;
    assert_eq!(published.record_hash, object_hash(&published.record)?);
    let after = harness.account(write.now)?.record().body.devices.clone();
    preserve_existing(&before, &after, &recipient.device_id)?;
    assert_eq!(published.record.body.devices, after);
    assert!(harness.db.lock().map_err(|_| "db")?.pairing_head()?.is_none());
    Ok(())
}

fn preserve_existing(before: &[Device], after: &[Device], extra: &str) -> TestResult {
    for old in before {
        let found = after.iter().find(|device| device.device_id == old.device_id).ok_or("kept")?;
        if found != old {
            return Err(format!("device {} mutated", old.device_id).into());
        }
    }
    if !after.iter().any(|device| device.device_id == extra) {
        return Err("enrolled device missing".into());
    }
    Ok(())
}

#[tokio::test]
async fn pairing_concurrent_head_writers_do_not_fork() -> TestResult {
    let harness = Harness::open("p09race").await?;
    let now = Harness::now()?;
    persist_current(&harness, now)?;
    enroll_sibling(&harness, now)?;
    let base = harness.account(now)?.record().clone();
    let enroll = enroll_write(&harness, "third", now.saturating_add(1))?;
    let profile = profile_write(&harness, "Renamed Human", now.saturating_add(1))?;
    let revoke = revoke_write(&harness, "sibling", now.saturating_add(1))?;
    let published = race_three(&harness, enroll.0, profile, revoke)?;
    assert_linear_chain(&base, &published)?;
    Ok(())
}

fn race_three(
    harness: &Harness,
    enroll: HeadWrite,
    profile: HeadWrite,
    revoke: HeadWrite,
) -> TestResult<Vec<PublishedHead>> {
    let db = &harness.db;
    let root = harness.root();
    let vault = &harness.fixture.vault;
    let persist = &harness.persist;
    let results = Mutex::new(Vec::new());
    let errors = Mutex::new(Vec::new());
    let results_ref = &results;
    let errors_ref = &errors;
    std::thread::scope(|scope| {
        for write in [enroll, profile, revoke] {
            scope.spawn(move || {
                match publish_head(db, root, vault.as_ref(), &write, persist.as_ref()) {
                    Ok(published) => {
                        if let Ok(mut held) = results_ref.lock() {
                            held.push(published);
                        }
                    }
                    Err(error) => {
                        if let Ok(mut held) = errors_ref.lock() {
                            held.push(error.to_string());
                        }
                    }
                }
            });
        }
    });
    let failures = errors.lock().map_err(|_| "errors")?;
    if !failures.is_empty() {
        return Err(format!("writer failures {failures:?}").into());
    }
    let mut published = results.lock().map_err(|_| "results")?.clone();
    if published.len() != 3 {
        return Err(format!("writers {}", published.len()).into());
    }
    published.sort_by_key(|head| head.epoch);
    Ok(published)
}

fn assert_linear_chain(
    base: &Envelope<ramflux_protocol::custody::DeviceSet>,
    heads: &[PublishedHead],
) -> TestResult {
    let mut previous = object_hash(base)?;
    let mut epoch = base.body.device_set_epoch;
    let mut seen = Vec::new();
    for head in heads {
        if seen.contains(&head.epoch) {
            return Err(format!("forked epoch {}", head.epoch).into());
        }
        seen.push(head.epoch);
        if head.epoch <= epoch {
            return Err(format!("epoch {} after {epoch}", head.epoch).into());
        }
        if head.record.body.previous_record_hash.as_deref() != Some(previous.as_str()) {
            return Err("previous_record_hash chain broken".into());
        }
        if object_hash(&head.record)? != head.record_hash {
            return Err("Published hash mismatch".into());
        }
        previous = head.record_hash.clone();
        epoch = head.epoch;
    }
    Ok(())
}

#[tokio::test]
async fn pairing_publisher_cannot_skip_submitted() -> TestResult {
    let harness = Harness::open("p09skip").await?;
    let now = Harness::now()?;
    persist_current(&harness, now)?;
    let (write, _) = enroll_write(&harness, "skip", now.saturating_add(1))?;
    seed_prepared(&harness, &write)?;
    let publisher = write.publisher_ref.clone();
    match acknowledge_as_responder(&harness.db, &publisher) {
        Err(SdkError::PairingField("submitted_required")) => Ok(()),
        other => Err(format!("publisher skip submitted: {other:?}").into()),
    }
}

#[tokio::test]
async fn pairing_responder_skips_submitted() -> TestResult {
    let harness = Harness::open("p09resp").await?;
    let now = Harness::now()?;
    persist_current(&harness, now)?;
    let (write, recipient) = enroll_write(&harness, "resp", now.saturating_add(1))?;
    seed_prepared(&harness, &write)?;
    acknowledge_as_responder(&harness.db, &recipient)?;
    let head = harness.db.lock().map_err(|_| "db")?.pairing_head()?.ok_or("head")?;
    assert_eq!(head.state, "acknowledged");
    Ok(())
}

#[tokio::test]
async fn pairing_terminal_transition_deletes_head() -> TestResult {
    let harness = Harness::open("p09term").await?;
    let now = Harness::now()?;
    persist_current(&harness, now)?;
    enroll_sibling(&harness, now)?;
    let (write, _) = enroll_write(&harness, "term", now.saturating_add(1))?;
    let published = publish_head(
        &harness.db,
        harness.root(),
        harness.fixture.vault.as_ref(),
        &write,
        harness.persist.as_ref(),
    )?;
    assert_eq!(published.record_hash.len(), 43);
    let db = harness.db.lock().map_err(|_| "db")?;
    if db.pairing_head()?.is_some() {
        return Err("head survived terminal".into());
    }
    let terminals = db.pairing_terminal_rows()?;
    if terminals.len() != 1 || terminals[0].outcome != "completed" {
        return Err(format!("terminal {terminals:?}").into());
    }
    Ok(())
}

#[tokio::test]
async fn pairing_publish_refuses_foreign_pending_head() -> TestResult {
    let harness = Harness::open("p09fence").await?;
    let now = Harness::now()?;
    persist_current(&harness, now)?;
    enroll_sibling(&harness, now)?;
    let (seed, _) = enroll_write(&harness, "held", now.saturating_add(1))?;
    seed_prepared(&harness, &seed)?;
    let before_head = held_head(&harness)?;
    let before_record = harness.account(now)?.record().clone();
    let profile = profile_write(&harness, "Renamed Human", now.saturating_add(1))?;
    let revoke = revoke_write(&harness, "sibling", now.saturating_add(1))?;
    let (enroll, _) = enroll_write(&harness, "other", now.saturating_add(1))?;
    assert_busy(&harness, &profile)?;
    assert_busy(&harness, &revoke)?;
    assert_busy(&harness, &enroll)?;
    assert_eq!(held_head(&harness)?, before_head);
    assert_eq!(harness.account(now)?.record(), &before_record);
    Ok(())
}

#[tokio::test]
async fn pairing_non_primary_cannot_submit_stored_head() -> TestResult {
    let harness = Harness::open("p09stored").await?;
    let now = Harness::now()?;
    persist_current(&harness, now)?;
    let (mut write, recipient) = enroll_write(&harness, "stolen", now.saturating_add(1))?;
    seed_prepared(&harness, &write)?;
    write.publisher_ref = recipient.clone();
    write.local_ref = recipient;
    match publish_head(
        &harness.db,
        harness.root(),
        harness.fixture.vault.as_ref(),
        &write,
        harness.persist.as_ref(),
    ) {
        Err(SdkError::PairingCode("PrimaryRequired")) => Ok(()),
        other => Err(format!("non-primary submit: {other:?}").into()),
    }
}

#[tokio::test]
async fn pairing_resume_refuses_kind_mismatch() -> TestResult {
    let harness = Harness::open("p09kind").await?;
    let now = Harness::now()?;
    persist_current(&harness, now)?;
    let (seed, _) = enroll_write(&harness, "kind", now.saturating_add(1))?;
    seed_prepared(&harness, &seed)?;
    let mut profile = profile_write(&harness, "Renamed Human", now.saturating_add(1))?;
    profile.operation_id = seed.operation_id.clone();
    profile.invitation_id = seed.invitation_id.clone();
    assert_busy(&harness, &profile)?;
    Ok(())
}

fn held_head(harness: &Harness) -> TestResult<HeadRow> {
    Ok(harness.db.lock().map_err(|_| "db")?.pairing_head()?.ok_or("head")?)
}

fn assert_busy(harness: &Harness, write: &HeadWrite) -> TestResult {
    match publish_head(
        &harness.db,
        harness.root(),
        harness.fixture.vault.as_ref(),
        write,
        harness.persist.as_ref(),
    ) {
        Err(SdkError::PairingCode("Busy")) => Ok(()),
        other => Err(format!("expected Busy, got {other:?}").into()),
    }
}

fn seed_prepared(harness: &Harness, write: &HeadWrite) -> TestResult {
    let account = harness.account(write.now)?;
    let primary = harness.primary(write.now)?;
    let certificate = write.certificate.clone().ok_or("certificate")?;
    let record = primary.enroll_device(account.verified(), certificate, write.now)?;
    let publication = Publication { record: record.clone(), compacted_ids: None };
    let row = HeadRow {
        account_id: write.account_id.clone(),
        operation_id: write.operation_id.clone(),
        invitation_id: write.invitation_id.clone(),
        generation: write.generation,
        kind: "enroll".into(),
        base_record_hash: object_hash(account.record())?,
        base_epoch: account.record().body.device_set_epoch,
        publisher_ref: ramflux_protocol::canonical_json_bytes(&write.publisher_ref)?,
        candidate: ramflux_protocol::canonical_json_bytes(&publication)?,
        candidate_hash: object_hash(&record)?,
        state: "prepared".into(),
        ack: None,
        recipient_ref: Some(ramflux_protocol::canonical_json_bytes(
            write.recipient_ref.as_ref().ok_or("recipient")?,
        )?),
        revoked_ref: None,
        created_at: write.now,
    };
    harness.db.lock().map_err(|_| "db")?.put_pairing_head(&row)?;
    Ok(())
}

#[test]
fn pairing_head_fence_blocks_foreign_operation() {
    assert!(crate::custody::pending_head_fence_blocks(Some("op-a"), "op-b"));
    assert!(!crate::custody::pending_head_fence_blocks(Some("op-a"), "op-a"));
    assert!(!crate::custody::pending_head_fence_blocks(None, "op-a"));
}
