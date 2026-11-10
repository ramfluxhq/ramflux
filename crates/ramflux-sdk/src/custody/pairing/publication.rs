// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary head writers (profile, revoke, enroll) share one pending-head fence.
//! Dormant and default-off: callers opt in; P18 wires native Publish.
use super::coordinator::validate_head_advance;
use crate::SdkError;
use crate::custody::{PrimaryVault, accept_publication, load_account, pending_head_fence_blocks};
use ramflux_crypto::custody::{SelfSigningKey, VerifiedRecord};
use ramflux_protocol::custody::{
    BranchCertificate, CustodyAuthority, DeviceRef, DeviceSet, Envelope, Publication, decode_epoch,
    encode_epoch, object_hash,
};
use ramflux_protocol::{canonical_json_bytes, parse_i_json};
use ramflux_storage::{AccountDb, AdoptionRow, HeadRow, TerminalRow};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

static GATES: OnceLock<Mutex<BTreeMap<String, Arc<Mutex<()>>>>> = OnceLock::new();

/// Kind of primary head mutation. `pairing_head` is written only for `Enroll`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadKind {
    Enroll,
    Profile,
    Revoke,
}

/// Request for one fenced primary head write.
pub struct HeadWrite {
    pub account_id: String,
    pub operation_id: String,
    pub invitation_id: Option<String>,
    pub generation: u64,
    pub issuer_seq: u64,
    pub local_seq: u64,
    pub kind: HeadKind,
    pub publisher_ref: DeviceRef,
    pub local_ref: DeviceRef,
    pub recipient_ref: Option<DeviceRef>,
    pub revoked_id: Option<String>,
    pub certificate: Option<Envelope<BranchCertificate>>,
    pub display_name: Option<String>,
    pub now: u64,
    pub branch_vault_ref: String,
    pub data_vault_ref: String,
    pub primary_vault_ref: Option<String>,
}

/// Node persistence for a signed candidate. Tests inject the real router path.
pub trait NodeHeadPersist: Send + Sync {
    /// Persist `publication` and return the Published `record_hash`.
    ///
    /// # Errors
    /// Returns a pairing or local-bus error when the node refuses the candidate.
    fn persist_head(&self, publication: &Publication, now: u64) -> Result<String, SdkError>;
}

/// Outcome of a published head.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct PublishedHead {
    pub record_hash: String,
    pub record: Envelope<DeviceSet>,
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HeadAck {
    record_hash: String,
    device_set_epoch: u64,
}

/// Publish one primary head through the pending-head fence.
///
/// # Errors
/// `Busy` when another operation holds the durable head, `PrimaryRequired` when the
/// caller is not the current primary, `submitted_required` when a publisher skips
/// submitted, or storage/crypto/node errors.
pub fn publish_head(
    db: &Mutex<AccountDb>,
    root: &Path,
    vault: &dyn PrimaryVault,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
) -> Result<PublishedHead, SdkError> {
    with_pending_head_fence(db, &write.account_id, &write.operation_id, || {
        publish_inside_fence(db, root, vault, write, persist)
    })
}

/// Responder-only prepared→acknowledged using the stored `publisher_ref`.
///
/// # Errors
/// `submitted_required` when the local device is the publisher; `state` when no
/// prepared head exists; storage errors otherwise.
pub fn acknowledge_as_responder(
    db: &Mutex<AccountDb>,
    local_ref: &DeviceRef,
) -> Result<(), SdkError> {
    journal(db, |db| {
        let mut head = db.pairing_head()?.ok_or(SdkError::PairingField("state"))?;
        let publisher = decode_ref(&head.publisher_ref)?;
        validate_head_advance(&head.state, "acknowledged", &publisher, local_ref)?;
        let publication = decode_candidate(&head.candidate)?;
        head.ack = Some(ack_bytes(&head.candidate_hash, publication.record.body.device_set_epoch)?);
        head.state = "acknowledged".into();
        db.put_pairing_head(&head)?;
        Ok(())
    })
}

/// Write adoption and atomically delete the acknowledged head.
///
/// # Errors
/// Storage field errors when adoption or terminal cleanup is refused.
pub fn retire_prepared_head(
    db: &Mutex<AccountDb>,
    write: &HeadWrite,
    record_hash: &str,
    finished_at: u64,
) -> Result<(), SdkError> {
    journal(db, |db| retire_acknowledged(db, write, record_hash, finished_at))
}

fn publish_inside_fence(
    db: &Mutex<AccountDb>,
    root: &Path,
    vault: &dyn PrimaryVault,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
) -> Result<PublishedHead, SdkError> {
    if let Some(published) = resume_submitted(db, root, write, persist)? {
        return Ok(published);
    }
    let account = load_account(root, &write.account_id, write.now)?;
    let primary = require_primary(&account, vault, &write.publisher_ref, &write.local_ref)?;
    #[cfg(test)]
    std::thread::yield_now();
    match write.kind {
        HeadKind::Enroll => enroll_head(db, root, &account, &primary, write, persist),
        HeadKind::Profile => profile_head(root, &account, &primary, write, persist),
        HeadKind::Revoke => revoke_head(root, &account, &primary, write, persist),
    }
}

fn resume_submitted(
    db: &Mutex<AccountDb>,
    root: &Path,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
) -> Result<Option<PublishedHead>, SdkError> {
    let existing = journal(db, |db| Ok(db.pairing_head()?))?;
    let Some(head) = existing else {
        return Ok(None);
    };
    if head.operation_id != write.operation_id {
        return Err(SdkError::PairingCode("Busy"));
    }
    match head.state.as_str() {
        "acknowledged" => {
            journal(db, |db| retire_acknowledged(db, write, &head.candidate_hash, write.now))?;
            Ok(Some(published_from_head(&head)?))
        }
        "prepared" | "submitted" => Ok(Some(submit_and_ack(db, root, write, persist, head)?)),
        _ => Err(SdkError::PairingField("state")),
    }
}

fn enroll_head(
    db: &Mutex<AccountDb>,
    root: &Path,
    account: &crate::custody::BornAccount,
    primary: &SelfSigningKey,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
) -> Result<PublishedHead, SdkError> {
    let certificate = write.certificate.clone().ok_or(SdkError::PairingField("certificate"))?;
    let record = primary.enroll_device(account.verified(), certificate, write.now)?;
    let head = prepared_enroll_row(account, write, &record)?;
    journal(db, |db| {
        db.put_pairing_head(&head)?;
        Ok(())
    })?;
    submit_and_ack(db, root, write, persist, head)
}

fn profile_head(
    root: &Path,
    account: &crate::custody::BornAccount,
    primary: &SelfSigningKey,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
) -> Result<PublishedHead, SdkError> {
    let name = write.display_name.as_ref().ok_or(SdkError::PairingField("display_name"))?;
    let mut body = next_body(account.verified(), write.now)?;
    body.profile.display_name.clone_from(name);
    let record = primary.sign_record(body)?;
    persist_plain(root, write, persist, record)
}

fn revoke_head(
    root: &Path,
    account: &crate::custody::BornAccount,
    primary: &SelfSigningKey,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
) -> Result<PublishedHead, SdkError> {
    let device_id = write.revoked_id.as_deref().ok_or(SdkError::PairingField("revoked_ref"))?;
    let record = primary.revoke_device(account.verified(), device_id, write.now)?;
    persist_plain(root, write, persist, record)
}

fn submit_and_ack(
    db: &Mutex<AccountDb>,
    root: &Path,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
    mut head: HeadRow,
) -> Result<PublishedHead, SdkError> {
    let publication = decode_candidate(&head.candidate)?;
    if head.state == "prepared" {
        validate_head_advance("prepared", "submitted", &write.publisher_ref, &write.local_ref)?;
        head.state = "submitted".into();
        journal(db, |db| {
            db.put_pairing_head(&head)?;
            Ok(())
        })?;
    }
    let published = persist.persist_head(&publication, write.now)?;
    if published != head.candidate_hash {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    validate_head_advance("submitted", "acknowledged", &write.publisher_ref, &write.local_ref)?;
    head.ack = Some(ack_bytes(&published, publication.record.body.device_set_epoch)?);
    head.state = "acknowledged".into();
    journal(db, |db| {
        db.put_pairing_head(&head)?;
        Ok(())
    })?;
    adopt_local(root, write, &publication)?;
    journal(db, |db| retire_acknowledged(db, write, &published, write.now))?;
    Ok(PublishedHead {
        record_hash: published,
        epoch: publication.record.body.device_set_epoch,
        record: publication.record,
    })
}

fn persist_plain(
    root: &Path,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
    record: Envelope<DeviceSet>,
) -> Result<PublishedHead, SdkError> {
    let publication = Publication { record: record.clone(), compacted_ids: None };
    let published = persist.persist_head(&publication, write.now)?;
    let expected = object_hash(&record)?;
    if published != expected {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    adopt_local(root, write, &publication)?;
    Ok(PublishedHead { record_hash: published, record, epoch: publication_epoch(&publication) })
}

fn retire_acknowledged(
    db: &AccountDb,
    write: &HeadWrite,
    record_hash: &str,
    finished_at: u64,
) -> Result<(), SdkError> {
    let invitation_id =
        write.invitation_id.clone().ok_or(SdkError::PairingField("invitation_id"))?;
    db.put_pairing_adoption(&AdoptionRow {
        account_id: write.account_id.clone(),
        operation_id: write.operation_id.clone(),
        record_hash: record_hash.to_owned(),
        local_ref: ref_bytes(&write.local_ref)?,
        local_role: "primary".into(),
        branch_vault_ref: write.branch_vault_ref.clone(),
        data_vault_ref: write.data_vault_ref.clone(),
        primary_vault_ref: write.primary_vault_ref.clone(),
    })?;
    db.commit_pairing_terminal_cleanup(&TerminalRow {
        account_id: write.account_id.clone(),
        operation_id: write.operation_id.clone(),
        invitation_id,
        issuer_seq: write.issuer_seq,
        local_seq: write.local_seq,
        generation: write.generation,
        outcome: "completed".into(),
        record_hash: Some(record_hash.to_owned()),
        finished_at,
        cleanup: "done".into(),
    })?;
    Ok(())
}

fn prepared_enroll_row(
    account: &crate::custody::BornAccount,
    write: &HeadWrite,
    record: &Envelope<DeviceSet>,
) -> Result<HeadRow, SdkError> {
    let invitation_id =
        write.invitation_id.clone().ok_or(SdkError::PairingField("invitation_id"))?;
    let recipient = write.recipient_ref.as_ref().ok_or(SdkError::PairingField("recipient_ref"))?;
    let publication = Publication { record: record.clone(), compacted_ids: None };
    let candidate = canonical_json_bytes(&publication)?;
    let candidate_hash = object_hash(record)?;
    Ok(HeadRow {
        account_id: write.account_id.clone(),
        operation_id: write.operation_id.clone(),
        invitation_id: Some(invitation_id),
        generation: write.generation,
        kind: "enroll".into(),
        base_record_hash: object_hash(account.record())?,
        base_epoch: account.record().body.device_set_epoch,
        publisher_ref: ref_bytes(&write.publisher_ref)?,
        candidate,
        candidate_hash,
        state: "prepared".into(),
        ack: None,
        recipient_ref: Some(ref_bytes(recipient)?),
        revoked_ref: None,
        created_at: write.now,
    })
}

fn require_primary(
    account: &crate::custody::BornAccount,
    vault: &dyn PrimaryVault,
    publisher_ref: &DeviceRef,
    local_ref: &DeviceRef,
) -> Result<SelfSigningKey, SdkError> {
    if publisher_ref != local_ref {
        return Err(SdkError::PairingCode("PrimaryRequired"));
    }
    let primary =
        account.group_primary(vault).map_err(|_| SdkError::PairingCode("PrimaryRequired"))?;
    let expected = &account.record().body.master_certificate.body.primary_device_ref;
    if expected != publisher_ref {
        return Err(SdkError::PairingCode("PrimaryRequired"));
    }
    Ok(primary)
}

fn adopt_local(root: &Path, write: &HeadWrite, publication: &Publication) -> Result<(), SdkError> {
    let authority =
        CustodyAuthority { publication: publication.clone(), custodian_publication: None };
    accept_publication(root, &write.account_id, &authority, write.now)?;
    Ok(())
}

fn with_pending_head_fence<T>(
    db: &Mutex<AccountDb>,
    account_id: &str,
    operation_id: &str,
    write: impl FnOnce() -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    let gate = account_gate(account_id);
    let _hold = match gate.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    refuse_foreign_head(db, operation_id)?;
    write()
}

fn refuse_foreign_head(db: &Mutex<AccountDb>, operation_id: &str) -> Result<(), SdkError> {
    journal(db, |db| {
        let pending = db.pairing_head()?.map(|head| head.operation_id);
        if pending_head_fence_blocks(pending.as_deref(), operation_id) {
            Err(SdkError::PairingCode("Busy"))
        } else {
            Ok(())
        }
    })
}

fn account_gate(account_id: &str) -> Arc<Mutex<()>> {
    let mut map = match GATES.get_or_init(|| Mutex::new(BTreeMap::new())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    Arc::clone(map.entry(account_id.to_owned()).or_insert_with(|| Arc::new(Mutex::new(()))))
}

fn journal<T>(
    db: &Mutex<AccountDb>,
    body: impl FnOnce(&AccountDb) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    let Ok(held) = db.lock() else {
        return Err(SdkError::PairingCode("Busy"));
    };
    body(&held)
}

fn next_body(current: &VerifiedRecord, now: u64) -> Result<DeviceSet, SdkError> {
    let mut body = current.envelope().body.clone();
    let (range, revision) = decode_epoch(body.device_set_epoch)?;
    if now < body.issued_at {
        return Err(SdkError::PairingField("issued_at"));
    }
    body.device_set_epoch =
        encode_epoch(range, revision.checked_add(1).ok_or(SdkError::PairingField("epoch"))?)?;
    body.previous_record_hash = Some(object_hash(current.envelope())?);
    body.issued_at = now;
    Ok(body)
}

fn published_from_head(head: &HeadRow) -> Result<PublishedHead, SdkError> {
    let publication = decode_candidate(&head.candidate)?;
    Ok(PublishedHead {
        record_hash: head.candidate_hash.clone(),
        epoch: publication.record.body.device_set_epoch,
        record: publication.record,
    })
}

fn decode_candidate(bytes: &[u8]) -> Result<Publication, SdkError> {
    let value: Publication =
        parse_i_json(bytes).map_err(|_| SdkError::PairingField("candidate"))?;
    Ok(value)
}

fn decode_ref(bytes: &[u8]) -> Result<DeviceRef, SdkError> {
    let value: DeviceRef =
        parse_i_json(bytes).map_err(|_| SdkError::PairingField("publisher_ref"))?;
    Ok(value)
}

fn ref_bytes(value: &DeviceRef) -> Result<Vec<u8>, SdkError> {
    Ok(canonical_json_bytes(value)?)
}

fn ack_bytes(record_hash: &str, device_set_epoch: u64) -> Result<Vec<u8>, SdkError> {
    Ok(canonical_json_bytes(&HeadAck { record_hash: record_hash.to_owned(), device_set_epoch })?)
}

fn publication_epoch(publication: &Publication) -> u64 {
    publication.record.body.device_set_epoch
}

#[cfg(test)]
#[path = "publication/tests.rs"]
mod tests;
