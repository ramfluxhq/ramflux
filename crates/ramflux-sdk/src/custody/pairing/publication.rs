// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary head writers (profile, revoke, enroll) share one pending-head fence.
//! Dormant and default-off: callers opt in; P18 wires native Publish.
use super::coordinator::validate_head_advance;
use crate::SdkError;
use crate::custody::{PrimaryVault, load_account, load_data_account, pending_head_fence_blocks};
use ramflux_crypto::custody::{SelfSigningKey, VerifiedRecord};
use ramflux_protocol::custody::{
    BranchCertificate, CustodyAuthority, DeviceRef, DeviceSet, Envelope, Publication, decode_epoch,
    encode_epoch, object_hash,
};
use ramflux_protocol::{canonical_json_bytes, parse_i_json};
use ramflux_storage::{AccountDb, HeadRow, TerminalRow};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

static GATES: OnceLock<Mutex<BTreeMap<String, Arc<Mutex<()>>>>> = OnceLock::new();

/// Every head mutation has an immutable durable candidate before network I/O.
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
        publish_inside_fence(db, root, vault, write, persist, true)
    })
}

/// Ceremony publishers retain their acknowledged head until the recipient has installed it.
pub(crate) fn publish_ceremony_head(
    db: &Mutex<AccountDb>,
    root: &Path,
    vault: &dyn PrimaryVault,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
) -> Result<PublishedHead, SdkError> {
    with_pending_head_fence(db, &write.account_id, &write.operation_id, || {
        publish_inside_fence(db, root, vault, write, persist, false)
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
        db.commit_pairing_head(&head)?;
        Ok(())
    })
}

/// Write adoption and atomically delete the acknowledged head.
/// `local_role` is derived from the stored head's publisher versus `write.local_ref`.
///
/// # Errors
/// Storage field errors when adoption or terminal cleanup is refused.
pub(crate) fn retire_prepared_head(
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
    retire: bool,
) -> Result<PublishedHead, SdkError> {
    let head = {
        let _lock = super::activate::authority_lock(root, &write.account_id)?;
        refuse_foreign_head(db, &write.operation_id)?;
        if let Some(head) = journal(db, |db| Ok(db.pairing_head()?))? {
            require_resume_primary(root, vault, write, &head)?;
            if head.kind != kind_label(write.kind) {
                return Err(SdkError::PairingCode("Busy"));
            }
            head
        } else {
            let account = load_account(root, &write.account_id, write.now)?;
            let primary = require_primary(&account, vault, &write.publisher_ref, &write.local_ref)?;
            let record = match write.kind {
                HeadKind::Enroll => primary.enroll_device(
                    account.verified(),
                    write.certificate.clone().ok_or(SdkError::PairingField("certificate"))?,
                    write.now,
                )?,
                HeadKind::Profile => {
                    let mut body = next_body(account.verified(), write.now)?;
                    body.profile.display_name.clone_from(
                        write
                            .display_name
                            .as_ref()
                            .ok_or(SdkError::PairingField("display_name"))?,
                    );
                    primary.sign_record(body)?
                }
                HeadKind::Revoke => primary.revoke_device(
                    account.verified(),
                    write.revoked_id.as_deref().ok_or(SdkError::PairingField("revoked_ref"))?,
                    write.now,
                )?,
            };
            let head = prepared_head_row(&account, write, &record)?;
            journal(db, |db| {
                db.commit_pairing_head(&head)?;
                Ok(())
            })?;
            head
        }
    };
    let published = submit_and_ack(db, root, vault, write, persist, head)?;
    if retire {
        retire_prepared_head(db, write, &published.record_hash, write.now)?;
    }
    Ok(published)
}

fn require_resume_primary(
    root: &Path,
    vault: &dyn PrimaryVault,
    write: &HeadWrite,
    head: &HeadRow,
) -> Result<(), SdkError> {
    let publisher = decode_ref(&head.publisher_ref)?;
    if publisher != write.publisher_ref || publisher != write.local_ref {
        return Err(SdkError::PairingCode("PrimaryRequired"));
    }
    let account = load_data_account(root, &write.account_id, write.now)?;
    let current_hash = object_hash(account.record())?;
    if account.authority_blocked()
        || (current_hash != head.base_record_hash && current_hash != head.candidate_hash)
    {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    if account.local_device_id()? != publisher.device_id
        || account.record().body.master_certificate.body.primary_device_ref != publisher
        || vault.load_primary(account.primary_vault_ref())?.public_key()
            != account.record().body.master_certificate.body.self_signing_public_key
    {
        return Err(SdkError::PairingCode("PrimaryRequired"));
    }
    Ok(())
}

fn submit_and_ack(
    db: &Mutex<AccountDb>,
    root: &Path,
    vault: &dyn PrimaryVault,
    write: &HeadWrite,
    persist: &dyn NodeHeadPersist,
    mut head: HeadRow,
) -> Result<PublishedHead, SdkError> {
    let publication = decode_candidate(&head.candidate)?;
    let stored = decode_ref(&head.publisher_ref)?;
    if stored != write.publisher_ref || stored != write.local_ref {
        return Err(SdkError::PairingCode("PrimaryRequired"));
    }
    if head.state != "acknowledged" {
        {
            let _lock = super::activate::authority_lock(root, &write.account_id)?;
            head = journal(db, |db| db.pairing_head()?.ok_or(SdkError::PairingField("state")))?;
            if head.state == "prepared" {
                validate_head_advance("prepared", "submitted", &stored, &write.local_ref)?;
                head.state = "submitted".into();
                journal(db, |db| {
                    db.commit_pairing_head(&head)?;
                    Ok(())
                })?;
            }
        }
        if head.state != "acknowledged" {
            // No authority file lock (and no SQLite transaction) spans this call.
            let published = persist.persist_head(&publication, write.now)?;
            if published != head.candidate_hash {
                return Err(SdkError::PairingCode("HeadChanged"));
            }
            let _lock = super::activate::authority_lock(root, &write.account_id)?;
            validate_head_advance("submitted", "acknowledged", &stored, &write.local_ref)?;
            head.ack = Some(ack_bytes(&published, publication.record.body.device_set_epoch)?);
            head.state = "acknowledged".into();
            journal(db, |db| {
                db.commit_pairing_head(&head)?;
                Ok(())
            })?;
        }
    }
    journal(db, |db| {
        super::activate::refresh_authority(
            root,
            db,
            vault,
            &write.account_id,
            &CustodyAuthority { publication: publication.clone(), custodian_publication: None },
            write.now,
        )
    })?;
    Ok(PublishedHead {
        record_hash: head.candidate_hash,
        epoch: publication.record.body.device_set_epoch,
        record: publication.record,
    })
}

fn retire_acknowledged(
    db: &AccountDb,
    write: &HeadWrite,
    record_hash: &str,
    finished_at: u64,
) -> Result<(), SdkError> {
    let adoption = db.pairing_adoption()?.ok_or(SdkError::PairingField("record_hash"))?;
    if adoption.operation_id != write.operation_id || adoption.record_hash != record_hash {
        return Err(SdkError::PairingField("record_hash"));
    }
    if write.kind != HeadKind::Enroll {
        db.commit_ordinary_head_cleanup(&adoption)?;
        return Ok(());
    }
    let invitation_id =
        write.invitation_id.clone().ok_or(SdkError::PairingField("invitation_id"))?;
    db.commit_pairing_adoption_cleanup(
        &adoption,
        &TerminalRow {
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
        },
    )?;
    Ok(())
}

fn prepared_head_row(
    account: &crate::custody::BornAccount,
    write: &HeadWrite,
    record: &Envelope<DeviceSet>,
) -> Result<HeadRow, SdkError> {
    let recipient_ref = if write.kind == HeadKind::Enroll {
        Some(ref_bytes(
            write.recipient_ref.as_ref().ok_or(SdkError::PairingField("recipient_ref"))?,
        )?)
    } else {
        None
    };
    let revoked_ref = if write.kind == HeadKind::Revoke {
        let id = write.revoked_id.as_deref().ok_or(SdkError::PairingField("revoked_ref"))?;
        let entry = account
            .record()
            .body
            .devices
            .iter()
            .find(|device| device.device_id == id)
            .ok_or(SdkError::PairingField("revoked_ref"))?;
        Some(ref_bytes(&DeviceRef {
            account_anchor: account.record().body.account_anchor.clone(),
            device_id: id.into(),
            device_epoch: entry.device_epoch,
        })?)
    } else {
        None
    };
    Ok(HeadRow {
        account_id: write.account_id.clone(),
        operation_id: write.operation_id.clone(),
        invitation_id: write.invitation_id.clone(),
        generation: write.generation,
        kind: kind_label(write.kind).into(),
        base_record_hash: object_hash(account.record())?,
        base_epoch: account.record().body.device_set_epoch,
        publisher_ref: ref_bytes(&write.publisher_ref)?,
        candidate: canonical_json_bytes(&Publication {
            record: record.clone(),
            compacted_ids: None,
        })?,
        candidate_hash: object_hash(record)?,
        state: "prepared".into(),
        ack: None,
        recipient_ref,
        revoked_ref,
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

fn kind_label(kind: HeadKind) -> &'static str {
    match kind {
        HeadKind::Enroll => "enroll",
        HeadKind::Profile => "head_update",
        HeadKind::Revoke => "revoke",
    }
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

#[cfg(test)]
#[path = "publication/tests.rs"]
mod tests;
