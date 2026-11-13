// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source submission owns public bytes and weak unlock liveness, never an account loan.
use super::{LocalPairingParticipant, custody, wrong};
use crate::{
    SdkError,
    custody::pairing::{NodeHeadPersist, PairingAuthorityQuery},
};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{CustodyAuthority, Publication, object_hash},
};
use ramflux_storage::{
    AccountDb, FullLocalUnlockGuard, FullSourceTailCut, FullStageIoCancel, FullStageReference,
    HeadRow,
};
use std::{path::PathBuf, sync::Arc};

/// Exact durable source submission, created only by an attended live coordinator.
/// There is no database, stage key, primary key or participant owner in this work item.
pub struct FullSourceSubmission {
    work: Arc<SubmissionWork>,
}
struct SubmissionWork {
    root: PathBuf,
    account: String,
    head: HeadRow,
    reference: FullStageReference,
    publication: Publication,
    approval_expires_at: u64,
    unlock: FullLocalUnlockGuard,
    cancelled: FullStageIoCancel,
    runtime: Arc<crate::custody::pairing::coordinator::FullRuntimeCancel>,
    persist: Arc<dyn NodeHeadPersist>,
    query: Arc<dyn PairingAuthorityQuery>,
}
/// Exact publication independently observed through A's own native query.
/// This receipt still needs the original local writer to commit J6 and pin the tail.
pub struct FullSourcePublished {
    submission: Arc<SubmissionWork>,
    authority: CustodyAuthority,
}
impl SubmissionWork {
    fn require_live(&self) -> Result<(), SdkError> {
        self.runtime.require_live()?;
        if self.cancelled.is_cancelled() {
            return Err(SdkError::PairingCode("Retired"));
        }
        self.unlock.require_unlocked()?;
        Ok(())
    }
}
impl FullSourceSubmission {
    /// Publish the saved candidate outside all database loans, then independently query it.
    /// A lost response leaves the durable submitted fence; retry never creates new keys.
    /// # Errors
    /// Refuses a dead original writer, expired unpublished approval, another native head
    /// or a persistence/query failure. A peer acknowledgement grants no publication proof.
    pub fn submit(&self) -> Result<FullSourcePublished, SdkError> {
        let work = &self.work;
        work.require_live()?;
        let anchor = &work.publication.record.body.account_anchor;
        let authority = work.query.current_authority(anchor)?;
        work.require_live()?;
        let now = custody::network_now()?;
        let verified = ramflux_crypto::custody::verify_publication(&authority, now)?;
        let current = object_hash(verified.envelope())?;
        if current != work.head.candidate_hash {
            if current != work.head.base_record_hash {
                return Err(SdkError::PairingCode("HeadChanged"));
            }
            if now >= work.approval_expires_at {
                return Err(SdkError::PairingCode("LeaseExpired"));
            }
            if work.persist.persist_head(&work.publication, now)? != work.head.candidate_hash {
                return Err(wrong());
            }
        }
        work.require_live()?;
        let authority = work.query.current_authority(anchor)?;
        work.require_live()?;
        let verified =
            ramflux_crypto::custody::verify_publication(&authority, custody::network_now()?)?;
        if object_hash(verified.envelope())? != work.head.candidate_hash
            || canonical_json_bytes(&authority.publication)?
                != canonical_json_bytes(&work.publication)?
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        Ok(FullSourcePublished { submission: self.work.clone(), authority })
    }
}
impl FullSourcePublished {
    #[must_use]
    pub const fn authority(&self) -> &CustodyAuthority {
        &self.authority
    }

    /// Commit local J6 and its one immutable tail read view under the account writer fence.
    /// Return the database loan before performing bulk private snapshot copying.
    /// # Errors
    /// Refuses another root/writer/stage, a changed submitted candidate or an existing cut.
    pub fn acknowledge(self, db: &AccountDb, now: u64) -> Result<FullSourceTailCut, SdkError> {
        let work = self.submission;
        work.require_live()?;
        let _local = work.runtime.local_work()?;
        if matches!(
            custody::accept_publication(&work.root, &work.account, &self.authority, now)?,
            ramflux_crypto::custody::PinOutcome::Fenced(_)
        ) {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        let selected = ramflux_storage::AccountIndex::open(&work.root)?.account(&work.account)?;
        if db.local_account_id != work.account
            || std::fs::canonicalize(&db.path)?
                != std::fs::canonicalize(work.root.join(selected.db_relative_path))?
        {
            return Err(wrong());
        }
        let mut stage = db.open_full_transfer_stage(
            &work.head.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            now,
        )?;
        stage.bind_local_io_cancellation(&work.cancelled)?;
        if stage.reference() != &work.reference {
            return Err(wrong());
        }
        let mut head = work.head.clone();
        head.state = "acknowledged".into();
        head.ack = Some(canonical_json_bytes(
            &serde_json::json!({"record_hash":head.candidate_hash,"device_set_epoch":self.authority.publication.record.body.device_set_epoch}),
        )?);
        let snapshot = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        Ok(stage.commit_source_ack_and_pin_tail(&head, &snapshot, now)?)
    }
}
impl LocalPairingParticipant {
    pub(crate) fn prepare_full_source_submission(
        &self,
        scope: (String, u64, [u8; 32]),
        publication: Publication,
        runtime: Arc<crate::custody::pairing::coordinator::FullRuntimeCancel>,
        cancelled: FullStageIoCancel,
    ) -> Result<FullSourceSubmission, SdkError> {
        let (operation, generation, th) = scope;
        let operation = operation.as_str();
        if cancelled.is_cancelled() {
            return Err(SdkError::PairingCode("Retired"));
        }
        // Fresh native verification and actual primary preservation finish before intent.
        // The coordinator checks original local confirmations before reaching this owner.
        let approval = self.preserve_full_candidate(operation, generation, th, &publication)?;
        runtime.require_live()?;
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.full_selected_db(db, Some(&publication.record.body.account_anchor))?;
        let stage = db.open_full_transfer_stage(
            operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            custody::network_now()?,
        )?;
        let record = stage.resume_record()?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if record.th != th || live.generation != generation || live.role != "initiator" {
            return Err(wrong());
        }
        let mut head = HeadRow {
            account_id: self.account_id.clone(),
            operation_id: operation.into(),
            invitation_id: Some(live.invitation_id),
            generation,
            kind: "transfer".into(),
            base_record_hash: record.base_record_hash,
            base_epoch: live.base_epoch,
            publisher_ref: canonical_json_bytes(&record.grant.source_ref)?,
            candidate: canonical_json_bytes(&publication)?,
            candidate_hash: object_hash(&publication.record)?,
            state: "prepared".into(),
            ack: None,
            recipient_ref: Some(canonical_json_bytes(&record.grant.destination_ref)?),
            revoked_ref: None,
            created_at: custody::network_now()?,
        };
        if let Some(saved) = db.pairing_head()? {
            // An existing submitted intent must be reconciled, not replaced by a fresh ceremony.
            if saved.operation_id != head.operation_id
                || saved.candidate != head.candidate
                || saved.state != "prepared"
            {
                return Err(SdkError::PairingCode("Busy"));
            }
            head = saved;
        } else {
            db.commit_pairing_head(&head)?;
        }
        let unlock = db.full_local_unlock_guard()?;
        head.state = "submitted".into();
        db.commit_pairing_head(&head)?;
        Ok(FullSourceSubmission {
            work: Arc::new(SubmissionWork {
                root: self.root.clone(),
                account: self.account_id.clone(),
                head,
                reference: stage.reference().clone(),
                publication,
                approval_expires_at: approval.body.expires_at,
                unlock,
                cancelled,
                runtime,
                persist: self.persist.clone(),
                query: self.query.clone(),
            }),
        })
    }
}
