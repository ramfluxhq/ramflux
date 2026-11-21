// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-only native reconciliation can retire a published primary without reviving DATA.
use super::{LocalPairingParticipant, custody, wrong};
use crate::{
    SdkError,
    custody::pairing::{Installation, PairingAuthorityQuery},
};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{CustodyAuthority, Publication, object_hash},
    parse_i_json,
};
use ramflux_storage::{AccountDb, FullLocalUnlockGuard, HeadRow};
use std::{path::PathBuf, sync::Arc};
/// Public query work from the actual retained source. No publisher, key or approval provider.
pub struct FullSourcePublicationQuery {
    root: PathBuf,
    account: String,
    head: HeadRow,
    unlock: FullLocalUnlockGuard,
    query: Arc<dyn PairingAuthorityQuery>,
}
/// Own native evidence can finish local source retirement only, never restore a data epoch.
pub struct FullSourceNativeObservation {
    work: FullSourcePublicationQuery,
    authority: CustodyAuthority,
}
impl FullSourcePublicationQuery {
    /// Query outside the frontend loan. Stale/missing evidence never authorizes deletion.
    /// # Errors
    /// Refuses a dead original unlock or invalid native publication.
    pub fn observe(self) -> Result<FullSourceNativeObservation, SdkError> {
        self.unlock.require_unlocked()?;
        let candidate: Publication = parse_i_json(&self.head.candidate)?;
        let authority = self.query.current_authority(&candidate.record.body.account_anchor)?;
        self.unlock.require_unlocked()?;
        ramflux_crypto::custody::verify_publication(&authority, custody::network_now()?)?;
        Ok(FullSourceNativeObservation { work: self, authority })
    }
}
impl FullSourceNativeObservation {
    /// Acknowledge the exact own query, permanently decline DATA/tail and retain cleanup proof.
    /// # Errors
    /// Refuses another writer/root/head, stale evidence or missing positive source ownership.
    pub fn acknowledge(&self, db: &AccountDb) -> Result<(), SdkError> {
        self.work.unlock.require_unlocked()?;
        let selected =
            ramflux_storage::AccountIndex::open(&self.work.root)?.account(&self.work.account)?;
        if db.local_account_id != self.work.account
            || std::fs::canonicalize(&db.path)?
                != std::fs::canonicalize(self.work.root.join(selected.db_relative_path))?
        {
            return Err(wrong());
        }
        let now = custody::network_now()?;
        let verified = ramflux_crypto::custody::verify_publication(&self.authority, now)?;
        db.observe_full_install_native_head(&self.work.head.operation_id, &verified, now)?;
        if matches!(
            custody::accept_publication(&self.work.root, &self.work.account, &self.authority, now)?,
            ramflux_crypto::custody::PinOutcome::Fenced(_)
        ) {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        if object_hash(verified.envelope())? != self.work.head.candidate_hash
            || canonical_json_bytes(&self.authority.publication)? != self.work.head.candidate
        {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        db.reconcile_full_source_retirement(&self.work.head, &verified, now)?;
        Ok(())
    }
    /// Retire only the positively owned old management key after the exact local J6.
    /// # Errors
    /// Refuses changed native/local owners. Cleanup failures remain independently retryable.
    pub fn retire_source(
        &self,
        local: &Installation<'_>,
    ) -> Result<super::FullSourceRetirementOutcome, SdkError> {
        self.work.unlock.require_unlocked()?;
        super::retirement::install(&self.work.root, &self.work.head, &self.authority, local)
    }
}
impl LocalPairingParticipant {
    /// Open read-only reconciliation after source restart without SAS or phrase approval.
    /// # Errors
    /// Refuses another source/link or an absent/malformed submitted candidate.
    pub fn full_source_publication_query(
        &self,
        operation: &str,
    ) -> Result<FullSourcePublicationQuery, SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.full_selected_db(db, None)?;
        let head = db.pairing_head()?.ok_or_else(wrong)?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if head.operation_id != operation
            || head.kind != "transfer"
            || live.role != "initiator"
            || live.generation != head.generation
            || live.full_stage_reference()?.is_none()
            || !matches!(head.state.as_str(), "submitted" | "acknowledged")
        {
            return Err(wrong());
        }
        Ok(FullSourcePublicationQuery {
            root: self.root.clone(),
            account: self.account_id.clone(),
            head,
            unlock: db.full_local_unlock_guard()?,
            query: self.query.clone(),
        })
    }
}
