// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! B's own native-query receipt can finish one retained install, never restore pairing approval.
use super::{LocalPairingParticipant, custody, wrong};
use crate::{
    SdkError,
    custody::pairing::{PairingAuthorityQuery, install_store},
};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{CustodyAuthority, Publication, object_hash},
    parse_i_json,
};
use ramflux_storage::{AccountDb, FullLocalUnlockGuard, HeadRow};
use std::{path::PathBuf, sync::Arc};

/// Public exact candidate query after handing back B's actual data loan.
/// It owns no participant, database/key, vault provider, phrase or signer.
pub struct FullRecipientPublicationQuery {
    root: PathBuf,
    account: String,
    head: HeadRow,
    unlock: FullLocalUnlockGuard,
    query: Arc<dyn PairingAuthorityQuery>,
}
/// B independently observed native authority; only exact local acknowledgement can install it.
pub struct FullRecipientNativeObservation {
    work: FullRecipientPublicationQuery,
    authority: CustodyAuthority,
}
impl FullRecipientPublicationQuery {
    /// Obtain native evidence without any frontend database loan. Missing/stale evidence
    /// preserves the candidate, primary ref and closed ordinary-network latch.
    /// # Errors
    /// Refuses dead original unlock or unverifiable native authority. Exact-candidate and
    /// durable rollback-floor checks run on the subsequent short local acknowledgement.
    pub fn observe(self) -> Result<FullRecipientNativeObservation, SdkError> {
        self.unlock.require_unlocked()?;
        let saved: Publication = parse_i_json(&self.head.candidate)?;
        let authority = self.query.current_authority(&saved.record.body.account_anchor)?;
        self.unlock.require_unlocked()?;
        ramflux_crypto::custody::verify_publication(&authority, custody::network_now()?)?;
        Ok(FullRecipientNativeObservation { work: self, authority })
    }
}
impl FullRecipientNativeObservation {
    #[must_use]
    pub const fn authority(&self) -> &CustodyAuthority {
        &self.authority
    }
    /// Durably acknowledge only the exact query result through a fresh short B loan.
    /// Terminal data state remains closed; G1/G2 use the separate installation-only owner.
    /// # Errors
    /// Refuses another writer/root/candidate, replaced pending key owner or a stale generation.
    pub fn acknowledge(&self, db: &AccountDb) -> Result<(), SdkError> {
        self.work.unlock.require_unlocked()?;
        let index = ramflux_storage::AccountIndex::open(&self.work.root)?;
        let selected = index.account(&self.work.account)?;
        if db.local_account_id != self.work.account
            || std::fs::canonicalize(&db.path)?
                != std::fs::canonicalize(self.work.root.join(selected.db_relative_path))?
        {
            return Err(wrong());
        }
        let now = custody::network_now()?;
        let verified = ramflux_crypto::custody::verify_publication(&self.authority, now)?;
        db.observe_full_install_native_head(&self.work.head.operation_id, &verified, now)?;
        if object_hash(verified.envelope())? != self.work.head.candidate_hash
            || canonical_json_bytes(&self.authority.publication)? != self.work.head.candidate
        {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        let mut head = db.pairing_head()?.ok_or_else(wrong)?;
        if head.operation_id != self.work.head.operation_id
            || head.generation != self.work.head.generation
            || head.kind != "transfer"
            || head.candidate != self.work.head.candidate
            || head.candidate_hash != self.work.head.candidate_hash
            || head.publisher_ref != self.work.head.publisher_ref
            || head.recipient_ref != self.work.head.recipient_ref
            || !matches!(head.state.as_str(), "prepared" | "acknowledged")
        {
            return Err(wrong());
        }
        let pending =
            install_store::read_pending(&self.work.root, &self.work.account, &head.operation_id)?
                .ok_or_else(wrong)?;
        if pending.record_hash.as_deref() != Some(head.candidate_hash.as_str())
            || pending.primary_vault_ref.is_none()
        {
            return Err(wrong());
        }
        head.state = "acknowledged".into();
        head.ack = Some(canonical_json_bytes(
            &serde_json::json!({"record_hash":head.candidate_hash,"device_set_epoch":self.authority.publication.record.body.device_set_epoch}),
        )?);
        db.commit_pairing_head(&head)?;
        Ok(())
    }
}
impl LocalPairingParticipant {
    /// Construct a read-only exact-candidate query from the actual retained B owners.
    /// This works after process restart and does not call the phrase/approval provider.
    /// # Errors
    /// Refuses a source/foreign account, absent candidate or changed positive local key owner.
    pub fn full_recipient_publication_query(
        &self,
        operation: &str,
    ) -> Result<FullRecipientPublicationQuery, SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.full_recipient_publication_query_with_db(db, operation)
    }
    pub(crate) fn full_recipient_publication_query_with_db(
        &self,
        db: &AccountDb,
        operation: &str,
    ) -> Result<FullRecipientPublicationQuery, SdkError> {
        self.full_selected_db(db, None)?;
        let head = db.pairing_head()?.ok_or_else(wrong)?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        let pending = install_store::read_pending(&self.root, &self.account_id, operation)?
            .ok_or_else(wrong)?;
        let publication: Publication = parse_i_json(&head.candidate)?;
        if live.role != "responder"
            || live.generation != head.generation
            || live.full_stage_reference()?.is_none()
            || head.operation_id != operation
            || head.kind != "transfer"
            || !matches!(head.state.as_str(), "prepared" | "acknowledged")
            || pending.install_purpose != "transfer_destination"
            || pending.record_hash.as_deref() != Some(head.candidate_hash.as_str())
            || pending.primary_vault_ref.is_none()
            || pending.account_id != self.account_id
            || publication.record.body.master_certificate.body.primary_device_ref
                != pending.recipient_ref
            || head.recipient_ref.as_deref()
                != Some(canonical_json_bytes(&pending.recipient_ref)?.as_slice())
        {
            return Err(wrong());
        }
        Ok(FullRecipientPublicationQuery {
            root: self.root.clone(),
            account: self.account_id.clone(),
            head,
            unlock: db.full_local_unlock_guard()?,
            query: self.query.clone(),
        })
    }
}
