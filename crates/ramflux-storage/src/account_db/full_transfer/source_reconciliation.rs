// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact source retirement after cancellation never restores a data/tail opportunity.
use crate::{AccountDb, HeadRow, StorageError};
use ramflux_crypto::custody::{VerifiedRecord, pairing::PairingRole};
use ramflux_protocol::{canonical_json_bytes, custody::Publication, parse_i_json};
fn pending() -> StorageError {
    StorageError::PairingField("PublicationPending")
}
impl AccountDb {
    /// Record this source's own verified native floor and exact J6 for retirement only.
    /// The actual J6 cut is pinned under the writer fence and immediately declined;
    /// its row is abandoned, DATA stays closed, and no resume/signing surface escapes.
    /// # Errors
    /// Refuses another head/source, stale native evidence or missing retained preservation.
    pub fn reconcile_full_source_retirement(
        &self,
        expected: &HeadRow,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<(), StorageError> {
        self.require_full_stage_unlock()?;
        let mut head = self.pairing_head()?.ok_or_else(pending)?;
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == expected.operation_id)
            .ok_or_else(pending)?;
        if head.operation_id != expected.operation_id
            || head.kind != "transfer"
            || head.candidate != expected.candidate
            || head.candidate_hash != expected.candidate_hash
            || head.publisher_ref != expected.publisher_ref
            || head.recipient_ref != expected.recipient_ref
            || head.generation != expected.generation
            || live.generation != head.generation
            || live.role != "initiator"
            || !matches!(head.state.as_str(), "submitted" | "acknowledged")
        {
            return Err(pending());
        }
        let reference = live.full_stage_reference()?.ok_or_else(pending)?;
        let mut stage =
            self.open_full_stage_reference_inner(reference, PairingRole::Initiator, now, true)?;
        stage.observe_full_native_head(current)?; // Even a nonmatching head advances the job floor.
        let candidate: Publication = parse_i_json(&head.candidate)?;
        if canonical_json_bytes(current.envelope())? != canonical_json_bytes(&candidate.record)?
            || stage.source_published_candidate_hash()? != head.candidate_hash
        {
            return Err(pending());
        }
        let record = stage.resume_record()?;
        if head.base_record_hash != stage.full_prepublication_record_hash()?
            || head.base_epoch != stage.full_prepublication_record_epoch()?
            || head.publisher_ref != canonical_json_bytes(&record.grant.source_ref)?
            || head.recipient_ref.as_deref()
                != Some(canonical_json_bytes(&record.grant.destination_ref)?.as_slice())
            || current.envelope().body.master_certificate.body.primary_device_ref
                != record.grant.destination_ref
            || stage.source_primary_owner()?.is_none()
        {
            return Err(pending());
        }
        stage.connection.execute(
            "INSERT INTO data_terminal VALUES(1,'cancelled') ON CONFLICT(singleton) DO NOTHING",
            [],
        )?;
        super::stage::sync_stage(&stage.directory)?;
        if head.state == "acknowledged" {
            // A repeated receipt cannot recapture or reopen the declined cut.
            let exists: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3 AND record_hash=?4)",rusqlite::params![self.local_account_id,head.operation_id,stage.reference().stage_id,head.candidate_hash], |row| row.get(0))?;
            if !exists {
                return Err(pending());
            }
            self.connection.execute("UPDATE pairing_full_tail SET tail_status='abandoned' WHERE account_id=?1 AND operation_id=?2 AND tail_status='pending'", rusqlite::params![self.local_account_id, head.operation_id])?;
            return Ok(());
        }
        head.state = "acknowledged".into();
        head.ack = Some(canonical_json_bytes(
            &serde_json::json!({"record_hash":head.candidate_hash,"device_set_epoch":current.envelope().body.device_set_epoch}),
        )?);
        let snapshot =
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32().map_err(|_| pending())?);
        let owner = stage.source_primary_owner()?.ok_or_else(pending)?;
        drop(self.commit_full_ack_tail(
            &head,
            &stage.reference().stage_id,
            &snapshot,
            true,
            &owner,
        )?);
        Ok(())
    }
}
