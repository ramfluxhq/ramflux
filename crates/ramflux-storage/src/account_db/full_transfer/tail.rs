// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source J6 binds the exact saved candidate and one immutable tail opportunity.
use super::FullTransferStage;
use super::tail_capture::FullSourceTailCut;
use crate::{HeadRow, StorageError};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::pairing::PairingWire,
    custody::{DeviceSet, Envelope, Publication},
    parse_i_json,
};
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl FullTransferStage<'_> {
    /// Commit this source's independently checked exact J6 and pin tail content
    /// under the same all-writer fence. Bulk encrypted copying runs after this call.
    /// Caller must obtain `head` from its own verified native publication/query owner;
    /// a relay ACK is insufficient. This data primitive grants no native authority.
    /// # Errors
    /// Refuses B, changed/cancelled input/candidate, unsigned preservation, an already
    /// reserved tail (never recut), stale writers or a busy ten-second writer budget.
    pub fn commit_source_ack_and_pin_tail(
        &self,
        head: &HeadRow,
        snapshot_id: &str,
        now: u64,
    ) -> Result<FullSourceTailCut, StorageError> {
        self.require_io()?;
        crate::account_db::pairing::journal::decode_head(head)?;
        let record = self.resume_record()?;
        let context =
            ramflux_protocol::custody::pairing::context_v3::TranscriptV3::from_wire_bytes(
                &record.transcript,
            )
            .map_err(|_| wrong())?;
        let reference = self.reference();
        let live = self
            .db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == head.operation_id)
            .ok_or_else(wrong)?;
        let linked =
            crate::FullStageReference::from_wire_bytes(live.context.as_deref().ok_or_else(wrong)?)
                .map_err(|_| wrong())?;
        if record.role != ramflux_crypto::custody::pairing::PairingRole::Initiator
            || head.account_id != self.db.local_account_id
            || live.role != "initiator"
            || live.phase != "submitted"
            || linked != *reference
            || head.invitation_id.as_deref() != Some(live.invitation_id.as_str())
            || live.invitation_id != context.initiator.common.invitation_id
            || head.base_epoch != context.initiator.common.device_set_epoch
            || head.generation != live.generation
            || head.base_epoch != live.base_epoch
            || head.base_record_hash != record.base_record_hash
            || head.publisher_ref != canonical_json_bytes(&record.grant.source_ref)?
            || head.recipient_ref.as_deref()
                != Some(canonical_json_bytes(&record.grant.destination_ref)?.as_slice())
        {
            return Err(wrong());
        }
        let candidate: Publication = parse_i_json(&head.candidate)?;
        if candidate.record.body.account_anchor != record.grant.source_ref.account_anchor
            || candidate.record.body.master_certificate.body.primary_device_ref
                != record.grant.destination_ref
        {
            return Err(wrong());
        }
        let old: Vec<u8> = self.connection.query_row(
            "SELECT base_record FROM full_preservation WHERE singleton=1 AND length(base_record)<=524288",
            [],
            |row| row.get(0),
        )?;
        if old.len() > 524_288 {
            return Err(wrong());
        }
        let previous: Envelope<DeviceSet> = parse_i_json(&old)?;
        if self.retained_source_after_native_ack(&previous, &candidate.record, now)?.is_none() {
            return Err(wrong());
        }
        let cut = self.db.commit_full_ack_tail(head, &reference.stage_id, snapshot_id)?;
        Ok(FullSourceTailCut {
            cut,
            operation: head.operation_id.clone(),
            stage: reference.stage_id.clone(),
            snapshot: snapshot_id.into(),
            hash: head.candidate_hash.clone(),
        })
    }
}
