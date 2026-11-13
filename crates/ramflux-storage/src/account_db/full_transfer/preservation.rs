// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact signed source preservation retention. No signer or restored local affirmation.
use super::FullTransferStage;
use crate::StorageError;
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{
        DeviceSet, Envelope, object_hash,
        pairing::{PairingWire, full_transfer::PreservationFull},
    },
    encode_base64url,
};
use rusqlite::{OptionalExtension as _, params};
pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS full_preservation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),base_record BLOB NOT NULL,candidate BLOB NOT NULL,bytes BLOB NOT NULL);";
#[derive(Clone, Copy)]
enum ApprovalTime {
    BeforePublish,
    AfterNativeAck,
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl FullTransferStage<'_> {
    /// Read only an existing exact statement; this creates no signature or affirmation.
    /// # Errors
    /// Refuses another candidate/base, corrupt/expired bytes or missing current duplex.
    pub fn retained_source_full_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        now: u64,
    ) -> Result<Option<Envelope<PreservationFull>>, StorageError> {
        self.read_source_preservation(previous, candidate, now, ApprovalTime::BeforePublish)
    }
    // An expired local approval cannot undo an independently confirmed native
    // publication. This is exact submitted-candidate reconciliation, never signing.
    pub(super) fn retained_source_after_native_ack(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        now: u64,
    ) -> Result<Option<Envelope<PreservationFull>>, StorageError> {
        self.read_source_preservation(previous, candidate, now, ApprovalTime::AfterNativeAck)
    }
    fn read_source_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        now: u64,
        validity: ApprovalTime,
    ) -> Result<Option<Envelope<PreservationFull>>, StorageError> {
        self.require_io()?;
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT base_record,candidate,bytes FROM full_preservation WHERE singleton=1 AND length(base_record)<=524288 AND length(candidate)<=524288 AND length(bytes)<=11700",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((old, proposed, bytes)) = row else { return Ok(None) };
        if old != canonical_json_bytes(previous)?
            || proposed != canonical_json_bytes(candidate)?
            || bytes.len() > PreservationFull::LIMIT
        {
            return Err(wrong());
        }
        let signed: Envelope<PreservationFull> = ramflux_protocol::parse_i_json(&bytes)?;
        if canonical_json_bytes(&signed)? != bytes {
            return Err(wrong());
        }
        self.check_source_preservation(previous, candidate, &signed, now, validity)?;
        Ok(Some(signed))
    }
    /// Fsync A's exact signed preservation before releasing `TransferReadyFull`.
    /// Repeated identical writes are idempotent. A different candidate or statement
    /// cannot replace the saved approval. Reading this row never creates a signer.
    /// # Errors
    /// Refuses B, missing application/duplex, wrong original native key/context,
    /// expired approval or a replacement of a possibly released candidate.
    pub fn retain_source_full_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        signed: &Envelope<PreservationFull>,
        now: u64,
    ) -> Result<(), StorageError> {
        self.check_source_preservation(
            previous,
            candidate,
            signed,
            now,
            ApprovalTime::BeforePublish,
        )?;
        let old = canonical_json_bytes(previous)?;
        let candidate = canonical_json_bytes(candidate)?;
        let bytes = canonical_json_bytes(signed)?;
        if old.len() > 524_288 || candidate.len() > 524_288 || bytes.len() > PreservationFull::LIMIT
        {
            return Err(wrong());
        }
        let changed=self.connection.execute("INSERT INTO full_preservation VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET bytes=excluded.bytes WHERE full_preservation.base_record=excluded.base_record AND full_preservation.candidate=excluded.candidate AND full_preservation.bytes=excluded.bytes",params![old,candidate,bytes])?;
        if changed != 1 {
            return Err(wrong());
        }
        super::stage::sync_stage(&self.directory)?;
        self.require_io()
    }
    fn check_source_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        signed: &Envelope<PreservationFull>,
        now: u64,
        validity: ApprovalTime,
    ) -> Result<(), StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        let proof = self.verified_duplex(now)?;
        let context =
            ramflux_protocol::custody::pairing::context_v3::TranscriptV3::from_wire_bytes(
                &record.transcript,
            )
            .map_err(|_| wrong())?;
        let body = &signed.body;
        body.validate().map_err(|_| wrong())?;
        if record.role != ramflux_crypto::custody::pairing::PairingRole::Initiator
            || previous.body.master_certificate.body.primary_device_ref != record.grant.source_ref
            || object_hash(previous)? != record.base_record_hash
            || body.recipient_mode != context.initiator.common.recipient_mode
            || body.transfer_id != record.transfer_id
            || body.transcript_hash != encode_base64url(record.th)
            || body.old_record_hash != record.base_record_hash
            || body.new_record_hash != object_hash(candidate)?
            || body.destination_ref != record.grant.destination_ref
            || body.manifest_chain_hash != proof.manifest_chain_hash()
            || body.data_verified_hash != proof.data_verified_hash()
            || body.target_restrictions_root != proof.target_restrictions_root()
            || (matches!(validity, ApprovalTime::BeforePublish) && body.expires_at <= now)
            || body.expires_at > proof.expires_at()
            || body.expires_at > now.saturating_add(300)
        {
            return Err(wrong());
        }
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::custody::signing_bytes(&body.schema, body)?,
            &signed.signature,
            &previous.body.master_certificate.body.self_signing_public_key,
        )
        .map_err(|_| wrong())?;
        Ok(())
    }
}
