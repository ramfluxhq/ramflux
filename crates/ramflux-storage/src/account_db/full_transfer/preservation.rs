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
        self.read_preservation(
            previous,
            candidate,
            now,
            ApprovalTime::BeforePublish,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
        )
    }
    // An expired local approval cannot undo an independently confirmed native
    // publication. This is exact submitted-candidate reconciliation, never signing.
    pub(super) fn retained_source_after_native_ack(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        now: u64,
    ) -> Result<Option<Envelope<PreservationFull>>, StorageError> {
        self.read_preservation(
            previous,
            candidate,
            now,
            ApprovalTime::AfterNativeAck,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
        )
    }
    pub(super) fn source_published_candidate_hash(&self) -> Result<String, StorageError> {
        let (base,candidate):(Vec<u8>,Vec<u8>)=self.connection.query_row("SELECT base_record,candidate FROM full_preservation WHERE singleton=1 AND length(base_record)<=524288 AND length(candidate)<=524288",[],|row|Ok((row.get(0)?,row.get(1)?)))?;
        let base: Envelope<DeviceSet> = ramflux_protocol::parse_i_json(&base)?;
        let candidate: Envelope<DeviceSet> = ramflux_protocol::parse_i_json(&candidate)?;
        // Historical signed input is an integrity operand after publication, never
        // a renewed wire lease or permission to construct another candidate.
        let when = self.reference().lease_expires_at.0.saturating_sub(1);
        self.retained_source_after_native_ack(&base, &candidate, when)?.ok_or_else(wrong)?;
        Ok(object_hash(&candidate)?)
    }
    fn read_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        now: u64,
        validity: ApprovalTime,
        role: ramflux_crypto::custody::pairing::PairingRole,
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
        self.check_preservation(previous, candidate, &signed, now, (role, validity))?;
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
        self.retain_preservation_bytes(previous, candidate, signed, now)
    }
    /// Retain B's independently checked exact source signature against B's own duplex.
    /// This grants no native publication receipt or authority to sign.
    /// # Errors
    /// Refuses a foreign base/candidate/source key, wrong local role or application roots.
    pub fn retain_destination_full_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        signed: &Envelope<PreservationFull>,
        now: u64,
    ) -> Result<(), StorageError> {
        self.check_preservation(
            previous,
            candidate,
            signed,
            now,
            (ramflux_crypto::custody::pairing::PairingRole::Responder, ApprovalTime::BeforePublish),
        )?;
        self.retain_preservation_bytes(previous, candidate, signed, now)
    }
    /// Read B's retained source approval only after separately obtaining its own native J6.
    /// Expired approval cannot undo a publication already verified by the native owner.
    /// # Errors
    /// Refuses missing/mismatched local proof or a signature from another source key.
    pub fn retained_destination_after_native_ack(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        now: u64,
    ) -> Result<Option<Envelope<PreservationFull>>, StorageError> {
        self.read_preservation(
            previous,
            candidate,
            now,
            ApprovalTime::AfterNativeAck,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
        )
    }
    /// Require B's exact retained source signature in addition to a caller's own J6.
    /// This reads historical data proof only and never restores signing approval.
    /// # Errors
    /// Refuses missing/changed candidate bytes, wrong role or corrupt source/duplex proof.
    pub fn require_destination_preservation_after_native_ack(
        &self,
        candidate: &Envelope<DeviceSet>,
        now: u64,
    ) -> Result<(), StorageError> {
        self.require_io()?;
        let old:Vec<u8>=self.connection.query_row("SELECT base_record FROM full_preservation WHERE singleton=1 AND length(base_record)<=524288",[],|row|row.get(0))?;
        let previous: Envelope<DeviceSet> = ramflux_protocol::custody::decode(&old, 524_288)?;
        self.retained_destination_after_native_ack(&previous, candidate, now)?.ok_or_else(wrong)?;
        Ok(())
    }
    /// Inspect an expired original statement before an explicit new attended affirmation.
    /// This grants no signing capability and never treats a corrupt statement as absent.
    /// # Errors
    /// Refuses wrong base/candidate/role, malformed signatures or changed duplex operands.
    pub fn has_expired_source_full_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        now: u64,
    ) -> Result<bool, StorageError> {
        self.require_io()?;
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT bytes FROM full_preservation WHERE singleton=1 AND length(bytes)<=11700",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(bytes) = bytes else { return Ok(false) };
        let prior: Envelope<PreservationFull> = ramflux_protocol::parse_i_json(&bytes)?;
        if prior.body.expires_at > now {
            return Ok(false);
        }
        self.read_preservation(
            previous,
            candidate,
            prior.body.expires_at.saturating_sub(1),
            ApprovalTime::BeforePublish,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
        )?
        .ok_or_else(wrong)?;
        self.verified_duplex(now)?;
        Ok(true)
    }
    fn replace_expired_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        signed: &Envelope<PreservationFull>,
        now: u64,
    ) -> Result<(), StorageError> {
        let prior: Option<(Vec<u8>,Vec<u8>,Vec<u8>)> = self.connection.query_row(
            "SELECT base_record,candidate,bytes FROM full_preservation WHERE singleton=1 AND length(base_record)<=524288 AND length(candidate)<=524288 AND length(bytes)<=11700",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional()?;
        let Some((base, proposed, bytes)) = prior else { return Ok(()) };
        if bytes == canonical_json_bytes(signed)? {
            return Ok(());
        }
        let prior: Envelope<PreservationFull> = ramflux_protocol::parse_i_json(&bytes)?;
        let mut body = prior.body.clone();
        body.expires_at = signed.body.expires_at;
        if base != canonical_json_bytes(previous)?
            || proposed != canonical_json_bytes(candidate)?
            || prior.body.expires_at > now
            || signed.body.expires_at <= prior.body.expires_at
            || canonical_json_bytes(&body)? != canonical_json_bytes(&signed.body)?
            || canonical_json_bytes(&prior)? != bytes
        {
            return Err(wrong());
        }
        self.check_preservation(
            previous,
            candidate,
            &prior,
            prior.body.expires_at.saturating_sub(1),
            (self.resume_record()?.role, ApprovalTime::BeforePublish),
        )?;
        let changed = self.connection.execute(
            "UPDATE full_preservation SET bytes=?1 WHERE singleton=1 AND bytes=?2",
            params![canonical_json_bytes(signed)?, bytes],
        )?;
        if changed != 1 {
            return Err(wrong());
        }
        Ok(())
    }
    fn retain_preservation_bytes(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        signed: &Envelope<PreservationFull>,
        now: u64,
    ) -> Result<(), StorageError> {
        let old = canonical_json_bytes(previous)?;
        let candidate_bytes = canonical_json_bytes(candidate)?;
        let bytes = canonical_json_bytes(signed)?;
        if old.len() > 524_288
            || candidate_bytes.len() > 524_288
            || bytes.len() > PreservationFull::LIMIT
        {
            return Err(wrong());
        }
        self.replace_expired_preservation(previous, candidate, signed, now)?;
        let changed=self.connection.execute("INSERT INTO full_preservation VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET bytes=excluded.bytes WHERE full_preservation.base_record=excluded.base_record AND full_preservation.candidate=excluded.candidate AND full_preservation.bytes=excluded.bytes",params![old,candidate_bytes,bytes])?;
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
        self.check_preservation(
            previous,
            candidate,
            signed,
            now,
            (ramflux_crypto::custody::pairing::PairingRole::Initiator, validity),
        )
    }
    fn check_preservation(
        &self,
        previous: &Envelope<DeviceSet>,
        candidate: &Envelope<DeviceSet>,
        signed: &Envelope<PreservationFull>,
        now: u64,
        (role, validity): (ramflux_crypto::custody::pairing::PairingRole, ApprovalTime),
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
        let bound_hash = self.full_prepublication_record_hash()?;
        body.validate().map_err(|_| wrong())?;
        if record.role != role
            || previous.body.master_certificate.body.primary_device_ref != record.grant.source_ref
            || object_hash(previous)? != bound_hash
            || body.recipient_mode != context.initiator.common.recipient_mode
            || body.transfer_id != record.transfer_id
            || body.transcript_hash != encode_base64url(record.th)
            || body.old_record_hash != bound_hash
            || body.new_record_hash != object_hash(candidate)?
            || body.destination_ref != record.grant.destination_ref
            || body.manifest_chain_hash != proof.manifest_chain_hash()
            || body.data_verified_hash != proof.data_verified_hash()
            || body.target_restrictions_root != proof.target_restrictions_root()
            || (matches!(validity, ApprovalTime::BeforePublish)
                && (body.expires_at <= now || body.expires_at > now.saturating_add(300)))
            || body.expires_at > proof.expires_at()
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
