// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable local old-primary ownership retained before any preservation artifact escapes.
use super::FullTransferStage;
use crate::StorageError;
use ramflux_protocol::custody::{DeviceSet, Envelope, object_hash};
use rusqlite::OptionalExtension as _;
pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS source_primary_owner(singleton INTEGER PRIMARY KEY CHECK(singleton=1),primary_ref TEXT NOT NULL CHECK(length(primary_ref)=43),old_self_key TEXT NOT NULL CHECK(length(old_self_key)=43));";
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
/// Local reference only. Never a signing key or authority/recovery credential.
pub struct FullSourcePrimaryOwner {
    reference: String,
    public_key: String,
}
impl FullSourcePrimaryOwner {
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}
impl FullTransferStage<'_> {
    /// Retain the source-local reference AFTER the SDK verifies its actual old primary key
    /// and BEFORE releasing a preservation signature. An existing different reference refuses
    /// the complete signing attempt; data input cannot replace a positive owner later.
    /// # Errors
    /// Refuses another source/base, malformed references or conflicting retained ownership.
    pub fn retain_source_primary_owner(
        &self,
        reference: &str,
        base: &Envelope<DeviceSet>,
    ) -> Result<(), StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        if record.role != ramflux_crypto::custody::pairing::PairingRole::Initiator
            || record.base_record_hash != object_hash(base).map_err(|_| wrong())?
            || record.grant.source_ref != base.body.master_certificate.body.primary_device_ref
        {
            return Err(wrong());
        }
        super::stage::raw32(reference)?;
        let public = base.body.master_certificate.body.self_signing_public_key.clone();
        super::stage::raw32(&public)?;
        self.connection.execute(
            "INSERT INTO source_primary_owner VALUES(1,?1,?2) ON CONFLICT(singleton) DO NOTHING",
            rusqlite::params![reference, public],
        )?;
        let exact: bool = self.connection.query_row(
            "SELECT primary_ref=?1 AND old_self_key=?2 FROM source_primary_owner WHERE singleton=1",
            rusqlite::params![reference, public],
            |row| row.get(0),
        )?;
        if !exact {
            return Err(wrong());
        }
        super::stage::sync_stage(&self.directory)
    }
    /// Read the source-only immutable reference; callers still require their own exact
    /// native publication and retained signed preservation before attempting cleanup.
    /// # Errors
    /// Refuses another role, malformed local metadata or unavailable unlock.
    pub fn source_primary_owner(&self) -> Result<Option<FullSourcePrimaryOwner>, StorageError> {
        self.require_io()?;
        if self.resume_record()?.role != ramflux_crypto::custody::pairing::PairingRole::Initiator {
            return Err(wrong());
        }
        let owner = self
            .connection
            .query_row(
                "SELECT primary_ref,old_self_key FROM source_primary_owner WHERE singleton=1",
                [],
                |row| {
                    Ok(FullSourcePrimaryOwner { reference: row.get(0)?, public_key: row.get(1)? })
                },
            )
            .optional()?;
        if let Some(owner) = &owner {
            super::stage::raw32(&owner.reference)?;
            super::stage::raw32(&owner.public_key)?;
        }
        Ok(owner)
    }
}

impl crate::AccountDb {
    /// Read only the immutable positive old-owner proof for an exact locally acknowledged
    /// source candidate. This is data evidence; the SDK separately verifies native authority.
    /// # Errors
    /// Refuses another source/link/candidate, missing J6 or conflicting retained ownership.
    pub fn full_source_retirement_owner(
        &self,
        operation: &str,
        hash: &str,
        now: u64,
    ) -> Result<FullSourcePrimaryOwner, StorageError> {
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if live.role != "initiator" {
            return Err(wrong());
        }
        if let Some(head) = self.pairing_head()? {
            if head.operation_id != operation
                || head.kind != "transfer"
                || head.state != "acknowledged"
                || head.candidate_hash != hash
            {
                return Err(wrong());
            }
        } else {
            let adoption = self.pairing_adoption()?.ok_or_else(wrong)?;
            if adoption.operation_id != operation
                || adoption.record_hash != hash
                || adoption.local_role != "secondary"
            {
                return Err(wrong());
            }
        }
        let stage = self.open_full_stage_reference_inner(
            live.full_stage_reference()?.ok_or_else(wrong)?,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            now,
            true,
        )?;
        if stage.source_published_candidate_hash()? != hash {
            return Err(wrong());
        }
        let owner = stage.source_primary_owner()?.ok_or_else(wrong)?;
        let bytes:Vec<u8>=stage.connection.query_row("SELECT base_record FROM full_preservation WHERE singleton=1 AND length(base_record)<=524288",[],|row|row.get(0))?;
        let base: Envelope<DeviceSet> = ramflux_protocol::parse_i_json(&bytes)?;
        if owner.public_key != base.body.master_certificate.body.self_signing_public_key {
            return Err(wrong());
        }
        Ok(owner)
    }
}
