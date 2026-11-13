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
    pub(in crate::account_db) reference: String,
    pub(in crate::account_db) public_key: String,
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
        self.require_full_stage_unlock()?;
        let _ = now;
        super::stage::raw32(operation)?;
        super::stage::raw32(hash)?;
        let (source, owner): (Vec<u8>, FullSourcePrimaryOwner) = self.connection.query_row(
            "SELECT source_ref,primary_ref,old_self_key FROM pairing_source_cleanup WHERE account_id=?1 AND operation_id=?2 AND record_hash=?3",
            rusqlite::params![self.local_account_id,operation,hash],
            |row| Ok((row.get(0)?, FullSourcePrimaryOwner {reference:row.get(1)?,public_key:row.get(2)?})),
        )?;
        super::stage::raw32(&owner.reference)?;
        super::stage::raw32(&owner.public_key)?;
        let source: ramflux_protocol::custody::DeviceRef = ramflux_protocol::parse_i_json(&source)?;
        if let Some(adoption) = self.pairing_adoption()? {
            let local: ramflux_protocol::custody::DeviceRef =
                ramflux_protocol::parse_i_json(&adoption.local_ref)?;
            if local != source {
                return Err(wrong());
            }
        }
        Ok(owner)
    }
}
