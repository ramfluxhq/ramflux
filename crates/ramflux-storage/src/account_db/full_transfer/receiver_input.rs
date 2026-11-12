// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable input provenance only: no live writes, semantic-application bit or signed receipt.
use super::{FamilyRule, FullTransferStage};
use crate::{StorageError, database::Connection};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::RecordOp;
use rusqlite::params;
use zeroize::Zeroizing;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS receiver_scalar_input(manifest_hash TEXT PRIMARY KEY,source_ref TEXT NOT NULL,records INTEGER NOT NULL CHECK(records>=0),encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes>=0));
CREATE TABLE IF NOT EXISTS receiver_scalar_record(manifest_hash TEXT NOT NULL,source_ref TEXT NOT NULL,family TEXT NOT NULL,key TEXT NOT NULL COLLATE BINARY,record_offset INTEGER NOT NULL CHECK(record_offset>=0),encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes>0),absent INTEGER NOT NULL CHECK(absent IN(0,1)),PRIMARY KEY(manifest_hash,family,key));";

/// Counts of validated, durably indexed input. These are never semantic merge evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullScalarInputCounts {
    pub records: u64,
    pub encoded_bytes: u64,
}

struct PendingInput {
    connection: Connection,
    committed: bool,
}
impl Drop for PendingInput {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.connection.execute_batch("ROLLBACK");
        }
    }
}

impl FullTransferStage<'_> {
    /// Index the complete forward scalar input in the independently encrypted stage.
    /// Positions reference authenticated immutable slots; cell bodies are not copied into
    /// generic SQL values or accumulated in memory. The contribution owner comes only from
    /// the locally retained, original-source-signed manifest. Every retry revalidates input;
    /// partial/error attempts roll back all index rows, including an incomplete last record.
    /// No application rows, erasure generations, authority or `DataVerified` flags change.
    /// # Errors
    /// Refuses the source role, stale unlock, missing/corrupt slots, untyped declarations,
    /// malformed/order/count failures and any failed SQL commit or durable synchronization.
    pub fn index_forward_scalar_records(
        &self,
        hash: &str,
        rules: &[FamilyRule],
    ) -> Result<FullScalarInputCounts, StorageError> {
        self.db.require_full_stage_unlock()?;
        if self.resume_record()?.role != PairingRole::Responder {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let source = String::from_utf8(
            ramflux_protocol::canonical_json_bytes(
                &self.forward_manifest(hash)?.manifest.source_ref,
            )
            .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        let mut pending = PendingInput { connection: self.connection.clone(), committed: false };
        self.connection
            .execute("DELETE FROM receiver_scalar_record WHERE manifest_hash=?1", params![hash])?;
        self.connection
            .execute("DELETE FROM receiver_scalar_input WHERE manifest_hash=?1", params![hash])?;
        let mut counts = FullScalarInputCounts { records: 0, encoded_bytes: 0 };
        self.visit_forward_scalar_records(hash, rules, |header, offset, bytes| {
            self.db.require_full_stage_unlock()?;
            let manifest = hash.to_owned();
            let owner = source.clone();
            let family = header.family.clone();
            let key = Zeroizing::new(header.key.clone());
            let absent = header.op == RecordOp::Absent;
            // Move erasing key ownership onto the worker instead of generic Param copies.
            self.connection.call(move |db| {
                db.execute(
                    "INSERT INTO receiver_scalar_record(manifest_hash,source_ref,family,key,record_offset,encoded_bytes,absent) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![manifest,owner,family,key.as_str(),offset,bytes,absent],
                )
            })?;
            counts.records = counts.records.checked_add(1).ok_or_else(invalid)?;
            counts.encoded_bytes = counts.encoded_bytes.checked_add(bytes).ok_or_else(invalid)?;
            Ok(())
        })?;
        self.connection.execute(
            "INSERT INTO receiver_scalar_input(manifest_hash,source_ref,records,encoded_bytes) VALUES(?1,?2,?3,?4)",
            params![hash,source,counts.records,counts.encoded_bytes],
        )?;
        self.db.require_full_stage_unlock()?;
        self.connection.execute_batch("COMMIT")?;
        pending.committed = true;
        super::stage::sync_stage(&self.directory)?;
        self.db.require_full_stage_unlock()?;
        Ok(counts)
    }
}
fn invalid() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
