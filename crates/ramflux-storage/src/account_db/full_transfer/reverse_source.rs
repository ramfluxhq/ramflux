// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Once-only original-B restrictive cut and encrypted off-loan encoding. No signer or approval.
use super::{
    FullTransferStage, keys::FullSourceMetadataKey, source_owner::SourceContext,
    source_scalar::SourceGuard,
};
use crate::{StorageError, database::Connection};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    context_v3::TranscriptV3,
    full_transfer::{CHUNK_BYTES, Manifest, ManifestKind, SourceManifest, U64},
};
use rusqlite::{OptionalExtension as _, params};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
use zeroize::Zeroizing;
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS reverse_source_pending(singleton INTEGER PRIMARY KEY CHECK(singleton=1),snapshot_id TEXT NOT NULL); CREATE TABLE IF NOT EXISTS reverse_source_ready(singleton INTEGER PRIMARY KEY CHECK(singleton=1),manifest BLOB NOT NULL);";
fn wrong() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
/// Owned local bulk work only: independent stage bytes/key and a weak original-B writer.
pub struct FullReverseSourceWork {
    connection: Connection,
    _lock: std::fs::File,
    directory: PathBuf,
    key: FullSourceMetadataKey,
    cut: Option<crate::account_db::backup::FullTransferCut>,
    guard: SourceGuard,
    cancelled: Arc<AtomicBool>,
    snapshot: String,
    forward: SourceManifest,
    digest: [u8; 32],
}
/// Exact own-cut reverse manifest metadata, with no signature or publication permission.
pub struct FullReverseSourceDraft {
    manifest: Manifest,
    digest: [u8; 32],
    guard: SourceGuard,
}
impl FullTransferStage<'_> {
    /// Freeze original B once after retaining A's first forward base; release its writer
    /// before copying/encoding. Recovery reuses only an already durable exact cut.
    /// # Errors
    /// Refuses another mode/role, missing forward base, a previously signed reverse or lost cut.
    pub fn into_reverse_source_work(self) -> Result<FullReverseSourceWork, StorageError> {
        self.reverse_source_context()?.require_source_live()?;
        let record = self.resume_record()?;
        let transcript = TranscriptV3::from_wire_bytes(&record.transcript).map_err(|_| wrong())?;
        if record.role != PairingRole::Responder
            || transcript.initiator.common.recipient_mode != "existing"
        {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let forward = self.forward_manifest(&record.base_manifest_hash)?;
        let saved: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM manifest WHERE direction=1)",
            [],
            |row| row.get(0),
        )?;
        if saved {
            return Err(wrong());
        }
        self.connection.execute_batch(SCHEMA)?;
        let pending: Option<String> = self
            .connection
            .query_row(
                "SELECT snapshot_id FROM reverse_source_pending WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let captured: Option<String> = self
            .connection
            .query_row("SELECT snapshot_id FROM source_cut WHERE cut=0", [], |row| row.get(0))
            .optional()?;
        let (snapshot, cut) = match (pending, captured) {
            (Some(pending), Some(captured)) if pending == captured => (captured, None),
            (None, None) => {
                let snapshot = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
                self.connection.execute(
                    "INSERT INTO reverse_source_pending VALUES(1,?1)",
                    params![snapshot],
                )?;
                super::stage::sync_stage(&self.directory)?;
                let cut = self.db.pin_full_transfer_cut()?;
                (snapshot, Some(cut))
            }
            _ => return Err(StorageError::PairingField("SnapshotInvalidated")),
        };
        let guard = SourceGuard::new(self.db, Some(self.source_cancelled.clone()));
        let key = self.key.source_job_key(guard.clone())?;
        Ok(FullReverseSourceWork {
            connection: self.connection,
            _lock: self.lock,
            directory: self.directory,
            key,
            cut,
            guard,
            cancelled: self.source_cancelled,
            snapshot,
            forward,
            digest: record.stage_digest()?,
        })
    }
    /// Verify opaque own-cut output through a fresh short B loan before constructing a signer draft.
    /// # Errors
    /// Refuses changed stage/unlock or disagreement with the independently encrypted ready owner.
    pub fn accept_reverse_source_draft(
        &self,
        draft: &FullReverseSourceDraft,
    ) -> Result<Manifest, StorageError> {
        self.reverse_source_context()?.require_source_live()?;
        draft.guard.require()?;
        if self.resume_record()?.stage_digest()? != draft.digest {
            return Err(wrong());
        }
        let bytes = Zeroizing::new(ramflux_protocol::canonical_json_bytes(&draft.manifest)?);
        let saved: Vec<u8> = self.connection.query_row(
            "SELECT manifest FROM reverse_source_ready WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if bytes.as_slice() != saved.as_slice() {
            return Err(wrong());
        }
        Ok(draft.manifest.clone())
    }
}
impl FullReverseSourceWork {
    /// Copy and encode the exact pinned/captured B view using bounded encrypted spools.
    /// Unknown actual owners refuse, and the complete full census remains bound in metadata.
    /// # Errors
    /// Refuses cancellation/lock, a changed saved cut, unsupported data or durability failure.
    pub fn encode(self) -> Result<FullReverseSourceDraft, StorageError> {
        self.guard.require()?;
        let mut source = SourceContext {
            key: &self.key,
            connection: &self.connection,
            guard: self.guard.clone(),
            directory: &self.directory,
        };
        if let Some(cut) = self.cut {
            let pending = self.directory.join("reverse-copy-pending.db");
            let snapshot = cut.write_private_snapshot(&pending, self.cancelled)?;
            source.adopt_source_cut(0, &self.snapshot, &pending, snapshot)?;
        }
        let (_, encoded) = source.encode_fixed_reverse_source(&self.snapshot, std::io::sink())?;
        let base = self.forward.manifest;
        let manifest = Manifest {
            schema: "ramflux.pairing.full_transfer.manifest.v1".into(),
            version: 1,
            transfer_id: base.transfer_id,
            account_anchor: base.account_anchor,
            source_ref: base.destination_ref,
            destination_ref: base.source_ref,
            base_record_hash: base.base_record_hash,
            snapshot_id: self.snapshot,
            snapshot_cut: U64(0),
            previous_cut: None,
            parent_manifest_hash: None,
            kind: ManifestKind::Base,
            source_erasure_generation: U64(encoded.source_erasure_generation),
            storage_generation: U64(encoded.storage_generation),
            census_hash: ramflux_protocol::encode_base64url(encoded.schema.census_hash),
            families: encoded.schema.families,
            total_bytes: U64(encoded.total_bytes),
            chunk_bytes: U64(u64::from(CHUNK_BYTES)),
            chunk_count: U64(encoded.chunk_count),
            chunks_root: ramflux_protocol::encode_base64url(encoded.chunks_root),
            attachment_policy: "remote_ciphertext".into(),
        };
        manifest.validate().map_err(|_| wrong())?;
        if manifest.census_hash != base.census_hash {
            return Err(StorageError::PairingField("SchemaMismatch"));
        }
        let bytes = Zeroizing::new(ramflux_protocol::canonical_json_bytes(&manifest)?);
        let old: Option<Vec<u8>> = self
            .connection
            .query_row("SELECT manifest FROM reverse_source_ready WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if old.is_some_and(|old| old.as_slice() != bytes.as_slice()) {
            return Err(wrong());
        }
        self.connection.execute(
            "INSERT INTO reverse_source_ready VALUES(1,?1) ON CONFLICT(singleton) DO NOTHING",
            params![bytes.as_slice()],
        )?;
        super::stage::sync_stage(&self.directory)?;
        self.guard.require()?;
        Ok(FullReverseSourceDraft { manifest, digest: self.digest, guard: self.guard })
    }
}

#[cfg(test)]
mod tests;
