// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-process, data-only handoff. No constructor/decoder can restore a SAS confirmation.
use super::{Arc, AtomicBool, FullBaseSourceEncoding, FullSourcePreparation, Ordering};
use crate::account_db::full_transfer::{
    WrappedFullStageKey,
    stage::{context, open_regular, raw32, read_bounded, stage_directory, sync_stage},
};
use crate::{AccountDb, StorageError};
use ramflux_crypto::custody::pairing::PairingRole;
mod work;
use std::{marker::PhantomData, path::PathBuf};
pub use work::FullSourcePreparationWork;

/// Opaque local data reference across network waits; holds no account key, database
/// connection, SAS confirmation, signing permission or lease. Ordinary unlock is required
/// to reopen its encrypted files. It is intentionally not serializable or deserializable.
pub struct PreparedFullSource {
    local_account_id: String,
    principal: String,
    database_path: PathBuf,
    preparation_id: String,
    snapshot_id: String,
    encoding: FullBaseSourceEncoding,
    digest: [u8; 32],
    cancelled: Arc<AtomicBool>,
}
impl PreparedFullSource {
    /// Immutable local data identity, not a network credential or signature permission.
    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.digest
    }
    /// Local source account selected by the datastore owner, never a peer-supplied locator.
    #[must_use]
    pub fn local_account_id(&self) -> &str {
        &self.local_account_id
    }
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    /// Read-only source operands. They convey no signing, publication or resume permission.
    #[must_use]
    pub const fn encoding(&self) -> &FullBaseSourceEncoding {
        &self.encoding
    }
    #[must_use]
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
}
fn digest(
    db: &AccountDb,
    id: &str,
    snapshot: &str,
    encoding: &FullBaseSourceEncoding,
) -> Result<[u8; 32], StorageError> {
    digest_identity(&db.local_account_id, &db.principal_commitment, id, snapshot, encoding)
}
fn digest_identity(
    account: &str,
    principal: &str,
    id: &str,
    snapshot: &str,
    encoding: &FullBaseSourceEncoding,
) -> Result<[u8; 32], StorageError> {
    let mut hash = blake3::Hasher::new();
    for bytes in
        [b"ramflux.full.source.preparation.v2".as_slice(), account.as_bytes(), principal.as_bytes()]
    {
        hash.update(&u32::try_from(bytes.len()).map_err(|_| context())?.to_be_bytes());
        hash.update(bytes);
    }
    hash.update(&raw32(id)?);
    hash.update(&raw32(snapshot)?);
    hash.update(&encoding.schema.census_hash);
    hash.update(&encoding.storage_generation.to_be_bytes());
    hash.update(&encoding.source_erasure_generation.to_be_bytes());
    hash.update(&encoding.total_bytes.to_be_bytes());
    hash.update(&encoding.chunk_count.to_be_bytes());
    hash.update(&encoding.chunks_root);
    // Family counters use their existing U64-string codecs, never lossy JSON numbers.
    let families = ramflux_protocol::canonical_json_bytes(&encoding.schema.families)?;
    hash.update(&u32::try_from(families.len()).map_err(|_| context())?.to_be_bytes());
    hash.update(&families);
    Ok(*hash.finalize().as_bytes())
}
impl FullSourcePreparation<'_> {
    /// Commit the ready-data digest and release the key/lock/account borrow for a network wait.
    /// The returned handle is data only; no invitation, lease or confirmation is manufactured.
    /// # Errors
    /// Refuses an unfinished/cancelled/stale preparation or failed durable metadata write.
    pub fn close_ready(mut self) -> Result<PreparedFullSource, StorageError> {
        self.context()?.require_source_live()?;
        let (snapshot_id, encoding) = self.prepared.take().ok_or_else(context)?;
        self.context()?.with_source_cut(0, &snapshot_id, |_| Ok(()))?;
        let digest = digest(self.db, &self.preparation_id, &snapshot_id, &encoding)?;
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS source_preparation_ready(singleton INTEGER PRIMARY KEY CHECK(singleton=1),digest BLOB NOT NULL CHECK(length(digest)=32));")?;
        self.connection.execute("INSERT INTO source_preparation_ready VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET digest=excluded.digest",rusqlite::params![digest.as_slice()])?;
        sync_stage(&self.directory)?;
        self.context()?.require_source_live()?;
        Ok(PreparedFullSource {
            local_account_id: self.db.local_account_id.clone(),
            principal: self.db.principal_commitment.clone(),
            database_path: self.db.path.clone(),
            preparation_id: self.preparation_id,
            snapshot_id,
            encoding,
            digest,
            cancelled: self.cancelled,
        })
    }
}
impl AccountDb {
    /// Reopen an opaque prepared source under this account's actual ordinary unlock. The
    /// handle restores only immutable data operands; a separately attended SAS/bootstrap
    /// and its exact grant/lease are still required to create an authenticated data stage.
    /// # Errors
    /// Refuses another account/generation, cancellation, wrong key/digest or unsafe files.
    pub fn open_full_source_preparation(
        &self,
        prepared: &PreparedFullSource,
    ) -> Result<FullSourcePreparation<'_>, StorageError> {
        self.require_full_stage_unlock()?;
        if prepared.cancelled.load(Ordering::Acquire) {
            return Err(StorageError::PairingField("Cancelled"));
        }
        if self.local_account_id != prepared.local_account_id
            || self.principal_commitment != prepared.principal
            || self.path != prepared.database_path
            || digest(self, &prepared.preparation_id, &prepared.snapshot_id, &prepared.encoding)?
                != prepared.digest
        {
            return Err(context());
        }
        let directory = stage_directory(self, &prepared.preparation_id, false)?;
        let lock = open_regular(&directory.join("stage.lock"), true)?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        let wrapped = WrappedFullStageKey::from_file_bytes(&read_bounded(
            &directory.join("stage.key"),
            1024,
        )?)?;
        let key = self.open_full_stage_key(
            &raw32(&prepared.preparation_id)?,
            PairingRole::Initiator,
            &wrapped,
        )?;
        let connection = key.open_metadata(&directory.join("stage.db"))?;
        let bound:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name IN ('stage','resume'))",[],|row|row.get(0))?;
        if bound {
            return Err(context());
        }
        let stored: [u8; 32] = connection.query_row(
            "SELECT digest FROM source_preparation_ready WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if stored != prepared.digest {
            return Err(context());
        }
        let owner = FullSourcePreparation {
            connection,
            lock,
            key,
            db: self,
            directory,
            preparation_id: prepared.preparation_id.clone(),
            prepared: Some((prepared.snapshot_id.clone(), prepared.encoding.clone())),
            cancelled: prepared.cancelled.clone(),
            _serial: PhantomData,
        };
        owner.context()?.with_source_cut(0, &prepared.snapshot_id, |_| Ok(()))?;
        Ok(owner)
    }
}
