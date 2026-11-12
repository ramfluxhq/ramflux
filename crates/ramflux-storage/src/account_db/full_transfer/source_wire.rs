// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted private wire spool. A separate worker avoids reentrant calls from scalar cursors.
use super::{
    source_owner::SourceContext,
    source_scalar::SourceGuard,
    stage::{create_file, open_regular},
};
use crate::{StorageError, database::Connection};
use ramflux_protocol::custody::pairing::full_transfer::{CHUNK_BYTES, chunk_digest, chunk_layout};
use rusqlite::params;
use zeroize::Zeroizing;

const FILE: &str = "source-wire.db";
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS wire_chunk(snapshot_id TEXT NOT NULL,cut INTEGER NOT NULL,idx INTEGER NOT NULL,length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 262144),digest BLOB NOT NULL CHECK(length(digest)=32),bytes BLOB NOT NULL,PRIMARY KEY(snapshot_id,cut,idx));
CREATE TABLE IF NOT EXISTS wire_complete(snapshot_id TEXT NOT NULL,cut INTEGER NOT NULL,total_bytes INTEGER NOT NULL,chunk_count INTEGER NOT NULL,root BLOB NOT NULL CHECK(length(root)=32),PRIMARY KEY(snapshot_id,cut));";
fn mismatch() -> StorageError {
    StorageError::PairingField("ChunkMismatch")
}
fn integer(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| mismatch())
}

pub(super) struct SourceWireSpool {
    connection: Connection,
    snapshot: String,
    cut: u64,
    next: u64,
    written: u64,
    guard: SourceGuard,
    committed: bool,
}
impl Drop for SourceWireSpool {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.connection.execute_batch("ROLLBACK");
        }
    }
}
impl SourceContext<'_> {
    pub(super) fn wire_spool(
        &self,
        cut: u64,
        snapshot: &str,
    ) -> Result<SourceWireSpool, StorageError> {
        self.require_source_live()?;
        let path = self.directory.join(FILE);
        if path.try_exists()? {
            drop(open_regular(&path, false)?);
        } else {
            create_file(&path)?.sync_all()?;
        }
        let connection = self.key.open_metadata(&path)?;
        connection.execute_batch(SCHEMA)?;
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let spool = SourceWireSpool {
            connection,
            snapshot: snapshot.into(),
            cut,
            next: 0,
            written: 0,
            guard: SourceGuard::new(self.db, self.cancelled.clone()),
            committed: false,
        };
        spool.connection.execute(
            "DELETE FROM wire_chunk WHERE snapshot_id=?1 AND cut=?2",
            params![snapshot, integer(cut)?],
        )?;
        spool.connection.execute(
            "DELETE FROM wire_complete WHERE snapshot_id=?1 AND cut=?2",
            params![snapshot, integer(cut)?],
        )?;
        Ok(spool)
    }
}
impl SourceWireSpool {
    pub(super) fn push(&mut self, index: u64, bytes: &[u8]) -> Result<(), StorageError> {
        self.guard.require()?;
        if index != self.next || bytes.is_empty() || bytes.len() > CHUNK_BYTES as usize {
            return Err(mismatch());
        }
        let digest = chunk_digest(index, bytes).map_err(|_| mismatch())?;
        let body = Zeroizing::new(bytes.to_vec());
        let snapshot = self.snapshot.clone();
        let cut = integer(self.cut)?;
        let index = integer(index)?;
        let length = integer(u64::try_from(body.len()).map_err(|_| mismatch())?)?;
        let guard = self.guard.clone();
        self.connection.call(move |db| {
            let write = || -> Result<(), StorageError> {
                guard.require()?;
                db.execute("INSERT INTO wire_chunk(snapshot_id,cut,idx,length,digest,bytes) VALUES(?1,?2,?3,?4,?5,?6)",params![snapshot,cut,index,length,digest.as_slice(),body.as_slice()])?;
                guard.require()
            };
            Ok(write())
        })??;
        self.next = self.next.checked_add(1).ok_or_else(mismatch)?;
        self.written = self
            .written
            .checked_add(u64::try_from(bytes.len()).map_err(|_| mismatch())?)
            .ok_or_else(mismatch)?;
        Ok(())
    }
    pub(super) fn finish(mut self, total: u64, root: [u8; 32]) -> Result<(), StorageError> {
        self.guard.require()?;
        if self.written != total || self.next != chunk_layout(total).map_err(|_| mismatch())?.0 {
            return Err(mismatch());
        }
        self.connection.execute("INSERT INTO wire_complete(snapshot_id,cut,total_bytes,chunk_count,root) VALUES(?1,?2,?3,?4,?5)",params![self.snapshot,integer(self.cut)?,integer(total)?,integer(self.next)?,root.as_slice()])?;
        self.guard.require()?;
        self.connection.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }
}

impl super::FullTransferStage<'_> {
    /// Read one exact committed source wire chunk for an OWN retained signed base/delta.
    /// The ordinary DB/stage-key borrow stays local and must end before any network wait.
    /// This grants no receipt, source-cut retirement, J6/tail or publication permission.
    /// # Errors
    /// Refuses wrong role/scope/signature/root/index, partial spools, corruption or cancellation.
    pub fn read_source_wire_chunk(
        &self,
        manifest_hash: &str,
        index: u64,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        use ramflux_protocol::custody::pairing::full_transfer::{
            ManifestKind, manifest_hash as hash,
        };
        let source = self.source_context()?;
        source.require_source_live()?;
        let manifest = self.forward_manifest(manifest_hash)?;
        let record = self.resume_record()?;
        let body = &manifest.manifest;
        if body.kind == ManifestKind::Tail
            || body.transfer_id != record.transfer_id
            || body.source_ref != record.grant.source_ref
            || body.destination_ref != record.grant.destination_ref
            || body.base_record_hash != record.base_record_hash
            || ramflux_protocol::encode_base64url(hash(&manifest).map_err(|_| mismatch())?)
                != manifest_hash
        {
            return Err(mismatch());
        }
        ramflux_crypto::verify_canonical_signature(
            &body.signing_bytes().map_err(|_| mismatch())?,
            &manifest.source_signature,
            &record.grant.branch_keys.source,
        )
        .map_err(|_| mismatch())?;
        let path = source.directory.join(FILE);
        drop(open_regular(&path, false)?);
        let connection = source.key.open_metadata(&path)?;
        let (total, count, root) =
            wire_summary(&connection, &body.snapshot_id, body.snapshot_cut.0)?;
        if total != body.total_bytes.0
            || count != body.chunk_count.0
            || ramflux_protocol::encode_base64url(root) != body.chunks_root
            || index >= count
        {
            return Err(mismatch());
        }
        let expected = if index + 1 == count {
            u64::from(chunk_layout(total).map_err(|_| mismatch())?.1)
        } else {
            u64::from(CHUNK_BYTES)
        };
        let snapshot = body.snapshot_id.clone();
        let cut = integer(body.snapshot_cut.0)?;
        let sql_index = integer(index)?;
        let value=connection.call(move |db| {
            db.query_row("SELECT length,digest,bytes FROM wire_chunk WHERE snapshot_id=?1 AND cut=?2 AND idx=?3 AND length(bytes) BETWEEN 1 AND 262144",params![snapshot,cut,sql_index],|row| {
                let length:u64=row.get(0)?;
                let bytes=row.get_ref(2)?.as_blob()?;
                let digest=row.get_ref(1)?.as_blob()?;
                if length!=expected || bytes.len() as u64!=expected || digest.len()!=32
                    || chunk_digest(index,bytes).map_err(|_|rusqlite::Error::InvalidQuery)?.as_slice()!=digest {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(Zeroizing::new(bytes.to_vec()))
            })
        }).map_err(|error| match error {
            rusqlite::Error::InvalidQuery | rusqlite::Error::QueryReturnedNoRows => mismatch(),
            other => other.into(),
        })?;
        source.require_source_live()?;
        Ok(value)
    }
}

fn wire_summary(
    connection: &Connection,
    snapshot: &str,
    cut: u64,
) -> Result<(u64, u64, [u8; 32]), StorageError> {
    let snapshot = snapshot.to_owned();
    let cut = integer(cut)?;
    Ok(connection.call(move |db| {
        db.query_row("SELECT total_bytes,chunk_count,root FROM wire_complete WHERE snapshot_id=?1 AND cut=?2",params![snapshot,cut],|row| {
            let root=row.get_ref(2)?.as_blob()?;
            let root=root.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?;
            Ok((row.get(0)?,row.get(1)?,root))
        })
    })?)
}
