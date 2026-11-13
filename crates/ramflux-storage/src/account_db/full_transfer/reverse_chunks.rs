// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reverse-only immutable encrypted slots. Receipts attest durable bytes, never semantic application.
use super::{
    EncryptedStageChunk, FullTransferStage, StageDirection,
    stage::{create_file, open_regular, raw32},
};
use crate::StorageError;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{CHUNK_BYTES, RootHasher, SourceManifest, chunk_digest},
};
use rusqlite::{OptionalExtension as _, params};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use zeroize::Zeroizing;
const SLOT_BYTES: u64 = 262_172;
const SLOTS_PER_FILE: u64 = 256;
const SEGMENT_SLACK: u64 = 67_108_864;
fn mismatch() -> StorageError {
    StorageError::PairingField("ChunkMismatch")
}
fn no_space() -> StorageError {
    StorageError::PairingField("NoSpace")
}
impl FullTransferStage<'_> {
    pub(super) fn recover_reverse_receipts(&self) -> Result<(), StorageError> {
        if self.resume_record()?.role != ramflux_crypto::custody::pairing::PairingRole::Initiator {
            return Ok(());
        }
        let hash = self
            .connection
            .query_row(
                "SELECT manifest_hash FROM manifest WHERE direction=1 AND cut=0 AND verified=0",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(hash) = hash {
            self.revalidate_reverse_prefix(&hash)?;
        }
        Ok(())
    }

    /// Encrypt and fsync one immutable original-B chunk before committing its receipt row.
    /// This receiver-only operation confers no semantic or native authority.
    /// # Errors
    /// Refuses another role, malformed bytes, slot conflicts, cancellation or low disk space.
    pub fn retain_reverse_chunk(
        &self,
        manifest_hash: &str,
        index: u64,
        plaintext: &[u8],
    ) -> Result<bool, StorageError> {
        self.require_io()?;
        if self.resume_record()?.role != ramflux_crypto::custody::pairing::PairingRole::Initiator {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let manifest = self.reverse_manifest(manifest_hash)?;
        let body = &manifest.manifest;
        if index >= body.chunk_count.0 {
            return Err(mismatch());
        }
        let expected = if index + 1 == body.chunk_count.0 {
            u32::try_from(body.total_bytes.0 - index * u64::from(CHUNK_BYTES))
                .map_err(|_| mismatch())?
        } else {
            CHUNK_BYTES
        };
        if plaintext.len() != expected as usize {
            return Err(mismatch());
        }
        let digest = chunk_digest(index, plaintext).map_err(|_| mismatch())?;
        let existing = self
            .connection
            .query_row(
                "SELECT length,digest FROM chunk WHERE direction=1 AND manifest_hash=?1 AND idx=?2",
                params![manifest_hash, index],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        if let Some((length, retained)) = existing {
            if length != expected || retained.as_slice() != digest {
                return Err(mismatch());
            }
            let checked = self.read_reverse_chunk(&manifest, manifest_hash, index, length)?;
            if chunk_digest(index, &checked).map_err(|_| mismatch())? != digest {
                return Err(mismatch());
            }
            return Ok(false);
        }
        let encrypted = self.key.seal_chunk(
            &raw32(manifest_hash)?,
            StageDirection::Reverse,
            index,
            plaintext,
        )?;
        if fs2::available_space(&self.directory)?
            < SEGMENT_SLACK + encrypted.as_file_bytes().len() as u64
        {
            return Err(no_space());
        }
        let path = self.reverse_segment_path(index);
        let mut file = match open_regular(&path, true) {
            Ok(file) => file,
            Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                create_file(&path)?
            }
            Err(error) => return Err(error),
        };
        file.seek(SeekFrom::Start(slot_offset(index)))?;
        file.write_all(encrypted.as_file_bytes())?;
        file.sync_all()?;
        std::fs::File::open(&self.directory)?.sync_all()?;
        self.require_io()?;
        self.connection.execute(
            "INSERT INTO chunk(direction,manifest_hash,idx,length,digest,file_durable) VALUES(1,?1,?2,?3,?4,1)",
            params![manifest_hash,index,expected,digest.as_slice()],
        )?;
        self.require_io()?;
        Ok(true)
    }

    /// Re-read/decrypt every receipted slot in order. First missing/torn/corrupt slot cuts
    /// the durable prefix and invalidates all later receipts before any resume response.
    /// # Errors
    /// Refuses wrong owners/manifests or failure to persist the repaired prefix.
    pub fn revalidate_reverse_prefix(&self, hash: &str) -> Result<Option<u64>, StorageError> {
        self.require_io()?;
        let manifest = self.reverse_manifest(hash)?;
        let mut next = 0;
        while next < manifest.manifest.chunk_count.0 {
            let retained = self.connection.query_row(
                "SELECT length,digest FROM chunk WHERE direction=1 AND manifest_hash=?1 AND idx=?2",params![hash,next],
                |row| Ok((row.get::<_,u32>(0)?, row.get::<_,Vec<u8>>(1)?)),
            ).optional()?;
            let Some((length, digest)) = retained else { break };
            let Ok(plaintext) = self.read_reverse_chunk(&manifest, hash, next, length) else {
                break;
            };
            if !chunk_digest(next, &plaintext).is_ok_and(|actual| actual.as_slice() == digest) {
                break;
            }
            next += 1;
        }
        // A repaired prefix is durable before the caller can advertise it. This is receipt
        // state, never a DataVerified claim; verification below recomputes the complete root.
        self.connection.execute(
            "DELETE FROM chunk WHERE direction=1 AND manifest_hash=?1 AND idx>=?2",
            params![hash, next],
        )?;
        if next < manifest.manifest.chunk_count.0 {
            self.connection.execute(
                "UPDATE manifest SET root_verified=0 WHERE direction=1 AND manifest_hash=?1",
                params![hash],
            )?;
        }
        self.require_io()?;
        Ok(next.checked_sub(1))
    }

    /// Recompute the complete ordered root from authenticated disk slots, then persist only
    /// the root marker. Logical record validation is still required before `DataVerified`;
    /// this operation never changes the separate verified/predecessor admission marker.
    /// # Errors
    /// Refuses incomplete/corrupt streams or a root mismatch.
    pub fn verify_reverse_root(&self, hash: &str) -> Result<(), StorageError> {
        self.require_io()?;
        let manifest = self.reverse_manifest(hash)?;
        let body = &manifest.manifest;
        let mut root = RootHasher::new(body.total_bytes.0).map_err(|_| mismatch())?;
        for index in 0..body.chunk_count.0 {
            let length = self.connection.query_row(
                "SELECT length FROM chunk WHERE direction=1 AND manifest_hash=?1 AND idx=?2",
                params![hash, index],
                |row| row.get::<_, u32>(0),
            )?;
            root.push(index, &self.read_reverse_chunk(&manifest, hash, index, length)?)
                .map_err(|_| mismatch())?;
        }
        if root.finish().map_err(|_| mismatch())? != raw32(&body.chunks_root)? {
            return Err(mismatch());
        }
        self.connection.execute(
            "UPDATE manifest SET root_verified=1 WHERE direction=1 AND manifest_hash=?1",
            params![hash],
        )?;
        Ok(())
    }

    pub(super) fn reverse_manifest(&self, hash: &str) -> Result<SourceManifest, StorageError> {
        self.require_io()?;
        raw32(hash)?;
        let bytes = Zeroizing::new(self.connection.query_row(
            "SELECT bytes FROM manifest WHERE direction=1 AND manifest_hash=?1 AND cut=0 AND kind='base'",
            params![hash], |row| row.get::<_, Vec<u8>>(0),
        ).optional()?.ok_or_else(mismatch)?);
        SourceManifest::from_wire_bytes(&bytes).map_err(|_| mismatch())
    }
    fn reverse_segment_path(&self, index: u64) -> std::path::PathBuf {
        self.directory.join(format!("seg-r-0-{}.bin", index / SLOTS_PER_FILE))
    }
    pub(super) fn read_reverse_chunk(
        &self,
        _manifest: &SourceManifest,
        hash: &str,
        index: u64,
        length: u32,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        if length == 0 || length > CHUNK_BYTES {
            return Err(mismatch());
        }
        let mut file = open_regular(&self.reverse_segment_path(index), false)?;
        file.seek(SeekFrom::Start(slot_offset(index)))?;
        let mut bytes = Zeroizing::new(vec![0; length as usize + 28]);
        file.read_exact(&mut bytes)?;
        self.key.open_chunk(
            &raw32(hash)?,
            StageDirection::Reverse,
            index,
            length,
            &EncryptedStageChunk::from_file_bytes(bytes)?,
        )
    }
}
const fn slot_offset(index: u64) -> u64 {
    (index % SLOTS_PER_FILE) * SLOT_BYTES
}

#[cfg(test)]
mod tests;
