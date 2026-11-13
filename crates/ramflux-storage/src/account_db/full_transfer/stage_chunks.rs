// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Forward data retention only. Publication/J6/tail and native freshness are separate gates.
use super::stage::{FullTransferStage, create_file, open_regular, raw32};
use super::{EncryptedStageChunk, StageDirection};
use crate::StorageError;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        CHUNK_BYTES, Family, ManifestKind, RootHasher, SourceManifest, chunk_digest, manifest_hash,
    },
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
fn manifest_error() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
fn no_space() -> StorageError {
    StorageError::PairingField("NoSpace")
}

impl FullTransferStage<'_> {
    pub(super) fn recover_forward_receipts(&self) -> Result<(), StorageError> {
        let in_progress = self.connection.query_row(
            "SELECT manifest_hash FROM manifest WHERE direction=0 AND verified=0 ORDER BY cut DESC LIMIT 1",
            [], |row| row.get::<_,String>(0),
        ).optional()?;
        if let Some(hash) = in_progress {
            self.revalidate_forward_prefix(&hash)?;
        }
        Ok(())
    }
    /// Retain a source-signed pre-publication forward manifest. The compiled catalog is
    /// supplied by the local export owner, never copied from the peer. This storage method
    /// refuses tails until the separate persisted J6 endpoint owner admits them.
    /// # Errors
    /// Refuses wrong source/scope/catalog/signature, skipped/unverified predecessors or disk bounds.
    pub fn retain_forward_manifest(
        &mut self,
        manifest: &SourceManifest,
        catalog: &[Family],
    ) -> Result<(), StorageError> {
        self.retain_manifest_for_role(manifest, catalog, PairingRole::Responder)
    }

    pub(super) fn retain_manifest_for_role(
        &mut self,
        manifest: &SourceManifest,
        catalog: &[Family],
        role: PairingRole,
    ) -> Result<(), StorageError> {
        self.require_io()?;
        manifest.validate().map_err(|error| match error {
            ramflux_protocol::custody::pairing::WireError::Field("NoSpace") => no_space(),
            _ => manifest_error(),
        })?;
        manifest.manifest.validate_catalog(catalog, false).map_err(|_| manifest_error())?;
        let record = self.resume_record()?;
        let body = &manifest.manifest;
        if record.role != role
            || body.kind == ManifestKind::Tail
            || body.transfer_id != record.transfer_id
            || body.source_ref != record.grant.source_ref
            || body.destination_ref != record.grant.destination_ref
            || body.base_record_hash != record.base_record_hash
        {
            return Err(manifest_error());
        }
        ramflux_crypto::verify_canonical_signature(
            &body.signing_bytes().map_err(|_| manifest_error())?,
            &manifest.source_signature,
            &record.grant.branch_keys.source,
        )
        .map_err(|_| manifest_error())?;
        let hash = ramflux_protocol::encode_base64url(
            manifest_hash(manifest).map_err(|_| manifest_error())?,
        );
        if body.kind == ManifestKind::Base && hash != record.base_manifest_hash {
            return Err(manifest_error());
        }
        let bytes = Zeroizing::new(manifest.to_wire_bytes().map_err(|_| manifest_error())?);
        let existing = self
            .connection
            .query_row(
                "SELECT bytes,verified FROM manifest WHERE direction=0 AND cut=?1",
                params![body.snapshot_cut.0],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        if let Some((existing, verified)) = existing {
            if existing.as_slice() == bytes.as_slice() {
                return Ok(());
            }
            if verified {
                return Err(manifest_error());
            }
        }
        if body.kind != ManifestKind::Base {
            let parent = self.connection.query_row(
                "SELECT bytes FROM manifest WHERE direction=0 AND verified=1 ORDER BY cut DESC LIMIT 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            ).optional()?.ok_or_else(manifest_error)?;
            let previous =
                SourceManifest::from_wire_bytes(&parent).map_err(|_| manifest_error())?;
            manifest.verify_predecessor(&previous).map_err(|_| manifest_error())?;
        }
        let required = body
            .total_bytes
            .0
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::fs::metadata(&self.db.path).ok()?.len()))
            .and_then(|bytes| bytes.checked_add(268_435_456))
            .ok_or_else(no_space)?;
        if fs2::available_space(&self.directory)? < required {
            return Err(no_space());
        }
        let obsolete: Vec<u64> = self.connection.call(|db| {
            db.prepare("SELECT cut FROM manifest WHERE direction=0 AND verified=0")?
                .query_map([], |row| row.get(0))?
                .collect()
        })?;
        // Destroy old unverified ciphertext before committing its replacement. A crash
        // here leaves old metadata whose receipt prefix is repaired on reopen; it cannot
        // advertise removed slots. No verified metadata or source snapshots are removed.
        for cut in obsolete {
            self.discard_unverified_forward_files(cut)?;
        }
        let cut = body.snapshot_cut.0;
        let kind = if body.kind == ManifestKind::Base { "base" } else { "delta" };
        let root = body.chunks_root.clone();
        self.require_io()?;
        self.connection.call(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute("DELETE FROM receiver_scalar_record WHERE manifest_hash IN(SELECT manifest_hash FROM manifest WHERE direction=0 AND verified=0)", [])?;
            tx.execute("DELETE FROM receiver_scalar_input WHERE manifest_hash IN(SELECT manifest_hash FROM manifest WHERE direction=0 AND verified=0)", [])?;
            tx.execute("DELETE FROM chunk WHERE direction=0 AND manifest_hash IN(SELECT manifest_hash FROM manifest WHERE direction=0 AND verified=0)", [])?;
            tx.execute("DELETE FROM manifest WHERE direction=0 AND verified=0", [])?;
            tx.execute(
                "INSERT INTO manifest(direction,cut,manifest_hash,kind,bytes,chunks_root,verified) VALUES(0,?1,?2,?3,?4,?5,0)",
                params![cut,hash,kind,bytes.as_slice(),root],
            )?;
            tx.commit()
        })?;
        Ok(())
    }

    fn discard_unverified_forward_files(&self, cut: u64) -> Result<(), StorageError> {
        let prefix = format!("seg-f-{cut}-");
        for entry in std::fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(group) = name.strip_prefix(&prefix).and_then(|v| v.strip_suffix(".bin"))
            else {
                continue;
            };
            let number = group.parse::<u64>().map_err(|_| manifest_error())?;
            if number.to_string() != group {
                return Err(manifest_error());
            }
            drop(open_regular(&entry.path(), true)?);
            std::fs::remove_file(entry.path())?;
        }
        std::fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    /// OVP-19/20 commit order: encrypt/write slot, fsync file, commit durable row. A caller
    /// may issue a Receipt only after success. True means a new durable write; false means
    /// an exact, independently re-read duplicate. Receipted slots are never overwritten.
    /// # Errors
    /// Refuses wrong index/length/digest, immutable-slot conflicts, corruption or disk pressure.
    pub fn retain_forward_chunk(
        &self,
        manifest_hash: &str,
        index: u64,
        plaintext: &[u8],
    ) -> Result<bool, StorageError> {
        self.require_io()?;
        let manifest = self.forward_manifest(manifest_hash)?;
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
                "SELECT length,digest FROM chunk WHERE direction=0 AND manifest_hash=?1 AND idx=?2",
                params![manifest_hash, index],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        if let Some((length, retained)) = existing {
            if length != expected || retained.as_slice() != digest {
                return Err(mismatch());
            }
            let checked = self.read_forward_chunk(&manifest, manifest_hash, index, length)?;
            if chunk_digest(index, &checked).map_err(|_| mismatch())? != digest {
                return Err(mismatch());
            }
            return Ok(false);
        }
        let encrypted = self.key.seal_chunk(
            &raw32(manifest_hash)?,
            StageDirection::Forward,
            index,
            plaintext,
        )?;
        if fs2::available_space(&self.directory)?
            < SEGMENT_SLACK + encrypted.as_file_bytes().len() as u64
        {
            return Err(no_space());
        }
        let path = self.segment_path(body.snapshot_cut.0, index);
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
            "INSERT INTO chunk(direction,manifest_hash,idx,length,digest,file_durable) VALUES(0,?1,?2,?3,?4,1)",
            params![manifest_hash,index,expected,digest.as_slice()],
        )?;
        Ok(true)
    }

    /// Re-read/decrypt every receipted slot in order. First missing/torn/corrupt slot cuts
    /// the durable prefix and invalidates all later receipts before any resume response.
    /// # Errors
    /// Refuses wrong owners/manifests or failure to persist the repaired prefix.
    pub fn revalidate_forward_prefix(&self, hash: &str) -> Result<Option<u64>, StorageError> {
        self.require_io()?;
        let manifest = self.forward_manifest(hash)?;
        let mut next = 0;
        while next < manifest.manifest.chunk_count.0 {
            let retained = self.connection.query_row(
                "SELECT length,digest FROM chunk WHERE direction=0 AND manifest_hash=?1 AND idx=?2",params![hash,next],
                |row| Ok((row.get::<_,u32>(0)?, row.get::<_,Vec<u8>>(1)?)),
            ).optional()?;
            let Some((length, digest)) = retained else { break };
            let Ok(plaintext) = self.read_forward_chunk(&manifest, hash, next, length) else {
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
            "DELETE FROM chunk WHERE direction=0 AND manifest_hash=?1 AND idx>=?2",
            params![hash, next],
        )?;
        if next < manifest.manifest.chunk_count.0 {
            self.connection.execute(
                "UPDATE manifest SET root_verified=0 WHERE direction=0 AND manifest_hash=?1",
                params![hash],
            )?;
        }
        Ok(next.checked_sub(1))
    }

    /// Recompute the complete ordered root from authenticated disk slots, then persist only
    /// the root marker. Logical record validation is still required before `DataVerified`;
    /// this operation never changes the separate verified/predecessor admission marker.
    /// # Errors
    /// Refuses incomplete/corrupt streams or a root mismatch.
    pub fn verify_forward_root(&self, hash: &str) -> Result<(), StorageError> {
        self.require_io()?;
        let manifest = self.forward_manifest(hash)?;
        let body = &manifest.manifest;
        let mut root = RootHasher::new(body.total_bytes.0).map_err(|_| mismatch())?;
        for index in 0..body.chunk_count.0 {
            let length = self.connection.query_row(
                "SELECT length FROM chunk WHERE direction=0 AND manifest_hash=?1 AND idx=?2",
                params![hash, index],
                |row| row.get::<_, u32>(0),
            )?;
            root.push(index, &self.read_forward_chunk(&manifest, hash, index, length)?)
                .map_err(|_| mismatch())?;
        }
        if root.finish().map_err(|_| mismatch())? != raw32(&body.chunks_root)? {
            return Err(mismatch());
        }
        self.connection.execute(
            "UPDATE manifest SET root_verified=1 WHERE direction=0 AND manifest_hash=?1",
            params![hash],
        )?;
        Ok(())
    }
    /// Read the latest exact retained signed forward manifest after ordinary unlock.
    /// This returns metadata only and grants neither semantic DV nor publication authority.
    /// # Errors
    /// Refuses a stale stage, malformed retained metadata or a foreign original signature.
    pub fn current_forward_manifest(&self) -> Result<Option<SourceManifest>, StorageError> {
        self.require_io()?;
        let hash: Option<String> = self
            .connection
            .query_row(
                "SELECT manifest_hash FROM manifest WHERE direction=0 ORDER BY cut DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        hash.map(|hash| self.forward_manifest(&hash)).transpose()
    }
    pub(super) fn forward_manifest(&self, hash: &str) -> Result<SourceManifest, StorageError> {
        raw32(hash)?;
        let bytes = Zeroizing::new(
            self.connection
                .query_row(
                    "SELECT bytes FROM manifest WHERE direction=0 AND manifest_hash=?1",
                    params![hash],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?
                .ok_or_else(manifest_error)?,
        );
        SourceManifest::from_wire_bytes(&bytes).map_err(|_| manifest_error())
    }
    fn segment_path(&self, cut: u64, index: u64) -> std::path::PathBuf {
        self.directory.join(format!("seg-f-{cut}-{}.bin", index / SLOTS_PER_FILE))
    }
    pub(super) fn read_forward_chunk(
        &self,
        manifest: &SourceManifest,
        hash: &str,
        index: u64,
        length: u32,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        if length == 0 || length > CHUNK_BYTES {
            return Err(mismatch());
        }
        let mut file =
            open_regular(&self.segment_path(manifest.manifest.snapshot_cut.0, index), false)?;
        file.seek(SeekFrom::Start(slot_offset(index)))?;
        let mut bytes = Zeroizing::new(vec![0; length as usize + 28]);
        file.read_exact(&mut bytes)?;
        self.key.open_chunk(
            &raw32(hash)?,
            StageDirection::Forward,
            index,
            length,
            &EncryptedStageChunk::from_file_bytes(bytes)?,
        )
    }
}
const fn slot_offset(index: u64) -> u64 {
    (index % SLOTS_PER_FILE) * SLOT_BYTES
}
