// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant segment-file persistence. Call from bounded I/O workers, never the
//! account actor. Activation, resource retirement and restore admission are
//! separate prerequisites; this module provides no remote grant authority.
mod files;
mod lease;
pub(super) mod retirement;
pub use retirement::{SegmentCleanupPage, SegmentReference};
mod orphan;
pub use orphan::SegmentOrphanSweep;
#[cfg(test)]
mod retirement_tests;
#[cfg(test)]
mod tests;
use super::AccountDb;
use crate::StorageError;
use ramflux_protocol::large_attachment::VerifiedContentManifest;
use rusqlite::{OptionalExtension, params};
use std::path::PathBuf;

const PAGE_LIMIT: u32 = 128;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentDirection {
    Upload,
    Download,
}
impl SegmentDirection {
    fn name(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentPageEntry {
    pub index: u32,
    pub expected_digest: [u8; 32],
    pub expected_length: u64,
    pub received_bitmap: u8,
    pub cipher_verified: bool,
}

/// Borrows the account's single metadata owner; does not open another database.
/// The account directory must be private to the daemon, with no external writers.
pub struct SegmentStore<'a> {
    db: &'a AccountDb,
    root: PathBuf,
    #[cfg(test)]
    crash: Option<files::CrashPoint>,
    #[cfg(test)]
    during_write: Option<Box<dyn Fn() + 'a>>,
}

impl AccountDb {
    /// Opens the dormant I/O owner and reconciles once per account handle.
    /// Busy transfers remain owned and reconciled by their active lease holder.
    /// # Errors
    /// Returns schema or private-directory I/O failures.
    pub fn segment_store(&self) -> Result<SegmentStore<'_>, StorageError> {
        let root = self.path.with_extension("segments");
        files::private_dir(&root)?;
        let root = std::fs::canonicalize(root)?;
        let mut store = SegmentStore {
            db: self,
            root,
            #[cfg(test)]
            crash: None,
            #[cfg(test)]
            during_write: None,
        };
        if self.segment_reconciled.get().is_none() {
            store.cleanup_retired(32)?;
            store.recover_startup()?;
            let _ = self.segment_reconciled.set(());
        }
        Ok(store)
    }
}

impl SegmentStore<'_> {
    /// Admits an immutable manifest for a monotonically increasing local generation.
    /// Network negotiation, quota and selector admission are caller prerequisites.
    /// # Errors
    /// Refuses stale generations, identity changes, invalid layout or storage errors.
    fn admit_inner(
        &mut self,
        transfer_id: &str,
        generation: u64,
        direction: SegmentDirection,
        verified: &VerifiedContentManifest,
        reference: Option<&SegmentReference<'_>>,
    ) -> Result<(), StorageError> {
        if transfer_id.is_empty() || transfer_id.len() > 256 || generation == 0 {
            return Err(StorageError::Integrity("segment transfer identity"));
        }
        let _lease = self.lease(transfer_id)?;
        let manifest = verified.manifest();
        let generation = integer(generation)?;
        let canonical =
            manifest.canonical_bytes().map_err(|_| StorageError::Integrity("segment manifest"))?;
        let wire = ramflux_protocol::encode_base64url(manifest.object_id);
        let hash = ramflux_protocol::encode_base64url(
            manifest.hash().map_err(|_| StorageError::Integrity("segment manifest"))?,
        );
        let tx = self.db.connection.immediate_transaction()?;
        self.db.check_object_identity(&wire, &hash)?;
        if let Some(reference) = reference {
            self.check_reference(reference, &wire, &hash)?;
        }
        self.record_resource(transfer_id, generation, &wire, &hash, reference)?;
        let previous = self.db.connection.query_row("SELECT object_id,manifest_hash,direction,segment_generation,segment_manifest FROM object_transfer_state WHERE transfer_id=?1",params![transfer_id],|r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<i64>>(3)?,r.get::<_,Option<Vec<u8>>>(4)?))).optional()?;
        if let Some((old_wire, old_hash, old_direction, old_generation, old_manifest)) = previous {
            if old_wire != wire
                || old_hash != hash.as_bytes()
                || old_direction != direction.name()
                || old_manifest.as_deref() != Some(canonical.as_slice())
                || old_generation.is_none_or(|old| old > generation)
            {
                return Err(StorageError::ObjectIdentityConflict);
            }
            if old_generation == Some(generation) {
                tx.commit()?;
                return Ok(());
            }
            self.db.connection.execute(
                "DELETE FROM object_segment_file WHERE transfer_id=?1",
                params![transfer_id],
            )?;
            self.db.connection.execute("UPDATE object_transfer_state SET segment_generation=?2,segment_sequence=segment_sequence+1,done_bytes=0,state='segmented',completed_chunk_bitmap=x'5b5d',missing_chunk_bitmap=x'5b5d' WHERE transfer_id=?1",params![transfer_id,generation])?;
        } else {
            self.db.connection.execute("INSERT INTO object_transfer_state(transfer_id,object_id,direction,peer_device_id,manifest_hash,missing_chunk_bitmap,completed_chunk_bitmap,state,updated_at,chunk_size,total_bytes,done_bytes,total_chunks,segment_generation,segment_manifest) VALUES(?1,?2,?3,'',?4,x'5b5d',x'5b5d','segmented',0,?5,?6,0,?7,?8,?9)",params![transfer_id,wire,direction.name(),hash.as_bytes(),manifest.layout.network_chunk_bytes,integer(manifest.layout.dimensions().map_err(|_| StorageError::Integrity("segment layout"))?.1)?,integer(manifest.layout.dimensions().map_err(|_|StorageError::Integrity("segment layout"))?.1.div_ceil(u64::from(manifest.layout.network_chunk_bytes)))?,generation,canonical])?;
        }
        for (index, digest) in manifest.segment_digests.iter().enumerate() {
            let length = manifest
                .layout
                .segment_plaintext_length(index as u64)
                .map_err(|_| StorageError::Integrity("segment index"))?
                + 16;
            self.db.connection.execute("INSERT INTO object_segment_file(transfer_id,generation,segment_index,expected_digest,expected_length,chunk_digests) VALUES(?1,?2,?3,?4,?5,zeroblob(256))",params![transfer_id,generation,integer(index as u64)?,digest.as_slice(),integer(length)?])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Bounded keyset page; start is inclusive, the next page starts at last+1.
    /// # Errors
    /// Refuses stale generations, invalid limits and database corruption.
    fn metadata_page(
        &self,
        transfer_id: &str,
        generation: u64,
        start: u32,
        limit: u32,
    ) -> Result<Vec<SegmentPageEntry>, StorageError> {
        if limit == 0 || limit > PAGE_LIMIT {
            return Err(StorageError::Integrity("segment page limit"));
        }
        self.current(transfer_id, generation)?;
        let mut stmt = self.db.connection.prepare("SELECT segment_index,expected_digest,expected_length,received_bitmap,cipher_verified FROM object_segment_file WHERE transfer_id=?1 AND generation=?2 AND segment_index>=?3 ORDER BY segment_index LIMIT ?4")?;
        let rows = stmt
            .query_map(params![transfer_id, integer(generation)?, start, limit], |r| {
                Ok((
                    r.get::<_, u32>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, u8>(3)?,
                    r.get::<_, bool>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(index, hash, expected_length, received_bitmap, cipher_verified)| {
                if !(16..=4_194_304).contains(&expected_length) {
                    return Err(StorageError::Integrity("segment expected length"));
                }
                let expected_length = u64::try_from(expected_length)
                    .map_err(|_| StorageError::Integrity("segment expected length"))?;
                let chunk = self.current(transfer_id, generation)?;
                if expected_length.div_ceil(u64::from(chunk)) > 8 {
                    return Err(StorageError::Integrity("segment expected length"));
                }
                Ok(SegmentPageEntry {
                    index,
                    expected_digest: hash
                        .try_into()
                        .map_err(|_| StorageError::Integrity("segment digest length"))?,
                    expected_length,
                    received_bitmap,
                    cipher_verified,
                })
            })
            .collect()
    }

    /// Durable monotonic progress sequence, never inferred from unverified files.
    /// # Errors
    /// Refuses stale generations or unreadable progress.
    pub fn sequence(&self, transfer_id: &str, generation: u64) -> Result<u64, StorageError> {
        self.current(transfer_id, generation)?;
        Ok(self.db.connection.query_row(
            "SELECT segment_sequence FROM object_transfer_state WHERE transfer_id=?1",
            params![transfer_id],
            |r| r.get(0),
        )?)
    }

    fn current(&self, id: &str, generation: u64) -> Result<u32, StorageError> {
        let row = self.db.connection.query_row("SELECT segment_generation,object_id,manifest_hash,chunk_size FROM object_transfer_state WHERE transfer_id=?1 AND state='segmented'",params![id],|r| Ok((r.get::<_,Option<i64>>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,i64>(3)?))).optional()?.ok_or(StorageError::ObjectIdentityConflict)?;
        if generation == 0
            || row.0 != Some(integer(generation)?)
            || !matches!(row.3, 524_288 | 1_048_576)
        {
            return Err(StorageError::ObjectIdentityConflict);
        }
        self.check_resource(id, generation)?;
        let hash =
            std::str::from_utf8(&row.2).map_err(|_| StorageError::Integrity("manifest hash"))?;
        self.db.check_object_identity(&row.1, hash)?;
        u32::try_from(row.3).map_err(|_| StorageError::ObjectIdentityConflict)
    }

    /// Returns a bounded keyset page after the store's startup reconciliation.
    /// # Errors
    /// Refuses invalid bounds, stale identity or unreadable persistence.
    pub fn page(
        &mut self,
        id: &str,
        generation: u64,
        start: u32,
        limit: u32,
    ) -> Result<Vec<SegmentPageEntry>, StorageError> {
        self.metadata_page(id, generation, start, limit)
    }

    fn lease(&self, id: &str) -> Result<retirement::ResourceLease, StorageError> {
        let name = ramflux_protocol::encode_base64url(blake3::hash(id.as_bytes()).as_bytes());
        let path = self.root.join(name);
        let held = lease::Lease::acquire(path.clone())?;
        Ok(retirement::ResourceLease::new(held, self.db.connection.clone(), path))
    }

    fn recover_startup(&mut self) -> Result<(), StorageError> {
        let mut after = String::new();
        loop {
            let mut stmt=self.db.connection.prepare("SELECT transfer_id,segment_generation FROM object_transfer_state WHERE segment_generation IS NOT NULL AND state='segmented' AND transfer_id>?1 ORDER BY transfer_id LIMIT 128")?;
            let transfers = stmt
                .query_map(params![after], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            if transfers.is_empty() {
                break;
            }
            for (id, generation) in transfers {
                after.clone_from(&id);
                let _lease = match self.lease(&id) {
                    Ok(lease) => lease,
                    Err(StorageError::AccountWriterBusy(_)) => continue,
                    Err(error) => return Err(error),
                };
                let generation = match u64::try_from(generation) {
                    Ok(g) if g > 0 => g,
                    _ => {
                        self.quarantine(&id, generation)?;
                        continue;
                    }
                };
                if matches!(self.current(&id, generation), Err(StorageError::ObjectErased)) {
                    continue;
                }
                let mut start = 0;
                loop {
                    let rows = match self.recover_page(&id, generation, start, PAGE_LIMIT) {
                        Ok(rows) => rows,
                        Err(StorageError::Integrity(_) | StorageError::ObjectIdentityConflict) => {
                            self.quarantine(&id, integer(generation)?)?;
                            break;
                        }
                        Err(error) => return Err(error),
                    };
                    let Some(last) = rows.last() else {
                        break;
                    };
                    start = last
                        .index
                        .checked_add(1)
                        .ok_or(StorageError::Integrity("segment page cursor"))?;
                    if rows.len() < PAGE_LIMIT as usize {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn quarantine(&self, id: &str, generation: i64) -> Result<(), StorageError> {
        let tx = self.db.connection.immediate_transaction()?;
        self.db.connection.execute("UPDATE object_transfer_state SET state='segment_quarantined',last_error='segment_integrity',done_bytes=0,segment_sequence=segment_sequence+1 WHERE transfer_id=?1 AND segment_generation=?2",params![id,generation])?;
        self.db.connection.execute("UPDATE object_segment_file SET received_bitmap=0,cipher_verified=0 WHERE transfer_id=?1 AND generation=?2",params![id,generation])?;
        tx.commit()?;
        Ok(())
    }

    fn location(&self, id: &str, generation: u64) -> PathBuf {
        let name = ramflux_protocol::encode_base64url(blake3::hash(id.as_bytes()).as_bytes());
        self.root.join(name).join(generation.to_string())
    }

    fn directory(&self, id: &str, generation: u64) -> Result<PathBuf, StorageError> {
        let name = ramflux_protocol::encode_base64url(blake3::hash(id.as_bytes()).as_bytes());
        let parent = self.root.join(name);
        files::private_dir(&parent)?;
        let path = parent.join(generation.to_string());
        files::private_dir(&path)?;
        Ok(path)
    }
}
fn integer(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::Integrity("segment integer overflow"))
}
