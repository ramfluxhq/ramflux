// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A private durable primary projection; its saved head never restores witness READY.
use super::{
    CheckpointError, CheckpointHead, CheckpointObserver, CheckpointWitness, IMAGE, ImagePage,
    Result, WriterLease, apply, cell, page, put_head, read_head, require, reserve_file, storage,
};
use ramflux_protocol::username_directory as wire;
use redb::ReadableDatabase;
use std::path::Path;

pub struct CheckpointPrimary {
    db: redb::Database,
}
impl CheckpointPrimary {
    /// Create one new incarnation-private empty image under privileged bootstrap/reconciliation.
    /// # Errors
    /// Refuses an existing file, invalid genesis head or unavailable storage.
    pub fn create(path: &Path, genesis: &CheckpointHead) -> Result<Self> {
        require(!path.exists(), "primary_exists")?;
        require(genesis.lsn == 0, "primary_genesis")?;
        genesis.validate()?;
        reserve_file(path)?;
        let db = redb::Database::create(path).map_err(storage)?;
        let mut tx = db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        tx.open_table(IMAGE).map_err(storage)?;
        put_head(&tx, genesis)?;
        tx.commit().map_err(storage)?;
        Ok(Self { db })
    }
    /// # Errors
    /// Refuses missing/corrupt primary files; never creates or trusts a saved READY flag.
    pub fn open(path: &Path) -> Result<Self> {
        require(path.is_file(), "missing_primary")?;
        let db = redb::Database::open(path).map_err(storage)?;
        read_head(&db)?;
        Ok(Self { db })
    }
    /// # Errors
    /// Refuses corrupt/unsupported durable metadata.
    pub fn head(&self) -> Result<CheckpointHead> {
        read_head(&self.db)
    }
    /// # Errors
    /// Refuses a foreign/ahead/conflicting primary. A behind primary remains closed for recovery.
    pub fn reconcile(&self, witness: &mut CheckpointWitness, lease: &WriterLease) -> Result<()> {
        let primary = self.head()?;
        let authority = witness.head();
        require(
            primary.center_id == authority.center_id && primary.generation == authority.generation,
            "primary_identity",
        )?;
        require(primary.lsn <= authority.lsn, "primary_ahead")?;
        require(primary.lsn == authority.lsn, "primary_behind")?;
        require(primary == authority, "primary_head")?;
        witness.primary_applied(lease, &primary)
    }
    /// Durably apply the exact witness-issued checkpoint, then notify its captured incarnation.
    /// # Errors
    /// Refuses stale leases/head/CAS, forged checkpoints, I/O or physical-boundary observer faults.
    pub fn apply(
        &self,
        witness: &mut CheckpointWitness,
        lease: &WriterLease,
        checkpoint: &wire::Checkpoint,
        observer: &dyn CheckpointObserver,
    ) -> Result<()> {
        witness.renew(lease)?;
        let old = self.head()?;
        let head = witness.head();
        require(
            checkpoint.center_id == old.center_id && checkpoint.generation == old.generation,
            "primary_identity",
        )?;
        require(
            checkpoint.lsn
                == old.lsn.checked_add(1).ok_or(CheckpointError::Refused("lsn_exhausted"))?
                && checkpoint.previous_digest == old.digest,
            "primary_cas",
        )?;
        require(
            checkpoint.lsn == head.lsn
                && ramflux_crypto::username_directory::checkpoint_hash(checkpoint)? == head.digest,
            "primary_checkpoint",
        )?;
        observer.boundary("before_primary_image")?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        apply(&tx, &checkpoint.delta)?;
        put_head(&tx, &head)?;
        observer.boundary("before_primary_fsync")?;
        tx.commit().map_err(storage)?;
        observer.boundary("after_primary_fsync")?;
        // A retired callback can update only its own file. It cannot mark a replacement READY.
        witness.primary_applied(lease, &head)
    }
    /// Rebuild a NEW private image in indexed pages from the protected authoritative image.
    /// Caller authenticates privileged controller reconciliation; no primary snapshot is imported.
    /// # Errors
    /// Refuses an existing destination, lost lease, corrupt cells or changing/mismatched head.
    pub fn rebuild(
        path: &Path,
        witness: &mut CheckpointWitness,
        lease: &WriterLease,
    ) -> Result<Self> {
        require(!path.exists(), "primary_exists")?;
        witness.renew(lease)?;
        let head = witness.head();
        reserve_file(path)?;
        let db = redb::Database::create(path).map_err(storage)?;
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = witness.image_page(cursor.as_deref(), 128)?;
            if page.rows.is_empty() {
                break;
            }
            let mut tx = db.begin_write().map_err(storage)?;
            tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
            {
                let mut table = tx.open_table(IMAGE).map_err(storage)?;
                for (key, value) in &page.rows {
                    let row: wire::Replacement = wire::decode(value)?;
                    let (expected, old, new) = cell(&row)?;
                    require(
                        expected == *key && old.is_none() && new.as_ref() == Some(value),
                        "image_cell",
                    )?;
                    table.insert(key.as_slice(), value.as_slice()).map_err(storage)?;
                }
            }
            tx.commit().map_err(storage)?;
            cursor = page.next;
            witness.renew(lease)?;
        }
        require(witness.head() == head, "rebuild_head")?;
        let mut tx = db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        tx.open_table(IMAGE).map_err(storage)?;
        put_head(&tx, &head)?;
        tx.commit().map_err(storage)?;
        let primary = Self { db };
        primary.reconcile(witness, lease)?;
        Ok(primary)
    }
    /// # Errors
    /// Refuses malformed bounds or unavailable image pages.
    pub fn image_page(&self, after: Option<&[u8]>, limit: usize) -> Result<ImagePage> {
        page(&self.db, after, limit)
    }
    /// Replayed records are read from the witness, never from an untrusted primary snapshot.
    /// # Errors
    /// Refuses absent/compacted history or any invalid primary application.
    pub fn replay_transaction(
        &self,
        witness: &mut CheckpointWitness,
        lease: &WriterLease,
        tx_id: &str,
        observer: &dyn CheckpointObserver,
    ) -> Result<()> {
        let checkpoint =
            witness.transaction(tx_id)?.ok_or(CheckpointError::Refused("redo_compacted"))?;
        self.apply(witness, lease, &checkpoint, observer)
    }
    /// Independent exact-key inspection for bounded tests and center projection consumers.
    /// # Errors
    /// Refuses invalid typed replacement keys or unavailable storage.
    pub fn image_cell(&self, key: &wire::Replacement) -> Result<Option<Vec<u8>>> {
        let (key, _, _) = cell(key)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(IMAGE).map_err(storage)?;
        Ok(table.get(key.as_slice()).map_err(storage)?.map(|v| v.value().to_vec()))
    }
}
