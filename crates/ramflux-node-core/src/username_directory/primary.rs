// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private per-incarnation projection. A rebuild has no serving head until its final durable commit.
use super::{
    CheckpointError, CheckpointHead, IMAGE, ImagePage, META, Result, WriterIdentity, apply,
    canonical, cell, image::ImagePlan, put_head, read_head, require, reserve_file, storage,
};
use ramflux_protocol::username_directory as w;
use std::path::Path;

pub struct PrimaryProjection {
    db: redb::Database,
    writer: WriterIdentity,
    rebuilding: Option<CheckpointHead>,
    last_key: Option<Vec<u8>>,
    complete: bool,
}

impl PrimaryProjection {
    /// Creates only a new private image; it never opens or rewrites a predecessor's file.
    /// # Errors
    /// Refuses existing paths, unsafe writer identity, and unavailable durable storage.
    pub fn create(path: &Path, writer: WriterIdentity) -> Result<Self> {
        super::fixed(&writer.witness_boot)?;
        super::fixed(&writer.incarnation)?;
        require(writer.generation > 0, "generation")?;
        reserve_file(path)?;
        crate::durability_io::sync_dir(
            path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")),
        )?;
        let db = redb::Database::create(path).map_err(storage)?;
        let mut tx = db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        tx.open_table(IMAGE).map_err(storage)?;
        tx.open_table(META)
            .map_err(storage)?
            .insert("writer", canonical(&writer)?.as_slice())
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(Self { db, writer, rebuilding: None, last_key: None, complete: false })
    }

    /// # Errors
    /// Refuses foreign generations, repeated initialization and malformed target heads.
    pub fn begin_rebuild(&mut self, target: &CheckpointHead) -> Result<()> {
        target.validate()?;
        require(
            self.rebuilding.is_none()
                && !self.complete
                && target.generation == self.writer.generation,
            "rebuild_state",
        )?;
        self.rebuilding = Some(target.clone());
        Ok(())
    }

    /// Source pages come from the authenticated witness, outside projection DB transactions.
    /// # Errors
    /// Refuses reordered/duplicate pages, malformed image cells, oversized pages or a changed head.
    pub fn copy_image_page(&mut self, target: &CheckpointHead, page: ImagePage) -> Result<()> {
        require(
            self.rebuilding.as_ref() == Some(target) && !self.complete && page.rows.len() <= 128,
            "rebuild_state",
        )?;
        if page.rows.is_empty() {
            require(page.next.is_none(), "rebuild_cursor")?;
            self.complete = true;
            return Ok(());
        }
        let mut rows = Vec::new();
        let mut batches = Vec::new();
        let mut previous = self.last_key.clone();
        for (key, value) in page.rows {
            require(previous.as_ref().is_none_or(|last| last < &key), "rebuild_order")?;
            let row: w::Replacement = w::decode(&value)?;
            if let w::Replacement::Batch { key: id, old: None, new: Some(_) } = &row {
                require(super::checkpoint_batch::batch_key(id)? == key, "rebuild_key")?;
                batches.push((key.clone(), value));
            } else {
                let (expected, old, new) = cell(&row)?;
                require(expected == key && old.is_none() && new.is_some(), "rebuild_key")?;
                rows.push(row);
            }
            previous = Some(key);
        }
        require(page.next == previous, "rebuild_cursor")?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        // The source image wrappers are already canonical and individually admitted.
        let delta = w::CheckpointDelta {
            kind: w::DeltaKind::Gc,
            tx_id: self.writer.incarnation.clone(),
            writer_incarnation: self.writer.incarnation.clone(),
            clock_floor: target.clock_floor,
            operation: None,
            rows,
        };
        apply(&tx, &delta)?;
        {
            let mut image = tx.open_table(IMAGE).map_err(storage)?;
            for (key, value) in batches {
                image.insert(key.as_slice(), value.as_slice()).map_err(storage)?;
            }
        }
        tx.commit().map_err(storage)?;
        self.last_key = previous;
        Ok(())
    }

    /// Only an unchanged final witness head can publish the projection's first durable head.
    /// The caller must then notify PrimaryApplied using this same writer identity.
    /// # Errors
    /// Refuses interrupted rebuilds and witness changes; never selects max(primary,witness).
    pub fn finish_rebuild(&mut self, final_witness: &CheckpointHead) -> Result<CheckpointHead> {
        require(
            self.complete && self.rebuilding.as_ref() == Some(final_witness),
            "rebuild_incomplete",
        )?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        put_head(&tx, final_witness)?;
        tx.commit().map_err(storage)?;
        self.rebuilding = None;
        read_head(&self.db)
    }

    /// Apply exactly one canonical record or one descriptor-bound delete pair atomically.
    /// # Errors
    /// Refuses stale images/heads, missing members and wrong chain/digest/generation correlations.
    pub fn apply_records(
        &mut self,
        records: &[w::Checkpoint],
        batch: Option<&w::BatchRow>,
    ) -> Result<CheckpointHead> {
        require(
            self.rebuilding.is_none()
                && self.complete
                && records.len() == if batch.is_some() { 2 } else { 1 },
            "primary_group",
        )?;
        let mut next = read_head(&self.db)?;
        for record in records {
            w::encode(record)?;
            require(
                record.center_id == next.center_id
                    && record.generation == next.generation
                    && next.lsn.checked_add(1) == Some(record.lsn)
                    && record.previous_digest == next.digest
                    && record.delta.clock_floor >= next.clock_floor,
                "primary_chain",
            )?;
            next = CheckpointHead {
                lsn: record.lsn,
                digest: ramflux_crypto::username_directory::checkpoint_hash(record)?,
                clock_floor: record.delta.clock_floor,
                ..next
            };
        }
        if let Some(batch) = batch {
            w::encode(batch)?;
            let first = records.first().ok_or(CheckpointError::Refused("primary_group"))?;
            let last = records.last().ok_or(CheckpointError::Refused("primary_group"))?;
            require(
                first.lsn == batch.lsn_n1
                    && last.lsn == batch.lsn_n2
                    && first.delta.tx_id == batch.abort_tx_id
                    && last.delta.tx_id == batch.batch_id
                    && first.delta.kind == w::DeltaKind::Abort
                    && first.delta.operation.is_none()
                    && last.delta.kind == w::DeltaKind::Commit
                    && last.delta.operation.as_ref().is_some_and(|op| {
                        op.body.action == w::Action::Delete
                            && op.body.principal_commitment == batch.root
                    })
                    && ramflux_crypto::username_directory::checkpoint_hash(first)?
                        == batch.result.abort_digest
                    && next.digest == batch.result.delete_digest
                    && first.delta.clock_floor == batch.result.clock_floor
                    && last.delta.clock_floor == batch.result.clock_floor,
                "primary_batch",
            )?;
        }
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        for record in records {
            apply(&tx, &record.delta)?;
        }
        if let Some(batch) = batch {
            let value = w::Replacement::Batch {
                key: batch.batch_id.clone(),
                old: None,
                new: Some(batch.clone()),
            };
            tx.open_table(IMAGE)
                .map_err(storage)?
                .insert(
                    super::checkpoint_batch::batch_key(&batch.batch_id)?.as_slice(),
                    w::encode(&value)?.as_slice(),
                )
                .map_err(storage)?;
        }
        put_head(&tx, &next)?;
        tx.commit().map_err(storage)?;
        Ok(next)
    }

    /// # Errors
    /// Refuses an unpublished or corrupt projection.
    pub fn head(&self) -> Result<CheckpointHead> {
        read_head(&self.db)
    }

    /// # Errors
    /// Refuses reads during an unfinished rebuild or on storage corruption.
    pub fn root(&self, root: &str) -> Result<Option<w::RootRow>> {
        require(self.complete && self.rebuilding.is_none(), "primary_unpublished")?;
        super::fixed(root)?;
        ImagePlan::new(&self.db).root(&root.to_owned())
    }
}
