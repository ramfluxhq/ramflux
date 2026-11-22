// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Single-sync appends, including the witness-derived two-record delete unit.
use super::checkpoint::{owner_index, prune_results, prune_root_results, put_safe_wall};
use super::{
    COMPACTED, CheckpointError, CheckpointHead, CheckpointTime, CheckpointWitness, IMAGE, META,
    REDO, Result, TX_IDS, apply, canonical, fixed, put_head, require, storage,
};
use ramflux_protocol::username_directory as w;
use redb::{ReadableTable, ReadableTableMetadata};

pub(super) struct BatchSeed {
    pub request_hash: String,
}

pub(super) struct AppendGroup<'a> {
    pub expected: &'a CheckpointHead,
    pub deltas: Vec<w::CheckpointDelta>,
    pub root: &'a str,
    pub control: bool,
    pub time: CheckpointTime,
    pub batch: Option<BatchSeed>,
}

impl CheckpointWitness {
    fn validate_group(
        &self,
        expected: &CheckpointHead,
        count: usize,
        batch: bool,
        time: CheckpointTime,
    ) -> Result<()> {
        require(*expected == self.head, "head_cas")?;
        require(count == if batch { 2 } else { 1 }, "batch_count")?;
        require(
            time.monotonic >= self.last_monotonic
                && time.wall >= self.safe_wall
                && time.wall <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "clock",
        )?;
        Ok(())
    }

    pub(super) fn append_group(&mut self, group: AppendGroup<'_>) -> Result<Vec<w::Checkpoint>> {
        let AppendGroup { expected, deltas, root, control, time, batch } = group;
        fixed(root)?;
        self.validate_group(expected, deltas.len(), batch.is_some(), time)?;
        let mut next = self.head.clone();
        let mut records = Vec::new();
        for mut delta in deltas {
            delta.clock_floor = time.wall;
            w::encode(&delta)?;
            let lsn = next
                .lsn
                .checked_add(1)
                .filter(|n| *n <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
                .ok_or(CheckpointError::Refused("lsn_exhausted"))?;
            let record = w::Checkpoint {
                center_id: next.center_id.clone(),
                generation: next.generation,
                lsn,
                previous_digest: next.digest.clone(),
                delta,
            };
            w::encode(&record)?;
            next = CheckpointHead {
                lsn,
                digest: ramflux_crypto::username_directory::checkpoint_hash(&record)?,
                clock_floor: time.wall,
                ..next
            };
            records.push(record);
        }
        let descriptor =
            batch.map(|seed| make_batch(&records, root, &seed.request_hash)).transpose()?;
        require(
            canonical(&(&records, &descriptor))?.len()
                <= if descriptor.is_some() { 135_168 } else { 67_584 + 16 },
            "batch_frame",
        )?;
        let slots =
            u64::try_from(records.len()).map_err(|_| CheckpointError::Refused("batch_count"))?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        prune_root_results(&tx, root, time.wall)?;
        prune_results(&tx, time.wall)?;
        super::checkpoint_batch::prune_batches(&tx, time.wall)?;
        let redo = tx.open_table(REDO).map_err(storage)?;
        let cap = if control { 16384 } else { 16368 };
        require(redo.len().map_err(storage)? + slots <= cap, "redo_global")?;
        let retained = tx.open_table(COMPACTED).map_err(storage)?.len().map_err(storage)?;
        require(redo.len().map_err(storage)? + retained + slots <= cap, "result_global")?;
        drop(redo);
        let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
        let mut seen = std::collections::BTreeSet::new();
        for record in &records {
            require(
                seen.insert(&record.delta.tx_id)
                    && ids.get(record.delta.tx_id.as_str()).map_err(storage)?.is_none(),
                "tx_id",
            )?;
        }
        let mut meta = tx.open_table(META).map_err(storage)?;
        let count_key = format!("redo_root:{root}");
        let count: u64 = meta
            .get(count_key.as_str())
            .map_err(storage)?
            .map(|v| serde_json::from_slice(v.value()))
            .transpose()?
            .unwrap_or(0);
        require(count + slots <= 64, "redo_root")?;
        meta.insert(count_key.as_str(), canonical(&(count + slots))?.as_slice())
            .map_err(storage)?;
        drop(meta);
        let mut redo = tx.open_table(REDO).map_err(storage)?;
        for record in &records {
            let lsn = record.lsn;
            let mut meta = tx.open_table(META).map_err(storage)?;
            meta.insert(format!("redo_owner:{lsn}").as_str(), canonical(&root)?.as_slice())
                .map_err(storage)?;
            meta.insert(owner_index(root, lsn).as_str(), canonical(&true)?.as_slice())
                .map_err(storage)?;
            drop(meta);
            apply(&tx, &record.delta)?;
            redo.insert(lsn, w::encode(record)?.as_slice()).map_err(storage)?;
            ids.insert(record.delta.tx_id.as_str(), lsn).map_err(storage)?;
        }
        if let Some(row) = &descriptor {
            write_batch(&tx, row)?;
        }
        drop(redo);
        drop(ids);
        put_head(&tx, &next)?;
        put_safe_wall(&tx, time.wall)?;
        tx.commit().map_err(storage)?;
        self.head = next;
        self.safe_wall = time.wall;
        self.last_monotonic = time.monotonic;
        Ok(records)
    }
}

fn make_batch(records: &[w::Checkpoint], root: &str, hash: &str) -> Result<w::BatchRow> {
    let abort = records.first().ok_or(CheckpointError::Refused("batch_count"))?;
    let delete = records.last().ok_or(CheckpointError::Refused("batch_count"))?;
    require(
        abort.delta.kind == w::DeltaKind::Abort
            && abort.delta.operation.is_none()
            && delete.delta.kind == w::DeltaKind::Commit
            && delete.delta.operation.as_ref().is_some_and(|op| {
                op.body.action == w::Action::Delete && op.body.principal_commitment == root
            })
            && abort.delta.writer_incarnation == delete.delta.writer_incarnation
            && abort.delta.clock_floor == delete.delta.clock_floor,
        "batch_semantics",
    )?;
    let row = w::BatchRow {
        batch_id: delete.delta.tx_id.clone(),
        root: root.into(),
        request_hash: hash.into(),
        abort_tx_id: abort.delta.tx_id.clone(),
        lsn_n1: abort.lsn,
        lsn_n2: delete.lsn,
        retain_until: super::transitions::after(delete.delta.clock_floor, 86400)?,
        result: w::BatchResult {
            abort_digest: ramflux_crypto::username_directory::checkpoint_hash(abort)?,
            delete_digest: ramflux_crypto::username_directory::checkpoint_hash(delete)?,
            clock_floor: delete.delta.clock_floor,
        },
    };
    w::encode(&row)?;
    Ok(row)
}

fn write_batch(tx: &redb::WriteTransaction, row: &w::BatchRow) -> Result<()> {
    let mut meta = tx.open_table(META).map_err(storage)?;
    let mut image = tx.open_table(IMAGE).map_err(storage)?;
    let key = super::checkpoint_batch::batch_key(&row.batch_id)?;
    require(image.get(key.as_slice()).map_err(storage)?.is_none(), "batch_collision")?;
    let value =
        w::Replacement::Batch { key: row.batch_id.clone(), old: None, new: Some(row.clone()) };
    image.insert(key.as_slice(), w::encode(&value)?.as_slice()).map_err(storage)?;
    for (id, lsn) in [(&row.abort_tx_id, row.lsn_n1), (&row.batch_id, row.lsn_n2)] {
        meta.insert(format!("batch_member:{id}").as_str(), canonical(&row.batch_id)?.as_slice())
            .map_err(storage)?;
        meta.insert(format!("batch_lsn:{lsn:020}").as_str(), canonical(&row.batch_id)?.as_slice())
            .map_err(storage)?;
    }
    meta.insert(
        format!("batch_root:{}:{}", row.root, row.batch_id).as_str(),
        canonical(&true)?.as_slice(),
    )
    .map_err(storage)?;
    meta.insert(
        format!("batch_expiry:{:020}:{}", row.retain_until, row.batch_id).as_str(),
        canonical(&row.batch_id)?.as_slice(),
    )
    .map_err(storage)?;
    Ok(())
}
