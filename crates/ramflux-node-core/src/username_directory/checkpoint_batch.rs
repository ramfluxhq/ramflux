// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Batches retain, compact and expire as an indivisible pair with verified durable associations.
use super::{
    COMPACTED, CheckpointError, CheckpointWitness, IMAGE, META, REDO, Result, TX_IDS, canonical,
    require, storage,
};
use ramflux_protocol::username_directory as w;
use redb::ReadableTable;

/// Install the exact retained pair in a private projection during replay or image rebuild.
pub(super) fn install_projection_results(
    tx: &redb::WriteTransaction,
    row: &w::BatchRow,
    records: &[w::Checkpoint],
) -> Result<()> {
    use redb::ReadableTableMetadata;
    require(records.len() == 2, "batch_count")?;
    {
        let mut results = tx.open_table(COMPACTED).map_err(storage)?;
        require(results.len().map_err(storage)? + 2 <= 16384, "result_global")?;
        let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
        let mut meta = tx.open_table(META).map_err(storage)?;
        let count_key = format!("redo_root:{}", row.root);
        let count: u64 = meta
            .get(count_key.as_str())
            .map_err(storage)?
            .map(|v| serde_json::from_slice(v.value()))
            .transpose()?
            .unwrap_or(0);
        require(count + 2 <= 64, "redo_root")?;
        for record in records {
            let id = &record.delta.tx_id;
            require(
                ids.get(id.as_str()).map_err(storage)?.is_none()
                    && results.get(record.lsn).map_err(storage)?.is_none(),
                "batch_collision",
            )?;
            results.insert(record.lsn, w::encode(record)?.as_slice()).map_err(storage)?;
            ids.insert(id.as_str(), record.lsn).map_err(storage)?;
            meta.insert(
                format!("batch_member:{id}").as_str(),
                canonical(&row.batch_id)?.as_slice(),
            )
            .map_err(storage)?;
            meta.insert(
                format!("batch_lsn:{:020}", record.lsn).as_str(),
                canonical(&row.batch_id)?.as_slice(),
            )
            .map_err(storage)?;
            meta.insert(
                format!("redo_owner:{}", record.lsn).as_str(),
                canonical(&row.root)?.as_slice(),
            )
            .map_err(storage)?;
            meta.insert(
                super::checkpoint::owner_index(&row.root, record.lsn).as_str(),
                canonical(&true)?.as_slice(),
            )
            .map_err(storage)?;
        }
        meta.insert(count_key.as_str(), canonical(&(count + 2))?.as_slice()).map_err(storage)?;
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
    }
    pair(tx, row)?;
    Ok(())
}

pub(super) fn batch_key(id: &str) -> Result<Vec<u8>> {
    super::fixed(id)?;
    let mut key = b"batch\0".to_vec();
    key.extend(canonical(&id)?);
    Ok(key)
}

pub(super) fn member_batch(tx: &redb::WriteTransaction, id: &str) -> Result<Option<w::BatchRow>> {
    let batch_id: Option<String> = {
        let meta = tx.open_table(META).map_err(storage)?;
        meta.get(format!("batch_member:{id}").as_str())
            .map_err(storage)?
            .map(|v| serde_json::from_slice(v.value()))
            .transpose()?
    };
    batch_id.map(|id| batch_by_id(tx, &id)).transpose()
}

fn batch_by_id(tx: &redb::WriteTransaction, id: &str) -> Result<w::BatchRow> {
    let image = tx.open_table(IMAGE).map_err(storage)?;
    let key = batch_key(id)?;
    let value = image
        .get(key.as_slice())
        .map_err(storage)?
        .ok_or(CheckpointError::Refused("batch_missing"))?;
    match w::decode(value.value())? {
        w::Replacement::Batch { key, old: None, new: Some(row) }
            if key == id && row.batch_id == id =>
        {
            Ok(row)
        }
        _ => Err(CheckpointError::Refused("batch_corrupt")),
    }
}

pub(super) fn record(tx: &redb::WriteTransaction, lsn: u64) -> Result<w::Checkpoint> {
    let redo = tx.open_table(REDO).map_err(storage)?;
    if let Some(frame) = redo.get(lsn).map_err(storage)? {
        return Ok(w::decode(frame.value())?);
    }
    let retained = tx.open_table(COMPACTED).map_err(storage)?;
    let frame = retained
        .get(lsn)
        .map_err(storage)?
        .ok_or(CheckpointError::Refused("batch_result_missing"))?;
    Ok(w::decode(frame.value())?)
}

pub(super) fn pair(tx: &redb::WriteTransaction, row: &w::BatchRow) -> Result<[w::Checkpoint; 2]> {
    let abort = record(tx, row.lsn_n1)?;
    let delete = record(tx, row.lsn_n2)?;
    require(
        abort.lsn == row.lsn_n1
            && delete.lsn == row.lsn_n2
            && abort.delta.tx_id == row.abort_tx_id
            && delete.delta.tx_id == row.batch_id
            && abort.delta.kind == w::DeltaKind::Abort
            && abort.delta.operation.is_none()
            && delete.delta.kind == w::DeltaKind::Commit
            && delete.delta.operation.as_ref().is_some_and(|op| {
                op.body.action == w::Action::Delete && op.body.principal_commitment == row.root
            })
            && abort.generation == delete.generation
            && abort.center_id == delete.center_id
            && delete.previous_digest == row.result.abort_digest
            && abort.delta.writer_incarnation == delete.delta.writer_incarnation
            && abort.delta.clock_floor == row.result.clock_floor
            && delete.delta.clock_floor == row.result.clock_floor
            && ramflux_crypto::username_directory::checkpoint_hash(&abort)?
                == row.result.abort_digest
            && ramflux_crypto::username_directory::checkpoint_hash(&delete)?
                == row.result.delete_digest,
        "batch_corrupt",
    )?;
    let meta = tx.open_table(META).map_err(storage)?;
    let ids = tx.open_table(TX_IDS).map_err(storage)?;
    for (id, lsn) in [(&row.abort_tx_id, row.lsn_n1), (&row.batch_id, row.lsn_n2)] {
        let owner: String = serde_json::from_slice(
            meta.get(format!("batch_member:{id}").as_str())
                .map_err(storage)?
                .ok_or(CheckpointError::Refused("batch_association"))?
                .value(),
        )?;
        let by_lsn: String = serde_json::from_slice(
            meta.get(format!("batch_lsn:{lsn:020}").as_str())
                .map_err(storage)?
                .ok_or(CheckpointError::Refused("batch_association"))?
                .value(),
        )?;
        require(
            owner == row.batch_id
                && by_lsn == owner
                && ids.get(id.as_str()).map_err(storage)?.is_some_and(|v| v.value() == lsn),
            "batch_association",
        )?;
    }
    Ok([abort, delete])
}

pub(super) type CompactEntry = (u64, String, u64, Vec<u8>);

pub(super) fn compaction_entries(
    tx: &redb::WriteTransaction,
    through: u64,
) -> Result<Vec<CompactEntry>> {
    let raw = {
        let redo = tx.open_table(REDO).map_err(storage)?;
        let mut raw = Vec::new();
        for entry in redo.range(..=through).map_err(storage)?.take(128) {
            let (lsn, frame) = entry.map_err(storage)?;
            raw.push((lsn.value(), frame.value().to_vec()));
        }
        raw
    };
    let mut entries = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    for (lsn, bytes) in raw {
        if visited.contains(&lsn) {
            continue;
        }
        let cp: w::Checkpoint = w::decode(&bytes)?;
        if let Some(batch) = member_batch(tx, &cp.delta.tx_id)? {
            if batch.lsn_n2 > through || entries.len() + 2 > 128 {
                break;
            }
            for record in pair(tx, &batch)? {
                visited.insert(record.lsn);
                entries.push((
                    record.lsn,
                    record.delta.tx_id.clone(),
                    record.delta.clock_floor,
                    w::encode(&record)?,
                ));
            }
        } else {
            if entries.len() == 128 {
                break;
            }
            visited.insert(lsn);
            entries.push((lsn, cp.delta.tx_id, cp.delta.clock_floor, bytes));
        }
    }
    Ok(entries)
}

pub(super) fn prune_batches(tx: &redb::WriteTransaction, now: u64) -> Result<()> {
    let due = {
        let meta = tx.open_table(META).map_err(storage)?;
        let mut due = Vec::new();
        for entry in meta.range("batch_expiry:"..).map_err(storage)?.take(64) {
            let (key, value) = entry.map_err(storage)?;
            if !key.value().starts_with("batch_expiry:") {
                break;
            }
            let id: String = serde_json::from_slice(value.value())?;
            due.push((key.value().to_owned(), id));
        }
        due
    };
    for (index, id) in due {
        let row = batch_by_id(tx, &id)?;
        if now < row.retain_until {
            break;
        }
        {
            let redo = tx.open_table(REDO).map_err(storage)?;
            if redo.get(row.lsn_n1).map_err(storage)?.is_some()
                || redo.get(row.lsn_n2).map_err(storage)?.is_some()
            {
                continue;
            }
        }
        pair(tx, &row)?;
        for (id, lsn) in [(&row.abort_tx_id, row.lsn_n1), (&row.batch_id, row.lsn_n2)] {
            tx.open_table(COMPACTED).map_err(storage)?.remove(lsn).map_err(storage)?;
            tx.open_table(TX_IDS).map_err(storage)?.remove(id.as_str()).map_err(storage)?;
            super::checkpoint::release_result_owner(tx, lsn)?;
            let mut meta = tx.open_table(META).map_err(storage)?;
            meta.remove(format!("batch_member:{id}").as_str()).map_err(storage)?;
            meta.remove(format!("batch_lsn:{lsn:020}").as_str()).map_err(storage)?;
        }
        tx.open_table(IMAGE)
            .map_err(storage)?
            .remove(batch_key(&row.batch_id)?.as_slice())
            .map_err(storage)?;
        let mut meta = tx.open_table(META).map_err(storage)?;
        meta.remove(index.as_str()).map_err(storage)?;
        meta.remove(format!("batch_root:{}:{}", row.root, row.batch_id).as_str())
            .map_err(storage)?;
    }
    Ok(())
}

impl CheckpointWitness {
    /// Only an identical original whole delete request may retrieve a batch result.
    /// # Errors
    /// Refuses reused IDs, member retries and incomplete/corrupt durable associations.
    pub fn delete_batch_retry(&mut self, bytes: &[u8]) -> Result<Option<w::BatchRow>> {
        let request: w::DeletePreemptingPending = w::decode(bytes)?;
        let hash = ramflux_protocol::encode_base64url(blake3::hash(bytes).as_bytes());
        let time = self.sample_time()?;
        self.update_aux(time, |tx| {
            let Some(row) = member_batch(tx, &request.tx_id)? else {
                let ids = tx.open_table(TX_IDS).map_err(storage)?;
                require(
                    ids.get(request.tx_id.as_str()).map_err(storage)?.is_none(),
                    "batch_replay",
                )?;
                return Ok(None);
            };
            require(row.batch_id == request.tx_id && row.request_hash == hash, "batch_replay")?;
            pair(tx, &row)?;
            Ok(Some(row))
        })
    }
}
