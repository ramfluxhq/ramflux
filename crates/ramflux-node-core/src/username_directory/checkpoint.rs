// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed persistence primitive: durable image, bounded redo and atomic delta CAS.
//! Semantic authority admission is a prerequisite supplied by the directory layer.
use super::{
    COMPACTED, CheckpointClock, CheckpointError, CheckpointHead, IMAGE, ImagePage, META, REDO,
    Result, TX_IDS, canonical, fixed, page, put_head, read_head, require, reserve_file, storage,
};
use ramflux_protocol::username_directory as wire;
use redb::{ReadableDatabase, ReadableTable};
use std::{path::Path, sync::Arc};

/// Typed storage primitive, not an authority admission API.
///
/// Callers must validate image relationships, action semantics, quota accounting and
/// signatures before append. Authentication, leases and serving barriers are separate layers.
/// The directory authority supplies those checks before a service can publish a result.
pub struct CheckpointWitness {
    pub(crate) db: redb::Database,
    pub(super) head: CheckpointHead,
    clock: Arc<dyn CheckpointClock>,
    pub(super) last_monotonic: u64,
    pub(super) safe_wall: u64,
}
impl CheckpointWitness {
    /// Privileged initialization only. Service adapters must authenticate controller authority.
    /// # Errors
    /// Refuses existing initialization, malformed schema/clock or unavailable storage.
    pub fn initialize(
        path: &Path,
        center: &str,
        generation: u64,
        clock: Arc<dyn CheckpointClock>,
    ) -> Result<Self> {
        require(!path.exists(), "already_initialized")?;
        let head = CheckpointHead::genesis(center, generation, clock.now().wall)?;
        reserve_file(path)?;
        crate::durability_io::sync_dir(
            path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")),
        )?;
        let db = redb::Database::create(path).map_err(storage)?;
        let mut tx = db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        tx.open_table(META).map_err(storage)?;
        tx.open_table(IMAGE).map_err(storage)?;
        tx.open_table(REDO).map_err(storage)?;
        tx.open_table(TX_IDS).map_err(storage)?;
        tx.open_table(COMPACTED).map_err(storage)?;
        tx.open_table(META)
            .map_err(storage)?
            .insert("initialized", b"1".as_slice())
            .map_err(storage)?;
        put_head(&tx, &head)?;
        put_safe_wall(&tx, head.clock_floor)?;
        tx.commit().map_err(storage)?;
        Self::from_db(db, head, clock)
    }
    /// Open existing protected state; missing anchors are never recreated.
    /// # Errors
    /// Refuses absent/corrupt/foreign/unsupported anchors and a concurrent witness instance.
    pub fn open(
        path: &Path,
        center: &str,
        generation: u64,
        clock: Arc<dyn CheckpointClock>,
    ) -> Result<Self> {
        require(path.is_file(), "missing_witness")?;
        let db = redb::Database::open(path).map_err(storage)?;
        let head = read_head(&db)?;
        require(head.center_id == center && head.generation == generation, "identity")?;
        {
            let tx = db.begin_read().map_err(storage)?;
            let table = tx.open_table(META).map_err(storage)?;
            require(
                table.get("initialized").map_err(storage)?.is_some_and(|v| v.value() == b"1"),
                "uninitialized",
            )?;
        }
        Self::from_db(db, head, clock)
    }
    fn from_db(
        db: redb::Database,
        head: CheckpointHead,
        clock: Arc<dyn CheckpointClock>,
    ) -> Result<Self> {
        let safe_wall = read_safe_wall(&db, head.clock_floor)?;
        let time = clock.now();
        require(
            time.wall >= safe_wall && time.wall <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "clock",
        )?;
        Ok(Self { db, head, clock, last_monotonic: time.monotonic, safe_wall })
    }
    #[must_use]
    pub fn head(&self) -> CheckpointHead {
        self.head.clone()
    }
    /// Append one prevalidated typed delta atomically with its image, digest and retained redo.
    /// `root_id` is the caller-validated redo attribution; `control` requires cleanup authority.
    /// The witness stamps its sampled time; callers do not choose the durable clock floor.
    /// This layer validates wire grammar and exact old images, not authority semantics.
    /// # Errors
    /// Refuses stale heads, invalid rows, rollback, exhaustion or storage failure.
    pub fn append(
        &mut self,
        expected: &CheckpointHead,
        delta: wire::CheckpointDelta,
        root_id: &str,
        control: bool,
    ) -> Result<wire::Checkpoint> {
        let time = self.sample_time()?;
        self.append_at(expected, delta, root_id, control, time)
    }

    pub(super) fn sample_time(&self) -> Result<super::CheckpointTime> {
        let time = self.clock.now();
        require(
            time.monotonic >= self.last_monotonic
                && time.wall >= self.safe_wall
                && time.wall <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "clock",
        )?;
        Ok(time)
    }

    pub(super) fn update_aux<T>(
        &mut self,
        time: super::CheckpointTime,
        update: impl FnOnce(&redb::WriteTransaction) -> Result<T>,
    ) -> Result<T> {
        require(time.wall >= self.safe_wall && time.monotonic >= self.last_monotonic, "clock")?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        let value = update(&tx)?;
        put_safe_wall(&tx, time.wall)?;
        tx.commit().map_err(storage)?;
        self.safe_wall = time.wall;
        self.last_monotonic = time.monotonic;
        Ok(value)
    }

    pub(super) fn append_at(
        &mut self,
        expected: &CheckpointHead,
        delta: wire::CheckpointDelta,
        root_id: &str,
        control: bool,
        time: super::CheckpointTime,
    ) -> Result<wire::Checkpoint> {
        self.append_group(super::checkpoint_group::AppendGroup {
            expected,
            deltas: vec![delta],
            root: root_id,
            control,
            time,
            batch: None,
        })?
        .pop()
        .ok_or(CheckpointError::Refused("append_result"))
    }

    /// Resolve a lost reply by its exact transaction ID; never append a replacement blindly.
    /// # Errors
    /// Refuses invalid IDs or corrupt storage. Results survive compaction for at least 24 hours.
    pub fn transaction(&self, id: &str) -> Result<Option<wire::Checkpoint>> {
        fixed(id)?;
        let tx = self.db.begin_read().map_err(storage)?;
        require(
            tx.open_table(META)
                .map_err(storage)?
                .get(format!("batch_member:{id}").as_str())
                .map_err(storage)?
                .is_none(),
            "batch_member_retry",
        )?;
        let ids = tx.open_table(TX_IDS).map_err(storage)?;
        let Some(lsn) = ids.get(id).map_err(storage)?.map(|v| v.value()) else { return Ok(None) };
        let redo = tx.open_table(REDO).map_err(storage)?;
        if let Some(frame) = redo.get(lsn).map_err(storage)? {
            return Ok(Some(wire::decode(frame.value())?));
        }
        let compacted = tx.open_table(COMPACTED).map_err(storage)?;
        let frame = compacted
            .get(lsn)
            .map_err(storage)?
            .ok_or(CheckpointError::Refused("result_missing"))?;
        Ok(Some(wire::decode(frame.value())?))
    }
    /// # Errors
    /// Refuses oversized pages or unavailable/corrupt image storage.
    pub fn image_page(&self, after: Option<&[u8]>, limit: usize) -> Result<ImagePage> {
        page(&self.db, after, limit)
    }
    /// Compact at most128 already-applied redo records; the authoritative image/head stays intact.
    /// # Errors
    /// Refuses invalid bounds or storage failure. Effects and head already share one durable commit;
    /// primary recovery can use the image after redo compaction.
    pub fn compact(&mut self, through: u64) -> Result<usize> {
        require(through <= self.head.lsn, "compact_head")?;
        let time = self.clock.now();
        require(
            time.monotonic >= self.last_monotonic
                && time.wall >= self.safe_wall
                && time.wall <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "clock",
        )?;
        self.last_monotonic = time.monotonic;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        // Expired results are pruned even when this pass has nothing to compact.
        prune_results(&tx, time.wall)?;
        let entries = super::checkpoint_batch::compaction_entries(&tx, through)?;
        let mut redo = tx.open_table(REDO).map_err(storage)?;
        let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
        let now = time.wall;
        let mut compacted = tx.open_table(COMPACTED).map_err(storage)?;
        for (lsn, id, at, frame) in &entries {
            let batch = super::checkpoint_batch::member_batch(&tx, id)?.is_some();
            if !batch && now.saturating_sub(*at) >= 86400 {
                release_result_owner(&tx, *lsn)?;
            }
            redo.remove(*lsn).map_err(storage)?;
            if batch || now.saturating_sub(*at) < 86400 {
                compacted.insert(*lsn, frame.as_slice()).map_err(storage)?;
            } else {
                ids.remove(id.as_str()).map_err(storage)?;
            }
        }
        drop(compacted);
        drop(ids);
        drop(redo);
        super::checkpoint_batch::prune_batches(&tx, time.wall)?;
        put_safe_wall(&tx, time.wall)?;
        tx.commit().map_err(storage)?;
        self.safe_wall = time.wall;
        Ok(entries.len())
    }
}

// Per-root index key; lsn is zero-padded so one root's entries are a contiguous, oldest-first range.
pub(super) fn owner_index(root: &str, lsn: u64) -> String {
    format!("retained_owner:{root}:{lsn:020}")
}

// Prunes at most 128 expired results owned by `root`, in the caller's transaction.
pub(super) fn prune_root_results(tx: &redb::WriteTransaction, root: &str, now: u64) -> Result<()> {
    let prefix = format!("retained_owner:{root}:");
    let mut expired = Vec::new();
    {
        let meta = tx.open_table(META).map_err(storage)?;
        let compacted = tx.open_table(COMPACTED).map_err(storage)?;
        for entry in meta.range(prefix.as_str()..).map_err(storage)?.take(128) {
            let (key, _) = entry.map_err(storage)?;
            let Some(suffix) = key.value().strip_prefix(prefix.as_str()) else { break };
            let lsn: u64 = suffix.parse().map_err(|_| CheckpointError::Refused("redo_owner"))?;
            // Owned redo that is not yet compacted is newer than every retained result.
            let Some(frame) = compacted.get(lsn).map_err(storage)? else { break };
            let checkpoint: wire::Checkpoint = wire::decode(frame.value())?;
            if now.saturating_sub(checkpoint.delta.clock_floor) < 86400 {
                break;
            }
            if meta
                .get(format!("batch_member:{}", checkpoint.delta.tx_id).as_str())
                .map_err(storage)?
                .is_some()
            {
                continue;
            }
            expired.push((lsn, checkpoint.delta.tx_id));
        }
    }
    let mut compacted = tx.open_table(COMPACTED).map_err(storage)?;
    let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
    for (lsn, id) in expired {
        compacted.remove(lsn).map_err(storage)?;
        ids.remove(id.as_str()).map_err(storage)?;
        release_result_owner(tx, lsn)?;
    }
    Ok(())
}

// lsn and witness time are monotonic, so oldest retained results form an indexed prefix.
pub(super) fn prune_results(tx: &redb::WriteTransaction, now: u64) -> Result<()> {
    let mut compacted = tx.open_table(COMPACTED).map_err(storage)?;
    let mut expired = Vec::new();
    for entry in compacted.iter().map_err(storage)?.take(128) {
        let (lsn, frame) = entry.map_err(storage)?;
        let checkpoint: wire::Checkpoint = wire::decode(frame.value())?;
        if now.saturating_sub(checkpoint.delta.clock_floor) < 86400 {
            break;
        }
        if super::checkpoint_batch::member_batch(tx, &checkpoint.delta.tx_id)?.is_some() {
            continue;
        }
        expired.push((lsn.value(), checkpoint.delta.tx_id));
    }
    let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
    for (lsn, id) in expired {
        compacted.remove(lsn).map_err(storage)?;
        ids.remove(id.as_str()).map_err(storage)?;
        release_result_owner(tx, lsn)?;
    }
    Ok(())
}

// Retained results consume the same root budget as physical redo until safe expiry.
pub(super) fn release_result_owner(tx: &redb::WriteTransaction, lsn: u64) -> Result<()> {
    let mut meta = tx.open_table(META).map_err(storage)?;
    let owner_key = format!("redo_owner:{lsn}");
    let owner: String = serde_json::from_slice(
        meta.get(owner_key.as_str())
            .map_err(storage)?
            .ok_or(CheckpointError::Refused("redo_owner"))?
            .value(),
    )?;
    let count_key = format!("redo_root:{owner}");
    let count: u64 = serde_json::from_slice(
        meta.get(count_key.as_str())
            .map_err(storage)?
            .ok_or(CheckpointError::Refused("redo_root"))?
            .value(),
    )?;
    require(count > 0, "redo_root")?;
    if count == 1 {
        meta.remove(count_key.as_str()).map_err(storage)?;
    } else {
        meta.insert(count_key.as_str(), canonical(&(count - 1))?.as_slice()).map_err(storage)?;
    }
    meta.remove(owner_index(&owner, lsn).as_str()).map_err(storage)?;
    meta.remove(owner_key.as_str()).map_err(storage)?;
    Ok(())
}
fn read_safe_wall(db: &redb::Database, head_floor: u64) -> Result<u64> {
    let tx = db.begin_read().map_err(storage)?;
    let meta = tx.open_table(META).map_err(storage)?;
    let row =
        meta.get("safe_clock").map_err(storage)?.ok_or(CheckpointError::Refused("clock_marker"))?;
    let value: u64 =
        serde_json::from_slice(row.value()).map_err(|_| CheckpointError::Refused("clock"))?;
    require(value >= head_floor && value <= ramflux_protocol::MAX_SAFE_JSON_INTEGER, "clock")?;
    require(canonical(&value)? == row.value(), "clock_canonical")?;
    Ok(value)
}
pub(super) fn put_safe_wall(tx: &redb::WriteTransaction, value: u64) -> Result<()> {
    tx.open_table(META)
        .map_err(storage)?
        .insert("safe_clock", canonical(&value)?.as_slice())
        .map_err(storage)?;
    Ok(())
}
