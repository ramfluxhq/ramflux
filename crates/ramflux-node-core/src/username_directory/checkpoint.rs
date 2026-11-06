// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant typed persistence primitive: durable image, bounded redo and atomic delta CAS.
//! Semantic authority admission is a prerequisite supplied by the directory layer.
use super::{
    COMPACTED, CheckpointClock, CheckpointError, CheckpointHead, IMAGE, ImagePage, META, REDO,
    ReadableTable, Result, TX_IDS, apply, canonical, fixed, page, put_head, read_head, require,
    reserve_file, storage,
};
use ramflux_protocol::username_directory as wire;
use redb::{ReadableDatabase, ReadableTableMetadata};
use std::{path::Path, sync::Arc};

/// Typed storage primitive, not an authority admission API.
///
/// Callers must validate image relationships, action semantics, quota accounting and
/// signatures before append. Authentication, leases and serving barriers are separate layers.
/// No service adapter calls this dormant component.
pub struct CheckpointWitness {
    pub(crate) db: redb::Database,
    head: CheckpointHead,
    clock: Arc<dyn CheckpointClock>,
    last_monotonic: u64,
    safe_wall: u64,
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
        mut delta: wire::CheckpointDelta,
        root_id: &str,
        control: bool,
    ) -> Result<wire::Checkpoint> {
        fixed(root_id)?;
        require(*expected == self.head, "head_cas")?;
        let time = self.clock.now();
        require(
            time.monotonic >= self.last_monotonic
                && time.wall >= self.safe_wall
                && time.wall <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "clock",
        )?;
        delta.clock_floor = time.wall;
        self.last_monotonic = time.monotonic;
        wire::encode(&delta)?;
        let lsn = self
            .head
            .lsn
            .checked_add(1)
            .filter(|v| *v <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or(CheckpointError::Refused("lsn_exhausted"))?;
        let checkpoint = wire::Checkpoint {
            center_id: self.head.center_id.clone(),
            generation: self.head.generation,
            lsn,
            previous_digest: self.head.digest.clone(),
            delta,
        };
        let frame = wire::encode(&checkpoint)?;
        let digest = ramflux_crypto::username_directory::checkpoint_hash(&checkpoint)?;
        let next = CheckpointHead { lsn, digest, clock_floor: time.wall, ..self.head.clone() };
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        prune_results(&tx, time.wall)?;
        let redo = tx.open_table(REDO).map_err(storage)?;
        require(redo.len().map_err(storage)? < if control { 16384 } else { 16368 }, "redo_global")?;
        let retained = tx.open_table(COMPACTED).map_err(storage)?.len().map_err(storage)?;
        require(
            redo.len().map_err(storage)? + retained < if control { 16384 } else { 16368 },
            "result_global",
        )?;
        drop(redo);
        {
            let ids = tx.open_table(TX_IDS).map_err(storage)?;
            require(ids.get(checkpoint.delta.tx_id.as_str()).map_err(storage)?.is_none(), "tx_id")?;
        }
        // Physical redo is bounded independently per root, with no scan over unrelated roots.
        {
            let mut table = tx.open_table(META).map_err(storage)?;
            let index = format!("redo_root:{root_id}");
            let count = table
                .get(index.as_str())
                .map_err(storage)?
                .map(|v| v.value().to_vec())
                .map(|v| serde_json::from_slice::<u64>(&v))
                .transpose()?
                .unwrap_or(0);
            require(count < 64, "redo_root")?;
            table.insert(index.as_str(), canonical(&(count + 1))?.as_slice()).map_err(storage)?;
            table
                .insert(format!("redo_owner:{lsn}").as_str(), canonical(&root_id)?.as_slice())
                .map_err(storage)?;
        }

        apply(&tx, &checkpoint.delta)?;

        tx.open_table(REDO).map_err(storage)?.insert(lsn, frame.as_slice()).map_err(storage)?;
        tx.open_table(TX_IDS)
            .map_err(storage)?
            .insert(checkpoint.delta.tx_id.as_str(), lsn)
            .map_err(storage)?;
        put_head(&tx, &next)?;
        put_safe_wall(&tx, time.wall)?;

        tx.commit().map_err(storage)?;
        self.head = next;
        self.safe_wall = time.wall;

        Ok(checkpoint)
    }
    /// Resolve a lost reply by its exact transaction ID; never append a replacement blindly.
    /// # Errors
    /// Refuses invalid IDs or corrupt storage. Results survive compaction for at least 24 hours.
    pub fn transaction(&self, id: &str) -> Result<Option<wire::Checkpoint>> {
        fixed(id)?;
        let tx = self.db.begin_read().map_err(storage)?;
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
        let mut redo = tx.open_table(REDO).map_err(storage)?;
        let mut entries = Vec::new();
        for row in redo.range(..=through).map_err(storage)?.take(128) {
            let (lsn, frame) = row.map_err(storage)?;
            let checkpoint: wire::Checkpoint = wire::decode(frame.value())?;
            entries.push((
                lsn.value(),
                checkpoint.delta.tx_id,
                checkpoint.delta.clock_floor,
                frame.value().to_vec(),
            ));
        }
        let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
        let now = time.wall;
        let mut compacted = tx.open_table(COMPACTED).map_err(storage)?;
        for (lsn, id, at, frame) in &entries {
            if now.saturating_sub(*at) >= 86400 {
                release_result_owner(&tx, *lsn)?;
            }
            redo.remove(*lsn).map_err(storage)?;
            if now.saturating_sub(*at) < 86400 {
                compacted.insert(*lsn, frame.as_slice()).map_err(storage)?;
            } else {
                ids.remove(id.as_str()).map_err(storage)?;
            }
        }
        drop(compacted);
        drop(ids);
        drop(redo);
        put_safe_wall(&tx, time.wall)?;
        tx.commit().map_err(storage)?;
        self.safe_wall = time.wall;
        Ok(entries.len())
    }
}

// lsn and witness time are monotonic, so oldest retained results form an indexed prefix.
fn prune_results(tx: &redb::WriteTransaction, now: u64) -> Result<()> {
    let mut compacted = tx.open_table(COMPACTED).map_err(storage)?;
    let mut expired = Vec::new();
    for entry in compacted.iter().map_err(storage)?.take(128) {
        let (lsn, frame) = entry.map_err(storage)?;
        let checkpoint: wire::Checkpoint = wire::decode(frame.value())?;
        if now.saturating_sub(checkpoint.delta.clock_floor) < 86400 {
            break;
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
fn release_result_owner(tx: &redb::WriteTransaction, lsn: u64) -> Result<()> {
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
fn put_safe_wall(tx: &redb::WriteTransaction, value: u64) -> Result<()> {
    tx.open_table(META)
        .map_err(storage)?
        .insert("safe_clock", canonical(&value)?.as_slice())
        .map_err(storage)?;
    Ok(())
}
