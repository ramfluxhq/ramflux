// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant independent durable witness image, bounded redo and atomic delta CAS.
use super::{
    CheckpointClock, CheckpointError, CheckpointHead, IMAGE, ImagePage, META, REDO, ReadableTable,
    Result, TX_IDS, apply, canonical, fixed, page, put_head, read_head, require, reserve_file,
    storage,
};
use ramflux_protocol::username_directory as wire;
use redb::{ReadableDatabase, ReadableTableMetadata};
use std::{path::Path, sync::Arc};

/// Durable storage component; service authentication and writer leases are separate layers.
pub struct CheckpointWitness {
    pub(crate) db: redb::Database,
    head: CheckpointHead,
    clock: Arc<dyn CheckpointClock>,
    last_monotonic: u64,
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
        let db = redb::Database::create(path).map_err(storage)?;
        let mut tx = db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        tx.open_table(META).map_err(storage)?;
        tx.open_table(IMAGE).map_err(storage)?;
        tx.open_table(REDO).map_err(storage)?;
        tx.open_table(TX_IDS).map_err(storage)?;
        tx.open_table(META)
            .map_err(storage)?
            .insert("initialized", b"1".as_slice())
            .map_err(storage)?;
        put_head(&tx, &head)?;
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
        let time = clock.now();
        require(
            time.wall >= head.clock_floor && time.wall <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "clock",
        )?;
        Ok(Self { db, head, clock, last_monotonic: time.monotonic })
    }
    #[must_use]
    pub fn head(&self) -> CheckpointHead {
        self.head.clone()
    }
    /// Append one typed delta atomically with its image, digest and retained redo.
    /// # Errors
    /// Refuses stale heads, invalid rows, rollback, exhaustion or storage failure.
    pub fn append(
        &mut self,
        expected: &CheckpointHead,
        delta: wire::CheckpointDelta,
        root_id: &str,
        control: bool,
    ) -> Result<wire::Checkpoint> {
        fixed(root_id)?;
        require(*expected == self.head, "head_cas")?;
        let time = self.clock.now();
        require(
            time.monotonic >= self.last_monotonic
                && time.wall >= self.head.clock_floor
                && time.wall <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "clock",
        )?;
        require(delta.clock_floor == time.wall, "commit_clock")?;
        self.last_monotonic = time.monotonic;
        wire::encode(&delta)?;
        validate_transitions(&delta, root_id, time.wall)?;
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
        let redo = tx.open_table(REDO).map_err(storage)?;
        require(redo.len().map_err(storage)? < if control { 16384 } else { 16368 }, "redo_global")?;
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
        validate_image(&tx, &checkpoint.delta)?;
        validate_counters(&tx, &checkpoint.delta)?;

        tx.open_table(REDO).map_err(storage)?.insert(lsn, frame.as_slice()).map_err(storage)?;
        tx.open_table(TX_IDS)
            .map_err(storage)?
            .insert(checkpoint.delta.tx_id.as_str(), lsn)
            .map_err(storage)?;
        put_head(&tx, &next)?;

        tx.commit().map_err(storage)?;
        self.head = next;

        Ok(checkpoint)
    }
    /// Resolve a lost reply by its exact transaction ID; never append a replacement blindly.
    /// # Errors
    /// Refuses invalid IDs or corrupt storage. Compacted historical IDs may be absent.
    pub fn transaction(&self, id: &str) -> Result<Option<wire::Checkpoint>> {
        fixed(id)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let ids = tx.open_table(TX_IDS).map_err(storage)?;
        let Some(lsn) = ids.get(id).map_err(storage)?.map(|v| v.value()) else { return Ok(None) };
        let redo = tx.open_table(REDO).map_err(storage)?;
        let frame =
            redo.get(lsn).map_err(storage)?.ok_or(CheckpointError::Refused("redo_missing"))?;
        Ok(Some(wire::decode(frame.value())?))
    }
    /// # Errors
    /// Refuses oversized pages or unavailable/corrupt image storage.
    pub fn image_page(&self, after: Option<&[u8]>, limit: usize) -> Result<ImagePage> {
        page(&self.db, after, limit)
    }
    /// Compact at most128 already-applied redo records; the authoritative image/head stays intact.
    /// # Errors
    /// Refuses live primary inequality, invalid bounds or storage failure.
    pub fn compact(&mut self, through: u64) -> Result<usize> {
        require(through <= self.head.lsn, "compact_head")?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        let mut redo = tx.open_table(REDO).map_err(storage)?;
        let mut entries = Vec::new();
        for row in redo.range(..=through).map_err(storage)?.take(128) {
            let (lsn, frame) = row.map_err(storage)?;
            let checkpoint: wire::Checkpoint = wire::decode(frame.value())?;
            entries.push((lsn.value(), checkpoint.delta.tx_id));
        }
        let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
        for (lsn, id) in &entries {
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
                meta.insert(count_key.as_str(), canonical(&(count - 1))?.as_slice())
                    .map_err(storage)?;
            }
            meta.remove(owner_key.as_str()).map_err(storage)?;
            redo.remove(*lsn).map_err(storage)?;
            ids.remove(id.as_str()).map_err(storage)?;
        }
        drop(ids);
        drop(redo);
        tx.commit().map_err(storage)?;
        Ok(entries.len())
    }
}
fn validate_transitions(delta: &wire::CheckpointDelta, root_id: &str, now: u64) -> Result<()> {
    if let Some(op) = &delta.operation {
        require(delta.rows.iter().any(|r|matches!(r, wire::Replacement::Operation {new:Some(row),..} if row.operation == *op)), "operation_missing")?;
        require(
            delta
                .rows
                .iter()
                .any(|r| matches!(r, wire::Replacement::Root {key,..} if key == root_id)),
            "root_missing",
        )?;
    }
    if let Some(operation) = &delta.operation {
        require(
            now.saturating_add(60) >= operation.body.issued_at && now < operation.body.expires_at,
            "operation_expired",
        )?;
    }
    for row in &delta.rows {
        match row {
            wire::Replacement::Root { key, old, new } => {
                validate_root_transition(key, old.as_ref(), new.as_ref(), delta, root_id, now)?;
            }
            wire::Replacement::Operation { key, old, new } => {
                validate_operation_transition(
                    key,
                    old.as_ref(),
                    new.as_ref(),
                    delta,
                    root_id,
                    now,
                )?;
            }
            wire::Replacement::Hold { old, new, .. } => {
                if let Some(next) = new {
                    require(
                        old.is_none()
                            && delta.kind == wire::DeltaKind::Commit
                            && next.release_at == now,
                        "hold_time",
                    )?;
                } else {
                    require(
                        delta.kind == wire::DeltaKind::Gc
                            && old.as_ref().is_some_and(|v| now >= v.hold_until),
                        "hold_gc",
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_root_transition(
    key: &str,
    old: Option<&wire::RootRow>,
    new: Option<&wire::RootRow>,
    delta: &wire::CheckpointDelta,
    root_id: &str,
    now: u64,
) -> Result<()> {
    require(key == root_id, "admission_root")?;
    let next = new.ok_or(CheckpointError::Refused("root_delete"))?;
    if old.is_none() {
        require(
            delta.kind == wire::DeltaKind::Reserve && next.epoch == 0 && !next.deleted,
            "root_initial",
        )?;
    }
    if let Some(previous) = old {
        require(
            !previous.deleted || next.deleted && next.epoch == previous.epoch,
            "deleted_fence",
        )?;
        require(next.epoch >= previous.epoch, "epoch_floor")?;
        require(
            next.profile.epoch >= previous.profile.epoch
                && next.profile.version >= previous.profile.version,
            "profile_floor",
        )?;
        if next.profile.epoch == previous.profile.epoch {
            require(next.profile == previous.profile, "profile_equivocation")?;
        }
        if delta.kind != wire::DeltaKind::Commit {
            require(
                next.epoch == previous.epoch
                    && next.name == previous.name
                    && next.node == previous.node
                    && next.discoverable == previous.discoverable
                    && next.deleted == previous.deleted
                    && next.profile == previous.profile
                    && next.binding_hash == previous.binding_hash
                    && next.current_binding == previous.current_binding
                    && next.receipt_decision == previous.receipt_decision
                    && next.last_operation_id == previous.last_operation_id
                    && next.last_operation_hash == previous.last_operation_hash,
                "uncommitted_authority",
            )?;
        }
    }
    if let Some(decision) = &next.receipt_decision {
        require(decision.committed_at <= now, "decision_time")?;
    }
    if delta.kind == wire::DeltaKind::Commit {
        require(
            next.receipt_decision.as_ref().is_some_and(|v| v.committed_at == now),
            "decision_time",
        )?;
        let op = delta.operation.as_ref().ok_or(CheckpointError::Refused("operation"))?;
        let previous = old.ok_or(CheckpointError::Refused("commit_previous"))?;
        require(
            previous.epoch == op.body.expected_epoch
                && previous.profile == op.body.expected_profile
                && previous.pending_operation_id.as_ref() == Some(&op.body.operation_id)
                && next.pending_operation_id.is_none()
                && next.discoverable == op.body.discoverable
                && next.deleted == (op.body.action == wire::Action::Delete),
            "commit_previous",
        )?;
        require(
            op.body.principal_commitment == *key
                && next.epoch == op.body.next_epoch
                && next.profile == op.body.profile
                && next.current_binding == op.body.binding
                && next.last_operation_id.as_ref() == Some(&op.body.operation_id)
                && next.last_operation_hash.as_ref()
                    == Some(&ramflux_crypto::username_directory::operation_hash(op)?),
            "commit_tuple",
        )?;
    }
    if let Some(binding) = &next.current_binding {
        require(
            next.binding_hash.as_ref()
                == Some(&ramflux_crypto::username_directory::binding_hash(binding)?),
            "binding_hash",
        )?;
    }

    Ok(())
}

fn validate_operation_transition(
    key: &wire::OperationKey,
    old: Option<&wire::OperationRow>,
    new: Option<&wire::OperationRow>,
    delta: &wire::CheckpointDelta,
    root_id: &str,
    now: u64,
) -> Result<()> {
    require(key.root == root_id, "admission_root")?;
    if let Some(next) = new {
        require(
            next.operation_hash
                == ramflux_crypto::username_directory::operation_hash(&next.operation)?,
            "operation_hash",
        )?;
        if let Some(previous) = old {
            require(
                next.operation == previous.operation
                    && next.operation_hash == previous.operation_hash
                    && next.reserved_at == previous.reserved_at
                    && next.reservation_expires_at == previous.reservation_expires_at,
                "operation_immutable",
            )?;
            require(
                previous.state == wire::ReceiptState::Reserved
                    && next.state != wire::ReceiptState::Reserved,
                "operation_state",
            )?;
        }
        if next.state == wire::ReceiptState::Reserved {
            require(next.reserved_at == now, "reservation_time")?;
        } else {
            require(next.finished_at == Some(now), "finished_at")?;
        }
        if next.state == wire::ReceiptState::Committed {
            require(
                now < next.reservation_expires_at && now < next.operation.body.expires_at,
                "operation_expired",
            )?;
        }
    } else {
        require(
            delta.kind == wire::DeltaKind::Gc
                && old.is_some_and(|v| {
                    v.state != wire::ReceiptState::Reserved
                        && v.retain_until.is_some_and(|until| now >= until)
                }),
            "detail_gc",
        )?;
    }

    Ok(())
}

// Every lookup addresses a typed key in the resulting transaction image. No whole-image clone.
fn image_row(
    tx: &redb::WriteTransaction,
    probe: &wire::Replacement,
) -> Result<Option<wire::Replacement>> {
    let (key, _, _) = super::cell(probe)?;
    let table = tx.open_table(IMAGE).map_err(storage)?;
    table
        .get(key.as_slice())
        .map_err(storage)?
        .map(|r| wire::decode(r.value()).map_err(Into::into))
        .transpose()
}
macro_rules! lookup {
    ($tx:expr, $variant:ident, $key:expr) => {
        match image_row($tx, &wire::Replacement::$variant { key: $key, old: None, new: None })? {
            Some(wire::Replacement::$variant { new, .. }) => new,
            None => None,
            _ => return Err(CheckpointError::Refused("image_type")),
        }
    };
}
fn operation_due(key: &wire::OperationKey, row: &wire::OperationRow) -> wire::DueKey {
    wire::DueKey::Operation {
        at: row.retain_until.unwrap_or(row.reservation_expires_at),
        root: key.root.clone(),
        operation_id: key.operation_id.clone(),
        phase: if row.state == wire::ReceiptState::Reserved {
            wire::DuePhase::Reservation
        } else {
            wire::DuePhase::Detail
        },
    }
}
fn root_due(root: &wire::RootRow) -> Option<u64> {
    root.changes
        .iter()
        .map(|t| t.saturating_add(2_592_000))
        .chain(root.hold_deadlines.iter().copied())
        .min()
}
fn validate_image(tx: &redb::WriteTransaction, delta: &wire::CheckpointDelta) -> Result<()> {
    for row in &delta.rows {
        validate_root_image(tx, row, delta)?;
        validate_name_image(tx, row)?;
        validate_skeleton_image(tx, row)?;
        validate_operation_image(tx, row)?;
        validate_owner_image(tx, row)?;
        validate_hold_image(tx, row)?;
        validate_due_image(tx, row, delta)?;
    }
    Ok(())
}
fn validate_root_image(
    tx: &redb::WriteTransaction,
    replacement: &wire::Replacement,
    delta: &wire::CheckpointDelta,
) -> Result<()> {
    if let wire::Replacement::Root { key, old, new } = replacement {
        if let Some(root) = new {
            require(
                root.changes.iter().all(|t| *t <= delta.clock_floor)
                    && root
                        .hold_deadlines
                        .iter()
                        .all(|t| *t <= delta.clock_floor.saturating_add(2_592_000)),
                "root_time",
            )?;
            if let Some(name) = &root.name {
                let index =
                    lookup!(tx, Name, name.clone()).ok_or(CheckpointError::Refused("root_name"))?;
                require(
                    index.root == *key && index.state == wire::IndexState::Active,
                    "root_name",
                )?;
            }
            if let Some(id) = &root.pending_operation_id {
                let op = lookup!(
                    tx,
                    Operation,
                    wire::OperationKey { root: key.clone(), operation_id: id.clone() }
                )
                .ok_or(CheckpointError::Refused("root_pending"))?;
                require(
                    op.state == wire::ReceiptState::Reserved
                        && op.operation.body.expected_epoch == root.epoch
                        && op.operation.body.expected_profile == root.profile,
                    "root_pending",
                )?;
            }
            if let Some(at) = root_due(root) {
                require(
                    lookup!(tx, Due, wire::DueKey::RootWindow { at, root: key.clone() }).is_some(),
                    "root_due",
                )?;
            }
        }
        if let Some(root) = old {
            if let Some(name) = &root.name
                && new.as_ref().and_then(|r| r.name.as_ref()) != Some(name)
            {
                require(lookup!(tx, Name, name.clone()).is_none(), "old_name")?;
            }
            if let Some(at) = root_due(root)
                && new.as_ref().and_then(root_due) != Some(at)
            {
                require(
                    lookup!(tx, Due, wire::DueKey::RootWindow { at, root: key.clone() }).is_none(),
                    "old_due",
                )?;
            }
        }
    }
    Ok(())
}

fn validate_name_image(tx: &redb::WriteTransaction, replacement: &wire::Replacement) -> Result<()> {
    if let wire::Replacement::Name { key, old, new } = replacement {
        let skeleton = ramflux_protocol::username_comparison_key(key).map_err(storage)?;
        let paired = lookup!(tx, Skeleton, skeleton.clone());
        if let Some(row) = new {
            let pair = paired.ok_or(CheckpointError::Refused("name_pair"))?;
            require(
                pair.name == *key
                    && pair.root == row.root
                    && pair.state == row.state
                    && pair.operation_id == row.operation_id,
                "name_pair",
            )?;
            let root =
                lookup!(tx, Root, row.root.clone()).ok_or(CheckpointError::Refused("name_root"))?;
            match row.state {
                wire::IndexState::Active => {
                    require(root.name.as_ref() == Some(key), "name_root")?;
                }
                wire::IndexState::Reserved => {
                    require(root.pending_operation_id == row.operation_id, "name_pending")?;
                    let operation = lookup!(
                        tx,
                        Operation,
                        wire::OperationKey {
                            root: row.root.clone(),
                            operation_id: row
                                .operation_id
                                .clone()
                                .ok_or(CheckpointError::Refused("name_pending"))?
                        }
                    )
                    .ok_or(CheckpointError::Refused("name_pending"))?;
                    require(
                        operation.state == wire::ReceiptState::Reserved
                            && operation
                                .operation
                                .body
                                .binding
                                .as_ref()
                                .is_some_and(|b| b.body.name == *key),
                        "name_pending",
                    )?;
                }
            }
        } else if let Some(row) = old {
            require(paired.is_none_or(|p| p.name != *key || p.root != row.root), "name_pair")?;
        }
    }
    Ok(())
}

fn validate_skeleton_image(
    tx: &redb::WriteTransaction,
    replacement: &wire::Replacement,
) -> Result<()> {
    match replacement {
        wire::Replacement::Skeleton { key: _, old: _, new: Some(row) } => {
            let pair = lookup!(tx, Name, row.name.clone())
                .ok_or(CheckpointError::Refused("skeleton_pair"))?;
            require(
                pair.root == row.root
                    && pair.state == row.state
                    && pair.operation_id == row.operation_id,
                "skeleton_pair",
            )?;
        }
        wire::Replacement::Skeleton { old: Some(row), new: None, .. } => {
            require(lookup!(tx, Name, row.name.clone()).is_none(), "skeleton_pair")?;
        }
        _ => {}
    }
    Ok(())
}
fn validate_operation_image(
    tx: &redb::WriteTransaction,
    replacement: &wire::Replacement,
) -> Result<()> {
    if let wire::Replacement::Operation { key, old, new } = replacement {
        if let Some(row) = new {
            let owner = lookup!(tx, OpOwner, key.operation_id.clone())
                .ok_or(CheckpointError::Refused("operation_owner"))?;
            require(
                owner.root == key.root && owner.operation_hash == row.operation_hash,
                "operation_owner",
            )?;
            require(lookup!(tx, Due, operation_due(key, row)).is_some(), "operation_due")?;
            let root = lookup!(tx, Root, key.root.clone())
                .ok_or(CheckpointError::Refused("operation_root"))?;
            if row.state == wire::ReceiptState::Reserved {
                require(
                    root.pending_operation_id.as_ref() == Some(&key.operation_id),
                    "operation_pending",
                )?;
            } else {
                require(
                    root.pending_operation_id.as_ref() != Some(&key.operation_id),
                    "operation_pending",
                )?;
            }
            if row.state == wire::ReceiptState::Committed
                && root.last_operation_id.as_ref() == Some(&key.operation_id)
            {
                require(
                    root.receipt_decision
                        .as_ref()
                        .is_some_and(|d| Some(d.committed_at) == row.finished_at),
                    "receipt_decision",
                )?;
            }
        } else {
            require(lookup!(tx, OpOwner, key.operation_id.clone()).is_none(), "operation_owner")?;
        }
        if let Some(row) = old
            && new.as_ref().is_none_or(|n| operation_due(key, n) != operation_due(key, row))
        {
            require(lookup!(tx, Due, operation_due(key, row)).is_none(), "old_due")?;
        }
    }
    Ok(())
}

fn validate_owner_image(
    tx: &redb::WriteTransaction,
    replacement: &wire::Replacement,
) -> Result<()> {
    match replacement {
        wire::Replacement::OpOwner { key, new: Some(row), .. } => {
            let op = lookup!(
                tx,
                Operation,
                wire::OperationKey { root: row.root.clone(), operation_id: key.clone() }
            )
            .ok_or(CheckpointError::Refused("owner_operation"))?;
            require(op.operation_hash == row.operation_hash, "owner_operation")?;
        }
        wire::Replacement::OpOwner { key, old: Some(row), new: None } => {
            require(
                lookup!(
                    tx,
                    Operation,
                    wire::OperationKey { root: row.root.clone(), operation_id: key.clone() }
                )
                .is_none(),
                "owner_operation",
            )?;
        }
        _ => {}
    }
    Ok(())
}
fn validate_hold_image(tx: &redb::WriteTransaction, replacement: &wire::Replacement) -> Result<()> {
    if let wire::Replacement::Hold { key, new, old } = replacement {
        let due = |r: &wire::HoldRow| wire::DueKey::Hold {
            at: r.hold_until,
            name: key.name.clone(),
            skeleton: key.skeleton.clone(),
        };
        if let Some(row) = new {
            require(
                lookup!(tx, Name, key.name.clone()).is_none()
                    && lookup!(tx, Skeleton, key.skeleton.clone()).is_none(),
                "hold_overlap",
            )?;
            require(lookup!(tx, Due, due(row)).is_some(), "hold_due")?;
        } else if let Some(row) = old {
            require(lookup!(tx, Due, due(row)).is_none(), "old_due")?;
        }
    }
    Ok(())
}

fn validate_due_image(
    tx: &redb::WriteTransaction,
    replacement: &wire::Replacement,
    delta: &wire::CheckpointDelta,
) -> Result<()> {
    if let wire::Replacement::Due { key, new: Some(row), .. } = replacement {
        match key {
            wire::DueKey::Operation { root, operation_id, .. } => {
                let op_key =
                    wire::OperationKey { root: root.clone(), operation_id: operation_id.clone() };
                let op = lookup!(tx, Operation, op_key.clone())
                    .ok_or(CheckpointError::Refused("due_operation"))?;
                require(operation_due(&op_key, &op) == *key, "due_operation")?;
            }
            wire::DueKey::Hold { at, name, skeleton } => {
                let hold = lookup!(
                    tx,
                    Hold,
                    wire::HoldKey { name: name.clone(), skeleton: skeleton.clone() }
                )
                .ok_or(CheckpointError::Refused("due_hold"))?;
                require(hold.hold_until == *at, "due_hold")?;
            }
            wire::DueKey::RootWindow { at, root } => {
                let root =
                    lookup!(tx, Root, root.clone()).ok_or(CheckpointError::Refused("due_root"))?;
                require(root_due(&root) == Some(*at), "due_root")?;
            }
            wire::DueKey::HomeHoldCredit { at, .. } => require(
                row.count > 0 && *at <= delta.clock_floor.saturating_add(2_592_000),
                "credit_time",
            )?,
        }
    }
    Ok(())
}

fn validate_counters(tx: &redb::WriteTransaction, delta: &wire::CheckpointDelta) -> Result<()> {
    let mut changes: std::collections::BTreeMap<Vec<u8>, (wire::CounterKey, i128)> =
        std::collections::BTreeMap::new();
    let mut charge = |key: wire::CounterKey, amount: i128| -> Result<()> {
        let entry = changes.entry(canonical(&key)?).or_insert((key, 0));
        entry.1 += amount;
        Ok(())
    };
    for replacement in &delta.rows {
        match replacement {
            wire::Replacement::Root { old, new, .. } => {
                for (row, sign) in [(old, -1), (new, 1)] {
                    if let Some(root) = row {
                        for (metric, present) in [
                            (wire::Metric::RootSlots, true),
                            (wire::Metric::ActiveNames, root.name.is_some()),
                            (wire::Metric::PendingOperations, root.pending_operation_id.is_some()),
                        ] {
                            if present {
                                charge(wire::CounterKey::Global { metric }, sign)?;
                                charge(
                                    wire::CounterKey::Home { home: root.node.clone(), metric },
                                    sign,
                                )?;
                            }
                        }
                    }
                }
            }
            wire::Replacement::Hold { old, new, .. } => charge(
                wire::CounterKey::Global { metric: wire::Metric::HeldNames },
                i128::from(new.is_some()) - i128::from(old.is_some()),
            )?,
            wire::Replacement::Operation { key, old, new } => {
                let root = lookup!(tx, Root, key.root.clone())
                    .ok_or(CheckpointError::Refused("operation_root"))?;
                let amount = i128::from(new.is_some()) - i128::from(old.is_some());
                charge(
                    wire::CounterKey::Global { metric: wire::Metric::OperationDetails },
                    amount,
                )?;
                charge(
                    wire::CounterKey::Home {
                        home: root.node,
                        metric: wire::Metric::OperationDetails,
                    },
                    amount,
                )?;
            }
            wire::Replacement::Due { key: wire::DueKey::HomeHoldCredit { home, .. }, old, new } => {
                let amount = i128::from(new.as_ref().map_or(0, |r| r.count))
                    - i128::from(old.as_ref().map_or(0, |r| r.count));
                charge(
                    wire::CounterKey::Home { home: home.clone(), metric: wire::Metric::HeldNames },
                    amount,
                )?;
            }
            _ => {}
        }
    }
    for row in &delta.rows {
        if let wire::Replacement::Counter { key, old, new } = row {
            let expected = changes.remove(&canonical(key)?).map_or(0, |(_, v)| v);
            require(
                i128::from(new.as_ref().map_or(0, |r| r.value))
                    - i128::from(old.as_ref().map_or(0, |r| r.value))
                    == expected,
                "counter_delta",
            )?;
            require(
                new.is_some()
                    || old.as_ref().is_some_and(|r| r.value == 0)
                        && delta.kind == wire::DeltaKind::Gc,
                "counter_delete",
            )?;
        }
    }
    require(changes.values().all(|(_, amount)| *amount == 0), "counter_missing")
}
