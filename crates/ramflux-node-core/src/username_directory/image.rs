// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded point-read transaction planning over the witness-owned authority image.
use super::{CheckpointError, IMAGE, META, Result, cell, require, storage};
use ramflux_protocol::username_directory as wire;
use redb::{ReadableDatabase, ReadableTable};
use std::collections::BTreeMap;

pub(super) struct ImagePlan<'a> {
    db: &'a redb::Database,
    base: BTreeMap<(String, Vec<u8>), wire::Replacement>,
    rows: BTreeMap<(String, Vec<u8>), wire::Replacement>,
}

impl<'a> ImagePlan<'a> {
    pub fn new(db: &'a redb::Database) -> Self {
        Self { db, base: BTreeMap::new(), rows: BTreeMap::new() }
    }

    fn get(&self, probe: &wire::Replacement) -> Result<Option<wire::Replacement>> {
        let ordered = probe.order_key()?;
        if let Some(row) = self.rows.get(&ordered) {
            return Ok(Some(row.clone()));
        }
        if let Some(row) = self.base.get(&ordered) {
            return Ok(Some(row.clone()));
        }
        let (key, _, _) = cell(probe)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(IMAGE).map_err(storage)?;
        table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|v| wire::decode(v.value()).map_err(CheckpointError::from))
            .transpose()
    }

    fn put(&mut self, mut row: wire::Replacement) -> Result<()> {
        let key = row.order_key()?;
        if let Some(previous) = self.rows.get(&key) {
            macro_rules! original { ($($arm:ident),*) => { match (&mut row, previous) {
                $((wire::Replacement::$arm { old, .. }, wire::Replacement::$arm { old: original, .. }) => *old = original.clone(),)*
                _ => return Err(CheckpointError::Refused("image_variant")),
            }}; }
            original!(Root, Name, Skeleton, Hold, Operation, OpOwner, Due, Counter, Batch);
        }
        let (_, old, new) = cell(&row)?;
        if old == new {
            self.rows.remove(&key);
        } else {
            wire::encode(&row)?;
            self.rows.insert(key, row);
        }
        require(self.rows.len() <= 256, "delta_rows")?;
        Ok(())
    }

    pub fn finish(self) -> Vec<wire::Replacement> {
        self.rows.into_values().collect()
    }

    pub fn fork(&self) -> Self {
        let mut base = self.base.clone();
        base.extend(self.rows.clone());
        Self { db: self.db, base, rows: BTreeMap::new() }
    }

    pub fn detail_count(&self, root: &str) -> Result<u64> {
        let tx = self.db.begin_read().map_err(storage)?;
        let meta = tx.open_table(META).map_err(storage)?;
        let key = format!("detail_count:{root}");
        meta.get(key.as_str())
            .map_err(storage)?
            .map(|value| serde_json::from_slice(value.value()).map_err(CheckpointError::from))
            .transpose()
            .map(|n| n.unwrap_or(0))
    }

    pub fn held_skeleton(&self, skeleton: &str) -> Result<Option<wire::HoldKey>> {
        let tx = self.db.begin_read().map_err(storage)?;
        let meta = tx.open_table(META).map_err(storage)?;
        let key = format!("held_skeleton:{skeleton}");
        meta.get(key.as_str())
            .map_err(storage)?
            .map(|value| serde_json::from_slice(value.value()).map_err(CheckpointError::from))
            .transpose()
    }
}

pub(super) fn update_indexes(
    tx: &redb::WriteTransaction,
    delta: &wire::CheckpointDelta,
) -> Result<()> {
    let mut meta = tx.open_table(META).map_err(storage)?;
    for row in &delta.rows {
        match row {
            wire::Replacement::Operation { key, old, new } => {
                let index = format!("detail_count:{}", key.root);
                let count: u64 = meta
                    .get(index.as_str())
                    .map_err(storage)?
                    .map(|v| serde_json::from_slice(v.value()))
                    .transpose()?
                    .unwrap_or(0);
                let change = i64::from(new.is_some()) - i64::from(old.is_some());
                let next = count
                    .checked_add_signed(change)
                    .ok_or(CheckpointError::Refused("detail_count"))?;
                meta.insert(index.as_str(), super::canonical(&next)?.as_slice())
                    .map_err(storage)?;
            }
            wire::Replacement::Hold { key, old, new } => {
                let index = format!("held_skeleton:{}", key.skeleton);
                if old.is_none() && new.is_some() {
                    require(meta.get(index.as_str()).map_err(storage)?.is_none(), "hold_skeleton")?;
                    meta.insert(index.as_str(), super::canonical(key)?.as_slice())
                        .map_err(storage)?;
                } else if new.is_none() {
                    let actual =
                        meta.get(index.as_str()).map_err(storage)?.map(|v| v.value().to_vec());
                    require(
                        actual.as_deref() == Some(super::canonical(key)?.as_slice()),
                        "hold_skeleton",
                    )?;
                    meta.remove(index.as_str()).map_err(storage)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

macro_rules! accessors {
    ($($get:ident, $put:ident, $arm:ident, $key:ty => $borrow:ty, $row:ty;)*) => {
        impl ImagePlan<'_> {$ (
            pub fn $get(&self, key: &$borrow) -> Result<Option<$row>> {
                match self.get(&wire::Replacement::$arm { key: key.to_owned(), old: None, new: None })? {
                    Some(wire::Replacement::$arm { new, .. }) => Ok(new),
                    None => Ok(None),
                    _ => Err(CheckpointError::Refused("image_variant")),
                }
            }
            pub fn $put(&mut self, key: &$borrow, new: Option<$row>) -> Result<()> {
                let old = self.$get(key)?;
                self.put(wire::Replacement::$arm { key: key.to_owned(), old, new })
            }
        )*}
    };
}
accessors! {
    root, put_root, Root, String => str, wire::RootRow;
    name, put_name, Name, String => str, wire::NameRow;
    skeleton, put_skeleton, Skeleton, String => str, wire::SkeletonRow;
    hold, put_hold, Hold, wire::HoldKey => wire::HoldKey, wire::HoldRow;
    operation, put_operation, Operation, wire::OperationKey => wire::OperationKey, wire::OperationRow;
    owner, put_owner, OpOwner, String => str, wire::OperationOwnerRow;
    due, put_due, Due, wire::DueKey => wire::DueKey, wire::DueRow;
    counter, put_counter, Counter, wire::CounterKey => wire::CounterKey, wire::CounterRow;
}

pub(super) fn skeleton(name: &str) -> Result<String> {
    ramflux_protocol::username_comparison_key(name).map_err(|_| CheckpointError::Refused("name"))
}
