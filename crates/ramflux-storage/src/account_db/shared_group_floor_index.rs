// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed monotonic receiver fences, with lazy migration from the legacy actor-state blob.
use super::shared_group_removals::{DeviceFloor, Floors};
use crate::StorageError;
use ramflux_protocol::{GroupStateLimit, ProtocolError};
use rusqlite::Connection;
use rusqlite::params;
impl Floors {
    pub(super) fn len(&self) -> usize {
        self.roots.len() + self.devices.len()
    }
    pub(super) fn prune(&mut self) {
        self.devices.retain(|d| self.roots.get(&d.root).is_none_or(|e| *e < d.epoch));
    }
    pub(super) fn check_capacity(&self, previous: usize) -> Result<(), StorageError> {
        if self.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_EXCLUSIONS * 2
            && self.len() > previous
        {
            return Err(ProtocolError::GroupStateLimit(GroupStateLimit::RemovalFences).into());
        }
        Ok(())
    }
    pub(super) fn load_index(
        db: &Connection,
        database: &str,
        group: &str,
    ) -> rusqlite::Result<Option<Self>> {
        Self::load_matching_index(db, database, group, None)
    }
    pub(super) fn load_matching_index(
        db: &Connection,
        database: &str,
        group: &str,
        roots: Option<&str>,
    ) -> rusqlite::Result<Option<Self>> {
        // The database selector is internal and only ever main or incoming.
        let table = format!("{database}.shared_group_removal_floor");
        let exists: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {database}.sqlite_master WHERE name='shared_group_removal_floor')"), [], |r|r.get(0))?;
        if !exists {
            return Ok(None);
        }
        let initialized: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {database}.shared_group_floor_generation WHERE group_id=?1)"),params![group],|r|r.get(0))?;
        if !initialized {
            return Ok(None);
        }
        let filter = if roots.is_some() {
            " AND root_commitment IN (SELECT value FROM json_each(?2))"
        } else {
            " AND ?2 IS NULL"
        };
        let mut query = db.prepare(&format!(
            "SELECT root_commitment,device_id,epoch FROM {table} WHERE group_id=?1{filter}"
        ))?;
        let mut floors = Self::default();
        for row in query.query_map(params![group, roots], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, u64>(2)?))
        })? {
            let (root, device, epoch) = row?;
            if device.is_empty() {
                floors.remember_root(root, epoch);
            } else {
                floors.devices.push(DeviceFloor { root, device, epoch });
            }
        }
        floors.prune();
        Ok(Some(floors))
    }
    pub(super) fn store_index_delta(
        &self,
        db: &Connection,
        group: &str,
        old: &Self,
    ) -> rusqlite::Result<()> {
        let initialized: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM shared_group_floor_generation WHERE group_id=?1)",
            params![group],
            |r| r.get(0),
        )?;
        if !initialized {
            return self.store_index(db, group);
        }
        let old_devices: std::collections::BTreeMap<_, _> =
            old.devices.iter().map(|d| ((d.root.as_str(), d.device.as_str()), d.epoch)).collect();
        for (root, epoch) in &self.roots {
            if old.roots.get(root) != Some(epoch) {
                put(db, group, root, "", *epoch)?;
            }
        }
        for floor in &self.devices {
            if old_devices.get(&(floor.root.as_str(), floor.device.as_str())) != Some(&floor.epoch)
            {
                put(db, group, &floor.root, &floor.device, floor.epoch)?;
            }
        }
        prune_index(db, group)
    }
    pub(super) fn store_index(&self, db: &Connection, group: &str) -> rusqlite::Result<()> {
        for (root, epoch) in &self.roots {
            put(db, group, root, "", *epoch)?;
        }
        for floor in &self.devices {
            put(db, group, &floor.root, &floor.device, floor.epoch)?;
        }
        prune_index(db, group)?;
        db.execute(
            "INSERT OR IGNORE INTO shared_group_floor_generation(group_id) VALUES(?1)",
            params![group],
        )?;
        Ok(())
    }
}
fn put(db: &Connection, group: &str, root: &str, device: &str, epoch: u64) -> rusqlite::Result<()> {
    db.execute("INSERT INTO shared_group_removal_floor(group_id,root_commitment,device_id,epoch) VALUES(?1,?2,?3,?4) ON CONFLICT(group_id,root_commitment,device_id) DO UPDATE SET epoch=excluded.epoch WHERE excluded.epoch>shared_group_removal_floor.epoch",params![group,root,device,epoch])?;
    Ok(())
}

fn prune_index(db: &Connection, group: &str) -> rusqlite::Result<()> {
    db.execute("DELETE FROM shared_group_removal_floor AS d WHERE group_id=?1 AND device_id<>'' AND EXISTS(SELECT 1 FROM shared_group_removal_floor r WHERE r.group_id=d.group_id AND r.root_commitment=d.root_commitment AND r.device_id='' AND r.epoch>=d.epoch)",params![group])?;
    Ok(())
}
