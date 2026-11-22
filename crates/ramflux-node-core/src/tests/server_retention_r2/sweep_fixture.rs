// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persist the sweep's scale fixture in one transaction, without 1,100 registration journals.
use super::*;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

const OWNERS: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_route_authority_v1");
const MARKS: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_route_high_water_v1");

pub(super) fn store(path: &Path, now: u64) -> Result<NotifyRedbStore, Box<dyn std::error::Error>> {
    let key = NodeSecret::ephemeral()?;
    let mut store = NotifyRedbStore::open_with_route_key(path, key.clone())?;
    store.set_push_route_authorizer(|_| Ok(true));
    let mut authority = owner("delivery-0000")?;
    store.register_authenticated_push_route(&authority, &route_for("delivery-0000", now))?;
    drop(store);
    {
        let db = redb::Database::open(path)?;
        let read = db.begin_read()?;
        let routes = read.open_table(NOTIFY_ROUTE_TABLE)?;
        let seed = routes.get("delivery-0000")?.ok_or("registered seed route")?;
        let route_bytes = key.open(b"ramflux.notify.routes.v1\0delivery-0000", seed.value())?;
        let seed_routes: Vec<DevicePushRoute> = serde_json::from_slice(&route_bytes)?;
        let mut route = seed_routes.first().ok_or("registered seed route body")?.clone();
        let marks = read.open_table(MARKS)?;
        let marks = marks.get("delivery-0000")?.ok_or("registered seed marks")?.value().to_vec();
        let write = db.begin_write()?;
        {
            let mut routes = write.open_table(NOTIFY_ROUTE_TABLE)?;
            let mut owners = write.open_table(OWNERS)?;
            let mut high_water = write.open_table(MARKS)?;
            for index in 1..1_100 {
                let target = format!("delivery-{index:04}");
                authority.target_delivery_id.clone_from(&target);
                route.device_delivery_id.clone_from(&target);
                let owner = key.seal(
                    format!("ramflux.notify.route_owner.v1\0{target}").as_bytes(),
                    &serde_json::to_vec(&authority)?,
                )?;
                let body = key.seal(
                    format!("ramflux.notify.routes.v1\0{target}").as_bytes(),
                    &serde_json::to_vec(std::slice::from_ref(&route))?,
                )?;
                owners.insert(target.as_str(), owner.as_slice())?;
                routes.insert(target.as_str(), body.as_slice())?;
                high_water.insert(target.as_str(), marks.as_slice())?;
            }
        }
        write.commit()?;
    }
    // Real open validates every encrypted route/owner binding before the production sweep.
    Ok(NotifyRedbStore::open_with_route_key(path, key)?)
}
