// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact transport verification retains its UTC floor independently of provisional peer caches.
use super::{FederationRedbStore, NodeCoreError};
use redb::{ReadableTable, TableDefinition};
const CLOCK: TableDefinition<&str, u64> = TableDefinition::new("contact_foreign_clock_v1");
impl FederationRedbStore {
    /// Persist a nondecreasing safe-integer verification clock before using peer expiry windows.
    /// This single metadata row is not a peer/home pin or an account authority record.
    /// # Errors
    /// Refuses unsafe times and failed durable storage operations.
    pub fn contact_clock_floor(&self, now: u64) -> Result<u64, NodeCoreError> {
        let error = |e: &dyn std::fmt::Display| NodeCoreError::Redb(e.to_string());
        if now > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
            return Err(NodeCoreError::Unauthorized("unsafe contact clock".into()));
        }
        let mut tx = self.db.begin_write().map_err(|e| error(&e))?;
        tx.set_durability(redb::Durability::Immediate).map_err(|e| error(&e))?;
        let mut table = tx.open_table(CLOCK).map_err(|e| error(&e))?;
        let old = table.get("floor").map_err(|e| error(&e))?.map_or(0, |v| v.value());
        if old > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
            return Err(NodeCoreError::Unauthorized("unsafe retained contact clock".into()));
        }
        let now = old.max(now);
        table.insert("floor", now).map_err(|e| error(&e))?;
        drop(table);
        tx.commit().map_err(|e| error(&e))?;
        Ok(now)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_contact_clock_floor_survives_reopen_and_rejects_unsafe_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("federation.redb");
        {
            let store = FederationRedbStore::open(&path)?;
            assert_eq!(
                store.contact_clock_floor(1000)?,
                1000,
                "first verification fixes its durable minimum"
            );
            assert_eq!(
                store.contact_clock_floor(900)?,
                1000,
                "wall-clock rollback cannot extend an expired peer lease"
            );
        }
        let store = FederationRedbStore::open(&path)?;
        assert_eq!(
            store.contact_clock_floor(950)?,
            1000,
            "restart must retain the independent verification floor"
        );
        assert!(
            store.contact_clock_floor(u64::MAX).is_err(),
            "unsafe JSON times cannot poison the floor"
        );
        Ok(())
    }
}
