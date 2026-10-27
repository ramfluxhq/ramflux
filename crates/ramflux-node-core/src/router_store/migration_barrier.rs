// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Mailbox high-water capture inside the home commit's existing redb transaction.
use super::{
    NodeCoreError, ROUTER_INBOX_ENTRY_TABLE, ReadableTable, RouterRedbStore, expiry_index,
    inbox_entry_storage_key,
};
use crate::MigrationBacklogCursor;
use ramflux_protocol::home_migration::{BacklogProgress, DeliveryMapEntry};
impl RouterRedbStore {
    pub(crate) fn migration_backlog_barrier(
        tx: &redb::WriteTransaction,
        anchor: &str,
        id: &str,
        map: &[DeliveryMapEntry],
        now: u64,
    ) -> Result<Vec<MigrationBacklogCursor>, NodeCoreError> {
        let table = tx.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(db_error)?;
        let mut result = Vec::with_capacity(map.len());
        for target in map {
            let start = inbox_entry_storage_key(&target.target_delivery_id, 0);
            let end = inbox_entry_storage_key(&target.target_delivery_id, u64::MAX);
            let mut high_water = 0;
            let mut count = 0_u64;
            for row in table.range(start.as_str()..=end.as_str()).map_err(db_error)? {
                let (_, value) = row.map_err(db_error)?;
                let (entry, until) = expiry_index::decode_entry(value.value())?;
                if until > i64::try_from(now).unwrap_or(i64::MAX) {
                    high_water = high_water.max(entry.inbox_seq);
                    count += 1;
                }
            }
            result.push(MigrationBacklogCursor {
                account_anchor: anchor.into(),
                migration_id: id.into(),
                target_delivery_id: target.target_delivery_id.clone(),
                high_water,
                next_seq: 0,
                progress: BacklogProgress {
                    scheduled: count,
                    remaining: count,
                    ..BacklogProgress::default()
                },
            });
        }
        Ok(result)
    }
}
fn db_error(e: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(e.to_string())
}
