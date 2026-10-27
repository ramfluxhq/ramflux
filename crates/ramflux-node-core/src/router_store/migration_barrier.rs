// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Capture the same WAL/redb/ACK/retention view used by delivery recovery before cutover.
use super::{NodeCoreError, RouterRedbStore};
use crate::MigrationBacklogCursor;
use ramflux_protocol::home_migration::{BacklogProgress, DeliveryMapEntry};
impl RouterRedbStore {
    pub(crate) fn migration_backlog_barrier(
        &self,
        anchor: &str,
        id: &str,
        map: &[DeliveryMapEntry],
        now: u64,
    ) -> Result<Vec<MigrationBacklogCursor>, NodeCoreError> {
        // The caller holds mapped submission stripes through the subsequent redb commit.
        // Resolve legacy WAL deadlines before opening that write transaction.
        let (inbox, _) = self.load_delivery_state(
            i64::try_from(now).map_err(|e| NodeCoreError::Redb(e.to_string()))?,
        )?;
        let mut result = Vec::with_capacity(map.len());
        for target in map {
            let mut high_water = inbox.issued_sequence(&target.target_delivery_id);
            let mut count = 0_u64;
            for (entry, until) in inbox.pending_entries_with_deadline() {
                if entry.target_delivery_id == target.target_delivery_id
                    && until > i64::try_from(now).unwrap_or(i64::MAX)
                {
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
