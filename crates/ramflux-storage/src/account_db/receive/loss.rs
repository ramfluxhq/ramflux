// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WJ projects unpublished loss outbox into the unique-source-key journal. WP prunes
//! projected ranges only. W2 consults the 2,048-range and 1 MiB unpublished-loss caps.
use super::ReceiveTransaction;
use super::cover::ReceiveGap;
use crate::{AccountDb, JournalEvent, ProjectionStore, StorageError};
use rusqlite::params;

pub(super) const PROJECTED_RANGE_CAP: i64 = 1_024;
pub(super) const TOTAL_RANGE_CAP: i64 = 2_048;
pub(super) const PENDING_LOSS_BYTES: i64 = 1_024 * 1_024;

pub(super) fn gap_source(target: &str, incarnation: &str, from: u64, to: u64) -> String {
    format!("receive-gap:{target}:{incarnation}:{from}:{to}")
}

pub(super) fn gap_keys_json(
    target: &str,
    incarnation: &str,
    gap: &ReceiveGap<'_>,
    count: u64,
) -> Result<String, StorageError> {
    Ok(serde_json::to_string(&serde_json::json!({
        "source_key": gap_source(target, incarnation, gap.from_seq, gap.to_seq),
        "target": target,
        "incarnation": incarnation,
        "from_seq": gap.from_seq,
        "to_seq": gap.to_seq,
        "count": count,
        "reason": gap.reason,
        "classification": gap.classification,
    }))?)
}

pub(super) fn loss_journal_event(
    keys: &serde_json::Value,
) -> (String, serde_json::Value, Option<String>) {
    let mut body = serde_json::Map::new();
    for name in [
        "source_key",
        "target",
        "incarnation",
        "from_seq",
        "to_seq",
        "count",
        "reason",
        "classification",
    ] {
        if let Some(value) = keys.get(name) {
            body.insert(name.to_owned(), value.clone());
        }
    }
    ("receive.gap".to_owned(), serde_json::Value::Object(body), None)
}

impl ReceiveTransaction<'_> {
    /// True when adding `gaps` would exceed the total-range or unpublished-byte cap.
    pub(super) fn loss_backpressure(&self, gaps: &[ReceiveGap<'_>]) -> Result<bool, StorageError> {
        if gaps.is_empty() {
            return Ok(false);
        }
        let existing: i64 = self.db.connection.query_row(
            "SELECT count(*) FROM gateway_inbox_loss WHERE target_delivery_id=?1",
            params![self.target],
            |row| row.get(0),
        )?;
        let pending: i64 = self.db.connection.query_row(
            "SELECT coalesce(sum(length(CAST(keys_json AS BLOB))),0) FROM runtime_outbox
             WHERE published=0 AND table_name='gateway_inbox_loss'
               AND json_extract(keys_json,'$.target')=?1",
            params![self.target],
            |row| row.get(0),
        )?;
        let mut new_ranges = 0i64;
        let mut new_bytes = 0i64;
        for gap in gaps {
            let from = gap.from_seq.to_be_bytes();
            let to = gap.to_seq.to_be_bytes();
            let present: i64 = self.db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM gateway_inbox_loss WHERE target_delivery_id=?1 AND incarnation_id=?2 AND from_seq=?3 AND to_seq=?4)",
                params![self.target, self.incarnation, from.as_slice(), to.as_slice()],
                |row| row.get(0),
            )?;
            if present == 0 {
                new_ranges += 1;
            }
            let source = gap_source(self.target, self.incarnation, gap.from_seq, gap.to_seq);
            let unpublished: i64 = self.db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM runtime_outbox WHERE published=0 AND json_extract(keys_json,'$.source_key')=?1)",
                params![source],
                |row| row.get(0),
            )?;
            if unpublished == 0 {
                let count = gap.to_seq.saturating_sub(gap.from_seq).saturating_add(1);
                let keys = gap_keys_json(self.target, self.incarnation, gap, count)?;
                new_bytes = new_bytes.saturating_add(i64::try_from(keys.len()).unwrap_or(i64::MAX));
            }
        }
        Ok(existing.saturating_add(new_ranges) > TOTAL_RANGE_CAP
            || pending.saturating_add(new_bytes) > PENDING_LOSS_BYTES)
    }
}

impl AccountDb {
    /// WJ: project unpublished `gateway_inbox_loss` outbox rows through `journal_outbox`.
    ///
    /// # Errors
    /// Returns SQL or journal-body errors. Each outbox row is one unique source-key event.
    pub fn project_loss_outbox(&self, at: i64) -> Result<Vec<JournalEvent>, StorageError> {
        let mut projected = Vec::new();
        loop {
            let entries = self.pending_loss_outbox(256)?;
            if entries.is_empty() {
                return Ok(projected);
            }
            for (sequence, keys) in entries {
                projected.extend(self.journal_outbox(
                    sequence,
                    &[loss_journal_event(&keys)],
                    at,
                )?);
            }
        }
    }

    /// WP: delete oldest projected loss ranges above 1,024 per target. Counters survive.
    ///
    /// # Errors
    /// Returns SQL errors. Unpublished ranges are never deleted.
    pub fn prune_projected_loss(&self, target: &str) -> Result<(), StorageError> {
        self.write_transaction(|| {
            let mut projected = Vec::new();
            {
                let mut query = self.connection.prepare(
                    "SELECT incarnation_id,from_seq,to_seq,count FROM gateway_inbox_loss
                     WHERE target_delivery_id=?1 ORDER BY recorded_at,from_seq",
                )?;
                let rows = query.query_map(params![target], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                })?;
                for row in rows {
                    let (incarnation, from, to, count) = row?;
                    let from_seq = be_u64(&from)?;
                    let to_seq = be_u64(&to)?;
                    let source = gap_source(target, &incarnation, from_seq, to_seq);
                    let unpublished: i64 = self.connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM runtime_outbox WHERE published=0 AND json_extract(keys_json,'$.source_key')=?1)",
                        params![source],
                        |r| r.get(0),
                    )?;
                    if unpublished == 0 {
                        projected.push((incarnation, from, to, be_u64(&count)?));
                    }
                }
            }
            let keep = usize::try_from(PROJECTED_RANGE_CAP).unwrap_or(usize::MAX);
            let overflow = projected.len().saturating_sub(keep);
            let mut survived = 0u64;
            for (incarnation, from, to, count) in projected.into_iter().take(overflow) {
                survived = survived.saturating_add(count);
                self.connection.execute(
                    "DELETE FROM gateway_inbox_loss WHERE target_delivery_id=?1 AND incarnation_id=?2 AND from_seq=?3 AND to_seq=?4",
                    params![target, incarnation, from, to],
                )?;
            }
            if survived > 0 {
                let key = format!("gateway_receive_loss_count:{target}");
                let prior = match self.projection_checkpoint(&key)? {
                    Some(value) => {
                        value.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected)?
                    }
                    None => 0,
                };
                self.set_projection_checkpoint(&key, &prior.saturating_add(survived).to_string())?;
            }
            Ok(())
        })
    }

    fn pending_loss_outbox(
        &self,
        limit: u32,
    ) -> Result<Vec<(i64, serde_json::Value)>, StorageError> {
        self.pending_loss_outbox_for(None, None, limit)
    }

    /// Unpublished loss outbox rows, optionally filtered to one target and incarnation.
    pub(super) fn pending_loss_outbox_for(
        &self,
        target: Option<&str>,
        incarnation: Option<&str>,
        limit: u32,
    ) -> Result<Vec<(i64, serde_json::Value)>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence,keys_json FROM runtime_outbox
             WHERE published=0 AND table_name='gateway_inbox_loss'
               AND (?1 IS NULL OR json_extract(keys_json,'$.target')=?1)
               AND (?2 IS NULL OR json_extract(keys_json,'$.incarnation')=?2)
             ORDER BY sequence LIMIT ?3",
        )?;
        let rows = statement.query_map(params![target, incarnation, limit.min(256)], |row| {
            let sequence: i64 = row.get(0)?;
            let keys: String = row.get(1)?;
            Ok((sequence, keys))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (sequence, keys) = row?;
            let value: serde_json::Value = serde_json::from_str(&keys)?;
            entries.push((sequence, value));
        }
        Ok(entries)
    }
}

fn be_u64(bytes: &[u8]) -> Result<u64, StorageError> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| StorageError::AuthorizationRejected)?;
    Ok(u64::from_be_bytes(arr))
}
