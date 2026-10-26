// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receipt bookkeeping expires independently of stored messages and their wire shape.
use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;
const AGE: i64 = 30 * 24 * 60 * 60;
const PREFIXES: [&str; 3] =
    ["delivery-receipt/status/", "message/origin/", "delivery-receipt/outbound/"];
const CURSOR: &str = "delivery-receipt/retention-cursor";
impl AccountDb {
    pub(super) fn install_receipt_retention_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS runtime_receipt_retention (state_kind TEXT PRIMARY KEY, at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS runtime_receipt_retention_age ON runtime_receipt_retention(at,state_kind);")?;
        Ok(())
    }

    /// Stores receipt metadata with a separate retention timestamp, preserving its JSON shape.
    /// # Errors
    /// Rejects unrelated namespaces and reports serialization or transaction errors.
    pub fn persist_receipt_state<T: serde::Serialize>(
        &self,
        kind: &str,
        state: &T,
        at: i64,
    ) -> Result<(), StorageError> {
        if !PREFIXES.iter().any(|prefix| kind.starts_with(prefix)) {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            self.persist_actor_state(kind, state)?;
            self.connection.execute("INSERT INTO runtime_receipt_retention(state_kind,at) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET at=max(at,excluded.at)",params![kind,at])?;
            Ok(())
        })
    }
    // Each namespace walks a durable keyset cursor: no repeated anti-join over all history.
    // At most `batch` keys per namespace are enrolled, and wrapping also uses indexed ranges.
    fn enroll_legacy_receipts(&self, now: i64, batch: u32) -> Result<(), StorageError> {
        let old = self
            .load_actor_state::<std::collections::BTreeMap<String, String>>(CURSOR)?
            .unwrap_or_default();
        let mut cursors = old.clone();
        for prefix in PREFIXES {
            let after = cursors.get(prefix).cloned().unwrap_or_default();
            let mut keys = self.actor_state_key_page_after(prefix, &after, batch)?;
            if keys.is_empty() && !after.is_empty() {
                keys = self.actor_state_key_page_after(prefix, "", batch)?;
            }
            if let Some(last) = keys.last() {
                cursors.insert(prefix.into(), last.clone());
            } else {
                cursors.remove(prefix);
            }
            for key in keys {
                self.connection.execute(
                    "INSERT OR IGNORE INTO runtime_receipt_retention(state_kind,at) VALUES(?1,?2)",
                    params![key, now],
                )?;
            }
        }
        if cursors != old {
            self.persist_actor_state(CURSOR, &cursors)?;
        }
        Ok(())
    }
    /// Expires at most `batch` metadata rows and `batch` failed-receipt events after thirty days.
    /// Untimestamped legacy rows get thirty days from first observation, without changing payloads.
    /// # Errors
    /// Reports SQL/transaction errors and preserves journal gap detection on deletion.
    pub fn retain_delivery_receipts(&self, now: i64, batch: u32) -> Result<(), StorageError> {
        let batch = batch.clamp(1, 256);
        self.write_transaction(|| {
            self.enroll_legacy_receipts(now, batch)?;
            let cutoff=now.saturating_sub(AGE);
            self.connection.execute("DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM runtime_receipt_retention WHERE at<=?1 ORDER BY at,state_kind LIMIT ?2)", params![cutoff,batch])?;
            self.connection.execute("DELETE FROM runtime_receipt_retention WHERE state_kind IN (SELECT state_kind FROM runtime_receipt_retention WHERE at<=?1 ORDER BY at,state_kind LIMIT ?2)", params![cutoff,batch])?;
            let max_seq: Option<u64> = self.connection.query_row("SELECT max(seq) FROM (SELECT seq FROM runtime_journal WHERE topic='message.delivery_receipt.failed' AND at<=?1 ORDER BY seq LIMIT ?2)",params![cutoff,batch], |row|row.get(0))?;
            if let Some(seq)=max_seq {
                self.connection.execute("DELETE FROM runtime_journal WHERE topic='message.delivery_receipt.failed' AND at<=?1 AND seq<=?2",params![cutoff,seq])?;
                self.connection.execute("UPDATE runtime_journal_bounds SET pruned_through=max(pruned_through,?1) WHERE singleton=1",params![seq])?;
            }
            Ok(())
        })
    }
}
