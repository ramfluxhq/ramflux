// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Monotonic snapshot guards and bounded restore diagnostics.
use super::*;
use rusqlite::OptionalExtension;
impl AccountDb {
    /// Returns the locally committed group epoch, including groups with inactive members.
    /// # Errors
    /// Returns database errors.
    pub fn group_snapshot_epoch(&self, group: &str) -> Result<Option<u64>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT group_epoch FROM group_projection WHERE group_id=?1",
                params![group],
                |r| r.get(0),
            )
            .optional()?)
    }
    /// Detects a membership tombstone without treating a missing member as removed.
    /// # Errors
    /// Returns database errors.
    pub fn group_snapshot_member_removed(
        &self,
        group: &str,
        member: &str,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_projection WHERE group_id=?1 AND member_id=?2 AND active=0)",params![group,member],|r|r.get(0))?)
    }
    /// Retires an omitted member only at the snapshot epoch currently being applied.
    /// # Errors
    /// Returns database errors.
    pub fn retire_group_snapshot_member(
        &self,
        group: &str,
        member: &str,
        epoch: u64,
    ) -> Result<(), StorageError> {
        self.ensure_legacy_group_writable(group)?;
        self.connection.execute("UPDATE group_member_projection SET active=0,removed_epoch=?3,updated_at=?4 WHERE group_id=?1 AND member_id=?2 AND active=1 AND EXISTS(SELECT 1 FROM group_projection WHERE group_id=?1 AND group_epoch=?3)",params![group,member,epoch,self.now_unix()])?;
        self.archive_removed_group_pin(group, member)?;
        Ok(())
    }
    /// Records a skipped restore item without retaining keys or decrypted message contents.
    /// # Errors
    /// Returns database or serialization errors.
    pub fn record_own_device_restore_skip(
        &self,
        snapshot: &str,
        item: &str,
        reason: &str,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            let key = format!(
                "own-device/restore-skip/{}",
                ramflux_protocol::hash_base64url(
                    "ramflux.own_device.restore_skip.v1",
                    &serde_json::to_vec(&(snapshot, item, reason))?,
                ),
            );
            self.persist_actor_state(
                &key,
                &serde_json::json!({"snapshot_id": snapshot, "item": item, "reason": reason}),
            )?;
            self.connection.execute(
                "DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM runtime_actor_state WHERE state_kind LIKE 'own-device/restore-skip/%' ORDER BY rowid DESC LIMIT -1 OFFSET 256)",
                [],
            )?;
            Ok(())
        })
    }
}
