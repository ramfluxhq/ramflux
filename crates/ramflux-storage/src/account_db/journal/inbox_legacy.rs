// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy compatibility holds remain unacknowledged when a retry budget expires.
use super::*;
impl AccountDb {
    /// Marks already-held legacy ciphertext so expiry cannot turn it into a terminal rejection.
    /// # Errors
    /// Returns database errors.
    pub fn retain_legacy_inbox(&self, key: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO runtime_actor_state SELECT 'inbox/legacy-held/'||envelope_id,CAST('true' AS BLOB) FROM runtime_unrouted WHERE envelope_id=?1",
            params![key],
        )?;
        self.cleanup_legacy_inbox_holds()
    }
    /// Parks an exhausted legacy retry without acknowledging or dropping its ciphertext.
    /// # Errors
    /// Returns database errors.
    pub fn park_legacy_inbox_retry(&self, key: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE runtime_inbox_retry SET next_at=?2 WHERE envelope_key=?1",
            params![key, i64::MAX],
        )?;
        Ok(())
    }
    pub(super) fn cleanup_legacy_inbox_holds(&self) -> Result<(), StorageError> {
        self.connection.execute("DELETE FROM runtime_actor_state WHERE substr(state_kind,1,18)='inbox/legacy-held/' AND substr(state_kind,19) NOT IN (SELECT envelope_id FROM runtime_unrouted)", [])?;
        Ok(())
    }
}
