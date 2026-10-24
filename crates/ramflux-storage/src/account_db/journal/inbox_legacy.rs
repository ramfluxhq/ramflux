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
    /// Remembers why a bounded legacy hold is parked, without retaining any plaintext.
    /// # Errors
    /// Returns database or serialization errors.
    pub fn record_legacy_inbox_failure(
        &self,
        key: &str,
        lookup_recoverable: bool,
        quota_blocked: bool,
    ) -> Result<(), StorageError> {
        self.persist_actor_state(&format!("inbox/legacy-held/{key}"), &serde_json::json!({"lookup_recoverable":lookup_recoverable,"quota_blocked":quota_blocked}))
    }
    /// Reports whether a hold awaits retry capacity rather than a fresh delivery attempt.
    /// # Errors
    /// Returns database or decoding errors.
    pub fn legacy_inbox_quota_blocked(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self
            .load_actor_state::<serde_json::Value>(&format!("inbox/legacy-held/{key}"))?
            .is_some_and(|value| value["quota_blocked"] == true))
    }
    /// Reports whether verified local cache repair can finish a held lookup without network work.
    /// # Errors
    /// Returns database or decoding errors.
    pub fn legacy_inbox_lookup_recoverable(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self
            .load_actor_state::<serde_json::Value>(&format!("inbox/legacy-held/{key}"))?
            .is_some_and(|value| value["lookup_recoverable"] == true))
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
        self.connection.execute("DELETE FROM runtime_inbox_retry WHERE envelope_key IN (SELECT substr(state_kind,19) FROM runtime_actor_state WHERE substr(state_kind,1,18)='inbox/legacy-held/' AND substr(state_kind,19) NOT IN (SELECT envelope_id FROM runtime_unrouted))", [])?;
        self.connection.execute("DELETE FROM runtime_inbox_policy WHERE envelope_key IN (SELECT substr(state_kind,19) FROM runtime_actor_state WHERE substr(state_kind,1,18)='inbox/legacy-held/' AND substr(state_kind,19) NOT IN (SELECT envelope_id FROM runtime_unrouted)) AND envelope_key NOT IN (SELECT envelope_key FROM runtime_inbox_dead_letter)", [])?;
        self.connection.execute("DELETE FROM runtime_actor_state WHERE substr(state_kind,1,18)='inbox/legacy-held/' AND substr(state_kind,19) NOT IN (SELECT envelope_id FROM runtime_unrouted)", [])?;
        Ok(())
    }
}
