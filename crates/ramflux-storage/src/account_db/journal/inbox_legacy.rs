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
        let mut marker = self
            .load_actor_state::<serde_json::Value>(&format!("inbox/legacy-held/{key}"))?
            .filter(serde_json::Value::is_object)
            .unwrap_or_else(|| serde_json::json!({}));
        marker["lookup_recoverable"] = serde_json::json!(lookup_recoverable);
        marker["quota_blocked"] = serde_json::json!(quota_blocked);
        self.persist_actor_state(&format!("inbox/legacy-held/{key}"), &marker)
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
        self.write_transaction(|| {
            let name = format!("inbox/legacy-held/{key}");
            let Some(value) = self.load_actor_state::<serde_json::Value>(&name)? else {
                return Err(StorageError::AuthorizationRejected);
            };
            let mut marker = if value.is_object() { value } else { serde_json::json!({}) };
            marker["parked"] = serde_json::json!(true);
            self.persist_actor_state(&name, &marker)?;
            self.connection
                .execute("DELETE FROM runtime_inbox_retry WHERE envelope_key=?1", params![key])?;
            self.connection.execute(
                "DELETE FROM runtime_inbox_dead_letter WHERE envelope_key=?1",
                params![key],
            )?;
            self.connection
                .execute("DELETE FROM runtime_inbox_policy WHERE envelope_key=?1", params![key])?;
            Ok(())
        })
    }
    /// Reports a retained hold that has permanently released its network retry admission.
    /// # Errors
    /// Returns database or decoding errors.
    pub fn legacy_inbox_parked(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self
            .load_actor_state::<serde_json::Value>(&format!("inbox/legacy-held/{key}"))?
            .is_some_and(|value| value["parked"] == true))
    }
    pub(super) fn release_expired_legacy_inbox(&self, at: i64) -> Result<(), StorageError> {
        let mut query = self.connection.prepare("SELECT p.envelope_key FROM runtime_inbox_policy p LEFT JOIN runtime_inbox_retry r USING(envelope_key) WHERE EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind='inbox/legacy-held/'||p.envelope_key) AND (p.expires_at<=?1 OR p.attempts>=CASE WHEN p.trusted=1 THEN 8 ELSE 3 END OR r.next_at=9223372036854775807)")?;
        let keys = query
            .query_map(params![at], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(query);
        for key in keys {
            self.park_legacy_inbox_retry(&key)?;
        }
        Ok(())
    }
    pub(super) fn cleanup_legacy_inbox_holds(&self) -> Result<(), StorageError> {
        self.connection.execute("DELETE FROM runtime_inbox_retry WHERE envelope_key IN (SELECT substr(state_kind,19) FROM runtime_actor_state WHERE substr(state_kind,1,18)='inbox/legacy-held/' AND substr(state_kind,19) NOT IN (SELECT envelope_id FROM runtime_unrouted))", [])?;
        self.connection.execute("DELETE FROM runtime_inbox_policy WHERE envelope_key IN (SELECT substr(state_kind,19) FROM runtime_actor_state WHERE substr(state_kind,1,18)='inbox/legacy-held/' AND substr(state_kind,19) NOT IN (SELECT envelope_id FROM runtime_unrouted)) AND envelope_key NOT IN (SELECT envelope_key FROM runtime_inbox_dead_letter)", [])?;
        self.connection.execute("DELETE FROM runtime_actor_state WHERE substr(state_kind,1,18)='inbox/legacy-held/' AND substr(state_kind,19) NOT IN (SELECT envelope_id FROM runtime_unrouted)", [])?;
        Ok(())
    }
}
