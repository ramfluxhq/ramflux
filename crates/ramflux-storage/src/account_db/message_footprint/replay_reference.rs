// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed replay aliases become honest deleted references at the projection erasure boundary.
use super::AccountDb;
use crate::{MessageReplayReference, StorageError};
use rusqlite::params;

fn replay_key(key: &str) -> Option<&str> {
    ["own-device/sent-alias/", "own-device/sent-ciphertext/", "own-device/imported-ciphertext/"]
        .into_iter()
        .find_map(|prefix| key.strip_prefix(prefix))
}
fn require_digest(value: &str) -> Result<(), StorageError> {
    let decoded = ramflux_protocol::decode_base64url(value)
        .map_err(|_| StorageError::AuthorizationRejected)?;
    if decoded.len() != 32 || ramflux_protocol::encode_base64url(decoded) != value {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(())
}
pub(super) fn register(
    db: &AccountDb,
    key: &str,
    value: &serde_json::Value,
) -> Result<(), StorageError> {
    let Some(digest) = replay_key(key) else { return Ok(()) };
    require_digest(digest)?;
    let reference: MessageReplayReference = serde_json::from_value(value.clone())?;
    // Replacing a target with an ambiguity fence must detach its old owner as well.
    db.connection.execute(
        "DELETE FROM message_footprint WHERE locator=?1 AND kind IN ('actor','replay_actor')",
        params![key],
    )?;
    db.connection.execute(
        "DELETE FROM message_copy_binding WHERE copy_id=?1",
        params![format!("actor:{key}")],
    )?;
    if let MessageReplayReference::Target { message_id, binding, scope, .. } = reference {
        for digest in binding.iter().chain(scope.iter()) {
            require_digest(digest)?;
        }
        db.connection.execute(
            "INSERT OR IGNORE INTO message_footprint VALUES(?1,'replay_actor',?2)",
            params![message_id, key],
        )?;
    }
    Ok(())
}
impl AccountDb {
    /// Stores a replay target using its real projection deletion state, or an ambiguity fence.
    /// Only private index names and opaque binding/scope digests are retained with the target.
    ///
    /// # Errors
    /// Rejects unknown keys, missing targets, malformed digests and storage failures.
    pub fn persist_message_replay_reference(
        &self,
        key: &str,
        message: Option<&str>,
        binding: Option<&str>,
        scope: Option<&str>,
    ) -> Result<(), StorageError> {
        require_digest(replay_key(key).ok_or(StorageError::AuthorizationRejected)?)?;
        self.write_transaction(|| {
            let reference = if let Some(id) = message {
                let target =
                    self.direct_message_by_id(id)?.ok_or(StorageError::AuthorizationRejected)?;
                MessageReplayReference::Target {
                    message_id: id.into(),
                    deleted: target.deleted,
                    binding: binding.map(str::to_owned),
                    scope: scope.map(str::to_owned),
                }
            } else {
                if binding.is_some() || scope.is_some() {
                    return Err(StorageError::AuthorizationRejected);
                }
                MessageReplayReference::Ambiguous
            };
            self.persist_actor_state(key, &reference)
        })
    }
}

#[cfg(test)]
mod tests;
