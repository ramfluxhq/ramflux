// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared writers/readers for prepared copies, history containers, and operation receipts.
use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Actor locator for a prepared recipient envelope or own-copy work item.
#[must_use]
pub fn prepared_copy_locator(copy_id: &str) -> String {
    format!("own-copy/prepared/{copy_id}")
}

/// Actor locator for a serialized own-history page.
#[must_use]
pub fn history_container_locator(transfer_id: &str, page: u32) -> String {
    format!("own-device/history-container/{transfer_id}/{page}")
}

impl AccountDb {
    /// Persists a prepared copy and its erasure locator in the caller's transaction.
    ///
    /// # Errors
    /// Rejects autocommit, empty ids, a deleted owner, or SQLite/serialization failures.
    pub fn put_prepared_message_copy(
        &self,
        message: &str,
        copy_id: &str,
        value: &impl Serialize,
    ) -> Result<(), StorageError> {
        refuse_autocommit(self)?;
        require_id(message)?;
        require_id(copy_id)?;
        if self.message_is_deleted(message)? {
            return Err(StorageError::AuthorizationRejected);
        }
        let locator = prepared_copy_locator(copy_id);
        persist_copy_bytes(self, &locator, value)?;
        if drop_prepared_copy_registration() {
            return Ok(());
        }
        register_kind(self, message, "prepared", &locator)
    }

    /// Persists a history page linked to every included message (any-owner invalidation).
    ///
    /// # Errors
    /// Rejects autocommit, empty ids, a deleted included owner, or SQLite/serialization failures.
    pub fn put_history_container(
        &self,
        transfer_id: &str,
        page: u32,
        included_message_ids: &[&str],
        value: &impl Serialize,
    ) -> Result<(), StorageError> {
        refuse_autocommit(self)?;
        require_id(transfer_id)?;
        if included_message_ids.is_empty() {
            return Err(StorageError::AuthorizationRejected);
        }
        for message in included_message_ids {
            require_id(message)?;
            if self.message_is_deleted(message)? {
                return Err(StorageError::AuthorizationRejected);
            }
        }
        let locator = history_container_locator(transfer_id, page);
        self.connection.execute(
            "DELETE FROM message_footprint WHERE kind IN ('history_container','actor') AND locator=?1",
            params![locator],
        )?;
        self.connection.execute(
            "DELETE FROM message_copy_binding WHERE copy_id IN (?1,?2)",
            params![format!("history_container:{locator}"), format!("actor:{locator}")],
        )?;
        persist_copy_bytes(self, &locator, &history_body(value, included_message_ids)?)?;
        for message in included_message_ids {
            register_kind(self, message, "history_container", &locator)?;
        }
        Ok(())
    }

    /// Registers an operation receipt that holds a message copy, in the caller's transaction.
    /// A response that names an already-deleted message is treated as erased: the receipt
    /// is recorded and the id is skipped, so a keyed delete or a send racing a local delete
    /// can complete and replay.
    ///
    /// # Errors
    /// Rejects autocommit or SQLite failures.
    pub fn register_operation_message_copy(
        &self,
        operation_id: &str,
        response: &Value,
    ) -> Result<(), StorageError> {
        refuse_autocommit(self)?;
        require_id(operation_id)?;
        let mut messages = BTreeSet::new();
        collect_message_ids(response, &mut messages);
        for message in messages {
            if self.message_is_deleted(&message)? {
                continue;
            }
            register_kind(self, &message, "operation", operation_id)?;
        }
        Ok(())
    }

    /// Loads a prepared copy previously written by [`Self::put_prepared_message_copy`].
    ///
    /// # Errors
    /// Returns SQLite or stored-state deserialization errors.
    pub fn load_prepared_message_copy<T: serde::de::DeserializeOwned>(
        &self,
        copy_id: &str,
    ) -> Result<Option<T>, StorageError> {
        self.load_actor_state(&prepared_copy_locator(copy_id))
    }

    /// Loads a history page previously written by [`Self::put_history_container`].
    ///
    /// # Errors
    /// Returns SQLite or stored-state deserialization errors.
    pub fn load_history_container<T: serde::de::DeserializeOwned>(
        &self,
        transfer_id: &str,
        page: u32,
    ) -> Result<Option<T>, StorageError> {
        self.load_actor_state(&history_container_locator(transfer_id, page))
    }
}

fn refuse_autocommit(db: &AccountDb) -> Result<(), StorageError> {
    if db.connection.is_autocommit()? {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(())
}

fn require_id(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(())
}

fn persist_copy_bytes(
    db: &AccountDb,
    locator: &str,
    value: &impl Serialize,
) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec(value)?;
    db.connection.execute(
        "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)
         ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json
         WHERE state_json<>excluded.state_json",
        params![locator, bytes],
    )?;
    Ok(())
}

fn register_kind(
    db: &AccountDb,
    message: &str,
    kind: &str,
    locator: &str,
) -> Result<(), StorageError> {
    db.connection.execute(
        "INSERT OR IGNORE INTO message_copy_binding VALUES(?1,?2)",
        params![format!("{kind}:{locator}"), message],
    )?;
    if matches!(kind, "prepared" | "history_container") {
        db.connection.execute(
            "INSERT OR IGNORE INTO message_copy_binding VALUES(?1,?2)",
            params![format!("actor:{locator}"), message],
        )?;
    }
    db.connection.execute(
        "INSERT OR IGNORE INTO message_footprint VALUES(?1,?2,?3)",
        params![message, kind, locator],
    )?;
    db.connection.execute(
        "UPDATE direct_message_projection SET deleted=1 WHERE deleted=1 AND message_id=?1",
        params![message],
    )?;
    Ok(())
}

fn history_body(value: &impl Serialize, included: &[&str]) -> Result<Value, StorageError> {
    let mut stored = serde_json::to_value(value)?;
    let Value::Object(fields) = &mut stored else {
        return Err(StorageError::AuthorizationRejected);
    };
    fields.insert(
        "included".into(),
        json!(included.iter().map(|id| json!({"message_id": id})).collect::<Vec<_>>()),
    );
    Ok(stored)
}

pub(super) fn collect_message_ids(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for (name, child) in fields {
                if super::schema::is_json_message_id_key(name)
                    && let Some(message) = child.as_str()
                {
                    output.insert(message.to_owned());
                }
                collect_message_ids(child, output);
            }
            if let Some(message) = fields
                .get("message")
                .and_then(Value::as_object)
                .and_then(|message| message.get("id"))
                .and_then(Value::as_str)
            {
                output.insert(message.to_owned());
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_message_ids(child, output);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
fn drop_prepared_copy_registration() -> bool {
    std::env::var_os("RAMFLUX_TEST_DROP_PREPARED_COPY_REGISTRATION").is_some()
}

#[cfg(not(test))]
const fn drop_prepared_copy_registration() -> bool {
    false
}
