// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Write-time ownership of per-message copies; deletion visits indexed locators only.
#[cfg(test)]
mod audit;
mod erasure;
mod generic_copy;
#[cfg(test)]
mod generic_copy_tests;
pub(super) mod migration;
#[cfg(test)]
mod migration_tests;
mod replay_reference;
mod schema;

use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
use serde_json::Value;
use std::collections::BTreeSet;

/// Stages one actor registration; the consume trigger writes the footprint rows.
pub(super) const STAGE_ACTOR: &str =
    "INSERT INTO message_footprint_actor_stage VALUES(?1,?2,?3,?4)";
/// Re-fires erasure for a deleted owner reached through a freshly registered actor locator.
pub(super) const FENCE_OUTBOX: &str = "INSERT INTO message_footprint
             SELECT f.message_id,'outbox',CAST(o.sequence AS TEXT)
             FROM runtime_outbox o
             JOIN runtime_actor_state a ON a.rowid=o.row_id
             JOIN message_footprint f ON f.kind='actor' AND f.locator=a.state_kind
             WHERE o.table_name='runtime_actor_state' AND o.change_kind<>'delete'
              AND a.state_kind=?1 ON CONFLICT DO NOTHING";
pub(super) const FENCE_PROJECTION: &str =
    "UPDATE direct_message_projection SET deleted=1 WHERE deleted=1 AND message_id IN
             (SELECT message_id FROM message_footprint WHERE kind='actor' AND locator=?1)";

pub(crate) fn install(db: &rusqlite::Connection) -> rusqlite::Result<()> {
    // Migration bookkeeping lives outside `projection_checkpoint`, so it never reaches the
    // domain outbox.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_footprint_migration(name TEXT PRIMARY KEY NOT NULL,value TEXT NOT NULL);",
    )?;
    super::object_retention::install(db)?;
    schema::install(db)?;
    erased_input_store(db)?;
    super::receive::erased_capture::sweep_open(db, crate::unix_now())?;
    Ok(())
}

/// Tombstones of deleted authenticated inputs (selector MACs only) and the bundle-retirement
/// guard. An ordinary rowid table: whole-database digests and audits enumerate by rowid. The guard needs the MAC bundle table, which a fresh account creates after the first
/// install, so open installs it again once that table exists.
pub(super) fn erased_input_store(db: &rusqlite::Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS receive_erased_input(
            selector TEXT PRIMARY KEY NOT NULL,bundle_id TEXT NOT NULL,expires_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS receive_erased_input_expiry ON receive_erased_input(expires_at);",
    )?;
    if !schema::exists(db, "account_mac_bundle")? {
        return Ok(());
    }
    db.execute_batch(
        "DROP TRIGGER IF EXISTS main.receive_erased_input_bundle_guard;
         CREATE TRIGGER receive_erased_input_bundle_guard BEFORE DELETE ON account_mac_bundle
         WHEN EXISTS(SELECT 1 FROM receive_erased_input
                     WHERE bundle_id=OLD.bundle_id AND expires_at>unixepoch())
          OR EXISTS(SELECT 1 FROM message_copy_binding
                    WHERE copy_id GLOB 'erased-input:'||OLD.bundle_id||':*'
                    AND CAST(substr(copy_id,length(rtrim(copy_id,'0123456789'))+1) AS INTEGER)>unixepoch())
         BEGIN SELECT RAISE(ABORT,'mac bundle retains erased-input authority'); END;",
    )
}

impl AccountDb {
    pub(super) fn register_actor_message_footprint(
        &self,
        key: &str,
        value: &Value,
    ) -> Result<(), StorageError> {
        self.guard_object_actor(key, value)?;
        if !admits(key, value) {
            return Ok(());
        }
        if drop_actor_registration_for_mutation_test() {
            return Ok(());
        }
        replay_reference::register(self, key, value)?;
        let registration = actor_registration(key, value);
        self.connection.execute(
            STAGE_ACTOR,
            params![
                key,
                serde_json::to_string(&registration.message_ids)?,
                serde_json::to_string(&registration.copy_ids)?,
                serde_json::to_string(&registration.bindings)?,
            ],
        )?;
        Ok(())
    }

    pub(super) fn fence_actor_message_footprint(&self, key: &str) -> Result<(), StorageError> {
        self.connection.execute(FENCE_OUTBOX, params![key])?;
        self.connection.execute(FENCE_PROJECTION, params![key])?;
        Ok(())
    }

    pub(super) fn register_journal_message_footprint(
        &self,
        sequence: u64,
        topic: &str,
        body: &[u8],
    ) -> Result<(), StorageError> {
        if !topic.contains("message") {
            return Ok(());
        }
        self.connection.execute(
            "INSERT INTO message_footprint_journal_stage VALUES(?1,?2)",
            params![sequence, body],
        )?;
        Ok(())
    }

    /// Reads live actor copies reached by an erasure alias; this grants no admission authority.
    ///
    /// # Errors
    /// Returns SQLite or stored-state deserialization errors.
    pub fn message_copy_actor_states<T: serde::de::DeserializeOwned>(
        &self,
        copy: &str,
        prefix: &str,
    ) -> Result<Vec<T>, StorageError> {
        let mut query = self.connection.prepare(
            "SELECT a.state_json FROM message_copy_binding b \
             JOIN message_footprint f ON f.message_id=b.message_id AND f.kind='actor' \
             JOIN runtime_actor_state a ON a.state_kind=f.locator \
             WHERE b.copy_id=?1 AND substr(a.state_kind,1,length(?2))=?2",
        )?;
        query
            .query_map(params![copy, prefix], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| Ok(serde_json::from_slice(&row?)?))
            .collect()
    }

    /// Rewrites an existing receipt with its original erasure owner, including private scopes.
    /// Unbound legacy receipts retain their existing registration behavior.
    /// # Errors
    /// Returns SQLite, serialization or transaction errors.
    pub fn persist_bound_message_actor_state(
        &self,
        key: &str,
        value: &impl serde::Serialize,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            use rusqlite::OptionalExtension;
            let message: Option<String> = self
                .connection
                .query_row(
                    "SELECT message_id FROM message_copy_binding WHERE copy_id=?1 LIMIT 1",
                    params![format!("actor:{key}")],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(message) = message {
                self.persist_message_actor_state(&message, key, value)
            } else {
                self.persist_actor_state(key, value)
            }
        })
    }

    /// Persists an opaque message copy and its erasure locator atomically.
    ///
    /// # Errors
    /// Returns serialization or transaction errors.
    pub fn persist_message_actor_state(
        &self,
        message: &str,
        key: &str,
        value: &impl serde::Serialize,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.connection.execute(
                "DELETE FROM message_copy_binding WHERE copy_id=?1",
                params![format!("actor:{key}")],
            )?;
            self.connection.execute(
                "DELETE FROM message_footprint WHERE kind='actor' AND locator=?1",
                params![key],
            )?;
            self.connection.execute(
                "INSERT OR IGNORE INTO message_copy_binding VALUES(?1,?2)",
                params![format!("actor:{key}"), message],
            )?;
            self.connection.execute(
                "INSERT OR IGNORE INTO message_footprint VALUES(?1,'actor',?2)",
                params![message, key],
            )?;
            self.persist_actor_state(key, value)?;
            self.connection.execute(
                "UPDATE direct_message_projection SET deleted=1 WHERE deleted=1 AND message_id=?1",
                params![message],
            )?;
            Ok(())
        })
    }
}

#[derive(Default)]
struct ActorRegistration {
    message_ids: BTreeSet<String>,
    copy_ids: BTreeSet<String>,
    bindings: BTreeSet<(String, String)>,
}

fn actor_registration(key: &str, value: &Value) -> ActorRegistration {
    let mut registration = ActorRegistration::default();
    collect_generic_references(value, &mut registration);

    if let Some(message) = key.strip_prefix("group-message/alias/") {
        registration.message_ids.insert(message.to_owned());
    }
    if let Some(message) = key.strip_prefix("routed/message-owner/") {
        registration.message_ids.insert(message.to_owned());
    }
    if let Some(message) = key.strip_prefix("routed/message-metadata/") {
        registration.message_ids.insert(message.to_owned());
    }
    if let Some(object) =
        key.strip_prefix("attachment/chunk/").and_then(|suffix| suffix.split('/').next())
    {
        registration.copy_ids.insert(format!("object:{object}"));
    }
    if (key.starts_with("attachment/reference-by-sender/")
        || key.starts_with("attachment/reference-by-slot/"))
        && let Some(object) = value.as_str()
    {
        registration.copy_ids.insert(format!("object:{object}"));
    }
    if let Some(object) = key.strip_prefix("attachment/reference/") {
        registration.copy_ids.insert(format!("object:{object}"));
    }
    if (key.starts_with("routed/projection/") || key.starts_with("directory/message/"))
        && let Some(message) = value.as_str()
    {
        registration.message_ids.insert(message.to_owned());
    }
    if key.starts_with("delivery-receipt/") {
        collect_named_text(value, "message", &mut registration.message_ids);
    }
    if key.starts_with("own-device/send/")
        && let Some(message) = value.pointer("/intent/id").and_then(Value::as_str)
    {
        // Plain sent copies use the transport envelope as intent.id, not as another owner.
        let owner =
            if value.pointer("/intent/owner_record/0").and_then(Value::as_str) == Some("message") {
                value.pointer("/intent/owner_record/1").and_then(Value::as_str).unwrap_or(message)
            } else {
                message
            };
        registration.message_ids.insert(owner.to_owned());
    }

    if key.starts_with("delivery-receipt/pending/")
        && let (Some(status), Some(message)) = (
            value.get("status_id").and_then(Value::as_str),
            value.get("message").and_then(Value::as_str),
        )
    {
        registration
            .bindings
            .insert((format!("actor:delivery-receipt/status/{status}"), message.to_owned()));
    }
    if let Some(object) = key.strip_prefix("directory/object/")
        && let Some(message) = value.get("message_id").and_then(Value::as_str)
    {
        registration.bindings.insert((format!("object:{object}"), message.to_owned()));
    }
    if (key.starts_with("routed/committed/") || key.starts_with("legacy/replay/committed/"))
        && let Some(message) = value.pointer("/routing/message_id").and_then(Value::as_str)
    {
        if let Some(payload) = value.pointer("/entry/envelope/payload_hash").and_then(Value::as_str)
        {
            registration.bindings.insert((format!("payload:{payload}"), message.to_owned()));
        }
        if let Some(envelope) = value.pointer("/entry/envelope/envelope_id").and_then(Value::as_str)
        {
            registration.bindings.insert((format!("envelope:{envelope}"), message.to_owned()));
        }
    }
    if key.starts_with("routed/message-metadata/")
        && let (Some(group), Some(group_message), Some(message)) = (
            value.get("group_id").and_then(Value::as_str),
            value.get("group_message_id").and_then(Value::as_str),
            value.get("message_id").and_then(Value::as_str),
        )
    {
        registration
            .bindings
            .insert((format!("group:{group}:{group_message}"), message.to_owned()));
    }
    registration
}

fn collect_generic_references(value: &Value, registration: &mut ActorRegistration) {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if matches!(
                    name.as_str(),
                    "message_id" | "own_copy_message_id" | "target_message_id"
                ) && let Some(message) = value.as_str()
                {
                    registration.message_ids.insert(message.to_owned());
                } else if name == "payload_hash"
                    && let Some(payload) = value.as_str()
                {
                    registration.copy_ids.insert(format!("payload:{payload}"));
                } else if name == "object_id"
                    && let Some(object) = value.as_str()
                {
                    registration.copy_ids.insert(format!("object:{object}"));
                }
                collect_generic_references(value, registration);
            }
            if let Some(message) = fields
                .get("message")
                .and_then(Value::as_object)
                .and_then(|message| message.get("id"))
                .and_then(Value::as_str)
            {
                registration.message_ids.insert(message.to_owned());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_generic_references(value, registration);
            }
        }
        _ => {}
    }
}

fn collect_named_text(value: &Value, name: &str, output: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for (field, value) in fields {
                if field == name
                    && let Some(value) = value.as_str()
                {
                    output.insert(value.to_owned());
                }
                collect_named_text(value, name, output);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_named_text(value, name, output);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
fn drop_actor_registration_for_mutation_test() -> bool {
    std::env::var_os("RAMFLUX_TEST_DROP_MESSAGE_REGISTRATION").is_some()
}

#[cfg(not(test))]
const fn drop_actor_registration_for_mutation_test() -> bool {
    false
}

/// Shared registration predicate for both runtime gates: a listed prefix, or a value that holds
/// a complete envelope at a fixed path, so a future key name cannot bypass ownership.
pub(super) fn admits(key: &str, value: &Value) -> bool {
    actor_state_may_reference_message(key) || value_holds_envelope(value)
}

/// The first fixed-path object (`$`, `$.envelope`, `$.entry.envelope`) holding all six envelope
/// fields with the right JSON types. Anything below `ext` is never read.
pub(in crate::account_db) fn fixed_path_envelope(value: &Value) -> Option<&Value> {
    [value.pointer(""), value.pointer("/envelope"), value.pointer("/entry/envelope")]
        .into_iter()
        .flatten()
        .find(|candidate| {
            let text = |name: &str| candidate.get(name).is_some_and(Value::is_string);
            let number = |name: &str| candidate.get(name).is_some_and(Value::is_number);
            text("source_principal_id")
                && text("source_device_id")
                && text("signing_key_id")
                && text("payload_hash")
                && number("created_at")
                && number("ttl")
        })
}

fn value_holds_envelope(value: &Value) -> bool {
    fixed_path_envelope(value).is_some()
}

fn actor_state_may_reference_message(key: &str) -> bool {
    !key.starts_with("routed/seen/")
        && [
            "routed/",
            "directory/message/",
            "directory/object/",
            "message/origin/",
            "delivery-receipt/",
            "attachment/",
            "sync/attachment/",
            "surface/origin/",
            "surface/message/",
            "surface/pending/",
            "surface/history/",
            "directory/surface_error/",
            "task/message/",
            "group-message/alias/",
            "own-copy/",
            "own-device/",
            "inbox/",
            "backup/staging/",
            "legacy/replay/",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

impl AccountDb {
    /// Stores a conversation's latest commit pointer with its message's erasure footprint.
    /// # Errors
    /// Returns serialization or transaction errors.
    pub fn persist_message_watermark(
        &self,
        message: &str,
        conversation: &str,
        key: &str,
        value: &impl serde::Serialize,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            if self.message_is_deleted(message)? {
                return Ok(());
            }
            self.persist_message_actor_state(message, key, value)?;
            self.connection.execute(
                "DELETE FROM message_footprint WHERE kind='watermark' AND locator=?1",
                params![conversation],
            )?;
            self.connection.execute(
                "INSERT OR IGNORE INTO message_footprint VALUES(?1,'watermark',?2)",
                params![message, conversation],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;

/// Creates the actor archive on first use and installs its registration and erasure triggers
/// in the same transaction, before any caller writes to it. Every lazy creation site uses this.
pub(super) fn ensure_archive_actor_table(db: &rusqlite::Connection) -> rusqlite::Result<()> {
    if schema::exists(db, "backup_archived_actor_state")? {
        return Ok(());
    }
    db.execute_batch(
        "CREATE TABLE backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind));",
    )?;
    install(db)
}

pub(super) fn table_exists(db: &rusqlite::Connection, table: &str) -> rusqlite::Result<bool> {
    schema::exists(db, table)
}
