// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed payload retirement inside the same transaction that installs a winning Edit.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{Connection, params};

impl AccountDb {
    /// Read indexed actor copies without granting authority from their contents.
    /// # Errors
    /// Returns SQL or stored JSON decoding errors.
    pub fn message_actor_entries<T: serde::de::DeserializeOwned>(
        &self,
        message: &str,
        prefix: &str,
    ) -> Result<Vec<(String, T)>, StorageError> {
        let mut query = self.connection.prepare("SELECT DISTINCT a.state_kind,a.state_json FROM runtime_actor_state a JOIN message_footprint f ON f.kind='actor' AND f.locator=a.state_kind WHERE f.message_id=?1 AND substr(a.state_kind,1,length(?2))=?2 ORDER BY a.state_kind")?;
        query
            .query_map(params![message, prefix], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .map(|row| {
                let (key, bytes) = row?;
                Ok((key, serde_json::from_slice(&bytes)?))
            })
            .collect()
    }

    /// Read indexed actor keys belonging to a logical message.
    /// # Errors
    /// Returns SQL errors.
    pub fn message_actor_keys(
        &self,
        message: &str,
        prefix: &str,
    ) -> Result<Vec<String>, StorageError> {
        let mut query = self.connection.prepare("SELECT locator FROM message_footprint WHERE message_id=?1 AND kind='actor' AND substr(locator,1,length(?2))=?2 ORDER BY locator")?;
        Ok(query
            .query_map(params![message, prefix], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Retire indexed old payload copies without deleting the logical Message identity.
    /// `keep_actors` must name only separately verified body-free metadata or sanitized receipts.
    /// The caller writes replacement content and immutable original evidence in this transaction.
    /// # Errors
    /// Refuses autocommit and returns SQL errors, rolling back with the caller's transaction.
    pub fn retire_message_payload_copies(
        &self,
        message: &str,
        keep_actors: &[String],
    ) -> Result<(), StorageError> {
        let message = message.to_owned();
        let keep = keep_actors.to_vec();
        self.connection.call(move |db| {
            let write = || {
                if db.is_autocommit() { return Err(StorageError::AuthorizationRejected); }
                let mut query = db.prepare("SELECT kind,locator FROM message_footprint WHERE message_id=?1")?;
                let copies = query.query_map([&message], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
                drop(query);
                for (kind, locator) in copies { retire_copy(db, &kind, &locator, &keep)?; }
                db.execute("DELETE FROM raw_inner_evidence WHERE message_id=?1", [&message])?;
                db.execute("DELETE FROM raw_inner_owner WHERE owner_id=?1", [&message])?;
                db.execute("INSERT INTO runtime_privacy_maintenance VALUES(1,1) ON CONFLICT(singleton) DO UPDATE SET erasure_pending=1", [])?;
                Ok(())
            };
            Ok(write())
        }).map_err(StorageError::from)?
    }
}

fn retire_actor(db: &Connection, key: &str) -> rusqlite::Result<()> {
    let independently_owned: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM object_reference_actor a JOIN object_message_reference m USING(reference_hash) WHERE a.state_kind=?1) OR EXISTS(SELECT 1 FROM object_payload_actor a JOIN object_retention_payload p USING(commitment) WHERE a.state_kind=?1 AND (p.owner_count>0 OR p.retention_class='standalone'))", [key], |row| row.get(0))?;
    if independently_owned {
        return Ok(());
    }
    db.execute("DELETE FROM runtime_outbox WHERE table_name='runtime_actor_state' AND (actor_state_kind=?1 OR row_id IN (SELECT rowid FROM runtime_actor_state WHERE state_kind=?1))", [key])?;
    db.execute("DELETE FROM runtime_receipt_retention WHERE state_kind=?1", [key])?;
    db.execute("DELETE FROM runtime_actor_state WHERE state_kind=?1", [key])?;
    // Actor delete triggers may enqueue a final row; it must not contain the old JSON either.
    db.execute(
        "DELETE FROM runtime_outbox WHERE table_name='runtime_actor_state' AND actor_state_kind=?1",
        [key],
    )?;
    Ok(())
}

fn retire_copy(
    db: &Connection,
    kind: &str,
    locator: &str,
    keep: &[String],
) -> rusqlite::Result<()> {
    match kind {
        "actor" | "prepared" | "history_container" if !keep.iter().any(|key| key == locator) => {
            retire_actor(db, locator)?;
        }
        "receive_work" => {
            if super::message_footprint::table_exists(db, "gateway_receive_work")? {
                db.execute("UPDATE gateway_receive_receipt SET disposition='erased' WHERE (target_delivery_id,incarnation_id,inbox_seq)=(json_extract(?1,'$[0]'),json_extract(?1,'$[1]'),unhex(json_extract(?1,'$[2]')))", [locator])?;
                db.execute("DELETE FROM gateway_receive_work WHERE (target_delivery_id,incarnation_id,inbox_seq)=(json_extract(?1,'$[0]'),json_extract(?1,'$[1]'),unhex(json_extract(?1,'$[2]')))", [locator])?;
            }
        }
        "event" => {
            db.execute("DELETE FROM local_event_log WHERE event_id=?1", [locator])?;
        }
        "raw_inner" => {
            db.execute("DELETE FROM raw_inner_copy WHERE copy_id=?1", [locator])?;
        }
        "journal" => {
            db.execute("UPDATE runtime_journal SET body_json=CAST('{\"content_retired\":true}' AS BLOB),source_key='retired:'||seq,subject=NULL WHERE seq=CAST(?1 AS INTEGER)", [locator])?;
        }
        "operation" => {
            db.execute("UPDATE runtime_operation SET response_json='{\"content_retired\":true}' WHERE operation_id=?1", [locator])?;
        }
        "retry" | "dead_letter" | "unrouted" => retire_inbox_copy(db, kind, locator)?,
        "archived_actor" => delete_row(db, "backup_archived_actor_state", locator)?,
        "archived_event" => delete_row(db, "backup_archived_local_event", locator)?,
        "runtime_message_content"
        | "message_projection"
        | "group_pending_undecrypted"
        | "contact_message_request" => delete_row(db, kind, locator)?,
        "raw_envelope_log:envelope_id" => delete_row(db, "raw_envelope_log", locator)?,
        "outbox_queue:envelope_id" => delete_row(db, "outbox_queue", locator)?,
        "outbox" => {
            db.execute("DELETE FROM runtime_outbox WHERE sequence=CAST(?1 AS INTEGER)", [locator])?;
        }
        // Identity, read/delivery pointers and counters contain no retired content or opening.
        _ => (),
    }
    Ok(())
}

fn delete_row(db: &Connection, table: &str, locator: &str) -> rusqlite::Result<()> {
    if super::message_footprint::table_exists(db, table)? {
        db.execute(&format!("DELETE FROM {table} WHERE rowid=CAST(?1 AS INTEGER)"), [locator])?;
    }
    Ok(())
}

fn retire_inbox_copy(db: &Connection, kind: &str, locator: &str) -> rusqlite::Result<()> {
    let (table, column) = match kind {
        "retry" => ("runtime_inbox_retry", "envelope_key"),
        "dead_letter" => ("runtime_inbox_dead_letter", "envelope_key"),
        _ => ("runtime_unrouted", "envelope_id"),
    };
    db.execute(&format!("DELETE FROM {table} WHERE {column}=?1"), params![locator])?;
    Ok(())
}

#[cfg(test)]
mod tests;

impl AccountDb {
    /// Retire every native attachment reference when a full-Message Edit drops all media.
    /// Native last-owner rules preserve payloads independently owned by another message.
    /// # Errors
    /// Requires the enclosing Edit transaction and returns SQL failures.
    pub fn retire_message_attachment_references(&self, message: &str) -> Result<(), StorageError> {
        let message = message.to_owned();
        self.connection.call(move |db| {
            let write = || {
                if db.is_autocommit() { return Err(StorageError::AuthorizationRejected); }
                db.execute_batch("CREATE TEMP TABLE IF NOT EXISTS edit_retirement_context(message_id TEXT NOT NULL); DELETE FROM edit_retirement_context;")?;
                db.execute("INSERT INTO edit_retirement_context VALUES(?1)", [&message])?;
                let body = super::object_retention::erasure_body(db)?.replace("NEW.message_id", "(SELECT message_id FROM temp.edit_retirement_context)");
                db.execute_batch(&body)?;
                db.execute("DELETE FROM edit_retirement_context", [])?;
                Ok(())
            };
            Ok(write())
        }).map_err(StorageError::from)?
    }
}
