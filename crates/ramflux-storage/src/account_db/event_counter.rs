// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent local signing progress survives removal of per-message event copies.
use super::AccountDb;
use crate::StorageError;

impl AccountDb {
    pub(super) fn install_event_counter_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch(SCHEMA)?;
        Ok(())
    }
}

pub(super) const SCHEMA:&str="CREATE TABLE IF NOT EXISTS local_event_counter(actor_device_id TEXT PRIMARY KEY,counter INTEGER NOT NULL);
        CREATE TRIGGER IF NOT EXISTS local_event_counter_insert AFTER INSERT ON local_event_log BEGIN
            INSERT INTO local_event_counter VALUES(NEW.actor_device_id,NEW.device_counter)
            ON CONFLICT(actor_device_id) DO UPDATE SET counter=max(counter,excluded.counter);
        END;
        CREATE TRIGGER IF NOT EXISTS local_event_counter_update AFTER UPDATE OF actor_device_id,device_counter ON local_event_log BEGIN
            INSERT INTO local_event_counter VALUES(NEW.actor_device_id,NEW.device_counter)
            ON CONFLICT(actor_device_id) DO UPDATE SET counter=max(counter,excluded.counter);
        END;";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventStore;
    use rusqlite::params;
    use serde_json::json;

    #[test]
    fn deleting_the_latest_message_event_never_reuses_a_local_signing_counter()
    -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-event-counter")?;
        db.send_direct_message("thread", "message", "peer", b"secret")?;
        db.append_event(
            "first",
            "message.received",
            &serde_json::to_vec(&json!({"message_id":"message"}))?,
        )?;
        let first: i64 = db.connection.query_row(
            "SELECT device_counter FROM local_event_log WHERE event_id='first'",
            [],
            |r| r.get(0),
        )?;
        db.delete_direct_message("thread", "message", "local", "delete")?;
        assert!(db.event_body("first")?.is_none());
        assert_eq!(
            db.connection.query_row(
                "SELECT counter FROM local_event_counter WHERE actor_device_id='device'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            first
        );
        db.append_event("second", "identity.test", b"{}")?;
        assert_eq!(
            db.connection.query_row(
                "SELECT device_counter FROM local_event_log WHERE event_id=?1",
                params!["second"],
                |r| r.get::<_, i64>(0)
            )?,
            first + 1
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
