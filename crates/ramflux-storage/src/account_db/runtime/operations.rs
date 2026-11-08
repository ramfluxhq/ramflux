// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable account-scoped retry reservations and response receipts.

use super::super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};

/// Read-only disposition of an account-scoped operation key.
#[derive(Clone, Debug, PartialEq)]
pub enum OperationLookup {
    Absent,
    Completed(serde_json::Value),
    Pending,
    Mismatch,
}

impl AccountDb {
    /// Looks up a retry receipt without reserving a key or starting a write transaction.
    ///
    /// # Errors
    /// Returns a storage or decoding error if the saved receipt cannot be read.
    pub fn lookup_operation(
        &self,
        id: &str,
        fingerprint: &str,
    ) -> Result<OperationLookup, StorageError> {
        let existing: Option<(String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT fingerprint,response_json FROM runtime_operation WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(match existing {
            None => OperationLookup::Absent,
            Some((saved, _)) if saved != fingerprint => OperationLookup::Mismatch,
            Some((_, None)) => OperationLookup::Pending,
            Some((_, Some(response))) => {
                OperationLookup::Completed(serde_json::from_str(&response)?)
            }
        })
    }

    /// Reserves a mutation key before effects. A pending receipt fails closed after a crash.
    ///
    /// # Errors
    /// Rejects conflicting payloads and pending operations that require reconciliation.
    pub fn reserve_operation(
        &self,
        id: &str,
        fingerprint: &str,
        kind: &str,
    ) -> Result<Option<serde_json::Value>, StorageError> {
        let transaction = self.connection.immediate_transaction()?;
        let existing: Option<(String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT fingerprint,response_json FROM runtime_operation WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((saved, response)) = existing {
            if saved != fingerprint {
                return Err(StorageError::EventIdConflict(id.to_owned()));
            }
            let response = response.ok_or_else(|| {
                StorageError::OperationReconciliationRequired { key: id.to_owned() }
            })?;
            transaction.commit()?;
            let response: serde_json::Value = serde_json::from_str(&response)?;
            if response.get("object_erased").and_then(serde_json::Value::as_bool) == Some(true) {
                return Err(StorageError::ObjectErased);
            }
            return Ok(Some(response));
        }
        self.connection.execute(
            "INSERT INTO runtime_operation(operation_id,fingerprint,operation_kind) VALUES(?1,?2,?3)",
            params![id, fingerprint, kind],
        )?;
        transaction.commit()?;
        Ok(None)
    }

    /// # Errors
    /// Binds a reserved operation to its payloads before effects, including payload-free responses.
    pub fn bind_operation_objects(
        &self,
        id: &str,
        request: &serde_json::Value,
    ) -> Result<(), StorageError> {
        self.register_object_response(id, request)
    }

    /// # Errors
    /// Returns an error if the committed mutation response cannot be saved for retries.
    pub fn complete_operation(
        &self,
        id: &str,
        response: &serde_json::Value,
    ) -> Result<(), StorageError> {
        let transaction = self.connection.immediate_transaction()?;
        if let Err(error) = self.register_object_response(id, response) {
            if matches!(error, StorageError::ObjectErased) {
                self.connection.execute("UPDATE runtime_operation SET response_json='{\"object_erased\":true}' WHERE operation_id=?1",params![id])?;
                transaction.commit()?;
            }
            return Err(error);
        }
        self.connection.execute(
            "UPDATE runtime_operation SET response_json=?2 WHERE operation_id=?1",
            params![id, serde_json::to_string(response)?],
        )?;
        self.register_operation_message_copy(id, response)?;
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lookup_operation_is_read_only_and_preserves_every_receipt_state() -> Result<(), StorageError>
    {
        let (root, db) = crate::tests::test_db("operation-lookup")?;
        let reader = db.open_reader()?;
        assert_eq!(reader.lookup_operation("new", "a")?, OperationLookup::Absent);
        assert_eq!(db.lookup_operation("new", "b")?, OperationLookup::Absent);
        assert_eq!(db.reserve_operation("new", "a", "")?, None);
        assert_eq!(reader.lookup_operation("new", "a")?, OperationLookup::Pending);
        assert_eq!(reader.lookup_operation("new", "b")?, OperationLookup::Mismatch);
        assert!(
            matches!(db.reserve_operation("new", "a", ""), Err(StorageError::OperationReconciliationRequired { key }) if key == "new")
        );
        let response = json!({"value":"committed"});
        db.complete_operation("new", &response)?;
        assert_eq!(
            reader.lookup_operation("new", "a")?,
            OperationLookup::Completed(response.clone())
        );
        assert_eq!(db.reserve_operation("new", "a", "")?, Some(response));
        db.complete_operation("new", &json!({"object_erased":true}))?;
        assert_eq!(
            reader.lookup_operation("new", "a")?,
            OperationLookup::Completed(json!({"object_erased":true}))
        );
        assert!(matches!(db.reserve_operation("new", "a", ""), Err(StorageError::ObjectErased)));
        drop(reader);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn keyed_delete_and_send_complete_after_the_message_is_already_deleted()
    -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("keyed-delete-complete")?;
        db.send_direct_message("thread", "m", "peer", b"private-content")?;
        db.reserve_operation("op-delete", "fp-op", "message.delete")?;
        db.reserve_operation("idem-delete", "fp-idem", "message.delete")?;
        db.reserve_operation("send-race", "fp-send", "message.send")?;
        db.delete_direct_message("thread", "m", "local", "delete")?;
        let delete_body = json!({
            "tombstone_id": "tombstone:thread:m",
            "conversation_id": "thread",
            "message_id": "m",
            "delete_scope": "local"
        });
        db.complete_operation("op-delete", &delete_body)?;
        db.complete_operation("idem-delete", &delete_body)?;
        db.complete_operation("send-race", &json!({"message_id":"m","preview":"send-body"}))?;
        for (id, fingerprint) in [("op-delete", "fp-op"), ("idem-delete", "fp-idem")] {
            let replay = db.reserve_operation(id, fingerprint, "message.delete")?;
            assert_eq!(replay, Some(delete_body.clone()), "{id}");
        }
        assert!(
            matches!(
                db.reserve_operation("send-race", "fp-send", "message.send"),
                Err(StorageError::ObjectErased)
            ),
            "send-race replay must be ObjectErased"
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn keyed_expire_replays_nested_tombstones_exactly() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("keyed-expire-replay")?;
        db.send_direct_message("thread", "m1", "peer", b"private-content")?;
        db.send_direct_message("thread", "m2", "peer", b"private-content")?;
        db.reserve_operation("op-expire", "fp-expire", "conversation.disappearing.expire")?;
        db.delete_direct_message("thread", "m1", "local", "delete")?;
        db.delete_direct_message("thread", "m2", "local", "delete")?;
        let expire_body = json!({
            "tombstones": [
                {
                    "tombstone_id": "tombstone:thread:m1",
                    "conversation_id": "thread",
                    "message_id": "m1",
                    "delete_scope": "local"
                },
                {
                    "tombstone_id": "tombstone:thread:m2",
                    "conversation_id": "thread",
                    "message_id": "m2",
                    "delete_scope": "local"
                }
            ]
        });
        db.complete_operation("op-expire", &expire_body)?;
        let replay =
            db.reserve_operation("op-expire", "fp-expire", "conversation.disappearing.expire")?;
        assert_eq!(replay, Some(expire_body));
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn echoed_tool_started_receipt_with_nested_tombstone_id_replays_object_erased()
    -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("echoed-tool-started-erasure")?;
        db.send_direct_message("thread", "m", "peer", b"private-content")?;
        db.reserve_operation("op-mcp", "fp-mcp", "mcp.tool.started")?;
        db.complete_operation(
            "op-mcp",
            &json!({
                "status": "ok",
                "output": {
                    "echo": {
                        "message_id": "m",
                        "text": "echoed-plaintext-body",
                        "tombstone_id": "x"
                    }
                }
            }),
        )?;
        db.delete_direct_message("thread", "m", "local", "delete")?;
        assert!(
            matches!(
                db.reserve_operation("op-mcp", "fp-mcp", "mcp.tool.started"),
                Err(StorageError::ObjectErased)
            ),
            "echoed tool-started receipt must replay ObjectErased"
        );
        let receipt: String = db.connection.query_row(
            "SELECT response_json FROM runtime_operation WHERE operation_id='op-mcp'",
            [],
            |row| row.get(0),
        )?;
        assert!(!receipt.contains("echoed-plaintext-body"), "{receipt}");
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
