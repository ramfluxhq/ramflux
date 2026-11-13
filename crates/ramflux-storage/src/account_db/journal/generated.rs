// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed durable updates receive their real cursor before the writer commits.
use super::{JournalEvent, row};
use crate::{AccountDb, StorageError};
use ramflux_protocol::message as g;
use rusqlite::{OptionalExtension, params};

impl AccountDb {
    /// Append a durable generated update, assigning its cursor atomically with publication.
    /// Identical source retries return the original update; conflicting retries are refused.
    /// # Errors
    /// Refuses transient Typing, invalid account/identity, oversized updates and storage errors.
    pub fn append_message_update(
        &self,
        source: &str,
        topic: &str,
        update: &g::MessageUpdate,
        at: i64,
    ) -> Result<JournalEvent, StorageError> {
        let identity = update.identity.as_ref().ok_or(StorageError::AuthorizationRejected)?;
        if update.account_id != self.local_account_id
            || identity.id.len() != 32
            || identity.conversation_id.is_empty()
            || update.state.is_none()
            || matches!(
                update.state.as_ref(),
                Some(g::message_update::State::Content(g::Content {
                    value: Some(g::content::Value::Typing(_))
                }))
            )
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let id = ramflux_protocol::encode_base64url(&identity.id);
        self.write_transaction(|| {
            let previous = self
                .connection
                .query_row(
                    "SELECT seq,at,topic,body_json FROM runtime_journal WHERE source_key=?1",
                    params![source],
                    row,
                )
                .optional()?;
            let mut update = update.clone();
            g::private_revision::redact_update(&mut update);
            if let Some(previous) = previous {
                update.journal_sequence = previous.seq;
                if previous.topic != topic
                    || previous.body != serde_json::json!({"message_id":id,"update":update})
                {
                    return Err(StorageError::EventIdConflict(source.to_owned()));
                }
                return Ok(previous);
            }
            update.journal_sequence = 0;
            let mut event = self.insert_journal(
                source,
                topic,
                &serde_json::json!({"message_id":id,"update":update}),
                at,
                Some(&identity.conversation_id),
            )?;
            update.journal_sequence = event.seq;
            event.body = serde_json::json!({"message_id":id,"update":update});
            let bytes = serde_json::to_vec(&event.body)?;
            if bytes.len() > 512 * 1024 {
                return Err(StorageError::AuthorizationRejected);
            }
            self.connection.execute(
                "UPDATE runtime_journal SET body_json=?2 WHERE seq=?1",
                params![event.seq, bytes],
            )?;
            Ok(event)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn typed_update_cursor_is_atomic_idempotent_and_never_captures_typing() -> TestResult {
        let (_root, db) = crate::tests::test_db("generated-journal-cursor")?;
        let mut update = g::MessageUpdate {
            account_id: db.local_account_id.clone(),
            journal_sequence: 0,
            identity: Some(g::EventIdentity {
                id: vec![7; 32],
                conversation_id: "c".into(),
                ..Default::default()
            }),
            state: Some(g::message_update::State::Content(g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: "hello".into(),
                    ..Default::default()
                })),
            })),
        };
        let first = db.append_message_update("source", "message.schema.updated", &update, 1)?;
        let stored: g::MessageUpdate = serde_json::from_value(first.body["update"].clone())?;
        assert_eq!(stored.journal_sequence, first.seq);
        assert!(stored.journal_sequence > 0);
        assert_eq!(
            db.append_message_update("source", "message.schema.updated", &update, 2)?,
            first
        );
        let head = db.journal_bounds()?.head_seq;
        update.state = Some(g::message_update::State::Content(g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "fork".into(),
                ..Default::default()
            })),
        }));
        assert!(matches!(
            db.append_message_update("source", "message.schema.updated", &update, 3),
            Err(StorageError::EventIdConflict(_))
        ));
        update.state = Some(g::message_update::State::Content(g::Content {
            value: Some(g::content::Value::Typing(g::Typing { active: true, expires_at: 5 })),
        }));
        assert!(db.append_message_update("transient", "message.transient", &update, 4).is_err());
        assert_eq!(db.journal_bounds()?.head_seq, head);
        Ok(())
    }
}
