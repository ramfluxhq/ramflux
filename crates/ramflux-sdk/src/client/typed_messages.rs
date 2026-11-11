// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated history contract shared by SDK readers and the TUI. Raw bytes stay private.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use std::collections::BTreeMap;

/// Bounded journal cursor refusal. A consumer discards cached state and takes a new snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("resync required: cursor {cursor}, retained {floor}..={head}")]
pub struct ResyncRequired {
    pub cursor: u64,
    pub floor: u64,
    pub head: u64,
}

/// Consumer cache with explicit tombstone invalidation and stale-cursor reset.
#[derive(Default)]
pub struct MessageCache {
    entries: BTreeMap<(String, Vec<u8>), g::MessageUpdate>,
    cursor: u64,
    account_id: Option<String>,
}

impl MessageCache {
    /// Apply one generated update. A tombstone atomically replaces every cached preview.
    pub fn apply(&mut self, update: g::MessageUpdate) {
        if self.account_id.as_ref().is_some_and(|account| *account != update.account_id) {
            return;
        }
        self.account_id.get_or_insert_with(|| update.account_id.clone());
        if let Some(identity) = update.identity.as_ref() {
            let key = (identity.conversation_id.clone(), identity.id.clone());
            if let Some(previous) = self.entries.get(&key)
                && (matches!(previous.state, Some(g::message_update::State::Tombstone(_)))
                    || (previous.journal_sequence > update.journal_sequence
                        && !matches!(update.state, Some(g::message_update::State::Tombstone(_)))))
            {
                return;
            }
            self.cursor = self.cursor.max(update.journal_sequence);
            self.entries.insert(key, update);
        }
    }

    /// Drop all private cached projections before requesting a fresh snapshot.
    pub fn resync(&mut self, refusal: ResyncRequired) {
        self.entries.clear();
        self.cursor = refusal.head;
    }

    #[must_use]
    pub fn get(&self, conversation: &str, id: &[u8]) -> Option<&g::MessageUpdate> {
        self.entries.get(&(conversation.to_owned(), id.to_vec()))
    }
}

impl RamfluxClient {
    /// Typed history snapshot. Includes Unsupported views and narrow tombstones, never raw bytes.
    /// # Errors
    /// Refuses non-generated stored content or returns storage/codec errors.
    pub fn generated_message_page(
        &self,
        conversation: &str,
    ) -> Result<Vec<g::MessageUpdate>, SdkError> {
        let db = self.account_db()?;
        let account_id = db.local_account_id.clone();
        let head = db.journal_bounds()?.head_seq;
        let mut updates = Vec::new();
        for message in self.direct_messages(conversation)? {
            let mut identity = g::EventIdentity {
                id: message.message_id.as_bytes().to_vec(),
                conversation_id: conversation.to_owned(),
                ..Default::default()
            };
            let state = if message.deleted {
                g::message_update::State::Tombstone(g::Delete {
                    targets: vec![g::MessageRef {
                        id: identity.id.clone(),
                        conversation_id: conversation.to_owned(),
                        author_anchor: String::new(),
                    }],
                    scope: g::DeleteScope::Local as i32,
                    ..Default::default()
                })
            } else if let Some(view) = db.load_actor_state::<g::UnsupportedView>(&format!(
                "routed/unsupported/{}",
                message.message_id
            ))? {
                g::message_update::State::Unsupported(view)
            } else {
                let bytes = db.message_content(&message.message_id)?.ok_or_else(|| {
                    SdkError::InboundRejected("generated message content missing".into())
                })?;
                let (original, mut content) = Self::decode_generated_inner(&bytes)?;
                identity = db
                    .load_actor_state::<g::EventIdentity>(&format!(
                        "routed/generated-identity/{}",
                        message.message_id
                    ))?
                    .unwrap_or(original);
                if let Some(message) = db.load_actor_state::<g::Message>(&format!(
                    "routed/group-projection/{}",
                    message.message_id
                ))? {
                    content.value = Some(g::content::Value::Message(message));
                }
                if let Some(g::content::Value::Edit(edit)) = content.value.as_ref() {
                    content.value = edit.replacement.clone().map(g::content::Value::Message);
                }
                g::message_update::State::Content(content)
            };
            updates.push(g::MessageUpdate {
                account_id: account_id.clone(),
                journal_sequence: head,
                identity: Some(identity),
                state: Some(state),
            });
        }
        Ok(updates)
    }

    /// Validate a subscription cursor before replay; future and pruned cursors require resync.
    /// # Errors
    /// Returns storage errors. The inner error carries the resync bounds.
    pub fn generated_cursor_status(
        &self,
        cursor: u64,
    ) -> Result<Result<(), ResyncRequired>, SdkError> {
        let bounds = self.account_db()?.journal_bounds()?;
        if cursor < bounds.pruned_through || cursor > bounds.head_seq {
            Ok(Err(ResyncRequired { cursor, floor: bounds.floor_seq, head: bounds.head_seq }))
        } else {
            Ok(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_updates_invalidate_deleted_cache_and_resync_stale_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let (client, root) = crate::client::own_device_sync::tests::client_with_account(
            "typed-cache",
            "principal_sync",
            "local",
        )?;
        let refusal =
            client.generated_cursor_status(1)?.err().ok_or("future cursor needs resync")?;
        let identity = g::EventIdentity {
            id: b"message".to_vec(),
            conversation_id: "c".into(),
            ..Default::default()
        };
        let mut cache = MessageCache::default();
        cache.apply(g::MessageUpdate {
            account_id: "acct".into(),
            journal_sequence: 1,
            identity: Some(identity.clone()),
            state: Some(g::message_update::State::Content(g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: "private preview".into(),
                    ..Default::default()
                })),
            })),
        });
        cache.apply(g::MessageUpdate {
            account_id: "acct".into(),
            journal_sequence: 2,
            identity: Some(identity),
            state: Some(g::message_update::State::Tombstone(g::Delete::default())),
        });
        let tombstone = cache.get("c", b"message").ok_or("tombstone")?;
        assert!(matches!(tombstone.state, Some(g::message_update::State::Tombstone(_))));
        assert!(!serde_json::to_string(tombstone)?.contains("private preview"));
        cache.resync(refusal);
        assert!(cache.get("c", b"message").is_none());
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
