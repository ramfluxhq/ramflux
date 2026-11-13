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
    pub fn apply(&mut self, mut update: g::MessageUpdate) {
        g::private_revision::redact_update(&mut update);
        // Typing belongs to the expiring live indicator model, never history previews.
        // Reject it even if a caller supplies a forged durable sequence.
        if matches!(
            update.state.as_ref(),
            Some(g::message_update::State::Content(g::Content {
                value: Some(g::content::Value::Typing(_))
            }))
        ) {
            return;
        }
        if self.account_id.as_ref().is_some_and(|account| *account != update.account_id) {
            return;
        }
        self.account_id.get_or_insert_with(|| update.account_id.clone());
        if let Some(identity) = update.identity.as_ref() {
            self.cursor = self.cursor.max(update.journal_sequence);
            let key = (identity.conversation_id.clone(), identity.id.clone());
            if let Some(previous) = self.entries.get(&key)
                && (matches!(previous.state, Some(g::message_update::State::Tombstone(_)))
                    || (previous.journal_sequence > update.journal_sequence
                        && !matches!(update.state, Some(g::message_update::State::Tombstone(_)))))
            {
                return;
            }
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

    /// Resume sequence, including settled updates whose projection was already terminal.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }
}

/// Bounded generated history snapshot. Cursors contain only original immutable headers.
#[derive(Clone, Debug, serde::Serialize)]
pub struct GeneratedMessagePage {
    pub messages: Vec<g::MessageUpdate>,
    pub next_before: Option<g::EventIdentity>,
    pub snapshot_sequence: u64,
}

impl RamfluxClient {
    /// Typed history snapshot. Includes Unsupported views and narrow tombstones, never raw bytes.
    /// # Errors
    /// Refuses non-generated stored content or returns storage/codec errors.
    pub fn generated_message_page(
        &self,
        conversation: &str,
        before_order_key: Option<&g::EventIdentity>,
        limit: u32,
    ) -> Result<GeneratedMessagePage, SdkError> {
        use crate::bindings::{AdapterError, GeneratedErrorCode};
        if !(1..=100).contains(&limit) {
            return Err(AdapterError::new(
                GeneratedErrorCode::InvalidArgument,
                "page limit must be 1..=100",
            )
            .into());
        }
        let before = before_order_key
            .map(|identity| {
                g::identity::verify(identity).map_err(|_| {
                    SdkError::from(AdapterError::new(
                        GeneratedErrorCode::InvalidArgument,
                        "invalid page cursor",
                    ))
                })?;
                if identity.conversation_id != conversation {
                    return Err(AdapterError::new(
                        GeneratedErrorCode::InvalidArgument,
                        "cursor conversation mismatch",
                    )
                    .into());
                }
                g::identity::order_key(identity).map_err(|_| {
                    SdkError::from(AdapterError::new(
                        GeneratedErrorCode::InvalidArgument,
                        "invalid page cursor",
                    ))
                })
            })
            .transpose()?;
        let db = self.account_db()?;
        db.read_snapshot(|| {
            let mut rows = Vec::new();
            for (identity, sequence) in db.generated_message_identities(conversation)? {
                g::identity::verify(&identity)
                    .map_err(|_| SdkError::InboundRejected("invalid stored identity".into()))?;
                let order = g::identity::order_key(&identity)
                    .map_err(|_| SdkError::InboundRejected("invalid stored order".into()))?;
                if before.as_ref().is_none_or(|before| order < *before) {
                    rows.push((order, identity, sequence));
                }
            }
            rows.sort_unstable_by(|left, right| right.0.cmp(&left.0));
            let mut page = GeneratedMessagePage {
                messages: Vec::new(),
                next_before: None,
                snapshot_sequence: db.journal_bounds()?.head_seq,
            };
            let total = rows.len();
            for (_, identity, sequence) in rows.into_iter().take(limit as usize) {
                let id = ramflux_protocol::encode_base64url(&identity.id);
                let message = db
                    .direct_message_by_id(&id)?
                    .ok_or_else(|| SdkError::InboundRejected("page row missing".into()))?;
                let previous = page.next_before.replace(identity);
                page.messages.push(self.generated_message_update(
                    &message,
                    conversation,
                    sequence,
                )?);
                if serde_json::to_vec(&page)?.len() > 768 * 1024 {
                    page.messages.pop();
                    page.next_before = previous;
                    if page.messages.is_empty() {
                        return Err(SdkError::PayloadTooLarge);
                    }
                    return Ok(page);
                }
            }
            if page.messages.len() == total {
                page.next_before = None;
            }
            Ok(page)
        })
    }

    pub(crate) fn generated_message_update(
        &self,
        message: &ramflux_storage::DirectMessageRecord,
        conversation: &str,
        sequence: u64,
    ) -> Result<g::MessageUpdate, SdkError> {
        let db = self.account_db()?;
        let saved_identity = db
            .load_actor_state::<g::EventIdentity>(&format!(
                "routed/generated-identity/{}",
                message.message_id
            ))?
            .ok_or_else(|| {
                SdkError::InboundRejected("generated original identity missing".into())
            })?;
        let mut identity = saved_identity.clone();
        let state = if message.deleted {
            let (original, tombstone) = self.generated_tombstone_projection(
                conversation,
                &message.message_id,
                Some(saved_identity),
            )?;
            identity = original;
            g::message_update::State::Tombstone(tombstone)
        } else if let Some(view) = db.load_actor_state::<g::UnsupportedView>(&format!(
            "routed/unsupported/{}",
            message.message_id
        ))? {
            g::message_update::State::Unsupported(view)
        } else {
            let bytes = db.message_content(&message.message_id)?.ok_or_else(|| {
                SdkError::InboundRejected("generated message content missing".into())
            })?;
            let (_, mut content) = Self::decode_generated_inner(&bytes)?;
            if let Some(message) = db.load_actor_state::<g::Message>(&format!(
                "routed/group-projection/{}",
                message.message_id
            ))? {
                content.value = Some(g::content::Value::Message(message));
            }
            if let Some(g::content::Value::Edit(edit)) = content.value.as_ref() {
                content.value = edit.replacement.clone().map(g::content::Value::Message);
            }
            g::private_revision::redact_content(&mut content);
            g::message_update::State::Content(content)
        };
        Ok(g::MessageUpdate {
            account_id: db.local_account_id.clone(),
            journal_sequence: sequence,
            identity: Some(identity),
            state: Some(state),
        })
    }

    fn generated_tombstone_projection(
        &self,
        conversation: &str,
        message_id: &str,
        saved_identity: Option<g::EventIdentity>,
    ) -> Result<(g::EventIdentity, g::Delete), SdkError> {
        let db = self.account_db()?;
        let fence = db.load_actor_state::<crate::client::generated_delete_fence::Fence>(
            &format!("message-delete-tombstone/{message_id}"),
        )?;
        let identity =
            fence.as_ref().and_then(|fence| fence.identity.clone()).or(saved_identity).ok_or_else(
                || SdkError::InboundRejected("generated tombstone identity missing".into()),
            )?;
        let author_anchor = identity
            .author
            .as_ref()
            .ok_or_else(|| SdkError::InboundRejected("generated tombstone author missing".into()))?
            .account_anchor
            .clone();
        let tombstone = if let Some(fence) = fence {
            g::Delete {
                targets: vec![g::MessageRef {
                    id: identity.id.clone(),
                    conversation_id: conversation.to_owned(),
                    author_anchor,
                }],
                scope: fence.scope,
                tombstone_id: fence.tombstone_id,
                ..Default::default()
            }
        } else {
            let recorded =
                db.message_tombstone_for_message(conversation, message_id)?.ok_or_else(|| {
                    SdkError::InboundRejected("generated tombstone record missing".into())
                })?;
            let scope = match recorded.delete_scope.as_str() {
                "local" => g::DeleteScope::Local,
                "everyone" => g::DeleteScope::Everyone,
                _ => {
                    return Err(SdkError::InboundRejected(
                        "generated tombstone scope invalid".into(),
                    ));
                }
            };
            g::Delete {
                targets: vec![g::MessageRef {
                    id: identity.id.clone(),
                    conversation_id: conversation.to_owned(),
                    author_anchor,
                }],
                scope: scope as i32,
                tombstone_id: ramflux_protocol::decode_base64url(&recorded.tombstone_id)
                    .ok()
                    .filter(|id| id.len() == 32)
                    .ok_or_else(|| {
                        SdkError::InboundRejected("generated tombstone id invalid".into())
                    })?,
                ..Default::default()
            }
        };
        g::identity::verify(&identity)
            .map_err(|_| SdkError::InboundRejected("invalid tombstone identity".into()))?;
        if identity.conversation_id != conversation
            || ramflux_protocol::encode_base64url(&identity.id) != message_id
        {
            return Err(SdkError::InboundRejected("tombstone identity differs from row".into()));
        }
        Ok((identity, tombstone))
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
        let (root, client) = crate::client::own_device_sync::tests::client_with_account(
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
        cache.apply(g::MessageUpdate {
            account_id: "acct".into(),
            journal_sequence: 3,
            identity: Some(g::EventIdentity {
                id: b"message".to_vec(),
                conversation_id: "c".into(),
                ..Default::default()
            }),
            state: Some(g::message_update::State::Content(g::Content::default())),
        });
        assert_eq!(
            cache.cursor(),
            3,
            "settled stale previews must still advance the resume cursor"
        );
        cache.apply(g::MessageUpdate {
            account_id: "other-account".into(),
            journal_sequence: 99,
            identity: Some(g::EventIdentity {
                id: b"message".to_vec(),
                conversation_id: "c".into(),
                ..Default::default()
            }),
            state: Some(g::message_update::State::Tombstone(g::Delete::default())),
        });
        assert_eq!(cache.cursor(), 3, "another account must not advance this cursor");
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

#[cfg(test)]
mod transient_tests {
    use super::*;
    #[test]
    fn history_cache_never_keeps_typing_or_uses_its_cursor_or_account() {
        let mut cache = MessageCache::default();
        let identity =
            g::EventIdentity { id: vec![7; 32], conversation_id: "c".into(), ..Default::default() };
        for sequence in [0, 99] {
            cache.apply(g::MessageUpdate {
                account_id: "wrong-account".into(),
                journal_sequence: sequence,
                identity: Some(identity.clone()),
                state: Some(g::message_update::State::Content(g::Content {
                    value: Some(g::content::Value::Typing(g::Typing {
                        active: true,
                        expires_at: 5,
                    })),
                })),
            });
        }
        assert_eq!(cache.cursor(), 0);
        assert!(cache.get("c", &identity.id).is_none(), "Typing entered durable history cache");
        cache.apply(g::MessageUpdate {
            account_id: "real-account".into(),
            journal_sequence: 40,
            identity: Some(identity.clone()),
            state: Some(g::message_update::State::Tombstone(g::Delete::default())),
        });
        assert_eq!(cache.cursor(), 40);
        assert!(matches!(
            cache.get("c", &identity.id).and_then(|update| update.state.as_ref()),
            Some(g::message_update::State::Tombstone(_))
        ));
    }
}
