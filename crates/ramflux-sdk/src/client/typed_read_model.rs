// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unified message read model consumed by `rf` and `rf-tui`.
//!
//! Every view is rebuilt from the durable account store. No RAM-only delivery page is consulted,
//! so a restart or a long unread backlog cannot hide a committed message from a reader.
use crate::bindings::{AdapterError, GeneratedErrorCode};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use serde::Serialize;
use std::collections::BTreeMap;

/// Contract name carried by every read-model response.
pub const READ_MODEL_SCHEMA: &str = "ramflux.message.read_model.v1";
/// Largest encoded page or change batch.
pub const MAX_RESPONSE_BYTES: usize = 768 * 1024;
/// Largest row count of one page or change batch.
pub const MAX_ROWS: u32 = 100;

/// Author of the original immutable event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorView {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
}

/// Content-free placeholder for a kind this build cannot render.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnsupportedPlaceholder {
    pub layer: u32,
    pub kind: u32,
    pub raw_length: u32,
    pub reason: String,
}

/// Erasure state of a deleted message. Carries no body, digest or evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ErasureView {
    /// `local`, `everyone` or `unspecified`.
    pub scope: &'static str,
    /// Base64url tombstone identifier.
    pub tombstone_id: String,
}

/// Visible reaction token with the number of visible registers that carry it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReactionView {
    pub token: String,
    pub count: u32,
}

/// One message as a client renders it.
#[derive(Clone, Debug, Serialize)]
pub struct MessageView {
    /// Base64url of the 32-byte original event identifier.
    pub id: String,
    pub conversation_id: String,
    pub author: Option<AuthorView>,
    pub device_sequence: u64,
    pub hlc: u64,
    pub group_id: Option<String>,
    /// Durable sequence of this row's last change; the change cursor.
    pub journal_sequence: u64,
    pub is_own: bool,
    /// `content`, `unsupported` or `tombstone`.
    pub state: &'static str,
    /// Content kind name, or `unsupported` / `tombstone`.
    pub kind: &'static str,
    pub text: Option<String>,
    /// Typed public content in force. Absent for placeholders and tombstones.
    pub content: Option<g::Content>,
    pub unsupported: Option<UnsupportedPlaceholder>,
    pub erasure: Option<ErasureView>,
    /// Highest applied Edit revision; zero for an unedited message.
    pub revision: u64,
    pub edited: bool,
    pub reactions: Vec<ReactionView>,
    pub receipts: Vec<ramflux_storage::MessageReceiptState>,
}

/// Newest-first bounded page.
#[derive(Clone, Debug, Serialize)]
pub struct MessageViewPage {
    pub schema: &'static str,
    pub conversation_id: String,
    pub messages: Vec<MessageView>,
    /// Cursor for the next older page; absent at the beginning of history.
    pub next_before: Option<g::EventIdentity>,
    pub snapshot_sequence: u64,
}

/// Durable changes after a cursor, oldest change first.
#[derive(Clone, Debug, Serialize)]
pub struct MessageChanges {
    pub schema: &'static str,
    pub conversation_id: String,
    pub changes: Vec<MessageView>,
    /// Cursor to pass as `after_sequence` on the next call.
    pub next_after: u64,
    /// True when more changes were committed than this batch carries.
    pub more: bool,
    pub snapshot_sequence: u64,
}

/// One message with its revision, reaction, receipt and erasure state.
#[derive(Clone, Debug, Serialize)]
pub struct MessageDetail {
    pub schema: &'static str,
    pub message: MessageView,
    pub snapshot_sequence: u64,
}

#[derive(serde::Deserialize)]
struct AppliedRevision {
    revision: u64,
}

fn refused(code: GeneratedErrorCode, message: &'static str) -> SdkError {
    AdapterError::new(code, message).into()
}

fn check_limit(limit: u32) -> Result<(), SdkError> {
    if (1..=MAX_ROWS).contains(&limit) {
        Ok(())
    } else {
        Err(refused(GeneratedErrorCode::InvalidArgument, "page limit must be 1..=100"))
    }
}

const fn kind_name(value: &g::content::Value) -> &'static str {
    match value {
        g::content::Value::Message(_) => "message",
        g::content::Value::Service(_) => "service",
        g::content::Value::Edit(_) => "edit",
        g::content::Value::Delete(_) => "delete",
        g::content::Value::Reaction(_) => "reaction",
        g::content::Value::Receipt(_) => "receipt",
        g::content::Value::Typing(_) => "typing",
        g::content::Value::Control(_) => "control",
        g::content::Value::Surface(_) => "surface",
        g::content::Value::Task(_) => "task",
        g::content::Value::Call(_) => "call",
        g::content::Value::SelfSync(_) => "self_sync",
    }
}

fn erasure_view(delete: &g::Delete) -> ErasureView {
    let scope = if delete.scope == g::DeleteScope::Local as i32 {
        "local"
    } else if delete.scope == g::DeleteScope::Everyone as i32 {
        "everyone"
    } else {
        "unspecified"
    };
    ErasureView { scope, tombstone_id: ramflux_protocol::encode_base64url(&delete.tombstone_id) }
}

fn encoded_len<T: Serialize>(value: &T) -> Result<usize, SdkError> {
    Ok(serde_json::to_vec(value)?.len())
}

impl RamfluxClient {
    /// Newest-first bounded page of rendered messages, read from the durable store.
    /// # Errors
    /// Returns typed argument refusals, `payload_too_large`, or storage/codec errors.
    pub fn generated_message_view_page(
        &self,
        conversation: &str,
        before_order_key: Option<&g::EventIdentity>,
        limit: u32,
    ) -> Result<MessageViewPage, SdkError> {
        let page = self.generated_message_page(conversation, before_order_key, limit)?;
        let mut identities = Vec::with_capacity(page.messages.len());
        let mut messages = Vec::with_capacity(page.messages.len());
        for update in page.messages {
            let identity = update.identity.clone();
            if let Some(view) = self.message_view(conversation, update)? {
                messages.push(view);
                identities.push(identity);
            }
        }
        let mut views = MessageViewPage {
            schema: READ_MODEL_SCHEMA,
            conversation_id: conversation.to_owned(),
            messages,
            next_before: page.next_before,
            snapshot_sequence: page.snapshot_sequence,
        };
        // Views add reactions and receipts to the bounded updates; keep the same frame cap.
        while encoded_len(&views)? > MAX_RESPONSE_BYTES {
            views.messages.pop();
            identities.pop();
            let Some(last) = identities.last() else {
                return Err(SdkError::PayloadTooLarge);
            };
            views.next_before.clone_from(last);
        }
        Ok(views)
    }

    /// Durable changes of one conversation after `after_sequence`, oldest change first.
    ///
    /// Zero requests a full snapshot in change order. Every other cursor must lie inside the
    /// retained journal; a pruned or future cursor is refused with `resync_required`.
    /// # Errors
    /// Returns typed argument or resync refusals, `payload_too_large`, or storage/codec errors.
    pub fn generated_message_changes(
        &self,
        conversation: &str,
        after_sequence: u64,
        limit: u32,
    ) -> Result<MessageChanges, SdkError> {
        check_limit(limit)?;
        if after_sequence != 0
            && let Err(refusal) = self.generated_cursor_status(after_sequence)?
        {
            return Err(AdapterError::resync(refusal.cursor, refusal.floor, refusal.head).into());
        }
        let db = self.account_db()?;
        let (rows, head) = db.read_snapshot(|| {
            let mut rows = Vec::new();
            for (identity, sequence) in db.generated_message_identities(conversation)? {
                if after_sequence != 0 && sequence <= after_sequence {
                    continue;
                }
                g::identity::verify(&identity)
                    .map_err(|_| SdkError::InboundRejected("invalid stored identity".into()))?;
                let order = g::identity::order_key(&identity)
                    .map_err(|_| SdkError::InboundRejected("invalid stored order".into()))?;
                rows.push((sequence, order, identity));
            }
            rows.sort_unstable_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
            let total = rows.len();
            // Rows sharing one sequence travel together so the cursor never splits a commit.
            let mut cut = total.min(limit as usize);
            while cut > 0
                && rows
                    .get(cut)
                    .zip(rows.get(cut - 1))
                    .is_some_and(|(next, last)| next.0 == last.0)
            {
                cut += 1;
            }
            rows.truncate(cut);
            let mut updates = Vec::with_capacity(rows.len());
            for (sequence, _, identity) in rows {
                let id = ramflux_protocol::encode_base64url(&identity.id);
                let Some(message) = db.direct_message_by_id(&id)? else {
                    continue;
                };
                updates.push((
                    self.generated_message_update(&message, conversation, sequence)?,
                    message,
                ));
            }
            Ok::<_, SdkError>(((updates, total > cut), db.journal_bounds()?.head_seq))
        })?;
        let (updates, mut more) = rows;
        let mut changes = MessageChanges {
            schema: READ_MODEL_SCHEMA,
            conversation_id: conversation.to_owned(),
            changes: Vec::with_capacity(updates.len()),
            next_after: after_sequence,
            more,
            snapshot_sequence: head,
        };
        for (update, message) in updates {
            changes.changes.push(self.view_of(update, &message)?);
        }
        while encoded_len(&changes)? > MAX_RESPONSE_BYTES {
            let Some(dropped) = changes.changes.pop() else {
                return Err(SdkError::PayloadTooLarge);
            };
            while changes
                .changes
                .last()
                .is_some_and(|last| last.journal_sequence == dropped.journal_sequence)
            {
                changes.changes.pop();
            }
            if changes.changes.is_empty() {
                return Err(SdkError::PayloadTooLarge);
            }
            more = true;
        }
        changes.more = more;
        changes.next_after = if more {
            changes.changes.last().map_or(after_sequence, |last| last.journal_sequence)
        } else {
            head.max(after_sequence)
        };
        Ok(changes)
    }

    /// One message with revision, reactions, receipts and erasure state.
    /// # Errors
    /// Returns `invalid_argument`, `target_not_found`, or storage/codec errors.
    pub fn generated_message_detail(
        &self,
        conversation: &str,
        message_id: &str,
    ) -> Result<MessageDetail, SdkError> {
        let wanted = ramflux_protocol::decode_base64url(message_id)
            .ok()
            .filter(|id| id.len() == 32)
            .ok_or_else(|| refused(GeneratedErrorCode::InvalidArgument, "invalid message id"))?;
        let db = self.account_db()?;
        let (update, message, head) = db.read_snapshot(|| {
            let sequence = db
                .generated_message_identities(conversation)?
                .into_iter()
                .find_map(|(identity, sequence)| (identity.id == wanted).then_some(sequence))
                .ok_or_else(|| refused(GeneratedErrorCode::TargetNotFound, "message not found"))?;
            let message = db
                .direct_message_by_id(message_id)?
                .ok_or_else(|| refused(GeneratedErrorCode::TargetNotFound, "message not found"))?;
            let update = self.generated_message_update(&message, conversation, sequence)?;
            Ok::<_, SdkError>((update, message, db.journal_bounds()?.head_seq))
        })?;
        Ok(MessageDetail {
            schema: READ_MODEL_SCHEMA,
            message: self.view_of(update, &message)?,
            snapshot_sequence: head,
        })
    }

    /// Reload the row behind an update read in an earlier snapshot. A row erased since then is
    /// omitted and a row deleted since then is rendered as its tombstone, never as old content.
    fn message_view(
        &self,
        conversation: &str,
        update: g::MessageUpdate,
    ) -> Result<Option<MessageView>, SdkError> {
        let Some(identity) = update.identity.as_ref() else {
            return Err(SdkError::InboundRejected("generated update identity missing".into()));
        };
        let id = ramflux_protocol::encode_base64url(&identity.id);
        let Some(message) = self.account_db()?.direct_message_by_id(&id)? else {
            return Ok(None);
        };
        let update = if message.deleted
            && !matches!(update.state, Some(g::message_update::State::Tombstone(_)))
        {
            self.generated_message_update(&message, conversation, update.journal_sequence)?
        } else {
            update
        };
        self.view_of(update, &message).map(Some)
    }

    fn view_of(
        &self,
        mut update: g::MessageUpdate,
        message: &ramflux_storage::DirectMessageRecord,
    ) -> Result<MessageView, SdkError> {
        g::private_revision::redact_update(&mut update);
        let identity = update
            .identity
            .ok_or_else(|| SdkError::InboundRejected("generated update identity missing".into()))?;
        let id = ramflux_protocol::encode_base64url(&identity.id);
        let mut view = MessageView {
            id: id.clone(),
            conversation_id: identity.conversation_id,
            author: identity.author.map(|author| AuthorView {
                account_anchor: author.account_anchor,
                device_id: author.device_id,
                device_epoch: author.device_epoch,
            }),
            device_sequence: identity.device_sequence,
            hlc: identity.hlc,
            group_id: identity.group_id,
            journal_sequence: update.journal_sequence,
            is_own: message.is_own,
            state: "tombstone",
            kind: "tombstone",
            text: None,
            content: None,
            unsupported: None,
            erasure: None,
            revision: 0,
            edited: false,
            reactions: Vec::new(),
            receipts: Vec::new(),
        };
        match update.state {
            Some(g::message_update::State::Tombstone(delete)) => {
                // Erased rows expose only the narrow tombstone; no revision, reaction or receipt.
                view.erasure = Some(erasure_view(&delete));
            }
            Some(g::message_update::State::Unsupported(unsupported)) => {
                view.state = "unsupported";
                view.kind = "unsupported";
                view.unsupported = Some(UnsupportedPlaceholder {
                    layer: unsupported.layer,
                    kind: unsupported.kind,
                    raw_length: unsupported.raw_length,
                    reason: unsupported.reason,
                });
            }
            Some(g::message_update::State::Content(content)) => {
                view.state = "content";
                view.kind = content.value.as_ref().map_or("unspecified", kind_name);
                if let Some(g::content::Value::Message(body)) = content.value.as_ref() {
                    view.text = Some(body.text.clone());
                }
                view.content = Some(content);
                view.revision = self
                    .account_db()?
                    .load_actor_state::<AppliedRevision>(&format!("routed/edit-revision/{id}"))?
                    .map_or(0, |applied| applied.revision);
                view.edited = view.revision > 0;
                let mut tokens = BTreeMap::<String, u32>::new();
                for reaction in self.generated_visible_reactions(&id)? {
                    let count = tokens.entry(reaction.token).or_default();
                    *count = count.saturating_add(1);
                }
                view.reactions =
                    tokens.into_iter().map(|(token, count)| ReactionView { token, count }).collect();
                view.receipts.clone_from(&message.receipts);
            }
            None => {
                return Err(SdkError::InboundRejected("generated update state missing".into()));
            }
        }
        Ok(view)
    }
}
