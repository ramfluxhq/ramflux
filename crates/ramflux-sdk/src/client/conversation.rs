// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

/// Read-only, account-wide summary of a conversation for list views.
///
/// Fields mirror exactly what the storage schema persists: the conversation
/// id, derived message activity, and the archived/pinned list flags. The
/// schema has no peer/display-name column and no reader-scoped unread count
/// without a reader id, so neither is exposed here.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ConversationSummary {
    pub conversation_id: String,
    pub message_count: u64,
    pub last_message_id: Option<String>,
    pub last_activity_at: Option<i64>,
    pub is_archived: bool,
    pub pin_order: Option<i64>,
}

impl From<ConversationSummaryRecord> for ConversationSummary {
    fn from(record: ConversationSummaryRecord) -> Self {
        Self {
            conversation_id: record.conversation_id,
            message_count: record.message_count,
            last_message_id: record.last_message_id,
            last_activity_at: record.last_activity_at,
            is_archived: record.is_archived,
            pin_order: record.pin_order,
        }
    }
}

impl RamfluxClient {
    /// Lists every conversation for the unlocked account, newest activity first.
    ///
    /// # Errors
    /// Returns an error when no account DB is unlocked or the query fails.
    pub fn conversation_list(&self) -> Result<Vec<ConversationSummary>, SdkError> {
        Ok(self
            .account_db()?
            .conversation_summaries()?
            .into_iter()
            .map(ConversationSummary::from)
            .collect())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn set_disappearing_policy(
        &self,
        conversation_id: &str,
        timer_seconds: i64,
        countdown_mode: &str,
        scope: &str,
        updated_at: i64,
    ) -> Result<DisappearingPolicyRecord, SdkError> {
        Ok(self.account_db()?.set_disappearing_policy(
            conversation_id,
            timer_seconds,
            countdown_mode,
            scope,
            updated_at,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn expire_disappearing_messages(
        &self,
        conversation_id: &str,
        now: i64,
    ) -> Result<Vec<MessageTombstoneRecord>, SdkError> {
        Ok(self.account_db()?.expire_disappearing_messages(conversation_id, now)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn typing_started(
        &self,
        conversation_id: &str,
        actor_identity: &str,
        started_at: i64,
        ttl_seconds: i64,
        privacy_scope: &str,
    ) -> Result<(), SdkError> {
        self.account_db()?.typing_started(
            conversation_id,
            actor_identity,
            started_at,
            ttl_seconds,
            privacy_scope,
        );
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn typing_stopped(
        &self,
        conversation_id: &str,
        actor_identity: &str,
    ) -> Result<(), SdkError> {
        self.account_db()?.typing_stopped(conversation_id, actor_identity);
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn active_typing(
        &self,
        conversation_id: &str,
        now: i64,
    ) -> Result<Vec<TypingStateRecord>, SdkError> {
        Ok(self.account_db()?.active_typing(conversation_id, now))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn update_contact_presence(
        &self,
        update: ContactPresenceUpdate<'_>,
    ) -> Result<(), SdkError> {
        self.account_db()?.update_contact_presence(update);
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn contact_presence(
        &self,
        identity_commitment: &str,
        now: i64,
    ) -> Result<Option<ContactPresenceRecord>, SdkError> {
        Ok(self.account_db()?.contact_presence(identity_commitment, now))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn apply_identity_lifecycle_event(
        &self,
        identity_commitment: &str,
        event_id: &str,
        event_type: &str,
        lifecycle_epoch: u64,
        timing: IdentityLifecycleTiming<'_>,
    ) -> Result<IdentityLifecycleRecord, SdkError> {
        Ok(self.account_db()?.apply_identity_lifecycle_event(
            identity_commitment,
            event_id,
            event_type,
            lifecycle_epoch,
            timing,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn identity_lifecycle(
        &self,
        identity_commitment: &str,
    ) -> Result<Option<IdentityLifecycleRecord>, SdkError> {
        Ok(self.account_db()?.identity_lifecycle(identity_commitment)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn message_mentions(
        &self,
        conversation_id: &str,
        message_id: &str,
        identity_commitment: &str,
    ) -> Result<bool, SdkError> {
        Ok(self.account_db()?.message_mentions(conversation_id, message_id, identity_commitment)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn direct_messages(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<DirectMessageRecord>, SdkError> {
        Ok(self.account_db()?.direct_messages(conversation_id)?)
    }

    /// # Errors
    /// Returns an error when storage lookup fails.
    pub fn direct_message_by_id(
        &self,
        message_id: &str,
    ) -> Result<Option<DirectMessageRecord>, SdkError> {
        Ok(self.account_db()?.direct_message_by_id(message_id)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn set_conversation_archived(
        &self,
        conversation_id: &str,
        archived: bool,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.set_conversation_archived(conversation_id, archived)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn pin_conversation(&self, conversation_id: &str, pin_order: i64) -> Result<(), SdkError> {
        Ok(self.account_db()?.pin_conversation(conversation_id, pin_order)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the conversation cannot be unpinned.
    pub fn unpin_conversation(&self, conversation_id: &str) -> Result<(), SdkError> {
        Ok(self.account_db()?.unpin_conversation(conversation_id)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mute_conversation(
        &self,
        conversation_id: &str,
        mute_until: i64,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.mute_conversation(conversation_id, mute_until)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn unmute_conversation(&self, conversation_id: &str) -> Result<(), SdkError> {
        Ok(self.account_db()?.unmute_conversation(conversation_id)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the conversation cannot be hidden.
    pub fn hide_conversation_at(
        &self,
        conversation_id: &str,
        hidden_at: i64,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.hide_conversation_at(conversation_id, hidden_at)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn clear_conversation_at(
        &self,
        conversation_id: &str,
        cleared_at: i64,
        scope: &str,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.clear_conversation_at(conversation_id, cleared_at, scope)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn conversation_list_state(
        &self,
        conversation_id: &str,
    ) -> Result<ConversationListState, SdkError> {
        Ok(self.account_db()?.conversation_list_state(conversation_id)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn delete_direct_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        delete_scope: &str,
        tombstone_id: &str,
    ) -> Result<MessageTombstoneRecord, SdkError> {
        Ok(self.account_db()?.delete_direct_message(
            conversation_id,
            message_id,
            delete_scope,
            tombstone_id,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mark_read(
        &self,
        conversation_id: &str,
        reader_id: &str,
        message_id: &str,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.mark_read(conversation_id, reader_id, message_id)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mark_delivered(
        &self,
        conversation_id: &str,
        receiver_device_id: &str,
        message_id: &str,
        delivered_at: i64,
        ttl_seconds: i64,
    ) -> Result<DeliveryReceiptRecord, SdkError> {
        Ok(self.account_db()?.mark_delivered(
            conversation_id,
            receiver_device_id,
            message_id,
            delivered_at,
            ttl_seconds,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn set_unread_marker(
        &self,
        conversation_id: &str,
        marker_owner: &str,
        message_id: &str,
        marker_epoch: u64,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.set_unread_marker(
            conversation_id,
            marker_owner,
            message_id,
            marker_epoch,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn clear_unread_marker(
        &self,
        conversation_id: &str,
        marker_owner: &str,
        marker_epoch: u64,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.clear_unread_marker(conversation_id, marker_owner, marker_epoch)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn conversation_projection(
        &self,
        conversation_id: &str,
        reader_id: &str,
    ) -> Result<ConversationProjection, SdkError> {
        Ok(self.account_db()?.conversation_projection(conversation_id, reader_id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("ramflux-sdk-conversation-list-{test_name}-{nanos}"))
    }

    fn client_with_account(test_name: &str) -> Result<(RamfluxClient, PathBuf), SdkError> {
        let root = temp_root(test_name);
        let mut client = RamfluxClient::new();
        client.create_identity_root("principal_conv", [0x71; 32]);
        client.create_device_branch("principal_conv", "device_conv", 1, [0x72; 32]);
        client.open_account_index(&root)?;
        client.create_account("acct", "principal_conv")?;
        client.unlock_account("acct", b"conversation-list-test")?;
        Ok((client, root))
    }

    #[test]
    fn conversation_list_returns_inserted_conversations() -> Result<(), SdkError> {
        let (client, root) = client_with_account("returns-inserted")?;
        let metadata = MessageMetadata::default();
        client.account_db()?.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "conv_one",
            message_id: "msg_one_a",
            sender_id: "alice",
            encrypted_body: b"first",
            metadata: &metadata,
            created_at: 1_900_000_000,
        })?;
        client.account_db()?.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "conv_one",
            message_id: "msg_one_b",
            sender_id: "alice",
            encrypted_body: b"second",
            metadata: &metadata,
            created_at: 1_900_000_100,
        })?;
        client.account_db()?.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "conv_two",
            message_id: "msg_two_a",
            sender_id: "bob",
            encrypted_body: b"hi",
            metadata: &metadata,
            created_at: 1_900_000_050,
        })?;

        let summaries = client.conversation_list()?;
        assert!(summaries.iter().any(|summary| summary.conversation_id == "conv_one"
            && summary.message_count == 2
            && summary.last_message_id.as_deref() == Some("msg_one_b")
            && summary.last_activity_at == Some(1_900_000_100)));
        assert!(
            summaries
                .iter()
                .any(|summary| summary.conversation_id == "conv_two" && summary.message_count == 1)
        );
        // Newest activity sorts first.
        assert_eq!(
            summaries.first().map(|summary| summary.conversation_id.as_str()),
            Some("conv_one")
        );
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
