// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
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
