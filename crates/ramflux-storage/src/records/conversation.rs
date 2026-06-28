// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationProjection {
    pub conversation_id: String,
    pub message_count: u64,
    pub last_message_id: Option<String>,
    pub read_through_message_id: Option<String>,
    pub delivered_through_message_id: Option<String>,
    pub manual_unread_message_id: Option<String>,
    pub is_unread: bool,
    pub is_archived: bool,
    pub pin_order: Option<i64>,
    pub mute_until: Option<i64>,
    pub is_hidden: bool,
    pub cleared_at: Option<i64>,
}

/// Read-only summary of a single conversation for the account-wide list view.
///
/// Only carries metadata the schema actually persists: the conversation id,
/// derived message activity from `direct_message_projection`, and list flags
/// from `conversation_list_state`. There is no peer/display-name column in the
/// schema and no reader-scoped unread count without a reader id, so neither is
/// included here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationSummaryRecord {
    pub conversation_id: String,
    pub message_count: u64,
    pub last_message_id: Option<String>,
    pub last_activity_at: Option<i64>,
    pub is_archived: bool,
    pub pin_order: Option<i64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConversationListState {
    pub conversation_id: String,
    pub archived: bool,
    pub pin_order: Option<i64>,
    pub mute_until: Option<i64>,
    pub hidden_at: Option<i64>,
    pub cleared_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryReceiptRecord {
    pub conversation_id: String,
    pub receiver_device_id: String,
    pub delivered_through_message_id: String,
    pub delivered_at: i64,
    pub ttl_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisappearingPolicyRecord {
    pub conversation_id: String,
    pub timer_seconds: i64,
    pub countdown_mode: String,
    pub scope: String,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypingStateRecord {
    pub conversation_id: String,
    pub actor_identity: String,
    pub started_at: i64,
    pub expires_at: i64,
    pub privacy_scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactPresenceRecord {
    pub identity_commitment: String,
    pub presence_state: String,
    pub last_seen_at: Option<i64>,
    pub expires_at: i64,
    pub privacy_scope: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactPresenceUpdate<'a> {
    pub identity_commitment: &'a str,
    pub presence_state: &'a str,
    pub last_seen_at: Option<i64>,
    pub observed_at: i64,
    pub ttl_seconds: i64,
    pub privacy_scope: &'a str,
}
