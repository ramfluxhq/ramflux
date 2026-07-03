// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirectMessageRecord {
    pub conversation_id: String,
    pub message_id: String,
    pub sender_id: String,
    pub encrypted_body: Vec<u8>,
    pub metadata: MessageMetadata,
    pub deleted: bool,
    pub created_at: i64,
    pub receipts: Vec<MessageReceiptState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectMessageWrite<'a> {
    pub conversation_id: &'a str,
    pub message_id: &'a str,
    pub sender_id: &'a str,
    pub encrypted_body: &'a [u8],
    pub metadata: &'a MessageMetadata,
    pub created_at: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MessageMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_report: Option<FrankingReportMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<ReplyToMetadata>,
    #[serde(default)]
    pub mentions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_from: Option<ForwardedFromMetadata>,
    #[serde(default)]
    pub forward_count: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FrankingReportMetadata {
    pub node_id: String,
    pub envelope_id: String,
    pub plaintext_base64: String,
    pub opening_key: String,
    pub commitment_key: String,
    pub sender_device_id_hash: String,
    pub msg_event_id: String,
    pub canonical_header_bytes: String,
    pub associated_data: String,
    pub ciphertext: String,
    pub header_hash: String,
    pub associated_data_hash: String,
    pub ciphertext_hash: String,
    pub franking_commitment: String,
    pub commitment: String,
    pub franking_tag: String,
    pub franking_timestamp: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplyToMetadata {
    pub message_id: String,
    pub quoted_cipher: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForwardedFromMetadata {
    pub source_message_id_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MessageReceiptState {
    pub device_id: String,
    pub state: String,
    pub delivered_at: Option<i64>,
    pub read_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptEventWrite<'a> {
    pub receipt_id: &'a str,
    pub conversation_id: &'a str,
    pub message_id: &'a str,
    pub receipt_type: &'a str,
    pub actor_device_id: &'a str,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageTombstoneRecord {
    pub tombstone_id: String,
    pub conversation_id: String,
    pub message_id: String,
    pub delete_scope: String,
}
