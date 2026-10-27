// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize, Serializer};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct DirectMessageRecord {
    pub conversation_id: String,
    pub message_id: String,
    #[serde(default)]
    pub sender_id: String,
    #[serde(default)]
    pub encrypted_body: Vec<u8>,
    #[serde(default)]
    pub metadata: MessageMetadata,
    pub deleted: bool,
    #[serde(default)]
    pub is_own: bool,
    pub created_at: i64,
    #[serde(default)]
    pub receipts: Vec<MessageReceiptState>,
}

#[derive(Serialize)]
struct MessageTombstoneWire<'a> {
    conversation_id: &'a str,
    message_id: &'a str,
    deleted: bool,
    is_own: bool,
    created_at: i64,
}

#[derive(Serialize)]
struct LiveMessageWire<'a> {
    conversation_id: &'a str,
    message_id: &'a str,
    sender_id: &'a str,
    encrypted_body: &'a [u8],
    metadata: &'a MessageMetadata,
    deleted: bool,
    created_at: i64,
    receipts: &'a [MessageReceiptState],
}

impl Serialize for DirectMessageRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.deleted {
            return MessageTombstoneWire {
                conversation_id: &self.conversation_id,
                message_id: &self.message_id,
                deleted: true,
                is_own: self.is_own,
                created_at: self.created_at,
            }
            .serialize(serializer);
        }
        LiveMessageWire {
            conversation_id: &self.conversation_id,
            message_id: &self.message_id,
            sender_id: &self.sender_id,
            encrypted_body: &self.encrypted_body,
            metadata: &self.metadata,
            deleted: false,
            created_at: self.created_at,
            receipts: &self.receipts,
        }
        .serialize(serializer)
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_commitment: Option<String>,
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
    pub actor: &'a ramflux_crypto::RootQualifiedDeviceRef,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageTombstoneRecord {
    pub tombstone_id: String,
    pub conversation_id: String,
    pub message_id: String,
    pub delete_scope: String,
}
