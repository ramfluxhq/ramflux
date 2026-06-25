use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirectMessageRecord {
    pub conversation_id: String,
    pub message_id: String,
    pub sender_id: String,
    pub encrypted_body: Vec<u8>,
    pub metadata: MessageMetadata,
    pub deleted: bool,
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
    pub reply_to: Option<ReplyToMetadata>,
    pub mentions: Vec<String>,
    pub forwarded_from: Option<ForwardedFromMetadata>,
    pub forward_count: u8,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageTombstoneRecord {
    pub tombstone_id: String,
    pub conversation_id: String,
    pub message_id: String,
    pub delete_scope: String,
}
