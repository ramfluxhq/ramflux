use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FriendLinkRecord {
    pub link_id: String,
    pub requester_id: String,
    pub target_id: String,
    pub state: String,
    #[serde(default)]
    pub remove_scope: Option<String>,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub capability_revoked_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RejectedInboxRecord {
    pub conversation_id: String,
    pub message_id: String,
    pub sender_id: String,
    pub reason: String,
    pub rejected_at: i64,
}
