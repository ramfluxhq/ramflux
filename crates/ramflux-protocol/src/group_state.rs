// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-root snapshots, bounded signed requests and root-qualified group membership.
use serde::{Deserialize, Serialize};
pub const GROUP_STATE_SNAPSHOT_DOMAIN: &str = "ramflux.group_state.snapshot.v2";
pub const GROUP_CHANGE_REQUEST_DOMAIN: &str = "ramflux.group_state.request.v1";
pub const GROUP_CHANGE_RESULT_DOMAIN: &str = "ramflux.group_state.result.v1";
pub const GROUP_STATE_ACTOR_DOMAIN: &str = "ramflux.group_state.actor.v1";
pub const MAX_GROUP_CREATOR_TRANSFERS: usize = 32;
pub const MAX_GROUP_DEVICES: usize = 1024;
pub const MAX_GROUP_DEVICES_PER_ROOT: usize = 16;
pub const GROUP_REQUEST_TTL_SECONDS: i64 = 7 * 24 * 3600;
pub const MAX_GROUP_PENDING_REQUESTS: usize = 64;
pub const MAX_GROUP_REQUESTS_PER_ROOT: usize = 8;
// Reserve 64 KiB of the 1 MiB gateway frame; the sealed path expands state by at most 10x.
pub const MAX_GROUP_STATE_BYTES: usize = (1024 * 1024 - 64 * 1024) / 10;
pub const MAX_GROUP_STATE_MEMBERS: usize = 200;
pub const MAX_GROUP_STATE_EXCLUSIONS: usize = 2048;
pub const MAX_GROUP_NAME_BYTES: usize = 256;

/// A deterministic group capacity refusal, distinct from an authentication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GroupStateLimit {
    #[error("member limit exceeded")]
    Members,
    #[error("snapshot byte budget exceeded")]
    Bytes,
    #[error("device limit exceeded")]
    Devices,
    #[error("pending request limit exceeded")]
    Requests,
    #[error("ownership transfer limit exceeded")]
    Transfers,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedGroupRole {
    Owner,
    Admin,
    Member,
    Bot,
}
impl SharedGroupRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Bot => "bot",
        }
    }
}
impl std::str::FromStr for SharedGroupRole {
    type Err = crate::ProtocolError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            "bot" => Ok(Self::Bot),
            _ => Err(crate::ProtocolError::InvalidGroupState("invalid group role")),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMemberIdentity {
    pub principal_id: String,
    pub root_commitment: String,
    pub device_id: String,
    pub signing_public_key: String,
    pub target_delivery_id: String,
}
/// The root authenticates the exact branch key. No role is asserted by this certificate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateActor {
    pub identity: GroupMemberIdentity,
    pub root_public_key: String,
    pub root_signature: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupStateChange {
    Add { member: GroupMemberIdentity, role: SharedGroupRole },
    Remove { root_commitment: String, device_id: String },
    SetRole { root_commitment: String, device_id: String, role: SharedGroupRole },
    SetName { name: String },
    TransferOwnership { creator: GroupStateActor },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateGenesis {
    pub group_id: String,
    pub conversation_id: String,
    pub actor: GroupStateActor,
    pub max_members: u32,
    pub new_member_history: String,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupCreatorTransfer {
    pub group_id: String,
    pub genesis_hash: String,
    pub from_public_key: String,
    pub creator: GroupStateActor,
    pub epoch: u64,
    pub previous_hash: String,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateSnapshot {
    pub schema: String,
    pub group_id: String,
    pub epoch: u64,
    pub state_hash: String,
    pub previous_hash: Option<String>,
    pub genesis: GroupStateGenesis,
    pub creator: GroupStateActor,
    pub transfers: Vec<GroupCreatorTransfer>,
    pub state: SharedGroupState,
    pub issued_at: i64,
    pub root_signature: String,
    pub issuer: GroupStateActor,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupChangeRequest {
    pub schema: String,
    pub group_id: String,
    pub genesis_hash: String,
    pub base_epoch: u64,
    pub creator_root: String,
    pub request_id: String,
    pub actor: GroupStateActor,
    pub change: GroupStateChange,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupChangeStatus {
    Applied,
    AlreadyApplied,
    PermissionDenied,
    Capacity,
    Expired,
    Invalid,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupChangeResult {
    pub schema: String,
    pub group_id: String,
    pub request_id: String,
    pub request_hash: String,
    pub requester: GroupMemberIdentity,
    pub creator: GroupStateActor,
    pub status: GroupChangeStatus,
    pub epoch: u64,
    pub state_hash: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: String,
}
impl GroupStateSnapshot {
    /// # Errors
    /// Rejects oversized input, duplicate keys, invalid I-JSON or malformed typed fields.
    /// Creator and transport signature verification is mandatory after decoding.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, crate::ProtocolError> {
        if bytes.len() > MAX_GROUP_STATE_BYTES {
            return Err(crate::ProtocolError::GroupStateLimit(GroupStateLimit::Bytes));
        }
        crate::parse_i_json(bytes)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedGroupMember {
    pub identity: GroupMemberIdentity,
    pub role: SharedGroupRole,
    pub joined_epoch: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDeviceExclusion {
    pub root_commitment: String,
    pub device_id: String,
    pub removed_epoch: u64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedGroupState {
    pub group_id: String,
    pub conversation_id: String,
    pub epoch: u64,
    pub max_members: u32,
    pub new_member_history: String,
    pub name: Option<String>,
    pub name_epoch: u64,
    pub members: Vec<SharedGroupMember>,
    pub excluded: Vec<GroupDeviceExclusion>,
    pub head_hash: String,
}
impl SharedGroupState {
    /// A known root's sibling follows its membership unless that exact device was removed.
    #[must_use]
    pub fn effective_role(&self, root: &str, device: &str) -> Option<SharedGroupRole> {
        if self.excluded.iter().any(|e| e.root_commitment == root && e.device_id == device) {
            return None;
        }
        if let Some(member) = self
            .members
            .iter()
            .find(|m| m.identity.root_commitment == root && m.identity.device_id == device)
        {
            return Some(member.role);
        }
        self.members
            .iter()
            .filter(|m| m.identity.root_commitment == root)
            .map(|m| m.role)
            .min_by_key(|role| match role {
                SharedGroupRole::Owner => 0,
                SharedGroupRole::Admin => 1,
                SharedGroupRole::Member => 2,
                SharedGroupRole::Bot => 3,
            })
    }
}

/// Stable group projection id bound to authenticated sender identity, never arrival order.
/// # Errors
/// Returns canonical encoding errors.
pub fn group_message_id(
    group: &str,
    root: &str,
    device: &str,
    logical: &str,
) -> Result<String, crate::ProtocolError> {
    Ok(format!(
        "groupmsg:{}",
        crate::hash_base64url(
            "ramflux.group.message-id.v1",
            &crate::canonical_json_bytes(&(group, root, device, logical))?
        )
    ))
}
