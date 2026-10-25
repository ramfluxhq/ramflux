// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded signed group state, complete bootstrap history and account-root membership.
use serde::{Deserialize, Serialize};
pub const GROUP_STATE_OPERATION_DOMAIN: &str = "ramflux.group_state.operation.v1";
pub const GROUP_STATE_SNAPSHOT_DOMAIN: &str = "ramflux.group_state.snapshot.v1";
pub const GROUP_STATE_CHECKPOINT_DOMAIN: &str = "ramflux.group_state.checkpoint.v1";
pub const GROUP_STATE_ACTOR_DOMAIN: &str = "ramflux.group_state.actor.v1";
pub const MAX_GROUP_STATE_STEPS: usize = 512;
pub const MAX_GROUP_STATE_BYTES: usize = 524_288;
pub const MAX_GROUP_STATE_MEMBERS: usize = 1000;
pub const MAX_GROUP_STATE_EXCLUSIONS: usize = 2048;
pub const MAX_GROUP_NAME_BYTES: usize = 256;

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
    Create {
        conversation_id: String,
        max_members: u32,
        new_member_history: String,
        name: Option<String>,
    },
    Add {
        member: GroupMemberIdentity,
        role: SharedGroupRole,
    },
    Remove {
        root_commitment: String,
        device_id: String,
    },
    SetRole {
        root_commitment: String,
        device_id: String,
        role: SharedGroupRole,
    },
    SetName {
        name: String,
    },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateOperation {
    pub schema: String,
    pub group_id: String,
    pub epoch: u64,
    pub previous_hash: Option<String>,
    pub actor: GroupStateActor,
    pub change: GroupStateChange,
    pub root_signature: String,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateSnapshot {
    pub schema: String,
    pub group_id: String,
    pub epoch: u64,
    pub state_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<GroupStateCheckpoint>,
    pub operations: Vec<GroupStateOperation>,
    pub issuer: GroupStateActor,
    pub signature: String,
}
impl GroupStateSnapshot {
    /// # Errors
    /// Rejects oversized input, duplicate keys, invalid I-JSON or malformed typed fields.
    /// Cryptographic history verification is mandatory after decoding.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, crate::ProtocolError> {
        if bytes.len() > MAX_GROUP_STATE_BYTES {
            return Err(crate::ProtocolError::InvalidGroupState("snapshot byte budget exceeded"));
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

/// The immutable creator root can compact verified history without granting that power to an admin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateCheckpoint {
    pub schema: String,
    pub genesis: GroupStateOperation,
    pub state: SharedGroupState,
    pub owner: GroupStateActor,
    pub signature: String,
}
