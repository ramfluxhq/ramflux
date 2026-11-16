// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creator-root snapshots, bounded signed requests and root-qualified group membership.
use serde::{Deserialize, Serialize};
pub const GROUP_STATE_CONTENT_HASH_DOMAIN: &str = "ramflux.group_state.content.v2";
pub const GROUP_STATE_CREATOR_SIGNATURE_DOMAIN: &str = "ramflux.group_state.creator_signature.v2";
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
/// Physical half of a message hybrid clock. Stays below the I-JSON safe-integer ceiling.
pub const MAX_SERVICE_HLC_MS: u64 = (1 << 48) - 1;

/// Message-timeline order of one signed group snapshot.
///
/// `device_sequence`, `hlc_ms` and `hlc_logical` are the same keys a conversation message
/// uses. Every member reconstructs one event id from them and the signing device.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupServiceOrder {
    pub device_sequence: u64,
    pub hlc_ms: u64,
    pub hlc_logical: u64,
    pub device_epoch: u64,
}

impl GroupServiceOrder {
    /// Clock-derived order for a snapshot that does not enter the message timeline.
    ///
    /// # Errors
    /// Rejects a clock that cannot be represented as a safe JSON integer.
    pub fn from_clock(epoch: u64, issued_at: i64) -> Result<Self, crate::ProtocolError> {
        let issued = u64::try_from(issued_at)
            .map_err(|_| crate::ProtocolError::InvalidGroupState("group service order"))?;
        let order = Self {
            device_sequence: (1_u64 << 52)
                .checked_add(epoch)
                .ok_or(crate::ProtocolError::InvalidGroupState("group service order"))?,
            hlc_ms: issued
                .checked_mul(1000)
                .filter(|ms| *ms > 0)
                .ok_or(crate::ProtocolError::InvalidGroupState("group service order"))?,
            hlc_logical: 0,
            device_epoch: 1,
        };
        order.check()?;
        Ok(order)
    }

    /// Split a message hybrid clock into the signed timeline fields.
    ///
    /// # Errors
    /// Rejects a zero or out-of-range sequence, epoch or clock.
    pub fn from_allocated(
        device_epoch: u64,
        device_sequence: u64,
        hlc: u64,
    ) -> Result<Self, crate::ProtocolError> {
        let order =
            Self { device_sequence, hlc_ms: hlc >> 16, hlc_logical: hlc & 0xffff, device_epoch };
        order.check()?;
        if order.hlc()? != hlc {
            return Err(crate::ProtocolError::InvalidGroupState("group service order"));
        }
        Ok(order)
    }

    /// # Errors
    /// Rejects a zero sequence, epoch or physical clock, a logical counter above 16 bits,
    /// or any integer I-JSON cannot carry.
    pub fn check(&self) -> Result<(), crate::ProtocolError> {
        if self.device_sequence == 0
            || self.device_sequence > crate::MAX_SAFE_JSON_INTEGER
            || self.hlc_ms == 0
            || self.hlc_ms > MAX_SERVICE_HLC_MS
            || self.hlc_logical > u64::from(u16::MAX)
            || self.device_epoch == 0
            || self.device_epoch > crate::MAX_SAFE_JSON_INTEGER
        {
            return Err(crate::ProtocolError::InvalidGroupState("group service order"));
        }
        Ok(())
    }

    /// # Errors
    /// Rejects an order that fails [`Self::check`] or whose physical half does not fit in `u64`.
    pub fn hlc(&self) -> Result<u64, crate::ProtocolError> {
        self.check()?;
        self.hlc_ms
            .checked_shl(16)
            .map(|shifted| shifted | self.hlc_logical)
            .ok_or(crate::ProtocolError::InvalidGroupState("group service order"))
    }
}

/// The accepted change that produced one timeline row.
///
/// This is the creator-certified action, not a diff of two rosters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupServiceChange {
    SetName { name: String },
    Add { root_commitment: String, device_id: String },
    Remove { root_commitment: String, device_id: String },
}

/// One accepted timeline change, frozen when the creator certifies that epoch.
///
/// `author_root` and `author_device` are the device that allocated `device_sequence`.
/// Transport forwarding replaces the snapshot issuer and leaves this record unchanged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupServiceEvent {
    pub group_epoch: u64,
    pub device_sequence: u64,
    pub hlc_ms: u64,
    pub hlc_logical: u64,
    pub device_epoch: u64,
    pub author_root: String,
    pub author_device: String,
    pub change: GroupServiceChange,
}

impl GroupServiceEvent {
    /// # Errors
    /// Rejects an order, author, or change that cannot identify a timeline row.
    pub fn check(&self) -> Result<(), crate::ProtocolError> {
        GroupServiceOrder {
            device_sequence: self.device_sequence,
            hlc_ms: self.hlc_ms,
            hlc_logical: self.hlc_logical,
            device_epoch: self.device_epoch,
        }
        .check()?;
        if self.group_epoch == 0 || self.group_epoch > crate::MAX_SAFE_JSON_INTEGER {
            return Err(crate::ProtocolError::InvalidGroupState("group service event"));
        }
        canonical_root(&self.author_root)?;
        crate::validate_device_name(&self.author_device)?;
        match &self.change {
            GroupServiceChange::SetName { name } => {
                if name.trim().is_empty()
                    || name.len() > MAX_GROUP_NAME_BYTES
                    || !crate::text_safety::single_line_is_safe(name)
                {
                    return Err(crate::ProtocolError::InvalidGroupState("group service event"));
                }
            }
            GroupServiceChange::Add { root_commitment, device_id }
            | GroupServiceChange::Remove { root_commitment, device_id } => {
                canonical_root(root_commitment)?;
                crate::validate_device_name(device_id)?;
            }
        }
        Ok(())
    }

    /// Hybrid clock packed the same way as a conversation message.
    ///
    /// # Errors
    /// Rejects an order that fails [`GroupServiceOrder::check`].
    pub fn hlc(&self) -> Result<u64, crate::ProtocolError> {
        GroupServiceOrder {
            device_sequence: self.device_sequence,
            hlc_ms: self.hlc_ms,
            hlc_logical: self.hlc_logical,
            device_epoch: self.device_epoch,
        }
        .hlc()
    }
}

fn canonical_root(value: &str) -> Result<(), crate::ProtocolError> {
    let bytes = crate::decode_base64url(value)
        .map_err(|_| crate::ProtocolError::InvalidGroupState("group service event"))?;
    if bytes.len() != 32 || crate::encode_base64url(&bytes) != value {
        return Err(crate::ProtocolError::InvalidGroupState("group service event"));
    }
    Ok(())
}

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
    #[error("removal fence limit exceeded")]
    RemovalFences,
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
/// Born-v3 authority for a group actor. The master certificate authenticates the current
/// self-signing key, while the branch certificate grants the exact device the `group` capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupNativeAuthority {
    pub master_certificate: crate::custody::Envelope<crate::custody::MasterCertificate>,
    pub branch_certificate: crate::custody::Envelope<crate::custody::BranchCertificate>,
}
/// The root authenticates the exact branch key. No role is asserted by this certificate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateActor {
    pub identity: GroupMemberIdentity,
    pub root_public_key: String,
    pub root_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_authority: Option<Box<GroupNativeAuthority>>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupStateChange {
    Add { member: GroupMemberIdentity, role: SharedGroupRole },
    Remove { root_commitment: String, device_id: String },
    SetRole { root_commitment: String, device_id: String, role: SharedGroupRole },
    SetName { name: String },
    TransferOwnership { creator: GroupStateActor, acceptance: Box<GroupTransferAcceptance> },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupStateGenesis {
    pub group_id: String,
    pub conversation_id: String,
    pub actor: GroupStateActor,
    /// Signed native creation time. Legacy genesis encoding omits this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    pub max_members: u32,
    pub new_member_history: String,
    pub signature: String,
}
/// A fresh transferee branch countersignature binds the exact creator head being handed over.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupTransferAcceptance {
    pub group_id: String,
    pub genesis_hash: String,
    pub base_epoch: u64,
    pub base_hash: String,
    pub from_public_key: String,
    pub creator: GroupStateActor,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupCreatorTransfer {
    pub acceptance: GroupTransferAcceptance,
    pub issued_at: i64,
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
    pub service_order: GroupServiceOrder,
    /// Accepted timeline changes in epoch order. A later snapshot carries every earlier event.
    pub service_events: Vec<GroupServiceEvent>,
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

#[cfg(test)]
mod service_order_tests {
    use super::{
        GroupServiceChange, GroupServiceEvent, GroupServiceOrder, GroupStateSnapshot,
        MAX_SERVICE_HLC_MS,
    };

    fn order(sequence: u64, hlc_ms: u64, hlc_logical: u64, device_epoch: u64) -> GroupServiceOrder {
        GroupServiceOrder { device_sequence: sequence, hlc_ms, hlc_logical, device_epoch }
    }

    #[test]
    fn minimum_service_order_is_representable() {
        assert!(order(1, 1, 0, 1).check().is_ok(), "test: a minimum order is representable");
    }

    #[test]
    fn zero_device_sequence_is_rejected() {
        assert!(order(0, 1, 0, 1).check().is_err(), "test: a zero sequence is rejected");
    }

    #[test]
    fn device_sequence_above_the_json_safe_integer_is_rejected() {
        assert!(
            order(crate::MAX_SAFE_JSON_INTEGER + 1, 1, 0, 1).check().is_err(),
            "test: a sequence above the I-JSON safe integer is rejected"
        );
    }

    #[test]
    fn zero_hlc_ms_is_rejected() {
        assert!(order(1, 0, 0, 1).check().is_err(), "test: a zero physical clock is rejected");
    }

    #[test]
    fn hlc_ms_above_the_clock_band_is_rejected() {
        assert!(
            order(1, MAX_SERVICE_HLC_MS + 1, 0, 1).check().is_err(),
            "test: a physical clock above 48 bits is rejected"
        );
    }

    #[test]
    fn hlc_logical_above_16_bits_is_rejected() {
        assert!(
            order(1, 1, u64::from(u16::MAX) + 1, 1).check().is_err(),
            "test: a logical counter above 16 bits is rejected"
        );
    }

    #[test]
    fn zero_device_epoch_is_rejected() {
        assert!(order(1, 1, 0, 0).check().is_err(), "test: a zero device epoch is rejected");
    }

    #[test]
    fn device_epoch_above_the_json_safe_integer_is_rejected() {
        assert!(
            order(1, 1, 0, crate::MAX_SAFE_JSON_INTEGER + 1).check().is_err(),
            "test: a device epoch above the I-JSON safe integer is rejected"
        );
    }

    #[test]
    fn from_clock_rejects_a_zero_or_negative_or_overflowing_clock() {
        assert!(GroupServiceOrder::from_clock(1, 0).is_err(), "test: a zero clock is rejected");
        assert!(
            GroupServiceOrder::from_clock(1, -1).is_err(),
            "test: a negative clock is rejected"
        );
        assert!(
            GroupServiceOrder::from_clock(1, i64::MAX).is_err(),
            "test: a clock that overflows milliseconds is rejected"
        );
        assert!(
            GroupServiceOrder::from_clock(u64::MAX, 1).is_err(),
            "test: a sequence that overflows the clock band is rejected"
        );
    }

    #[test]
    fn from_allocated_rejects_a_zero_epoch_and_rebuilds_an_in_range_clock() {
        assert!(
            GroupServiceOrder::from_allocated(0, 1, 1 << 16).is_err(),
            "test: a zero device epoch is rejected"
        );
        let allocated = GroupServiceOrder::from_allocated(2, 7, (9 << 16) | 4)
            .expect("test: an in-range allocation splits");
        assert_eq!(allocated.hlc().expect("test: the split clock rebuilds"), (9 << 16) | 4);
    }

    #[test]
    fn snapshot_without_service_order_is_rejected() -> Result<(), crate::ProtocolError> {
        let snapshot = sample_snapshot()?;
        let encoded = crate::canonical_json_bytes(&snapshot)?;
        GroupStateSnapshot::from_wire_bytes(&encoded).expect("test: a complete snapshot decodes");
        let mut value = serde_json::to_value(&snapshot).expect("test: snapshot serializes");
        let object = value.as_object_mut().expect("test: snapshot is an object");
        assert!(object.remove("service_order").is_some(), "test: the sample carries service_order");
        let stripped = crate::canonical_json_bytes(&value)?;
        assert!(
            GroupStateSnapshot::from_wire_bytes(&stripped).is_err(),
            "test: a snapshot without service_order is rejected"
        );
        let mut value = serde_json::to_value(&snapshot).expect("test: snapshot serializes");
        let object = value.as_object_mut().expect("test: snapshot is an object");
        assert!(
            object.remove("service_events").is_some(),
            "test: the sample carries service_events"
        );
        let stripped = crate::canonical_json_bytes(&value)?;
        assert!(
            GroupStateSnapshot::from_wire_bytes(&stripped).is_err(),
            "test: a snapshot without service_events is rejected"
        );
        Ok(())
    }

    #[test]
    fn service_event_rejects_an_author_that_is_not_a_root() {
        let event = GroupServiceEvent {
            group_epoch: 1,
            device_sequence: 1,
            hlc_ms: 1,
            hlc_logical: 0,
            device_epoch: 1,
            author_root: "root".to_owned(),
            author_device: "phone".to_owned(),
            change: GroupServiceChange::SetName { name: "Checklist".to_owned() },
        };
        assert!(event.check().is_err(), "test: a service author must be a canonical root");
    }

    fn sample_snapshot() -> Result<GroupStateSnapshot, crate::ProtocolError> {
        let identity = super::GroupMemberIdentity {
            principal_id: "principal".to_owned(),
            root_commitment: "root".to_owned(),
            device_id: "device".to_owned(),
            signing_public_key: "key".to_owned(),
            target_delivery_id: "delivery".to_owned(),
        };
        let actor = super::GroupStateActor {
            identity: identity.clone(),
            root_public_key: "root-key".to_owned(),
            root_signature: "root-sig".to_owned(),
            native_authority: None,
        };
        Ok(GroupStateSnapshot {
            schema: "ramflux.group_state.snapshot.v2".to_owned(),
            group_id: "group".to_owned(),
            epoch: 1,
            state_hash: "hash".to_owned(),
            previous_hash: Some("previous".to_owned()),
            genesis: super::GroupStateGenesis {
                group_id: "group".to_owned(),
                conversation_id: "thread".to_owned(),
                actor: actor.clone(),
                issued_at: Some(1),
                max_members: 2,
                new_member_history: "no_history".to_owned(),
                signature: "genesis-sig".to_owned(),
            },
            creator: actor.clone(),
            transfers: Vec::new(),
            state: super::SharedGroupState {
                group_id: "group".to_owned(),
                conversation_id: "thread".to_owned(),
                epoch: 1,
                max_members: 2,
                new_member_history: "no_history".to_owned(),
                name: Some("Checklist".to_owned()),
                name_epoch: 1,
                members: vec![super::SharedGroupMember {
                    identity,
                    role: super::SharedGroupRole::Owner,
                    joined_epoch: 1,
                }],
                excluded: Vec::new(),
                head_hash: "head".to_owned(),
            },
            issued_at: 1,
            service_order: GroupServiceOrder::from_clock(1, 1)?,
            service_events: Vec::new(),
            root_signature: "root-body-sig".to_owned(),
            issuer: actor,
            signature: "snapshot-sig".to_owned(),
        })
    }
}
