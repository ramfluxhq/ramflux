use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::HostingModel;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryQuorumMemberKind {
    RootShare,
    DeviceShare,
    GuardianShare,
    HardwareTokenShare,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryQuorumMemberCommitment {
    pub member_kind: RecoveryQuorumMemberKind,
    pub signing_key_id: String,
    pub public_key_base64url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryQuorumConfigured {
    pub recovery_quorum_id: String,
    pub threshold: u8,
    pub total: u8,
    pub members: Vec<RecoveryQuorumMemberCommitment>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApprovalContext {
    pub recovery_id: String,
    pub event_type: String,
    pub principal_id: String,
    pub lifecycle_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timelock_until: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApproval {
    pub member_kind: RecoveryQuorumMemberKind,
    pub signing_key_id: String,
    pub signature_alg: crate::SignatureAlg,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryQuorumProof {
    pub context: RecoveryApprovalContext,
    pub approvals: Vec<RecoveryApproval>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum IdentityEventBody {
    RecoveryQuorumConfigured {
        recovery_quorum: RecoveryQuorumConfigured,
    },
    DeviceBranchAuthorized {
        device_id: String,
        device_epoch: u64,
        branch_proof_hash: String,
        capability_scope: Vec<String>,
    },
    DeviceBranchRevoked {
        device_id: String,
        revoked_at: i64,
        reason: String,
        causal_event_id: String,
    },
    RootRotationProposed {
        old_root_hash: String,
        new_root_hash: String,
        timelock_until: i64,
    },
    RootRotationFinalized {
        proposal_id: String,
        finalized_at: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_quorum_proof: Option<RecoveryQuorumProof>,
    },
    RecoveryAuthorized {
        recovery_id: String,
        new_device_id: String,
        recovery_method: String,
        recovery_quorum_proof: RecoveryQuorumProof,
    },
    IdentityDeactivated {
        identity_commitment: String,
        lifecycle_epoch: u64,
        reason_code: String,
        timelock_until: i64,
        recovery_quorum_proof_hash: String,
    },
    IdentityReactivated {
        identity_commitment: String,
        lifecycle_epoch: u64,
        previous_deactivation_event_id: String,
        recovery_quorum_proof_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_quorum_proof: Option<RecoveryQuorumProof>,
    },
    IdentityDeleted {
        identity_commitment: String,
        lifecycle_epoch: u64,
        grace_window_until: i64,
        finalization_time: i64,
        identity_lifecycle_tombstone: Value,
    },
    HomeNodeMigrationProof {
        old_home_node: String,
        new_home_node: String,
        migration_proof_hash: String,
    },
    IdentityHomeNodeMigrated {
        old_home_node: String,
        new_home_node: String,
        migration_proof_hash: String,
        lineage_head: String,
        effective_at: i64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum FriendLinkEventBody {
    Requested {
        link_id: String,
        requester_id: String,
        target_id: String,
        request_capability_hash: String,
    },
    Accepted {
        link_id: String,
        accepted_by: String,
        delivery_capability_hash: String,
    },
    Removed {
        link_id: String,
        actor_identity: String,
        remove_scope: String,
    },
    CapabilityRevoked {
        link_id: String,
        revoked_capability_id: String,
        reason: String,
        effective_at: i64,
        causal_event_id: String,
    },
    Blocked {
        blocked_identity: String,
        scope: String,
    },
    Unblocked {
        unblocked_identity: String,
        scope: String,
    },
    HomeNodeMigrated {
        link_id: String,
        identity: String,
        old_home_node: String,
        new_home_node: String,
        migration_proof: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum GroupEventBody {
    Created {
        group_id: String,
        group_epoch: u64,
        initial_policy: Value,
        creator_role: String,
    },
    MemberInvited {
        group_id: String,
        group_epoch: u64,
        invitee_id: String,
        invited_by: String,
    },
    MemberJoined {
        group_id: String,
        previous_epoch: u64,
        new_group_epoch: u64,
        joined_identity: String,
    },
    MemberRemoved {
        group_id: String,
        previous_epoch: u64,
        new_group_epoch: u64,
        removed_identity: String,
        reason: String,
    },
    MemberHomeNodeMigrated {
        group_id: String,
        member_identity: String,
        old_home_node: String,
        new_home_node: String,
        migration_proof_hash: String,
    },
    RoleChanged {
        group_id: String,
        previous_epoch: u64,
        new_group_epoch: u64,
        target_identity: String,
        new_role: String,
    },
    PolicyUpdated {
        group_id: String,
        group_epoch: u64,
        policy_patch: Value,
    },
    MuteUpdated {
        group_id: String,
        group_epoch: u64,
        target_identity: String,
        mute_state: String,
    },
    NotificationUpdated {
        group_id: String,
        notification_scope: String,
        notification_state: String,
    },
    BotInvited {
        group_id: String,
        bot_identity: String,
        requested_permissions: Vec<String>,
    },
    BotJoined {
        group_id: String,
        previous_epoch: u64,
        new_group_epoch: u64,
        bot_identity: String,
        granted_permissions: Vec<String>,
    },
    BotRemoved {
        group_id: String,
        previous_epoch: u64,
        new_group_epoch: u64,
        bot_identity: String,
    },
    BotPermissionUpdated {
        group_id: String,
        group_epoch: u64,
        bot_identity: String,
        permission_patch: Value,
    },
    BotKeyDisclosureAccepted {
        group_id: String,
        bot_identity_commitment: String,
        hosting_model: HostingModel,
        manifest_hash: String,
        granted_permissions: Vec<String>,
        accepted_by: String,
        accepted_at: i64,
    },
    Deleted {
        group_id: String,
        group_epoch: u64,
        delete_scope: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConversationEventBody {
    Created {
        conversation_id: String,
        conversation_kind: String,
        root_ref: String,
    },
    Hidden {
        conversation_id: String,
        scope: String,
    },
    Archived {
        conversation_id: String,
        archived: bool,
    },
    Pinned {
        conversation_id: String,
        pin_order: u32,
    },
    Unpinned {
        conversation_id: String,
    },
    Muted {
        conversation_id: String,
        mute_until: i64,
    },
    Unmuted {
        conversation_id: String,
    },
    Cleared {
        conversation_id: String,
        clear_scope: String,
    },
    ClearLocal {
        conversation_id: String,
    },
    ClearOwnDevices {
        conversation_id: String,
        causal_event_id: String,
    },
    DisappearingUpdated {
        conversation_id: String,
        timer_seconds: u32,
        countdown_mode: String,
        scope: String,
    },
    Typing {
        conversation_id: String,
        ttl_seconds: u32,
        privacy_scope: String,
    },
    PresenceContactUpdated {
        identity_commitment: String,
        presence_state: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_seen_at: Option<i64>,
        ttl_seconds: u32,
        privacy_scope: String,
    },
    ReceiptDelivered {
        conversation_id: String,
        message_id: String,
        delivered_at: i64,
        receiver_device_id: String,
        scope: String,
        ttl_seconds: u32,
    },
    ReceiptReadPrivate {
        conversation_id: String,
        message_id: String,
        reader_identity: String,
        read_at: i64,
        own_device_scope: String,
    },
    ReceiptReadPublic {
        conversation_id: String,
        message_id: String,
        reader_identity: String,
        read_at: i64,
        visibility_scope: String,
        ttl_seconds: u32,
    },
    UnreadMarkerSet {
        conversation_id: String,
        message_id: String,
        marker_owner: String,
        marker_epoch: u64,
    },
    UnreadMarkerClear {
        conversation_id: String,
        message_id: String,
        marker_owner: String,
        marker_epoch: u64,
        cleared_at: i64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MessageEventBody {
    Created {
        conversation_id: String,
        message_id: String,
        encrypted_body: String,
        object_refs: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reply_to: Option<ReplyTo>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mentions: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        forwarded_from: Option<ForwardedFrom>,
        #[serde(skip_serializing_if = "Option::is_none")]
        forward_count: Option<u8>,
    },
    Edited {
        conversation_id: String,
        message_id: String,
        encrypted_body: String,
        edit_counter: u32,
    },
    Deleted {
        conversation_id: String,
        message_id: String,
        delete_scope: String,
        tombstone_id: String,
    },
    Reacted {
        conversation_id: String,
        message_id: String,
        reaction: String,
        reaction_scope: String,
    },
    ObjectRefAdded {
        conversation_id: String,
        message_id: String,
        object_id: String,
        manifest_hash: String,
    },
    Forwarded {
        conversation_id: String,
        message_id: String,
        forwarded_from: ForwardedFrom,
        forward_count: u8,
        encrypted_body: String,
        object_refs: Vec<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplyTo {
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quoted_cipher: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForwardedFrom {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_conversation_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_message_id_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sender_identity_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_timestamp_bucket: Option<String>,
}
