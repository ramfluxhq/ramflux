// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupState {
    pub group_id: String,
    pub group_epoch: u64,
    pub max_members: u32,
    pub new_member_history: String,
    pub members: BTreeSet<String>,
    pub roles: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupTransition {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub auth_chain: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupKeyEpochState {
    pub group_id: String,
    pub group_epoch: u64,
    pub group_key_epoch: u64,
    pub members: BTreeSet<ramflux_crypto::RootQualifiedDeviceRef>,
    pub removed_members: BTreeSet<ramflux_crypto::RootQualifiedDeviceRef>,
    pub sender_key_distributed: BTreeSet<ramflux_crypto::RootQualifiedDeviceRef>,
    pub queued_sender_key_distribution: BTreeSet<ramflux_crypto::RootQualifiedDeviceRef>,
    pub readable_objects: BTreeMap<String, BTreeSet<ramflux_crypto::RootQualifiedDeviceRef>>,
    pub conflict_pending: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupPendingUndecryptedRecord {
    pub group_id: String,
    pub conversation_id: String,
    pub group_key_epoch: u64,
    pub message_id: String,
    pub sender_id: String,
    pub inbox_seq: u64,
    pub envelope_json: Vec<u8>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupSenderKeyCounterRecord {
    pub group_id: String,
    pub group_key_epoch: u64,
    pub sender_id: String,
    #[serde(default)]
    pub session_id: String,
    pub counter: u64,
    pub message_id: String,
    pub seen_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupRoleChangeWrite {
    pub group_id: String,
    pub event_id: String,
    pub actor_device_id: String,
    pub target_member_id: String,
    pub previous_epoch: u64,
    pub new_group_epoch: u64,
    pub new_role: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupMemberKickWrite {
    pub group_id: String,
    pub event_id: String,
    pub actor_device_id: String,
    pub target_member_id: String,
    pub previous_epoch: u64,
    pub new_group_epoch: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupMemberBanWrite {
    pub group_id: String,
    pub event_id: String,
    pub actor_device_id: String,
    pub target_member_id: String,
    pub previous_epoch: u64,
    pub new_group_epoch: u64,
    pub reason: String,
    pub ban_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupMessageDeleteWrite {
    pub group_id: String,
    pub event_id: String,
    pub actor_device_id: String,
    pub target_message_id: String,
    pub group_epoch: u64,
    pub delete_scope: String,
    pub tombstone_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupInviteRecord {
    pub group_id: String,
    pub invite_id: String,
    pub invitee_identity: String,
    pub invitee_signing_public_key: String,
    pub invited_role: String,
    pub inviter_device_id: String,
    pub invite_epoch: u64,
    pub expires_at: i64,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupInviteWrite {
    pub group_id: String,
    pub event_id: String,
    pub actor_device_id: String,
    pub invite_id: String,
    pub invitee_identity: String,
    /// An offer's expected root claim; identity is authenticated only when its acceptor arrives.
    pub invitee_principal_commitment: String,
    pub invitee_signing_public_key: String,
    pub invited_role: String,
    pub group_epoch: u64,
    pub expires_at: i64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupInviteAcceptWrite {
    pub group_id: String,
    pub event_id: String,
    pub actor_device_id: String,
    pub invite_id: String,
    pub invitee_identity: String,
    pub accepted_role: String,
    pub previous_epoch: u64,
    pub new_group_epoch: u64,
    pub now: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupMemberJoinWrite {
    pub group_id: String,
    pub event_id: String,
    pub actor_device_id: String,
    pub joined_identity: String,
    pub joined_role: String,
    pub actor_role: String,
    pub actor_principal_commitment: String,
    pub actor_device_signing_public_key: String,
    pub previous_epoch: u64,
    pub new_group_epoch: u64,
    pub max_members: u32,
    pub new_member_history: String,
}

impl GroupKeyEpochState {
    #[must_use]
    pub fn new(
        group_id: &str,
        members: impl IntoIterator<Item = ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Self {
        let members = members.into_iter().collect::<BTreeSet<_>>();
        Self {
            group_id: group_id.to_owned(),
            group_epoch: 1,
            group_key_epoch: 1,
            members,
            removed_members: BTreeSet::new(),
            sender_key_distributed: BTreeSet::new(),
            queued_sender_key_distribution: BTreeSet::new(),
            readable_objects: BTreeMap::new(),
            conflict_pending: false,
        }
    }

    /// # Errors
    /// Returns an error when `group_id` is not a valid core group id.
    pub fn typed_group_id(&self) -> Result<ramflux_core::GroupId, StorageError> {
        Ok(ramflux_core::GroupId::new(self.group_id.clone())?)
    }

    pub fn distribute_sender_key(&mut self, member: &ramflux_crypto::RootQualifiedDeviceRef) {
        if self.members.contains(member) {
            self.sender_key_distributed.insert(member.to_owned());
            self.queued_sender_key_distribution.remove(member);
        }
    }

    pub fn queue_sender_key_for_offline_member(
        &mut self,
        member: &ramflux_crypto::RootQualifiedDeviceRef,
    ) {
        if self.members.contains(member) {
            self.queued_sender_key_distribution.insert(member.to_owned());
        }
    }

    pub fn reconnect_member(&mut self, member: &ramflux_crypto::RootQualifiedDeviceRef) {
        if self.queued_sender_key_distribution.remove(member) {
            self.sender_key_distributed.insert(member.to_owned());
        }
    }

    pub fn remove_member(&mut self, member: &ramflux_crypto::RootQualifiedDeviceRef) {
        self.members.remove(member);
        self.removed_members.insert(member.to_owned());
        self.group_epoch += 1;
        self.group_key_epoch += 1;
        self.sender_key_distributed.clear();
    }

    pub fn add_member_no_history(&mut self, member: &ramflux_crypto::RootQualifiedDeviceRef) {
        self.members.insert(member.to_owned());
        self.group_epoch += 1;
        self.group_key_epoch += 1;
        self.sender_key_distributed.remove(member);
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn assert_can_send(
        &self,
        member: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), StorageError> {
        if self.members.contains(member) && self.sender_key_distributed.contains(member) {
            Ok(())
        } else {
            Err(StorageError::SenderKeyNotDistributed)
        }
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn encrypt_epoch_message_for(
        &self,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        self.assert_can_send(sender)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.group_key_epoch.to_be_bytes());
        bytes.extend_from_slice(sender.storage_key().as_bytes());
        bytes.extend_from_slice(plaintext);
        Ok(bytes)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn decrypt_epoch_message_for(
        &self,
        member: &ramflux_crypto::RootQualifiedDeviceRef,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        if !self.members.contains(member) || self.removed_members.contains(member) {
            return Err(StorageError::GroupEpochAccessDenied);
        }
        Ok(ciphertext[8..].to_vec())
    }

    pub fn wrap_object_for_current_members(&mut self, object_id: &str) {
        self.readable_objects.insert(object_id.to_owned(), self.members.iter().cloned().collect());
    }

    #[must_use]
    pub fn can_read_object(
        &self,
        member: &ramflux_crypto::RootQualifiedDeviceRef,
        object_id: &str,
    ) -> bool {
        self.readable_objects.get(object_id).is_some_and(|readers| readers.contains(member))
    }

    pub fn admin_shared_history_rewrap(
        &mut self,
        member: &ramflux_crypto::RootQualifiedDeviceRef,
        object_ids: &[String],
    ) {
        for object_id in object_ids {
            self.readable_objects.entry(object_id.clone()).or_default().insert(member.to_owned());
        }
    }

    #[must_use]
    pub const fn membership_commitment_reject_deferred(&self) -> bool {
        self.conflict_pending
    }
}

/// Immutable group-member key with an optional legacy principal binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMemberKeyBinding {
    pub signing_public_key: String,
    pub principal_id: Option<String>,
    pub principal_commitment: Option<String>,
}

/// Compare-and-swap parameters for a caller-verified root-authorized group key rotation.
#[derive(Clone, Copy, Debug)]
pub struct RootAuthorizedGroupKeyRotation<'a> {
    pub group_id: &'a str,
    pub device_id: &'a ramflux_crypto::RootQualifiedDeviceRef,
    pub principal_id: &'a str,
    pub principal_commitment: &'a str,
    pub previous_key: &'a str,
    pub next_key: &'a str,
}
