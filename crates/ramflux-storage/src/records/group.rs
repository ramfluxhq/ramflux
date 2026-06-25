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
    pub members: BTreeSet<String>,
    pub removed_members: BTreeSet<String>,
    pub sender_key_distributed: BTreeSet<String>,
    pub queued_sender_key_distribution: BTreeSet<String>,
    pub readable_objects: BTreeMap<String, BTreeSet<String>>,
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
    pub counter: u64,
    pub message_id: String,
    pub seen_at: i64,
}

impl GroupKeyEpochState {
    #[must_use]
    pub fn new(group_id: &str, members: impl IntoIterator<Item = String>) -> Self {
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

    pub fn distribute_sender_key(&mut self, member: &str) {
        if self.members.contains(member) {
            self.sender_key_distributed.insert(member.to_owned());
            self.queued_sender_key_distribution.remove(member);
        }
    }

    pub fn queue_sender_key_for_offline_member(&mut self, member: &str) {
        if self.members.contains(member) {
            self.queued_sender_key_distribution.insert(member.to_owned());
        }
    }

    pub fn reconnect_member(&mut self, member: &str) {
        if self.queued_sender_key_distribution.remove(member) {
            self.sender_key_distributed.insert(member.to_owned());
        }
    }

    pub fn remove_member(&mut self, member: &str) {
        self.members.remove(member);
        self.removed_members.insert(member.to_owned());
        self.group_epoch += 1;
        self.group_key_epoch += 1;
        self.sender_key_distributed.clear();
    }

    pub fn add_member_no_history(&mut self, member: &str) {
        self.members.insert(member.to_owned());
        self.group_epoch += 1;
        self.group_key_epoch += 1;
        self.sender_key_distributed.remove(member);
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn assert_can_send(&self, member: &str) -> Result<(), StorageError> {
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
        sender: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        self.assert_can_send(sender)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.group_key_epoch.to_be_bytes());
        bytes.extend_from_slice(sender.as_bytes());
        bytes.extend_from_slice(plaintext);
        Ok(bytes)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn decrypt_epoch_message_for(
        &self,
        member: &str,
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
    pub fn can_read_object(&self, member: &str, object_id: &str) -> bool {
        self.readable_objects.get(object_id).is_some_and(|readers| readers.contains(member))
    }

    pub fn admin_shared_history_rewrap(&mut self, member: &str, object_ids: &[String]) {
        for object_id in object_ids {
            self.readable_objects.entry(object_id.clone()).or_default().insert(member.to_owned());
        }
    }

    #[must_use]
    pub const fn membership_commitment_reject_deferred(&self) -> bool {
        self.conflict_pending
    }
}
