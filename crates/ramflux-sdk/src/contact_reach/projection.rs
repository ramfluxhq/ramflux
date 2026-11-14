// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local presentation and optional-signal permissions from verified recipient-owned state.
use super::{SavedReachState, refused};
use crate::SdkError;
use ramflux_protocol::contact_reach::{
    Permissions, Placement, Reason, Relationship, StateRecord, Subject,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationPermission {
    None,
    Active,
    Expired,
}
/// Friendship, placement and a renewable conversation grant are independent observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationReach {
    pub placement: Placement,
    pub relationship: Relationship,
    pub conversation_permission: ConversationPermission,
    pub permissions: Permissions,
}

impl SavedReachState {
    pub(super) fn conversation(
        &self,
        peer_root: &str,
        peer_node: &str,
        conversation_id: &str,
        now: u64,
    ) -> Result<ConversationReach, SdkError> {
        if self.conflict {
            return Err(refused(Reason::HomeFork));
        }
        let matches = |subject: &Subject| match subject {
            Subject::Friendship { root } => root == peer_root,
            Subject::Node { node_id } => node_id == peer_node,
            Subject::Conversation { root, conversation_id: id } => {
                root == peer_root && id == conversation_id
            }
            Subject::Group { .. } => false,
        };
        for record in self.records.iter().chain(self.restrictions.values()) {
            let denied = match record {
                StateRecord::Block { subject, .. }
                | StateRecord::Floor { subject, denied: true, .. } => matches(subject),
                StateRecord::Decline { root, until, .. } => root == peer_root && *until > now,
                StateRecord::Conflict { .. } => true,
                _ => false,
            };
            if denied {
                return Err(refused(Reason::ForeignReadRefused));
            }
        }
        let mut result = ConversationReach {
            placement: Placement::Strangers,
            relationship: Relationship::Unaccepted,
            conversation_permission: ConversationPermission::None,
            permissions: Permissions::UNACCEPTED,
        };
        for record in &self.records {
            if let StateRecord::Placement {
                conversation_id: id,
                placement,
                relationship,
                tombstone,
                ..
            } = record
                && id == conversation_id
            {
                if *tombstone {
                    return Err(refused(Reason::ForeignReadRefused));
                }
                result.placement = *placement;
                result.relationship = *relationship;
            }
        }
        let mut friendship = None;
        let mut conversation = None;
        for record in &self.records {
            let StateRecord::Grant { subject, permissions, grant_until, .. } = record else {
                continue;
            };
            if !matches(subject) {
                continue;
            }
            match subject {
                Subject::Friendship { .. } if *grant_until == 0 => friendship = Some(*permissions),
                Subject::Conversation { .. } => {
                    result.conversation_permission = if *grant_until > now {
                        conversation = Some(*permissions);
                        ConversationPermission::Active
                    } else {
                        ConversationPermission::Expired
                    };
                }
                _ => {}
            }
        }
        if let Some(permissions) = friendship {
            result.relationship = Relationship::Accepted;
            result.placement = Placement::Direct;
            result.permissions = permissions;
        } else {
            // A home placement is not authority to resurrect an absent friendship grant.
            result.relationship = Relationship::Unaccepted;
            if let Some(permissions) = conversation {
                result.permissions = permissions;
            }
        }
        Ok(result)
    }
}
impl crate::RamfluxClient {
    /// Read independently verified presentation and inbound optional-signal permission.
    /// Both endpoints' local settings must also permit a signal; this is not an outbound grant.
    /// # Errors
    /// Refuses missing/forked state, wrong accounts and retained block/decline/erase fences.
    pub fn conversation_reach(
        &self,
        peer_root: &str,
        peer_node: &str,
        conversation_id: &str,
        now: u64,
    ) -> Result<ConversationReach, SdkError> {
        let own = self.owned_device_identity()?;
        let db = self.account_db()?;
        let state: SavedReachState = serde_json::from_value(
            db.client_record("reach", "state")?
                .ok_or_else(|| refused(Reason::ReachPolicyRequired))?,
        )?;
        if state.root != own.root_commitment() {
            return Err(refused(Reason::AnchorMismatch));
        }
        state.conversation(peer_root, peer_node, conversation_id, now)
    }
}

#[cfg(test)]
mod tests;
