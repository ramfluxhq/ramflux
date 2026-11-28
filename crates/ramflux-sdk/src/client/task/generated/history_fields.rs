// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lossless historical metadata fields; conversion grants no membership authority.
use super::super::{historical::Membership, own_history::TaskExportMetadata};
use super::{g, invalid};
use crate::{SdkError, client::surface::OwnContext};

impl TryFrom<&Membership> for g::TaskMembership {
    type Error = SdkError;
    fn try_from(value: &Membership) -> Result<Self, Self::Error> {
        Ok(Self {
            conversation: value.conversation().to_owned(),
            group: None,
            epoch: None,
            at: value.at(),
            members: value.members().to_vec(),
        })
    }
}

impl TryFrom<&g::TaskMembership> for Membership {
    type Error = SdkError;
    fn try_from(value: &g::TaskMembership) -> Result<Self, Self::Error> {
        if value.group.is_some() || value.epoch.is_some() {
            return Err(invalid("task membership group witness is not accepted"));
        }
        Ok(serde_json::from_value(serde_json::json!({
            "conversation": value.conversation, "at": value.at, "members": value.members,
        }))?)
    }
}

impl From<&TaskExportMetadata> for g::TaskExportMetadata {
    fn from(value: &TaskExportMetadata) -> Self {
        Self {
            truncated: value.truncated,
            skipped_items: value.skipped_items,
            next_cursor: value.next_cursor.clone(),
        }
    }
}

impl From<&g::TaskExportMetadata> for TaskExportMetadata {
    fn from(value: &g::TaskExportMetadata) -> Self {
        Self {
            truncated: value.truncated,
            skipped_items: value.skipped_items,
            next_cursor: value.next_cursor.clone(),
        }
    }
}

impl TryFrom<&OwnContext> for g::OwnContext {
    type Error = SdkError;
    fn try_from(value: &OwnContext) -> Result<Self, Self::Error> {
        Ok(Self {
            conversation_id: value.conversation_id.clone(),
            participants: value.participants.clone(),
            group: None,
            friend: value
                .friend
                .as_ref()
                .map(|friend| serde_json::from_value(serde_json::to_value(friend)?))
                .transpose()?,
        })
    }
}

impl TryFrom<&g::OwnContext> for OwnContext {
    type Error = SdkError;
    fn try_from(value: &g::OwnContext) -> Result<Self, Self::Error> {
        if value.group.is_some() {
            return Err(invalid("task group context is not accepted"));
        }
        let friend = value.friend.as_ref().map(|friend| {
            serde_json::from_value(serde_json::json!({
                "link_id": friend.link_id, "requester_id": friend.requester_id, "target_id": friend.target_id,
                "state": friend.state, "remove_scope": friend.remove_scope, "blocked": friend.blocked,
                "capability_revoked_at": friend.capability_revoked_at,
            }))
        }).transpose()?;
        Ok(Self {
            conversation_id: value.conversation_id.clone(),
            participants: value.participants.clone(),
            friend,
        })
    }
}
