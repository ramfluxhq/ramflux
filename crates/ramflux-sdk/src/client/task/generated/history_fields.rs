// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lossless historical metadata fields; conversion grants no membership authority.
use super::super::{historical::Membership, own_history::TaskExportMetadata};
use super::{g, invalid};
use crate::own_device_sync::{SdkOwnDeviceGroupMemberPin, SdkOwnDeviceGroupSnapshot};
use crate::{SdkError, client::surface::OwnContext};

impl TryFrom<&Membership> for g::TaskMembership {
    type Error = SdkError;
    fn try_from(value: &Membership) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(serde_json::to_value(value)?)?)
    }
}

impl TryFrom<&g::TaskMembership> for Membership {
    type Error = SdkError;
    fn try_from(value: &g::TaskMembership) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(serde_json::json!({
            "conversation": value.conversation, "group": value.group,
            "epoch": value.epoch, "at": value.at, "members": value.members,
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

impl From<&SdkOwnDeviceGroupMemberPin> for g::SdkOwnDeviceGroupMemberPin {
    fn from(value: &SdkOwnDeviceGroupMemberPin) -> Self {
        Self {
            group_id: value.group_id.clone(),
            device_id: value.device_id.clone(),
            signing_public_key: value.signing_public_key.clone(),
            principal_id: value.principal_id.clone(),
            principal_commitment: value.principal_commitment.clone(),
        }
    }
}

impl From<&g::SdkOwnDeviceGroupMemberPin> for SdkOwnDeviceGroupMemberPin {
    fn from(value: &g::SdkOwnDeviceGroupMemberPin) -> Self {
        Self {
            group_id: value.group_id.clone(),
            device_id: value.device_id.clone(),
            signing_public_key: value.signing_public_key.clone(),
            principal_id: value.principal_id.clone(),
            principal_commitment: value.principal_commitment.clone(),
        }
    }
}

impl TryFrom<&OwnContext> for g::OwnContext {
    type Error = SdkError;
    fn try_from(value: &OwnContext) -> Result<Self, Self::Error> {
        let group = value
            .group
            .as_ref()
            .map(|native| {
                let mut fields = serde_json::to_value(native)?;
                fields
                    .as_object_mut()
                    .ok_or_else(|| invalid("task group context missing"))?
                    .remove("shared_state");
                let mut group: g::SdkOwnDeviceGroupSnapshot = serde_json::from_value(fields)?;
                group.shared_state = native
                    .shared_state
                    .as_ref()
                    .map(|state| {
                        Ok::<_, SdkError>(g::NativeGroupSnapshot {
                            canonical: ramflux_protocol::canonical_json_bytes(state)?,
                        })
                    })
                    .transpose()?;
                Ok::<_, SdkError>(group)
            })
            .transpose()?;
        Ok(Self {
            conversation_id: value.conversation_id.clone(),
            participants: value.participants.clone(),
            group,
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
        let group = value
            .group
            .as_ref()
            .map(|group| {
                let shared_state = group
                    .shared_state
                    .as_ref()
                    .map(|document| {
                        let native =
                            ramflux_protocol::group_state::GroupStateSnapshot::from_wire_bytes(
                                &document.canonical,
                            )?;
                        if ramflux_protocol::canonical_json_bytes(&native)? != document.canonical {
                            return Err(invalid("noncanonical task group snapshot"));
                        }
                        Ok(native)
                    })
                    .transpose()?;
                Ok::<_, SdkError>(SdkOwnDeviceGroupSnapshot {
                    shared_state,
                    group_id: group.group_id.clone(),
                    group_epoch: group.group_epoch,
                    max_members: group.max_members,
                    new_member_history: group.new_member_history.clone(),
                    local_role: group.local_role.clone(),
                    local_joined_epoch: group.local_joined_epoch,
                    members: group
                        .members
                        .iter()
                        .map(|member| crate::own_device_sync::SdkOwnDeviceGroupMemberSnapshot {
                            member_id: member.member_id.clone(),
                            role: member.role.clone(),
                            joined_epoch: member.joined_epoch,
                        })
                        .collect(),
                    routes: group
                        .routes
                        .iter()
                        .map(|route| crate::LocalBusGroupMemberRoute {
                            member_id: route.member_id.clone(),
                            member_principal_commitment: route.member_principal_commitment.clone(),
                            device_signing_public_key: route.device_signing_public_key.clone(),
                            target_delivery_id: route.target_delivery_id.clone(),
                            federation: route.federation.as_ref().map(|route| {
                                crate::LocalBusFederationRoute {
                                    federation_url: route.federation_url.clone(),
                                    source_node_id: route.source_node_id.clone(),
                                    target_node_id: route.target_node_id.clone(),
                                    required_capability: route.required_capability.clone(),
                                    admin_token: route.admin_token.clone(),
                                    recipient_prekey_url: route.recipient_prekey_url.clone(),
                                }
                            }),
                        })
                        .collect(),
                })
            })
            .transpose()?;
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
            group,
            friend,
        })
    }
}
