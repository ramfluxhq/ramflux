// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn create_group(&self, group_id: &str, creator_id: &str) -> Result<GroupState, SdkError> {
        let group = self.account_db()?.create_group(group_id, creator_id)?;
        if let Some(branch) = self.device_branch.as_ref()
            && branch.device_id == creator_id
        {
            let public_key =
                ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
            self.account_db()?.persist_group_member_device_key(
                group_id,
                creator_id,
                &public_key,
            )?;
        }
        Ok(group)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the member cannot be added.
    pub fn add_group_member(
        &self,
        group_id: &str,
        member_id: &str,
        role: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.add_group_member(group_id, member_id, role)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the member cannot be removed.
    pub fn remove_group_member(
        &self,
        group_id: &str,
        actor_id: &str,
        target_member_id: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.remove_group_member(group_id, actor_id, target_member_id)?)
    }

    /// # Errors
    /// Returns an error when the signed control event fails signature, epoch, or permission checks.
    #[allow(clippy::too_many_lines)]
    pub fn apply_group_control_event(
        &self,
        event: &ramflux_protocol::GroupEvent,
    ) -> Result<GroupState, SdkError> {
        self.verify_group_control_event(event)?;
        match &event.body {
            ramflux_protocol::GroupEventBody::RoleChanged {
                group_id,
                previous_epoch,
                new_group_epoch,
                target_identity,
                new_role,
            } => self.apply_verified_group_role_change(
                event,
                group_id,
                *previous_epoch,
                *new_group_epoch,
                target_identity,
                new_role,
            ),
            ramflux_protocol::GroupEventBody::MemberRemoved {
                group_id,
                previous_epoch,
                new_group_epoch,
                removed_identity,
                reason,
            } => self.apply_verified_group_member_kick(
                event,
                group_id,
                *previous_epoch,
                *new_group_epoch,
                removed_identity,
                reason,
            ),
            ramflux_protocol::GroupEventBody::MemberBanned {
                group_id,
                previous_epoch,
                new_group_epoch,
                banned_identity,
                reason,
                ban_id,
            } => self.apply_verified_group_member_ban(
                event,
                group_id,
                *previous_epoch,
                *new_group_epoch,
                banned_identity,
                reason,
                ban_id,
            ),
            ramflux_protocol::GroupEventBody::MessageDeleted {
                group_id,
                group_epoch,
                target_message_id,
                delete_scope,
                tombstone_id,
                reason,
            } => self.apply_verified_group_message_delete(
                event,
                group_id,
                *group_epoch,
                target_message_id,
                delete_scope,
                tombstone_id,
                reason,
            ),
            ramflux_protocol::GroupEventBody::MemberInvitedV2 {
                group_id,
                group_epoch,
                invite_id,
                invitee_identity,
                invitee_signing_public_key,
                invited_role,
                inviter_device_id: _,
                expires_at,
                reason,
            } => self.apply_verified_group_member_invite(
                event,
                group_id,
                *group_epoch,
                invite_id,
                invitee_identity,
                invitee_signing_public_key,
                invited_role,
                *expires_at,
                reason,
            ),
            ramflux_protocol::GroupEventBody::MemberAccepted {
                group_id,
                previous_epoch,
                new_group_epoch,
                invite_id,
                invitee_identity,
                accepted_role,
            } => self.apply_verified_group_member_accept(
                event,
                group_id,
                *previous_epoch,
                *new_group_epoch,
                invite_id,
                invitee_identity,
                accepted_role,
            ),
            ramflux_protocol::GroupEventBody::MemberJoined {
                group_id,
                previous_epoch,
                new_group_epoch,
                joined_identity,
                joined_role,
                actor_role,
                actor_principal_commitment,
                actor_device_signing_public_key,
                max_members,
                new_member_history,
            } => self.apply_verified_group_member_join(
                event,
                group_id,
                *previous_epoch,
                *new_group_epoch,
                joined_identity,
                joined_role,
                actor_role,
                actor_principal_commitment,
                actor_device_signing_public_key,
                *max_members,
                new_member_history,
            ),
            _ => Err(SdkError::LocalBus("unsupported group control event body".to_owned())),
        }
    }

    /// # Errors
    /// Returns an error when the signed role-change control event fails verification.
    pub fn apply_group_role_change(
        &self,
        event: &ramflux_protocol::GroupEvent,
    ) -> Result<GroupState, SdkError> {
        self.apply_group_control_event(event)
    }

    fn verify_group_control_event(
        &self,
        event: &ramflux_protocol::GroupEvent,
    ) -> Result<(), SdkError> {
        let (group_id, event_type) = match &event.body {
            ramflux_protocol::GroupEventBody::RoleChanged { group_id, .. } => {
                (group_id, "group.role_changed")
            }
            ramflux_protocol::GroupEventBody::MemberRemoved { group_id, .. } => {
                (group_id, "group.member_kicked")
            }
            ramflux_protocol::GroupEventBody::MemberBanned { group_id, .. } => {
                (group_id, "group.member_banned")
            }
            ramflux_protocol::GroupEventBody::MessageDeleted { group_id, .. } => {
                (group_id, "group.message_deleted")
            }
            ramflux_protocol::GroupEventBody::MemberInvitedV2 { group_id, .. } => {
                (group_id, "group.member_invited")
            }
            ramflux_protocol::GroupEventBody::MemberAccepted { group_id, .. } => {
                (group_id, "group.member_accepted")
            }
            ramflux_protocol::GroupEventBody::MemberJoined { group_id, .. } => {
                (group_id, "group.member_joined")
            }
            _ => return Err(SdkError::LocalBus("unsupported group control event body".to_owned())),
        };
        if event.domain != ramflux_protocol::domain::GROUP_EVENT {
            return Err(SdkError::LocalBus(format!(
                "unsupported group control event domain: {}",
                event.domain
            )));
        }
        if event.event_type != event_type {
            return Err(SdkError::LocalBus(format!(
                "unsupported group control event type: {}",
                event.event_type
            )));
        }
        if event.signed.signing_key_id != format!("device:{}", event.actor_device_id) {
            return Err(SdkError::LocalBus(format!(
                "group control signing key id mismatch for {}",
                event.actor_device_id
            )));
        }
        let public_key =
            if let ramflux_protocol::GroupEventBody::MemberAccepted { invite_id, .. } = &event.body
            {
                self.account_db()?.group_invite(group_id, invite_id)?.invitee_signing_public_key
            } else {
                self.account_db()?
                    .group_member_device_key(group_id, &event.actor_device_id)?
                    .ok_or_else(|| {
                        StorageError::GroupControlSigningKeyMissing(event.actor_device_id.clone())
                    })?
            };
        ramflux_protocol::verify_signed_fields(event, &event.signed, &public_key)?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when a first-seen direct-add onboard event is not bound to the authenticated
    /// source device and its verified manifest signing key.
    pub(crate) fn apply_bootstrap_group_member_join_event(
        &self,
        event: &ramflux_protocol::GroupEvent,
        authenticated_source_device_id: &str,
        verified_actor_public_key: &str,
    ) -> Result<GroupState, SdkError> {
        let ramflux_protocol::GroupEventBody::MemberJoined {
            actor_device_signing_public_key, ..
        } = &event.body
        else {
            return Err(SdkError::LocalBus("expected group member joined event".to_owned()));
        };
        if event.domain != ramflux_protocol::domain::GROUP_EVENT
            || event.event_type != "group.member_joined"
        {
            return Err(SdkError::LocalBus(format!(
                "unsupported bootstrap group event type: {}",
                event.event_type
            )));
        }
        if event.actor_device_id != authenticated_source_device_id {
            return Err(SdkError::LocalBus(format!(
                "bootstrap group event actor {} does not match envelope source {}",
                event.actor_device_id, authenticated_source_device_id
            )));
        }
        if event.signed.signing_key_id != format!("device:{}", event.actor_device_id) {
            return Err(SdkError::LocalBus(format!(
                "bootstrap group event signing key id mismatch for {}",
                event.actor_device_id
            )));
        }
        if actor_device_signing_public_key != verified_actor_public_key {
            return Err(SdkError::LocalBus(
                "bootstrap group event signing key does not match verified manifest".to_owned(),
            ));
        }
        ramflux_protocol::verify_signed_fields(event, &event.signed, verified_actor_public_key)?;
        self.apply_verified_group_member_join_from_event(event)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_verified_group_role_change(
        &self,
        event: &ramflux_protocol::GroupEvent,
        group_id: &str,
        previous_epoch: u64,
        new_group_epoch: u64,
        target_identity: &str,
        new_role: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.apply_group_role_change(&GroupRoleChangeWrite {
            group_id: group_id.to_owned(),
            event_id: event.event_id.clone(),
            actor_device_id: event.actor_device_id.clone(),
            target_member_id: target_identity.to_owned(),
            previous_epoch,
            new_group_epoch,
            new_role: new_role.to_owned(),
        })?)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_verified_group_member_join(
        &self,
        event: &ramflux_protocol::GroupEvent,
        group_id: &str,
        previous_epoch: u64,
        new_group_epoch: u64,
        joined_identity: &str,
        joined_role: &str,
        actor_role: &str,
        actor_principal_commitment: &str,
        actor_device_signing_public_key: &str,
        max_members: u32,
        new_member_history: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.apply_group_member_join(&GroupMemberJoinWrite {
            group_id: group_id.to_owned(),
            event_id: event.event_id.clone(),
            actor_device_id: event.actor_device_id.clone(),
            joined_identity: joined_identity.to_owned(),
            joined_role: joined_role.to_owned(),
            actor_role: actor_role.to_owned(),
            actor_principal_commitment: actor_principal_commitment.to_owned(),
            actor_device_signing_public_key: actor_device_signing_public_key.to_owned(),
            previous_epoch,
            new_group_epoch,
            max_members,
            new_member_history: new_member_history.to_owned(),
        })?)
    }

    fn apply_verified_group_member_join_from_event(
        &self,
        event: &ramflux_protocol::GroupEvent,
    ) -> Result<GroupState, SdkError> {
        let ramflux_protocol::GroupEventBody::MemberJoined {
            group_id,
            previous_epoch,
            new_group_epoch,
            joined_identity,
            joined_role,
            actor_role,
            actor_principal_commitment,
            actor_device_signing_public_key,
            max_members,
            new_member_history,
        } = &event.body
        else {
            return Err(SdkError::LocalBus("expected group member joined event".to_owned()));
        };
        self.apply_verified_group_member_join(
            event,
            group_id,
            *previous_epoch,
            *new_group_epoch,
            joined_identity,
            joined_role,
            actor_role,
            actor_principal_commitment,
            actor_device_signing_public_key,
            *max_members,
            new_member_history,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_verified_group_member_kick(
        &self,
        event: &ramflux_protocol::GroupEvent,
        group_id: &str,
        previous_epoch: u64,
        new_group_epoch: u64,
        removed_identity: &str,
        reason: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.apply_group_member_kick(&GroupMemberKickWrite {
            group_id: group_id.to_owned(),
            event_id: event.event_id.clone(),
            actor_device_id: event.actor_device_id.clone(),
            target_member_id: removed_identity.to_owned(),
            previous_epoch,
            new_group_epoch,
            reason: reason.to_owned(),
        })?)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_verified_group_member_ban(
        &self,
        event: &ramflux_protocol::GroupEvent,
        group_id: &str,
        previous_epoch: u64,
        new_group_epoch: u64,
        banned_identity: &str,
        reason: &str,
        ban_id: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.apply_group_member_ban(&GroupMemberBanWrite {
            group_id: group_id.to_owned(),
            event_id: event.event_id.clone(),
            actor_device_id: event.actor_device_id.clone(),
            target_member_id: banned_identity.to_owned(),
            previous_epoch,
            new_group_epoch,
            reason: reason.to_owned(),
            ban_id: ban_id.to_owned(),
        })?)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_verified_group_message_delete(
        &self,
        event: &ramflux_protocol::GroupEvent,
        group_id: &str,
        group_epoch: u64,
        target_message_id: &str,
        delete_scope: &str,
        tombstone_id: &str,
        reason: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.apply_group_message_delete(&GroupMessageDeleteWrite {
            group_id: group_id.to_owned(),
            event_id: event.event_id.clone(),
            actor_device_id: event.actor_device_id.clone(),
            target_message_id: target_message_id.to_owned(),
            group_epoch,
            delete_scope: delete_scope.to_owned(),
            tombstone_id: tombstone_id.to_owned(),
            reason: reason.to_owned(),
        })?)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_verified_group_member_invite(
        &self,
        event: &ramflux_protocol::GroupEvent,
        group_id: &str,
        group_epoch: u64,
        invite_id: &str,
        invitee_identity: &str,
        invitee_signing_public_key: &str,
        invited_role: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.apply_group_member_invite(&GroupInviteWrite {
            group_id: group_id.to_owned(),
            event_id: event.event_id.clone(),
            actor_device_id: event.actor_device_id.clone(),
            invite_id: invite_id.to_owned(),
            invitee_identity: invitee_identity.to_owned(),
            invitee_signing_public_key: invitee_signing_public_key.to_owned(),
            invited_role: invited_role.to_owned(),
            group_epoch,
            expires_at,
            reason: reason.to_owned(),
        })?)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_verified_group_member_accept(
        &self,
        event: &ramflux_protocol::GroupEvent,
        group_id: &str,
        previous_epoch: u64,
        new_group_epoch: u64,
        invite_id: &str,
        invitee_identity: &str,
        accepted_role: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.apply_group_member_accept(&GroupInviteAcceptWrite {
            group_id: group_id.to_owned(),
            event_id: event.event_id.clone(),
            actor_device_id: event.actor_device_id.clone(),
            invite_id: invite_id.to_owned(),
            invitee_identity: invitee_identity.to_owned(),
            accepted_role: accepted_role.to_owned(),
            previous_epoch,
            new_group_epoch,
            now: now_unix_timestamp(),
        })?)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_group_control_base(
        &self,
        group_id: &str,
        actor_device_id: &str,
        event_id: String,
        event_type: &str,
        group_epoch: u64,
        body: ramflux_protocol::GroupEventBody,
    ) -> Result<ramflux_protocol::GroupEvent, SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if branch.device_id != actor_device_id {
            return Err(SdkError::LocalBus(format!(
                "actor device {actor_device_id} does not match local signer {}",
                branch.device_id
            )));
        }
        Ok(ramflux_protocol::GroupEvent {
            schema: "ramflux.client_event.v1".to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::GROUP_EVENT.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: sdk_device_signed_fields(actor_device_id, ""),
            event_id,
            event_type: event_type.to_owned(),
            actor_principal_id: branch.principal_id.clone(),
            actor_device_id: actor_device_id.to_owned(),
            device_counter: group_epoch,
            lamport_time: group_epoch,
            created_at: now_unix_timestamp(),
            causal_prev: vec![format!("group:{group_id}:epoch:{group_epoch}")],
            body,
        })
    }

    fn sign_group_control_event(
        &self,
        mut event: ramflux_protocol::GroupEvent,
    ) -> Result<ramflux_protocol::GroupEvent, SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        event.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(branch, &event)?;
        Ok(event)
    }

    /// # Errors
    /// Returns an error when the signed control event fails signature, epoch, or permission checks.
    pub fn create_signed_group_member_kick(
        &self,
        group_id: &str,
        actor_device_id: &str,
        target_member_id: &str,
        reason: &str,
    ) -> Result<(ramflux_protocol::GroupEvent, GroupState), SdkError> {
        let group = self.group_state(group_id)?;
        let new_group_epoch = group.group_epoch + 1;
        let event_id = group_member_kicked_event_id(
            group_id,
            actor_device_id,
            target_member_id,
            new_group_epoch,
        );
        let event = self.signed_group_control_base(
            group_id,
            actor_device_id,
            event_id,
            "group.member_kicked",
            new_group_epoch,
            ramflux_protocol::GroupEventBody::MemberRemoved {
                group_id: group_id.to_owned(),
                previous_epoch: group.group_epoch,
                new_group_epoch,
                removed_identity: target_member_id.to_owned(),
                reason: reason.to_owned(),
            },
        )?;
        let event = self.sign_group_control_event(event)?;
        let state = self.apply_group_control_event(&event)?;
        Ok((event, state))
    }

    /// # Errors
    /// Returns an error when the signed control event fails signature, epoch, or permission checks.
    pub fn create_signed_group_member_ban(
        &self,
        group_id: &str,
        actor_device_id: &str,
        target_member_id: &str,
        reason: &str,
    ) -> Result<(ramflux_protocol::GroupEvent, GroupState), SdkError> {
        let group = self.group_state(group_id)?;
        let new_group_epoch = group.group_epoch + 1;
        let event_id = group_member_banned_event_id(
            group_id,
            actor_device_id,
            target_member_id,
            new_group_epoch,
        );
        let ban_id = format!("group.ban:{group_id}:{target_member_id}:{new_group_epoch}");
        let event = self.signed_group_control_base(
            group_id,
            actor_device_id,
            event_id,
            "group.member_banned",
            new_group_epoch,
            ramflux_protocol::GroupEventBody::MemberBanned {
                group_id: group_id.to_owned(),
                previous_epoch: group.group_epoch,
                new_group_epoch,
                banned_identity: target_member_id.to_owned(),
                reason: reason.to_owned(),
                ban_id,
            },
        )?;
        let event = self.sign_group_control_event(event)?;
        let state = self.apply_group_control_event(&event)?;
        Ok((event, state))
    }

    /// # Errors
    /// Returns an error when the signed control event fails signature, epoch, or permission checks.
    pub fn create_signed_group_message_delete(
        &self,
        group_id: &str,
        actor_device_id: &str,
        target_message_id: &str,
        delete_scope: &str,
        reason: &str,
    ) -> Result<(ramflux_protocol::GroupEvent, GroupState), SdkError> {
        let group = self.group_state(group_id)?;
        let event_id = group_message_deleted_event_id(
            group_id,
            actor_device_id,
            target_message_id,
            group.group_epoch,
        );
        let tombstone_id = format!("group.message.tombstone:{group_id}:{target_message_id}");
        let event = self.signed_group_control_base(
            group_id,
            actor_device_id,
            event_id,
            "group.message_deleted",
            group.group_epoch,
            ramflux_protocol::GroupEventBody::MessageDeleted {
                group_id: group_id.to_owned(),
                group_epoch: group.group_epoch,
                target_message_id: target_message_id.to_owned(),
                delete_scope: delete_scope.to_owned(),
                tombstone_id,
                reason: reason.to_owned(),
            },
        )?;
        let event = self.sign_group_control_event(event)?;
        let state = self.apply_group_control_event(&event)?;
        Ok((event, state))
    }

    /// # Errors
    /// Returns an error when the signed invite fails signature, epoch, or permission checks.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed_group_member_invite(
        &self,
        group_id: &str,
        actor_device_id: &str,
        invitee_identity: &str,
        invitee_signing_public_key: &str,
        invited_role: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<(ramflux_protocol::GroupEvent, GroupState), SdkError> {
        let group = self.group_state(group_id)?;
        let event_id = group_member_invited_event_id(
            group_id,
            actor_device_id,
            invitee_identity,
            group.group_epoch,
        );
        let invite_id = format!("group.invite:{group_id}:{invitee_identity}:{}", group.group_epoch);
        let event = self.signed_group_control_base(
            group_id,
            actor_device_id,
            event_id,
            "group.member_invited",
            group.group_epoch,
            ramflux_protocol::GroupEventBody::MemberInvitedV2 {
                group_id: group_id.to_owned(),
                group_epoch: group.group_epoch,
                invite_id,
                invitee_identity: invitee_identity.to_owned(),
                invitee_signing_public_key: invitee_signing_public_key.to_owned(),
                invited_role: invited_role.to_owned(),
                inviter_device_id: actor_device_id.to_owned(),
                expires_at,
                reason: reason.to_owned(),
            },
        )?;
        let event = self.sign_group_control_event(event)?;
        let state = self.apply_group_control_event(&event)?;
        Ok((event, state))
    }

    /// # Errors
    /// Returns an error when the signed accept fails signature, epoch, or invite checks.
    pub fn create_signed_group_member_accept(
        &self,
        group_id: &str,
        actor_device_id: &str,
        invite_id: &str,
    ) -> Result<(ramflux_protocol::GroupEvent, GroupState), SdkError> {
        let group = self.group_state(group_id)?;
        let invite = self.account_db()?.group_invite(group_id, invite_id)?;
        let new_group_epoch = group.group_epoch + 1;
        let event_id =
            group_member_accepted_event_id(group_id, actor_device_id, invite_id, new_group_epoch);
        let event = self.signed_group_control_base(
            group_id,
            actor_device_id,
            event_id,
            "group.member_accepted",
            new_group_epoch,
            ramflux_protocol::GroupEventBody::MemberAccepted {
                group_id: group_id.to_owned(),
                previous_epoch: group.group_epoch,
                new_group_epoch,
                invite_id: invite_id.to_owned(),
                invitee_identity: invite.invitee_identity,
                accepted_role: invite.invited_role,
            },
        )?;
        let event = self.sign_group_control_event(event)?;
        let state = self.apply_group_control_event(&event)?;
        Ok((event, state))
    }

    /// # Errors
    /// Returns an error when the local owner/admin cannot sign a direct-add onboard event.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_signed_group_member_join_event(
        &self,
        group_id: &str,
        actor_device_id: &str,
        joined_identity: &str,
        joined_role: &str,
        actor_principal_commitment: &str,
    ) -> Result<ramflux_protocol::GroupEvent, SdkError> {
        let group = self.group_state(group_id)?;
        let Some(actor_role) = group.roles.get(actor_device_id) else {
            return Err(SdkError::Storage(StorageError::GroupPermissionDenied));
        };
        if actor_role != "owner" && actor_role != "admin" {
            return Err(SdkError::Storage(StorageError::GroupPermissionDenied));
        }
        let previous_epoch = group.group_epoch.saturating_sub(1);
        let event_id = group_member_joined_event_id(
            group_id,
            actor_device_id,
            joined_identity,
            group.group_epoch,
        );
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let actor_device_signing_public_key =
            ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
        let event = self.signed_group_control_base(
            group_id,
            actor_device_id,
            event_id,
            "group.member_joined",
            group.group_epoch,
            ramflux_protocol::GroupEventBody::MemberJoined {
                group_id: group_id.to_owned(),
                previous_epoch,
                new_group_epoch: group.group_epoch,
                joined_identity: joined_identity.to_owned(),
                joined_role: joined_role.to_owned(),
                actor_role: actor_role.clone(),
                actor_principal_commitment: actor_principal_commitment.to_owned(),
                actor_device_signing_public_key,
                max_members: group.max_members,
                new_member_history: group.new_member_history,
            },
        )?;
        self.sign_group_control_event(event)
    }

    /// # Errors
    /// Returns an error when the local device cannot sign or the event cannot be locally applied.
    pub fn create_signed_group_role_change(
        &self,
        group_id: &str,
        actor_device_id: &str,
        target_member_id: &str,
        new_role: &str,
    ) -> Result<(ramflux_protocol::GroupEvent, GroupState), SdkError> {
        let group = self.group_state(group_id)?;
        let new_group_epoch = group.group_epoch + 1;
        let event_id = group_role_changed_event_id(
            group_id,
            actor_device_id,
            target_member_id,
            new_group_epoch,
        );
        let event = self.signed_group_control_base(
            group_id,
            actor_device_id,
            event_id,
            "group.role_changed",
            new_group_epoch,
            ramflux_protocol::GroupEventBody::RoleChanged {
                group_id: group_id.to_owned(),
                previous_epoch: group.group_epoch,
                new_group_epoch,
                target_identity: target_member_id.to_owned(),
                new_role: new_role.to_owned(),
            },
        )?;
        let event = self.sign_group_control_event(event)?;
        let state = self.apply_group_control_event(&event)?;
        Ok((event, state))
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or group state cannot be read.
    pub fn group_state(&self, group_id: &str) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.group_state(group_id)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or groups cannot be read.
    pub fn groups(&self) -> Result<Vec<GroupState>, SdkError> {
        Ok(self.account_db()?.groups()?)
    }

    /// # Errors
    /// Returns an error when the account DB is locked or the route cannot be persisted.
    pub fn persist_group_member_route(
        &self,
        group_id: &str,
        route: &LocalBusGroupMemberRoute,
    ) -> Result<(), SdkError> {
        let event_id = group_member_route_event_id(group_id, &route.member_id);
        if self.event_body(&event_id)?.is_some() {
            return Ok(());
        }
        if let Some(public_key) = route.device_signing_public_key.as_ref() {
            self.account_db()?.persist_group_member_device_key(
                group_id,
                &route.member_id,
                public_key,
            )?;
        }
        self.append_event(&event_id, "group.member.route", &serde_json::to_vec(route)?)
    }

    /// # Errors
    /// Returns an error when group state or a stored member route cannot be read.
    pub fn group_member_routes(
        &self,
        group_id: &str,
    ) -> Result<Vec<LocalBusGroupMemberRoute>, SdkError> {
        let group = self.group_state(group_id)?;
        let mut routes = Vec::new();
        for member_id in group.members {
            let event_id = group_member_route_event_id(group_id, &member_id);
            if let Some(bytes) = self.event_body(&event_id)? {
                routes.push(serde_json::from_slice(&bytes)?);
            }
        }
        Ok(routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("ramflux-sdk-group-{test_name}-{nanos}"))
    }

    fn group_client(
        test_name: &str,
        principal: &str,
        device: &str,
        device_seed: [u8; 32],
    ) -> Result<RamfluxClient, SdkError> {
        let root = temp_root(test_name);
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal, [0x31; 32]);
        client.create_device_branch(principal, device, 1, device_seed);
        client.open_account_index(root)?;
        client.create_account("acct", principal)?;
        client.unlock_account("acct", b"group-control-test")?;
        Ok(client)
    }

    fn device_public_key(principal: &str, device: &str, seed: [u8; 32]) -> String {
        let branch = ramflux_crypto::create_device_branch(principal, device, 1, seed);
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())
    }

    fn seed_group_named(
        client: &RamfluxClient,
        group_id: &str,
        alice_key: &str,
    ) -> Result<(), SdkError> {
        client.create_group(group_id, "alice_device")?;
        client.account_db()?.persist_group_member_device_key(
            group_id,
            "alice_device",
            alice_key,
        )?;
        client.add_group_member(group_id, "bob_device", "member")?;
        Ok(())
    }

    fn seed_group(client: &RamfluxClient, alice_key: &str) -> Result<(), SdkError> {
        seed_group_named(client, "group_test", alice_key)?;
        Ok(())
    }

    fn seed_member_key(
        client: &RamfluxClient,
        member_id: &str,
        public_key: &str,
    ) -> Result<(), SdkError> {
        client.account_db()?.persist_group_member_device_key(
            "group_test",
            member_id,
            public_key,
        )?;
        Ok(())
    }

    fn invite_id_from_event(event: &ramflux_protocol::GroupEvent) -> Result<String, SdkError> {
        match &event.body {
            ramflux_protocol::GroupEventBody::MemberInvitedV2 { invite_id, .. } => {
                Ok(invite_id.clone())
            }
            _ => Err(SdkError::LocalBus("expected member invite event".to_owned())),
        }
    }

    #[test]
    fn bootstrap_member_join_requires_verified_actor_key_and_source_device() -> Result<(), SdkError>
    {
        let alice_seed = [0x72; 32];
        let bob_seed = [0x73; 32];
        let carol_seed = [0x74; 32];
        let alice_key = device_public_key("alice", "alice_device", alice_seed);
        let bob_key = device_public_key("bob", "bob_device", bob_seed);
        let carol_key = device_public_key("carol", "carol_device", carol_seed);
        let alice = group_client("alice_join", "alice", "alice_device", alice_seed)?;
        let bob = group_client("bob_join", "bob", "bob_device", bob_seed)?;
        let carol = group_client("carol_join", "carol", "carol_device", carol_seed)?;

        alice.create_group("group_join", "alice_device")?;
        alice.add_group_member("group_join", "bob_device", "member")?;
        let event = alice.create_signed_group_member_join_event(
            "group_join",
            "alice_device",
            "bob_device",
            "member",
            "alice_commitment",
        )?;

        assert!(
            bob.apply_bootstrap_group_member_join_event(&event, "mallory_device", &alice_key)
                .is_err()
        );
        assert!(
            carol
                .apply_bootstrap_group_member_join_event(&event, "alice_device", &carol_key)
                .is_err()
        );

        let state =
            bob.apply_bootstrap_group_member_join_event(&event, "alice_device", &alice_key)?;
        assert!(state.members.contains("bob_device"));
        assert_eq!(state.roles.get("alice_device").map(String::as_str), Some("owner"));
        assert_eq!(state.roles.get("bob_device").map(String::as_str), Some("member"));
        assert_eq!(
            bob.account_db()?.group_member_device_key("group_join", "alice_device")?,
            Some(alice_key)
        );
        assert_ne!(bob_key, carol_key);
        Ok(())
    }

    #[test]
    fn signed_group_role_change_rejects_forgery_epoch_mismatch_and_replay() -> Result<(), SdkError>
    {
        let alice_seed = [0x42; 32];
        let alice_key = device_public_key("alice", "alice_device", alice_seed);
        let alice = group_client("alice", "alice", "alice_device", alice_seed)?;
        let bob = group_client("bob", "bob", "bob_device", [0x44; 32])?;
        seed_group(&alice, &alice_key)?;
        seed_group(&bob, &alice_key)?;

        let (event, _state) = alice.create_signed_group_role_change(
            "group_test",
            "alice_device",
            "bob_device",
            "admin",
        )?;

        let mut forged = event.clone();
        if let ramflux_protocol::GroupEventBody::RoleChanged { new_role, .. } = &mut forged.body {
            *new_role = "bot".to_owned();
        }
        assert!(bob.apply_group_role_change(&forged).is_err());

        let mut wrong_epoch = event.clone();
        if let ramflux_protocol::GroupEventBody::RoleChanged { previous_epoch, .. } =
            &mut wrong_epoch.body
        {
            *previous_epoch = 99;
        }
        let branch = alice.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        wrong_epoch.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(branch, &wrong_epoch)?;
        assert!(matches!(
            bob.apply_group_role_change(&wrong_epoch),
            Err(SdkError::Storage(StorageError::GroupControlEpochMismatch { .. }))
        ));

        bob.apply_group_role_change(&event)?;
        assert!(matches!(
            bob.apply_group_role_change(&event),
            Err(SdkError::Storage(StorageError::GroupControlReplay(_)))
        ));
        Ok(())
    }

    #[test]
    fn signed_group_invite_accept_enforces_state_expiry_and_bound_invitee_key()
    -> Result<(), SdkError> {
        let alice_seed = [0x62; 32];
        let bob_seed = [0x63; 32];
        let carol_seed = [0x64; 32];
        let alice_key = device_public_key("alice", "alice_device", alice_seed);
        let bob_key = device_public_key("bob", "bob_device", bob_seed);
        let carol_key = device_public_key("carol", "carol_device", carol_seed);
        let alice = group_client("alice_s46", "alice", "alice_device", alice_seed)?;
        let bob = group_client("bob_s46", "bob", "bob_device", bob_seed)?;
        let carol = group_client("carol_s46", "carol", "carol_device", carol_seed)?;
        seed_group(&alice, &alice_key)?;
        seed_group(&bob, &alice_key)?;
        seed_group(&carol, &alice_key)?;
        seed_member_key(&alice, "bob_device", &bob_key)?;
        seed_member_key(&bob, "bob_device", &bob_key)?;
        seed_member_key(&carol, "bob_device", &bob_key)?;

        let (invite, _state) = alice.create_signed_group_member_invite(
            "group_test",
            "alice_device",
            "carol_device",
            &carol_key,
            "member",
            4_000_000_000,
            "unit test",
        )?;
        let invite_id = invite_id_from_event(&invite)?;
        bob.apply_group_control_event(&invite)?;
        carol.apply_group_control_event(&invite)?;

        assert!(matches!(
            bob.create_signed_group_member_accept("group_test", "bob_device", &invite_id),
            Err(SdkError::Protocol(_))
        ));

        let (accept, carol_state) =
            carol.create_signed_group_member_accept("group_test", "carol_device", &invite_id)?;
        assert!(carol_state.members.contains("carol_device"));
        let alice_state = alice.apply_group_control_event(&accept)?;
        assert!(alice_state.members.contains("carol_device"));
        assert!(matches!(
            carol.create_signed_group_member_accept("group_test", "carol_device", &invite_id),
            Err(SdkError::Storage(StorageError::GroupInviteInvalidState { .. }))
        ));

        let expired_group = "group_expired";
        seed_group_named(&alice, expired_group, &alice_key)?;
        seed_group_named(&carol, expired_group, &alice_key)?;
        let (expired_invite, _state) = alice.create_signed_group_member_invite(
            expired_group,
            "alice_device",
            "carol_device",
            &carol_key,
            "member",
            1,
            "unit test",
        )?;
        let expired_invite_id = invite_id_from_event(&expired_invite)?;
        carol.apply_group_control_event(&expired_invite)?;
        assert!(matches!(
            carol.create_signed_group_member_accept(
                expired_group,
                "carol_device",
                &expired_invite_id
            ),
            Err(SdkError::Storage(StorageError::GroupInviteExpired(_)))
        ));
        Ok(())
    }

    #[test]
    fn signed_group_kick_ban_and_delete_apply_authoritatively() -> Result<(), SdkError> {
        let alice_seed = [0x52; 32];
        let bob_seed = [0x53; 32];
        let alice_key = device_public_key("alice", "alice_device", alice_seed);
        let bob_key = device_public_key("bob", "bob_device", bob_seed);
        let alice = group_client("alice_s45", "alice", "alice_device", alice_seed)?;
        let bob = group_client("bob_s45", "bob", "bob_device", bob_seed)?;
        seed_group(&alice, &alice_key)?;
        seed_group(&bob, &alice_key)?;
        seed_member_key(&alice, "bob_device", &bob_key)?;
        seed_member_key(&bob, "bob_device", &bob_key)?;

        alice.account_db()?.send_direct_message(
            "group_test",
            "msg_from_bob",
            "bob_device",
            b"ciphertext",
        )?;
        let epoch_before_delete = alice.group_state("group_test")?.group_epoch;
        let (_delete, delete_state) = alice.create_signed_group_message_delete(
            "group_test",
            "alice_device",
            "msg_from_bob",
            "group_tombstone",
            "unit test",
        )?;
        assert_eq!(delete_state.group_epoch, epoch_before_delete);

        let (kick, _state) = alice.create_signed_group_member_kick(
            "group_test",
            "alice_device",
            "bob_device",
            "unit test",
        )?;
        bob.apply_group_control_event(&kick)?;
        assert!(!bob.group_state("group_test")?.members.contains("bob_device"));
        assert!(matches!(
            bob.apply_group_control_event(&kick),
            Err(SdkError::Storage(StorageError::GroupControlReplay(_)))
        ));

        let alice_ban = group_client("alice_s45_ban", "alice", "alice_device", alice_seed)?;
        seed_group(&alice_ban, &alice_key)?;
        seed_member_key(&alice_ban, "bob_device", &bob_key)?;
        let (_ban, state) = alice_ban.create_signed_group_member_ban(
            "group_test",
            "alice_device",
            "bob_device",
            "unit test",
        )?;
        assert!(!state.members.contains("bob_device"));
        assert!(matches!(
            alice_ban.add_group_member("group_test", "bob_device", "member"),
            Err(SdkError::Storage(StorageError::GroupPermissionDenied))
        ));
        Ok(())
    }
}
