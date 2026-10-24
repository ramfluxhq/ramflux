// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn create_group(&self, group_id: &str, creator_id: &str) -> Result<GroupState, SdkError> {
        let address = ramflux_protocol::parse_qualified_device_id(creator_id)?;
        let raw = address.as_ref().map_or(creator_id, |(_, raw)| raw.as_str());
        ramflux_protocol::validate_device_name(raw)?;
        self.account_db()?.write_transaction(|| {
            let group = self.account_db()?.create_group(group_id, raw)?;
            if self.device_branch.as_ref().is_some_and(|own| own.device_id == raw)
                && (address.is_none() || self.local_device_reference(raw)? == creator_id)
            {
                self.pin_local_group_member(group_id)?;
            } else if address.is_some() {
                self.pin_joined_group_member(group_id, creator_id)?;
            }
            Ok(group)
        })
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the member cannot be added.
    pub fn add_group_member(
        &self,
        group_id: &str,
        member_id: &str,
        role: &str,
    ) -> Result<GroupState, SdkError> {
        self.add_group_member_address(group_id, member_id, role, None)
    }
    pub(crate) fn add_group_member_with_root(
        &self,
        group: &str,
        member: &str,
        role: &str,
        root: &str,
    ) -> Result<GroupState, SdkError> {
        self.add_group_member_address(group, member, role, Some(root))
    }
    fn add_group_member_address(
        &self,
        group_id: &str,
        member_id: &str,
        role: &str,
        root: Option<&str>,
    ) -> Result<GroupState, SdkError> {
        let explicit = ramflux_protocol::parse_qualified_device_id(member_id)?;
        let raw = explicit.as_ref().map_or(member_id, |(_, raw)| raw.as_str());
        ramflux_protocol::validate_device_name(raw)?;
        let reference = if let Some(root) = root {
            ramflux_protocol::qualified_device_id(root, raw)?
        } else if explicit.is_some() {
            member_id.to_owned()
        } else {
            self.group_device_reference(group_id, raw)?
        };
        self.account_db()?.write_transaction(|| {
            let state = self.account_db()?.add_group_member(group_id, raw, role)?;
            self.pin_joined_group_member(group_id, &reference)?;
            Ok(state)
        })
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the member cannot be removed.
    pub fn remove_group_member(
        &self,
        group_id: &str,
        actor_id: &str,
        target_member_id: &str,
    ) -> Result<GroupState, SdkError> {
        let actor = self.local_device_identity(actor_id)?;
        if let Some(target) = self.group_route_identity(group_id, target_member_id)? {
            Ok(self.account_db()?.remove_group_member(group_id, &actor, &target)?)
        } else {
            Ok(self.account_db()?.legacy_remove_group_member(group_id, &actor, target_member_id)?)
        }
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
        self.group_control_signer(event, group_id)?;
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
            return Err(SdkError::LocalBus("expected group join".into()));
        };
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if joined_identity != &local.device_id {
            return Err(SdkError::LocalBus("bootstrap joined identity is not local".into()));
        }
        self.bootstrap_group_member_reference(event)?;
        self.account_db()?.write_transaction(|| {
            let state = self.account_db()?.apply_bootstrap_group_member_join(
                &GroupMemberJoinWrite {
                    group_id: group_id.clone(),
                    event_id: event.event_id.clone(),
                    actor_device_id: event.actor_device_id.clone(),
                    joined_identity: joined_identity.clone(),
                    joined_role: joined_role.clone(),
                    actor_role: actor_role.clone(),
                    actor_principal_commitment: actor_principal_commitment.clone(),
                    actor_device_signing_public_key: actor_device_signing_public_key.clone(),
                    previous_epoch: *previous_epoch,
                    new_group_epoch: *new_group_epoch,
                    max_members: *max_members,
                    new_member_history: new_member_history.clone(),
                },
                &self
                    .device_identity_for_root(actor_principal_commitment, &event.actor_device_id)?,
            )?;
            self.pin_local_group_member(group_id)?;
            self.pin_joined_group_member(
                group_id,
                &ramflux_protocol::qualified_device_id(
                    actor_principal_commitment,
                    &event.actor_device_id,
                )?,
            )?;
            Ok(state)
        })
    }

    pub(crate) async fn prepare_group_join_identity(
        &self,
        gateway: &GatewaySessionConfig,
        event: &ramflux_protocol::GroupEvent,
    ) -> Result<(), SdkError> {
        if let ramflux_protocol::GroupEventBody::MemberJoined {
            group_id, joined_identity, ..
        } = &event.body
        {
            self.verify_group_control_event(event)?;
            if !matches!(
                self.account_db()?
                    .group_member_role_metadata(group_id, &event.actor_device_id)?
                    .as_deref(),
                Some("owner" | "admin")
            ) {
                return Err(StorageError::GroupPermissionDenied.into());
            }
            let reference = self.group_event_member_reference(event)?.ok_or_else(|| {
                SdkError::InboundPending("joined member root context absent".into())
            })?;
            let (root, raw) = ramflux_protocol::parse_qualified_device_id(&reference)?
                .ok_or_else(|| SdkError::InboundPending("joined member root absent".into()))?;
            if self.account_db()?.client_record("device", &reference)?.is_none()
                && self.device_branch.as_ref().is_none_or(|own| own.device_id != *joined_identity)
            {
                self.resolve_target_principal_commitment(gateway, Some(&root), &raw).await?;
            }
        }
        Ok(())
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
        Ok(self.account_db()?.apply_group_role_change(
            &GroupRoleChangeWrite {
                group_id: group_id.to_owned(),
                event_id: event.event_id.clone(),
                actor_device_id: event.actor_device_id.clone(),
                target_member_id: target_identity.to_owned(),
                previous_epoch,
                new_group_epoch,
                new_role: new_role.to_owned(),
            },
            &self.group_control_actor_identity(event, group_id)?,
        )?)
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
        let reference = self
            .group_event_member_reference(event)?
            .ok_or_else(|| SdkError::InboundPending("joined member root unavailable".into()))?;
        self.account_db()?.write_transaction(|| {
            let state = self.account_db()?.apply_group_member_join(
                &GroupMemberJoinWrite {
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
                },
                &self
                    .device_identity_for_root(actor_principal_commitment, &event.actor_device_id)?,
            )?;
            self.pin_joined_group_member(group_id, &reference)?;
            Ok(state)
        })
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
        Ok(self.account_db()?.apply_group_member_kick(
            &GroupMemberKickWrite {
                group_id: group_id.to_owned(),
                event_id: event.event_id.clone(),
                actor_device_id: event.actor_device_id.clone(),
                target_member_id: removed_identity.to_owned(),
                previous_epoch,
                new_group_epoch,
                reason: reason.to_owned(),
            },
            &self.group_control_actor_identity(event, group_id)?,
        )?)
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
        Ok(self.account_db()?.apply_group_member_ban(
            &GroupMemberBanWrite {
                group_id: group_id.to_owned(),
                event_id: event.event_id.clone(),
                actor_device_id: event.actor_device_id.clone(),
                target_member_id: banned_identity.to_owned(),
                previous_epoch,
                new_group_epoch,
                reason: reason.to_owned(),
                ban_id: ban_id.to_owned(),
            },
            &self.group_control_actor_identity(event, group_id)?,
        )?)
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
        Ok(self.account_db()?.apply_group_message_delete(
            &GroupMessageDeleteWrite {
                group_id: group_id.to_owned(),
                event_id: event.event_id.clone(),
                actor_device_id: event.actor_device_id.clone(),
                target_message_id: target_message_id.to_owned(),
                group_epoch,
                delete_scope: delete_scope.to_owned(),
                tombstone_id: tombstone_id.to_owned(),
                reason: reason.to_owned(),
            },
            &self.group_control_actor_identity(event, group_id)?,
        )?)
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
        self.account_db()?.write_transaction(|| {
            let state = self.account_db()?.apply_group_member_invite(
                &GroupInviteWrite {
                    group_id: group_id.to_owned(),
                    event_id: event.event_id.clone(),
                    actor_device_id: event.actor_device_id.clone(),
                    invite_id: invite_id.to_owned(),
                    invitee_identity: invitee_identity.to_owned(),
                    invitee_principal_commitment: ramflux_protocol::parse_qualified_device_id(
                        &self.group_event_member_reference(event)?.ok_or_else(|| {
                            SdkError::InboundPending("invited member root absent".into())
                        })?,
                    )?
                    .ok_or_else(|| SdkError::InboundPending("invited member root absent".into()))?
                    .0,
                    invitee_signing_public_key: invitee_signing_public_key.to_owned(),
                    invited_role: invited_role.to_owned(),
                    group_epoch,
                    expires_at,
                    reason: reason.to_owned(),
                },
                &self.group_control_actor_identity(event, group_id)?,
            )?;
            self.remember_group_invite_root(event, group_id, invitee_identity, invite_id)?;
            Ok(state)
        })
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
        let reference = self
            .group_event_member_reference(event)?
            .ok_or_else(|| SdkError::InboundPending("accepted member root absent".into()))?;
        self.account_db()?.write_transaction(|| {
            let state = self.account_db()?.apply_group_member_accept(
                &GroupInviteAcceptWrite {
                    group_id: group_id.to_owned(),
                    event_id: event.event_id.clone(),
                    actor_device_id: event.actor_device_id.clone(),
                    invite_id: invite_id.to_owned(),
                    invitee_identity: invitee_identity.to_owned(),
                    accepted_role: accepted_role.to_owned(),
                    previous_epoch,
                    new_group_epoch,
                    now: now_unix_timestamp(),
                },
                &self.device_identity(&reference)?,
            )?;
            self.pin_joined_group_member(group_id, &reference)?;
            self.remember_group_invite_root(event, group_id, invitee_identity, invite_id)?;
            Ok(state)
        })
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
        let mut event = ramflux_protocol::GroupEvent {
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
        };
        self.attach_group_device_roots(group_id, &mut event)?;
        Ok(event)
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
        if invite.invitee_identity != actor_device_id {
            return Err(ramflux_protocol::ProtocolError::InvalidIdentityRecord(
                "accept actor differs from invited device",
            )
            .into());
        }

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
        let actor = self
            .local_device_identity(actor_device_id)
            .map_err(|_| SdkError::Storage(StorageError::GroupPermissionDenied))?;
        if actor.root_commitment() != actor_principal_commitment {
            return Err(SdkError::InboundRejected("group join actor root mismatch".into()));
        }
        let group = self.group_state(group_id)?;
        let Some(actor_role) = group.roles.get(actor.device_id()) else {
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
        let device = if let Some(root) = &route.member_principal_commitment {
            self.device_identity_for_root(root, &route.member_id)?
        } else {
            self.device_identity(&self.group_device_reference(group_id, &route.member_id)?)?
        };
        let id = group_member_route_event_id(group_id, &device)?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            let db = self.account_db()?;
            if db.group_member_requires_readd(group_id, &device)? {
                return Err(SdkError::InboundPending(
                    "legacy group member pin requires re-add".into(),
                ));
            }
            // Existing routes retain their original idempotent first-write behavior.
            if let Some(bytes) = self.event_body(&id)? {
                let old: LocalBusGroupMemberRoute = serde_json::from_slice(&bytes)?;
                if old.member_id != device.device_id()
                    || old.member_principal_commitment.as_deref() != Some(device.root_commitment())
                {
                    return Err(SdkError::InboundRejected(
                        "retained group route root mismatch".into(),
                    ));
                }
                db.persist_actor_state(&id, &old)?;
                return Ok(());
            }
            let mut route = route.clone();
            route.member_principal_commitment = Some(device.root_commitment().into());
            if let Some(public) = &route.device_signing_public_key {
                db.persist_group_member_device_key(group_id, &device, public)?;
            }
            db.persist_actor_state(&id, &route)?;
            self.append_event(&id, "group.member.route", &serde_json::to_vec(&route)?)
        })
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
            let Some(device) = self.group_route_identity(group_id, &member_id)? else { continue };
            let event_id = group_member_route_event_id(group_id, &device)?;
            if let Some(bytes) = self.event_body(&event_id)? {
                let route: LocalBusGroupMemberRoute = serde_json::from_slice(&bytes)?;
                if route.member_id != device.device_id()
                    || route
                        .member_principal_commitment
                        .as_deref()
                        .is_some_and(|root| root != device.root_commitment())
                {
                    return Err(SdkError::InboundRejected("group route root mismatch".into()));
                }
                routes.push(route);
            } else if let Some((legacy_device, route)) =
                self.legacy_group_member_route(group_id, &member_id)?
                && legacy_device == device
            {
                routes.push(route);
            }
        }
        Ok(routes)
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod tests;
