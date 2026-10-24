// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed group root context and bounded provenance for legacy invite/accept resolution.
use crate::prelude::*;
use ramflux_protocol::{
    GroupDeviceRoots, GroupEvent, GroupEventBody, group_event_member, parse_qualified_device_id,
    qualified_device_id,
};
use serde::{Deserialize, Serialize};
fn pending() -> SdkError {
    SdkError::InboundPending("group member root context unavailable or ambiguous".into())
}
fn rejected() -> SdkError {
    SdkError::InboundRejected("group control root binding mismatch".into())
}
fn root(reference: &str) -> Result<String, SdkError> {
    parse_qualified_device_id(reference)?.map(|(root, _)| root).ok_or_else(pending)
}
fn invite_key(group: &str, member: &str) -> Result<String, SdkError> {
    Ok(format!(
        "group/invite-root/{}",
        ramflux_protocol::hash_base64url(
            "ramflux.sdk.group.invite_root.v1",
            &ramflux_protocol::canonical_json_bytes(&(group, member))?
        )
    ))
}
fn exact_invite_key(group: &str, invite: &str) -> Result<String, SdkError> {
    Ok(format!(
        "group/invite-record-root/{}",
        ramflux_protocol::hash_base64url(
            "ramflux.sdk.group.invite_record_root.v1",
            &ramflux_protocol::canonical_json_bytes(&(group, invite))?
        )
    ))
}
#[derive(Deserialize, Serialize)]
struct InviteRoot {
    root: String,
    invite_id: String,
    ambiguous: bool,
}
impl RamfluxClient {
    pub(super) fn attach_group_device_roots(
        &self,
        group: &str,
        event: &mut GroupEvent,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let own = root(&self.local_device_reference(&local.device_id)?)?;
        let member = group_event_member(&event.body).map(str::to_owned);
        let member_root = if let Some(member) = member {
            let (commitment, raw) =
                if let Some((commitment, raw)) = parse_qualified_device_id(&member)? {
                    (commitment, raw)
                } else if member == local.device_id {
                    (own.clone(), member.clone())
                } else {
                    (root(&self.group_device_reference(group, &member)?)?, member.clone())
                };
            ramflux_protocol::validate_device_name(&raw)?;
            match &mut event.body {
                GroupEventBody::MemberInvitedV2 { invitee_identity, .. }
                | GroupEventBody::MemberAccepted { invitee_identity, .. } => {
                    *invitee_identity = raw;
                }
                GroupEventBody::MemberJoined { joined_identity, .. } => *joined_identity = raw,
                GroupEventBody::MemberRemoved { removed_identity, .. } => *removed_identity = raw,
                GroupEventBody::MemberBanned { banned_identity, .. } => *banned_identity = raw,
                GroupEventBody::RoleChanged { target_identity, .. } => *target_identity = raw,
                _ => return Err(rejected()),
            }
            Some(commitment)
        } else {
            None
        };
        event.schema = "ramflux.client_event.v2".into();
        event.version = 2;
        event.ext.ext.insert(
            ramflux_protocol::GROUP_DEVICE_ROOTS_EXTENSION.into(),
            serde_json::to_value(GroupDeviceRoots {
                schema: "ramflux.group.device_roots.v2".into(),
                actor_principal_commitment: own,
                member_principal_commitment: member_root,
            })?,
        );
        GroupDeviceRoots::from_event(event)?;
        Ok(())
    }
    pub(super) fn group_event_member_reference(
        &self,
        event: &GroupEvent,
    ) -> Result<Option<String>, SdkError> {
        let Some(member) = group_event_member(&event.body) else { return Ok(None) };
        ramflux_protocol::validate_device_name(member)?;
        if let Some(roots) = GroupDeviceRoots::from_event(event)? {
            return Ok(Some(qualified_device_id(
                &roots.member_principal_commitment.ok_or_else(pending)?,
                member,
            )?));
        }
        if self.device_branch.as_ref().is_some_and(|local| local.device_id == member) {
            return self.local_device_reference(member).map(Some);
        }
        match &event.body {
            GroupEventBody::MemberJoined { group_id, previous_epoch, .. } => {
                self.invited_group_member_reference(group_id, member, *previous_epoch).map(Some)
            }
            GroupEventBody::MemberAccepted { group_id, invite_id, .. } => {
                let root = self
                    .account_db()?
                    .load_actor_state::<String>(&exact_invite_key(group_id, invite_id)?)?
                    .ok_or_else(pending)?;
                Ok(Some(qualified_device_id(&root, member)?))
            }
            GroupEventBody::MemberInvitedV2 { .. } => Ok(None),
            GroupEventBody::MemberRemoved { group_id, .. }
            | GroupEventBody::MemberBanned { group_id, .. }
            | GroupEventBody::RoleChanged { group_id, .. } => {
                self.group_device_reference(group_id, member).map(Some)
            }
            _ => Err(pending()),
        }
    }
    fn invited_group_member_reference(
        &self,
        group: &str,
        member: &str,
        epoch: u64,
    ) -> Result<String, SdkError> {
        let witness = self
            .account_db()?
            .load_actor_state::<InviteRoot>(&invite_key(group, member)?)?
            .ok_or_else(pending)?;
        if witness.ambiguous {
            return Err(pending());
        }
        let invite =
            self.account_db()?.group_invite(group, &witness.invite_id).map_err(|_| pending())?;
        if invite.invite_epoch > epoch
            || invite.invitee_identity != member
            || !matches!(invite.state.as_str(), "pending" | "accepted")
        {
            return Err(pending());
        }
        Ok(qualified_device_id(&witness.root, member)?)
    }
    pub(super) fn remember_group_invite_root(
        &self,
        event: &GroupEvent,
        group: &str,
        member: &str,
        invite: &str,
    ) -> Result<(), SdkError> {
        let Some(reference) = self.group_event_member_reference(event)? else { return Ok(()) };
        let commitment = root(&reference)?;
        let exact = exact_invite_key(group, invite)?;
        if self
            .account_db()?
            .load_actor_state::<String>(&exact)?
            .is_some_and(|old| old != commitment)
        {
            return Err(rejected());
        }
        self.account_db()?.persist_actor_state(&exact, &commitment)?;
        let key = invite_key(group, member)?;
        let db = self.account_db()?;
        let old = db.load_actor_state::<InviteRoot>(&key)?;
        let ambiguous = old.as_ref().is_some_and(|old| old.ambiguous || old.root != commitment);
        db.persist_actor_state(
            &key,
            &InviteRoot { root: commitment, invite_id: invite.into(), ambiguous },
        )?;
        Ok(())
    }
    pub(super) fn group_control_signer(
        &self,
        event: &GroupEvent,
        group: &str,
    ) -> Result<String, SdkError> {
        let roots = GroupDeviceRoots::from_event(event)?;
        let actor = if let Some(roots) = &roots {
            qualified_device_id(&roots.actor_principal_commitment, &event.actor_device_id)?
        } else if matches!(event.body, GroupEventBody::MemberAccepted { .. }) {
            self.group_event_member_reference(event)?.ok_or_else(pending)?
        } else {
            self.group_device_reference(group, &event.actor_device_id)?
        };
        let public = if let GroupEventBody::MemberAccepted { invite_id, invitee_identity, .. } =
            &event.body
        {
            let invite = self.account_db()?.group_invite(group, invite_id)?;
            if invite.invitee_identity != *invitee_identity
                || invitee_identity != &event.actor_device_id
            {
                return Err(rejected());
            }
            if self.group_event_member_reference(event)?.as_deref() != Some(actor.as_str()) {
                return Err(rejected());
            }
            if self
                .account_db()?
                .load_actor_state::<String>(&exact_invite_key(group, invite_id)?)?
                .is_some_and(|expected| root(&actor).is_ok_and(|actual| expected != actual))
            {
                return Err(rejected());
            }
            invite.invitee_signing_public_key
        } else {
            self.account_db()?.group_member_device_key(group, &actor)?.ok_or_else(pending)?
        };
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if actor == self.local_device_reference(&local.device_id)? {
            if event.actor_principal_id != local.principal_id
                || public
                    != ramflux_protocol::encode_base64url(
                        local.signing_key.verifying_key().to_bytes(),
                    )
            {
                return Err(rejected());
            }
        } else {
            if self.account_db()?.client_record("device", &actor)?.is_none() {
                return Err(pending());
            }
            let device = self.trusted_device(&actor)?;
            if device["principal_id"] != event.actor_principal_id
                || device["signing_public_key"] != public
            {
                return Err(rejected());
            }
        }
        // Signature precedes any target-root admission or mutation.
        ramflux_protocol::verify_signed_fields(event, &event.signed, &public)?;
        self.check_group_event_target(event, group)?;
        Ok(public)
    }
    fn check_group_event_target(&self, event: &GroupEvent, group: &str) -> Result<(), SdkError> {
        let Some(reference) = self.group_event_member_reference(event)? else { return Ok(()) };
        let member = group_event_member(&event.body).ok_or_else(pending)?;
        let previous = self.account_db()?.group_member_key_binding_by_name(group, member).map_err(
            |error| match error {
                StorageError::AmbiguousDeviceId(_) => pending(),
                other => other.into(),
            },
        )?;
        if let Some(previous) = previous
            && previous
                .principal_commitment
                .as_deref()
                .is_some_and(|old| root(&reference).is_ok_and(|new| new != old))
        {
            return Err(rejected());
        }
        if matches!(
            event.body,
            GroupEventBody::MemberRemoved { .. }
                | GroupEventBody::MemberBanned { .. }
                | GroupEventBody::RoleChanged { .. }
        ) && self.group_device_reference(group, member)? != reference
        {
            return Err(rejected());
        }
        Ok(())
    }
    pub(super) fn bootstrap_group_member_reference(
        &self,
        event: &GroupEvent,
    ) -> Result<String, SdkError> {
        let member = self.group_event_member_reference(event)?.ok_or_else(pending)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if member != self.local_device_reference(&local.device_id)? {
            return Err(rejected());
        }
        Ok(member)
    }
}
