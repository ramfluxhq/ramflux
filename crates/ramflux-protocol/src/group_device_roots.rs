// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed version-two group controls bind literal device names to explicit identity roots.
use crate::{GroupEvent, GroupEventBody, ProtocolError, validate_device_name};
use serde::{Deserialize, Serialize};
/// Signed extension key in a version-two group client event.
pub const GROUP_DEVICE_ROOTS_EXTENSION: &str = "group_device_roots";
/// Root commitments for the actor and optional member named by the existing event body.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupDeviceRoots {
    pub schema: String,
    pub actor_principal_commitment: String,
    pub member_principal_commitment: Option<String>,
}
impl GroupDeviceRoots {
    /// Read a signed context; legacy v1 controls return None and cannot select roots by name.
    /// # Errors
    /// Rejects missing, malformed, downgraded or unbound version-two contexts.
    pub fn from_event(event: &GroupEvent) -> Result<Option<Self>, ProtocolError> {
        let value = event.ext.ext.get(GROUP_DEVICE_ROOTS_EXTENSION);
        if event.version == 1 && event.schema == "ramflux.client_event.v1" && value.is_none() {
            return Ok(None);
        }
        if event.version != 2 || event.schema != "ramflux.client_event.v2" {
            return Err(invalid("group control version/root context mismatch"));
        }
        let roots: Self =
            serde_json::from_value(value.cloned().ok_or_else(|| invalid("group roots missing"))?)?;
        if roots.schema != "ramflux.group.device_roots.v2" {
            return Err(invalid("unsupported group root schema"));
        }
        validate_device_name(&event.actor_device_id)?;
        root(&roots.actor_principal_commitment)?;
        match (group_event_member(&event.body), roots.member_principal_commitment.as_deref()) {
            (Some(member), Some(commitment)) => {
                validate_device_name(member)?;
                root(commitment)?;
            }
            (None, None) => {}
            _ => return Err(invalid("group member root binding missing or unexpected")),
        }
        if let GroupEventBody::MemberJoined { actor_principal_commitment, .. } = &event.body
            && actor_principal_commitment != &roots.actor_principal_commitment
        {
            return Err(invalid("joined actor root differs from signed context"));
        }
        if let GroupEventBody::MemberAccepted { invitee_identity, .. } = &event.body
            && (invitee_identity != &event.actor_device_id
                || roots.member_principal_commitment.as_deref()
                    != Some(&roots.actor_principal_commitment))
        {
            return Err(invalid("accept actor/member root mismatch"));
        }
        Ok(Some(roots))
    }
}
/// The existing group member selector; message ids and group ids are never device selectors.
#[must_use]
pub fn group_event_member(body: &GroupEventBody) -> Option<&str> {
    match body {
        GroupEventBody::MemberInvitedV2 { invitee_identity, .. }
        | GroupEventBody::MemberAccepted { invitee_identity, .. } => Some(invitee_identity),
        GroupEventBody::MemberJoined { joined_identity, .. } => Some(joined_identity),
        GroupEventBody::MemberRemoved { removed_identity, .. } => Some(removed_identity),
        GroupEventBody::MemberBanned { banned_identity, .. } => Some(banned_identity),
        GroupEventBody::RoleChanged { target_identity, .. } => Some(target_identity),
        _ => None,
    }
}
fn root(value: &str) -> Result<(), ProtocolError> {
    let bytes =
        crate::decode_base64url(value).map_err(|_| invalid("invalid group root commitment"))?;
    if bytes.len() != 32 || crate::encode_base64url(&bytes) != value {
        return Err(invalid("invalid group root commitment"));
    }
    Ok(())
}
fn invalid(reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidIdentityRecord(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> GroupEvent {
        GroupEvent {
            schema: "ramflux.client_event.v2".into(),
            version: 2,
            domain: crate::domain::GROUP_EVENT.into(),
            ext: crate::Ext::default(),
            signed: crate::SignedFields {
                signing_key_id: "actor".into(),
                signature_alg: crate::SignatureAlg::Ed25519,
                signature: String::new(),
            },
            event_id: "join".into(),
            event_type: "group.member_joined".into(),
            actor_principal_id: "alice".into(),
            actor_device_id: "phone".into(),
            device_counter: 1,
            lamport_time: 1,
            created_at: 1,
            causal_prev: vec![],
            body: GroupEventBody::MemberJoined {
                group_id: "g".into(),
                previous_epoch: 1,
                new_group_epoch: 2,
                joined_identity: "shared".into(),
                joined_role: "member".into(),
                actor_role: "owner".into(),
                actor_principal_commitment: crate::encode_base64url([1; 32]),
                actor_device_signing_public_key: "key".into(),
                max_members: 64,
                new_member_history: "none".into(),
            },
        }
    }
    fn attach(event: &mut GroupEvent, member: Option<String>) -> Result<(), ProtocolError> {
        event.ext.ext.insert(
            GROUP_DEVICE_ROOTS_EXTENSION.into(),
            serde_json::to_value(GroupDeviceRoots {
                schema: "ramflux.group.device_roots.v2".into(),
                actor_principal_commitment: crate::encode_base64url([1; 32]),
                member_principal_commitment: member,
            })?,
        );
        Ok(())
    }
    #[test]
    fn signed_group_root_context_rejects_missing_downgraded_and_malformed_bindings()
    -> Result<(), ProtocolError> {
        let mut control = event();
        assert!(GroupDeviceRoots::from_event(&control).is_err());
        attach(&mut control, None)?;
        assert!(GroupDeviceRoots::from_event(&control).is_err());
        attach(&mut control, Some("invalid-root".into()))?;
        assert!(GroupDeviceRoots::from_event(&control).is_err());
        attach(&mut control, Some(crate::encode_base64url([2; 32])))?;
        assert!(GroupDeviceRoots::from_event(&control)?.is_some());
        control.version = 1;
        control.schema = "ramflux.client_event.v1".into();
        assert!(GroupDeviceRoots::from_event(&control).is_err());
        control.ext.ext.clear();
        assert!(GroupDeviceRoots::from_event(&control)?.is_none());
        Ok(())
    }
    #[test]
    fn actor_body_binding_and_live_reserved_names_are_enforced() -> Result<(), ProtocolError> {
        let mut control = event();
        attach(&mut control, Some(crate::encode_base64url([2; 32])))?;
        if let GroupEventBody::MemberJoined { actor_principal_commitment, .. } = &mut control.body {
            *actor_principal_commitment = crate::encode_base64url([3; 32]);
        }
        assert!(GroupDeviceRoots::from_event(&control).is_err());
        for name in ["root~literal", "legacy~literal", "", "control\nname"] {
            assert!(validate_device_name(name).is_err());
        }
        assert!(validate_device_name("phone").is_ok());
        Ok(())
    }
}
