// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant generated Control Inner conversion and native payload checks (S10a P15).
//! Native adapters retain their authority checks; all receive effects join W1.
mod receive;
use super::generated_content::GeneratedEventStream;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use ramflux_protocol::message::registry::CONTROLS;
use ramflux_protocol::message::validation::ValidationError;

/// Operation number and payload tag for one Control oneof arm.
fn payload_operation_and_tag(payload: &g::control::Payload) -> (u32, u32) {
    match payload {
        g::control::Payload::Reset(_) => (1, 16),
        g::control::Payload::ResetAck(_) => (2, 17),
        g::control::Payload::ContactControl(_) => (3, 18),
        g::control::Payload::GroupState(_) => (4, 19),
        g::control::Payload::GroupKeyControl(_) => (5, 20),
        g::control::Payload::OwnContactSync(_) => (6, 21),
        g::control::Payload::OwnHistory(_) => (7, 22),
        g::control::Payload::HomeMigration(_) => (8, 23),
        g::control::Payload::RecoveryControl(_) => (9, 24),
        g::control::Payload::LivePresence(_) => (10, 25),
        g::control::Payload::A2i(_) => (11, 26),
        g::control::Payload::ObjectRevoke(_) => (12, 27),
        g::control::Payload::OwnContactTombstone(_) => (13, 28),
        g::control::Payload::OwnGroupConsent(_) => (14, 29),
        g::control::Payload::OwnMessageCopy(_) => (15, 30),
        g::control::Payload::Friend(_) => (16, 31),
    }
}

/// Build a Control whose operation matches the payload arm.
/// # Errors
/// Returns an operation mismatch if the operation cannot be represented.
pub fn control_from_payload(payload: g::control::Payload) -> Result<g::Control, SdkError> {
    let (operation, _) = payload_operation_and_tag(&payload);
    Ok(g::Control {
        operation: i32::try_from(operation).map_err(|_| operation_mismatch())?,
        payload: Some(payload),
    })
}

/// Exact CONTROLS pairing: one operation, one payload tag.
/// # Errors
/// Refuses a missing payload or a payload arm that disagrees with `operation`.
pub fn validate_control_operation(control: &g::Control) -> Result<(), SdkError> {
    let Some(payload) = control.payload.as_ref() else {
        return Err(operation_mismatch());
    };
    let (operation, tag) = payload_operation_and_tag(payload);
    let Some(binding) =
        CONTROLS.iter().find(|binding| binding.operation == operation && binding.tag == tag)
    else {
        return Err(operation_mismatch());
    };
    if u32::try_from(control.operation).ok() != Some(binding.operation) {
        return Err(operation_mismatch());
    }
    Ok(())
}

/// Native payload checks that proto optionality does not encode.
/// # Errors
/// Refuses a mismatched arm or a payload that fails its named native rule.
pub fn validate_control_native(control: &g::Control) -> Result<(), SdkError> {
    validate_control_operation(control)?;
    match control.payload.as_ref() {
        Some(g::control::Payload::Reset(_) | g::control::Payload::ResetAck(_)) => Ok(()),
        Some(g::control::Payload::ContactControl(body)) => require_canonical(
            body.consent.as_ref().map(|leaf| leaf.canonical.as_slice()),
            "contact control requires native consent",
        ),
        Some(g::control::Payload::GroupState(body)) => validate_group_state(body),
        Some(g::control::Payload::GroupKeyControl(body)) => validate_group_key(body),
        Some(g::control::Payload::OwnContactSync(body)) => validate_own_contact_sync(body),
        Some(g::control::Payload::OwnHistory(page)) => {
            if page.transfer_id.is_empty() {
                Err(refused("own history requires a transfer id"))
            } else {
                Ok(())
            }
        }
        Some(g::control::Payload::HomeMigration(body)) => require_canonical(
            body.proposal.as_ref().map(|leaf| leaf.canonical.as_slice()),
            "home migration requires native authorization",
        ),
        Some(g::control::Payload::RecoveryControl(body)) => validate_recovery(body),
        Some(g::control::Payload::LivePresence(body)) => {
            if body.epoch == 0 || body.subjects.is_empty() {
                Err(refused("live presence requires an epoch and subjects"))
            } else {
                Ok(())
            }
        }
        Some(g::control::Payload::A2i(body)) => validate_a2i_domain(body),
        Some(g::control::Payload::ObjectRevoke(body)) => validate_object_revoke_fields(body),
        Some(g::control::Payload::OwnContactTombstone(body)) => {
            if body.link.is_none() || body.decided_at.is_none() {
                Err(refused("own contact tombstone requires a link and decided_at"))
            } else {
                Ok(())
            }
        }
        Some(g::control::Payload::OwnGroupConsent(body)) => validate_own_group_consent(body),
        Some(g::control::Payload::OwnMessageCopy(body)) => validate_own_message_copy(body),
        Some(g::control::Payload::Friend(body)) => validate_friend(body),
        None => Err(operation_mismatch()),
    }
}

/// Sender must own the received object reference.
/// # Errors
/// Refuses missing revoke fields or a sender that is not the object owner.
pub fn authorize_object_revoke(
    sender_principal: &str,
    object_owner: &str,
    revoke: &g::ObjectRevokeAccess,
) -> Result<(), SdkError> {
    validate_object_revoke_fields(revoke)?;
    if sender_principal.is_empty() || sender_principal != object_owner {
        return Err(refused("object revoke requires the object owner"));
    }
    Ok(())
}

fn validate_a2i_domain(event: &g::A2iControlEvent) -> Result<(), SdkError> {
    match event.control_domain.as_ref().and_then(|domain| domain.value.as_ref()) {
        Some(
            g::control_domain::Value::Message(_)
            | g::control_domain::Value::Conversation(_)
            | g::control_domain::Value::A2ui(_)
            | g::control_domain::Value::McpTool(_),
        ) => Ok(()),
        None => Err(refused("a2i control requires a typed domain")),
    }
}

fn validate_group_state(state: &g::GroupStateControl) -> Result<(), SdkError> {
    match state.body.as_ref().and_then(|body| body.value.as_ref()) {
        Some(g::group_control_body::Value::Request(request)) => {
            require_canonical(
                request.request.as_ref().map(|leaf| leaf.canonical.as_slice()),
                "group request requires native change bytes",
            )?;
            let Some(route) = request.federation.as_ref() else {
                return Err(refused("group request requires a federation route"));
            };
            if route.federation_url.is_empty()
                || route.source_node_id.is_empty()
                || route.target_node_id.is_empty()
            {
                return Err(refused("group request federation route is incomplete"));
            }
            Ok(())
        }
        Some(g::group_control_body::Value::Result(result)) => require_canonical(
            result.result.as_ref().map(|leaf| leaf.canonical.as_slice()),
            "group result requires native change bytes",
        ),
        Some(g::group_control_body::Value::DeviceSet(device_set)) => {
            if device_set.group_id.is_empty() || device_set.device_set_epoch == 0 {
                Err(refused("group device set requires group_id and beacon epoch"))
            } else {
                Ok(())
            }
        }
        Some(g::group_control_body::Value::Transfer(transfer)) => validate_transfer(transfer),
        None => Err(refused("group state requires a typed body")),
    }
}

fn validate_transfer(transfer: &g::GroupControlBodyTransfer) -> Result<(), SdkError> {
    let Some(control) = transfer.control.as_ref() else {
        return Err(refused("group transfer requires TransferControl"));
    };
    match control.body.as_ref().and_then(|body| body.value.as_ref()) {
        Some(g::transfer_body::Value::Probe(wrapper)) => {
            let Some(probe) = wrapper.probe.as_ref() else {
                return Err(refused("group transfer probe is missing"));
            };
            if probe.id.is_empty() || probe.issued_at == 0 || probe.expires_at == 0 {
                Err(refused("group transfer probe requires id and lifetime"))
            } else {
                Ok(())
            }
        }
        Some(g::transfer_body::Value::Head(wrapper)) => {
            let Some(head) = wrapper.reply.as_ref() else {
                return Err(refused("group transfer head is missing"));
            };
            if head.proposal.is_empty() || head.issued_at == 0 || head.expires_at == 0 {
                Err(refused("group transfer head requires proposal and lifetime"))
            } else {
                Ok(())
            }
        }
        None => Err(refused("group transfer requires Probe or Head")),
    }
}

fn validate_group_key(body: &g::GroupKeyControl) -> Result<(), SdkError> {
    let Some(distribution) = body.distribution.as_ref() else {
        return Err(refused("group key requires a distribution"));
    };
    if distribution.group_id.is_empty()
        || distribution.sender_id.is_empty()
        || distribution.group_key_epoch == 0
        || distribution.sender_key_seed.is_empty()
    {
        return Err(refused("group key distribution requires group, sender, epoch and seed"));
    }
    Ok(())
}

fn validate_own_contact_sync(body: &g::OwnContactSync) -> Result<(), SdkError> {
    let Some(manifest) = body.manifest.as_ref() else {
        return Err(refused("own contact sync requires a device manifest"));
    };
    if manifest.principal_id.is_empty() || body.link.is_none() {
        return Err(refused("own contact sync requires principal and friend link"));
    }
    Ok(())
}

fn validate_recovery(body: &g::RecoveryControl) -> Result<(), SdkError> {
    match body.payload.as_ref() {
        Some(g::recovery_control::Payload::Invite(invite)) => {
            if invite.invite_id.is_empty()
                || invite.inviter_principal_id.is_empty()
                || invite.guardian_principal_id.is_empty()
                || invite.issued_at == 0
                || invite.expires_at == 0
            {
                Err(refused("guardian invite requires identities and lifetime"))
            } else {
                Ok(())
            }
        }
        Some(g::recovery_control::Payload::Accept(accept)) => {
            if accept.accept_id.is_empty()
                || accept.invite_id.is_empty()
                || accept.owner_principal_id.is_empty()
                || accept.guardian_principal_id.is_empty()
            {
                Err(refused("guardian accept requires identities"))
            } else {
                Ok(())
            }
        }
        None => Err(refused("recovery control requires Invite or Accept")),
    }
}

fn validate_own_group_consent(body: &g::OwnGroupConsent) -> Result<(), SdkError> {
    if body.actor.is_none()
        || body.snapshot.is_none()
        || body.signature.is_empty()
        || body.issued_at == 0
        || body.expires_at == 0
    {
        return Err(refused("own group consent requires actor, snapshot, signature and lifetime"));
    }
    Ok(())
}

fn validate_own_message_copy(body: &g::OwnMessageCopy) -> Result<(), SdkError> {
    if body.source.is_none()
        || body.target.is_none()
        || body.created_at == 0
        || body.expires_at == 0
    {
        return Err(refused("own message copy requires source, target and lifetime"));
    }
    match body.payload.as_ref() {
        Some(g::own_message_copy::Payload::Item(item)) => {
            if item.exact_inner.is_empty() {
                Err(refused("own message copy HistoryItem requires exact_inner"))
            } else {
                Ok(())
            }
        }
        Some(g::own_message_copy::Payload::Sent(sent)) => {
            if sent.envelope_id.is_empty()
                || sent.message_id.is_empty()
                || sent.sender_id.is_empty()
                || sent.exact_inner.is_empty()
            {
                Err(refused("own message copy OwnSentMessage requires the sent identity fields"))
            } else {
                Ok(())
            }
        }
        None => Err(refused("own message copy requires HistoryItem or OwnSentMessage")),
    }
}

fn validate_friend(body: &g::FriendControl) -> Result<(), SdkError> {
    if !(1..=5).contains(&body.action)
        || body.link_id.is_empty()
        || body.requester.is_empty()
        || body.target.is_empty()
        || body
            .remove_scope
            .as_deref()
            .is_some_and(|scope| !matches!(scope, "me" | "own_devices" | "both"))
        || (body.remove_scope.is_some() && body.action != 3)
        || (body.blocked && body.action != 4)
        || (body.capability_revoked_at.is_some() && !matches!(body.action, 3 | 4))
    {
        return Err(refused("friend control requires action 1-5 and link identities"));
    }
    Ok(())
}

fn validate_object_revoke_fields(revoke: &g::ObjectRevokeAccess) -> Result<(), SdkError> {
    if revoke.object_id.is_empty()
        || revoke.recipient_principal_id.is_empty()
        || revoke.link_id.is_empty()
        || revoke.effective_at == 0
    {
        return Err(refused("object revoke requires object, recipient, link and effective_at"));
    }
    Ok(())
}

fn require_canonical(bytes: Option<&[u8]>, message: &str) -> Result<(), SdkError> {
    if bytes.is_some_and(|value| !value.is_empty()) { Ok(()) } else { Err(refused(message)) }
}

fn operation_mismatch() -> SdkError {
    SdkError::LocalBus(ValidationError::Operation.to_string())
}

fn refused(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

impl RamfluxClient {
    /// Encode a generated Control Inner. Additive candidate API; does not send or persist.
    /// # Errors
    /// Rejects a mismatched operation/payload arm, a failed native check, or invalid Inner.
    pub fn encode_generated_control(
        stream: &mut GeneratedEventStream,
        event_id: Vec<u8>,
        control: g::Control,
    ) -> Result<Vec<u8>, SdkError> {
        validate_control_native(&control)?;
        let identity = stream.next(event_id)?;
        Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Control(control)) },
        )
    }

    /// Candidate Control operation/payload and native checks. Does not send or persist.
    /// # Errors
    /// Same as [`validate_control_native`].
    pub fn validate_generated_control(control: &g::Control) -> Result<(), SdkError> {
        validate_control_native(control)
    }

    /// Candidate object-revoke ownership check. Does not send or persist.
    /// # Errors
    /// Same as [`authorize_object_revoke`].
    pub fn authorize_generated_object_revoke(
        sender_principal: &str,
        object_owner: &str,
        revoke: &g::ObjectRevokeAccess,
    ) -> Result<(), SdkError> {
        authorize_object_revoke(sender_principal, object_owner, revoke)
    }

    /// Build a Control whose operation matches the payload arm.
    /// # Errors
    /// Same as [`control_from_payload`].
    pub fn generated_control_from_payload(
        payload: g::control::Payload,
    ) -> Result<g::Control, SdkError> {
        control_from_payload(payload)
    }
}

#[cfg(test)]
mod tests;
