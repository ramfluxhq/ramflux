// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pure receive checks for an agent creation custody packet (contract §7.3, decision D8). They
//! take the authenticated sender and this device as plain fields, so the same rules run in the
//! client receive path and in unit tests over real plans. Nothing here reads a clock or a store.
use crate::SdkError;
use ramflux_protocol::custody::{RegisterPlan, decode_register_plan, validate_register_plan};
use ramflux_protocol::message::dm_scope;

/// The authenticated sender must be a sibling device of this root: same root, and not this device.
/// # Errors
/// `InboundRejected` for a sender outside this root or this device itself.
pub fn check_sender(
    own_root: &str,
    source_root: &str,
    source_device: &str,
    local_device: &str,
) -> Result<(), SdkError> {
    if source_root != own_root {
        return Err(SdkError::InboundRejected("agent custody sender is outside this root".into()));
    }
    if source_device == local_device {
        return Err(SdkError::InboundRejected(
            "agent custody sender must be a sibling device".into(),
        ));
    }
    Ok(())
}

/// The plan must name this root as owner and the authenticated sibling as desktop, and this device
/// as the human primary. A secondary that receives a plan naming another primary refuses.
/// # Errors
/// `CustodySetupInvalid` when any endpoint field disagrees.
pub fn check_plan_endpoints(
    plan: &RegisterPlan,
    own_root: &str,
    source_device: &str,
    local_device: &str,
) -> Result<(), SdkError> {
    if plan.owner_anchor != own_root
        || plan.desktop.account_anchor != own_root
        || plan.desktop.device_id != source_device
        || plan.human_primary.account_anchor != own_root
        || plan.human_primary.device_id != local_device
    {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(())
}

/// The conversation scope of the custody control, `dm_scope::derive(owner, pending agent)`.
/// # Errors
/// `InboundRejected` when the anchors cannot be derived (for example equal roots).
pub fn expected_scope(owner_anchor: &str, agent_anchor: &str) -> Result<String, SdkError> {
    dm_scope::derive(owner_anchor, agent_anchor)
        .map_err(|_| SdkError::InboundRejected("agent custody scope cannot be derived".into()))
}

/// The receiver recomputes the scope from the plan and refuses any other conversation.
/// # Errors
/// `InboundRejected` on a scope mismatch.
pub fn check_scope(
    conversation: &str,
    owner_anchor: &str,
    plan: &RegisterPlan,
) -> Result<(), SdkError> {
    if expected_scope(owner_anchor, &plan.agent_anchor)? != conversation {
        return Err(SdkError::InboundRejected("agent custody scope mismatch".into()));
    }
    Ok(())
}

/// Full receive check of a request packet before any store, UI or signature side effect.
/// # Errors
/// The first failing rule of the sender, endpoint, plan and scope checks.
pub fn check_received_request(
    plan_bytes: &[u8],
    conversation: &str,
    own_root: &str,
    source_root: &str,
    source_device: &str,
    local_device: &str,
) -> Result<RegisterPlan, SdkError> {
    check_sender(own_root, source_root, source_device, local_device)?;
    let plan = decode_register_plan(plan_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    validate_register_plan(&plan).map_err(|_| SdkError::CustodySetupInvalid)?;
    check_plan_endpoints(&plan, own_root, source_device, local_device)?;
    check_scope(conversation, own_root, &plan)?;
    Ok(plan)
}
