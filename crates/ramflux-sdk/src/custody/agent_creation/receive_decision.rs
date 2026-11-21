// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Desktop side of a received decision (contract 7.2 steps 3 and 4). The decision is checked
//! against the stored plan and the current primary branch of the human authority before it is
//! consumed. A deny closes the request and cleans up its pending secrets.
use super::machine::apply_decision;
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use crate::custody::PrimaryVault;
use ramflux_protocol::DeviceSetStatus;
use ramflux_protocol::custody::{
    DeviceRef, DeviceSet, Envelope, decode_register_decision, decode_register_plan,
};

/// The branch signing key of `primary` in the human authority, valid at `now`.
/// # Errors
/// `CustodySetupInvalid` when the primary is not an active device with a current branch.
pub fn primary_branch_public_key(
    human: &Envelope<DeviceSet>,
    primary: &DeviceRef,
    now: u64,
) -> Result<String, SdkError> {
    human
        .body
        .devices
        .iter()
        .find(|device| {
            device.device_id == primary.device_id
                && device.device_epoch == primary.device_epoch
                && matches!(device.status, DeviceSetStatus::Active)
                && device.revoked_at.is_none()
        })
        .and_then(|device| device.branch_certificate.as_ref())
        .filter(|branch| branch.body.not_before <= now && now < branch.body.expires_at)
        .map(|branch| branch.body.branch_signing_public_key.clone())
        .ok_or(SdkError::CustodySetupInvalid)
}

/// Receive one decision packet on the desktop. The request it names must be stored here; its
/// plan supplies the primary whose branch signs it. Approve moves the request to `authorized`;
/// deny refuses it and cleans up. Any other failure leaves the record as it was.
/// # Errors
/// `CustodySetupInvalid` for an unknown request, a decision that does not decode, or a primary
/// that is not current in `human`; `CustodyExpired` past the deadline; vault failures pass through.
pub fn receive_decision(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    human: &Envelope<DeviceSet>,
    decision_bytes: &[u8],
    now: u64,
) -> Result<AgentCreationRecord, SdkError> {
    let decision =
        decode_register_decision(decision_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    let request_id = decision.body.request_id.clone();
    let stored = store.load(&request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
    let plan =
        decode_register_plan(&stored.plan_bytes()?).map_err(|_| SdkError::CustodySetupInvalid)?;
    let key = primary_branch_public_key(human, &plan.human_primary, now)?;
    apply_decision(store, vault, &request_id, decision_bytes, &key, now)
}

/// Receive checks of a decision packet, run before any store effect. The decision must come from
/// the stored plan's human primary, go to its desktop, name the plan's request and stay in the
/// agent scope of the plan.
/// # Errors
/// `InboundRejected` for a sender outside the root or a sibling check that fails; `CustodySetupInvalid`
/// for any endpoint, request or scope mismatch.
pub fn check_received_decision(
    plan: &ramflux_protocol::custody::RegisterPlan,
    decision_bytes: &[u8],
    conversation: &str,
    own_root: &str,
    // (root commitment, device id) of the authenticated sender, and this device.
    source: (&str, &str),
    local_device: &str,
) -> Result<(), SdkError> {
    let (source_root, source_device) = source;
    super::check_sender(own_root, source_root, source_device, local_device)?;
    let decision =
        decode_register_decision(decision_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    if plan.human_primary.account_anchor != own_root
        || plan.human_primary.device_id != source_device
        || plan.desktop.account_anchor != own_root
        || plan.desktop.device_id != local_device
        || decision.body.request_id != plan.request_id
    {
        return Err(SdkError::CustodySetupInvalid);
    }
    super::check_scope(conversation, own_root, plan)
}
