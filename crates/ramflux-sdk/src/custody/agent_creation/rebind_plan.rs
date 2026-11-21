// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Rebind request of a bound agent after a human primary transfer (AGENT-IDENTITY-01 stage D3,
//! contract 7.5). The desktop freezes a `purpose = rebind` plan for the new primary: the agent
//! anchor, principal, master key, self-signing key and branch keys stay the same, the custodian
//! primary and the human head are the new ones, the predecessor hashes are the stored agent's, and
//! the range is the next one. Capabilities and the branch lease never widen. No vault item is
//! written here: the agent's master and keys are reused in stage D4.
//!
//! Pattern copied: `machine.rs` `begin` (plan freezing, the record written before the plan is
//! returned, the replay of a saved request) and `commit.rs` `desktop_is_enrolled` (enrollment).
use super::commit::desktop_is_enrolled;
use super::machine::{BeginOutcome, random_id};
use super::state::AgentCreationState;
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use ramflux_protocol::agent_profile::AgentProfileEnvelope;
use ramflux_protocol::custody::{
    AGENT_REGISTER_VERSION, AgentRegisterProfile, DeviceRef, DeviceSet, Envelope,
    REGISTER_PLAN_SCHEMA, REGISTER_TTL_SECONDS, RegisterPlan, RegisterPurpose,
    decode_register_plan, encode_register_plan, object_hash, register_plan_hash,
    validate_register_plan,
};
use ramflux_protocol::{DeviceSetStatus, decode_base64url, encode_base64url};

/// Inputs of one rebind request, all read by the desktop from its committed agent account and its
/// verified human authority. `now` is the clock of the call.
pub struct RebindInput<'a> {
    pub request_id: String,
    /// Local account id of the bound agent.
    pub agent_account_id: String,
    /// The agent's committed publication record (its `DeviceSet`).
    pub agent: &'a Envelope<DeviceSet>,
    /// The agent's committed profile (its `profile_epoch` is raised by one).
    pub profile: &'a AgentProfileEnvelope,
    /// The human's authority that names the new primary (the transferred record).
    pub human: &'a Envelope<DeviceSet>,
    /// This desktop, which must still be an enrolled sibling of the human account.
    pub desktop: &'a DeviceRef,
    pub now: u64,
}

/// Freeze the rebind plan and save its request on the desktop. A repeated request id returns the
/// saved request and writes nothing. The record keeps no vault items and no decision.
/// # Errors
/// `AgentCreationRefused("creation_pairing_required")` when the desktop is not an enrolled sibling
/// (nothing is written); `AgentCreationRefused("creation_not_primary")` when the human has no
/// current primary branch; `CustodyExpired` when the plan would expire at `now`.
pub fn begin_rebind(
    store: &AgentCreationStore,
    input: &RebindInput<'_>,
) -> Result<BeginOutcome, SdkError> {
    crate::custody::valid_id(&input.request_id)?;
    crate::custody::valid_id(&input.agent_account_id)?;
    if let Some(existing) = store.load(&input.request_id)? {
        return outcome(&existing);
    }
    if !desktop_is_enrolled(input.human, input.desktop, input.now) {
        return Err(SdkError::AgentCreationRefused("creation_pairing_required"));
    }
    let primary = input.human.body.master_certificate.body.primary_device_ref.clone();
    let primary_expires = primary_branch_expiry(input.human, &primary, input.now)
        .ok_or(SdkError::AgentCreationRefused("creation_not_primary"))?;
    let plan = rebind_plan(input, primary, primary_expires)?;
    validate_register_plan(&plan).map_err(|_| SdkError::CustodySetupInvalid)?;
    let plan_bytes = encode_register_plan(&plan).map_err(|_| SdkError::CustodySetupInvalid)?;
    let record = AgentCreationRecord {
        request_id: input.request_id.clone(),
        account_id: Some(input.agent_account_id.clone()),
        request_hash: register_plan_hash(&plan).map_err(|_| SdkError::CustodySetupInvalid)?,
        plan_b64: encode_base64url(&plan_bytes),
        state: AgentCreationState::AuthorizationPending,
        issued_at: plan.issued_at,
        expires_at: plan.expires_at,
        vault_refs: Vec::new(),
        intended: None,
        failure: None,
        decision_b64: None,
        master_range: 0,
        profile_b64: None,
        receipt_b64: None,
        agent_record_b64: None,
        intent_b64: None,
    };
    store.save(&record)?;
    outcome(&record)
}

/// The rebind plan of the agent: every value from the committed agent, the new primary and the
/// new head. Nothing is widened: the branch keeps its capabilities and its lease.
fn rebind_plan(
    input: &RebindInput<'_>,
    primary: DeviceRef,
    primary_expires: u64,
) -> Result<RegisterPlan, SdkError> {
    let agent = input.agent;
    let certificate = &agent.body.master_certificate;
    let device = agent.body.devices.first().ok_or(SdkError::CustodySetupInvalid)?;
    let branch = device
        .branch_certificate
        .as_ref()
        .map(|cert| &cert.body)
        .ok_or(SdkError::CustodySetupInvalid)?;
    let previous = &input.profile.body;
    let profile_epoch =
        previous.profile_epoch.checked_add(1).ok_or(SdkError::CustodySetupInvalid)?;
    let next_range =
        certificate.body.range_index.checked_add(1).ok_or(SdkError::CustodySetupInvalid)?;
    let expires_at = input
        .now
        .checked_add(REGISTER_TTL_SECONDS)
        .map(|ttl| ttl.min(primary_expires))
        .filter(|expires| *expires > input.now)
        .ok_or(SdkError::CustodyExpired)?;
    Ok(RegisterPlan {
        schema: REGISTER_PLAN_SCHEMA.into(),
        version: AGENT_REGISTER_VERSION,
        request_id: input.request_id.clone(),
        purpose: RegisterPurpose::Rebind,
        owner_anchor: input.human.body.account_anchor.clone(),
        human_head_hash: object_hash(input.human).map_err(|_| SdkError::CustodySetupInvalid)?,
        human_primary: primary,
        desktop: input.desktop.clone(),
        agent_anchor: agent.body.account_anchor.clone(),
        principal_id: agent.body.principal_id.clone(),
        agent_device: DeviceRef {
            account_anchor: agent.body.account_anchor.clone(),
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
        },
        master_public_key: certificate.body.master_public_key.clone(),
        self_signing_public_key: certificate.body.self_signing_public_key.clone(),
        branch_signing_public_key: branch.branch_signing_public_key.clone(),
        agreement_public_key: branch.agreement_identity_public_key.clone(),
        capabilities: branch.capabilities.clone(),
        display_name: agent.body.profile.display_name.clone(),
        certificate_issued_at: input.now,
        branch_not_before: branch.not_before,
        branch_expires_at: branch.expires_at,
        master_cert_id: random_id()?,
        branch_cert_id: random_id()?,
        profile: AgentRegisterProfile {
            responsibility: previous.responsibility.clone(),
            provider: previous.provider.clone(),
            model: previous.model.clone(),
            persona_version: previous.persona_version,
            persona_hash: previous.persona_hash.clone(),
            profile_epoch,
        },
        issued_at: input.now,
        expires_at,
        previous_agent_head_hash: Some(
            object_hash(agent).map_err(|_| SdkError::CustodySetupInvalid)?,
        ),
        previous_master_certificate_hash: Some(
            object_hash(certificate).map_err(|_| SdkError::CustodySetupInvalid)?,
        ),
        next_range,
    })
}

/// The expiry of the active branch of `device` in `human`, when it is valid at `now`.
pub(crate) fn primary_branch_expiry(
    human: &Envelope<DeviceSet>,
    device: &DeviceRef,
    now: u64,
) -> Option<u64> {
    human
        .body
        .devices
        .iter()
        .find(|entry| {
            entry.device_id == device.device_id
                && entry.device_epoch == device.device_epoch
                && entry.status == DeviceSetStatus::Active
                && entry.revoked_at.is_none()
        })
        .and_then(|entry| entry.branch_certificate.as_ref())
        .map(|branch| branch.body.expires_at)
        .filter(|expires| *expires > now)
}

/// The checks a primary makes before it signs a plan of any purpose: the plan names the exact
/// current human head, and it names this device as the current primary. Returns the closed refusal
/// token (`creation_plan_changed` for a stale head, `creation_not_primary` otherwise).
pub(crate) fn check_decision_context(
    plan: &RegisterPlan,
    human: &Envelope<DeviceSet>,
    local: &DeviceRef,
) -> Result<(), &'static str> {
    let head = object_hash(human).map_err(|_| "creation_plan_changed")?;
    if head != plan.human_head_hash {
        return Err("creation_plan_changed");
    }
    let primary = &human.body.master_certificate.body.primary_device_ref;
    if plan.human_primary != *local || plan.human_primary != *primary {
        return Err("creation_not_primary");
    }
    Ok(())
}

/// Whether a stored request is a rebind (its plan has `purpose = rebind`). Rebind requests never
/// create an account and never count as the agent's creation record.
pub(crate) fn is_rebind(record: &AgentCreationRecord) -> bool {
    record
        .plan_bytes()
        .ok()
        .and_then(|bytes| decode_register_plan(&bytes).ok())
        .is_some_and(|plan| plan.purpose == RegisterPurpose::Rebind)
}

fn outcome(record: &AgentCreationRecord) -> Result<BeginOutcome, SdkError> {
    Ok(BeginOutcome {
        request_id: record.request_id.clone(),
        request_hash: record.request_hash.clone(),
        plan_bytes: record.plan_bytes()?,
        state: record.state,
    })
}

/// The profile bytes of a stored creation record, decoded for a rebind input.
/// # Errors
/// `CustodySetupInvalid` when the record holds no profile or the profile does not decode.
pub fn stored_profile(record: &AgentCreationRecord) -> Result<AgentProfileEnvelope, SdkError> {
    let encoded = record.profile_b64.as_deref().ok_or(SdkError::CustodySetupInvalid)?;
    let bytes = decode_base64url(encoded).map_err(|_| SdkError::CustodySetupInvalid)?;
    ramflux_protocol::agent_profile::decode_agent_profile(&bytes)
        .map_err(|_| SdkError::CustodySetupInvalid)
}
