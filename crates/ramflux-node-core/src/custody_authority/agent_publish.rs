// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission of `AgentPublish`: a headless first birth or a rebind to a changed custodian
//! primary, admitted only with a current primary decision over the exact plan. The checks run
//! in the order of contract decision D5; each refusal names one check.

use super::{CustodyAccountState, CustodyPublication, reject};
use crate::router_store::{AgentPublicationWrite, StoredAgentPublish};
use crate::{IdentityRegistry, NodeCoreError, RouterCore, RouterRedbStore};
use ramflux_crypto::custody::{PinOutcome, VerifiedRecord, verify_register_decision};
use ramflux_protocol::{
    agent_profile::{AgentProfileEnvelope, encode_agent_profile},
    custody::{
        AgentPublishReceipt, CustodyRefusal, DeviceRef, RegisterDecision, RegisterOutcome,
        RegisterPlan, RegisterPurpose, object_hash, register_plan_hash,
    },
};

/// Everything `AgentPublish` carries besides the directory publication, borrowed from the action.
pub(crate) struct AgentPublishInput<'a> {
    pub publication: &'a CustodyPublication,
    pub agent_profile: &'a AgentProfileEnvelope,
    pub plan: &'a RegisterPlan,
    pub authorization: &'a RegisterDecision,
}

fn refused(refusal: CustodyRefusal) -> NodeCoreError {
    NodeCoreError::AgentPublishRefused(refusal)
}

fn host_of(
    plan: &RegisterPlan,
    primary: DeviceRef,
) -> crate::router_store::agent_host::AgentHostBinding {
    crate::router_store::agent_host::AgentHostBinding {
        owner_anchor: plan.owner_anchor.clone(),
        desktop: plan.desktop.clone(),
        primary,
        agent_device: plan.agent_device.clone(),
    }
}

/// Digests of the three objects a saved authorization is keyed by.
struct Digests {
    plan: String,
    decision: String,
    record: String,
}

/// Plan and decision agree on the request identifier and the plan hash (D5 step 1).
fn digests(input: &AgentPublishInput<'_>) -> Result<Digests, NodeCoreError> {
    let plan = register_plan_hash(input.plan).map_err(|_| refused(CustodyRefusal::InvalidInput))?;
    let decision =
        object_hash(input.authorization).map_err(|_| refused(CustodyRefusal::InvalidInput))?;
    let record = object_hash(&input.publication.record)
        .map_err(|_| refused(CustodyRefusal::InvalidInput))?;
    if input.authorization.body.request_hash != plan
        || input.authorization.body.request_id != input.plan.request_id
    {
        return Err(refused(CustodyRefusal::InvalidInput));
    }
    Ok(Digests { plan, decision, record })
}

/// Every field the plan commits to must equal the record, the profile or the custodian.
fn plan_matches_record(
    plan: &RegisterPlan,
    publication: &CustodyPublication,
    agent_profile: &AgentProfileEnvelope,
    human: &VerifiedRecord,
) -> bool {
    let record = &publication.record.body;
    let certificate = &record.master_certificate.body;
    let Some(device) = record.devices.first() else {
        return false;
    };
    let Some(branch) = device.branch_certificate.as_ref().map(|cert| &cert.body) else {
        return false;
    };
    let human_body = &human.envelope().body;
    let primary = &certificate.primary_device_ref;
    let profile = &agent_profile.body;
    let plan_profile = &plan.profile;
    plan.agent_anchor == record.account_anchor
        && plan.principal_id == record.principal_id
        && plan.owner_anchor == human_body.account_anchor
        && plan.human_primary == *primary
        && primary == &human_body.master_certificate.body.primary_device_ref
        && plan.agent_device.account_anchor == record.account_anchor
        && plan.agent_device.device_id == device.device_id
        && plan.agent_device.device_epoch == device.device_epoch
        && plan.master_public_key == certificate.master_public_key
        && plan.self_signing_public_key == certificate.self_signing_public_key
        && plan.master_cert_id == certificate.cert_id
        && plan.certificate_issued_at == certificate.issued_at
        && plan.next_range == certificate.range_index
        && plan.branch_signing_public_key == branch.branch_signing_public_key
        && plan.agreement_public_key == branch.agreement_identity_public_key
        && plan.branch_cert_id == branch.cert_id
        && plan.capabilities == branch.capabilities
        && plan.branch_not_before == branch.not_before
        && plan.branch_expires_at == branch.expires_at
        && plan.display_name == record.profile.display_name
        && record.profile.custodian.as_ref() == Some(&plan.human_primary)
        && plan_profile.responsibility == profile.responsibility
        && plan_profile.provider == profile.provider
        && plan_profile.model == profile.model
        && plan_profile.persona_version == profile.persona_version
        && plan_profile.persona_hash == profile.persona_hash
        && plan_profile.profile_epoch == profile.profile_epoch
        && profile.agent_anchor == record.account_anchor
        && profile.custodian_anchor == human_body.account_anchor
        && profile.custodian_primary == *primary
}

/// Current custodian head, its primary and the decision signature (D5 steps 2 to 4).
fn verify_decision(
    registry: &IdentityRegistry,
    plan: &RegisterPlan,
    authorization: &RegisterDecision,
    now: u64,
) -> Result<(VerifiedRecord, DeviceRef), NodeCoreError> {
    let human_record = registry
        .custody
        .records
        .get(&plan.owner_anchor)
        .ok_or_else(|| refused(CustodyRefusal::AuthorityUnavailable))?;
    let human = registry
        .verify_custody(human_record, now)
        .map_err(|_| refused(CustodyRefusal::AuthorityUnavailable))?;
    registry
        .custody
        .require_current(&human)
        .map_err(|_| refused(CustodyRefusal::AuthorityUnavailable))?;
    let primary = human.envelope().body.master_certificate.body.primary_device_ref.clone();
    if authorization.body.signer != primary || plan.human_primary != primary {
        return Err(refused(CustodyRefusal::BindingRefused));
    }
    let branch = human
        .authorize(&primary, "register", now)
        .map_err(|_| refused(CustodyRefusal::BindingRefused))?;
    verify_register_decision(&branch.branch_signing_public_key, authorization)
        .map_err(|_| refused(CustodyRefusal::BindingRefused))?;
    if authorization.body.decision != RegisterOutcome::Approve {
        return Err(refused(CustodyRefusal::InvalidInput));
    }
    let decision = &authorization.body;
    if now < decision.issued_at
        || now >= decision.expires_at
        || decision.expires_at > plan.expires_at
    {
        return Err(refused(CustodyRefusal::InvalidInput));
    }
    Ok((human, primary))
}

/// Agent record, principal ownership, plan fields and the agent profile (D5 step 5).
fn verify_agent(
    registry: &IdentityRegistry,
    input: &AgentPublishInput<'_>,
    human: &VerifiedRecord,
    now: u64,
) -> Result<VerifiedRecord, NodeCoreError> {
    let agent = registry
        .verify_custody(input.publication, now)
        .map_err(|_| refused(CustodyRefusal::InvalidInput))?;
    let body = &input.publication.record.body;
    registry
        .check_principal_root_ownership(
            &body.principal_id,
            &body.master_certificate.body.master_public_key,
        )
        .map_err(|_| refused(CustodyRefusal::PrincipalIdTaken))?;
    if !plan_matches_record(input.plan, input.publication, input.agent_profile, human) {
        return Err(refused(CustodyRefusal::InvalidInput));
    }
    let profile_bytes = encode_agent_profile(input.agent_profile)
        .map_err(|_| refused(CustodyRefusal::InvalidInput))?;
    ramflux_crypto::agent_profile::verify_agent_profile(&profile_bytes, &agent, human, now)
        .map_err(|_| refused(CustodyRefusal::InvalidInput))?;
    Ok(agent)
}

/// Predecessors (D5 steps 6 and 7): the custodian head the plan names, and either a new anchor
/// (create) or the stored head and certificate (rebind). Returns the stored state, if any.
fn check_predecessors(
    registry: &IdentityRegistry,
    plan: &RegisterPlan,
    human_head: &str,
) -> Result<Option<CustodyAccountState>, NodeCoreError> {
    if plan.human_head_hash != human_head {
        return Err(refused(CustodyRefusal::InvalidInput));
    }
    let anchor = &plan.agent_anchor;
    let expected = registry.custody.records.get(anchor).map(|stored| CustodyAccountState {
        publication: stored.clone(),
        pins: registry.custody.pins_for(anchor),
    });
    match (plan.purpose, expected.as_ref()) {
        (RegisterPurpose::Create, None) => Ok(None),
        (RegisterPurpose::Rebind, Some(stored)) => {
            let head = object_hash(&stored.publication.record)
                .map_err(|_| refused(CustodyRefusal::InvalidInput))?;
            let certificate = object_hash(&stored.publication.record.body.master_certificate)
                .map_err(|_| refused(CustodyRefusal::InvalidInput))?;
            let stored_range = stored.publication.record.body.master_certificate.body.range_index;
            if plan.previous_agent_head_hash.as_deref() != Some(head.as_str())
                || plan.previous_master_certificate_hash.as_deref() != Some(certificate.as_str())
                || plan.next_range <= stored_range
            {
                return Err(refused(CustodyRefusal::InvalidInput));
            }
            Ok(expected)
        }
        _ => Err(refused(CustodyRefusal::InvalidInput)),
    }
}

impl RouterCore {
    /// Verify an `AgentPublish` in the order of contract decision D5 and commit the directory
    /// record together with its consumed authorization. An exact replay returns the saved
    /// receipt without a second write.
    /// # Errors
    /// Refuses every failed check with [`NodeCoreError::AgentPublishRefused`], and durable
    /// write failures with the usual node errors.
    pub(crate) fn publish_agent_custody_record(
        &self,
        input: &AgentPublishInput<'_>,
        now: u64,
        store: &RouterRedbStore,
        source: std::net::IpAddr,
    ) -> Result<AgentPublishReceipt, NodeCoreError> {
        let digests = digests(input)?;
        // An admitted request returns its saved receipt, even after its decision has expired.
        if let Some(saved) = store.agent_publish_by_request(&input.plan.request_id)? {
            return if saved.request_hash == digests.plan
                && saved.record_hash == digests.record
                && saved.decision_hash == digests.decision
            {
                Ok(saved.receipt)
            } else {
                Err(refused(CustodyRefusal::IdempotencyConflict))
            };
        }
        if store.agent_decision_consumer(&digests.decision)?.is_some() {
            return Err(refused(CustodyRefusal::IdempotencyConflict));
        }
        let anchor = &input.publication.record.body.account_anchor;
        let mut control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let registry = &mut control.mvp1_identities;
        if registry.signed_device_sets.contains_key(anchor)
            || registry.root_public_keys_by_commitment.contains_key(anchor)
        {
            return Err(reject("legacy-to-custody migration is not enabled"));
        }
        let (human, primary) = verify_decision(registry, input.plan, input.authorization, now)?;
        let human_head = object_hash(
            &registry
                .custody
                .records
                .get(&input.plan.owner_anchor)
                .ok_or_else(|| refused(CustodyRefusal::AuthorityUnavailable))?
                .record,
        )
        .map_err(|_| refused(CustodyRefusal::InvalidInput))?;
        let agent = verify_agent(registry, input, &human, now)?;
        let expected = check_predecessors(registry, input.plan, &human_head)?;
        let mut pins = registry.custody.pins_for(anchor);
        let previous = registry.custody.records.get(anchor).map(|entry| &entry.record);
        let outcome = pins
            .observe_with_previous(&agent, previous)
            .map_err(|_| refused(CustodyRefusal::InvalidInput))?;
        let state = match outcome {
            PinOutcome::Fenced(alert) => {
                return Err(NodeCoreError::CustodyConflict { alert: Box::new(alert) });
            }
            PinOutcome::Advanced | PinOutcome::Unchanged => {
                CustodyAccountState { publication: input.publication.clone(), pins }
            }
        };
        if expected.is_none() && registry.custody.records.len() >= 65_536 {
            return Err(NodeCoreError::Capacity { resource: "custody account count" });
        }
        let receipt = AgentPublishReceipt {
            request_id: input.plan.request_id.clone(),
            request_hash: digests.plan.clone(),
            record_hash: digests.record.clone(),
            profile_hash: object_hash(input.agent_profile)
                .map_err(|_| refused(CustodyRefusal::InvalidInput))?,
            custodian_head_hash: human_head,
            custodian_primary: primary.clone(),
            accepted_at: now,
        };
        let row = StoredAgentPublish {
            request_hash: digests.plan,
            record_hash: digests.record,
            decision_hash: digests.decision,
            receipt: receipt.clone(),
        };
        let host = host_of(input.plan, primary);
        drop(control);
        store.record_agent_publication(&AgentPublicationWrite {
            request_id: &input.plan.request_id,
            row: &row,
            anchor,
            state: &state,
            expected: expected.as_ref(),
            source,
            now,
            host: &host,
        })?;
        let mut control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let registry = &mut control.mvp1_identities;
        let current = registry.custody.records.get(anchor).map(|stored| CustodyAccountState {
            publication: stored.clone(),
            pins: registry.custody.pins_for(anchor),
        });
        if current.as_ref() == expected.as_ref() || current.as_ref() == Some(&state) {
            registry.apply_custody_account(anchor.clone(), state)?;
        }
        Ok(receipt)
    }
}
