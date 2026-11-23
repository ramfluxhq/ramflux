// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creation of the agent record when an agent creation completes (AGENT-IDENTITY-01 E2). The record
//! is written once with lifecycle `U`, holding the persona and access the creation was requested
//! with. Its identity is minted from the plan's issue time, and its author is the desktop that asked
//! for the agent.
use super::{
    AgentIntent, AgentRecordStore, LIFECYCLE_ACTIVE, LIFECYCLE_RETIRED, ROLE_NAMED,
    StoredAgentRecord, check_access, check_persona, check_record,
};
use crate::SdkError;
use crate::custody::agent_creation::AgentCreationRecord;
use ramflux_crypto::random_32;
use ramflux_protocol::custody::{DeviceRef, RegisterPlan, decode_register_plan};
use ramflux_protocol::message::{EventIdentity, QualifiedDevice};
use std::path::PathBuf;

/// Writes the record of a planned agent, or returns the one already stored (idempotent: a completed
/// creation replayed after a crash keeps its first identity).
pub(crate) fn create_from_plan(
    store: &AgentRecordStore,
    plan: &RegisterPlan,
    intent: &AgentIntent,
) -> Result<StoredAgentRecord, SdkError> {
    if let Some(existing) = store.load(&plan.agent_anchor)? {
        if existing.lifecycle == LIFECYCLE_RETIRED {
            // A retired anchor is never created again on this device (AGENT-IDENTITY-01 E4).
            return Err(SdkError::AgentCreationRefused("agent_retired"));
        }
        return Ok(existing);
    }
    check_persona(&intent.persona)?;
    check_access(&intent.access)?;
    let mut record = StoredAgentRecord {
        agent_anchor: plan.agent_anchor.clone(),
        custodian_anchor: plan.human_primary.account_anchor.clone(),
        persona: intent.persona.clone(),
        access: intent.access.clone(),
        role: ROLE_NAMED.into(),
        lifecycle: LIFECYCLE_ACTIVE.into(),
        identity: mint(None, &plan.agent_anchor, &plan.desktop, plan.issued_at)?,
        change_seq: 0,
        provider: intent.provider.clone(),
        model: intent.model.clone(),
        max_concurrent_turns: intent.max_concurrent_turns,
        max_cost_per_day_cents: intent.max_cost_per_day_cents,
    };
    store.save(&mut record)?;
    Ok(record)
}

/// Test fixture: the `U` record that the completing desktop writes (E2), written by `author` without
/// a creation. The replicas on the other devices come from the metadata packets, not from this.
#[cfg(test)]
pub(crate) fn seed_for_test(
    store: &AgentRecordStore,
    agent: &str,
    author: &DeviceRef,
    now: u64,
) -> Result<StoredAgentRecord, SdkError> {
    let mut record = StoredAgentRecord {
        agent_anchor: agent.into(),
        custodian_anchor: author.account_anchor.clone(),
        persona: ramflux_protocol::message::AgentPersona {
            name: "seeded".into(),
            avatar: String::new(),
            responsibility: "seeded for the test".into(),
        },
        access: ramflux_protocol::message::AgentAccessPolicy {
            dm: "owner".into(),
            group_inviters: "owner".into(),
            allowed_humans: Vec::new(),
        },
        role: ROLE_NAMED.into(),
        lifecycle: LIFECYCLE_ACTIVE.into(),
        identity: mint(None, agent, author, now)?,
        change_seq: 0,
        provider: None,
        model: None,
        max_concurrent_turns: None,
        max_cost_per_day_cents: None,
    };
    store.save(&mut record)?;
    Ok(record)
}

/// Completion hook of the creation store (`complete_with_receipt`). A creation that carries no intent
/// (an SDK flow that calls `begin` directly) writes no agent record; `agent.create` always stores one.
pub(crate) fn record_completed(dir: PathBuf, record: &AgentCreationRecord) -> Result<(), SdkError> {
    let Some(encoded) = record.intent_b64.as_deref() else {
        return Ok(());
    };
    let bytes =
        ramflux_protocol::decode_base64url(encoded).map_err(|_| SdkError::CustodySetupInvalid)?;
    let intent: AgentIntent =
        serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    let plan =
        decode_register_plan(&record.plan_bytes()?).map_err(|_| SdkError::CustodySetupInvalid)?;
    create_from_plan(&AgentRecordStore::at(dir), &plan, &intent)?;
    Ok(())
}

/// A local change of the stored record (AGENT-IDENTITY-01 E3/E4). The change applies only when `base`
/// names the stored identity (`EventOrder` equal), otherwise it refuses with `stale_base`. The new
/// identity is minted by this device, so the change is strictly newer than the stored one.
/// # Errors
/// `agent_not_found` for no record, `agent_retired` for a retired one, `stale_base` for a base that
/// is not the stored identity, and the store's own refusals.
pub(crate) fn edit_record(
    store: &AgentRecordStore,
    agent: &str,
    base: &EventIdentity,
    author: &DeviceRef,
    now: u64,
    change: impl FnOnce(&mut StoredAgentRecord),
) -> Result<StoredAgentRecord, SdkError> {
    let current = store.load(agent)?.ok_or(SdkError::AgentCreationRefused("agent_not_found"))?;
    if current.lifecycle == LIFECYCLE_RETIRED {
        return Err(SdkError::AgentCreationRefused("agent_retired"));
    }
    let base_order = ramflux_protocol::message::identity::order_key(base)
        .map_err(|_| SdkError::AgentCreationRefused("stale_base"))?;
    let stored_order = ramflux_protocol::message::identity::order_key(&current.identity)
        .map_err(|_| SdkError::CustodySetupInvalid)?;
    if base_order != stored_order {
        return Err(SdkError::AgentCreationRefused("stale_base"));
    }
    let mut next = current.clone();
    change(&mut next);
    next.identity = mint(Some(&current.identity), agent, author, now)?;
    check_record(&next)?;
    store.save(&mut next)?;
    Ok(next)
}

/// Retires the record (state `X`, contract 2 delete). Idempotent: a record that is already retired
/// is returned unchanged, so a replayed delete mints nothing new.
/// # Errors
/// `agent_not_found` for no record, `stale_base` for a base that is not the stored identity.
pub(crate) fn retire(
    store: &AgentRecordStore,
    agent: &str,
    base: &EventIdentity,
    author: &DeviceRef,
    now: u64,
) -> Result<StoredAgentRecord, SdkError> {
    let current = store.load(agent)?.ok_or(SdkError::AgentCreationRefused("agent_not_found"))?;
    if current.lifecycle == LIFECYCLE_RETIRED {
        return Ok(current);
    }
    let retired = edit_record(store, agent, base, author, now, |record| {
        record.lifecycle = LIFECYCLE_RETIRED.into();
    })?;
    Ok(retired)
}

/// Mints the `EventIdentity` of one change. The HLC never goes back, and the device sequence grows, so
/// two changes of one agent have strictly increasing `EventOrder` keys.
pub(crate) fn mint(
    previous: Option<&EventIdentity>,
    agent: &str,
    author: &DeviceRef,
    now: u64,
) -> Result<EventIdentity, SdkError> {
    let hlc = previous.map_or(now, |earlier| earlier.hlc.saturating_add(1).max(now));
    let device_sequence = previous.map_or(1, |earlier| earlier.device_sequence.saturating_add(1));
    let id = random_32().map_err(|_| SdkError::CustodyRandomUnavailable)?;
    let identity = EventIdentity {
        id: id.to_vec(),
        conversation_id: format!("agent-record:{agent}"),
        author: Some(QualifiedDevice {
            account_anchor: author.account_anchor.clone(),
            device_id: author.device_id.clone(),
            device_epoch: author.device_epoch,
        }),
        device_sequence,
        hlc,
        group_id: None,
        group_epoch: None,
    };
    ramflux_protocol::message::identity::order_key(&identity)
        .map_err(|_| SdkError::CustodySetupInvalid)?;
    Ok(identity)
}
