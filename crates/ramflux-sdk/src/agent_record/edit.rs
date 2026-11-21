// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Creation of the agent record when an agent creation completes (AGENT-IDENTITY-01 E2). The record
//! is written once with lifecycle `U`, holding the persona and access the creation was requested
//! with. Its identity is minted from the plan's issue time, and its author is the desktop that asked
//! for the agent.
use super::{
    AgentIntent, AgentRecordStore, LIFECYCLE_ACTIVE, ROLE_NAMED, StoredAgentRecord, check_access,
    check_persona,
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
        return Ok(existing);
    }
    check_persona(&intent.persona)?;
    check_access(&intent.access)?;
    let record = StoredAgentRecord {
        agent_anchor: plan.agent_anchor.clone(),
        custodian_anchor: plan.human_primary.account_anchor.clone(),
        persona: intent.persona.clone(),
        access: intent.access.clone(),
        role: ROLE_NAMED.into(),
        lifecycle: LIFECYCLE_ACTIVE.into(),
        identity: mint(None, &plan.agent_anchor, &plan.desktop, plan.issued_at)?,
    };
    store.save(&record)?;
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

/// Mints the `EventIdentity` of one change. The HLC never goes back, and the device sequence grows, so
/// two changes of one agent have strictly increasing `EventOrder` keys.
fn mint(
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
