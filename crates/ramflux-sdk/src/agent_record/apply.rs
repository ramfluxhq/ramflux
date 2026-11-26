// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replication of the agent record (AGENT-IDENTITY-01 E3, contract 4). A change made on one owner
//! device is broadcast as `AgentHostPacket.metadata`; a receiver applies it only when its native
//! `EventOrder` is strictly newer than the stored one. Equal and older packets are ignored, and a
//! retired record (`X`) never changes again, so a replayed older packet cannot resurrect an agent.
use super::{LIFECYCLE_ACTIVE, LIFECYCLE_RETIRED, ROLE_NAMED, StoredAgentRecord, check_record};
use crate::SdkError;
use crate::agent_record::AgentRecordStore;
use ramflux_protocol::message as g;
use ramflux_protocol::message::identity::order_key;

/// The `AgentMetadata` body that carries `record` to the other owner devices.
pub(crate) fn metadata_of(record: &StoredAgentRecord) -> g::AgentMetadata {
    g::AgentMetadata {
        agent_anchor: record.agent_anchor.clone(),
        custodian_anchor: record.custodian_anchor.clone(),
        persona: Some(record.persona.clone()),
        host: None,
        identity_retired: (record.lifecycle == LIFECYCLE_RETIRED).then_some(true),
        identity: Some(record.identity.clone()),
        access: Some(record.access.clone()),
        role: record.role.clone(),
    }
}

/// Refuses a metadata body that is not a whole, owner-authored record.
fn refused() -> SdkError {
    SdkError::AgentCreationRefused("metadata_invalid")
}

/// Applies one received `AgentMetadata` to the local store of `own_root`. Returns `true` when the
/// stored record changed. A missing record is created (the first replica); an existing one is
/// replaced only by a strictly newer `EventOrder`; a retired record is final.
///
/// # Errors
/// `AgentCreationRefused("metadata_invalid")` for a body outside the closed shapes or not authored
/// by a device of `own_root`; store errors otherwise.
pub(crate) fn apply_metadata(
    store: &AgentRecordStore,
    own_root: &str,
    metadata: &g::AgentMetadata,
) -> Result<bool, SdkError> {
    let identity = metadata.identity.as_ref().ok_or_else(refused)?;
    let incoming = order_key(identity).map_err(|_| refused())?;
    if incoming.account_anchor != own_root || metadata.role != ROLE_NAMED {
        return Err(refused());
    }
    let retired = metadata.identity_retired.unwrap_or(false);
    let mut candidate = StoredAgentRecord {
        agent_anchor: metadata.agent_anchor.clone(),
        custodian_anchor: metadata.custodian_anchor.clone(),
        persona: metadata.persona.clone().ok_or_else(refused)?,
        access: metadata.access.clone().ok_or_else(refused)?,
        role: ROLE_NAMED.into(),
        lifecycle: if retired { LIFECYCLE_RETIRED } else { LIFECYCLE_ACTIVE }.into(),
        identity: identity.clone(),
        change_seq: 0,
        provider: None,
        model: None,
        autonomy: None,
        prompt: None,
        tools: None,
        enabled: None,
        revision: None,
        max_concurrent_turns: None,
        max_cost_per_day_cents: None,
    };
    check_record(&candidate).map_err(|_| refused())?;
    let Some(current) = store.load(&metadata.agent_anchor)? else {
        store.save(&mut candidate)?;
        return Ok(true);
    };
    if current.lifecycle == LIFECYCLE_RETIRED {
        return Ok(false);
    }
    let stored = order_key(&current.identity).map_err(|_| SdkError::CustodySetupInvalid)?;
    if incoming <= stored {
        return Ok(false);
    }
    // The metadata carries no config: the desktop's mirror of the PRX config stays.
    candidate.provider = current.provider;
    candidate.model = current.model;
    candidate.autonomy = current.autonomy;
    candidate.prompt = current.prompt;
    candidate.tools = current.tools;
    candidate.enabled = current.enabled;
    candidate.revision = current.revision;
    candidate.max_concurrent_turns = current.max_concurrent_turns;
    candidate.max_cost_per_day_cents = current.max_cost_per_day_cents;
    store.save(&mut candidate)?;
    Ok(true)
}
