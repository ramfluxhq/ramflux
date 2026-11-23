// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The wire view of a stored agent record (AGENT-IDENTITY-01 E4, contract 1 `AgentRecord`). The
//! fields that belong to later modules (`host`, `config`, `revision`, `observation`, `cleanup`) are
//! present in the message and always absent or empty here. `base` is the stored event identity.
use super::StoredAgentRecord;
use ramflux_protocol::message as g;

/// The `AgentRecord` message of one stored record.
pub(crate) fn to_wire(record: &StoredAgentRecord) -> g::AgentRecord {
    g::AgentRecord {
        agent_anchor: record.agent_anchor.clone(),
        custodian_anchor: record.custodian_anchor.clone(),
        persona: Some(record.persona.clone()),
        host: None,
        config: config_of(record),
        revision: None,
        lifecycle: record.lifecycle.clone(),
        observation: String::new(),
        cleanup: String::new(),
        access: Some(record.access.clone()),
        role: record.role.clone(),
        base: Some(record.identity.clone()),
    }
}

fn config_of(record: &StoredAgentRecord) -> Option<g::AgentConfigData> {
    let bounded = record.max_concurrent_turns.is_some() || record.max_cost_per_day_cents.is_some();
    if !bounded && record.provider.is_none() && record.model.is_none() {
        return None;
    }
    Some(g::AgentConfigData {
        provider: record.provider.clone().unwrap_or_default(),
        model: record.model.clone().unwrap_or_default(),
        prompt: None,
        autonomy: String::new(),
        tools: Vec::new(),
        enabled: None,
        limits: bounded.then_some(g::AgentLimits {
            max_concurrent_turns: record.max_concurrent_turns,
            max_cost_per_day_cents: record.max_cost_per_day_cents,
        }),
    })
}
