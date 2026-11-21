// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The wire view of a stored agent record (AGENT-IDENTITY-01 E4, contract 1 `AgentRecord`). The
//! fields that belong to later modules (`host`, `config`, `revision`, `observation`, `cleanup`) are
//! present in the message and always absent or empty here.
use super::StoredAgentRecord;
use ramflux_protocol::message as g;

/// The `AgentRecord` message of one stored record.
pub(crate) fn to_wire(record: &StoredAgentRecord) -> g::AgentRecord {
    g::AgentRecord {
        agent_anchor: record.agent_anchor.clone(),
        custodian_anchor: record.custodian_anchor.clone(),
        persona: Some(record.persona.clone()),
        host: None,
        config: None,
        revision: None,
        lifecycle: record.lifecycle.clone(),
        observation: String::new(),
        cleanup: String::new(),
        access: Some(record.access.clone()),
        role: record.role.clone(),
    }
}
