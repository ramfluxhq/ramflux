// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The per-owner agent record (AGENT-IDENTITY-01 E2, contract 1 and 4). One JSON file per agent under
//! `custody_accounts/<owner>/agent_record/`, written when the agent creation completes (lifecycle
//! `U`). Persona and access are RF-owned metadata ordered by the native `EventOrder` of `identity`.
//! This module stores and validates them. It holds no key material, and it does not enforce the
//! access policy on incoming messages (a later module).
use crate::SdkError;
use ramflux_protocol::message::{AgentAccessPolicy, AgentPersona, EventIdentity};
use serde::{Deserialize, Serialize};

mod apply;
mod edit;
mod policy;
mod store;
#[cfg(test)]
mod tests;

pub(crate) use apply::{apply_metadata, metadata_of};
#[cfg(test)]
pub(crate) use edit::seed_for_test;
pub(crate) use edit::{edit_record, record_completed, retire};
pub(crate) use policy::{check_access, check_persona};
pub(crate) use store::AgentRecordStore;

/// Lifecycle of an agent that exists with no runtime bound (contract lifecycle state `U`).
pub(crate) const LIFECYCLE_ACTIVE: &str = "U";
/// Lifecycle after `agent.delete` (state `X`): the identity is retired and never resurrected.
pub(crate) const LIFECYCLE_RETIRED: &str = "X";
/// The only role of this module.
pub(crate) const ROLE_NAMED: &str = "named";

/// The persona and access an `agent.create` was requested with. Stored on the creation record so
/// the agent record can be written when the agent completes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentIntent {
    pub(crate) persona: AgentPersona,
    pub(crate) access: AgentAccessPolicy,
}

/// The stored agent record. `identity` is the `EventIdentity` of the latest accepted change.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredAgentRecord {
    pub(crate) agent_anchor: String,
    pub(crate) custodian_anchor: String,
    pub(crate) persona: AgentPersona,
    pub(crate) access: AgentAccessPolicy,
    pub(crate) role: String,
    pub(crate) lifecycle: String,
    pub(crate) identity: EventIdentity,
}

/// Refuses a record whose fields are outside the closed shapes of this module.
pub(crate) fn check_record(record: &StoredAgentRecord) -> Result<(), SdkError> {
    crate::custody::valid_id(&record.agent_anchor)?;
    crate::custody::valid_id(&record.custodian_anchor)?;
    if record.role != ROLE_NAMED
        || !matches!(record.lifecycle.as_str(), LIFECYCLE_ACTIVE | LIFECYCLE_RETIRED)
    {
        return Err(SdkError::CustodySetupInvalid);
    }
    ramflux_protocol::message::identity::order_key(&record.identity)
        .map_err(|_| SdkError::CustodySetupInvalid)?;
    check_persona(&record.persona)?;
    check_access(&record.access)
}
