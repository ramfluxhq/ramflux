// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage D R1 (contract 7.5): once the desktop's own human authority names a new primary, the
//! desktop freezes the rebind plan for that primary and hands its bytes to the custody transport.
//! The predecessors come from the agent's committed `DeviceSet` copy on the newest complete record
//! (`AgentCreationRecord::agent_record_b64`), so the agent's authority file is never read here.
//! A desktop that is no longer an enrolled sibling freezes nothing: the agent stays in R with
//! `creation_pairing_required`, and the caller sends nothing.
//!
//! Pattern copied: `rebind_plan.rs` `begin_rebind` (the plan and its replay) and `machine.rs`
//! `random_id`.
use super::machine::random_id;
use super::rebind::{RebindBinding, RebindEntry};
use super::rebind_plan::{RebindInput, begin_rebind, stored_profile};
use super::state::{AgentCreationState, AgentFailure};
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use ramflux_protocol::custody::{DeviceRef, DeviceSet, Envelope, decode_register_plan};
use ramflux_protocol::decode_base64url;

/// A rebind request ready for the custody transport.
pub struct PreparedRebind {
    /// Request id of the rebind (the correlation id of the packet).
    pub request_id: String,
    /// Canonical plan bytes, the same bytes on every replay.
    pub plan_bytes: Vec<u8>,
    /// The new primary: the one device the plan goes to.
    pub primary: DeviceRef,
    /// The bound agent's anchor, which fixes the conversation scope of the packet.
    pub agent_anchor: String,
}

/// Freeze (or replay) the rebind request of one paused agent and record it in the inventory.
/// # Errors
/// `CustodySetupInvalid` when the agent is not in R or has no complete record;
/// `AgentCreationRefused("creation_pairing_required")` when this desktop is not an enrolled sibling
/// of the human (the inventory keeps R and records `creation_pairing_required`, nothing is sent);
/// `AgentCreationRefused("creation_not_primary")` when the human still names the bound primary.
pub fn prepare_rebind_request(
    store: &AgentCreationStore,
    human: &Envelope<DeviceSet>,
    desktop: &DeviceRef,
    agent_account_id: &str,
    now: u64,
) -> Result<PreparedRebind, SdkError> {
    let entry = store.load_rebind(agent_account_id)?.ok_or(SdkError::CustodySetupInvalid)?;
    if entry.binding != RebindBinding::RebindPending {
        return Err(SdkError::CustodySetupInvalid);
    }
    if human.body.master_certificate.body.primary_device_ref == entry.bound_primary {
        return Err(SdkError::AgentCreationRefused("creation_not_primary"));
    }
    let request_id = match &entry.request_id {
        Some(saved) => saved.clone(),
        None => random_id()?,
    };
    let source = newest_complete(store, agent_account_id)?;
    let agent = stored_agent_record(&source)?;
    let profile = stored_profile(&source)?;
    let input = RebindInput {
        request_id,
        agent_account_id: agent_account_id.into(),
        agent: &agent,
        profile: &profile,
        human,
        desktop,
        now,
    };
    match begin_rebind(store, &input) {
        Ok(outcome) => {
            let plan = decode_register_plan(&outcome.plan_bytes)
                .map_err(|_| SdkError::CustodySetupInvalid)?;
            let saved = RebindEntry {
                request_id: Some(outcome.request_id.clone()),
                failure: None,
                ..entry
            };
            store.save_rebind(&saved)?;
            Ok(PreparedRebind {
                request_id: outcome.request_id,
                plan_bytes: outcome.plan_bytes,
                primary: plan.human_primary.clone(),
                agent_anchor: plan.agent_anchor.clone(),
            })
        }
        Err(SdkError::AgentCreationRefused(token)) if token == "creation_pairing_required" => {
            store.save_rebind(&RebindEntry {
                failure: Some(AgentFailure::CreationPairingRequired),
                ..entry
            })?;
            Err(SdkError::AgentCreationRefused(token))
        }
        Err(error) => Err(error),
    }
}

/// The newest complete record of one agent: the one with the highest master range.
fn newest_complete(
    store: &AgentCreationStore,
    agent_account_id: &str,
) -> Result<AgentCreationRecord, SdkError> {
    store
        .records()?
        .into_iter()
        .filter(|record| {
            record.state == AgentCreationState::Complete
                && record.account_id.as_deref() == Some(agent_account_id)
        })
        .max_by_key(|record| record.master_range)
        .ok_or(SdkError::CustodySetupInvalid)
}

/// The agent `DeviceSet` copy of a record, decoded.
fn stored_agent_record(record: &AgentCreationRecord) -> Result<Envelope<DeviceSet>, SdkError> {
    let encoded = record.agent_record_b64.as_deref().ok_or(SdkError::CustodySetupInvalid)?;
    let bytes = decode_base64url(encoded).map_err(|_| SdkError::CustodySetupInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)
}
