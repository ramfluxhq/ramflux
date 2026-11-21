// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary observation (stage D2): compare every complete agent's binding with the human's
//! current primary and pause the agents whose binding was approved for another primary.
//! The rule is the contract's §7.6 rebinding table: only a settled binding (L or B) can move to R.
//! An observation never returns R or C to a settled state, because an old-head proof is not a
//! new-primary approval.
use super::rebind::{RebindBinding, RebindEntry};
use super::state::AgentCreationState;
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use ramflux_protocol::custody::{DeviceRef, decode_register_plan};
use std::collections::BTreeMap;

/// Observe the human's current primary and bring every complete agent's inventory entry up to date.
/// Returns the entries of all complete agents after the observation, sorted by agent id.
///
/// # Errors
/// Refuses an unreadable creation directory, a corrupt record or entry, and an inventory write
/// that fails. A failed write leaves the previous entry in place.
pub fn observe_primary(
    store: &AgentCreationStore,
    current_primary: &DeviceRef,
) -> Result<Vec<RebindEntry>, SdkError> {
    let mut entries = Vec::new();
    for (agent_account_id, record) in latest_complete_per_agent(store)? {
        let stored = store.load_rebind(&agent_account_id)?;
        let next = match &stored {
            Some(existing) => next_binding(existing, current_primary),
            None => first_entry(&agent_account_id, &record, current_primary)?,
        };
        if stored.as_ref() != Some(&next) {
            store.save_rebind(&next)?;
        }
        entries.push(next);
    }
    Ok(entries)
}

/// The entry of an agent that already has one. Settled bindings compare with the current primary;
/// R and C are left as they are.
fn next_binding(existing: &RebindEntry, current_primary: &DeviceRef) -> RebindEntry {
    if existing.binding.is_settled() && existing.bound_primary != *current_primary {
        RebindEntry {
            binding: RebindBinding::RebindPending,
            request_id: None,
            failure: None,
            ..existing.clone()
        }
    } else {
        existing.clone()
    }
}

/// The entry of an agent seen for the first time: live when its approved primary is still current.
fn first_entry(
    agent_account_id: &str,
    record: &AgentCreationRecord,
    current_primary: &DeviceRef,
) -> Result<RebindEntry, SdkError> {
    let plan =
        decode_register_plan(&record.plan_bytes()?).map_err(|_| SdkError::CustodySetupInvalid)?;
    let binding = if plan.human_primary == *current_primary {
        RebindBinding::Live
    } else {
        RebindBinding::RebindPending
    };
    Ok(RebindEntry {
        agent_account_id: agent_account_id.into(),
        binding,
        bound_primary: plan.human_primary,
        master_range: record.master_range,
        request_id: None,
        failure: None,
    })
}

/// One complete record per agent account: the one with the highest master range.
fn latest_complete_per_agent(
    store: &AgentCreationStore,
) -> Result<BTreeMap<String, AgentCreationRecord>, SdkError> {
    let mut latest: BTreeMap<String, AgentCreationRecord> = BTreeMap::new();
    for record in store.records()? {
        if record.state != AgentCreationState::Complete {
            continue;
        }
        let Some(account_id) = record.account_id.clone() else {
            continue;
        };
        let newer =
            latest.get(&account_id).is_none_or(|known| record.master_range > known.master_range);
        if newer {
            latest.insert(account_id, record);
        }
    }
    Ok(latest)
}
