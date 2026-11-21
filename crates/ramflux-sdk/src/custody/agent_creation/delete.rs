// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The local half of `agent.delete` (AGENT-IDENTITY-01 E4, decision r22 item 2 a to c). The agent's
//! pending and committed vault items are deleted (the seed `agent-master:` with every recorded
//! certificate up to the highest range), the creation records stop naming them, and the local
//! agent account directory is removed. The published custody record stays on the node: no native
//! retirement path exists yet (a follow-up, see the stage E report). Every step is repeatable, so a
//! failed call is retried by the same request.
use super::AgentCreationState;
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use crate::custody::PrimaryVault;
use crate::custody::vault::AGENT_MASTER_PREFIX;
use ramflux_protocol::custody::{RegisterPurpose, decode_register_plan};

/// Whether a record publishes an agent account (its request reached the commit point or later).
fn publishing(record: &AgentCreationRecord) -> bool {
    matches!(
        record.state,
        AgentCreationState::PublicationPending
            | AgentCreationState::PublicationUnknown
            | AgentCreationState::Complete
    )
}

/// The local account id of the agent `agent` (its anchor): the account of the creation record that
/// published it. `Ok(None)` when no creation of this agent published an account.
fn account_of_agent(
    records: &[AgentCreationRecord],
    agent: &str,
) -> Result<Option<String>, SdkError> {
    let mut origin: Option<String> = None;
    for record in records.iter().filter(|record| publishing(record)) {
        let plan = decode_register_plan(&record.plan_bytes()?)
            .map_err(|_| SdkError::CustodySetupInvalid)?;
        if plan.purpose != RegisterPurpose::Rebind && plan.agent_anchor == agent {
            origin.clone_from(&record.account_id);
        }
    }
    Ok(origin)
}

/// The local account id of the agent `agent` in this human's creation store. `Ok(None)` when no
/// creation of this agent published an account here.
///
/// # Errors
/// The store's refusals.
pub(crate) fn agent_account_id(
    store: &AgentCreationStore,
    agent: &str,
) -> Result<Option<String>, SdkError> {
    account_of_agent(&store.records()?, agent)
}

/// Whether the agent account with this local id belongs to an agent whose record was retired
/// (`agent.delete`, lifecycle `X`). The account id is mapped to its agent anchor through the
/// creation records of every human on this root, and the anchor is looked up in that human's agent
/// records. No directory is created. An id that no creation record names is not retired.
///
/// # Errors
/// `CustodySetupInvalid` for an invalid id or a corrupt record; `CustodyVaultUnavailable` for I/O.
pub(crate) fn is_retired_agent_account(
    root: &std::path::Path,
    account_id: &str,
) -> Result<bool, SdkError> {
    crate::custody::valid_id(account_id)?;
    let humans = match std::fs::read_dir(root.join("custody_accounts")) {
        Ok(humans) => humans,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(SdkError::CustodyVaultUnavailable),
    };
    for human in humans {
        let human = human.map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if !human.path().join("agent_creation").is_dir() {
            continue;
        }
        let Some(human_id) = human.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let store = AgentCreationStore::open(root, &human_id)?;
        let records = store.records()?;
        let Some(record) =
            records.iter().find(|record| record.account_id.as_deref() == Some(account_id))
        else {
            continue;
        };
        let plan = decode_register_plan(&record.plan_bytes()?)
            .map_err(|_| SdkError::CustodySetupInvalid)?;
        let agents = crate::agent_record::AgentRecordStore::at(store.agent_record_dir());
        if let Some(stored) = agents.load(&plan.agent_anchor)?
            && stored.lifecycle == crate::agent_record::LIFECYCLE_RETIRED
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Deletes the vault items of the agent `agent` (its anchor) and its local account directory.
/// Every publishing record of the agent's local account contributes its items. The records keep
/// their state and lose their item references only after every delete succeeded.
///
/// # Errors
/// `agent_not_found` when no creation of this agent published an account; the store's and the
/// vault's refusals, which leave the remaining items for a repeated call.
pub(crate) fn retire_agent_material(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    agent: &str,
) -> Result<(), SdkError> {
    let records = store.records()?;
    let account_id = account_of_agent(&records, agent)?
        .ok_or(SdkError::AgentCreationRefused("agent_not_found"))?;
    crate::custody::valid_id(&account_id)?;
    let of_account: Vec<&AgentCreationRecord> = records
        .iter()
        .filter(|record| publishing(record) && record.account_id.as_deref() == Some(&account_id))
        .collect();
    let mut refs: Vec<String> = Vec::new();
    let mut last_range = 0_u64;
    for record in &of_account {
        refs.extend(record.vault_refs.iter().cloned());
        last_range = last_range.max(record.master_range);
    }
    refs.sort_unstable();
    refs.dedup();
    for reference in &refs {
        if reference.starts_with(AGENT_MASTER_PREFIX) {
            vault.delete_agent_master(reference, last_range)?;
        } else {
            vault.delete(reference)?;
        }
    }
    for record in of_account {
        if !record.vault_refs.is_empty() {
            let mut cleared = record.clone();
            cleared.vault_refs.clear();
            store.save(&cleared)?;
        }
    }
    remove_account_directory(store, &account_id)
}

/// Removes the local directory of the agent account: its authority, account database and session
/// files. The creation directory of the human is never removed here.
fn remove_account_directory(store: &AgentCreationStore, account_id: &str) -> Result<(), SdkError> {
    let directory = store.root().join("custody_accounts").join(account_id);
    match std::fs::remove_dir_all(&directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SdkError::CustodyVaultUnavailable),
    }
}
