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
    let mut origin: Option<String> = None;
    for record in records.iter().filter(|record| publishing(record)) {
        let plan = decode_register_plan(&record.plan_bytes()?)
            .map_err(|_| SdkError::CustodySetupInvalid)?;
        if plan.purpose != RegisterPurpose::Rebind && plan.agent_anchor == agent {
            origin.clone_from(&record.account_id);
        }
    }
    let account_id = origin.ok_or(SdkError::AgentCreationRefused("agent_not_found"))?;
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
