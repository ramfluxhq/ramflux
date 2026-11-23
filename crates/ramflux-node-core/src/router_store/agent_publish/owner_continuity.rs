// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner continuity inside the agent publication transaction.
//!
//! An existing agent is admitted only when the stored profile custodian anchor, the stored
//! host owner and the proposed owner are the same account. A missing stored owner is refused.
//! Master certification does not carry this check: it never sees the host row, and a modified
//! client can certify a different external anchor.

use super::agent_host::{AgentHostBinding, HOSTS};
use crate::NodeCoreError;
use crate::custody_authority::CustodyAccountState;
use crate::router_store::custody_accounts::ACCOUNTS;
use ramflux_protocol::PrincipalKind;
use ramflux_protocol::custody::CustodyRefusal;
use redb::{ReadableTable, TableDefinition, TableHandle};

const MAX_OWNER_ROW_BYTES: usize = 16 * 1024 * 1024;

struct Prior {
    host: Option<String>,
    agent: bool,
    custodian: Option<String>,
}

impl Prior {
    fn existing_agent(&self) -> bool {
        self.host.is_some() || self.agent
    }
}

fn refused() -> NodeCoreError {
    NodeCoreError::AgentPublishRefused(CustodyRefusal::OwnerContinuity)
}

fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

fn table_present(tx: &redb::WriteTransaction, name: &str) -> Result<bool, NodeCoreError> {
    Ok(tx.list_tables().map_err(error)?.any(|table| table.name() == name))
}

fn read_row(
    tx: &redb::WriteTransaction,
    name: &str,
    definition: TableDefinition<'_, &str, &[u8]>,
    anchor: &str,
) -> Result<Option<Vec<u8>>, NodeCoreError> {
    if !table_present(tx, name)? {
        return Ok(None);
    }
    let table = tx.open_table(definition).map_err(error)?;
    let Some(value) = table.get(anchor).map_err(error)? else {
        return Ok(None);
    };
    if value.value().len() > MAX_OWNER_ROW_BYTES {
        return Err(NodeCoreError::Capacity { resource: "agent owner continuity row" });
    }
    Ok(Some(value.value().to_vec()))
}

fn nonempty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn host_owner(tx: &redb::WriteTransaction, anchor: &str) -> Result<Option<String>, NodeCoreError> {
    let Some(bytes) = read_row(tx, HOSTS.name(), HOSTS, anchor)? else {
        return Ok(None);
    };
    let binding: AgentHostBinding = serde_json::from_slice(&bytes).map_err(error)?;
    Ok(nonempty(binding.owner_anchor))
}

fn account_fields(state: &CustodyAccountState) -> (bool, Option<String>) {
    let body = &state.publication.record.body;
    if body.principal_kind != PrincipalKind::HeadlessAi {
        return (false, None);
    }
    let custodian =
        body.profile.custodian.as_ref().and_then(|device| nonempty(device.account_anchor.clone()));
    (true, custodian)
}

fn account_owner(
    tx: &redb::WriteTransaction,
    anchor: &str,
) -> Result<(bool, Option<String>), NodeCoreError> {
    let Some(bytes) = read_row(tx, ACCOUNTS.name(), ACCOUNTS, anchor)? else {
        return Ok((false, None));
    };
    let state: CustodyAccountState = serde_json::from_slice(&bytes).map_err(error)?;
    Ok(account_fields(&state))
}

fn incoming_owner(state: &CustodyAccountState) -> Option<&str> {
    let body = &state.publication.record.body;
    if body.principal_kind != PrincipalKind::HeadlessAi {
        return None;
    }
    body.profile.custodian.as_ref().and_then(|device| {
        let anchor = device.account_anchor.as_str();
        if anchor.is_empty() { None } else { Some(anchor) }
    })
}

fn load(tx: &redb::WriteTransaction, anchor: &str) -> Result<Prior, NodeCoreError> {
    let host = host_owner(tx, anchor)?;
    let (agent, custodian) = account_owner(tx, anchor)?;
    Ok(Prior { host, agent, custodian })
}

fn same_owner(prior: &Prior, proposed: &str, incoming: &CustodyAccountState) -> bool {
    !proposed.is_empty()
        && prior.host.as_deref() == Some(proposed)
        && prior.custodian.as_deref() == Some(proposed)
        && incoming_owner(incoming) == Some(proposed)
}

/// Refuse a host publication whose proposed owner differs from the stored agent.
///
/// A first birth has no stored owner. The record being written and the host row must still
/// name one account, so a later rebind has a single anchor to compare.
///
/// # Errors
/// [`CustodyRefusal::OwnerContinuity`] when an existing agent is missing an owner or the
/// three anchors differ, and when a first birth's record and host owner differ. Durable
/// read failures use the usual node errors.
pub(crate) fn require_publish_owner(
    tx: &redb::WriteTransaction,
    anchor: &str,
    proposed_owner: &str,
    incoming: &CustodyAccountState,
) -> Result<(), NodeCoreError> {
    let prior = load(tx, anchor)?;
    let agreed = if prior.existing_agent() {
        same_owner(&prior, proposed_owner, incoming)
    } else {
        !proposed_owner.is_empty() && incoming_owner(incoming) == Some(proposed_owner)
    };
    if agreed { Ok(()) } else { Err(refused()) }
}

/// Refuse an ordinary republish of an existing agent that would change its human owner.
///
/// # Errors
/// [`CustodyRefusal::OwnerContinuity`] when the stored account is an agent and its custodian
/// anchor, host owner and incoming custodian are not the same account. A non-agent account
/// is unchanged by this check.
pub(crate) fn require_republish_owner(
    tx: &redb::WriteTransaction,
    anchor: &str,
    incoming: &CustodyAccountState,
) -> Result<(), NodeCoreError> {
    let prior = load(tx, anchor)?;
    if !prior.agent {
        return Ok(());
    }
    let proposed = incoming_owner(incoming).unwrap_or("");
    if same_owner(&prior, proposed, incoming) { Ok(()) } else { Err(refused()) }
}
