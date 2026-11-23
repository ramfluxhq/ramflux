// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host binding and retirement of one agent anchor. These rows are new tables. The
//! agent-publish receipt format is unchanged.

use crate::{NodeCoreError, RouterRedbStore};
use ramflux_protocol::custody::{CustodyRefusal, DeviceRef};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const HOSTS: TableDefinition<&str, &[u8]> = TableDefinition::new("agent_host_bindings_v1");
const RETIREMENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("agent_retirements_v1");
const ANCHOR_LIMIT: usize = 128;
const DEVICE_ID_LIMIT: usize = 128;
const SCAN_LIMIT: usize = 65_536;

/// The human pair that approved one agent, plus the agent device used to close its session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentHostBinding {
    pub owner_anchor: String,
    pub desktop: DeviceRef,
    pub primary: DeviceRef,
    pub agent_device: DeviceRef,
}

/// One completed retirement. A second retire leaves this row as it was first written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentRetirement {
    pub owner_anchor: String,
    pub retired_by: DeviceRef,
    pub retired_at: u64,
}

fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

fn refused(code: CustodyRefusal) -> NodeCoreError {
    NodeCoreError::AgentPublishRefused(code)
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= ANCHOR_LIMIT && !value.chars().any(char::is_control)
}

fn device_ok(reference: &DeviceRef, account: &str) -> bool {
    reference.account_anchor == account
        && !reference.device_id.is_empty()
        && reference.device_id.len() <= DEVICE_ID_LIMIT
        && !reference.device_id.chars().any(char::is_control)
}

pub(crate) fn binding_ok(anchor: &str, host: &AgentHostBinding) -> Result<(), NodeCoreError> {
    if !bounded(anchor)
        || !bounded(&host.owner_anchor)
        || !device_ok(&host.desktop, &host.owner_anchor)
        || !device_ok(&host.primary, &host.owner_anchor)
        || !device_ok(&host.agent_device, anchor)
    {
        return Err(refused(CustodyRefusal::InvalidInput));
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, NodeCoreError> {
    serde_json::from_slice(bytes).map_err(error)
}

impl RouterRedbStore {
    pub(crate) fn agent_host(
        &self,
        anchor: &str,
    ) -> Result<Option<AgentHostBinding>, NodeCoreError> {
        if !bounded(anchor) {
            return Ok(None);
        }
        let tx = self.db.begin_read().map_err(error)?;
        let table = match tx.open_table(HOSTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(error(e)),
        };
        let Some(value) = table.get(anchor).map_err(error)? else {
            return Ok(None);
        };
        read_json(value.value()).map(Some)
    }

    pub(crate) fn agent_retirement(
        &self,
        anchor: &str,
    ) -> Result<Option<AgentRetirement>, NodeCoreError> {
        if !bounded(anchor) {
            return Ok(None);
        }
        let tx = self.db.begin_read().map_err(error)?;
        let table = match tx.open_table(RETIREMENTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(error(e)),
        };
        let Some(value) = table.get(anchor).map_err(error)? else {
            return Ok(None);
        };
        read_json(value.value()).map(Some)
    }

    /// `Some("retired")` when a retirement row exists. An unknown anchor is `None`.
    pub(crate) fn agent_lifecycle_label(
        &self,
        anchor: &str,
    ) -> Result<Option<String>, NodeCoreError> {
        Ok(self.agent_retirement(anchor)?.map(|_| "retired".to_owned()))
    }

    /// Host rows whose owner is `owner`. A table larger than [`SCAN_LIMIT`] is refused.
    pub(crate) fn agent_hosts_of(
        &self,
        owner: &str,
    ) -> Result<Vec<(String, AgentHostBinding)>, NodeCoreError> {
        if !bounded(owner) {
            return Ok(Vec::new());
        }
        let tx = self.db.begin_read().map_err(error)?;
        let table = match tx.open_table(HOSTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(error(e)),
        };
        let mut found = Vec::new();
        let mut seen = 0_usize;
        for row in table.iter().map_err(error)? {
            seen += 1;
            if seen > SCAN_LIMIT {
                return Err(NodeCoreError::Capacity { resource: "agent host bindings" });
            }
            let (key, value) = row.map_err(error)?;
            let binding: AgentHostBinding = read_json(value.value())?;
            if binding.owner_anchor == owner {
                found.push((key.value().to_owned(), binding));
            }
        }
        Ok(found)
    }

    /// Insert or replace the host row inside `tx`. A retirement row refuses the write.
    pub(crate) fn insert_agent_host_in_tx(
        tx: &redb::WriteTransaction,
        anchor: &str,
        host: &AgentHostBinding,
    ) -> Result<(), NodeCoreError> {
        binding_ok(anchor, host)?;
        {
            let retirements = tx.open_table(RETIREMENTS).map_err(error)?;
            if retirements.get(anchor).map_err(error)?.is_some() {
                return Err(refused(CustodyRefusal::AgentRetired));
            }
        }
        let bytes = serde_json::to_vec(host).map_err(error)?;
        let mut hosts = tx.open_table(HOSTS).map_err(error)?;
        hosts.insert(anchor, bytes.as_slice()).map_err(error)?;
        Ok(())
    }

    /// Record a retirement. An existing row is left unchanged and this returns `Ok`.
    pub(crate) fn record_agent_retirement(
        &self,
        anchor: &str,
        row: &AgentRetirement,
    ) -> Result<(), NodeCoreError> {
        if !bounded(anchor) || !bounded(&row.owner_anchor) || !bounded(&row.retired_by.device_id) {
            return Err(refused(CustodyRefusal::InvalidInput));
        }
        let tx = self.begin_write().map_err(error)?;
        {
            let mut table = tx.open_table(RETIREMENTS).map_err(error)?;
            if table.get(anchor).map_err(error)?.is_some() {
                return Ok(());
            }
            let bytes = serde_json::to_vec(row).map_err(error)?;
            table.insert(anchor, bytes.as_slice()).map_err(error)?;
        }
        tx.commit().map_err(error)?;
        Ok(())
    }
}
