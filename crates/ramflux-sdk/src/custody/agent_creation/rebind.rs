// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-agent rebind inventory of the creation store (contract §7.6 binding states L, R, C, B).
//! One JSON file per agent account under `agent_creation/rebind/`. It holds public identifiers,
//! the bound primary and the master range only: no key material, no prose.
use super::state::AgentFailure;
use super::store::{AgentCreationStore, write_json_atomic};
use crate::SdkError;
use ramflux_protocol::custody::DeviceRef;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read};
use std::path::PathBuf;

/// Upper bound on one inventory file.
const MAX_ENTRY_BYTES: u64 = 16 * 1024;
/// Subdirectory of the creation directory that holds the inventory.
const REBIND_DIR: &str = "rebind";

/// Binding state of one agent against the human's current primary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebindBinding {
    /// L: live under the primary it was approved for.
    Live,
    /// R: a primary change was observed; the agent is paused until the new primary approves.
    RebindPending,
    /// C: a valid rebind bundle is committed and waits for its publication receipt.
    Committed,
    /// B: a rebound binding is live under the current primary.
    Bound,
}

impl RebindBinding {
    /// Stable wire token (equal to the serde name).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::RebindPending => "rebind_pending",
            Self::Committed => "committed",
            Self::Bound => "bound",
        }
    }

    /// L and B are the settled bindings: only these are compared with the current primary.
    /// R and C never return to a settled state by an observation (old-head proofs never clear R).
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Live | Self::Bound)
    }
}

/// Inventory entry of one agent account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebindEntry {
    pub agent_account_id: String,
    pub binding: RebindBinding,
    /// Primary the binding was approved for. The observation compares it with the current primary.
    pub bound_primary: DeviceRef,
    /// Highest master-certificate range issued for the agent.
    pub master_range: u64,
    /// Rebind request that moves this binding, when one exists.
    pub request_id: Option<String>,
    /// Typed reason beside the state (`custody_key_unavailable`, `creation_primary_changed`).
    pub failure: Option<AgentFailure>,
}

impl AgentCreationStore {
    /// Persist one inventory entry atomically.
    /// # Errors
    /// `CustodySetupInvalid` for an invalid account id or range; `CustodyVaultUnavailable` for I/O.
    pub fn save_rebind(&self, entry: &RebindEntry) -> Result<(), SdkError> {
        check_entry(entry)?;
        let bytes = serde_json::to_vec(entry).map_err(|_| SdkError::CustodySetupInvalid)?;
        let dir = self.rebind_dir();
        std::fs::create_dir_all(&dir).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        write_json_atomic(&dir, &format!("{}.json", entry.agent_account_id), &bytes)
    }

    /// Load the entry of one agent account. `Ok(None)` when none exists.
    /// # Errors
    /// `CustodySetupInvalid` for an invalid id, an oversized, corrupt or mismatched file.
    pub fn load_rebind(&self, agent_account_id: &str) -> Result<Option<RebindEntry>, SdkError> {
        crate::custody::valid_id(agent_account_id)?;
        let path = self.rebind_dir().join(format!("{agent_account_id}.json"));
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(SdkError::CustodyVaultUnavailable),
        };
        let mut bytes = Vec::new();
        file.take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ENTRY_BYTES {
            return Err(SdkError::CustodySetupInvalid);
        }
        let entry: RebindEntry =
            serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
        if entry.agent_account_id != agent_account_id {
            return Err(SdkError::CustodySetupInvalid);
        }
        check_entry(&entry)?;
        Ok(Some(entry))
    }

    /// Every inventory entry, sorted by agent account id. An absent inventory is empty.
    /// # Errors
    /// Refuses a directory that cannot be read and any entry that fails [`Self::load_rebind`].
    pub fn rebind_entries(&self) -> Result<Vec<RebindEntry>, SdkError> {
        let dir = self.rebind_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(SdkError::CustodyVaultUnavailable),
        };
        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| SdkError::CustodyVaultUnavailable)?;
            let name = entry.file_name();
            let Some(account_id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
                continue;
            };
            if let Some(found_entry) = self.load_rebind(account_id)? {
                found.push(found_entry);
            }
        }
        found.sort_by(|left, right| left.agent_account_id.cmp(&right.agent_account_id));
        Ok(found)
    }

    fn rebind_dir(&self) -> PathBuf {
        self.dir.join(REBIND_DIR)
    }
}

fn check_entry(entry: &RebindEntry) -> Result<(), SdkError> {
    crate::custody::valid_id(&entry.agent_account_id)?;
    if entry.master_range == 0 || entry.bound_primary.device_id.is_empty() {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(())
}
