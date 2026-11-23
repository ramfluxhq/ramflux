// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable note that this device learned its own branch is revoked.
//! The file is absent until that proof is stored. It is not a field of the
//! stored authority, so an account that has not learned revocation keeps its format.

use super::rebind::{RebindBinding, RebindEntry};
use super::state::AgentCreationState;
use super::store::{AgentCreationRecord, AgentCreationStore, write_json_atomic};
use crate::SdkError;
use ramflux_protocol::custody::decode_register_plan;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "host_branch_revoked.json";
const MAX_MARKER_BYTES: usize = 4 * 1024;
const MAX_FIELD: usize = 128;

/// Account anchor stored in a readable revocation marker.
#[must_use]
pub(crate) fn marked_account_anchor(root: &Path, account_id: &str) -> Option<String> {
    let path = marker_path(root, account_id).ok()?;
    let bytes = std::fs::read(path).ok()?;
    if !marker_bytes_ok(&bytes) {
        return None;
    }
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("account_anchor")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Whether this account has a readable revocation marker.
#[must_use]
pub(crate) fn host_branch_marked(root: &Path, account_id: &str) -> bool {
    let Ok(path) = marker_path(root, account_id) else {
        return false;
    };
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    marker_bytes_ok(&bytes)
}

/// Store the marker. A second call leaves the first file in place.
/// # Errors
/// Refuses an invalid account id or a failed write.
pub(crate) fn note_host_branch_revoked(
    root: &Path,
    account_id: &str,
    device_id: &str,
    device_epoch: u64,
    account_anchor: &str,
    learned_at: u64,
) -> Result<(), SdkError> {
    if host_branch_marked(root, account_id) {
        return Ok(());
    }
    let path = marker_path(root, account_id)?;
    let dir = path.parent().ok_or(SdkError::CustodySetupInvalid)?;
    if !dir.is_dir() {
        return Err(SdkError::CustodySetupInvalid);
    }
    let bytes = serde_json::to_vec(&serde_json::json!({
        "device_id": device_id,
        "device_epoch": device_epoch,
        "account_anchor": account_anchor,
        "learned_at": learned_at,
    }))
    .map_err(|_| SdkError::CustodySetupInvalid)?;
    if !marker_bytes_ok(&bytes) {
        return Err(SdkError::CustodySetupInvalid);
    }
    write_json_atomic(dir, FILE_NAME, &bytes)
}

/// Store the marker when this verified publication revokes the local device.
/// A publication that leaves the device active writes nothing, so a pairing
/// adoption that is still pending does not suspend the desktop.
/// # Errors
/// Refuses an invalid device id or a failed marker or inventory write.
pub(crate) fn note_if_verified_revokes(
    root: &Path,
    account_id: &str,
    local: &crate::custody::BornAccount,
    verified: &ramflux_crypto::custody::VerifiedRecord,
    now: u64,
) -> Result<bool, SdkError> {
    if verified.envelope().body.account_anchor != local.record().body.account_anchor {
        return Ok(false);
    }
    let device_id = local.local_device_id()?;
    if !verified.revoked_ids().contains(device_id) {
        return Ok(false);
    }
    let epoch = local
        .record()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == device_id)
        .map_or(0, |device| device.device_epoch);
    note_host_branch_revoked(
        root,
        account_id,
        device_id,
        epoch,
        &local.record().body.account_anchor,
        now,
    )?;
    suspend_hosted_agents(root, account_id)?;
    Ok(true)
}

fn marker_bytes_ok(bytes: &[u8]) -> bool {
    if bytes.len() > MAX_MARKER_BYTES {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    bounded(object, "device_id")
        && bounded(object, "account_anchor")
        && object.get("device_epoch").and_then(serde_json::Value::as_u64).is_some()
        && object.get("learned_at").and_then(serde_json::Value::as_u64).is_some()
}

fn bounded(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty() && value.len() <= MAX_FIELD)
}

/// Move every settled complete agent to rebind-pending without a request id.
/// An account with no creation directory is left untouched. R and C stay as they are,
/// so a plan is not sent while the local primary is still the one that was bound.
/// # Errors
/// Refuses an unreadable creation directory or a failed inventory write.
pub(crate) fn suspend_hosted_agents(root: &Path, account_id: &str) -> Result<(), SdkError> {
    let directory = root.join("custody_accounts").join(account_id).join("agent_creation");
    if !directory.is_dir() {
        return Ok(());
    }
    let store = AgentCreationStore::open(root, account_id)?;
    for (agent_id, record) in complete_agents(&store)? {
        suspend_one(&store, &agent_id, &record)?;
    }
    Ok(())
}

fn marker_path(root: &Path, account_id: &str) -> Result<PathBuf, SdkError> {
    crate::custody::valid_id(account_id)?;
    Ok(root.join("custody_accounts").join(account_id).join(FILE_NAME))
}

fn complete_agents(
    store: &AgentCreationStore,
) -> Result<BTreeMap<String, AgentCreationRecord>, SdkError> {
    let mut latest = BTreeMap::new();
    for record in store.records()? {
        if record.state != AgentCreationState::Complete {
            continue;
        }
        let Some(account_id) = record.account_id.clone() else {
            continue;
        };
        let replace = latest
            .get(&account_id)
            .is_none_or(|known: &AgentCreationRecord| record.master_range > known.master_range);
        if replace {
            latest.insert(account_id, record);
        }
    }
    Ok(latest)
}

fn suspend_one(
    store: &AgentCreationStore,
    agent_id: &str,
    record: &AgentCreationRecord,
) -> Result<(), SdkError> {
    if let Some(existing) = store.load_rebind(agent_id)? {
        if !existing.binding.is_settled() {
            return Ok(());
        }
        return store.save_rebind(&RebindEntry {
            binding: RebindBinding::RebindPending,
            request_id: None,
            failure: None,
            ..existing
        });
    }
    if record.master_range == 0 {
        return Ok(());
    }
    let bytes = record.plan_bytes()?;
    let plan = decode_register_plan(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    if plan.human_primary.device_id.is_empty() {
        return Ok(());
    }
    store.save_rebind(&RebindEntry {
        agent_account_id: agent_id.to_owned(),
        binding: RebindBinding::RebindPending,
        bound_primary: plan.human_primary,
        master_range: record.master_range,
        request_id: None,
        failure: None,
    })
}
