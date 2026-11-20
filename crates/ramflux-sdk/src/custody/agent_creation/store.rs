// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable local record of each agent creation request. One JSON file per request id, written
//! with a temporary file, `sync_all` and an atomic rename. The record holds public bytes and
//! vault reference names only: no key material is ever written here.
use super::state::{AgentCreationState, AgentFailure};
use crate::SdkError;
use ramflux_protocol::custody::{decode_register_plan, register_plan_hash};
use ramflux_protocol::decode_base64url;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;

/// Upper bound on one record file. A plan is at most a few kilobytes.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// Persisted state of one request. `plan_b64` and `decision_b64` are canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCreationRecord {
    pub request_id: String,
    /// Empty only while `state` is `preparing`.
    pub request_hash: String,
    pub plan_b64: String,
    pub state: AgentCreationState,
    /// Stored plan issue time. Restarts never restart the deadline.
    pub issued_at: u64,
    /// Stored plan expiry (the original deadline).
    pub expires_at: u64,
    /// Pending vault items to delete before the request can close.
    pub vault_refs: Vec<String>,
    /// Target state recorded while cleanup is pending.
    pub intended: Option<AgentCreationState>,
    pub failure: Option<AgentFailure>,
    pub decision_b64: Option<String>,
}

impl AgentCreationRecord {
    /// Canonical plan bytes.
    /// # Errors
    /// Refuses a record whose plan field is not canonical base64url.
    pub fn plan_bytes(&self) -> Result<Vec<u8>, SdkError> {
        decode_base64url(&self.plan_b64).map_err(|_| SdkError::CustodySetupInvalid)
    }

    /// Saved decision bytes, when a decision was accepted or refused.
    /// # Errors
    /// Refuses a record whose decision field is not canonical base64url.
    pub fn decision_bytes(&self) -> Result<Option<Vec<u8>>, SdkError> {
        self.decision_b64
            .as_deref()
            .map(|value| decode_base64url(value).map_err(|_| SdkError::CustodySetupInvalid))
            .transpose()
    }
}

/// Directory of creation records, one file per request id.
#[derive(Debug)]
pub struct AgentCreationStore {
    dir: PathBuf,
}

impl AgentCreationStore {
    /// Open (and create) the record directory.
    /// # Errors
    /// `CustodyVaultUnavailable` when the directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, SdkError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        Ok(Self { dir })
    }

    /// Load one record. `Ok(None)` when no record exists for the id.
    /// # Errors
    /// Refuses an invalid id, an oversized or corrupt file, or a plan that does not match the
    /// stored hash and validity window.
    pub fn load(&self, request_id: &str) -> Result<Option<AgentCreationRecord>, SdkError> {
        let path = self.path(request_id)?;
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(SdkError::CustodyVaultUnavailable),
        };
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECORD_BYTES {
            return Err(SdkError::CustodySetupInvalid);
        }
        let record: AgentCreationRecord =
            serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
        if record.request_id != request_id {
            return Err(SdkError::CustodySetupInvalid);
        }
        check_consistency(&record)?;
        Ok(Some(record))
    }

    /// Persist one record atomically and durably before the caller acts on it.
    /// # Errors
    /// Refuses an inconsistent record and reports I/O failures without partial writes.
    pub fn save(&self, record: &AgentCreationRecord) -> Result<(), SdkError> {
        check_consistency(record)?;
        let bytes = serde_json::to_vec(record).map_err(|_| SdkError::CustodySetupInvalid)?;
        let path = self.path(&record.request_id)?;
        let tmp = self.dir.join(format!("{}.json.tmp", record.request_id));
        {
            let mut file =
                std::fs::File::create(&tmp).map_err(|_| SdkError::CustodyVaultUnavailable)?;
            file.write_all(&bytes).map_err(|_| SdkError::CustodyVaultUnavailable)?;
            file.sync_all().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        }
        std::fs::rename(&tmp, &path).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        crate::platform::fs::sync_path(&self.dir).map_err(|_| SdkError::CustodyVaultUnavailable)
    }

    fn path(&self, request_id: &str) -> Result<PathBuf, SdkError> {
        crate::custody::valid_id(request_id)?;
        Ok(self.dir.join(format!("{request_id}.json")))
    }
}

/// A record must describe one exact plan: its hash, deadline and identity are re-derived from
/// the canonical bytes. A preparing record has no plan yet.
fn check_consistency(record: &AgentCreationRecord) -> Result<(), SdkError> {
    if record.state == AgentCreationState::Preparing {
        return if record.plan_b64.is_empty() && record.request_hash.is_empty() {
            Ok(())
        } else {
            Err(SdkError::CustodySetupInvalid)
        };
    }
    let bytes = decode_base64url(&record.plan_b64).map_err(|_| SdkError::CustodySetupInvalid)?;
    let plan = decode_register_plan(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    let hash = register_plan_hash(&plan).map_err(|_| SdkError::CustodySetupInvalid)?;
    if plan.request_id != record.request_id
        || hash != record.request_hash
        || plan.issued_at != record.issued_at
        || plan.expires_at != record.expires_at
    {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(())
}
