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
    /// Local account id the agent account is committed under. Chosen at begin on the initiating
    /// desktop; `None` on the receiving primary, which never creates the account.
    pub account_id: Option<String>,
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
    /// Highest master-certificate range issued for this agent. Written before the certificate is
    /// requested (write-ahead), so a cleanup deletes every certificate item that can exist.
    #[serde(default)]
    pub master_range: u64,
    /// Signed agent profile (canonical bytes), written with the commit bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_b64: Option<String>,
    /// Publication receipt (canonical bytes), written once the receipt has been compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_b64: Option<String>,
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

/// Directory of creation records, one file per request id. It lives inside the data directory
/// of the human account that owns the request (`custody_accounts/<human>/agent_creation`), on
/// the desktop (initiator) and on the primary (receiver) alike.
#[derive(Clone, Debug)]
pub struct AgentCreationStore {
    root: PathBuf,
    dir: PathBuf,
}

impl AgentCreationStore {
    /// Open (and create) the record directory of one human account under its data root.
    /// # Errors
    /// `CustodyVaultUnavailable` when the directory cannot be created; `CustodySetupInvalid` for
    /// an invalid human account id.
    pub fn open(root: impl Into<PathBuf>, human_account_id: &str) -> Result<Self, SdkError> {
        crate::custody::valid_id(human_account_id)?;
        let root = root.into();
        let dir = root.join("custody_accounts").join(human_account_id).join("agent_creation");
        std::fs::create_dir_all(&dir).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        Ok(Self { root, dir })
    }

    /// True when the agent account of this local id has published its authority: the commit point
    /// of a creation. Read from the data root, so a restart sees a commit even when the record
    /// still says `authorized`.
    /// # Errors
    /// `CustodyVaultUnavailable` when the account directory cannot be inspected.
    pub fn account_committed(&self, account_id: &str) -> Result<bool, SdkError> {
        crate::custody::valid_id(account_id)?;
        self.root
            .join("custody_accounts")
            .join(account_id)
            .join("authority.json")
            .try_exists()
            .map_err(|_| SdkError::CustodyVaultUnavailable)
    }

    /// Whether the record's agent account has its authority on this root (false without an id).
    /// # Errors
    /// Propagates [`Self::account_committed`] failures.
    pub(super) fn committed(&self, record: &AgentCreationRecord) -> Result<bool, SdkError> {
        match &record.account_id {
            Some(account_id) => self.account_committed(account_id),
            None => Ok(false),
        }
    }

    /// Data root that the agent account is committed under.
    #[must_use]
    pub(crate) fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// The record whose agent account has this local id, if any. Scans this directory only.
    /// # Errors
    /// Propagates [`Self::load`] failures and refuses a directory that cannot be read.
    pub fn find_by_account(
        &self,
        account_id: &str,
    ) -> Result<Option<AgentCreationRecord>, SdkError> {
        let entries =
            std::fs::read_dir(&self.dir).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| SdkError::CustodyVaultUnavailable)?;
            let name = entry.file_name();
            let Some(request_id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
                continue;
            };
            if let Some(record) = self.load(request_id)?
                && record.account_id.as_deref() == Some(account_id)
            {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Every record that still needs a step: `authorized`, `publication_pending` or
    /// `publication_unknown`, oldest request id first.
    /// # Errors
    /// Refuses a directory that cannot be read and any record that fails [`Self::load`].
    pub fn pending(&self) -> Result<Vec<AgentCreationRecord>, SdkError> {
        let entries =
            std::fs::read_dir(&self.dir).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| SdkError::CustodyVaultUnavailable)?;
            let name = entry.file_name();
            let Some(request_id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
                continue;
            };
            if let Some(record) = self.load(request_id)?
                && matches!(
                    record.state,
                    AgentCreationState::Authorized
                        | AgentCreationState::PublicationPending
                        | AgentCreationState::PublicationUnknown
                )
            {
                records.push(record);
            }
        }
        records.sort_by(|left, right| left.request_id.cmp(&right.request_id));
        Ok(records)
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
        check_account_id(&record)?;
        check_consistency(&record)?;
        Ok(Some(record))
    }

    /// Persist one record atomically and durably before the caller acts on it.
    /// # Errors
    /// Refuses an inconsistent record and reports I/O failures without partial writes.
    pub fn save(&self, record: &AgentCreationRecord) -> Result<(), SdkError> {
        check_consistency(record)?;
        check_account_id(record)?;
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

fn check_account_id(record: &AgentCreationRecord) -> Result<(), SdkError> {
    match &record.account_id {
        Some(account_id) => crate::custody::valid_id(account_id),
        None => Ok(()),
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
