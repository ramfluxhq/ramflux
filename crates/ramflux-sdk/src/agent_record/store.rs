// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! File store of the agent records of one owner: one JSON file per agent, written atomically and
//! read back under a size bound. A file that names another agent, or that fails `check_record`, is
//! refused.
use super::{StoredAgentRecord, check_record};
use crate::SdkError;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;

/// Upper bound on one record file.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

pub(crate) struct AgentRecordStore {
    dir: PathBuf,
}

impl AgentRecordStore {
    /// The store in `dir`. Nothing is created until a record is saved.
    pub(crate) fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Load the record of one agent; `Ok(None)` when none exists.
    /// # Errors
    /// `CustodySetupInvalid` for an invalid id, an oversized, corrupt or mismatched file.
    pub(crate) fn load(&self, agent_anchor: &str) -> Result<Option<StoredAgentRecord>, SdkError> {
        crate::custody::valid_id(agent_anchor)?;
        let file = match std::fs::File::open(self.dir.join(format!("{agent_anchor}.json"))) {
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
        let record: StoredAgentRecord =
            serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
        if record.agent_anchor != agent_anchor {
            return Err(SdkError::CustodySetupInvalid);
        }
        check_record(&record)?;
        Ok(Some(record))
    }

    /// Persist one record atomically (temporary file, sync, rename, directory sync).
    /// # Errors
    /// `CustodySetupInvalid` for a record outside the closed shapes; `CustodyVaultUnavailable` for I/O.
    pub(crate) fn save(&self, record: &StoredAgentRecord) -> Result<(), SdkError> {
        check_record(record)?;
        let bytes = serde_json::to_vec(record).map_err(|_| SdkError::CustodySetupInvalid)?;
        std::fs::create_dir_all(&self.dir).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        crate::custody::agent_creation::write_json_atomic(
            &self.dir,
            &format!("{}.json", record.agent_anchor),
            &bytes,
        )
    }
}

#[cfg(test)]
impl AgentRecordStore {
    /// The directory of the store, for tests that plant a file.
    pub(crate) fn dir_for_test(&self) -> &std::path::Path {
        &self.dir
    }
}
