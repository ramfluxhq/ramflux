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
/// Upper bound on the records of one `agent.list` page.
const MAX_PAGE: usize = 100;

/// One change read of `AgentRecordStore::changes`.
pub(crate) struct Changes {
    pub(crate) records: Vec<StoredAgentRecord>,
    /// The cursor to pass to the next read.
    pub(crate) cursor: u64,
    /// Whether more changes follow `cursor`.
    pub(crate) more: bool,
}

/// Parses a `journal_cursor` (decimal, canonical; empty is the start, `0`). Anything else refuses.
/// # Errors
/// `journal_cursor_invalid` for a non-canonical or overflowing value.
pub(crate) fn parse_cursor(text: &str) -> Result<u64, SdkError> {
    if text.is_empty() {
        return Ok(0);
    }
    let value: u64 =
        text.parse().map_err(|_| SdkError::AgentCreationRefused("journal_cursor_invalid"))?;
    if value.to_string() != text {
        return Err(SdkError::AgentCreationRefused("journal_cursor_invalid"));
    }
    Ok(value)
}

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

    /// Persist one record atomically (temporary file, sync, rename, directory sync). The write takes
    /// the next change sequence of this owner (one more than the highest stored), so `agent.watch`
    /// sees it after every earlier cursor.
    /// # Errors
    /// `CustodySetupInvalid` for a record outside the closed shapes; `CustodyVaultUnavailable` for I/O.
    pub(crate) fn save(&self, record: &mut StoredAgentRecord) -> Result<(), SdkError> {
        record.change_seq = self.head()?.checked_add(1).ok_or(SdkError::CustodySetupInvalid)?;
        check_record(record)?;
        let bytes = serde_json::to_vec(record).map_err(|_| SdkError::CustodySetupInvalid)?;
        std::fs::create_dir_all(&self.dir).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        crate::custody::agent_creation::write_json_atomic(
            &self.dir,
            &format!("{}.json", record.agent_anchor),
            &bytes,
        )
    }

    /// Every stored record of this owner, loaded through `load` (so each one is checked).
    fn all(&self) -> Result<Vec<StoredAgentRecord>, SdkError> {
        let mut records = Vec::new();
        for anchor in self.anchors()? {
            if let Some(record) = self.load(&anchor)? {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// The highest change sequence stored for this owner; `0` when no record exists.
    pub(crate) fn head(&self) -> Result<u64, SdkError> {
        Ok(self.all()?.iter().map(|record| record.change_seq).max().unwrap_or(0))
    }

    /// The records written after `cursor` (tombstones included), in change order, at most
    /// `MAX_PAGE`. `cursor` is the sequence of the last delivered record or of a previous `head`.
    /// `more` is true when records remain; the next call then starts from `cursor`.
    /// # Errors
    /// `journal_cursor_invalid` for a cursor above the stored head (not issued by this owner's store;
    /// the caller lists again); the refusals of `load` for a bad record.
    pub(crate) fn changes(&self, cursor: u64) -> Result<Changes, SdkError> {
        let head = self.head()?;
        if cursor > head {
            return Err(SdkError::AgentCreationRefused("journal_cursor_invalid"));
        }
        let mut changed: Vec<StoredAgentRecord> =
            self.all()?.into_iter().filter(|record| record.change_seq > cursor).collect();
        changed.sort_by_key(|record| record.change_seq);
        let more = changed.len() > MAX_PAGE;
        changed.truncate(MAX_PAGE);
        let next =
            if more { changed.last().map_or(cursor, |record| record.change_seq) } else { head };
        Ok(Changes { records: changed, cursor: next, more })
    }

    /// The anchors of the stored files, in anchor order.
    fn anchors(&self) -> Result<Vec<String>, SdkError> {
        let mut anchors: Vec<String> = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter_map(|name| name.strip_suffix(".json").map(str::to_owned))
                .collect(),
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err(SdkError::CustodyVaultUnavailable),
        };
        anchors.sort_unstable();
        Ok(anchors)
    }

    /// One page of the records of this owner in agent-anchor order, after `after` when given. `next`
    /// names the last anchor of the page when more records follow it. An empty or missing directory
    /// is an empty page.
    /// # Errors
    /// `CustodyVaultUnavailable` for a listing failure; the refusals of `load` for a bad record.
    pub(crate) fn page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<StoredAgentRecord>, Option<String>), SdkError> {
        let anchors = self.anchors()?;
        let start =
            after.map_or(0, |cursor| anchors.partition_point(|anchor| anchor.as_str() <= cursor));
        let rest = anchors.get(start..).unwrap_or_default();
        let take = limit.clamp(1, MAX_PAGE);
        let mut records = Vec::new();
        for anchor in rest.iter().take(take) {
            if let Some(record) = self.load(anchor)? {
                records.push(record);
            }
        }
        let next = if rest.len() > take { rest.get(take.saturating_sub(1)).cloned() } else { None };
        Ok((records, next))
    }
}

#[cfg(test)]
impl AgentRecordStore {
    /// The directory of the store, for tests that plant a file.
    pub(crate) fn dir_for_test(&self) -> &std::path::Path {
        &self.dir
    }
}
