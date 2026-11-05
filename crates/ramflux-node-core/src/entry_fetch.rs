// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A point view classifies disappearance before measuring a live legacy record.
use crate::{DeadLetterReason, InboxEntry, OpaqueDeviceInbox, PageEntryRecord, RouterCore};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryGoneReason {
    Expired,
    AckWindowOverflow,
    Nacked,
    Aborted,
    Unknown,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
pub enum InboxEntryResponse {
    Entry {
        incarnation_id: Option<String>,
        record: Box<PageEntryRecord>,
    },
    EntryTooLarge {
        incarnation_id: Option<String>,
        inbox_seq: u64,
        retain_until: i64,
    },
    EntryGone {
        incarnation_id: Option<String>,
        inbox_seq: u64,
        observed_issued_inbox_seq: u64,
        reason: EntryGoneReason,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EntryFetchError {
    #[error("invalid_seq")]
    InvalidSeq,
    #[error("entry_serialization_failed")]
    Serialization,
}
#[derive(Serialize)]
struct BorrowedEntryReply<'a> {
    frame_type: &'static str,
    incarnation_id: Option<&'a str>,
    record: BorrowedRecord<'a>,
}
#[derive(Serialize)]
struct BorrowedRecord<'a> {
    entry: &'a InboxEntry,
    retain_until: i64,
}
impl RouterCore {
    /// Return the exact published entry or an authoritative terminal point result.
    /// # Errors
    /// Rejects zero/unpublished sequences and encoding failures without creating state.
    pub fn fetch_entry(
        &self,
        target: &str,
        seq: u64,
        now: i64,
    ) -> Result<InboxEntryResponse, EntryFetchError> {
        self.target_shard(target).inbox.fetch_entry(target, seq, now)
    }
}
impl OpaqueDeviceInbox {
    /// Read a point under its caller's inbox lock; expiry is observed without deleting rows.
    /// # Errors
    /// Rejects invalid sequences and serialization errors.
    pub fn fetch_entry(
        &self,
        target: &str,
        seq: u64,
        now: i64,
    ) -> Result<InboxEntryResponse, EntryFetchError> {
        if let (Some(core), Some(id)) = (&self.publication, self.incarnation_id(target)) {
            return core.with_page_view(target, id, |issued, _, ranges| {
                let aborted = ranges.range(..=seq).next_back().is_some_and(|(_, end)| *end >= seq);
                self.point_view(target, seq, now, issued, aborted)
            });
        }
        let ranges = self.aborted_ranges.get(target).map_or(&[][..], Vec::as_slice);
        let index = ranges.partition_point(|(lo, _)| *lo <= seq);
        let aborted = index.checked_sub(1).is_some_and(|i| ranges[i].1 >= seq);
        self.point_view(target, seq, now, self.issued_sequence(target), aborted)
    }
    fn point_view(
        &self,
        target: &str,
        seq: u64,
        now: i64,
        issued: u64,
        aborted: bool,
    ) -> Result<InboxEntryResponse, EntryFetchError> {
        if seq == 0 || seq > issued {
            return Err(EntryFetchError::InvalidSeq);
        }
        let id = self.incarnation_id(target);
        let entry = self.pending.get(target).and_then(|rows| rows.get(&seq));
        let reason = if let Some(entry) = entry {
            let deadline = self.retain_until(entry);
            if deadline > now {
                let wire = BorrowedEntryReply {
                    frame_type: "entry",
                    incarnation_id: id,
                    record: BorrowedRecord { entry, retain_until: deadline },
                };
                let size = crate::entry_bound::serialized_size(&wire)
                    .map_err(|_| EntryFetchError::Serialization)?;
                return if size > crate::ENTRY_FRAME_BYTE_CAP {
                    Ok(InboxEntryResponse::EntryTooLarge {
                        incarnation_id: id.map(str::to_owned),
                        inbox_seq: seq,
                        retain_until: deadline,
                    })
                } else {
                    Ok(InboxEntryResponse::Entry {
                        incarnation_id: id.map(str::to_owned),
                        record: Box::new(PageEntryRecord {
                            entry: entry.clone(),
                            retain_until: deadline,
                        }),
                    })
                };
            }
            EntryGoneReason::Expired
        } else if let Some(row) = self
            .dead_letter_index
            .get(target)
            .and_then(|rows| rows.get(&seq))
            .filter(|row| row.retain_until > now)
        {
            match row.reason {
                DeadLetterReason::Nacked(_) => EntryGoneReason::Nacked,
                DeadLetterReason::AckWindowOverflow => EntryGoneReason::AckWindowOverflow,
            }
        } else if aborted {
            EntryGoneReason::Aborted
        } else {
            EntryGoneReason::Unknown
        };
        Ok(InboxEntryResponse::EntryGone {
            incarnation_id: id.map(str::to_owned),
            inbox_seq: seq,
            observed_issued_inbox_seq: issued,
            reason,
        })
    }
}
#[cfg(test)]
mod tests;
