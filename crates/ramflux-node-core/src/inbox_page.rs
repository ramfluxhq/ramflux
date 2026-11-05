// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded sparse coverage over the published mailbox.
use crate::{DeadLetterReason, InboxEntry, OpaqueDeviceInbox, RouterCore};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, cmp::Ordering, io, ops::Bound};

pub const PAGE_BYTE_CAP: usize = 1_048_576 - 65_536;
const VISIT_CAP: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SequenceKey(pub u64);
impl From<u64> for SequenceKey {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
impl Borrow<u64> for SequenceKey {
    fn borrow(&self) -> &u64 {
        &self.0
    }
}
impl PartialOrd for SequenceKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SequenceKey {
    fn cmp(&self, other: &Self) -> Ordering {
        #[cfg(test)]
        COMPARISONS.with(|count| count.set(count.get() + 1));
        self.0.cmp(&other.0)
    }
}
#[cfg(test)]
thread_local! { static COMPARISONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PageEntryRecord {
    pub entry: InboxEntry,
    pub retain_until: i64,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PageReason {
    Expired,
    AckWindowOverflow,
    Nacked,
    Aborted,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KnownLoss {
    pub from_seq: u64,
    pub to_seq: u64,
    pub reason: PageReason,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResumePage {
    pub frame_type: String,
    pub target_delivery_id: String,
    pub incarnation_id: Option<String>,
    pub after_inbox_seq: u64,
    pub covered_through_seq: u64,
    pub issued_inbox_seq: u64,
    pub settled_through_seq: u64,
    pub entries: Vec<PageEntryRecord>,
    pub known_losses: Vec<KnownLoss>,
    pub oversize_next: Option<u64>,
    pub more: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PageError {
    #[error("invalid_limit")]
    InvalidLimit,
    #[error("cursor_ahead")]
    CursorAhead,
    #[error("payload_too_large")]
    HeaderTooLarge,
    #[error("page_serialization_failed")]
    Serialization,
}
struct Counter(usize);
impl io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn measured<T: Serialize>(value: &T) -> Result<usize, PageError> {
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value).map_err(|_| PageError::Serialization)?;
    Ok(count.0)
}
impl ResumePage {
    fn worst_size(&self) -> Result<usize, PageError> {
        // Borrow the same schema: only mutable header fields change width.
        let mut header = self.clone();
        header.after_inbox_seq = u64::MAX;
        header.covered_through_seq = u64::MAX;
        header.issued_inbox_seq = u64::MAX;
        header.settled_through_seq = u64::MAX;
        header.oversize_next = Some(u64::MAX);
        header.more = false;
        measured(&header)
    }
}
#[derive(Clone, Copy)]
struct PageRequest<'a> {
    target: &'a str,
    after: u64,
    limit: usize,
    now: i64,
}
impl ResumePage {
    fn empty(
        request: PageRequest<'_>,
        id: Option<&str>,
        (issued, settled): (u64, u64),
    ) -> Result<Self, PageError> {
        let page = Self {
            frame_type: "resume_page".into(),
            target_delivery_id: request.target.into(),
            incarnation_id: id.map(str::to_owned),
            after_inbox_seq: request.after,
            covered_through_seq: request.after.max(settled),
            issued_inbox_seq: issued,
            settled_through_seq: settled,
            entries: Vec::new(),
            known_losses: Vec::new(),
            oversize_next: None,
            more: false,
        };
        if page.worst_size()? > 16 * 1024 {
            return Err(PageError::HeaderTooLarge);
        }
        Ok(page)
    }
}
impl RouterCore {
    /// Reads one published coverage page under the target shard lock.
    /// # Errors
    /// Rejects zero limits, cursors above publication, and oversized headers.
    pub fn resume_page(
        &self,
        target: &str,
        after: u64,
        limit: usize,
        now: i64,
    ) -> Result<ResumePage, PageError> {
        self.target_shard(target).inbox.resume_page(target, after, limit, now)
    }
}
impl OpaqueDeviceInbox {
    /// Builds a page without deleting expired rows or creating an unknown inbox.
    /// # Errors
    /// Returns a typed input or serialization refusal.
    pub fn resume_page(
        &self,
        target: &str,
        after: u64,
        limit: usize,
        now: i64,
    ) -> Result<ResumePage, PageError> {
        if limit == 0 {
            return Err(PageError::InvalidLimit);
        }
        let id = self.incarnation_id(target);
        if let (Some(core), Some(id)) = (&self.publication, id) {
            return core.with_page_view(target, id, |issued, settled, ranges| {
                let start = after.max(settled);
                let lower = ranges
                    .range(..=start)
                    .next_back()
                    .filter(|(_, end)| **end > start)
                    .map_or(Bound::Excluded(start), |(&lo, _)| Bound::Included(lo));
                self.build_page(
                    PageRequest { target, after, limit, now },
                    (issued, settled),
                    ranges.range((lower, Bound::Unbounded)).map(|(&lo, &hi)| (lo, hi)),
                )
            });
        }
        let issued = self.issued_sequence(target);
        let settled = self.cursor_state(target).map_or(0, |c| c.settled_inbox_seq.min(issued));
        let ranges = self.aborted_ranges.get(target).map_or(&[][..], Vec::as_slice);
        let start = after.max(settled);
        self.build_page(
            PageRequest { target, after, limit, now },
            (issued, settled),
            ranges[ranges.partition_point(|(_, end)| *end <= start)..].iter().copied(),
        )
    }

    fn build_page(
        &self,
        request: PageRequest<'_>,
        (issued, settled): (u64, u64),
        mut aborted: impl Iterator<Item = (u64, u64)>,
    ) -> Result<ResumePage, PageError> {
        let PageRequest { target, after, limit, now } = request;
        if after > issued {
            return Err(PageError::CursorAhead);
        }
        let mut page = ResumePage::empty(request, self.incarnation_id(target), (issued, settled))?;
        let start = page.covered_through_seq;
        let mut pending = seek_rows(self.pending.get(target), start);
        let mut dead = seek_rows(self.dead_letter_index.get(target), start);
        // Every fetched boundary, including lookahead, consumes one visit.
        let mut visits = 0;
        let mut p = next_counted(&mut pending, &mut visits);
        let mut d = next_counted(&mut dead, &mut visits);
        let mut aborted = aborted.by_ref().inspect(|_| observe_visit());
        let mut a = next_counted(&mut aborted, &mut visits);
        loop {
            let next = [
                p.map(|(k, _)| k.0),
                d.map(|(k, _)| k.0),
                a.map(|(lo, _)| lo.max(start.saturating_add(1))),
            ]
            .into_iter()
            .flatten()
            .min();
            let Some(seq) = next.filter(|s| *s <= issued) else {
                page.covered_through_seq = issued;
                break;
            };
            page.covered_through_seq = page.covered_through_seq.max(seq - 1);
            let mut candidate = page.clone();
            let mut end = seq;
            if p.is_some_and(|(k, _)| k.0 == seq) {
                let (_, entry) = p.ok_or(PageError::Serialization)?;
                let deadline = self.retain_until(entry);
                if deadline > now {
                    if candidate.entries.len() == limit.min(256) {
                        break;
                    }
                    let record = PageEntryRecord { entry: entry.clone(), retain_until: deadline };
                    let mut alone = page.clone();
                    alone.entries = vec![record.clone()];
                    alone.known_losses.clear();
                    if alone.worst_size()? > PAGE_BYTE_CAP {
                        page.oversize_next = Some(seq);
                        break;
                    }
                    candidate.entries.push(record);
                } else {
                    add_loss(&mut candidate, seq, seq, PageReason::Expired);
                }
            } else if d.is_some_and(|(k, _)| k.0 == seq) {
                let (_, row) = d.ok_or(PageError::Serialization)?;
                if row.retain_until > now {
                    add_loss(
                        &mut candidate,
                        seq,
                        seq,
                        match row.reason {
                            DeadLetterReason::AckWindowOverflow => PageReason::AckWindowOverflow,
                            DeadLetterReason::Nacked(_) => PageReason::Nacked,
                        },
                    );
                }
            } else if let Some((_, hi)) = a {
                end = hi.min(issued);
                add_loss(&mut candidate, seq, end, PageReason::Aborted);
            }
            candidate.covered_through_seq = end;
            if candidate.known_losses.len() > 64 || candidate.worst_size()? > PAGE_BYTE_CAP {
                break;
            }
            page = candidate;
            // Stop before loading another key if the shared visit budget is spent.
            let advance_pending = p.is_some_and(|(k, _)| k.0 <= end);
            let advance_dead = d.is_some_and(|(k, _)| k.0 <= end);
            let advance_abort = a.is_some_and(|(_, hi)| hi <= end);
            if visits
                + usize::from(advance_pending)
                + usize::from(advance_dead)
                + usize::from(advance_abort)
                > VISIT_CAP
            {
                break;
            }
            if p.is_some_and(|(k, _)| k.0 <= end) {
                p = next_counted(&mut pending, &mut visits);
            }
            if d.is_some_and(|(k, _)| k.0 <= end) {
                d = next_counted(&mut dead, &mut visits);
            }
            if a.is_some_and(|(_, hi)| hi <= end) {
                a = next_counted(&mut aborted, &mut visits);
            }
        }
        page.more = page.covered_through_seq < issued;
        let bytes = serde_json::to_vec(&page).map_err(|_| PageError::Serialization)?;
        if bytes.len() > PAGE_BYTE_CAP {
            return Err(PageError::Serialization);
        }
        Ok(page)
    }
}
fn seek_rows<V>(
    rows: Option<&std::collections::BTreeMap<SequenceKey, V>>,
    start: u64,
) -> impl Iterator<Item = (&SequenceKey, &V)> {
    rows.into_iter()
        .flat_map(move |rows| rows.range((Bound::Excluded(SequenceKey(start)), Bound::Unbounded)))
        .inspect(|_| observe_visit())
}
fn observe_visit() {
    #[cfg(test)]
    VISITS.with(|count| count.set(count.get() + 1));
}
fn next_counted<I: Iterator>(iter: &mut I, visits: &mut usize) -> Option<I::Item> {
    if *visits == VISIT_CAP {
        return None;
    }
    let item = iter.next();
    if item.is_some() {
        *visits += 1;
    }
    item
}
fn add_loss(page: &mut ResumePage, from_seq: u64, to_seq: u64, reason: PageReason) {
    if let Some(last) = page
        .known_losses
        .last_mut()
        .filter(|last| last.to_seq.checked_add(1) == Some(from_seq) && last.reason == reason)
    {
        last.to_seq = to_seq;
    } else {
        page.known_losses.push(KnownLoss { from_seq, to_seq, reason });
    }
}
#[cfg(test)]
mod tests;
