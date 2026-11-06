// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded sparse coverage over the published mailbox.
use crate::{DeadLetterReason, InboxEntry, OpaqueDeviceInbox, RouterCore};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, cmp::Ordering, io, ops::Bound};

pub const PAGE_BYTE_CAP: usize = 1_048_576 - 65_536;
pub(crate) const VISIT_CAP: usize = 512;

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
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("page size overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn measured<T: Serialize>(value: &T) -> Result<usize, PageError> {
    #[cfg(test)]
    MEASUREMENTS.with(|count| count.set(count.get() + 1));
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value).map_err(|_| PageError::Serialization)?;
    Ok(count.0)
}
#[derive(Serialize)]
struct BorrowedRecord<'a> {
    entry: &'a InboxEntry,
    retain_until: i64,
}
impl ResumePage {
    fn push_loss(
        &mut self,
        from: u64,
        to: u64,
        reason: PageReason,
        size: &mut usize,
    ) -> Result<bool, PageError> {
        let merges = self
            .known_losses
            .last()
            .is_some_and(|last| last.to_seq.checked_add(1) == Some(from) && last.reason == reason);
        if !merges {
            if self.known_losses.len() == 64 {
                return Ok(false);
            }
            let added = measured(&KnownLoss { from_seq: u64::MAX, to_seq: u64::MAX, reason })?
                + usize::from(!self.known_losses.is_empty());
            if *size + added > PAGE_BYTE_CAP {
                return Ok(false);
            }
            *size += added;
        }
        add_loss(self, from, to, reason);
        Ok(true)
    }
    fn push_entry(
        &mut self,
        entry: &InboxEntry,
        deadline: i64,
        header: usize,
        size: &mut usize,
    ) -> Result<bool, PageError> {
        let record_size = measured(&BorrowedRecord { entry, retain_until: deadline })?;
        if header + record_size > PAGE_BYTE_CAP {
            self.oversize_next = Some(entry.inbox_seq);
            return Ok(false);
        }
        let added = record_size + usize::from(!self.entries.is_empty());
        if *size + added > PAGE_BYTE_CAP {
            return Ok(false);
        }
        *size += added;
        self.entries.push(PageEntryRecord { entry: entry.clone(), retain_until: deadline });
        Ok(true)
    }
    fn worst_header_size(&self) -> Result<usize, PageError> {
        // Called once while both arrays are empty; reserve all mutable header widths.
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
    fn empty(request: PageRequest<'_>, id: Option<&str>, (issued, settled): (u64, u64)) -> Self {
        Self {
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
        }
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
            let (issued, settled, ranges) = core.page_view(target, id, after);
            return self.build_page(
                PageRequest { target, after, limit, now },
                (issued, settled),
                ranges.into_iter(),
            );
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
        let mut page = ResumePage::empty(request, self.incarnation_id(target), (issued, settled));
        let header_size = page.worst_header_size()?;
        if header_size > 16 * 1024 {
            return Err(PageError::HeaderTooLarge);
        }
        let mut size = header_size;
        let start = page.covered_through_seq;
        let mut pending = seek_rows(self.pending.get(target), start);
        let mut dead = seek_rows(self.dead_letter_index.get(target), start);
        let mut visits = 0;
        let mut p = next_counted(&mut pending, &mut visits);
        let mut d = next_counted(&mut dead, &mut visits);
        let mut aborted = aborted.by_ref().inspect(|_| observe_visit());
        let mut a = next_counted(&mut aborted, &mut visits);
        loop {
            #[cfg(test)]
            WALK_HOOK.with(|hook| {
                if let Some(hook) = hook.borrow().as_ref() {
                    hook();
                }
            });
            if p.budget_spent() || d.budget_spent() || a.budget_spent() {
                break;
            }
            let next = [
                p.item().map(|(k, _)| k.0),
                d.item().map(|(k, _)| k.0),
                a.item().map(|(lo, _)| lo.max(start.saturating_add(1))),
            ]
            .into_iter()
            .flatten()
            .min();
            let Some(seq) = next.filter(|s| *s <= issued) else {
                page.covered_through_seq = issued;
                break;
            };
            page.covered_through_seq = page.covered_through_seq.max(seq - 1);
            let mut end = seq;
            let mut loss = None;
            if let Some((_, entry)) = p.item().filter(|(k, _)| k.0 == seq) {
                let deadline = self.retain_until(entry);
                if deadline > now {
                    if page.entries.len() == limit.min(256) {
                        break;
                    }
                    if !page.push_entry(entry, deadline, header_size, &mut size)? {
                        break;
                    }
                } else {
                    loss = Some(PageReason::Expired);
                }
            } else if let Some((_, row)) = d.item().filter(|(k, _)| k.0 == seq) {
                if row.retain_until > now {
                    loss = Some(match row.reason {
                        DeadLetterReason::AckWindowOverflow => PageReason::AckWindowOverflow,
                        DeadLetterReason::Nacked(_) => PageReason::Nacked,
                    });
                }
            } else if let Some((_, hi)) = a.item() {
                end = hi.min(issued);
                loss = Some(PageReason::Aborted);
            }
            if let Some(reason) = loss
                && !page.push_loss(seq, end, reason, &mut size)?
            {
                break;
            }
            page.covered_through_seq = end;
            if p.item().is_some_and(|(k, _)| k.0 <= end) {
                p = next_counted(&mut pending, &mut visits);
            }
            if d.item().is_some_and(|(k, _)| k.0 <= end) {
                d = next_counted(&mut dead, &mut visits);
            }
            if a.item().is_some_and(|(_, hi)| hi <= end) {
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
enum Counted<T> {
    Item(T),
    Exhausted,
    BudgetSpent,
}
impl<T: Copy> Counted<T> {
    fn item(&self) -> Option<T> {
        match self {
            Self::Item(item) => Some(*item),
            _ => None,
        }
    }
    fn budget_spent(&self) -> bool {
        matches!(self, Self::BudgetSpent)
    }
}
fn next_counted<I: Iterator>(iter: &mut I, visits: &mut usize) -> Counted<I::Item> {
    if *visits >= VISIT_CAP {
        return Counted::BudgetSpent;
    }
    match iter.next() {
        Some(item) => {
            *visits += 1;
            Counted::Item(item)
        }
        None => Counted::Exhausted,
    }
}
#[cfg(test)]
thread_local! { static MEASUREMENTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; static WALK_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) }; }
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
