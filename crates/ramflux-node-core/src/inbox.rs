// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{NodeCoreError, WakeHint};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const ROUTER_ACK_WINDOW: usize = 1024;
/// NACKs accepted for one delivery before it leaves the redelivery window.
pub const ROUTER_NACK_RETRY_LIMIT: u32 = 3;
/// Metadata-only dead-letter records retained per mailbox.
pub const ROUTER_DEAD_LETTER_LIMIT: usize = 128;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InboxEntry {
    pub inbox_seq: u64,
    pub target_delivery_id: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CursorAckState {
    pub target_delivery_id: String,
    pub inbox_seq: u64,
    pub last_envelope_id: Option<String>,
    #[serde(default)]
    pub settled_inbox_seq: u64,
    #[serde(default)]
    pub issued_inbox_seq: u64,
    #[serde(default)]
    pub recent_ack_ids: VecDeque<String>,
    pub acked_envelope_ids: BTreeSet<String>,
    #[serde(default)]
    pub acked_inbox_seqs: BTreeSet<u64>,
    #[serde(default)]
    pub last_acknowledged_inbox_seq: Option<u64>,
    pub nacked_envelope_ids: BTreeMap<String, ramflux_protocol::NackReason>,
    /// NACK count per outstanding sequence; bounded by the pending mailbox.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nack_attempts: BTreeMap<u64, u32>,
    /// Retired deliveries whose ciphertext was dropped so the ACK window can move.
    #[serde(default, skip_serializing_if = "VecDeque::is_empty")]
    pub dead_letters: VecDeque<DeadLetterRecord>,
    /// Sequences retired by the last mutation; storage removes their rows. Never persisted.
    #[serde(skip)]
    pub retired_inbox_seqs: Vec<u64>,
}

/// Why a delivery left the redelivery window without an ACK.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadLetterReason {
    Nacked(ramflux_protocol::NackReason),
    AckWindowOverflow,
}

/// Dead letters keep no ciphertext: only the sequence, envelope id and reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeadLetterRecord {
    pub inbox_seq: u64,
    pub envelope_id: String,
    pub reason: DeadLetterReason,
    pub retain_until: i64,
}

/// Retention deadline for a delivery accepted at server time `accepted_at`.
///
/// The envelope's own expiry applies, but never beyond seven days after acceptance, so a
/// future-dated `created_at` cannot extend storage.
#[must_use]
pub fn inbox_retain_until(envelope: &ramflux_protocol::Envelope, accepted_at: i64) -> i64 {
    let cap = ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS;
    envelope
        .created_at
        .saturating_add(i64::from(envelope.ttl).min(cap))
        .min(accepted_at.saturating_add(cap))
}

/// Deadline for a delivery stored before acceptance times were recorded: it is treated as
/// accepted at the earlier of its creation and `migrated_at`, so a far-future `created_at`
/// written by an older build still expires seven days after the upgrade.
#[must_use]
pub fn inbox_legacy_retain_until(envelope: &ramflux_protocol::Envelope, migrated_at: i64) -> i64 {
    inbox_retain_until(envelope, envelope.created_at.min(migrated_at))
}

fn server_now() -> i64 {
    i64::try_from(crate::now_unix_seconds()).unwrap_or(i64::MAX)
}

impl CursorAckState {
    fn bound_receipts(&mut self) {
        if self.recent_ack_ids.is_empty() {
            self.recent_ack_ids
                .extend(self.acked_envelope_ids.iter().rev().take(ROUTER_ACK_WINDOW).cloned());
        }
        while self.recent_ack_ids.len() > ROUTER_ACK_WINDOW {
            self.recent_ack_ids.pop_front();
        }
        self.acked_envelope_ids = self.recent_ack_ids.iter().cloned().collect();
        while self.nacked_envelope_ids.len() > ROUTER_ACK_WINDOW {
            self.nacked_envelope_ids.pop_first();
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvelopeSubmitResponse {
    pub outcome: String,
    pub target_delivery_id: String,
    pub inbox_seq: Option<u64>,
    pub cursor: Option<InboxCursorResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nack: Option<ramflux_protocol::Nack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InboxCursorResponse {
    pub target_delivery_id: String,
    pub inbox_seq: u64,
    pub last_envelope_id: Option<String>,
    pub acked_envelope_ids: Vec<String>,
    pub nacked_envelope_ids: BTreeMap<String, ramflux_protocol::NackReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetAckRequest {
    pub target_delivery_id: String,
    pub ack: ramflux_protocol::Ack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetNackRequest {
    pub target_delivery_id: String,
    pub nack: ramflux_protocol::Nack,
}

impl From<&CursorAckState> for InboxCursorResponse {
    fn from(cursor: &CursorAckState) -> Self {
        Self {
            target_delivery_id: cursor.target_delivery_id.clone(),
            inbox_seq: cursor.inbox_seq,
            last_envelope_id: cursor.last_envelope_id.clone(),
            acked_envelope_ids: cursor.acked_envelope_ids.iter().cloned().collect(),
            nacked_envelope_ids: cursor.nacked_envelope_ids.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OpaqueDeviceInbox {
    next_seq: BTreeMap<String, u64>,
    pending: BTreeMap<String, Vec<InboxEntry>>,
    cursors: BTreeMap<String, CursorAckState>,
    /// Server-assigned retention deadline per pending sequence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    retain_until: BTreeMap<String, BTreeMap<u64, i64>>,
    #[serde(skip)]
    expiry: InboxExpiryIndex,
    #[serde(skip)]
    checkpoint_due: BTreeSet<String>,
}

/// Deadline-ordered index so expiry touches only due deliveries.
#[derive(Clone, Debug, Default)]
struct InboxExpiryIndex {
    ready: bool,
    due: BTreeSet<(i64, String, u64)>,
}

impl PartialEq for OpaqueDeviceInbox {
    fn eq(&self, other: &Self) -> bool {
        self.next_seq == other.next_seq
            && self.pending == other.pending
            && self.cursors == other.cursors
            && self.retain_until == other.retain_until
    }
}

impl Eq for OpaqueDeviceInbox {}

impl OpaqueDeviceInbox {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends at the current server time.
    pub fn append(&mut self, envelope: ramflux_protocol::Envelope) -> InboxEntry {
        let now = i64::try_from(crate::now_unix_seconds()).unwrap_or(i64::MAX);
        self.append_at(envelope, now)
    }

    /// Appends a delivery accepted at server time `now`.
    pub fn append_at(&mut self, envelope: ramflux_protocol::Envelope, now: i64) -> InboxEntry {
        let target_delivery_id = envelope.target_delivery_id.clone();
        let retain_until = inbox_retain_until(&envelope, now);
        let next_seq = self.next_seq.entry(target_delivery_id.clone()).or_insert(1);
        let entry = InboxEntry {
            inbox_seq: *next_seq,
            target_delivery_id: target_delivery_id.clone(),
            envelope,
        };
        *next_seq = next_seq.saturating_add(1);
        self.pending.entry(target_delivery_id.clone()).or_default().push(entry.clone());
        self.cursors
            .entry(target_delivery_id.clone())
            .or_insert(CursorAckState { target_delivery_id, ..CursorAckState::default() })
            .issued_inbox_seq = entry.inbox_seq;
        self.set_deadline(&entry.target_delivery_id, entry.inbox_seq, retain_until);
        entry
    }

    /// Server retention deadline of a pending delivery.
    #[must_use]
    pub fn retain_until(&self, entry: &InboxEntry) -> i64 {
        self.retain_until
            .get(&entry.target_delivery_id)
            .and_then(|deadlines| deadlines.get(&entry.inbox_seq))
            .copied()
            .unwrap_or_else(|| inbox_legacy_retain_until(&entry.envelope, server_now()))
    }

    fn set_deadline(&mut self, target: &str, seq: u64, deadline: i64) {
        let previous =
            self.retain_until.entry(target.to_owned()).or_default().insert(seq, deadline);
        if self.expiry.ready {
            if let Some(previous) = previous {
                self.expiry.due.remove(&(previous, target.to_owned(), seq));
            }
            self.expiry.due.insert((deadline, target.to_owned(), seq));
        }
    }

    fn ensure_expiry_index(&mut self) {
        if self.expiry.ready {
            return;
        }
        // Fix deadlines missing from older snapshots once, so they stop moving with the clock.
        let migrated_at = server_now();
        let missing: Vec<(String, u64, i64)> = self
            .pending
            .values()
            .flatten()
            .filter(|entry| {
                self.retain_until
                    .get(&entry.target_delivery_id)
                    .is_none_or(|deadlines| !deadlines.contains_key(&entry.inbox_seq))
            })
            .map(|entry| {
                (
                    entry.target_delivery_id.clone(),
                    entry.inbox_seq,
                    inbox_legacy_retain_until(&entry.envelope, migrated_at),
                )
            })
            .collect();
        for (target, seq, deadline) in missing {
            self.retain_until.entry(target).or_default().insert(seq, deadline);
        }
        let mut due = BTreeSet::new();
        for entries in self.pending.values() {
            for entry in entries {
                due.insert((
                    self.retain_until(entry),
                    entry.target_delivery_id.clone(),
                    entry.inbox_seq,
                ));
            }
        }
        self.expiry = InboxExpiryIndex { ready: true, due };
    }

    /// Removes one pending delivery and its deadline bookkeeping.
    fn retire_pending(&mut self, target: &str, seq: u64) -> Option<InboxEntry> {
        let entries = self.pending.get_mut(target)?;
        let position = entries.iter().position(|entry| entry.inbox_seq == seq)?;
        let entry = entries.remove(position);
        if entries.is_empty() {
            self.pending.remove(target);
        }
        let deadline = self.retain_until(&entry);
        if let Some(deadlines) = self.retain_until.get_mut(target) {
            deadlines.remove(&seq);
            if deadlines.is_empty() {
                self.retain_until.remove(target);
            }
        }
        if self.expiry.ready {
            self.expiry.due.remove(&(deadline, target.to_owned(), seq));
        }
        Some(entry)
    }

    #[must_use]
    pub fn pull_after(
        &self,
        target_delivery_id: &str,
        after_inbox_seq: u64,
        limit: usize,
    ) -> Vec<InboxEntry> {
        self.pending
            .get(target_delivery_id)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| entry.inbox_seq > after_inbox_seq)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Reads only deliveries still inside their retention deadline, without mutating the shard.
    #[must_use]
    pub fn pull_live_after(
        &self,
        target_delivery_id: &str,
        after_inbox_seq: u64,
        limit: usize,
        now: i64,
    ) -> Vec<InboxEntry> {
        self.pending
            .get(target_delivery_id)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| entry.inbox_seq > after_inbox_seq)
                    .filter(|entry| self.retain_until(entry) > now)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn apply_ack(
        &mut self,
        ack: &ramflux_protocol::Ack,
    ) -> Result<CursorAckState, NodeCoreError> {
        let Some(target_delivery_id) = self.target_for_envelope(&ack.envelope_id) else {
            if let Some(cursor) = self
                .cursors
                .values()
                .find(|cursor| cursor.acked_envelope_ids.contains(&ack.envelope_id))
            {
                return Ok(cursor.clone());
            }
            return Err(NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone()));
        };
        self.apply_ack_for_target(&target_delivery_id, ack)
    }

    /// A server-assigned sequence selects one delivery even when sender-chosen IDs collide.
    /// # Errors
    /// Rejects missing deliveries, mismatched IDs, and ambiguous legacy selectors.
    pub fn apply_ack_for_target(
        &mut self,
        target: &str,
        ack: &ramflux_protocol::Ack,
    ) -> Result<CursorAckState, NodeCoreError> {
        let entry_seq = match ack.ext.ext.get("inbox_seq") {
            Some(value) => value
                .as_u64()
                .filter(|seq| *seq > 0)
                .ok_or_else(|| NodeCoreError::ItestHttp("invalid ACK inbox sequence".into()))?,
            None => self
                .legacy_seq_for_envelope(target, &ack.envelope_id)?
                .ok_or_else(|| NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone()))?,
        };
        if !ack.ext.ext.contains_key("inbox_seq")
            && self.cursors.get(target).is_some_and(|cursor| {
                cursor.acked_envelope_ids.contains(&ack.envelope_id)
                    && !cursor.acked_inbox_seqs.contains(&entry_seq)
            })
        {
            return Err(NodeCoreError::AmbiguousEnvelopeId(ack.envelope_id.clone()));
        }
        let pending = self
            .pending
            .get(target)
            .and_then(|entries| entries.iter().find(|entry| entry.inbox_seq == entry_seq));
        if let Some(entry) = pending {
            if entry.envelope.envelope_id != ack.envelope_id {
                return Err(NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone()));
            }
        } else if !self.cursors.get(target).is_some_and(|cursor| {
            cursor.acked_inbox_seqs.contains(&entry_seq) || entry_seq <= cursor.settled_inbox_seq
        }) {
            return Err(NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone()));
        }
        let cursor = self.cursors.entry(target.into()).or_insert(CursorAckState {
            target_delivery_id: target.into(),
            ..CursorAckState::default()
        });
        cursor.retired_inbox_seqs.clear();
        self.make_ack_window_room(target, entry_seq);
        let cursor = self.cursors.entry(target.into()).or_insert(CursorAckState {
            target_delivery_id: target.into(),
            ..CursorAckState::default()
        });
        cursor.inbox_seq = cursor.inbox_seq.max(entry_seq);
        cursor.last_envelope_id = Some(ack.envelope_id.clone());
        cursor.last_acknowledged_inbox_seq = Some(entry_seq);
        if cursor.acked_envelope_ids.insert(ack.envelope_id.clone()) {
            cursor.recent_ack_ids.push_back(ack.envelope_id.clone());
        }
        while cursor.recent_ack_ids.len() > ROUTER_ACK_WINDOW {
            if let Some(old) = cursor.recent_ack_ids.pop_front() {
                cursor.acked_envelope_ids.remove(&old);
            }
        }
        cursor.acked_inbox_seqs.insert(entry_seq);
        cursor.nack_attempts.remove(&entry_seq);
        let result = cursor.clone();
        self.retire_pending(target, entry_seq);
        self.advance_settled(target);
        Ok(self.cursors.get(target).cloned().unwrap_or(result))
    }

    /// One stuck delivery must not stall later ACKs: once the out-of-order window is full,
    /// the oldest outstanding deliveries move to the dead-letter record.
    fn make_ack_window_room(&mut self, target: &str, entry_seq: u64) {
        loop {
            let Some(cursor) = self.cursors.get(target) else {
                return;
            };
            if cursor.acked_inbox_seqs.len() < ROUTER_ACK_WINDOW
                || entry_seq <= cursor.settled_inbox_seq.saturating_add(1)
                || cursor.acked_inbox_seqs.contains(&entry_seq)
            {
                return;
            }
            let head = self.pending.get(target).and_then(|entries| {
                entries.iter().map(|entry| entry.inbox_seq).filter(|seq| *seq < entry_seq).min()
            });
            let Some(head) = head else {
                return;
            };
            self.dead_letter(target, head, DeadLetterReason::AckWindowOverflow);
            self.advance_settled(target);
        }
    }

    /// Drops the ciphertext and records only metadata, so redelivery and WAL replay skip it.
    fn dead_letter(&mut self, target: &str, seq: u64, reason: DeadLetterReason) {
        let Some(retain_until) = self
            .pending
            .get(target)
            .and_then(|entries| entries.iter().find(|entry| entry.inbox_seq == seq))
            .map(|entry| self.retain_until(entry))
        else {
            return;
        };
        let Some(entry) = self.retire_pending(target, seq) else {
            return;
        };
        let cursor = self.cursors.entry(target.into()).or_insert(CursorAckState {
            target_delivery_id: target.into(),
            ..CursorAckState::default()
        });
        cursor.nack_attempts.remove(&seq);
        if seq > cursor.settled_inbox_seq {
            cursor.acked_inbox_seqs.insert(seq);
        }
        cursor.retired_inbox_seqs.push(seq);
        cursor.dead_letters.push_back(DeadLetterRecord {
            inbox_seq: seq,
            envelope_id: entry.envelope.envelope_id,
            reason,
            retain_until,
        });
        while cursor.dead_letters.len() > ROUTER_DEAD_LETTER_LIMIT {
            cursor.dead_letters.pop_front();
        }
        self.checkpoint_due.insert(target.to_owned());
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn apply_nack(
        &mut self,
        nack: &ramflux_protocol::Nack,
    ) -> Result<CursorAckState, NodeCoreError> {
        let Some(target_delivery_id) = self.target_for_envelope(&nack.envelope_id) else {
            if let Some(cursor) = self
                .cursors
                .values()
                .find(|cursor| cursor.nacked_envelope_ids.contains_key(&nack.envelope_id))
            {
                return Ok(cursor.clone());
            }
            if let Some(cursor) = self
                .cursors
                .values()
                .find(|cursor| cursor.acked_envelope_ids.contains(&nack.envelope_id))
            {
                return Ok(cursor.clone());
            }
            return Err(NodeCoreError::EnvelopeNotFound(nack.envelope_id.clone()));
        };
        self.apply_nack_for_target(&target_delivery_id, nack)
    }

    /// Records a NACK; after [`ROUTER_NACK_RETRY_LIMIT`] NACKs the delivery is dead-lettered.
    /// # Errors
    /// Rejects an invalid sequence selector or an ambiguous legacy envelope id.
    pub fn apply_nack_for_target(
        &mut self,
        target: &str,
        nack: &ramflux_protocol::Nack,
    ) -> Result<CursorAckState, NodeCoreError> {
        let seq =
            match nack.ext.ext.get("inbox_seq") {
                Some(value) => Some(value.as_u64().filter(|seq| *seq > 0).ok_or_else(|| {
                    NodeCoreError::ItestHttp("invalid NACK inbox sequence".into())
                })?),
                None => self.legacy_seq_for_envelope(target, &nack.envelope_id)?,
            }
            .filter(|seq| {
                self.pending.get(target).is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry.inbox_seq == *seq && entry.envelope.envelope_id == nack.envelope_id
                    })
                })
            });
        let cursor = self.cursors.entry(target.into()).or_insert(CursorAckState {
            target_delivery_id: target.into(),
            ..CursorAckState::default()
        });
        cursor.retired_inbox_seqs.clear();
        cursor.nacked_envelope_ids.insert(nack.envelope_id.clone(), nack.reason.clone());
        while cursor.nacked_envelope_ids.len() > ROUTER_ACK_WINDOW {
            cursor.nacked_envelope_ids.pop_first();
        }
        if let Some(seq) = seq {
            let attempts = cursor.nack_attempts.entry(seq).or_default();
            *attempts = attempts.saturating_add(1);
            if *attempts >= ROUTER_NACK_RETRY_LIMIT {
                self.dead_letter(target, seq, DeadLetterReason::Nacked(nack.reason.clone()));
                self.advance_settled(target);
            }
        }
        self.cursors
            .get(target)
            .cloned()
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(nack.envelope_id.clone()))
    }

    fn advance_settled(&mut self, target: &str) {
        let issued = self.next_seq.get(target).copied().unwrap_or(1).saturating_sub(1);
        let settled = self
            .pending
            .get(target)
            .and_then(|entries| entries.iter().map(|entry| entry.inbox_seq).min())
            .map_or(issued, |first| first.saturating_sub(1));
        if let Some(cursor) = self.cursors.get_mut(target) {
            cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(issued);
            cursor.settled_inbox_seq = cursor.settled_inbox_seq.max(settled);
            cursor.acked_inbox_seqs.retain(|seq| *seq > cursor.settled_inbox_seq);
            let pending = self.pending.get(target);
            cursor.nack_attempts.retain(|seq, _| {
                pending.is_some_and(|entries| entries.iter().any(|entry| entry.inbox_seq == *seq))
            });
            while cursor.acked_envelope_ids.len() > ROUTER_ACK_WINDOW {
                cursor.acked_envelope_ids.pop_first();
            }
            while cursor.nacked_envelope_ids.len() > ROUTER_ACK_WINDOW {
                cursor.nacked_envelope_ids.pop_first();
            }
        }
    }

    /// Removes deliveries whose server deadline has passed, visiting only due index entries.
    pub(crate) fn expire(&mut self, now: i64) -> usize {
        self.expire_entries(now).len()
    }

    /// Like [`Self::expire`], returning the removed deliveries.
    pub(crate) fn expire_entries(&mut self, now: i64) -> Vec<InboxEntry> {
        self.ensure_expiry_index();
        let mut removed = Vec::new();
        let mut touched = BTreeSet::new();
        while let Some((deadline, target, seq)) = self.expiry.due.first().cloned() {
            if deadline > now {
                break;
            }
            self.expiry.due.pop_first();
            if let Some(entry) = self.retire_pending(&target, seq) {
                removed.push(entry);
            }
            touched.insert(target);
        }
        for target in touched {
            self.advance_settled(&target);
            if let Some(cursor) = self.cursors.get_mut(&target) {
                cursor.dead_letters.retain(|record| record.retain_until > now);
            }
            self.checkpoint_due.insert(target);
        }
        removed
    }

    /// Cursors changed by expiry, dead-lettering or recovery that need a durable checkpoint.
    pub(crate) fn take_checkpoint_due(&mut self) -> Vec<CursorAckState> {
        std::mem::take(&mut self.checkpoint_due)
            .into_iter()
            .filter_map(|target| self.cursors.get(&target).cloned())
            .collect()
    }

    /// Marks cursors whose checkpoint could not be saved as due again.
    pub(crate) fn requeue_checkpoints(&mut self, targets: impl IntoIterator<Item = String>) {
        for target in targets {
            if self.cursors.contains_key(&target) {
                self.checkpoint_due.insert(target);
            }
        }
    }

    /// Never reuse a sequence that a recovered log already issued, even if it expired.
    pub(crate) fn observe_issued_seq(&mut self, target: &str, seq: u64) {
        let next_seq = self.next_seq.entry(target.to_owned()).or_insert(1);
        if *next_seq > seq {
            return;
        }
        *next_seq = seq.saturating_add(1);
        let cursor = self.cursors.entry(target.to_owned()).or_insert(CursorAckState {
            target_delivery_id: target.to_owned(),
            ..CursorAckState::default()
        });
        cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(seq);
        self.advance_settled(target);
        self.checkpoint_due.insert(target.to_owned());
    }

    #[must_use]
    pub fn cursor_state(&self, target_delivery_id: &str) -> Option<&CursorAckState> {
        self.cursors.get(target_delivery_id)
    }

    pub(crate) fn pending_entries(&self) -> impl Iterator<Item = &InboxEntry> {
        self.pending.values().flat_map(|entries| entries.iter())
    }

    /// Pending deliveries with their server retention deadlines.
    pub(crate) fn pending_entries_with_deadline(&self) -> impl Iterator<Item = (&InboxEntry, i64)> {
        self.pending_entries().map(|entry| (entry, self.retain_until(entry)))
    }

    pub(crate) fn cursor_states(&self) -> impl Iterator<Item = &CursorAckState> {
        self.cursors.values()
    }

    /// Restores a delivery; a missing deadline falls back to the envelope's capped expiry.
    pub(crate) fn restore_pending_entry_until(
        &mut self,
        entry: InboxEntry,
        retain_until: Option<i64>,
    ) {
        let cursor = self.cursors.entry(entry.target_delivery_id.clone()).or_insert_with(|| {
            CursorAckState {
                target_delivery_id: entry.target_delivery_id.clone(),
                ..CursorAckState::default()
            }
        });
        cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(entry.inbox_seq);
        let next_seq = self.next_seq.entry(entry.target_delivery_id.clone()).or_insert(1);
        *next_seq = (*next_seq).max(entry.inbox_seq.saturating_add(1));
        let target = entry.target_delivery_id.clone();
        let seq = entry.inbox_seq;
        let deadline = retain_until
            .unwrap_or_else(|| inbox_legacy_retain_until(&entry.envelope, server_now()));
        let entries = self.pending.entry(target.clone()).or_default();
        if !entries.iter().any(|existing| existing.inbox_seq == seq) {
            entries.push(entry);
            entries.sort_by_key(|entry| entry.inbox_seq);
            self.set_deadline(&target, seq, deadline);
        }
    }

    pub(crate) fn restore_cursor_state(&mut self, mut cursor: CursorAckState) {
        cursor.bound_receipts();
        cursor.retired_inbox_seqs.clear();
        let next_seq = self.next_seq.entry(cursor.target_delivery_id.clone()).or_insert(1);
        *next_seq =
            (*next_seq).max(cursor.inbox_seq.max(cursor.issued_inbox_seq).saturating_add(1));
        self.cursors.insert(cursor.target_delivery_id.clone(), cursor);
    }

    pub(crate) fn bound_retained_receipts(&mut self) {
        for cursor in self.cursors.values_mut() {
            cursor.bound_receipts();
        }
    }

    pub(crate) fn merge_from(&mut self, other: &Self) {
        for (entry, deadline) in other.pending_entries_with_deadline() {
            self.restore_pending_entry_until(entry.clone(), Some(deadline));
        }
        for cursor in other.cursor_states().cloned() {
            self.restore_cursor_state(cursor);
        }
    }

    pub(crate) fn remove_target(&mut self, target_delivery_id: &str) -> usize {
        let pending_count =
            self.pending.remove(target_delivery_id).map_or(0, |entries| entries.len());
        if self.retain_until.remove(target_delivery_id).is_some() {
            self.expiry = InboxExpiryIndex::default();
        }
        self.checkpoint_due.remove(target_delivery_id);
        let cursor_count = usize::from(self.cursors.remove(target_delivery_id).is_some());
        let seq_count = usize::from(self.next_seq.remove(target_delivery_id).is_some());
        pending_count.saturating_add(cursor_count).saturating_add(seq_count)
    }

    pub(crate) fn target_for_envelope(&self, envelope_id: &str) -> Option<String> {
        self.pending.iter().find_map(|(target, entries)| {
            entries
                .iter()
                .any(|entry| entry.envelope.envelope_id == envelope_id)
                .then(|| target.clone())
        })
    }

    fn legacy_seq_for_envelope(
        &self,
        target: &str,
        id: &str,
    ) -> Result<Option<u64>, NodeCoreError> {
        let Some(entries) = self.pending.get(target) else {
            return Ok(None);
        };
        let mut matching = entries.iter().filter(|entry| entry.envelope.envelope_id == id);
        let first = matching.next().map(|entry| entry.inbox_seq);
        if matching.next().is_some() {
            return Err(NodeCoreError::AmbiguousEnvelopeId(id.into()));
        }
        Ok(first)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OnlineDelivery {
    pub gateway_id: String,
    pub session_id: String,
    pub target_delivery_id: String,
    pub inbox_seq: u64,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OfflineQueuedDelivery {
    pub entry: InboxEntry,
    pub wake_hint: WakeHint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RouterSubmitOutcome {
    Online(OnlineDelivery),
    OfflineQueued(OfflineQueuedDelivery),
    ForwardedHomeNodeMigrated(Box<crate::HomeNodeMigrationForwardDelivery>),
    ForwardInProgress { target_delivery_id: String },
    DuplicateFederatedForward { target_delivery_id: String },
    RejectedHomeNodeMigrated(crate::HomeNodeMigratedNackDelivery),
    RejectedDeactivated { target_delivery_id: String },
    RejectedDeleted { target_delivery_id: String },
    RejectedSecurity { target_delivery_id: String, reason: String },
}
