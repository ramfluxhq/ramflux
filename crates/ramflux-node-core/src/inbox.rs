// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{NodeCoreError, WakeHint};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const ROUTER_ACK_WINDOW: usize = 1024;
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpaqueDeviceInbox {
    next_seq: BTreeMap<String, u64>,
    pending: BTreeMap<String, Vec<InboxEntry>>,
    cursors: BTreeMap<String, CursorAckState>,
}

impl OpaqueDeviceInbox {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, envelope: ramflux_protocol::Envelope) -> InboxEntry {
        let target_delivery_id = envelope.target_delivery_id.clone();
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
        entry
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
        if self.cursors.get(target).is_some_and(|cursor| {
            cursor.acked_inbox_seqs.len() >= ROUTER_ACK_WINDOW
                && entry_seq > cursor.settled_inbox_seq.saturating_add(1)
                && !cursor.acked_inbox_seqs.contains(&entry_seq)
        }) {
            return Err(NodeCoreError::Capacity { resource: "router_ack_window" });
        }
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
        if let Some(entries) = self.pending.get_mut(target) {
            entries.retain(|entry| entry.inbox_seq != entry_seq);
        }
        let result = cursor.clone();
        self.advance_settled(target);
        Ok(self.cursors.get(target).cloned().unwrap_or(result))
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
        let cursor = self
            .cursors
            .entry(target_delivery_id.clone())
            .or_insert(CursorAckState { target_delivery_id, ..CursorAckState::default() });
        cursor.nacked_envelope_ids.insert(nack.envelope_id.clone(), nack.reason.clone());
        while cursor.nacked_envelope_ids.len() > ROUTER_ACK_WINDOW {
            cursor.nacked_envelope_ids.pop_first();
        }
        Ok(cursor.clone())
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
            while cursor.acked_envelope_ids.len() > ROUTER_ACK_WINDOW {
                cursor.acked_envelope_ids.pop_first();
            }
            while cursor.nacked_envelope_ids.len() > ROUTER_ACK_WINDOW {
                cursor.nacked_envelope_ids.pop_first();
            }
        }
    }

    pub(crate) fn expire(&mut self, now: i64) -> usize {
        let mut removed = 0;
        let targets: Vec<_> = self.pending.keys().cloned().collect();
        for target in targets {
            if let Some(entries) = self.pending.get_mut(&target) {
                let before = entries.len();
                entries.retain(|entry| {
                    entry.envelope.created_at.saturating_add(
                        i64::from(entry.envelope.ttl)
                            .min(ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS),
                    ) > now
                });
                removed += before - entries.len();
            }
            self.advance_settled(&target);
        }
        self.pending.retain(|_, entries| !entries.is_empty());
        removed
    }

    #[must_use]
    pub fn cursor_state(&self, target_delivery_id: &str) -> Option<&CursorAckState> {
        self.cursors.get(target_delivery_id)
    }

    pub(crate) fn pending_entries(&self) -> impl Iterator<Item = &InboxEntry> {
        self.pending.values().flat_map(|entries| entries.iter())
    }

    pub(crate) fn cursor_states(&self) -> impl Iterator<Item = &CursorAckState> {
        self.cursors.values()
    }

    pub(crate) fn restore_pending_entry(&mut self, entry: InboxEntry) {
        let cursor = self.cursors.entry(entry.target_delivery_id.clone()).or_insert_with(|| {
            CursorAckState {
                target_delivery_id: entry.target_delivery_id.clone(),
                ..CursorAckState::default()
            }
        });
        cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(entry.inbox_seq);
        let next_seq = self.next_seq.entry(entry.target_delivery_id.clone()).or_insert(1);
        *next_seq = (*next_seq).max(entry.inbox_seq.saturating_add(1));
        let entries = self.pending.entry(entry.target_delivery_id.clone()).or_default();
        if !entries.iter().any(|existing| existing.inbox_seq == entry.inbox_seq) {
            entries.push(entry);
            entries.sort_by_key(|entry| entry.inbox_seq);
        }
    }

    pub(crate) fn restore_cursor_state(&mut self, mut cursor: CursorAckState) {
        cursor.bound_receipts();
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
        for entry in other.pending_entries().cloned() {
            self.restore_pending_entry(entry);
        }
        for cursor in other.cursor_states().cloned() {
            self.restore_cursor_state(cursor);
        }
    }

    pub(crate) fn remove_target(&mut self, target_delivery_id: &str) -> usize {
        let pending_count =
            self.pending.remove(target_delivery_id).map_or(0, |entries| entries.len());
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
    RejectedHomeNodeMigrated(crate::HomeNodeMigratedNackDelivery),
    RejectedDeactivated { target_delivery_id: String },
    RejectedDeleted { target_delivery_id: String },
    RejectedSecurity { target_delivery_id: String, reason: String },
}
