// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{NodeCoreError, WakeHint};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
    pub acked_envelope_ids: BTreeSet<String>,
    pub nacked_envelope_ids: BTreeMap<String, ramflux_protocol::NackReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp0SubmitResponse {
    pub outcome: String,
    pub target_delivery_id: String,
    pub inbox_seq: Option<u64>,
    pub cursor: Option<ItestMvp0CursorResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp0CursorResponse {
    pub target_delivery_id: String,
    pub inbox_seq: u64,
    pub last_envelope_id: Option<String>,
    pub acked_envelope_ids: Vec<String>,
    pub nacked_envelope_ids: BTreeMap<String, ramflux_protocol::NackReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp0BoundAckRequest {
    pub target_delivery_id: String,
    pub ack: ramflux_protocol::Ack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp0BoundNackRequest {
    pub target_delivery_id: String,
    pub nack: ramflux_protocol::Nack,
}

impl From<&CursorAckState> for ItestMvp0CursorResponse {
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
            .or_insert(CursorAckState { target_delivery_id, ..CursorAckState::default() });
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
        let entry_seq = self
            .seq_for_envelope(&target_delivery_id, &ack.envelope_id)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone()))?;
        let cursor = self.cursors.entry(target_delivery_id.clone()).or_insert(CursorAckState {
            target_delivery_id: target_delivery_id.clone(),
            ..CursorAckState::default()
        });
        cursor.inbox_seq = cursor.inbox_seq.max(entry_seq);
        cursor.last_envelope_id = Some(ack.envelope_id.clone());
        cursor.acked_envelope_ids.insert(ack.envelope_id.clone());
        if let Some(entries) = self.pending.get_mut(&target_delivery_id) {
            entries.retain(|entry| entry.envelope.envelope_id != ack.envelope_id);
        }
        Ok(cursor.clone())
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
        Ok(cursor.clone())
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
        let next_seq = self.next_seq.entry(entry.target_delivery_id.clone()).or_insert(1);
        *next_seq = (*next_seq).max(entry.inbox_seq.saturating_add(1));
        let entries = self.pending.entry(entry.target_delivery_id.clone()).or_default();
        if !entries
            .iter()
            .any(|existing| existing.envelope.envelope_id == entry.envelope.envelope_id)
        {
            entries.push(entry);
            entries.sort_by_key(|entry| entry.inbox_seq);
        }
    }

    pub(crate) fn restore_cursor_state(&mut self, cursor: CursorAckState) {
        let next_seq = self.next_seq.entry(cursor.target_delivery_id.clone()).or_insert(1);
        *next_seq = (*next_seq).max(cursor.inbox_seq.saturating_add(1));
        self.cursors.insert(cursor.target_delivery_id.clone(), cursor);
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

    fn seq_for_envelope(&self, target_delivery_id: &str, envelope_id: &str) -> Option<u64> {
        self.pending.get(target_delivery_id).and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.envelope.envelope_id == envelope_id)
                .map(|entry| entry.inbox_seq)
        })
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
    RejectedDeactivated { target_delivery_id: String },
    RejectedDeleted { target_delivery_id: String },
    RejectedSecurity { target_delivery_id: String, reason: String },
}
