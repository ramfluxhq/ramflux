// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{InboxEntry, NodeCoreError, durability_io};

#[cfg(test)]
mod durability_tests;
#[cfg(test)]
pub(crate) mod fatal_tests;
pub(crate) mod identity;
#[cfg(test)]
pub(crate) mod identity_tests;
#[cfg(test)]
mod maintenance_tests;
#[cfg(test)]
mod segment_tests;
#[cfg(test)]
mod startup_tests;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const ROUTER_WAL_SEGMENT_BYTES_ENV: &str = "RAMFLUX_ROUTER_WAL_SEGMENT_BYTES";
const ROUTER_WAL_SEGMENT_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;
const ROUTER_WAL_BATCH_MAX_ENV: &str = "RAMFLUX_ROUTER_WAL_BATCH_MAX";
const ROUTER_WAL_BATCH_MAX_DEFAULT: usize = 256;
const ROUTER_WAL_COMMIT_WINDOW_US_ENV: &str = "RAMFLUX_ROUTER_WAL_COMMIT_WINDOW_US";
const ROUTER_WAL_COMMIT_WINDOW_US_DEFAULT: u64 = 0;
const ROUTER_WAL_QUEUE_CAPACITY_ENV: &str = "RAMFLUX_ROUTER_WAL_QUEUE_CAPACITY";
const ROUTER_WAL_QUEUE_CAPACITY_DEFAULT: usize = 65_536;
const ROUTER_WAL_SHARDS_ENV: &str = "RAMFLUX_ROUTER_WAL_SHARDS";
const ROUTER_WAL_PIPELINE_ENV: &str = "RAMFLUX_ROUTER_WAL_PIPELINE";
const ROUTER_WAL_SHARD_DIR_PREFIX: &str = "router-wal-shard-";
const ROUTER_WAL_MAGIC: &[u8] = b"ramflux-router-wal-v1\n";
/// Extra time after the retention window before a closed segment is unlinked: one roll
/// interval plus the 30-second sweep, so recovered watermarks are checkpointed first.
const ROUTER_WAL_RETIRE_MARGIN_SECONDS: u64 = 3_600 + 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouterWalRecordLocation {
    pub segment_id: u64,
    pub offset: u64,
    pub len: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouterWalPayload {
    Submission {
        replay_key: String,
        replay_expires_at: i64,
        entry: Option<Box<InboxEntry>>,
        /// Server acceptance time; absent in records written before deadlines were logged.
        accepted_at: Option<i64>,
        local_delivery: Option<RouterWalLocalDelivery>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterWalLocalDelivery {
    pub sender_root_commitment: String,
    pub envelope_id: String,
    pub target_delivery_id: String,
}

/// Postcard encodes the variant index, so new record shapes are appended, never edited.
#[derive(Deserialize, Serialize)]
enum StoredRouterWalPayload {
    Submission {
        replay_key: String,
        replay_expires_at: i64,
        entry: Option<Box<StoredRouterWalInboxEntry>>,
    },
    SubmissionAccepted {
        replay_key: String,
        replay_expires_at: i64,
        accepted_at: i64,
        entry: Option<Box<StoredRouterWalInboxEntry>>,
    },
    SubmissionClassified {
        replay_key: String,
        replay_expires_at: i64,
        accepted_at: i64,
        entry: Option<Box<StoredRouterWalInboxEntry>>,
        local_delivery: RouterWalLocalDelivery,
    },
    Incarnated {
        incarnation_id: String,
        payload: Box<StoredRouterWalPayload>,
    },
    /// New classified receipts carry a complete sender assignment; older variants keep legacy replay.
    SenderAssigned {
        payload: Box<StoredRouterWalPayload>,
    },
}

#[derive(Deserialize, Serialize)]
struct StoredRouterWalInboxEntry {
    inbox_seq: u64,
    target_delivery_id: String,
    envelope: StoredRouterWalEnvelope,
}

#[derive(Deserialize, Serialize)]
struct StoredRouterWalEnvelope {
    schema: String,
    version: u32,
    domain: String,
    ext_json: Option<Vec<u8>>,
    signed: ramflux_protocol::SignedFields,
    envelope_id: String,
    source_principal_id: String,
    source_device_id: String,
    target_delivery_id: String,
    routing_set_id: Option<String>,
    delivery_class: ramflux_protocol::DeliveryClass,
    priority: ramflux_protocol::Priority,
    ttl: u32,
    created_at: i64,
    encrypted_payload: String,
    payload_hash: String,
}

impl StoredRouterWalPayload {
    fn sender_assigned(&self) -> bool {
        match self {
            Self::SenderAssigned { .. } => true,
            Self::Incarnated { payload, .. } => payload.sender_assigned(),
            _ => false,
        }
    }
}

impl TryFrom<&RouterWalPayload> for StoredRouterWalPayload {
    type Error = NodeCoreError;

    fn try_from(payload: &RouterWalPayload) -> Result<Self, Self::Error> {
        match payload {
            RouterWalPayload::Submission {
                replay_key,
                replay_expires_at,
                entry,
                accepted_at,
                local_delivery,
            } => {
                let entry = entry
                    .as_ref()
                    .map(|entry| StoredRouterWalInboxEntry::try_from(entry.as_ref()))
                    .transpose()?
                    .map(Box::new);
                let stored = match (accepted_at, local_delivery) {
                    (Some(accepted_at), Some(local_delivery)) => Self::SubmissionClassified {
                        replay_key: replay_key.clone(),
                        replay_expires_at: *replay_expires_at,
                        accepted_at: *accepted_at,
                        entry,
                        local_delivery: local_delivery.clone(),
                    },
                    (Some(accepted_at), None) => Self::SubmissionAccepted {
                        replay_key: replay_key.clone(),
                        replay_expires_at: *replay_expires_at,
                        accepted_at: *accepted_at,
                        entry,
                    },
                    (None, _) => Self::Submission {
                        replay_key: replay_key.clone(),
                        replay_expires_at: *replay_expires_at,
                        entry,
                    },
                };
                Ok(if local_delivery.is_some() {
                    Self::SenderAssigned { payload: Box::new(stored) }
                } else {
                    stored
                })
            }
        }
    }
}

impl TryFrom<StoredRouterWalPayload> for RouterWalPayload {
    type Error = NodeCoreError;

    fn try_from(payload: StoredRouterWalPayload) -> Result<Self, Self::Error> {
        match payload {
            StoredRouterWalPayload::Incarnated { payload, .. } => (*payload).try_into(),
            StoredRouterWalPayload::SenderAssigned { payload } => {
                if !matches!(*payload, StoredRouterWalPayload::SubmissionClassified { .. }) {
                    return Err(identity::error("invalid sender assignment WAL wrapper"));
                }
                (*payload).try_into()
            }
            StoredRouterWalPayload::Submission { replay_key, replay_expires_at, entry } => {
                // Records from before acceptance times were logged. The router store resolves
                // and persists their deadline once, so it is never rebased at a later restart.
                let entry = entry.map(|entry| InboxEntry::try_from(*entry)).transpose()?;
                Ok(Self::Submission {
                    replay_key,
                    replay_expires_at,
                    entry: entry.map(Box::new),
                    accepted_at: None,
                    local_delivery: None,
                })
            }
            StoredRouterWalPayload::SubmissionAccepted {
                replay_key,
                replay_expires_at,
                accepted_at,
                entry,
            } => Ok(Self::Submission {
                replay_key,
                replay_expires_at,
                entry: entry.map(|entry| InboxEntry::try_from(*entry)).transpose()?.map(Box::new),
                accepted_at: Some(accepted_at),
                local_delivery: None,
            }),
            StoredRouterWalPayload::SubmissionClassified {
                replay_key,
                replay_expires_at,
                accepted_at,
                entry,
                local_delivery,
            } => Ok(Self::Submission {
                replay_key,
                replay_expires_at,
                entry: entry.map(|entry| InboxEntry::try_from(*entry)).transpose()?.map(Box::new),
                accepted_at: Some(accepted_at),
                local_delivery: Some(local_delivery),
            }),
        }
    }
}

impl TryFrom<&InboxEntry> for StoredRouterWalInboxEntry {
    type Error = NodeCoreError;

    fn try_from(entry: &InboxEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            inbox_seq: entry.inbox_seq,
            target_delivery_id: entry.target_delivery_id.clone(),
            envelope: StoredRouterWalEnvelope::try_from(&entry.envelope)?,
        })
    }
}

impl TryFrom<StoredRouterWalInboxEntry> for InboxEntry {
    type Error = NodeCoreError;

    fn try_from(entry: StoredRouterWalInboxEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            inbox_seq: entry.inbox_seq,
            target_delivery_id: entry.target_delivery_id,
            envelope: entry.envelope.try_into()?,
        })
    }
}

impl TryFrom<&ramflux_protocol::Envelope> for StoredRouterWalEnvelope {
    type Error = NodeCoreError;

    fn try_from(envelope: &ramflux_protocol::Envelope) -> Result<Self, Self::Error> {
        let ext_json = if envelope.ext.ext.is_empty() {
            None
        } else {
            Some(
                serde_json::to_vec(&envelope.ext.ext)
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?,
            )
        };
        Ok(Self {
            schema: envelope.schema.clone(),
            version: envelope.version,
            domain: envelope.domain.clone(),
            ext_json,
            signed: envelope.signed.clone(),
            envelope_id: envelope.envelope_id.clone(),
            source_principal_id: envelope.source_principal_id.clone(),
            source_device_id: envelope.source_device_id.clone(),
            target_delivery_id: envelope.target_delivery_id.clone(),
            routing_set_id: envelope.routing_set_id.clone(),
            delivery_class: envelope.delivery_class.clone(),
            priority: envelope.priority.clone(),
            ttl: envelope.ttl,
            created_at: envelope.created_at,
            encrypted_payload: envelope.encrypted_payload.clone(),
            payload_hash: envelope.payload_hash.clone(),
        })
    }
}

impl TryFrom<StoredRouterWalEnvelope> for ramflux_protocol::Envelope {
    type Error = NodeCoreError;

    fn try_from(envelope: StoredRouterWalEnvelope) -> Result<Self, Self::Error> {
        let ext = match envelope.ext_json {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?,
            None => std::collections::BTreeMap::new(),
        };
        Ok(Self {
            schema: envelope.schema,
            version: envelope.version,
            domain: envelope.domain,
            ext: ramflux_protocol::Ext { ext },
            signed: envelope.signed,
            envelope_id: envelope.envelope_id,
            source_principal_id: envelope.source_principal_id,
            source_device_id: envelope.source_device_id,
            target_delivery_id: envelope.target_delivery_id,
            routing_set_id: envelope.routing_set_id,
            delivery_class: envelope.delivery_class,
            priority: envelope.priority,
            ttl: envelope.ttl,
            created_at: envelope.created_at,
            encrypted_payload: envelope.encrypted_payload,
            payload_hash: envelope.payload_hash,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RouterWalSubmissionRecord {
    pub replay_key: String,
    pub replay_expires_at: i64,
    pub entry: Option<InboxEntry>,
    pub accepted_at: Option<i64>,
    pub local_delivery: Option<RouterWalLocalDelivery>,
    pub location: RouterWalRecordLocation,
    sender_assigned: bool,
}

impl RouterWalSubmissionRecord {
    /// Server retention deadline of the logged delivery (the envelope expiry for old records).
    #[must_use]
    pub fn retain_until(&self) -> i64 {
        self.entry.as_ref().map_or(self.replay_expires_at, |entry| {
            self.accepted_at.map_or_else(
                || crate::inbox_legacy_retain_until(&entry.envelope, router_wal_now()),
                |accepted_at| crate::inbox_retain_until(&entry.envelope, accepted_at),
            )
        })
    }
}

#[derive(Clone, Debug, Default)]
struct RouterWalState {
    #[cfg(test)]
    ack_pause: Arc<Mutex<Option<acknowledgement_test::Pause>>>,
    submissions_by_replay_key: BTreeMap<String, RouterWalSubmissionRecord>,
    submissions_by_target: BTreeMap<String, BTreeMap<u64, BTreeSet<String>>>,
    local_delivery_by_sender_envelope:
        HashMap<String, HashMap<(String, String), RouterWalLocalDeliveryIndex>>,
    /// Highest sequence ever logged per mailbox, including records that later expired.
    issued_by_target: BTreeMap<String, u64>,
    incarnations: BTreeMap<String, String>,
    incarnation_conflict: bool,
    replay_due: BTreeSet<(i64, String)>,
    entry_due: BTreeSet<(i64, String)>,
}

#[derive(Clone, Debug)]
struct RouterWalLocalDeliveryIndex {
    replay_key: String,
    target_delivery_id: String,
    replay_expires_at: i64,
    assignment: Option<crate::router_store::sender_retry::SenderAssignment>,
}

impl RouterWalState {
    fn apply(&mut self, payload: RouterWalPayload, location: RouterWalRecordLocation) {
        self.apply_with_sender_assignment(payload, location, true);
    }
    fn apply_with_sender_assignment(
        &mut self,
        payload: RouterWalPayload,
        location: RouterWalRecordLocation,
        sender_assigned: bool,
    ) {
        match payload {
            RouterWalPayload::Submission {
                replay_key,
                replay_expires_at,
                entry,
                accepted_at,
                local_delivery,
            } => {
                if let Some(entry) = entry.as_ref() {
                    let issued =
                        self.issued_by_target.entry(entry.target_delivery_id.clone()).or_default();
                    *issued = (*issued).max(entry.inbox_seq);
                }
                let replay_key = if let Some(tail) = replay_key.strip_prefix("envelope/v2/") {
                    entry.as_ref().map_or_else(
                        || replay_key.clone(),
                        |entry| {
                            format!(
                                "envelope/v3/{tail}/{}",
                                ramflux_protocol::encode_base64url(&entry.target_delivery_id)
                            )
                        },
                    )
                } else {
                    replay_key
                };
                let record = RouterWalSubmissionRecord {
                    replay_key: replay_key.clone(),
                    replay_expires_at,
                    entry: entry.map(|entry| *entry),
                    accepted_at,
                    local_delivery,
                    location,
                    sender_assigned,
                };
                if let Some(previous) = self.submissions_by_replay_key.remove(&replay_key) {
                    self.unindex(&previous);
                }
                self.index(&record);
                self.submissions_by_replay_key.insert(replay_key, record);
            }
        }
    }

    fn index(&mut self, record: &RouterWalSubmissionRecord) {
        self.replay_due.insert((record.replay_expires_at, record.replay_key.clone()));
        if let Some(entry) = &record.entry {
            self.submissions_by_target
                .entry(entry.target_delivery_id.clone())
                .or_default()
                .entry(entry.inbox_seq)
                .or_default()
                .insert(record.replay_key.clone());
            self.entry_due.insert((record.retain_until(), record.replay_key.clone()));
        }
        if let Some(delivery) = &record.local_delivery {
            self.local_delivery_by_sender_envelope
                .entry(delivery.sender_root_commitment.clone())
                .or_default()
                .insert(
                    (delivery.envelope_id.clone(), delivery.target_delivery_id.clone()),
                    RouterWalLocalDeliveryIndex {
                        replay_key: record.replay_key.clone(),
                        target_delivery_id: delivery.target_delivery_id.clone(),
                        replay_expires_at: record.replay_expires_at,
                        assignment: record
                            .entry
                            .as_ref()
                            .filter(|_| record.sender_assigned)
                            .and_then(|entry| {
                                self.incarnations.get(&entry.target_delivery_id).map(|id| {
                                    crate::router_store::sender_retry::SenderAssignment::new(
                                        entry,
                                        id.clone(),
                                        record.retain_until(),
                                    )
                                })
                            })
                            .transpose()
                            .unwrap_or_else(|_| {
                                crate::fatal_durability::fence(false);
                                None
                            }),
                    },
                );
        }
    }

    fn unindex(&mut self, record: &RouterWalSubmissionRecord) {
        self.replay_due.remove(&(record.replay_expires_at, record.replay_key.clone()));
        if let Some(entry) = &record.entry {
            self.unindex_target(entry, &record.replay_key);
            self.entry_due.remove(&(record.retain_until(), record.replay_key.clone()));
        }
        if let Some(delivery) = &record.local_delivery {
            let remove_sender = if let Some(by_envelope) =
                self.local_delivery_by_sender_envelope.get_mut(&delivery.sender_root_commitment)
            {
                if by_envelope
                    .get(&(delivery.envelope_id.clone(), delivery.target_delivery_id.clone()))
                    .is_some_and(|indexed| indexed.replay_key == record.replay_key)
                {
                    by_envelope.remove(&(
                        delivery.envelope_id.clone(),
                        delivery.target_delivery_id.clone(),
                    ));
                }
                by_envelope.is_empty()
            } else {
                false
            };
            if remove_sender {
                self.local_delivery_by_sender_envelope.remove(&delivery.sender_root_commitment);
            }
        }
    }

    fn unindex_target(&mut self, entry: &InboxEntry, key: &str) {
        if let Some(sequences) = self.submissions_by_target.get_mut(&entry.target_delivery_id) {
            if let Some(keys) = sequences.get_mut(&entry.inbox_seq) {
                keys.remove(key);
                if keys.is_empty() {
                    sequences.remove(&entry.inbox_seq);
                }
            }
            if sequences.is_empty() {
                self.submissions_by_target.remove(&entry.target_delivery_id);
            }
        }
    }
    fn observe_settlement(&mut self, cursor: &crate::CursorAckState) {
        let Some(sequences) = self.submissions_by_target.get(&cursor.target_delivery_id) else {
            return;
        };
        let mut keys = sequences
            .range(..=cursor.settled_inbox_seq)
            .flat_map(|(_, keys)| keys.iter().cloned())
            .collect::<BTreeSet<_>>();
        for seq in cursor.acked_inbox_seqs.iter().chain(&cursor.retired_inbox_seqs) {
            if let Some(set) = sequences.get(seq) {
                keys.extend(set.iter().cloned());
            }
        }
        for key in keys {
            if let Some(record) = self.submissions_by_replay_key.get_mut(&key) {
                let deadline = record.retain_until();
                if let Some(entry) = record.entry.take() {
                    self.entry_due.remove(&(deadline, key.clone()));
                    self.unindex_target(&entry, &key);
                }
            }
        }
    }

    /// Visits only due index entries; returns the number of retired records and entries.
    fn prune(&mut self, now: i64) -> usize {
        let mut removed = 0;
        while let Some((expires_at, key)) = self.replay_due.first().cloned() {
            if expires_at >= now {
                break;
            }
            self.replay_due.pop_first();
            if let Some(record) = self.submissions_by_replay_key.remove(&key) {
                self.unindex(&record);
                removed += 1;
            }
        }
        while let Some((deadline, key)) = self.entry_due.first().cloned() {
            if deadline > now {
                break;
            }
            self.entry_due.pop_first();
            if let Some(record) = self.submissions_by_replay_key.get_mut(&key)
                && let Some(entry) = record.entry.take()
            {
                self.unindex_target(&entry, &key);
                removed += 1;
            }
        }
        removed
    }

    fn has_local_delivery_envelope(
        &self,
        sender_root_commitment: &str,
        envelope_id: &str,
        target_delivery_id: &str,
        now: i64,
    ) -> bool {
        self.local_delivery_by_sender_envelope
            .get(sender_root_commitment)
            .and_then(|by_envelope| {
                by_envelope.get(&(envelope_id.to_owned(), target_delivery_id.to_owned()))
            })
            .is_some_and(|delivery| {
                delivery.target_delivery_id == target_delivery_id
                    && delivery.replay_expires_at > now
            })
    }

    fn due_count(&self, now: i64) -> usize {
        self.replay_due.iter().take_while(|(expires_at, _)| *expires_at < now).count()
            + self.entry_due.iter().take_while(|(deadline, _)| *deadline <= now).count()
    }
}

pub struct RouterWalStore {
    root: PathBuf,
    state: Arc<Mutex<RouterWalState>>,
    writer: RouterWalWriter,
    association: Option<Arc<identity::Association>>,
}

impl RouterWalStore {
    /// # Errors
    /// Returns an error when the WAL directory cannot be created, recovered, or opened.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        Self::open_with_shards(root, router_wal_shard_count())
    }

    fn open_with_shards(root: impl AsRef<Path>, shard_count: usize) -> Result<Self, NodeCoreError> {
        Self::open_with_shards_config(root, shard_count, router_wal_pipeline_enabled())
    }

    fn open_with_shards_config(
        root: impl AsRef<Path>,
        shard_count: usize,
        pipeline: bool,
    ) -> Result<Self, NodeCoreError> {
        let root = root.as_ref().to_path_buf();
        durability_io::create_dir_all(&root)
            .map_err(|source| NodeCoreError::StoreDirectory { path: root.clone(), source })?;
        let shard_count = shard_count.max(1);
        let segment_bytes =
            router_wal_u64_env(ROUTER_WAL_SEGMENT_BYTES_ENV, ROUTER_WAL_SEGMENT_BYTES_DEFAULT)
                .max(1024 * 1024);
        let recovered = recover_router_wal(&root)?;
        let state = Arc::new(Mutex::new(recovered.state));
        let writer = RouterWalWriter::start(
            &root,
            segment_bytes,
            shard_count,
            &recovered.shards,
            &state,
            pipeline,
        )?;
        Ok(Self { root, state, writer, association: None })
    }

    /// # Errors
    /// Returns an error when the submission cannot be durably appended.
    pub fn record_submission(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
        entry: Option<&InboxEntry>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
        self.record_submission_classified(replay_key, replay_expires_at, entry, None)
    }

    pub(crate) fn record_submission_classified(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
        entry: Option<&InboxEntry>,
        local_delivery: Option<RouterWalLocalDelivery>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
        self.prepare_sender_identity(entry)?;
        self.writer.append(RouterWalPayload::Submission {
            replay_key: replay_key.to_owned(),
            replay_expires_at,
            entry: entry.cloned().map(Box::new),
            accepted_at: Some(router_wal_now()),
            local_delivery,
        })
    }

    /// # Errors
    /// Returns an error when the submission cannot be durably appended.
    pub async fn record_submission_async(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
        entry: Option<&InboxEntry>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
        self.record_submission_classified_async(replay_key, replay_expires_at, entry, None).await
    }

    pub(crate) async fn record_submission_classified_async(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
        entry: Option<&InboxEntry>,
        local_delivery: Option<RouterWalLocalDelivery>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
        self.record_submission_classified_with_lease_async(
            replay_key,
            replay_expires_at,
            entry,
            local_delivery,
            None,
        )
        .await
    }

    pub(crate) async fn record_submission_classified_with_lease_async(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
        entry: Option<&InboxEntry>,
        local_delivery: Option<RouterWalLocalDelivery>,
        lease: Option<crate::SubmissionLease>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
        self.prepare_sender_identity(entry)?;
        self.writer
            .append_async(
                RouterWalPayload::Submission {
                    replay_key: replay_key.to_owned(),
                    replay_expires_at,
                    entry: entry.cloned().map(Box::new),
                    accepted_at: Some(router_wal_now()),
                    local_delivery,
                },
                lease,
            )
            .await
    }

    fn prepare_sender_identity(&self, entry: Option<&InboxEntry>) -> Result<(), NodeCoreError> {
        if let (Some(association), Some(entry)) = (&self.association, entry) {
            let id = association.reserve(&entry.target_delivery_id)?;
            self.state
                .lock()
                .map_err(identity::error)?
                .incarnations
                .insert(entry.target_delivery_id.clone(), id);
        }
        Ok(())
    }

    pub(crate) fn sender_assignment(
        &self,
        root: &str,
        envelope: &ramflux_protocol::Envelope,
        now: i64,
    ) -> Result<Option<crate::router_store::sender_retry::SenderAssignment>, NodeCoreError> {
        let state = self.state.lock().map_err(identity::error)?;
        Ok(state
            .local_delivery_by_sender_envelope
            .get(root)
            .and_then(|entries| {
                entries.get(&(envelope.envelope_id.clone(), envelope.target_delivery_id.clone()))
            })
            .filter(|index| index.replay_expires_at > now)
            .and_then(|index| index.assignment.clone()))
    }

    pub(crate) fn retry_lookup(
        &self,
        root: &str,
        envelope: &ramflux_protocol::Envelope,
        now: i64,
    ) -> crate::router_store::sender_retry::RetryLookup {
        let state = std::sync::Arc::downgrade(&self.state);
        let root = root.to_owned();
        let key = (envelope.envelope_id.clone(), envelope.target_delivery_id.clone());
        Box::new(move || {
            let state = state.upgrade().ok_or(NodeCoreError::Publication(
                crate::publication::PublicationRefusal::StoreClosed,
            ))?;
            let state = state.lock().map_err(identity::error)?;
            let assignment = state
                .local_delivery_by_sender_envelope
                .get(&root)
                .and_then(|rows| rows.get(&key))
                .filter(|row| row.replay_expires_at > now)
                .and_then(|row| row.assignment.clone());
            if let Some(assignment) = &assignment
                && state.incarnations.get(&key.1) != Some(&assignment.inbox_incarnation_id)
            {
                return Err(NodeCoreError::Publication(
                    crate::publication::PublicationRefusal::IncarnationMismatch,
                ));
            }
            Ok(assignment)
        })
    }

    /// # Errors
    /// Counts logical WAL retention candidates without changing delivery recovery state.
    pub fn retention_candidate_count(&self, now: i64) -> Result<usize, NodeCoreError> {
        let state =
            self.state.lock().map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
        Ok(state.due_count(now))
    }

    /// Highest mailbox sequence ever logged per target, so recovery never reissues one.
    #[must_use]
    pub fn issued_watermarks(&self) -> BTreeMap<String, u64> {
        self.state.lock().map_or_else(|_| BTreeMap::new(), |state| state.issued_by_target.clone())
    }

    pub(crate) fn issued_sequence(&self, target: &str) -> Result<u64, NodeCoreError> {
        Ok(self
            .state
            .lock()
            .map_err(identity::error)?
            .issued_by_target
            .get(target)
            .copied()
            .unwrap_or(0))
    }

    /// Visit only due entries, retaining the ordered sweep's bounded footprint.
    pub(crate) fn retention_targets(&self, now: i64) -> Result<BTreeSet<String>, NodeCoreError> {
        let state = self.state.lock().map_err(identity::error)?;
        Ok(state
            .entry_due
            .iter()
            .take_while(|(deadline, _)| *deadline <= now)
            .filter_map(|(_, key)| {
                state
                    .submissions_by_replay_key
                    .get(key)?
                    .entry
                    .as_ref()
                    .map(|entry| entry.target_delivery_id.clone())
            })
            .collect())
    }

    /// Apply a durable ACK/NACK cursor to the live projection, retaining replay receipts and issued floors.
    pub(crate) fn observe_settlement(
        &self,
        cursor: &crate::CursorAckState,
    ) -> Result<(), NodeCoreError> {
        self.state
            .lock()
            .map_err(|error| NodeCoreError::Redb(error.to_string()))?
            .observe_settlement(cursor);
        Ok(())
    }

    /// First durable live row after the previously committed floor; numeric gaps
    /// are skipped by the ordered index, never enumerated.
    pub(crate) fn settlement_head(
        &self,
        cursor: &crate::CursorAckState,
        previous: u64,
        expired_at: Option<i64>,
    ) -> Result<Option<u64>, NodeCoreError> {
        let state = self.state.lock().map_err(identity::error)?;
        Ok(state.submissions_by_target.get(&cursor.target_delivery_id).and_then(|sequences| {
            sequences
                .range((std::ops::Bound::Excluded(previous), std::ops::Bound::Unbounded))
                .filter(|(_, keys)| {
                    !expired_at.is_some_and(|now| {
                        keys.iter().all(|key| {
                            state
                                .submissions_by_replay_key
                                .get(key)
                                .is_some_and(|record| record.retain_until() <= now)
                        })
                    })
                })
                .map(|(&seq, _)| seq)
                .find(|seq| !crate::router_store::settlement::retires(cursor, *seq))
        }))
    }

    /// Snapshot one mailbox's WAL view without walking unrelated accounts or swallowing lock errors.
    pub(crate) fn migration_target_view(
        &self,
        target: &str,
    ) -> Result<(u64, Vec<RouterWalSubmissionRecord>), NodeCoreError> {
        let state = self.state.lock().map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        let records =
            state
                .submissions_by_target
                .get(target)
                .into_iter()
                .flat_map(|sequences| sequences.values().filter_map(BTreeSet::first))
                .map(|key| {
                    state.submissions_by_replay_key.get(key).cloned().ok_or_else(|| {
                        NodeCoreError::Redb("WAL target index lost submission".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
        Ok((state.issued_by_target.get(target).copied().unwrap_or(0), records))
    }

    /// Removes expired recovery records and closed segment files older than the full retention
    /// window. The newest segment of each directory is the writer's active file and is never
    /// unlinked, even when idle.
    /// # Errors
    /// Returns lock, directory or segment deletion errors.
    pub fn prune_expired(&self, now: i64) -> Result<usize, NodeCoreError> {
        let mut removed = self
            .state
            .lock()
            .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?
            .prune(now);
        let retire_after = u64::try_from(
            ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS
                .saturating_add(ramflux_protocol::MAX_CLOCK_SKEW_SECONDS),
        )
        .unwrap_or(u64::MAX)
        .saturating_add(ROUTER_WAL_RETIRE_MARGIN_SECONDS);
        let roots = std::iter::once(self.root.clone())
            .chain(router_wal_existing_shard_roots(&self.root)?.into_iter().map(|(_, path)| path));
        for root in roots {
            let mut ids = router_wal_segment_ids(&root)?;
            ids.sort_unstable();
            ids.pop();
            for id in ids {
                let path = router_wal_segment_path(&root, id);
                let expired = fs::metadata(&path)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age.as_secs() > retire_after);
                if expired {
                    if let Some(association) = &self.association
                        && !association.retire(&root, id)?
                    {
                        continue;
                    }
                    fs::remove_file(&path)
                        .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
                    durability_io::sync_dir(&root).map_err(identity::error)?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    #[must_use]
    pub fn submissions(&self, now_unix_seconds: i64) -> Vec<RouterWalSubmissionRecord> {
        self.state.lock().map_or_else(
            |_| Vec::new(),
            |state| {
                state
                    .submissions_by_replay_key
                    .values()
                    .filter(|record| record.replay_expires_at >= now_unix_seconds)
                    .cloned()
                    .collect()
            },
        )
    }

    #[must_use]
    pub fn has_local_delivery_envelope(
        &self,
        sender_root_commitment: &str,
        envelope_id: &str,
        target_delivery_id: &str,
        now: i64,
    ) -> bool {
        self.state.lock().is_ok_and(|state| {
            state.has_local_delivery_envelope(
                sender_root_commitment,
                envelope_id,
                target_delivery_id,
                now,
            )
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |state| state.submissions_by_replay_key.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct RouterWalWriter {
    shards: Vec<RouterWalWriterShard>,
}

struct RouterWalWriterShard {
    sender: Option<mpsc::SyncSender<RouterWalAppendRequest>>,
    thread: Option<thread::JoinHandle<()>>,
    fsync_thread: Option<thread::JoinHandle<()>>,
}

struct RouterWalAppendRequest {
    payload: RouterWalPayload,
    reply: RouterWalAppendReply,
}

enum RouterWalAppendReply {
    Sync(mpsc::SyncSender<Result<RouterWalRecordLocation, NodeCoreError>>),
    Async(
        tokio::sync::oneshot::Sender<Result<RouterWalRecordLocation, NodeCoreError>>,
        Option<crate::SubmissionLease>,
    ),
}

impl RouterWalAppendReply {
    fn send(self, result: Result<RouterWalRecordLocation, NodeCoreError>) {
        match self {
            Self::Sync(reply) => {
                let _sent = reply.send(result);
            }
            Self::Async(reply, _submission) => {
                let _sent = reply.send(result);
            }
        }
    }
}

impl RouterWalWriter {
    fn start(
        root: &Path,
        segment_bytes: u64,
        shard_count: usize,
        recovered_shards: &BTreeMap<usize, RouterWalRecoveredShard>,
        wal_state: &Arc<Mutex<RouterWalState>>,
        pipeline: bool,
    ) -> Result<Self, NodeCoreError> {
        Self::start_associated(
            root,
            segment_bytes,
            shard_count,
            recovered_shards,
            wal_state,
            pipeline,
            None,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "internal writer configuration preserves existing constructor"
    )]
    fn start_associated(
        root: &Path,
        segment_bytes: u64,
        shard_count: usize,
        recovered_shards: &BTreeMap<usize, RouterWalRecoveredShard>,
        wal_state: &Arc<Mutex<RouterWalState>>,
        pipeline: bool,
        association: Option<&Arc<identity::Association>>,
    ) -> Result<Self, NodeCoreError> {
        let batch_max =
            router_wal_usize_env(ROUTER_WAL_BATCH_MAX_ENV, ROUTER_WAL_BATCH_MAX_DEFAULT).max(1);
        let queue_capacity =
            router_wal_usize_env(ROUTER_WAL_QUEUE_CAPACITY_ENV, ROUTER_WAL_QUEUE_CAPACITY_DEFAULT)
                .max(batch_max);
        let window = Duration::from_micros(router_wal_u64_env(
            ROUTER_WAL_COMMIT_WINDOW_US_ENV,
            ROUTER_WAL_COMMIT_WINDOW_US_DEFAULT,
        ));
        let mut shards = Vec::with_capacity(shard_count);
        for shard_id in 0..shard_count {
            let shard_root = router_wal_shard_root(root, shard_id);
            let recovered = recovered_shards.get(&shard_id).cloned().unwrap_or_default();
            let state = RouterWalWriterState::open_associated(
                shard_root,
                recovered.last_segment_id.unwrap_or(0),
                recovered.current_offset,
                segment_bytes,
                association.cloned(),
            )?;
            let wal_state = Arc::clone(wal_state);
            let (sender, receiver) = mpsc::sync_channel(queue_capacity);
            if pipeline {
                let (fsync_sender, fsync_receiver) = mpsc::sync_channel(queue_capacity);
                let fsync_wal_state = Arc::clone(&wal_state);
                let fsync_thread = thread::Builder::new()
                    .name(format!("ramflux-router-wal-fsync-{shard_id}"))
                    .spawn(move || {
                        router_wal_fsync_loop(&fsync_receiver, &fsync_wal_state);
                    })
                    .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
                let thread = thread::Builder::new()
                    .name(format!("ramflux-router-wal-writer-{shard_id}"))
                    .spawn(move || {
                        router_wal_pipeline_writer_loop(
                            state,
                            &receiver,
                            fsync_sender,
                            batch_max,
                            window,
                        );
                    })
                    .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
                shards.push(RouterWalWriterShard {
                    sender: Some(sender),
                    thread: Some(thread),
                    fsync_thread: Some(fsync_thread),
                });
            } else {
                let thread = thread::Builder::new()
                    .name(format!("ramflux-router-wal-writer-{shard_id}"))
                    .spawn(move || {
                        router_wal_writer_loop(state, &receiver, &wal_state, batch_max, window);
                    })
                    .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
                shards.push(RouterWalWriterShard {
                    sender: Some(sender),
                    thread: Some(thread),
                    fsync_thread: None,
                });
            }
        }
        Ok(Self { shards })
    }

    fn append(&self, payload: RouterWalPayload) -> Result<RouterWalRecordLocation, NodeCoreError> {
        let (reply, response) = mpsc::sync_channel(1);
        let shard = self.shard_for_payload(&payload)?;
        self.submit(
            shard,
            RouterWalAppendRequest { payload, reply: RouterWalAppendReply::Sync(reply) },
        )?;
        response.recv().map_err(|source| {
            crate::fatal_durability::fence(false);
            NodeCoreError::ItestJson(format!("router WAL append response closed: {source}"))
        })?
    }

    async fn append_async(
        &self,
        payload: RouterWalPayload,
        lease: Option<crate::SubmissionLease>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let shard = self.shard_for_payload(&payload)?;
        self.submit_async(
            shard,
            RouterWalAppendRequest { payload, reply: RouterWalAppendReply::Async(reply, lease) },
        )
        .await?;
        response.await.map_err(|source| {
            crate::fatal_durability::fence(false);
            NodeCoreError::ItestJson(format!("router WAL append response closed: {source}"))
        })?
    }

    fn shard_for_payload(&self, payload: &RouterWalPayload) -> Result<usize, NodeCoreError> {
        if self.shards.is_empty() {
            return Err(NodeCoreError::ItestJson("router WAL writer stopped".to_owned()));
        }
        Ok(router_wal_shard_for_payload(payload, self.shards.len()))
    }

    fn submit(&self, shard: usize, request: RouterWalAppendRequest) -> Result<(), NodeCoreError> {
        crate::fatal_durability::check()?;
        self.shards
            .get(shard)
            .and_then(|shard| shard.sender.as_ref())
            .ok_or_else(|| NodeCoreError::ItestJson("router WAL writer stopped".to_owned()))?
            .send(request)
            .map_err(|source| {
                crate::fatal_durability::fence(false);
                NodeCoreError::ItestJson(format!("router WAL writer stopped: {source}"))
            })
    }

    async fn submit_async(
        &self,
        shard: usize,
        mut request: RouterWalAppendRequest,
    ) -> Result<(), NodeCoreError> {
        let sender = self
            .shards
            .get(shard)
            .and_then(|shard| shard.sender.as_ref())
            .ok_or_else(|| NodeCoreError::ItestJson("router WAL writer stopped".to_owned()))?;
        loop {
            crate::fatal_durability::check()?;
            match sender.try_send(request) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) => {
                    request = returned;
                    crate::record_router_wal_submit_backpressure_yield();
                    tokio::task::yield_now().await;
                }
                Err(mpsc::TrySendError::Disconnected(_returned)) => {
                    crate::fatal_durability::fence(false);
                    return Err(NodeCoreError::ItestJson("router WAL writer stopped".to_owned()));
                }
            }
        }
    }
}

impl Drop for RouterWalWriter {
    fn drop(&mut self) {
        for shard in &mut self.shards {
            shard.sender.take();
        }
        for shard in &mut self.shards {
            if let Some(thread) = shard.thread.take() {
                let _joined = thread.join();
            }
        }
        for shard in &mut self.shards {
            if let Some(thread) = shard.fsync_thread.take() {
                let _joined = thread.join();
            }
        }
    }
}

struct RouterWalWriterState {
    root: PathBuf,
    segment_bytes: u64,
    segment_born: std::time::SystemTime,
    segment_id: u64,
    offset: u64,
    file: Arc<File>,
    association: Option<Arc<identity::Association>>,
    poisoned: bool,
    header_len: u64,
}

impl RouterWalWriterState {
    #[cfg(test)]
    fn open(
        root: PathBuf,
        segment_id: u64,
        offset: u64,
        segment_bytes: u64,
    ) -> Result<Self, NodeCoreError> {
        Self::open_associated(root, segment_id, offset, segment_bytes, None)
    }

    fn open_associated(
        root: PathBuf,
        segment_id: u64,
        offset: u64,
        segment_bytes: u64,
        association: Option<Arc<identity::Association>>,
    ) -> Result<Self, NodeCoreError> {
        durability_io::create_dir_all(&root)
            .map_err(|source| NodeCoreError::StoreDirectory { path: root.clone(), source })?;
        let path = router_wal_segment_path(&root, segment_id);
        writer_check(&root, "roll_open")?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        if offset == 0 && file.metadata().map_or(0, |metadata| metadata.len()) == 0 {
            let header = identity::header(association.as_deref(), &root, segment_id)?;
            durability_io::write_header(&mut file, &path, &header)
                .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
            durability_io::sync_file(&file, &path)
                .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
            durability_io::sync_dir(&root)
                .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        }
        if let Some(association) = &association {
            association.record_head(&root, segment_id)?;
        }
        file.rewind().map_err(identity::error)?;
        let header_len = read_router_wal_magic(&mut file)?;
        let offset = file
            .seek(io::SeekFrom::End(0))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let segment_born = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
        Ok(Self {
            root,
            segment_bytes,
            segment_born,
            segment_id,
            offset,
            file: Arc::new(file),
            association,
            poisoned: false,
            header_len,
        })
    }

    fn append_batch(
        &mut self,
        payloads: &[RouterWalPayload],
    ) -> Result<Vec<RouterWalRecordLocation>, NodeCoreError> {
        crate::fatal_durability::run(|| {
            let mut locations = Vec::with_capacity(payloads.len());
            let write_started = Instant::now();
            for payload in payloads {
                crate::fatal_durability::check()?;
                if self.poisoned {
                    return Err(identity::error("router WAL writer fenced"));
                }
                writer_check(&self.root, "wal_convert")?;
                let stored = identity::encode_payload(self.association.as_deref(), payload)?;
                writer_check(&self.root, "wal_serialize")?;
                let encoded = postcard::to_allocvec(&stored)
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
                writer_check(&self.root, "wal_frame_len")?;
                let frame_len = 8_u64
                    .checked_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| {
                        NodeCoreError::ItestJson("router WAL frame too large".to_owned())
                    })?;
                if self.offset > self.header_len
                    && (self.offset.saturating_add(frame_len) > self.segment_bytes
                        || self.segment_born.elapsed().is_ok_and(|age| age.as_secs() >= 3600))
                {
                    durability_io::sync_file(
                        &self.file,
                        &router_wal_segment_path(&self.root, self.segment_id),
                    )
                    .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
                    self.roll_segment()?;
                }
                locations.push(self.write_record(&encoded)?);
            }
            crate::record_router_save_mutation_us(elapsed_us(write_started));
            let sync_started = Instant::now();
            durability_io::sync_file(
                &self.file,
                &router_wal_segment_path(&self.root, self.segment_id),
            )
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
            let sync_us = elapsed_us(sync_started);
            crate::record_router_save_commit_us(sync_us);
            crate::record_router_wal_batch(payloads.len(), sync_us);
            Ok(locations)
        })
    }

    fn append_batch_no_sync(
        &mut self,
        payloads: &[RouterWalPayload],
    ) -> Result<RouterWalAppendGroup, NodeCoreError> {
        crate::fatal_durability::run(|| {
            let mut locations = Vec::with_capacity(payloads.len());
            let mut sync_files = Vec::with_capacity(1);
            let write_started = Instant::now();
            for payload in payloads {
                crate::fatal_durability::check()?;
                if self.poisoned {
                    return Err(identity::error("router WAL writer fenced"));
                }
                writer_check(&self.root, "wal_convert")?;
                let stored = identity::encode_payload(self.association.as_deref(), payload)?;
                writer_check(&self.root, "wal_serialize")?;
                let encoded = postcard::to_allocvec(&stored)
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
                writer_check(&self.root, "wal_frame_len")?;
                let frame_len = 8_u64
                    .checked_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| {
                        NodeCoreError::ItestJson("router WAL frame too large".to_owned())
                    })?;
                if self.offset > self.header_len
                    && (self.offset.saturating_add(frame_len) > self.segment_bytes
                        || self.segment_born.elapsed().is_ok_and(|age| age.as_secs() >= 3600))
                {
                    self.roll_segment()?;
                }
                push_unique_router_wal_file(
                    &mut sync_files,
                    &router_wal_segment_path(&self.root, self.segment_id),
                    &self.file,
                );
                locations.push(self.write_record(&encoded)?);
            }
            crate::record_router_save_mutation_us(elapsed_us(write_started));
            Ok(RouterWalAppendGroup { locations, sync_files })
        })
    }

    fn write_record(&mut self, encoded: &[u8]) -> Result<RouterWalRecordLocation, NodeCoreError> {
        let len = u32::try_from(encoded.len())
            .map_err(|_| NodeCoreError::ItestJson("router WAL record too large".to_owned()))?;
        let offset = self.offset;
        let path = router_wal_segment_path(&self.root, self.segment_id);
        durability_io::boundary(&path, "record_write", || {
            write_router_wal_record_with_path(&self.file, encoded, &path).map_err(io::Error::other)
        })
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        self.offset = self.offset.saturating_add(8 + u64::from(len));
        Ok(RouterWalRecordLocation { segment_id: self.segment_id, offset, len })
    }

    fn roll_segment(&mut self) -> Result<(), NodeCoreError> {
        self.segment_id = self.segment_id.saturating_add(1);
        let path = router_wal_segment_path(&self.root, self.segment_id);
        writer_check(&self.root, "roll_open")?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let header = identity::header(self.association.as_deref(), &self.root, self.segment_id)?;
        durability_io::write_header(&mut file, &path, &header)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        durability_io::sync_file(&file, &path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        durability_io::sync_dir(&self.root)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        if let Some(association) = &self.association
            && let Err(error) = association.record_head(&self.root, self.segment_id)
        {
            self.poisoned = true;
            return Err(error);
        }
        self.file = Arc::new(file);
        self.segment_born = std::time::SystemTime::now();
        self.offset = u64::try_from(header.len()).unwrap_or(0);
        self.header_len = self.offset;
        Ok(())
    }
}

struct RouterWalAppendGroup {
    locations: Vec<RouterWalRecordLocation>,
    sync_files: Vec<(PathBuf, Arc<File>)>,
}

struct RouterWalFsyncGroup {
    batch: Vec<RouterWalAppendRequest>,
    payloads: Vec<RouterWalPayload>,
    locations: Vec<RouterWalRecordLocation>,
    sync_files: Vec<(PathBuf, Arc<File>)>,
}

fn router_wal_writer_loop(
    mut state: RouterWalWriterState,
    receiver: &mpsc::Receiver<RouterWalAppendRequest>,
    wal_state: &Arc<Mutex<RouterWalState>>,
    batch_max: usize,
    window: Duration,
) {
    while crate::fatal_durability::check().is_ok() {
        let Ok(first) = receiver.recv() else { break };
        let Ok(batch_guard) = crate::fatal_durability::WriteGuard::new(false) else { return };
        if crate::fatal_durability::check().is_err() {
            return;
        }
        let mut batch = Vec::with_capacity(batch_max);
        batch.push(first);
        let deadline = Instant::now() + window;
        while batch.len() < batch_max {
            if crate::fatal_durability::check().is_err() {
                return;
            }
            match receiver.try_recv() {
                Ok(request) => batch.push(request),
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {
                    if window.is_zero() {
                        break;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    match receiver.recv_timeout(deadline.saturating_duration_since(now)) {
                        Ok(request) => batch.push(request),
                        Err(
                            mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected,
                        ) => break,
                    }
                }
            }
        }
        let payloads = batch.iter().map(|request| request.payload.clone()).collect::<Vec<_>>();
        match state.append_batch(&payloads) {
            Ok(locations) => {
                router_wal_ack_success(batch, &payloads, locations, wal_state, &state.root);
            }
            Err(error) => router_wal_ack_error(batch, &error),
        }

        let _ = batch_guard.complete();
    }
}

fn router_wal_pipeline_writer_loop(
    mut state: RouterWalWriterState,
    receiver: &mpsc::Receiver<RouterWalAppendRequest>,
    fsync_sender: mpsc::SyncSender<RouterWalFsyncGroup>,
    batch_max: usize,
    window: Duration,
) {
    while crate::fatal_durability::check().is_ok() {
        let Ok(first) = receiver.recv() else { break };
        let Ok(batch_guard) = crate::fatal_durability::WriteGuard::new(false) else { return };
        if crate::fatal_durability::check().is_err() {
            return;
        }
        let mut batch = Vec::with_capacity(batch_max);
        batch.push(first);
        let deadline = Instant::now() + window;
        while batch.len() < batch_max {
            if crate::fatal_durability::check().is_err() {
                return;
            }
            match receiver.try_recv() {
                Ok(request) => batch.push(request),
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {
                    if window.is_zero() {
                        break;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    match receiver.recv_timeout(deadline.saturating_duration_since(now)) {
                        Ok(request) => batch.push(request),
                        Err(
                            mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected,
                        ) => break,
                    }
                }
            }
        }
        let payloads = batch.iter().map(|request| request.payload.clone()).collect::<Vec<_>>();
        match state.append_batch_no_sync(&payloads) {
            Ok(group) => {
                let fsync_group = RouterWalFsyncGroup {
                    batch,
                    payloads,
                    locations: group.locations,
                    sync_files: group.sync_files,
                };
                if let Err(error) = writer_check(&state.root, "fsync_enqueue") {
                    router_wal_ack_error(fsync_group.batch, &error);
                    return;
                }
                if let Err(error) = fsync_sender.send(fsync_group) {
                    router_wal_ack_error(
                        error.0.batch,
                        &NodeCoreError::ItestJson("router WAL fsync writer stopped".to_owned()),
                    );
                }
            }
            Err(error) => router_wal_ack_error(batch, &error),
        }

        let _ = batch_guard.complete();
    }
    drop(fsync_sender);
}

fn router_wal_fsync_loop(
    receiver: &mpsc::Receiver<RouterWalFsyncGroup>,
    wal_state: &Arc<Mutex<RouterWalState>>,
) {
    while crate::fatal_durability::check().is_ok() {
        let Ok(first) = receiver.recv() else { break };
        let Ok(batch_guard) = crate::fatal_durability::WriteGuard::new(false) else { return };
        if crate::fatal_durability::check().is_err() {
            return;
        }
        let mut groups = vec![first];
        while crate::fatal_durability::check().is_ok() {
            let Ok(group) = receiver.try_recv() else { break };
            groups.push(group);
        }

        let mut sync_files = Vec::new();
        let mut record_count = 0usize;
        for group in &groups {
            record_count = record_count.saturating_add(group.payloads.len());
            for (path, file) in &group.sync_files {
                push_unique_router_wal_file(&mut sync_files, path, file);
            }
        }

        let sync_started = Instant::now();
        let sync_result = crate::fatal_durability::run(|| sync_router_wal_files(&sync_files));
        let sync_us = elapsed_us(sync_started);
        match sync_result {
            Ok(()) => {
                crate::record_router_save_commit_us(sync_us);
                crate::record_router_wal_batch(record_count, sync_us);
                for group in groups {
                    router_wal_ack_success(
                        group.batch,
                        &group.payloads,
                        group.locations,
                        wal_state,
                        sync_files.first().map_or(Path::new(""), |(path, _)| path.as_path()),
                    );
                }
            }
            Err(error) => {
                for group in groups {
                    router_wal_ack_error(group.batch, &error);
                }
            }
        }

        let _ = batch_guard.complete();
    }
}

fn router_wal_ack_success(
    batch: Vec<RouterWalAppendRequest>,
    payloads: &[RouterWalPayload],
    locations: Vec<RouterWalRecordLocation>,
    wal_state: &Arc<Mutex<RouterWalState>>,
    path: &Path,
) {
    let Ok(guard) = crate::fatal_durability::WriteGuard::new(false) else { return };
    #[cfg(test)]
    let _pause = acknowledgement_test::before_apply(wal_state);
    if writer_check(path, "index_update").is_err() {
        crate::fatal_durability::fence(false);
        return;
    }
    let update_result = wal_state
        .lock()
        .map_err(|source| source.to_string())
        .map(|mut guard| {
            let _gate = crate::fatal_durability::publication().map_err(|e| e.to_string())?;
            for (payload, location) in payloads.iter().cloned().zip(locations.iter().cloned()) {
                guard.apply(payload, location);
            }
            Ok::<_, String>(())
        })
        .and_then(std::convert::identity);
    match update_result {
        Ok(()) => {
            for (request, location) in batch.into_iter().zip(locations) {
                let Ok(reply_guard) = crate::fatal_durability::WriteGuard::new(false) else {
                    return;
                };
                if writer_check(path, "writer_reply").is_err() {
                    crate::fatal_durability::fence(false);
                    return;
                }
                let Ok(_gate) = crate::fatal_durability::publication() else { return };
                request.reply.send(Ok(location));
                let _ = reply_guard.complete();
            }
        }
        Err(error) => {
            crate::fatal_durability::fence(false);
            for request in batch {
                request.reply.send(Err(NodeCoreError::ItestJson(format!(
                    "router WAL index lock poisoned: {error}"
                ))));
            }
        }
    }
    let _ = guard.complete();
}

fn router_wal_ack_error(batch: Vec<RouterWalAppendRequest>, error: &NodeCoreError) {
    crate::fatal_durability::fence(false);
    let message = error.to_string();
    for request in batch {
        request.reply.send(Err(NodeCoreError::ItestJson(message.clone())));
    }
}

struct RouterWalRecovery {
    state: RouterWalState,
    shards: BTreeMap<usize, RouterWalRecoveredShard>,
}

#[derive(Clone, Debug, Default)]
struct RouterWalRecoveredShard {
    last_segment_id: Option<u64>,
    current_offset: u64,
}

fn recover_router_wal(root: &Path) -> Result<RouterWalRecovery, NodeCoreError> {
    recover_router_wal_at(root, &BTreeMap::new())
}

fn recover_router_wal_at(
    root: &Path,
    anchors: &BTreeMap<String, u64>,
) -> Result<RouterWalRecovery, NodeCoreError> {
    let mut state = RouterWalState::default();
    let _legacy = recover_router_wal_directory(root, &mut state, anchors.get("").copied())?;
    let mut shards = BTreeMap::new();
    for (shard_id, shard_root) in router_wal_existing_shard_roots(root)? {
        let key = shard_root.strip_prefix(root).map_err(identity::error)?.to_string_lossy();
        let recovered = recover_router_wal_directory(
            &shard_root,
            &mut state,
            anchors.get(key.as_ref()).copied(),
        )?;
        durability_io::sync_dir(&shard_root)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        if recovered.last_segment_id.is_some() {
            shards.insert(shard_id, recovered);
        }
    }
    durability_io::sync_dir(root).map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(RouterWalRecovery { state, shards })
}

fn recover_router_wal_directory(
    root: &Path,
    state: &mut RouterWalState,
    anchor: Option<u64>,
) -> Result<RouterWalRecoveredShard, NodeCoreError> {
    let mut segments = router_wal_segment_ids(root)?;
    if let Some(anchor) = anchor {
        segments.retain(|segment| *segment >= anchor);
    }
    segments.sort_unstable();
    let newest = segments.last().copied();
    let mut current_offset = 0_u64;
    let mut last_segment_id = None;
    for segment_id in segments {
        let offset =
            recover_router_wal_segment(root, segment_id, newest == Some(segment_id), state)?;
        current_offset = offset;
        last_segment_id = Some(segment_id);
    }
    Ok(RouterWalRecoveredShard { last_segment_id, current_offset })
}

fn recover_router_wal_segment(
    root: &Path,
    segment_id: u64,
    newest: bool,
    state: &mut RouterWalState,
) -> Result<u64, NodeCoreError> {
    let path = router_wal_segment_path(root, segment_id);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    // Only a newest header with no following bytes can be an empty crash residue.
    let size =
        file.metadata().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?.len();
    if newest && size <= ROUTER_WAL_MAGIC.len() as u64 {
        let mut header = Vec::new();
        file.read_to_end(&mut header)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        file.rewind().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        if header != ROUTER_WAL_MAGIC {
            durability_io::set_len(&file, &path, 0)
                .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
            durability_io::write_header(&mut file, &path, ROUTER_WAL_MAGIC)
                .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
            file.rewind().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        }
    }
    identity::repair_empty_header(&mut file, &path, newest)
        .map_err(|cause| identity::segment_error(&path, cause))?;
    let mut offset =
        read_router_wal_magic(&mut file).map_err(|cause| identity::segment_error(&path, cause))?;
    loop {
        let record_offset = offset;
        let Some((stored, len)) = read_router_wal_record(&mut file)? else {
            break;
        };
        offset = offset.saturating_add(8 + u64::from(len));
        let location = RouterWalRecordLocation { segment_id, offset: record_offset, len };
        let sender_assigned = stored.sender_assigned();
        let payload = identity::decode_payload(stored, state)?;
        state.apply_with_sender_assignment(payload, location, sender_assigned);
    }
    durability_io::set_len(&file, &path, offset)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    durability_io::sync_file(&file, &path)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(offset)
}

fn read_router_wal_magic(file: &mut File) -> Result<u64, NodeCoreError> {
    identity::read_header(file).map(|header| header.0)
}

fn read_router_wal_record(
    file: &mut File,
) -> Result<Option<(StoredRouterWalPayload, u32)>, NodeCoreError> {
    let mut header = [0_u8; 8];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(NodeCoreError::ItestJson(error.to_string())),
    }
    let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let expected_crc = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
    let mut payload = vec![0_u8; len_usize];
    match file.read_exact(&mut payload) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(NodeCoreError::ItestJson(error.to_string())),
    }
    if crc32fast::hash(&payload) != expected_crc {
        return Ok(None);
    }
    let payload = postcard::from_bytes::<StoredRouterWalPayload>(&payload)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    Ok(Some((payload, len)))
}

fn router_wal_segment_ids(root: &Path) -> Result<Vec<u64>, NodeCoreError> {
    let mut ids = Vec::new();
    if !root.exists() {
        return Ok(ids);
    }
    for entry in fs::read_dir(root)
        .map_err(|source| NodeCoreError::StoreDirectory { path: root.to_path_buf(), source })?
    {
        let entry = entry.map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(id) = router_wal_segment_id_from_name(&name) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn router_wal_existing_shard_roots(root: &Path) -> Result<Vec<(usize, PathBuf)>, NodeCoreError> {
    let mut shards = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|source| NodeCoreError::StoreDirectory { path: root.to_path_buf(), source })?
    {
        let entry = entry.map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        if !entry
            .file_type()
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?
            .is_dir()
        {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(shard_id) = router_wal_shard_id_from_name(&name) {
            shards.push((shard_id, entry.path()));
        }
    }
    shards.sort_unstable_by_key(|(shard_id, _path)| *shard_id);
    Ok(shards)
}

fn router_wal_segment_id_from_name(name: &str) -> Option<u64> {
    name.strip_prefix("router-wal-")
        .and_then(|value| value.strip_suffix(".wal"))
        .and_then(|value| value.parse().ok())
}

fn router_wal_shard_id_from_name(name: &str) -> Option<usize> {
    name.strip_prefix(ROUTER_WAL_SHARD_DIR_PREFIX).and_then(|value| value.parse().ok())
}

fn router_wal_shard_root(root: &Path, shard_id: usize) -> PathBuf {
    root.join(format!("{ROUTER_WAL_SHARD_DIR_PREFIX}{shard_id:04}"))
}

fn router_wal_now() -> i64 {
    i64::try_from(crate::now_unix_seconds()).unwrap_or(i64::MAX)
}

fn router_wal_segment_path(root: &Path, segment_id: u64) -> PathBuf {
    root.join(format!("router-wal-{segment_id:020}.wal"))
}

fn router_wal_shard_for_payload(payload: &RouterWalPayload, shard_count: usize) -> usize {
    let key = match payload {
        RouterWalPayload::Submission { replay_key, entry, .. } => {
            entry.as_ref().map_or(replay_key.as_str(), |entry| entry.target_delivery_id.as_str())
        }
    };
    let hash = crc32fast::hash(key.as_bytes());
    usize::try_from(u64::from(hash) % u64::try_from(shard_count.max(1)).unwrap_or(1)).unwrap_or(0)
}

fn push_unique_router_wal_file(
    files: &mut Vec<(PathBuf, Arc<File>)>,
    path: &Path,
    file: &Arc<File>,
) {
    if !files.iter().any(|(_, existing)| Arc::ptr_eq(existing, file)) {
        files.push((path.to_path_buf(), Arc::clone(file)));
    }
}

fn sync_router_wal_files(files: &[(PathBuf, Arc<File>)]) -> Result<(), NodeCoreError> {
    for (path, file) in files {
        durability_io::sync_file(file, path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    }
    Ok(())
}

/// Writes a record in the format used before acceptance times were logged (test fixture).
#[cfg(test)]
pub(crate) fn write_legacy_router_wal_segment(
    root: &Path,
    replay_key: &str,
    replay_expires_at: i64,
    entry: &InboxEntry,
) -> Result<(), NodeCoreError> {
    fs::create_dir_all(root).map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    let stored = StoredRouterWalPayload::Submission {
        replay_key: replay_key.to_owned(),
        replay_expires_at,
        entry: Some(Box::new(StoredRouterWalInboxEntry::try_from(entry)?)),
    };
    let encoded = postcard::to_allocvec(&stored)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    let mut file = File::create(router_wal_segment_path(root, 0))
        .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    file.write_all(ROUTER_WAL_MAGIC)
        .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    write_router_wal_record_to_file(&file, &encoded)
}

fn writer_check(path: &Path, operation: &str) -> Result<(), NodeCoreError> {
    crate::fatal_durability::check()?;
    #[cfg(any(test, feature = "durability-test-hooks"))]
    crate::durability_test_hooks::notify(path, operation, false).map_err(identity::error)?;
    #[cfg(not(any(test, feature = "durability-test-hooks")))]
    let _ = (path, operation);
    Ok(())
}
fn write_router_wal_record_to_file(file: &File, encoded: &[u8]) -> Result<(), NodeCoreError> {
    write_router_wal_record_with_path(file, encoded, Path::new(""))
}
fn write_router_wal_record_with_path(
    file: &File,
    encoded: &[u8],
    path: &Path,
) -> Result<(), NodeCoreError> {
    let len = u32::try_from(encoded.len())
        .map_err(|_| NodeCoreError::ItestJson("router WAL record too large".to_owned()))?;
    let crc = crc32fast::hash(encoded);
    let mut writer = file;
    for (operation, bytes) in [
        ("record_length", len.to_le_bytes().as_slice()),
        ("record_crc", crc.to_le_bytes().as_slice()),
        ("record_payload", encoded),
    ] {
        durability_io::boundary(path, operation, || writer.write_all(bytes))
            .map_err(identity::error)?;
    }
    Ok(())
}

fn router_wal_usize_env(name: &str, default: usize) -> usize {
    crate::environment::parsed::<usize>(name).filter(|value| *value > 0).unwrap_or(default)
}

fn router_wal_u64_env(name: &str, default: u64) -> u64 {
    crate::environment::parsed::<u64>(name).filter(|value| *value > 0).unwrap_or(default)
}

fn router_wal_pipeline_enabled() -> bool {
    crate::environment::var(ROUTER_WAL_PIPELINE_ENV).is_ok_and(|value| {
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("on")
    })
}

fn router_wal_shard_count() -> usize {
    crate::environment::parsed::<usize>(ROUTER_WAL_SHARDS_ENV)
        .filter(|value| *value > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(8, usize::from))
        .max(1)
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
    use std::sync::Barrier;

    #[test]
    fn legacy_classified_receipts_do_not_gain_sender_assignments()
    -> Result<(), Box<dyn std::error::Error>> {
        for assigned in [false, true] {
            let entry = router_wal_inbox_entry("legacy-classified", "target");
            let stored = StoredRouterWalPayload::SubmissionClassified {
                replay_key: "legacy".into(),
                replay_expires_at: i64::MAX,
                accepted_at: 1_760_000_001,
                entry: Some(Box::new(StoredRouterWalInboxEntry::try_from(&entry)?)),
                local_delivery: RouterWalLocalDelivery {
                    sender_root_commitment: "sender".into(),
                    envelope_id: entry.envelope.envelope_id.clone(),
                    target_delivery_id: "target".into(),
                },
            };
            let stored = if assigned {
                StoredRouterWalPayload::SenderAssigned { payload: Box::new(stored) }
            } else {
                stored
            };
            let stored = StoredRouterWalPayload::Incarnated {
                incarnation_id: crate::router_store::incarnation::new_id()?,
                payload: Box::new(stored),
            };
            let bytes = postcard::to_allocvec(&stored)?;
            let stored: StoredRouterWalPayload = postcard::from_bytes(&bytes)?;
            assert_eq!(stored.sender_assigned(), assigned);
            let mut state = RouterWalState::default();
            let payload = identity::decode_payload(stored, &mut state)?;
            state.apply_with_sender_assignment(
                payload,
                RouterWalRecordLocation { segment_id: 0, offset: 0, len: 1 },
                assigned,
            );
            assert!(state.has_local_delivery_envelope(
                "sender",
                "legacy-classified",
                "target",
                1_760_000_002
            ));
            let receipt = &state.local_delivery_by_sender_envelope["sender"]
                [&("legacy-classified".into(), "target".into())];
            assert_eq!(
                receipt.assignment.is_some(),
                assigned,
                "legacy replay behavior must survive upgrade"
            );
        }
        Ok(())
    }

    #[test]
    fn wal_record_with_v2_key_replays_into_tuple_index() -> Result<(), Box<dyn std::error::Error>> {
        let root = ramflux_crypto::create_identity_root("alice", [0x91; 32]);
        let branch = ramflux_crypto::create_device_branch(
            "alice",
            "device_router_wal",
            1,
            ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
        );
        let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
        let path = temp_router_wal_dir("v2-upgrade")?;
        let db_path = path.join("db");
        let wal_path = path.join("wal");
        let entry = router_wal_inbox_entry("same-id", "left");
        let key = format!(
            "envelope/v2/{}/{}",
            source.storage_key(),
            ramflux_protocol::encode_base64url("same-id")
        );
        {
            let wal = RouterWalStore::open(&wal_path)?;
            wal.record_submission_classified(
                &key,
                1_760_000_300,
                Some(&entry),
                Some(RouterWalLocalDelivery {
                    sender_root_commitment: source.root_commitment().into(),
                    envelope_id: "same-id".into(),
                    target_delivery_id: "left".into(),
                }),
            )?;
        }
        let store = crate::RouterRedbStore::open_with_wal(&db_path, &wal_path)?;
        let (inbox, mut guard) = store.load_delivery_state(1_760_000_001)?;
        assert_eq!(inbox.pending_entries().count(), 1);
        assert!(!guard.accept_envelope_once(&source, &entry.envelope, 1_760_000_001)?);
        assert!(guard.accept_envelope_once(
            &source,
            &router_wal_envelope("same-id", "right"),
            1_760_000_001
        )?);
        assert!(store.has_local_delivery_envelope(
            source.root_commitment(),
            "same-id",
            "left",
            1_760_000_001
        )?);
        assert!(!store.has_local_delivery_envelope(
            source.root_commitment(),
            "same-id",
            "right",
            1_760_000_001
        )?);
        drop(store);
        remove_router_wal_dir(path);
        Ok(())
    }

    #[test]
    fn same_sender_envelope_id_two_targets_survive_restart_and_dedup_independently()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = ramflux_crypto::create_identity_root("alice", [0x91; 32]);
        let branch = ramflux_crypto::create_device_branch(
            "alice",
            "device_router_wal",
            1,
            ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
        );
        let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
        for use_wal in [false, true] {
            let path = temp_router_wal_dir("tuple-v3")?;
            fs::create_dir_all(&path)?;
            let open = || {
                if use_wal {
                    crate::RouterRedbStore::open_with_wal(path.join("db"), path.join("wal"))
                } else {
                    crate::RouterRedbStore::open_without_wal(path.join("db"))
                }
            };
            let store = open()?;
            let mut guard = crate::NodeReplayGuardState::new();
            for target in ["left", "right"] {
                let mut entry = router_wal_inbox_entry("same-id", target);
                // Forwarder attribution is deliberately outside the sender tuple.
                entry.envelope.ext.ext.insert("forwarder".into(), serde_json::json!(target));
                assert!(guard.accept_envelope_once(&source, &entry.envelope, 1_760_000_001)?);
                store.record_submission_increment_for_sender(
                    &crate::envelope_replay_tuple_key(&source, &entry.envelope),
                    1_760_000_300,
                    Some(&entry),
                    Some(source.root_commitment()),
                )?;
            }
            drop(store);
            let store = open()?;
            let (inbox, mut guard) = store.load_delivery_state(1_760_000_001)?;
            assert_eq!(inbox.pending_entries().count(), 2);
            for target in ["left", "right"] {
                let envelope = router_wal_envelope("same-id", target);
                assert_eq!(
                    inbox
                        .pending_entries()
                        .filter(|entry| entry.target_delivery_id == target
                            && entry.envelope.envelope_id == "same-id")
                        .count(),
                    1
                );
                assert!(store.has_local_delivery_envelope(
                    source.root_commitment(),
                    "same-id",
                    target,
                    1_760_000_001
                )?);
                assert!(!guard.accept_envelope_once(&source, &envelope, 1_760_000_001)?);
            }
            assert!(!store.has_local_delivery_envelope(
                source.root_commitment(),
                "same-id",
                "third",
                1_760_000_001
            )?);
            drop(store);
            remove_router_wal_dir(path);
        }
        Ok(())
    }

    #[test]
    fn local_delivery_index_is_keyed_rebuilt_and_pruned_without_submission_scan() {
        let mut state = RouterWalState::default();
        for index in 0..10_000_u64 {
            state.apply(
                RouterWalPayload::Submission {
                    replay_key: format!("unrelated-replay-{index}"),
                    replay_expires_at: 200,
                    entry: None,
                    accepted_at: Some(100),
                    local_delivery: None,
                },
                RouterWalRecordLocation { segment_id: 0, offset: index, len: 1 },
            );
        }
        state.apply(
            RouterWalPayload::Submission {
                replay_key: "indexed-replay".to_owned(),
                replay_expires_at: 200,
                entry: None,
                accepted_at: Some(100),
                local_delivery: Some(RouterWalLocalDelivery {
                    sender_root_commitment: "sender-root".to_owned(),
                    envelope_id: "indexed-envelope".to_owned(),
                    target_delivery_id: "indexed-target".to_owned(),
                }),
            },
            RouterWalRecordLocation { segment_id: 0, offset: 10_001, len: 1 },
        );

        assert_eq!(state.submissions_by_replay_key.len(), 10_001);
        assert_eq!(state.local_delivery_by_sender_envelope.len(), 1);
        assert!(state.has_local_delivery_envelope(
            "sender-root",
            "indexed-envelope",
            "indexed-target",
            199,
        ));
        assert!(!state.has_local_delivery_envelope(
            "other-root",
            "indexed-envelope",
            "indexed-target",
            199,
        ));
        assert_eq!(state.prune(201), 10_001);
        assert!(state.local_delivery_by_sender_envelope.is_empty());
    }

    #[test]
    fn router_wal_recovers_submission_and_truncates_bad_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_router_wal_dir("router_wal_recovers_submission_and_truncates_bad_tail")?;
        let store = RouterWalStore::open(&root)?;
        let entry = router_wal_inbox_entry("env_router_wal_recover", "target_router_wal");
        store.record_submission(
            "device:env_router_wal_recover:env_router_wal_recover",
            9_999_999_999,
            Some(&entry),
        )?;
        drop(store);

        let segment = first_router_wal_segment_file(&root)?;
        let mut file = OpenOptions::new().append(true).open(&segment)?;
        file.write_all(&32_u32.to_le_bytes())?;
        file.write_all(&123_u32.to_le_bytes())?;
        file.write_all(b"partial")?;
        drop(file);
        let len_with_tail = fs::metadata(&segment)?.len();

        let reopened = RouterWalStore::open(&root)?;
        let submissions = reopened.submissions(0);
        assert_eq!(submissions.len(), 1);
        assert_eq!(
            submissions[0].entry.as_ref().map(|entry| entry.envelope.envelope_id.as_str()),
            Some("env_router_wal_recover")
        );
        assert!(fs::metadata(&segment)?.len() < len_with_tail);
        remove_router_wal_dir(root);
        Ok(())
    }

    #[test]
    fn router_wal_shards_route_by_target_and_recover_all_shards()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_router_wal_dir("router_wal_shards_route_by_target_and_recover_all_shards")?;
        let shard_count = 4usize;
        let (left_target, right_target) = different_shard_targets(shard_count);
        let store = RouterWalStore::open_with_shards(&root, shard_count)?;
        let left_entry = router_wal_inbox_entry("env_router_wal_shard_left", &left_target);
        let right_entry = router_wal_inbox_entry("env_router_wal_shard_right", &right_target);
        let left_replay_key = format!(
            "device_router_wal_shard:{}:{}",
            left_entry.envelope.envelope_id, left_entry.envelope.envelope_id
        );
        let right_replay_key = format!(
            "device_router_wal_shard:{}:{}",
            right_entry.envelope.envelope_id, right_entry.envelope.envelope_id
        );

        store.record_submission(&left_replay_key, 9_999_999_999, Some(&left_entry))?;
        store.record_submission(&right_replay_key, 9_999_999_999, Some(&right_entry))?;
        let left_shard = router_wal_shard_for_payload(
            &RouterWalPayload::Submission {
                replay_key: left_replay_key.clone(),
                replay_expires_at: 9_999_999_999,
                entry: Some(Box::new(left_entry)),
                accepted_at: None,
                local_delivery: None,
            },
            shard_count,
        );
        let right_shard = router_wal_shard_for_payload(
            &RouterWalPayload::Submission {
                replay_key: right_replay_key.clone(),
                replay_expires_at: 9_999_999_999,
                entry: Some(Box::new(right_entry)),
                accepted_at: None,
                local_delivery: None,
            },
            shard_count,
        );
        drop(store);

        assert!(router_wal_segment_path(&router_wal_shard_root(&root, left_shard), 0).exists());
        assert!(router_wal_segment_path(&router_wal_shard_root(&root, right_shard), 0).exists());
        let reopened = RouterWalStore::open_with_shards(&root, shard_count)?;
        let submissions = reopened.submissions(0);
        assert_eq!(submissions.len(), 2);
        assert!(submissions.iter().any(|submission| submission.replay_key == left_replay_key));
        assert!(submissions.iter().any(|submission| submission.replay_key == right_replay_key));
        remove_router_wal_dir(root);
        Ok(())
    }

    #[test]
    fn router_wal_shard_routing_keeps_same_target_on_same_writer() {
        let shard_count = 8usize;
        let first = router_wal_submission_payload(
            "replay_router_wal_same_target_1",
            "env_router_wal_same_target_1",
            "target_router_wal_same_target",
        );
        let second = router_wal_submission_payload(
            "replay_router_wal_same_target_2",
            "env_router_wal_same_target_2",
            "target_router_wal_same_target",
        );
        assert_eq!(
            router_wal_shard_for_payload(&first, shard_count),
            router_wal_shard_for_payload(&second, shard_count)
        );
    }

    #[test]
    fn router_wal_group_commit_recovers_concurrent_submissions()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_router_wal_dir("router_wal_group_commit_recovers_concurrent_submissions")?;
        let store = Arc::new(RouterWalStore::open(&root)?);
        let thread_count = 8usize;
        let started = Arc::new(Barrier::new(thread_count + 1));
        let mut workers = Vec::with_capacity(thread_count);
        for thread_index in 0..thread_count {
            let worker_store = Arc::clone(&store);
            let worker_started = Arc::clone(&started);
            workers.push(thread::spawn(move || -> Result<(), NodeCoreError> {
                worker_started.wait();
                let entry = router_wal_inbox_entry(
                    &format!("env_router_wal_batch_{thread_index}"),
                    "target_router_wal_batch",
                );
                worker_store.record_submission(
                    &format!(
                        "device_router_wal_batch:{}:{}",
                        entry.envelope.envelope_id, entry.envelope.envelope_id
                    ),
                    9_999_999_999,
                    Some(&entry),
                )?;
                Ok(())
            }));
        }
        started.wait();
        for worker in workers {
            worker.join().map_err(|_| io::Error::other("router WAL worker panicked"))??;
        }
        drop(store);

        let reopened = RouterWalStore::open(&root)?;
        assert_eq!(reopened.submissions(0).len(), thread_count);
        remove_router_wal_dir(root);
        Ok(())
    }

    #[test]
    fn router_wal_async_append_recovers_after_await() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_router_wal_dir("router_wal_async_append_recovers_after_await")?;
        let store = Arc::new(RouterWalStore::open(&root)?);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let task_count = 64usize;
            let mut tasks = tokio::task::JoinSet::new();
            for task_index in 0..task_count {
                let task_store = Arc::clone(&store);
                tasks.spawn(async move {
                    let entry = router_wal_inbox_entry(
                        &format!("env_router_wal_async_{task_index}"),
                        "target_router_wal_async",
                    );
                    task_store
                        .record_submission_async(
                            &format!(
                                "device_router_wal_async:{}:{}",
                                entry.envelope.envelope_id, entry.envelope.envelope_id
                            ),
                            9_999_999_999,
                            Some(&entry),
                        )
                        .await
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.map_err(|source| io::Error::other(source.to_string()))??;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        drop(store);

        let reopened = RouterWalStore::open(&root)?;
        assert_eq!(reopened.submissions(0).len(), 64);
        remove_router_wal_dir(root);
        Ok(())
    }

    #[test]
    fn router_wal_pipeline_append_recovers_submission() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_router_wal_dir("router_wal_pipeline_append_recovers_submission")?;
        let store = RouterWalStore::open_with_shards_config(&root, 1, true)?;
        let entry =
            router_wal_inbox_entry("env_router_wal_pipeline_recover", "target_router_wal_pipeline");
        let replay_key = format!(
            "device_router_wal_pipeline:{}:{}",
            entry.envelope.envelope_id, entry.envelope.envelope_id
        );
        store.record_submission(&replay_key, 9_999_999_999, Some(&entry))?;
        drop(store);

        let reopened = RouterWalStore::open_with_shards_config(&root, 1, true)?;
        let submissions = reopened.submissions(0);
        assert_eq!(submissions.len(), 1);
        assert_eq!(submissions[0].replay_key, replay_key);
        assert_eq!(
            submissions[0].entry.as_ref().map(|entry| entry.target_delivery_id.as_str()),
            Some("target_router_wal_pipeline")
        );
        remove_router_wal_dir(root);
        Ok(())
    }

    #[test]
    #[ignore = "set RAMFLUX_ROUTER_WAL_BENCH=1 to run the router WAL throughput bench"]
    fn router_wal_throughput_bench() -> Result<(), Box<dyn std::error::Error>> {
        if crate::environment::var("RAMFLUX_ROUTER_WAL_BENCH").as_deref() != Ok("1") {
            eprintln!("ROUTER_WAL_BENCH skipped set RAMFLUX_ROUTER_WAL_BENCH=1 to run");
            return Ok(());
        }
        let thread_count =
            router_wal_bench_env_usize("RAMFLUX_ROUTER_WAL_BENCH_THREADS", 64).max(1);
        let total_ops =
            router_wal_bench_env_usize("RAMFLUX_ROUTER_WAL_BENCH_TOTAL", 200_000).max(1);
        let root = temp_router_wal_dir("router_wal_throughput_bench")?;
        let store = Arc::new(RouterWalStore::open(&root)?);
        let started = Arc::new(Barrier::new(thread_count + 1));
        let ops_per_thread = total_ops.div_ceil(thread_count);
        let mut workers = Vec::with_capacity(thread_count);
        for thread_index in 0..thread_count {
            let worker_store = Arc::clone(&store);
            let worker_started = Arc::clone(&started);
            let first_op = thread_index * ops_per_thread;
            let end_op = total_ops.min(first_op + ops_per_thread);
            workers.push(thread::spawn(move || -> Result<usize, NodeCoreError> {
                worker_started.wait();
                for op_index in first_op..end_op {
                    let target = format!("target_router_wal_bench_{}", op_index % 1024);
                    let entry = router_wal_inbox_entry(
                        &format!("env_router_wal_bench_{op_index}"),
                        &target,
                    );
                    worker_store.record_submission(
                        &format!(
                            "device_router_wal:{}:{}",
                            entry.envelope.envelope_id, entry.envelope.envelope_id
                        ),
                        9_999_999_999,
                        Some(&entry),
                    )?;
                }
                Ok(end_op.saturating_sub(first_op))
            }));
        }
        let begun_at = Instant::now();
        started.wait();
        let mut completed_ops = 0usize;
        for worker in workers {
            let worker_result =
                worker.join().map_err(|_| io::Error::other("router WAL bench worker panicked"))?;
            completed_ops += worker_result?;
        }
        let elapsed = begun_at.elapsed();
        let completed_ops_f64 = f64::from(u32::try_from(completed_ops).unwrap_or(u32::MAX));
        let ops_per_sec = completed_ops_f64 / elapsed.as_secs_f64();
        eprintln!(
            "ROUTER_WAL_BENCH ops_per_sec={ops_per_sec:.2} total_ops={completed_ops} threads={thread_count} elapsed_ms={:.2}",
            elapsed.as_secs_f64() * 1000.0
        );
        remove_router_wal_dir(root);
        Ok(())
    }

    #[test]
    #[ignore = "set RAMFLUX_ROUTER_WAL_BENCH=1 to run the async router WAL throughput bench"]
    fn router_wal_async_throughput_bench() -> Result<(), Box<dyn std::error::Error>> {
        if crate::environment::var("RAMFLUX_ROUTER_WAL_BENCH").as_deref() != Ok("1") {
            eprintln!("ROUTER_WAL_ASYNC_BENCH skipped set RAMFLUX_ROUTER_WAL_BENCH=1 to run");
            return Ok(());
        }
        let concurrency =
            router_wal_bench_env_usize("RAMFLUX_ROUTER_WAL_BENCH_CONCURRENCY", 1024).max(1);
        let total_ops =
            router_wal_bench_env_usize("RAMFLUX_ROUTER_WAL_BENCH_TOTAL", 200_000).max(1);
        let root = temp_router_wal_dir("router_wal_async_throughput_bench")?;
        let store = Arc::new(RouterWalStore::open(&root)?);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let begun_at = Instant::now();
        let completed_ops = runtime.block_on(async {
            let mut tasks = tokio::task::JoinSet::new();
            let ops_per_task = total_ops.div_ceil(concurrency);
            for task_index in 0..concurrency {
                let task_store = Arc::clone(&store);
                let first_op = task_index * ops_per_task;
                let end_op = total_ops.min(first_op + ops_per_task);
                tasks.spawn(async move {
                    for op_index in first_op..end_op {
                        let target = format!("target_router_wal_async_bench_{}", op_index % 4096);
                        let entry = router_wal_inbox_entry(
                            &format!("env_router_wal_async_bench_{op_index}"),
                            &target,
                        );
                        task_store
                            .record_submission_async(
                                &format!(
                                    "device_router_wal_async_bench:{}:{}",
                                    entry.envelope.envelope_id, entry.envelope.envelope_id
                                ),
                                9_999_999_999,
                                Some(&entry),
                            )
                            .await?;
                    }
                    Ok::<usize, NodeCoreError>(end_op.saturating_sub(first_op))
                });
            }
            let mut completed_ops = 0usize;
            while let Some(result) = tasks.join_next().await {
                completed_ops +=
                    result.map_err(|source| io::Error::other(source.to_string()))??;
            }
            Ok::<usize, Box<dyn std::error::Error>>(completed_ops)
        })?;
        let elapsed = begun_at.elapsed();
        let completed_ops_f64 = f64::from(u32::try_from(completed_ops).unwrap_or(u32::MAX));
        let ops_per_sec = completed_ops_f64 / elapsed.as_secs_f64();
        eprintln!(
            "ROUTER_WAL_ASYNC_BENCH ops_per_sec={ops_per_sec:.2} total_ops={completed_ops} concurrency={concurrency} elapsed_ms={:.2}",
            elapsed.as_secs_f64() * 1000.0
        );
        remove_router_wal_dir(root);
        Ok(())
    }

    pub(super) fn router_wal_inbox_entry(
        envelope_id: &str,
        target_delivery_id: &str,
    ) -> InboxEntry {
        InboxEntry {
            inbox_seq: 1,
            target_delivery_id: target_delivery_id.to_owned(),
            envelope: router_wal_envelope(envelope_id, target_delivery_id),
        }
    }

    fn router_wal_submission_payload(
        replay_key: &str,
        envelope_id: &str,
        target_delivery_id: &str,
    ) -> RouterWalPayload {
        RouterWalPayload::Submission {
            replay_key: replay_key.to_owned(),
            replay_expires_at: 9_999_999_999,
            entry: Some(Box::new(router_wal_inbox_entry(envelope_id, target_delivery_id))),
            accepted_at: None,
            local_delivery: None,
        }
    }

    fn different_shard_targets(shard_count: usize) -> (String, String) {
        let left = "target_router_wal_shard_0".to_owned();
        let left_shard = router_wal_shard_for_payload(
            &router_wal_submission_payload("replay_left", "env_left", &left),
            shard_count,
        );
        for index in 1..1024 {
            let right = format!("target_router_wal_shard_{index}");
            let right_shard = router_wal_shard_for_payload(
                &router_wal_submission_payload("replay_right", "env_right", &right),
                shard_count,
            );
            if right_shard != left_shard {
                return (left, right);
            }
        }
        (left, "target_router_wal_shard_fallback".to_owned())
    }

    fn router_wal_envelope(envelope_id: &str, target_delivery_id: &str) -> Envelope {
        Envelope {
            schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "router_wal_test".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".to_owned(),
            },
            envelope_id: envelope_id.to_owned(),
            source_principal_id: "principal_router_wal".to_owned(),
            source_device_id: "device_router_wal".to_owned(),
            target_delivery_id: target_delivery_id.to_owned(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Normal,
            ttl: 300,
            created_at: 1_760_000_000,
            encrypted_payload: "ciphertext".to_owned(),
            payload_hash: "payload_hash".to_owned(),
        }
    }

    fn temp_router_wal_dir(test_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        Ok(std::env::temp_dir().join(format!(
            "ramflux-node-core-{test_name}-{}-{}",
            std::process::id(),
            elapsed.as_nanos()
        )))
    }

    fn remove_router_wal_dir(path: PathBuf) {
        let _removed = fs::remove_dir_all(path);
    }

    fn first_router_wal_segment_file(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if router_wal_segment_id_from_name(name).is_some() {
                    return Ok(entry.path());
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "router WAL segment file not found").into())
    }

    fn router_wal_bench_env_usize(name: &str, default: usize) -> usize {
        crate::environment::parsed::<usize>(name).unwrap_or(default)
    }
}

#[cfg(test)]
pub(crate) mod acknowledgement_test;
