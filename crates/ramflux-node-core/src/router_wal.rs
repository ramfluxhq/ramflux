// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{InboxEntry, NodeCoreError};
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
                Ok(match (accepted_at, local_delivery) {
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
                })
            }
        }
    }
}

impl TryFrom<StoredRouterWalPayload> for RouterWalPayload {
    type Error = NodeCoreError;

    fn try_from(payload: StoredRouterWalPayload) -> Result<Self, Self::Error> {
        match payload {
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
    local_delivery_by_sender_envelope:
        HashMap<String, HashMap<String, RouterWalLocalDeliveryIndex>>,
    /// Highest sequence ever logged per mailbox, including records that later expired.
    issued_by_target: BTreeMap<String, u64>,
    replay_due: BTreeSet<(i64, String)>,
    entry_due: BTreeSet<(i64, String)>,
}

#[derive(Clone, Debug)]
struct RouterWalLocalDeliveryIndex {
    replay_key: String,
    target_delivery_id: String,
    replay_expires_at: i64,
}

impl RouterWalState {
    fn apply(&mut self, payload: RouterWalPayload, location: RouterWalRecordLocation) {
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
                let record = RouterWalSubmissionRecord {
                    replay_key: replay_key.clone(),
                    replay_expires_at,
                    entry: entry.map(|entry| *entry),
                    accepted_at,
                    local_delivery,
                    location,
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
        if record.entry.is_some() {
            self.entry_due.insert((record.retain_until(), record.replay_key.clone()));
        }
        if let Some(delivery) = &record.local_delivery {
            self.local_delivery_by_sender_envelope
                .entry(delivery.sender_root_commitment.clone())
                .or_default()
                .insert(
                    delivery.envelope_id.clone(),
                    RouterWalLocalDeliveryIndex {
                        replay_key: record.replay_key.clone(),
                        target_delivery_id: delivery.target_delivery_id.clone(),
                        replay_expires_at: record.replay_expires_at,
                    },
                );
        }
    }

    fn unindex(&mut self, record: &RouterWalSubmissionRecord) {
        self.replay_due.remove(&(record.replay_expires_at, record.replay_key.clone()));
        if record.entry.is_some() {
            self.entry_due.remove(&(record.retain_until(), record.replay_key.clone()));
        }
        if let Some(delivery) = &record.local_delivery {
            let remove_sender = if let Some(by_envelope) =
                self.local_delivery_by_sender_envelope.get_mut(&delivery.sender_root_commitment)
            {
                if by_envelope
                    .get(&delivery.envelope_id)
                    .is_some_and(|indexed| indexed.replay_key == record.replay_key)
                {
                    by_envelope.remove(&delivery.envelope_id);
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
                && record.entry.take().is_some()
            {
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
            .and_then(|by_envelope| by_envelope.get(envelope_id))
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
        fs::create_dir_all(&root)
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
        Ok(Self { root, state, writer })
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
        lease: Option<tokio::sync::OwnedRwLockReadGuard<()>>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
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
                    fs::remove_file(&path)
                        .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
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
        Option<tokio::sync::OwnedRwLockReadGuard<()>>,
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
            let state = RouterWalWriterState::open(
                shard_root,
                recovered.last_segment_id.unwrap_or(0),
                recovered.current_offset,
                segment_bytes,
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
            NodeCoreError::ItestJson(format!("router WAL append response closed: {source}"))
        })?
    }

    async fn append_async(
        &self,
        payload: RouterWalPayload,
        lease: Option<tokio::sync::OwnedRwLockReadGuard<()>>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let shard = self.shard_for_payload(&payload)?;
        self.submit_async(
            shard,
            RouterWalAppendRequest { payload, reply: RouterWalAppendReply::Async(reply, lease) },
        )
        .await?;
        response.await.map_err(|source| {
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
        self.shards
            .get(shard)
            .and_then(|shard| shard.sender.as_ref())
            .ok_or_else(|| NodeCoreError::ItestJson("router WAL writer stopped".to_owned()))?
            .send(request)
            .map_err(|source| {
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
            match sender.try_send(request) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) => {
                    request = returned;
                    crate::record_router_wal_submit_backpressure_yield();
                    tokio::task::yield_now().await;
                }
                Err(mpsc::TrySendError::Disconnected(_returned)) => {
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
}

impl RouterWalWriterState {
    fn open(
        root: PathBuf,
        segment_id: u64,
        offset: u64,
        segment_bytes: u64,
    ) -> Result<Self, NodeCoreError> {
        fs::create_dir_all(&root)
            .map_err(|source| NodeCoreError::StoreDirectory { path: root.clone(), source })?;
        let path = router_wal_segment_path(&root, segment_id);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        if offset == 0 && file.metadata().map_or(0, |metadata| metadata.len()) == 0 {
            file.write_all(ROUTER_WAL_MAGIC)
                .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
            file.sync_all().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        }
        let offset = file
            .seek(io::SeekFrom::End(0))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let segment_born = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
        Ok(Self { root, segment_bytes, segment_born, segment_id, offset, file: Arc::new(file) })
    }

    fn append_batch(
        &mut self,
        payloads: &[RouterWalPayload],
    ) -> Result<Vec<RouterWalRecordLocation>, NodeCoreError> {
        let mut locations = Vec::with_capacity(payloads.len());
        let write_started = Instant::now();
        for payload in payloads {
            let stored = StoredRouterWalPayload::try_from(payload)?;
            let encoded = postcard::to_allocvec(&stored)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
            let frame_len = 8_u64
                .checked_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| NodeCoreError::ItestJson("router WAL frame too large".to_owned()))?;
            if self.offset > u64::try_from(ROUTER_WAL_MAGIC.len()).unwrap_or(0)
                && (self.offset.saturating_add(frame_len) > self.segment_bytes
                    || self.segment_born.elapsed().is_ok_and(|age| age.as_secs() >= 3600))
            {
                self.file
                    .sync_all()
                    .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
                self.roll_segment()?;
            }
            locations.push(self.write_record(&encoded)?);
        }
        crate::record_router_save_mutation_us(elapsed_us(write_started));
        let sync_started = Instant::now();
        self.file.sync_all().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let sync_us = elapsed_us(sync_started);
        crate::record_router_save_commit_us(sync_us);
        crate::record_router_wal_batch(payloads.len(), sync_us);
        Ok(locations)
    }

    fn append_batch_no_sync(
        &mut self,
        payloads: &[RouterWalPayload],
    ) -> Result<RouterWalAppendGroup, NodeCoreError> {
        let mut locations = Vec::with_capacity(payloads.len());
        let mut sync_files = Vec::with_capacity(1);
        let write_started = Instant::now();
        for payload in payloads {
            let stored = StoredRouterWalPayload::try_from(payload)?;
            let encoded = postcard::to_allocvec(&stored)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
            let frame_len = 8_u64
                .checked_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| NodeCoreError::ItestJson("router WAL frame too large".to_owned()))?;
            if self.offset > u64::try_from(ROUTER_WAL_MAGIC.len()).unwrap_or(0)
                && (self.offset.saturating_add(frame_len) > self.segment_bytes
                    || self.segment_born.elapsed().is_ok_and(|age| age.as_secs() >= 3600))
            {
                self.roll_segment()?;
            }
            push_unique_router_wal_file(&mut sync_files, &self.file);
            locations.push(self.write_record(&encoded)?);
        }
        crate::record_router_save_mutation_us(elapsed_us(write_started));
        Ok(RouterWalAppendGroup { locations, sync_files })
    }

    fn write_record(&mut self, encoded: &[u8]) -> Result<RouterWalRecordLocation, NodeCoreError> {
        let len = u32::try_from(encoded.len())
            .map_err(|_| NodeCoreError::ItestJson("router WAL record too large".to_owned()))?;
        let offset = self.offset;
        write_router_wal_record_to_file(&self.file, encoded)?;
        self.offset = self.offset.saturating_add(8 + u64::from(len));
        Ok(RouterWalRecordLocation { segment_id: self.segment_id, offset, len })
    }

    fn roll_segment(&mut self) -> Result<(), NodeCoreError> {
        self.segment_id = self.segment_id.saturating_add(1);
        let path = router_wal_segment_path(&self.root, self.segment_id);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        file.write_all(ROUTER_WAL_MAGIC)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        self.file = Arc::new(file);
        self.segment_born = std::time::SystemTime::now();
        self.offset = u64::try_from(ROUTER_WAL_MAGIC.len()).unwrap_or(0);
        Ok(())
    }
}

struct RouterWalAppendGroup {
    locations: Vec<RouterWalRecordLocation>,
    sync_files: Vec<Arc<File>>,
}

struct RouterWalFsyncGroup {
    batch: Vec<RouterWalAppendRequest>,
    payloads: Vec<RouterWalPayload>,
    locations: Vec<RouterWalRecordLocation>,
    sync_files: Vec<Arc<File>>,
}

fn router_wal_writer_loop(
    mut state: RouterWalWriterState,
    receiver: &mpsc::Receiver<RouterWalAppendRequest>,
    wal_state: &Arc<Mutex<RouterWalState>>,
    batch_max: usize,
    window: Duration,
) {
    while let Ok(first) = receiver.recv() {
        let mut batch = Vec::with_capacity(batch_max);
        batch.push(first);
        let deadline = Instant::now() + window;
        while batch.len() < batch_max {
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
            Ok(locations) => router_wal_ack_success(batch, &payloads, locations, wal_state),
            Err(error) => router_wal_ack_error(batch, &error),
        }
    }
}

fn router_wal_pipeline_writer_loop(
    mut state: RouterWalWriterState,
    receiver: &mpsc::Receiver<RouterWalAppendRequest>,
    fsync_sender: mpsc::SyncSender<RouterWalFsyncGroup>,
    batch_max: usize,
    window: Duration,
) {
    while let Ok(first) = receiver.recv() {
        let mut batch = Vec::with_capacity(batch_max);
        batch.push(first);
        let deadline = Instant::now() + window;
        while batch.len() < batch_max {
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
                if let Err(error) = fsync_sender.send(fsync_group) {
                    router_wal_ack_error(
                        error.0.batch,
                        &NodeCoreError::ItestJson("router WAL fsync writer stopped".to_owned()),
                    );
                }
            }
            Err(error) => router_wal_ack_error(batch, &error),
        }
    }
    drop(fsync_sender);
}

fn router_wal_fsync_loop(
    receiver: &mpsc::Receiver<RouterWalFsyncGroup>,
    wal_state: &Arc<Mutex<RouterWalState>>,
) {
    while let Ok(first) = receiver.recv() {
        let mut groups = vec![first];
        while let Ok(group) = receiver.try_recv() {
            groups.push(group);
        }

        let mut sync_files = Vec::new();
        let mut record_count = 0usize;
        for group in &groups {
            record_count = record_count.saturating_add(group.payloads.len());
            for file in &group.sync_files {
                push_unique_router_wal_file(&mut sync_files, file);
            }
        }

        let sync_started = Instant::now();
        let sync_result = sync_router_wal_files(&sync_files);
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
                    );
                }
            }
            Err(error) => {
                for group in groups {
                    router_wal_ack_error(group.batch, &error);
                }
            }
        }
    }
}

fn router_wal_ack_success(
    batch: Vec<RouterWalAppendRequest>,
    payloads: &[RouterWalPayload],
    locations: Vec<RouterWalRecordLocation>,
    wal_state: &Arc<Mutex<RouterWalState>>,
) {
    #[cfg(test)]
    let _pause = acknowledgement_test::before_apply(wal_state);
    let update_result = wal_state.lock().map_err(|source| source.to_string()).map(|mut guard| {
        for (payload, location) in payloads.iter().cloned().zip(locations.iter().cloned()) {
            guard.apply(payload, location);
        }
    });
    match update_result {
        Ok(()) => {
            for (request, location) in batch.into_iter().zip(locations) {
                request.reply.send(Ok(location));
            }
        }
        Err(error) => {
            for request in batch {
                request.reply.send(Err(NodeCoreError::ItestJson(format!(
                    "router WAL index lock poisoned: {error}"
                ))));
            }
        }
    }
}

fn router_wal_ack_error(batch: Vec<RouterWalAppendRequest>, error: &NodeCoreError) {
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
    let mut state = RouterWalState::default();
    let _legacy = recover_router_wal_directory(root, &mut state)?;
    let mut shards = BTreeMap::new();
    for (shard_id, shard_root) in router_wal_existing_shard_roots(root)? {
        let recovered = recover_router_wal_directory(&shard_root, &mut state)?;
        if recovered.last_segment_id.is_some() {
            shards.insert(shard_id, recovered);
        }
    }
    Ok(RouterWalRecovery { state, shards })
}

fn recover_router_wal_directory(
    root: &Path,
    state: &mut RouterWalState,
) -> Result<RouterWalRecoveredShard, NodeCoreError> {
    let mut segments = router_wal_segment_ids(root)?;
    if segments.is_empty() {
        return Ok(RouterWalRecoveredShard::default());
    }
    segments.sort_unstable();
    let mut current_offset = 0_u64;
    let mut last_segment_id = None;
    for segment_id in segments {
        let offset = recover_router_wal_segment(root, segment_id, state)?;
        current_offset = offset;
        last_segment_id = Some(segment_id);
    }
    Ok(RouterWalRecoveredShard { last_segment_id, current_offset })
}

fn recover_router_wal_segment(
    root: &Path,
    segment_id: u64,
    state: &mut RouterWalState,
) -> Result<u64, NodeCoreError> {
    let path = router_wal_segment_path(root, segment_id);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    let mut offset = read_router_wal_magic(&mut file)?;
    loop {
        let record_offset = offset;
        let Some((payload, len)) = read_router_wal_record(&mut file)? else {
            break;
        };
        offset = offset.saturating_add(8 + u64::from(len));
        let location = RouterWalRecordLocation { segment_id, offset: record_offset, len };
        state.apply(payload, location);
    }
    file.set_len(offset).map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(offset)
}

fn read_router_wal_magic(file: &mut File) -> Result<u64, NodeCoreError> {
    let mut magic = vec![0_u8; ROUTER_WAL_MAGIC.len()];
    let bytes =
        file.read(&mut magic).map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    if bytes == 0 {
        file.write_all(ROUTER_WAL_MAGIC)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        return Ok(u64::try_from(ROUTER_WAL_MAGIC.len()).unwrap_or(0));
    }
    if bytes != ROUTER_WAL_MAGIC.len() || magic != ROUTER_WAL_MAGIC {
        return Err(NodeCoreError::ItestJson("invalid router WAL segment magic".to_owned()));
    }
    Ok(u64::try_from(ROUTER_WAL_MAGIC.len()).unwrap_or(0))
}

fn read_router_wal_record(
    file: &mut File,
) -> Result<Option<(RouterWalPayload, u32)>, NodeCoreError> {
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
    Ok(Some((payload.try_into()?, len)))
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

fn push_unique_router_wal_file(files: &mut Vec<Arc<File>>, file: &Arc<File>) {
    if !files.iter().any(|existing| Arc::ptr_eq(existing, file)) {
        files.push(Arc::clone(file));
    }
}

fn sync_router_wal_files(files: &[Arc<File>]) -> Result<(), NodeCoreError> {
    for file in files {
        file.sync_all().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
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

fn write_router_wal_record_to_file(file: &File, encoded: &[u8]) -> Result<(), NodeCoreError> {
    let len = u32::try_from(encoded.len())
        .map_err(|_| NodeCoreError::ItestJson("router WAL record too large".to_owned()))?;
    let crc = crc32fast::hash(encoded);
    let mut writer = file;
    writer
        .write_all(&len.to_le_bytes())
        .and_then(|()| writer.write_all(&crc.to_le_bytes()))
        .and_then(|()| writer.write_all(encoded))
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
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

    fn router_wal_inbox_entry(envelope_id: &str, target_delivery_id: &str) -> InboxEntry {
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
