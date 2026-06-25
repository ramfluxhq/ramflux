// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::{NodeCoreError, NotifyQueueEntry, ProviderPushAttempt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const NOTIFY_WAL_SEGMENT_BYTES_ENV: &str = "RAMFLUX_NOTIFY_WAL_SEGMENT_BYTES";
const NOTIFY_WAL_SEGMENT_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;
const NOTIFY_WAL_BATCH_MAX_ENV: &str = "RAMFLUX_NOTIFY_WAL_BATCH_MAX";
const NOTIFY_WAL_BATCH_MAX_DEFAULT: usize = 256;
const NOTIFY_WAL_COMMIT_WINDOW_US_ENV: &str = "RAMFLUX_NOTIFY_WAL_COMMIT_WINDOW_US";
const NOTIFY_WAL_COMMIT_WINDOW_US_DEFAULT: u64 = 1_000;
const NOTIFY_WAL_QUEUE_CAPACITY_ENV: &str = "RAMFLUX_NOTIFY_WAL_QUEUE_CAPACITY";
const NOTIFY_WAL_QUEUE_CAPACITY_DEFAULT: usize = 65_536;
const NOTIFY_WAL_COMPACT_INTERVAL_SECS_ENV: &str = "RAMFLUX_NOTIFY_WAL_COMPACT_INTERVAL_SECS";
const NOTIFY_WAL_COMPACT_INTERVAL_SECS_DEFAULT: u64 = 30;
const NOTIFY_WAL_COMPACT_SEGMENTS_ENV: &str = "RAMFLUX_NOTIFY_WAL_COMPACT_SEGMENTS";
const NOTIFY_WAL_COMPACT_SEGMENTS_DEFAULT: usize = 8;
const NOTIFY_WAL_MAGIC: &[u8] = b"ramflux-notify-wal-v1\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyWalRecordLocation {
    pub segment_id: u64,
    pub offset: u64,
    pub len: u32,
}

#[derive(Clone, Debug)]
pub struct NotifyWalRecoveredRecord {
    pub payload: NotifyWalPayload,
    pub location: NotifyWalRecordLocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotifyWalPendingWake {
    Entry(Box<NotifyQueueEntry>),
    Raw(NotifyWalRawWake),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NotifyWalRecoveredCounts {
    pub queue_entry_count: usize,
    pub raw_wake_count: usize,
    pub provider_attempt_queue_count: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NotifyWalPendingCounts {
    pub queue_entry_count: usize,
    pub raw_wake_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum NotifyWalPayload {
    QueueEntry(NotifyQueueEntry),
    RawWake(NotifyWalRawWake),
    ProviderAttempt(ProviderPushAttempt),
    Delivered { queue_id: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotifyWalRawWake {
    pub queue_id: String,
    pub raw_body: Vec<u8>,
    pub queued_at: u64,
}

#[derive(Deserialize, Serialize)]
enum StoredNotifyWalPayload {
    QueueEntry(StoredNotifyWalQueueEntry),
    RawWake(NotifyWalRawWake),
    ProviderAttempt(ProviderPushAttempt),
    Delivered { queue_id: String },
}

#[derive(Deserialize, Serialize)]
struct StoredNotifyWalQueueEntry {
    queue_id: String,
    device_delivery_id: String,
    wake: StoredNotifyWalWake,
    push_alias_hash: String,
    queued_at: u64,
    expires_at: u64,
    attempt_count: u32,
    status: crate::NotifyQueueStatus,
    dnd_active: bool,
}

#[derive(Deserialize, Serialize)]
struct StoredNotifyWalWake {
    schema: String,
    version: u32,
    domain: String,
    ext_json: Option<Vec<u8>>,
    signed: ramflux_protocol::SignedFields,
    wake_id: String,
    push_alias: String,
    delivery_class: ramflux_protocol::NotificationDeliveryClass,
    priority: ramflux_protocol::PushPriority,
    ttl: u32,
    collapse_key: Option<String>,
    encrypted_hint: Option<String>,
}

impl NotifyWalPayload {
    #[must_use]
    pub fn record_id(&self) -> String {
        match self {
            Self::QueueEntry(entry) => format!("queue:{}", entry.queue_id),
            Self::RawWake(raw) => format!("raw:{}", raw.queue_id),
            Self::ProviderAttempt(attempt) => format!("attempt:{}", attempt.queue_id),
            Self::Delivered { queue_id } => format!("delivered:{queue_id}"),
        }
    }
}

impl TryFrom<&NotifyWalPayload> for StoredNotifyWalPayload {
    type Error = NodeCoreError;

    fn try_from(payload: &NotifyWalPayload) -> Result<Self, Self::Error> {
        match payload {
            NotifyWalPayload::QueueEntry(entry) => {
                Ok(Self::QueueEntry(StoredNotifyWalQueueEntry::try_from(entry)?))
            }
            NotifyWalPayload::RawWake(raw) => Ok(Self::RawWake(raw.clone())),
            NotifyWalPayload::ProviderAttempt(attempt) => {
                Ok(Self::ProviderAttempt(attempt.clone()))
            }
            NotifyWalPayload::Delivered { queue_id } => {
                Ok(Self::Delivered { queue_id: queue_id.clone() })
            }
        }
    }
}

impl TryFrom<StoredNotifyWalPayload> for NotifyWalPayload {
    type Error = NodeCoreError;

    fn try_from(payload: StoredNotifyWalPayload) -> Result<Self, Self::Error> {
        match payload {
            StoredNotifyWalPayload::QueueEntry(entry) => Ok(Self::QueueEntry(entry.try_into()?)),
            StoredNotifyWalPayload::RawWake(raw) => Ok(Self::RawWake(raw)),
            StoredNotifyWalPayload::ProviderAttempt(attempt) => Ok(Self::ProviderAttempt(attempt)),
            StoredNotifyWalPayload::Delivered { queue_id } => Ok(Self::Delivered { queue_id }),
        }
    }
}

impl TryFrom<&NotifyQueueEntry> for StoredNotifyWalQueueEntry {
    type Error = NodeCoreError;

    fn try_from(entry: &NotifyQueueEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            queue_id: entry.queue_id.clone(),
            device_delivery_id: entry.device_delivery_id.clone(),
            wake: StoredNotifyWalWake::try_from(&entry.wake)?,
            push_alias_hash: entry.push_alias_hash.clone(),
            queued_at: entry.queued_at,
            expires_at: entry.expires_at,
            attempt_count: entry.attempt_count,
            status: entry.status.clone(),
            dnd_active: entry.dnd_active,
        })
    }
}

impl TryFrom<StoredNotifyWalQueueEntry> for NotifyQueueEntry {
    type Error = NodeCoreError;

    fn try_from(entry: StoredNotifyWalQueueEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            queue_id: entry.queue_id,
            device_delivery_id: entry.device_delivery_id,
            wake: entry.wake.try_into()?,
            push_alias_hash: entry.push_alias_hash,
            queued_at: entry.queued_at,
            expires_at: entry.expires_at,
            attempt_count: entry.attempt_count,
            status: entry.status,
            dnd_active: entry.dnd_active,
        })
    }
}

impl TryFrom<&ramflux_protocol::NotificationWake> for StoredNotifyWalWake {
    type Error = NodeCoreError;

    fn try_from(wake: &ramflux_protocol::NotificationWake) -> Result<Self, Self::Error> {
        let ext_json = if wake.ext.ext.is_empty() {
            None
        } else {
            Some(
                serde_json::to_vec(&wake.ext.ext)
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?,
            )
        };
        Ok(Self {
            schema: wake.schema.clone(),
            version: wake.version,
            domain: wake.domain.clone(),
            ext_json,
            signed: wake.signed.clone(),
            wake_id: wake.wake_id.clone(),
            push_alias: wake.push_alias.clone(),
            delivery_class: wake.delivery_class.clone(),
            priority: wake.priority.clone(),
            ttl: wake.ttl,
            collapse_key: wake.collapse_key.clone(),
            encrypted_hint: wake.encrypted_hint.clone(),
        })
    }
}

impl TryFrom<StoredNotifyWalWake> for ramflux_protocol::NotificationWake {
    type Error = NodeCoreError;

    fn try_from(wake: StoredNotifyWalWake) -> Result<Self, Self::Error> {
        let ext = match wake.ext_json {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?,
            None => std::collections::BTreeMap::new(),
        };
        Ok(Self {
            schema: wake.schema,
            version: wake.version,
            domain: wake.domain,
            ext: ramflux_protocol::Ext { ext },
            signed: wake.signed,
            wake_id: wake.wake_id,
            push_alias: wake.push_alias,
            delivery_class: wake.delivery_class,
            priority: wake.priority,
            ttl: wake.ttl,
            collapse_key: wake.collapse_key,
            encrypted_hint: wake.encrypted_hint,
        })
    }
}

pub struct NotifyWalStore {
    state: Arc<Mutex<NotifyWalState>>,
    writer: NotifyWalWriter,
}

#[derive(Clone, Debug, Default)]
struct NotifyWalState {
    entries_by_id: BTreeMap<String, NotifyWalRecoveredRecord>,
    raw_wakes_by_id: BTreeMap<String, NotifyWalRecoveredRecord>,
    provider_attempts_by_queue: BTreeMap<String, Vec<ProviderPushAttempt>>,
}

impl NotifyWalState {
    fn apply(&mut self, payload: NotifyWalPayload, location: NotifyWalRecordLocation) {
        match payload {
            NotifyWalPayload::QueueEntry(entry) => {
                self.raw_wakes_by_id.remove(&entry.queue_id);
                self.entries_by_id.insert(
                    entry.queue_id.clone(),
                    NotifyWalRecoveredRecord {
                        payload: NotifyWalPayload::QueueEntry(entry),
                        location,
                    },
                );
            }
            NotifyWalPayload::RawWake(raw) => {
                if !self.entries_by_id.contains_key(&raw.queue_id) {
                    self.raw_wakes_by_id.insert(
                        raw.queue_id.clone(),
                        NotifyWalRecoveredRecord {
                            payload: NotifyWalPayload::RawWake(raw),
                            location,
                        },
                    );
                }
            }
            NotifyWalPayload::ProviderAttempt(attempt) => {
                let attempts =
                    self.provider_attempts_by_queue.entry(attempt.queue_id.clone()).or_default();
                if !attempts.contains(&attempt) {
                    attempts.push(attempt);
                }
            }
            NotifyWalPayload::Delivered { queue_id } => {
                self.entries_by_id.remove(&queue_id);
                self.raw_wakes_by_id.remove(&queue_id);
            }
        }
    }

    fn pending_wakes_without_attempts(&self, limit: usize) -> Vec<NotifyWalPendingWake> {
        if limit == 0 {
            return Vec::new();
        }
        let mut entries = Vec::with_capacity(limit);
        for recovered in self.entries_by_id.values() {
            if entries.len() >= limit {
                break;
            }
            let NotifyWalPayload::QueueEntry(entry) = &recovered.payload else {
                continue;
            };
            if entry.status == crate::NotifyQueueStatus::Pending
                && !entry.device_delivery_id.is_empty()
                && !self.provider_attempts_by_queue.contains_key(&entry.queue_id)
            {
                entries.push(NotifyWalPendingWake::Entry(Box::new(entry.clone())));
            }
        }
        for recovered in self.raw_wakes_by_id.values() {
            if entries.len() >= limit {
                break;
            }
            let NotifyWalPayload::RawWake(raw) = &recovered.payload else {
                continue;
            };
            if !raw.queue_id.is_empty()
                && !self.provider_attempts_by_queue.contains_key(&raw.queue_id)
            {
                entries.push(NotifyWalPendingWake::Raw(raw.clone()));
            }
        }
        entries
    }

    fn compacted_payloads(&self) -> Vec<NotifyWalPayload> {
        let mut payloads = Vec::with_capacity(
            self.entries_by_id.len()
                + self.raw_wakes_by_id.len()
                + self.provider_attempts_by_queue.values().map(Vec::len).sum::<usize>(),
        );
        payloads.extend(self.entries_by_id.values().filter_map(|record| match &record.payload {
            NotifyWalPayload::QueueEntry(entry) => {
                Some(NotifyWalPayload::QueueEntry(entry.clone()))
            }
            NotifyWalPayload::RawWake(_)
            | NotifyWalPayload::ProviderAttempt(_)
            | NotifyWalPayload::Delivered { .. } => None,
        }));
        payloads.extend(self.raw_wakes_by_id.values().filter_map(|record| match &record.payload {
            NotifyWalPayload::RawWake(raw) => Some(NotifyWalPayload::RawWake(raw.clone())),
            NotifyWalPayload::QueueEntry(_)
            | NotifyWalPayload::ProviderAttempt(_)
            | NotifyWalPayload::Delivered { .. } => None,
        }));
        payloads.extend(
            self.provider_attempts_by_queue.values().flat_map(|attempts| {
                attempts.iter().cloned().map(NotifyWalPayload::ProviderAttempt)
            }),
        );
        payloads
    }
}

impl NotifyWalStore {
    /// # Errors
    /// Returns an error when the WAL directory cannot be created, recovered, or opened.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)
            .map_err(|source| NodeCoreError::StoreDirectory { path: root.clone(), source })?;
        let segment_bytes =
            notify_wal_u64_env(NOTIFY_WAL_SEGMENT_BYTES_ENV, NOTIFY_WAL_SEGMENT_BYTES_DEFAULT)
                .max(1024 * 1024);
        let recovered = recover_notify_wal(&root)?;
        let next_segment_id = recovered.last_segment_id.unwrap_or(0);
        let writer_state = NotifyWalWriterState::open(
            root,
            next_segment_id,
            recovered.current_offset,
            segment_bytes,
        )?;
        let state = Arc::new(Mutex::new(recovered.state));
        let writer = NotifyWalWriter::start(writer_state, Arc::clone(&state))?;
        Ok(Self { state, writer })
    }

    #[must_use]
    pub fn recovered_counts(&self) -> NotifyWalRecoveredCounts {
        self.state.lock().map_or_else(
            |_| NotifyWalRecoveredCounts::default(),
            |state| NotifyWalRecoveredCounts {
                queue_entry_count: state.entries_by_id.len(),
                raw_wake_count: state.raw_wakes_by_id.len(),
                provider_attempt_queue_count: state.provider_attempts_by_queue.len(),
            },
        )
    }

    #[must_use]
    pub fn pending_counts(&self, limit: usize) -> NotifyWalPendingCounts {
        self.pending_wakes_without_attempts(limit).into_iter().fold(
            NotifyWalPendingCounts::default(),
            |mut counts, pending| {
                match pending {
                    NotifyWalPendingWake::Entry(_) => {
                        counts.queue_entry_count = counts.queue_entry_count.saturating_add(1);
                    }
                    NotifyWalPendingWake::Raw(_) => {
                        counts.raw_wake_count = counts.raw_wake_count.saturating_add(1);
                    }
                }
                counts
            },
        )
    }

    /// # Errors
    /// Returns an error when the record cannot be durably appended.
    pub fn append(
        &self,
        payload: NotifyWalPayload,
    ) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        self.writer.append(payload)
    }

    /// # Errors
    /// Returns an error when the record cannot be durably appended.
    pub async fn append_async(
        &self,
        payload: NotifyWalPayload,
    ) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        self.writer.append_async(payload).await
    }

    #[must_use]
    pub fn get(&self, record_id: &str) -> Option<NotifyWalRecoveredRecord> {
        let queue_id = record_id.strip_prefix("queue:").unwrap_or(record_id);
        self.state.lock().ok()?.entries_by_id.get(queue_id).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |state| state.entries_by_id.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn provider_attempts(&self, queue_id: &str) -> Vec<ProviderPushAttempt> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.provider_attempts_by_queue.get(queue_id).cloned())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn all_provider_attempts(&self) -> BTreeMap<String, Vec<ProviderPushAttempt>> {
        self.state
            .lock()
            .map_or_else(|_| BTreeMap::new(), |state| state.provider_attempts_by_queue.clone())
    }

    #[must_use]
    pub fn active_entries(&self) -> Vec<NotifyQueueEntry> {
        self.state.lock().map_or_else(
            |_| Vec::new(),
            |state| {
                state
                    .entries_by_id
                    .values()
                    .filter_map(|recovered| match &recovered.payload {
                        NotifyWalPayload::QueueEntry(entry) => Some(entry.clone()),
                        NotifyWalPayload::RawWake(_)
                        | NotifyWalPayload::ProviderAttempt(_)
                        | NotifyWalPayload::Delivered { .. } => None,
                    })
                    .collect()
            },
        )
    }

    #[must_use]
    pub fn pending_entries_without_attempts(&self, limit: usize) -> Vec<NotifyQueueEntry> {
        self.pending_wakes_without_attempts(limit)
            .into_iter()
            .filter_map(|pending| match pending {
                NotifyWalPendingWake::Entry(entry) => Some(*entry),
                NotifyWalPendingWake::Raw(_) => None,
            })
            .collect()
    }

    #[must_use]
    pub fn pending_wakes_without_attempts(&self, limit: usize) -> Vec<NotifyWalPendingWake> {
        self.state
            .lock()
            .map_or_else(|_| Vec::new(), |state| state.pending_wakes_without_attempts(limit))
    }

    /// # Errors
    /// Returns an error when the raw wake cannot be durably appended.
    pub fn record_raw_wake(
        &self,
        raw: NotifyWalRawWake,
    ) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        self.append(NotifyWalPayload::RawWake(raw))
    }

    /// # Errors
    /// Returns an error when the raw wakes cannot be durably appended in one WAL batch.
    pub fn record_raw_wakes_batch(
        &self,
        raws: Vec<NotifyWalRawWake>,
    ) -> Result<Vec<NotifyWalRecordLocation>, NodeCoreError> {
        self.writer
            .append_batch(raws.into_iter().map(NotifyWalPayload::RawWake).collect::<Vec<_>>())
    }

    /// # Errors
    /// Returns an error when the raw wake cannot be durably appended.
    pub async fn record_raw_wake_async(
        &self,
        raw: NotifyWalRawWake,
    ) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        self.append_async(NotifyWalPayload::RawWake(raw)).await
    }

    /// # Errors
    /// Returns an error when the provider attempt cannot be durably appended.
    pub fn record_provider_attempt(
        &self,
        attempt: ProviderPushAttempt,
    ) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        self.append(NotifyWalPayload::ProviderAttempt(attempt))
    }

    /// # Errors
    /// Returns an error when the delivery tombstone cannot be durably appended.
    pub fn mark_delivered(
        &self,
        queue_id: impl Into<String>,
    ) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        self.append(NotifyWalPayload::Delivered { queue_id: queue_id.into() })
    }

    /// # Errors
    /// Returns an error when the WAL cannot be compacted durably.
    pub fn compact(&self) -> Result<(), NodeCoreError> {
        self.writer.compact()
    }
}

struct NotifyWalWriter {
    sender: Option<mpsc::SyncSender<NotifyWalWriterRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

enum NotifyWalWriterRequest {
    Append(Box<NotifyWalAppendRequest>),
    AppendBatch(Box<NotifyWalAppendBatchRequest>),
    Compact(NotifyWalCompactRequest),
}

struct NotifyWalAppendRequest {
    payload: NotifyWalPayload,
    reply: NotifyWalAppendReply,
}

struct NotifyWalAppendBatchRequest {
    payloads: Vec<NotifyWalPayload>,
    reply: NotifyWalAppendBatchReply,
}

struct NotifyWalCompactRequest {
    reply: mpsc::SyncSender<Result<(), NodeCoreError>>,
}

#[derive(Clone, Copy)]
struct NotifyWalCompactionPolicy {
    interval: Duration,
    max_segments: usize,
}

enum NotifyWalAppendReply {
    Sync(mpsc::SyncSender<Result<NotifyWalRecordLocation, NodeCoreError>>),
    Async(tokio::sync::oneshot::Sender<Result<NotifyWalRecordLocation, NodeCoreError>>),
}

impl NotifyWalAppendReply {
    fn send(self, result: Result<NotifyWalRecordLocation, NodeCoreError>) {
        match self {
            Self::Sync(reply) => {
                let _sent = reply.send(result);
            }
            Self::Async(reply) => {
                let _sent = reply.send(result);
            }
        }
    }
}

enum NotifyWalAppendBatchReply {
    Sync(mpsc::SyncSender<Result<Vec<NotifyWalRecordLocation>, NodeCoreError>>),
}

impl NotifyWalAppendBatchReply {
    fn send(self, result: Result<Vec<NotifyWalRecordLocation>, NodeCoreError>) {
        match self {
            Self::Sync(reply) => {
                let _sent = reply.send(result);
            }
        }
    }
}

impl NotifyWalWriter {
    fn start(
        state: NotifyWalWriterState,
        wal_state: Arc<Mutex<NotifyWalState>>,
    ) -> Result<Self, NodeCoreError> {
        let batch_max =
            notify_wal_usize_env(NOTIFY_WAL_BATCH_MAX_ENV, NOTIFY_WAL_BATCH_MAX_DEFAULT).max(1);
        let queue_capacity =
            notify_wal_usize_env(NOTIFY_WAL_QUEUE_CAPACITY_ENV, NOTIFY_WAL_QUEUE_CAPACITY_DEFAULT)
                .max(batch_max);
        let window = Duration::from_micros(notify_wal_u64_env(
            NOTIFY_WAL_COMMIT_WINDOW_US_ENV,
            NOTIFY_WAL_COMMIT_WINDOW_US_DEFAULT,
        ));
        let compact_interval = Duration::from_secs(notify_wal_u64_env(
            NOTIFY_WAL_COMPACT_INTERVAL_SECS_ENV,
            NOTIFY_WAL_COMPACT_INTERVAL_SECS_DEFAULT,
        ));
        let compact_segments = notify_wal_usize_env(
            NOTIFY_WAL_COMPACT_SEGMENTS_ENV,
            NOTIFY_WAL_COMPACT_SEGMENTS_DEFAULT,
        )
        .max(2);
        let compaction = NotifyWalCompactionPolicy {
            interval: compact_interval,
            max_segments: compact_segments,
        };
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let thread = thread::Builder::new()
            .name("ramflux-notify-wal-writer".to_owned())
            .spawn(move || {
                notify_wal_writer_loop(state, &receiver, &wal_state, batch_max, window, compaction);
            })
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        Ok(Self { sender: Some(sender), thread: Some(thread) })
    }

    fn append(&self, payload: NotifyWalPayload) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.submit(NotifyWalAppendRequest { payload, reply: NotifyWalAppendReply::Sync(reply) })?;
        response.recv().map_err(|source| {
            NodeCoreError::ItestJson(format!("notify WAL append response closed: {source}"))
        })?
    }

    fn append_batch(
        &self,
        payloads: Vec<NotifyWalPayload>,
    ) -> Result<Vec<NotifyWalRecordLocation>, NodeCoreError> {
        if payloads.is_empty() {
            return Ok(Vec::new());
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.submit_batch(NotifyWalAppendBatchRequest {
            payloads,
            reply: NotifyWalAppendBatchReply::Sync(reply),
        })?;
        response.recv().map_err(|source| {
            NodeCoreError::ItestJson(format!("notify WAL batch append response closed: {source}"))
        })?
    }

    async fn append_async(
        &self,
        payload: NotifyWalPayload,
    ) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.submit_async(NotifyWalAppendRequest {
            payload,
            reply: NotifyWalAppendReply::Async(reply),
        })
        .await?;
        response.await.map_err(|source| {
            NodeCoreError::ItestJson(format!("notify WAL append response closed: {source}"))
        })?
    }

    fn submit(&self, request: NotifyWalAppendRequest) -> Result<(), NodeCoreError> {
        self.sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("notify WAL writer stopped".to_owned()))?
            .send(NotifyWalWriterRequest::Append(Box::new(request)))
            .map_err(|source| {
                NodeCoreError::ItestJson(format!("notify WAL writer stopped: {source}"))
            })
    }

    fn submit_batch(&self, request: NotifyWalAppendBatchRequest) -> Result<(), NodeCoreError> {
        self.sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("notify WAL writer stopped".to_owned()))?
            .send(NotifyWalWriterRequest::AppendBatch(Box::new(request)))
            .map_err(|source| {
                NodeCoreError::ItestJson(format!("notify WAL writer stopped: {source}"))
            })
    }

    async fn submit_async(&self, mut request: NotifyWalAppendRequest) -> Result<(), NodeCoreError> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("notify WAL writer stopped".to_owned()))?;
        loop {
            match sender.try_send(NotifyWalWriterRequest::Append(Box::new(request))) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(NotifyWalWriterRequest::Append(returned))) => {
                    request = *returned;
                    tokio::task::yield_now().await;
                }
                Err(mpsc::TrySendError::Full(NotifyWalWriterRequest::Compact(_))) => {
                    return Err(NodeCoreError::ItestJson(
                        "notify WAL compact request returned while submitting append".to_owned(),
                    ));
                }
                Err(mpsc::TrySendError::Full(NotifyWalWriterRequest::AppendBatch(_))) => {
                    return Err(NodeCoreError::ItestJson(
                        "notify WAL batch append request returned while submitting append"
                            .to_owned(),
                    ));
                }
                Err(mpsc::TrySendError::Disconnected(_returned)) => {
                    return Err(NodeCoreError::ItestJson("notify WAL writer stopped".to_owned()));
                }
            }
        }
    }

    fn compact(&self) -> Result<(), NodeCoreError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("notify WAL writer stopped".to_owned()))?
            .send(NotifyWalWriterRequest::Compact(NotifyWalCompactRequest { reply }))
            .map_err(|source| {
                NodeCoreError::ItestJson(format!("notify WAL writer stopped: {source}"))
            })?;
        response.recv().map_err(|source| {
            NodeCoreError::ItestJson(format!("notify WAL compact response closed: {source}"))
        })?
    }
}

impl Drop for NotifyWalWriter {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

struct NotifyWalWriterState {
    root: PathBuf,
    segment_bytes: u64,
    segment_id: u64,
    offset: u64,
    file: File,
}

impl NotifyWalWriterState {
    fn open(
        root: PathBuf,
        segment_id: u64,
        offset: u64,
        segment_bytes: u64,
    ) -> Result<Self, NodeCoreError> {
        let path = notify_wal_segment_path(&root, segment_id);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        if offset == 0 && file.metadata().map_or(0, |metadata| metadata.len()) == 0 {
            file.write_all(NOTIFY_WAL_MAGIC)
                .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
            file.sync_all().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        }
        let offset = file
            .seek(io::SeekFrom::End(0))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        Ok(Self { root, segment_bytes, segment_id, offset, file })
    }

    fn append_batch(
        &mut self,
        payloads: &[NotifyWalPayload],
    ) -> Result<Vec<NotifyWalRecordLocation>, NodeCoreError> {
        let mut locations = Vec::with_capacity(payloads.len());
        for payload in payloads {
            let stored = StoredNotifyWalPayload::try_from(payload)?;
            let encoded = postcard::to_allocvec(&stored)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
            let frame_len = 8_u64
                .checked_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| NodeCoreError::ItestJson("notify WAL frame too large".to_owned()))?;
            if self.offset > u64::try_from(NOTIFY_WAL_MAGIC.len()).unwrap_or(0)
                && self.offset.saturating_add(frame_len) > self.segment_bytes
            {
                self.file
                    .sync_all()
                    .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
                self.roll_segment()?;
            }
            let location = self.write_record(&encoded)?;
            locations.push(location);
        }
        self.file.sync_all().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        Ok(locations)
    }

    fn write_record(&mut self, encoded: &[u8]) -> Result<NotifyWalRecordLocation, NodeCoreError> {
        let len = u32::try_from(encoded.len())
            .map_err(|_| NodeCoreError::ItestJson("notify WAL record too large".to_owned()))?;
        let offset = self.offset;
        write_notify_wal_record_to_file(&mut self.file, encoded)?;
        self.offset = self.offset.saturating_add(8 + u64::from(len));
        Ok(NotifyWalRecordLocation { segment_id: self.segment_id, offset, len })
    }

    fn roll_segment(&mut self) -> Result<(), NodeCoreError> {
        self.segment_id = self.segment_id.saturating_add(1);
        let path = notify_wal_segment_path(&self.root, self.segment_id);
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        self.file
            .write_all(NOTIFY_WAL_MAGIC)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        self.offset = u64::try_from(NOTIFY_WAL_MAGIC.len()).unwrap_or(0);
        Ok(())
    }

    fn compact(&mut self, payloads: &[NotifyWalPayload]) -> Result<(), NodeCoreError> {
        self.file.sync_all().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let mut old_segments = notify_wal_segment_ids(&self.root)?;
        old_segments.sort_unstable();
        let new_segment_id =
            old_segments.iter().copied().max().unwrap_or(self.segment_id).saturating_add(1);
        let tmp_path = notify_wal_compaction_tmp_path(&self.root, new_segment_id);
        let final_path = notify_wal_segment_path(&self.root, new_segment_id);
        let _removed = fs::remove_file(&tmp_path);
        let _removed = fs::remove_file(&final_path);

        let mut compacted = OpenOptions::new()
            .create_new(true)
            .append(true)
            .read(true)
            .open(&tmp_path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        compacted
            .write_all(NOTIFY_WAL_MAGIC)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let mut offset = u64::try_from(NOTIFY_WAL_MAGIC.len()).unwrap_or(0);
        for payload in payloads {
            let stored = StoredNotifyWalPayload::try_from(payload)?;
            let encoded = postcard::to_allocvec(&stored)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
            write_notify_wal_record_to_file(&mut compacted, &encoded)?;
            offset = offset.saturating_add(8 + u64::try_from(encoded.len()).unwrap_or(u64::MAX));
        }
        compacted.sync_all().map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        drop(compacted);
        fs::rename(&tmp_path, &final_path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        sync_notify_wal_directory(&self.root)?;

        for segment_id in old_segments {
            if segment_id < new_segment_id {
                let _removed = fs::remove_file(notify_wal_segment_path(&self.root, segment_id));
            }
        }
        sync_notify_wal_directory(&self.root)?;

        self.segment_id = new_segment_id;
        self.file = OpenOptions::new()
            .append(true)
            .read(true)
            .open(&final_path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        self.offset = self
            .file
            .seek(io::SeekFrom::End(0))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        if self.offset != offset {
            return Err(NodeCoreError::ItestJson(format!(
                "notify WAL compaction offset mismatch: expected {offset}, got {}",
                self.offset
            )));
        }
        Ok(())
    }
}

fn notify_wal_writer_loop(
    mut state: NotifyWalWriterState,
    receiver: &mpsc::Receiver<NotifyWalWriterRequest>,
    wal_state: &Arc<Mutex<NotifyWalState>>,
    batch_max: usize,
    window: Duration,
    compaction: NotifyWalCompactionPolicy,
) {
    let mut last_compaction = Instant::now();
    while let Ok(first) = receiver.recv() {
        let NotifyWalWriterRequest::Append(first) = first else {
            match first {
                NotifyWalWriterRequest::AppendBatch(request) => {
                    notify_wal_ack_batch_request(*request, &mut state, wal_state);
                }
                NotifyWalWriterRequest::Compact(request) => {
                    let _sent = request.reply.send(notify_wal_compact(&mut state, wal_state));
                    last_compaction = Instant::now();
                }
                NotifyWalWriterRequest::Append(_) => {}
            }
            continue;
        };
        let mut batch = Vec::with_capacity(batch_max);
        let mut batch_requests = Vec::new();
        let mut compact_requests = Vec::new();
        batch.push(*first);
        let deadline = Instant::now() + window;
        while batch.len() < batch_max {
            match receiver.try_recv() {
                Ok(NotifyWalWriterRequest::Append(request)) => batch.push(*request),
                Ok(NotifyWalWriterRequest::AppendBatch(request)) => batch_requests.push(*request),
                Ok(NotifyWalWriterRequest::Compact(request)) => compact_requests.push(request),
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    match receiver.recv_timeout(deadline.saturating_duration_since(now)) {
                        Ok(NotifyWalWriterRequest::Append(request)) => batch.push(*request),
                        Ok(NotifyWalWriterRequest::AppendBatch(request)) => {
                            batch_requests.push(*request);
                        }
                        Ok(NotifyWalWriterRequest::Compact(request)) => {
                            compact_requests.push(request);
                        }
                        Err(
                            mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected,
                        ) => {
                            break;
                        }
                    }
                }
            }
        }
        let payloads = batch.iter().map(|request| request.payload.clone()).collect::<Vec<_>>();
        match state.append_batch(&payloads) {
            Ok(locations) => notify_wal_ack_success(batch, &payloads, locations, wal_state),
            Err(error) => notify_wal_ack_error(batch, &error),
        }
        for request in batch_requests {
            notify_wal_ack_batch_request(request, &mut state, wal_state);
        }
        for request in compact_requests {
            let _sent = request.reply.send(notify_wal_compact(&mut state, wal_state));
            last_compaction = Instant::now();
        }
        if notify_wal_should_compact(&state, last_compaction, compaction) {
            if let Err(error) = notify_wal_compact(&mut state, wal_state) {
                eprintln!("notify WAL background compaction failed: {error}");
            } else {
                last_compaction = Instant::now();
            }
        }
    }
}

fn notify_wal_ack_batch_request(
    request: NotifyWalAppendBatchRequest,
    state: &mut NotifyWalWriterState,
    wal_state: &Arc<Mutex<NotifyWalState>>,
) {
    match state.append_batch(&request.payloads) {
        Ok(locations) => {
            let update_result =
                wal_state.lock().map_err(|source| source.to_string()).map(|mut guard| {
                    for (payload, location) in
                        request.payloads.iter().cloned().zip(locations.iter().cloned())
                    {
                        guard.apply(payload, location);
                    }
                });
            match update_result {
                Ok(()) => request.reply.send(Ok(locations)),
                Err(error) => request.reply.send(Err(NodeCoreError::ItestJson(format!(
                    "notify WAL index lock poisoned: {error}"
                )))),
            }
        }
        Err(error) => request.reply.send(Err(NodeCoreError::ItestJson(error.to_string()))),
    }
}

fn notify_wal_should_compact(
    state: &NotifyWalWriterState,
    last_compaction: Instant,
    compaction: NotifyWalCompactionPolicy,
) -> bool {
    if compaction.interval.as_secs() > 0 && last_compaction.elapsed() >= compaction.interval {
        return true;
    }
    notify_wal_segment_ids(&state.root)
        .is_ok_and(|segments| segments.len() > compaction.max_segments)
}

fn notify_wal_compact(
    state: &mut NotifyWalWriterState,
    wal_state: &Arc<Mutex<NotifyWalState>>,
) -> Result<(), NodeCoreError> {
    let payloads = wal_state
        .lock()
        .map_err(|source| {
            NodeCoreError::ItestJson(format!("notify WAL index lock poisoned: {source}"))
        })?
        .compacted_payloads();
    state.compact(&payloads)
}

fn notify_wal_ack_success(
    batch: Vec<NotifyWalAppendRequest>,
    payloads: &[NotifyWalPayload],
    locations: Vec<NotifyWalRecordLocation>,
    wal_state: &Arc<Mutex<NotifyWalState>>,
) {
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
                    "notify WAL index lock poisoned: {error}"
                ))));
            }
        }
    }
}

fn notify_wal_ack_error(batch: Vec<NotifyWalAppendRequest>, error: &NodeCoreError) {
    let message = error.to_string();
    for request in batch {
        request.reply.send(Err(NodeCoreError::ItestJson(message.clone())));
    }
}

struct NotifyWalRecovery {
    state: NotifyWalState,
    last_segment_id: Option<u64>,
    current_offset: u64,
}

fn recover_notify_wal(root: &Path) -> Result<NotifyWalRecovery, NodeCoreError> {
    let mut state = NotifyWalState::default();
    let mut segments = notify_wal_segment_ids(root)?;
    if segments.is_empty() {
        return Ok(NotifyWalRecovery { state, last_segment_id: None, current_offset: 0 });
    }
    segments.sort_unstable();
    let mut current_offset = 0_u64;
    let mut last_segment_id = None;
    for segment_id in segments {
        let offset = recover_notify_wal_segment(root, segment_id, &mut state)?;
        current_offset = offset;
        last_segment_id = Some(segment_id);
    }
    Ok(NotifyWalRecovery { state, last_segment_id, current_offset })
}

fn recover_notify_wal_segment(
    root: &Path,
    segment_id: u64,
    state: &mut NotifyWalState,
) -> Result<u64, NodeCoreError> {
    let path = notify_wal_segment_path(root, segment_id);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    let mut offset = read_notify_wal_magic(&mut file)?;
    loop {
        let record_offset = offset;
        let Some((payload, len)) = read_notify_wal_record(&mut file)? else {
            break;
        };
        offset = offset.saturating_add(8 + u64::from(len));
        let location = NotifyWalRecordLocation { segment_id, offset: record_offset, len };
        state.apply(payload, location);
    }
    file.set_len(offset).map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(offset)
}

fn read_notify_wal_magic(file: &mut File) -> Result<u64, NodeCoreError> {
    let mut magic = vec![0_u8; NOTIFY_WAL_MAGIC.len()];
    let bytes =
        file.read(&mut magic).map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    if bytes == 0 {
        file.write_all(NOTIFY_WAL_MAGIC)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        return Ok(u64::try_from(NOTIFY_WAL_MAGIC.len()).unwrap_or(0));
    }
    if bytes != NOTIFY_WAL_MAGIC.len() || magic != NOTIFY_WAL_MAGIC {
        return Err(NodeCoreError::ItestJson("invalid notify WAL segment magic".to_owned()));
    }
    Ok(u64::try_from(NOTIFY_WAL_MAGIC.len()).unwrap_or(0))
}

fn read_notify_wal_record(
    file: &mut File,
) -> Result<Option<(NotifyWalPayload, u32)>, NodeCoreError> {
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
    let payload = postcard::from_bytes::<StoredNotifyWalPayload>(&payload)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    let payload = payload.try_into()?;
    Ok(Some((payload, len)))
}

fn notify_wal_segment_ids(root: &Path) -> Result<Vec<u64>, NodeCoreError> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|source| NodeCoreError::StoreDirectory { path: root.to_path_buf(), source })?
    {
        let entry = entry.map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(id) = notify_wal_segment_id_from_name(&name) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn notify_wal_segment_id_from_name(name: &str) -> Option<u64> {
    name.strip_prefix("notify-wal-")
        .and_then(|value| value.strip_suffix(".wal"))
        .and_then(|value| value.parse().ok())
}

fn notify_wal_segment_path(root: &Path, segment_id: u64) -> PathBuf {
    root.join(format!("notify-wal-{segment_id:020}.wal"))
}

fn notify_wal_compaction_tmp_path(root: &Path, segment_id: u64) -> PathBuf {
    root.join(format!("notify-wal-{segment_id:020}.wal.tmp"))
}

fn write_notify_wal_record_to_file(file: &mut File, encoded: &[u8]) -> Result<(), NodeCoreError> {
    let len = u32::try_from(encoded.len())
        .map_err(|_| NodeCoreError::ItestJson("notify WAL record too large".to_owned()))?;
    let crc = crc32fast::hash(encoded);
    file.write_all(&len.to_le_bytes())
        .and_then(|()| file.write_all(&crc.to_le_bytes()))
        .and_then(|()| file.write_all(encoded))
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

fn sync_notify_wal_directory(root: &Path) -> Result<(), NodeCoreError> {
    let directory =
        File::open(root).map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    directory.sync_all().map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

fn notify_wal_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn notify_wal_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NotifyDeliveryAction, NotifyQueueStatus, PushProviderKind};
    use ramflux_protocol::{
        Ext, NotificationDeliveryClass, PushPriority, SignatureAlg, SignedFields,
    };
    use std::sync::Barrier;

    #[test]
    fn notify_wal_recovers_appended_queue_entries() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_notify_wal_dir("notify_wal_recovers_appended_queue_entries")?;
        let store = NotifyWalStore::open(&root)?;
        let entry = notify_wal_queue_entry("wal_recover_1");
        let location = store.append(NotifyWalPayload::QueueEntry(entry.clone()))?;
        assert_eq!(location.segment_id, 0);
        drop(store);

        let reopened = NotifyWalStore::open(&root)?;
        let recovered = reopened.get("queue:wal_recover_1").ok_or("missing recovered WAL entry")?;
        assert_eq!(recovered.payload.record_id(), "queue:wal_recover_1");
        assert_eq!(reopened.len(), 1);
        remove_notify_wal_dir(root);
        Ok(())
    }

    #[test]
    fn notify_wal_replays_attempts_and_delivered_tombstones()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_notify_wal_dir("notify_wal_replays_attempts_and_delivered_tombstones")?;
        let store = NotifyWalStore::open(&root)?;
        let entry = notify_wal_queue_entry("wal_delivered_1");
        store.append(NotifyWalPayload::QueueEntry(entry))?;
        store.record_provider_attempt(notify_wal_attempt("wal_delivered_1"))?;
        store.mark_delivered("wal_delivered_1")?;
        assert!(store.pending_entries_without_attempts(10).is_empty());
        drop(store);

        let reopened = NotifyWalStore::open(&root)?;
        assert!(reopened.get("queue:wal_delivered_1").is_none());
        assert!(reopened.pending_entries_without_attempts(10).is_empty());
        assert_eq!(reopened.provider_attempts("wal_delivered_1").len(), 1);

        remove_notify_wal_dir(root);
        Ok(())
    }

    #[test]
    fn notify_wal_truncates_bad_tail_on_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_notify_wal_dir("notify_wal_truncates_bad_tail_on_recovery")?;
        let store = NotifyWalStore::open(&root)?;
        store.append(NotifyWalPayload::QueueEntry(notify_wal_queue_entry("wal_tail_1")))?;
        drop(store);

        let segment = notify_wal_segment_path(&root, 0);
        let mut file = OpenOptions::new().append(true).open(&segment)?;
        file.write_all(&32_u32.to_le_bytes())?;
        file.write_all(&123_u32.to_le_bytes())?;
        file.write_all(b"partial")?;
        drop(file);
        let len_with_tail = fs::metadata(&segment)?.len();

        let reopened = NotifyWalStore::open(&root)?;
        assert!(reopened.get("queue:wal_tail_1").is_some());
        let len_after_recovery = fs::metadata(&segment)?.len();
        assert!(len_after_recovery < len_with_tail);
        remove_notify_wal_dir(root);
        Ok(())
    }

    #[test]
    fn notify_wal_compaction_rewrites_active_state_and_reclaims_segments()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_notify_wal_dir(
            "notify_wal_compaction_rewrites_active_state_and_reclaims_segments",
        )?;
        let store = NotifyWalStore::open(&root)?;
        store.append(NotifyWalPayload::QueueEntry(notify_wal_queue_entry("wal_compact_keep")))?;
        store.append(NotifyWalPayload::QueueEntry(notify_wal_queue_entry("wal_compact_drop")))?;
        store.record_provider_attempt(notify_wal_attempt("wal_compact_drop"))?;
        store.mark_delivered("wal_compact_drop")?;
        assert!(!notify_wal_segment_ids(&root)?.is_empty());

        store.compact()?;
        let segments_after_compaction = notify_wal_segment_ids(&root)?;
        assert_eq!(segments_after_compaction.len(), 1);
        drop(store);

        let reopened = NotifyWalStore::open(&root)?;
        assert!(reopened.get("queue:wal_compact_keep").is_some());
        assert!(reopened.get("queue:wal_compact_drop").is_none());
        assert_eq!(reopened.provider_attempts("wal_compact_drop").len(), 1);
        assert_eq!(reopened.pending_entries_without_attempts(10).len(), 1);
        remove_notify_wal_dir(root);
        Ok(())
    }

    #[test]
    fn notify_wal_recovery_keeps_acked_records_and_ignores_corrupt_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_notify_wal_dir(
            "notify_wal_recovery_keeps_acked_records_and_ignores_corrupt_tail",
        )?;
        let store = NotifyWalStore::open(&root)?;
        store.append(NotifyWalPayload::QueueEntry(notify_wal_queue_entry("wal_crash_keep_1")))?;
        store.append(NotifyWalPayload::QueueEntry(notify_wal_queue_entry("wal_crash_keep_2")))?;
        store.record_provider_attempt(notify_wal_attempt("wal_crash_keep_2"))?;
        store.mark_delivered("wal_crash_keep_2")?;
        drop(store);

        let segment = notify_wal_segment_path(&root, 0);
        let mut file = OpenOptions::new().append(true).open(&segment)?;
        let corrupt_payload = postcard::to_allocvec(&StoredNotifyWalPayload::Delivered {
            queue_id: "wal_crash_keep_1".to_owned(),
        })?;
        file.write_all(&u32::try_from(corrupt_payload.len())?.to_le_bytes())?;
        file.write_all(&0_u32.to_le_bytes())?;
        file.write_all(&corrupt_payload)?;
        drop(file);

        let reopened = NotifyWalStore::open(&root)?;
        assert!(reopened.get("queue:wal_crash_keep_1").is_some());
        assert!(reopened.get("queue:wal_crash_keep_2").is_none());
        assert_eq!(reopened.pending_entries_without_attempts(10).len(), 1);
        assert_eq!(reopened.provider_attempts("wal_crash_keep_2").len(), 1);
        remove_notify_wal_dir(root);
        Ok(())
    }

    #[test]
    #[ignore = "set RAMFLUX_NOTIFY_BENCH=1 to run the notify WAL throughput bench"]
    fn notify_wal_throughput_bench() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var("RAMFLUX_NOTIFY_BENCH").as_deref() != Ok("1") {
            eprintln!("WAL_BENCH skipped set RAMFLUX_NOTIFY_BENCH=1 to run");
            return Ok(());
        }
        let thread_count = notify_wal_bench_env_usize("RAMFLUX_NOTIFY_BENCH_THREADS", 64).max(1);
        let total_ops = notify_wal_bench_env_usize("RAMFLUX_NOTIFY_BENCH_TOTAL", 200_000).max(1);
        let root = temp_notify_wal_dir("notify_wal_throughput_bench")?;
        let store = Arc::new(NotifyWalStore::open(&root)?);
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
                    let entry = notify_wal_queue_entry(&format!("wal_bench_{op_index}"));
                    worker_store.append(NotifyWalPayload::QueueEntry(entry))?;
                }
                Ok(end_op.saturating_sub(first_op))
            }));
        }
        let begun_at = Instant::now();
        started.wait();
        let mut completed_ops = 0usize;
        for worker in workers {
            let worker_result =
                worker.join().map_err(|_| io::Error::other("notify WAL bench worker panicked"))?;
            completed_ops += worker_result?;
        }
        let elapsed = begun_at.elapsed();
        let completed_ops_f64 = f64::from(u32::try_from(completed_ops).unwrap_or(u32::MAX));
        let ops_per_sec = completed_ops_f64 / elapsed.as_secs_f64();
        eprintln!(
            "WAL_BENCH ops_per_sec={ops_per_sec:.2} total_ops={completed_ops} threads={thread_count} elapsed_ms={:.2}",
            elapsed.as_secs_f64() * 1000.0
        );
        remove_notify_wal_dir(root);
        Ok(())
    }

    fn notify_wal_queue_entry(queue_id: &str) -> NotifyQueueEntry {
        NotifyQueueEntry {
            queue_id: queue_id.to_owned(),
            device_delivery_id: "device_notify_wal".to_owned(),
            wake: notify_wal_wake(queue_id),
            push_alias_hash: "push_alias_hash".to_owned(),
            queued_at: 1_760_000_000,
            expires_at: 1_760_000_300,
            attempt_count: 0,
            status: NotifyQueueStatus::Pending,
            dnd_active: false,
        }
    }

    fn notify_wal_wake(wake_id: &str) -> ramflux_protocol::NotificationWake {
        ramflux_protocol::NotificationWake {
            schema: "ramflux.notification_wake.v1".to_owned(),
            version: 1,
            domain: "ramflux.notification_wake.v1".to_owned(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "notify_wal_test".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".to_owned(),
            },
            wake_id: wake_id.to_owned(),
            push_alias: "push_alias_raw_notify_only".to_owned(),
            delivery_class: NotificationDeliveryClass::SelfDeviceControlNotification,
            priority: PushPriority::Normal,
            ttl: 300,
            collapse_key: Some("collapse_self_device".to_owned()),
            encrypted_hint: Some("encrypted_hint".to_owned()),
        }
    }

    #[allow(dead_code)]
    fn notify_wal_attempt(queue_id: &str) -> ProviderPushAttempt {
        ProviderPushAttempt {
            queue_id: queue_id.to_owned(),
            device_delivery_id: "device_notify_wal".to_owned(),
            provider: PushProviderKind::WebPush,
            push_alias_hash: "push_alias_hash".to_owned(),
            collapse_key_hash: "collapse_key_hash".to_owned(),
            delivery_class: NotificationDeliveryClass::SelfDeviceControlNotification,
            action: NotifyDeliveryAction::Accept,
            sent_at: 1_760_000_001,
            accepted: true,
            error_class: None,
        }
    }

    fn temp_notify_wal_dir(test_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let path = std::env::temp_dir().join(format!(
            "ramflux-node-core-{test_name}-{}-{}",
            std::process::id(),
            elapsed.as_nanos()
        ));
        Ok(path)
    }

    fn remove_notify_wal_dir(path: PathBuf) {
        let _removed = fs::remove_dir_all(path);
    }

    fn notify_wal_bench_env_usize(name: &str, default: usize) -> usize {
        std::env::var(name).ok().and_then(|value| value.parse::<usize>().ok()).unwrap_or(default)
    }
}
