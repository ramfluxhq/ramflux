#![allow(unused_imports)]

use crate::{
    NOTIFY_CREDENTIAL_TABLE, NOTIFY_PROVIDER_ATTEMPT_TABLE, NOTIFY_QUEUE_ENTRY_TABLE,
    NOTIFY_QUEUE_KEY, NOTIFY_QUEUE_TABLE, NOTIFY_ROUTE_TABLE, NodeCoreError, NotifyWalPayload,
    NotifyWalPendingCounts, NotifyWalPendingWake, NotifyWalRawWake, NotifyWalRecoveredCounts,
    NotifyWalStore, now_unix_seconds,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const NOTIFY_RATE_ALIAS_PER_MINUTE: usize = 60;
pub const NOTIFY_RATE_ALIAS_PER_HOUR: usize = 600;
pub const NOTIFY_RATE_PROVIDER_PER_MINUTE: usize = 3_000;
pub const NOTIFY_MAX_PENDING_COLLAPSE_GROUPS_PER_DEVICE: usize = 10;
const NOTIFY_COMMIT_BATCH_MAX_ENV: &str = "RAMFLUX_NOTIFY_COMMIT_BATCH_MAX";
const NOTIFY_COMMIT_WINDOW_US_ENV: &str = "RAMFLUX_NOTIFY_COMMIT_WINDOW_US";
const NOTIFY_COMMIT_QUEUE_CAPACITY_ENV: &str = "RAMFLUX_NOTIFY_COMMIT_QUEUE_CAPACITY";
const NOTIFY_WAL_ENABLED_ENV: &str = "RAMFLUX_NOTIFY_WAL";
const NOTIFY_WAL_DIR_ENV: &str = "RAMFLUX_NOTIFY_WAL_DIR";
const NOTIFY_INGEST_SHARDS_ENV: &str = "RAMFLUX_NOTIFY_INGEST_SHARDS";
const NOTIFY_COMMIT_BATCH_MAX_DEFAULT: usize = 256;
const NOTIFY_COMMIT_WINDOW_US_DEFAULT: u64 = 1_000;
const NOTIFY_COMMIT_QUEUE_CAPACITY_DEFAULT: usize = 8_192;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NotifyQueueStatus {
    Pending,
    Delivered,
    DroppedExpired,
    ProviderRejected,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushProviderKind {
    Apns,
    Fcm,
    #[serde(rename = "webpush")]
    WebPush,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum ProviderCredential {
    Apns(ApnsProviderCredential),
    Fcm(FcmProviderCredential),
    #[serde(rename = "webpush")]
    WebPush(WebPushProviderCredential),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApnsProviderCredential {
    pub credential_id: String,
    pub team_id: String,
    pub key_id: String,
    pub p8_key_ref: String,
    pub topic: String,
    pub sandbox: bool,
    #[serde(default)]
    pub provider_ca_pem_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FcmProviderCredential {
    pub credential_id: String,
    pub project_id: String,
    pub service_account_json_ref: String,
    #[serde(default = "default_fcm_oauth_scope")]
    pub oauth_scope: String,
    #[serde(default)]
    pub oauth_token_url: Option<String>,
    #[serde(default)]
    pub provider_ca_pem_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WebPushProviderCredential {
    pub credential_id: String,
    pub vapid_public_key_ref: String,
    pub vapid_private_key_ref: String,
    pub subject: String,
    #[serde(default)]
    pub provider_ca_pem_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevicePushRoute {
    pub device_delivery_id: String,
    pub provider: PushProviderKind,
    #[serde(default)]
    pub credential_id: Option<String>,
    pub token: String,
    pub endpoint: String,
    #[serde(default)]
    pub webpush_p256dh: Option<String>,
    #[serde(default)]
    pub webpush_auth: Option<String>,
    pub registered_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPushPayload {
    pub wake_id: String,
    pub provider: PushProviderKind,
    pub delivery_class: ramflux_protocol::NotificationDeliveryClass,
    pub priority: ramflux_protocol::PushPriority,
    pub ttl: u32,
    pub collapse_key: Option<String>,
    pub encrypted_hint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPushAttempt {
    pub queue_id: String,
    pub device_delivery_id: String,
    pub provider: PushProviderKind,
    pub push_alias_hash: String,
    pub collapse_key_hash: String,
    pub delivery_class: ramflux_protocol::NotificationDeliveryClass,
    pub action: NotifyDeliveryAction,
    pub sent_at: u64,
    pub accepted: bool,
    #[serde(default)]
    pub error_class: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyDeliveryAction {
    Accept,
    Collapse,
    DeferWithRetryAfter,
    DropExpired,
    DropLowPriorityDueToDnd,
    NackRateLimited,
    ProviderRejected,
    StaleToken,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedProviderPush {
    pub route: DevicePushRoute,
    pub credential: ProviderCredential,
    pub payload: ProviderPushPayload,
    pub push_alias_hash: String,
    pub collapse_key_hash: String,
    pub action: NotifyDeliveryAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotifyQueueEntry {
    pub queue_id: String,
    #[serde(default)]
    pub device_delivery_id: String,
    pub wake: ramflux_protocol::NotificationWake,
    pub push_alias_hash: String,
    pub queued_at: u64,
    pub expires_at: u64,
    pub attempt_count: u32,
    pub status: NotifyQueueStatus,
    #[serde(default)]
    pub dnd_active: bool,
}

#[derive(Deserialize)]
struct RawS13WakeRequest {
    device_delivery_id: String,
    wake: ramflux_protocol::NotificationWake,
    #[serde(default)]
    dnd_active: Option<bool>,
}

#[derive(Deserialize, Serialize)]
struct StoredNotifyQueueEntry {
    queue_id: String,
    device_delivery_id: String,
    wake: StoredNotificationWake,
    push_alias_hash: String,
    queued_at: u64,
    expires_at: u64,
    attempt_count: u32,
    status: NotifyQueueStatus,
    dnd_active: bool,
}

#[derive(Serialize)]
struct StoredNotifyQueueEntryRef<'a> {
    queue_id: &'a str,
    device_delivery_id: &'a str,
    wake: StoredNotificationWakeRef<'a>,
    push_alias_hash: &'a str,
    queued_at: u64,
    expires_at: u64,
    attempt_count: u32,
    status: &'a NotifyQueueStatus,
    dnd_active: bool,
}

#[derive(Deserialize, Serialize)]
struct StoredNotificationWake {
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

#[derive(Serialize)]
struct StoredNotificationWakeRef<'a> {
    schema: &'a str,
    version: u32,
    domain: &'a str,
    ext_json: Option<Vec<u8>>,
    signed: &'a ramflux_protocol::SignedFields,
    wake_id: &'a str,
    push_alias: &'a str,
    delivery_class: &'a ramflux_protocol::NotificationDeliveryClass,
    priority: &'a ramflux_protocol::PushPriority,
    ttl: u32,
    collapse_key: Option<&'a String>,
    encrypted_hint: Option<&'a String>,
}

impl<'a> TryFrom<&'a NotifyQueueEntry> for StoredNotifyQueueEntryRef<'a> {
    type Error = NodeCoreError;

    fn try_from(entry: &'a NotifyQueueEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            queue_id: &entry.queue_id,
            device_delivery_id: &entry.device_delivery_id,
            wake: StoredNotificationWakeRef::try_from(&entry.wake)?,
            push_alias_hash: &entry.push_alias_hash,
            queued_at: entry.queued_at,
            expires_at: entry.expires_at,
            attempt_count: entry.attempt_count,
            status: &entry.status,
            dnd_active: entry.dnd_active,
        })
    }
}

impl TryFrom<StoredNotifyQueueEntry> for NotifyQueueEntry {
    type Error = NodeCoreError;

    fn try_from(entry: StoredNotifyQueueEntry) -> Result<Self, Self::Error> {
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

impl<'a> TryFrom<&'a ramflux_protocol::NotificationWake> for StoredNotificationWakeRef<'a> {
    type Error = NodeCoreError;

    fn try_from(wake: &'a ramflux_protocol::NotificationWake) -> Result<Self, Self::Error> {
        let ext_json = if wake.ext.ext.is_empty() {
            None
        } else {
            Some(
                serde_json::to_vec(&wake.ext.ext)
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?,
            )
        };
        Ok(Self {
            schema: &wake.schema,
            version: wake.version,
            domain: &wake.domain,
            ext_json,
            signed: &wake.signed,
            wake_id: &wake.wake_id,
            push_alias: &wake.push_alias,
            delivery_class: &wake.delivery_class,
            priority: &wake.priority,
            ttl: wake.ttl,
            collapse_key: wake.collapse_key.as_ref(),
            encrypted_hint: wake.encrypted_hint.as_ref(),
        })
    }
}

impl TryFrom<StoredNotificationWake> for ramflux_protocol::NotificationWake {
    type Error = NodeCoreError;

    fn try_from(wake: StoredNotificationWake) -> Result<Self, Self::Error> {
        let ext = match wake.ext_json {
            Some(bytes) => serde_json::from_slice::<BTreeMap<String, serde_json::Value>>(&bytes)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?,
            None => BTreeMap::new(),
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotifyQueueState {
    entries_by_id: BTreeMap<String, NotifyQueueEntry>,
    #[serde(default)]
    routes_by_device: BTreeMap<String, Vec<DevicePushRoute>>,
    #[serde(default)]
    credentials_by_id: BTreeMap<String, ProviderCredential>,
    #[serde(default)]
    provider_attempts_by_queue: BTreeMap<String, Vec<ProviderPushAttempt>>,
    #[serde(default)]
    rate_events_by_alias: BTreeMap<String, Vec<u64>>,
    #[serde(default)]
    rate_events_by_provider: BTreeMap<PushProviderKind, Vec<u64>>,
    #[serde(default)]
    deferred_by_device: BTreeMap<String, Vec<String>>,
}

impl NotifyQueueState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn queue_wake(
        &mut self,
        wake: ramflux_protocol::NotificationWake,
        push_alias_hash: impl Into<String>,
        queued_at: u64,
    ) -> NotifyQueueEntry {
        self.queue_wake_for_device("", wake, push_alias_hash, queued_at, false)
    }

    pub fn queue_wake_for_device(
        &mut self,
        device_delivery_id: impl Into<String>,
        wake: ramflux_protocol::NotificationWake,
        push_alias_hash: impl Into<String>,
        queued_at: u64,
        dnd_active: bool,
    ) -> NotifyQueueEntry {
        let expires_at = queued_at.saturating_add(u64::from(wake.ttl));
        let entry = NotifyQueueEntry {
            queue_id: wake.wake_id.clone(),
            device_delivery_id: device_delivery_id.into(),
            wake,
            push_alias_hash: push_alias_hash.into(),
            queued_at,
            expires_at,
            attempt_count: 0,
            status: NotifyQueueStatus::Pending,
            dnd_active,
        };
        self.entries_by_id.insert(entry.queue_id.clone(), entry.clone());
        entry
    }

    pub fn register_push_route(&mut self, route: DevicePushRoute) {
        let routes = self.routes_by_device.entry(route.device_delivery_id.clone()).or_default();
        routes.retain(|existing| {
            existing.provider != route.provider || existing.token != route.token
        });
        routes.push(route);
    }

    pub fn update_provider_credential(&mut self, credential: ProviderCredential) {
        self.credentials_by_id.insert(credential.credential_id().to_owned(), credential);
    }

    #[must_use]
    pub fn provider_credential(&self, credential_id: &str) -> Option<&ProviderCredential> {
        self.credentials_by_id.get(credential_id)
    }

    #[must_use]
    pub fn push_routes(&self, device_delivery_id: &str, now: u64) -> Vec<DevicePushRoute> {
        self.routes_by_device
            .get(device_delivery_id)
            .into_iter()
            .flat_map(|routes| routes.iter())
            .filter(|route| route.expires_at > now)
            .cloned()
            .collect()
    }

    pub fn record_provider_attempt(&mut self, attempt: ProviderPushAttempt) {
        self.provider_attempts_by_queue.entry(attempt.queue_id.clone()).or_default().push(attempt);
    }

    #[must_use]
    pub fn provider_attempts(&self, queue_id: &str) -> &[ProviderPushAttempt] {
        self.provider_attempts_by_queue.get(queue_id).map_or(&[], Vec::as_slice)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mark_delivered(&mut self, queue_id: &str) -> Result<(), NodeCoreError> {
        let entry = self
            .entries_by_id
            .get_mut(queue_id)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(queue_id.to_owned()))?;
        entry.status = NotifyQueueStatus::Delivered;
        entry.attempt_count = entry.attempt_count.saturating_add(1);
        Ok(())
    }

    pub fn drop_expired(&mut self, now: u64) -> usize {
        let mut expired_count = 0;
        for entry in self.entries_by_id.values_mut() {
            if entry.status == NotifyQueueStatus::Pending && entry.expires_at <= now {
                entry.status = NotifyQueueStatus::DroppedExpired;
                expired_count += 1;
            }
        }
        expired_count
    }

    #[must_use]
    pub fn entry(&self, queue_id: &str) -> Option<&NotifyQueueEntry> {
        self.entries_by_id.get(queue_id)
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.entries_by_id
            .values()
            .filter(|entry| entry.status == NotifyQueueStatus::Pending)
            .count()
    }
}

pub struct NotifyRedbStore {
    db: std::sync::Arc<redb::Database>,
    commit_writer: NotifyCommitWriter,
    runtime_state: Mutex<NotifyRuntimeState>,
    wal_shards: Option<Vec<NotifyWalShard>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NotifyWalShardRecoveredCounts {
    pub shard_id: usize,
    pub counts: NotifyWalRecoveredCounts,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NotifyWalShardPendingCounts {
    pub shard_id: usize,
    pub counts: NotifyWalPendingCounts,
}

struct NotifyWalShard {
    store: NotifyWalStore,
    raw_wake_sequence: AtomicU64,
}

struct NotifyCommitWriter {
    sender: Option<mpsc::SyncSender<NotifyCommitRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

struct NotifyCommitRequest {
    op: NotifyCommitOp,
    reply: NotifyCommitReply,
}

enum NotifyCommitReply {
    Sync(mpsc::SyncSender<Result<(), NodeCoreError>>),
    Async(tokio::sync::oneshot::Sender<Result<(), NodeCoreError>>),
}

impl NotifyCommitReply {
    fn send(self, result: Result<(), NodeCoreError>) {
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

enum NotifyCommitOp {
    QueueEntry { entry: Box<NotifyQueueEntry>, bounded_state: Option<Box<NotifyQueueState>> },
    ProviderAttempt { attempt: Box<ProviderPushAttempt> },
}

#[derive(Default)]
struct NotifyRuntimeState {
    rate_events_by_alias: BTreeMap<String, Vec<u64>>,
    rate_events_by_provider: BTreeMap<PushProviderKind, Vec<u64>>,
}

impl NotifyCommitWriter {
    fn start(db: std::sync::Arc<redb::Database>) -> Result<Self, NodeCoreError> {
        let batch_max =
            notify_usize_env(NOTIFY_COMMIT_BATCH_MAX_ENV, NOTIFY_COMMIT_BATCH_MAX_DEFAULT).max(1);
        let queue_capacity = notify_usize_env(
            NOTIFY_COMMIT_QUEUE_CAPACITY_ENV,
            NOTIFY_COMMIT_QUEUE_CAPACITY_DEFAULT,
        )
        .max(batch_max);
        let window = Duration::from_micros(notify_u64_env(
            NOTIFY_COMMIT_WINDOW_US_ENV,
            NOTIFY_COMMIT_WINDOW_US_DEFAULT,
        ));
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let thread = thread::Builder::new()
            .name("ramflux-notify-commit-writer".to_owned())
            .spawn(move || notify_commit_writer_loop(&db, &receiver, batch_max, window))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        Ok(Self { sender: Some(sender), thread: Some(thread) })
    }

    fn commit(&self, op: NotifyCommitOp) -> Result<(), NodeCoreError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.submit(op, NotifyCommitReply::Sync(reply))?;
        response.recv().map_err(|source| {
            NodeCoreError::ItestJson(format!("notify commit response closed: {source}"))
        })?
    }

    async fn commit_async(&self, op: NotifyCommitOp) -> Result<(), NodeCoreError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.submit_async(NotifyCommitRequest { op, reply: NotifyCommitReply::Async(reply) })
            .await?;
        response.await.map_err(|source| {
            NodeCoreError::ItestJson(format!("notify commit response closed: {source}"))
        })?
    }

    fn submit(&self, op: NotifyCommitOp, reply: NotifyCommitReply) -> Result<(), NodeCoreError> {
        self.sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("notify commit writer stopped".to_owned()))?
            .send(NotifyCommitRequest { op, reply })
            .map_err(|source| {
                NodeCoreError::ItestJson(format!("notify commit writer stopped: {source}"))
            })
    }

    async fn submit_async(&self, mut request: NotifyCommitRequest) -> Result<(), NodeCoreError> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("notify commit writer stopped".to_owned()))?;
        loop {
            match sender.try_send(request) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) => {
                    request = returned;
                    tokio::task::yield_now().await;
                }
                Err(mpsc::TrySendError::Disconnected(_returned)) => {
                    return Err(NodeCoreError::ItestJson(
                        "notify commit writer stopped".to_owned(),
                    ));
                }
            }
        }
    }
}

impl Drop for NotifyCommitWriter {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

fn notify_commit_writer_loop(
    db: &redb::Database,
    receiver: &mpsc::Receiver<NotifyCommitRequest>,
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
        let result = notify_commit_batch(db, batch.iter().map(|request| &request.op));
        match result {
            Ok(()) => {
                for request in batch {
                    request.reply.send(Ok(()));
                }
            }
            Err(error) => {
                let message = error.to_string();
                for request in batch {
                    request.reply.send(Err(NodeCoreError::Redb(message.clone())));
                }
            }
        }
    }
}

fn notify_commit_batch<'a>(
    db: &redb::Database,
    ops: impl Iterator<Item = &'a NotifyCommitOp>,
) -> Result<(), NodeCoreError> {
    let write_txn = db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    {
        for op in ops {
            notify_apply_commit_op(&write_txn, op)?;
        }
    }
    write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn notify_apply_commit_op(
    write_txn: &redb::WriteTransaction,
    op: &NotifyCommitOp,
) -> Result<(), NodeCoreError> {
    match op {
        NotifyCommitOp::QueueEntry { entry, bounded_state } => {
            if let Some(state) = bounded_state {
                record_notify_bounded_snapshot_in_txn(write_txn, state)?;
            }
            let entry_bytes = serialize_notify_queue_entry_binary(entry)?;
            record_notify_queue_entry_in_txn(write_txn, entry, &entry_bytes)
        }
        NotifyCommitOp::ProviderAttempt { attempt } => {
            record_notify_attempt_in_txn(write_txn, attempt)
        }
    }
}

impl NotifyRedbStore {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let wal_root = if notify_wal_enabled() {
            Some(notify_wal_root_for_redb_path(path.as_ref()))
        } else {
            None
        };
        Self::open_with_wal_root(path, wal_root.as_deref())
    }

    #[cfg(test)]
    pub(crate) fn open_with_wal(
        path: impl AsRef<Path>,
        wal_root: impl AsRef<Path>,
    ) -> Result<Self, NodeCoreError> {
        Self::open_with_wal_root(path, Some(wal_root.as_ref()))
    }

    #[cfg(test)]
    pub(crate) fn open_with_wal_shard_count(
        path: impl AsRef<Path>,
        wal_root: impl AsRef<Path>,
        shard_count: usize,
    ) -> Result<Self, NodeCoreError> {
        Self::open_with_wal_root_and_shard_count(path, Some(wal_root.as_ref()), Some(shard_count))
    }

    #[cfg(test)]
    pub(crate) fn open_without_wal(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        Self::open_with_wal_root(path, None)
    }

    fn open_with_wal_root(
        path: impl AsRef<Path>,
        wal_root: Option<&Path>,
    ) -> Result<Self, NodeCoreError> {
        Self::open_with_wal_root_and_shard_count(path, wal_root, None)
    }

    fn open_with_wal_root_and_shard_count(
        path: impl AsRef<Path>,
        wal_root: Option<&Path>,
        shard_count_override: Option<usize>,
    ) -> Result<Self, NodeCoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| NodeCoreError::StoreDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let db = redb::Database::create(path)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let write_txn =
            db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let _table = write_txn
                .open_table(NOTIFY_QUEUE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(NOTIFY_QUEUE_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(NOTIFY_PROVIDER_ATTEMPT_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(NOTIFY_ROUTE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(NOTIFY_CREDENTIAL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let wal_shards = match (wal_root, shard_count_override) {
            (Some(root), Some(shard_count)) => {
                Some(open_notify_wal_shards_with_config(root, shard_count)?)
            }
            (Some(root), None) => Some(open_notify_wal_shards(root)?),
            (None, _) => None,
        };
        let db = std::sync::Arc::new(db);
        let commit_writer = NotifyCommitWriter::start(std::sync::Arc::clone(&db))?;
        Ok(Self {
            db,
            commit_writer,
            runtime_state: Mutex::new(NotifyRuntimeState::default()),
            wal_shards,
        })
    }

    #[must_use]
    pub fn uses_notify_wal(&self) -> bool {
        self.wal_shards.as_ref().is_some_and(|shards| !shards.is_empty())
    }

    #[must_use]
    pub fn notify_ingest_shard_count(&self) -> usize {
        self.wal_shards.as_ref().map_or(1, Vec::len).max(1)
    }

    #[must_use]
    pub fn notify_ingest_shard_for_key(&self, key: &str) -> usize {
        notify_shard_index_for_key(key, self.notify_ingest_shard_count())
    }

    #[must_use]
    pub fn notify_wal_recovered_counts(&self) -> Vec<NotifyWalShardRecoveredCounts> {
        self.wal_shards.as_ref().map_or_else(Vec::new, |shards| {
            shards
                .iter()
                .enumerate()
                .map(|(shard_id, shard)| NotifyWalShardRecoveredCounts {
                    shard_id,
                    counts: shard.store.recovered_counts(),
                })
                .collect()
        })
    }

    #[must_use]
    pub fn notify_wal_pending_counts(
        &self,
        limit_per_shard: usize,
    ) -> Vec<NotifyWalShardPendingCounts> {
        self.wal_shards.as_ref().map_or_else(Vec::new, |shards| {
            shards
                .iter()
                .enumerate()
                .map(|(shard_id, shard)| NotifyWalShardPendingCounts {
                    shard_id,
                    counts: shard.store.pending_counts(limit_per_shard),
                })
                .collect()
        })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn save_state(&self, state: &NotifyQueueState) -> Result<(), NodeCoreError> {
        let snapshot = notify_bounded_snapshot(state);
        let snapshot = serialize_notify_value(&snapshot)?;
        let queue_entries = state
            .entries_by_id
            .values()
            .map(|entry| {
                serialize_notify_queue_entry_binary(entry)
                    .map(|bytes| (entry.queue_id.clone(), bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let attempt_entries = state
            .provider_attempts_by_queue
            .iter()
            .flat_map(|(queue_id, attempts)| {
                attempts.iter().enumerate().map(move |(index, attempt)| {
                    let key = notify_provider_attempt_key(queue_id, index, attempt)?;
                    serialize_notify_provider_attempt_binary(attempt).map(|bytes| (key, bytes))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let route_entries = state
            .routes_by_device
            .iter()
            .map(|(device_id, routes)| {
                serialize_notify_value(routes).map(|bytes| (device_id.clone(), bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let credential_entries = state
            .credentials_by_id
            .iter()
            .map(|(credential_id, credential)| {
                serialize_notify_value(credential).map(|bytes| (credential_id.clone(), bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(NOTIFY_QUEUE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(NOTIFY_QUEUE_KEY, snapshot.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            replace_notify_table_values(&write_txn, NOTIFY_QUEUE_ENTRY_TABLE, &queue_entries)?;
            replace_notify_table_values(
                &write_txn,
                NOTIFY_PROVIDER_ATTEMPT_TABLE,
                &attempt_entries,
            )?;
            replace_notify_table_values(&write_txn, NOTIFY_ROUTE_TABLE, &route_entries)?;
            replace_notify_table_values(&write_txn, NOTIFY_CREDENTIAL_TABLE, &credential_entries)?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn load_state(&self) -> Result<Option<NotifyQueueState>, NodeCoreError> {
        let (state, _has_incremental_rows) = self.load_state_with_incremental_flag()?;
        if let Some(shards) = &self.wal_shards {
            let had_redb_state = state.is_some();
            let mut state = state.unwrap_or_default();
            let mut had_active_entries = false;
            for shard in shards {
                let active_entries = shard.store.active_entries();
                if !active_entries.is_empty() {
                    had_active_entries = true;
                }
                let provider_attempts = shard.store.all_provider_attempts();
                for entry in active_entries.iter().cloned() {
                    state.entries_by_id.insert(entry.queue_id.clone(), entry);
                }
                for (_queue_id, attempts) in provider_attempts {
                    for attempt in attempts {
                        state.record_provider_attempt(attempt);
                    }
                }
            }
            if had_redb_state || had_active_entries || !state.provider_attempts_by_queue.is_empty()
            {
                Ok(Some(state))
            } else {
                Ok(None)
            }
        } else {
            Ok(state)
        }
    }

    fn load_bounded_state_with_incremental_flag(
        &self,
    ) -> Result<(Option<NotifyQueueState>, bool), NodeCoreError> {
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(NOTIFY_QUEUE_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let state = match table
            .get(NOTIFY_QUEUE_KEY)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        {
            Some(snapshot) => serde_json::from_slice(snapshot.value())
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?,
            None => NotifyQueueState::new(),
        };
        let has_incremental_rows = notify_table_has_rows(&read_txn, NOTIFY_QUEUE_ENTRY_TABLE)?
            || notify_table_has_rows(&read_txn, NOTIFY_PROVIDER_ATTEMPT_TABLE)?
            || notify_table_has_rows(&read_txn, NOTIFY_ROUTE_TABLE)?
            || notify_table_has_rows(&read_txn, NOTIFY_CREDENTIAL_TABLE)?;
        if state == NotifyQueueState::new() && !has_incremental_rows {
            Ok((None, false))
        } else {
            Ok((Some(state), has_incremental_rows))
        }
    }

    fn load_state_with_incremental_flag(
        &self,
    ) -> Result<(Option<NotifyQueueState>, bool), NodeCoreError> {
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(NOTIFY_QUEUE_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let mut state = match table
            .get(NOTIFY_QUEUE_KEY)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        {
            Some(snapshot) => serde_json::from_slice(snapshot.value())
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?,
            None => NotifyQueueState::new(),
        };
        let mut has_incremental_rows = false;
        {
            let table = read_txn
                .open_table(NOTIFY_ROUTE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
                has_incremental_rows = true;
                let (key, value) =
                    entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                let routes: Vec<DevicePushRoute> = serde_json::from_slice(value.value())
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
                state.routes_by_device.insert(key.value().to_owned(), routes);
            }
        }
        {
            let table = read_txn
                .open_table(NOTIFY_CREDENTIAL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
                has_incremental_rows = true;
                let (_key, value) =
                    entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                let credential: ProviderCredential = serde_json::from_slice(value.value())
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
                state.credentials_by_id.insert(credential.credential_id().to_owned(), credential);
            }
        }
        {
            let table = read_txn
                .open_table(NOTIFY_QUEUE_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
                has_incremental_rows = true;
                let (_key, value) =
                    entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                let queue_entry: NotifyQueueEntry = deserialize_notify_queue_entry(value.value())?;
                state.entries_by_id.insert(queue_entry.queue_id.clone(), queue_entry);
            }
        }
        {
            let table = read_txn
                .open_table(NOTIFY_PROVIDER_ATTEMPT_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
                has_incremental_rows = true;
                let (_key, value) =
                    entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                let attempt: ProviderPushAttempt =
                    deserialize_notify_provider_attempt(value.value())?;
                state
                    .provider_attempts_by_queue
                    .entry(attempt.queue_id.clone())
                    .or_default()
                    .push(attempt);
            }
        }
        if state == NotifyQueueState::new() && !has_incremental_rows {
            Ok((None, false))
        } else {
            Ok((Some(state), has_incremental_rows))
        }
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn queue_wake(
        &self,
        wake: ramflux_protocol::NotificationWake,
        push_alias_hash: impl Into<String>,
        queued_at: u64,
    ) -> Result<NotifyQueueEntry, NodeCoreError> {
        let mut state = NotifyQueueState::new();
        let entry = state.queue_wake(wake, push_alias_hash, queued_at);
        self.commit_writer.commit(NotifyCommitOp::QueueEntry {
            entry: Box::new(entry.clone()),
            bounded_state: None,
        })?;
        Ok(entry)
    }

    /// # Errors
    /// Returns an error when the notify state cannot be persisted.
    pub fn register_push_route(&self, route: DevicePushRoute) -> Result<(), NodeCoreError> {
        let (state, has_incremental_rows) = self.load_bounded_state_with_incremental_flag()?;
        let mut state = state.unwrap_or_default();
        if has_incremental_rows {
            let mut routes = self.load_notify_routes(&route.device_delivery_id)?;
            routes.retain(|existing| {
                existing.provider != route.provider || existing.token != route.token
            });
            routes.push(route);
            self.record_notify_routes(&routes)
        } else {
            state.register_push_route(route);
            self.save_state(&state)
        }
    }

    /// # Errors
    /// Returns an error when the provider credential cannot be persisted.
    pub fn update_provider_credential(
        &self,
        credential: ProviderCredential,
    ) -> Result<(), NodeCoreError> {
        let (state, has_incremental_rows) = self.load_bounded_state_with_incremental_flag()?;
        let mut state = state.unwrap_or_default();
        if has_incremental_rows {
            self.record_notify_credential(&credential)
        } else {
            state.update_provider_credential(credential);
            self.save_state(&state)
        }
    }

    /// # Errors
    /// Returns an error when the wake cannot be queued or provider attempts cannot be persisted.
    pub fn queue_wake_for_push(
        &self,
        device_delivery_id: &str,
        wake: &ramflux_protocol::NotificationWake,
        queued_at: u64,
        dnd_active: bool,
    ) -> Result<(NotifyQueueEntry, Vec<PreparedProviderPush>), NodeCoreError> {
        let (state, has_incremental_rows) = self.load_bounded_state_with_incremental_flag()?;
        let mut state = state.unwrap_or_default();
        let normalized_wake = normalized_notification_wake(wake, device_delivery_id);
        let push_alias_hash = notification_hash(
            "ramflux.notification.push_alias_hash.v1",
            normalized_wake.push_alias.as_bytes(),
        );
        let entry = state.queue_wake_for_device(
            device_delivery_id,
            normalized_wake.clone(),
            push_alias_hash.clone(),
            queued_at,
            dnd_active,
        );
        let routes = if has_incremental_rows {
            self.load_notify_routes(device_delivery_id)?
                .into_iter()
                .filter(|route| route.expires_at > queued_at)
                .collect()
        } else {
            state.push_routes(device_delivery_id, queued_at)
        };
        let mut credential_cache: BTreeMap<String, ProviderCredential> = BTreeMap::new();
        let mut pushes = Vec::new();
        let mut deferred_changed = false;
        for route in routes {
            let collapse_key = canonical_collapse_key(&normalized_wake, device_delivery_id);
            let collapse_key_hash = notification_hash(
                "ramflux.notification.collapse_key_hash.v1",
                collapse_key.as_bytes(),
            );
            let action = delivery_action_for_wake(&normalized_wake, dnd_active);
            if matches!(
                action,
                NotifyDeliveryAction::DropLowPriorityDueToDnd
                    | NotifyDeliveryAction::DeferWithRetryAfter
            ) {
                state
                    .deferred_by_device
                    .entry(device_delivery_id.to_owned())
                    .or_default()
                    .push(entry.queue_id.clone());
                deferred_changed = true;
                continue;
            }
            if self.notify_rate_limited(&route.provider, &push_alias_hash, queued_at)? {
                continue;
            }
            let credential = self.provider_credential_for_route(
                &state,
                has_incremental_rows,
                &mut credential_cache,
                &route,
            )?;
            self.record_notify_rate_event(
                push_alias_hash.clone(),
                route.provider.clone(),
                queued_at,
            )?;
            let route_provider = route.provider.clone();
            pushes.push({
                let payload = ProviderPushPayload {
                    wake_id: normalized_wake.wake_id.clone(),
                    provider: route_provider,
                    delivery_class: normalized_wake.delivery_class.clone(),
                    priority: normalized_wake.priority.clone(),
                    ttl: normalized_wake.ttl,
                    collapse_key: Some(collapse_key),
                    encrypted_hint: normalized_wake.encrypted_hint.clone(),
                };
                PreparedProviderPush {
                    route,
                    credential,
                    payload,
                    push_alias_hash: push_alias_hash.clone(),
                    collapse_key_hash,
                    action,
                }
            });
        }
        if has_incremental_rows {
            self.commit_writer.commit(NotifyCommitOp::QueueEntry {
                entry: Box::new(entry.clone()),
                bounded_state: deferred_changed.then_some(Box::new(state)),
            })?;
        } else {
            self.save_state(&state)?;
        }
        Ok((entry, pushes))
    }

    /// # Errors
    /// Returns an error when the wake cannot be normalized or durably queued.
    pub fn queue_wake_for_async_accept(
        &self,
        device_delivery_id: &str,
        wake: &ramflux_protocol::NotificationWake,
        _queued_at: u64,
        dnd_active: bool,
    ) -> Result<NotifyQueueEntry, NodeCoreError> {
        let queued_at = now_unix_seconds();
        let normalized_wake = normalized_notification_wake(wake, device_delivery_id);
        let push_alias_hash = notification_hash(
            "ramflux.notification.push_alias_hash.v1",
            normalized_wake.push_alias.as_bytes(),
        );
        let mut state = NotifyQueueState::new();
        let entry = state.queue_wake_for_device(
            device_delivery_id,
            normalized_wake,
            push_alias_hash,
            queued_at,
            dnd_active,
        );
        if let Some(shards) = &self.wal_shards {
            let shard_id = self.notify_ingest_shard_for_key(device_delivery_id);
            let shard = shards.get(shard_id).ok_or_else(|| {
                NodeCoreError::ItestJson(format!("notify WAL shard {shard_id} not available"))
            })?;
            shard.store.append(NotifyWalPayload::QueueEntry(entry.clone()))?;
        } else {
            self.commit_writer.commit(NotifyCommitOp::QueueEntry {
                entry: Box::new(entry.clone()),
                bounded_state: None,
            })?;
        }
        Ok(entry)
    }

    /// # Errors
    /// Returns an error when the wake cannot be normalized or durably queued.
    pub async fn queue_wake_for_async_accept_async(
        &self,
        device_delivery_id: &str,
        wake: &ramflux_protocol::NotificationWake,
        _queued_at: u64,
        dnd_active: bool,
    ) -> Result<NotifyQueueEntry, NodeCoreError> {
        let queued_at = now_unix_seconds();
        let normalized_wake = normalized_notification_wake(wake, device_delivery_id);
        let push_alias_hash = notification_hash(
            "ramflux.notification.push_alias_hash.v1",
            normalized_wake.push_alias.as_bytes(),
        );
        let mut state = NotifyQueueState::new();
        let entry = state.queue_wake_for_device(
            device_delivery_id,
            normalized_wake,
            push_alias_hash,
            queued_at,
            dnd_active,
        );
        if let Some(shards) = &self.wal_shards {
            let shard_id = self.notify_ingest_shard_for_key(device_delivery_id);
            let shard = shards.get(shard_id).ok_or_else(|| {
                NodeCoreError::ItestJson(format!("notify WAL shard {shard_id} not available"))
            })?;
            shard.store.append_async(NotifyWalPayload::QueueEntry(entry.clone())).await?;
        } else {
            self.commit_writer
                .commit_async(NotifyCommitOp::QueueEntry {
                    entry: Box::new(entry.clone()),
                    bounded_state: None,
                })
                .await?;
        }
        Ok(entry)
    }

    /// # Errors
    /// Returns an error when the raw wake cannot be durably queued in the notify WAL.
    pub async fn queue_raw_wake_for_async_accept_async(
        &self,
        raw_body: Vec<u8>,
        queued_at: u64,
    ) -> Result<NotifyWalRawWake, NodeCoreError> {
        self.queue_raw_wake_for_async_accept_shard_async(0, raw_body, queued_at).await
    }

    /// # Errors
    /// Returns an error when the raw wake cannot be durably queued in the notify WAL shard.
    pub async fn queue_raw_wake_for_async_accept_shard_async(
        &self,
        shard_id: usize,
        raw_body: Vec<u8>,
        queued_at: u64,
    ) -> Result<NotifyWalRawWake, NodeCoreError> {
        let shard = self.wal_shard(shard_id)?;
        let sequence = shard.raw_wake_sequence.fetch_add(1, Ordering::Relaxed);
        let queue_id = notify_raw_wake_queue_id(shard_id, queued_at, sequence);
        let raw = NotifyWalRawWake { queue_id, raw_body, queued_at };
        shard.store.record_raw_wake_async(raw.clone()).await?;
        Ok(raw)
    }

    fn wal_shard(&self, shard_id: usize) -> Result<&NotifyWalShard, NodeCoreError> {
        let shards = self.wal_shards.as_ref().ok_or_else(|| {
            NodeCoreError::ItestJson(
                "raw notify WAL enqueue requested without RAMFLUX_NOTIFY_WAL=1".to_owned(),
            )
        })?;
        shards.get(shard_id).ok_or_else(|| {
            NodeCoreError::ItestJson(format!("notify WAL shard {shard_id} not available"))
        })
    }

    fn wal_shard_index_for_queue_id(&self, queue_id: &str) -> Option<usize> {
        let shards = self.wal_shards.as_ref()?;
        if let Some(shard_id) = notify_raw_wake_shard_from_queue_id(queue_id)
            && shard_id < shards.len()
        {
            return Some(shard_id);
        }
        for (shard_id, shard) in shards.iter().enumerate() {
            if shard.store.active_entries().iter().any(|entry| entry.queue_id == queue_id) {
                return Some(shard_id);
            }
        }
        Some(notify_shard_index_for_key(queue_id, shards.len()))
    }

    /// # Errors
    /// Returns an error when the raw wakes cannot be durably queued in one notify WAL batch.
    pub fn queue_raw_wakes_for_async_accept_batch(
        &self,
        raw_bodies: Vec<(Vec<u8>, u64)>,
    ) -> Result<Vec<NotifyWalRawWake>, NodeCoreError> {
        self.queue_raw_wakes_for_async_accept_shard_batch(0, raw_bodies)
    }

    /// # Errors
    /// Returns an error when the raw wakes cannot be durably queued in one notify WAL shard batch.
    pub fn queue_raw_wakes_for_async_accept_shard_batch(
        &self,
        shard_id: usize,
        raw_bodies: Vec<(Vec<u8>, u64)>,
    ) -> Result<Vec<NotifyWalRawWake>, NodeCoreError> {
        let shard = self.wal_shard(shard_id)?;
        let mut raws = Vec::with_capacity(raw_bodies.len());
        for (raw_body, queued_at) in raw_bodies {
            let sequence = shard.raw_wake_sequence.fetch_add(1, Ordering::Relaxed);
            let queue_id = notify_raw_wake_queue_id(shard_id, queued_at, sequence);
            raws.push(NotifyWalRawWake { queue_id, raw_body, queued_at });
        }
        shard.store.record_raw_wakes_batch(raws.clone())?;
        Ok(raws)
    }

    /// # Errors
    /// Returns an error when queued entries or provider attempts cannot be read.
    pub fn pending_entries_without_attempts(
        &self,
        limit: usize,
    ) -> Result<Vec<NotifyQueueEntry>, NodeCoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        if let Some(shards) = &self.wal_shards {
            let mut entries = Vec::with_capacity(limit);
            for (shard_id, shard) in shards.iter().enumerate() {
                if entries.len() >= limit {
                    break;
                }
                let remaining = limit - entries.len();
                let mut shard_entries =
                    self.pending_wal_entries_without_attempts(shard_id, &shard.store, remaining)?;
                entries.append(&mut shard_entries);
            }
            return Ok(entries);
        }
        let state = self.load_state()?.unwrap_or_default();
        let mut entries = Vec::with_capacity(limit);
        for entry in state.entries_by_id.values() {
            if entries.len() >= limit {
                break;
            }
            if entry.status == NotifyQueueStatus::Pending
                && !entry.device_delivery_id.is_empty()
                && state.provider_attempts(&entry.queue_id).is_empty()
            {
                entries.push(entry.clone());
            }
        }
        Ok(entries)
    }

    fn pending_wal_entries_without_attempts(
        &self,
        shard_id: usize,
        wal: &NotifyWalStore,
        limit: usize,
    ) -> Result<Vec<NotifyQueueEntry>, NodeCoreError> {
        let pending = wal.pending_wakes_without_attempts(limit.saturating_mul(2).max(limit));
        let mut entries = Vec::with_capacity(limit);
        for wake in pending {
            if entries.len() >= limit {
                break;
            }
            match wake {
                NotifyWalPendingWake::Entry(entry) => entries.push(*entry),
                NotifyWalPendingWake::Raw(raw) => match Self::parse_raw_wake_entry(&raw) {
                    Ok(entry) => entries.push(entry),
                    Err(error) => {
                        self.record_raw_wake_parse_failure(shard_id, &raw, &error)?;
                    }
                },
            }
        }
        Ok(entries)
    }

    fn parse_raw_wake_entry(raw: &NotifyWalRawWake) -> Result<NotifyQueueEntry, NodeCoreError> {
        let request: RawS13WakeRequest = serde_json::from_slice(&raw.raw_body)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let queued_at = raw.queued_at;
        let normalized_wake =
            normalized_notification_wake(&request.wake, &request.device_delivery_id);
        let push_alias_hash = notification_hash(
            "ramflux.notification.push_alias_hash.v1",
            normalized_wake.push_alias.as_bytes(),
        );
        let mut state = NotifyQueueState::new();
        let mut entry = state.queue_wake_for_device(
            request.device_delivery_id,
            normalized_wake,
            push_alias_hash,
            queued_at,
            request.dnd_active.unwrap_or(false),
        );
        entry.queue_id.clone_from(&raw.queue_id);
        Ok(entry)
    }

    fn record_raw_wake_parse_failure(
        &self,
        shard_id: usize,
        raw: &NotifyWalRawWake,
        error: &NodeCoreError,
    ) -> Result<(), NodeCoreError> {
        let attempt = ProviderPushAttempt {
            queue_id: raw.queue_id.clone(),
            device_delivery_id: String::new(),
            provider: PushProviderKind::WebPush,
            push_alias_hash: String::new(),
            collapse_key_hash: String::new(),
            delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            action: NotifyDeliveryAction::ProviderRejected,
            sent_at: now_unix_seconds(),
            accepted: false,
            error_class: Some(format!("raw_wake_parse_failed:{error}")),
        };
        self.record_provider_attempt(attempt)?;
        if let Some(shard) = self.wal_shards.as_ref().and_then(|shards| shards.get(shard_id)) {
            shard.store.mark_delivered(raw.queue_id.clone())?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when routes, credentials, or rate-limit state cannot be read.
    pub fn prepare_provider_pushes_for_entry(
        &self,
        entry: &NotifyQueueEntry,
    ) -> Result<Vec<PreparedProviderPush>, NodeCoreError> {
        if entry.device_delivery_id.is_empty()
            || entry.status != NotifyQueueStatus::Pending
            || entry.expires_at <= now_unix_seconds()
        {
            return Ok(Vec::new());
        }
        let (state, has_incremental_rows) = self.load_bounded_state_with_incremental_flag()?;
        let state = state.unwrap_or_default();
        let routes = if has_incremental_rows {
            self.load_notify_routes(&entry.device_delivery_id)?
                .into_iter()
                .filter(|route| route.expires_at > entry.queued_at)
                .collect()
        } else {
            state.push_routes(&entry.device_delivery_id, entry.queued_at)
        };
        let mut credential_cache: BTreeMap<String, ProviderCredential> = BTreeMap::new();
        let mut pushes = Vec::new();
        for route in routes {
            let collapse_key = canonical_collapse_key(&entry.wake, &entry.device_delivery_id);
            let collapse_key_hash = notification_hash(
                "ramflux.notification.collapse_key_hash.v1",
                collapse_key.as_bytes(),
            );
            let action = delivery_action_for_wake(&entry.wake, entry.dnd_active);
            if matches!(
                action,
                NotifyDeliveryAction::DropLowPriorityDueToDnd
                    | NotifyDeliveryAction::DeferWithRetryAfter
            ) {
                continue;
            }
            if self.notify_rate_limited(&route.provider, &entry.push_alias_hash, entry.queued_at)? {
                continue;
            }
            let credential = self.provider_credential_for_route(
                &state,
                has_incremental_rows,
                &mut credential_cache,
                &route,
            )?;
            self.record_notify_rate_event(
                entry.push_alias_hash.clone(),
                route.provider.clone(),
                entry.queued_at,
            )?;
            let route_provider = route.provider.clone();
            pushes.push({
                let payload = ProviderPushPayload {
                    wake_id: entry.wake.wake_id.clone(),
                    provider: route_provider,
                    delivery_class: entry.wake.delivery_class.clone(),
                    priority: entry.wake.priority.clone(),
                    ttl: entry.wake.ttl,
                    collapse_key: Some(collapse_key),
                    encrypted_hint: entry.wake.encrypted_hint.clone(),
                };
                PreparedProviderPush {
                    route,
                    credential,
                    payload,
                    push_alias_hash: entry.push_alias_hash.clone(),
                    collapse_key_hash,
                    action,
                }
            });
        }
        Ok(pushes)
    }

    fn notify_rate_limited(
        &self,
        provider: &PushProviderKind,
        push_alias_hash: &str,
        now: u64,
    ) -> Result<bool, NodeCoreError> {
        let mut runtime_state = self.runtime_state.lock().map_err(|source| {
            NodeCoreError::ItestJson(format!("notify runtime state lock poisoned: {source}"))
        })?;
        Ok(runtime_state.is_provider_rate_limited(provider, now)
            || runtime_state.is_alias_rate_limited(push_alias_hash, now))
    }

    fn record_notify_rate_event(
        &self,
        push_alias_hash: String,
        provider: PushProviderKind,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let mut runtime_state = self.runtime_state.lock().map_err(|source| {
            NodeCoreError::ItestJson(format!("notify runtime state lock poisoned: {source}"))
        })?;
        runtime_state.record_rate_event(push_alias_hash, provider, now);
        Ok(())
    }

    fn provider_credential_for_route(
        &self,
        state: &NotifyQueueState,
        has_incremental_rows: bool,
        credential_cache: &mut BTreeMap<String, ProviderCredential>,
        route: &DevicePushRoute,
    ) -> Result<ProviderCredential, NodeCoreError> {
        let credential_id = route.credential_id.as_deref().ok_or_else(|| {
            NodeCoreError::ItestJson(format!(
                "missing provider credential for {}",
                route.device_delivery_id
            ))
        })?;
        let credential = if has_incremental_rows {
            if let Some(cached) = credential_cache.get(credential_id) {
                cached.clone()
            } else {
                let credential = self.load_notify_credential(credential_id)?.ok_or_else(|| {
                    NodeCoreError::ItestJson(format!(
                        "provider credential {credential_id} not registered for {:?}",
                        route.provider
                    ))
                })?;
                credential_cache.insert(credential_id.to_owned(), credential.clone());
                credential
            }
        } else {
            state.provider_credential(credential_id).cloned().ok_or_else(|| {
                NodeCoreError::ItestJson(format!(
                    "provider credential {credential_id} not registered for {:?}",
                    route.provider
                ))
            })?
        };
        if credential.provider_kind() != route.provider {
            return Err(NodeCoreError::ItestJson(format!(
                "provider credential {credential_id} not registered for {:?}",
                route.provider
            )));
        }
        Ok(credential)
    }

    /// # Errors
    /// Returns an error when the notify state cannot be persisted.
    pub fn record_provider_attempt(
        &self,
        attempt: ProviderPushAttempt,
    ) -> Result<(), NodeCoreError> {
        if let Some(shards) = &self.wal_shards {
            let shard_id = self
                .wal_shard_index_for_queue_id(&attempt.queue_id)
                .ok_or_else(|| NodeCoreError::ItestJson("notify WAL is not enabled".to_owned()))?;
            let shard = shards.get(shard_id).ok_or_else(|| {
                NodeCoreError::ItestJson(format!("notify WAL shard {shard_id} not available"))
            })?;
            shard.store.record_provider_attempt(attempt.clone())?;
            if attempt.accepted {
                shard.store.mark_delivered(attempt.queue_id)?;
            }
            Ok(())
        } else {
            self.commit_writer
                .commit(NotifyCommitOp::ProviderAttempt { attempt: Box::new(attempt) })
        }
    }

    #[cfg(test)]
    pub(crate) fn save_legacy_state_only(
        &self,
        state: &NotifyQueueState,
    ) -> Result<(), NodeCoreError> {
        let snapshot = serialize_notify_value(state)?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(NOTIFY_QUEUE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(NOTIFY_QUEUE_KEY, snapshot.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            replace_notify_table_values(&write_txn, NOTIFY_QUEUE_ENTRY_TABLE, &[])?;
            replace_notify_table_values(&write_txn, NOTIFY_PROVIDER_ATTEMPT_TABLE, &[])?;
            replace_notify_table_values(&write_txn, NOTIFY_ROUTE_TABLE, &[])?;
            replace_notify_table_values(&write_txn, NOTIFY_CREDENTIAL_TABLE, &[])?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn save_legacy_json_incremental_entry_and_attempt(
        &self,
        entry: &NotifyQueueEntry,
        attempt: &ProviderPushAttempt,
    ) -> Result<(), NodeCoreError> {
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut entry_table = write_txn
                .open_table(NOTIFY_QUEUE_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let entry_bytes = serialize_notify_value(entry)?;
            entry_table
                .insert(entry.queue_id.as_str(), entry_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;

            let mut attempt_table = write_txn
                .open_table(NOTIFY_PROVIDER_ATTEMPT_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let attempt_bytes = serialize_notify_value(attempt)?;
            attempt_table
                .insert("legacy-json-attempt", attempt_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    fn record_notify_routes(&self, routes: &[DevicePushRoute]) -> Result<(), NodeCoreError> {
        let Some(device_delivery_id) =
            routes.first().map(|route| route.device_delivery_id.as_str())
        else {
            return Ok(());
        };
        let routes_bytes = serialize_notify_value(&routes)?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(NOTIFY_ROUTE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(device_delivery_id, routes_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    fn record_notify_credential(
        &self,
        credential: &ProviderCredential,
    ) -> Result<(), NodeCoreError> {
        let credential_bytes = serialize_notify_value(credential)?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(NOTIFY_CREDENTIAL_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(credential.credential_id(), credential_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    fn load_notify_routes(
        &self,
        device_delivery_id: &str,
    ) -> Result<Vec<DevicePushRoute>, NodeCoreError> {
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(NOTIFY_ROUTE_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        match table
            .get(device_delivery_id)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        {
            Some(routes) => serde_json::from_slice(routes.value())
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string())),
            None => Ok(Vec::new()),
        }
    }

    fn load_notify_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<ProviderCredential>, NodeCoreError> {
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(NOTIFY_CREDENTIAL_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        match table.get(credential_id).map_err(|source| NodeCoreError::Redb(source.to_string()))? {
            Some(credential) => serde_json::from_slice(credential.value())
                .map(Some)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string())),
            None => Ok(None),
        }
    }
}

impl NotifyRuntimeState {
    fn is_alias_rate_limited(&mut self, push_alias_hash: &str, now: u64) -> bool {
        let events = self.rate_events_by_alias.entry(push_alias_hash.to_owned()).or_default();
        prune_before(events, now.saturating_sub(3_600));
        let in_minute = events.iter().filter(|event| **event > now.saturating_sub(60)).count();
        in_minute >= NOTIFY_RATE_ALIAS_PER_MINUTE || events.len() >= NOTIFY_RATE_ALIAS_PER_HOUR
    }

    fn is_provider_rate_limited(&mut self, provider: &PushProviderKind, now: u64) -> bool {
        let events = self.rate_events_by_provider.entry(provider.clone()).or_default();
        prune_before(events, now.saturating_sub(60));
        events.len() >= NOTIFY_RATE_PROVIDER_PER_MINUTE
    }

    fn record_rate_event(&mut self, push_alias_hash: String, provider: PushProviderKind, now: u64) {
        self.rate_events_by_alias.entry(push_alias_hash).or_default().push(now);
        self.rate_events_by_provider.entry(provider).or_default().push(now);
    }
}

impl ProviderCredential {
    #[must_use]
    pub fn credential_id(&self) -> &str {
        match self {
            Self::Apns(credential) => &credential.credential_id,
            Self::Fcm(credential) => &credential.credential_id,
            Self::WebPush(credential) => &credential.credential_id,
        }
    }

    #[must_use]
    pub fn provider_kind(&self) -> PushProviderKind {
        match self {
            Self::Apns(_) => PushProviderKind::Apns,
            Self::Fcm(_) => PushProviderKind::Fcm,
            Self::WebPush(_) => PushProviderKind::WebPush,
        }
    }

    #[must_use]
    pub fn provider_ca_pem_ref(&self) -> Option<&str> {
        match self {
            Self::Apns(credential) => credential.provider_ca_pem_ref.as_deref(),
            Self::Fcm(credential) => credential.provider_ca_pem_ref.as_deref(),
            Self::WebPush(credential) => credential.provider_ca_pem_ref.as_deref(),
        }
    }
}

#[must_use]
pub fn notification_default_ttl(
    delivery_class: &ramflux_protocol::NotificationDeliveryClass,
) -> u32 {
    match delivery_class {
        ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification => 300,
        ramflux_protocol::NotificationDeliveryClass::UserContentNotification => 86_400,
        ramflux_protocol::NotificationDeliveryClass::AiTaskNotification => 1_800,
        ramflux_protocol::NotificationDeliveryClass::A2uiSurfaceNotification => 600,
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        | ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification => 60,
    }
}

#[must_use]
pub fn notification_default_priority(
    delivery_class: &ramflux_protocol::NotificationDeliveryClass,
    requested: &ramflux_protocol::PushPriority,
) -> ramflux_protocol::PushPriority {
    match delivery_class {
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        | ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification => {
            ramflux_protocol::PushPriority::High
        }
        ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification => {
            if *requested == ramflux_protocol::PushPriority::High {
                ramflux_protocol::PushPriority::High
            } else {
                ramflux_protocol::PushPriority::Normal
            }
        }
        ramflux_protocol::NotificationDeliveryClass::AiTaskNotification => {
            ramflux_protocol::PushPriority::Low
        }
        ramflux_protocol::NotificationDeliveryClass::UserContentNotification
        | ramflux_protocol::NotificationDeliveryClass::A2uiSurfaceNotification => {
            ramflux_protocol::PushPriority::Normal
        }
    }
}

#[must_use]
pub fn normalized_notification_wake(
    wake: &ramflux_protocol::NotificationWake,
    target_device_id: &str,
) -> ramflux_protocol::NotificationWake {
    let mut normalized = wake.clone();
    let default_ttl = notification_default_ttl(&normalized.delivery_class);
    normalized.ttl =
        if normalized.ttl == 0 { default_ttl } else { normalized.ttl.min(default_ttl) };
    normalized.priority =
        notification_default_priority(&normalized.delivery_class, &normalized.priority);
    normalized.collapse_key = Some(canonical_collapse_key(&normalized, target_device_id));
    normalized
}

#[must_use]
pub fn canonical_collapse_key(
    wake: &ramflux_protocol::NotificationWake,
    target_device_id: &str,
) -> String {
    match wake.delivery_class {
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        | ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification => {
            format!("wake:{}", wake.wake_id)
        }
        ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification => format!(
            "target:{target_device_id}:correlation:{}",
            encrypted_bucket(wake, "self_device_control")
        ),
        ramflux_protocol::NotificationDeliveryClass::UserContentNotification => {
            format!("target:{target_device_id}:content")
        }
        ramflux_protocol::NotificationDeliveryClass::AiTaskNotification => {
            format!("target:{target_device_id}:task:{}", encrypted_bucket(wake, "ai_task"))
        }
        ramflux_protocol::NotificationDeliveryClass::A2uiSurfaceNotification => {
            format!("target:{target_device_id}:surface:{}", encrypted_bucket(wake, "a2ui_surface"))
        }
    }
}

#[must_use]
pub fn delivery_action_for_wake(
    wake: &ramflux_protocol::NotificationWake,
    dnd_active: bool,
) -> NotifyDeliveryAction {
    if !dnd_active {
        return NotifyDeliveryAction::Accept;
    }
    match wake.delivery_class {
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        | ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification => {
            NotifyDeliveryAction::Accept
        }
        ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification
            if wake.priority == ramflux_protocol::PushPriority::High =>
        {
            NotifyDeliveryAction::Accept
        }
        ramflux_protocol::NotificationDeliveryClass::AiTaskNotification => {
            NotifyDeliveryAction::DropLowPriorityDueToDnd
        }
        _ => NotifyDeliveryAction::DeferWithRetryAfter,
    }
}

#[must_use]
pub fn redacted_provider_attempt(
    entry: &NotifyQueueEntry,
    prepared: &PreparedProviderPush,
    accepted: bool,
    error_class: Option<String>,
) -> ProviderPushAttempt {
    ProviderPushAttempt {
        queue_id: entry.queue_id.clone(),
        device_delivery_id: prepared.route.device_delivery_id.clone(),
        provider: prepared.route.provider.clone(),
        push_alias_hash: prepared.push_alias_hash.clone(),
        collapse_key_hash: prepared.collapse_key_hash.clone(),
        delivery_class: prepared.payload.delivery_class.clone(),
        action: if accepted {
            prepared.action.clone()
        } else {
            NotifyDeliveryAction::ProviderRejected
        },
        sent_at: now_unix_seconds(),
        accepted,
        error_class,
    }
}

fn encrypted_bucket(wake: &ramflux_protocol::NotificationWake, label: &str) -> String {
    let material = wake.collapse_key.as_deref().or(wake.encrypted_hint.as_deref()).unwrap_or(label);
    notification_hash("ramflux.notification.encrypted_bucket.v1", material.as_bytes())
}

fn notification_hash(domain: &str, bytes: &[u8]) -> String {
    ramflux_crypto::blake3_256_base64url(domain, bytes)
}

fn prune_before(events: &mut Vec<u64>, min_timestamp: u64) {
    events.retain(|event| *event > min_timestamp);
}

fn notify_bounded_snapshot(state: &NotifyQueueState) -> NotifyQueueState {
    NotifyQueueState {
        entries_by_id: BTreeMap::new(),
        routes_by_device: BTreeMap::new(),
        credentials_by_id: BTreeMap::new(),
        provider_attempts_by_queue: BTreeMap::new(),
        rate_events_by_alias: BTreeMap::new(),
        rate_events_by_provider: BTreeMap::new(),
        deferred_by_device: state.deferred_by_device.clone(),
    }
}

fn serialize_notify_value<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeCoreError> {
    serde_json::to_vec(value)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn deserialize_notify_hot_value<T>(bytes: &[u8]) -> Result<T, NodeCoreError>
where
    T: serde::de::DeserializeOwned,
{
    postcard::from_bytes(bytes)
        .or_else(|_postcard_error| serde_json::from_slice(bytes))
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn deserialize_notify_queue_entry(bytes: &[u8]) -> Result<NotifyQueueEntry, NodeCoreError> {
    match postcard::from_bytes::<StoredNotifyQueueEntry>(bytes) {
        Ok(entry) => entry.try_into(),
        Err(_postcard_error) => serde_json::from_slice(bytes)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string())),
    }
}

fn deserialize_notify_provider_attempt(bytes: &[u8]) -> Result<ProviderPushAttempt, NodeCoreError> {
    deserialize_notify_hot_value(bytes)
}

fn serialize_notify_queue_entry_binary(entry: &NotifyQueueEntry) -> Result<Vec<u8>, NodeCoreError> {
    let stored = StoredNotifyQueueEntryRef::try_from(entry)?;
    postcard::to_allocvec(&stored)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn serialize_notify_provider_attempt_binary(
    attempt: &ProviderPushAttempt,
) -> Result<Vec<u8>, NodeCoreError> {
    postcard::to_allocvec(attempt)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn notify_provider_attempt_key(
    queue_id: &str,
    index: usize,
    attempt: &ProviderPushAttempt,
) -> Result<String, NodeCoreError> {
    let material = serialize_notify_provider_attempt_binary(attempt)?;
    let digest =
        ramflux_crypto::blake3_256_base64url("ramflux.notify.provider_attempt_key.v1", &material);
    Ok(format!("{queue_id}\u{1f}{index:020}\u{1f}{digest}"))
}

fn notify_table_has_rows(
    read_txn: &redb::ReadTransaction,
    table: TableDefinition<&str, &[u8]>,
) -> Result<bool, NodeCoreError> {
    let table =
        read_txn.open_table(table).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let mut iter = table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(iter.next().is_some())
}

fn replace_notify_table_values(
    write_txn: &redb::WriteTransaction,
    table: TableDefinition<&str, &[u8]>,
    entries: &[(String, Vec<u8>)],
) -> Result<(), NodeCoreError> {
    let mut table =
        write_txn.open_table(table).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let keys = table
        .iter()
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        .map(|entry| {
            entry
                .map(|(key, _value)| key.value().to_owned())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for key in keys {
        let _removed =
            table.remove(key.as_str()).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    for (key, value) in entries {
        table
            .insert(key.as_str(), value.as_slice())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    Ok(())
}

fn record_notify_bounded_snapshot_in_txn(
    write_txn: &redb::WriteTransaction,
    state: &NotifyQueueState,
) -> Result<(), NodeCoreError> {
    let snapshot = notify_bounded_snapshot(state);
    let snapshot = serialize_notify_value(&snapshot)?;
    let mut table = write_txn
        .open_table(NOTIFY_QUEUE_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    table
        .insert(NOTIFY_QUEUE_KEY, snapshot.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn record_notify_queue_entry_in_txn(
    write_txn: &redb::WriteTransaction,
    entry: &NotifyQueueEntry,
    entry_bytes: &[u8],
) -> Result<(), NodeCoreError> {
    let mut table = write_txn
        .open_table(NOTIFY_QUEUE_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    table
        .insert(entry.queue_id.as_str(), entry_bytes)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn record_notify_attempt_in_txn(
    write_txn: &redb::WriteTransaction,
    attempt: &ProviderPushAttempt,
) -> Result<(), NodeCoreError> {
    let mut entry = {
        let table = write_txn
            .open_table(NOTIFY_QUEUE_ENTRY_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let Some(entry) = table
            .get(attempt.queue_id.as_str())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        else {
            return Err(NodeCoreError::EnvelopeNotFound(attempt.queue_id.clone()));
        };
        deserialize_notify_queue_entry(entry.value())?
    };
    if attempt.accepted {
        entry.status = NotifyQueueStatus::Delivered;
        entry.attempt_count = entry.attempt_count.saturating_add(1);
    }
    let entry_bytes = serialize_notify_queue_entry_binary(&entry)?;
    record_notify_queue_entry_in_txn(write_txn, &entry, &entry_bytes)?;

    let attempt_bytes = serialize_notify_provider_attempt_binary(attempt)?;
    let attempt_key = notify_provider_attempt_key(&attempt.queue_id, 0, attempt)?;
    let mut attempt_table = write_txn
        .open_table(NOTIFY_PROVIDER_ATTEMPT_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    attempt_table
        .insert(attempt_key.as_str(), attempt_bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn default_fcm_oauth_scope() -> String {
    "https://www.googleapis.com/auth/firebase.messaging".to_owned()
}

fn notify_wal_enabled() -> bool {
    std::env::var(NOTIFY_WAL_ENABLED_ENV).map_or(true, |value| {
        let trimmed = value.trim();
        !(trimmed == "0"
            || trimmed.eq_ignore_ascii_case("false")
            || trimmed.eq_ignore_ascii_case("off")
            || trimmed.eq_ignore_ascii_case("no"))
    })
}

fn notify_wal_root_for_redb_path(redb_path: &Path) -> PathBuf {
    if let Ok(path) = std::env::var(NOTIFY_WAL_DIR_ENV)
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    let file_name = redb_path
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| "notify.redb".to_owned(), ToOwned::to_owned);
    redb_path.with_file_name(format!("{file_name}.wal"))
}

fn open_notify_wal_shards(root: &Path) -> Result<Vec<NotifyWalShard>, NodeCoreError> {
    let default_shards =
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let configured_shards = notify_usize_env(NOTIFY_INGEST_SHARDS_ENV, default_shards).max(1);
    open_notify_wal_shards_with_config(root, configured_shards)
}

fn open_notify_wal_shards_with_config(
    root: &Path,
    configured_shards: usize,
) -> Result<Vec<NotifyWalShard>, NodeCoreError> {
    let existing_shards = existing_notify_wal_shard_count(root)?;
    let shard_count = configured_shards.max(existing_shards).max(1);
    let mut shards = Vec::with_capacity(shard_count);
    for shard_id in 0..shard_count {
        let shard_root = root.join(format!("shard_{shard_id}"));
        shards.push(NotifyWalShard {
            store: NotifyWalStore::open(shard_root)?,
            raw_wake_sequence: AtomicU64::new(0),
        });
    }
    Ok(shards)
}

fn existing_notify_wal_shard_count(root: &Path) -> Result<usize, NodeCoreError> {
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(0);
    };
    let mut count = 0_usize;
    for entry in entries {
        let entry = entry
            .map_err(|source| NodeCoreError::StoreDirectory { path: root.to_path_buf(), source })?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Some(index) = name.strip_prefix("shard_").and_then(|value| value.parse::<usize>().ok())
        else {
            continue;
        };
        count = count.max(index.saturating_add(1));
    }
    Ok(count)
}

fn notify_shard_index_for_key(key: &str, shard_count: usize) -> usize {
    if shard_count <= 1 {
        return 0;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    usize::try_from(hash % u64::try_from(shard_count).unwrap_or(u64::MAX)).unwrap_or(0)
}

fn notify_raw_wake_queue_id(shard_id: usize, queued_at: u64, sequence: u64) -> String {
    format!("raw_wake_s{shard_id}_{queued_at}_{sequence:016}")
}

fn notify_raw_wake_shard_from_queue_id(queue_id: &str) -> Option<usize> {
    let rest = queue_id.strip_prefix("raw_wake_s")?;
    let (shard, _suffix) = rest.split_once('_')?;
    shard.parse::<usize>().ok()
}

fn notify_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn notify_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
