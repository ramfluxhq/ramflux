// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

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

mod bootstrap;
pub(crate) mod retention;
mod route_authority;
mod send_gate;
#[cfg(test)]
mod tests;
mod wake_admission;
pub use route_authority::PUSH_ROUTE_FENCE_SECONDS;
mod format;
pub(crate) use send_gate::retire_call_wakes;
mod route_selection;
pub use route_selection::{apns_topic_is_voip, voip_push_enabled};
mod routes;
mod wake_policy;
pub use wake_policy::project_wake_v2;

const NOTIFY_WAKE_DUE: TableDefinition<(u64, &str), u8> =
    TableDefinition::new("notify_wake_due_v1");
const NOTIFY_WAKE_FORMAT: TableDefinition<&str, u64> =
    TableDefinition::new("notify_wake_state_format");
const NOTIFY_WAKE_CLEANUP_LIMIT: usize = 128;

pub const NOTIFY_RATE_ALIAS_PER_MINUTE: usize = 60;
pub const NOTIFY_RATE_ALIAS_PER_HOUR: usize = 600;
pub const NOTIFY_RATE_PROVIDER_PER_MINUTE: usize = 3_000;
pub const NOTIFY_MAX_PENDING_COLLAPSE_GROUPS_PER_DEVICE: usize = 10;
const NOTIFY_COMMIT_BATCH_MAX_ENV: &str = "RAMFLUX_NOTIFY_COMMIT_BATCH_MAX";
const NOTIFY_COMMIT_WINDOW_US_ENV: &str = "RAMFLUX_NOTIFY_COMMIT_WINDOW_US";
const NOTIFY_COMMIT_QUEUE_CAPACITY_ENV: &str = "RAMFLUX_NOTIFY_COMMIT_QUEUE_CAPACITY";
const NOTIFY_WAL_ENABLED_ENV: &str = "RAMFLUX_NOTIFY_WAL";
const NOTIFY_WAKE_LEDGER: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notify_wake_ledger_v1");
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
    ApnsVoip,
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
    /// Server-allocated id. It is never reused. Zero was not admitted here.
    #[serde(default)]
    pub route_generation: u64,
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
    /// Absolute provider deadline in Unix seconds. Retries must not move it.
    #[serde(default)]
    pub expires_at: u64,
    /// Server clock when this push was prepared. A call sees rollback when `now` moves backward.
    #[serde(default)]
    pub admitted_unix: u64,
    /// Process boot that prepared this push. A call from another boot is not sent.
    #[serde(default)]
    pub boot_id: u64,
    /// Owner epoch observed at prepare. Zero means the route had no authorizer.
    #[serde(default)]
    pub owner_epoch: u64,
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
#[serde(deny_unknown_fields)]
struct RawS13WakeRequest {
    device_delivery_id: String,
    signed_wake: ramflux_protocol::SignedWakeV2,
    #[serde(default, rename = "queued_at")]
    _queued_at: Option<u64>,
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
    #[serde(default)]
    absolute_expires_at: u64,
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
    absolute_expires_at: u64,
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
            absolute_expires_at: wake.absolute_expires_at,
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
            absolute_expires_at: wake.absolute_expires_at,
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
        if let Some(existing) = self.entries_by_id.get(&wake.wake_id) {
            return existing.clone();
        }
        // The signed effective expiry is the only deadline. Queue time cannot move it.
        let expires_at = wake.absolute_expires_at;
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
    send_authority: std::sync::Arc<crate::send_authority::SendAuthorityStore>,
    local_writer: Mutex<()>,
    send_authority_reader: Option<Box<send_gate::RemoteAuthorityReader>>,
    route_key: crate::NodeSecret,
    route_authorizer: Option<Box<route_authority::RouteAuthorizer>>,
    allow_itest_unbound_routes: bool,
    revocation_cursor: Mutex<Option<String>>,
    route_owners_checked: std::sync::atomic::AtomicBool,
    route_cleanup_cursors: Mutex<[Option<String>; 2]>,
    route_expiry_cursor: Mutex<Option<String>>,
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

    /// # Errors
    /// Opens persistent routes using an explicitly loaded mounted encryption key.
    pub fn open_with_route_key(
        path: impl AsRef<Path>,
        key: crate::NodeSecret,
    ) -> Result<Self, NodeCoreError> {
        let root = notify_wal_enabled().then(|| notify_wal_root_for_redb_path(path.as_ref()));
        Self::open_with_wal_root_and_shard_count(path, root.as_deref(), None, Some(key))
    }

    #[cfg(test)]
    pub(crate) fn open_with_wal(
        path: impl AsRef<Path>,
        wal_root: impl AsRef<Path>,
    ) -> Result<Self, NodeCoreError> {
        Self::open_with_wal_root(path, Some(wal_root.as_ref()))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn open_with_wal_shard_count(
        path: impl AsRef<Path>,
        wal_root: impl AsRef<Path>,
        shard_count: usize,
    ) -> Result<Self, NodeCoreError> {
        Self::open_with_wal_root_and_shard_count(
            path,
            Some(wal_root.as_ref()),
            Some(shard_count),
            None,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn open_without_wal(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        Self::open_with_wal_root(path, None)
    }

    fn open_with_wal_root(
        path: impl AsRef<Path>,
        wal_root: Option<&Path>,
    ) -> Result<Self, NodeCoreError> {
        Self::open_with_wal_root_and_shard_count(path, wal_root, None, None)
    }

    fn open_with_wal_root_and_shard_count(
        path: impl AsRef<Path>,
        wal_root: Option<&Path>,
        shard_count_override: Option<usize>,
        route_key_override: Option<crate::NodeSecret>,
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
        let route_key = route_key_override.map_or_else(routes::configured_key, Ok)?;
        format::validate_store(&db)?;
        routes::validate(&db, &route_key)?;
        initialize_wake_state_format(&db)?;
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
            let _table = write_txn
                .open_table(NOTIFY_WAKE_LEDGER)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            write_txn
                .open_table(send_gate::ROOT_WAKES)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            write_txn
                .open_table(send_gate::CALL_WAKES)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn
            .open_table(send_gate::DIAGNOSTICS)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        wake_admission::initialize(&write_txn)?;
        route_authority::initialize(&write_txn)?;
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let wal_shards = match (wal_root, shard_count_override) {
            (Some(root), Some(shard_count)) => {
                Some(open_notify_wal_shards_with_config(root, shard_count)?)
            }
            (Some(root), None) => Some(open_notify_wal_shards(root)?),
            (None, _) => None,
        };
        let db = std::sync::Arc::new(db);
        let boot = ramflux_protocol::encode_base64url(
            ramflux_crypto::random_32()
                .map_err(|e| crate::send_authority::SendAuthorityError::Storage(e.to_string()))?,
        );
        let send_authority = std::sync::Arc::new(crate::send_authority::SendAuthorityStore::new(
            std::sync::Arc::clone(&db),
            boot,
        )?);
        send_authority.set_voip_enabled(route_selection::voip_push_enabled())?;
        let commit_writer = NotifyCommitWriter::start(std::sync::Arc::clone(&db))?;
        Ok(Self {
            send_authority,
            local_writer: Mutex::new(()),
            send_authority_reader: None,
            route_key,
            route_authorizer: None,
            allow_itest_unbound_routes: false,
            revocation_cursor: Mutex::new(None),
            route_owners_checked: std::sync::atomic::AtomicBool::new(false),
            route_cleanup_cursors: Mutex::new([None, None]),
            route_expiry_cursor: Mutex::new(None),
            db,
            commit_writer,
            runtime_state: Mutex::new(NotifyRuntimeState::default()),
            wal_shards,
        })
    }

    #[must_use]
    pub fn send_authority(&self) -> &crate::send_authority::SendAuthorityStore {
        &self.send_authority
    }

    #[must_use]
    pub fn send_authority_handle(
        &self,
    ) -> std::sync::Arc<crate::send_authority::SendAuthorityStore> {
        std::sync::Arc::clone(&self.send_authority)
    }

    /// Install a store-local `VoIP` policy. `None` reads the operator environment again.
    ///
    /// # Errors
    /// Returns an error when the policy lock is poisoned.
    pub fn set_voip_policy(&self, enabled: Option<bool>) -> Result<(), NodeCoreError> {
        self.send_authority
            .set_voip_enabled(enabled.unwrap_or_else(route_selection::voip_push_enabled))?;
        Ok(())
    }

    fn voip_enabled(&self) -> bool {
        self.send_authority.voip_enabled()
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
        self.replace_authority_snapshot(state)?;
        self.save_queue_state(state)
    }

    /// Persist queue/diagnostic state without overwriting independently published routes.
    /// # Errors
    /// Returns queue storage errors.
    pub fn save_queue_state(&self, state: &NotifyQueueState) -> Result<(), NodeCoreError> {
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

    fn load_bounded_state(&self) -> Result<NotifyQueueState, NodeCoreError> {
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(NOTIFY_QUEUE_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        match table
            .get(NOTIFY_QUEUE_KEY)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        {
            Some(snapshot) => deserialize_notify_bounded_snapshot(snapshot.value()),
            None => Ok(NotifyQueueState::new()),
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
            Some(snapshot) => deserialize_notify_bounded_snapshot(snapshot.value())?,
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
                let routes = routes::open(&self.route_key, key.value(), value.value())?;
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
        self.load_bounded_state()?;
        let mut routes = self.load_notify_routes(&route.device_delivery_id)?;
        routes.retain(|existing| {
            existing.provider != route.provider || existing.token != route.token
        });
        routes.push(route);
        self.record_notify_routes(&routes)
    }

    /// # Errors
    /// Returns a closed mutation or storage error without publishing stale credentials.
    pub fn update_provider_credential(
        &self,
        credential: &ProviderCredential,
    ) -> Result<(), NodeCoreError> {
        self.load_bounded_state()?;
        self.record_notify_credential(credential)
    }

    /// Stop a wake, including one that has not been queued yet.
    ///
    /// An attempt that already left this process is not recalled. The tombstone
    /// reaches the ledger, the decoded queue, and every raw WAL shard.
    ///
    /// # Errors
    /// Returns an error when the ledger, queue, or WAL cannot be written.
    pub fn cancel_pending_wake(&self, wake_id: &str) -> Result<(), NodeCoreError> {
        let target = self.send_authority.wake_target(wake_id)?;
        let root = target.as_deref().map(wake_admission::target_root).transpose()?;
        self.send_authority.close_wake(wake_id)?;
        self.tombstone_wake_id(wake_id, root.as_deref())?;
        if let Some(shards) = &self.wal_shards {
            if let Some(target) = target {
                shards
                    .get(self.notify_ingest_shard_for_key(&target))
                    .ok_or(crate::send_authority::SendAuthorityError::Invalid)?
                    .store
                    .tombstone_wake(wake_id)?;
            } else {
                for shard in shards {
                    shard.store.tombstone_wake(wake_id)?;
                }
            }
        }
        self.cancel_decoded_queue(wake_id)
    }

    fn cancel_decoded_queue(&self, wake_id: &str) -> Result<(), NodeCoreError> {
        // Queue rows live in the incremental table. The bounded snapshot does not.
        let (state, _incremental) = self.load_state_with_incremental_flag()?;
        let Some(mut state) = state else {
            return Ok(());
        };
        let Some(entry) = state.entries_by_id.get_mut(wake_id) else {
            return Ok(());
        };
        if entry.status != NotifyQueueStatus::Pending {
            return Ok(());
        }
        entry.status = NotifyQueueStatus::DroppedExpired;
        let entry = entry.clone();
        self.commit_writer
            .commit(NotifyCommitOp::QueueEntry { entry: Box::new(entry), bounded_state: None })?;
        Ok(())
    }

    /// Retain an authenticated cancel-before-enqueue inside its recipient's bounded share.
    /// # Errors
    /// Capacity and persistence failures keep the wake closed without acknowledging a tombstone.
    pub fn cancel_signed_wake(
        &self,
        signed: &ramflux_protocol::SignedWakeV2,
    ) -> Result<(), NodeCoreError> {
        self.send_authority.close_wake(&signed.body.wake_id)?;
        let _writer = self
            .local_writer
            .try_lock()
            .map_err(|_| crate::send_authority::SendAuthorityError::Busy)?;
        let root = self.wake_root(&signed.body.target_delivery_id)?;
        self.tombstone_wake_id(&signed.body.wake_id, Some(&root))?;
        if let Some(shards) = &self.wal_shards {
            shards
                .get(self.notify_ingest_shard_for_key(&signed.body.target_delivery_id))
                .ok_or(crate::send_authority::SendAuthorityError::Invalid)?
                .store
                .tombstone_wake(&signed.body.wake_id)?;
        }
        self.cancel_decoded_queue(&signed.body.wake_id)
    }

    /// Drops every pending notification that is not a current `WakeV2`.
    ///
    /// Pre-upgrade snapshots, incremental rows, decoded queue rows, and raw WAL
    /// bodies are removed. A surviving row keeps the expiry it was admitted with.
    /// This store is not the durable message inbox; that database is not opened.
    ///
    /// # Errors
    /// Returns an error when the queue or WAL cannot be read or written.
    pub fn drop_legacy_pending_wakes(&self) -> Result<usize, NodeCoreError> {
        let mut dropped = 0_usize;
        if let Some(shards) = &self.wal_shards {
            for shard in shards {
                dropped = dropped.saturating_add(shard.store.drop_legacy_wakes()?);
            }
        }
        let Some(mut state) = self.load_state()? else {
            return Ok(dropped);
        };
        let legacy_ids: Vec<String> = state
            .entries_by_id
            .iter()
            .filter(|(_, entry)| !crate::notify_wal::notification_wake_is_current_v2(&entry.wake))
            .map(|(queue_id, _)| queue_id.clone())
            .collect();
        if legacy_ids.is_empty() {
            return Ok(dropped);
        }
        for queue_id in &legacy_ids {
            state.entries_by_id.remove(queue_id);
            state.provider_attempts_by_queue.remove(queue_id);
        }
        self.save_queue_state(&state)?;
        Ok(dropped.saturating_add(legacy_ids.len()))
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
        let mut state = self.load_bounded_state()?;
        let normalized_wake = normalized_notification_wake(wake, device_delivery_id);
        let push_alias_hash = notification_hash(
            "ramflux.notification.push_alias_hash.v1",
            normalized_wake.push_alias.as_bytes(),
        );
        if let Some(existing) = self.existing_queue_entry(&normalized_wake.wake_id)? {
            return Ok((existing, Vec::new()));
        }
        let entry = state.queue_wake_for_device(
            device_delivery_id,
            normalized_wake.clone(),
            push_alias_hash.clone(),
            queued_at,
            dnd_active,
        );
        if entry.status != NotifyQueueStatus::Pending {
            return Ok((entry, Vec::new()));
        }
        let routes = self
            .load_notify_routes(device_delivery_id)?
            .into_iter()
            .filter(|route| route.expires_at > now_unix_seconds())
            .collect::<Vec<_>>();
        // All routes share the target's owner binding: one authority check per wake.
        let routes: Vec<DevicePushRoute> =
            if routes.is_empty() || self.authorize_push_route(device_delivery_id)? {
                routes
            } else {
                Vec::new()
            };
        let mut credential_cache: BTreeMap<String, ProviderCredential> = BTreeMap::new();
        let routes = route_selection::select_wake_routes(
            routes,
            &normalized_wake.delivery_class,
            self.voip_enabled(),
            |route| {
                self.provider_credential_for_route(&mut credential_cache, route).is_ok_and(
                    |credential| credential.provider_kind() == PushProviderKind::ApnsVoip,
                )
            },
        );
        let mut pushes = Vec::new();
        let mut deferred_changed = false;
        for route in routes {
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
            let credential = self.provider_credential_for_route(&mut credential_cache, &route)?;
            self.record_notify_rate_event(
                push_alias_hash.clone(),
                route.provider.clone(),
                queued_at,
            )?;
            pushes.push(self.finish_prepared_push(route, credential, &entry, action)?);
        }
        self.charge_prepared_work(&entry.queue_id, &pushes)?;
        self.commit_writer.commit(NotifyCommitOp::QueueEntry {
            entry: Box::new(entry.clone()),
            bounded_state: deferred_changed.then_some(Box::new(state)),
        })?;
        Ok((entry, pushes))
    }

    fn existing_queue_entry(
        &self,
        queue_id: &str,
    ) -> Result<Option<NotifyQueueEntry>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        let table = tx
            .open_table(NOTIFY_QUEUE_ENTRY_TABLE)
            .map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        if let Some(value) =
            table.get(queue_id).map_err(|error| NodeCoreError::Redb(error.to_string()))?
        {
            return deserialize_notify_queue_entry(value.value()).map(Some);
        }
        drop(table);
        drop(tx);
        if let Some(shards) = &self.wal_shards {
            for shard in shards {
                if let Some(entry) = shard.store.queue_entry(queue_id)? {
                    return Ok(Some(entry));
                }
            }
        }
        Ok(None)
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
        if let Some(existing) = self.existing_queue_entry(&wake.wake_id)? {
            return Ok(existing);
        }
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
        if let Some(existing) = self.existing_queue_entry(&wake.wake_id)? {
            return Ok(existing);
        }
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
        let raw = self.prepare_raw_wake(shard_id, &shard.store, raw_body, queued_at)?;
        if shard.store.enqueue_raw_once_async(raw.clone()).await? {
            return Ok(raw);
        }
        Ok(raw)
    }

    /// Check-and-insert one signed wake. `Ok(None)` is terminal. `Ok(Some(deadline))`
    /// is the first persisted effective expiry and is not recomputed on replay.
    ///
    /// # Errors
    /// Returns an error when the digest cannot be computed or the ledger cannot be written.
    /// A conflicting reuse of the same wake id is `InvalidConfiguration`.
    pub fn claim_signed_wake(
        &self,
        signed: &ramflux_protocol::SignedWakeV2,
        effective_expires_at: u64,
    ) -> Result<Option<u64>, NodeCoreError> {
        let clock = self.send_authority.capture_wake_clock()?;
        let _writer = self
            .local_writer
            .try_lock()
            .map_err(|_| crate::send_authority::SendAuthorityError::Busy)?;
        let digest = ramflux_protocol::wake_request_digest(signed).map_err(|_source| {
            NodeCoreError::InvalidConfiguration("wake contract rejected".to_owned())
        })?;
        let key = signed.body.wake_id.clone();
        let root = wake_admission::target_root(&signed.body.target_delivery_id)?;
        let existing = self.load_wake_ledger_row(&key)?;
        if existing.as_ref().is_some_and(|row| row.terminal) {
            return Ok(None);
        }
        let pending = wake_admission::read(&self.db, &root, &key)?;
        if let Some(row) = &existing
            && !row.terminal
            && (row.digest != digest
                || row.audience != signed.body.audience
                || row.target_owner_epoch != signed.body.target_owner_epoch)
        {
            return Err(NodeCoreError::InvalidConfiguration("wake dedup conflict".into()));
        }
        let first = existing.is_none();
        if first {
            self.local_call_mapping(signed)?;
            if signed.body.call_intent_digest.is_none() {
                self.wake_root(&signed.body.target_delivery_id)?;
            }
        }
        let rehydrate_message = signed.body.call_intent_digest.is_none()
            && existing.as_ref().is_some_and(|row| !row.terminal)
            && self.send_authority.wake_deadline(&key, &digest).is_err();
        let effective_expires_at = if first || rehydrate_message {
            self.send_authority.admit_wake_at(
                crate::send_authority::WakeAdmission {
                    wake_id: &key,
                    digest: &digest,
                    target: &signed.body.target_delivery_id,
                    owner_epoch: signed.body.target_owner_epoch,
                    start: signed.body.call_intent_digest.as_deref(),
                    expiry: existing.as_ref().map_or_else(
                        || pending.as_ref().map_or(effective_expires_at, |row| row.expiry),
                        |row| row.effective_expires_at,
                    ),
                },
                clock,
            )?
        } else {
            effective_expires_at
        };
        if first
            && let Err(error) = self.reserve_pending_wake(
                &root,
                &key,
                &digest,
                signed.body.call_intent_digest.as_deref(),
                effective_expires_at,
            )
        {
            self.send_authority.discard_unfunded_wake(&key)?;
            return Err(error);
        }
        let mapping = if first { self.verified_call_mapping(signed)? } else { None };
        self.persist_wake_claim(signed, &digest, mapping.as_ref(), effective_expires_at)
    }

    fn persist_wake_claim(
        &self,
        signed: &ramflux_protocol::SignedWakeV2,
        digest: &str,
        mapping: Option<&send_gate::WakeMapping>,
        effective_expires_at: u64,
    ) -> Result<Option<u64>, NodeCoreError> {
        let key = signed.body.wake_id.clone();
        let root = wake_admission::target_root(&signed.body.target_delivery_id)?;
        let now = now_unix_seconds();
        let wire_bytes = ramflux_protocol::canonical_json_bytes(signed)
            .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?
            .len();
        if wire_bytes > 8192 {
            return Err(crate::send_authority::SendAuthorityError::Capacity.into());
        }
        let recipient_root = match mapping {
            Some(map) => Some(map.root.clone()),
            None => Some(root.clone()),
        };
        let txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        wake_admission::remove(&txn, &root, &key)?;
        let deadline = {
            let mut table = txn
                .open_table(NOTIFY_WAKE_LEDGER)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let existing = ledger_row(&table, &key)?;
            let (row, deadline) = match existing {
                Some(row) if row.terminal => (row, None),
                Some(row)
                    if row.digest == *digest
                        && row.audience == signed.body.audience
                        && row.target_owner_epoch == signed.body.target_owner_epoch =>
                {
                    let deadline = row.effective_expires_at;
                    (row, Some(deadline))
                }
                Some(_row) => {
                    return Err(NodeCoreError::InvalidConfiguration(
                        "wake dedup conflict".to_owned(),
                    ));
                }
                None => {
                    let row = WakeLedgerRow {
                        work_bytes: u64::try_from(
                            2 * wire_bytes + signed.body.target_delivery_id.len() + 8192,
                        )
                        .map_err(|_| crate::send_authority::SendAuthorityError::Capacity)?,
                        recipient_root,
                        call_generation: mapping.as_ref().map(|map| map.generation),
                        authority_boot: self.send_authority.boot().into(),
                        start_digest: signed.body.call_intent_digest.clone(),
                        audience: signed.body.audience.clone(),
                        target_owner_epoch: signed.body.target_owner_epoch,
                        digest: digest.to_owned(),
                        effective_expires_at,
                        terminal: false,
                        sent: false,
                        retain_until: ledger_retain_until(effective_expires_at, now),
                        boot_id: notify_boot_id(),
                        admitted_unix: now,
                    };
                    (row, Some(effective_expires_at))
                }
            };
            if row.start_digest.is_some() && row.authority_boot != self.send_authority.boot() {
                return Err(crate::send_authority::SendAuthorityError::Closed.into());
            }
            Self::charge_wake_row(&txn, &key, &row)?;
            Self::charge_wake_work(&txn, &key, &row, &[])?;
            write_ledger_row(&txn, &mut table, &key, &row)?;
            deadline
        };
        self.send_authority.persist_clock(&txn)?;
        txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        if deadline.is_some() {
            self.send_authority.commit_wake_claim(&key, digest, false)?;
        }
        Ok(deadline)
    }

    fn tombstone_wake_id(&self, wake_id: &str, root: Option<&str>) -> Result<(), NodeCoreError> {
        let now = now_unix_seconds();
        let pending =
            root.map(|root| wake_admission::read(&self.db, root, wake_id)).transpose()?.flatten();
        let txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        if let Some(root) = root {
            wake_admission::remove(&txn, root, wake_id)?;
        }
        {
            let mut table = txn
                .open_table(NOTIFY_WAKE_LEDGER)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let mut row = ledger_row(&table, wake_id)?.unwrap_or(WakeLedgerRow {
                work_bytes: 0,
                recipient_root: root.map(str::to_owned),
                call_generation: None,
                authority_boot: self.send_authority.boot().into(),
                start_digest: pending.as_ref().and_then(|row| row.start.clone()),
                audience: String::new(),
                target_owner_epoch: 0,
                digest: String::new(),
                effective_expires_at: 0,
                terminal: true,
                sent: false,
                retain_until: ledger_retain_until(0, now),
                boot_id: 0,
                admitted_unix: 0,
            });
            row.terminal = true;
            Self::charge_wake_row(&txn, wake_id, &row)?;
            write_ledger_row(&txn, &mut table, wake_id, &row)?;
        }
        txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// The signed wake is terminal, already handed to a provider, or past its deadline.
    ///
    /// # Errors
    /// Returns an error when the ledger cannot be read.
    pub fn wake_send_blocked(&self, wake_id: &str, now: u64) -> Result<bool, NodeCoreError> {
        self.ledger_blocks(wake_id, now, true)
    }

    fn ledger_blocks(
        &self,
        wake_id: &str,
        now: u64,
        sent_blocks: bool,
    ) -> Result<bool, NodeCoreError> {
        let txn = self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = match txn.open_table(NOTIFY_WAKE_LEDGER) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(source) => return Err(NodeCoreError::Redb(source.to_string())),
        };
        let Some(row) = ledger_row(&table, wake_id)? else {
            return Ok(false);
        };
        Ok(row.terminal
            || (sent_blocks && row.sent)
            || (row.effective_expires_at != 0 && now >= row.effective_expires_at))
    }

    /// Mark one reserved wake as sent. A second caller gets `false` and must not send.
    ///
    /// A wake that was never reserved (tests and unsigned fixtures) is allowed through.
    ///
    /// # Errors
    /// Returns an error when the ledger cannot be updated.
    pub fn begin_wake_send(&self, wake_id: &str) -> Result<bool, NodeCoreError> {
        let txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let allowed = {
            let mut table = txn
                .open_table(NOTIFY_WAKE_LEDGER)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let Some(mut row) = ledger_row(&table, wake_id)? else {
                return Ok(true);
            };
            if row.terminal || row.sent {
                false
            } else {
                row.sent = true;
                write_ledger_row(&txn, &mut table, wake_id, &row)?;
                true
            }
        };
        if allowed {
            txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        if allowed {
            self.send_authority.claim_attempt(wake_id)?;
        }
        Ok(allowed)
    }

    /// Delete ledger rows whose retain horizon has passed.
    ///
    /// # Errors
    /// Returns an error when the ledger cannot be read or written.
    pub fn prune_wake_ledger(&self, now: u64) -> Result<usize, NodeCoreError> {
        let now = self.send_authority.retention_clock(now)?;
        self.prune_wake_copies(now)?;
        let txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let removed = wake_admission::prune(&txn, now)? + {
            let mut table = txn
                .open_table(NOTIFY_WAKE_LEDGER)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            prune_open_ledger(&txn, &mut table, now)?
        };
        txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(removed)
    }

    fn load_wake_ledger_row(&self, wake_id: &str) -> Result<Option<WakeLedgerRow>, NodeCoreError> {
        let txn = self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = match txn.open_table(NOTIFY_WAKE_LEDGER) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(source) => return Err(NodeCoreError::Redb(source.to_string())),
        };
        ledger_row(&table, wake_id)
    }

    fn prepare_raw_wake(
        &self,
        shard_id: usize,
        wal: &NotifyWalStore,
        raw_body: Vec<u8>,
        admission_now: u64,
    ) -> Result<NotifyWalRawWake, NodeCoreError> {
        if let Some(signed) = signed_wake_from_raw(&raw_body) {
            let queue_id = signed.body.wake_id.clone();
            if signed.body.action == ramflux_protocol::WakeAction::Cancel {
                self.cancel_signed_wake(&signed)?;
                wal.tombstone_wake(&queue_id)?;
                return Ok(NotifyWalRawWake {
                    queue_id,
                    raw_body,
                    queued_at: admission_now,
                    effective_expires_at: 0,
                });
            }
            if wal.wake_is_closed(&queue_id) {
                return Ok(closed_raw(queue_id, raw_body, admission_now));
            }
            let projected = project_wake_v2(&signed, admission_now).map_err(|_source| {
                NodeCoreError::InvalidConfiguration("wake contract rejected".to_owned())
            })?;
            let Some(deadline) = self.claim_signed_wake(&signed, projected.absolute_expires_at)?
            else {
                wal.tombstone_wake(&queue_id)?;
                return Ok(closed_raw(queue_id, raw_body, admission_now));
            };
            return Ok(NotifyWalRawWake {
                queue_id,
                raw_body,
                queued_at: admission_now,
                effective_expires_at: deadline,
            });
        }
        let sequence = self.wal_shard(shard_id)?.raw_wake_sequence.fetch_add(1, Ordering::Relaxed);
        Ok(NotifyWalRawWake {
            queue_id: notify_raw_wake_queue_id(shard_id, admission_now, sequence),
            raw_body,
            queued_at: admission_now,
            effective_expires_at: 0,
        })
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
        let mut fresh = Vec::new();
        for (raw_body, queued_at) in raw_bodies {
            let raw = self.prepare_raw_wake(shard_id, &shard.store, raw_body, queued_at)?;
            if !shard.store.wake_is_closed(&raw.queue_id) {
                fresh.push(raw.clone());
            }
            raws.push(raw);
        }
        if !fresh.is_empty() {
            shard.store.record_raw_wakes_batch(fresh)?;
        }
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
        if raw.effective_expires_at == 0 {
            return Err(NodeCoreError::InvalidConfiguration("wake contract rejected".to_owned()));
        }
        let request: RawS13WakeRequest = ramflux_protocol::parse_i_json(&raw.raw_body)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        let queued_at = raw.queued_at;
        if request.signed_wake.body.target_delivery_id != request.device_delivery_id {
            return Err(NodeCoreError::InvalidConfiguration("wake contract rejected".to_owned()));
        }
        let clock = raw.effective_expires_at.saturating_sub(1);
        let mut projected = project_wake_v2(&request.signed_wake, clock).map_err(|_source| {
            NodeCoreError::InvalidConfiguration("wake contract rejected".to_owned())
        })?;
        // Replay keeps the deadline persisted at admission. Queue time is not an input.
        projected.absolute_expires_at = raw.effective_expires_at;
        let normalized_wake = normalized_notification_wake(&projected, &request.device_delivery_id);
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

    /// Build one provider push. Messages carry the device collapse key. Calls omit it.
    /// The signed wake is not mutated.
    ///
    /// # Errors
    /// Returns an error when the collapse MAC cannot be initialized.
    fn finish_prepared_push(
        &self,
        route: DevicePushRoute,
        credential: ProviderCredential,
        entry: &NotifyQueueEntry,
        action: NotifyDeliveryAction,
    ) -> Result<PreparedProviderPush, NodeCoreError> {
        let collapse = if matches!(
            entry.wake.delivery_class,
            ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        ) {
            None
        } else {
            Some(self.route_key.device_collapse_key(&route.device_delivery_id)?)
        };
        let collapse_key_hash = collapse.clone().unwrap_or_default();
        let route_provider = route.provider.clone();
        let admitted = self.admission_stamp(&entry.wake.wake_id, &route.device_delivery_id)?;
        Ok(PreparedProviderPush {
            route,
            credential,
            payload: ProviderPushPayload {
                wake_id: entry.wake.wake_id.clone(),
                provider: route_provider,
                delivery_class: entry.wake.delivery_class.clone(),
                priority: entry.wake.priority.clone(),
                ttl: entry.wake.ttl,
                collapse_key: collapse,
                encrypted_hint: None,
            },
            push_alias_hash: entry.push_alias_hash.clone(),
            collapse_key_hash,
            action,
            expires_at: entry.expires_at,
            admitted_unix: admitted.admitted_unix,
            boot_id: admitted.boot_id,
            owner_epoch: admitted.owner_epoch,
        })
    }

    /// Copy the signed claim when one exists. A missing row is stamped now.
    /// A stored boot of zero is left zero so a call fails closed.
    fn admission_stamp(
        &self,
        wake_id: &str,
        device_delivery_id: &str,
    ) -> Result<AdmissionStamp, NodeCoreError> {
        if let Some(row) = self.load_wake_ledger_row(wake_id)? {
            return Ok(AdmissionStamp {
                owner_epoch: row.target_owner_epoch,
                boot_id: row.boot_id,
                admitted_unix: row.admitted_unix,
            });
        }
        Ok(AdmissionStamp {
            owner_epoch: self.current_owner_epoch(device_delivery_id)?,
            boot_id: notify_boot_id(),
            admitted_unix: now_unix_seconds(),
        })
    }

    /// Live check immediately before a provider request, including every retry.
    ///
    /// Calls fail closed on clock rollback and on a different process boot.
    /// An expired, terminal, or rotated route is not sent.
    ///
    /// # Errors
    /// Returns an error when the ledger or the route store cannot be read.
    pub fn provider_send_still_allowed(
        &self,
        prepared: &PreparedProviderPush,
        now: u64,
    ) -> Result<bool, NodeCoreError> {
        if prepared.expires_at == 0 || now >= prepared.expires_at {
            return Ok(false);
        }
        let call = matches!(
            prepared.payload.delivery_class,
            ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        );
        if call
            && (prepared.boot_id != notify_boot_id()
                || (prepared.admitted_unix != 0 && now < prepared.admitted_unix))
        {
            return Ok(false);
        }
        // `sent` stays false here: this check runs on the send that already claimed the row.
        if self.ledger_blocks(&prepared.payload.wake_id, now, false)? {
            return Ok(false);
        }
        if !self.authorize_push_route(&prepared.route.device_delivery_id)? {
            return Ok(false);
        }
        let live_epoch = self.current_owner_epoch(&prepared.route.device_delivery_id)?;
        if live_epoch != 0 && prepared.owner_epoch != 0 && live_epoch != prepared.owner_epoch {
            return Ok(false);
        }
        self.load_bounded_state()?;
        let routes = self.load_notify_routes(&prepared.route.device_delivery_id)?;
        let Some(live) = routes.into_iter().find(|route| {
            route.provider == prepared.route.provider
                && route.token == prepared.route.token
                && route.route_generation == prepared.route.route_generation
                && route.expires_at > now
        }) else {
            return Ok(false);
        };
        self.credential_still_current(prepared, &live)
    }

    fn credential_still_current(
        &self,
        prepared: &PreparedProviderPush,
        live: &DevicePushRoute,
    ) -> Result<bool, NodeCoreError> {
        if live.credential_id.is_none()
            || live.credential_id.as_deref() != prepared.route.credential_id.as_deref()
        {
            return Ok(false);
        }
        let mut cache = BTreeMap::new();
        match self.provider_credential_for_route(&mut cache, live) {
            Ok(credential) => Ok(credential == prepared.credential),
            Err(NodeCoreError::ItestJson(_)) => Ok(false),
            Err(error) => Err(error),
        }
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
        self.load_bounded_state()?;
        let routes = self
            .load_notify_routes(&entry.device_delivery_id)?
            .into_iter()
            .filter(|route| route.expires_at > now_unix_seconds())
            .collect::<Vec<_>>();
        let routes: Vec<DevicePushRoute> =
            if routes.is_empty() || self.authorize_push_route(&entry.device_delivery_id)? {
                routes
            } else {
                Vec::new()
            };
        let mut credential_cache: BTreeMap<String, ProviderCredential> = BTreeMap::new();
        let routes = route_selection::select_wake_routes(
            routes,
            &entry.wake.delivery_class,
            self.voip_enabled(),
            |route| {
                self.provider_credential_for_route(&mut credential_cache, route).is_ok_and(
                    |credential| credential.provider_kind() == PushProviderKind::ApnsVoip,
                )
            },
        );
        let mut pushes = Vec::new();
        for route in routes {
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
            let credential = self.provider_credential_for_route(&mut credential_cache, &route)?;
            self.record_notify_rate_event(
                entry.push_alias_hash.clone(),
                route.provider.clone(),
                entry.queued_at,
            )?;
            pushes.push(self.finish_prepared_push(route, credential, entry, action)?);
        }
        self.charge_prepared_work(&entry.queue_id, &pushes)?;
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
        credential_cache: &mut BTreeMap<String, ProviderCredential>,
        route: &DevicePushRoute,
    ) -> Result<ProviderCredential, NodeCoreError> {
        let credential_id = route.credential_id.as_deref().ok_or_else(|| {
            NodeCoreError::ItestJson(format!(
                "missing provider credential for {}",
                route.device_delivery_id
            ))
        })?;
        let credential = {
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
        if self
            .load_wake_ledger_row(&attempt.queue_id)?
            .is_some_and(|row| row.start_digest.is_some())
        {
            if let Some(shards) = &self.wal_shards {
                let index = self
                    .wal_shard_index_for_queue_id(&attempt.queue_id)
                    .ok_or(crate::send_authority::SendAuthorityError::Invalid)?;
                shards
                    .get(index)
                    .ok_or(crate::send_authority::SendAuthorityError::Invalid)?
                    .store
                    .mark_delivered(attempt.queue_id)?;
            } else {
                let tx = self.db.begin_write().map_err(|e| NodeCoreError::Redb(e.to_string()))?;
                let mut table = tx
                    .open_table(NOTIFY_QUEUE_ENTRY_TABLE)
                    .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
                let bytes = table
                    .get(attempt.queue_id.as_str())
                    .map_err(|e| NodeCoreError::Redb(e.to_string()))?
                    .map(|v| v.value().to_vec());
                if let Some(bytes) = bytes {
                    let mut entry = deserialize_notify_queue_entry(&bytes)?;
                    entry.status = if attempt.accepted {
                        NotifyQueueStatus::Delivered
                    } else {
                        NotifyQueueStatus::ProviderRejected
                    };
                    table
                        .insert(
                            attempt.queue_id.as_str(),
                            serialize_notify_queue_entry_binary(&entry)?.as_slice(),
                        )
                        .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
                }
                drop(table);
                tx.commit().map_err(|e| NodeCoreError::Redb(e.to_string()))?;
            }
            return Ok(());
        }
        self.charge_provider_diagnostic(&attempt)?;
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
        entry: Option<&NotifyQueueEntry>,
        attempt: Option<&ProviderPushAttempt>,
    ) -> Result<(), NodeCoreError> {
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            if let Some(entry) = entry {
                let entry_bytes = serialize_notify_value(entry)?;
                write_txn
                    .open_table(NOTIFY_QUEUE_ENTRY_TABLE)
                    .map_err(|e| NodeCoreError::Redb(e.to_string()))?
                    .insert(entry.queue_id.as_str(), entry_bytes.as_slice())
                    .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
            }
            if let Some(attempt) = attempt {
                let attempt_bytes = serialize_notify_value(attempt)?;
                write_txn
                    .open_table(NOTIFY_PROVIDER_ATTEMPT_TABLE)
                    .map_err(|e| NodeCoreError::Redb(e.to_string()))?
                    .insert("legacy_json_attempt", attempt_bytes.as_slice())
                    .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
            }
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    fn record_notify_routes(&self, routes: &[DevicePushRoute]) -> Result<(), NodeCoreError> {
        let _writer = self
            .local_writer
            .try_lock()
            .map_err(|_| crate::send_authority::SendAuthorityError::Busy)?;
        let Some(device_delivery_id) =
            routes.first().map(|route| route.device_delivery_id.as_str())
        else {
            return Ok(());
        };
        let routes_bytes = routes::seal(&self.route_key, device_delivery_id, routes)?;
        self.resume_local_mutation(&crate::send_authority::AuthorityScope::TargetRoutes {
            target_delivery_id: device_delivery_id.into(),
        })?;
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
        self.commit_route_transaction(write_txn, device_delivery_id)
    }

    fn record_notify_credential(
        &self,
        credential: &ProviderCredential,
    ) -> Result<(), NodeCoreError> {
        let _writer = self
            .local_writer
            .try_lock()
            .map_err(|_| crate::send_authority::SendAuthorityError::Busy)?;
        let credential_bytes = serialize_notify_value(credential)?;
        self.resume_local_mutation(&crate::send_authority::AuthorityScope::Credential {
            credential_id: credential.credential_id().into(),
        })?;
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
        self.commit_credential_transaction(write_txn, credential.credential_id())
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
            Some(routes) => routes::open(&self.route_key, device_delivery_id, routes.value()),
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
            Self::Apns(credential) => {
                if apns_topic_is_voip(&credential.topic) {
                    PushProviderKind::ApnsVoip
                } else {
                    PushProviderKind::Apns
                }
            }
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
        ramflux_protocol::NotificationDeliveryClass::UserContentNotification
        | ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification => 86_400,
        ramflux_protocol::NotificationDeliveryClass::AiTaskNotification => 1_800,
        ramflux_protocol::NotificationDeliveryClass::A2uiSurfaceNotification => 600,
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification => 30,
    }
}

#[must_use]
pub fn notification_default_priority(
    delivery_class: &ramflux_protocol::NotificationDeliveryClass,
    requested: &ramflux_protocol::PushPriority,
) -> ramflux_protocol::PushPriority {
    match delivery_class {
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification => {
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
        | ramflux_protocol::NotificationDeliveryClass::A2uiSurfaceNotification
        | ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification => {
            ramflux_protocol::PushPriority::Normal
        }
    }
}

#[must_use]
pub fn normalized_notification_wake(
    wake: &ramflux_protocol::NotificationWake,
    _target_device_id: &str,
) -> ramflux_protocol::NotificationWake {
    let mut normalized = wake.clone();
    let default_ttl = notification_default_ttl(&normalized.delivery_class);
    normalized.ttl =
        if normalized.ttl == 0 { default_ttl } else { normalized.ttl.min(default_ttl) };
    normalized.priority =
        notification_default_priority(&normalized.delivery_class, &normalized.priority);
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
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification => {
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
    let (value, trailing) = postcard::take_from_bytes(bytes)
        .map_err(|_| NodeCoreError::UnsupportedPersistedFormat("notify binary row"))?;
    if !trailing.is_empty() {
        return Err(NodeCoreError::UnsupportedPersistedFormat("notify binary row"));
    }
    Ok(value)
}

fn deserialize_notify_queue_entry(bytes: &[u8]) -> Result<NotifyQueueEntry, NodeCoreError> {
    let stored: StoredNotifyQueueEntry = deserialize_notify_hot_value(bytes)?;
    stored.try_into()
}

fn deserialize_notify_bounded_snapshot(bytes: &[u8]) -> Result<NotifyQueueState, NodeCoreError> {
    let state: NotifyQueueState = serde_json::from_slice(bytes)
        .map_err(|_| NodeCoreError::UnsupportedPersistedFormat("notify bounded snapshot"))?;
    if state != notify_bounded_snapshot(&state) {
        return Err(NodeCoreError::UnsupportedPersistedFormat("notify full snapshot"));
    }
    Ok(state)
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
    crate::environment::var(NOTIFY_WAL_ENABLED_ENV).map_or(true, |value| {
        let trimmed = value.trim();
        !(trimmed == "0"
            || trimmed.eq_ignore_ascii_case("false")
            || trimmed.eq_ignore_ascii_case("off")
            || trimmed.eq_ignore_ascii_case("no"))
    })
}

fn notify_wal_root_for_redb_path(redb_path: &Path) -> PathBuf {
    if let Ok(path) = crate::environment::var(NOTIFY_WAL_DIR_ENV)
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
    crate::environment::parsed::<usize>(name).filter(|value| *value > 0).unwrap_or(default)
}

fn notify_u64_env(name: &str, default: u64) -> u64 {
    crate::environment::parsed::<u64>(name).filter(|value| *value > 0).unwrap_or(default)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WakeLedgerRow {
    work_bytes: u64,
    #[serde(deserialize_with = "crate::send_authority::required_nullable")]
    recipient_root: Option<String>,
    #[serde(deserialize_with = "crate::send_authority::required_nullable")]
    call_generation: Option<u64>,
    authority_boot: String,
    #[serde(deserialize_with = "crate::send_authority::required_nullable")]
    start_digest: Option<String>,
    audience: String,
    target_owner_epoch: u64,
    digest: String,
    effective_expires_at: u64,
    terminal: bool,
    #[serde(default)]
    sent: bool,
    /// Immutable nonzero expiry of this ledger row.
    retain_until: u64,
    boot_id: u64,
    admitted_unix: u64,
}

struct AdmissionStamp {
    owner_epoch: u64,
    boot_id: u64,
    admitted_unix: u64,
}

fn ledger_retain_until(effective_expires_at: u64, now: u64) -> u64 {
    let skew = ramflux_protocol::CLOCK_UNCERTAINTY_SECONDS;
    if effective_expires_at == 0 {
        now.saturating_add(ramflux_protocol::MESSAGE_MAX_LIFETIME_SECONDS).saturating_add(skew)
    } else {
        effective_expires_at.saturating_add(skew)
    }
}

fn initialize_wake_state_format(db: &redb::Database) -> Result<(), NodeCoreError> {
    let tx = db.begin_read().map_err(|e| NodeCoreError::Redb(e.to_string()))?;
    let marker = match tx.open_table(NOTIFY_WAKE_FORMAT) {
        Ok(table) => table
            .get("notify_wake_state_format")
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?
            .map(|v| v.value()),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(NodeCoreError::Redb(e.to_string())),
    };
    if marker == Some(1) {
        tx.open_table(NOTIFY_WAKE_DUE).map_err(|_| NodeCoreError::NotifyWakeStateResetRequired)?;
        if let Ok(table) = tx.open_table(NOTIFY_WAKE_LEDGER) {
            for entry in table.iter().map_err(|e| NodeCoreError::Redb(e.to_string()))? {
                let (key, _) = entry.map_err(|e| NodeCoreError::Redb(e.to_string()))?;
                ledger_row(&table, key.value())?;
            }
        }
        return Ok(());
    }
    if marker.is_some() || tx.open_table(NOTIFY_WAKE_LEDGER).is_ok() {
        return Err(NodeCoreError::NotifyWakeStateResetRequired);
    }
    drop(tx);
    let tx = db.begin_write().map_err(|e| NodeCoreError::Redb(e.to_string()))?;
    {
        tx.open_table(NOTIFY_WAKE_FORMAT)
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?
            .insert("notify_wake_state_format", 1)
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
        tx.open_table(NOTIFY_WAKE_DUE).map_err(|e| NodeCoreError::Redb(e.to_string()))?;
    }
    tx.commit().map_err(|e| NodeCoreError::Redb(e.to_string()))
}

fn prune_open_ledger(
    txn: &redb::WriteTransaction,
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
    now: u64,
) -> Result<usize, NodeCoreError> {
    let mut due =
        txn.open_table(NOTIFY_WAKE_DUE).map_err(|e| NodeCoreError::Redb(e.to_string()))?;
    let candidates = due
        .iter()
        .map_err(|e| NodeCoreError::Redb(e.to_string()))?
        .take(NOTIFY_WAKE_CLEANUP_LIMIT)
        .map(|row| {
            row.map(|(key, _)| (key.value().0, key.value().1.to_owned()))
                .map_err(|e| NodeCoreError::Redb(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut removed = 0;
    for (until, key) in candidates {
        if until > now {
            break;
        }
        if let Some(row) = ledger_row(table, &key)?
            && row.retain_until == until
        {
            send_gate::retire_wake_rows(txn, &key, &row)?;
            table.remove(key.as_str()).map_err(|e| NodeCoreError::Redb(e.to_string()))?;
            removed += 1;
        }
        due.remove((until, key.as_str())).map_err(|e| NodeCoreError::Redb(e.to_string()))?;
    }
    Ok(removed)
}

fn ledger_row(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<WakeLedgerRow>, NodeCoreError> {
    let Some(value) = table.get(key).map_err(|source| NodeCoreError::Redb(source.to_string()))?
    else {
        return Ok(None);
    };
    if value.value().len() > 8192 {
        return Err(NodeCoreError::NotifyWakeStateResetRequired);
    }
    let row: WakeLedgerRow = serde_json::from_slice(value.value())
        .map_err(|_| NodeCoreError::NotifyWakeStateResetRequired)?;
    if row.retain_until == 0 {
        return Err(NodeCoreError::NotifyWakeStateResetRequired);
    }
    Ok(Some(row))
}

fn write_ledger_row(
    txn: &redb::WriteTransaction,
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
    key: &str,
    row: &WakeLedgerRow,
) -> Result<(), NodeCoreError> {
    if row.retain_until == 0 {
        return Err(NodeCoreError::NotifyWakeStateResetRequired);
    }
    txn.open_table(NOTIFY_WAKE_DUE)
        .map_err(|e| NodeCoreError::Redb(e.to_string()))?
        .insert((row.retain_until, key), 0)
        .map_err(|e| NodeCoreError::Redb(e.to_string()))?;
    let bytes = serde_json::to_vec(row)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    table
        .insert(key, bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn closed_raw(queue_id: String, raw_body: Vec<u8>, admission_now: u64) -> NotifyWalRawWake {
    NotifyWalRawWake { queue_id, raw_body, queued_at: admission_now, effective_expires_at: 0 }
}

fn signed_wake_from_raw(body: &[u8]) -> Option<ramflux_protocol::SignedWakeV2> {
    let value = ramflux_protocol::parse_i_json::<serde_json::Value>(body).ok()?;
    let wake = value.get("signed_wake")?;
    let bytes = serde_json::to_vec(wake).ok()?;
    ramflux_protocol::parse_signed_wake_v2(&bytes).ok()
}

/// Process start. Calls admitted under another boot are not sent.
#[must_use]
pub fn notify_boot_id() -> u64 {
    static BOOT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BOOT.get_or_init(|| {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| u64::try_from(duration.as_nanos()).unwrap_or(1));
        let mixed = nanos ^ u64::from(std::process::id());
        if mixed == 0 { 1 } else { mixed }
    })
}
