// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{InboxEntry, NodeCoreError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
const ROUTER_WAL_COMMIT_WINDOW_US_DEFAULT: u64 = 1_000;
const ROUTER_WAL_QUEUE_CAPACITY_ENV: &str = "RAMFLUX_ROUTER_WAL_QUEUE_CAPACITY";
const ROUTER_WAL_QUEUE_CAPACITY_DEFAULT: usize = 65_536;
const ROUTER_WAL_MAGIC: &[u8] = b"ramflux-router-wal-v1\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouterWalRecordLocation {
    pub segment_id: u64,
    pub offset: u64,
    pub len: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouterWalPayload {
    Submission { replay_key: String, replay_expires_at: i64, entry: Option<Box<InboxEntry>> },
}

#[derive(Deserialize, Serialize)]
enum StoredRouterWalPayload {
    Submission {
        replay_key: String,
        replay_expires_at: i64,
        entry: Option<Box<StoredRouterWalInboxEntry>>,
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
            RouterWalPayload::Submission { replay_key, replay_expires_at, entry } => {
                Ok(Self::Submission {
                    replay_key: replay_key.clone(),
                    replay_expires_at: *replay_expires_at,
                    entry: entry
                        .as_ref()
                        .map(|entry| StoredRouterWalInboxEntry::try_from(entry.as_ref()))
                        .transpose()?
                        .map(Box::new),
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
                Ok(Self::Submission {
                    replay_key,
                    replay_expires_at,
                    entry: entry
                        .map(|entry| InboxEntry::try_from(*entry))
                        .transpose()?
                        .map(Box::new),
                })
            }
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
    pub location: RouterWalRecordLocation,
}

#[derive(Clone, Debug, Default)]
struct RouterWalState {
    submissions_by_replay_key: BTreeMap<String, RouterWalSubmissionRecord>,
}

impl RouterWalState {
    fn apply(&mut self, payload: RouterWalPayload, location: RouterWalRecordLocation) {
        match payload {
            RouterWalPayload::Submission { replay_key, replay_expires_at, entry } => {
                self.submissions_by_replay_key.insert(
                    replay_key.clone(),
                    RouterWalSubmissionRecord {
                        replay_key,
                        replay_expires_at,
                        entry: entry.map(|entry| *entry),
                        location,
                    },
                );
            }
        }
    }
}

pub struct RouterWalStore {
    state: Arc<Mutex<RouterWalState>>,
    writer: RouterWalWriter,
}

impl RouterWalStore {
    /// # Errors
    /// Returns an error when the WAL directory cannot be created, recovered, or opened.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)
            .map_err(|source| NodeCoreError::StoreDirectory { path: root.clone(), source })?;
        let segment_bytes =
            router_wal_u64_env(ROUTER_WAL_SEGMENT_BYTES_ENV, ROUTER_WAL_SEGMENT_BYTES_DEFAULT)
                .max(1024 * 1024);
        let recovered = recover_router_wal(&root)?;
        let next_segment_id = recovered.last_segment_id.unwrap_or(0);
        let writer_state = RouterWalWriterState::open(
            root,
            next_segment_id,
            recovered.current_offset,
            segment_bytes,
        )?;
        let state = Arc::new(Mutex::new(recovered.state));
        let writer = RouterWalWriter::start(writer_state, Arc::clone(&state))?;
        Ok(Self { state, writer })
    }

    /// # Errors
    /// Returns an error when the submission cannot be durably appended.
    pub fn record_submission(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
        entry: Option<&InboxEntry>,
    ) -> Result<RouterWalRecordLocation, NodeCoreError> {
        self.writer.append(RouterWalPayload::Submission {
            replay_key: replay_key.to_owned(),
            replay_expires_at,
            entry: entry.cloned().map(Box::new),
        })
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
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |state| state.submissions_by_replay_key.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct RouterWalWriter {
    sender: Option<mpsc::SyncSender<RouterWalAppendRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

struct RouterWalAppendRequest {
    payload: RouterWalPayload,
    reply: mpsc::SyncSender<Result<RouterWalRecordLocation, NodeCoreError>>,
}

impl RouterWalWriter {
    fn start(
        state: RouterWalWriterState,
        wal_state: Arc<Mutex<RouterWalState>>,
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
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let thread = thread::Builder::new()
            .name("ramflux-router-wal-writer".to_owned())
            .spawn(move || router_wal_writer_loop(state, &receiver, &wal_state, batch_max, window))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        Ok(Self { sender: Some(sender), thread: Some(thread) })
    }

    fn append(&self, payload: RouterWalPayload) -> Result<RouterWalRecordLocation, NodeCoreError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("router WAL writer stopped".to_owned()))?
            .send(RouterWalAppendRequest { payload, reply })
            .map_err(|source| {
                NodeCoreError::ItestJson(format!("router WAL writer stopped: {source}"))
            })?;
        response.recv().map_err(|source| {
            NodeCoreError::ItestJson(format!("router WAL append response closed: {source}"))
        })?
    }
}

impl Drop for RouterWalWriter {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

struct RouterWalWriterState {
    root: PathBuf,
    segment_bytes: u64,
    segment_id: u64,
    offset: u64,
    file: File,
}

impl RouterWalWriterState {
    fn open(
        root: PathBuf,
        segment_id: u64,
        offset: u64,
        segment_bytes: u64,
    ) -> Result<Self, NodeCoreError> {
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
        Ok(Self { root, segment_bytes, segment_id, offset, file })
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
                && self.offset.saturating_add(frame_len) > self.segment_bytes
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
        crate::record_router_save_commit_us(elapsed_us(sync_started));
        Ok(locations)
    }

    fn write_record(&mut self, encoded: &[u8]) -> Result<RouterWalRecordLocation, NodeCoreError> {
        let len = u32::try_from(encoded.len())
            .map_err(|_| NodeCoreError::ItestJson("router WAL record too large".to_owned()))?;
        let offset = self.offset;
        write_router_wal_record_to_file(&mut self.file, encoded)?;
        self.offset = self.offset.saturating_add(8 + u64::from(len));
        Ok(RouterWalRecordLocation { segment_id: self.segment_id, offset, len })
    }

    fn roll_segment(&mut self) -> Result<(), NodeCoreError> {
        self.segment_id = self.segment_id.saturating_add(1);
        let path = router_wal_segment_path(&self.root, self.segment_id);
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        self.file
            .write_all(ROUTER_WAL_MAGIC)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        self.offset = u64::try_from(ROUTER_WAL_MAGIC.len()).unwrap_or(0);
        Ok(())
    }
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

fn router_wal_ack_success(
    batch: Vec<RouterWalAppendRequest>,
    payloads: &[RouterWalPayload],
    locations: Vec<RouterWalRecordLocation>,
    wal_state: &Arc<Mutex<RouterWalState>>,
) {
    let update_result = wal_state.lock().map_err(|source| source.to_string()).map(|mut guard| {
        for (payload, location) in payloads.iter().cloned().zip(locations.iter().cloned()) {
            guard.apply(payload, location);
        }
    });
    match update_result {
        Ok(()) => {
            for (request, location) in batch.into_iter().zip(locations) {
                let _sent = request.reply.send(Ok(location));
            }
        }
        Err(error) => {
            for request in batch {
                let _sent = request.reply.send(Err(NodeCoreError::ItestJson(format!(
                    "router WAL index lock poisoned: {error}"
                ))));
            }
        }
    }
}

fn router_wal_ack_error(batch: Vec<RouterWalAppendRequest>, error: &NodeCoreError) {
    let message = error.to_string();
    for request in batch {
        let _sent = request.reply.send(Err(NodeCoreError::ItestJson(message.clone())));
    }
}

struct RouterWalRecovery {
    state: RouterWalState,
    last_segment_id: Option<u64>,
    current_offset: u64,
}

fn recover_router_wal(root: &Path) -> Result<RouterWalRecovery, NodeCoreError> {
    let mut state = RouterWalState::default();
    let mut segments = router_wal_segment_ids(root)?;
    if segments.is_empty() {
        return Ok(RouterWalRecovery { state, last_segment_id: None, current_offset: 0 });
    }
    segments.sort_unstable();
    let mut current_offset = 0_u64;
    let mut last_segment_id = None;
    for segment_id in segments {
        let offset = recover_router_wal_segment(root, segment_id, &mut state)?;
        current_offset = offset;
        last_segment_id = Some(segment_id);
    }
    Ok(RouterWalRecovery { state, last_segment_id, current_offset })
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

fn router_wal_segment_id_from_name(name: &str) -> Option<u64> {
    name.strip_prefix("router-wal-")
        .and_then(|value| value.strip_suffix(".wal"))
        .and_then(|value| value.parse().ok())
}

fn router_wal_segment_path(root: &Path, segment_id: u64) -> PathBuf {
    root.join(format!("router-wal-{segment_id:020}.wal"))
}

fn write_router_wal_record_to_file(file: &mut File, encoded: &[u8]) -> Result<(), NodeCoreError> {
    let len = u32::try_from(encoded.len())
        .map_err(|_| NodeCoreError::ItestJson("router WAL record too large".to_owned()))?;
    let crc = crc32fast::hash(encoded);
    file.write_all(&len.to_le_bytes())
        .and_then(|()| file.write_all(&crc.to_le_bytes()))
        .and_then(|()| file.write_all(encoded))
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

fn router_wal_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn router_wal_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
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

        let segment = router_wal_segment_path(&root, 0);
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
    #[ignore = "set RAMFLUX_ROUTER_WAL_BENCH=1 to run the router WAL throughput bench"]
    fn router_wal_throughput_bench() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var("RAMFLUX_ROUTER_WAL_BENCH").as_deref() != Ok("1") {
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

    fn router_wal_inbox_entry(envelope_id: &str, target_delivery_id: &str) -> InboxEntry {
        InboxEntry {
            inbox_seq: 1,
            target_delivery_id: target_delivery_id.to_owned(),
            envelope: router_wal_envelope(envelope_id, target_delivery_id),
        }
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

    fn router_wal_bench_env_usize(name: &str, default: usize) -> usize {
        std::env::var(name).ok().and_then(|value| value.parse::<usize>().ok()).unwrap_or(default)
    }
}
