// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Batched redb commit writer and transactional relay mutations.

use super::{
    Duration, Instant, NodeCoreError, ObjectRelayTombstoneMutation, RELAY_CHUNK_ENTRY_TABLE,
    RELAY_TOMBSTONE_TABLE, RelayChunkEntry, RelayExpiryMutation, env, mpsc,
    remove_relay_legacy_snapshot, serialize_relay_value, thread,
};

use redb::ReadableTable;

pub(super) const RELAY_COMMIT_BATCH_MAX_ENV: &str = "RAMFLUX_RELAY_COMMIT_BATCH_MAX";
pub(super) const RELAY_COMMIT_BATCH_MAX_DEFAULT: usize = 256;
pub(super) const RELAY_COMMIT_WINDOW_US_ENV: &str = "RAMFLUX_RELAY_COMMIT_WINDOW_US";
pub(super) const RELAY_COMMIT_WINDOW_US_DEFAULT: u64 = 1_000;
pub(super) const RELAY_COMMIT_QUEUE_CAPACITY_ENV: &str = "RAMFLUX_RELAY_COMMIT_QUEUE_CAPACITY";
pub(super) const RELAY_COMMIT_QUEUE_CAPACITY_DEFAULT: usize = 4_096;

pub(super) struct RelayCommitWriter {
    sender: Option<mpsc::SyncSender<RelayCommitRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

pub(super) struct RelayCommitRequest {
    op: RelayCommitOp,
    reply: mpsc::SyncSender<Result<(), NodeCoreError>>,
}

pub(super) enum RelayCommitOp {
    ChunkEntry { entry: Box<RelayChunkEntry> },
    TombstoneMutation { mutation: Box<ObjectRelayTombstoneMutation> },
    ExpiryMutation { mutation: Box<RelayExpiryMutation> },
}

impl RelayCommitWriter {
    pub(super) fn start(db: std::sync::Arc<redb::Database>) -> Result<Self, NodeCoreError> {
        let batch_max =
            relay_usize_env(RELAY_COMMIT_BATCH_MAX_ENV, RELAY_COMMIT_BATCH_MAX_DEFAULT).max(1);
        let queue_capacity =
            relay_usize_env(RELAY_COMMIT_QUEUE_CAPACITY_ENV, RELAY_COMMIT_QUEUE_CAPACITY_DEFAULT)
                .max(batch_max);
        let window = Duration::from_micros(relay_u64_env(
            RELAY_COMMIT_WINDOW_US_ENV,
            RELAY_COMMIT_WINDOW_US_DEFAULT,
        ));
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let thread = thread::Builder::new()
            .name("ramflux-relay-commit-writer".to_owned())
            .spawn(move || relay_commit_writer_loop(&db, &receiver, batch_max, window))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        Ok(Self { sender: Some(sender), thread: Some(thread) })
    }

    pub(super) fn commit(&self, op: RelayCommitOp) -> Result<(), NodeCoreError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("relay commit writer stopped".to_owned()))?
            .send(RelayCommitRequest { op, reply })
            .map_err(|source| {
                NodeCoreError::ItestJson(format!("relay commit writer stopped: {source}"))
            })?;
        response.recv().map_err(|source| {
            NodeCoreError::ItestJson(format!("relay commit response closed: {source}"))
        })?
    }
}

impl Drop for RelayCommitWriter {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

pub(super) fn relay_commit_writer_loop(
    db: &redb::Database,
    receiver: &mpsc::Receiver<RelayCommitRequest>,
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
        let result = relay_commit_batch(db, batch.iter().map(|request| &request.op));
        match result {
            Ok(()) => {
                for request in batch {
                    let _sent = request.reply.send(Ok(()));
                }
            }
            Err(error) => {
                let message = error.to_string();
                for request in batch {
                    let _sent = request.reply.send(Err(NodeCoreError::Redb(message.clone())));
                }
            }
        }
    }
}

pub(super) fn relay_commit_batch<'a>(
    db: &redb::Database,
    ops: impl Iterator<Item = &'a RelayCommitOp>,
) -> Result<(), NodeCoreError> {
    let write_txn = db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    {
        for op in ops {
            relay_apply_commit_op(&write_txn, op)?;
        }
    }
    write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

pub(super) fn relay_apply_commit_op(
    write_txn: &redb::WriteTransaction,
    op: &RelayCommitOp,
) -> Result<(), NodeCoreError> {
    match op {
        RelayCommitOp::ChunkEntry { entry } => record_relay_chunk_entry_in_txn(write_txn, entry),
        RelayCommitOp::TombstoneMutation { mutation } => {
            record_relay_tombstone_mutation_in_txn(write_txn, mutation)
        }
        RelayCommitOp::ExpiryMutation { mutation } => {
            record_relay_expiry_mutation_in_txn(write_txn, mutation)
        }
    }
}

pub(super) fn record_relay_chunk_entry_in_txn(
    write_txn: &redb::WriteTransaction,
    entry: &RelayChunkEntry,
) -> Result<(), NodeCoreError> {
    let entry_bytes = serialize_relay_value(entry)?;
    let mut table = write_txn
        .open_table(RELAY_CHUNK_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    table
        .insert(entry.chunk_id.as_str(), entry_bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    remove_relay_legacy_snapshot(write_txn)
}

pub(super) fn record_relay_tombstone_mutation_in_txn(
    write_txn: &redb::WriteTransaction,
    mutation: &ObjectRelayTombstoneMutation,
) -> Result<(), NodeCoreError> {
    let tombstone_bytes = serialize_relay_value(&mutation.tombstone)?;
    let mut tombstone_table = write_txn
        .open_table(RELAY_TOMBSTONE_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    tombstone_table
        .insert(mutation.tombstone.object_id.as_str(), tombstone_bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let mut chunk_table = write_txn
        .open_table(RELAY_CHUNK_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    for meta in &mutation.affected_chunks {
        // A tombstone clears the ciphertext, so persist a payload-empty full-entry row. The schema
        // is unchanged: this is a `RelayChunkEntry` with an empty `encrypted_chunk`.
        let entry = meta.to_entry(Vec::new());
        let entry_bytes = serialize_relay_value(&entry)?;
        chunk_table
            .insert(entry.chunk_id.as_str(), entry_bytes.as_slice())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    remove_relay_legacy_snapshot(write_txn)
}

pub(super) fn record_relay_expiry_mutation_in_txn(
    write_txn: &redb::WriteTransaction,
    mutation: &RelayExpiryMutation,
) -> Result<(), NodeCoreError> {
    let mut chunk_table = write_txn
        .open_table(RELAY_CHUNK_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    for chunk_id in &mutation.expired_chunk_ids {
        let _removed = chunk_table
            .remove(chunk_id.as_str())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    let mut tombstone_table = write_txn
        .open_table(RELAY_TOMBSTONE_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    for object_id in &mutation.expired_tombstone_object_ids {
        let _removed = tombstone_table
            .remove(object_id.as_str())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    remove_relay_legacy_snapshot(write_txn)
}

pub(super) fn relay_usize_env(name: &str, default: usize) -> usize {
    env::parsed::<usize>(name).filter(|value| *value > 0).unwrap_or(default)
}

pub(super) fn relay_u64_env(name: &str, default: u64) -> u64 {
    env::parsed::<u64>(name).filter(|value| *value > 0).unwrap_or(default)
}
