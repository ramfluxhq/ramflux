// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]

use crate::{
    AbuseReportRecord, AccountLifecycleRecord, CursorAckState, IdentityLifecycleTombstone,
    InboxEntry, ItestMvp1IdentityRegistry, NodeCoreError, NodeReplayGuardState, OpaqueDeviceInbox,
    ROUTER_ABUSE_REPORT_KEY, ROUTER_ABUSE_REPORT_TABLE, ROUTER_CURSOR_STATE_TABLE,
    ROUTER_DEACTIVATED_TARGET_TABLE, ROUTER_DEACTIVATED_TARGETS_KEY, ROUTER_DELETED_TARGET_TABLE,
    ROUTER_DELETED_TARGETS_KEY, ROUTER_IDENTITY_REGISTRY_KEY, ROUTER_INBOX_ENTRY_TABLE,
    ROUTER_INBOX_SLICE_KEY, ROUTER_LIFECYCLE_RECORD_TABLE, ROUTER_LIFECYCLE_STATE_KEY,
    ROUTER_LIFECYCLE_TOMBSTONE_KEY, ROUTER_LIFECYCLE_TOMBSTONE_TABLE,
    ROUTER_REPLAY_GUARD_STATE_KEY, ROUTER_REPLAY_TUPLE_TABLE, ROUTER_SESSION_CHECKPOINT_KEY,
    ROUTER_SESSION_ENTRY_TABLE, ROUTER_SNAPSHOT_TABLE, RouterCore, SessionDescriptor,
    SessionRegistry, load_snapshot, now_unix_seconds, save_snapshot,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ROUTER_COMMIT_BATCH_MAX_ENV: &str = "RAMFLUX_ROUTER_COMMIT_BATCH_MAX";
const ROUTER_COMMIT_BATCH_MAX_DEFAULT: usize = 256;
const ROUTER_COMMIT_WINDOW_US_ENV: &str = "RAMFLUX_ROUTER_COMMIT_WINDOW_US";
const ROUTER_COMMIT_WINDOW_US_DEFAULT: u64 = 1_000;
const ROUTER_COMMIT_QUEUE_CAPACITY_ENV: &str = "RAMFLUX_ROUTER_COMMIT_QUEUE_CAPACITY";
const ROUTER_COMMIT_QUEUE_CAPACITY_DEFAULT: usize = 4_096;
const ROUTER_GROUP_COMMIT_ENV: &str = "RAMFLUX_ROUTER_GROUP_COMMIT";

pub struct RouterRedbStore {
    db: Arc<redb::Database>,
    path: PathBuf,
    commit_writer: Option<RouterCommitWriter>,
}

struct RouterCommitWriter {
    sender: Option<mpsc::SyncSender<RouterCommitRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

struct RouterCommitRequest {
    op: RouterCommitOp,
    reply: mpsc::SyncSender<Result<(), NodeCoreError>>,
}

enum RouterCommitOp {
    Submission { replay_key: String, replay_expires_at: i64, entry: Option<Box<InboxEntry>> },
    ReplayTuple { replay_key: String, replay_expires_at: i64 },
    InboxEntry { entry: Box<InboxEntry> },
    Fanout { replay_key: String, replay_expires_at: i64, entries: Vec<InboxEntry> },
}

impl RouterCommitWriter {
    fn start(db: Arc<redb::Database>) -> Result<Self, NodeCoreError> {
        let batch_max =
            router_usize_env(ROUTER_COMMIT_BATCH_MAX_ENV, ROUTER_COMMIT_BATCH_MAX_DEFAULT).max(1);
        let queue_capacity = router_usize_env(
            ROUTER_COMMIT_QUEUE_CAPACITY_ENV,
            ROUTER_COMMIT_QUEUE_CAPACITY_DEFAULT,
        )
        .max(batch_max);
        let window = Duration::from_micros(router_u64_env(
            ROUTER_COMMIT_WINDOW_US_ENV,
            ROUTER_COMMIT_WINDOW_US_DEFAULT,
        ));
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let thread = thread::Builder::new()
            .name("ramflux-router-commit-writer".to_owned())
            .spawn(move || router_commit_writer_loop(&db, &receiver, batch_max, window))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        Ok(Self { sender: Some(sender), thread: Some(thread) })
    }

    fn commit(&self, op: RouterCommitOp) -> Result<(), NodeCoreError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("router commit writer stopped".to_owned()))?
            .send(RouterCommitRequest { op, reply })
            .map_err(|source| {
                NodeCoreError::ItestJson(format!("router commit writer stopped: {source}"))
            })?;
        response.recv().map_err(|source| {
            NodeCoreError::ItestJson(format!("router commit response closed: {source}"))
        })?
    }
}

impl Drop for RouterCommitWriter {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

fn router_commit_writer_loop(
    db: &redb::Database,
    receiver: &mpsc::Receiver<RouterCommitRequest>,
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
        let result = router_commit_batch(db, batch.iter().map(|request| &request.op));
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

fn router_commit_batch<'a>(
    db: &redb::Database,
    ops: impl Iterator<Item = &'a RouterCommitOp>,
) -> Result<(), NodeCoreError> {
    let begin_write_started = Instant::now();
    let write_txn = db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    crate::record_router_save_begin_write_us(elapsed_us(begin_write_started));
    let mutation_started = Instant::now();
    {
        for op in ops {
            router_apply_commit_op(&write_txn, op)?;
        }
    }
    crate::record_router_save_mutation_us(elapsed_us(mutation_started));
    let commit_started = Instant::now();
    write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    crate::record_router_save_commit_us(elapsed_us(commit_started));
    Ok(())
}

fn router_apply_commit_op(
    write_txn: &redb::WriteTransaction,
    op: &RouterCommitOp,
) -> Result<(), NodeCoreError> {
    match op {
        RouterCommitOp::Submission { replay_key, replay_expires_at, entry } => {
            record_replay_tuple_in_txn(write_txn, replay_key, *replay_expires_at)?;
            if let Some(entry) = entry {
                record_inbox_entry_in_txn(write_txn, entry)?;
            }
            Ok(())
        }
        RouterCommitOp::ReplayTuple { replay_key, replay_expires_at } => {
            record_replay_tuple_in_txn(write_txn, replay_key, *replay_expires_at)
        }
        RouterCommitOp::InboxEntry { entry } => record_inbox_entry_in_txn(write_txn, entry),
        RouterCommitOp::Fanout { replay_key, replay_expires_at, entries } => {
            record_replay_tuple_in_txn(write_txn, replay_key, *replay_expires_at)?;
            for entry in entries {
                record_inbox_entry_in_txn(write_txn, entry)?;
            }
            Ok(())
        }
    }
}

fn record_replay_tuple_in_txn(
    write_txn: &redb::WriteTransaction,
    replay_key: &str,
    replay_expires_at: i64,
) -> Result<(), NodeCoreError> {
    let replay_bytes = serialize_value(&replay_expires_at)?;
    let mut replay_table = write_txn
        .open_table(ROUTER_REPLAY_TUPLE_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    replay_table
        .insert(replay_key, replay_bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn record_inbox_entry_in_txn(
    write_txn: &redb::WriteTransaction,
    entry: &InboxEntry,
) -> Result<(), NodeCoreError> {
    let entry_bytes = serialize_value(entry)?;
    let mut inbox_table = write_txn
        .open_table(ROUTER_INBOX_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    inbox_table
        .insert(entry.envelope.envelope_id.as_str(), entry_bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

impl RouterRedbStore {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| NodeCoreError::StoreDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let db = Arc::new(
            redb::Database::create(path)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?,
        );
        let write_txn =
            db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let _table = write_txn
                .open_table(ROUTER_SNAPSHOT_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_INBOX_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_CURSOR_STATE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_REPLAY_TUPLE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_SESSION_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_LIFECYCLE_RECORD_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_LIFECYCLE_TOMBSTONE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_DEACTIVATED_TARGET_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_DELETED_TARGET_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(ROUTER_ABUSE_REPORT_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let commit_writer = if router_group_commit_enabled() {
            Some(RouterCommitWriter::start(Arc::clone(&db))?)
        } else {
            None
        };
        Ok(Self { db, path: path.to_path_buf(), commit_writer })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn save_router(&self, router: &RouterCore) -> Result<(), NodeCoreError> {
        let save_started = Instant::now();
        crate::record_router_snapshot_save();
        let snapshot = router.snapshot();
        save_snapshot(
            &self.db,
            ROUTER_SNAPSHOT_TABLE,
            ROUTER_SESSION_CHECKPOINT_KEY,
            &snapshot.registry,
        )?;
        let inbox_started = Instant::now();
        self.replace_incremental_router_tables(&snapshot)?;
        crate::record_router_save_inbox_us(elapsed_us(inbox_started));
        save_snapshot(
            &self.db,
            ROUTER_SNAPSHOT_TABLE,
            ROUTER_IDENTITY_REGISTRY_KEY,
            &snapshot.mvp1_identities,
        )?;
        save_snapshot(
            &self.db,
            ROUTER_SNAPSHOT_TABLE,
            ROUTER_LIFECYCLE_STATE_KEY,
            &snapshot.lifecycle_by_principal,
        )?;
        save_snapshot(
            &self.db,
            ROUTER_SNAPSHOT_TABLE,
            ROUTER_LIFECYCLE_TOMBSTONE_KEY,
            &snapshot.lifecycle_tombstones,
        )?;
        save_snapshot(
            &self.db,
            ROUTER_SNAPSHOT_TABLE,
            ROUTER_DEACTIVATED_TARGETS_KEY,
            &snapshot.deactivated_delivery_targets,
        )?;
        save_snapshot(
            &self.db,
            ROUTER_SNAPSHOT_TABLE,
            ROUTER_DELETED_TARGETS_KEY,
            &snapshot.deleted_delivery_targets,
        )?;
        save_snapshot(
            &self.db,
            ROUTER_SNAPSHOT_TABLE,
            ROUTER_ABUSE_REPORT_KEY,
            &snapshot.abuse_reports,
        )?;
        self.replace_per_key_router_tables(&snapshot)?;
        let replay_guard_started = Instant::now();
        crate::record_router_save_replay_guard_us(elapsed_us(replay_guard_started));
        crate::record_router_replay_guard_redb_write();
        crate::record_router_save_total_us(elapsed_us(save_started));
        Ok(())
    }

    fn replace_per_key_router_tables(
        &self,
        router: &crate::RouterCoreSnapshot,
    ) -> Result<(), NodeCoreError> {
        let sessions = router.registry.sessions().cloned().collect::<Vec<_>>();
        let lifecycle_records = router.lifecycle_by_principal.values().cloned().collect::<Vec<_>>();
        let lifecycle_tombstones =
            router.lifecycle_tombstones.values().cloned().collect::<Vec<_>>();
        let abuse_reports = router.abuse_reports.values().cloned().collect::<Vec<_>>();
        let session_bytes = sessions.iter().map(serialize_value).collect::<Result<Vec<_>, _>>()?;
        let lifecycle_record_bytes =
            lifecycle_records.iter().map(serialize_value).collect::<Result<Vec<_>, _>>()?;
        let lifecycle_tombstone_bytes =
            lifecycle_tombstones.iter().map(serialize_value).collect::<Result<Vec<_>, _>>()?;
        let abuse_report_bytes =
            abuse_reports.iter().map(serialize_value).collect::<Result<Vec<_>, _>>()?;
        let true_bytes = serialize_value(&true)?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            replace_table_values(
                &write_txn,
                ROUTER_SESSION_ENTRY_TABLE,
                sessions
                    .iter()
                    .map(|session| session.target_delivery_id.as_str())
                    .zip(session_bytes.iter().map(Vec::as_slice)),
            )?;
            replace_table_values(
                &write_txn,
                ROUTER_LIFECYCLE_RECORD_TABLE,
                lifecycle_records
                    .iter()
                    .map(|record| record.principal_id.as_str())
                    .zip(lifecycle_record_bytes.iter().map(Vec::as_slice)),
            )?;
            replace_table_values(
                &write_txn,
                ROUTER_LIFECYCLE_TOMBSTONE_TABLE,
                lifecycle_tombstones
                    .iter()
                    .map(|tombstone| tombstone.tombstone_id.as_str())
                    .zip(lifecycle_tombstone_bytes.iter().map(Vec::as_slice)),
            )?;
            replace_table_values(
                &write_txn,
                ROUTER_ABUSE_REPORT_TABLE,
                abuse_reports
                    .iter()
                    .map(|report| report.report_id.as_str())
                    .zip(abuse_report_bytes.iter().map(Vec::as_slice)),
            )?;
            replace_table_values(
                &write_txn,
                ROUTER_DEACTIVATED_TARGET_TABLE,
                router
                    .deactivated_delivery_targets
                    .iter()
                    .map(String::as_str)
                    .zip(std::iter::repeat(true_bytes.as_slice())),
            )?;
            replace_table_values(
                &write_txn,
                ROUTER_DELETED_TARGET_TABLE,
                router
                    .deleted_delivery_targets
                    .iter()
                    .map(String::as_str)
                    .zip(std::iter::repeat(true_bytes.as_slice())),
            )?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the incremental submission cannot be durably recorded.
    pub fn record_submission_increment(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
        entry: Option<&InboxEntry>,
    ) -> Result<(), NodeCoreError> {
        let save_started = Instant::now();
        let replay_started = Instant::now();
        self.commit_router_op(RouterCommitOp::Submission {
            replay_key: replay_key.to_owned(),
            replay_expires_at,
            entry: entry.cloned().map(Box::new),
        })?;
        crate::record_router_save_replay_guard_us(elapsed_us(replay_started));
        crate::record_router_replay_guard_redb_write();
        crate::record_router_save_total_us(elapsed_us(save_started));
        Ok(())
    }

    /// # Errors
    /// Returns an error when the replay tuple cannot be durably recorded.
    pub fn record_replay_tuple(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
    ) -> Result<(), NodeCoreError> {
        let save_started = Instant::now();
        let replay_started = Instant::now();
        self.commit_router_op(RouterCommitOp::ReplayTuple {
            replay_key: replay_key.to_owned(),
            replay_expires_at,
        })?;
        crate::record_router_save_replay_guard_us(elapsed_us(replay_started));
        crate::record_router_replay_guard_redb_write();
        crate::record_router_save_total_us(elapsed_us(save_started));
        Ok(())
    }

    /// # Errors
    /// Returns an error when the inbox entry cannot be durably recorded.
    pub fn record_inbox_entry(&self, entry: &InboxEntry) -> Result<(), NodeCoreError> {
        let save_started = Instant::now();
        let inbox_started = Instant::now();
        self.commit_router_op(RouterCommitOp::InboxEntry { entry: Box::new(entry.clone()) })?;
        crate::record_router_save_inbox_us(elapsed_us(inbox_started));
        crate::record_router_save_total_us(elapsed_us(save_started));
        Ok(())
    }

    /// # Errors
    /// Returns an error when the cursor update cannot be durably recorded.
    pub fn record_ack_increment(
        &self,
        cursor: &CursorAckState,
        envelope_id: &str,
    ) -> Result<(), NodeCoreError> {
        let save_started = Instant::now();
        let inbox_started = Instant::now();
        let cursor_bytes = serialize_value(cursor)?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut cursor_table = write_txn
                .open_table(ROUTER_CURSOR_STATE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            cursor_table
                .insert(cursor.target_delivery_id.as_str(), cursor_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let mut inbox_table = write_txn
                .open_table(ROUTER_INBOX_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _removed = inbox_table
                .remove(envelope_id)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        crate::record_router_save_inbox_us(elapsed_us(inbox_started));
        crate::record_router_save_total_us(elapsed_us(save_started));
        Ok(())
    }

    /// # Errors
    /// Returns an error when the cursor update cannot be durably recorded.
    pub fn record_nack_increment(&self, cursor: &CursorAckState) -> Result<(), NodeCoreError> {
        let save_started = Instant::now();
        let inbox_started = Instant::now();
        let cursor_bytes = serialize_value(cursor)?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut cursor_table = write_txn
                .open_table(ROUTER_CURSOR_STATE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            cursor_table
                .insert(cursor.target_delivery_id.as_str(), cursor_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        crate::record_router_save_inbox_us(elapsed_us(inbox_started));
        crate::record_router_save_total_us(elapsed_us(save_started));
        Ok(())
    }

    /// # Errors
    /// Returns an error when the session entry cannot be durably recorded.
    pub fn record_session_entry(&self, session: &SessionDescriptor) -> Result<(), NodeCoreError> {
        self.insert_table_value(ROUTER_SESSION_ENTRY_TABLE, &session.target_delivery_id, session)
    }

    /// # Errors
    /// Returns an error when the identity registry cannot be durably recorded.
    pub fn record_identity_registry(
        &self,
        registry: &ItestMvp1IdentityRegistry,
    ) -> Result<(), NodeCoreError> {
        save_snapshot(&self.db, ROUTER_SNAPSHOT_TABLE, ROUTER_IDENTITY_REGISTRY_KEY, registry)
    }

    /// # Errors
    /// Returns an error when the lifecycle record cannot be durably recorded.
    pub fn record_lifecycle_record(
        &self,
        record: &AccountLifecycleRecord,
    ) -> Result<(), NodeCoreError> {
        self.insert_table_value(ROUTER_LIFECYCLE_RECORD_TABLE, &record.principal_id, record)
    }

    /// # Errors
    /// Returns an error when the lifecycle tombstone cannot be durably recorded.
    pub fn record_lifecycle_tombstone(
        &self,
        tombstone: &IdentityLifecycleTombstone,
    ) -> Result<(), NodeCoreError> {
        self.insert_table_value(
            ROUTER_LIFECYCLE_TOMBSTONE_TABLE,
            &tombstone.tombstone_id,
            tombstone,
        )
    }

    /// # Errors
    /// Returns an error when the federated target lifecycle marker cannot be recorded.
    pub fn record_target_lifecycle_marker(
        &self,
        target_delivery_id: &str,
        state: &crate::AccountLifecycleState,
    ) -> Result<(), NodeCoreError> {
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            record_target_lifecycle_marker_in_txn(&write_txn, target_delivery_id, state)?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the federated tombstone and lifecycle marker cannot be atomically recorded.
    pub fn record_federated_lifecycle_tombstone(
        &self,
        tombstone: Option<&IdentityLifecycleTombstone>,
        target_delivery_id: &str,
        state: &crate::AccountLifecycleState,
    ) -> Result<(), NodeCoreError> {
        let tombstone_bytes = tombstone.map(serialize_value).transpose()?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            if let (Some(tombstone), Some(bytes)) = (tombstone, tombstone_bytes.as_deref()) {
                let mut tombstone_table = write_txn
                    .open_table(ROUTER_LIFECYCLE_TOMBSTONE_TABLE)
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                tombstone_table
                    .insert(tombstone.tombstone_id.as_str(), bytes)
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
            record_target_lifecycle_marker_in_txn(&write_txn, target_delivery_id, state)?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when finalized target cleanup cannot be durably recorded.
    pub fn record_target_deleted_cleanup(
        &self,
        target_delivery_id: &str,
        identity_registry: &ItestMvp1IdentityRegistry,
        lifecycle_record: &AccountLifecycleRecord,
    ) -> Result<(), NodeCoreError> {
        let identity_bytes = serialize_value(identity_registry)?;
        let lifecycle_bytes = serialize_value(lifecycle_record)?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut snapshot_table = write_txn
                .open_table(ROUTER_SNAPSHOT_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            snapshot_table
                .insert(ROUTER_IDENTITY_REGISTRY_KEY, identity_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;

            let mut lifecycle_table = write_txn
                .open_table(ROUTER_LIFECYCLE_RECORD_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            lifecycle_table
                .insert(lifecycle_record.principal_id.as_str(), lifecycle_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;

            remove_key(&write_txn, ROUTER_SESSION_ENTRY_TABLE, target_delivery_id)?;
            remove_key(&write_txn, ROUTER_CURSOR_STATE_TABLE, target_delivery_id)?;
            put_bool(&write_txn, ROUTER_DEACTIVATED_TARGET_TABLE, target_delivery_id, false)?;
            put_bool(&write_txn, ROUTER_DELETED_TARGET_TABLE, target_delivery_id, true)?;
            remove_inbox_entries_for_target(&write_txn, target_delivery_id)?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the abuse report cannot be durably recorded.
    pub fn record_abuse_report(&self, report: &AbuseReportRecord) -> Result<(), NodeCoreError> {
        self.insert_table_value(ROUTER_ABUSE_REPORT_TABLE, &report.report_id, report)
    }

    /// # Errors
    /// Returns an error when fan-out replay and inbox entries cannot be recorded.
    pub fn record_fanout_increment(
        &self,
        replay_key: &str,
        replay_expires_at: i64,
        entries: &[InboxEntry],
    ) -> Result<(), NodeCoreError> {
        let save_started = Instant::now();
        let replay_started = Instant::now();
        self.commit_router_op(RouterCommitOp::Fanout {
            replay_key: replay_key.to_owned(),
            replay_expires_at,
            entries: entries.to_vec(),
        })?;
        crate::record_router_save_replay_guard_us(elapsed_us(replay_started));
        crate::record_router_replay_guard_redb_write();
        crate::record_router_save_total_us(elapsed_us(save_started));
        Ok(())
    }

    fn commit_router_op(&self, op: RouterCommitOp) -> Result<(), NodeCoreError> {
        if let Some(writer) = &self.commit_writer {
            return writer.commit(op);
        }
        router_commit_batch(&self.db, std::iter::once(&op))
    }

    fn insert_table_value<T: Serialize>(
        &self,
        table: redb::TableDefinition<&str, &[u8]>,
        key: &str,
        value: &T,
    ) -> Result<(), NodeCoreError> {
        let value_bytes = serialize_value(value)?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(table)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(key, value_bytes.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn load_router(&self) -> Result<Option<RouterCore>, NodeCoreError> {
        let mut registry = self.load_session_registry()?;
        let incremental_entries = self.load_incremental_inbox_entries()?;
        let incremental_cursors = self.load_incremental_cursor_states()?;
        let incremental_replay_tuples = self.load_incremental_replay_tuples(
            i64::try_from(now_unix_seconds()).unwrap_or(i64::MAX),
        )?;
        let has_incremental_inbox =
            !incremental_entries.is_empty() || !incremental_cursors.is_empty();
        let has_incremental_replay = !incremental_replay_tuples.is_empty();
        let mut inbox = if has_incremental_inbox {
            OpaqueDeviceInbox::new()
        } else {
            load_snapshot(&self.db, ROUTER_SNAPSHOT_TABLE, ROUTER_INBOX_SLICE_KEY)?
                .unwrap_or_default()
        };
        for entry in incremental_entries {
            inbox.restore_pending_entry(entry);
        }
        for cursor in incremental_cursors {
            inbox.restore_cursor_state(cursor);
        }
        let mut replay_guard_state = if has_incremental_replay {
            NodeReplayGuardState::new()
        } else {
            load_snapshot(&self.db, ROUTER_SNAPSHOT_TABLE, ROUTER_REPLAY_GUARD_STATE_KEY)?
                .unwrap_or_default()
        };
        for (key, expires_at) in incremental_replay_tuples {
            replay_guard_state.restore_accepted(key, expires_at);
        }
        let mvp1_identities =
            load_snapshot(&self.db, ROUTER_SNAPSHOT_TABLE, ROUTER_IDENTITY_REGISTRY_KEY)?
                .unwrap_or_default();
        let lifecycle_by_principal = self.load_lifecycle_records()?;
        let lifecycle_tombstones = self.load_lifecycle_tombstones()?;
        let deactivated_delivery_targets = self.load_target_marker_set(
            ROUTER_DEACTIVATED_TARGET_TABLE,
            ROUTER_DEACTIVATED_TARGETS_KEY,
        )?;
        let deleted_delivery_targets =
            self.load_target_marker_set(ROUTER_DELETED_TARGET_TABLE, ROUTER_DELETED_TARGETS_KEY)?;
        for target_delivery_id in &deleted_delivery_targets {
            let _removed = registry.remove_target(target_delivery_id);
            let _removed_count = inbox.remove_target(target_delivery_id);
        }
        let abuse_reports = self.load_abuse_reports()?;
        if registry == SessionRegistry::default()
            && inbox == OpaqueDeviceInbox::default()
            && mvp1_identities == ItestMvp1IdentityRegistry::default()
            && lifecycle_by_principal.is_empty()
            && lifecycle_tombstones.is_empty()
            && deactivated_delivery_targets.is_empty()
            && deleted_delivery_targets.is_empty()
            && abuse_reports.is_empty()
            && replay_guard_state == NodeReplayGuardState::default()
        {
            return Ok(None);
        }
        Ok(Some(RouterCore::from_snapshot(crate::RouterCoreSnapshot {
            registry,
            inbox,
            mvp1_identities,
            lifecycle_by_principal,
            lifecycle_tombstones,
            deactivated_delivery_targets,
            deleted_delivery_targets,
            abuse_reports,
            replay_guard_state,
        })))
    }

    fn replace_incremental_router_tables(
        &self,
        router: &crate::RouterCoreSnapshot,
    ) -> Result<(), NodeCoreError> {
        let pending_entries = router.inbox.pending_entries().cloned().collect::<Vec<_>>();
        let cursor_states = router.inbox.cursor_states().cloned().collect::<Vec<_>>();
        let replay_tuples = router
            .replay_guard_state
            .accepted_entries()
            .map(|(key, expires_at)| (key.clone(), *expires_at))
            .collect::<Vec<_>>();
        let pending_entry_bytes =
            pending_entries.iter().map(serialize_value).collect::<Result<Vec<_>, _>>()?;
        let cursor_state_bytes =
            cursor_states.iter().map(serialize_value).collect::<Result<Vec<_>, _>>()?;
        let replay_tuple_bytes = replay_tuples
            .iter()
            .map(|(_key, expires_at)| serialize_value(expires_at))
            .collect::<Result<Vec<_>, _>>()?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut inbox_table = write_txn
                .open_table(ROUTER_INBOX_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let inbox_keys = inbox_table
                .iter()
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?
                .map(|entry| {
                    entry
                        .map(|(key, _value)| key.value().to_owned())
                        .map_err(|source| NodeCoreError::Redb(source.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for key in inbox_keys {
                let _removed = inbox_table
                    .remove(key.as_str())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
            for (entry, bytes) in pending_entries.iter().zip(pending_entry_bytes.iter()) {
                inbox_table
                    .insert(entry.envelope.envelope_id.as_str(), bytes.as_slice())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }

            let mut cursor_table = write_txn
                .open_table(ROUTER_CURSOR_STATE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let cursor_keys = cursor_table
                .iter()
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?
                .map(|entry| {
                    entry
                        .map(|(key, _value)| key.value().to_owned())
                        .map_err(|source| NodeCoreError::Redb(source.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for key in cursor_keys {
                let _removed = cursor_table
                    .remove(key.as_str())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
            for (cursor, bytes) in cursor_states.iter().zip(cursor_state_bytes.iter()) {
                cursor_table
                    .insert(cursor.target_delivery_id.as_str(), bytes.as_slice())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }

            let mut replay_table = write_txn
                .open_table(ROUTER_REPLAY_TUPLE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let replay_keys = replay_table
                .iter()
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?
                .map(|entry| {
                    entry
                        .map(|(key, _value)| key.value().to_owned())
                        .map_err(|source| NodeCoreError::Redb(source.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for key in replay_keys {
                let _removed = replay_table
                    .remove(key.as_str())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
            for ((key, _expires_at), bytes) in replay_tuples.iter().zip(replay_tuple_bytes.iter()) {
                replay_table
                    .insert(key.as_str(), bytes.as_slice())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    fn load_session_registry(&self) -> Result<SessionRegistry, NodeCoreError> {
        let sessions: Vec<SessionDescriptor> =
            load_table_values(&self.db, ROUTER_SESSION_ENTRY_TABLE)?;
        if sessions.is_empty() {
            return Ok(load_snapshot(
                &self.db,
                ROUTER_SNAPSHOT_TABLE,
                ROUTER_SESSION_CHECKPOINT_KEY,
            )?
            .unwrap_or_default());
        }
        let mut registry = SessionRegistry::new();
        for session in sessions {
            registry.restore_session(session);
        }
        Ok(registry)
    }

    fn load_lifecycle_records(
        &self,
    ) -> Result<BTreeMap<String, AccountLifecycleRecord>, NodeCoreError> {
        let records: Vec<AccountLifecycleRecord> =
            load_table_values(&self.db, ROUTER_LIFECYCLE_RECORD_TABLE)?;
        if records.is_empty() {
            return Ok(load_snapshot(&self.db, ROUTER_SNAPSHOT_TABLE, ROUTER_LIFECYCLE_STATE_KEY)?
                .unwrap_or_default());
        }
        Ok(records.into_iter().map(|record| (record.principal_id.clone(), record)).collect())
    }

    fn load_lifecycle_tombstones(
        &self,
    ) -> Result<BTreeMap<String, IdentityLifecycleTombstone>, NodeCoreError> {
        let tombstones: Vec<IdentityLifecycleTombstone> =
            load_table_values(&self.db, ROUTER_LIFECYCLE_TOMBSTONE_TABLE)?;
        if tombstones.is_empty() {
            return Ok(load_snapshot(
                &self.db,
                ROUTER_SNAPSHOT_TABLE,
                ROUTER_LIFECYCLE_TOMBSTONE_KEY,
            )?
            .unwrap_or_default());
        }
        Ok(tombstones
            .into_iter()
            .map(|tombstone| (tombstone.tombstone_id.clone(), tombstone))
            .collect())
    }

    fn load_target_marker_set(
        &self,
        table: redb::TableDefinition<&str, &[u8]>,
        fallback_snapshot_key: &str,
    ) -> Result<BTreeSet<String>, NodeCoreError> {
        let (markers, has_marker_rows) = load_bool_key_set(&self.db, table)?;
        if !has_marker_rows {
            return Ok(load_snapshot(&self.db, ROUTER_SNAPSHOT_TABLE, fallback_snapshot_key)?
                .unwrap_or_default());
        }
        Ok(markers)
    }

    fn load_abuse_reports(&self) -> Result<BTreeMap<String, AbuseReportRecord>, NodeCoreError> {
        let reports: Vec<AbuseReportRecord> =
            load_table_values(&self.db, ROUTER_ABUSE_REPORT_TABLE)?;
        if reports.is_empty() {
            return Ok(load_snapshot(&self.db, ROUTER_SNAPSHOT_TABLE, ROUTER_ABUSE_REPORT_KEY)?
                .unwrap_or_default());
        }
        Ok(reports.into_iter().map(|report| (report.report_id.clone(), report)).collect())
    }

    fn load_incremental_inbox_entries(&self) -> Result<Vec<InboxEntry>, NodeCoreError> {
        load_table_values(&self.db, ROUTER_INBOX_ENTRY_TABLE)
    }

    fn load_incremental_cursor_states(&self) -> Result<Vec<CursorAckState>, NodeCoreError> {
        load_table_values(&self.db, ROUTER_CURSOR_STATE_TABLE)
    }

    fn load_incremental_replay_tuples(
        &self,
        now_unix_seconds: i64,
    ) -> Result<Vec<(String, i64)>, NodeCoreError> {
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let (active, expired_keys) = {
            let table = write_txn
                .open_table(ROUTER_REPLAY_TUPLE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let mut active = Vec::new();
            let mut expired_keys = Vec::new();
            for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
                let (key, value) =
                    entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                let key = key.value().to_owned();
                let expires_at = serde_json::from_slice(value.value())
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
                if expires_at < now_unix_seconds {
                    expired_keys.push(key);
                } else {
                    active.push((key, expires_at));
                }
            }
            (active, expired_keys)
        };
        if !expired_keys.is_empty() {
            let mut table = write_txn
                .open_table(ROUTER_REPLAY_TUPLE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for key in expired_keys {
                let _removed = table
                    .remove(key.as_str())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(active)
    }
}

fn serialize_value<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeCoreError> {
    serde_json::to_vec(value)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn router_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn router_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn router_group_commit_enabled() -> bool {
    std::env::var(ROUTER_GROUP_COMMIT_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn load_table_values<T: serde::de::DeserializeOwned>(
    db: &redb::Database,
    table: redb::TableDefinition<&str, &[u8]>,
) -> Result<Vec<T>, NodeCoreError> {
    let read_txn = db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let table =
        read_txn.open_table(table).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    table
        .iter()
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        .map(|entry| {
            let (_key, value) = entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            serde_json::from_slice(value.value())
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
        })
        .collect()
}

fn load_bool_key_set(
    db: &redb::Database,
    table: redb::TableDefinition<&str, &[u8]>,
) -> Result<(BTreeSet<String>, bool), NodeCoreError> {
    let read_txn = db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let table =
        read_txn.open_table(table).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let mut keys = BTreeSet::new();
    let mut has_rows = false;
    for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
        has_rows = true;
        let (key, value) = entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let present: bool = serde_json::from_slice(value.value())
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        if present {
            keys.insert(key.value().to_owned());
        }
    }
    Ok((keys, has_rows))
}

fn remove_key(
    write_txn: &redb::WriteTransaction,
    table: redb::TableDefinition<&str, &[u8]>,
    key: &str,
) -> Result<(), NodeCoreError> {
    let mut table =
        write_txn.open_table(table).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let _removed = table.remove(key).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn put_bool(
    write_txn: &redb::WriteTransaction,
    table: redb::TableDefinition<&str, &[u8]>,
    key: &str,
    value: bool,
) -> Result<(), NodeCoreError> {
    let value_bytes = serialize_value(&value)?;
    let mut table =
        write_txn.open_table(table).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    table
        .insert(key, value_bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn replace_table_values<'a, I>(
    write_txn: &redb::WriteTransaction,
    table: redb::TableDefinition<&str, &[u8]>,
    entries: I,
) -> Result<(), NodeCoreError>
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
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
        table.insert(key, value).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    Ok(())
}

fn remove_inbox_entries_for_target(
    write_txn: &redb::WriteTransaction,
    target_delivery_id: &str,
) -> Result<(), NodeCoreError> {
    let mut table = write_txn
        .open_table(ROUTER_INBOX_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let mut keys = Vec::new();
    for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
        let (key, value) = entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let entry: InboxEntry = serde_json::from_slice(value.value())
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        if entry.target_delivery_id == target_delivery_id {
            keys.push(key.value().to_owned());
        }
    }
    for key in keys {
        let _removed =
            table.remove(key.as_str()).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    Ok(())
}

fn record_target_lifecycle_marker_in_txn(
    write_txn: &redb::WriteTransaction,
    target_delivery_id: &str,
    state: &crate::AccountLifecycleState,
) -> Result<(), NodeCoreError> {
    match state {
        crate::AccountLifecycleState::Deactivated => {
            put_bool(write_txn, ROUTER_DEACTIVATED_TARGET_TABLE, target_delivery_id, true)?;
        }
        crate::AccountLifecycleState::Deleted => {
            put_bool(write_txn, ROUTER_DELETED_TARGET_TABLE, target_delivery_id, true)?;
            put_bool(write_txn, ROUTER_DEACTIVATED_TARGET_TABLE, target_delivery_id, false)?;
        }
        crate::AccountLifecycleState::Active => {
            put_bool(write_txn, ROUTER_DEACTIVATED_TARGET_TABLE, target_delivery_id, false)?;
        }
        crate::AccountLifecycleState::DeletePending => {}
    }
    Ok(())
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
