// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static GATEWAY_SUBMIT_RECEIVED_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_ENVELOPE_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_REPLAY_GUARD_CHECKS_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_REPLAY_GUARD_REDB_WRITES_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SNAPSHOT_SAVES_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_ACK_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_DECODE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_DECODE_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_LOCK_WAIT_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_LOCK_WAIT_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_DISPATCH_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_DISPATCH_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_SAVE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_SAVE_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_RESPONSE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_RESPONSE_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_TOTAL_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_TOTAL_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_TARGET_LOCAL_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_TARGET_REMOTE_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_TARGET_LOCAL_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_TARGET_LOCAL_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_TARGET_REMOTE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SUBMIT_TARGET_REMOTE_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_REPLAY_GUARD_CHECK_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_REPLAY_GUARD_CHECK_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_TOTAL_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_TOTAL_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_INBOX_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_INBOX_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_REPLAY_GUARD_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_REPLAY_GUARD_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_BEGIN_WRITE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_BEGIN_WRITE_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_MUTATION_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_MUTATION_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_COMMIT_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_SAVE_COMMIT_US_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_WAL_BATCHES_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_WAL_RECORDS_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_WAL_BATCH_SIZE_MAX: AtomicU64 = AtomicU64::new(0);
static ROUTER_WAL_SYNC_ALL_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROUTER_WAL_SYNC_ALL_US_MAX: AtomicU64 = AtomicU64::new(0);
static PERF_ENABLED: OnceLock<bool> = OnceLock::new();

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct NodePerfSnapshot {
    pub enabled: bool,
    pub gateway_submit_received_total: u64,
    pub router_envelope_accepted_total: u64,
    pub router_replay_guard_checks_total: u64,
    pub router_replay_guard_redb_writes_total: u64,
    pub router_snapshot_saves_total: u64,
    pub router_ack_total: u64,
    pub router_submit_decode_us_total: u64,
    pub router_submit_decode_us_max: u64,
    pub router_submit_lock_wait_us_total: u64,
    pub router_submit_lock_wait_us_max: u64,
    pub router_submit_dispatch_us_total: u64,
    pub router_submit_dispatch_us_max: u64,
    pub router_submit_save_us_total: u64,
    pub router_submit_save_us_max: u64,
    pub router_submit_response_us_total: u64,
    pub router_submit_response_us_max: u64,
    pub router_submit_total_us_total: u64,
    pub router_submit_total_us_max: u64,
    pub router_submit_target_local_total: u64,
    pub router_submit_target_remote_total: u64,
    pub router_submit_target_local_us_total: u64,
    pub router_submit_target_local_us_max: u64,
    pub router_submit_target_remote_us_total: u64,
    pub router_submit_target_remote_us_max: u64,
    pub router_replay_guard_check_us_total: u64,
    pub router_replay_guard_check_us_max: u64,
    pub router_save_total_us_total: u64,
    pub router_save_total_us_max: u64,
    pub router_save_inbox_us_total: u64,
    pub router_save_inbox_us_max: u64,
    pub router_save_replay_guard_us_total: u64,
    pub router_save_replay_guard_us_max: u64,
    pub router_save_begin_write_us_total: u64,
    pub router_save_begin_write_us_max: u64,
    pub router_save_mutation_us_total: u64,
    pub router_save_mutation_us_max: u64,
    pub router_save_commit_us_total: u64,
    pub router_save_commit_us_max: u64,
    pub router_wal_batches_total: u64,
    pub router_wal_records_total: u64,
    pub router_wal_batch_size_max: u64,
    pub router_wal_sync_all_us_total: u64,
    pub router_wal_sync_all_us_max: u64,
}

#[must_use]
pub fn node_perf_enabled() -> bool {
    *PERF_ENABLED.get_or_init(|| std::env::var("RAMFLUX_ITEST_PERF").as_deref() == Ok("1"))
}

pub fn record_gateway_submit_received() {
    if node_perf_enabled() {
        GATEWAY_SUBMIT_RECEIVED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_router_envelope_accepted() {
    if node_perf_enabled() {
        ROUTER_ENVELOPE_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_router_replay_guard_check() {
    if node_perf_enabled() {
        ROUTER_REPLAY_GUARD_CHECKS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_router_replay_guard_redb_write() {
    if node_perf_enabled() {
        ROUTER_REPLAY_GUARD_REDB_WRITES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_router_snapshot_save() {
    if node_perf_enabled() {
        ROUTER_SNAPSHOT_SAVES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_router_ack() {
    if node_perf_enabled() {
        ROUTER_ACK_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_router_submit_decode_us(us: u64) {
    record_duration(&ROUTER_SUBMIT_DECODE_US_TOTAL, &ROUTER_SUBMIT_DECODE_US_MAX, us);
}

pub fn record_router_submit_lock_wait_us(us: u64) {
    record_duration(&ROUTER_SUBMIT_LOCK_WAIT_US_TOTAL, &ROUTER_SUBMIT_LOCK_WAIT_US_MAX, us);
}

pub fn record_router_submit_dispatch_us(us: u64) {
    record_duration(&ROUTER_SUBMIT_DISPATCH_US_TOTAL, &ROUTER_SUBMIT_DISPATCH_US_MAX, us);
}

pub fn record_router_submit_save_us(us: u64) {
    record_duration(&ROUTER_SUBMIT_SAVE_US_TOTAL, &ROUTER_SUBMIT_SAVE_US_MAX, us);
}

pub fn record_router_submit_response_us(us: u64) {
    record_duration(&ROUTER_SUBMIT_RESPONSE_US_TOTAL, &ROUTER_SUBMIT_RESPONSE_US_MAX, us);
}

pub fn record_router_submit_total_us(us: u64) {
    record_duration(&ROUTER_SUBMIT_TOTAL_US_TOTAL, &ROUTER_SUBMIT_TOTAL_US_MAX, us);
}

pub fn record_router_submit_target_local_us(us: u64) {
    if node_perf_enabled() {
        ROUTER_SUBMIT_TARGET_LOCAL_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    record_duration(&ROUTER_SUBMIT_TARGET_LOCAL_US_TOTAL, &ROUTER_SUBMIT_TARGET_LOCAL_US_MAX, us);
}

pub fn record_router_submit_target_remote_us(us: u64) {
    if node_perf_enabled() {
        ROUTER_SUBMIT_TARGET_REMOTE_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    record_duration(&ROUTER_SUBMIT_TARGET_REMOTE_US_TOTAL, &ROUTER_SUBMIT_TARGET_REMOTE_US_MAX, us);
}

pub(crate) fn record_router_replay_guard_check_us(us: u64) {
    record_duration(&ROUTER_REPLAY_GUARD_CHECK_US_TOTAL, &ROUTER_REPLAY_GUARD_CHECK_US_MAX, us);
}

pub(crate) fn record_router_save_total_us(us: u64) {
    record_duration(&ROUTER_SAVE_TOTAL_US_TOTAL, &ROUTER_SAVE_TOTAL_US_MAX, us);
}

pub(crate) fn record_router_save_inbox_us(us: u64) {
    record_duration(&ROUTER_SAVE_INBOX_US_TOTAL, &ROUTER_SAVE_INBOX_US_MAX, us);
}

pub(crate) fn record_router_save_replay_guard_us(us: u64) {
    record_duration(&ROUTER_SAVE_REPLAY_GUARD_US_TOTAL, &ROUTER_SAVE_REPLAY_GUARD_US_MAX, us);
}

pub(crate) fn record_router_save_begin_write_us(us: u64) {
    record_duration(&ROUTER_SAVE_BEGIN_WRITE_US_TOTAL, &ROUTER_SAVE_BEGIN_WRITE_US_MAX, us);
}

pub(crate) fn record_router_save_mutation_us(us: u64) {
    record_duration(&ROUTER_SAVE_MUTATION_US_TOTAL, &ROUTER_SAVE_MUTATION_US_MAX, us);
}

pub(crate) fn record_router_save_commit_us(us: u64) {
    record_duration(&ROUTER_SAVE_COMMIT_US_TOTAL, &ROUTER_SAVE_COMMIT_US_MAX, us);
}

pub(crate) fn record_router_wal_batch(record_count: usize, sync_all_us: u64) {
    if node_perf_enabled() {
        ROUTER_WAL_BATCHES_TOTAL.fetch_add(1, Ordering::Relaxed);
        let record_count = u64::try_from(record_count).unwrap_or(u64::MAX);
        ROUTER_WAL_RECORDS_TOTAL.fetch_add(record_count, Ordering::Relaxed);
        ROUTER_WAL_BATCH_SIZE_MAX.fetch_max(record_count, Ordering::Relaxed);
        ROUTER_WAL_SYNC_ALL_US_TOTAL.fetch_add(sync_all_us, Ordering::Relaxed);
        ROUTER_WAL_SYNC_ALL_US_MAX.fetch_max(sync_all_us, Ordering::Relaxed);
    }
}

fn record_duration(total: &AtomicU64, max: &AtomicU64, us: u64) {
    if node_perf_enabled() {
        total.fetch_add(us, Ordering::Relaxed);
        max.fetch_max(us, Ordering::Relaxed);
    }
}

#[must_use]
pub fn node_perf_snapshot() -> NodePerfSnapshot {
    NodePerfSnapshot {
        enabled: node_perf_enabled(),
        gateway_submit_received_total: GATEWAY_SUBMIT_RECEIVED_TOTAL.load(Ordering::Relaxed),
        router_envelope_accepted_total: ROUTER_ENVELOPE_ACCEPTED_TOTAL.load(Ordering::Relaxed),
        router_replay_guard_checks_total: ROUTER_REPLAY_GUARD_CHECKS_TOTAL.load(Ordering::Relaxed),
        router_replay_guard_redb_writes_total: ROUTER_REPLAY_GUARD_REDB_WRITES_TOTAL
            .load(Ordering::Relaxed),
        router_snapshot_saves_total: ROUTER_SNAPSHOT_SAVES_TOTAL.load(Ordering::Relaxed),
        router_ack_total: ROUTER_ACK_TOTAL.load(Ordering::Relaxed),
        router_submit_decode_us_total: ROUTER_SUBMIT_DECODE_US_TOTAL.load(Ordering::Relaxed),
        router_submit_decode_us_max: ROUTER_SUBMIT_DECODE_US_MAX.load(Ordering::Relaxed),
        router_submit_lock_wait_us_total: ROUTER_SUBMIT_LOCK_WAIT_US_TOTAL.load(Ordering::Relaxed),
        router_submit_lock_wait_us_max: ROUTER_SUBMIT_LOCK_WAIT_US_MAX.load(Ordering::Relaxed),
        router_submit_dispatch_us_total: ROUTER_SUBMIT_DISPATCH_US_TOTAL.load(Ordering::Relaxed),
        router_submit_dispatch_us_max: ROUTER_SUBMIT_DISPATCH_US_MAX.load(Ordering::Relaxed),
        router_submit_save_us_total: ROUTER_SUBMIT_SAVE_US_TOTAL.load(Ordering::Relaxed),
        router_submit_save_us_max: ROUTER_SUBMIT_SAVE_US_MAX.load(Ordering::Relaxed),
        router_submit_response_us_total: ROUTER_SUBMIT_RESPONSE_US_TOTAL.load(Ordering::Relaxed),
        router_submit_response_us_max: ROUTER_SUBMIT_RESPONSE_US_MAX.load(Ordering::Relaxed),
        router_submit_total_us_total: ROUTER_SUBMIT_TOTAL_US_TOTAL.load(Ordering::Relaxed),
        router_submit_total_us_max: ROUTER_SUBMIT_TOTAL_US_MAX.load(Ordering::Relaxed),
        router_submit_target_local_total: ROUTER_SUBMIT_TARGET_LOCAL_TOTAL.load(Ordering::Relaxed),
        router_submit_target_remote_total: ROUTER_SUBMIT_TARGET_REMOTE_TOTAL
            .load(Ordering::Relaxed),
        router_submit_target_local_us_total: ROUTER_SUBMIT_TARGET_LOCAL_US_TOTAL
            .load(Ordering::Relaxed),
        router_submit_target_local_us_max: ROUTER_SUBMIT_TARGET_LOCAL_US_MAX
            .load(Ordering::Relaxed),
        router_submit_target_remote_us_total: ROUTER_SUBMIT_TARGET_REMOTE_US_TOTAL
            .load(Ordering::Relaxed),
        router_submit_target_remote_us_max: ROUTER_SUBMIT_TARGET_REMOTE_US_MAX
            .load(Ordering::Relaxed),
        router_replay_guard_check_us_total: ROUTER_REPLAY_GUARD_CHECK_US_TOTAL
            .load(Ordering::Relaxed),
        router_replay_guard_check_us_max: ROUTER_REPLAY_GUARD_CHECK_US_MAX.load(Ordering::Relaxed),
        router_save_total_us_total: ROUTER_SAVE_TOTAL_US_TOTAL.load(Ordering::Relaxed),
        router_save_total_us_max: ROUTER_SAVE_TOTAL_US_MAX.load(Ordering::Relaxed),
        router_save_inbox_us_total: ROUTER_SAVE_INBOX_US_TOTAL.load(Ordering::Relaxed),
        router_save_inbox_us_max: ROUTER_SAVE_INBOX_US_MAX.load(Ordering::Relaxed),
        router_save_replay_guard_us_total: ROUTER_SAVE_REPLAY_GUARD_US_TOTAL
            .load(Ordering::Relaxed),
        router_save_replay_guard_us_max: ROUTER_SAVE_REPLAY_GUARD_US_MAX.load(Ordering::Relaxed),
        router_save_begin_write_us_total: ROUTER_SAVE_BEGIN_WRITE_US_TOTAL.load(Ordering::Relaxed),
        router_save_begin_write_us_max: ROUTER_SAVE_BEGIN_WRITE_US_MAX.load(Ordering::Relaxed),
        router_save_mutation_us_total: ROUTER_SAVE_MUTATION_US_TOTAL.load(Ordering::Relaxed),
        router_save_mutation_us_max: ROUTER_SAVE_MUTATION_US_MAX.load(Ordering::Relaxed),
        router_save_commit_us_total: ROUTER_SAVE_COMMIT_US_TOTAL.load(Ordering::Relaxed),
        router_save_commit_us_max: ROUTER_SAVE_COMMIT_US_MAX.load(Ordering::Relaxed),
        router_wal_batches_total: ROUTER_WAL_BATCHES_TOTAL.load(Ordering::Relaxed),
        router_wal_records_total: ROUTER_WAL_RECORDS_TOTAL.load(Ordering::Relaxed),
        router_wal_batch_size_max: ROUTER_WAL_BATCH_SIZE_MAX.load(Ordering::Relaxed),
        router_wal_sync_all_us_total: ROUTER_WAL_SYNC_ALL_US_TOTAL.load(Ordering::Relaxed),
        router_wal_sync_all_us_max: ROUTER_WAL_SYNC_ALL_US_MAX.load(Ordering::Relaxed),
    }
}

pub fn node_perf_reset() {
    if node_perf_enabled() {
        GATEWAY_SUBMIT_RECEIVED_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_ENVELOPE_ACCEPTED_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_REPLAY_GUARD_CHECKS_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_REPLAY_GUARD_REDB_WRITES_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SNAPSHOT_SAVES_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_ACK_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_DECODE_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_DECODE_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_LOCK_WAIT_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_LOCK_WAIT_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_DISPATCH_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_DISPATCH_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_SAVE_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_SAVE_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_RESPONSE_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_RESPONSE_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_TOTAL_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_TOTAL_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_TARGET_LOCAL_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_TARGET_REMOTE_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_TARGET_LOCAL_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_TARGET_LOCAL_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_TARGET_REMOTE_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SUBMIT_TARGET_REMOTE_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_REPLAY_GUARD_CHECK_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_REPLAY_GUARD_CHECK_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SAVE_TOTAL_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SAVE_TOTAL_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SAVE_INBOX_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SAVE_INBOX_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SAVE_REPLAY_GUARD_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SAVE_REPLAY_GUARD_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SAVE_BEGIN_WRITE_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SAVE_BEGIN_WRITE_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SAVE_MUTATION_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SAVE_MUTATION_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_SAVE_COMMIT_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_SAVE_COMMIT_US_MAX.store(0, Ordering::Relaxed);
        ROUTER_WAL_BATCHES_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_WAL_RECORDS_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_WAL_BATCH_SIZE_MAX.store(0, Ordering::Relaxed);
        ROUTER_WAL_SYNC_ALL_US_TOTAL.store(0, Ordering::Relaxed);
        ROUTER_WAL_SYNC_ALL_US_MAX.store(0, Ordering::Relaxed);
    }
}
