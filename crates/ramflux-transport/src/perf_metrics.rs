// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static MESH_CLIENT_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_TLS_HANDSHAKES_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_CONNECT_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_CONNECT_COUNT: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_POOL_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_POOL_MISSES_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_POOL_IDLE_EVICTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_CACHED_REQUEST_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_RETRIES_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_RETRY_SUCCESSES_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_RETRY_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_REQUEST_TIMEOUTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_EXCHANGE_COUNT: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_EXCHANGE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_EXCHANGE_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_TASK_SCHED_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_TASK_SCHED_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_ACQUIRE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_ACQUIRE_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_OPEN_BI_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_OPEN_BI_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_REQUEST_WRITE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_REQUEST_WRITE_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_RESPONSE_READ_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_RESPONSE_READ_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_RUNTIME_QUEUE_WAIT_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_RUNTIME_QUEUE_WAIT_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_CLIENT_RUNTIME_JOBS_DEQUEUED_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_TLS_HANDSHAKES_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_QUIC_CONNECTIONS_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_QUIC_STREAMS_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_QUIC_STREAM_ACCEPT_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_QUIC_STREAM_ACCEPT_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_QUIC_REQUEST_READ_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_QUIC_REQUEST_READ_US_MAX: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_QUIC_RESPONSE_WRITE_US_TOTAL: AtomicU64 = AtomicU64::new(0);
static MESH_SERVER_QUIC_RESPONSE_WRITE_US_MAX: AtomicU64 = AtomicU64::new(0);
static PERF_ENABLED: OnceLock<bool> = OnceLock::new();

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct MeshHttpPerfSnapshot {
    pub enabled: bool,
    pub mesh_client_requests_total: u64,
    pub mesh_client_tls_handshakes_total: u64,
    pub mesh_client_connect_ms_total: u64,
    pub mesh_client_connect_count: u64,
    pub mesh_client_pool_hits_total: u64,
    pub mesh_client_pool_misses_total: u64,
    pub mesh_client_pool_idle_evictions_total: u64,
    pub mesh_client_cached_request_failures_total: u64,
    pub mesh_client_retries_total: u64,
    pub mesh_client_retry_successes_total: u64,
    pub mesh_client_retry_failures_total: u64,
    pub mesh_client_request_timeouts_total: u64,
    pub mesh_client_exchange_count: u64,
    pub mesh_client_exchange_us_total: u64,
    pub mesh_client_exchange_us_max: u64,
    pub mesh_client_task_sched_us_total: u64,
    pub mesh_client_task_sched_us_max: u64,
    pub mesh_client_acquire_us_total: u64,
    pub mesh_client_acquire_us_max: u64,
    pub mesh_client_open_bi_us_total: u64,
    pub mesh_client_open_bi_us_max: u64,
    pub mesh_client_request_write_us_total: u64,
    pub mesh_client_request_write_us_max: u64,
    pub mesh_client_response_read_us_total: u64,
    pub mesh_client_response_read_us_max: u64,
    pub mesh_client_runtime_queue_wait_us_total: u64,
    pub mesh_client_runtime_queue_wait_us_max: u64,
    pub mesh_client_runtime_jobs_dequeued_total: u64,
    pub mesh_server_tls_handshakes_total: u64,
    pub mesh_server_quic_connections_accepted_total: u64,
    pub mesh_server_quic_streams_accepted_total: u64,
    pub mesh_server_quic_stream_accept_us_total: u64,
    pub mesh_server_quic_stream_accept_us_max: u64,
    pub mesh_server_quic_request_read_us_total: u64,
    pub mesh_server_quic_request_read_us_max: u64,
    pub mesh_server_quic_response_write_us_total: u64,
    pub mesh_server_quic_response_write_us_max: u64,
}

#[must_use]
pub fn mesh_perf_enabled() -> bool {
    *PERF_ENABLED.get_or_init(|| std::env::var("RAMFLUX_ITEST_PERF").as_deref() == Ok("1"))
}

pub(crate) fn record_mesh_client_request() {
    if mesh_perf_enabled() {
        MESH_CLIENT_REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_tls_handshake() {
    if mesh_perf_enabled() {
        MESH_CLIENT_TLS_HANDSHAKES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_connect(duration: Duration) {
    if mesh_perf_enabled() {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        MESH_CLIENT_CONNECT_MS_TOTAL.fetch_add(millis, Ordering::Relaxed);
        MESH_CLIENT_CONNECT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_pool_hit() {
    if mesh_perf_enabled() {
        MESH_CLIENT_POOL_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_pool_miss() {
    if mesh_perf_enabled() {
        MESH_CLIENT_POOL_MISSES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_pool_idle_eviction() {
    if mesh_perf_enabled() {
        MESH_CLIENT_POOL_IDLE_EVICTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_cached_request_failure() {
    if mesh_perf_enabled() {
        MESH_CLIENT_CACHED_REQUEST_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_retry() {
    if mesh_perf_enabled() {
        MESH_CLIENT_RETRIES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_retry_success() {
    if mesh_perf_enabled() {
        MESH_CLIENT_RETRY_SUCCESSES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_retry_failure() {
    if mesh_perf_enabled() {
        MESH_CLIENT_RETRY_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_request_timeout() {
    if mesh_perf_enabled() {
        MESH_CLIENT_REQUEST_TIMEOUTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_client_exchange(duration: Duration) {
    if mesh_perf_enabled() {
        MESH_CLIENT_EXCHANGE_COUNT.fetch_add(1, Ordering::Relaxed);
        record_duration(&MESH_CLIENT_EXCHANGE_US_TOTAL, &MESH_CLIENT_EXCHANGE_US_MAX, duration);
    }
}

pub(crate) fn record_mesh_client_task_sched(duration: Duration) {
    record_duration(&MESH_CLIENT_TASK_SCHED_US_TOTAL, &MESH_CLIENT_TASK_SCHED_US_MAX, duration);
}

pub(crate) fn record_mesh_client_acquire(duration: Duration) {
    record_duration(&MESH_CLIENT_ACQUIRE_US_TOTAL, &MESH_CLIENT_ACQUIRE_US_MAX, duration);
}

pub(crate) fn record_mesh_client_open_bi(duration: Duration) {
    record_duration(&MESH_CLIENT_OPEN_BI_US_TOTAL, &MESH_CLIENT_OPEN_BI_US_MAX, duration);
}

pub(crate) fn record_mesh_client_request_write(duration: Duration) {
    record_duration(
        &MESH_CLIENT_REQUEST_WRITE_US_TOTAL,
        &MESH_CLIENT_REQUEST_WRITE_US_MAX,
        duration,
    );
}

pub(crate) fn record_mesh_client_response_read(duration: Duration) {
    record_duration(
        &MESH_CLIENT_RESPONSE_READ_US_TOTAL,
        &MESH_CLIENT_RESPONSE_READ_US_MAX,
        duration,
    );
}

pub(crate) fn record_mesh_client_runtime_queue_wait(duration: Duration) {
    if mesh_perf_enabled() {
        MESH_CLIENT_RUNTIME_JOBS_DEQUEUED_TOTAL.fetch_add(1, Ordering::Relaxed);
        record_duration(
            &MESH_CLIENT_RUNTIME_QUEUE_WAIT_US_TOTAL,
            &MESH_CLIENT_RUNTIME_QUEUE_WAIT_US_MAX,
            duration,
        );
    }
}

pub(crate) fn record_mesh_server_tls_handshake() {
    if mesh_perf_enabled() {
        MESH_SERVER_TLS_HANDSHAKES_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_server_quic_connection_accepted() {
    if mesh_perf_enabled() {
        MESH_SERVER_QUIC_CONNECTIONS_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_mesh_server_quic_stream_accepted(duration: Duration) {
    if mesh_perf_enabled() {
        MESH_SERVER_QUIC_STREAMS_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        record_duration(
            &MESH_SERVER_QUIC_STREAM_ACCEPT_US_TOTAL,
            &MESH_SERVER_QUIC_STREAM_ACCEPT_US_MAX,
            duration,
        );
    }
}

pub(crate) fn record_mesh_server_quic_request_read(duration: Duration) {
    record_duration(
        &MESH_SERVER_QUIC_REQUEST_READ_US_TOTAL,
        &MESH_SERVER_QUIC_REQUEST_READ_US_MAX,
        duration,
    );
}

pub(crate) fn record_mesh_server_quic_response_write(duration: Duration) {
    record_duration(
        &MESH_SERVER_QUIC_RESPONSE_WRITE_US_TOTAL,
        &MESH_SERVER_QUIC_RESPONSE_WRITE_US_MAX,
        duration,
    );
}

fn record_duration(total: &AtomicU64, max: &AtomicU64, duration: Duration) {
    if mesh_perf_enabled() {
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        total.fetch_add(micros, Ordering::Relaxed);
        max.fetch_max(micros, Ordering::Relaxed);
    }
}

#[must_use]
pub fn mesh_perf_snapshot() -> MeshHttpPerfSnapshot {
    MeshHttpPerfSnapshot {
        enabled: mesh_perf_enabled(),
        mesh_client_requests_total: MESH_CLIENT_REQUESTS_TOTAL.load(Ordering::Relaxed),
        mesh_client_tls_handshakes_total: MESH_CLIENT_TLS_HANDSHAKES_TOTAL.load(Ordering::Relaxed),
        mesh_client_connect_ms_total: MESH_CLIENT_CONNECT_MS_TOTAL.load(Ordering::Relaxed),
        mesh_client_connect_count: MESH_CLIENT_CONNECT_COUNT.load(Ordering::Relaxed),
        mesh_client_pool_hits_total: MESH_CLIENT_POOL_HITS_TOTAL.load(Ordering::Relaxed),
        mesh_client_pool_misses_total: MESH_CLIENT_POOL_MISSES_TOTAL.load(Ordering::Relaxed),
        mesh_client_pool_idle_evictions_total: MESH_CLIENT_POOL_IDLE_EVICTIONS_TOTAL
            .load(Ordering::Relaxed),
        mesh_client_cached_request_failures_total: MESH_CLIENT_CACHED_REQUEST_FAILURES_TOTAL
            .load(Ordering::Relaxed),
        mesh_client_retries_total: MESH_CLIENT_RETRIES_TOTAL.load(Ordering::Relaxed),
        mesh_client_retry_successes_total: MESH_CLIENT_RETRY_SUCCESSES_TOTAL
            .load(Ordering::Relaxed),
        mesh_client_retry_failures_total: MESH_CLIENT_RETRY_FAILURES_TOTAL.load(Ordering::Relaxed),
        mesh_client_request_timeouts_total: MESH_CLIENT_REQUEST_TIMEOUTS_TOTAL
            .load(Ordering::Relaxed),
        mesh_client_exchange_count: MESH_CLIENT_EXCHANGE_COUNT.load(Ordering::Relaxed),
        mesh_client_exchange_us_total: MESH_CLIENT_EXCHANGE_US_TOTAL.load(Ordering::Relaxed),
        mesh_client_exchange_us_max: MESH_CLIENT_EXCHANGE_US_MAX.load(Ordering::Relaxed),
        mesh_client_task_sched_us_total: MESH_CLIENT_TASK_SCHED_US_TOTAL.load(Ordering::Relaxed),
        mesh_client_task_sched_us_max: MESH_CLIENT_TASK_SCHED_US_MAX.load(Ordering::Relaxed),
        mesh_client_acquire_us_total: MESH_CLIENT_ACQUIRE_US_TOTAL.load(Ordering::Relaxed),
        mesh_client_acquire_us_max: MESH_CLIENT_ACQUIRE_US_MAX.load(Ordering::Relaxed),
        mesh_client_open_bi_us_total: MESH_CLIENT_OPEN_BI_US_TOTAL.load(Ordering::Relaxed),
        mesh_client_open_bi_us_max: MESH_CLIENT_OPEN_BI_US_MAX.load(Ordering::Relaxed),
        mesh_client_request_write_us_total: MESH_CLIENT_REQUEST_WRITE_US_TOTAL
            .load(Ordering::Relaxed),
        mesh_client_request_write_us_max: MESH_CLIENT_REQUEST_WRITE_US_MAX.load(Ordering::Relaxed),
        mesh_client_response_read_us_total: MESH_CLIENT_RESPONSE_READ_US_TOTAL
            .load(Ordering::Relaxed),
        mesh_client_response_read_us_max: MESH_CLIENT_RESPONSE_READ_US_MAX.load(Ordering::Relaxed),
        mesh_client_runtime_queue_wait_us_total: MESH_CLIENT_RUNTIME_QUEUE_WAIT_US_TOTAL
            .load(Ordering::Relaxed),
        mesh_client_runtime_queue_wait_us_max: MESH_CLIENT_RUNTIME_QUEUE_WAIT_US_MAX
            .load(Ordering::Relaxed),
        mesh_client_runtime_jobs_dequeued_total: MESH_CLIENT_RUNTIME_JOBS_DEQUEUED_TOTAL
            .load(Ordering::Relaxed),
        mesh_server_tls_handshakes_total: MESH_SERVER_TLS_HANDSHAKES_TOTAL.load(Ordering::Relaxed),
        mesh_server_quic_connections_accepted_total: MESH_SERVER_QUIC_CONNECTIONS_ACCEPTED_TOTAL
            .load(Ordering::Relaxed),
        mesh_server_quic_streams_accepted_total: MESH_SERVER_QUIC_STREAMS_ACCEPTED_TOTAL
            .load(Ordering::Relaxed),
        mesh_server_quic_stream_accept_us_total: MESH_SERVER_QUIC_STREAM_ACCEPT_US_TOTAL
            .load(Ordering::Relaxed),
        mesh_server_quic_stream_accept_us_max: MESH_SERVER_QUIC_STREAM_ACCEPT_US_MAX
            .load(Ordering::Relaxed),
        mesh_server_quic_request_read_us_total: MESH_SERVER_QUIC_REQUEST_READ_US_TOTAL
            .load(Ordering::Relaxed),
        mesh_server_quic_request_read_us_max: MESH_SERVER_QUIC_REQUEST_READ_US_MAX
            .load(Ordering::Relaxed),
        mesh_server_quic_response_write_us_total: MESH_SERVER_QUIC_RESPONSE_WRITE_US_TOTAL
            .load(Ordering::Relaxed),
        mesh_server_quic_response_write_us_max: MESH_SERVER_QUIC_RESPONSE_WRITE_US_MAX
            .load(Ordering::Relaxed),
    }
}

pub fn mesh_perf_reset() {
    if mesh_perf_enabled() {
        MESH_CLIENT_REQUESTS_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_TLS_HANDSHAKES_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_CONNECT_MS_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_CONNECT_COUNT.store(0, Ordering::Relaxed);
        MESH_CLIENT_POOL_HITS_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_POOL_MISSES_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_POOL_IDLE_EVICTIONS_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_CACHED_REQUEST_FAILURES_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_RETRIES_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_RETRY_SUCCESSES_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_RETRY_FAILURES_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_REQUEST_TIMEOUTS_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_EXCHANGE_COUNT.store(0, Ordering::Relaxed);
        MESH_CLIENT_EXCHANGE_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_EXCHANGE_US_MAX.store(0, Ordering::Relaxed);
        MESH_CLIENT_TASK_SCHED_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_TASK_SCHED_US_MAX.store(0, Ordering::Relaxed);
        MESH_CLIENT_ACQUIRE_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_ACQUIRE_US_MAX.store(0, Ordering::Relaxed);
        MESH_CLIENT_OPEN_BI_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_OPEN_BI_US_MAX.store(0, Ordering::Relaxed);
        MESH_CLIENT_REQUEST_WRITE_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_REQUEST_WRITE_US_MAX.store(0, Ordering::Relaxed);
        MESH_CLIENT_RESPONSE_READ_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_RESPONSE_READ_US_MAX.store(0, Ordering::Relaxed);
        MESH_CLIENT_RUNTIME_QUEUE_WAIT_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_CLIENT_RUNTIME_QUEUE_WAIT_US_MAX.store(0, Ordering::Relaxed);
        MESH_CLIENT_RUNTIME_JOBS_DEQUEUED_TOTAL.store(0, Ordering::Relaxed);
        MESH_SERVER_TLS_HANDSHAKES_TOTAL.store(0, Ordering::Relaxed);
        MESH_SERVER_QUIC_CONNECTIONS_ACCEPTED_TOTAL.store(0, Ordering::Relaxed);
        MESH_SERVER_QUIC_STREAMS_ACCEPTED_TOTAL.store(0, Ordering::Relaxed);
        MESH_SERVER_QUIC_STREAM_ACCEPT_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_SERVER_QUIC_STREAM_ACCEPT_US_MAX.store(0, Ordering::Relaxed);
        MESH_SERVER_QUIC_REQUEST_READ_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_SERVER_QUIC_REQUEST_READ_US_MAX.store(0, Ordering::Relaxed);
        MESH_SERVER_QUIC_RESPONSE_WRITE_US_TOTAL.store(0, Ordering::Relaxed);
        MESH_SERVER_QUIC_RESPONSE_WRITE_US_MAX.store(0, Ordering::Relaxed);
    }
}
