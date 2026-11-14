// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{
    Arc, Mutex as StdMutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

use crate::mesh_tls::extract_spiffe_uri_from_certificate;
use crate::perf_metrics::{
    record_mesh_client_acquire, record_mesh_client_cached_request_failure,
    record_mesh_client_connect, record_mesh_client_exchange, record_mesh_client_open_bi,
    record_mesh_client_pool_hit, record_mesh_client_pool_miss, record_mesh_client_request,
    record_mesh_client_request_timeout, record_mesh_client_request_write,
    record_mesh_client_response_read, record_mesh_client_retry, record_mesh_client_retry_failure,
    record_mesh_client_retry_success, record_mesh_client_runtime_queue_wait,
    record_mesh_client_task_sched, record_mesh_client_tls_handshake,
    record_mesh_server_quic_connection_accepted, record_mesh_server_quic_request_read,
    record_mesh_server_quic_response_write, record_mesh_server_quic_stream_accepted,
};
use crate::tls_config::{
    MeshRootPemProvider, mesh_quic_client_config_with_pem_roots,
    mesh_quic_server_config_with_dynamic_pem_roots,
};
use crate::{
    GatewayQuicRequest, GatewayQuicResponse, MeshTlsConfig, TransportError,
    quic_gateway::{read_quic_raw_frame, write_quic_raw_frame},
    read_quic_json_frame, write_quic_json_message,
};
mod raw_request;
use arc_swap::ArcSwap;
pub use raw_request::{MeshQuicRawPost, mesh_quic_post_raw_with_peer_ca_pems_async};
use tokio::sync::{Mutex, Notify};

/// Paths under this prefix keep their request body bytes exactly as received.
pub const RAW_BODY_PATH_PREFIX: &str = "/s9/attachments/";

fn raw_attachment_body(frame: &[u8]) -> Result<Vec<u8>, ramflux_protocol::ProtocolError> {
    ramflux_protocol::validate_i_json_bytes(frame)?;
    let raw = serde_json::from_slice::<crate::mesh_quic_limited::RawBodyOnly>(frame)
        .map_err(ramflux_protocol::ProtocolError::IJson)?;
    Ok(raw.body.get().as_bytes().to_vec())
}
const MESH_QUIC_CONNECT_TIMEOUT_DEFAULT: Duration = Duration::from_secs(3);
const MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT: Duration = Duration::from_secs(5);
const MESH_QUIC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MESH_QUIC_CACHED_CONNECTION_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MESH_I_JSON_REJECT_DEADLINE: Duration = Duration::from_secs(2);
const MESH_I_JSON_REJECTED_CODE: u32 = 0x4A53;
// Backstop poll interval for the pool-acquire wait: even if a wakeup is ever missed,
// re-check pool state at least this often instead of blocking forever.
const MESH_QUIC_ACQUIRE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const MESH_QUIC_CLIENT_POOL_SIZE_ENV: &str = "RAMFLUX_MESH_QUIC_CLIENT_POOL_SIZE";
const ROUTER_ASYNC_POOL_SIZE_ENV: &str = "RAMFLUX_ROUTER_ASYNC_POOL_SIZE";
const MESH_QUIC_CONNECT_TIMEOUT_MS_ENV: &str = "RAMFLUX_MESH_QUIC_CONNECT_TIMEOUT_MS";
const MESH_QUIC_CONNECT_BREAKER_COOLDOWN_MS_ENV: &str =
    "RAMFLUX_MESH_QUIC_CONNECT_BREAKER_COOLDOWN_MS";
const MESH_QUIC_CLIENT_POOL_SIZE_DEFAULT: usize = 8;
const MESH_QUIC_POSTCARD_MAGIC: &[u8] = b"ramflux.mesh.postcard.v1\0";

pub struct MeshQuicServer {
    endpoint: quinn::Endpoint,
}

pub struct MeshQuicConnection {
    pub(crate) connection: quinn::Connection,
    pub(crate) peer_spiffe_uri: Option<String>,
}

pub struct MeshQuicAcceptedRequest {
    pub request: GatewayQuicRequest,
    /// The body exactly as received, kept for [`RAW_BODY_PATH_PREFIX`] routes so their
    /// byte cap is enforced on the wire bytes, not on a re-serialized `Value`.
    pub raw_body: Option<Vec<u8>>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

pub struct MeshQuicPostcardAcceptedRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

pub struct MeshQuicAcceptedBiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
    pub remote_address: SocketAddr,
}

pub enum MeshQuicAcceptedWireRequest {
    Json(MeshQuicAcceptedRequest),
    Postcard(MeshQuicPostcardAcceptedRequest),
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct MeshQuicPostcardRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct MeshQuicPostcardResponse {
    status: u16,
    body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MeshQuicPoolKey {
    endpoint: String,
    server_name: String,
    peer_addr: SocketAddr,
    peer_ca_pems: Vec<String>,
}

struct MeshQuicClientJob {
    request: MeshQuicClientRequestJob,
    response: MeshQuicClientResponse,
    raw: Option<raw_request::RawRequestControl>,
}

struct MeshQuicClientRequestJob {
    endpoint: String,
    server_name: String,
    tls: MeshTlsConfig,
    peer_ca_pems: Vec<String>,
    request: MeshQuicClientRequestPayload,
    expected_gateway_instance: Option<String>,
    enqueued_at: std::time::Instant,
}

enum MeshQuicClientRequestPayload {
    RawJson(GatewayQuicRequest),
    Json(GatewayQuicRequest),
    Postcard(MeshQuicPostcardRequest),
}

enum MeshQuicClientResponsePayload {
    RawJson(Vec<u8>),
    Json(GatewayQuicResponse),
    Postcard(MeshQuicPostcardResponse),
}

enum MeshQuicClientResponse {
    Sync(mpsc::Sender<Result<MeshQuicClientResponsePayload, TransportError>>),
    Async(tokio::sync::oneshot::Sender<Result<MeshQuicClientResponsePayload, TransportError>>),
}

impl MeshQuicClientResponse {
    /// Resolves when the waiting caller has dropped its receiver. Sync callers
    /// cannot signal cancellation, so their side never resolves.
    async fn closed(&mut self) {
        match self {
            Self::Sync(_) => std::future::pending::<()>().await,
            Self::Async(sender) => sender.closed().await,
        }
    }

    fn send(self, result: Result<MeshQuicClientResponsePayload, TransportError>) {
        match self {
            Self::Sync(sender) => {
                let _sent = sender.send(result);
            }
            Self::Async(sender) => {
                let _sent = sender.send(result);
            }
        }
    }
}

struct MeshQuicClientRuntime {
    jobs: mpsc::Sender<MeshQuicClientJob>,
}

struct MeshQuicCachedConnection {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

struct MeshQuicSelectedConnection {
    cached: Arc<MeshQuicCachedConnection>,
}

impl MeshQuicSelectedConnection {
    fn connection(&self) -> &quinn::Connection {
        &self.cached.connection
    }

    fn remote_address(&self) -> SocketAddr {
        self.cached.connection.remote_address()
    }

    fn stable_id(&self) -> usize {
        self.cached.connection.stable_id()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MeshQuicCircuitBreakerKey {
    peer_addr: SocketAddr,
    server_name: String,
}

#[derive(Clone, Debug)]
struct MeshQuicCircuitProbe {
    key: MeshQuicCircuitBreakerKey,
    previous: Option<MeshQuicCircuitBreakerState>,
}

#[derive(Clone, Copy, Debug)]
enum MeshQuicCircuitBreakerState {
    Open { retry_after: Instant },
    HalfOpen,
}

#[derive(Default)]
struct MeshQuicCircuitBreakers {
    states: StdMutex<HashMap<MeshQuicCircuitBreakerKey, MeshQuicCircuitBreakerState>>,
}

impl MeshQuicCircuitBreakers {
    fn before_connect(
        &self,
        peer_addr: SocketAddr,
        server_name: &str,
        now: Instant,
    ) -> Result<MeshQuicCircuitProbe, TransportError> {
        let key = MeshQuicCircuitBreakerKey { peer_addr, server_name: server_name.to_owned() };
        let mut states = self.states.lock().map_err(|error| {
            TransportError::Quic(format!("mesh QUIC circuit breaker lock poisoned: {error}"))
        })?;
        match states.get(&key).copied() {
            Some(MeshQuicCircuitBreakerState::Open { retry_after }) if now < retry_after => {
                let remaining_ms = retry_after.saturating_duration_since(now).as_millis();
                Err(TransportError::Quic(format!(
                    "mesh QUIC circuit breaker open for {server_name}@{peer_addr}; skipping connect for {remaining_ms}ms"
                )))
            }
            Some(MeshQuicCircuitBreakerState::Open { retry_after }) => {
                states.insert(key.clone(), MeshQuicCircuitBreakerState::HalfOpen);
                Ok(MeshQuicCircuitProbe {
                    key,
                    previous: Some(MeshQuicCircuitBreakerState::Open { retry_after }),
                })
            }
            Some(MeshQuicCircuitBreakerState::HalfOpen) => Err(TransportError::Quic(format!(
                "mesh QUIC circuit breaker half-open probe already in flight for {server_name}@{peer_addr}; skipping connect"
            ))),
            None => Ok(MeshQuicCircuitProbe { key, previous: None }),
        }
    }

    fn record_connect_failure(
        &self,
        probe: &MeshQuicCircuitProbe,
        now: Instant,
        cooldown: Duration,
    ) {
        let retry_after = now + cooldown;
        match self.states.lock() {
            Ok(mut states) => {
                states.insert(probe.key.clone(), MeshQuicCircuitBreakerState::Open { retry_after });
            }
            Err(error) => {
                tracing::warn!(%error, "mesh QUIC circuit breaker lock poisoned while recording failure");
            }
        }
    }

    fn record_connect_error(
        &self,
        probe: &MeshQuicCircuitProbe,
        error: &TransportError,
        now: Instant,
        cooldown: Duration,
    ) {
        if !error.is_tls_failure() {
            self.record_connect_failure(probe, now, cooldown);
        } else if let Some(previous) = probe.previous {
            // Restore an acquired half-open probe; a trust error is neither a transport success
            // nor an outage. Do not erase a concurrent attempt's newer availability failure.
            if let Ok(mut states) = self.states.lock()
                && matches!(states.get(&probe.key), Some(MeshQuicCircuitBreakerState::HalfOpen))
            {
                states.insert(probe.key.clone(), previous);
            }
        }
    }

    fn record_connect_success(&self, probe: &MeshQuicCircuitProbe) {
        match self.states.lock() {
            Ok(mut states) => {
                states.remove(&probe.key);
            }
            Err(error) => {
                tracing::warn!(%error, "mesh QUIC circuit breaker lock poisoned while recording success");
            }
        }
    }

    /// Gives back a half-open probe whose attempt was cancelled before any outcome was recorded.
    /// The breaker returns to the state the probe found, so the next dial can probe again.
    fn release_connect_probe(&self, probe: &MeshQuicCircuitProbe) {
        let Some(previous) = probe.previous else {
            return;
        };
        if let Ok(mut states) = self.states.lock()
            && matches!(states.get(&probe.key), Some(MeshQuicCircuitBreakerState::HalfOpen))
        {
            states.insert(probe.key.clone(), previous);
        }
    }
}

/// Owns a probe acquired by `before_connect`. Every connect outcome settles it; if the attempt
/// is cancelled first, dropping the guard releases the half-open slot.
struct MeshQuicCircuitProbeGuard<'a> {
    breakers: &'a MeshQuicCircuitBreakers,
    probe: MeshQuicCircuitProbe,
    settled: bool,
}

impl<'a> MeshQuicCircuitProbeGuard<'a> {
    fn new(breakers: &'a MeshQuicCircuitBreakers, probe: MeshQuicCircuitProbe) -> Self {
        Self { breakers, probe, settled: false }
    }

    fn record_connect_failure(&mut self, now: Instant, cooldown: Duration) {
        self.breakers.record_connect_failure(&self.probe, now, cooldown);
        self.settled = true;
    }

    fn record_connect_error(&mut self, error: &TransportError, now: Instant, cooldown: Duration) {
        self.breakers.record_connect_error(&self.probe, error, now, cooldown);
        self.settled = true;
    }

    fn record_connect_success(&mut self) {
        self.breakers.record_connect_success(&self.probe);
        self.settled = true;
    }
}

impl Drop for MeshQuicCircuitProbeGuard<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.breakers.release_connect_probe(&self.probe);
        }
    }
}

#[derive(Default)]
struct MeshQuicPoolRegistry {
    pools: ArcSwap<HashMap<MeshQuicPoolKey, Arc<MeshQuicConnectionPool>>>,
    write_lock: Mutex<()>,
}

impl MeshQuicPoolRegistry {
    async fn pool_for(&self, key: MeshQuicPoolKey) -> Arc<MeshQuicConnectionPool> {
        let snapshot = self.pools.load();
        if let Some(pool) = snapshot.get(&key) {
            return Arc::clone(pool);
        }
        let _guard = self.write_lock.lock().await;
        let snapshot = self.pools.load();
        if let Some(pool) = snapshot.get(&key) {
            return Arc::clone(pool);
        }
        let pool = Arc::new(MeshQuicConnectionPool::default());
        let mut next = snapshot.as_ref().clone();
        next.insert(key, Arc::clone(&pool));
        self.pools.store(Arc::new(next));
        pool
    }
}

/// Owns one `connecting` slot of a pool. Dropping it (success, error, timeout or cancellation)
/// releases the slot and wakes waiters.
struct MeshQuicConnectReservation<'a> {
    pool: &'a MeshQuicConnectionPool,
}

impl Drop for MeshQuicConnectReservation<'_> {
    fn drop(&mut self) {
        self.pool.finish_connect_reservation();
    }
}

#[derive(Default)]
struct MeshQuicConnectionPool {
    next: AtomicUsize,
    connecting: AtomicUsize,
    connections: ArcSwap<Vec<Arc<MeshQuicCachedConnection>>>,
    write_lock: Mutex<()>,
    notify: Notify,
}

impl MeshQuicConnectionPool {
    fn select_connection(&self) -> Option<MeshQuicSelectedConnection> {
        let connections = self.connections.load();
        if connections.is_empty() {
            return None;
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for offset in 0..connections.len() {
            let index = start.wrapping_add(offset) % connections.len();
            let cached = &connections[index];
            if cached.connection.close_reason().is_none() {
                return Some(MeshQuicSelectedConnection { cached: Arc::clone(cached) });
            }
        }
        None
    }

    fn try_reserve_connect(&self, pool_size: usize) -> bool {
        let pool_size = pool_size.max(1);
        loop {
            let live = self.live_connection_count();
            let connecting = self.connecting.load(Ordering::Acquire);
            if live.saturating_add(connecting) >= pool_size {
                return false;
            }
            if self
                .connecting
                .compare_exchange(
                    connecting,
                    connecting.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    fn finish_connect_reservation(&self) {
        self.connecting.fetch_sub(1, Ordering::AcqRel);
        self.notify.notify_waiters();
    }

    async fn insert_connection(
        &self,
        cached: MeshQuicCachedConnection,
        pool_size: usize,
    ) -> MeshQuicSelectedConnection {
        let cached = Arc::new(cached);
        let _guard = self.write_lock.lock().await;
        let mut next = self.live_connections_snapshot();
        if next.len() < pool_size.max(1) {
            next.push(Arc::clone(&cached));
            self.connections.store(Arc::new(next));
        } else {
            self.connections.store(Arc::new(next));
        }
        self.notify.notify_waiters();
        MeshQuicSelectedConnection { cached }
    }

    async fn remove_connection(&self, target: &MeshQuicSelectedConnection) {
        let _guard = self.write_lock.lock().await;
        let snapshot = self.connections.load();
        let next: Vec<_> = snapshot
            .iter()
            .filter(|cached| {
                !Arc::ptr_eq(cached, &target.cached) && cached.connection.close_reason().is_none()
            })
            .cloned()
            .collect();
        if next.len() != snapshot.len() {
            self.connections.store(Arc::new(next));
        }
        self.notify.notify_waiters();
    }

    fn live_connection_count(&self) -> usize {
        self.connections
            .load()
            .iter()
            .filter(|cached| cached.connection.close_reason().is_none())
            .count()
    }

    fn live_connections_snapshot(&self) -> Vec<Arc<MeshQuicCachedConnection>> {
        self.connections
            .load()
            .iter()
            .filter(|cached| cached.connection.close_reason().is_none())
            .cloned()
            .collect()
    }
}

impl MeshQuicServer {
    /// # Errors
    /// Returns an error when the UDP socket cannot bind or TLS material cannot be loaded.
    pub fn bind_with_pem_roots_provider(
        addr: &str,
        tls: &MeshTlsConfig,
        root_pems_provider: MeshRootPemProvider,
    ) -> Result<Self, TransportError> {
        tracing::info!(addr, "binding mesh QUIC endpoint");
        let socket_addr = addr
            .parse()
            .map_err(|error| TransportError::Quic(format!("bad QUIC bind addr: {error}")))?;
        let server_config =
            mesh_quic_server_config_with_dynamic_pem_roots(tls, root_pems_provider)?;
        let endpoint = quinn::Endpoint::server(server_config, socket_addr)?;
        tracing::info!(
            addr,
            local_addr = %endpoint.local_addr()?,
            "mesh QUIC endpoint bound"
        );
        Ok(Self { endpoint })
    }

    /// # Errors
    /// Returns an error when TLS material cannot be loaded or QUIC cannot use the socket.
    pub fn bind_with_udp_socket_and_pem_roots_provider(
        socket: std::net::UdpSocket,
        tls: &MeshTlsConfig,
        root_pems_provider: MeshRootPemProvider,
    ) -> Result<Self, TransportError> {
        let socket_addr = socket.local_addr()?;
        tracing::info!(addr = %socket_addr, "binding mesh QUIC endpoint from UDP socket");
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(mesh_quic_server_config_with_dynamic_pem_roots(tls, root_pems_provider)?),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        tracing::info!(
            addr = %socket_addr,
            local_addr = %endpoint.local_addr()?,
            "mesh QUIC endpoint bound from UDP socket"
        );
        Ok(Self { endpoint })
    }

    /// # Errors
    /// Returns an error when the local UDP address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    /// # Errors
    /// Returns an error when QUIC accept or handshake fails.
    pub async fn accept_connection(&self) -> Result<MeshQuicConnection, TransportError> {
        let connecting = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| TransportError::Quic("mesh QUIC endpoint closed".to_owned()))?;
        let remote_address = connecting.remote_address();
        tracing::info!(%remote_address, "mesh QUIC connection accepted; completing handshake");
        let connection = connecting.await.map_err(|error| {
            tracing::error!(%remote_address, %error, "mesh QUIC handshake failed");
            crate::quic_errors::connection(&error)
        })?;
        record_mesh_server_quic_connection_accepted();
        tracing::info!(%remote_address, "mesh QUIC handshake completed");
        let peer_spiffe_uri = quinn_peer_spiffe_uri(&connection)?;
        Ok(MeshQuicConnection { connection, peer_spiffe_uri })
    }

    /// # Errors
    /// Returns an error when accepting a bidirectional QUIC stream fails.
    pub async fn accept_bi_on_connection(
        connection: &MeshQuicConnection,
    ) -> Result<MeshQuicAcceptedBiStream, TransportError> {
        let remote_address = connection.remote_address();
        let stream_accept_started = std::time::Instant::now();
        let (send, recv) = connection
            .connection
            .accept_bi()
            .await
            .map_err(|error| {
                tracing::error!(%remote_address, %error, "mesh QUIC bidirectional stream accept failed");
                TransportError::Quic(format!(
                    "mesh QUIC bidirectional stream accept failed from {remote_address}: {error}"
                ))
            })?;
        record_mesh_server_quic_stream_accepted(stream_accept_started.elapsed());
        Ok(MeshQuicAcceptedBiStream { send, recv, remote_address })
    }

    /// # Errors
    /// Returns an error when request framing or decoding fails.
    pub async fn read_wire_request_from_bi(
        stream: MeshQuicAcceptedBiStream,
    ) -> Result<MeshQuicAcceptedWireRequest, TransportError> {
        Self::read_wire_request_from_bi_with_deadline(stream, None).await
    }

    async fn read_wire_request_from_bi_with_deadline(
        stream: MeshQuicAcceptedBiStream,
        reject_deadline: Option<Instant>,
    ) -> Result<MeshQuicAcceptedWireRequest, TransportError> {
        let MeshQuicAcceptedBiStream { send, mut recv, remote_address } = stream;
        let request_read_started = std::time::Instant::now();
        let frame = read_quic_raw_frame(&mut recv).await.map_err(|error| {
            tracing::error!(%remote_address, %error, "mesh QUIC request frame decode failed");
            error
        })?;
        record_mesh_server_quic_request_read(request_read_started.elapsed());
        if let Some(body) = frame.strip_prefix(MESH_QUIC_POSTCARD_MAGIC) {
            let request = postcard_from_bytes::<MeshQuicPostcardRequest>(body)?;
            return Ok(MeshQuicAcceptedWireRequest::Postcard(MeshQuicPostcardAcceptedRequest {
                method: request.method,
                path: request.path,
                body: request.body,
                send,
                recv,
            }));
        }
        let request = match ramflux_protocol::parse_i_json::<GatewayQuicRequest>(&frame) {
            Ok(request) => request,
            Err(error) => {
                let error = TransportError::Protocol(error);
                if ramflux_protocol::is_i_json_rejection(&error) {
                    reject_i_json(
                        send,
                        recv,
                        reject_deadline
                            .unwrap_or_else(|| Instant::now() + MESH_I_JSON_REJECT_DEADLINE),
                    );
                }
                return Err(error);
            }
        };
        let raw_body = if request.path.starts_with(RAW_BODY_PATH_PREFIX) {
            let raw = match ramflux_protocol::validate_i_json_bytes(&frame).and_then(|()| {
                serde_json::from_slice::<crate::mesh_quic_limited::RawBodyOnly>(&frame)
                    .map_err(ramflux_protocol::ProtocolError::IJson)
            }) {
                Ok(raw) => raw,
                Err(error) => {
                    let error = TransportError::Protocol(error);
                    if ramflux_protocol::is_i_json_rejection(&error) {
                        reject_i_json(
                            send,
                            recv,
                            reject_deadline
                                .unwrap_or_else(|| Instant::now() + MESH_I_JSON_REJECT_DEADLINE),
                        );
                    }
                    return Err(error);
                }
            };
            Some(raw.body.get().as_bytes().to_vec())
        } else {
            None
        };
        Ok(MeshQuicAcceptedWireRequest::Json(MeshQuicAcceptedRequest {
            request,
            raw_body,
            send,
            recv,
        }))
    }

    /// # Errors
    /// Returns an error when QUIC accept, stream accept, or request decoding fails.
    pub async fn accept_json_or_postcard_request_on_connection(
        connection: &MeshQuicConnection,
    ) -> Result<MeshQuicAcceptedWireRequest, TransportError> {
        loop {
            let stream = Self::accept_bi_on_connection(connection).await?;
            match Self::read_wire_request_from_bi(stream).await {
                Err(error) if ramflux_protocol::is_i_json_rejection(&error) => {}
                result => return result,
            }
        }
    }

    /// # Errors
    /// Returns an error when QUIC accept, stream accept, or request decoding fails.
    pub async fn accept_request(&self) -> Result<MeshQuicAcceptedRequest, TransportError> {
        let connection = self.accept_connection().await?;
        Self::accept_request_on_connection(&connection).await
    }

    /// # Errors
    /// Returns an error when stream accept or request decoding fails.
    pub async fn accept_request_on_connection(
        connection: &MeshQuicConnection,
    ) -> Result<MeshQuicAcceptedRequest, TransportError> {
        loop {
            match Self::accept_request_on_connection_once(connection, None).await {
                Err(error) if ramflux_protocol::is_i_json_rejection(&error) => {}
                result => return result,
            }
        }
    }

    async fn accept_request_on_connection_once(
        connection: &MeshQuicConnection,
        reject_deadline: Option<Instant>,
    ) -> Result<MeshQuicAcceptedRequest, TransportError> {
        let remote_address = connection.remote_address();
        let stream_accept_started = std::time::Instant::now();
        let (send, mut recv) = connection
            .connection
            .accept_bi()
            .await
            .map_err(|error| {
                tracing::error!(%remote_address, %error, "mesh QUIC bidirectional stream accept failed");
                TransportError::Quic(format!(
                    "mesh QUIC bidirectional stream accept failed from {remote_address}: {error}"
                ))
            })?;
        record_mesh_server_quic_stream_accepted(stream_accept_started.elapsed());
        let request_read_started = std::time::Instant::now();
        let frame = read_quic_raw_frame(&mut recv).await?;
        let request = match ramflux_protocol::parse_i_json::<GatewayQuicRequest>(&frame) {
            Ok(request) => request,
            Err(error) => {
                let error = TransportError::Protocol(error);
                tracing::error!(%remote_address, %error, "mesh QUIC request frame decode failed");
                if ramflux_protocol::is_i_json_rejection(&error) {
                    reject_i_json(
                        send,
                        recv,
                        reject_deadline
                            .unwrap_or_else(|| Instant::now() + MESH_I_JSON_REJECT_DEADLINE),
                    );
                }
                return Err(error);
            }
        };
        record_mesh_server_quic_request_read(request_read_started.elapsed());
        let raw_body = if request.path.starts_with(RAW_BODY_PATH_PREFIX) {
            match raw_attachment_body(&frame) {
                Ok(body) => Some(body),
                Err(error) => {
                    let error = TransportError::Protocol(error);
                    reject_i_json(
                        send,
                        recv,
                        reject_deadline
                            .unwrap_or_else(|| Instant::now() + MESH_I_JSON_REJECT_DEADLINE),
                    );
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok(MeshQuicAcceptedRequest { request, raw_body, send, recv })
    }
}

fn reject_i_json(mut send: quinn::SendStream, mut recv: quinn::RecvStream, deadline: Instant) {
    let code = quinn::VarInt::from_u32(MESH_I_JSON_REJECTED_CODE);
    if let Err(error) = recv.stop(code) {
        tracing::debug!(%error, "failed to stop I-JSON request stream");
    }
    tokio::spawn(async move {
        if Instant::now() >= deadline {
            tracing::debug!("I-JSON rejection response deadline expired");
            if let Err(error) = send.reset(code) {
                tracing::debug!(%error, "failed to reset rejected I-JSON response stream");
            }
            return;
        }
        let response =
            GatewayQuicResponse { status: 400, body: ramflux_protocol::i_json_rejection_body() };
        let write = async {
            write_quic_json_message(&mut send, &response).await?;
            send.finish().map_err(|error| TransportError::Quic(error.to_string()))
        };
        match tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), write).await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(%error, "failed to write I-JSON rejection response");
                if let Err(reset_error) = send.reset(code) {
                    tracing::debug!(%reset_error, "failed to reset rejected I-JSON response stream");
                }
            }
            Err(_elapsed) => {
                tracing::debug!("I-JSON rejection response deadline expired");
                if let Err(error) = send.reset(code) {
                    tracing::debug!(%error, "failed to reset rejected I-JSON response stream");
                }
            }
        }
    });
}

impl MeshQuicConnection {
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    #[must_use]
    pub fn peer_spiffe_uri(&self) -> Option<&str> {
        self.peer_spiffe_uri.as_deref()
    }
}

pub(crate) fn quinn_peer_spiffe_uri(
    connection: &quinn::Connection,
) -> Result<Option<String>, TransportError> {
    let Some(peer_identity) = connection.peer_identity() else {
        return Ok(None);
    };
    match peer_identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>() {
        Ok(certs) => match certs.first() {
            Some(cert) => extract_spiffe_uri_from_certificate(cert),
            None => Ok(None),
        },
        Err(_identity) => Ok(None),
    }
}

impl MeshQuicAcceptedRequest {
    /// Resolves when the peer stops reading the response, which happens when the
    /// requesting client drops its stream before the response is complete.
    pub async fn response_stopped(&mut self) {
        let _stopped = self.send.stopped().await;
    }

    /// # Errors
    /// Returns an error when response serialization or stream writes fail.
    pub async fn write_json_response<T: serde::Serialize>(
        mut self,
        status: u16,
        value: &T,
    ) -> Result<(), TransportError> {
        let response_started = std::time::Instant::now();
        let body = serde_json::to_value(value)?;
        write_quic_json_message(&mut self.send, &GatewayQuicResponse { status, body }).await?;
        self.finish_response_stream().await?;
        record_mesh_server_quic_response_write(response_started.elapsed());
        Ok(())
    }

    /// # Errors
    /// Returns an error when response serialization or stream writes fail.
    pub async fn write_text_response(
        mut self,
        status: u16,
        body: &str,
    ) -> Result<(), TransportError> {
        let response_started = std::time::Instant::now();
        write_quic_json_message(
            &mut self.send,
            &GatewayQuicResponse { status, body: serde_json::json!({ "error": body }) },
        )
        .await?;
        self.finish_response_stream().await?;
        record_mesh_server_quic_response_write(response_started.elapsed());
        Ok(())
    }

    async fn finish_response_stream(&mut self) -> Result<(), TransportError> {
        self.send.finish().map_err(|error| TransportError::Quic(error.to_string()))?;
        drain_quic_recv_to_fin(&mut self.recv).await
    }
}

impl MeshQuicPostcardAcceptedRequest {
    /// # Errors
    /// Returns an error when response serialization or stream writes fail.
    pub async fn write_postcard_response<T: serde::Serialize>(
        mut self,
        status: u16,
        value: &T,
    ) -> Result<(), TransportError> {
        let response_started = std::time::Instant::now();
        let body = serde_json::to_vec(value)?;
        write_postcard_frame(&mut self.send, &MeshQuicPostcardResponse { status, body }).await?;
        self.finish_response_stream().await?;
        record_mesh_server_quic_response_write(response_started.elapsed());
        Ok(())
    }

    /// # Errors
    /// Returns an error when response serialization or stream writes fail.
    pub async fn write_text_response(
        mut self,
        status: u16,
        body: &str,
    ) -> Result<(), TransportError> {
        let response_started = std::time::Instant::now();
        let response_body = body.as_bytes().to_vec();
        write_postcard_frame(
            &mut self.send,
            &MeshQuicPostcardResponse { status, body: response_body },
        )
        .await?;
        self.finish_response_stream().await?;
        record_mesh_server_quic_response_write(response_started.elapsed());
        Ok(())
    }

    async fn finish_response_stream(&mut self) -> Result<(), TransportError> {
        self.send.finish().map_err(|error| TransportError::Quic(error.to_string()))?;
        drain_quic_recv_to_fin(&mut self.recv).await
    }
}

/// # Errors
/// Returns an error when the JSON request cannot be encoded, QUIC/TLS fails, or
/// the response cannot be decoded.
pub fn mesh_quic_post_json_with_peer_ca_pems<T, R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    value: &T,
) -> Result<R, TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_value(value)?;
    let response = run_mesh_quic_request(
        endpoint,
        tls,
        server_name,
        peer_ca_pems,
        GatewayQuicRequest { method: "POST".to_owned(), path: path.to_owned(), body },
    )?;
    if (200..300).contains(&response.status) {
        Ok(serde_json::from_value(response.body)?)
    } else {
        Err(TransportError::HttpStatus { status: response.status, body: response.body.to_string() })
    }
}

/// Posts JSON like [`mesh_quic_post_json_with_peer_ca_pems`], but refuses to send
/// the body unless the server certificate SPIFFE instance equals `expected_gateway_instance`.
///
/// # Errors
/// Returns an error when the JSON request cannot be encoded, QUIC/TLS fails, the
/// server identity does not match `expected_gateway_instance`, or the response
/// cannot be decoded.
#[allow(clippy::too_many_arguments)]
pub fn mesh_quic_post_json_with_peer_ca_pems_and_instance<T, R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    expected_gateway_instance: &str,
    value: &T,
) -> Result<R, TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_value(value)?;
    let response = run_mesh_quic_request_with_instance(
        endpoint,
        tls,
        server_name,
        peer_ca_pems,
        GatewayQuicRequest { method: "POST".to_owned(), path: path.to_owned(), body },
        expected_gateway_instance,
    )?;
    if (200..300).contains(&response.status) {
        Ok(serde_json::from_value(response.body)?)
    } else {
        Err(TransportError::HttpStatus { status: response.status, body: response.body.to_string() })
    }
}

/// # Errors
/// Returns an error when the JSON request cannot be encoded, QUIC/TLS fails, or
/// the response cannot be decoded.
pub fn mesh_quic_get_json_with_peer_ca_pems<R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
) -> Result<R, TransportError>
where
    R: serde::de::DeserializeOwned,
{
    let response = run_mesh_quic_request(
        endpoint,
        tls,
        server_name,
        peer_ca_pems,
        GatewayQuicRequest {
            method: "GET".to_owned(),
            path: path.to_owned(),
            body: serde_json::Value::Null,
        },
    )?;
    if (200..300).contains(&response.status) {
        Ok(serde_json::from_value(response.body)?)
    } else {
        Err(TransportError::HttpStatus { status: response.status, body: response.body.to_string() })
    }
}

/// # Errors
/// Returns an error when the JSON request cannot be encoded, QUIC/TLS fails, or
/// the response cannot be decoded.
pub async fn mesh_quic_post_json_with_peer_ca_pems_async<T, R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    value: &T,
) -> Result<R, TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_value(value)?;
    let response = run_mesh_quic_request_async(
        endpoint,
        tls,
        server_name,
        peer_ca_pems,
        GatewayQuicRequest { method: "POST".to_owned(), path: path.to_owned(), body },
    )
    .await?;
    if (200..300).contains(&response.status) {
        Ok(serde_json::from_value(response.body)?)
    } else {
        Err(TransportError::HttpStatus { status: response.status, body: response.body.to_string() })
    }
}

/// # Errors
/// Returns an error when the JSON request cannot be encoded, QUIC/TLS fails, or
/// the response cannot be decoded.
pub async fn mesh_quic_get_json_with_peer_ca_pems_async<R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
) -> Result<R, TransportError>
where
    R: serde::de::DeserializeOwned,
{
    let response = run_mesh_quic_request_async(
        endpoint,
        tls,
        server_name,
        peer_ca_pems,
        GatewayQuicRequest {
            method: "GET".to_owned(),
            path: path.to_owned(),
            body: serde_json::Value::Null,
        },
    )
    .await?;
    if (200..300).contains(&response.status) {
        Ok(serde_json::from_value(response.body)?)
    } else {
        Err(TransportError::HttpStatus { status: response.status, body: response.body.to_string() })
    }
}

/// # Errors
/// Returns an error when the request cannot be encoded, QUIC/TLS fails, or
/// the response cannot be decoded.
pub async fn mesh_quic_post_postcard_with_peer_ca_pems_async<T, R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    value: &T,
) -> Result<R, TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_vec(value)?;
    let response = run_mesh_quic_postcard_request_async(
        endpoint,
        tls,
        server_name,
        peer_ca_pems,
        MeshQuicPostcardRequest { method: "POST".to_owned(), path: path.to_owned(), body },
    )
    .await?;
    if (200..300).contains(&response.status) {
        Ok(ramflux_protocol::parse_i_json(&response.body)?)
    } else {
        Err(TransportError::Http(format!(
            "HTTP {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )))
    }
}

/// Posts like [`mesh_quic_post_postcard_with_peer_ca_pems_async`] but returns the status and the
/// original postcard response payload bytes, before any JSON parsing or value construction.
/// This is only available to tests and explicit test-support builds.
/// # Errors
/// Returns an error when the request cannot be encoded or QUIC/TLS fails.
#[cfg(any(test, feature = "test-support"))]
pub async fn mesh_quic_post_postcard_raw_body_with_peer_ca_pems_async<T>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    value: &T,
) -> Result<(u16, Vec<u8>), TransportError>
where
    T: serde::Serialize,
{
    let body = serde_json::to_vec(value)?;
    let response = run_mesh_quic_postcard_request_async(
        endpoint,
        tls,
        server_name,
        peer_ca_pems,
        MeshQuicPostcardRequest { method: "POST".to_owned(), path: path.to_owned(), body },
    )
    .await?;
    Ok((response.status, response.body))
}

fn run_mesh_quic_request(
    endpoint: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    request: GatewayQuicRequest,
) -> Result<GatewayQuicResponse, TransportError> {
    mesh_quic_client_runtime().request(endpoint, tls, server_name, peer_ca_pems, request)
}

fn run_mesh_quic_request_with_instance(
    endpoint: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    request: GatewayQuicRequest,
    expected_gateway_instance: &str,
) -> Result<GatewayQuicResponse, TransportError> {
    mesh_quic_client_runtime().submit_json_job(MeshQuicClientRequestJob {
        endpoint: endpoint.to_owned(),
        server_name: server_name.to_owned(),
        tls: tls.clone(),
        peer_ca_pems: peer_ca_pems.to_vec(),
        request: MeshQuicClientRequestPayload::Json(request),
        expected_gateway_instance: Some(expected_gateway_instance.to_owned()),
        enqueued_at: std::time::Instant::now(),
    })
}

fn gateway_instance_from_spiffe_uri(spiffe_uri: &str) -> Option<&str> {
    let rest = spiffe_uri.strip_prefix("spiffe://")?;
    let (_node_id, service_path) = rest.split_once('/')?;
    let mut segments = service_path.split('/');
    let service_id = segments.next()?;
    let instance_id = segments.next()?;
    if service_id != "ramflux-gateway" || instance_id.is_empty() || segments.next().is_some() {
        return None;
    }
    Some(instance_id)
}

fn require_gateway_instance(
    connection: &quinn::Connection,
    expected_gateway_instance: &str,
) -> Result<(), TransportError> {
    let uri = quinn_peer_spiffe_uri(connection)?.ok_or_else(|| {
        TransportError::Tls("mesh peer certificate missing SPIFFE SAN".to_owned())
    })?;
    let Some(instance_id) = gateway_instance_from_spiffe_uri(&uri) else {
        return Err(TransportError::Tls(format!(
            "mesh peer SPIFFE is not a gateway instance: {uri}"
        )));
    };
    if instance_id != expected_gateway_instance {
        return Err(TransportError::Tls(format!(
            "mesh peer gateway instance {instance_id} does not match directory key {expected_gateway_instance}"
        )));
    }
    Ok(())
}

async fn run_mesh_quic_request_async(
    endpoint: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    request: GatewayQuicRequest,
) -> Result<GatewayQuicResponse, TransportError> {
    mesh_quic_client_runtime()
        .request_async(endpoint, tls, server_name, peer_ca_pems, request)
        .await
}

async fn run_mesh_quic_postcard_request_async(
    endpoint: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    request: MeshQuicPostcardRequest,
) -> Result<MeshQuicPostcardResponse, TransportError> {
    mesh_quic_client_runtime()
        .request_postcard_async(endpoint, tls, server_name, peer_ca_pems, request)
        .await
}

impl MeshQuicClientRuntime {
    fn request(
        &self,
        endpoint: &str,
        tls: &MeshTlsConfig,
        server_name: &str,
        peer_ca_pems: &[String],
        request: GatewayQuicRequest,
    ) -> Result<GatewayQuicResponse, TransportError> {
        self.submit_json_job(MeshQuicClientRequestJob {
            endpoint: endpoint.to_owned(),
            server_name: server_name.to_owned(),
            tls: tls.clone(),
            peer_ca_pems: peer_ca_pems.to_vec(),
            request: MeshQuicClientRequestPayload::Json(request),
            expected_gateway_instance: None,
            enqueued_at: std::time::Instant::now(),
        })
    }

    fn submit_json_job(
        &self,
        job: MeshQuicClientRequestJob,
    ) -> Result<GatewayQuicResponse, TransportError> {
        let (response, receiver) = mpsc::channel();
        self.jobs
            .send(MeshQuicClientJob {
                request: job,
                response: MeshQuicClientResponse::Sync(response),
                raw: None,
            })
            .map_err(|error| TransportError::Quic(format!("mesh QUIC runtime stopped: {error}")))?;
        match receiver.recv().map_err(|error| {
            TransportError::Quic(format!("mesh QUIC runtime stopped: {error}"))
        })?? {
            MeshQuicClientResponsePayload::Json(response) => Ok(response),
            MeshQuicClientResponsePayload::Postcard(_)
            | MeshQuicClientResponsePayload::RawJson(_) => Err(crate::quic_errors::wire(
                "mesh QUIC runtime returned postcard response for JSON request".to_owned(),
            )),
        }
    }

    async fn request_async(
        &self,
        endpoint: &str,
        tls: &MeshTlsConfig,
        server_name: &str,
        peer_ca_pems: &[String],
        request: GatewayQuicRequest,
    ) -> Result<GatewayQuicResponse, TransportError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.jobs
            .send(MeshQuicClientJob {
                request: MeshQuicClientRequestJob {
                    endpoint: endpoint.to_owned(),
                    server_name: server_name.to_owned(),
                    tls: tls.clone(),
                    peer_ca_pems: peer_ca_pems.to_vec(),
                    request: MeshQuicClientRequestPayload::Json(request),
                    expected_gateway_instance: None,
                    enqueued_at: std::time::Instant::now(),
                },
                response: MeshQuicClientResponse::Async(response),
                raw: None,
            })
            .map_err(|error| TransportError::Quic(format!("mesh QUIC runtime stopped: {error}")))?;
        match receiver.await.map_err(|error| {
            TransportError::Quic(format!("mesh QUIC runtime stopped: {error}"))
        })?? {
            MeshQuicClientResponsePayload::Json(response) => Ok(response),
            MeshQuicClientResponsePayload::Postcard(_)
            | MeshQuicClientResponsePayload::RawJson(_) => Err(crate::quic_errors::wire(
                "mesh QUIC runtime returned postcard response for JSON request".to_owned(),
            )),
        }
    }

    async fn request_postcard_async(
        &self,
        endpoint: &str,
        tls: &MeshTlsConfig,
        server_name: &str,
        peer_ca_pems: &[String],
        request: MeshQuicPostcardRequest,
    ) -> Result<MeshQuicPostcardResponse, TransportError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.jobs
            .send(MeshQuicClientJob {
                request: MeshQuicClientRequestJob {
                    endpoint: endpoint.to_owned(),
                    server_name: server_name.to_owned(),
                    tls: tls.clone(),
                    peer_ca_pems: peer_ca_pems.to_vec(),
                    request: MeshQuicClientRequestPayload::Postcard(request),
                    expected_gateway_instance: None,
                    enqueued_at: std::time::Instant::now(),
                },
                response: MeshQuicClientResponse::Async(response),
                raw: None,
            })
            .map_err(|error| TransportError::Quic(format!("mesh QUIC runtime stopped: {error}")))?;
        match receiver.await.map_err(|error| {
            TransportError::Quic(format!("mesh QUIC runtime stopped: {error}"))
        })?? {
            MeshQuicClientResponsePayload::Postcard(response) => Ok(response),
            MeshQuicClientResponsePayload::Json(_) | MeshQuicClientResponsePayload::RawJson(_) => {
                Err(crate::quic_errors::wire(
                    "mesh QUIC runtime returned JSON response for postcard request".to_owned(),
                ))
            }
        }
    }
}

fn mesh_quic_client_runtime() -> &'static MeshQuicClientRuntime {
    static RUNTIME: OnceLock<MeshQuicClientRuntime> = OnceLock::new();
    RUNTIME.get_or_init(spawn_mesh_quic_client_runtime)
}

fn spawn_mesh_quic_client_runtime() -> MeshQuicClientRuntime {
    let (jobs, receiver) = mpsc::channel();
    let pool_size = mesh_quic_client_pool_size();
    std::thread::spawn(move || {
        if let Err(error) = run_mesh_quic_client_runtime(receiver, pool_size) {
            tracing::error!(%error, "mesh QUIC client runtime stopped");
        }
    });
    MeshQuicClientRuntime { jobs }
}

fn run_mesh_quic_client_runtime(
    receiver: mpsc::Receiver<MeshQuicClientJob>,
    pool_size: usize,
) -> Result<(), TransportError> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let handle = runtime.handle().clone();
    let pools = Arc::new(MeshQuicPoolRegistry::default());
    let breakers = Arc::new(MeshQuicCircuitBreakers::default());
    tracing::info!(pool_size, "mesh QUIC client connection pool configured");
    for job in receiver {
        record_mesh_client_runtime_queue_wait(job.request.enqueued_at.elapsed());
        let pools = Arc::clone(&pools);
        let breakers = Arc::clone(&breakers);
        let sched_started = std::time::Instant::now();
        handle.spawn(async move {
            record_mesh_client_task_sched(sched_started.elapsed());
            let MeshQuicClientJob { request, response: mut response_sender, raw } = job;
            if let Some(control) = raw {
                raw_request::run(pools, breakers, request, response_sender, control, pool_size)
                    .await;
                return;
            }
            // The caller dropping its receiver (deadline or cancellation) aborts the whole
            // attempt, including acquisition and the cached-connection retry.
            let response = tokio::select! {
                biased;
                () = response_sender.closed() => return,
                response = mesh_quic_cached_request(pools, breakers, request, pool_size, true) => response,
            };
            response_sender.send(response);
        });
    }
    Ok(())
}

/// `retry_cached` permits one re-send after a failed cached-connection attempt. Callers
/// with a hard wire-attempt budget pass `false`: the request is then sent at most once.
async fn mesh_quic_cached_request(
    pools: Arc<MeshQuicPoolRegistry>,
    breakers: Arc<MeshQuicCircuitBreakers>,
    job: MeshQuicClientRequestJob,
    pool_size: usize,
    retry_cached: bool,
) -> Result<MeshQuicClientResponsePayload, TransportError> {
    record_mesh_client_request();
    let peer_addr = if matches!(&job.request, MeshQuicClientRequestPayload::RawJson(_)) {
        tokio::net::lookup_host(job.endpoint.as_str())
            .await?
            .next()
            .ok_or_else(|| crate::quic_errors::wire("mesh QUIC endpoint did not resolve"))?
    } else {
        resolve_endpoint(&job.endpoint)?
    };
    let key = MeshQuicPoolKey {
        endpoint: job.endpoint.clone(),
        server_name: job.server_name.clone(),
        peer_addr,
        peer_ca_pems: job.peer_ca_pems.clone(),
    };
    let acquire_started = std::time::Instant::now();
    let pool = pools.pool_for(key).await;
    let (connection, reused_cached_connection) =
        mesh_quic_acquire_connection(&pool, &breakers, peer_addr, &job, pool_size).await?;
    record_mesh_client_acquire(acquire_started.elapsed());
    if let Some(expected) = job.expected_gateway_instance.as_deref() {
        require_gateway_instance(connection.connection(), expected)?;
    }
    let request_timeout = if reused_cached_connection && retry_cached {
        MESH_QUIC_CACHED_CONNECTION_PROBE_TIMEOUT
    } else {
        MESH_QUIC_REQUEST_TIMEOUT
    };
    match timed_mesh_quic_request_on_connection(
        connection.connection(),
        &job.request,
        request_timeout,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(error) if reused_cached_connection && retry_cached => {
            record_mesh_client_cached_request_failure();
            record_mesh_client_retry();
            tracing::warn!(
                %error,
                peer_addr = %connection.remote_address(),
                connection_id = connection.stable_id(),
                retry_peer_addr = %peer_addr,
                "mesh QUIC cached request failed; dropping cached connection and retrying once"
            );
            pool.remove_connection(&connection).await;
            let retry_acquire_started = std::time::Instant::now();
            let (retry_connection, _reused_retry_connection) =
                mesh_quic_acquire_connection(&pool, &breakers, peer_addr, &job, pool_size).await?;
            record_mesh_client_acquire(retry_acquire_started.elapsed());
            if let Some(expected) = job.expected_gateway_instance.as_deref() {
                require_gateway_instance(retry_connection.connection(), expected)?;
            }
            match timed_mesh_quic_request_on_connection(
                retry_connection.connection(),
                &job.request,
                MESH_QUIC_REQUEST_TIMEOUT,
            )
            .await
            {
                Ok(response) => {
                    record_mesh_client_retry_success();
                    Ok(response)
                }
                Err(retry_error) => {
                    record_mesh_client_retry_failure();
                    tracing::warn!(
                        %retry_error,
                        peer_addr = %retry_connection.remote_address(),
                        connection_id = retry_connection.stable_id(),
                        "mesh QUIC request failed after reconnect; dropping cached connection"
                    );
                    pool.remove_connection(&retry_connection).await;
                    Err(retry_error)
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                %error,
                peer_addr = %connection.remote_address(),
                connection_id = connection.stable_id(),
                "mesh QUIC request failed on fresh connection; dropping cached connection"
            );
            pool.remove_connection(&connection).await;
            Err(error)
        }
    }
}

async fn mesh_quic_acquire_connection(
    pool: &MeshQuicConnectionPool,
    breakers: &MeshQuicCircuitBreakers,
    peer_addr: SocketAddr,
    job: &MeshQuicClientRequestJob,
    pool_size: usize,
) -> Result<(MeshQuicSelectedConnection, bool), TransportError> {
    loop {
        // Register this waiter with the Notify BEFORE checking pool state. tokio's
        // notify_waiters() only wakes waiters already enqueued; a bare `notified()`
        // future is not enqueued until first polled. Without `pin!`+`enable()` here,
        // any notify_waiters() firing between the checks below and the `.await` is
        // lost, and a waiter can then block forever once the peer goes quiet.
        let notified = pool.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if pool.try_reserve_connect(pool_size) {
            record_mesh_client_pool_miss();
            // The guard owns the slot from here on: an error, timeout or cancellation of the
            // connect releases it when the future is dropped.
            let reservation = MeshQuicConnectReservation { pool };
            let connection =
                mesh_quic_connect_and_insert(reservation, breakers, peer_addr, job, pool_size)
                    .await?;
            return Ok((connection, false));
        }
        if let Some(connection) = pool.select_connection() {
            record_mesh_client_pool_hit();
            return Ok((connection, true));
        }
        // Bounded wait: a missed wakeup self-heals on the next poll instead of hanging.
        let _ = tokio::time::timeout(MESH_QUIC_ACQUIRE_POLL_INTERVAL, notified.as_mut()).await;
    }
}

async fn mesh_quic_connect_and_insert(
    reservation: MeshQuicConnectReservation<'_>,
    breakers: &MeshQuicCircuitBreakers,
    peer_addr: SocketAddr,
    job: &MeshQuicClientRequestJob,
    pool_size: usize,
) -> Result<MeshQuicSelectedConnection, TransportError> {
    let pool = reservation.pool;
    let connect_result =
        mesh_quic_connect(peer_addr, &job.tls, &job.server_name, &job.peer_ca_pems, breakers).await;
    // Release the connecting slot before the connection is inserted, as before the guard.
    drop(reservation);
    let cached = connect_result?;
    Ok(pool.insert_connection(cached, pool_size).await)
}

fn mesh_quic_client_pool_size() -> usize {
    let (name, value) = match ramflux_core::environment::var(ROUTER_ASYNC_POOL_SIZE_ENV) {
        Ok(value) => (ROUTER_ASYNC_POOL_SIZE_ENV, Some(value)),
        Err(_) => (
            MESH_QUIC_CLIENT_POOL_SIZE_ENV,
            ramflux_core::environment::var(MESH_QUIC_CLIENT_POOL_SIZE_ENV).ok(),
        ),
    };
    ramflux_core::environment::parse_value::<usize>(name, value.as_deref())
        .filter(|value| *value > 0)
        .unwrap_or(MESH_QUIC_CLIENT_POOL_SIZE_DEFAULT)
}

fn mesh_quic_connect_timeout() -> Duration {
    duration_from_millis_env(MESH_QUIC_CONNECT_TIMEOUT_MS_ENV, MESH_QUIC_CONNECT_TIMEOUT_DEFAULT)
}

pub(crate) fn mesh_quic_post_worst_case_timeout() -> Duration {
    MESH_QUIC_CACHED_CONNECTION_PROBE_TIMEOUT
        .saturating_add(mesh_quic_connect_timeout())
        .saturating_add(MESH_QUIC_REQUEST_TIMEOUT)
}

fn mesh_quic_connect_breaker_cooldown() -> Duration {
    duration_from_millis_env(
        MESH_QUIC_CONNECT_BREAKER_COOLDOWN_MS_ENV,
        MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT,
    )
}

fn duration_from_millis_env(name: &str, default: Duration) -> Duration {
    duration_from_millis_value(name, ramflux_core::environment::var(name).ok().as_deref(), default)
}

fn duration_from_millis_value(name: &str, value: Option<&str>, default: Duration) -> Duration {
    let Some(value) = value else {
        return default;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("${") {
        return default;
    }
    match ramflux_core::environment::parse_value::<u64>(name, Some(trimmed)) {
        Some(millis) if millis > 0 => Duration::from_millis(millis),
        Some(_) | None => default,
    }
}

async fn mesh_quic_connect(
    peer_addr: SocketAddr,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    breakers: &MeshQuicCircuitBreakers,
) -> Result<MeshQuicCachedConnection, TransportError> {
    let connect_started = std::time::Instant::now();
    let connect_timeout = mesh_quic_connect_timeout();
    let breaker_cooldown = mesh_quic_connect_breaker_cooldown();
    let bind_addr = if peer_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let mut endpoint = quinn::Endpoint::client(
        bind_addr
            .parse()
            .map_err(|error| TransportError::Quic(format!("bad QUIC bind addr: {error}")))?,
    )?;
    endpoint.set_default_client_config(mesh_quic_client_config_with_pem_roots(tls, peer_ca_pems)?);
    // From here on the guard owns any half-open probe: a cancelled dial releases it.
    let mut probe = MeshQuicCircuitProbeGuard::new(
        breakers,
        breakers.before_connect(peer_addr, server_name, Instant::now())?,
    );
    let connecting = endpoint.connect(peer_addr, server_name).map_err(|error| {
        let error = crate::quic_errors::connect(error);
        probe.record_connect_failure(Instant::now(), breaker_cooldown);
        error
    })?;
    tracing::info!(
        peer_addr = %peer_addr,
        server_name,
        timeout_ms = connect_timeout.as_millis(),
        "mesh QUIC client connecting"
    );
    let connection_result = tokio::time::timeout(connect_timeout, connecting)
        .await
        .map_err(|error| {
            tracing::error!(peer_addr = %peer_addr, server_name, %error, "mesh QUIC client connect timed out");
            TransportError::Quic(format!(
                "mesh QUIC connect to {peer_addr} timed out after {}ms: {error}",
                connect_timeout.as_millis()
            ))
        })?
        .map_err(|error| {
            tracing::error!(peer_addr = %peer_addr, server_name, %error, "mesh QUIC client handshake failed");
            crate::quic_errors::connection(&error)
        });
    let connection = match connection_result {
        Ok(connection) => {
            probe.record_connect_success();
            connection
        }
        Err(error) => {
            probe.record_connect_error(&error, Instant::now(), breaker_cooldown);
            return Err(error);
        }
    };
    record_mesh_client_connect(connect_started.elapsed());
    record_mesh_client_tls_handshake();
    tracing::info!(peer_addr = %peer_addr, server_name, "mesh QUIC client connected");
    Ok(MeshQuicCachedConnection { _endpoint: endpoint, connection })
}

async fn mesh_quic_request_on_connection(
    connection: &quinn::Connection,
    request: &MeshQuicClientRequestPayload,
    timeout: Duration,
) -> Result<MeshQuicClientResponsePayload, TransportError> {
    let result = tokio::time::timeout(timeout, async {
        let open_bi_started = std::time::Instant::now();
        let open_bi_result =
            connection.open_bi().await.map_err(|error| crate::quic_errors::connection(&error));
        record_mesh_client_open_bi(open_bi_started.elapsed());
        let (mut send, mut recv) = open_bi_result?;
        let request_write_started = std::time::Instant::now();
        let request_write_result = async {
            match request {
                MeshQuicClientRequestPayload::Json(request)
                | MeshQuicClientRequestPayload::RawJson(request) => {
                    write_quic_json_message(&mut send, request).await?;
                }
                MeshQuicClientRequestPayload::Postcard(request) => {
                    write_postcard_frame(&mut send, request).await?;
                }
            }
            send.finish().map_err(|error| TransportError::Quic(error.to_string()))
        }
        .await;
        record_mesh_client_request_write(request_write_started.elapsed());
        request_write_result?;
        let response_read_started = std::time::Instant::now();
        let response_read_result = async {
            let response = match request {
                MeshQuicClientRequestPayload::RawJson(_) => {
                    MeshQuicClientResponsePayload::RawJson(read_quic_raw_frame(&mut recv).await?)
                }
                MeshQuicClientRequestPayload::Json(_request) => {
                    MeshQuicClientResponsePayload::Json(read_quic_json_frame(&mut recv).await?)
                }
                MeshQuicClientRequestPayload::Postcard(_request) => {
                    let frame = read_quic_raw_frame(&mut recv).await?;
                    let body = frame.strip_prefix(MESH_QUIC_POSTCARD_MAGIC).ok_or_else(|| {
                        crate::quic_errors::wire("mesh QUIC postcard response missing binary magic")
                    })?;
                    MeshQuicClientResponsePayload::Postcard(postcard_from_bytes(body)?)
                }
            };
            drain_quic_recv_to_fin(&mut recv).await?;
            Ok(response)
        }
        .await;
        record_mesh_client_response_read(response_read_started.elapsed());
        response_read_result
    })
    .await
    .map_err(|error| {
        record_mesh_client_request_timeout();
        TransportError::Quic(error.to_string())
    })?;
    if result.is_err()
        && let Some(reason) = connection.close_reason()
    {
        let error = crate::quic_errors::connection(&reason);
        if error.is_tls_failure() {
            return Err(error);
        }
    }
    result
}

async fn timed_mesh_quic_request_on_connection(
    connection: &quinn::Connection,
    request: &MeshQuicClientRequestPayload,
    timeout: Duration,
) -> Result<MeshQuicClientResponsePayload, TransportError> {
    let started = std::time::Instant::now();
    let result = mesh_quic_request_on_connection(connection, request, timeout).await;
    record_mesh_client_exchange(started.elapsed());
    result
}

async fn write_postcard_frame<T: serde::Serialize>(
    send: &mut quinn::SendStream,
    value: &T,
) -> Result<(), TransportError> {
    let payload = postcard_to_allocvec(value)?;
    let mut frame =
        Vec::with_capacity(MESH_QUIC_POSTCARD_MAGIC.len().saturating_add(payload.len()));
    frame.extend_from_slice(MESH_QUIC_POSTCARD_MAGIC);
    frame.extend_from_slice(&payload);
    write_quic_raw_frame(send, &frame).await
}

fn postcard_to_allocvec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, TransportError> {
    postcard::to_allocvec(value)
        .map_err(|error| crate::quic_errors::wire(format!("postcard encode failed: {error}")))
}

fn postcard_from_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, TransportError> {
    postcard::from_bytes(bytes)
        .map_err(|error| crate::quic_errors::wire(format!("postcard decode failed: {error}")))
}

async fn drain_quic_recv_to_fin(recv: &mut quinn::RecvStream) -> Result<(), TransportError> {
    tokio::time::timeout(MESH_QUIC_REQUEST_TIMEOUT, recv.read_to_end(0))
        .await
        .map_err(|error| TransportError::Quic(error.to_string()))?
        .map(|_trailing| ())
        .map_err(|error| crate::quic_errors::read_to_end(&error))
}

fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr, TransportError> {
    let endpoint = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    endpoint
        .to_socket_addrs()
        .map_err(|source| TransportError::Quic(format!("bad endpoint {endpoint}: {source}")))?
        .next()
        .ok_or_else(|| TransportError::Quic(format!("bad endpoint {endpoint}: no addresses")))
}

#[cfg(test)]
mod tests {
    use crate::MeshQuicLimitedIngress;
    use crate::tls_config::mesh_quic_client_config_with_pem_roots;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::{
        GatewayQuicRequest, GatewayQuicResponse, MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT,
        MESH_QUIC_CONNECT_TIMEOUT_DEFAULT, MeshQuicAcceptedWireRequest, MeshQuicCircuitBreakerKey,
        MeshQuicCircuitBreakerState, MeshQuicCircuitBreakers, MeshQuicClientJob,
        MeshQuicClientRequestJob, MeshQuicClientRequestPayload, MeshQuicClientResponsePayload,
        MeshQuicClientRuntime, MeshQuicConnectionPool, MeshQuicPoolKey, MeshQuicPoolRegistry,
        MeshQuicPostcardRequest, MeshQuicPostcardResponse, MeshQuicServer, MeshTlsConfig,
        drain_quic_recv_to_fin, duration_from_millis_value, mesh_quic_acquire_connection,
        mesh_quic_get_json_with_peer_ca_pems, mesh_quic_post_json_with_peer_ca_pems_and_instance,
        mesh_quic_post_postcard_with_peer_ca_pems_async, postcard_from_bytes, postcard_to_allocvec,
        resolve_endpoint, write_quic_json_message,
    };
    use crate::TransportError;

    #[test]
    fn a_trust_failure_never_erases_another_connect_failure_or_strands_a_half_open_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let breakers = MeshQuicCircuitBreakers::default();
        let address = "127.0.0.1:5443".parse()?;
        let now = Instant::now();
        let first = breakers.before_connect(address, "peer", now)?;
        let concurrent = breakers.before_connect(address, "peer", now)?;
        breakers.record_connect_failure(&first, now, Duration::from_secs(1));
        breakers.record_connect_error(
            &concurrent,
            &TransportError::Tls("certificate".into()),
            now,
            Duration::from_secs(1),
        );
        assert!(breakers.before_connect(address, "peer", now).is_err());
        let later = now + Duration::from_secs(2);
        let probe = breakers.before_connect(address, "peer", later)?;
        breakers.record_connect_error(
            &probe,
            &TransportError::Tls("certificate".into()),
            later,
            Duration::from_secs(1),
        );
        assert!(breakers.before_connect(address, "peer", later).is_ok());
        Ok(())
    }

    type CapturedQuicRequest = (Option<String>, GatewayQuicRequest);

    #[test]
    fn mesh_quic_pool_reserves_at_most_configured_connects_under_concurrency()
    -> Result<(), Box<dyn std::error::Error>> {
        let pool = Arc::new(MeshQuicConnectionPool::default());
        let reserved = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _index in 0..256 {
            let pool = Arc::clone(&pool);
            let reserved = Arc::clone(&reserved);
            handles.push(std::thread::spawn(move || {
                if pool.try_reserve_connect(16) {
                    reserved.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| std::io::Error::other("reservation thread panicked"))?;
        }
        assert_eq!(reserved.load(Ordering::Relaxed), 16);
        assert_eq!(pool.connecting.load(Ordering::Relaxed), 16);
        for _index in 0..16 {
            pool.finish_connect_reservation();
        }
        assert_eq!(pool.connecting.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn mesh_quic_connect_timeout_defaults_to_fail_fast_and_accepts_env_override() {
        assert_eq!(
            duration_from_millis_value("QUIC_TIMEOUT", None, MESH_QUIC_CONNECT_TIMEOUT_DEFAULT),
            Duration::from_secs(3)
        );
        assert_eq!(
            duration_from_millis_value(
                "QUIC_TIMEOUT",
                Some("2500"),
                MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
            ),
            Duration::from_millis(2500)
        );
        assert_eq!(
            duration_from_millis_value(
                "QUIC_TIMEOUT",
                Some("${RAMFLUX_MESH_QUIC_CONNECT_TIMEOUT_MS:-3000}"),
                MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
            ),
            MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
        );
        assert_eq!(
            duration_from_millis_value(
                "QUIC_TIMEOUT",
                Some("not-a-duration"),
                MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
            ),
            MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
        );
        assert_eq!(
            duration_from_millis_value(
                "QUIC_TIMEOUT",
                Some("0"),
                MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
            ),
            MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
        );
    }

    #[test]
    fn mesh_quic_breaker_cooldown_defaults_to_five_seconds_and_accepts_env_override() {
        assert_eq!(
            duration_from_millis_value(
                "QUIC_TIMEOUT",
                None,
                MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT
            ),
            Duration::from_secs(5)
        );
        assert_eq!(
            duration_from_millis_value(
                "QUIC_TIMEOUT",
                Some("7500"),
                MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT
            ),
            Duration::from_millis(7500)
        );
        assert_eq!(
            duration_from_millis_value(
                "QUIC_TIMEOUT",
                Some("${RAMFLUX_MESH_QUIC_CONNECT_BREAKER_COOLDOWN_MS:-5000}"),
                MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT
            ),
            MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT
        );
        assert_eq!(
            duration_from_millis_value(
                "QUIC_TIMEOUT",
                Some("bad"),
                MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT
            ),
            MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT
        );
    }

    #[test]
    fn mesh_quic_circuit_breaker_opens_half_opens_and_closes()
    -> Result<(), Box<dyn std::error::Error>> {
        let breakers = MeshQuicCircuitBreakers::default();
        let peer_addr = test_peer_addr();
        let server_name = "ramflux-router";
        let cooldown = Duration::from_secs(5);
        let started = Instant::now();

        let probe = breakers.before_connect(peer_addr, server_name, started)?;
        breakers.record_connect_failure(&probe, started, cooldown);

        assert_quic_result_contains(
            breakers.before_connect(peer_addr, server_name, started + Duration::from_secs(1)),
            "circuit breaker open",
        )?;

        let half_open_probe =
            breakers.before_connect(peer_addr, server_name, started + cooldown)?;
        assert_quic_result_contains(
            breakers.before_connect(peer_addr, server_name, started + cooldown),
            "half-open probe already in flight",
        )?;

        breakers.record_connect_success(&half_open_probe);
        let _closed_probe = breakers.before_connect(peer_addr, server_name, started + cooldown)?;
        Ok(())
    }

    #[test]
    fn mesh_quic_circuit_breaker_reopens_after_half_open_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let breakers = MeshQuicCircuitBreakers::default();
        let peer_addr = test_peer_addr();
        let server_name = "ramflux-retention";
        let cooldown = Duration::from_secs(5);
        let started = Instant::now();

        let probe = breakers.before_connect(peer_addr, server_name, started)?;
        breakers.record_connect_failure(&probe, started, cooldown);
        let half_open_probe =
            breakers.before_connect(peer_addr, server_name, started + cooldown)?;
        breakers.record_connect_failure(&half_open_probe, started + cooldown, cooldown);

        assert_quic_result_contains(
            breakers.before_connect(
                peer_addr,
                server_name,
                started + cooldown + Duration::from_secs(1),
            ),
            "circuit breaker open",
        )?;
        Ok(())
    }

    #[test]
    fn mesh_quic_circuit_breaker_allows_one_concurrent_half_open_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let breakers = Arc::new(MeshQuicCircuitBreakers::default());
        let peer_addr = test_peer_addr();
        let server_name = "ramflux-notify";
        let cooldown = Duration::from_secs(5);
        let started = Instant::now();
        let probe = breakers.before_connect(peer_addr, server_name, started)?;
        breakers.record_connect_failure(&probe, started, cooldown);

        let ready = Arc::new(Barrier::new(17));
        let allowed = Arc::new(AtomicUsize::new(0));
        let skipped = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _index in 0..16 {
            let breakers = Arc::clone(&breakers);
            let ready = Arc::clone(&ready);
            let allowed = Arc::clone(&allowed);
            let skipped = Arc::clone(&skipped);
            handles.push(std::thread::spawn(move || {
                ready.wait();
                match breakers.before_connect(peer_addr, server_name, started + cooldown) {
                    Ok(_probe) => {
                        allowed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TransportError::Quic(_message)) => {
                        skipped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_other) => {}
                }
            }));
        }
        ready.wait();
        for handle in handles {
            handle.join().map_err(|_| std::io::Error::other("breaker thread panicked"))?;
        }

        assert_eq!(allowed.load(Ordering::Relaxed), 1);
        assert_eq!(skipped.load(Ordering::Relaxed), 15);
        Ok(())
    }

    /// Waits on observed state with yields only (no timers), so the gate is causal.
    async fn wait_until(mut ready: impl FnMut() -> bool) -> Result<(), Box<dyn std::error::Error>> {
        for _ in 0..100_000 {
            if ready() {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
        Err(test_error("gate condition was never reached"))
    }

    #[test]
    fn cancelled_handshakes_release_reservations_and_half_open_probes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("cancelled_handshakes_release_reservations_and_half_open")?;
        let ca = issue_test_ca(&root)?;
        let client = issue_test_service_cert(&ca, "node-cancel-a", "ramflux-federation")?;
        let server = issue_test_service_cert(&ca, "node-cancel-a", "ramflux-router")?;
        // Nothing answers on this socket, so every dial stays in its handshake until cancelled.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let peer_addr = socket.local_addr()?;
        let pool = Arc::new(MeshQuicConnectionPool::default());
        let breakers = Arc::new(MeshQuicCircuitBreakers::default());
        let pool_size = 2;
        let key = MeshQuicCircuitBreakerKey { peer_addr, server_name: "ramflux-router".to_owned() };
        let make_job = || MeshQuicClientRequestJob {
            endpoint: peer_addr.to_string(),
            server_name: "ramflux-router".to_owned(),
            tls: client.tls.clone(),
            peer_ca_pems: vec![server.ca_pem.clone()],
            request: MeshQuicClientRequestPayload::Json(GatewayQuicRequest {
                method: "GET".to_owned(),
                path: "/healthz".to_owned(),
                body: serde_json::Value::Null,
            }),
            expected_gateway_instance: None,
            enqueued_at: Instant::now(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            // Phase 1: four dials against a pool of two. Two hold reservations mid-handshake.
            let mut dials = Vec::new();
            for _ in 0..4 {
                let (pool, breakers, job) = (Arc::clone(&pool), Arc::clone(&breakers), make_job());
                dials.push(tokio::spawn(async move {
                    mesh_quic_acquire_connection(&pool, &breakers, peer_addr, &job, pool_size)
                        .await
                        .map(|_| ())
                }));
            }
            wait_until(|| pool.connecting.load(Ordering::Acquire) == pool_size).await?;
            for dial in &dials {
                dial.abort();
            }
            for dial in dials {
                let _ = dial.await;
            }
            assert_eq!(pool.connecting.load(Ordering::Acquire), 0, "reservations leaked");
            assert!(breakers.states.lock().map_err(|_| test_error("poisoned"))?.is_empty());

            // Phase 2: an expired Open breaker makes the next dial the half-open probe.
            let now = Instant::now();
            let seed = breakers.before_connect(peer_addr, "ramflux-router", now)?;
            breakers.record_connect_failure(&seed, now, Duration::ZERO);
            let probe_dial = {
                let (pool, breakers, job) = (Arc::clone(&pool), Arc::clone(&breakers), make_job());
                tokio::spawn(async move {
                    mesh_quic_acquire_connection(&pool, &breakers, peer_addr, &job, pool_size)
                        .await
                        .map(|_| ())
                })
            };
            let half_open = |breakers: &MeshQuicCircuitBreakers| {
                breakers.states.lock().ok().and_then(|states| states.get(&key).copied())
            };
            wait_until(|| {
                matches!(half_open(&breakers), Some(MeshQuicCircuitBreakerState::HalfOpen))
            })
            .await?;
            probe_dial.abort();
            let _ = probe_dial.await;
            assert!(
                matches!(half_open(&breakers), Some(MeshQuicCircuitBreakerState::Open { .. })),
                "cancelled probe stranded the breaker half-open"
            );
            assert_eq!(pool.connecting.load(Ordering::Acquire), 0, "reservation leaked on probe");

            // Phase 3: the router answers on the same socket again, and a new dial succeeds.
            let server_tls = server.tls.clone();
            let trusted_client_ca = client.ca_pem.clone();
            let roots = Arc::new(move || Ok(vec![trusted_client_ca.clone()]));
            let mesh_server = MeshQuicServer::bind_with_udp_socket_and_pem_roots_provider(
                socket,
                &server_tls,
                roots,
            )?;
            tokio::spawn(async move {
                loop {
                    if mesh_server.accept_connection().await.is_err() {
                        tokio::task::yield_now().await;
                    }
                }
            });
            let (_connection, reused) = tokio::time::timeout(
                Duration::from_secs(10),
                mesh_quic_acquire_connection(&pool, &breakers, peer_addr, &make_job(), pool_size),
            )
            .await
            .map_err(|_| test_error("recovery dial did not complete"))??;
            assert!(!reused);
            assert!(half_open(&breakers).is_none(), "successful dial must close the breaker");
            assert_eq!(pool.connecting.load(Ordering::Acquire), 0);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }

    #[test]
    fn mesh_quic_get_json_sends_get_with_null_body() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("mesh_quic_get_json_sends_get_with_null_body")?;
        let ca = issue_test_ca(&root)?;
        let client = issue_test_service_cert(&ca, "node-quic-get-a", "ramflux-federation")?;
        let server = issue_test_service_cert(&ca, "node-quic-get-a", "ramflux-router")?;
        let (endpoint, received) =
            spawn_mesh_quic_get_echo_server(server.tls.clone(), client.ca_pem.clone(), 200)?;

        let response: serde_json::Value = mesh_quic_get_json_with_peer_ca_pems(
            &endpoint,
            "/mvp1/prekey/device-a",
            &client.tls,
            "ramflux-router",
            &[server.ca_pem],
        )?;

        assert_eq!(response, serde_json::json!({"ok": true}));
        let (peer_spiffe_uri, request) =
            received.recv_timeout(std::time::Duration::from_secs(5))?;
        assert_eq!(peer_spiffe_uri.as_deref(), Some("spiffe://node-quic-get-a/ramflux-federation"));
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/mvp1/prekey/device-a");
        assert!(request.body.is_null());
        Ok(())
    }

    #[test]
    fn mesh_quic_endpoint_resolution_failure_is_quic_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let Err(error) = resolve_endpoint("127.0.0.1:not-a-port") else {
            return Err("bad endpoint should fail resolution".into());
        };

        assert!(matches!(error, TransportError::Quic(_)));
        Ok(())
    }

    #[test]
    fn mesh_quic_http_status_error_remains_http_error() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("mesh_quic_http_status_error_remains_http_error")?;
        let ca = issue_test_ca(&root)?;
        let client = issue_test_service_cert(&ca, "node-quic-http-a", "ramflux-federation")?;
        let server = issue_test_service_cert(&ca, "node-quic-http-a", "ramflux-router")?;
        let (endpoint, received) =
            spawn_mesh_quic_get_echo_server(server.tls.clone(), client.ca_pem.clone(), 404)?;

        let Err(error) = mesh_quic_get_json_with_peer_ca_pems::<serde_json::Value>(
            &endpoint,
            "/mvp1/prekey/missing-device",
            &client.tls,
            "ramflux-router",
            &[server.ca_pem],
        ) else {
            return Err("HTTP 404 response should remain a business HTTP error".into());
        };

        match error {
            TransportError::HttpStatus { status, .. } => assert_eq!(status, 404),
            TransportError::Quic(message) => {
                return Err(format!(
                    "business HTTP response must not become QUIC fallback error: {message}"
                )
                .into());
            }
            other => {
                return Err(
                    format!("business HTTP response returned unexpected error: {other}").into()
                );
            }
        }
        let (_peer_spiffe_uri, request) =
            received.recv_timeout(std::time::Duration::from_secs(5))?;
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/mvp1/prekey/missing-device");
        Ok(())
    }

    #[test]
    fn mesh_quic_post_json_refuses_server_instance_mismatch_before_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("mesh_quic_instance_mismatch_before_body")?;
        let ca = issue_test_ca(&root)?;
        let client = issue_test_gateway_instance_cert(&ca, "node-gw-id", "gw-a")?;
        let server = issue_test_gateway_instance_cert(&ca, "node-gw-id", "gw-b")?;
        let (endpoint, received) =
            spawn_mesh_quic_post_capture_server(server.tls.clone(), client.ca_pem.clone())?;

        let Err(error) = mesh_quic_post_json_with_peer_ca_pems_and_instance::<_, serde_json::Value>(
            &endpoint,
            "/gateway/mesh/forward-deliver",
            &client.tls,
            "ramflux-gateway",
            &[server.ca_pem],
            "gw-c",
            &serde_json::json!({"source_gateway_id":"gw-a","forwarded":true}),
        ) else {
            return Err("mismatched server instance must be refused".into());
        };
        match error {
            TransportError::Tls(message) => {
                assert!(
                    message.contains("does not match directory key gw-c"),
                    "unexpected tls error: {message}"
                );
            }
            other => return Err(format!("expected TransportError::Tls, got {other}").into()),
        }
        match received.try_recv() {
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => Ok(()),
            Ok((_, request)) => {
                Err(format!("body must not be sent before instance check: {}", request.path).into())
            }
        }
    }

    #[test]
    fn mesh_quic_post_json_sends_body_when_server_instance_matches()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("mesh_quic_instance_match_sends_body")?;
        let ca = issue_test_ca(&root)?;
        let client = issue_test_gateway_instance_cert(&ca, "node-gw-id", "gw-a")?;
        let server = issue_test_gateway_instance_cert(&ca, "node-gw-id", "gw-b")?;
        let (endpoint, received) =
            spawn_mesh_quic_post_capture_server(server.tls.clone(), client.ca_pem.clone())?;

        let response: serde_json::Value = mesh_quic_post_json_with_peer_ca_pems_and_instance(
            &endpoint,
            "/gateway/mesh/forward-deliver",
            &client.tls,
            "ramflux-gateway",
            &[server.ca_pem],
            "gw-b",
            &serde_json::json!({"source_gateway_id":"gw-a","forwarded":true}),
        )?;
        assert_eq!(response, serde_json::json!({"ok": true}));
        let (peer_spiffe_uri, request) =
            received.recv_timeout(std::time::Duration::from_secs(5))?;
        assert_eq!(peer_spiffe_uri.as_deref(), Some("spiffe://node-gw-id/ramflux-gateway/gw-a"));
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/gateway/mesh/forward-deliver");
        Ok(())
    }

    #[test]
    fn mesh_quic_pool_registry_reuses_existing_pool_for_same_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let registry = MeshQuicPoolRegistry::default();
            let key = test_pool_key();
            let first = registry.pool_for(key.clone()).await;
            let second = registry.pool_for(key).await;
            assert!(Arc::ptr_eq(&first, &second));
            assert_eq!(registry.pools.load().len(), 1);
        });
        Ok(())
    }

    fn test_pool_key() -> MeshQuicPoolKey {
        MeshQuicPoolKey {
            endpoint: "127.0.0.1:7443".to_owned(),
            server_name: "ramflux-router".to_owned(),
            peer_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 7443)),
            peer_ca_pems: vec!["ca".to_owned()],
        }
    }

    fn test_peer_addr() -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], 17444))
    }

    fn assert_quic_result_contains(
        result: Result<super::MeshQuicCircuitProbe, TransportError>,
        expected: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match result {
            Err(TransportError::Quic(message)) => {
                assert!(
                    message.contains(expected),
                    "expected QUIC error containing {expected:?}, got {message:?}"
                );
                Ok(())
            }
            Err(other) => Err(format!("expected TransportError::Quic, got {other}").into()),
            Ok(_probe) => Err("expected circuit breaker to skip connect".into()),
        }
    }

    fn spawn_mesh_quic_get_echo_server(
        server_tls: MeshTlsConfig,
        trusted_client_ca: String,
        response_status: u16,
    ) -> Result<(String, mpsc::Receiver<CapturedQuicRequest>), Box<dyn std::error::Error>> {
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let (request_tx, request_rx) = mpsc::channel::<CapturedQuicRequest>();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| source.to_string());
            let Ok(runtime) = runtime else {
                let _ = endpoint_tx.send(runtime.map(|_| String::new()));
                return;
            };
            let result: Result<(), String> = runtime.block_on(async move {
                let roots = Arc::new(move || Ok(vec![trusted_client_ca.clone()]));
                let server =
                    MeshQuicServer::bind_with_pem_roots_provider("127.0.0.1:0", &server_tls, roots)
                        .map_err(|source| source.to_string())?;
                endpoint_tx
                    .send(
                        server
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .map_err(|source| source.to_string()),
                    )
                    .map_err(|source| source.to_string())?;
                let connection =
                    server.accept_connection().await.map_err(|source| source.to_string())?;
                let accepted = MeshQuicServer::accept_request_on_connection(&connection)
                    .await
                    .map_err(|source| source.to_string())?;
                request_tx
                    .send((
                        connection.peer_spiffe_uri().map(str::to_owned),
                        accepted.request.clone(),
                    ))
                    .map_err(|source| source.to_string())?;
                accepted
                    .write_json_response(response_status, &serde_json::json!({"ok": true}))
                    .await
                    .map_err(|source| source.to_string())?;
                std::future::pending::<()>().await;
                Ok(())
            });
            if let Err(error) = result {
                tracing::debug!(%error, "mesh QUIC GET test server stopped");
            }
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|source| test_error(source.to_string()))?
            .map_err(test_error)?;
        Ok((endpoint, request_rx))
    }

    fn spawn_mesh_quic_post_capture_server(
        server_tls: MeshTlsConfig,
        trusted_client_ca: String,
    ) -> Result<(String, mpsc::Receiver<CapturedQuicRequest>), Box<dyn std::error::Error>> {
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let (request_tx, request_rx) = mpsc::channel::<CapturedQuicRequest>();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| source.to_string());
            let Ok(runtime) = runtime else {
                let _ = endpoint_tx.send(runtime.map(|_| String::new()));
                return;
            };
            let result: Result<(), String> = runtime.block_on(async move {
                let roots = Arc::new(move || Ok(vec![trusted_client_ca.clone()]));
                let server =
                    MeshQuicServer::bind_with_pem_roots_provider("127.0.0.1:0", &server_tls, roots)
                        .map_err(|source| source.to_string())?;
                endpoint_tx
                    .send(
                        server
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .map_err(|source| source.to_string()),
                    )
                    .map_err(|source| source.to_string())?;
                let connection =
                    server.accept_connection().await.map_err(|source| source.to_string())?;
                let accepted = MeshQuicServer::accept_request_on_connection(&connection)
                    .await
                    .map_err(|source| source.to_string())?;
                request_tx
                    .send((
                        connection.peer_spiffe_uri().map(str::to_owned),
                        accepted.request.clone(),
                    ))
                    .map_err(|source| source.to_string())?;
                accepted
                    .write_json_response(200, &serde_json::json!({"ok": true}))
                    .await
                    .map_err(|source| source.to_string())?;
                std::future::pending::<()>().await;
                Ok(())
            });
            if let Err(error) = result {
                tracing::debug!(%error, "mesh QUIC POST capture test server stopped");
            }
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|source| test_error(source.to_string()))?
            .map_err(test_error)?;
        Ok((endpoint, request_rx))
    }

    struct TestCa {
        cert: PathBuf,
        key: PathBuf,
        pem: String,
    }

    struct TestPeerCerts {
        tls: MeshTlsConfig,
        ca_pem: String,
    }

    fn temp_cert_root(
        name: &str,
    ) -> Result<ramflux_test_support::TestPath, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("ramflux_mesh_quic_{name}_{}_{}", std::process::id(), nanos));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn issue_test_ca(root: &Path) -> Result<TestCa, Box<dyn std::error::Error>> {
        let ca_key = root.join("ca-key.pem");
        let ca_cert = root.join("ca.pem");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
        run_openssl(&[
            "req",
            "-x509",
            "-new",
            "-key",
            path_str(&ca_key)?,
            "-out",
            path_str(&ca_cert)?,
            "-days",
            "30",
            "-subj",
            "/CN=Ramflux Mesh QUIC GET Test CA",
        ])?;
        Ok(TestCa { pem: std::fs::read_to_string(&ca_cert)?, cert: ca_cert, key: ca_key })
    }

    fn issue_test_service_cert(
        ca: &TestCa,
        node_id: &str,
        service_id: &str,
    ) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
        let service_dir =
            ca.cert.parent().ok_or_else(|| test_error("CA cert has no parent"))?.join(service_id);
        std::fs::create_dir_all(&service_dir)?;
        let service_key = service_dir.join(format!("{service_id}-key.pem"));
        let service_csr = service_dir.join(format!("{service_id}.csr"));
        let service_cert = service_dir.join(format!("{service_id}.pem"));
        let ext = service_dir.join(format!("{service_id}.ext"));
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&service_key)?])?;
        run_openssl(&[
            "req",
            "-new",
            "-key",
            path_str(&service_key)?,
            "-out",
            path_str(&service_csr)?,
            "-subj",
            &format!("/CN={service_id}"),
        ])?;
        std::fs::write(
            &ext,
            format!(
                "subjectAltName = DNS:{service_id}, DNS:localhost, URI:spiffe://{node_id}/{service_id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
            ),
        )?;
        run_openssl(&[
            "x509",
            "-req",
            "-in",
            path_str(&service_csr)?,
            "-CA",
            path_str(&ca.cert)?,
            "-CAkey",
            path_str(&ca.key)?,
            "-CAcreateserial",
            "-out",
            path_str(&service_cert)?,
            "-days",
            "30",
            "-extfile",
            path_str(&ext)?,
        ])?;
        Ok(TestPeerCerts {
            tls: MeshTlsConfig { ca_cert: ca.cert.clone(), service_cert, service_key },
            ca_pem: ca.pem.clone(),
        })
    }

    fn issue_test_gateway_instance_cert(
        ca: &TestCa,
        node_id: &str,
        instance_id: &str,
    ) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
        let service_id = "ramflux-gateway";
        let service_dir = ca
            .cert
            .parent()
            .ok_or_else(|| test_error("CA cert has no parent"))?
            .join(format!("{service_id}-{instance_id}"));
        std::fs::create_dir_all(&service_dir)?;
        let service_key = service_dir.join(format!("{service_id}-key.pem"));
        let service_csr = service_dir.join(format!("{service_id}.csr"));
        let service_cert = service_dir.join(format!("{service_id}.pem"));
        let ext = service_dir.join(format!("{service_id}.ext"));
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&service_key)?])?;
        run_openssl(&[
            "req",
            "-new",
            "-key",
            path_str(&service_key)?,
            "-out",
            path_str(&service_csr)?,
            "-subj",
            &format!("/CN={service_id}"),
        ])?;
        std::fs::write(
            &ext,
            format!(
                "subjectAltName = DNS:{service_id}, DNS:localhost, URI:spiffe://{node_id}/{service_id}/{instance_id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
            ),
        )?;
        run_openssl(&[
            "x509",
            "-req",
            "-in",
            path_str(&service_csr)?,
            "-CA",
            path_str(&ca.cert)?,
            "-CAkey",
            path_str(&ca.key)?,
            "-CAcreateserial",
            "-out",
            path_str(&service_cert)?,
            "-days",
            "30",
            "-extfile",
            path_str(&ext)?,
        ])?;
        Ok(TestPeerCerts {
            tls: MeshTlsConfig { ca_cert: ca.cert.clone(), service_cert, service_key },
            ca_pem: ca.pem.clone(),
        })
    }

    fn run_openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("openssl").args(args).status()?;
        if !status.success() {
            return Err(format!("openssl failed with status {status}: {}", args.join(" ")).into());
        }
        Ok(())
    }

    fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
        path.to_str().ok_or_else(|| format!("non-UTF-8 path {}", path.display()).into())
    }

    #[test]
    fn r8_postcard_encode_and_decode_failures_are_permanent_protocol_errors() {
        struct CannotEncode;
        impl serde::Serialize for CannotEncode {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("cannot encode this value"))
            }
        }
        assert!(matches!(postcard_to_allocvec(&CannotEncode), Err(TransportError::Protocol(_))));
        assert!(matches!(postcard_from_bytes::<u64>(&[0xff]), Err(TransportError::Protocol(_))));
    }
    #[tokio::test]
    async fn r8_runtime_payload_type_mismatches_are_permanent_protocol_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let (jobs, receiver) = mpsc::channel::<MeshQuicClientJob>();
        let runtime = MeshQuicClientRuntime { jobs };
        let worker = std::thread::spawn(move || -> Result<(), String> {
            for _ in 0..3 {
                let job = receiver.recv().map_err(|e| e.to_string())?;
                let response = match job.request.request {
                    MeshQuicClientRequestPayload::Json(_)
                    | MeshQuicClientRequestPayload::RawJson(_) => {
                        MeshQuicClientResponsePayload::Postcard(MeshQuicPostcardResponse {
                            status: 200,
                            body: Vec::new(),
                        })
                    }
                    MeshQuicClientRequestPayload::Postcard(_) => {
                        MeshQuicClientResponsePayload::Json(GatewayQuicResponse {
                            status: 200,
                            body: serde_json::Value::Null,
                        })
                    }
                };
                job.response.send(Ok(response));
            }
            Ok(())
        });
        let tls = MeshTlsConfig {
            ca_cert: PathBuf::new(),
            service_cert: PathBuf::new(),
            service_key: PathBuf::new(),
        };
        let request = GatewayQuicRequest {
            method: "GET".into(),
            path: "/".into(),
            body: serde_json::Value::Null,
        };
        assert!(matches!(
            runtime.request("unused", &tls, "unused", &[], request.clone()),
            Err(TransportError::Protocol(_))
        ));
        assert!(matches!(
            runtime.request_async("unused", &tls, "unused", &[], request).await,
            Err(TransportError::Protocol(_))
        ));
        assert!(matches!(
            runtime
                .request_postcard_async(
                    "unused",
                    &tls,
                    "unused",
                    &[],
                    MeshQuicPostcardRequest {
                        method: "POST".into(),
                        path: "/".into(),
                        body: Vec::new()
                    }
                )
                .await,
            Err(TransportError::Protocol(_))
        ));
        worker.join().map_err(|_| test_error("worker panicked"))?.map_err(test_error)?;
        Ok(())
    }
    #[tokio::test]
    async fn r8_a_real_postcard_response_without_magic_is_a_permanent_protocol_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("r8-magic")?;
        let ca = issue_test_ca(&root)?;
        let client = issue_test_service_cert(&ca, "node-r8", "client")?;
        let server = issue_test_service_cert(&ca, "node-r8", "server")?;
        let roots = Arc::new(move || Ok(vec![client.ca_pem.clone()]));
        let listener =
            MeshQuicServer::bind_with_pem_roots_provider("127.0.0.1:0", &server.tls, roots)?;
        let endpoint = listener.local_addr()?.to_string();
        let task = tokio::spawn(async move {
            let connection = listener.accept_connection().await?;
            let MeshQuicAcceptedWireRequest::Postcard(mut request) =
                MeshQuicServer::accept_json_or_postcard_request_on_connection(&connection).await?
            else {
                return Err(TransportError::Io(std::io::Error::other("postcard request expected")));
            };
            write_quic_json_message(
                &mut request.send,
                &GatewayQuicResponse { status: 200, body: serde_json::Value::Null },
            )
            .await?;
            request.send.finish().map_err(|e| TransportError::Quic(e.to_string()))?;
            drain_quic_recv_to_fin(&mut request.recv).await?;
            std::future::pending::<()>().await;
            Ok::<(), TransportError>(())
        });
        let result = mesh_quic_post_postcard_with_peer_ca_pems_async::<_, u8>(
            &endpoint,
            "/",
            &client.tls,
            "server",
            &[server.ca_pem],
            &1_u8,
        )
        .await;
        task.abort();
        let _ = task.await;
        assert!(matches!(result, Err(TransportError::Protocol(_))), "{result:?}");
        Ok(())
    }

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
        message.into().into()
    }

    // ---- bounded ingress (mesh_quic_limited) ----

    struct LimitedRig {
        server: MeshQuicServer,
        client_tls: MeshTlsConfig,
        ca_pem: String,
        endpoint: quinn::Endpoint,
        addr: SocketAddr,
        _root: ramflux_test_support::TestPath,
    }

    fn limited_rig(name: &str) -> Result<LimitedRig, Box<dyn std::error::Error>> {
        let root = temp_cert_root(name)?;
        let ca = issue_test_ca(&root)?;
        let server_certs = issue_test_service_cert(&ca, "node-a", "ramflux-relay")?;
        let client = issue_test_service_cert(&ca, "node-a", "ramflux-router")?;
        let ca_pem = client.ca_pem.clone();
        let roots_pem = ca_pem.clone();
        let roots = Arc::new(move || Ok(vec![roots_pem.clone()]));
        let server =
            MeshQuicServer::bind_with_pem_roots_provider("127.0.0.1:0", &server_certs.tls, roots)?;
        let addr = server.local_addr()?;
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(mesh_quic_client_config_with_pem_roots(
            &client.tls,
            std::slice::from_ref(&ca_pem),
        )?);
        Ok(LimitedRig { server, client_tls: client.tls, ca_pem, endpoint, addr, _root: root })
    }

    fn mesh_ijson_rig(name: &str) -> Result<LimitedRig, Box<dyn std::error::Error>> {
        let root = temp_cert_root(name)?;
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate()?)?;
        let ca_pem = ca.pem();
        let ca_path = root.join("ca.pem");
        std::fs::write(&ca_path, &ca_pem)?;
        let make_peer = |name: &str, dns_name: &str, uri: &str| {
            let key = rcgen::KeyPair::generate()?;
            let mut params = rcgen::CertificateParams::new(vec![dns_name.to_owned()])?;
            params.subject_alt_names.push(rcgen::SanType::URI(uri.try_into()?));
            params.extended_key_usages = vec![
                rcgen::ExtendedKeyUsagePurpose::ServerAuth,
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let cert = params.signed_by(&key, &ca)?;
            let cert_path = root.join(format!("{name}.pem"));
            let key_path = root.join(format!("{name}.key"));
            std::fs::write(&cert_path, cert.pem())?;
            std::fs::write(&key_path, key.serialize_pem())?;
            Ok::<_, Box<dyn std::error::Error>>(MeshTlsConfig {
                ca_cert: ca_path.clone(),
                service_cert: cert_path,
                service_key: key_path,
            })
        };
        let server_tls = make_peer("server", "ramflux-relay", "spiffe://node/ramflux-relay")?;
        let client_tls = make_peer("client", "ramflux-router", "spiffe://node/ramflux-router")?;
        let trusted_ca = ca_pem.clone();
        let roots = Arc::new(move || Ok(vec![trusted_ca.clone()]));
        let server =
            MeshQuicServer::bind_with_pem_roots_provider("127.0.0.1:0", &server_tls, roots)?;
        let addr = server.local_addr()?;
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(mesh_quic_client_config_with_pem_roots(
            &client_tls,
            std::slice::from_ref(&ca_pem),
        )?);
        Ok(LimitedRig { server, client_tls, ca_pem, endpoint, addr, _root: root })
    }

    fn frame_of(body: &str) -> Vec<u8> {
        let json = format!(r#"{{"method":"POST","path":"/p","body":{body}}}"#);
        let mut out = u32::try_from(json.len()).unwrap_or(0).to_be_bytes().to_vec();
        out.extend(json.as_bytes());
        out
    }

    async fn limited_accept(
        rig: &LimitedRig,
        max: usize,
        budget: Duration,
    ) -> Result<MeshQuicLimitedIngress, TransportError> {
        let connection = rig.server.accept_connection().await?;
        MeshQuicServer::accept_limited_request(&connection, max, Instant::now() + budget).await
    }

    fn json_quic_frame(json: &[u8], trailing: bool) -> Vec<u8> {
        let mut frame = u32::try_from(json.len()).unwrap_or(0).to_be_bytes().to_vec();
        frame.extend_from_slice(json);
        if trailing {
            frame.extend_from_slice(b"trailing");
        }
        frame
    }

    fn valid_request_frame() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(json_quic_frame(
            &serde_json::to_vec(&GatewayQuicRequest {
                method: "GET".to_owned(),
                path: "/p".to_owned(),
                body: serde_json::json!({"created_at": 9_007_199_254_740_991_i64}),
            })?,
            false,
        ))
    }

    fn i_json_request_frame(body: &str, trailing: bool) -> Vec<u8> {
        json_quic_frame(
            format!(r#"{{"method":"POST","path":"/p","body":{body}}}"#).as_bytes(),
            trailing,
        )
    }

    fn padded_attachment_frame() -> (Vec<u8>, Vec<u8>) {
        const MAX_BODY: usize = 16 * 1024;
        let body = format!("{{\"a\":1{}}}", " ".repeat(MAX_BODY + 1 - 7));
        let frame =
            format!(r#"{{"method":"POST","path":"/s9/attachments/renew/source","body":{body}}}"#);
        (json_quic_frame(frame.as_bytes(), false), body.into_bytes())
    }

    async fn assert_attachment_cap_body_preserved(
        server_connection: &super::MeshQuicConnection,
        client_connection: &quinn::Connection,
        wire_api: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (frame, expected_body) = padded_attachment_frame();
        let (mut send, mut recv) = client_connection.open_bi().await?;
        send.write_all(&frame).await?;
        send.finish()?;
        let raw_body = if wire_api {
            let accepted =
                MeshQuicServer::accept_json_or_postcard_request_on_connection(server_connection)
                    .await?;
            let MeshQuicAcceptedWireRequest::Json(accepted) = accepted else {
                return Err(test_error("attachment request was not accepted as JSON"));
            };
            let raw = accepted
                .raw_body
                .as_deref()
                .ok_or_else(|| test_error("attachment request lost its raw body"))?;
            assert_eq!(raw, expected_body);
            assert!(raw.len() > 16 * 1024, "wire bytes must exceed the attachment cap");
            let preserved = raw.to_vec();
            accepted.write_json_response(413, &"body").await?;
            preserved
        } else {
            let accepted = MeshQuicServer::accept_request_on_connection(server_connection).await?;
            let raw = accepted
                .raw_body
                .as_deref()
                .ok_or_else(|| test_error("attachment request lost its raw body"))?;
            assert_eq!(raw, expected_body);
            assert!(raw.len() > 16 * 1024, "wire bytes must exceed the attachment cap");
            let preserved = raw.to_vec();
            accepted.write_json_response(413, &"body").await?;
            preserved
        };
        assert_eq!(raw_body, expected_body);
        let response =
            tokio::time::timeout(Duration::from_secs(10), super::read_quic_raw_frame(&mut recv))
                .await??;
        assert_eq!(
            response,
            serde_json::to_vec(&GatewayQuicResponse {
                status: 413,
                body: serde_json::json!("body")
            })?
        );
        Ok(())
    }

    async fn assert_i_json_rejection_response(
        recv: &mut quinn::RecvStream,
        reset_expected: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if reset_expected {
            let result =
                tokio::time::timeout(Duration::from_secs(10), recv.read_chunk(4, true)).await?;
            match result {
                Err(quinn::ReadError::Reset(code))
                    if code.into_inner() == u64::from(super::MESH_I_JSON_REJECTED_CODE) => {}
                other => {
                    return Err(test_error(format!(
                        "expired I-JSON rejection deadline must reset stream with code 0x4A53, got {other:?}"
                    )));
                }
            }
            return Ok(());
        }
        let response =
            tokio::time::timeout(Duration::from_secs(10), super::read_quic_raw_frame(recv))
                .await??;
        let expected =
            br#"{"status":400,"body":{"error":"i_json_rejected","reason_code":"i_json_rejected"}}"#;
        assert_eq!(response, expected, "I-JSON rejection response must be byte-exact");
        Ok(())
    }

    async fn assert_second_stream_served(
        server_connection: &super::MeshQuicConnection,
        client_connection: &quinn::Connection,
        wire_api: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut invalid_send, mut invalid_recv) = client_connection.open_bi().await?;
        invalid_send
            .write_all(&i_json_request_frame(r#"{"x_probe":null,"x_probe":null}"#, false))
            .await?;
        invalid_send.finish()?;
        let (mut send, mut recv) = client_connection.open_bi().await?;
        send.write_all(&valid_request_frame()?).await?;
        send.finish()?;
        if wire_api {
            let accepted =
                MeshQuicServer::accept_json_or_postcard_request_on_connection(server_connection)
                    .await?;
            let MeshQuicAcceptedWireRequest::Json(accepted) = accepted else {
                return Err(test_error("valid JSON request was not accepted as JSON"));
            };
            assert_eq!(
                accepted.request.body["created_at"].as_i64(),
                Some(9_007_199_254_740_991_i64),
                "safe integer endpoint must reach the request handler"
            );
            accepted.write_json_response(200, &serde_json::json!({"ok": true})).await?;
        } else {
            let accepted = MeshQuicServer::accept_request_on_connection(server_connection).await?;
            assert_eq!(
                accepted.request.body["created_at"].as_i64(),
                Some(9_007_199_254_740_991_i64),
                "safe integer endpoint must reach the request handler"
            );
            accepted.write_json_response(200, &serde_json::json!({"ok": true})).await?;
        }
        assert_i_json_rejection_response(&mut invalid_recv, false).await?;
        let response =
            tokio::time::timeout(Duration::from_secs(10), super::read_quic_raw_frame(&mut recv))
                .await??;
        assert_eq!(
            response,
            serde_json::to_vec(&GatewayQuicResponse {
                status: 200,
                body: serde_json::json!({"ok": true})
            })?
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mesh_frame_ijson_rejected_on_stream() -> Result<(), Box<dyn std::error::Error>> {
        for (row, body, trailing, expired) in [
            ("plain", r#"{"x_probe":null,"x_probe":null}"#, false, false),
            ("unsafe-integer", r#"{"created_at":9007199254740992}"#, false, false),
            ("trailing-withheld-fin", r#"{"x_probe":null,"x_probe":null}"#, true, false),
            ("expired-deadline", r#"{"x_probe":null,"x_probe":null}"#, false, true),
        ] {
            let rig = mesh_ijson_rig(&format!("mesh_ijson_{row}"))?;
            let (server_connection_result, client_result) =
                tokio::join!(rig.server.accept_connection(), async {
                    let connection = rig.endpoint.connect(rig.addr, "ramflux-relay")?.await?;
                    let (mut send, recv) = connection.open_bi().await?;
                    send.write_all(&i_json_request_frame(body, trailing)).await?;
                    if !trailing {
                        send.finish()?;
                    }
                    Ok::<_, Box<dyn std::error::Error>>((connection, send, recv))
                });
            let server_connection = server_connection_result?;
            let (client_connection, first_send, mut first_recv) = client_result?;
            let mut held_sends = vec![first_send];

            for wire_api in [false, true] {
                let deadline = if expired {
                    Instant::now()
                        .checked_sub(Duration::from_millis(1))
                        .ok_or_else(|| test_error("clock"))?
                } else {
                    Instant::now() + Duration::from_secs(2)
                };
                let rejected = if wire_api {
                    let stream =
                        MeshQuicServer::accept_bi_on_connection(&server_connection).await?;
                    MeshQuicServer::read_wire_request_from_bi_with_deadline(stream, Some(deadline))
                        .await
                        .map(|_| ())
                } else {
                    MeshQuicServer::accept_request_on_connection_once(
                        &server_connection,
                        Some(deadline),
                    )
                    .await
                    .map(|_| ())
                };
                assert!(
                    rejected
                        .as_ref()
                        .is_err_and(|error| ramflux_protocol::is_i_json_rejection(error)),
                    "{row}, wire_api={wire_api}: expected I-JSON refusal, got {rejected:?}"
                );
                assert_i_json_rejection_response(&mut first_recv, expired).await?;
                assert_second_stream_served(&server_connection, &client_connection, wire_api)
                    .await?;
                if wire_api {
                    break;
                }
                // Reopen a receive half for the wire API's independent rejection row.
                let (mut send, recv) = client_connection.open_bi().await?;
                send.write_all(&i_json_request_frame(body, trailing)).await?;
                if !trailing {
                    send.finish()?;
                }
                held_sends.push(send);
                first_recv = recv;
            }
            for wire_api in [false, true] {
                assert_attachment_cap_body_preserved(
                    &server_connection,
                    &client_connection,
                    wire_api,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn dial(
        rig: &LimitedRig,
    ) -> Result<
        (quinn::SendStream, (quinn::RecvStream, quinn::Connection)),
        Box<dyn std::error::Error>,
    > {
        let connection = rig.endpoint.connect(rig.addr, "ramflux-relay")?.await?;
        let (send, recv) = connection.open_bi().await?;
        // The receive side stays open: dropping it would send STOP_SENDING.
        Ok((send, (recv, connection)))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn limited_ingress_bounds_raw_received_bytes_exactly()
    -> Result<(), Box<dyn std::error::Error>> {
        const MAX: usize = 16384;
        let rig = limited_rig("limited_exact")?;
        let _keep = (&rig.client_tls, &rig.ca_pem);
        // A body of exactly MAX raw bytes is accepted as received; MAX + 1 is refused.
        let pad = |n: usize| format!("\"{}\"", "a".repeat(n - 2));
        // Whitespace padding inside the value counts: it is not normalized away.
        let spaced = |n: usize| format!("{{\"a\":1{}}}", " ".repeat(n - 7));
        let cases: Vec<(&str, String, bool)> = vec![
            ("string at cap", pad(MAX), true),
            ("string over cap", pad(MAX + 1), false),
            ("padded valid object at cap", spaced(MAX), true),
            ("padded valid object over cap", spaced(MAX + 1), false),
        ];
        for (name, body, accepted) in cases {
            let server = limited_accept(&rig, MAX, Duration::from_secs(10));
            let client = async {
                let (mut send, connection) = dial(&rig).await?;
                send.write_all(&frame_of(&body)).await?;
                Ok::<_, Box<dyn std::error::Error>>((send, connection))
            };
            let (ingress, held) = tokio::join!(server, client);
            let _held = held?;
            match (ingress?, accepted) {
                (MeshQuicLimitedIngress::Request(request), true) => {
                    assert_eq!(request.body.len(), body.len(), "{name}");
                    assert_eq!(request.body, body.as_bytes(), "{name}");
                }
                (MeshQuicLimitedIngress::TooLarge(_), false) => {}
                _ => return Err(test_error(format!("wrong outcome for {name}"))),
            }
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn limited_ingress_refuses_an_oversized_frame_before_reading_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let rig = limited_rig("limited_prefix")?;
        let server = limited_accept(&rig, 16384, Duration::from_secs(10));
        let client = async {
            let (mut send, connection) = dial(&rig).await?;
            // Only the length prefix of a 1 MiB frame is ever sent.
            send.write_all(&1_048_576_u32.to_be_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error>>((send, connection))
        };
        let (ingress, held) = tokio::join!(server, client);
        let _held = held?;
        assert!(matches!(ingress?, MeshQuicLimitedIngress::TooLarge(_)));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn limited_ingress_gives_up_on_a_stalled_read_within_the_original_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let rig = limited_rig("limited_held_read")?;
        let started = Instant::now();
        let server = limited_accept(&rig, 16384, Duration::from_millis(300));
        let client = async {
            let (mut send, connection) = dial(&rig).await?;
            // Promise 100 bytes, send 10, then hold the stream open.
            let mut partial = 100_u32.to_be_bytes().to_vec();
            partial.extend([b'x'; 10]);
            send.write_all(&partial).await?;
            Ok::<_, Box<dyn std::error::Error>>((send, connection))
        };
        let guarded =
            tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(server, client) });
        let (ingress, held) = guarded.await.map_err(|_| test_error("hang guard"))?;
        let _held = held?;
        assert!(matches!(ingress, Err(TransportError::Quic(ref m)) if m.contains("deadline")));
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn limited_response_does_not_wait_for_the_peer_to_finish_sending()
    -> Result<(), Box<dyn std::error::Error>> {
        let rig = limited_rig("limited_held_fin")?;
        let server = async {
            let MeshQuicLimitedIngress::Request(request) =
                limited_accept(&rig, 16384, Duration::from_secs(10)).await?
            else {
                return Err(test_error("expected a request"));
            };
            let started = Instant::now();
            request
                .responder
                .respond(
                    200,
                    &serde_json::json!({"ok": true}),
                    Instant::now() + Duration::from_secs(10),
                )
                .await?;
            Ok::<_, Box<dyn std::error::Error>>(started.elapsed())
        };
        let client = async {
            let (mut send, connection) = dial(&rig).await?;
            // The request is complete, but the send side is never finished and the
            // response is never read.
            send.write_all(&frame_of("1")).await?;
            Ok::<_, Box<dyn std::error::Error>>((send, connection))
        };
        let guarded =
            tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(server, client) });
        let (elapsed, held) = guarded.await.map_err(|_| test_error("hang guard"))?;
        let _held = held?;
        // The old drain would have waited out its 30 s timeout here.
        assert!(elapsed? < Duration::from_secs(5));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_deadline_stops_a_response_write_immediately()
    -> Result<(), Box<dyn std::error::Error>> {
        let rig = limited_rig("limited_expired_write")?;
        let server = async {
            let MeshQuicLimitedIngress::Request(request) =
                limited_accept(&rig, 16384, Duration::from_secs(10)).await?
            else {
                return Err(test_error("expected a request"));
            };
            let past = Instant::now()
                .checked_sub(Duration::from_millis(1))
                .ok_or_else(|| test_error("clock"))?;
            Ok(request.responder.respond(200, &serde_json::json!({}), past).await)
        };
        let client = async {
            let (mut send, connection) = dial(&rig).await?;
            send.write_all(&frame_of("1")).await?;
            Ok::<_, Box<dyn std::error::Error>>((send, connection))
        };
        let (result, held) = tokio::join!(server, client);
        let _held = held?;
        let result: Result<(), TransportError> = result?;
        assert!(matches!(result, Err(TransportError::Quic(ref m)) if m.contains("deadline")));
        Ok(())
    }
}
