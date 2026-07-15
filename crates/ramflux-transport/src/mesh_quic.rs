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
use arc_swap::ArcSwap;
use tokio::sync::{Mutex, Notify};

const MESH_QUIC_CONNECT_TIMEOUT_DEFAULT: Duration = Duration::from_secs(3);
const MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT: Duration = Duration::from_secs(5);
const MESH_QUIC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MESH_QUIC_CACHED_CONNECTION_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
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
    connection: quinn::Connection,
    peer_spiffe_uri: Option<String>,
}

pub struct MeshQuicAcceptedRequest {
    pub request: GatewayQuicRequest,
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
}

struct MeshQuicClientRequestJob {
    endpoint: String,
    server_name: String,
    tls: MeshTlsConfig,
    peer_ca_pems: Vec<String>,
    request: MeshQuicClientRequestPayload,
    enqueued_at: std::time::Instant,
}

enum MeshQuicClientRequestPayload {
    Json(GatewayQuicRequest),
    Postcard(MeshQuicPostcardRequest),
}

enum MeshQuicClientResponsePayload {
    Json(GatewayQuicResponse),
    Postcard(MeshQuicPostcardResponse),
}

enum MeshQuicClientResponse {
    Sync(mpsc::Sender<Result<MeshQuicClientResponsePayload, TransportError>>),
    Async(tokio::sync::oneshot::Sender<Result<MeshQuicClientResponsePayload, TransportError>>),
}

impl MeshQuicClientResponse {
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
            Some(MeshQuicCircuitBreakerState::Open { .. }) => {
                states.insert(key.clone(), MeshQuicCircuitBreakerState::HalfOpen);
                Ok(MeshQuicCircuitProbe { key })
            }
            Some(MeshQuicCircuitBreakerState::HalfOpen) => Err(TransportError::Quic(format!(
                "mesh QUIC circuit breaker half-open probe already in flight for {server_name}@{peer_addr}; skipping connect"
            ))),
            None => Ok(MeshQuicCircuitProbe { key }),
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
            TransportError::Quic(format!(
                "mesh QUIC handshake failed from {remote_address}: {error}"
            ))
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
        let request = serde_json::from_slice::<GatewayQuicRequest>(&frame)?;
        Ok(MeshQuicAcceptedWireRequest::Json(MeshQuicAcceptedRequest { request, send, recv }))
    }

    /// # Errors
    /// Returns an error when QUIC accept, stream accept, or request decoding fails.
    pub async fn accept_json_or_postcard_request_on_connection(
        connection: &MeshQuicConnection,
    ) -> Result<MeshQuicAcceptedWireRequest, TransportError> {
        let stream = Self::accept_bi_on_connection(connection).await?;
        Self::read_wire_request_from_bi(stream).await
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
        let request = read_quic_json_frame(&mut recv).await.map_err(|error| {
            tracing::error!(%remote_address, %error, "mesh QUIC request frame decode failed");
            error
        })?;
        record_mesh_server_quic_request_read(request_read_started.elapsed());
        Ok(MeshQuicAcceptedRequest { request, send, recv })
    }
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

fn quinn_peer_spiffe_uri(connection: &quinn::Connection) -> Result<Option<String>, TransportError> {
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
        Err(TransportError::Http(format!("HTTP {}: {}", response.status, response.body)))
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
        Err(TransportError::Http(format!("HTTP {}: {}", response.status, response.body)))
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
        Err(TransportError::Http(format!("HTTP {}: {}", response.status, response.body)))
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
        Err(TransportError::Http(format!("HTTP {}: {}", response.status, response.body)))
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
        Ok(serde_json::from_slice(&response.body)?)
    } else {
        Err(TransportError::Http(format!(
            "HTTP {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )))
    }
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
        let (response, receiver) = mpsc::channel();
        self.jobs
            .send(MeshQuicClientJob {
                request: MeshQuicClientRequestJob {
                    endpoint: endpoint.to_owned(),
                    server_name: server_name.to_owned(),
                    tls: tls.clone(),
                    peer_ca_pems: peer_ca_pems.to_vec(),
                    request: MeshQuicClientRequestPayload::Json(request),
                    enqueued_at: std::time::Instant::now(),
                },
                response: MeshQuicClientResponse::Sync(response),
            })
            .map_err(|error| TransportError::Quic(format!("mesh QUIC runtime stopped: {error}")))?;
        match receiver.recv().map_err(|error| {
            TransportError::Quic(format!("mesh QUIC runtime stopped: {error}"))
        })?? {
            MeshQuicClientResponsePayload::Json(response) => Ok(response),
            MeshQuicClientResponsePayload::Postcard(_response) => Err(TransportError::Quic(
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
                    enqueued_at: std::time::Instant::now(),
                },
                response: MeshQuicClientResponse::Async(response),
            })
            .map_err(|error| TransportError::Quic(format!("mesh QUIC runtime stopped: {error}")))?;
        match receiver.await.map_err(|error| {
            TransportError::Quic(format!("mesh QUIC runtime stopped: {error}"))
        })?? {
            MeshQuicClientResponsePayload::Json(response) => Ok(response),
            MeshQuicClientResponsePayload::Postcard(_response) => Err(TransportError::Quic(
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
                    enqueued_at: std::time::Instant::now(),
                },
                response: MeshQuicClientResponse::Async(response),
            })
            .map_err(|error| TransportError::Quic(format!("mesh QUIC runtime stopped: {error}")))?;
        match receiver.await.map_err(|error| {
            TransportError::Quic(format!("mesh QUIC runtime stopped: {error}"))
        })?? {
            MeshQuicClientResponsePayload::Postcard(response) => Ok(response),
            MeshQuicClientResponsePayload::Json(_response) => Err(TransportError::Quic(
                "mesh QUIC runtime returned JSON response for postcard request".to_owned(),
            )),
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
            let MeshQuicClientJob { request, response: response_sender } = job;
            let response = mesh_quic_cached_request(pools, breakers, request, pool_size).await;
            response_sender.send(response);
        });
    }
    Ok(())
}

async fn mesh_quic_cached_request(
    pools: Arc<MeshQuicPoolRegistry>,
    breakers: Arc<MeshQuicCircuitBreakers>,
    job: MeshQuicClientRequestJob,
    pool_size: usize,
) -> Result<MeshQuicClientResponsePayload, TransportError> {
    record_mesh_client_request();
    let peer_addr = resolve_endpoint(&job.endpoint)?;
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
    let request_timeout = if reused_cached_connection {
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
        Err(error) if reused_cached_connection => {
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
            let connection =
                mesh_quic_connect_and_insert(pool, breakers, peer_addr, job, pool_size).await?;
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
    pool: &MeshQuicConnectionPool,
    breakers: &MeshQuicCircuitBreakers,
    peer_addr: SocketAddr,
    job: &MeshQuicClientRequestJob,
    pool_size: usize,
) -> Result<MeshQuicSelectedConnection, TransportError> {
    let connect_result =
        mesh_quic_connect(peer_addr, &job.tls, &job.server_name, &job.peer_ca_pems, breakers).await;
    pool.finish_connect_reservation();
    let cached = connect_result?;
    Ok(pool.insert_connection(cached, pool_size).await)
}

fn mesh_quic_client_pool_size() -> usize {
    std::env::var(ROUTER_ASYNC_POOL_SIZE_ENV)
        .or_else(|_| std::env::var(MESH_QUIC_CLIENT_POOL_SIZE_ENV))
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(MESH_QUIC_CLIENT_POOL_SIZE_DEFAULT)
}

fn mesh_quic_connect_timeout() -> Duration {
    duration_from_millis_env(MESH_QUIC_CONNECT_TIMEOUT_MS_ENV, MESH_QUIC_CONNECT_TIMEOUT_DEFAULT)
}

fn mesh_quic_connect_breaker_cooldown() -> Duration {
    duration_from_millis_env(
        MESH_QUIC_CONNECT_BREAKER_COOLDOWN_MS_ENV,
        MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT,
    )
}

fn duration_from_millis_env(name: &str, default: Duration) -> Duration {
    duration_from_millis_value(std::env::var(name).ok().as_deref(), default)
}

fn duration_from_millis_value(value: Option<&str>, default: Duration) -> Duration {
    let Some(value) = value else {
        return default;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("${") {
        return default;
    }
    match trimmed.parse::<u64>() {
        Ok(millis) if millis > 0 => Duration::from_millis(millis),
        Ok(_) | Err(_) => default,
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
    let probe = breakers.before_connect(peer_addr, server_name, Instant::now())?;
    let connecting = endpoint.connect(peer_addr, server_name).map_err(|error| {
        let error = TransportError::Quic(error.to_string());
        breakers.record_connect_failure(&probe, Instant::now(), breaker_cooldown);
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
            TransportError::Quic(format!("mesh QUIC connect to {peer_addr} failed: {error}"))
        });
    let connection = match connection_result {
        Ok(connection) => {
            breakers.record_connect_success(&probe);
            connection
        }
        Err(error) => {
            breakers.record_connect_failure(&probe, Instant::now(), breaker_cooldown);
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
    tokio::time::timeout(timeout, async {
        let open_bi_started = std::time::Instant::now();
        let open_bi_result =
            connection.open_bi().await.map_err(|error| TransportError::Quic(error.to_string()));
        record_mesh_client_open_bi(open_bi_started.elapsed());
        let (mut send, mut recv) = open_bi_result?;
        let request_write_started = std::time::Instant::now();
        let request_write_result = async {
            match request {
                MeshQuicClientRequestPayload::Json(request) => {
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
                MeshQuicClientRequestPayload::Json(_request) => {
                    MeshQuicClientResponsePayload::Json(read_quic_json_frame(&mut recv).await?)
                }
                MeshQuicClientRequestPayload::Postcard(_request) => {
                    let frame = read_quic_raw_frame(&mut recv).await?;
                    let body = frame.strip_prefix(MESH_QUIC_POSTCARD_MAGIC).ok_or_else(|| {
                        TransportError::Quic(
                            "mesh QUIC postcard response missing binary magic".to_owned(),
                        )
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
    })?
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
        .map_err(|error| TransportError::Quic(format!("postcard encode failed: {error}")))
}

fn postcard_from_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, TransportError> {
    postcard::from_bytes(bytes)
        .map_err(|error| TransportError::Quic(format!("postcard decode failed: {error}")))
}

async fn drain_quic_recv_to_fin(recv: &mut quinn::RecvStream) -> Result<(), TransportError> {
    tokio::time::timeout(MESH_QUIC_REQUEST_TIMEOUT, recv.read_to_end(0))
        .await
        .map_err(|error| TransportError::Quic(error.to_string()))?
        .map(|_trailing| ())
        .map_err(|error| TransportError::Quic(error.to_string()))
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
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::{
        GatewayQuicRequest, MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT,
        MESH_QUIC_CONNECT_TIMEOUT_DEFAULT, MeshQuicCircuitBreakers, MeshQuicConnectionPool,
        MeshQuicPoolKey, MeshQuicPoolRegistry, MeshQuicServer, MeshTlsConfig,
        duration_from_millis_value, mesh_quic_get_json_with_peer_ca_pems, resolve_endpoint,
    };
    use crate::TransportError;

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
            duration_from_millis_value(None, MESH_QUIC_CONNECT_TIMEOUT_DEFAULT),
            Duration::from_secs(3)
        );
        assert_eq!(
            duration_from_millis_value(Some("2500"), MESH_QUIC_CONNECT_TIMEOUT_DEFAULT),
            Duration::from_millis(2500)
        );
        assert_eq!(
            duration_from_millis_value(
                Some("${RAMFLUX_MESH_QUIC_CONNECT_TIMEOUT_MS:-3000}"),
                MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
            ),
            MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
        );
        assert_eq!(
            duration_from_millis_value(Some("not-a-duration"), MESH_QUIC_CONNECT_TIMEOUT_DEFAULT),
            MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
        );
        assert_eq!(
            duration_from_millis_value(Some("0"), MESH_QUIC_CONNECT_TIMEOUT_DEFAULT),
            MESH_QUIC_CONNECT_TIMEOUT_DEFAULT
        );
    }

    #[test]
    fn mesh_quic_breaker_cooldown_defaults_to_five_seconds_and_accepts_env_override() {
        assert_eq!(
            duration_from_millis_value(None, MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT),
            Duration::from_secs(5)
        );
        assert_eq!(
            duration_from_millis_value(Some("7500"), MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT),
            Duration::from_millis(7500)
        );
        assert_eq!(
            duration_from_millis_value(
                Some("${RAMFLUX_MESH_QUIC_CONNECT_BREAKER_COOLDOWN_MS:-5000}"),
                MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT
            ),
            MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT
        );
        assert_eq!(
            duration_from_millis_value(Some("bad"), MESH_QUIC_CONNECT_BREAKER_COOLDOWN_DEFAULT),
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
            TransportError::Http(message) => assert!(message.contains("HTTP 404")),
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

    struct TestCa {
        cert: PathBuf,
        key: PathBuf,
        pem: String,
    }

    struct TestPeerCerts {
        tls: MeshTlsConfig,
        ca_pem: String,
    }

    fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ramflux_mesh_quic_{name}_{}_{}",
            std::process::id(),
            nanos
        ));
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

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
        message.into().into()
    }
}
