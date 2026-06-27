// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::Duration;

use crate::perf_metrics::{
    record_mesh_client_cached_request_failure, record_mesh_client_connect,
    record_mesh_client_pool_hit, record_mesh_client_pool_miss, record_mesh_client_request,
    record_mesh_client_request_timeout, record_mesh_client_retry, record_mesh_client_retry_failure,
    record_mesh_client_retry_success, record_mesh_client_runtime_queue_wait,
    record_mesh_client_tls_handshake, record_mesh_server_quic_connection_accepted,
    record_mesh_server_quic_request_read, record_mesh_server_quic_response_write,
    record_mesh_server_quic_stream_accepted,
};
use crate::tls_config::{
    MeshRootPemProvider, mesh_quic_client_config_with_pem_roots,
    mesh_quic_server_config_with_dynamic_pem_roots,
};
use crate::{
    GatewayQuicRequest, GatewayQuicResponse, MeshTlsConfig, TransportError, read_quic_json_frame,
    write_quic_json_message,
};
use tokio::sync::Mutex;

const MESH_QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MESH_QUIC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MESH_QUIC_CACHED_CONNECTION_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

pub struct MeshQuicServer {
    endpoint: quinn::Endpoint,
}

pub struct MeshQuicConnection {
    connection: quinn::Connection,
}

pub struct MeshQuicAcceptedRequest {
    pub request: GatewayQuicRequest,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MeshQuicPoolKey {
    endpoint: String,
    server_name: String,
    peer_addr: SocketAddr,
    peer_ca_pems: Vec<String>,
}

struct MeshQuicClientJob {
    endpoint: String,
    server_name: String,
    tls: MeshTlsConfig,
    peer_ca_pems: Vec<String>,
    request: GatewayQuicRequest,
    enqueued_at: std::time::Instant,
    response: mpsc::Sender<Result<GatewayQuicResponse, TransportError>>,
}

struct MeshQuicClientRuntime {
    jobs: mpsc::Sender<MeshQuicClientJob>,
}

struct MeshQuicCachedConnection {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
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
        let endpoint = quinn::Endpoint::server(
            mesh_quic_server_config_with_dynamic_pem_roots(tls, root_pems_provider)?,
            addr.parse::<SocketAddr>()
                .map_err(|error| TransportError::Http(format!("bad QUIC bind addr: {error}")))?,
        )?;
        tracing::info!(
            addr,
            local_addr = %endpoint.local_addr()?,
            "mesh QUIC endpoint bound"
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
        Ok(MeshQuicConnection { connection })
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

fn run_mesh_quic_request(
    endpoint: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    request: GatewayQuicRequest,
) -> Result<GatewayQuicResponse, TransportError> {
    mesh_quic_client_runtime().request(endpoint, tls, server_name, peer_ca_pems, request)
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
                endpoint: endpoint.to_owned(),
                server_name: server_name.to_owned(),
                tls: tls.clone(),
                peer_ca_pems: peer_ca_pems.to_vec(),
                request,
                enqueued_at: std::time::Instant::now(),
                response,
            })
            .map_err(|error| TransportError::Quic(format!("mesh QUIC runtime stopped: {error}")))?;
        receiver
            .recv()
            .map_err(|error| TransportError::Quic(format!("mesh QUIC runtime stopped: {error}")))?
    }
}

fn mesh_quic_client_runtime() -> &'static MeshQuicClientRuntime {
    static RUNTIME: OnceLock<MeshQuicClientRuntime> = OnceLock::new();
    RUNTIME.get_or_init(spawn_mesh_quic_client_runtime)
}

fn spawn_mesh_quic_client_runtime() -> MeshQuicClientRuntime {
    let (jobs, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        if let Err(error) = run_mesh_quic_client_runtime(receiver) {
            tracing::error!(%error, "mesh QUIC client runtime stopped");
        }
    });
    MeshQuicClientRuntime { jobs }
}

fn run_mesh_quic_client_runtime(
    receiver: mpsc::Receiver<MeshQuicClientJob>,
) -> Result<(), TransportError> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let handle = runtime.handle().clone();
    let connections =
        Arc::new(Mutex::new(HashMap::<MeshQuicPoolKey, MeshQuicCachedConnection>::new()));
    for job in receiver {
        record_mesh_client_runtime_queue_wait(job.enqueued_at.elapsed());
        let connections = Arc::clone(&connections);
        let response_sender = job.response.clone();
        handle.spawn(async move {
            let response = mesh_quic_cached_request(connections, job).await;
            let _ = response_sender.send(response);
        });
    }
    Ok(())
}

async fn mesh_quic_cached_request(
    connections: Arc<Mutex<HashMap<MeshQuicPoolKey, MeshQuicCachedConnection>>>,
    job: MeshQuicClientJob,
) -> Result<GatewayQuicResponse, TransportError> {
    record_mesh_client_request();
    let peer_addr = resolve_endpoint(&job.endpoint)?;
    let key = MeshQuicPoolKey {
        endpoint: job.endpoint.clone(),
        server_name: job.server_name.clone(),
        peer_addr,
        peer_ca_pems: job.peer_ca_pems.clone(),
    };
    let cached_connection = {
        let connections = connections.lock().await;
        connections
            .get(&key)
            .filter(|cached| cached.connection.close_reason().is_none())
            .map(|cached| cached.connection.clone())
    };
    let (connection, reused_cached_connection) = if let Some(connection) = cached_connection {
        record_mesh_client_pool_hit();
        (connection, true)
    } else {
        record_mesh_client_pool_miss();
        let cached =
            mesh_quic_connect(peer_addr, &job.tls, &job.server_name, &job.peer_ca_pems).await?;
        let connection = cached.connection.clone();
        connections.lock().await.insert(key.clone(), cached);
        (connection, false)
    };
    let request_timeout = if reused_cached_connection {
        MESH_QUIC_CACHED_CONNECTION_PROBE_TIMEOUT
    } else {
        MESH_QUIC_REQUEST_TIMEOUT
    };
    match mesh_quic_request_on_connection(&connection, &job.request, request_timeout).await {
        Ok(response) => Ok(response),
        Err(error) if reused_cached_connection => {
            record_mesh_client_cached_request_failure();
            record_mesh_client_retry();
            tracing::warn!(
                %error,
                peer_addr = %connection.remote_address(),
                retry_peer_addr = %peer_addr,
                "mesh QUIC cached request failed; dropping cached connection and retrying once"
            );
            connections.lock().await.remove(&key);
            let cached =
                mesh_quic_connect(peer_addr, &job.tls, &job.server_name, &job.peer_ca_pems).await?;
            let connection = cached.connection.clone();
            connections.lock().await.insert(key.clone(), cached);
            match mesh_quic_request_on_connection(
                &connection,
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
                        peer_addr = %connection.remote_address(),
                        "mesh QUIC request failed after reconnect; dropping cached connection"
                    );
                    connections.lock().await.remove(&key);
                    Err(retry_error)
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                %error,
                peer_addr = %connection.remote_address(),
                "mesh QUIC request failed on fresh connection; dropping cached connection"
            );
            connections.lock().await.remove(&key);
            Err(error)
        }
    }
}

async fn mesh_quic_connect(
    peer_addr: SocketAddr,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
) -> Result<MeshQuicCachedConnection, TransportError> {
    let connect_started = std::time::Instant::now();
    let bind_addr = if peer_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let mut endpoint = quinn::Endpoint::client(
        bind_addr
            .parse()
            .map_err(|error| TransportError::Http(format!("bad QUIC bind addr: {error}")))?,
    )?;
    endpoint.set_default_client_config(mesh_quic_client_config_with_pem_roots(tls, peer_ca_pems)?);
    let connecting = endpoint
        .connect(peer_addr, server_name)
        .map_err(|error| TransportError::Quic(error.to_string()))?;
    tracing::info!(
        peer_addr = %peer_addr,
        server_name,
        timeout_ms = MESH_QUIC_CONNECT_TIMEOUT.as_millis(),
        "mesh QUIC client connecting"
    );
    let connection = tokio::time::timeout(MESH_QUIC_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|error| {
            tracing::error!(peer_addr = %peer_addr, server_name, %error, "mesh QUIC client connect timed out");
            TransportError::Quic(format!(
                "mesh QUIC connect to {peer_addr} timed out after {}ms: {error}",
                MESH_QUIC_CONNECT_TIMEOUT.as_millis()
            ))
        })?
        .map_err(|error| {
            tracing::error!(peer_addr = %peer_addr, server_name, %error, "mesh QUIC client handshake failed");
            TransportError::Quic(format!("mesh QUIC connect to {peer_addr} failed: {error}"))
        })?;
    record_mesh_client_connect(connect_started.elapsed());
    record_mesh_client_tls_handshake();
    tracing::info!(peer_addr = %peer_addr, server_name, "mesh QUIC client connected");
    Ok(MeshQuicCachedConnection { _endpoint: endpoint, connection })
}

async fn mesh_quic_request_on_connection(
    connection: &quinn::Connection,
    request: &GatewayQuicRequest,
    timeout: Duration,
) -> Result<GatewayQuicResponse, TransportError> {
    tokio::time::timeout(timeout, async {
        let (mut send, mut recv) =
            connection.open_bi().await.map_err(|error| TransportError::Quic(error.to_string()))?;
        write_quic_json_message(&mut send, request).await?;
        send.finish().map_err(|error| TransportError::Quic(error.to_string()))?;
        let response = read_quic_json_frame(&mut recv).await?;
        drain_quic_recv_to_fin(&mut recv).await?;
        Ok(response)
    })
    .await
    .map_err(|error| {
        record_mesh_client_request_timeout();
        TransportError::Quic(error.to_string())
    })?
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
        .map_err(|source| TransportError::Http(format!("bad endpoint {endpoint}: {source}")))?
        .next()
        .ok_or_else(|| TransportError::Http(format!("bad endpoint {endpoint}: no addresses")))
}
