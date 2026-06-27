// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use bytes::Bytes;
use http::Request;
use ramflux_protocol::{Ack, Cursor, Nack, ObjectChunkRequest};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::loopback::LoopbackBackend;
use crate::mesh_http::mesh_http_post_json;
use crate::{
    AckFrame, AuthRequest, BackendKind, CursorFrame, DeliveryFrame, EnvelopeBatch, MeshTlsConfig,
    NackFrame, ObjectChunkStream, QuicGatewayClient, SubmitEnvelopeRequest, SubmitEnvelopeResult,
    TransportBackend, TransportError, TransportFuture, TransportListener, TransportSession,
};

#[derive(Clone, Debug)]
pub struct GrpcH2Backend {
    inner: LoopbackBackend,
    network: Option<GrpcH2NetworkBackend>,
}

#[derive(Clone, Debug)]
pub struct QuicQuinnBackend {
    inner: LoopbackBackend,
    network: Option<QuicQuinnNetworkBackend>,
}

#[derive(Clone, Debug)]
pub struct HttpsJsonBackend {
    inner: LoopbackBackend,
    network: Option<HttpsJsonNetworkBackend>,
}

#[derive(Clone, Debug)]
struct NetworkBackendState {
    opened: bool,
    authed: bool,
    next_session: u64,
}

#[derive(Clone, Debug)]
struct GrpcH2NetworkBackend {
    endpoint: SocketAddr,
    path: String,
    state: Arc<Mutex<NetworkBackendState>>,
}

#[derive(Clone, Debug)]
struct QuicQuinnNetworkBackend {
    bind_addr: SocketAddr,
    peer_addr: SocketAddr,
    server_name: String,
    ca_cert: PathBuf,
    path: String,
    timeout: Duration,
    state: Arc<Mutex<NetworkBackendState>>,
}

#[derive(Clone, Debug)]
struct HttpsJsonNetworkBackend {
    endpoint: String,
    path: String,
    tls: MeshTlsConfig,
    server_name: String,
    state: Arc<Mutex<NetworkBackendState>>,
}

impl GrpcH2Backend {
    #[must_use]
    pub fn new() -> Self {
        Self { inner: LoopbackBackend::new(BackendKind::GrpcH2), network: None }
    }

    #[must_use]
    pub fn connect_h2(endpoint: SocketAddr, path: impl Into<String>) -> Self {
        Self {
            inner: LoopbackBackend::new(BackendKind::GrpcH2),
            network: Some(GrpcH2NetworkBackend {
                endpoint,
                path: path.into(),
                state: Arc::new(Mutex::new(NetworkBackendState {
                    opened: false,
                    authed: false,
                    next_session: 0,
                })),
            }),
        }
    }
}

impl Default for GrpcH2Backend {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicQuinnBackend {
    #[must_use]
    pub fn new() -> Self {
        Self { inner: LoopbackBackend::new(BackendKind::QuicQuinn), network: None }
    }

    #[must_use]
    pub fn connect_quic(
        bind_addr: SocketAddr,
        peer_addr: SocketAddr,
        server_name: impl Into<String>,
        ca_cert: impl Into<PathBuf>,
        path: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            inner: LoopbackBackend::new(BackendKind::QuicQuinn),
            network: Some(QuicQuinnNetworkBackend {
                bind_addr,
                peer_addr,
                server_name: server_name.into(),
                ca_cert: ca_cert.into(),
                path: path.into(),
                timeout,
                state: Arc::new(Mutex::new(NetworkBackendState {
                    opened: false,
                    authed: false,
                    next_session: 0,
                })),
            }),
        }
    }
}

impl Default for QuicQuinnBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpsJsonBackend {
    #[must_use]
    pub fn new() -> Self {
        Self { inner: LoopbackBackend::new(BackendKind::HttpsJson), network: None }
    }

    #[must_use]
    pub fn connect_https_json(
        endpoint: impl Into<String>,
        path: impl Into<String>,
        tls: MeshTlsConfig,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            inner: LoopbackBackend::new(BackendKind::HttpsJson),
            network: Some(HttpsJsonNetworkBackend {
                endpoint: endpoint.into(),
                path: path.into(),
                tls,
                server_name: server_name.into(),
                state: Arc::new(Mutex::new(NetworkBackendState {
                    opened: false,
                    authed: false,
                    next_session: 0,
                })),
            }),
        }
    }
}

impl Default for HttpsJsonBackend {
    fn default() -> Self {
        Self::new()
    }
}
impl TransportBackend for GrpcH2Backend {
    fn kind(&self) -> BackendKind {
        self.inner.kind()
    }

    fn open(&self) -> TransportFuture<'_, TransportSession> {
        if let Some(network) = &self.network {
            network_open(BackendKind::GrpcH2, Arc::clone(&network.state))
        } else {
            self.inner.open()
        }
    }

    fn auth(
        &self,
        session: TransportSession,
        request: AuthRequest,
    ) -> TransportFuture<'_, TransportSession> {
        if let Some(network) = &self.network {
            network_auth(BackendKind::GrpcH2, Arc::clone(&network.state), session, request)
        } else {
            self.inner.auth(session, request)
        }
    }

    fn submit_envelope(
        &self,
        request: SubmitEnvelopeRequest,
    ) -> TransportFuture<'_, SubmitEnvelopeResult> {
        if let Some(network) = &self.network {
            let network = network.clone();
            Box::pin(async move {
                network_ensure_authed(&network.state)?;
                h2_submit_envelope(network.endpoint, &network.path, &request).await
            })
        } else {
            self.inner.submit_envelope(request)
        }
    }

    fn pull_envelopes(&self, cursor: Cursor) -> TransportFuture<'_, EnvelopeBatch> {
        if self.network.is_some() {
            unsupported_operation("grpc_h2.pull_envelopes")
        } else {
            self.inner.pull_envelopes(cursor)
        }
    }

    fn deliver(&self) -> TransportFuture<'_, DeliveryFrame> {
        self.inner.deliver()
    }

    fn ack(&self, ack: Ack) -> TransportFuture<'_, AckFrame> {
        self.inner.ack(ack)
    }

    fn nack(&self, nack: Nack) -> TransportFuture<'_, NackFrame> {
        self.inner.nack(nack)
    }

    fn cursor(&self, cursor: Cursor) -> TransportFuture<'_, CursorFrame> {
        self.inner.cursor(cursor)
    }

    fn request_object_chunks(
        &self,
        request: ObjectChunkRequest,
    ) -> TransportFuture<'_, ObjectChunkStream> {
        if self.network.is_some() {
            unsupported_operation("grpc_h2.request_object_chunks")
        } else {
            self.inner.request_object_chunks(request)
        }
    }
}

impl TransportBackend for QuicQuinnBackend {
    fn kind(&self) -> BackendKind {
        self.inner.kind()
    }

    fn open(&self) -> TransportFuture<'_, TransportSession> {
        if let Some(network) = &self.network {
            network_open(BackendKind::QuicQuinn, Arc::clone(&network.state))
        } else {
            self.inner.open()
        }
    }

    fn auth(
        &self,
        session: TransportSession,
        request: AuthRequest,
    ) -> TransportFuture<'_, TransportSession> {
        if let Some(network) = &self.network {
            network_auth(BackendKind::QuicQuinn, Arc::clone(&network.state), session, request)
        } else {
            self.inner.auth(session, request)
        }
    }

    fn submit_envelope(
        &self,
        request: SubmitEnvelopeRequest,
    ) -> TransportFuture<'_, SubmitEnvelopeResult> {
        if let Some(network) = &self.network {
            let network = network.clone();
            Box::pin(async move {
                network_ensure_authed(&network.state)?;
                let client = QuicGatewayClient::connect(
                    network.bind_addr,
                    network.peer_addr,
                    &network.server_name,
                    &network.ca_cert,
                    network.timeout,
                )
                .await?;
                client.post_json(&network.path, &request).await
            })
        } else {
            self.inner.submit_envelope(request)
        }
    }

    fn pull_envelopes(&self, cursor: Cursor) -> TransportFuture<'_, EnvelopeBatch> {
        if self.network.is_some() {
            unsupported_operation("quic_quinn.pull_envelopes")
        } else {
            self.inner.pull_envelopes(cursor)
        }
    }

    fn deliver(&self) -> TransportFuture<'_, DeliveryFrame> {
        self.inner.deliver()
    }

    fn ack(&self, ack: Ack) -> TransportFuture<'_, AckFrame> {
        self.inner.ack(ack)
    }

    fn nack(&self, nack: Nack) -> TransportFuture<'_, NackFrame> {
        self.inner.nack(nack)
    }

    fn cursor(&self, cursor: Cursor) -> TransportFuture<'_, CursorFrame> {
        self.inner.cursor(cursor)
    }

    fn request_object_chunks(
        &self,
        request: ObjectChunkRequest,
    ) -> TransportFuture<'_, ObjectChunkStream> {
        if self.network.is_some() {
            unsupported_operation("quic_quinn.request_object_chunks")
        } else {
            self.inner.request_object_chunks(request)
        }
    }
}

impl TransportBackend for HttpsJsonBackend {
    fn kind(&self) -> BackendKind {
        self.inner.kind()
    }

    fn open(&self) -> TransportFuture<'_, TransportSession> {
        if let Some(network) = &self.network {
            network_open(BackendKind::HttpsJson, Arc::clone(&network.state))
        } else {
            self.inner.open()
        }
    }

    fn auth(
        &self,
        session: TransportSession,
        request: AuthRequest,
    ) -> TransportFuture<'_, TransportSession> {
        if let Some(network) = &self.network {
            network_auth(BackendKind::HttpsJson, Arc::clone(&network.state), session, request)
        } else {
            self.inner.auth(session, request)
        }
    }

    fn submit_envelope(
        &self,
        request: SubmitEnvelopeRequest,
    ) -> TransportFuture<'_, SubmitEnvelopeResult> {
        if let Some(network) = &self.network {
            let network = network.clone();
            Box::pin(async move {
                network_ensure_authed(&network.state)?;
                mesh_http_post_json(
                    &network.endpoint,
                    &network.path,
                    &network.tls,
                    &network.server_name,
                    &request,
                )
            })
        } else {
            self.inner.submit_envelope(request)
        }
    }

    fn pull_envelopes(&self, cursor: Cursor) -> TransportFuture<'_, EnvelopeBatch> {
        if self.network.is_some() {
            unsupported_operation("https_json.pull_envelopes")
        } else {
            self.inner.pull_envelopes(cursor)
        }
    }

    fn deliver(&self) -> TransportFuture<'_, DeliveryFrame> {
        self.inner.deliver()
    }

    fn ack(&self, ack: Ack) -> TransportFuture<'_, AckFrame> {
        self.inner.ack(ack)
    }

    fn nack(&self, nack: Nack) -> TransportFuture<'_, NackFrame> {
        self.inner.nack(nack)
    }

    fn cursor(&self, cursor: Cursor) -> TransportFuture<'_, CursorFrame> {
        self.inner.cursor(cursor)
    }

    fn request_object_chunks(
        &self,
        request: ObjectChunkRequest,
    ) -> TransportFuture<'_, ObjectChunkStream> {
        if self.network.is_some() {
            unsupported_operation("https_json.request_object_chunks")
        } else {
            self.inner.request_object_chunks(request)
        }
    }
}

impl TransportListener for GrpcH2Backend {
    fn accept(&self) -> TransportFuture<'_, TransportSession> {
        self.inner.accept()
    }
}

impl TransportListener for QuicQuinnBackend {
    fn accept(&self) -> TransportFuture<'_, TransportSession> {
        self.inner.accept()
    }
}

impl TransportListener for HttpsJsonBackend {
    fn accept(&self) -> TransportFuture<'_, TransportSession> {
        self.inner.accept()
    }
}

fn network_open(
    backend: BackendKind,
    state: Arc<Mutex<NetworkBackendState>>,
) -> TransportFuture<'static, TransportSession> {
    Box::pin(async move {
        let mut state = state.lock().map_err(|_err| TransportError::LockPoisoned)?;
        state.opened = true;
        state.next_session = state.next_session.saturating_add(1);
        Ok(TransportSession {
            backend,
            session_id: format!("{}-network-session-{}", backend.as_str(), state.next_session),
        })
    })
}

fn network_auth(
    backend: BackendKind,
    state: Arc<Mutex<NetworkBackendState>>,
    session: TransportSession,
    _request: AuthRequest,
) -> TransportFuture<'static, TransportSession> {
    Box::pin(async move {
        if session.backend != backend {
            return Err(TransportError::BackendMismatch {
                expected: backend.as_str(),
                actual: session.backend.as_str(),
            });
        }
        let mut state = state.lock().map_err(|_err| TransportError::LockPoisoned)?;
        if !state.opened {
            return Err(TransportError::NotOpen);
        }
        state.authed = true;
        Ok(session)
    })
}

fn network_ensure_authed(state: &Arc<Mutex<NetworkBackendState>>) -> Result<(), TransportError> {
    let state = state.lock().map_err(|_err| TransportError::LockPoisoned)?;
    if !state.opened {
        return Err(TransportError::NotOpen);
    }
    if !state.authed {
        return Err(TransportError::NotAuthenticated);
    }
    Ok(())
}

fn unsupported_operation<T>(operation: &'static str) -> TransportFuture<'static, T> {
    Box::pin(async move { Err(TransportError::UnsupportedOperation { operation }) })
}

async fn h2_submit_envelope(
    endpoint: SocketAddr,
    path: &str,
    request: &SubmitEnvelopeRequest,
) -> Result<SubmitEnvelopeResult, TransportError> {
    let stream = tokio::net::TcpStream::connect(endpoint).await?;
    let (mut client, connection) = h2::client::handshake(stream)
        .await
        .map_err(|error| TransportError::Http(error.to_string()))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "grpc_h2 transport client connection ended");
        }
    });
    let body = serde_json::to_vec(request)?;
    let http_request = Request::post(path)
        .header("content-type", "application/json")
        .body(())
        .map_err(|error| TransportError::Http(error.to_string()))?;
    let (response, mut send_stream) = client
        .send_request(http_request, false)
        .map_err(|error| TransportError::Http(error.to_string()))?;
    send_stream
        .send_data(Bytes::from(body), true)
        .map_err(|error| TransportError::Http(error.to_string()))?;
    let response = response.await.map_err(|error| TransportError::Http(error.to_string()))?;
    if !response.status().is_success() {
        return Err(TransportError::Http(format!("HTTP/2 {}", response.status())));
    }
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        bytes.extend_from_slice(&chunk.map_err(|error| TransportError::Http(error.to_string()))?);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
