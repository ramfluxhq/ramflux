// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::net::{SocketAddr, ToSocketAddrs};

use compio_buf::bytes::Bytes;
use serde::{Serialize, de::DeserializeOwned};

use crate::mesh_tls::extract_spiffe_uri_from_certificate;
use crate::tls_config::{
    MeshRootPemProvider, compio_mesh_quic_client_config_with_pem_roots,
    compio_mesh_quic_server_config_with_dynamic_pem_roots,
};
use crate::{GatewayQuicRequest, GatewayQuicResponse, MeshTlsConfig, TransportError};

const COMP_IO_MESH_FRAME_MAX_BYTES: usize = 1024 * 1024;

pub struct CompioMeshQuicServer {
    endpoint: compio_quic::Endpoint,
}

pub struct CompioMeshQuicConnection {
    connection: compio_quic::Connection,
    peer_spiffe_uri: Option<String>,
}

pub struct CompioMeshQuicAcceptedRequest {
    pub request: GatewayQuicRequest,
    peer_spiffe_uri: Option<String>,
    send: compio_quic::SendStream,
    recv: compio_quic::RecvStream,
}

impl CompioMeshQuicServer {
    /// # Errors
    /// Returns an error when the UDP socket cannot bind or TLS material cannot be loaded.
    pub async fn bind_with_pem_roots_provider(
        addr: &str,
        tls: &MeshTlsConfig,
        root_pems_provider: MeshRootPemProvider,
    ) -> Result<Self, TransportError> {
        let endpoint = compio_quic::Endpoint::server(
            addr,
            compio_mesh_quic_server_config_with_dynamic_pem_roots(tls, root_pems_provider)?,
        )
        .await
        .map_err(TransportError::Io)?;
        Ok(Self { endpoint })
    }

    /// # Errors
    /// Returns an error when the local UDP address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// # Errors
    /// Returns an error if the endpoint cannot gracefully shut down.
    pub async fn shutdown(self) -> Result<(), TransportError> {
        self.endpoint.shutdown().await.map_err(TransportError::Io)
    }

    /// # Errors
    /// Returns an error when QUIC accept or handshake fails.
    pub async fn accept_connection(&self) -> Result<CompioMeshQuicConnection, TransportError> {
        let incoming =
            self.endpoint.wait_incoming().await.ok_or_else(|| {
                TransportError::Quic("compio mesh QUIC endpoint closed".to_owned())
            })?;
        let connection = incoming.await.map_err(|error| TransportError::Quic(error.to_string()))?;
        let peer_spiffe_uri = compio_peer_spiffe_uri(&connection)?;
        Ok(CompioMeshQuicConnection { connection, peer_spiffe_uri })
    }

    /// # Errors
    /// Returns an error when QUIC accept, stream accept, or request decoding fails.
    pub async fn accept_request(&self) -> Result<CompioMeshQuicAcceptedRequest, TransportError> {
        let connection = self.accept_connection().await?;
        Self::accept_request_on_connection(&connection).await
    }

    /// # Errors
    /// Returns an error when stream accept or request decoding fails.
    pub async fn accept_request_on_connection(
        connection: &CompioMeshQuicConnection,
    ) -> Result<CompioMeshQuicAcceptedRequest, TransportError> {
        let (send, mut recv) = connection
            .connection
            .accept_bi()
            .await
            .map_err(|error| TransportError::Quic(error.to_string()))?;
        tracing::trace!("compio mesh accepted bidirectional stream; reading request frame");
        let request: GatewayQuicRequest = compio_read_json_frame(&mut recv).await?;
        tracing::trace!(
            method = %request.method,
            path = %request.path,
            "compio mesh request frame decoded"
        );
        Ok(CompioMeshQuicAcceptedRequest {
            request,
            peer_spiffe_uri: connection.peer_spiffe_uri.clone(),
            send,
            recv,
        })
    }
}

impl CompioMeshQuicConnection {
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    #[must_use]
    pub fn peer_spiffe_uri(&self) -> Option<&str> {
        self.peer_spiffe_uri.as_deref()
    }
}

impl CompioMeshQuicAcceptedRequest {
    #[must_use]
    pub fn peer_spiffe_uri(&self) -> Option<&str> {
        self.peer_spiffe_uri.as_deref()
    }

    /// # Errors
    /// Returns an error when response serialization or stream writes fail.
    pub async fn write_json_response<T: Serialize>(
        mut self,
        status: u16,
        value: &T,
    ) -> Result<(), TransportError> {
        let body = serde_json::to_value(value)?;
        let response = GatewayQuicResponse { status, body };
        self.write_response_and_drain_request(&response).await
    }

    /// # Errors
    /// Returns an error when response serialization or stream writes fail.
    pub async fn write_text_response(
        mut self,
        status: u16,
        body: &str,
    ) -> Result<(), TransportError> {
        let response = GatewayQuicResponse { status, body: serde_json::json!({ "error": body }) };
        self.write_response_and_drain_request(&response).await
    }

    async fn write_response_and_drain_request<T: Serialize>(
        &mut self,
        response: &T,
    ) -> Result<(), TransportError> {
        compio_write_json_message(&mut self.send, response).await?;
        compio_finish_send_stream(&mut self.send)?;
        compio_drain_recv_to_fin(&mut self.recv).await
    }
}

/// # Errors
/// Returns an error when the JSON request cannot be encoded, QUIC/TLS fails, or
/// the response cannot be decoded.
pub async fn compio_mesh_quic_post_json_with_peer_ca_pems<T, R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    value: &T,
) -> Result<R, TransportError>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let body = serde_json::to_value(value)?;
    let response = compio_mesh_quic_request(
        endpoint,
        tls,
        server_name,
        peer_ca_pems,
        &GatewayQuicRequest { method: "POST".to_owned(), path: path.to_owned(), body },
    )
    .await?;
    if (200..300).contains(&response.status) {
        Ok(serde_json::from_value(response.body)?)
    } else {
        Err(TransportError::Http(format!("HTTP {}: {}", response.status, response.body)))
    }
}

async fn compio_mesh_quic_request(
    endpoint: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    request: &GatewayQuicRequest,
) -> Result<GatewayQuicResponse, TransportError> {
    let peer_addr = resolve_endpoint(endpoint)?;
    let endpoint = compio_quic::Endpoint::client("0.0.0.0:0").await.map_err(TransportError::Io)?;
    let client_config = compio_mesh_quic_client_config_with_pem_roots(tls, peer_ca_pems)?;
    tracing::trace!(%peer_addr, server_name, "compio mesh client connecting");
    let connection = endpoint
        .connect(peer_addr, server_name, Some(client_config))
        .map_err(|error| TransportError::Quic(error.to_string()))?
        .await
        .map_err(|error| TransportError::Quic(error.to_string()))?;
    tracing::trace!(%peer_addr, "compio mesh client connected");
    let (mut send, mut recv) =
        connection.open_bi().map_err(|error| TransportError::Quic(error.to_string()))?;
    tracing::trace!(%peer_addr, "compio mesh client opened bidirectional stream");
    compio_write_json_message(&mut send, request).await?;
    compio_finish_send_stream(&mut send)?;
    tracing::trace!(%peer_addr, "compio mesh client reading response");
    let response: GatewayQuicResponse = compio_read_json_frame(&mut recv).await?;
    compio_drain_recv_to_fin(&mut recv).await?;
    tracing::trace!(%peer_addr, status = response.status, "compio mesh client response decoded");
    drop(send);
    drop(recv);
    drop(connection);
    endpoint.shutdown().await.map_err(TransportError::Io)?;
    Ok(response)
}

async fn compio_write_json_message<T: Serialize>(
    send: &mut compio_quic::SendStream,
    value: &T,
) -> Result<(), TransportError> {
    let body = serde_json::to_vec(value)?;
    let len = u32::try_from(body.len())
        .map_err(|_error| TransportError::FrameTooLarge { len: body.len() })?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    let mut chunks = [Bytes::from(frame)];
    send.write_all_chunks(&mut chunks)
        .await
        .map_err(|error| TransportError::Quic(error.to_string()))?;
    tracing::trace!(len, "compio mesh JSON frame written");
    Ok(())
}

async fn compio_read_json_frame<T: DeserializeOwned>(
    recv: &mut compio_quic::RecvStream,
) -> Result<T, TransportError> {
    tracing::trace!("compio mesh reading JSON frame length");
    let mut len_bytes = [0_u8; 4];
    compio_read_exact(recv, &mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > COMP_IO_MESH_FRAME_MAX_BYTES {
        return Err(TransportError::FrameTooLarge { len });
    }
    tracing::trace!(len, "compio mesh reading JSON frame body");
    let mut body = vec![0_u8; len];
    compio_read_exact(recv, &mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn compio_read_exact(
    recv: &mut compio_quic::RecvStream,
    out: &mut [u8],
) -> Result<(), TransportError> {
    let mut filled = 0;
    while filled < out.len() {
        let max_len = out.len() - filled;
        match recv.read_chunk(max_len, true).await {
            Ok(Some(chunk)) => {
                let bytes = chunk.bytes;
                let len = bytes.len();
                out[filled..filled + len].copy_from_slice(&bytes);
                filled += len;
            }
            Ok(None) => {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("compio QUIC frame ended after {filled} of {} bytes", out.len()),
                )));
            }
            Err(error) => return Err(TransportError::Quic(error.to_string())),
        }
    }
    Ok(())
}

async fn compio_drain_recv_to_fin(
    recv: &mut compio_quic::RecvStream,
) -> Result<(), TransportError> {
    let mut drained = 0usize;
    while let Some(chunk) = recv
        .read_chunk(COMP_IO_MESH_FRAME_MAX_BYTES.saturating_sub(drained).saturating_add(1), true)
        .await
        .map_err(|error| TransportError::Quic(error.to_string()))?
    {
        let len = chunk.bytes.len();
        drained = drained.saturating_add(len);
        if drained > COMP_IO_MESH_FRAME_MAX_BYTES {
            return Err(TransportError::FrameTooLarge { len: drained });
        }
        tracing::trace!(len, drained, "compio mesh drained trailing request bytes");
    }
    Ok(())
}

fn compio_finish_send_stream(send: &mut compio_quic::SendStream) -> Result<(), TransportError> {
    tracing::trace!("compio mesh finishing send stream");
    send.finish().map_err(|error| TransportError::Quic(error.to_string()))?;
    tracing::trace!("compio mesh send stream finished");
    Ok(())
}

fn compio_peer_spiffe_uri(
    connection: &compio_quic::Connection,
) -> Result<Option<String>, TransportError> {
    match connection.peer_identity() {
        Some(certs) => match certs.first() {
            Some(cert) => extract_spiffe_uri_from_certificate(cert),
            None => Ok(None),
        },
        None => Ok(None),
    }
}

fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr, TransportError> {
    endpoint
        .to_socket_addrs()
        .map_err(|source| TransportError::Http(format!("bad endpoint {endpoint}: {source}")))?
        .next()
        .ok_or_else(|| TransportError::Http(format!("bad endpoint {endpoint}: no addresses")))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType,
    };
    use serde_json::json;
    use tracing_subscriber::EnvFilter;

    use crate::{MeshQuicServer, MeshTlsConfig, mesh_quic_post_json_with_peer_ca_pems};

    use super::{CompioMeshQuicServer, compio_mesh_quic_post_json_with_peer_ca_pems};

    static NEXT_TEMP_CERT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn compio_server_accepts_tokio_quinn_client_mesh_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        init_test_tracing();
        diag("dir1 test start: compio server <- tokio quinn client");
        let root = temp_cert_root("compio_server_accepts_tokio_quinn_client_mesh_frame")?;
        let node_a = issue_test_ca_and_service_cert(&root, "node-a")?;
        let node_b = issue_test_ca_and_service_cert(&root, "node-b")?;
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let (spiffe_tx, spiffe_rx) = mpsc::channel::<Option<String>>();
        let server_tls = node_b.tls.clone();
        let trusted_client_ca = node_a.ca_pem.clone();
        let server_thread = thread::spawn(move || -> Result<(), String> {
            diag("dir1 server: creating compio runtime");
            let runtime = compio::runtime::Runtime::new().map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                let roots = Arc::new(move || Ok(vec![trusted_client_ca.clone()]));
                diag("dir1 server: binding compio endpoint");
                let server = CompioMeshQuicServer::bind_with_pem_roots_provider(
                    "127.0.0.1:0",
                    &server_tls,
                    roots,
                )
                .await
                .map_err(|error| error.to_string())?;
                diag("dir1 server: bound compio endpoint");
                endpoint_tx
                    .send(
                        server
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .map_err(|error| error.to_string()),
                    )
                    .map_err(|error| error.to_string())?;
                diag("dir1 server: accept_request before");
                let accepted = server.accept_request().await.map_err(|error| error.to_string())?;
                diag("dir1 server: accept_request after");
                if accepted.request.method != "POST"
                    || accepted.request.path != "/s8/federation/envelope"
                {
                    return Err(format!(
                        "unexpected request {} {}",
                        accepted.request.method, accepted.request.path
                    ));
                }
                spiffe_tx
                    .send(accepted.peer_spiffe_uri().map(str::to_owned))
                    .map_err(|error| error.to_string())?;
                diag("dir1 server: write_json_response before");
                accepted
                    .write_json_response(200, &json!({"accepted": true}))
                    .await
                    .map_err(|error| error.to_string())?;
                diag("dir1 server: endpoint shutdown before");
                server.shutdown().await.map_err(|error| error.to_string())?;
                diag("dir1 server: endpoint shutdown after");
                Ok(())
            })
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|error| test_error(error.to_string()))?
            .map_err(test_error)?;
        diag("dir1 client: tokio quinn post before");
        let response: serde_json::Value = mesh_quic_post_json_with_peer_ca_pems(
            &endpoint,
            "/s8/federation/envelope",
            &node_a.tls,
            "ramflux-federation",
            std::slice::from_ref(&node_b.ca_pem),
            &json!({"source_node_id":"node-a","target_node_id":"node-b"}),
        )?;
        diag("dir1 client: tokio quinn post after");
        assert_eq!(response["accepted"], true);
        let spiffe = spiffe_rx.recv().map_err(|error| error.to_string())?;
        assert_eq!(spiffe.as_deref(), Some("spiffe://node-a/ramflux-federation"));
        diag("dir1 test: joining server thread");
        server_thread
            .join()
            .map_err(|_| test_error("server thread panicked"))?
            .map_err(test_error)?;
        diag("dir1 test done");
        Ok(())
    }

    #[test]
    #[ignore = "reverse compio-client to tokio-quinn-server interop is covered by B4b realnet with a persistent server; this in-process harness tears down the tokio server runtime immediately after response write"]
    fn tokio_quinn_server_accepts_compio_client_mesh_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        init_test_tracing();
        diag("dir2 test start: tokio quinn server <- compio client");
        let root = temp_cert_root("tokio_quinn_server_accepts_compio_client_mesh_frame")?;
        let node_a = issue_test_ca_and_service_cert(&root, "node-a")?;
        let node_b = issue_test_ca_and_service_cert(&root, "node-b")?;
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let server_tls = node_b.tls.clone();
        let trusted_client_ca = node_a.ca_pem.clone();
        let server_thread = thread::spawn(move || -> Result<(), String> {
            diag("dir2 server: creating tokio runtime");
            let roots = Arc::new(move || Ok(vec![trusted_client_ca.clone()]));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                diag("dir2 server: binding tokio quinn endpoint");
                let server =
                    MeshQuicServer::bind_with_pem_roots_provider("127.0.0.1:0", &server_tls, roots)
                        .map_err(|error| error.to_string())?;
                diag("dir2 server: bound tokio quinn endpoint");
                endpoint_tx
                    .send(
                        server
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .map_err(|error| error.to_string()),
                    )
                    .map_err(|error| error.to_string())?;
                diag("dir2 server: accept_request before");
                let accepted = server.accept_request().await.map_err(|error| error.to_string())?;
                diag("dir2 server: accept_request after");
                if accepted.request.method != "POST"
                    || accepted.request.path != "/s8/federation/envelope"
                {
                    return Err(format!(
                        "unexpected request {} {}",
                        accepted.request.method, accepted.request.path
                    ));
                }
                diag("dir2 server: write_json_response before");
                accepted
                    .write_json_response(200, &json!({"accepted": true}))
                    .await
                    .map_err(|error| error.to_string())?;
                diag("dir2 server: wait_idle before");
                server.wait_idle().await;
                diag("dir2 server: wait_idle after");
                Ok(())
            })
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|error| test_error(error.to_string()))?
            .map_err(test_error)?;
        diag("dir2 client: creating compio runtime");
        let runtime = compio::runtime::Runtime::new()?;
        diag("dir2 client: compio post before");
        let response: serde_json::Value = runtime.block_on(async {
            compio_mesh_quic_post_json_with_peer_ca_pems(
                &endpoint,
                "/s8/federation/envelope",
                &node_a.tls,
                "ramflux-federation",
                std::slice::from_ref(&node_b.ca_pem),
                &json!({"source_node_id":"node-a","target_node_id":"node-b"}),
            )
            .await
        })?;
        diag("dir2 client: compio post after");
        assert_eq!(response["accepted"], true);
        diag("dir2 test: joining server thread");
        server_thread
            .join()
            .map_err(|_| test_error("server thread panicked"))?
            .map_err(test_error)?;
        diag("dir2 test done");
        Ok(())
    }

    #[test]
    fn compio_server_accepts_compio_client_mesh_frame() -> Result<(), Box<dyn std::error::Error>> {
        init_test_tracing();
        diag("dir3 test start: compio server <- compio client");
        let root = temp_cert_root("compio_server_accepts_compio_client_mesh_frame")?;
        let node_a = issue_test_ca_and_service_cert(&root, "node-a")?;
        let node_b = issue_test_ca_and_service_cert(&root, "node-b")?;
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let (spiffe_tx, spiffe_rx) = mpsc::channel::<Option<String>>();
        let server_tls = node_b.tls.clone();
        let trusted_client_ca = node_a.ca_pem.clone();
        let server_thread = thread::spawn(move || -> Result<(), String> {
            diag("dir3 server: creating compio runtime");
            let runtime = compio::runtime::Runtime::new().map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                let roots = Arc::new(move || Ok(vec![trusted_client_ca.clone()]));
                diag("dir3 server: binding compio endpoint");
                let server = CompioMeshQuicServer::bind_with_pem_roots_provider(
                    "127.0.0.1:0",
                    &server_tls,
                    roots,
                )
                .await
                .map_err(|error| error.to_string())?;
                diag("dir3 server: bound compio endpoint");
                endpoint_tx
                    .send(
                        server
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .map_err(|error| error.to_string()),
                    )
                    .map_err(|error| error.to_string())?;
                diag("dir3 server: accept_request before");
                let accepted = server.accept_request().await.map_err(|error| error.to_string())?;
                diag("dir3 server: accept_request after");
                if accepted.request.method != "POST"
                    || accepted.request.path != "/s8/federation/envelope"
                {
                    return Err(format!(
                        "unexpected request {} {}",
                        accepted.request.method, accepted.request.path
                    ));
                }
                spiffe_tx
                    .send(accepted.peer_spiffe_uri().map(str::to_owned))
                    .map_err(|error| error.to_string())?;
                diag("dir3 server: write_json_response before");
                accepted
                    .write_json_response(200, &json!({"accepted": true}))
                    .await
                    .map_err(|error| error.to_string())?;
                diag("dir3 server: endpoint shutdown before");
                server.shutdown().await.map_err(|error| error.to_string())?;
                diag("dir3 server: endpoint shutdown after");
                Ok(())
            })
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|error| test_error(error.to_string()))?
            .map_err(test_error)?;
        diag("dir3 client: creating compio runtime");
        let runtime = compio::runtime::Runtime::new()?;
        diag("dir3 client: compio post before");
        let response: serde_json::Value = runtime.block_on(async {
            compio_mesh_quic_post_json_with_peer_ca_pems(
                &endpoint,
                "/s8/federation/envelope",
                &node_a.tls,
                "ramflux-federation",
                std::slice::from_ref(&node_b.ca_pem),
                &json!({"source_node_id":"node-a","target_node_id":"node-b"}),
            )
            .await
        })?;
        diag("dir3 client: compio post after");
        assert_eq!(response["accepted"], true);
        let spiffe = spiffe_rx.recv().map_err(|error| error.to_string())?;
        assert_eq!(spiffe.as_deref(), Some("spiffe://node-a/ramflux-federation"));
        diag("dir3 test: joining server thread");
        server_thread
            .join()
            .map_err(|_| test_error("server thread panicked"))?
            .map_err(test_error)?;
        diag("dir3 test done");
        Ok(())
    }

    #[test]
    fn compio_server_rejects_unpinned_client_ca() -> Result<(), Box<dyn std::error::Error>> {
        init_test_tracing();
        diag("bad-ca test start");
        let root = temp_cert_root("compio_server_rejects_unpinned_client_ca")?;
        let trusted_client = issue_test_ca_and_service_cert(&root, "node-a")?;
        let server_peer = issue_test_ca_and_service_cert(&root, "node-b")?;
        let wrong_client = issue_test_ca_and_service_cert(&root, "node-c")?;
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let server_tls = server_peer.tls.clone();
        let trusted_client_ca = trusted_client.ca_pem;
        let server_thread = thread::spawn(move || -> Result<bool, String> {
            diag("bad-ca server: creating compio runtime");
            let runtime = compio::runtime::Runtime::new().map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                let roots = Arc::new(move || Ok(vec![trusted_client_ca.clone()]));
                diag("bad-ca server: binding compio endpoint");
                let server = CompioMeshQuicServer::bind_with_pem_roots_provider(
                    "127.0.0.1:0",
                    &server_tls,
                    roots,
                )
                .await
                .map_err(|error| error.to_string())?;
                diag("bad-ca server: bound compio endpoint");
                endpoint_tx
                    .send(
                        server
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .map_err(|error| error.to_string()),
                    )
                    .map_err(|error| error.to_string())?;
                diag("bad-ca server: accept_connection before");
                Ok(server.accept_connection().await.is_err())
            })
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|error| test_error(error.to_string()))?
            .map_err(test_error)?;
        let rejected = mesh_quic_post_json_with_peer_ca_pems::<_, serde_json::Value>(
            &endpoint,
            "/s8/federation/envelope",
            &wrong_client.tls,
            "ramflux-federation",
            &[server_peer.ca_pem],
            &json!({"source_node_id":"node-c","target_node_id":"node-b"}),
        );
        diag("bad-ca client: tokio quinn post returned");
        assert!(rejected.is_err());
        let server_rejected = server_thread
            .join()
            .map_err(|_| test_error("server thread panicked"))?
            .map_err(test_error)?;
        assert!(server_rejected);
        diag("bad-ca test done");
        Ok(())
    }

    struct TestPeerCerts {
        tls: MeshTlsConfig,
        ca_pem: String,
    }

    fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "ramflux_transport_{name}_{}_{}",
            std::process::id(),
            NEXT_TEMP_CERT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn issue_test_ca_and_service_cert(
        root: &Path,
        node_id: &str,
    ) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
        let dir = root.join(node_id);
        std::fs::create_dir_all(&dir)?;
        let ca_cert = dir.join("ca.pem");
        let service_key = dir.join("federation-key.pem");
        let service_cert = dir.join("federation.pem");
        let mut ca_params = CertificateParams::new(Vec::new())?;
        ca_params.distinguished_name.push(DnType::CommonName, "Ramflux Test Federation CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
        let ca_key_pair = KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key_pair)?;
        let issuer = Issuer::new(ca_params, ca_key_pair);

        let mut service_params =
            CertificateParams::new(vec!["ramflux-federation".into(), "localhost".into()])?;
        service_params
            .subject_alt_names
            .push(SanType::URI(format!("spiffe://{node_id}/ramflux-federation").try_into()?));
        service_params.distinguished_name.push(DnType::CommonName, "ramflux-federation");
        service_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        service_params.extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
        service_params.extended_key_usages.push(ExtendedKeyUsagePurpose::ClientAuth);
        service_params.use_authority_key_identifier_extension = true;
        let service_key_pair = KeyPair::generate()?;
        let service = service_params.signed_by(&service_key_pair, &issuer)?;

        std::fs::write(&ca_cert, ca.pem())?;
        std::fs::write(&service_key, service_key_pair.serialize_pem())?;
        std::fs::write(&service_cert, service.pem())?;
        Ok(TestPeerCerts {
            tls: MeshTlsConfig { ca_cert: ca_cert.clone(), service_cert, service_key },
            ca_pem: std::fs::read_to_string(ca_cert)?,
        })
    }

    fn init_test_tracing() {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_error| EnvFilter::new("ramflux_transport=trace,compio=trace"));
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_test_writer().try_init();
    }

    fn diag(message: &str) {
        let millis =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_millis());
        eprintln!("[b4a {millis}] {message}");
    }

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
        Box::new(std::io::Error::other(message.into()))
    }
}
