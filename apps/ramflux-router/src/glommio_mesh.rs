use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use glommio::net::{TcpListener, TcpStream};
use glommio::{LocalExecutorBuilder, Placement};
use rustls::ServerConnection;

use crate::handlers::{MeshResponse, handle_mesh_request_value};

const TLS_IO_BUFFER_SIZE: usize = 16 * 1024;
const HTTP_MAX_HEADER_BYTES: usize = 16 * 1024;

fn glommio_error(context: &'static str, error: impl std::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{context}: {error:?}")
}

pub(crate) fn serve_router_mesh_glommio_mtls(
    config: &ramflux_node_core::NodeServiceConfig,
    router: &Arc<crate::router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    serve_router_mesh_glommio_mtls_with_ready(config, router, None, false)
}

pub(crate) fn serve_router_mesh_glommio_mtls_with_ready(
    config: &ramflux_node_core::NodeServiceConfig,
    router: &Arc<crate::router_runtime::RouterHandle>,
    ready: Option<mpsc::SyncSender<anyhow::Result<String>>>,
    allow_self_peer: bool,
) -> anyhow::Result<()> {
    let addr = config.mesh.listen_addr.clone();
    let tls = crate::serve::mesh_tls_config(config);
    let server_config = Arc::new(ramflux_transport::mesh_server_config(&tls)?);
    let router = Arc::clone(router);
    let local_service_id = config.service_id.clone();
    let allowed_service_ids = config.mesh.allowed_service_ids.clone();
    thread::spawn(move || {
        let spawn_result = LocalExecutorBuilder::new(Placement::Fixed(0))
            .name("ramflux-router-glommio-mesh")
            .spawn(move || async move {
                if let Err(error) = serve_mesh_loop(
                    &addr,
                    server_config,
                    router,
                    local_service_id,
                    allowed_service_ids,
                    ready,
                    allow_self_peer,
                )
                .await
                {
                    tracing::error!(%error, "router glommio mesh listener stopped");
                }
            });
        match spawn_result {
            Ok(handle) => {
                if handle.join().is_err() {
                    tracing::error!("router glommio mesh executor panicked");
                }
            }
            Err(error) => {
                tracing::error!(?error, "router glommio mesh executor failed to spawn");
            }
        }
    });
    Ok(())
}

async fn serve_mesh_loop(
    addr: &str,
    server_config: Arc<rustls::ServerConfig>,
    router: Arc<crate::router_runtime::RouterHandle>,
    local_service_id: String,
    allowed_service_ids: std::collections::BTreeSet<String>,
    ready: Option<mpsc::SyncSender<anyhow::Result<String>>>,
    allow_self_peer: bool,
) -> anyhow::Result<()> {
    let listener =
        match TcpListener::bind(addr).map_err(|error| glommio_error("bind failed", error)) {
            Ok(listener) => listener,
            Err(error) => {
                if let Some(ready) = ready {
                    let _ = ready.send(Err(anyhow::anyhow!("{error}")));
                }
                return Err(error);
            }
        };
    let local_addr =
        match listener.local_addr().map_err(|error| glommio_error("local_addr failed", error)) {
            Ok(local_addr) => local_addr,
            Err(error) => {
                if let Some(ready) = ready {
                    let _ = ready.send(Err(anyhow::anyhow!("{error}")));
                }
                return Err(error);
            }
        };
    if let Some(ready) = ready {
        let _ = ready.send(Ok(local_addr.to_string()));
    }
    tracing::info!(addr = %local_addr, "router glommio mesh mTLS surface listening");
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(?error, "router glommio mesh accept failed");
                continue;
            }
        };
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(?error, "router glommio mesh TCP_NODELAY failed");
            continue;
        }
        let server_config = Arc::clone(&server_config);
        let router = Arc::clone(&router);
        let local_service_id = local_service_id.clone();
        let allowed_service_ids = allowed_service_ids.clone();
        glommio::spawn_local(async move {
            if let Err(error) = handle_mesh_connection(
                stream,
                server_config,
                &router,
                &local_service_id,
                &allowed_service_ids,
                allow_self_peer,
            )
            .await
            {
                tracing::warn!(%error, "router glommio mesh connection ended");
            }
        })
        .detach();
    }
}

async fn handle_mesh_connection(
    stream: TcpStream,
    server_config: Arc<rustls::ServerConfig>,
    router: &crate::router_runtime::RouterHandle,
    local_service_id: &str,
    allowed_service_ids: &std::collections::BTreeSet<String>,
    allow_self_peer: bool,
) -> anyhow::Result<()> {
    let connection = ServerConnection::new(server_config)?;
    let mut tls = GlommioTlsStream::new(stream, connection);
    tls.handshake().await?;
    let peer_spiffe_uri = tls.peer_spiffe_uri()?;
    let peer = authorize_glommio_mesh_health_peer(
        local_service_id,
        allowed_service_ids,
        peer_spiffe_uri.as_deref(),
        allow_self_peer,
    )?;
    tracing::info!(
        peer_service_id = %peer.service_id,
        "router glommio mesh connection authorized"
    );
    let mut requests_on_connection = 0usize;
    loop {
        let Some(request) = tls.read_http_request().await? else {
            tracing::debug!(
                requests_on_connection,
                "router glommio mesh connection ended by client EOF"
            );
            break;
        };
        let is_healthz = request.method == "GET" && request.path == "/healthz";
        tracing::debug!(
            method = %request.method,
            path = %request.path,
            requests_on_connection = requests_on_connection + 1,
            "router glommio mesh request received"
        );
        let mut response = match handle_mesh_request_value(request, router, &peer.service_id) {
            Ok(response) => response,
            Err(error) => MeshResponse {
                status: "500 Internal Server Error",
                content_type: "text/plain; charset=utf-8",
                body: format!("{error}").into_bytes(),
                keep_alive: false,
            },
        };
        requests_on_connection += 1;
        if is_healthz && requests_on_connection >= 2 {
            response.keep_alive = false;
            tracing::debug!(
                requests_on_connection,
                "router glommio mesh health smoke will actively close after this response"
            );
        }
        let keep_alive = response.keep_alive;
        tracing::debug!(
            requests_on_connection,
            keep_alive,
            "router glommio mesh response selected"
        );
        tls.write_http_response(&response).await?;
        if !keep_alive {
            tracing::debug!(
                requests_on_connection,
                "router glommio mesh breaking request loop for server close"
            );
            break;
        }
    }
    tracing::trace!("router glommio mesh entering close_notify path");
    tls.close_notify().await?;
    tracing::trace!("router glommio mesh close_notify path completed");
    Ok(())
}

fn authorize_glommio_mesh_health_peer(
    local_service_id: &str,
    allowed_service_ids: &std::collections::BTreeSet<String>,
    peer_spiffe_uri: Option<&str>,
    allow_self_peer: bool,
) -> anyhow::Result<ramflux_node_core::MeshPeerIdentity> {
    match ramflux_node_core::authorize_mesh_peer(
        local_service_id,
        allowed_service_ids,
        peer_spiffe_uri,
    ) {
        Ok(peer) => Ok(peer),
        Err(error) if allow_self_peer => {
            let Some(spiffe_uri) = peer_spiffe_uri else {
                return Err(error.into());
            };
            let peer = ramflux_node_core::parse_mesh_spiffe_uri(spiffe_uri)?;
            if peer.service_id == local_service_id {
                tracing::debug!(
                    peer_spiffe_uri = %peer.spiffe_uri,
                    "router glommio mesh health smoke allowed self peer"
                );
                Ok(peer)
            } else {
                Err(error.into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

struct GlommioTlsStream {
    stream: TcpStream,
    connection: ServerConnection,
    plaintext: Vec<u8>,
}

impl GlommioTlsStream {
    fn new(stream: TcpStream, connection: ServerConnection) -> Self {
        Self { stream, connection, plaintext: Vec::new() }
    }

    async fn handshake(&mut self) -> anyhow::Result<()> {
        while self.connection.is_handshaking() {
            if self.connection.wants_write() {
                self.flush_tls().await?;
            }
            if self.connection.wants_read() {
                if !self.read_tls_from_socket().await? {
                    anyhow::bail!("mesh TLS EOF during handshake");
                }
            }
        }
        self.flush_tls().await?;
        Ok(())
    }

    fn peer_spiffe_uri(&self) -> anyhow::Result<Option<String>> {
        self.connection
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .map(ramflux_transport::extract_spiffe_uri_from_certificate)
            .transpose()
            .map_err(Into::into)
            .map(Option::flatten)
    }

    async fn read_http_request(
        &mut self,
    ) -> anyhow::Result<Option<ramflux_transport::MeshHttpRequest>> {
        loop {
            if let Some(request) = parse_http_request(&mut self.plaintext)? {
                return Ok(Some(request));
            }
            if !self.fill_plaintext().await? {
                if self.plaintext.is_empty() {
                    return Ok(None);
                }
                anyhow::bail!("incomplete mesh HTTP request before EOF");
            }
        }
    }

    async fn write_http_response(&mut self, response: &MeshResponse) -> anyhow::Result<()> {
        let connection = if response.keep_alive { "keep-alive" } else { "close" };
        let header = format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
            response.status,
            response.content_type,
            response.body.len(),
            connection
        );
        {
            let mut writer = self.connection.writer();
            writer.write_all(header.as_bytes())?;
            writer.write_all(&response.body)?;
        }
        self.flush_tls().await
    }

    async fn close_notify(&mut self) -> anyhow::Result<()> {
        self.connection.send_close_notify();
        tracing::trace!(
            wants_write_after_close_notify = self.connection.wants_write(),
            "router glommio mesh TLS close_notify queued"
        );
        self.write_pending_tls().await?;
        self.flush_tls().await?;
        tracing::trace!("router glommio mesh TLS close_notify bytes flushed");
        self.shutdown_write().await?;
        tracing::trace!("router glommio mesh TCP write side shutdown after close_notify");
        Ok(())
    }

    async fn fill_plaintext(&mut self) -> anyhow::Result<bool> {
        loop {
            let mut buffer = [0_u8; TLS_IO_BUFFER_SIZE];
            match self.connection.reader().read(&mut buffer) {
                Ok(read) if read > 0 => {
                    self.plaintext.extend_from_slice(&buffer[..read]);
                    return Ok(true);
                }
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    tracing::trace!(
                        wants_read = self.connection.wants_read(),
                        "router glommio mesh TLS plaintext reader would block"
                    );
                }
                Err(error) => return Err(error.into()),
            }
            if !self.connection.wants_read() {
                return Ok(false);
            }
            if !self.read_tls_from_socket().await? {
                return Ok(false);
            }
        }
    }

    async fn read_tls_from_socket(&mut self) -> anyhow::Result<bool> {
        let mut input = vec![0_u8; TLS_IO_BUFFER_SIZE];
        let read = self.read_socket_retry(&mut input).await?;
        if read == 0 {
            return Ok(false);
        }
        let mut cursor = std::io::Cursor::new(&input[..read]);
        while (cursor.position() as usize) < read {
            let before = cursor.position();
            let consumed = self.connection.read_tls(&mut cursor)?;
            self.connection.process_new_packets()?;
            if consumed == 0 && cursor.position() == before {
                anyhow::bail!(
                    "mesh TLS read_tls made no progress with {} bytes pending",
                    read - cursor.position() as usize
                );
            }
        }
        self.flush_tls().await?;
        Ok(true)
    }

    async fn flush_tls(&mut self) -> anyhow::Result<()> {
        self.write_pending_tls().await?;
        self.flush_socket_retry().await?;
        Ok(())
    }

    async fn write_pending_tls(&mut self) -> anyhow::Result<()> {
        loop {
            let mut output = Vec::with_capacity(TLS_IO_BUFFER_SIZE);
            let written = self.connection.write_tls(&mut output)?;
            tracing::trace!(
                written_bytes = written,
                wants_write_now = self.connection.wants_write(),
                "router glommio mesh TLS write_tls drained pending bytes"
            );
            if written == 0 {
                break;
            }
            self.write_all_socket_retry(&output).await?;
            if !self.connection.wants_write() {
                break;
            }
        }
        Ok(())
    }

    async fn read_socket_retry(&mut self, input: &mut [u8]) -> anyhow::Result<usize> {
        loop {
            match self.stream.read(input).await {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    tracing::trace!("router glommio mesh TCP read would block; retrying");
                    futures_lite::future::yield_now().await;
                }
                Err(error) => return Err(glommio_error("TLS socket read failed", error)),
            }
        }
    }

    async fn write_all_socket_retry(&mut self, mut output: &[u8]) -> anyhow::Result<()> {
        while !output.is_empty() {
            match self.stream.write(output).await {
                Ok(0) => anyhow::bail!("TLS socket write returned zero bytes"),
                Ok(written) => output = &output[written..],
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    tracing::trace!("router glommio mesh TCP write would block; retrying");
                    futures_lite::future::yield_now().await;
                }
                Err(error) => return Err(glommio_error("TLS socket write failed", error)),
            }
        }
        Ok(())
    }

    async fn flush_socket_retry(&mut self) -> anyhow::Result<()> {
        loop {
            match self.stream.flush().await {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    tracing::trace!("router glommio mesh TCP flush would block; retrying");
                    futures_lite::future::yield_now().await;
                }
                Err(error) => return Err(glommio_error("TLS socket flush failed", error)),
            }
        }
    }

    async fn shutdown_write(&mut self) -> anyhow::Result<()> {
        loop {
            match self.stream.shutdown(Shutdown::Write).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    let error = std::io::Error::from(error);
                    if error.kind() == ErrorKind::WouldBlock {
                        tracing::trace!("router glommio mesh TCP shutdown would block; retrying");
                        futures_lite::future::yield_now().await;
                    } else {
                        return Err(glommio_error("TLS socket shutdown failed", error));
                    }
                }
            }
        }
    }
}

fn parse_http_request(
    buffer: &mut Vec<u8>,
) -> anyhow::Result<Option<ramflux_transport::MeshHttpRequest>> {
    let Some(header_end) = find_header_end(buffer) else {
        if buffer.len() > HTTP_MAX_HEADER_BYTES {
            anyhow::bail!("mesh HTTP header exceeds {HTTP_MAX_HEADER_BYTES} bytes");
        }
        return Ok(None);
    };
    let header = std::str::from_utf8(&buffer[..header_end])?;
    let mut lines = header.split("\r\n");
    let request_line = lines.next().ok_or_else(|| anyhow::anyhow!("missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or_else(|| anyhow::anyhow!("missing method"))?.to_owned();
    let path = request_parts.next().ok_or_else(|| anyhow::anyhow!("missing path"))?.to_owned();
    let mut content_length = 0usize;
    for line in lines {
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = value.trim().parse()?;
        }
    }
    let request_len = header_end + 4 + content_length;
    if buffer.len() < request_len {
        tracing::trace!(
            content_length,
            have = buffer.len(),
            need = request_len,
            "router glommio mesh awaiting more request body"
        );
        return Ok(None);
    }
    let body = buffer[header_end + 4..request_len].to_vec();
    buffer.drain(..request_len);
    Ok(Some(ramflux_transport::MeshHttpRequest { method, path, body }))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_request_keeps_pipelined_request_bytes() -> anyhow::Result<()> {
        let mut bytes = b"GET /healthz HTTP/1.1\r\nHost: router\r\n\r\nGET /healthz HTTP/1.1\r\nHost: router\r\n\r\n".to_vec();
        let first = parse_http_request(&mut bytes)?.expect("first request");
        assert_eq!(first.method, "GET");
        assert_eq!(first.path, "/healthz");
        assert!(!bytes.is_empty());
        let second = parse_http_request(&mut bytes)?.expect("second request");
        assert_eq!(second.path, "/healthz");
        assert!(bytes.is_empty());
        Ok(())
    }

    #[test]
    fn parse_http_request_waits_for_complete_body() -> anyhow::Result<()> {
        let mut bytes = b"POST /healthz HTTP/1.1\r\nContent-Length: 4\r\n\r\nab".to_vec();
        assert!(parse_http_request(&mut bytes)?.is_none());
        bytes.extend_from_slice(b"cd");
        let request = parse_http_request(&mut bytes)?.expect("complete request");
        assert_eq!(request.body, b"abcd");
        assert!(bytes.is_empty());
        Ok(())
    }

    #[test]
    fn parse_http_request_waits_for_large_body_split_across_reads() -> anyhow::Result<()> {
        let body = vec![b'x'; TLS_IO_BUFFER_SIZE + 17];
        let header =
            format!("POST /mvp0/envelope HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
        let split = TLS_IO_BUFFER_SIZE / 2;
        let mut bytes = header.into_bytes();
        bytes.extend_from_slice(&body[..split]);
        assert!(parse_http_request(&mut bytes)?.is_none());
        bytes.extend_from_slice(&body[split..]);
        let request = parse_http_request(&mut bytes)?.expect("complete large request");
        assert_eq!(request.path, "/mvp0/envelope");
        assert_eq!(request.body, body);
        assert!(bytes.is_empty());
        Ok(())
    }
}
