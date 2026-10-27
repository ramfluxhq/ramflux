// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optional client-facing router TLS endpoint for direct exporter binding.
use crate::router_runtime::RouterHandle;
use ramflux_protocol::custody::{CustodyClientFrame, MAX_CUSTODY_FRAME_BYTES, decode};
use ramflux_transport::{
    GatewayTcpTlsStream, read_custody_open_frame, read_custody_tcp_frame, write_custody_tcp_frame,
};
use std::{sync::Arc, time::Duration};
pub(crate) fn start(
    config: &ramflux_node_core::NodeServiceConfig,
    router: Arc<RouterHandle>,
) -> anyhow::Result<()> {
    let Ok(address) = std::env::var("RAMFLUX_CUSTODY_TCP_ADDR") else { return Ok(()) };
    let listener = std::net::TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    let certificate = std::path::PathBuf::from(std::env::var("RAMFLUX_CUSTODY_TLS_CERT_FILE")?);
    let private_key = std::path::PathBuf::from(std::env::var("RAMFLUX_CUSTODY_TLS_KEY_FILE")?);
    if certificate == std::path::Path::new(&config.mesh.service_cert)
        || private_key == std::path::Path::new(&config.mesh.service_key)
    {
        anyhow::bail!("custody public TLS must be separate from mesh credentials")
    }
    if ramflux_transport::custody_certificate_public_key_hash(&certificate)?
        == ramflux_transport::custody_certificate_public_key_hash(std::path::Path::new(
            &config.mesh.service_cert,
        ))?
    {
        anyhow::bail!("custody public TLS cannot reuse the mesh signing key")
    }
    let hash = ramflux_transport::custody_certificate_file_hash(&certificate)?;
    if !router.custody_public_certificate(&hash) {
        anyhow::bail!("public TLS certificate is not bound in the signed node record")
    }
    let tls = ramflux_transport::tcp_gateway_server_config(&ramflux_transport::MeshTlsConfig {
        ca_cert: certificate.clone(),
        service_cert: certificate,
        service_key: private_key,
    })?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let capacity = ramflux_node_core::CustodyIngressLimiter::new(64);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    std::thread::Builder::new().name("custody-direct-tls".into()).spawn(move || {
        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(error) => {
                    tracing::error!(%error,"custody TLS listener unavailable");
                    return;
                }
            };
            loop {
                let (socket, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(error) => {
                        tracing::error!(%error,"custody TLS accept failed");
                        return;
                    }
                };
                let Some(permit) = capacity.acquire(peer.ip(), None, std::time::Instant::now())
                else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _permit = permit;
                    let run = async {
                        let tls = accept_tls(&acceptor, socket).await?;
                        serve(GatewayTcpTlsStream::Server(tls), router, &peer.ip().to_string())
                            .await
                    };
                    if let Err(error) = tokio::time::timeout(Duration::from_mins(15), run)
                        .await
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("custody TLS lifetime expired")))
                    {
                        tracing::warn!(%error,"custody TLS connection closed");
                    }
                });
            }
        });
    })?;
    Ok(())
}
async fn serve(
    mut stream: GatewayTcpTlsStream,
    router: Arc<RouterHandle>,
    peer: &str,
) -> anyhow::Result<()> {
    let auth_deadline = tokio::time::Instant::now() + ramflux_node_core::custody_auth_timeout()?;
    let bytes =
        tokio::time::timeout_at(auth_deadline, read_custody_open_frame(&mut stream)).await??;
    let frame: CustodyClientFrame = decode(&bytes, 4096)?;
    let CustodyClientFrame::CustodyOpen { binding_mode: mode } = &frame else {
        anyhow::bail!("custody preface required")
    };
    let mode = *mode;
    let connection = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let _cleanup = Disconnect { router: Arc::clone(&router), connection: connection.clone() };
    let mut authenticated = false;
    let response = router.custody_tls(frame, &connection, peer, mode, None);
    tokio::time::timeout_at(
        auth_deadline,
        write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?),
    )
    .await??;
    for _ in 0..2048 {
        let deadline = if authenticated {
            tokio::time::Instant::now() + Duration::from_secs(330)
        } else {
            auth_deadline
        };
        let bytes =
            tokio::time::timeout_at(deadline, read_custody_tcp_frame(&mut stream)).await??;
        let frame: CustodyClientFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        let exporter = if let CustodyClientFrame::Prove { proof, .. } = &frame {
            let nonce: [u8; 32] = ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid exporter context"))?;
            Some(ramflux_transport::custody_tcp_exporter(&stream, &nonce)?)
        } else {
            None
        };
        let shared = Arc::clone(&router);
        let connection = connection.clone();
        let peer = peer.to_owned();
        let response = tokio::time::timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || {
                shared.custody_tls(frame, &connection, &peer, mode, exporter)
            }),
        )
        .await??;
        authenticated |= matches!(
            response,
            ramflux_protocol::custody::CustodyServerFrame::SessionEstablished { .. }
        );
        tokio::time::timeout_at(
            deadline,
            write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?),
        )
        .await??;
    }
    Ok(())
}

struct Disconnect {
    router: Arc<RouterHandle>,
    connection: String,
}
impl Drop for Disconnect {
    fn drop(&mut self) {
        self.router.custody_disconnected(&self.connection);
    }
}

async fn accept_tls(
    acceptor: &tokio_rustls::TlsAcceptor,
    socket: tokio::net::TcpStream,
) -> anyhow::Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    Ok(tokio::time::timeout(Duration::from_secs(5), acceptor.accept(socket)).await??)
}

#[cfg(test)]
#[path = "custody_listener_tests.rs"]
mod tests;
