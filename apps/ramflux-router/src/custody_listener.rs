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
    let tls = ramflux_transport::tcp_gateway_server_config(&crate::serve::mesh_tls_config(config))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let capacity = Arc::new(tokio::sync::Semaphore::new(64));
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
                let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else { continue };
                let acceptor = acceptor.clone();
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _permit = permit;
                    let run = async {
                        let tls = acceptor.accept(socket).await?;
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
    let bytes = tokio::time::timeout(Duration::from_secs(30), read_custody_open_frame(&mut stream))
        .await??;
    let frame: CustodyClientFrame = decode(&bytes, 4096)?;
    let CustodyClientFrame::CustodyOpen { binding_mode: mode } = &frame else {
        anyhow::bail!("custody preface required")
    };
    let mode = *mode;
    let connection = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let response = router.custody_tls(frame, &connection, peer, mode, None);
    write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?).await?;
    for _ in 0..2048 {
        let bytes =
            tokio::time::timeout(Duration::from_secs(330), read_custody_tcp_frame(&mut stream))
                .await??;
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
        let response = tokio::task::spawn_blocking(move || {
            shared.custody_tls(frame, &connection, &peer, mode, exporter)
        })
        .await?;
        write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?).await?;
    }
    Ok(())
}
