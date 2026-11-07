// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Opt-in mesh QUIC listener for the relay authority (P25 N5b). A `MeshQuicServer` is
//! bound only when [`AuthorityListenerConfig::bind_addr`] is set; the transport
//! authenticates the peer with mTLS, and [`AuthorityListener`] admits only the router
//! SPIFFE identity from that verified certificate. Requests are served one at a time on
//! a dedicated thread, so the publication lease is held until the token is written to
//! the stream. No production caller starts it yet.
use super::{
    IssueHooks, SourceIssuer, TokenSink,
    listener::{AuthorityListener, AuthorityListenerConfig, Handled, Incoming},
};
use ramflux_transport::{MeshQuicAcceptedRequest, MeshQuicServer, MeshTlsConfig};
use std::{io, net::SocketAddr, sync::Arc, thread::JoinHandle, time::Duration};
use tokio::{runtime::Runtime, sync::Notify};

/// Per-request hang guard for reading the request frame.
const READ_BUDGET: Duration = Duration::from_secs(10);

/// A running listener. Dropping it without [`Self::stop`] leaves the thread running.
pub struct AuthorityQuicServer {
    addr: SocketAddr,
    stop: Arc<Notify>,
    thread: Option<JoinHandle<()>>,
}

impl AuthorityQuicServer {
    /// Binds and starts serving, or returns `None` when no bind address is configured.
    /// `client_ca_pems` are the CAs that may authenticate peers.
    /// # Errors
    /// The bind or TLS failure.
    pub fn start(
        config: &AuthorityListenerConfig,
        tls: &MeshTlsConfig,
        client_ca_pems: Vec<String>,
        issuer: SourceIssuer,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(bind) = config.bind_addr.clone() else { return Ok(None) };
        let tls = tls.clone();
        let stop = Arc::new(Notify::new());
        let stop_thread = Arc::clone(&stop);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<SocketAddr, String>>();
        let thread = std::thread::Builder::new()
            .name("relay-attachment-authority".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                let roots = Arc::new(move || Ok(client_ca_pems.clone()));
                let server = match runtime.block_on(async {
                    let server = MeshQuicServer::bind_with_pem_roots_provider(&bind, &tls, roots)?;
                    server.local_addr().map(|addr| (server, addr))
                }) {
                    Ok((server, addr)) => {
                        let _ = ready_tx.send(Ok(addr));
                        server
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                serve(&runtime, &server, &stop_thread, &issuer, clock.as_ref());
            })?;
        let addr = ready_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("authority listener thread ended before binding"))?
            .map_err(|error| anyhow::anyhow!("authority listener bind failed: {error}"))?;
        Ok(Some(Self { addr, stop, thread: Some(thread) }))
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops accepting and joins the thread.
    pub fn stop(mut self) {
        self.stop.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(
    runtime: &Runtime,
    server: &MeshQuicServer,
    stop: &Notify,
    issuer: &SourceIssuer,
    clock: &(dyn Fn() -> u64 + Send + Sync),
) {
    let listener = AuthorityListener::new(issuer);
    loop {
        let accepted = runtime.block_on(async {
            tokio::select! {
                connection = server.accept_connection() => Some(connection),
                () = stop.notified() => None,
            }
        });
        let Some(accepted) = accepted else { return };
        let connection = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(%error, "authority QUIC handshake rejected");
                continue;
            }
        };
        let peer = connection.peer_spiffe_uri().map(str::to_owned);
        let request = runtime.block_on(async {
            tokio::time::timeout(
                READ_BUDGET,
                MeshQuicServer::accept_request_on_connection(&connection),
            )
            .await
        });
        let Ok(Ok(request)) = request else {
            tracing::warn!("authority QUIC request not received");
            continue;
        };
        let method = request.request.method.clone();
        let path = request.request.path.clone();
        let Ok(body) = serde_json::to_vec(&request.request.body) else { continue };
        let mut sink = QuicSink { runtime, request: Some(request) };
        let handled = listener.handle(
            &Incoming {
                peer_spiffe_uri: peer.as_deref(),
                method: &method,
                path: &path,
                body: &body,
            },
            clock,
            &mut sink,
            &IssueHooks::none(),
        );
        let Some(request) = sink.request.take() else { continue };
        let written = match handled {
            Ok(Handled::Rejected { status, reason }) => {
                let code = status.split(' ').next().and_then(|c| c.parse().ok()).unwrap_or(500);
                runtime.block_on(request.write_text_response(code, reason))
            }
            Ok(Handled::Challenge(reply)) => {
                runtime.block_on(request.write_json_response(200, &reply))
            }
            // The renew frame is written through the sink, or the stream is reset.
            Ok(Handled::Renew(_)) | Err(_) => Ok(()),
        };
        if let Err(error) = written {
            tracing::warn!(%error, "authority QUIC response write failed");
        }
    }
}

/// Writes the renew frame to the QUIC stream from inside the lease-holding writer, so the
/// publication lease outlives the transport write.
struct QuicSink<'a> {
    runtime: &'a Runtime,
    request: Option<MeshQuicAcceptedRequest>,
}
impl TokenSink for QuicSink<'_> {
    fn write_token(&mut self, bytes: &[u8], deadline: Duration) -> io::Result<()> {
        let request =
            self.request.take().ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        self.runtime
            .block_on(async {
                tokio::time::timeout(deadline, request.write_json_response(200, &value)).await
            })
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(|error| io::Error::other(error.to_string()))
    }
    fn reset(&mut self) {
        // Dropping the request resets the stream without a token byte.
        self.request = None;
    }
}
