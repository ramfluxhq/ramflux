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
    listener::{AuthorityListener, AuthorityListenerConfig, Handled, Incoming, MAX_WIRE_BODY},
};
use ramflux_transport::{
    MeshQuicLimitedIngress, MeshQuicLimitedResponder, MeshQuicServer, MeshTlsConfig,
};
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::{runtime::Runtime, sync::Notify};

/// One original budget per connection: ingress read, handling and every response write.
pub const REQUEST_BUDGET: Duration = Duration::from_secs(10);
/// Close code for a peer that is not the router; no byte of its request is read.
const UNAUTHORIZED_CLOSE: u32 = 403;

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
        budget: Duration,
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
                serve(&runtime, &server, &stop_thread, &issuer, clock.as_ref(), budget);
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
    budget: Duration,
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
        // The one original deadline starts when the handshake completes.
        let deadline = Instant::now() + budget;
        let connection = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(%error, "authority QUIC handshake rejected");
                continue;
            }
        };
        let peer = connection.peer_spiffe_uri().map(str::to_owned);
        // Authenticate before reading a byte: other services never reach decoding.
        if !listener.authorize(peer.as_deref()) {
            connection.close(UNAUTHORIZED_CLOSE, b"router identity required");
            continue;
        }
        let ingress = runtime.block_on(MeshQuicServer::accept_limited_request(
            &connection,
            MAX_WIRE_BODY,
            deadline,
        ));
        let request = match ingress {
            Ok(MeshQuicLimitedIngress::Request(request)) => request,
            Ok(MeshQuicLimitedIngress::TooLarge(responder)) => {
                write_text(runtime, responder, 413, "body", deadline);
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, "authority QUIC request not received in budget");
                continue;
            }
        };
        let mut sink = QuicSink { runtime, responder: Some(request.responder), deadline };
        let handled = listener.handle(
            &Incoming {
                peer_spiffe_uri: peer.as_deref(),
                method: &request.method,
                path: &request.path,
                body: &request.body,
            },
            clock,
            &mut sink,
            &IssueHooks::none(),
        );
        let Some(responder) = sink.responder.take() else { continue };
        match handled {
            Ok(Handled::Rejected { status, reason }) => {
                let code = status.split(' ').next().and_then(|c| c.parse().ok()).unwrap_or(500);
                write_text(runtime, responder, code, reason, deadline);
            }
            Ok(Handled::Challenge(reply)) => {
                if let Err(error) = runtime.block_on(responder.respond(200, &reply, deadline)) {
                    tracing::warn!(%error, "authority QUIC challenge write failed");
                }
            }
            // The renew frame was written through the sink, or the stream is reset.
            Ok(Handled::Renew(_)) | Err(_) => {}
        }
    }
}

fn write_text(
    runtime: &Runtime,
    responder: MeshQuicLimitedResponder,
    code: u16,
    reason: &str,
    deadline: Instant,
) {
    if let Err(error) =
        runtime.block_on(responder.respond(code, &serde_json::json!({ "error": reason }), deadline))
    {
        tracing::warn!(%error, "authority QUIC response write failed");
    }
}

/// Writes the renew frame to the QUIC stream from inside the lease-holding writer, so the
/// publication lease outlives the transport write, bounded by the original deadline.
struct QuicSink<'a> {
    runtime: &'a Runtime,
    responder: Option<MeshQuicLimitedResponder>,
    deadline: Instant,
}
impl TokenSink for QuicSink<'_> {
    fn write_token(&mut self, bytes: &[u8], deadline: Duration) -> io::Result<()> {
        let responder =
            self.responder.take().ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        // Never later than the original deadline, nor than the writer's own bound.
        let bound = self.deadline.min(Instant::now() + deadline);
        self.runtime
            .block_on(responder.respond(200, &value, bound))
            .map_err(|error| io::Error::other(error.to_string()))
    }
    fn reset(&mut self) {
        // Dropping the responder resets the stream without a token byte.
        self.responder = None;
    }
}
