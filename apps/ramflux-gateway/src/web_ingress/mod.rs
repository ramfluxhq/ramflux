// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The web ingress: a separate TLS listener that upgrades to WebSocket and then speaks
//! the existing custody and gateway frames, one binary message per frame body.
//!
//! It never shares a socket, a port, a certificate key or an admission pool with the
//! native QUIC and TCP+TLS listeners, and it is off unless `RAMFLUX_GATEWAY_WEB_LISTEN`
//! is set. Authentication is the `web_origin_bound` branch proof; the `Origin` check
//! only protects browser users from other pages.

pub(crate) mod admission;
pub(crate) mod close;
pub(crate) mod config;
pub(crate) mod frame;
pub(crate) mod socket;
pub(crate) mod tls;
pub(crate) mod upgrade;

use crate::serve::GatewayListenerContext;
use admission::{Admission, Limits, Slot};
use close::CloseCode;
use config::{RawSettings, WebIngressConfig};
use ramflux_protocol::custody::{
    TRANSPORT_KIND_WEBSOCKET, WEB_ORIGIN_BINDING_LIFETIME_SECONDS, WEB_ORIGIN_BINDING_SCHEMA,
    WebOriginBindingV1,
};
use socket::{Socket, WebFrameSink, WebFrameSource};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

/// Message cap until the gateway session is established.
pub(crate) const WEB_PRE_SESSION_FRAME_MAX_BYTES: usize = 65_536;
/// Message cap of an established session: the existing gateway frame cap.
pub(crate) const WEB_SESSION_FRAME_MAX_BYTES: usize =
    ramflux_protocol::message::outer::MAX_COMPLETE_FRAME_BYTES;
/// A session must present a fresh proof at least this often. The native grant deadline
/// is shorter today; this ceiling holds if that ever changes.
pub(crate) const WEB_SESSION_MAX_LIFETIME_SECS: u64 = 43_200;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REAUTH_BACKSTOP_GRACE: Duration = Duration::from_secs(30);

/// Whether the operator switched the web listener on.
#[must_use]
pub(crate) fn configured() -> bool {
    RawSettings::from_env().listen.is_some()
}

struct Listener {
    config: WebIngressConfig,
    acceptor: tokio_rustls::TlsAcceptor,
    admission: Arc<Admission>,
    context: GatewayListenerContext,
}

impl Listener {
    /// The context a device must commit to. Every value is this listener's own: the
    /// configured URL, the origin that matched the allow-list, a fresh nonce, the clock.
    fn binding(&self, origin: &str) -> anyhow::Result<WebOriginBindingV1> {
        let now = ramflux_node_core::now_unix_seconds();
        Ok(WebOriginBindingV1 {
            schema: WEB_ORIGIN_BINDING_SCHEMA.to_owned(),
            version: 1,
            node_id: self.context.node_id.clone(),
            listener_url: self.config.listener_url.clone(),
            origin: origin.to_owned(),
            transport_kind: TRANSPORT_KIND_WEBSOCKET.to_owned(),
            gateway_nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            issued_at: now,
            expires_at: now + WEB_ORIGIN_BINDING_LIFETIME_SECONDS,
        })
    }

    fn session_context(&self, remote_addr: SocketAddr) -> crate::GatewayQuicContext {
        let context = self.context.clone();
        crate::GatewayQuicContext {
            custody: context.custody,
            node_id: context.node_id,
            gateway_id: context.gateway_id,
            peers: context.peers,
            router: context.router,
            notify: context.notify,
            #[cfg(feature = "itest-local-mint")]
            relay_service_key: context.relay_service_key,
            state: context.state,
            store: context.store,
            hub: context.hub,
            remote_addr,
        }
    }
}

/// Start the web listener when it is configured; do nothing otherwise.
///
/// # Errors
/// Refuses an unsafe configuration, a web key equal to the mesh service key, and a
/// gateway without custody (the web listener has no other authentication).
pub(crate) fn start(
    node: &ramflux_node_core::NodeServiceConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    let Some(config) = WebIngressConfig::parse(&RawSettings::from_env())? else {
        return Ok(());
    };
    if context.custody.is_none() {
        anyhow::bail!("the web listener requires custody to be configured");
    }
    // The gateway is a proxy in front of the authority: every web proof carries a
    // receipt signed by a node-authorised proxy key. Without one, do not listen.
    if ramflux_node_core::environment::var("RAMFLUX_CUSTODY_PROXY_SIGNING_SEED")
        .map_or(true, |seed| seed.trim().is_empty())
    {
        anyhow::bail!("the web listener requires RAMFLUX_CUSTODY_PROXY_SIGNING_SEED");
    }
    let mesh_key: &std::path::Path = node.mesh.service_key.as_ref();
    let server_config = tls::server_config(&config, mesh_key)?;
    if config.dev_origins {
        tracing::warn!("web listener accepts loopback http origins; never use this in production");
    }
    let listener = Arc::new(Listener {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        admission: Admission::new(Limits::default()),
        config,
        context,
    });
    ramflux_node_core::spawn_service_worker("ramflux-gateway-web", move |shutdown| {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        let _threads = ramflux_node_core::track_service_runtime(&mut builder);
        let runtime = match builder.worker_threads(2).enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "gateway web runtime failed");
                return;
            }
        };
        runtime.block_on(async move {
            tokio::select! {
                () = shutdown.cancelled() => {},
                result = run(listener) => {
                    if let Err(error) = result {
                        tracing::error!(%error, "gateway web listener stopped");
                    }
                }
            }
        });
        ramflux_node_core::drain_service_runtime(runtime);
    })?;
    Ok(())
}

async fn run(listener: Arc<Listener>) -> anyhow::Result<()> {
    let socket = tokio::net::TcpListener::bind(listener.config.listen).await?;
    tracing::info!(addr = %socket.local_addr()?, "gateway web session surface listening");
    let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
    loop {
        let (stream, peer) = match socket.accept().await {
            Ok(accepted) => {
                backoff.success();
                accepted
            }
            Err(error) => {
                let delay = backoff.failure(&error);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                continue;
            }
        };
        // Server-local source identity: the accepted TCP peer, aggregated exactly as the
        // native pre-auth gate aggregates it. Refused connections cost no TLS handshake.
        let source = crate::pre_auth::source_key(peer.ip());
        let Ok(slot) = listener.admission.connect(&source, Instant::now()) else {
            crate::pre_auth::record_ingress_failure("web");
            continue;
        };
        let listener = Arc::clone(&listener);
        tokio::spawn(async move { serve(stream, peer, source, listener, slot).await });
    }
}

async fn serve(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    source: String,
    listener: Arc<Listener>,
    slot: Slot,
) {
    let Ok(Ok(stream)) =
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, listener.acceptor.accept(stream)).await
    else {
        return;
    };
    // rustls answers an ALPN offer without `http/1.1` with `no_application_protocol`
    // itself; a ClientHello with no ALPN extension at all is dropped here.
    if stream.get_ref().1.alpn_protocol() != Some(tls::ALPN_HTTP_1_1) {
        return;
    }
    let (mut read, mut write) = tokio::io::split(stream);
    let Ok(Some(head)) =
        tokio::time::timeout(upgrade::REQUEST_HEAD_TIMEOUT, upgrade::read_head(&mut read)).await
    else {
        return;
    };
    let accepted = match upgrade::check(&head, &listener.config) {
        Ok(accepted) => accepted,
        Err(refused) => {
            upgrade::refuse(&mut write, refused).await;
            return;
        }
    };
    if listener.admission.upgrade(&source, &accepted.origin, Instant::now()).is_err() {
        upgrade::refuse(&mut write, upgrade::Refused::TooManyRequests).await;
        return;
    }
    if write.write_all(accepted.response().as_bytes()).await.is_err() || write.flush().await.is_err()
    {
        return;
    }
    let (socket, frames) = Socket::start(read, write);
    let code = session(&listener, peer, &source, &accepted.origin, &socket, frames, slot).await;
    socket.close(code).await;
}

/// Authenticate with `web_origin_bound`, then hand the connection to the one gateway
/// session state machine. Returns the close code, or `None` when the peer is gone.
async fn session(
    listener: &Listener,
    peer: SocketAddr,
    source: &str,
    origin: &str,
    socket: &Socket,
    mut frames: tokio::sync::mpsc::Receiver<Vec<u8>>,
    slot: Slot,
) -> Option<CloseCode> {
    let Some(pools) = listener.context.custody.as_ref() else {
        return Some(CloseCode::NodeUnavailable);
    };
    let Ok(capacity) = pools.web.acquire(peer.ip(), None, Instant::now()) else {
        return Some(CloseCode::RateLimited);
    };
    let Ok(binding) = listener.binding(origin) else {
        return Some(CloseCode::InternalError);
    };
    let context = listener.session_context(peer);
    let handshake = tokio::select! {
        biased;
        () = capacity.revoked() => return Some(CloseCode::AuthRefused),
        result = crate::custody::web::handshake(
            &mut frames, &socket.out, &context, binding, &capacity,
        ) => result,
    };
    let handoff = match handshake {
        Ok(handoff) => handoff,
        Err(refusal) => {
            if refusal == crate::custody::web::Refusal::ProofRefused {
                listener.admission.failed_proof(source, Instant::now());
            }
            crate::pre_auth::record_ingress_failure("web");
            return refusal.close_code();
        }
    };

    let lifetime = Duration::from_secs(WEB_SESSION_MAX_LIFETIME_SECS);
    let reauth_at = handoff.grant.deadline().min(Instant::now() + lifetime);
    let slot = Arc::new(Mutex::new(slot));
    let established_slot = Arc::clone(&slot);
    let sink = WebFrameSink {
        out: socket.out.clone(),
        shared: Arc::clone(&socket.shared),
        on_established: Some(Box::new(move || {
            established_slot.lock().unwrap_or_else(PoisonError::into_inner).mark_authenticated();
        })),
    };
    let source_frames = WebFrameSource { frames };
    let result = tokio::select! {
        biased;
        () = capacity.revoked() => return Some(CloseCode::AuthRefused),
        // The session loop ends itself at the grant deadline, between requests. This is
        // only a backstop, so it never cancels a request between its commit and reply.
        () = tokio::time::sleep_until(
            tokio::time::Instant::from_std(reauth_at + REAUTH_BACKSTOP_GRACE),
        ) => {
            return Some(if socket.shared.established() {
                CloseCode::ReauthRequired
            } else {
                CloseCode::Timeout
            });
        }
        result = crate::session::handle_gateway_custody_session_transport(
            Box::new(sink),
            Box::new(source_frames),
            context,
            handoff.first,
            handoff.grant,
        ) => result,
    };
    drop(slot);
    Some(if !socket.shared.established() || socket.shared.refused() {
        CloseCode::AuthRefused
    } else if result.is_err() {
        CloseCode::InternalError
    } else if Instant::now() >= reauth_at {
        CloseCode::ReauthRequired
    } else {
        CloseCode::Normal
    })
}
