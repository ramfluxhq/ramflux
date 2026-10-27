// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client QUIC listener, dispatch context, and request metrics.

use crate::client_quic::relay_client_quic_route;
use crate::config::{now_unix_seconds, relay_client_quic_addr, validate_relay_client_quic_tls};
#[cfg(feature = "itest-quic-fault")]
use crate::itest_quic_fault;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Ingress metrics for the client-facing object relay QUIC surface, shared (via `Arc`) across all
/// connections handled by one listener.
#[derive(Clone, Default)]
pub(crate) struct RelayClientQuicMetrics {
    pub(crate) ingress_total: Arc<AtomicU64>,
    pub(crate) object_rejected_total: Arc<AtomicU64>,
}

impl RelayClientQuicMetrics {
    fn record_ingress(&self) -> u64 {
        self.ingress_total.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn record_object_rejected(&self) -> u64 {
        self.object_rejected_total.fetch_add(1, Ordering::Relaxed) + 1
    }

    #[cfg(test)]
    fn ingress_total(&self) -> u64 {
        self.ingress_total.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn object_rejected_total(&self) -> u64 {
        self.object_rejected_total.load(Ordering::Relaxed)
    }
}

/// Per-listener request context for the client-facing object relay QUIC surface. Carries the ingress
/// metrics, the pinned trust snapshot cache consulted by the v3 ingress gate, and the store/state the
/// verified Get/Ack data plane reads and mutates.
#[derive(Clone)]
pub(crate) struct RelayClientQuicContext {
    pub(crate) metrics: RelayClientQuicMetrics,
    /// Pinned federation trust snapshot loaded at startup and shared across all connections. The v3
    /// gate reads the authoritative snapshot from here (never from a request body). Held behind a
    /// mutex so a future refresh can atomically replace it while requests read it.
    pub(crate) trust_snapshot_cache: Arc<Mutex<ramflux_node_core::RelayTrustSnapshotCache>>,
    pub(crate) node_id: Arc<str>,
    pub(crate) store: Arc<ramflux_node_core::RelayRedbStore>,
    pub(crate) state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    #[allow(dead_code)]
    pub(crate) config: Arc<ramflux_node_core::NodeServiceConfig>,
}

/// Routes a request while recording ingress/rejection metrics and logging the fail-closed reason for
/// rejected object requests. The v3 gate rejects a malformed/non-v3 request `401` and an
/// unauthenticated/unauthorized one `403` (both counted as object rejections); verified Get/Ack reach
/// the data plane and Put/Tombstone return `501`. Health is `200`; unknown routes are `404`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn relay_client_quic_dispatch(
    request: &ramflux_transport::GatewayQuicRequest,
    metrics: &RelayClientQuicMetrics,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    let ingress_total = metrics.record_ingress();
    let response =
        relay_client_quic_route(request, trust_cache, store, state, expected_node_id, now);
    if response.status == 401 || response.status == 403 {
        let object_rejected_total = metrics.record_object_rejected();
        tracing::info!(
            method = %request.method,
            path = %request.path,
            status = response.status,
            ingress_total,
            object_rejected_total,
            "relay client QUIC object ingress rejected: not an admissible v3 invocation"
        );
    } else {
        tracing::debug!(
            method = %request.method,
            path = %request.path,
            status = response.status,
            ingress_total,
            "relay client QUIC ingress served"
        );
    }
    response
}

/// Spawns the client-facing object relay QUIC listener on a dedicated tokio runtime thread. Fails
/// closed synchronously if the bind address or server-auth TLS credentials are missing/invalid.
pub(crate) fn serve_relay_client_quic(
    config: &ramflux_node_core::NodeServiceConfig,
    store: Arc<ramflux_node_core::RelayRedbStore>,
    state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    trust_snapshot_cache: Arc<Mutex<ramflux_node_core::RelayTrustSnapshotCache>>,
) -> anyhow::Result<()> {
    let addr = relay_client_quic_addr()?;
    let server_config = validate_relay_client_quic_tls(config)?;
    let context = RelayClientQuicContext {
        metrics: RelayClientQuicMetrics::default(),
        trust_snapshot_cache,
        node_id: Arc::from(config.node_id.as_str()),
        store,
        state,
        config: Arc::new(config.clone()),
    };
    ramflux_node_core::spawn_service_worker("ramflux-relay-client-quic", move |shutdown| {
        let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "failed to start relay client QUIC runtime");
                return;
            }
        };
        runtime.block_on(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                result = run_relay_client_quic(addr, server_config, context) => {
                    if let Err(error) = result {
                        tracing::error!(%error, "relay client QUIC listener stopped");
                    }
                }
            }
        });
    })?;
    Ok(())
}

pub(crate) async fn run_relay_client_quic(
    addr: std::net::SocketAddr,
    server_config: quinn::ServerConfig,
    context: RelayClientQuicContext,
) -> anyhow::Result<()> {
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    tracing::info!(addr = %endpoint.local_addr()?, "relay client-facing QUIC surface listening");
    while let Some(connecting) = endpoint.accept().await {
        let context = context.clone();
        tokio::spawn(async move {
            let Some(_in_flight) = ramflux_node_core::begin_service_request() else {
                return;
            };
            match connecting.await {
                Ok(connection) => handle_relay_client_quic_connection(connection, context).await,
                Err(error) => {
                    tracing::warn!(%error, detail = ?error, "relay client QUIC handshake rejected");
                }
            }
        });
    }
    Ok(())
}

pub(crate) async fn handle_relay_client_quic_connection(
    connection: quinn::Connection,
    context: RelayClientQuicContext,
) {
    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let request: ramflux_transport::GatewayQuicRequest =
                    match ramflux_transport::read_quic_json_frame(&mut recv).await {
                        Ok(request) => request,
                        Err(error) => {
                            tracing::debug!(%error, "relay client QUIC request read failed");
                            continue;
                        }
                    };
                // Ingress gate only: metrics + fail-closed routing. Object requests run through the
                // v3 verifier gate (non-v3 -> 401, unauthorized -> 403, verified -> 501); the pinned
                // trust snapshot is the authority and no data plane is wired yet.
                let response = {
                    let trust_cache = context
                        .trust_snapshot_cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    relay_client_quic_dispatch(
                        &request,
                        &context.metrics,
                        &trust_cache,
                        &context.store,
                        &context.state,
                        &context.node_id,
                        now_unix_seconds(),
                    )
                };
                // T24-A3 (itest-quic-fault only): after the business commit above and before the
                // response is written, optionally drop/hold the connection to exercise the SDK's
                // ambiguous-commit retry. Absent entirely in the default/release build.
                #[cfg(feature = "itest-quic-fault")]
                match itest_quic_fault::decide_and_capture(
                    &request,
                    response.status,
                    connection.stable_id() as u64,
                ) {
                    Ok(itest_quic_fault::Decision::Write) => {}
                    Ok(itest_quic_fault::Decision::Drop) => {
                        connection.close(
                            quinn::VarInt::from_u32(0),
                            b"itest-quic-fault: drop after commit",
                        );
                        return;
                    }
                    Ok(itest_quic_fault::Decision::Hold) => {
                        if itest_quic_fault::write_hold_marker().is_err() {
                            // Fail closed: cannot record the restart barrier.
                            connection.close(
                                quinn::VarInt::from_u32(0),
                                b"itest-quic-fault: hold marker write failed",
                            );
                            return;
                        }
                        // Park until the relay process is restarted by the test; the held
                        // connection dies with the process (no partial response is ever written).
                        std::future::pending::<()>().await;
                        return;
                    }
                    Err(()) => {
                        // Fail closed: a requested capture record could not be written, so the test
                        // must not proceed on an empty log.
                        connection.close(
                            quinn::VarInt::from_u32(0),
                            b"itest-quic-fault: capture write failed",
                        );
                        return;
                    }
                }
                if let Err(error) =
                    ramflux_transport::write_quic_json_frame(&mut send, &response).await
                {
                    tracing::debug!(%error, "relay client QUIC response write failed");
                    continue;
                }
                let _ = send.finish();
            }
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => return,
            Err(error) => {
                tracing::debug!(%error, "relay client QUIC connection closed");
                return;
            }
        }
    }
}
#[cfg(test)]
#[path = "tests/quic_service.rs"]
mod tests;

#[cfg(all(test, feature = "itest-quic-fault"))]
#[path = "tests/quic_failure_diagnostics.rs"]
mod failure_diagnostics_tests;
