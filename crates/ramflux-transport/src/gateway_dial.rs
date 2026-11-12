// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Executes a [`DialPlan`]: staggered carrier legs raced to the first completed handshake.
//!
//! Each leg starts at its plan offset. The first leg that completes its TLS handshake (for
//! the WebSocket carrier, the handshake and the upgrade) wins. Every other leg is aborted and
//! its socket is dropped before this function returns, so no second connection exists when
//! the caller writes its first frame. A leg that fails does not end the dial while another
//! leg is still running or yet to start.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::connection_policy::{
    CarrierKind, DialPlan, SESSION_KEEP_ALIVE_INTERVAL, SESSION_MAX_IDLE_TIMEOUT,
    bind_addr_for_peer,
};
use crate::gateway_websocket::{WebSocketTlsGatewayBidiStream, WebSocketTlsGatewayClient};
use crate::quic_gateway::{
    GatewaySessionTransport, QuicConnectPhase, QuicGatewayBidiStream, QuicGatewayClient,
    TcpTlsGatewayBidiStream, TcpTlsGatewayClient,
};
use crate::{TransportError, tls_config};

/// Where the native WebSocket carrier connects.
#[derive(Clone, Debug)]
pub struct WebSocketDialTarget {
    pub addr: SocketAddr,
    /// `host[:port]` for the `Host` header; the port is omitted when it is 443.
    pub authority: String,
}

/// Everything one dial needs. Every leg uses the same server name and the same pinned CA.
#[derive(Clone, Debug)]
pub struct GatewayDialTarget {
    pub bind_addr: SocketAddr,
    pub quic_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    pub server_name: String,
    pub ca_cert: PathBuf,
    /// Per-leg handshake deadline.
    pub handshake_timeout: Duration,
    /// Frame I/O deadline of the established stream.
    pub session_timeout: Duration,
    pub websocket: Option<WebSocketDialTarget>,
    /// Stream carriers tunnel through this proxy; QUIC is refused while it is set.
    #[cfg(all(feature = "http-connect-proxy", not(windows)))]
    pub http_proxy: Option<crate::http_connect_proxy::HttpConnectProxy>,
}

/// The winning connection of a dial.
pub enum DialedGateway {
    Quic { client: QuicGatewayClient, stream: QuicGatewayBidiStream },
    TcpTls { stream: TcpTlsGatewayBidiStream },
    WebSocketTls { stream: WebSocketTlsGatewayBidiStream },
}

impl DialedGateway {
    #[must_use]
    pub const fn carrier(&self) -> CarrierKind {
        match self {
            Self::Quic { .. } => CarrierKind::Quic,
            Self::TcpTls { .. } => CarrierKind::TcpTls,
            Self::WebSocketTls { .. } => CarrierKind::WebSocketTls,
        }
    }

    /// Split into the QUIC connection owner, if any, and the boxed session stream.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (Option<QuicGatewayClient>, Box<dyn GatewaySessionTransport + Send>) {
        let (client, stream): (_, Box<dyn GatewaySessionTransport + Send>) = match self {
            Self::Quic { client, stream } => (Some(client), Box::new(stream)),
            Self::TcpTls { stream } => (None, Box::new(stream)),
            Self::WebSocketTls { stream } => (None, Box::new(stream)),
        };
        (client, stream)
    }
}

/// Every leg of a dial failed.
#[derive(Debug)]
pub struct DialError {
    /// Failures in the order they happened.
    pub failures: Vec<(CarrierKind, TransportError)>,
}

impl DialError {
    /// True when at least one stream carrier reached a peer and every stream carrier that
    /// failed did so on the pinned-CA check (QUIC is usually just dropped on such a network).
    /// That is a captive portal or an intercepting middlebox: the host reports "network
    /// blocked". It must never offer to trust the presented certificate.
    #[must_use]
    pub fn is_network_blocked(&self) -> bool {
        let mut stream_failures =
            self.failures.iter().filter(|(carrier, _)| !carrier.needs_udp()).peekable();
        stream_failures.peek().is_some() && stream_failures.all(|(_, error)| error.is_tls_failure())
    }

    /// Collapse into the error of the last stream carrier that failed, or the last failure.
    #[must_use]
    pub fn into_transport_error(mut self) -> TransportError {
        let preferred = self.failures.iter().rposition(|(carrier, _)| !carrier.needs_udp());
        let index = preferred.or_else(|| self.failures.len().checked_sub(1));
        match index {
            Some(index) => self.failures.swap_remove(index).1,
            None => TransportError::NotOpen,
        }
    }
}

impl std::fmt::Display for DialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("every gateway carrier failed:")?;
        for (carrier, error) in &self.failures {
            write!(formatter, " {}={error};", carrier.label())?;
        }
        Ok(())
    }
}

impl std::error::Error for DialError {}

fn quic_phase_error(phase: QuicConnectPhase) -> TransportError {
    match phase {
        QuicConnectPhase::Setup(message) | QuicConnectPhase::HandshakeFailed(message) => {
            TransportError::Quic(message)
        }
        QuicConnectPhase::HandshakeTimeout => {
            TransportError::Quic("gateway QUIC handshake timed out".to_owned())
        }
        QuicConnectPhase::HandshakeSecurity(message) => TransportError::Tls(message),
    }
}

async fn dial_quic(target: &GatewayDialTarget) -> Result<DialedGateway, TransportError> {
    #[cfg(all(feature = "http-connect-proxy", not(windows)))]
    if target.http_proxy.is_some() {
        return Err(TransportError::UnsupportedOperation {
            operation: "QUIC through an HTTP proxy",
        });
    }
    let config = tls_config::quic_gateway_session_client_config(
        &target.ca_cert,
        SESSION_MAX_IDLE_TIMEOUT,
        SESSION_KEEP_ALIVE_INTERVAL,
    )?;
    let client = QuicGatewayClient::connect_pooled(
        bind_addr_for_peer(target.bind_addr, target.quic_addr),
        target.quic_addr,
        &target.server_name,
        config,
        target.handshake_timeout,
        target.session_timeout,
    )
    .await
    .map_err(quic_phase_error)?;
    let stream = client.open_bidi_stream().await?;
    Ok(DialedGateway::Quic { client, stream })
}

/// The byte stream a stream carrier runs TLS over: direct TCP, or a CONNECT tunnel.
async fn open_stream_path(
    target: &GatewayDialTarget,
    peer: SocketAddr,
) -> Result<tokio::net::TcpStream, TransportError> {
    #[cfg(all(feature = "http-connect-proxy", not(windows)))]
    if let Some(proxy) = &target.http_proxy {
        return proxy.open_tunnel(peer, target.handshake_timeout).await;
    }
    crate::quic_gateway::connect_gateway_tcp(
        bind_addr_for_peer(target.bind_addr, peer),
        peer,
        target.handshake_timeout,
    )
    .await
}

async fn dial_tcp_tls(target: &GatewayDialTarget) -> Result<DialedGateway, TransportError> {
    let tcp = open_stream_path(target, target.tcp_addr).await?;
    let (_client, stream) = TcpTlsGatewayClient::connect_over(
        tcp,
        &target.server_name,
        &target.ca_cert,
        target.session_timeout,
    )
    .await?;
    Ok(DialedGateway::TcpTls { stream })
}

async fn dial_websocket(target: &GatewayDialTarget) -> Result<DialedGateway, TransportError> {
    let Some(websocket) = &target.websocket else {
        return Err(TransportError::UnsupportedOperation {
            operation: "WebSocket carrier without a configured endpoint",
        });
    };
    let tcp = open_stream_path(target, websocket.addr).await?;
    let (_client, stream) = WebSocketTlsGatewayClient::connect_over(
        tcp,
        &target.server_name,
        &websocket.authority,
        &target.ca_cert,
        target.session_timeout,
    )
    .await?;
    Ok(DialedGateway::WebSocketTls { stream })
}

async fn dial_leg(
    target: Arc<GatewayDialTarget>,
    carrier: CarrierKind,
    start_after: Duration,
) -> (CarrierKind, Result<DialedGateway, TransportError>) {
    if !start_after.is_zero() {
        tokio::time::sleep(start_after).await;
    }
    let result = match carrier {
        CarrierKind::Quic => dial_quic(&target).await,
        CarrierKind::TcpTls => dial_tcp_tls(&target).await,
        CarrierKind::WebSocketTls => dial_websocket(&target).await,
    };
    (carrier, result)
}

/// Dial the gateway according to `plan`.
///
/// Must be called from within a Tokio runtime. Dropping the returned future aborts every leg.
///
/// # Errors
/// Returns [`DialError`] with every leg's failure when no leg completes.
pub async fn dial_gateway(
    target: GatewayDialTarget,
    plan: &DialPlan,
) -> Result<DialedGateway, DialError> {
    let target = Arc::new(target);
    // Dropping the set aborts its tasks, which covers cancellation of this future.
    let mut legs = tokio::task::JoinSet::new();
    for leg in plan.legs() {
        legs.spawn(dial_leg(Arc::clone(&target), leg.carrier, leg.start_after));
    }
    let mut failures = Vec::new();
    while let Some(joined) = legs.join_next().await {
        match joined {
            Ok((carrier, Ok(dialed))) => {
                legs.abort_all();
                // Wait until every losing leg has been dropped, so its socket is closed
                // before the caller sends the first frame on the winner.
                while legs.join_next().await.is_some() {}
                tracing::debug!(carrier = carrier.label(), "gateway dial completed");
                return Ok(dialed);
            }
            Ok((carrier, Err(error))) => {
                tracing::debug!(carrier = carrier.label(), %error, "gateway dial leg failed");
                failures.push((carrier, error));
            }
            Err(join_error) => {
                failures.push((
                    CarrierKind::TcpTls,
                    TransportError::Io(std::io::Error::other(join_error.to_string())),
                ));
            }
        }
    }
    Err(DialError { failures })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::connection_policy::DialInputs;

    fn unroutable_target() -> GatewayDialTarget {
        // TEST-NET-1 (RFC 5737): never routed, so every leg fails or times out locally.
        let peer: SocketAddr = "192.0.2.1:443".parse().expect("documentation address");
        GatewayDialTarget {
            bind_addr: "0.0.0.0:0".parse().expect("bind address"),
            quic_addr: peer,
            tcp_addr: peer,
            server_name: "gateway.invalid".to_owned(),
            ca_cert: PathBuf::from("/nonexistent/ca.pem"),
            handshake_timeout: Duration::from_millis(200),
            session_timeout: Duration::from_millis(200),
            websocket: None,
            #[cfg(all(feature = "http-connect-proxy", not(windows)))]
            http_proxy: None,
        }
    }

    #[tokio::test]
    async fn every_leg_failing_reports_each_carrier_once() {
        let plan = DialPlan::auto(DialInputs::default());
        let error = match dial_gateway(unroutable_target(), &plan).await {
            Ok(_) => unreachable!("no gateway is reachable in this test"),
            Err(error) => error,
        };
        let carriers: Vec<CarrierKind> = error.failures.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(carriers.len(), 2);
        assert!(carriers.contains(&CarrierKind::Quic));
        assert!(carriers.contains(&CarrierKind::TcpTls));
    }

    #[test]
    fn network_blocked_requires_a_trust_failure_on_every_stream_leg() {
        let portal = DialError {
            failures: vec![
                (CarrierKind::Quic, TransportError::Quic("timed out".to_owned())),
                (CarrierKind::TcpTls, TransportError::Tls("unknown issuer".to_owned())),
            ],
        };
        assert!(portal.is_network_blocked());
        let unreachable = DialError {
            failures: vec![
                (CarrierKind::Quic, TransportError::Tls("unknown issuer".to_owned())),
                (CarrierKind::TcpTls, TransportError::NotOpen),
            ],
        };
        assert!(!unreachable.is_network_blocked());
        let udp_only = DialError {
            failures: vec![(CarrierKind::Quic, TransportError::Tls("unknown issuer".to_owned()))],
        };
        assert!(!udp_only.is_network_blocked());
        assert!(!DialError { failures: Vec::new() }.is_network_blocked());
    }

    #[test]
    fn collapsed_error_prefers_the_stream_carrier() {
        let error = DialError {
            failures: vec![
                (CarrierKind::TcpTls, TransportError::Tls("stream".to_owned())),
                (CarrierKind::Quic, TransportError::Quic("udp".to_owned())),
            ],
        };
        assert!(matches!(error.into_transport_error(), TransportError::Tls(_)));
    }
}
