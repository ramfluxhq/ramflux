// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The raced `Auto` connect: plan from the per-network path memory, dial, remember the winner.
//!
//! Every leg dials the same gateway with the same server name and pinned CA, and the caller
//! runs the same channel-bound handoff on whichever carrier wins. Losing legs are closed by
//! the dialer before this returns, so the handoff is written on the only open connection.

use std::time::Instant;

use ramflux_transport::{CarrierKind, DialedGateway, GatewayDialTarget, dial_gateway};

use super::engine::GatewaySessionClientTransport;
use super::transport_opener::OpenedTransport;
use super::{GatewaySessionConfig, GatewaySessionTransportKind};
use crate::SdkError;

fn dial_target(config: &GatewaySessionConfig) -> GatewayDialTarget {
    GatewayDialTarget {
        bind_addr: config.bind_addr,
        quic_addr: config.gateway_addr,
        tcp_addr: config.tcp_gateway_addr.unwrap_or(config.gateway_addr),
        server_name: config.server_name.clone(),
        ca_cert: config.ca_cert.clone(),
        handshake_timeout: config.timeout,
        session_timeout: config.timeout,
        // The SDK does not dial the WebSocket carrier for a native device until a gateway
        // listener accepts the native binding on it and its `Open.transport_kind` is specified.
        websocket: None,
        #[cfg(all(feature = "http-connect-proxy", not(windows)))]
        http_proxy: config.http_proxy.clone(),
    }
}

pub(crate) async fn open_auto_raced(
    config: &GatewaySessionConfig,
) -> Result<OpenedTransport, SdkError> {
    let monitor = &config.network_monitor;
    let (network, plan) = monitor.auto_plan(config.has_http_proxy(), Instant::now());
    match dial_gateway(dial_target(config), &plan).await {
        Ok(dialed) => {
            let carrier = dialed.carrier();
            monitor.record_success(network, carrier, Instant::now());
            opened_transport(dialed, carrier)
        }
        Err(error) => {
            // Whatever was remembered did not work now; race every carrier next time.
            monitor.record_dial_failure(network);
            tracing::warn!(
                gateway_addr = %config.gateway_addr,
                network_blocked = error.is_network_blocked(),
                "gateway unreachable on every carrier"
            );
            Err(SdkError::from(error.into_transport_error()))
        }
    }
}

/// Connect with an HTTP proxy configured. QUIC cannot use the proxy, so an explicit `Quic`
/// kind is refused and every other kind uses TCP + TLS inside the tunnel.
pub(crate) async fn open_through_http_proxy(
    config: &GatewaySessionConfig,
) -> Result<OpenedTransport, SdkError> {
    if config.transport_kind == GatewaySessionTransportKind::Quic {
        return Err(SdkError::Transport(ramflux_transport::TransportError::UnsupportedOperation {
            operation: "QUIC through an HTTP proxy",
        }));
    }
    let plan = ramflux_transport::DialPlan::single(CarrierKind::TcpTls);
    match dial_gateway(dial_target(config), &plan).await {
        Ok(dialed) => opened_transport(dialed, CarrierKind::TcpTls),
        Err(error) => Err(SdkError::from(error.into_transport_error())),
    }
}

fn opened_transport(
    dialed: DialedGateway,
    carrier: CarrierKind,
) -> Result<OpenedTransport, SdkError> {
    let (client, stream) = dialed.into_parts();
    match (carrier, client) {
        (CarrierKind::Quic, Some(client)) => Ok((
            GatewaySessionClientTransport::Quic { _client: client },
            stream,
            GatewaySessionTransportKind::Quic,
        )),
        (CarrierKind::TcpTls, None) => Ok((
            GatewaySessionClientTransport::TcpTls { _client: ramflux_transport::TcpTlsGatewayClient },
            stream,
            GatewaySessionTransportKind::TcpTls,
        )),
        // Unreachable while `dial_target` sets no WebSocket endpoint; refuse rather than
        // report a carrier under another carrier's `transport_kind`.
        _ => Err(SdkError::Transport(ramflux_transport::TransportError::UnsupportedOperation {
            operation: "gateway carrier without a native transport kind",
        })),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::gateway::{ConnectionRace, GatewayQuicEndpointConfig};
    use std::path::PathBuf;
    use std::time::Duration;

    fn unreachable_auto_config() -> GatewaySessionConfig {
        // TEST-NET-1 (RFC 5737) is never routed.
        let mut config = GatewaySessionConfig::auto(GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse().expect("bind addr"),
            gateway_addr: "192.0.2.1:443".parse().expect("gateway addr"),
            server_name: "gateway.invalid".to_owned(),
            ca_cert: PathBuf::from("/nonexistent/ca.pem"),
            principal_id: "principal_test".to_owned(),
            device_id: "device_test".to_owned(),
            target_delivery_id: "target_test".to_owned(),
            prekey_http_url: None,
        })
        .with_connection_race(ConnectionRace::Raced);
        config.timeout = Duration::from_millis(200);
        config
    }

    #[test]
    fn auto_stays_serial_unless_the_host_opts_in() {
        let config = GatewaySessionConfig::auto(GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse().expect("bind addr"),
            gateway_addr: "192.0.2.1:443".parse().expect("gateway addr"),
            server_name: "gateway.invalid".to_owned(),
            ca_cert: PathBuf::from("/nonexistent/ca.pem"),
            principal_id: "principal_test".to_owned(),
            device_id: "device_test".to_owned(),
            target_delivery_id: "target_test".to_owned(),
            prekey_http_url: None,
        });
        assert_eq!(config.connection_race, ConnectionRace::Serial);
        assert!(!config.has_http_proxy());
    }

    #[test]
    fn dial_target_uses_one_server_name_and_one_pinned_ca_for_every_carrier() {
        let config = unreachable_auto_config();
        let target = dial_target(&config);
        assert_eq!(target.server_name, config.server_name);
        assert_eq!(target.ca_cert, config.ca_cert);
        assert_eq!(target.quic_addr, config.gateway_addr);
        assert_eq!(target.tcp_addr, config.gateway_addr);
        assert!(target.websocket.is_none());
    }

    #[tokio::test]
    async fn failed_race_forgets_the_remembered_carrier() {
        let config = unreachable_auto_config();
        let network = config.network_monitor.current_network();
        config.network_monitor.record_success(network, CarrierKind::TcpTls, Instant::now());
        assert!(open_auto_raced(&config).await.is_err());
        assert_eq!(config.network_monitor.remembered_carrier_label(), None);
    }
}
