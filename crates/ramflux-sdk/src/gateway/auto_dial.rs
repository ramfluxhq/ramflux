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
    async fn with_udp_dropped_tcp_tls_wins_and_is_remembered_for_that_network_only()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{NetworkChangeKind, NetworkKey};
        use ramflux_transport::GatewaySessionFrameSink;
        use tokio::io::AsyncReadExt;

        let dir = tempfile::tempdir()?;
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = ramflux_transport::MeshTlsConfig {
            ca_cert: dir.path().join("ca.pem"),
            service_cert: dir.path().join("server.pem"),
            service_key: dir.path().join("server.key"),
        };
        std::fs::write(&tls.ca_cert, generated.cert.pem())?;
        std::fs::write(&tls.service_cert, generated.cert.pem())?;
        std::fs::write(&tls.service_key, generated.signing_key.serialize_pem())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            ramflux_transport::tcp_gateway_server_config(&tls)?,
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let mut stream = acceptor.accept(socket).await?;
            // Hold the session until the client drops it.
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
            Ok::<(), std::io::Error>(())
        });
        // A bound UDP socket that never answers: QUIC to it is silently dropped.
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0")?;

        let mut config = GatewaySessionConfig::auto(GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse()?,
            gateway_addr: blackhole.local_addr()?,
            server_name: "localhost".to_owned(),
            ca_cert: tls.ca_cert.clone(),
            principal_id: "principal_test".to_owned(),
            device_id: "device_test".to_owned(),
            target_delivery_id: "target_test".to_owned(),
            prekey_http_url: None,
        })
        .with_tcp_gateway_addr(tcp_addr)
        .with_connection_race(ConnectionRace::Raced);
        config.timeout = Duration::from_secs(5);
        let office = NetworkKey::from_host_label(b"wifi:office");
        config.network_monitor.on_network_changed(NetworkChangeKind::Available(office));

        let started = Instant::now();
        let (_transport, stream, kind) = open_auto_raced(&config).await?;
        assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
        assert_eq!(kind, GatewaySessionTransportKind::TcpTls);
        // The binding material comes from the winning connection itself.
        assert!(stream.custody_exporter(&[9; 32]).is_ok());
        assert_eq!(config.network_monitor.remembered_carrier_label(), Some("tcp_tls"));
        let (_, plan) = config.network_monitor.auto_plan(false, Instant::now());
        assert!(!plan.contains(CarrierKind::Quic));

        // A different network has no memory and races QUIC again.
        let cell = NetworkKey::from_host_label(b"cell:1");
        config.network_monitor.on_network_changed(NetworkChangeKind::Changed(cell));
        assert_eq!(config.network_monitor.remembered_carrier_label(), None);
        let (_, plan) = config.network_monitor.auto_plan(false, Instant::now());
        assert!(plan.contains(CarrierKind::Quic));

        drop(stream);
        server.await??;
        Ok(())
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
