// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transport backends for `grpc_h2`, `quic_quinn`, and `https_json`.

mod backend;
#[cfg(all(target_os = "linux", feature = "compio-gateway"))]
mod compio_gateway;
#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
mod compio_mesh;
mod error;
mod loopback;
mod mesh_http;
mod mesh_quic;
mod mesh_tls;
mod perf_metrics;
mod policy;
mod quic_gateway;
mod tls_config;
mod types;

pub use backend::{GrpcH2Backend, HttpsJsonBackend, QuicQuinnBackend};
#[cfg(all(target_os = "linux", feature = "compio-gateway"))]
pub use compio_gateway::{
    CompioGatewayBidiStream, CompioGatewayQuicConnection, CompioGatewayQuicServer,
    CompioGatewayRecvStream, CompioGatewaySendStream,
};
#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
pub use compio_mesh::{
    CompioMeshQuicAcceptedRequest, CompioMeshQuicAcceptedWireRequest, CompioMeshQuicConnection,
    CompioMeshQuicPostcardAcceptedRequest, CompioMeshQuicServer,
    compio_mesh_quic_post_json_with_peer_ca_pems,
};
pub use error::TransportError;
pub use loopback::transport_submit_result;
pub use mesh_http::{
    MeshHttpClient, close_mesh_server_stream, mesh_http_get_json, mesh_http_post_json,
    mesh_http_post_json_with_peer_ca_pems, read_mesh_http_request, write_mesh_json_response,
    write_mesh_text_response,
};
pub use mesh_quic::{
    MeshQuicAcceptedRequest, MeshQuicAcceptedWireRequest, MeshQuicConnection,
    MeshQuicPostcardAcceptedRequest, MeshQuicServer, mesh_quic_post_json_with_peer_ca_pems,
    mesh_quic_post_json_with_peer_ca_pems_async, mesh_quic_post_postcard_with_peer_ca_pems_async,
};
pub use mesh_tls::{
    MeshTlsAcceptedStream, MeshTlsServer, MeshTlsServerStream, extract_spiffe_uri_from_certificate,
};
pub use perf_metrics::{MeshHttpPerfSnapshot, mesh_perf_reset, mesh_perf_snapshot};
pub use policy::{
    ShutdownDrain, ShutdownDrainPermit, TransportBackpressure, TransportBackpressurePermit,
    TransportRetryPolicy, retry_with_policy,
};
pub use quic_gateway::{
    GatewaySessionFrameSink, GatewaySessionFrameSource, GatewaySessionTransport,
    GatewayTcpTlsStream, QuicGatewayBidiStream, QuicGatewayClient, TcpTlsGatewayBidiStream,
    TcpTlsGatewayClient, read_gateway_session_json, read_quic_json_frame,
    write_gateway_session_json, write_quic_json_frame, write_quic_json_message,
};
pub use tls_config::{
    mesh_server_config, quic_gateway_client_config, quic_gateway_server_config,
    tcp_gateway_client_config, tcp_gateway_server_config,
};
pub use types::{
    AckFrame, AuthRequest, BackendKind, BackendProductionStatus, CursorFrame, DeliveryFrame,
    EnvelopeBatch, GatewayQuicRequest, GatewayQuicResponse, MeshHttpRequest, MeshTlsConfig,
    NackFrame, ObjectChunkStream, SendEnvelopeRequest, SubmitEnvelopeRequest, SubmitEnvelopeResult,
    TransportBackend, TransportFuture, TransportListener, TransportSession,
};

pub const CRATE_NAME: &str = "ramflux-transport";

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}

#[cfg(test)]
mod tests {
    use rustls::{ClientConfig, ServerConfig};

    use crate::tls_config::ensure_ring_crypto_provider_installed;
    use crate::{BackendKind, BackendProductionStatus};

    #[test]
    fn rustls_ring_provider_allows_mesh_config_builders() {
        ensure_ring_crypto_provider_installed();
        drop(ServerConfig::builder());
        drop(ClientConfig::builder());
    }

    #[test]
    fn backend_production_statuses_are_explicit() {
        assert!(matches!(
            BackendKind::GrpcH2.production_status(),
            BackendProductionStatus::NonProduction { .. }
        ));
        assert!(matches!(
            BackendKind::QuicQuinn.production_status(),
            BackendProductionStatus::Production { .. }
        ));
        assert!(matches!(
            BackendKind::HttpsJson.production_status(),
            BackendProductionStatus::Production { .. }
        ));
    }
}
