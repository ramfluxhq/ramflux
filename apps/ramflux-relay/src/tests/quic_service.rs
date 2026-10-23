// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::config::validate_relay_client_quic_tls;
use crate::quic_service::{RelayClientQuicMetrics, relay_client_quic_dispatch};
use std::time::Duration;

use crate::test_support::{
    V3_AUDIENCE_NODE, V3_NOW, V3_OWNER_SEED, client_quic_object_request, client_quic_request,
    issue_test_ca_and_service_cert, temp_cert_root, test_config, v3_envelope_body, v3_pinned_cache,
    v3_pk, v3_state_with, v3_stored_chunk, v3_temp_store,
};

use ramflux_node_core::ObjectRelayCapability::Get;
use std::path::Path;

#[test]
fn relay_client_quic_dispatch_records_ingress_and_object_rejections() -> Result<(), String> {
    let metrics = RelayClientQuicMetrics::default();
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;

    // Health: served (200), counts as ingress, not an object rejection.
    assert_eq!(
        relay_client_quic_dispatch(
            &client_quic_request("GET", "/healthz"),
            &metrics,
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        200
    );
    // Every bodyless object route is rejected by the v3 gate (401) and counted as a rejection.
    for path in [
        "/relay/v1/object/put_chunk",
        "/relay/v1/object/get_chunk",
        "/relay/v1/object/ack",
        "/relay/v1/object/tombstone",
    ] {
        assert_eq!(
            relay_client_quic_dispatch(
                &client_quic_request("POST", path),
                &metrics,
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            401,
            "object route {path} must fail closed"
        );
    }
    // A fully verified get reaches the data plane (200): ingress, not a rejection.
    assert_eq!(
        relay_client_quic_dispatch(
            &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
            &metrics,
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        200
    );
    // Unknown route: 404, ingress only.
    assert_eq!(
        relay_client_quic_dispatch(
            &client_quic_request("POST", "/nope"),
            &metrics,
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        404
    );

    assert_eq!(metrics.ingress_total(), 7, "every request must count as ingress");
    assert_eq!(
        metrics.object_rejected_total(),
        4,
        "only the four 401 object rejections count; the served get does not"
    );
    Ok(())
}

#[test]
fn relay_client_quic_endpoint_binds_with_valid_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_cert_root("relay_client_quic_bind")?;
    let certs = issue_test_ca_and_service_cert(&root, "node-relay-a", "ramflux-relay")?;
    let config = test_config(&certs.tls, "unused-retention:0");
    let server_config = validate_relay_client_quic_tls(&config)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse::<std::net::SocketAddr>()?)?;
        let addr = endpoint.local_addr()?;
        assert_ne!(addr.port(), 0, "bound client QUIC endpoint must have a concrete port");
        endpoint.close(0_u32.into(), b"test");
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[test]
fn relay_client_quic_health_round_trips_over_real_framing() -> Result<(), Box<dyn std::error::Error>>
{
    let root = temp_cert_root("relay_client_quic_framing")?;
    let certs = issue_test_ca_and_service_cert(&root, "node-relay-a", "ramflux-relay")?;
    let config = test_config(&certs.tls, "unused-retention:0");
    let server_config = validate_relay_client_quic_tls(&config)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse::<std::net::SocketAddr>()?)?;
        let addr = endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            let connecting = endpoint
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("QUIC server did not receive a connection"))?;
            let connection = connecting.await?;
            let (mut send, mut recv) = connection.accept_bi().await?;
            let request: ramflux_transport::GatewayQuicRequest =
                ramflux_transport::read_quic_json_frame(&mut recv).await?;
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/healthz");
            ramflux_transport::write_quic_json_frame(
                &mut send,
                &ramflux_transport::GatewayQuicResponse {
                    status: 200,
                    body: serde_json::json!({ "status": "ok" }),
                },
            )
            .await?;
            // Keep the endpoint alive long enough for the client to consume the final frame.
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<(), anyhow::Error>(())
        });
        let client = ramflux_transport::QuicGatewayClient::connect(
            "127.0.0.1:0".parse()?,
            addr,
            "ramflux-relay",
            Path::new(&certs.tls.ca_cert),
            Duration::from_secs(3),
        )
        .await?;
        let response = client.request(&client_quic_request("GET", "/healthz")).await;
        let server_result = server.await?;
        server_result?;
        let response = response?;
        assert_eq!(response.status, 200);
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}
