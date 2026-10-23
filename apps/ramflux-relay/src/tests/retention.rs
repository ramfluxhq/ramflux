// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[cfg(feature = "itest-object-v2")]
use crate::retention::{
    DEFAULT_RETENTION_ASYNC_ENDPOINT, RetentionAsyncMeshClient, RetentionMeshClient,
    register_object_relay_ttl, retention_async_mesh_client_from_endpoint_value,
};
use std::time::Duration;

use crate::test_support::{
    issue_test_ca_and_service_cert, spawn_retention_blocking_mesh_echo_server, temp_cert_root,
    test_config, test_error, test_relay_chunk_entry,
};

#[cfg(feature = "itest-object-v2")]
#[test]
fn retention_async_mesh_client_defaults_on_and_explicit_close_disables_it()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_cert_root("relay_retention_default")?;
    let certs = issue_test_ca_and_service_cert(&root, "node-retention-a", "ramflux-relay")?;
    let config = test_config(&certs.tls, "unused-retention:18443");

    let client = retention_async_mesh_client_from_endpoint_value(&config, None)?
        .ok_or_else(|| test_error("retention async mesh should default to QUIC"))?;
    assert_eq!(client.endpoint, DEFAULT_RETENTION_ASYNC_ENDPOINT);
    assert_eq!(client.server_name, "ramflux-retention");
    assert_eq!(client.peer_ca_pems, vec![certs.ca_pem.clone()]);

    assert!(
        retention_async_mesh_client_from_endpoint_value(&config, Some(""))
            .is_ok_and(|value| value.is_none())
    );
    assert!(
        retention_async_mesh_client_from_endpoint_value(&config, Some("0"))
            .is_ok_and(|value| value.is_none())
    );
    assert!(
        retention_async_mesh_client_from_endpoint_value(&config, Some("off"))
            .is_ok_and(|value| value.is_none())
    );
    assert_eq!(
        retention_async_mesh_client_from_endpoint_value(
            &config,
            Some("${RAMFLUX_RETENTION_ASYNC_ENDPOINT:-}")
        )?
        .ok_or_else(|| test_error("literal compose endpoint should use default"))?
        .endpoint,
        DEFAULT_RETENTION_ASYNC_ENDPOINT
    );
    Ok(())
}

#[cfg(feature = "itest-object-v2")]
#[test]
fn register_object_relay_ttl_falls_back_when_quic_transport_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_cert_root("relay_retention_fallback")?;
    let relay = issue_test_ca_and_service_cert(&root, "node-retention-a", "ramflux-relay")?;
    let retention = issue_test_ca_and_service_cert(&root, "node-retention-a", "ramflux-retention")?;
    let (endpoint, received) =
        spawn_retention_blocking_mesh_echo_server(retention.tls.clone(), relay.ca_pem.clone())?;
    let mut relay_client_tls = relay.tls.clone();
    relay_client_tls.ca_cert.clone_from(&retention.tls.ca_cert);
    let config = test_config(&relay_client_tls, &endpoint);
    let client = RetentionMeshClient {
        blocking: ramflux_transport::MeshHttpClient::new(),
        async_mesh: Some(RetentionAsyncMeshClient {
            endpoint: "127.0.0.1:1".to_owned(),
            server_name: "ramflux-retention".to_owned(),
            tls: relay_client_tls,
            peer_ca_pems: vec![retention.ca_pem],
        }),
    };
    let entry = test_relay_chunk_entry();

    register_object_relay_ttl(&config, &client, &entry, 1_000)?;

    let request = received.recv_timeout(Duration::from_secs(5))?;
    assert!(request.record.record_id.ends_with(&entry.chunk_id));
    assert_eq!(request.record.subject_hash, entry.object_id);
    Ok(())
}
