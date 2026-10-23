// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::config::{parse_client_quic_addr, validate_relay_client_quic_tls};

use crate::test_support::{issue_test_ca_and_service_cert, temp_cert_root, test_config};

#[test]
fn relay_client_quic_addr_requires_valid_explicit_config() {
    assert!(parse_client_quic_addr(None).is_err());
}

#[test]
fn relay_client_quic_addr_rejects_empty_and_invalid_values() {
    assert!(parse_client_quic_addr(Some(" ")).is_err());
    assert!(parse_client_quic_addr(Some("not-an-address")).is_err());
}

#[test]
fn relay_client_quic_addr_accepts_socket_address() -> anyhow::Result<()> {
    let address = parse_client_quic_addr(Some("127.0.0.1:0"))?;
    assert_eq!(address.port(), 0);
    Ok(())
}

#[test]
fn validate_relay_client_quic_tls_fails_closed_on_missing_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    // Missing cert/key files: fail closed with a clear configuration error.
    let missing = ramflux_transport::MeshTlsConfig {
        ca_cert: "/nonexistent/relay-ca.pem".into(),
        service_cert: "/nonexistent/relay.pem".into(),
        service_key: "/nonexistent/relay-key.pem".into(),
    };
    let missing_config = test_config(&missing, "unused-retention:0");
    assert!(validate_relay_client_quic_tls(&missing_config).is_err());

    // Present, valid server-auth credentials: accepted.
    let root = temp_cert_root("relay_client_quic_tls")?;
    let certs = issue_test_ca_and_service_cert(&root, "node-relay-a", "ramflux-relay")?;
    let valid_config = test_config(&certs.tls, "unused-retention:0");
    validate_relay_client_quic_tls(&valid_config)?;
    Ok(())
}
