// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed discovery refreshes do not reset node admission or freeze one timestamp's hash.
use super::*;
fn client_record(
    node: &MigrationNode,
    now: u64,
) -> TestResult<ramflux_protocol::WellKnownClientRecord> {
    let mut record = ramflux_protocol::WellKnownClientRecord {
        schema: ramflux_protocol::WELL_KNOWN_CLIENT_SCHEMA.into(),
        node_id: node.node_id().into(),
        node_public_key: node.public_key().into(),
        node_ca_cert_pem: "fixture-node-ca".into(),
        gateway_quic_addr: "127.0.0.1:9000".into(),
        gateway_tcp_addr: node.gateway_tcp_addr.clone(),
        gateway_server_name: "ramflux-gateway".into(),
        relay_quic_addr: "127.0.0.1:9001".into(),
        relay_server_name: "ramflux-relay".into(),
        prekey_http_url: "https://example.test".into(),
        signaling_turn_addr: "127.0.0.1:9002".into(),
        protocol_versions: vec!["v3".into()],
        client_capabilities: vec![crate::HOME_MIGRATION_CAPABILITY.into()],
        updated_at: now,
        expires_at: now + 60,
        signature: String::new(),
    };
    resign(&mut record)?;
    Ok(record)
}
fn resign(record: &mut ramflux_protocol::WellKnownClientRecord) -> TestResult {
    record.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::client_discovery_signing_bytes(record)?,
        [9; 32],
    );
    Ok(())
}
fn discovery_hash(record: &ramflux_protocol::WellKnownClientRecord) -> TestResult<String> {
    Ok(ramflux_protocol::custody::framed_hash(
        ramflux_protocol::domain::CUSTODY_OBJECT_HASH,
        record,
    )?)
}
#[test]
fn fresh_signed_discovery_hashes_share_configured_endpoints_and_the_node_job_limit() -> TestResult {
    let b = TestNode::with_registration("B", 9, false, false)?;
    let node = b.node.clone().require_client_discovery("fixture-node-ca".into())?;
    let first = client_record(&node, NOW)?;
    let next = client_record(&node, NOW + 1)?;
    assert_ne!(discovery_hash(&first)?, discovery_hash(&next)?);
    node.for_client_discovery(Some(&first), &discovery_hash(&first)?, NOW)?;
    let snapshot = node.for_client_discovery(Some(&next), &discovery_hash(&next)?, NOW + 1)?;
    let held =
        (0..16).map(|_| node.acquire_migration_verification()).collect::<Result<Vec<_>, _>>()?;
    assert!(matches!(
        snapshot.acquire_migration_verification(),
        Err(NodeCoreError::HomeMigration(Refusal::CapacityRefused))
    ));
    drop(held);
    assert!(snapshot.acquire_migration_verification().is_ok());
    Ok(())
}
#[test]
fn signed_discovery_cannot_substitute_another_node_gateway_ca_or_frozen_hash() -> TestResult {
    let b = TestNode::with_registration("B", 9, false, false)?;
    let node = b.node.clone().require_client_discovery("fixture-node-ca".into())?;
    let record = client_record(&node, NOW)?;
    assert!(node.for_client_discovery(None, &discovery_hash(&record)?, NOW).is_err());
    assert!(node.for_client_discovery(Some(&record), &hash(100), NOW).is_err());
    for field in 0..3 {
        let mut changed = record.clone();
        match field {
            0 => changed.node_id = "C".into(),
            1 => changed.gateway_tcp_addr = "127.0.0.1:9003".into(),
            _ => changed.node_ca_cert_pem = "another-fixture-ca".into(),
        }
        resign(&mut changed)?;
        assert!(
            node.for_client_discovery(Some(&changed), &discovery_hash(&changed)?, NOW).is_err()
        );
    }
    Ok(())
}
