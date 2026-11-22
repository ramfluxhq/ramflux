// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pin a peer from its signed server record the first time a forward needs it.
//!
//! The caller does not supply the URL. Production fetches
//! `https://<node-id>/.well-known/ramflux/server`. A loopback test socket, when configured,
//! is the only other destination. A key change is refused. Pins are not evicted.

use std::net::SocketAddr;

use ramflux_node_core::FederationServerRecord;

use crate::state::SharedFederationTrustState;

const RECORD_LIMIT: usize = 1024 * 1024;
const SOCKET_FILE_LIMIT: usize = 128;

/// The local node id and the capabilities it is willing to negotiate.
pub(crate) struct LocalNode {
    pub(crate) node_id: String,
    pub(crate) capabilities: Vec<String>,
}

/// Learn `target` when it is not already an active pinned route.
///
/// # Errors
/// Returns an error when the peer is blocked, the record fails verification, egress refuses
/// the address, the pin table or the hourly rate is full, or the signed key changed.
pub(crate) fn ensure_forward_pin(
    target: &str,
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
    local: &LocalNode,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if !node_id_ok(target) {
        return Err(invalid("federation peer id rejected"));
    }
    let now = crate::now_unix_seconds()?;
    let snapshot = state.snapshot()?;
    if snapshot.peer_pin_blocked(target, now) {
        return Err(invalid("federation node blocked"));
    }
    if snapshot.can_deliver_to(target, now) && snapshot.pinned_peer_ca_cert_pem(target).is_some() {
        return Ok(());
    }
    let (record, test_fetch) = fetch_record(target, now)?;
    if record.node_id != target {
        return Err(invalid("well-known node_id mismatch"));
    }
    ramflux_transport::public_mesh_endpoint(&record.node_endpoint, test_fetch)
        .map_err(|error| invalid(&error.to_string()))?;
    install(state, store, local, &record, now)
}

fn fetch_record(
    target: &str,
    now: u64,
) -> Result<(FederationServerRecord, bool), ramflux_node_core::NodeCoreError> {
    let socket = test_socket()?;
    let test_fetch = socket.is_some();
    let bytes = ramflux_transport::fetch_server_well_known(target, socket)
        .map_err(|error| invalid(&error.to_string()))?;
    if bytes.len() > RECORD_LIMIT {
        return Err(invalid("federation discovery record exceeds size limit"));
    }
    let record: FederationServerRecord =
        ramflux_protocol::parse_i_json(&bytes).map_err(|error| invalid(&error.to_string()))?;
    ramflux_node_core::verify_federation_server_record(&record, now)?;
    Ok((record, test_fetch))
}

fn install(
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
    local: &LocalNode,
    record: &FederationServerRecord,
    now: u64,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    state.update_and_save(store, |trust| {
        trust.admit_new_peer_pin(&record.node_id, now)?;
        let discovered = trust.resolve_discovery_result(
            &ramflux_node_core::FederationDiscoveryRequest {
                node_id: record.node_id.clone(),
                now,
                invite_endpoint: None,
                well_known_url: None,
                dns_srv_records: Vec::new(),
                address_records: Vec::new(),
                directory_endpoint: None,
            },
            Some(record),
            None,
        )?;
        let node_public_key_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            discovered.node_public_key.as_bytes(),
        );
        let proof = format!("{}:{}:{now}", local.node_id, discovered.node_id);
        let route = ramflux_node_core::FederationPeerRoute {
            node_id: discovered.node_id.clone(),
            endpoint: discovered.node_endpoint.clone(),
            node_public_key_hash,
            node_capabilities: discovered.node_capabilities.clone(),
            trust_status: ramflux_node_core::FederationTrustStatus::Invited,
            updated_at: now,
            expires_at: discovered.expires_at,
            route_update_proof_hash: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::FEDERATION_HANDSHAKE,
                proof.as_bytes(),
            ),
        };
        let mut peer_capabilities: Vec<String> = discovered
            .node_capabilities
            .iter()
            .filter(|capability| local.capabilities.iter().any(|allowed| allowed == *capability))
            .cloned()
            .collect();
        peer_capabilities.sort();
        if peer_capabilities.is_empty() {
            peer_capabilities.push("opaque_delivery".to_owned());
        }
        trust.admit_verified_discovered_peer(route, &peer_capabilities, &local.capabilities)?;
        Ok(())
    })
}

fn test_socket() -> Result<Option<SocketAddr>, ramflux_node_core::NodeCoreError> {
    if let Ok(value) = ramflux_node_core::environment::var("RAMFLUX_FEDERATION_EGRESS_TEST_SOCKET")
    {
        return parse_test_socket(value.trim()).map(Some);
    }
    let Ok(path) =
        ramflux_node_core::environment::var("RAMFLUX_FEDERATION_EGRESS_TEST_SOCKET_FILE")
    else {
        return Ok(None);
    };
    match std::fs::read(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(invalid(&error.to_string())),
        Ok(bytes) if bytes.len() > SOCKET_FILE_LIMIT => {
            Err(invalid("federation egress test socket rejected"))
        }
        Ok(bytes) => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| invalid("federation egress test socket rejected"))?;
            let text = text.trim();
            if text.is_empty() { Ok(None) } else { parse_test_socket(text).map(Some) }
        }
    }
}

fn parse_test_socket(value: &str) -> Result<SocketAddr, ramflux_node_core::NodeCoreError> {
    let socket: SocketAddr =
        value.parse().map_err(|_| invalid("federation egress test socket rejected"))?;
    if !socket.ip().is_loopback() || socket.port() == 0 {
        return Err(invalid("federation egress test socket must be loopback"));
    }
    Ok(socket)
}

fn node_id_ok(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn invalid(message: &str) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(message.to_owned())
}
