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
    snapshot.admit_new_peer_pin(target, now)?;
    admit_discovery_attempt(now)?;
    let record = fetch_record(target, now)?;
    if record.node_id != target {
        return Err(invalid("well-known node_id mismatch"));
    }
    checked_forward_endpoint(target, &record.node_endpoint)?;
    install(state, store, local, &record, now)
}

pub(crate) fn fetch_record(
    target: &str,
    now: u64,
) -> Result<FederationServerRecord, ramflux_node_core::NodeCoreError> {
    fetch_record_until(target, now, std::time::Instant::now() + std::time::Duration::from_secs(10))
}

pub(crate) fn fetch_record_until(
    target: &str,
    now: u64,
    deadline: std::time::Instant,
) -> Result<FederationServerRecord, ramflux_node_core::NodeCoreError> {
    fetch_record_classified(target, now, deadline).map_err(|failure| failure.error)
}

pub(crate) struct RecordFailure {
    pub(crate) error: ramflux_node_core::NodeCoreError,
    pub(crate) authoritative: bool,
}

pub(crate) fn fetch_record_classified(
    target: &str,
    now: u64,
    deadline: std::time::Instant,
) -> Result<FederationServerRecord, RecordFailure> {
    let bytes = fetch_record_bytes(target, deadline)
        .map_err(|error| RecordFailure { error, authoritative: false })?;
    decode_record(&bytes, now).map_err(|error| RecordFailure { error, authoritative: true })
}

fn fetch_record_bytes(
    target: &str,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, ramflux_node_core::NodeCoreError> {
    let fixture = ramflux_transport::test_node_endpoints(target)
        .map_err(|error| invalid(&error.to_string()))?;
    let socket = match fixture {
        Some(fixture) => Some(fixture.discovery),
        None => test_socket()?,
    };
    let bytes = ramflux_transport::fetch_server_well_known_until(target, socket, deadline)
        .map_err(|error| invalid(&error.to_string()))?;
    Ok(bytes)
}

fn decode_record(
    bytes: &[u8],
    now: u64,
) -> Result<FederationServerRecord, ramflux_node_core::NodeCoreError> {
    if bytes.len() > RECORD_LIMIT {
        return Err(invalid("federation discovery record exceeds size limit"));
    }
    let record: FederationServerRecord =
        ramflux_protocol::parse_i_json(bytes).map_err(|error| invalid(&error.to_string()))?;
    ramflux_node_core::verify_federation_server_record(&record, now)?;
    Ok(record)
}

fn install(
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
    local: &LocalNode,
    record: &FederationServerRecord,
    now: u64,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    state.update_and_save(store, |trust| install_candidate(trust, local, record, now))
}

pub(crate) fn install_candidate(
    trust: &mut ramflux_node_core::FederationTrustState,
    local: &LocalNode,
    record: &FederationServerRecord,
    now: u64,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if trust.peer_pin_blocked(&record.node_id, now) {
        return Err(invalid("federation node blocked"));
    }
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
    trust.admit_verified_discovered_peer(route, &peer_capabilities, &local.capabilities)?;
    Ok(())
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

pub(crate) fn node_id_ok(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && value.parse::<std::net::IpAddr>().is_err()
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn invalid(message: &str) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(message.to_owned())
}

/// Resolve once per forward and pass only the checked numeric socket to both transports.
pub(crate) fn checked_forward_endpoint(
    target: &str,
    endpoint: &str,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    checked_forward_endpoint_until(
        target,
        endpoint,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
}

pub(crate) fn checked_forward_endpoint_until(
    target: &str,
    endpoint: &str,
    deadline: std::time::Instant,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    let fixture = ramflux_transport::test_node_endpoints(target)
        .map_err(|error| invalid(&error.to_string()))?;
    // Only an exact node/socket mapping can authorize loopback mesh egress.
    let allow_loopback = fixture.is_some();
    let socket = ramflux_transport::checked_mesh_address_until(endpoint, allow_loopback, deadline)
        .map_err(|error| invalid(&error.to_string()))?;
    if socket.ip().is_loopback() && fixture.is_some_and(|node| node.mesh != socket) {
        return Err(invalid("test mesh socket does not match configured node"));
    }
    Ok(socket.to_string())
}

fn admit_discovery_attempt(now: u64) -> Result<(), ramflux_node_core::NodeCoreError> {
    // Charge before network IO, including invalid records and failed fetches. Pin caps are
    // independently checked before the fetch and again in the durable installation transaction.
    static ATTEMPTS: std::sync::Mutex<std::collections::VecDeque<u64>> =
        std::sync::Mutex::new(std::collections::VecDeque::new());
    let mut attempts = ATTEMPTS.lock().map_err(|_| invalid("discovery admission unavailable"))?;
    while attempts.front().is_some_and(|time| now.saturating_sub(*time) >= 3600) {
        attempts.pop_front();
    }
    if attempts.len() >= 32 {
        return Err(invalid("federation discovery attempt rate is full"));
    }
    attempts.push_back(now);
    Ok(())
}
