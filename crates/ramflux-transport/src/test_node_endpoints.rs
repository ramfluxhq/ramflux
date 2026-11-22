// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit local fixtures for reserved `.test` names; production DNS and TLS stay unchanged.
use crate::TransportError;
use std::{collections::BTreeMap, io::Read, net::SocketAddr};

const MAX_FILE_BYTES: u64 = 16 * 1024;
const MAX_NODES: usize = 16;

/// Exact sockets configured by the local-stack harness, never supplied by a peer.
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestNodeEndpoints {
    pub discovery: SocketAddr,
    pub mesh: SocketAddr,
}

/// Look up an explicitly configured reserved test name without performing DNS.
///
/// The optional `RAMFLUX_TEST_NODE_ENDPOINTS_FILE` is bounded JSON mapping names to
/// `{ "discovery": "127.0.0.1:port", "mesh": "127.0.0.1:port" }`. Every socket must be
/// loopback with a nonzero port. No match means the ordinary production path.
/// # Errors
/// Refuses malformed, oversized or non-loopback fixture configuration.
pub fn test_node_endpoints(node_id: &str) -> Result<Option<TestNodeEndpoints>, TransportError> {
    let Ok(file) = ramflux_core::environment::var("RAMFLUX_TEST_NODE_ENDPOINTS_FILE") else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    match std::fs::File::open(file) {
        Ok(file) => file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(invalid());
    }
    let nodes: BTreeMap<String, TestNodeEndpoints> =
        ramflux_protocol::parse_i_json(&bytes).map_err(|_| invalid())?;
    if nodes.len() > MAX_NODES {
        return Err(invalid());
    }
    for (name, endpoints) in &nodes {
        if !test_name(name)
            || [endpoints.discovery, endpoints.mesh]
                .iter()
                .any(|socket| !socket.ip().is_loopback() || socket.port() == 0)
        {
            return Err(invalid());
        }
    }
    Ok(nodes.get(node_id).copied())
}

/// Return the exact HTTP loopback origin for an explicitly mapped `.test` node.
///
/// Callers still verify the signed record's node id against the original requested name.
/// # Errors
/// Refuses invalid local fixture configuration; never disables TLS verification.
pub fn test_node_discovery_origin(node_id: &str) -> Result<Option<String>, TransportError> {
    Ok(test_node_endpoints(node_id)?.map(|node| format!("http://{}", node.discovery)))
}

fn test_name(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, suffix)| suffix == "test")
        && (6..=63).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn invalid() -> TransportError {
    TransportError::Http(
        "test node endpoints must map reserved names to exact loopback sockets".into(),
    )
}
