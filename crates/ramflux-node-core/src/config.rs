// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]

use crate::{NODE_SERVICE_SIGNING_SEED_ENV, NodeCoreError, RedactedString};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct NodeServiceConfig {
    pub node_id: String,
    pub service_id: String,
    pub redb_path: String,
    #[serde(default)]
    pub node_service_signing_seed_b64url: Option<RedactedString>,
    pub mesh: MeshConfig,
    #[serde(default)]
    pub gateway: Option<GatewayConfig>,
    #[serde(default)]
    pub signaling: Option<SignalingConfig>,
    #[serde(default)]
    pub relay: Option<RelayConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct MeshConfig {
    pub listen_addr: String,
    pub ca_cert: String,
    pub service_cert: String,
    pub service_key: String,
    pub allowed_service_ids: BTreeSet<String>,
    pub endpoints: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GatewayConfig {
    pub public_listen_addr: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SignalingConfig {
    pub turn_udp_addr: String,
    pub turn_tcp_addr: String,
    #[serde(default)]
    pub service_key_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RelayConfig {
    #[serde(default)]
    pub service_key_ref: Option<String>,
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn load_config(
    path: impl AsRef<Path>,
    expected_service_id: &str,
) -> Result<NodeServiceConfig, NodeCoreError> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .map_err(|source| NodeCoreError::ConfigRead { path: path.to_path_buf(), source })?;
    let mut config: NodeServiceConfig = toml::from_str(&contents)
        .map_err(|source| NodeCoreError::ConfigParse { path: path.to_path_buf(), source })?;
    apply_env_overrides(&mut config);
    validate_config(&config, expected_service_id)?;
    Ok(config)
}

fn apply_env_overrides(config: &mut NodeServiceConfig) {
    apply_node_id_override(config, std::env::var("RAMFLUX_NODE_ID").ok().as_deref());
    if let Ok(seed) = std::env::var(NODE_SERVICE_SIGNING_SEED_ENV)
        && !seed.trim().is_empty()
    {
        config.node_service_signing_seed_b64url = Some(RedactedString::new(seed));
    }
}

pub(crate) fn apply_node_id_override(config: &mut NodeServiceConfig, node_id: Option<&str>) {
    if let Some(node_id) = node_id
        && !node_id.trim().is_empty()
    {
        node_id.clone_into(&mut config.node_id);
    }
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn load_config_from_args(
    args: impl IntoIterator<Item = String>,
    expected_service_id: &str,
) -> Result<Option<NodeServiceConfig>, NodeCoreError> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let path = args.next().ok_or(NodeCoreError::MissingConfigPath)?;
            return load_config(path, expected_service_id).map(Some);
        }
    }
    Ok(None)
}

#[must_use]
pub fn effective_redb_path(config: &NodeServiceConfig) -> PathBuf {
    effective_redb_path_with_state_root(config, std::env::var("RAMFLUX_NODE_STATE_DIR").ok())
}

#[must_use]
pub fn effective_redb_path_with_state_root(
    config: &NodeServiceConfig,
    state_root: Option<String>,
) -> PathBuf {
    match state_root {
        Some(root) if !root.is_empty() => {
            PathBuf::from(root).join(format!("{}.redb", config.service_id))
        }
        _ => PathBuf::from(&config.redb_path),
    }
}

pub(crate) fn validate_config(
    config: &NodeServiceConfig,
    expected_service_id: &str,
) -> Result<(), NodeCoreError> {
    if config.service_id != expected_service_id {
        return Err(NodeCoreError::ServiceIdMismatch {
            expected: expected_service_id.to_owned(),
            actual: config.service_id.clone(),
        });
    }
    if !config.mesh.allowed_service_ids.contains(expected_service_id) {
        return Err(NodeCoreError::MissingAllowedServiceId(expected_service_id.to_owned()));
    }
    if config.mesh.endpoints.is_empty() {
        return Err(NodeCoreError::EmptyMeshEndpoints);
    }
    Ok(())
}
