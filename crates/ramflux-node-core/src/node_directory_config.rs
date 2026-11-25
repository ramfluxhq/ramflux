// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit configuration of the central node directory (`[node_directory]` in the service TOML).
//! Nothing is compiled in: an absent section keeps the directory off. The directory needs
//! `[node_report]` (its centre and identity); the node holds only the directory's public key.

use serde::Deserialize;
use std::path::Path;

use crate::NodeCoreError;

const MAX_KEY_ID_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NodeDirectorySanctionMode {
    /// Refuse outbound forwards to and inbound envelopes from `s`/`r` nodes.
    #[default]
    Refuse,
    /// Log sanctioned nodes; change nothing.
    Observe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeDirectoryConfig {
    /// Ed25519 public key of the centre's directory signing key (base64url, 32 bytes).
    pub public_key: String,
    /// Identifier of that key; a snapshot naming another key is refused.
    pub key_id: String,
    #[serde(default)]
    pub sanction: NodeDirectorySanctionMode,
}

#[derive(Deserialize)]
struct NodeDirectoryFile {
    #[serde(default)]
    node_directory: Option<NodeDirectoryConfig>,
}

/// Reads `--config <path>` from the arguments and returns the `[node_directory]` section, if any.
/// # Errors
/// Returns a configuration error for unreadable files, malformed TOML or invalid sections.
pub fn load_node_directory_config(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<NodeDirectoryConfig>, NodeCoreError> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let path = args.next().ok_or(NodeCoreError::MissingConfigPath)?;
            return load_node_directory_config_file(Path::new(&path));
        }
    }
    Ok(None)
}

/// # Errors
/// Returns a configuration error for unreadable files, malformed TOML or invalid sections.
pub fn load_node_directory_config_file(
    path: &Path,
) -> Result<Option<NodeDirectoryConfig>, NodeCoreError> {
    let text =
        std::fs::read_to_string(path).map_err(|error| invalid(format!("read config: {error}")))?;
    let file: NodeDirectoryFile =
        toml::from_str(&text).map_err(|error| invalid(format!("parse config: {error}")))?;
    file.node_directory.map(validate).transpose()
}

/// # Errors
/// Returns a configuration error when the key or key id is outside its grammar.
pub fn validate(config: NodeDirectoryConfig) -> Result<NodeDirectoryConfig, NodeCoreError> {
    let key = ramflux_protocol::decode_base64url(&config.public_key)
        .map_err(|_| invalid("node_directory.public_key must be base64url".into()))?;
    if key.len() != 32 {
        return Err(invalid("node_directory.public_key must be 32 bytes".into()));
    }
    let key_id_ok = !config.key_id.is_empty()
        && config.key_id.len() <= MAX_KEY_ID_BYTES
        && config.key_id.bytes().all(|byte| byte.is_ascii_graphic());
    if !key_id_ok {
        return Err(invalid("node_directory.key_id must be 1-64 printable ASCII bytes".into()));
    }
    Ok(config)
}

fn invalid(message: String) -> NodeCoreError {
    NodeCoreError::InvalidConfiguration(message)
}
