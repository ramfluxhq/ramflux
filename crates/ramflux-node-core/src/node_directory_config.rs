// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit configuration of the central node directory (`[node_directory]` in the service TOML).
//! Nothing is compiled in: an absent section keeps the directory off. The directory needs
//! `[node_report]` (its centre and identity). The verify keys are the `directory_verify` list of
//! the centre pin bundle (`rfc-centre-pin-1`, one or two entries for rotation overlap).

use serde::Deserialize;
use std::path::Path;

use crate::NodeCoreError;

const MAX_VERIFY_KEYS: usize = 2;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NodeDirectorySanctionMode {
    /// Refuse outbound forwards to and inbound envelopes from `suspended`/`revoked` nodes.
    #[default]
    Refuse,
    /// Log sanctioned nodes; change nothing.
    Observe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeDirectoryVerifyKey {
    /// `key_id` the centre puts in the snapshot document (`^[a-z0-9-]{1,32}$`).
    pub key_id: String,
    /// Ed25519 public key of the directory signing key (base64url, 32 bytes).
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeDirectoryConfig {
    /// `directory_verify` of the centre pin bundle: 1..2 entries.
    pub verify: Vec<NodeDirectoryVerifyKey>,
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
/// Returns a configuration error when a verify key or key id is outside its grammar.
pub fn validate(config: NodeDirectoryConfig) -> Result<NodeDirectoryConfig, NodeCoreError> {
    if config.verify.is_empty() || config.verify.len() > MAX_VERIFY_KEYS {
        return Err(invalid("node_directory.verify must hold 1 or 2 keys".into()));
    }
    for key in &config.verify {
        let key_id_ok = !key.key_id.is_empty()
            && key.key_id.len() <= 32
            && key
                .key_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !key_id_ok {
            return Err(invalid(
                "node_directory.verify.key_id must match ^[a-z0-9-]{1,32}$".into(),
            ));
        }
        let bytes = ramflux_protocol::decode_base64url(&key.public_key)
            .map_err(|_| invalid("node_directory.verify.public_key must be base64url".into()))?;
        if bytes.len() != 32 {
            return Err(invalid("node_directory.verify.public_key must be 32 bytes".into()));
        }
    }
    Ok(config)
}

fn invalid(message: String) -> NodeCoreError {
    NodeCoreError::InvalidConfiguration(message)
}
