// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit configuration of central push (`[push_central]` in the service TOML).
//! An absent section means direct push; a present section switches the whole node to central push.
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::NodeCoreError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodePushConfig {
    /// Must be `true` when the section is present; there is no "present but off" state.
    pub enabled: bool,
    /// Absolute path of the push state file written by federation (`ks`, `dir.served`, caps).
    pub state_file: PathBuf,
    /// Absolute path of the Unix socket federation serves handoff requests on.
    pub handoff_socket: PathBuf,
}

#[derive(Deserialize)]
struct NodePushFile {
    #[serde(default)]
    push_central: Option<NodePushConfig>,
}

/// Reads `--config <path>` from the arguments and returns the `[push_central]` section, if any.
/// # Errors
/// Returns a configuration error for unreadable files, malformed TOML or invalid sections.
pub fn load_node_push_config(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<NodePushConfig>, NodeCoreError> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let path = args.next().ok_or(NodeCoreError::MissingConfigPath)?;
            return load_node_push_config_file(Path::new(&path));
        }
    }
    Ok(None)
}

/// # Errors
/// Returns a configuration error for unreadable files, malformed TOML or invalid sections.
pub fn load_node_push_config_file(path: &Path) -> Result<Option<NodePushConfig>, NodeCoreError> {
    let text =
        std::fs::read_to_string(path).map_err(|error| invalid(format!("read config: {error}")))?;
    let file: NodePushFile =
        toml::from_str(&text).map_err(|error| invalid(format!("parse config: {error}")))?;
    file.push_central.map(validate).transpose()
}

/// # Errors
/// Returns a configuration error when a path is relative or the section is switched off.
pub fn validate(config: NodePushConfig) -> Result<NodePushConfig, NodeCoreError> {
    if !config.enabled {
        return Err(invalid(
            "push_central.enabled must be true when the section is present".into(),
        ));
    }
    if !config.state_file.is_absolute() || !config.handoff_socket.is_absolute() {
        return Err(invalid(
            "push_central.state_file and handoff_socket must be absolute paths".into(),
        ));
    }
    Ok(config)
}

fn invalid(message: String) -> NodeCoreError {
    NodeCoreError::InvalidConfiguration(message)
}
