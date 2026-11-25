// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit configuration of the central node-report sender (`[node_report]` in the service TOML).
//! Nothing is compiled in: an absent section means the node sends no reports.
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

use crate::NodeCoreError;

/// Upper bound of the centre identifier bytes (the frame carries it with a u16 length).
const MAX_CENTRE_ID_BYTES: usize = 128;
/// Largest integer a report body may carry (JSON integers are 0..2^53-1).
const MAX_KEY_GEN: u64 = (1 << 53) - 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeReportConfig {
    pub centre: NodeReportCentreConfig,
    /// Key generation the centre registered for this node key (`key_gen`, 1 until rotation).
    pub key_gen: u64,
    /// Operator-declared region. Absent: the hello carries no region (never inferred from an address).
    #[serde(default)]
    pub region: Option<NodeReportRegionConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeReportCentreConfig {
    /// `centre_id` the centre signs over; it names the whole central service.
    pub id: String,
    /// Edge address `host:port` (IP literal).
    pub addr: String,
    /// TLS server name the edge certificate must match.
    pub server_name: String,
    /// PEM CA certificate that pins the edge (the explicit trust anchor).
    pub ca_cert: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeReportRegionConfig {
    /// ISO 3166-1 alpha-2 upper case, or `ZZ` to withdraw a stored region.
    pub country: String,
    /// ISO 3166-2 code with the same country prefix; requires a real country (not `ZZ`).
    #[serde(default)]
    pub subdivision: Option<String>,
}

#[derive(Deserialize)]
struct NodeReportFile {
    #[serde(default)]
    node_report: Option<NodeReportConfig>,
}

/// Reads `--config <path>` from the arguments and returns the `[node_report]` section, if any.
/// # Errors
/// Returns a configuration error for unreadable files, malformed TOML or invalid sections.
pub fn load_node_report_config(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<NodeReportConfig>, NodeCoreError> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let path = args.next().ok_or(NodeCoreError::MissingConfigPath)?;
            return load_node_report_config_file(Path::new(&path));
        }
    }
    Ok(None)
}

/// # Errors
/// Returns a configuration error for unreadable files, malformed TOML or invalid sections.
pub fn load_node_report_config_file(
    path: &Path,
) -> Result<Option<NodeReportConfig>, NodeCoreError> {
    let text =
        std::fs::read_to_string(path).map_err(|error| invalid(format!("read config: {error}")))?;
    let file: NodeReportFile =
        toml::from_str(&text).map_err(|error| invalid(format!("parse config: {error}")))?;
    file.node_report.map(validate).transpose()
}

/// # Errors
/// Returns a configuration error when any field is outside its grammar.
pub fn validate(config: NodeReportConfig) -> Result<NodeReportConfig, NodeCoreError> {
    let centre = &config.centre;
    if centre.id.is_empty()
        || centre.id.len() > MAX_CENTRE_ID_BYTES
        || !centre.id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(invalid("node_report.centre.id must be 1-128 printable ASCII bytes".into()));
    }
    centre
        .addr
        .parse::<SocketAddr>()
        .map_err(|_| invalid("node_report.centre.addr must be an IP socket address".into()))?;
    if centre.server_name.is_empty() || centre.ca_cert.is_empty() {
        return Err(invalid("node_report.centre.server_name and ca_cert are required".into()));
    }
    if config.key_gen == 0 || config.key_gen > MAX_KEY_GEN {
        return Err(invalid("node_report.key_gen must be 1 or more, below 2^53".into()));
    }
    if let Some(region) = &config.region {
        validate_region(region)?;
    }
    Ok(config)
}

fn validate_region(region: &NodeReportRegionConfig) -> Result<(), NodeCoreError> {
    let country = region.country.as_str();
    if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(invalid(
            "node_report.region.country must be two upper-case ASCII letters".into(),
        ));
    }
    match (&region.subdivision, country) {
        (None, _) => Ok(()),
        (Some(_), "ZZ") => {
            Err(invalid("node_report.region: ZZ withdraws the region; no subdivision".into()))
        }
        (Some(subdivision), _) => {
            let (prefix, rest) = subdivision.split_once('-').unwrap_or(("", ""));
            let rest_ok = (1..=3).contains(&rest.len())
                && rest.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
            if prefix == country && rest_ok {
                Ok(())
            } else {
                Err(invalid(
                    "node_report.region.subdivision must be ISO 3166-2 with the country prefix"
                        .into(),
                ))
            }
        }
    }
}

fn invalid(message: String) -> NodeCoreError {
    NodeCoreError::InvalidConfiguration(message)
}
