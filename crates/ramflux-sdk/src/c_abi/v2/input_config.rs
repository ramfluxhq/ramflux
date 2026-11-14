// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validate complete node configuration using borrowed fields before allocating owned profiles.
use super::super::CAbiError;
use super::{
    exports::Config,
    input::{self as i, Decode},
};
use crate::{NodeGateway, NodePinSource, NodeProfile, NodeRelay};
use serde_json::Value;

struct Profile<'a> {
    strings: [&'a str; 6],
    gateway: (&'a str, &'a str, &'a str),
    relay: (&'a str, &'a str),
    pin: NodePinSource,
    protocol: Vec<&'a str>,
    capabilities: Vec<&'a str>,
    warnings: Vec<&'a str>,
    discovered: u64,
    expires: u64,
    enabled: bool,
    builtin: bool,
}
fn default_string<'a>(v: &'a Value, key: &str) -> Result<&'a str, CAbiError> {
    match v.get(key) {
        None => Ok(""),
        Some(Value::String(s)) => Ok(s),
        _ => Err(i::invalid()),
    }
}
fn strings<'a>(v: &'a Value, key: &str) -> Result<Vec<&'a str>, CAbiError> {
    match v.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => {
            values.iter().map(|v| v.as_str().ok_or_else(i::invalid)).collect()
        }
        _ => Err(i::invalid()),
    }
}
impl<'a> Profile<'a> {
    fn read(v: &'a Value) -> Result<Self, CAbiError> {
        let gateway = v.get("gateway").ok_or_else(i::invalid)?;
        let relay = v.get("relay").ok_or_else(i::invalid)?;
        let pin = match i::string(v, "pin_source")? {
            "builtin" => NodePinSource::Builtin,
            "invitation" => NodePinSource::Invitation,
            "tofu" => NodePinSource::Tofu,
            "operator" => NodePinSource::Operator,
            _ => return Err(i::invalid()),
        };
        Ok(Self {
            strings: [
                default_string(v, "discovery_url")?,
                i::string(v, "node_id")?,
                i::string(v, "node_public_key")?,
                i::string(v, "ca_cert_pem")?,
                i::string(v, "prekey_http_url")?,
                default_string(v, "signaling_turn_addr")?,
            ],
            gateway: (
                i::string(gateway, "quic_addr")?,
                i::string(gateway, "tcp_addr")?,
                i::string(gateway, "server_name")?,
            ),
            relay: (i::string(relay, "quic_addr")?, i::string(relay, "server_name")?),
            pin,
            protocol: strings(v, "protocol_versions")?,
            capabilities: strings(v, "client_capabilities")?,
            warnings: strings(v, "safety_warnings")?,
            discovered: v.get("discovered_at").and_then(Value::as_u64).ok_or_else(i::invalid)?,
            expires: v.get("expires_at").and_then(Value::as_u64).ok_or_else(i::invalid)?,
            enabled: i::boolean(v, "enabled", None)?,
            builtin: i::boolean(v, "builtin", None)?,
        })
    }
    fn own(self) -> NodeProfile {
        let [
            discovery_url,
            node_id,
            node_public_key,
            ca_cert_pem,
            prekey_http_url,
            signaling_turn_addr,
        ] = self.strings;
        NodeProfile {
            discovery_url: discovery_url.into(),
            node_id: node_id.into(),
            node_public_key: node_public_key.into(),
            pin_source: self.pin,
            ca_cert_pem: ca_cert_pem.into(),
            gateway: NodeGateway {
                quic_addr: self.gateway.0.into(),
                tcp_addr: self.gateway.1.into(),
                server_name: self.gateway.2.into(),
            },
            relay: NodeRelay { quic_addr: self.relay.0.into(), server_name: self.relay.1.into() },
            prekey_http_url: prekey_http_url.into(),
            signaling_turn_addr: signaling_turn_addr.into(),
            protocol_versions: self.protocol.into_iter().map(str::to_owned).collect(),
            client_capabilities: self.capabilities.into_iter().map(str::to_owned).collect(),
            // Deduplicate borrowed values before allocating any owned warning string.
            safety_warnings: self
                .warnings
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            discovered_at: self.discovered,
            expires_at: self.expires,
            enabled: self.enabled,
            builtin: self.builtin,
        }
    }
}
impl Decode for Config {
    fn decode(v: &mut Value) -> Result<Self, CAbiError> {
        i::object(
            v,
            &["data_root", "builtin_nodes", "allow_raw_messages", "allow_secret_exports"],
        )?;
        let root = i::string(v, "data_root")?;
        let raw = i::boolean(v, "allow_raw_messages", Some(false))?;
        let secret = i::boolean(v, "allow_secret_exports", Some(false))?;
        let nodes = match v.get("builtin_nodes") {
            None => Vec::new(),
            Some(Value::Array(nodes)) => {
                nodes.iter().map(Profile::read).collect::<Result<Vec<_>, _>>()?
            }
            _ => return Err(i::invalid()),
        };
        Ok(Config {
            allow_raw_messages: raw,
            allow_secret_exports: secret,
            data_root: root.into(),
            builtin_nodes: nodes.into_iter().map(Profile::own).collect(),
        })
    }
}
