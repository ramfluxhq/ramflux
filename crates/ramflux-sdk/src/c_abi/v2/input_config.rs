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
    fn own(self) -> OwnedProfile {
        OwnedProfile {
            strings: self.strings.map(str::to_owned),
            gateway: [self.gateway.0.into(), self.gateway.1.into(), self.gateway.2.into()],
            relay: [self.relay.0.into(), self.relay.1.into()],
            pin: self.pin,
            protocol: self.protocol.into_iter().map(str::to_owned).collect(),
            capabilities: self.capabilities.into_iter().map(str::to_owned).collect(),
            warnings: self
                .warnings
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            discovered: self.discovered,
            expires: self.expires,
            enabled: self.enabled,
            builtin: self.builtin,
        }
    }
}
// Own only types whose cleanup can be derived. SDK profiles are constructed only at handoff.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(super) struct OwnedProfile {
    strings: [String; 6],
    gateway: [String; 3],
    relay: [String; 2],
    #[zeroize(skip)] // Unit discriminator; contains no input bytes.
    pin: NodePinSource,
    protocol: Vec<String>,
    capabilities: Vec<String>,
    warnings: Vec<String>,
    discovered: u64,
    expires: u64,
    enabled: bool,
    builtin: bool,
}
impl OwnedProfile {
    pub(super) fn take_node(&mut self) -> NodeProfile {
        let [
            discovery_url,
            node_id,
            node_public_key,
            ca_cert_pem,
            prekey_http_url,
            signaling_turn_addr,
        ] = std::mem::take(&mut self.strings);
        let [quic_addr, tcp_addr, server_name] = std::mem::take(&mut self.gateway);
        let [relay_addr, relay_name] = std::mem::take(&mut self.relay);
        NodeProfile {
            discovery_url,
            node_id,
            node_public_key,
            ca_cert_pem,
            prekey_http_url,
            signaling_turn_addr,
            pin_source: self.pin,
            gateway: NodeGateway { quic_addr, tcp_addr, server_name },
            relay: NodeRelay { quic_addr: relay_addr, server_name: relay_name },
            protocol_versions: std::mem::take(&mut self.protocol),
            client_capabilities: std::mem::take(&mut self.capabilities),
            safety_warnings: std::mem::take(&mut self.warnings).into_iter().collect(),
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
