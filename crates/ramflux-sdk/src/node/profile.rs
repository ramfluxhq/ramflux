// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node endpoint profiles and account transport configuration.
use super::{
    BTreeSet, Deserialize, GatewayQuicEndpointConfig, Path, PathBuf, RamfluxClient,
    RelayTransferOptions, SdkError, Serialize, WellKnownClientRecord, node_error,
    parse_relay_transfer_options, resolve_node_addr, set_owner_only_dir_permissions,
    set_owner_only_file_permissions,
};
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodePinSource {
    Builtin,
    Invitation,
    Tofu,
    Operator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeGateway {
    pub quic_addr: String,
    pub tcp_addr: String,
    pub server_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeRelay {
    pub quic_addr: String,
    pub server_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeProfile {
    pub discovery_url: String,
    pub node_id: String,
    pub node_public_key: String,
    pub pin_source: NodePinSource,
    pub ca_cert_pem: String,
    pub gateway: NodeGateway,
    pub relay: NodeRelay,
    pub prekey_http_url: String,
    pub signaling_turn_addr: String,
    pub protocol_versions: Vec<String>,
    pub client_capabilities: Vec<String>,
    pub discovered_at: u64,
    pub expires_at: u64,
    pub enabled: bool,
    pub builtin: bool,
    #[serde(default)]
    pub safety_warnings: BTreeSet<String>,
}

impl NodeProfile {
    pub(crate) fn from_record(record: WellKnownClientRecord, now: u64) -> Self {
        Self {
            discovery_url: String::new(),
            node_id: record.node_id,
            node_public_key: record.node_public_key,
            pin_source: NodePinSource::Tofu,
            ca_cert_pem: record.node_ca_cert_pem,
            gateway: NodeGateway {
                quic_addr: record.gateway_quic_addr,
                tcp_addr: record.gateway_tcp_addr,
                server_name: record.gateway_server_name,
            },
            relay: NodeRelay {
                quic_addr: record.relay_quic_addr,
                server_name: record.relay_server_name,
            },
            prekey_http_url: record.prekey_http_url,
            signaling_turn_addr: record.signaling_turn_addr,
            protocol_versions: record.protocol_versions,
            client_capabilities: record.client_capabilities,
            discovered_at: now,
            expires_at: record.expires_at,
            enabled: true,
            builtin: false,
            safety_warnings: BTreeSet::from(["tofu_unverified".to_owned()]),
        }
    }

    pub(crate) fn ca_path(&self, root: &Path) -> PathBuf {
        root.join("node_cas").join(format!(
            "{}.pem",
            ramflux_protocol::hash_hex(
                ramflux_protocol::CLIENT_DISCOVERY_DOMAIN,
                self.node_id.as_bytes()
            )
        ))
    }

    pub(crate) fn write_ca(&self, root: &Path) -> Result<PathBuf, SdkError> {
        let path = self.ca_path(root);
        let parent = path.parent().ok_or_else(|| node_error("missing CA parent"))?;
        std::fs::create_dir_all(parent)?;
        set_owner_only_dir_permissions(parent)?;
        std::fs::write(&path, &self.ca_cert_pem)?;
        set_owner_only_file_permissions(&path)?;
        Ok(path)
    }

    pub(crate) async fn gateway_config(
        &self,
        root: &Path,
        mut endpoint: GatewayQuicEndpointConfig,
    ) -> Result<GatewayQuicEndpointConfig, SdkError> {
        endpoint.gateway_addr = resolve_node_addr(&self.gateway.quic_addr).await?;
        endpoint.server_name.clone_from(&self.gateway.server_name);
        endpoint.ca_cert = self.write_ca(root)?;
        endpoint.prekey_http_url = Some(self.prekey_http_url.clone());
        Ok(endpoint)
    }

    pub(crate) async fn relay_options(
        &self,
        root: &Path,
        principal_id: &str,
    ) -> Result<RelayTransferOptions, SdkError> {
        Ok(RelayTransferOptions {
            relay_endpoint: format!("quic://{}", self.relay.quic_addr),
            token_provider: crate::object::RelayTokenProvider::GatewayIssued,
            interrupt_after_chunks: None,
            relay_quic_peer_addr: Some(resolve_node_addr(&self.relay.quic_addr).await?.to_string()),
            relay_quic_server_name: Some(self.relay.server_name.clone()),
            relay_quic_ca_cert: Some(self.write_ca(root)?),
            relay_owner_home_node_id: Some(self.node_id.clone()),
            relay_owner_principal_id: Some(principal_id.to_owned()),
            relay_audience_node_id: Some(self.node_id.clone()),
        })
    }
}

impl RamfluxClient {
    pub(crate) fn relay_transfer_options(
        &self,
        endpoint: Option<String>,
        service_key: Option<String>,
        interrupt: Option<u32>,
    ) -> Result<Option<RelayTransferOptions>, SdkError> {
        if let Some(profile) = &self.node_relay_options {
            let mut options = profile.clone();
            options.interrupt_after_chunks = interrupt;
            return Ok(Some(options));
        }
        parse_relay_transfer_options(endpoint, service_key, interrupt)
    }
}
