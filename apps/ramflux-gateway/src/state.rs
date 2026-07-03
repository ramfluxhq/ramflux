// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

use crate::session::write_gateway_frame;

const DEFAULT_GATEWAY_ID: &str = "ramflux-gateway";
const DEFAULT_GATEWAY_FORWARD_PATH: &str = "/gateway/mesh/forward-deliver";
const GATEWAY_ID_ENV: &str = "RAMFLUX_GATEWAY_ID";
const GATEWAY_PEERS_ENV: &str = "RAMFLUX_GATEWAY_PEERS";

#[derive(Clone)]
pub(crate) struct RouterMeshClient {
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) tls: ramflux_transport::MeshTlsConfig,
    pub(crate) client: ramflux_transport::MeshHttpClient,
    pub(crate) async_mesh: Option<RouterAsyncMeshClient>,
}

#[derive(Clone)]
pub(crate) struct RouterAsyncMeshClient {
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) tls: ramflux_transport::MeshTlsConfig,
    pub(crate) peer_ca_pems: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct NotifyHttpClient {
    pub(crate) endpoint: String,
    pub(crate) signer: ramflux_node_core::NodeServiceSigningKey,
    pub(crate) mesh: Option<NotifyMeshClient>,
}

#[derive(Clone)]
pub(crate) struct NotifyMeshClient {
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) tls: ramflux_transport::MeshTlsConfig,
    pub(crate) peer_ca_pems: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct GatewayQuicContext {
    pub(crate) node_id: String,
    pub(crate) gateway_id: String,
    pub(crate) peers: GatewayPeerDirectory,
    pub(crate) router: RouterMeshClient,
    pub(crate) notify: NotifyHttpClient,
    pub(crate) state: Arc<Mutex<ramflux_node_core::GatewayState>>,
    pub(crate) store: Arc<ramflux_node_core::GatewayRedbStore>,
    pub(crate) hub: Arc<GatewaySessionHub>,
    pub(crate) remote_addr: SocketAddr,
}

pub(crate) struct GatewaySessionRuntime {
    pub(crate) session_id: String,
    pub(crate) resume_token: String,
    pub(crate) principal_id: String,
    pub(crate) device_id: String,
    pub(crate) target_delivery_id: String,
}

#[derive(Clone)]
pub(crate) struct GatewayPeerDirectory {
    tls: ramflux_transport::MeshTlsConfig,
    peer_ca_pems: Vec<String>,
    peers: Arc<BTreeMap<String, GatewayPeer>>,
}

#[derive(Clone)]
pub(crate) struct GatewayPeer {
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub(crate) struct GatewayForwardDeliverRequest {
    pub(crate) source_gateway_id: String,
    pub(crate) target_delivery_id: String,
    pub(crate) forwarded: bool,
    pub(crate) frame: ramflux_node_core::GatewayServerFrame,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub(crate) struct GatewayForwardDeliverResponse {
    pub(crate) delivered: bool,
}

impl GatewayPeerDirectory {
    pub(crate) fn empty(config: &ramflux_node_core::NodeServiceConfig) -> Self {
        Self {
            tls: mesh_tls_config(config),
            peer_ca_pems: Vec::new(),
            peers: Arc::new(BTreeMap::new()),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub(crate) fn peer(&self, gateway_id: &str) -> Option<&GatewayPeer> {
        self.peers.get(gateway_id)
    }

    pub(crate) fn tls(&self) -> &ramflux_transport::MeshTlsConfig {
        &self.tls
    }

    pub(crate) fn peer_ca_pems(&self) -> &[String] {
        &self.peer_ca_pems
    }

    pub(crate) fn forward_path() -> &'static str {
        DEFAULT_GATEWAY_FORWARD_PATH
    }
}

pub(crate) type GatewaySendHandle =
    Arc<AsyncMutex<Box<dyn ramflux_transport::GatewaySessionFrameSink + Send>>>;

#[derive(Clone)]
pub(crate) struct GatewayHubEntry {
    session_id: String,
    sender: GatewaySendHandle,
}

#[derive(Default)]
pub(crate) struct GatewaySessionHub {
    senders_by_target: AsyncMutex<BTreeMap<String, GatewayHubEntry>>,
}

impl GatewaySessionHub {
    pub(crate) async fn register(
        &self,
        target_delivery_id: String,
        session_id: String,
        sender: GatewaySendHandle,
    ) {
        self.senders_by_target
            .lock()
            .await
            .insert(target_delivery_id, GatewayHubEntry { session_id, sender });
    }

    pub(crate) async fn unregister(&self, target_delivery_id: &str, session_id: &str) {
        let mut senders = self.senders_by_target.lock().await;
        if senders.get(target_delivery_id).is_some_and(|entry| entry.session_id == session_id) {
            senders.remove(target_delivery_id);
        }
    }

    pub(crate) async fn send_to(
        &self,
        target_delivery_id: &str,
        frame: &ramflux_node_core::GatewayServerFrame,
    ) -> anyhow::Result<bool> {
        let sender = self
            .senders_by_target
            .lock()
            .await
            .get(target_delivery_id)
            .map(|entry| Arc::clone(&entry.sender));
        if let Some(sender) = sender {
            let mut sender = sender.lock().await;
            write_gateway_frame(&mut **sender, frame).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub(crate) fn gateway_instance_id_from_env() -> String {
    gateway_instance_id_from_value(std::env::var(GATEWAY_ID_ENV).ok().as_deref())
}

pub(crate) fn gateway_peer_directory_from_env(
    config: &ramflux_node_core::NodeServiceConfig,
    local_gateway_id: &str,
) -> anyhow::Result<GatewayPeerDirectory> {
    let Some(peers_value) = non_empty_env(GATEWAY_PEERS_ENV) else {
        return Ok(GatewayPeerDirectory::empty(config));
    };
    let mut peers = BTreeMap::new();
    for entry in peers_value.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
        let (gateway_id, peer_spec) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid RAMFLUX_GATEWAY_PEERS entry {entry}"))?;
        let gateway_id = gateway_id.trim();
        if gateway_id.is_empty() {
            return Err(anyhow::anyhow!(
                "invalid RAMFLUX_GATEWAY_PEERS entry with empty gateway id"
            ));
        }
        if gateway_id == local_gateway_id {
            continue;
        }
        let (endpoint, server_name) = parse_gateway_peer_spec(peer_spec)?;
        peers.insert(gateway_id.to_owned(), GatewayPeer { endpoint, server_name });
    }
    let peer_ca_pems = if peers.is_empty() {
        Vec::new()
    } else {
        vec![std::fs::read_to_string(&config.mesh.ca_cert)?]
    };
    Ok(GatewayPeerDirectory { tls: mesh_tls_config(config), peer_ca_pems, peers: Arc::new(peers) })
}

fn gateway_instance_id_from_value(value: Option<&str>) -> String {
    value.map(str::trim).filter(|value| !value.is_empty()).unwrap_or(DEFAULT_GATEWAY_ID).to_owned()
}

fn parse_gateway_peer_spec(peer_spec: &str) -> anyhow::Result<(String, String)> {
    let peer_spec = peer_spec.trim();
    if peer_spec.is_empty() {
        return Err(anyhow::anyhow!("invalid RAMFLUX_GATEWAY_PEERS entry with empty endpoint"));
    }
    let (endpoint, server_name) =
        peer_spec.split_once('|').map_or((peer_spec, None), |(endpoint, server_name)| {
            (endpoint.trim(), Some(server_name.trim()))
        });
    if endpoint.is_empty() {
        return Err(anyhow::anyhow!("invalid RAMFLUX_GATEWAY_PEERS entry with empty endpoint"));
    }
    let server_name = server_name
        .filter(|value| !value.is_empty())
        .map_or_else(|| default_gateway_peer_server_name(endpoint), ToOwned::to_owned);
    Ok((endpoint.to_owned(), server_name))
}

fn default_gateway_peer_server_name(endpoint: &str) -> String {
    if let Some(rest) = endpoint.strip_prefix('[')
        && let Some((host, _suffix)) = rest.split_once(']')
    {
        return host.to_owned();
    }
    endpoint.rsplit_once(':').map_or(endpoint, |(host, _port)| host).to_owned()
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn mesh_tls_config(
    config: &ramflux_node_core::NodeServiceConfig,
) -> ramflux_transport::MeshTlsConfig {
    ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_GATEWAY_ID, default_gateway_peer_server_name, gateway_instance_id_from_value,
        parse_gateway_peer_spec,
    };

    #[test]
    fn gateway_instance_id_defaults_and_trims_env_value() {
        assert_eq!(gateway_instance_id_from_value(None), DEFAULT_GATEWAY_ID);
        assert_eq!(gateway_instance_id_from_value(Some("   ")), DEFAULT_GATEWAY_ID);
        assert_eq!(gateway_instance_id_from_value(Some(" gateway-east-1 ")), "gateway-east-1");
    }

    #[test]
    fn gateway_peer_spec_defaults_server_name_to_endpoint_host() -> anyhow::Result<()> {
        assert_eq!(
            parse_gateway_peer_spec("ramflux-gateway-b:7443")?,
            ("ramflux-gateway-b:7443".to_owned(), "ramflux-gateway-b".to_owned())
        );
        assert_eq!(
            parse_gateway_peer_spec("[::1]:7443")?,
            ("[::1]:7443".to_owned(), "::1".to_owned())
        );
        assert_eq!(
            parse_gateway_peer_spec("10.0.0.9:7443|ramflux-gateway-b")?,
            ("10.0.0.9:7443".to_owned(), "ramflux-gateway-b".to_owned())
        );
        assert_eq!(default_gateway_peer_server_name("ramflux-gateway-b"), "ramflux-gateway-b");
        Ok(())
    }
}
