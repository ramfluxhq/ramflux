// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

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
    pub(crate) custody: Option<crate::custody::Pools>,
    pub(crate) node_id: String,
    pub(crate) gateway_id: String,
    pub(crate) peers: GatewayPeerDirectory,
    pub(crate) router: RouterMeshClient,
    pub(crate) notify: NotifyHttpClient,
    // T22-A1 / RQ-04: the legacy v2 shared-HMAC relay service key is compiled only under
    // `itest-local-mint`; production gateways never load or hold it.
    #[cfg(feature = "itest-local-mint")]
    pub(crate) relay_service_key: Vec<u8>,
    pub(crate) state: Arc<Mutex<ramflux_node_core::GatewayState>>,
    pub(crate) store: Arc<ramflux_node_core::GatewayRedbStore>,
    pub(crate) hub: Arc<GatewaySessionHub>,
    pub(crate) remote_addr: SocketAddr,
}

#[derive(Clone)]
pub(crate) struct GatewaySessionRuntime {
    pub(crate) source_identity: ramflux_crypto::RootQualifiedDeviceRef,
    pub(crate) session_id: String,
    pub(crate) resume_token: String,
    pub(crate) principal_id: String,
    pub(crate) device_id: String,
    pub(crate) target_delivery_id: String,
    pub(crate) branch_public_key: String,
    pub(crate) device_epoch: u64,
    pub(crate) supports_forward_ack: bool,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GatewayRegistrationToken(u64);

pub(crate) struct GatewayRegistration {
    pub(crate) token: GatewayRegistrationToken,
    pub(crate) closed: tokio::sync::watch::Receiver<bool>,
}

#[derive(Clone)]
pub(crate) struct GatewayHubEntry {
    session_id: String,
    token: GatewayRegistrationToken,
    closed: tokio::sync::watch::Sender<bool>,
    sender: GatewaySendHandle,
}

#[derive(Default)]
pub(crate) struct GatewaySessionHub {
    senders_by_target: AsyncMutex<BTreeMap<String, GatewayHubEntry>>,
    next_registration: std::sync::atomic::AtomicU64,
}

impl GatewaySessionHub {
    pub(crate) fn active_session_ids(&self) -> std::collections::BTreeSet<String> {
        self.senders_by_target
            .blocking_lock()
            .values()
            .map(|entry| entry.session_id.clone())
            .collect()
    }

    pub(crate) async fn register(
        &self,
        target_delivery_id: String,
        session_id: String,
        sender: GatewaySendHandle,
    ) -> anyhow::Result<GatewayRegistration> {
        use std::sync::atomic::Ordering;
        let sequence = self
            .next_registration
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| anyhow::anyhow!("gateway registration counter exhausted"))?;
        let token = GatewayRegistrationToken(sequence);
        let (closed, receiver) = tokio::sync::watch::channel(false);
        let old = self
            .senders_by_target
            .lock()
            .await
            .insert(target_delivery_id, GatewayHubEntry { session_id, token, closed, sender });
        if let Some(old) = old {
            let _ = old.closed.send(true);
        }
        Ok(GatewayRegistration { token, closed: receiver })
    }

    pub(crate) async fn unregister(
        &self,
        target_delivery_id: &str,
        token: GatewayRegistrationToken,
    ) {
        let mut senders = self.senders_by_target.lock().await;
        if senders.get(target_delivery_id).is_some_and(|entry| entry.token == token) {
            senders.remove(target_delivery_id);
        }
    }

    /// A peer sink failure is a delivery miss, never a failure of the calling session.
    pub(crate) async fn send_to(
        &self,
        target_delivery_id: &str,
        frame: &ramflux_node_core::GatewayServerFrame,
    ) -> bool {
        let entry = self.senders_by_target.lock().await.get(target_delivery_id).cloned();
        let Some(entry) = entry else {
            return false;
        };
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut sender = entry.sender.lock().await;
            ramflux_transport::write_gateway_session_json(&mut **sender, frame).await
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            tracing::warn!(result = ?result, target_delivery_id, session_id = %entry.session_id,
                "local peer delivery failed; closing registration");
            // Wake this exact loop before dropping a possibly partially written sink.
            let _ = entry.closed.send(true);
            if let Ok(mut sender) = entry.sender.try_lock() {
                let _ = sender.finish();
            }
            self.unregister(target_delivery_id, entry.token).await;
            return false;
        }
        true
    }
}

pub(crate) fn gateway_instance_id_from_env() -> String {
    gateway_instance_id_from_value(
        ramflux_node_core::environment::var(GATEWAY_ID_ENV).ok().as_deref(),
    )
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
    ramflux_node_core::environment::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        // Treat an unexpanded compose/shell variable (podman-compose leaves ${VAR:-default}
        // literal when the var is unset) as absent rather than a real value.
        if trimmed.is_empty() || trimmed.starts_with("${") {
            None
        } else {
            Some(trimmed.to_owned())
        }
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
