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
    /// Per-client wake observer. Clones share the counter so `spawn_blocking` is visible.
    #[cfg(test)]
    pub(crate) wake_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(test)]
impl NotifyHttpClient {
    pub(crate) fn wake_count(&self) -> u64 {
        self.wake_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
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
    pub(crate) call_session_generation: Option<String>,
    pub(crate) session_push: Option<String>,
    pub(crate) ephemeral: bool,
    pub(crate) push_limit: usize,
    pub(crate) source_identity: ramflux_crypto::RootQualifiedDeviceRef,
    pub(crate) session_id: String,
    pub(crate) resume_token: String,
    pub(crate) principal_id: String,
    pub(crate) device_id: String,
    pub(crate) target_delivery_id: String,
    pub(crate) branch_public_key: String,
    pub(crate) device_epoch: u64,
    pub(crate) supports_forward_ack: bool,
    /// Session-owned ephemeral admission bucket, shared by every clone of this session.
    pub(crate) ephemeral_rate: Arc<crate::ephemeral::EphemeralRate>,
}

impl GatewaySessionRuntime {
    /// True when establishment echoed `gateway.ephemeral.v1` onto this session (P10).
    /// Production stays dormant until a router advertises that capability.
    #[must_use]
    pub(crate) const fn ephemeral_negotiated(&self) -> bool {
        self.ephemeral
    }
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null_forward_field"
    )]
    pub(crate) incarnation_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null_forward_field"
    )]
    pub(crate) retain_until: Option<i64>,
    pub(crate) frame: ramflux_node_core::GatewayServerFrame,
}

fn non_null_forward_field<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    let value = <Option<T> as serde::Deserialize>::deserialize(decoder)?;
    value.map(Some).ok_or_else(|| serde::de::Error::custom("forward field must not be null"))
}

pub(crate) type GatewayForwardDeliverResponse = ramflux_node_core::SessionPushForwardResponse;

impl GatewayPeerDirectory {
    pub(crate) fn empty(config: &ramflux_node_core::NodeServiceConfig) -> Self {
        Self {
            tls: mesh_tls_config(config),
            peer_ca_pems: Vec::new(),
            peers: Arc::new(BTreeMap::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_peer(
        tls: ramflux_transport::MeshTlsConfig,
        ca: String,
        gateway: &str,
        endpoint: String,
    ) -> Self {
        Self {
            tls,
            peer_ca_pems: vec![ca],
            peers: Arc::new(BTreeMap::from([(
                gateway.to_owned(),
                GatewayPeer { endpoint, server_name: "ramflux-gateway".into() },
            )])),
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

    /// Authenticated, instance-bound same-node transient forwarding; never retries durably.
    pub(crate) async fn post_ephemeral(
        &self,
        gateway_id: &str,
        request: crate::ephemeral_forward::GatewayForwardEphemeralRequest,
    ) -> anyhow::Result<ramflux_node_core::SessionPushForwardResponse> {
        let peer = self
            .peer(gateway_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown target gateway"))?;
        let tls = self.tls.clone();
        let peer_ca_pems = self.peer_ca_pems.clone();
        let instance = gateway_id.to_owned();
        Ok(tokio::task::spawn_blocking(move || {
            ramflux_transport::mesh_quic_post_json_with_peer_ca_pems_and_instance(
                &peer.endpoint,
                crate::ephemeral_forward::PATH,
                &tls,
                &peer.server_name,
                &peer_ca_pems,
                &instance,
                &request,
            )
        })
        .await??)
    }

    pub(crate) fn forward_path() -> &'static str {
        DEFAULT_GATEWAY_FORWARD_PATH
    }
}

pub(crate) type GatewaySendHandle =
    Arc<AsyncMutex<Box<dyn ramflux_transport::GatewaySessionFrameSink + Send>>>;

pub(crate) use crate::session_hub::GatewaySessionHub;

pub(crate) fn gateway_instance_id_from_env() -> String {
    gateway_instance_id_from_value(
        ramflux_node_core::environment::var(GATEWAY_ID_ENV).ok().as_deref(),
    )
}

pub(crate) fn gateway_peer_directory_from_env(
    config: &ramflux_node_core::NodeServiceConfig,
    local_gateway_id: &str,
) -> anyhow::Result<GatewayPeerDirectory> {
    gateway_peer_directory_from_value(
        config,
        local_gateway_id,
        non_empty_env(GATEWAY_PEERS_ENV).as_deref(),
    )
}

fn gateway_peer_directory_from_value(
    config: &ramflux_node_core::NodeServiceConfig,
    local_gateway_id: &str,
    peers_value: Option<&str>,
) -> anyhow::Result<GatewayPeerDirectory> {
    let Some(peers_value) = peers_value else {
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
        if !ramflux_node_core::is_valid_gateway_instance_id(gateway_id) {
            anyhow::bail!("invalid gateway peer instance id in RAMFLUX_GATEWAY_PEERS");
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

pub(crate) fn validate_gateway_mesh_identity(
    config: &ramflux_node_core::NodeServiceConfig,
    gateway_id: &str,
) -> anyhow::Result<()> {
    if !ramflux_node_core::is_valid_gateway_instance_id(gateway_id) {
        anyhow::bail!("invalid RAMFLUX_GATEWAY_ID");
    }
    let cert_file = std::fs::File::open(&config.mesh.service_cert)?;
    let mut reader = std::io::BufReader::new(cert_file);
    let mut certificates = rustls_pemfile::certs(&mut reader);
    let certificate = certificates
        .next()
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("gateway service certificate has no certificate"))?;
    if certificates.next().transpose()?.is_some() {
        anyhow::bail!("gateway service certificate contains multiple certificates");
    }
    let spiffe_uri = ramflux_transport::extract_spiffe_uri_from_certificate(&certificate)?
        .ok_or_else(|| anyhow::anyhow!("gateway service certificate has no SPIFFE URI SAN"))?;
    let identity = ramflux_node_core::parse_mesh_spiffe_uri(&spiffe_uri)?;
    let Some(instance_id) = identity.instance_id.as_deref() else {
        anyhow::bail!("gateway service certificate has no instance id");
    };
    if instance_id != gateway_id {
        anyhow::bail!("gateway service certificate instance does not match RAMFLUX_GATEWAY_ID");
    }
    if identity.node_id != config.node_id {
        anyhow::bail!("gateway service certificate node id does not match configured node id");
    }
    Ok(())
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
        gateway_peer_directory_from_value, parse_gateway_peer_spec,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::Path,
    };

    struct TestRoot(std::path::PathBuf);

    impl TestRoot {
        fn new() -> anyhow::Result<Self> {
            let suffix = ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8]);
            let path = std::env::temp_dir()
                .join(format!("rf-gateway-instance-start-{}-{suffix}", std::process::id()));
            std::fs::create_dir_all(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn config(root: &Path, node_id: &str) -> ramflux_node_core::NodeServiceConfig {
        ramflux_node_core::NodeServiceConfig {
            send_authority: None,
            node_id: node_id.to_owned(),
            service_id: "ramflux-gateway".to_owned(),
            redb_path: root.join("gateway.redb").display().to_string(),
            node_service_signing_seed_b64url: None,
            mesh: ramflux_node_core::MeshConfig {
                listen_addr: "127.0.0.1:0".to_owned(),
                ca_cert: root.join("ca.pem").display().to_string(),
                service_cert: root.join("gateway.pem").display().to_string(),
                service_key: root.join("gateway-key.pem").display().to_string(),
                allowed_service_ids: BTreeSet::new(),
                endpoints: BTreeMap::new(),
            },
            gateway: None,
            signaling: None,
            relay: None,
        }
    }

    fn openssl(args: &[&str]) -> anyhow::Result<()> {
        anyhow::ensure!(
            std::process::Command::new("openssl").args(args).status()?.success(),
            "openssl command failed: {args:?}"
        );
        Ok(())
    }

    fn path_str(path: &Path) -> anyhow::Result<&str> {
        path.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF-8 test path"))
    }

    fn require_error(result: anyhow::Result<()>) -> anyhow::Result<anyhow::Error> {
        match result {
            Ok(()) => anyhow::bail!("expected gateway identity validation error"),
            Err(error) => Ok(error),
        }
    }

    fn issue_test_certificate(root: &Path, spiffe_uri: &str) -> anyhow::Result<()> {
        let ca_key = root.join("ca-key.pem");
        let ca = root.join("ca.pem");
        let key = root.join("gateway-key.pem");
        let csr = root.join("gateway.csr");
        let cert = root.join("gateway.pem");
        let ext = root.join("gateway.ext");
        let (ca_key_path, ca_path, key_path, csr_path, cert_path, ext_path) = (
            path_str(&ca_key)?,
            path_str(&ca)?,
            path_str(&key)?,
            path_str(&csr)?,
            path_str(&cert)?,
            path_str(&ext)?,
        );
        openssl(&["genpkey", "-algorithm", "ED25519", "-out", ca_key_path])?;
        openssl(&[
            "req",
            "-x509",
            "-new",
            "-key",
            ca_key_path,
            "-out",
            ca_path,
            "-days",
            "1",
            "-subj",
            "/CN=gateway identity test CA",
        ])?;
        openssl(&["genpkey", "-algorithm", "ED25519", "-out", key_path])?;
        openssl(&[
            "req",
            "-new",
            "-key",
            key_path,
            "-out",
            csr_path,
            "-subj",
            "/CN=ramflux-gateway",
        ])?;
        std::fs::write(
            &ext,
            format!("subjectAltName=URI:{spiffe_uri}\nextendedKeyUsage=serverAuth,clientAuth\n"),
        )?;
        openssl(&[
            "x509",
            "-req",
            "-in",
            csr_path,
            "-CA",
            ca_path,
            "-CAkey",
            ca_key_path,
            "-CAcreateserial",
            "-out",
            cert_path,
            "-days",
            "1",
            "-extfile",
            ext_path,
        ])
    }

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

    #[test]
    #[allow(clippy::too_many_lines, reason = "covers each gateway startup identity refusal")]
    fn gateway_start_identity_checks_bind_certificate_node_and_instance() -> anyhow::Result<()> {
        let directory = TestRoot::new()?;
        let root = directory.0.as_path();
        let config = config(root, "localhost");
        issue_test_certificate(root, "spiffe://localhost/ramflux-gateway/gw-a")?;
        super::validate_gateway_mesh_identity(&config, "gw-a")?;
        let error = require_error(super::validate_gateway_mesh_identity(&config, "gw-b"))?;
        assert_eq!(
            error.to_string(),
            "gateway service certificate instance does not match RAMFLUX_GATEWAY_ID"
        );
        let error = require_error(super::validate_gateway_mesh_identity(&config, "GW"))?;
        assert_eq!(error.to_string(), "invalid RAMFLUX_GATEWAY_ID");

        issue_test_certificate(root, "spiffe://localhost/ramflux-gateway")?;
        let error = require_error(super::validate_gateway_mesh_identity(&config, "gw-a"))?;
        assert_eq!(error.to_string(), "gateway service certificate has no instance id");

        issue_test_certificate(root, "spiffe://foreign/ramflux-gateway/gw-a")?;
        let error = require_error(super::validate_gateway_mesh_identity(&config, "gw-a"))?;
        assert_eq!(
            error.to_string(),
            "gateway service certificate node id does not match configured node id"
        );
        Ok(())
    }

    #[test]
    fn gateway_peer_directory_rejects_invalid_peer_instance_ids() -> anyhow::Result<()> {
        let directory = TestRoot::new()?;
        let config = config(&directory.0, "localhost");
        let Err(error) =
            gateway_peer_directory_from_value(&config, "gw-a", Some("GW-B=ramflux-gateway-b:7443"))
        else {
            anyhow::bail!("invalid peer id must refuse start");
        };
        assert_eq!(error.to_string(), "invalid gateway peer instance id in RAMFLUX_GATEWAY_PEERS");
        Ok(())
    }
}
