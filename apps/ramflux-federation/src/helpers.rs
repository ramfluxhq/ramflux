// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{FederationDiscoverySurface, RouterAsyncMeshClient, RouterMeshClient};

const ROUTER_ASYNC_ENDPOINT_ENV: &str = "RAMFLUX_ROUTER_ASYNC_ENDPOINT";
const ROUTER_ASYNC_SERVER_NAME_ENV: &str = "RAMFLUX_ROUTER_ASYNC_SERVER_NAME";
const ROUTER_ASYNC_PEER_CA_PEM_ENV: &str = "RAMFLUX_ROUTER_ASYNC_PEER_CA_PEM";
const ROUTER_ASYNC_PEER_CA_PEM_FILE_ENV: &str = "RAMFLUX_ROUTER_ASYNC_PEER_CA_PEM_FILE";
const DEFAULT_ROUTER_ASYNC_ENDPOINT: &str = "ramflux-router:17444";

pub(crate) fn router_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> Result<RouterMeshClient, ramflux_node_core::NodeCoreError> {
    let endpoint = config.mesh.endpoints.get("router").cloned().unwrap_or_default();
    if endpoint.is_empty() {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(
            "missing router mesh endpoint".to_owned(),
        ));
    }
    Ok(RouterMeshClient {
        endpoint,
        server_name: "ramflux-router".to_owned(),
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: config.mesh.ca_cert.clone().into(),
            service_cert: config.mesh.service_cert.clone().into(),
            service_key: config.mesh.service_key.clone().into(),
        },
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: router_async_mesh_client(config)?,
    })
}

fn router_async_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> Result<Option<RouterAsyncMeshClient>, ramflux_node_core::NodeCoreError> {
    router_async_mesh_client_from_endpoint_value(
        config,
        std::env::var(ROUTER_ASYNC_ENDPOINT_ENV).ok().as_deref(),
    )
}

fn router_async_mesh_client_from_endpoint_value(
    config: &ramflux_node_core::NodeServiceConfig,
    endpoint_value: Option<&str>,
) -> Result<Option<RouterAsyncMeshClient>, ramflux_node_core::NodeCoreError> {
    let Some(endpoint) = endpoint_from_env_value(endpoint_value, DEFAULT_ROUTER_ASYNC_ENDPOINT)
    else {
        return Ok(None);
    };
    Ok(Some(RouterAsyncMeshClient {
        endpoint,
        server_name: non_empty_env(ROUTER_ASYNC_SERVER_NAME_ENV)
            .unwrap_or_else(|| "ramflux-router".to_owned()),
        tls: mesh_tls_config(config),
        peer_ca_pems: router_async_peer_ca_pems(config)?,
    }))
}

pub(crate) fn router_post_json<T, R>(
    router: &RouterMeshClient,
    path: &str,
    value: &T,
) -> Result<R, ramflux_node_core::NodeCoreError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    if let Some(async_mesh) = &router.async_mesh {
        match ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
            &async_mesh.endpoint,
            path,
            &async_mesh.tls,
            &async_mesh.server_name,
            &async_mesh.peer_ca_pems,
            value,
        ) {
            Ok(response) => return Ok(response),
            Err(error @ ramflux_transport::TransportError::Quic(_)) => {
                tracing::warn!(%error, path, "federation router QUIC mesh failed; falling back to blocking mesh");
            }
            Err(error) => {
                return Err(ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()));
            }
        }
    }
    router
        .client
        .post_json(&router.endpoint, path, &router.tls, &router.server_name, value)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

pub(crate) fn router_get_json<R>(
    router: &RouterMeshClient,
    path: &str,
) -> Result<R, ramflux_node_core::NodeCoreError>
where
    R: serde::de::DeserializeOwned,
{
    if let Some(async_mesh) = &router.async_mesh {
        match ramflux_transport::mesh_quic_get_json_with_peer_ca_pems(
            &async_mesh.endpoint,
            path,
            &async_mesh.tls,
            &async_mesh.server_name,
            &async_mesh.peer_ca_pems,
        ) {
            Ok(response) => return Ok(response),
            Err(error @ ramflux_transport::TransportError::Quic(_)) => {
                tracing::warn!(%error, path, "federation router QUIC mesh failed; falling back to blocking mesh");
            }
            Err(error) => {
                return Err(ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()));
            }
        }
    }
    router
        .client
        .get_json(&router.endpoint, path, &router.tls, &router.server_name)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn router_async_peer_ca_pems(
    config: &ramflux_node_core::NodeServiceConfig,
) -> Result<Vec<String>, ramflux_node_core::NodeCoreError> {
    if let Some(pem) = non_empty_env(ROUTER_ASYNC_PEER_CA_PEM_ENV) {
        return Ok(vec![pem]);
    }
    let path = non_empty_env(ROUTER_ASYNC_PEER_CA_PEM_FILE_ENV)
        .unwrap_or_else(|| config.mesh.ca_cert.clone());
    std::fs::read_to_string(path)
        .map(|pem| vec![pem])
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn endpoint_from_env_value(value: Option<&str>, default: &str) -> Option<String> {
    let Some(value) = value else {
        return Some(default.to_owned());
    };
    let trimmed = value.trim();
    if trimmed.starts_with("${") {
        return Some(default.to_owned());
    }
    if trimmed.is_empty() || is_env_disabled(trimmed) {
        return None;
    }
    Some(trimmed.to_owned())
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.starts_with("${") {
            return None;
        }
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn is_env_disabled(value: &str) -> bool {
    value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("no")
}

pub(crate) fn federation_discovery_surface(
    config: &ramflux_node_core::NodeServiceConfig,
    node_signing_seed: [u8; 32],
) -> FederationDiscoverySurface {
    let node_ca_cert_pem = std::fs::read_to_string(&config.mesh.ca_cert).unwrap_or_default();
    FederationDiscoverySurface {
        node_id: std::env::var("RAMFLUX_FEDERATION_NODE_ID")
            .unwrap_or_else(|_| config.node_id.clone()),
        public_endpoint: std::env::var("RAMFLUX_FEDERATION_PUBLIC_ENDPOINT")
            .unwrap_or_else(|_| config.mesh.listen_addr.clone()),
        node_public_key: ramflux_crypto::public_key_base64url_from_seed(node_signing_seed),
        node_ca_cert_pem,
        node_signing_seed,
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned(), "https_json".to_owned()],
        node_capabilities: vec![
            "opaque_delivery".to_owned(),
            "federation_relay".to_owned(),
            "friend_request".to_owned(),
        ],
    }
}

pub(crate) fn federation_node_signing_seed(
    state: &mut ramflux_node_core::FederationTrustState,
) -> Result<[u8; 32], ramflux_node_core::NodeCoreError> {
    let configured = std::env::var("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL").ok();
    federation_node_signing_seed_from_config(
        state,
        configured.as_deref(),
        ramflux_crypto::random_32,
    )
}

impl FederationDiscoverySurface {
    pub(crate) fn well_known_record(
        &self,
    ) -> Result<ramflux_node_core::FederationServerRecord, ramflux_node_core::NodeCoreError> {
        let now = now_unix_seconds()?;
        let mut record = ramflux_node_core::FederationServerRecord {
            schema: "ramflux.well_known_server.v1".to_owned(),
            node_id: self.node_id.clone(),
            node_public_key: self.node_public_key.clone(),
            node_ca_cert_pem: self.node_ca_cert_pem.clone(),
            node_endpoint: self.public_endpoint.clone(),
            protocol_versions: self.protocol_versions.clone(),
            transport_backends: self.transport_backends.clone(),
            node_capabilities: self.node_capabilities.clone(),
            node_policy_hash: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::FEDERATION_HANDSHAKE,
                self.node_id.as_bytes(),
            ),
            updated_at: now,
            expires_at: now.saturating_add(86_400),
            signature: String::new(),
        };
        ramflux_node_core::sign_federation_server_record_with_seed(
            &mut record,
            self.node_signing_seed,
        )?;
        Ok(record)
    }
}

#[cfg(test)]
mod router_quic_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn router_async_mesh_client_defaults_on_and_explicit_close_disables_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("federation_router_default")?;
        let ca = issue_test_ca(&root)?;
        let federation = issue_test_service_cert(&ca, "node-router-a", "ramflux-federation")?;
        let config = test_config(&federation.tls, "unused-router:18443");

        let client = router_async_mesh_client_from_endpoint_value(&config, None)?
            .ok_or_else(|| test_error("router async mesh should default to QUIC"))?;
        assert_eq!(client.endpoint, DEFAULT_ROUTER_ASYNC_ENDPOINT);
        assert_eq!(client.server_name, "ramflux-router");
        assert_eq!(client.peer_ca_pems, vec![ca.pem.clone()]);

        assert!(router_async_mesh_client_from_endpoint_value(&config, Some(""))?.is_none());
        assert!(router_async_mesh_client_from_endpoint_value(&config, Some("0"))?.is_none());
        assert!(router_async_mesh_client_from_endpoint_value(&config, Some("off"))?.is_none());
        assert_eq!(
            router_async_mesh_client_from_endpoint_value(
                &config,
                Some("${RAMFLUX_ROUTER_ASYNC_ENDPOINT:-}")
            )?
            .ok_or_else(|| test_error("literal compose endpoint should use default"))?
            .endpoint,
            DEFAULT_ROUTER_ASYNC_ENDPOINT
        );
        Ok(())
    }

    #[test]
    fn router_post_json_falls_back_when_quic_transport_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("federation_router_post_fallback")?;
        let ca = issue_test_ca(&root)?;
        let federation = issue_test_service_cert(&ca, "node-router-a", "ramflux-federation")?;
        let router = issue_test_service_cert(&ca, "node-router-a", "ramflux-router")?;
        let (endpoint, received) =
            spawn_router_blocking_mesh_echo_server(router.tls.clone(), ca.pem.clone(), "POST")?;
        let config = test_config(&federation.tls, &endpoint);
        let client = test_router_client(&config, Some(bad_router_async_mesh(&federation, &ca)));

        let response: serde_json::Value =
            router_post_json(&client, "/mvp1/prekey/fetch", &serde_json::json!({"device": "a"}))?;

        assert_eq!(response, serde_json::json!({"ok": true, "method": "POST"}));
        let request = received.recv_timeout(Duration::from_secs(5))?;
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/mvp1/prekey/fetch");
        Ok(())
    }

    #[test]
    fn router_get_json_falls_back_when_quic_transport_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("federation_router_get_fallback")?;
        let ca = issue_test_ca(&root)?;
        let federation = issue_test_service_cert(&ca, "node-router-a", "ramflux-federation")?;
        let router = issue_test_service_cert(&ca, "node-router-a", "ramflux-router")?;
        let (endpoint, received) =
            spawn_router_blocking_mesh_echo_server(router.tls.clone(), ca.pem.clone(), "GET")?;
        let config = test_config(&federation.tls, &endpoint);
        let client = test_router_client(&config, Some(bad_router_async_mesh(&federation, &ca)));

        let response: serde_json::Value = router_get_json(&client, "/mvp1/prekey/device-a")?;

        assert_eq!(response, serde_json::json!({"ok": true, "method": "GET"}));
        let request = received.recv_timeout(Duration::from_secs(5))?;
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/mvp1/prekey/device-a");
        Ok(())
    }

    fn bad_router_async_mesh(federation: &TestPeerCerts, ca: &TestCa) -> RouterAsyncMeshClient {
        RouterAsyncMeshClient {
            endpoint: "127.0.0.1:1".to_owned(),
            server_name: "ramflux-router".to_owned(),
            tls: federation.tls.clone(),
            peer_ca_pems: vec![ca.pem.clone()],
        }
    }

    fn spawn_router_blocking_mesh_echo_server(
        server_tls: ramflux_transport::MeshTlsConfig,
        trusted_federation_ca: String,
        expected_method: &'static str,
    ) -> Result<
        (String, mpsc::Receiver<ramflux_transport::MeshHttpRequest>),
        Box<dyn std::error::Error>,
    > {
        let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &server_tls)?;
        let endpoint = server.local_addr()?.to_string();
        let (request_tx, request_rx) = mpsc::channel::<ramflux_transport::MeshHttpRequest>();
        std::thread::spawn(move || {
            let result: Result<(), String> = (|| {
                let mut accepted = server
                    .accept_authenticated_with_pem_roots(&server_tls, &[trusted_federation_ca])
                    .map_err(|source| source.to_string())?
                    .stream;
                let request = ramflux_transport::read_mesh_http_request(&mut accepted)
                    .map_err(|source| source.to_string())?
                    .ok_or_else(|| "missing router fallback mesh request".to_owned())?;
                if request.method != expected_method {
                    return Err(format!("unexpected router fallback method {}", request.method));
                }
                let response = serde_json::json!({"ok": true, "method": request.method});
                request_tx.send(request).map_err(|source| source.to_string())?;
                ramflux_transport::write_mesh_json_response(&mut accepted, "200 OK", &response)
                    .map_err(|source| source.to_string())?;
                ramflux_transport::close_mesh_server_stream(&mut accepted)
                    .map_err(|source| source.to_string())
            })();
            if let Err(error) = result {
                tracing::debug!(%error, "federation router fallback test server stopped");
            }
        });
        Ok((endpoint, request_rx))
    }

    fn test_router_client(
        config: &ramflux_node_core::NodeServiceConfig,
        async_mesh: Option<RouterAsyncMeshClient>,
    ) -> RouterMeshClient {
        RouterMeshClient {
            endpoint: config.mesh.endpoints.get("router").cloned().unwrap_or_default(),
            server_name: "ramflux-router".to_owned(),
            tls: mesh_tls_config(config),
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh,
        }
    }

    fn test_config(
        tls: &ramflux_transport::MeshTlsConfig,
        router_endpoint: &str,
    ) -> ramflux_node_core::NodeServiceConfig {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("router".to_owned(), router_endpoint.to_owned());
        ramflux_node_core::NodeServiceConfig {
            node_id: "node-router-a".to_owned(),
            service_id: "ramflux-federation".to_owned(),
            redb_path: ":memory:".to_owned(),
            node_service_signing_seed_b64url: None,
            mesh: ramflux_node_core::MeshConfig {
                listen_addr: "127.0.0.1:0".to_owned(),
                ca_cert: tls.ca_cert.to_string_lossy().into_owned(),
                service_cert: tls.service_cert.to_string_lossy().into_owned(),
                service_key: tls.service_key.to_string_lossy().into_owned(),
                allowed_service_ids: BTreeSet::from([
                    "ramflux-federation".to_owned(),
                    "ramflux-router".to_owned(),
                ]),
                endpoints,
            },
            gateway: None,
            signaling: None,
            relay: None,
        }
    }

    struct TestCa {
        cert: PathBuf,
        key: PathBuf,
        pem: String,
    }

    struct TestPeerCerts {
        tls: ramflux_transport::MeshTlsConfig,
    }

    fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ramflux_federation_{name}_{}_{}",
            std::process::id(),
            nanos
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn issue_test_ca(root: &Path) -> Result<TestCa, Box<dyn std::error::Error>> {
        let ca_key = root.join("ca-key.pem");
        let ca_cert = root.join("ca.pem");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
        run_openssl(&[
            "req",
            "-x509",
            "-new",
            "-key",
            path_str(&ca_key)?,
            "-out",
            path_str(&ca_cert)?,
            "-days",
            "30",
            "-subj",
            "/CN=Ramflux Federation Router Mesh Test CA",
        ])?;
        Ok(TestCa { cert: ca_cert.clone(), key: ca_key, pem: std::fs::read_to_string(ca_cert)? })
    }

    fn issue_test_service_cert(
        ca: &TestCa,
        node_id: &str,
        service_id: &str,
    ) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
        let service_dir =
            ca.cert.parent().ok_or_else(|| test_error("CA cert has no parent"))?.join(service_id);
        std::fs::create_dir_all(&service_dir)?;
        let service_key = service_dir.join(format!("{service_id}-key.pem"));
        let service_csr = service_dir.join(format!("{service_id}.csr"));
        let service_cert = service_dir.join(format!("{service_id}.pem"));
        let ext = service_dir.join(format!("{service_id}.ext"));
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&service_key)?])?;
        run_openssl(&[
            "req",
            "-new",
            "-key",
            path_str(&service_key)?,
            "-out",
            path_str(&service_csr)?,
            "-subj",
            &format!("/CN={service_id}"),
        ])?;
        std::fs::write(
            &ext,
            format!(
                "subjectAltName = DNS:{service_id}, DNS:localhost, URI:spiffe://{node_id}/{service_id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
            ),
        )?;
        run_openssl(&[
            "x509",
            "-req",
            "-in",
            path_str(&service_csr)?,
            "-CA",
            path_str(&ca.cert)?,
            "-CAkey",
            path_str(&ca.key)?,
            "-CAcreateserial",
            "-out",
            path_str(&service_cert)?,
            "-days",
            "30",
            "-extfile",
            path_str(&ext)?,
        ])?;
        Ok(TestPeerCerts {
            tls: ramflux_transport::MeshTlsConfig {
                ca_cert: ca.cert.clone(),
                service_cert,
                service_key,
            },
        })
    }

    fn run_openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("openssl").args(args).status()?;
        if !status.success() {
            return Err(format!("openssl failed with status {status}: {}", args.join(" ")).into());
        }
        Ok(())
    }

    fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
        path.to_str().ok_or_else(|| format!("non-UTF-8 path {}", path.display()).into())
    }

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
        message.into().into()
    }
}

fn federation_node_signing_seed_from_config(
    state: &mut ramflux_node_core::FederationTrustState,
    configured_seed: Option<&str>,
    random_seed: impl FnOnce() -> Result<[u8; 32], ramflux_crypto::CryptoError>,
) -> Result<[u8; 32], ramflux_node_core::NodeCoreError> {
    if let Some(encoded) = configured_seed.filter(|value| !value.trim().is_empty()) {
        let bytes = ramflux_protocol::decode_base64url(encoded)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        let seed = <[u8; 32]>::try_from(bytes).map_err(|bytes: Vec<u8>| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL length: {}",
                bytes.len()
            ))
        })?;
        state.set_node_signing_seed(seed);
        return Ok(seed);
    }
    if let Some(seed) = state.node_signing_seed() {
        return Ok(seed);
    }
    let seed = random_seed()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    state.set_node_signing_seed(seed);
    Ok(seed)
}

pub(crate) fn now_unix_seconds() -> Result<u64, ramflux_node_core::NodeCoreError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

pub(crate) fn mesh_tls_config(
    config: &ramflux_node_core::NodeServiceConfig,
) -> ramflux_transport::MeshTlsConfig {
    ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    }
}

pub(crate) fn mesh_transport_error(
    error: &ramflux_transport::TransportError,
) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_record_uses_current_time_window() -> Result<(), ramflux_node_core::NodeCoreError>
    {
        let now = now_unix_seconds()?;
        let seed = ramflux_crypto::blake3_256("ramflux.federation.test_seed.v1", b"well-known");
        let surface = FederationDiscoverySurface {
            node_id: "node_test.realnet".to_owned(),
            public_endpoint: "ramflux-test-federation:7443".to_owned(),
            node_public_key: ramflux_crypto::public_key_base64url_from_seed(seed),
            node_ca_cert_pem: "test-ca".to_owned(),
            node_signing_seed: seed,
            protocol_versions: vec!["v1".to_owned()],
            transport_backends: vec!["https_json".to_owned()],
            node_capabilities: vec!["opaque_delivery".to_owned()],
        };

        let record = surface.well_known_record()?;

        assert!(record.updated_at >= now);
        assert_eq!(record.expires_at, record.updated_at.saturating_add(86_400));
        ramflux_node_core::verify_federation_server_record(&record, record.updated_at)?;
        Ok(())
    }

    #[test]
    fn node_signing_seed_uses_env_and_persists_to_state()
    -> Result<(), ramflux_node_core::NodeCoreError> {
        let env_seed = [0x42; 32];
        let encoded = ramflux_protocol::encode_base64url(env_seed);
        let mut state = ramflux_node_core::FederationTrustState::new();

        let resolved = federation_node_signing_seed_from_config(
            &mut state,
            Some(&encoded),
            || Ok([0x77; 32]),
        )?;

        assert_eq!(resolved, env_seed);
        assert_eq!(state.node_signing_seed(), Some(env_seed));
        Ok(())
    }

    #[test]
    fn node_signing_seed_rejects_invalid_env_seed() -> Result<(), ramflux_node_core::NodeCoreError>
    {
        let mut state = ramflux_node_core::FederationTrustState::new();

        let Err(error) =
            federation_node_signing_seed_from_config(&mut state, Some("bad-seed"), || {
                Ok([0x77; 32])
            })
        else {
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "invalid configured federation seed must fail".to_owned(),
            ));
        };

        assert!(
            error
                .to_string()
                .contains("invalid RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL length"),
            "{error}"
        );
        assert_eq!(state.node_signing_seed(), None);
        Ok(())
    }

    #[test]
    fn node_signing_seed_reuses_persisted_seed_before_random()
    -> Result<(), ramflux_node_core::NodeCoreError> {
        let persisted_seed = [0x33; 32];
        let mut state = ramflux_node_core::FederationTrustState::new();
        state.set_node_signing_seed(persisted_seed);

        let resolved =
            federation_node_signing_seed_from_config(&mut state, None, || Ok([0x99; 32]))?;

        assert_eq!(resolved, persisted_seed);
        Ok(())
    }

    #[test]
    fn node_signing_seed_generates_and_persists_when_missing()
    -> Result<(), ramflux_node_core::NodeCoreError> {
        let generated_seed = [0x55; 32];
        let mut state = ramflux_node_core::FederationTrustState::new();

        let resolved =
            federation_node_signing_seed_from_config(&mut state, None, || Ok(generated_seed))?;

        assert_eq!(resolved, generated_seed);
        assert_eq!(state.node_signing_seed(), Some(generated_seed));
        Ok(())
    }
}
