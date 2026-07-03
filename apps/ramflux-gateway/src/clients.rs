// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::{Arc, Mutex};

use crate::{NotifyHttpClient, NotifyMeshClient, RouterAsyncMeshClient, RouterMeshClient};

const ROUTER_ASYNC_ENDPOINT_ENV: &str = "RAMFLUX_ROUTER_ASYNC_ENDPOINT";
const ROUTER_ASYNC_SERVER_NAME_ENV: &str = "RAMFLUX_ROUTER_ASYNC_SERVER_NAME";
const ROUTER_ASYNC_PEER_CA_PEM_ENV: &str = "RAMFLUX_ROUTER_ASYNC_PEER_CA_PEM";
const ROUTER_ASYNC_PEER_CA_PEM_FILE_ENV: &str = "RAMFLUX_ROUTER_ASYNC_PEER_CA_PEM_FILE";
const NOTIFY_MESH_ENDPOINT_ENV: &str = "RAMFLUX_NOTIFY_MESH_ENDPOINT";
const NOTIFY_MESH_SERVER_NAME_ENV: &str = "RAMFLUX_NOTIFY_MESH_SERVER_NAME";
const NOTIFY_MESH_PEER_CA_PEM_ENV: &str = "RAMFLUX_NOTIFY_MESH_PEER_CA_PEM";
const NOTIFY_MESH_PEER_CA_PEM_FILE_ENV: &str = "RAMFLUX_NOTIFY_MESH_PEER_CA_PEM_FILE";

pub(crate) fn router_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<RouterMeshClient> {
    let endpoint = config.mesh.endpoints.get("router").cloned().unwrap_or_default();
    if endpoint.is_empty() {
        return Err(anyhow::anyhow!("missing router mesh endpoint"));
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
) -> anyhow::Result<Option<RouterAsyncMeshClient>> {
    let Some(endpoint) = non_empty_env(ROUTER_ASYNC_ENDPOINT_ENV) else {
        return Ok(None);
    };
    Ok(Some(RouterAsyncMeshClient {
        endpoint,
        server_name: non_empty_env(ROUTER_ASYNC_SERVER_NAME_ENV)
            .unwrap_or_else(|| "ramflux-router".to_owned()),
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: config.mesh.ca_cert.clone().into(),
            service_cert: config.mesh.service_cert.clone().into(),
            service_key: config.mesh.service_key.clone().into(),
        },
        peer_ca_pems: router_async_peer_ca_pems(config)?,
    }))
}

pub(crate) fn notify_http_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<NotifyHttpClient> {
    Ok(NotifyHttpClient {
        endpoint: std::env::var("RAMFLUX_NOTIFY_HTTP_URL")
            .unwrap_or_else(|_| "http://ramflux-notify:18083".to_owned()),
        signer: ramflux_node_core::require_node_service_signing_key(config)?,
        mesh: notify_mesh_client(config)?,
    })
}

fn notify_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<Option<NotifyMeshClient>> {
    let Some(endpoint) = non_empty_env(NOTIFY_MESH_ENDPOINT_ENV) else {
        return Ok(None);
    };
    Ok(Some(NotifyMeshClient {
        endpoint,
        server_name: non_empty_env(NOTIFY_MESH_SERVER_NAME_ENV)
            .unwrap_or_else(|| "ramflux-notify".to_owned()),
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: config.mesh.ca_cert.clone().into(),
            service_cert: config.mesh.service_cert.clone().into(),
            service_key: config.mesh.service_key.clone().into(),
        },
        peer_ca_pems: notify_mesh_peer_ca_pems(config)?,
    }))
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn notify_mesh_peer_ca_pems(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<Vec<String>> {
    if let Some(pem) = non_empty_env(NOTIFY_MESH_PEER_CA_PEM_ENV) {
        return Ok(vec![pem]);
    }
    let path = non_empty_env(NOTIFY_MESH_PEER_CA_PEM_FILE_ENV)
        .unwrap_or_else(|| config.mesh.ca_cert.clone());
    Ok(vec![std::fs::read_to_string(&path)?])
}

fn router_async_peer_ca_pems(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<Vec<String>> {
    if let Some(pem) = non_empty_env(ROUTER_ASYNC_PEER_CA_PEM_ENV) {
        return Ok(vec![pem]);
    }
    let path = non_empty_env(ROUTER_ASYNC_PEER_CA_PEM_FILE_ENV)
        .unwrap_or_else(|| config.mesh.ca_cert.clone());
    Ok(vec![std::fs::read_to_string(&path)?])
}

#[cfg(feature = "itest-http")]
pub(crate) fn pre_auth_gate(
    request: &ramflux_node_core::NodeHttpRequest,
    state: &Arc<Mutex<ramflux_node_core::GatewayState>>,
    store: &ramflux_node_core::GatewayRedbStore,
) -> anyhow::Result<Option<ramflux_node_core::GatewayPreAuthChallengeResponse>> {
    let source_ip_hash =
        request.source_ip_hash.as_deref().unwrap_or("unknown-source-ip").to_owned();
    let now = request.pre_auth_now.unwrap_or_else(ramflux_node_core::now_unix_seconds);
    let mut gateway = gateway_state(state)?;
    let decision =
        match gateway.check_pre_auth(&source_ip_hash, request.pre_auth_cookie.as_deref(), now) {
            Ok(decision) => decision,
            Err(error) => {
                store.save_pre_auth_hot(&gateway)?;
                return Err(error.into());
            }
        };
    Ok(match decision {
        ramflux_node_core::GatewayPreAuthDecision::Accepted => {
            store.save_pre_auth_hot(&gateway)?;
            None
        }
        ramflux_node_core::GatewayPreAuthDecision::Challenge(challenge) => {
            store.save_pre_auth_with_challenges(&gateway)?;
            Some(challenge)
        }
    })
}

pub(crate) fn gateway_state(
    state: &Arc<Mutex<ramflux_node_core::GatewayState>>,
) -> anyhow::Result<std::sync::MutexGuard<'_, ramflux_node_core::GatewayState>> {
    state.lock().map_err(|error| anyhow::anyhow!("gateway state lock poisoned: {error}"))
}

#[cfg(feature = "itest-http")]
pub(crate) fn is_timeout_error(error: &ramflux_node_core::NodeCoreError) -> bool {
    matches!(error, ramflux_node_core::NodeCoreError::ItestHttp(message) if message.contains("timed out") || message.contains("WouldBlock"))
}

pub(crate) fn router_post_json<T, R>(
    router: &RouterMeshClient,
    path: &str,
    value: &T,
) -> Result<R, ramflux_transport::TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    router.client.post_json(&router.endpoint, path, &router.tls, &router.server_name, value)
}

pub(crate) async fn router_post_json_async<T, R>(
    router: &RouterMeshClient,
    path: &str,
    value: &T,
) -> Result<R, ramflux_transport::TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    if let Some(async_mesh) = &router.async_mesh {
        return ramflux_transport::mesh_quic_post_json_with_peer_ca_pems_async(
            &async_mesh.endpoint,
            path,
            &async_mesh.tls,
            &async_mesh.server_name,
            &async_mesh.peer_ca_pems,
            value,
        )
        .await;
    }
    // Without a configured async router endpoint, fall back to the blocking mesh client.
    // That client blocks on a std mpsc recv, so it must not run directly on the async
    // gateway QUIC worker (it would stall the runtime and the gateway never becomes ready).
    // Run it on a blocking thread instead.
    let router = router.clone();
    let path = path.to_owned();
    let body = serde_json::to_value(value)?;
    let response: serde_json::Value = tokio::task::spawn_blocking(move || {
        router_post_json::<serde_json::Value, serde_json::Value>(&router, &path, &body)
    })
    .await
    .map_err(|error| {
        ramflux_transport::TransportError::Quic(format!("router blocking join failed: {error}"))
    })??;
    Ok(serde_json::from_value(response)?)
}

pub(crate) fn router_get_json<R>(
    router: &RouterMeshClient,
    path: &str,
) -> Result<R, ramflux_transport::TransportError>
where
    R: serde::de::DeserializeOwned,
{
    router.client.get_json(&router.endpoint, path, &router.tls, &router.server_name)
}

pub(crate) fn router_cursor(
    router: &RouterMeshClient,
    target_delivery_id: &str,
) -> Result<Option<ramflux_node_core::InboxCursorResponse>, ramflux_transport::TransportError> {
    router_get_json(router, &format!("/mvp0/cursor/{target_delivery_id}"))
}

pub(crate) fn router_inbox(
    router: &RouterMeshClient,
    target_delivery_id: &str,
    after_inbox_seq: u64,
    limit: usize,
) -> Result<ramflux_node_core::InboxFetchResponse, ramflux_transport::TransportError> {
    router_get_json(
        router,
        &format!("/mvp1/inbox/{target_delivery_id}?after={after_inbox_seq}&limit={limit}"),
    )
}

pub(crate) fn router_session(
    router: &RouterMeshClient,
    target_delivery_id: &str,
) -> Result<Option<ramflux_node_core::SessionDescriptor>, ramflux_transport::TransportError> {
    router_get_json(router, &format!("/s1/session/{target_delivery_id}"))
}

pub(crate) fn notify_offline_wake(
    notify: &NotifyHttpClient,
    target_delivery_id: &str,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<()> {
    let encrypted_hint = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::NOTIFICATION_WAKE,
        envelope.encrypted_payload.as_bytes(),
    );
    let mut wake = ramflux_protocol::NotificationWake {
        schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: notify.signer.signing_key_id().to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        wake_id: format!("wake_{}", envelope.envelope_id),
        push_alias: target_delivery_id.to_owned(),
        delivery_class: notification_class_for_envelope(envelope),
        priority: ramflux_protocol::PushPriority::Normal,
        ttl: 86_400,
        collapse_key: Some(format!(
            "target:{}:content",
            ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::PUSH_ALIAS,
                target_delivery_id.as_bytes(),
            )
        )),
        encrypted_hint: Some(encrypted_hint),
    };
    notify.signer.sign_notification_wake(&mut wake)?;
    let request = S13WakeRequest {
        device_delivery_id: target_delivery_id.to_owned(),
        wake,
        queued_at: ramflux_node_core::now_unix_seconds(),
    };
    let response = if let Some(mesh) = &notify.mesh {
        ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
            &mesh.endpoint,
            "/s13/notify/wake",
            &mesh.tls,
            &mesh.server_name,
            &mesh.peer_ca_pems,
            &request,
        )?
    } else {
        ramflux_node_core::itest_http_post_json(
            &format!("{}/s13/notify/wake", notify.endpoint),
            &request,
        )?
    };
    observe_s13_wake_response(&response);
    Ok(())
}

fn observe_s13_wake_response(response: &S13WakeResponse) {
    let _observed = (&response.entry.queue_id, response.attempts.len());
}

#[derive(serde::Deserialize, serde::Serialize)]
struct S13WakeRequest {
    device_delivery_id: String,
    wake: ramflux_protocol::NotificationWake,
    queued_at: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct S13WakeResponse {
    entry: ramflux_node_core::NotifyQueueEntry,
    attempts: Vec<ramflux_node_core::ProviderPushAttempt>,
}

pub(crate) fn notification_class_for_envelope(
    envelope: &ramflux_protocol::Envelope,
) -> ramflux_protocol::NotificationDeliveryClass {
    match envelope.delivery_class {
        ramflux_protocol::DeliveryClass::SelfDeviceControl => {
            ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification
        }
        ramflux_protocol::DeliveryClass::NotificationWake => {
            ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        }
        _ => ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn notify_offline_wake_posts_over_mesh_when_configured()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("gateway_notify_mesh")?;
        let gateway = issue_test_ca_and_service_cert(&root, "node-mesh-a", "ramflux-gateway")?;
        let notify = issue_test_ca_and_service_cert(&root, "node-mesh-a", "ramflux-notify")?;
        let (endpoint, received) =
            spawn_notify_mesh_echo_server(notify.tls.clone(), gateway.ca_pem.clone())?;
        let signer = ramflux_node_core::NodeServiceSigningKey::from_seed(test_signing_seed());
        let client = NotifyHttpClient {
            endpoint: "http://unused-notify-http".to_owned(),
            signer: signer.clone(),
            mesh: Some(NotifyMeshClient {
                endpoint,
                server_name: "ramflux-notify".to_owned(),
                tls: gateway.tls,
                peer_ca_pems: vec![notify.ca_pem],
            }),
        };
        let envelope = test_envelope("env_notify_mesh");

        notify_offline_wake(&client, "target_notify_mesh", &envelope)?;

        let request = received.recv_timeout(Duration::from_secs(5))?;
        assert_eq!(request.device_delivery_id, "target_notify_mesh");
        assert_eq!(request.wake.wake_id, "wake_env_notify_mesh");
        assert_eq!(request.wake.push_alias, "target_notify_mesh");
        assert_eq!(
            request.wake.delivery_class,
            ramflux_protocol::NotificationDeliveryClass::UserContentNotification
        );
        signer.verify_notification_wake(&request.wake)?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn router_post_json_async_posts_over_mesh_when_configured()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("gateway_router_async_mesh")?;
        let gateway = issue_test_ca_and_service_cert(&root, "node-mesh-a", "ramflux-gateway")?;
        let router = issue_test_ca_and_service_cert(&root, "node-mesh-a", "ramflux-router")?;
        let (endpoint, received) =
            spawn_router_mesh_echo_server(router.tls.clone(), gateway.ca_pem.clone())?;
        let client = RouterMeshClient {
            endpoint: "unused-blocking-router".to_owned(),
            server_name: "ramflux-router".to_owned(),
            tls: gateway.tls.clone(),
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh: Some(RouterAsyncMeshClient {
                endpoint,
                server_name: "ramflux-router".to_owned(),
                tls: gateway.tls,
                peer_ca_pems: vec![router.ca_pem],
            }),
        };
        let envelope = test_envelope("env_router_async_mesh");
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let response: ramflux_node_core::EnvelopeSubmitResponse =
            runtime.block_on(router_post_json_async(&client, "/mvp0/envelope", &envelope))?;

        assert_eq!(response.outcome, "offline_queued");
        assert_eq!(response.target_delivery_id, "target_notify_mesh");
        let request = received.recv_timeout(Duration::from_secs(5))?;
        assert_eq!(request.envelope_id, "env_router_async_mesh");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    fn spawn_notify_mesh_echo_server(
        server_tls: ramflux_transport::MeshTlsConfig,
        trusted_gateway_ca: String,
    ) -> Result<(String, mpsc::Receiver<S13WakeRequest>), Box<dyn std::error::Error>> {
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let (request_tx, request_rx) = mpsc::channel::<S13WakeRequest>();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| source.to_string());
            let Ok(runtime) = runtime else {
                let _ = endpoint_tx.send(runtime.map(|_| String::new()));
                return;
            };
            let result: Result<(), String> = runtime.block_on(async move {
                let roots = Arc::new(move || Ok(vec![trusted_gateway_ca.clone()]));
                let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
                    "127.0.0.1:0",
                    &server_tls,
                    roots,
                )
                .map_err(|source| source.to_string())?;
                endpoint_tx
                    .send(
                        server
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .map_err(|source| source.to_string()),
                    )
                    .map_err(|source| source.to_string())?;
                let connection =
                    server.accept_connection().await.map_err(|source| source.to_string())?;
                let accepted =
                    ramflux_transport::MeshQuicServer::accept_request_on_connection(&connection)
                        .await
                        .map_err(|source| source.to_string())?;
                if accepted.request.method != "POST" || accepted.request.path != "/s13/notify/wake"
                {
                    return Err(format!(
                        "unexpected notify mesh request {} {}",
                        accepted.request.method, accepted.request.path
                    ));
                }
                let request: S13WakeRequest = serde_json::from_value(accepted.request.body.clone())
                    .map_err(|source| source.to_string())?;
                let response = S13WakeResponse {
                    entry: notify_queue_entry_from_request(&request),
                    attempts: Vec::new(),
                };
                request_tx.send(request).map_err(|source| source.to_string())?;
                accepted
                    .write_json_response(200, &response)
                    .await
                    .map_err(|source| source.to_string())?;
                std::future::pending::<()>().await;
                Ok(())
            });
            if let Err(error) = result {
                tracing::debug!(%error, "gateway notify mesh test server stopped");
            }
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|source| test_error(source.to_string()))?
            .map_err(test_error)?;
        Ok((endpoint, request_rx))
    }

    fn spawn_router_mesh_echo_server(
        server_tls: ramflux_transport::MeshTlsConfig,
        trusted_gateway_ca: String,
    ) -> Result<(String, mpsc::Receiver<ramflux_protocol::Envelope>), Box<dyn std::error::Error>>
    {
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let (request_tx, request_rx) = mpsc::channel::<ramflux_protocol::Envelope>();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| source.to_string());
            let Ok(runtime) = runtime else {
                let _ = endpoint_tx.send(runtime.map(|_| String::new()));
                return;
            };
            let result: Result<(), String> = runtime.block_on(async move {
                let roots = Arc::new(move || Ok(vec![trusted_gateway_ca.clone()]));
                let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
                    "127.0.0.1:0",
                    &server_tls,
                    roots,
                )
                .map_err(|source| source.to_string())?;
                endpoint_tx
                    .send(
                        server
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .map_err(|source| source.to_string()),
                    )
                    .map_err(|source| source.to_string())?;
                let connection =
                    server.accept_connection().await.map_err(|source| source.to_string())?;
                let accepted =
                    ramflux_transport::MeshQuicServer::accept_request_on_connection(&connection)
                        .await
                        .map_err(|source| source.to_string())?;
                if accepted.request.method != "POST" || accepted.request.path != "/mvp0/envelope" {
                    return Err(format!(
                        "unexpected router mesh request {} {}",
                        accepted.request.method, accepted.request.path
                    ));
                }
                let request: ramflux_protocol::Envelope =
                    serde_json::from_value(accepted.request.body.clone())
                        .map_err(|source| source.to_string())?;
                let response = ramflux_node_core::EnvelopeSubmitResponse {
                    outcome: "offline_queued".to_owned(),
                    target_delivery_id: request.target_delivery_id.clone(),
                    inbox_seq: Some(1),
                    cursor: None,
                    nack: None,
                };
                request_tx.send(request).map_err(|source| source.to_string())?;
                accepted
                    .write_json_response(200, &response)
                    .await
                    .map_err(|source| source.to_string())?;
                std::future::pending::<()>().await;
                Ok(())
            });
            if let Err(error) = result {
                tracing::debug!(%error, "gateway router async mesh test server stopped");
            }
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|source| test_error(source.to_string()))?
            .map_err(test_error)?;
        Ok((endpoint, request_rx))
    }

    fn notify_queue_entry_from_request(
        request: &S13WakeRequest,
    ) -> ramflux_node_core::NotifyQueueEntry {
        ramflux_node_core::NotifyQueueEntry {
            queue_id: request.wake.wake_id.clone(),
            device_delivery_id: request.device_delivery_id.clone(),
            wake: request.wake.clone(),
            push_alias_hash: "test_push_alias_hash".to_owned(),
            queued_at: request.queued_at,
            expires_at: request.queued_at.saturating_add(u64::from(request.wake.ttl)),
            attempt_count: 0,
            status: ramflux_node_core::NotifyQueueStatus::Pending,
            dnd_active: false,
        }
    }

    struct TestPeerCerts {
        tls: ramflux_transport::MeshTlsConfig,
        ca_pem: String,
    }

    fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ramflux_gateway_{name}_{}_{}",
            std::process::id(),
            nanos
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn issue_test_ca_and_service_cert(
        root: &Path,
        node_id: &str,
        service_id: &str,
    ) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
        let dir = root.join(service_id);
        std::fs::create_dir_all(&dir)?;
        let ca_key = dir.join("ca-key.pem");
        let ca_cert = dir.join("ca.pem");
        let service_key = dir.join(format!("{service_id}-key.pem"));
        let service_csr = dir.join(format!("{service_id}.csr"));
        let service_cert = dir.join(format!("{service_id}.pem"));
        let ext = dir.join(format!("{service_id}.ext"));
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
            "/CN=Ramflux Gateway Notify Mesh Test CA",
        ])?;
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
            path_str(&ca_cert)?,
            "-CAkey",
            path_str(&ca_key)?,
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
                ca_cert: ca_cert.clone(),
                service_cert,
                service_key,
            },
            ca_pem: std::fs::read_to_string(ca_cert)?,
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

    fn test_signing_seed() -> [u8; 32] {
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]
    }

    fn test_envelope(envelope_id: &str) -> ramflux_protocol::Envelope {
        ramflux_protocol::Envelope {
            schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "test-envelope-key".to_owned(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "test-envelope-signature".to_owned(),
            },
            envelope_id: envelope_id.to_owned(),
            source_principal_id: "principal_gateway_test".to_owned(),
            source_device_id: "device_gateway_test".to_owned(),
            target_delivery_id: "target_notify_mesh".to_owned(),
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 86_400,
            created_at: 1_760_000_000,
            encrypted_payload: "encrypted_payload".to_owned(),
            payload_hash: "payload_hash".to_owned(),
        }
    }

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
        Box::new(std::io::Error::other(message.into()))
    }
}
