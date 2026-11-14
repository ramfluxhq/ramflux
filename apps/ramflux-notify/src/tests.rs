// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
#[cfg(feature = "itest-http")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "itest-http")]
use std::sync::{Arc, Mutex, mpsc};
#[cfg(feature = "itest-http")]
use std::{path::Path, process::Command};

#[cfg(feature = "itest-http")]
#[test]
fn s13_body_rejects_duplicate_members_and_noncharacters() {
    let signed = r#"{"body":{"action":"enqueue","audience":"ramflux-notify","class":"message","created_at":1,"expires_at":2,"signature_alg":"ed25519","signing_key_id":"k","source_event_id":"env","target_delivery_id":"device","target_owner_epoch":1,"version":2,"wake_id":"AAAAAAAAAAAAAAAAAAAAAA"},"signature":"sig"}"#;
    let clean = format!(r#"{{"device_delivery_id":"device","signed_wake":{signed}}}"#);
    assert!(parse_s13_wake_request_body(clean.as_bytes()).is_ok());
    let duplicate = format!(
        r#"{{"device_delivery_id":"device","device_delivery_id":"other","signed_wake":{signed}}}"#
    );
    assert!(serde_json::from_slice::<serde_json::Value>(duplicate.as_bytes()).is_ok());
    let collapsed = serde_json::from_slice::<serde_json::Value>(duplicate.as_bytes())
        .unwrap_or(serde_json::Value::Null);
    assert!(serde_json::from_value::<S13WakeRequest>(collapsed).is_ok());
    assert!(parse_s13_wake_request_body(duplicate.as_bytes()).is_err());
    let noncharacter = format!(r#"{{"device_delivery_id":"bad\uFFFF","signed_wake":{signed}}}"#);
    assert!(serde_json::from_slice::<S13WakeRequest>(noncharacter.as_bytes()).is_ok());
    assert!(parse_s13_wake_request_body(noncharacter.as_bytes()).is_err());
}

#[test]
fn provider_common_headers_follow_s13_contract() -> Result<(), Box<dyn std::error::Error>> {
    let prepared = test_prepared_push(ramflux_node_core::PushProviderKind::Fcm);
    let parts = contract_parts(&prepared)?;
    assert!(
        parts.headers.iter().all(|(name, _)| !name.to_ascii_lowercase().starts_with("ramflux-"))
    );
    assert_eq!(parts.headers.len(), 0);
    let body: serde_json::Value = serde_json::from_slice(&parts.body)?;
    let message = body.get("message").ok_or("fcm message")?;
    assert!(message.get("notification").is_none());
    assert!(message.get("data").and_then(|data| data.get("encrypted_hint")).is_none());
    assert_eq!(
        message.get("data").and_then(|data| data.get("class")).and_then(|value| value.as_str()),
        Some("message")
    );
    Ok(())
}

#[test]
fn notify_mesh_ingress_defaults_on_and_opt_out_disables_it() {
    assert!(notify_mesh_ingress_enabled_from_value(None));
    assert!(notify_mesh_ingress_enabled_from_value(Some("1")));
    assert!(notify_mesh_ingress_enabled_from_value(Some("true")));
    assert!(notify_mesh_ingress_enabled_from_value(Some("on")));
    assert!(!notify_mesh_ingress_enabled_from_value(Some("0")));
    assert!(!notify_mesh_ingress_enabled_from_value(Some("false")));
    assert!(!notify_mesh_ingress_enabled_from_value(Some("off")));
    assert!(!notify_mesh_ingress_enabled_from_value(Some("no")));
}

#[test]
fn notify_mesh_listen_addr_defaults_and_guards_compose_literal() {
    assert_eq!(
        notify_mesh_listen_addr_from_value(None).as_deref(),
        Some(DEFAULT_NOTIFY_MESH_LISTEN_ADDR)
    );
    assert_eq!(
        notify_mesh_listen_addr_from_value(Some("${RAMFLUX_NOTIFY_MESH_LISTEN_ADDR:-}")).as_deref(),
        Some(DEFAULT_NOTIFY_MESH_LISTEN_ADDR)
    );
    assert_eq!(
        notify_mesh_listen_addr_from_value(Some(
            "${RAMFLUX_NOTIFY_MESH_LISTEN_ADDR:-0.0.0.0:18085}"
        ))
        .as_deref(),
        Some(DEFAULT_NOTIFY_MESH_LISTEN_ADDR)
    );
    assert_eq!(
        notify_mesh_listen_addr_from_value(Some(" 127.0.0.1:18085 ")).as_deref(),
        Some("127.0.0.1:18085")
    );
    assert!(notify_mesh_listen_addr_from_value(Some("")).is_none());
    assert_eq!(
        notify_mesh_listen_addr_from_value(Some("not-an-address")).as_deref(),
        Some(DEFAULT_NOTIFY_MESH_LISTEN_ADDR)
    );
}

#[test]
fn notify_mesh_ingress_runtime_defaults_to_tokio_and_unknown_values_do_not_error() {
    assert_eq!(notify_mesh_ingress_runtime_from_value(None), NotifyMeshIngressRuntime::Tokio);
    assert_eq!(
        notify_mesh_ingress_runtime_from_value(Some("tokio")),
        NotifyMeshIngressRuntime::Tokio
    );
    assert_eq!(
        notify_mesh_ingress_runtime_from_value(Some("quinn")),
        NotifyMeshIngressRuntime::Tokio
    );
    assert_eq!(
        notify_mesh_ingress_runtime_from_value(Some(
            "${RAMFLUX_NOTIFY_MESH_INGRESS_RUNTIME:-tokio}"
        )),
        NotifyMeshIngressRuntime::Tokio
    );
    assert_eq!(
        notify_mesh_ingress_runtime_from_value(Some("future-runtime")),
        NotifyMeshIngressRuntime::Tokio
    );
}

#[cfg(feature = "itest-http")]
#[test]
fn notify_mesh_quic_accepts_s13_wake() -> Result<(), Box<dyn std::error::Error>> {
    let root = notify_mesh_test_cert_root("notify_mesh_quic_accepts_s13_wake")?;
    let gateway = issue_notify_mesh_test_cert(&root, "node-mesh-a", "ramflux-gateway")?;
    let notify = issue_notify_mesh_test_cert(&root, "node-mesh-a", "ramflux-notify")?;
    let store_path = root.join("notify.redb");
    let store = Arc::new(ramflux_node_core::NotifyRedbStore::open(&store_path)?);
    let store_gate = Arc::new(Mutex::new(()));
    let signing_key =
        ramflux_node_core::NodeServiceSigningKey::from_seed(bench_node_service_signing_seed());
    let wake_auth = NotifyWakeAuth { key: signing_key.clone() };
    let ingress = Arc::new(NotifyIngressState {
        authority: Arc::new(send_authority::Surface::without_origins_for_test()),
        store: Arc::clone(&store),
        runtime: Arc::new(NotifyRuntime::Current),
        store_gate,
        async_accept: false,
        wake_auth,
        wake_verify_batcher: None,
    });
    let endpoint = spawn_notify_mesh_test_listener(
        notify.tls.clone(),
        gateway.ca_pem.clone(),
        Arc::clone(&ingress),
    )?;
    let signed = signed_message_wake(&signing_key, "device_mesh_s13", "env-mesh-s13", 7)?;
    let wake_id = signed.body.wake_id.clone();
    let response: serde_json::Value = ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
        &endpoint,
        "/s13/notify/wake",
        &gateway.tls,
        "ramflux-notify",
        std::slice::from_ref(&notify.ca_pem),
        &serde_json::json!({
            "device_delivery_id": "device_mesh_s13",
            "signed_wake": signed,
            "queued_at": 1_760_000_123_u64,
            "dnd_active": false
        }),
    )?;
    assert_eq!(response["entry"]["queue_id"], wake_id);
    assert_eq!(response["entry"]["device_delivery_id"], "device_mesh_s13");
    assert!(response["attempts"].as_array().is_some_and(Vec::is_empty));
    let state = store.load_state()?.ok_or("missing notify state")?;
    let entry = state.entry(&wake_id).ok_or("missing mesh wake entry")?;
    assert_eq!(entry.device_delivery_id, "device_mesh_s13");
    assert_eq!(entry.queued_at, 1_760_000_123);
    drop(ingress);
    drop(store);
    Ok(())
}

#[cfg(feature = "itest-http")]
fn spawn_notify_mesh_test_listener(
    server_tls: ramflux_transport::MeshTlsConfig,
    trusted_gateway_ca: String,
    ingress: Arc<NotifyIngressState>,
) -> Result<String, Box<dyn std::error::Error>> {
    let (endpoint_tx, endpoint_rx) = mpsc::sync_channel::<Result<String, String>>(1);
    let _server_thread = std::thread::spawn(move || {
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
            loop {
                let connection = match server.accept_connection().await {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::debug!(%error, "notify mesh test listener accept ended");
                        continue;
                    }
                };
                let request_ingress = Arc::clone(&ingress);
                tokio::spawn(async move {
                    if let Err(error) =
                        notify_mesh_quic_connection_loop(connection, request_ingress).await
                    {
                        tracing::debug!(%error, "notify mesh test connection ended");
                    }
                });
            }
        });
        if let Err(error) = result {
            tracing::debug!(%error, "notify mesh test listener stopped");
        }
    });
    endpoint_rx.recv().map_err(|source| test_error(source.to_string()))?.map_err(test_error)
}

#[ignore = "microbenchmark; set RAMFLUX_NOTIFY_WAL=1 and run explicitly with --ignored --nocapture"]
#[cfg(feature = "itest-http")]
#[test]
fn notify_ingest_throughput_bench() -> Result<(), Box<dyn std::error::Error>> {
    let total = bench_usize_env("RAMFLUX_INGEST_BENCH_TOTAL", 1_000_000);
    let producers = bench_usize_env("RAMFLUX_INGEST_BENCH_PRODUCERS", 16);
    let seed = bench_node_service_signing_seed();
    let key = ramflux_node_core::NodeServiceSigningKey::from_seed(seed);
    let raw_bodies = Arc::new(signed_s13_wake_request_bodies(&key, total)?);
    let temp_root = notify_ingest_bench_temp_root();
    std::fs::create_dir_all(&temp_root)?;
    let store_path = temp_root.join("notify.redb");
    let store = Arc::new(ramflux_node_core::NotifyRedbStore::open(&store_path)?);
    if !store.uses_notify_wal() {
        let _ = std::fs::remove_dir_all(&temp_root);
        return Err("notify ingest bench requires RAMFLUX_NOTIFY_WAL=1".into());
    }
    let store_gate = Arc::new(Mutex::new(()));
    let wake_auth = NotifyWakeAuth { key };
    let wake_verify_batcher = NotifyWakeVerifyBatcher::from_env(&wake_auth, &store)?;
    let ingress = Arc::new(NotifyIngressState {
        authority: Arc::new(send_authority::Surface::without_origins_for_test()),
        store,
        runtime: Arc::new(NotifyRuntime::Current),
        store_gate,
        async_accept: true,
        wake_auth,
        wake_verify_batcher,
    });
    let next = Arc::new(AtomicUsize::new(0));
    let started = std::time::Instant::now();
    let mut threads = Vec::with_capacity(producers);
    for producer_id in 0..producers {
        let thread_ingress = Arc::clone(&ingress);
        let thread_bodies = Arc::clone(&raw_bodies);
        let thread_next = Arc::clone(&next);
        threads.push(
            std::thread::Builder::new()
                .name(format!("ramflux-notify-ingest-bench-{producer_id}"))
                .spawn(move || {
                    notify_ingest_bench_producer(&thread_ingress, &thread_bodies, &thread_next)
                })?,
        );
    }
    let mut completed = 0_usize;
    for thread in threads {
        let result = thread.join().map_err(|_panic| "notify ingest bench producer panicked")?;
        completed = completed.saturating_add(result.map_err(std::io::Error::other)?);
    }
    let elapsed = started.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let completed_f64 = u32::try_from(completed).map_or(f64::from(u32::MAX), f64::from);
    let ops_per_sec = if elapsed_secs > 0.0 { completed_f64 / elapsed_secs } else { f64::INFINITY };
    let batch_verify = if ingress.wake_verify_batcher.is_some() { "on" } else { "off" };
    eprintln!(
        "INGEST_BENCH label=notify_ingest producers={producers} batch_verify={batch_verify} total={completed} elapsed_ms={} ops_per_sec={ops_per_sec:.2}",
        elapsed.as_millis()
    );
    drop(ingress);
    Ok(())
}

#[cfg(feature = "itest-http")]
fn notify_ingest_bench_producer(
    ingress: &Arc<NotifyIngressState>,
    raw_bodies: &Arc<Vec<Vec<u8>>>,
    next: &Arc<AtomicUsize>,
) -> Result<usize, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| source.to_string())?;
    let mut completed = 0_usize;
    loop {
        let index = next.fetch_add(1, Ordering::Relaxed);
        let Some(body) = raw_bodies.get(index) else {
            break;
        };
        runtime
            .block_on(ingest_raw_s13_wake_for_async_ingress(ingress, body.clone()))
            .map_err(|source| source.to_string())?;
        completed = completed.saturating_add(1);
    }
    Ok(completed)
}

fn signed_s13_wake_request_bodies(
    key: &ramflux_node_core::NodeServiceSigningKey,
    total: usize,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut bodies = Vec::with_capacity(total);
    for index in 0..total {
        let device = format!("device_ingest_{}", index % 1024);
        let signed = signed_message_wake(key, &device, &format!("env-ingest-{index}"), index)?;
        let body = serde_json::json!({
            "device_delivery_id": device,
            "signed_wake": signed,
            "queued_at": 1_760_000_000_u64.saturating_add(u64::try_from(index).unwrap_or(u64::MAX)),
            "dnd_active": false
        });
        bodies.push(serde_json::to_vec(&body)?);
    }
    Ok(bodies)
}

fn signed_message_wake(
    key: &ramflux_node_core::NodeServiceSigningKey,
    device: &str,
    source_event: &str,
    index: usize,
) -> Result<ramflux_protocol::SignedWakeV2, ramflux_node_core::NodeCoreError> {
    let now = ramflux_node_core::now_unix_seconds();
    let mut wake_id_bytes = [0_u8; 16];
    let index_bytes = index.to_le_bytes();
    let copied = index_bytes.len().min(wake_id_bytes.len());
    if let (Some(dest), Some(src)) = (wake_id_bytes.get_mut(..copied), index_bytes.get(..copied)) {
        dest.copy_from_slice(src);
    }
    let body = ramflux_protocol::WakeV2 {
        version: 2,
        signing_key_id: ramflux_node_core::NODE_SERVICE_SIGNING_KEY_ID.to_owned(),
        signature_alg: ramflux_protocol::WakeSignatureAlg::Ed25519,
        audience: ramflux_protocol::NOTIFY_WAKE_AUDIENCE.to_owned(),
        action: ramflux_protocol::WakeAction::Enqueue,
        wake_id: ramflux_protocol::encode_base64url(wake_id_bytes),
        target_delivery_id: device.to_owned(),
        target_owner_epoch: 1,
        source_event_id: source_event.to_owned(),
        class: ramflux_protocol::WakeClass::Message,
        created_at: now,
        expires_at: now.saturating_add(3_600),
        call_intent_digest: None,
    };
    key.sign_wake_v2(&body)
}

fn bench_node_service_signing_seed() -> [u8; 32] {
    [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]
}

fn notify_ingest_bench_temp_root() -> ramflux_test_support::TestPath {
    ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(format!(
        "ramflux-notify-ingest-bench-{}-{}",
        std::process::id(),
        ramflux_node_core::now_unix_seconds()
    ))
}

#[cfg(feature = "itest-http")]
struct NotifyMeshTestCert {
    tls: ramflux_transport::MeshTlsConfig,
    ca_pem: String,
}

#[cfg(feature = "itest-http")]
fn notify_mesh_test_cert_root(
    name: &str,
) -> Result<ramflux_test_support::TestPath, Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!("ramflux_notify_{name}_{}_{}", std::process::id(), nanos));
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

#[cfg(feature = "itest-http")]
fn issue_notify_mesh_test_cert(
    root: &Path,
    node_id: &str,
    service_id: &str,
) -> Result<NotifyMeshTestCert, Box<dyn std::error::Error>> {
    let dir = root.join(service_id);
    std::fs::create_dir_all(&dir)?;
    let ca_key = dir.join("ca-key.pem");
    let ca_cert = dir.join("ca.pem");
    let service_key = dir.join(format!("{service_id}-key.pem"));
    let service_csr = dir.join(format!("{service_id}.csr"));
    let service_cert = dir.join(format!("{service_id}.pem"));
    let ext = dir.join(format!("{service_id}.ext"));
    run_notify_mesh_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
    run_notify_mesh_openssl(&[
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
        "/CN=Ramflux Notify Mesh Test CA",
    ])?;
    run_notify_mesh_openssl(&[
        "genpkey",
        "-algorithm",
        "ED25519",
        "-out",
        path_str(&service_key)?,
    ])?;
    run_notify_mesh_openssl(&[
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
    run_notify_mesh_openssl(&[
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
    Ok(NotifyMeshTestCert {
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: ca_cert.clone(),
            service_cert,
            service_key,
        },
        ca_pem: std::fs::read_to_string(ca_cert)?,
    })
}

#[cfg(feature = "itest-http")]
fn run_notify_mesh_openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("openssl").args(args).status()?;
    if !status.success() {
        return Err(format!("openssl failed with status {status}: {}", args.join(" ")).into());
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| format!("non-UTF-8 path {}", path.display()).into())
}

#[cfg(feature = "itest-http")]
fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn bench_usize_env(name: &str, default: usize) -> usize {
    ramflux_node_core::environment::parsed::<usize>(name)
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn canonical_wake_id() -> String {
    ramflux_protocol::encode_base64url([0x11; 16])
}

fn canonical_collapse() -> String {
    ramflux_protocol::encode_base64url([0x22; 24])
}

pub(super) fn test_webpush_subscription() -> (String, String) {
    use p256::elliptic_curve::Generate;
    use p256::elliptic_curve::sec1::ToSec1Point;

    let key = p256::SecretKey::generate();
    let public = key.public_key().to_sec1_point(false);
    (
        ramflux_protocol::encode_base64url(public.as_bytes()),
        ramflux_protocol::encode_base64url([0x5a; 16]),
    )
}

fn test_prepared_push(
    provider: ramflux_node_core::PushProviderKind,
) -> ramflux_node_core::PreparedProviderPush {
    ramflux_node_core::PreparedProviderPush {
        route: ramflux_node_core::DevicePushRoute {
            device_delivery_id: "device_dispatch".to_owned(),
            provider: provider.clone(),
            credential_id: Some("credential_dispatch".to_owned()),
            token: "raw_token_not_logged".to_owned(),
            endpoint: "https://localhost:443/push".to_owned(),
            webpush_p256dh: None,
            webpush_auth: None,
            registered_at: 1_760_000_000,
            expires_at: 4_102_444_800,
            route_generation: 0,
        },
        credential: match &provider {
            ramflux_node_core::PushProviderKind::Fcm => ramflux_node_core::ProviderCredential::Fcm(
                ramflux_node_core::FcmProviderCredential {
                    credential_id: "credential_dispatch".to_owned(),
                    project_id: "project".to_owned(),
                    service_account_json_ref: "literal:{}".to_owned(),
                    oauth_scope: "https://www.googleapis.com/auth/firebase.messaging".to_owned(),
                    oauth_token_url: None,
                    provider_ca_pem_ref: None,
                },
            ),
            ramflux_node_core::PushProviderKind::Apns
            | ramflux_node_core::PushProviderKind::ApnsVoip => {
                let voip = matches!(provider, ramflux_node_core::PushProviderKind::ApnsVoip);
                ramflux_node_core::ProviderCredential::Apns(
                    ramflux_node_core::ApnsProviderCredential {
                        credential_id: "credential_dispatch".to_owned(),
                        team_id: "TEAM".to_owned(),
                        key_id: "KEY".to_owned(),
                        p8_key_ref: "literal:unused".to_owned(),
                        topic: if voip { "app.example.voip" } else { "app.example" }.to_owned(),
                        sandbox: true,
                        provider_ca_pem_ref: None,
                    },
                )
            }
            ramflux_node_core::PushProviderKind::WebPush => {
                ramflux_node_core::ProviderCredential::WebPush(
                    ramflux_node_core::WebPushProviderCredential {
                        credential_id: "credential_dispatch".to_owned(),
                        vapid_public_key_ref: "literal:test-public".to_owned(),
                        vapid_private_key_ref: "literal:test-private".to_owned(),
                        subject: "mailto:ops@ramflux.example".to_owned(),
                        provider_ca_pem_ref: None,
                    },
                )
            }
        },
        payload: ramflux_node_core::ProviderPushPayload {
            wake_id: canonical_wake_id(),
            provider,
            delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            priority: ramflux_protocol::PushPriority::Normal,
            ttl: 86_400,
            collapse_key: Some(canonical_collapse()),
            encrypted_hint: None,
        },
        push_alias_hash: "push_alias_hash".to_owned(),
        collapse_key_hash: canonical_collapse(),
        action: ramflux_node_core::NotifyDeliveryAction::Accept,
        expires_at: 4_102_444_800,
        admitted_unix: 1_760_000_000,
        boot_id: 0,
        owner_epoch: 0,
    }
}
