// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
#[cfg(feature = "itest-http")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
#[cfg(feature = "itest-http")]
use std::{path::Path, process::Command};

const TEST_EC_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwyBphzPT6zP0T3HT\nmUd3y/OXm9uWxWxy8nbR0YWA22ShRANCAAQAIpCYq6Tsdeuzzy1sjb/0VLEcd1+r\nQs8681WYx7uSG+akC/YXdlGjSeyiRGjZYJ1KHqoa2d4mAQwi9XAZuDT5\n-----END PRIVATE KEY-----\n";

#[test]
fn s13_dispatch_sends_wake_to_tls_h2_provider() -> Result<(), Box<dyn std::error::Error>> {
    let stub = LocalH2ProviderStub::start()?;
    let store_path = std::env::temp_dir().join(format!(
        "ramflux-notify-s13-dispatch-{}.redb",
        ramflux_node_core::now_unix_seconds()
    ));
    let _ = std::fs::remove_file(&store_path);
    let store = ramflux_node_core::NotifyRedbStore::open(&store_path)?;
    let subscription = test_webpush_subscription();
    store.update_provider_credential(ramflux_node_core::ProviderCredential::WebPush(
        ramflux_node_core::WebPushProviderCredential {
            credential_id: "credential_webpush".to_owned(),
            vapid_public_key_ref: "literal:test-vapid-public-key".to_owned(),
            vapid_private_key_ref: format!("literal:{TEST_EC_PRIVATE_KEY}"),
            subject: "mailto:ops@ramflux.example".to_owned(),
            provider_ca_pem_ref: Some(stub.ca_pem_secret_ref()),
        },
    ))?;
    store.register_push_route(ramflux_node_core::DevicePushRoute {
        device_delivery_id: "device_dispatch".to_owned(),
        provider: ramflux_node_core::PushProviderKind::WebPush,
        credential_id: Some("credential_webpush".to_owned()),
        token: "raw_token_not_logged".to_owned(),
        endpoint: stub.endpoint("/webpush"),
        webpush_p256dh: Some(subscription.0),
        webpush_auth: Some(subscription.1),
        registered_at: 1_760_000_000,
        expires_at: 4_102_444_800,
    })?;

    let (entry, pushes) = store.queue_wake_for_push(
        "device_dispatch",
        &test_wake(),
        ramflux_node_core::now_unix_seconds(),
        false,
    )?;
    assert_eq!(entry.queue_id, "wake_dispatch");
    assert_eq!(pushes.len(), 1);
    assert!(send_provider_push(&pushes[0])?);
    let received = stub.recv()?;
    assert_eq!(received.path, "/webpush");
    let topic = received.headers.get("topic").ok_or("WebPush topic missing")?;
    assert_eq!(topic.len(), 32);
    assert!(topic.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)));
    assert_ne!(Some(topic), test_wake().collapse_key.as_ref());
    assert!(pushes[0].collapse_key_hash.starts_with(topic));
    assert_eq!(
        received.headers.get("ramflux-delivery-class").map(String::as_str),
        Some("user_content_notification")
    );
    assert_eq!(received.headers.get("ttl").map(String::as_str), Some("86400"));
    assert_eq!(received.headers.get("urgency").map(String::as_str), Some("normal"));
    assert!(received.headers.contains_key("ramflux-push-alias-hash"));
    assert!(received.headers.contains_key("ramflux-collapse-key-hash"));
    assert_eq!(received.headers.get("content-encoding").map(String::as_str), Some("aes128gcm"));
    assert_ne!(received.body.len(), 0);
    for forbidden in
        [b"wake_dispatch".as_slice(), b"target:".as_slice(), b"encrypted_hint".as_slice()]
    {
        assert!(
            !received.body.windows(forbidden.len()).any(|window| window == forbidden),
            "webpush encrypted body leaked plaintext marker"
        );
    }
    Ok(())
}

#[test]
fn provider_common_headers_follow_s13_contract() {
    let prepared = test_prepared_push(ramflux_node_core::PushProviderKind::Fcm);
    let headers = generic_provider_headers(&prepared)
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(headers.get("ttl").map(String::as_str), Some("86400"));
    assert_eq!(headers.get("urgency").map(String::as_str), Some("normal"));
    assert_eq!(
        headers.get("ramflux-delivery-class").map(String::as_str),
        Some("user_content_notification")
    );
    assert!(headers.contains_key("ramflux-push-alias-hash"));
    assert!(headers.contains_key("ramflux-collapse-key-hash"));
    assert!(
        headers
            .get("ramflux-collapse-key")
            .map(String::as_str)
            .unwrap_or_default()
            .contains("target:")
    );
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
    let wake_auth = NotifyWakeAuth { require: true, key: Some(signing_key.clone()) };
    let ingress = Arc::new(NotifyIngressState {
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
    let mut wake = test_signed_wake(7);
    wake.wake_id = "wake_mesh_s13".to_owned();
    wake.push_alias = "device_mesh_s13".to_owned();
    wake.collapse_key = Some("target:device_mesh_s13:content".to_owned());
    signing_key.sign_notification_wake(&mut wake)?;
    let response: serde_json::Value = ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
        &endpoint,
        "/s13/notify/wake",
        &gateway.tls,
        "ramflux-notify",
        std::slice::from_ref(&notify.ca_pem),
        &serde_json::json!({
            "device_delivery_id": "device_mesh_s13",
            "wake": wake,
            "queued_at": 1_760_000_123_u64,
            "dnd_active": false
        }),
    )?;
    assert_eq!(response["entry"]["queue_id"], "wake_mesh_s13");
    assert_eq!(response["entry"]["device_delivery_id"], "device_mesh_s13");
    assert!(response["attempts"].as_array().is_some_and(Vec::is_empty));
    let state = store.load_state()?.ok_or("missing notify state")?;
    let entry = state.entry("wake_mesh_s13").ok_or("missing mesh wake entry")?;
    assert_eq!(entry.device_delivery_id, "device_mesh_s13");
    assert_eq!(entry.queued_at, 1_760_000_123);
    drop(ingress);
    drop(store);
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[cfg(feature = "itest-http")]
fn spawn_notify_mesh_test_listener(
    server_tls: ramflux_transport::MeshTlsConfig,
    trusted_gateway_ca: String,
    ingress: Arc<NotifyIngressState>,
) -> Result<String, Box<dyn std::error::Error>> {
    let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
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
    let wake_auth = NotifyWakeAuth { require: true, key: Some(key) };
    let wake_verify_batcher = NotifyWakeVerifyBatcher::from_env(&wake_auth, &store)?;
    let ingress = Arc::new(NotifyIngressState {
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
    let _ = std::fs::remove_dir_all(&temp_root);
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
        let mut wake = test_signed_wake(index);
        key.sign_notification_wake(&mut wake)?;
        let body = serde_json::json!({
            "device_delivery_id": format!("device_ingest_{}", index % 1024),
            "wake": wake,
            "queued_at": 1_760_000_000_u64.saturating_add(u64::try_from(index).unwrap_or(u64::MAX)),
            "dnd_active": false
        });
        bodies.push(serde_json::to_vec(&body)?);
    }
    Ok(bodies)
}

fn test_signed_wake(index: usize) -> ramflux_protocol::NotificationWake {
    ramflux_protocol::NotificationWake {
        schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: ramflux_node_core::NODE_SERVICE_SIGNING_KEY_ID.to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        wake_id: format!("wake_ingest_{index}"),
        push_alias: format!("device_ingest_{}", index % 1024),
        delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
        priority: ramflux_protocol::PushPriority::Normal,
        ttl: 86_400,
        collapse_key: Some(format!("target:device_ingest_{}:content", index % 1024)),
        encrypted_hint: Some("encrypted_hint".to_owned()),
    }
}

fn bench_node_service_signing_seed() -> [u8; 32] {
    [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]
}

fn notify_ingest_bench_temp_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
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
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ramflux_notify_{name}_{}_{}",
        std::process::id(),
        nanos
    ));
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
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn test_wake() -> ramflux_protocol::NotificationWake {
    ramflux_protocol::NotificationWake {
        schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "test-notify".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "test-signature".to_owned(),
        },
        wake_id: "wake_dispatch".to_owned(),
        push_alias: "device_dispatch".to_owned(),
        delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
        priority: ramflux_protocol::PushPriority::Normal,
        ttl: 86_400,
        collapse_key: Some("target:device_dispatch:content".to_owned()),
        encrypted_hint: Some("encrypted_hint".to_owned()),
    }
}

fn test_webpush_subscription() -> (String, String) {
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let key = p256::SecretKey::random(&mut OsRng);
    let public = key.public_key().to_encoded_point(false);
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
        },
        credential: ramflux_node_core::ProviderCredential::WebPush(
            ramflux_node_core::WebPushProviderCredential {
                credential_id: "credential_dispatch".to_owned(),
                vapid_public_key_ref: "literal:test-public".to_owned(),
                vapid_private_key_ref: "literal:test-private".to_owned(),
                subject: "mailto:ops@ramflux.example".to_owned(),
                provider_ca_pem_ref: None,
            },
        ),
        payload: ramflux_node_core::ProviderPushPayload {
            wake_id: "wake_dispatch".to_owned(),
            provider,
            delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            priority: ramflux_protocol::PushPriority::Normal,
            ttl: 86_400,
            collapse_key: Some("target:device_dispatch:content".to_owned()),
            encrypted_hint: Some("encrypted_hint".to_owned()),
        },
        push_alias_hash: "push_alias_hash".to_owned(),
        collapse_key_hash: "collapse_key_hash".to_owned(),
        action: ramflux_node_core::NotifyDeliveryAction::Accept,
    }
}

struct LocalH2ProviderStub {
    addr: std::net::SocketAddr,
    ca_pem: String,
    receiver: mpsc::Receiver<ReceivedProviderRequest>,
    _thread: std::thread::JoinHandle<()>,
}

impl LocalH2ProviderStub {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        ensure_ring_crypto_provider_installed();
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let ca_pem = certified.cert.pem();
        let cert_der = rustls_pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );
        let (sender, receiver) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            run_local_h2_provider(listener, cert_der, key_der, sender);
        });
        Ok(Self { addr, ca_pem, receiver, _thread: thread })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.addr.port())
    }

    fn ca_pem_secret_ref(&self) -> String {
        format!("literal:{}", self.ca_pem)
    }

    fn recv(&self) -> Result<ReceivedProviderRequest, Box<dyn std::error::Error>> {
        self.receiver.recv_timeout(Duration::from_secs(5)).map_err(Into::into)
    }
}

#[derive(Debug)]
struct ReceivedProviderRequest {
    path: String,
    headers: std::collections::BTreeMap<String, String>,
    body: Vec<u8>,
}

fn run_local_h2_provider(
    listener: std::net::TcpListener,
    cert_der: rustls_pki_types::CertificateDer<'static>,
    key_der: rustls_pki_types::PrivateKeyDer<'static>,
    sender: mpsc::Sender<ReceivedProviderRequest>,
) {
    ensure_ring_crypto_provider_installed();
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return;
    };
    runtime.block_on(async move {
        let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
            return;
        };
        let Ok(mut server_config) = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
        else {
            return;
        };
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let Ok(tls) = acceptor.accept(stream).await else {
            return;
        };
        let Ok(mut connection) = h2::server::handshake(tls).await else {
            return;
        };
        if let Some(Ok((request, respond))) = connection.accept().await {
            handle_local_h2_provider_request(request, respond, sender).await;
        }
        let _ = tokio::time::timeout(Duration::from_millis(100), connection.accept()).await;
    });
}

async fn handle_local_h2_provider_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    sender: mpsc::Sender<ReceivedProviderRequest>,
) {
    let path = request.uri().path().to_owned();
    let headers = request
        .headers()
        .iter()
        .filter_map(|(key, value)| {
            Some((key.as_str().to_ascii_lowercase(), value.to_str().ok()?.to_owned()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut body_stream = request.into_body();
    let mut body = Vec::new();
    while let Some(Ok(chunk)) = body_stream.data().await {
        body.extend_from_slice(&chunk);
    }
    let _ = sender.send(ReceivedProviderRequest { path, headers, body });
    let response =
        http::Response::builder().status(202).header("content-type", "application/json").body(());
    if let Ok(response) = response
        && let Ok(mut send) = respond.send_response(response, false)
    {
        let _ = send.send_data(bytes::Bytes::from_static(b"{}"), true);
    }
}
