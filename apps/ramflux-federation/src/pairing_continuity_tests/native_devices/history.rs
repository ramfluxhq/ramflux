// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment followed by ordinary encrypted existing-DM object delivery between independent SDKs.
use super::super::process_stack;
use super::*;
use ramflux_sdk::{NodeGateway, NodePinSource, NodeProfile, NodeRelay};
#[path = "history/objects.rs"]
mod objects;
pub(super) const BODY: &[u8] = b"existing DM authored on phone before enrollment";

struct Network {
    _front: TlsFront,
    objects: objects::Objects,
    stack: process_stack::Stack,
    config: PairingConfig,
    profile: NodeProfile,
    _issuer: tempfile::TempDir,
    _env: PairingEnv,
}
impl Network {
    fn open() -> TestResult<Self> {
        let env = enable_pairing_with_trusted_proxy("127.0.0.1");
        let front = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("https://localhost:{}", front.local_addr()?.port());
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let relay = socket.local_addr()?.to_string();
        let issuer = tempfile::tempdir()?;
        let (seed, certificate) = objects::issuer(issuer.path())?;
        let stack = process_stack::boot_pairing_stack(&[
            ("RAMFLUX_DEVICE_PAIRING_ENABLED", "1"),
            ("RAMFLUX_FEDERATION_TRUSTED_PROXIES", "127.0.0.1"),
            ("RAMFLUX_FEDERATION_PUBLIC_ORIGIN", &origin),
            ("RAMFLUX_CLIENT_RELAY_QUIC_ADDR", &relay),
            ("RAMFLUX_GATEWAY_V3_ISSUER_SEED", &seed),
            ("RAMFLUX_GATEWAY_V3_ISSUER_CERT_FILE", &certificate),
        ])?;
        let tls = rustls_server_config(
            &stack.root.join("certs/ramflux-federation.pem"),
            &stack.root.join("certs/ramflux-federation.key"),
        )?;
        let backend = stack
            .discovery_url
            .strip_prefix("http://")
            .ok_or("test: federation backend")?
            .parse()?;
        let front = spawn_tls_front(front, backend, tls)?;
        let ca = bounded_ca(&stack.root.join("certs/ca.pem"))?;
        let profile = NodeProfile {
            discovery_url: stack.discovery_url.clone(),
            node_id: "localhost".into(),
            node_public_key: ramflux_crypto::public_key_base64url_from_seed(
                ramflux_crypto::blake3_256("ramflux.cli.e2e.node.v1", b"localhost"),
            ),
            pin_source: NodePinSource::Operator,
            ca_cert_pem: ca.clone(),
            gateway: NodeGateway {
                quic_addr: stack.gateway_quic.clone(),
                tcp_addr: stack.gateway_public.clone(),
                server_name: "localhost".into(),
            },
            relay: NodeRelay { quic_addr: relay, server_name: "ramflux-relay".into() },
            prekey_http_url: stack.discovery_url.clone(),
            signaling_turn_addr: String::new(),
            protocol_versions: vec!["ramflux.v1".into()],
            client_capabilities: vec![],
            discovered_at: wall()?,
            expires_at: wall()? + 3600,
            enabled: true,
            builtin: false,
            safety_warnings: Default::default(),
        };
        let objects = objects::Objects::open(&stack, socket)?;
        Ok(Self {
            _front: front,
            objects,
            stack,
            profile,
            config: PairingConfig { enabled: true, extra_root_ca_pem: Some(ca) },
            _issuer: issuer,
            _env: env,
        })
    }
}
fn bounded_ca(path: &std::path::Path) -> TestResult<String> {
    let mut ca = String::new();
    std::fs::File::open(path)?.take(65_537).read_to_string(&mut ca)?;
    if ca.len() > 65_536 {
        return Err("test: oversized CA".into());
    }
    Ok(ca)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires prebuilt ordinary product service binaries; explicit module QA row"]
async fn pairing_tls_enrollment_delivers_existing_dm_through_ordinary_object_relay() -> TestResult {
    deadline(Box::pin(run())).await
}
async fn run() -> TestResult {
    let mut network = Network::open()?;
    let (mut primary, mut a) = Box::pin(device::Device::create_network(
        &network.profile,
        &network.stack,
        "history-phone-a",
        true,
        &network.config,
    ))
    .await?;
    let (mut recipient, mut b) = Box::pin(device::Device::create_network(
        &network.profile,
        &network.stack,
        "history-phone-b",
        false,
        &network.config,
    ))
    .await?;
    assert_ne!(a.root.path(), b.root.path(), "test: history endpoints share account directory");
    assert!(!Arc::ptr_eq(&a.vault, &b.vault), "test: history endpoints share vault");
    Box::pin(enroll(&mut primary, &mut recipient)).await?;
    let original_branch = branch_identity(&b)?;
    let wrapping =
        ramflux_storage::AccountIndex::open(b.root.path())?.load_wrapped_db_key(&b.id)?;
    let mut target = Box::pin(b.connect_network(&network.profile, &network.stack)).await?;
    let mut source = Box::pin(a.connect_network(&network.profile, &network.stack)).await?;
    assert!(
        !target.has_pairing_history("paired-history-before-enrollment")?,
        "test: recipient already owned the pre-enrollment DM"
    );
    assert!(
        Box::pin(source.pairing_history_attempt()).await?,
        "test: enrollment history attempt was absent"
    );
    Box::pin(target.wait_pairing_history("paired-history-before-enrollment", BODY)).await?;
    assert!(
        network.objects.puts.load(Ordering::SeqCst) > 0,
        "test: history bypassed authenticated object upload"
    );
    assert!(
        network.objects.gets.load(Ordering::SeqCst) > 0,
        "test: history bypassed authenticated object fetch"
    );
    let before_media = network.objects.gets.load(Ordering::SeqCst);
    let native = custody::load_account(b.root.path(), &b.id, wall()?)?;
    let sibling = native.local_device_id()?;
    const MEDIA: &[u8] = b"ordinary authorized media after independent pairing";
    Box::pin(source.send_pairing_media(sibling, BODY, MEDIA)).await?;
    Box::pin(target.wait_pairing_history("paired-ordinary-media-message", BODY)).await?;
    Box::pin(target.fetch_pairing_media(MEDIA)).await?;
    assert!(
        network.objects.gets.load(Ordering::SeqCst) > before_media,
        "test: ordinary paired media bypassed authenticated remote ciphertext fetch"
    );
    assert_eq!(a.vault.primary_entries()?, 1, "test: history delivery retired source primary");
    assert_eq!(b.vault.primary_entries()?, 0, "test: history delivery copied management key");
    assert_eq!(
        branch_identity(&b)?,
        original_branch,
        "test: history or media import replaced B's own branch keys"
    );
    assert_eq!(
        ramflux_storage::AccountIndex::open(b.root.path())?.load_wrapped_db_key(&b.id)?,
        wrapping,
        "test: history or media import replaced B's original data-password wrapping"
    );
    source.stop().await;
    target.stop().await;
    primary.lock().await?;
    recipient.lock().await?;
    network.objects.stop().await?;
    Ok(())
}
fn branch_identity(device: &device::Device) -> TestResult<([u8; 32], [u8; 32], DeviceRef)> {
    let native = custody::load_account(device.root.path(), &device.id, wall()?)?;
    let (branch, agreement, reference) = device.vault.local_branch(native.record())?;
    Ok((branch.signing_key.verifying_key().to_bytes(), agreement.public, reference))
}
async fn exchange(a: &mut PairingActor, b: &mut PairingActor) -> TestResult<(String, String)> {
    // Child services own real clocks; honor their one-second SAS poll admission turn.
    tokio::time::sleep(Duration::from_millis(1001)).await;
    let a = update(a.sync_relay().await?)?.phase;
    let b = update(b.sync_relay().await?)?.phase;
    Ok((a, b))
}
async fn enroll(a: &mut PairingActor, b: &mut PairingActor) -> TestResult {
    let mut begin = begin_body()?;
    begin.capabilities = vec!["group".into(), "message".into(), "register".into(), "sync".into()];
    begin.lease_expires_at = begin.lease_not_before + 604_800;
    let value = begin_result(a.begin(begin).await?)?;
    let operation = value.operation_id.clone();
    b.join(Join {
        schema: "ramflux.pairing.Join.v2".into(),
        version: 2,
        token: value.invite_token,
        display_name: "History recipient".into(),
    })
    .await?;
    for _ in 0..32 {
        exchange(a, b).await?;
        if a.displayed_transcript().is_ok() && b.displayed_transcript().is_ok() {
            break;
        }
    }
    assert_eq!(
        a.displayed_transcript()?,
        b.displayed_transcript()?,
        "test: ordinary wire enrollment SAS mismatch"
    );
    a.confirm(&confirm_ok(a, &operation)?).await?;
    b.confirm(&confirm_ok(b, &operation)?).await?;
    for _ in 0..32 {
        exchange(a, b).await?;
        if a.displayed_proposal().is_ok() {
            break;
        }
    }
    a.approve(&approve_ok(a, &operation)?).await?;
    for _ in 0..32 {
        if exchange(a, b).await? == ("completed".into(), "completed".into()) {
            return Ok(());
        }
    }
    Err("test: ordinary wire enrollment did not complete".into())
}
