// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cross-component pairing over the real public listener + TLS front proxy.
use super::pairing_limits;
use super::tests::{NodeMesh, PairingEnv, enable_pairing_with_trusted_proxy, spawn_node_mesh_at};
use crate::RouterMeshClient;
use ramflux_crypto::custody::{
    GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, branch_exporter_hash, create_genesis,
    sign_branch_proof_v3, sign_proxy_acceptance, verify_record,
};
use ramflux_crypto::{X25519KeyPair, create_device_branch, random_32};
use ramflux_node_core::NodeHttpRequest;
use ramflux_node_core::pairing_relay::{PairingClock, PairingRelayStore, TestPairingClock};
use ramflux_protocol::custody::pairing::local_dto::{
    Approve, Begin, BeginResult, Confirm, Join, LocalResult, Outcome, StatusRequest, Update,
};
use ramflux_protocol::custody::pairing::relay::{RelayFrame, Send};
use ramflux_protocol::custody::{
    BindingMode, BranchCertificate, BranchProofV3, CustodyMeshRequest, CustodyProofAction,
    CustodyRefusal, CustodyServerFrame, DeviceRef, MAX_BRANCH_LEASE_SECONDS, Publication,
    object_hash,
};
use ramflux_protocol::encode_base64url;
use ramflux_sdk::SdkError;
use ramflux_sdk::custody::pairing::{
    HttpRelay, PairingActor, PairingConfig, PairingIdentity, ProofPairingNative,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[path = "pairing_continuity_tests/native_devices.rs"]
mod native_devices;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Continuity {
    primary: PairingActor,
    recipient: PairingActor,
    clock: Arc<TestPairingClock>,
    store: Arc<Mutex<PairingRelayStore>>,
    origin: String,
    public_addr: SocketAddr,
    native: Arc<ProofPairingNative>,
    secondary_native: Arc<ProofPairingNative>,
    published: PublishedPrimary,
    config: PairingConfig,
    _env: PairingEnv,
    node: NodeMesh,
    _tls: crate::test_directories::TestDirectory,
    _public: crate::public_http::PublicHttpGuard,
    _front: TlsFront,
}

struct TlsFront {
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
    thread: Option<JoinHandle<()>>,
}

impl Drop for TlsFront {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct PublishedPrimary {
    reference: DeviceRef,
    master_public_key: String,
    base_record_hash: String,
    base_epoch: u64,
}

struct PrimaryProver {
    service: Arc<ramflux_node_core::CustodyService>,
    router: Arc<ramflux_node_core::RouterCore>,
    redb: Arc<ramflux_node_core::RouterRedbStore>,
    publication: ramflux_node_core::CustodyPublication,
    branch: ramflux_crypto::DeviceBranch,
    reference: DeviceRef,
    secondary_branch: ramflux_crypto::DeviceBranch,
    secondary_reference: DeviceRef,
    node: ramflux_crypto::custody::VerifiedNodeRecord,
    proxy_branch: ramflux_crypto::DeviceBranch,
    connection: String,
    secondary_connection: String,
}

#[tokio::test]
async fn pairing_two_local_confirmations_precede_approval() -> TestResult {
    let mut fx = Continuity::open()?;
    refuse_plaintext_http(&fx.origin)?;
    refuse_direct_pairing(&fx.public_addr)?;
    let begun = begin_result(fx.primary.begin(begin_body()?).await?)?;
    let secret = begun.invite_token.recipient_token.clone();
    let op = begun.operation_id.clone();
    let generation = begun.generation;
    assert_no_token(&fx.primary.status(&status_req(&op, generation)).await?, &secret)?;
    fx.recipient
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: begun.invite_token,
            display_name: "Recipient".into(),
        })
        .await?;
    drive_sas(&mut fx, &op, generation).await?;
    fx.recipient.confirm(&confirm_ok(&fx.recipient, &op)?).await?;
    drive_once(&mut fx).await?;
    fx.primary.note_peer_confirmed_flag(true);
    assert_approve_refused(&mut fx.primary, &op).await?;
    fx.primary.confirm(&confirm_ok(&fx.primary, &op)?).await?;
    drive_once(&mut fx).await?;
    let approved = update(fx.primary.approve(&approve_ok(&fx.primary, &op)?).await?)?;
    assert_eq!(approved.phase, "proposal_pending");
    drop(fx);

    let mut fx = Continuity::open()?;
    let (op, _) = Box::pin(joined(&mut fx)).await?;
    let mut bad = confirm_ok(&fx.primary, &op)?;
    bad.r#match = false;
    let mismatch = update(fx.primary.confirm(&bad).await?)?;
    assert_eq!(
        (mismatch.phase.as_str(), mismatch.result.as_deref()),
        ("rejected", Some("SasMismatch"))
    );
    drop(fx);

    let mut fx = Continuity::open()?;
    let _ = Box::pin(joined(&mut fx)).await?;
    let changed = update(fx.primary.note_head_change().await?)?;
    assert_eq!(
        (changed.phase.as_str(), changed.result.as_deref()),
        ("rejected", Some("HeadChanged"))
    );
    drop(fx);

    let mut fx = Continuity::open()?;
    let begun = begin_result(fx.primary.begin(begin_body()?).await?)?;
    let recipient_token = begun.invite_token.recipient_token.clone();
    let invitation_id = begun.invite_token.invitation.body.invitation_id.clone();
    let issuer_seq = begun.invite_token.invitation.body.issuer_seq;
    let op = begun.operation_id.clone();
    let generation = begun.generation;
    fx.recipient
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: begun.invite_token,
            display_name: "Recipient".into(),
        })
        .await?;
    drive_sas(&mut fx, &op, generation).await?;
    let th = fx.primary.displayed_transcript()?;
    held(&fx.store).send(&Send {
        schema: "ramflux.pairing.Send.v2".into(),
        version: 2,
        invitation_id,
        issuer_seq,
        role: "responder".into(),
        token: recipient_token,
        seq: 2,
        frame: RelayFrame::Confirm {
            role: "responder".into(),
            transcript_hash: th,
            mac: encode_base64url([9u8; 32]),
        },
    })?;
    fx.clock.advance_ms(1_001);
    let rejected = update(fx.primary.sync_relay().await?)?;
    assert_eq!(
        (rejected.phase.as_str(), rejected.result.as_deref(), rejected.emoji_indices.is_none()),
        ("rejected", Some("SasMismatch"), true)
    );
    fx.clock.advance_ms(1_001);
    match fx.recipient.sync_relay().await {
        Ok(result) => {
            let polled = update(result)?;
            assert!(
                polled.phase == "cancelled"
                    || polled.phase == "rejected"
                    || polled.result.as_deref() == Some("Retired"),
                "{polled:?}"
            );
        }
        Err(SdkError::PairingCode("Retired")) => {}
        Err(error) => return Err(format!("close observe {error}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn pairing_forged_invitation_is_refused() -> TestResult {
    let mut fx = Continuity::open()?;
    let mut begun = begin_result(fx.primary.begin(begin_body()?).await?)?;
    let mut raw = ramflux_protocol::decode_base64url(&begun.invite_token.invitation.signature)?;
    raw[0] ^= 1;
    begun.invite_token.invitation.signature = encode_base64url(raw);
    match fx
        .recipient
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: begun.invite_token,
            display_name: "Recipient".into(),
        })
        .await
    {
        Err(SdkError::PairingCode("InvalidInput")) => Ok(()),
        other => Err(format!("forged invitation: {other:?}").into()),
    }
}

#[tokio::test]
async fn pairing_stale_generation_is_refused() -> TestResult {
    let mut fx = Continuity::open()?;
    let (op, generation) = Box::pin(joined(&mut fx)).await?;
    let mut stale = confirm_ok(&fx.primary, &op)?;
    stale.generation = generation.saturating_add(1);
    match fx.primary.confirm(&stale).await {
        Err(SdkError::PairingCode("WrongContext")) => Ok(()),
        Ok(result) => Err(format!("stale confirm {}", update(result)?.phase).into()),
        Err(error) => Err(format!("stale confirm {error}").into()),
    }
}

#[tokio::test]
async fn pairing_begin_requires_current_primary_spec_primary_mismatch() -> TestResult {
    let fx = Continuity::open()?;
    let mut other = PairingActor::new(
        PairingIdentity {
            account_id: "other".into(),
            local_ref: DeviceRef {
                account_anchor: fx.published.reference.account_anchor.clone(),
                device_id: "other".into(),
                device_epoch: 1,
            },
            master_public_key: Some(fx.published.master_public_key.clone()),
            base_record_hash: fx.published.base_record_hash.clone(),
            base_epoch: fx.published.base_epoch,
            is_primary: true,
        },
        Some(Arc::clone(&fx.native) as _),
        Arc::new(HttpRelay::from_config(&PairingConfig { enabled: true, extra_root_ca_pem: None })?)
            as _,
        PairingConfig { enabled: true, extra_root_ca_pem: None },
    );
    match other.begin(begin_body()?).await {
        Err(SdkError::CustodyNetwork(CustodyRefusal::BindingRefused)) => Ok(()),
        other => Err(format!("non-primary begin: {other:?}").into()),
    }
}

#[tokio::test]
async fn pairing_begin_refuses_secondary_device() -> TestResult {
    let fx = Continuity::open()?;
    let mut secondary = PairingActor::new(
        PairingIdentity {
            account_id: "primary".into(),
            local_ref: fx.published.reference.clone(),
            master_public_key: Some(fx.published.master_public_key.clone()),
            base_record_hash: fx.published.base_record_hash.clone(),
            base_epoch: fx.published.base_epoch,
            is_primary: true,
        },
        Some(Arc::clone(&fx.secondary_native) as _),
        Arc::new(HttpRelay::from_config(&PairingConfig { enabled: true, extra_root_ca_pem: None })?)
            as _,
        PairingConfig { enabled: true, extra_root_ca_pem: None },
    );
    match secondary.begin(begin_body()?).await {
        Err(SdkError::CustodyNetwork(CustodyRefusal::BindingRefused)) => Ok(()),
        other => Err(format!("secondary-device begin: {other:?}").into()),
    }
}

impl Continuity {
    fn open() -> TestResult<Self> {
        let env = enable_pairing_with_trusted_proxy("127.0.0.1");
        let tls_root = crate::test_certificates::temp_cert_root("pairing-continuity-tls")?;
        let ca = crate::test_certificates::issue_test_ca(&tls_root)?;
        let server =
            crate::test_certificates::issue_test_service_cert(&ca, "node-a", "ramflux-federation")?;
        let front = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("https://localhost:{}", front.local_addr()?.port());
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let clock = TestPairingClock::new(now);
        let node =
            spawn_node_mesh_at(origin.clone(), Some(Arc::clone(&clock) as Arc<dyn PairingClock>))?;
        let router = Arc::new(RouterMeshClient {
            endpoint: node.endpoint.clone(),
            server_name: "ramflux-router".into(),
            tls: node.client_tls.clone(),
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh: None,
        });
        let discovery = crate::http_listener_tests::context(&tls_root)?.discovery;
        let (public_addr, public) = crate::public_http::serve_public_http_owned(
            "127.0.0.1:0",
            crate::public_http::public_context(router, discovery)?,
        )?;
        let server_config =
            rustls_server_config(&server.tls.service_cert, &server.tls.service_key)?;
        let tls_front = spawn_tls_front(front, public_addr, server_config)?;
        refuse_direct_pairing(&public_addr)?;
        let prover = Arc::new(PrimaryProver::bootstrap(&node)?);
        prover.publish()?;
        let published = published_from(&prover)?;
        let native = proof_native(Arc::clone(&prover), false);
        let secondary_native = proof_native(Arc::clone(&prover), true);
        let config = PairingConfig { enabled: true, extra_root_ca_pem: Some(server.ca_pem) };
        let relay = Arc::new(HttpRelay::from_config(&config)?);
        Ok(Self {
            primary: PairingActor::new(
                PairingIdentity {
                    account_id: "primary".into(),
                    local_ref: published.reference.clone(),
                    master_public_key: Some(published.master_public_key.clone()),
                    base_record_hash: published.base_record_hash.clone(),
                    base_epoch: published.base_epoch,
                    is_primary: true,
                },
                Some(Arc::clone(&native) as _),
                Arc::clone(&relay) as _,
                config.clone(),
            ),
            recipient: PairingActor::new(
                PairingIdentity {
                    account_id: "recipient".into(),
                    local_ref: DeviceRef {
                        account_anchor: String::new(),
                        device_id: "recipient".into(),
                        device_epoch: 1,
                    },
                    master_public_key: None,
                    base_record_hash: encode_base64url([2u8; 32]),
                    base_epoch: 1,
                    is_primary: false,
                },
                None,
                relay as _,
                config.clone(),
            ),
            clock,
            store: Arc::clone(&node.store),
            origin,
            public_addr,
            native,
            secondary_native,
            published,
            config,
            _env: env,
            node,
            _tls: tls_root,
            _public: public,
            _front: tls_front,
        })
    }
}

fn published_from(prover: &PrimaryProver) -> TestResult<PublishedPrimary> {
    Ok(PublishedPrimary {
        reference: prover.reference.clone(),
        master_public_key: prover
            .publication
            .record
            .body
            .master_certificate
            .body
            .master_public_key
            .clone(),
        base_record_hash: object_hash(&prover.publication.record)?,
        base_epoch: prover.publication.record.body.device_set_epoch,
    })
}

fn proof_native(prover: Arc<PrimaryProver>, secondary: bool) -> Arc<ProofPairingNative> {
    Arc::new(ProofPairingNative::new(Arc::new(move |action| {
        let prover = Arc::clone(&prover);
        Box::pin(async move {
            if secondary { prover.run_as_secondary(action) } else { prover.run(action) }
        })
    })))
}

fn spawn_tls_front(
    listener: TcpListener,
    backend: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
) -> TestResult<TlsFront> {
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    listener.set_nonblocking(true)?;
    let thread =
        std::thread::spawn(move || serve_tls_front(listener, backend, server_config, worker_stop));
    Ok(TlsFront { stop, addr, thread: Some(thread) })
}

#[allow(clippy::needless_pass_by_value)]
fn serve_tls_front(
    listener: TcpListener,
    backend: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    stop: Arc<AtomicBool>,
) {
    let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
    while !stop.load(Ordering::Relaxed) {
        let (mut tcp, peer) = match listener.accept() {
            Ok(accepted) => {
                backoff.success();
                accepted
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(error) => {
                backoff.wait_after_failure(&error);
                continue;
            }
        };
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let _ = tcp.set_nonblocking(false);
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
        let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&server_config)) else {
            continue;
        };
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let Ok(request) = read_http_request(&mut tls) else {
            continue;
        };
        let Ok(mut upstream) = TcpStream::connect(backend) else {
            continue;
        };
        let _ = upstream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = upstream.set_write_timeout(Some(Duration::from_secs(5)));
        let forwarded = reconstruct_forwarded(&request, peer);
        if upstream.write_all(&forwarded).is_err() {
            continue;
        }
        let mut reply = Vec::new();
        if upstream.read_to_end(&mut reply).is_err() {
            continue;
        }
        let _ = tls.write_all(&reply);
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }
}

fn reconstruct_forwarded(request: &NodeHttpRequest, peer: SocketAddr) -> Vec<u8> {
    let mut raw = format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: {}\r\n\r\n",
        request.method,
        request.path,
        request.body.len(),
        peer.ip()
    )
    .into_bytes();
    raw.extend_from_slice(&request.body);
    raw
}

fn rustls_server_config(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> TestResult<Arc<rustls::ServerConfig>> {
    let mut cert_pem = std::io::BufReader::new(std::fs::File::open(cert)?);
    let mut key_pem = std::io::BufReader::new(std::fs::File::open(key)?);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = rustls_pemfile::certs(&mut cert_pem).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem)?.ok_or("missing key")?;
    Ok(Arc::new(
        rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?,
    ))
}

fn read_http_request(tls: &mut impl Read) -> TestResult<NodeHttpRequest> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 512];
    let (header_end, start) = loop {
        if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break (end, end + 4);
        }
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Err("headers".into());
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > pairing_limits().max_header_bytes {
            return Err("header cap".into());
        }
    };
    let header = std::str::from_utf8(&raw[..header_end])?;
    let mut parts = header.lines().next().ok_or("line")?.split_whitespace();
    let method = parts.next().ok_or("method")?.to_owned();
    let path = parts.next().ok_or("path")?.to_owned();
    let mut length = 0_usize;
    for line in header.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("Content-Length")
        {
            length = value.trim().parse()?;
        }
    }
    if length > pairing_limits().max_body_bytes {
        return Err("body cap".into());
    }
    while raw.len() < start + length {
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Err("short body".into());
        }
        raw.extend_from_slice(&buf[..n]);
    }
    if raw.len() < start + length {
        return Err("short body".into());
    }
    Ok(NodeHttpRequest {
        method,
        path,
        body: raw[start..start + length].to_vec(),
        keep_alive: false,
        source_ip_hash: None,
        pre_auth_cookie: None,
        pre_auth_now: None,
        forwarded_proto: None,
        forwarded_for: None,
    })
}

fn refuse_plaintext_http(origin: &str) -> TestResult {
    let host = origin.strip_prefix("https://").ok_or("origin")?;
    let mut stream = TcpStream::connect(host)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(
        b"POST /client/pairing/v1/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )?;
    let mut buf = [0_u8; 64];
    match stream.read(&mut buf) {
        Ok(0) | Err(_) => Ok(()),
        Ok(_) if !buf.starts_with(b"HTTP/1.1 200") => Ok(()),
        Ok(_) => Err("plaintext HTTP accepted".into()),
    }
}

fn refuse_direct_pairing(addr: &SocketAddr) -> TestResult {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(
        b"POST /client/pairing/v1/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let response = String::from_utf8_lossy(&buf);
    if response.starts_with("HTTP/1.1 400") && response.contains("tls required") {
        Ok(())
    } else {
        Err(format!("direct pairing: {response}").into())
    }
}

async fn joined(fx: &mut Continuity) -> TestResult<(String, u64)> {
    let begun = begin_result(fx.primary.begin(begin_body()?).await?)?;
    let op = begun.operation_id.clone();
    let generation = begun.generation;
    fx.recipient
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: begun.invite_token,
            display_name: "Recipient".into(),
        })
        .await?;
    drive_sas(fx, &op, generation).await?;
    Ok((op, generation))
}

async fn drive_sas(fx: &mut Continuity, op: &str, generation: u64) -> TestResult {
    let mut last = String::new();
    for _ in 0..24 {
        drive_once(fx).await?;
        let primary = phase(&mut fx.primary, op, generation).await?;
        let recipient = phase(&mut fx.recipient, op, generation).await?;
        last = format!(
            "primary={primary} recipient={recipient} frames={}/{}",
            fx.primary.frames_seen(),
            fx.recipient.frames_seen()
        );
        if primary == "sas_pending" && recipient == "sas_pending" {
            return Ok(());
        }
        if terminal_phase(&primary) || terminal_phase(&recipient) {
            return Err(last.into());
        }
    }
    Err(last.into())
}

async fn drive_once(fx: &mut Continuity) -> TestResult {
    fx.clock.advance_ms(1_001);
    let _ = fx.primary.sync_relay().await?;
    fx.clock.advance_ms(1_001);
    let _ = fx.recipient.sync_relay().await?;
    Ok(())
}

async fn phase(actor: &mut PairingActor, op: &str, generation: u64) -> TestResult<String> {
    Ok(update(actor.status(&status_req(op, generation)).await?)?.phase)
}

async fn assert_approve_refused(actor: &mut PairingActor, op: &str) -> TestResult {
    match actor.approve(&approve_ok(actor, op)?).await {
        Err(SdkError::PairingCode("WrongContext")) => Ok(()),
        Ok(result) => Err(format!("premature approval {}", update(result)?.phase).into()),
        Err(error) => Err(format!("approve {error}").into()),
    }
}

fn assert_no_token(result: &LocalResult, secret: &str) -> TestResult {
    let json = serde_json::to_string(result)?;
    if json.contains("invite_token") || json.contains(secret) {
        return Err("status re-exported token".into());
    }
    Ok(())
}

fn confirm_ok(actor: &PairingActor, op: &str) -> TestResult<Confirm> {
    Ok(Confirm {
        schema: "ramflux.pairing.Confirm.v2".into(),
        version: 2,
        operation_id: op.into(),
        generation: actor.actor_generation(),
        transcript_hash: actor.displayed_transcript()?,
        r#match: true,
    })
}

fn approve_ok(actor: &PairingActor, op: &str) -> TestResult<Approve> {
    Ok(Approve {
        schema: "ramflux.pairing.Approve.v2".into(),
        version: 2,
        operation_id: op.into(),
        generation: actor.actor_generation(),
        transcript_hash: actor.displayed_transcript()?,
        proposal_hash: actor.displayed_proposal()?,
        approved: true,
    })
}

fn begin_body() -> TestResult<Begin> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(Begin {
        schema: "ramflux.pairing.Begin.v2".into(),
        version: 2,
        capabilities: vec!["message".into(), "register".into()],
        lease_not_before: now,
        lease_expires_at: now + 86_400,
        display_name: "Primary".into(),
    })
}

fn status_req(op: &str, generation: u64) -> StatusRequest {
    StatusRequest {
        schema: "ramflux.pairing.StatusRequest.v2".into(),
        version: 2,
        operation_id: op.into(),
        generation,
    }
}

fn begin_result(result: LocalResult) -> TestResult<BeginResult> {
    match result.outcome {
        Outcome::Begin { value } => Ok(*value),
        Outcome::Update { value } => Err(format!("begin {}", value.phase).into()),
        Outcome::Error { error } => Err(error.code.into()),
        Outcome::FullStatus { .. } => Err("unexpected full status".into()),
    }
}

fn update(result: LocalResult) -> TestResult<Update> {
    match result.outcome {
        Outcome::Update { value } => Ok(*value),
        Outcome::Begin { .. } => Err("update was begin".into()),
        Outcome::Error { error } => Err(error.code.into()),
        Outcome::FullStatus { .. } => Err("unexpected full status".into()),
    }
}

fn terminal_phase(phase: &str) -> bool {
    matches!(phase, "cancelled" | "expired" | "rejected" | "completed")
}

fn held(store: &Mutex<PairingRelayStore>) -> MutexGuard<'_, PairingRelayStore> {
    store.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wall() -> TestResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

impl PrimaryProver {
    fn bootstrap(node: &NodeMesh) -> TestResult<Self> {
        let now = wall()?;
        let seed = 10_u8;
        let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[seed; 32])?)?;
        let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([seed + 1; 32]));
        let branch = create_device_branch("alice", "primary", 1, [seed + 2; 32]);
        let agreement = X25519KeyPair::from_seed([seed + 3; 32]);
        let genesis = create_genesis(
            &master,
            &primary,
            &branch,
            &agreement,
            GenesisInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                display_name: "Human".into(),
                issued_at: now,
                master_cert_id: encode_base64url([seed + 4; 32]),
                branch_cert_id: encode_base64url([seed + 5; 32]),
                external_human_primary: None,
            },
        )?;
        let secondary_branch = create_device_branch("alice", "secondary", 1, [seed + 6; 32]);
        let secondary_agreement = X25519KeyPair::from_seed([seed + 7; 32]);
        let record =
            enroll_secondary(&primary, &genesis, &secondary_branch, &secondary_agreement, seed)?;
        let reference = DeviceRef {
            account_anchor: record.body.account_anchor.clone(),
            device_id: "primary".into(),
            device_epoch: 1,
        };
        let secondary_reference = DeviceRef {
            account_anchor: record.body.account_anchor.clone(),
            device_id: "secondary".into(),
            device_epoch: 1,
        };
        Ok(Self {
            service: Arc::clone(&node.service),
            router: Arc::clone(&node.router),
            redb: Arc::clone(&node.redb),
            publication: ramflux_node_core::CustodyPublication { record, compacted_ids: None },
            branch,
            reference,
            secondary_branch,
            secondary_reference,
            node: node.node.clone(),
            proxy_branch: node.proxy_branch.clone(),
            connection: encode_base64url([seed; 32]),
            secondary_connection: encode_base64url([seed.wrapping_add(9); 32]),
        })
    }

    fn publish(&self) -> TestResult {
        match self.run(CustodyProofAction::Publish {
            publication: Box::new(Publication {
                record: self.publication.record.clone(),
                compacted_ids: None,
            }),
        })? {
            CustodyServerFrame::Published { .. } => Ok(()),
            other => Err(format!("publish {other:?}").into()),
        }
    }

    fn run(&self, action: CustodyProofAction) -> Result<CustodyServerFrame, SdkError> {
        self.run_device(&self.branch, &self.reference, &self.connection, action)
    }

    fn run_as_secondary(&self, action: CustodyProofAction) -> Result<CustodyServerFrame, SdkError> {
        self.run_device(
            &self.secondary_branch,
            &self.secondary_reference,
            &self.secondary_connection,
            action,
        )
    }

    fn run_device(
        &self,
        branch: &ramflux_crypto::DeviceBranch,
        reference: &DeviceRef,
        connection: &str,
        action: CustodyProofAction,
    ) -> Result<CustodyServerFrame, SdkError> {
        let now = wall().map_err(|error| SdkError::LocalBus(error.to_string()))?;
        let challenge = match self.service.mesh(
            &self.router,
            &self.redb,
            CustodyMeshRequest::Challenge {
                device_ref: reference.clone(),
                action: action.clone(),
                binding_mode: BindingMode::HomeRelayReceipt,
                client_source: "192.0.2.1".into(),
                connection_id: connection.into(),
            },
            "ramflux-gateway",
            now,
        ) {
            CustodyServerFrame::Challenge { challenge } => challenge,
            other => return Ok(other),
        };
        let proof = self.proof(branch, reference, &challenge, now)?;
        let observed = branch_exporter_hash(&[5; 32]);
        let receipt = sign_proxy_acceptance(
            &self.proxy_branch.signing_key,
            &self.node,
            &proof,
            &observed,
            encode_base64url(random_32().map_err(|error| SdkError::LocalBus(error.to_string()))?),
            now,
        )
        .map_err(|error| SdkError::LocalBus(error.to_string()))?;
        Ok(self.service.mesh(
            &self.router,
            &self.redb,
            CustodyMeshRequest::Prove {
                action,
                proof: Box::new(proof),
                receipt: Some(Box::new(receipt)),
                connection_id: connection.into(),
            },
            "ramflux-gateway",
            now,
        ))
    }

    fn proof(
        &self,
        branch: &ramflux_crypto::DeviceBranch,
        reference: &DeviceRef,
        challenge: &ramflux_protocol::custody::BranchChallenge,
        now: u64,
    ) -> Result<ramflux_protocol::custody::Envelope<BranchProofV3>, SdkError> {
        let cert = self
            .publication
            .record
            .body
            .devices
            .iter()
            .find(|device| device.device_id == reference.device_id)
            .and_then(|device| device.branch_certificate.as_ref())
            .ok_or_else(|| SdkError::LocalBus("branch certificate".into()))?;
        sign_branch_proof_v3(
            branch,
            BranchProofV3 {
                schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                version: 3,
                device_ref: reference.clone(),
                certificate_hash: object_hash(cert)
                    .map_err(|error| SdkError::LocalBus(error.to_string()))?,
                record_hash: object_hash(&self.publication.record)
                    .map_err(|error| SdkError::LocalBus(error.to_string()))?,
                proof_id: encode_base64url(
                    random_32().map_err(|error| SdkError::LocalBus(error.to_string()))?,
                ),
                challenge_nonce: challenge.challenge_nonce.clone(),
                action_hash: challenge.action_hash.clone(),
                audience: challenge.audience.clone(),
                binding_mode: challenge.binding_mode,
                transport_binding: branch_exporter_hash(&[5; 32]),
                issued_at: now,
                expires_at: now.saturating_add(300),
            },
        )
        .map_err(|error| SdkError::LocalBus(error.to_string()))
    }
}

fn enroll_secondary(
    primary: &SelfSigningKey,
    genesis: &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    secondary: &ramflux_crypto::DeviceBranch,
    agreement: &X25519KeyPair,
    seed: u8,
) -> TestResult<ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>> {
    let now = genesis.body.issued_at;
    let current = verify_record(genesis, now, None, None)?;
    let signing = encode_base64url(secondary.signing_key.verifying_key().to_bytes());
    let agreement_public = encode_base64url(agreement.public);
    let cert = primary.certify_branch(BranchCertificate {
        schema: ramflux_protocol::domain::CUSTODY_BRANCH_CERTIFICATE.into(),
        version: 1,
        account_anchor: genesis.body.account_anchor.clone(),
        master_certificate_hash: object_hash(&genesis.body.master_certificate)?,
        device_id: secondary.device_id.clone(),
        device_epoch: secondary.device_epoch,
        principal_kind: genesis.body.principal_kind,
        branch_signing_public_key: signing,
        agreement_identity_public_key: agreement_public,
        capabilities: ["call", "group", "message", "register", "sync"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        not_before: now,
        expires_at: now.saturating_add(MAX_BRANCH_LEASE_SECONDS),
        cert_id: encode_base64url([seed.wrapping_add(8); 32]),
    })?;
    Ok(primary.enroll_device(&current, cert, now.saturating_add(1))?)
}

pub(super) fn native_issue_refused_when_disabled() -> TestResult {
    // This fixture owns an explicit relay for the mesh plumbing; the service under
    // test below is separately built through the real environment-gated constructor.
    let clock = ramflux_node_core::pairing_relay::TestPairingClock::new(wall()?);
    let node = spawn_node_mesh_at("https://relay.example:443".into(), Some(clock))?;
    let mut prover = PrimaryProver::bootstrap(&node)?;
    prover.service = Arc::new(
        ramflux_node_core::CustodyService::new(
            node.node.clone(),
            false,
            node.redb.as_ref(),
            wall()?,
        )?
        .with_pairing_relay_if_enabled(
            ramflux_crypto::fixture_signing_key().to_bytes(),
            "https://relay.example:443".into(),
        )?,
    );
    prover.publish()?;
    let now = wall()?;
    let reply = prover.run(CustodyProofAction::PairingIssue {
        request: Box::new(ramflux_protocol::custody::pairing::native::Issue {
            schema: "ramflux.pairing.Issue.v2".into(),
            version: 2,
            spec: ramflux_protocol::custody::pairing::native::CreateSpec {
                schema: "ramflux.pairing.CreateSpec.v2".into(),
                version: 2,
                account_anchor: prover.reference.account_anchor.clone(),
                primary_ref: prover.reference.clone(),
                base_record_hash: object_hash(&prover.publication.record)?,
                base_epoch: prover.publication.record.body.device_set_epoch,
                purpose: "enroll".into(),
                recipient_mode: "new".into(),
                destination_ref: None,
                capabilities: vec!["message".into()],
                lease_not_before: now,
                lease_expires_at: now + 86_400,
                data_selection: vec![],
                ttl_seconds: 300,
            },
        }),
    })?;
    assert!(
        matches!(reply, CustodyServerFrame::Refused { code: CustodyRefusal::Unsupported, .. }),
        "test: default-off native service issued an invitation: {reply:?}"
    );
    Ok(())
}
