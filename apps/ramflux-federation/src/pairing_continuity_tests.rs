// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cross-component pairing over real TLS + node-owned store forwarding.
use super::tests::{NodeMesh, PairingEnv, enable_pairing, spawn_node_mesh_at};
use super::{PairingHttpSurface, pairing_limits, respond};
use crate::RouterMeshClient;
use ramflux_node_core::NodeHttpRequest;
use ramflux_node_core::pairing_relay::{
    PairingClock, PairingRelayError, PairingRelayStore, TestPairingClock,
};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::local_dto::{
    Approve, Begin, BeginResult, Confirm, Join, LocalResult, Outcome, StatusRequest, Update,
};
use ramflux_protocol::custody::pairing::native::{Create, CreateSpec, Created, Issued};
use ramflux_protocol::custody::pairing::relay::{RelayFrame, Send};
use ramflux_protocol::encode_base64url;
use ramflux_sdk::SdkError;
use ramflux_sdk::custody::pairing::{
    HttpRelay, PairingActor, PairingConfig, PairingIdentity, PairingNative,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct StoreNative {
    store: Arc<Mutex<PairingRelayStore>>,
}

impl PairingNative for StoreNative {
    fn issue(&self, spec: CreateSpec) -> Result<Issued, SdkError> {
        held(&self.store).issue(spec).map_err(relay_err)
    }
    fn create(&self, create: Create) -> Result<Created, SdkError> {
        held(&self.store).create(create).map_err(relay_err)
    }
}

struct Continuity {
    primary: PairingActor,
    recipient: PairingActor,
    clock: Arc<TestPairingClock>,
    store: Arc<Mutex<PairingRelayStore>>,
    origin: String,
    _env: PairingEnv,
    _node: NodeMesh,
    _tls: crate::test_directories::TestDirectory,
}

#[tokio::test]
async fn pairing_two_local_confirmations_precede_approval() -> TestResult {
    let mut fx = Continuity::open()?;
    refuse_plaintext_http(&fx.origin)?;
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
    let (op, _) = joined(&mut fx).await?;
    let mut bad = confirm_ok(&fx.primary, &op)?;
    bad.r#match = false;
    let mismatch = update(fx.primary.confirm(&bad).await?)?;
    assert_eq!(
        (mismatch.phase.as_str(), mismatch.result.as_deref()),
        ("rejected", Some("SasMismatch"))
    );
    drop(fx);

    let mut fx = Continuity::open()?;
    let _ = joined(&mut fx).await?;
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
    let (op, generation) = joined(&mut fx).await?;
    let mut stale = confirm_ok(&fx.primary, &op)?;
    stale.generation = generation.saturating_add(1);
    match fx.primary.confirm(&stale).await {
        Err(SdkError::PairingCode("WrongContext")) => Ok(()),
        Ok(result) => Err(format!("stale confirm {}", update(result)?.phase).into()),
        Err(error) => Err(format!("stale confirm {error}").into()),
    }
}

impl Continuity {
    fn open() -> TestResult<Self> {
        let env = enable_pairing();
        let tls_root = crate::test_certificates::temp_cert_root("pairing-continuity-tls")?;
        let ca = crate::test_certificates::issue_test_ca(&tls_root)?;
        let server =
            crate::test_certificates::issue_test_service_cert(&ca, "node-a", "ramflux-federation")?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let origin = format!("https://localhost:{port}");
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
        let surface = PairingHttpSurface::open_if_enabled(Arc::clone(&router))?
            .ok_or("pairing surface off")?;
        let server_config =
            rustls_server_config(&server.tls.service_cert, &server.tls.service_key)?;
        std::thread::spawn(move || serve_pairing_tls(listener, surface, server_config));
        let config = PairingConfig { enabled: true, extra_root_ca_pem: Some(server.ca_pem) };
        let relay = Arc::new(HttpRelay::from_config(&config)?);
        let native = Arc::new(StoreNative { store: Arc::clone(&node.store) });
        Ok(Self {
            primary: PairingActor::new(
                identity("primary", true, true),
                Some(native as _),
                Arc::clone(&relay) as _,
                config.clone(),
            ),
            recipient: PairingActor::new(
                identity("recipient", false, false),
                None,
                relay as _,
                config,
            ),
            clock,
            store: Arc::clone(&node.store),
            origin,
            _env: env,
            _node: node,
            _tls: tls_root,
        })
    }
}

#[allow(clippy::needless_pass_by_value)]
fn serve_pairing_tls(
    listener: TcpListener,
    surface: Arc<PairingHttpSurface>,
    server_config: Arc<rustls::ServerConfig>,
) {
    loop {
        let Ok((mut tcp, peer)) = listener.accept() else {
            continue;
        };
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
        let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&server_config)) else {
            continue;
        };
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let Ok(request) = read_http_request(&mut tls) else {
            continue;
        };
        let reply = respond(&surface, peer.ip(), &request, true);
        let _ = reply.write_plain(&mut tls);
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }
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
            break;
        }
        raw.extend_from_slice(&buf[..n]);
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
    }
}

fn update(result: LocalResult) -> TestResult<Update> {
    match result.outcome {
        Outcome::Update { value } => Ok(*value),
        Outcome::Begin { .. } => Err("update was begin".into()),
        Outcome::Error { error } => Err(error.code.into()),
    }
}

fn terminal_phase(phase: &str) -> bool {
    matches!(phase, "cancelled" | "expired" | "rejected" | "completed")
}

fn identity(device: &str, primary: bool, with_master: bool) -> PairingIdentity {
    PairingIdentity {
        account_id: device.into(),
        local_ref: DeviceRef {
            account_anchor: encode_base64url([1u8; 32]),
            device_id: device.into(),
            device_epoch: 1,
        },
        master_public_key: with_master.then(|| encode_base64url([3u8; 32])),
        base_record_hash: encode_base64url([2u8; 32]),
        base_epoch: 1,
        is_primary: primary,
    }
}

fn held(store: &Mutex<PairingRelayStore>) -> MutexGuard<'_, PairingRelayStore> {
    store.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn relay_err(error: PairingRelayError) -> SdkError {
    SdkError::PairingCode(error.code())
}
