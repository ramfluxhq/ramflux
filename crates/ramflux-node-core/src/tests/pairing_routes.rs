// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-free pairing routes: native proof plus HTTPS relay, never an account grant.
use super::*;
use crate::pairing_relay::{
    PAIRING_CLAIM_PATH, PAIRING_POLL_PATH, PAIRING_SEND_PATH, PairingClock, PairingRelayConfig,
    PairingRelayStore, TestPairingClock, handle_pairing_http,
};
use ramflux_protocol::custody::object_hash;
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::native::{
    Create, CreateSpec, Created, Issue, NativeReply, PairingReply,
};
use ramflux_protocol::custody::pairing::relay::{Claim, Close, Poll, RelayFrame, Send};
use ramflux_protocol::custody::{CustodyProofAction, CustodyRefusal, CustodyServerFrame};
use ramflux_protocol::encode_base64url;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_760_000_000;
const WALL: u64 = NOW;
const ORIGIN: &str = "https://relay.example:443";

fn relay_store(clock: Arc<TestPairingClock>) -> TestResult<PairingRelayStore> {
    Ok(PairingRelayStore::new(PairingRelayConfig {
        clock: clock as Arc<dyn PairingClock>,
        node_seed: [7; 32],
        public_origin: ORIGIN.into(),
    })?)
}

fn locked(store: &Mutex<PairingRelayStore>) -> TestResult<MutexGuard<'_, PairingRelayStore>> {
    store.lock().map_err(|_| "pairing lock".into())
}

fn spec(driver: &custody_sessions::Driver, wall: u64) -> TestResult<CreateSpec> {
    Ok(CreateSpec {
        schema: "ramflux.pairing.CreateSpec.v2".into(),
        version: 2,
        account_anchor: driver.reference.account_anchor.clone(),
        primary_ref: driver.reference.clone(),
        base_record_hash: object_hash(&driver.publication.record)?,
        base_epoch: driver.publication.record.body.device_set_epoch,
        purpose: "enroll".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["message".into(), "register".into()],
        lease_not_before: wall,
        lease_expires_at: wall + 86_400,
        data_selection: vec![],
        ttl_seconds: 300,
    })
}

fn issue_action(driver: &custody_sessions::Driver, wall: u64) -> TestResult<CustodyProofAction> {
    Ok(CustodyProofAction::PairingIssue {
        request: Box::new(Issue {
            schema: "ramflux.pairing.Issue.v2".into(),
            version: 2,
            spec: spec(driver, wall)?,
        }),
    })
}

fn create_action(
    driver: &custody_sessions::Driver,
    ticket: ramflux_protocol::custody::Envelope<
        ramflux_protocol::custody::pairing::native::CreateTicket,
    >,
    wall: u64,
) -> TestResult<CustodyProofAction> {
    Ok(CustodyProofAction::PairingCreate {
        request: Box::new(Create {
            schema: "ramflux.pairing.Create.v2".into(),
            version: 2,
            ticket,
            spec: spec(driver, wall)?,
        }),
    })
}

fn pairing_reply(frame: CustodyServerFrame) -> TestResult<PairingReply> {
    match frame {
        CustodyServerFrame::Pairing { reply } => Ok(*reply),
        other => Err(format!("pairing frame: {other:?}").into()),
    }
}

fn issued_of(
    frame: CustodyServerFrame,
) -> TestResult<ramflux_protocol::custody::pairing::native::Issued> {
    match pairing_reply(frame)?.reply {
        NativeReply::Issued(issued) => Ok(*issued),
        other => Err(format!("issued: {other:?}").into()),
    }
}

fn created_of(frame: CustodyServerFrame) -> TestResult<Created> {
    match pairing_reply(frame)?.reply {
        NativeReply::Created(created) => Ok(*created),
        other => Err(format!("created: {other:?}").into()),
    }
}

fn failure_code(frame: CustodyServerFrame) -> TestResult<String> {
    match pairing_reply(frame)?.reply {
        NativeReply::Failure(failure) => Ok(failure.code),
        other => Err(format!("failure: {other:?}").into()),
    }
}

fn run_issue(
    driver: &custody_sessions::Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    wall: u64,
) -> TestResult<ramflux_protocol::custody::pairing::native::Issued> {
    issued_of(driver.run(service, router, store, issue_action(driver, wall)?)?)
}

fn run_create(
    driver: &custody_sessions::Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    ticket: ramflux_protocol::custody::Envelope<
        ramflux_protocol::custody::pairing::native::CreateTicket,
    >,
    wall: u64,
) -> TestResult<Created> {
    created_of(driver.run(service, router, store, create_action(driver, ticket, wall)?)?)
}

fn retired_create(
    driver: &custody_sessions::Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    ticket: ramflux_protocol::custody::Envelope<
        ramflux_protocol::custody::pairing::native::CreateTicket,
    >,
    wall: u64,
) -> TestResult {
    assert_eq!(
        failure_code(driver.run(service, router, store, create_action(driver, ticket, wall)?)?)?,
        "Retired"
    );
    Ok(())
}

fn http(
    store: &Mutex<PairingRelayStore>,
    path: &str,
    body: &[u8],
    source: u8,
) -> crate::pairing_relay::PairingHttpResponse {
    handle_pairing_http(store, IpAddr::V4(Ipv4Addr::new(198, 51, 100, source)), "POST", path, body)
}

fn wire<T: PairingWire>(value: &T) -> TestResult<Vec<u8>> {
    Ok(value.to_wire_bytes()?)
}

fn openssl_run(args: &[&str]) -> TestResult {
    let status = std::process::Command::new("openssl").args(args).status()?;
    if status.success() { Ok(()) } else { Err(format!("openssl {args:?}").into()) }
}

fn openssl_leaf(
    root: &std::path::Path,
) -> TestResult<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let ca_key = root.join("ca-key.pem");
    let ca_cert = root.join("ca.pem");
    let key = root.join("key.pem");
    let csr = root.join("leaf.csr");
    let cert = root.join("cert.pem");
    let ext = root.join("leaf.ext");
    let ca_key_s = ca_key.to_str().ok_or("ca key")?;
    let ca_cert_s = ca_cert.to_str().ok_or("ca cert")?;
    let key_s = key.to_str().ok_or("leaf key")?;
    let csr_s = csr.to_str().ok_or("csr")?;
    let cert_s = cert.to_str().ok_or("leaf cert")?;
    let ext_s = ext.to_str().ok_or("ext")?;
    openssl_run(&["genpkey", "-algorithm", "ED25519", "-out", ca_key_s])?;
    openssl_run(&[
        "req",
        "-x509",
        "-new",
        "-key",
        ca_key_s,
        "-out",
        ca_cert_s,
        "-days",
        "1",
        "-subj",
        "/CN=pairing-test-ca",
    ])?;
    openssl_run(&["genpkey", "-algorithm", "ED25519", "-out", key_s])?;
    openssl_run(&["req", "-new", "-key", key_s, "-out", csr_s, "-subj", "/CN=localhost"])?;
    std::fs::write(
        &ext,
        "subjectAltName = DNS:localhost\nextendedKeyUsage = serverAuth\nkeyUsage = digitalSignature\n",
    )?;
    openssl_run(&[
        "x509",
        "-req",
        "-in",
        csr_s,
        "-CA",
        ca_cert_s,
        "-CAkey",
        ca_key_s,
        "-CAcreateserial",
        "-out",
        cert_s,
        "-days",
        "1",
        "-extfile",
        ext_s,
    ])?;
    Ok((ca_cert, cert, key))
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

fn rustls_client_config(cert: &std::path::Path) -> TestResult<Arc<rustls::ClientConfig>> {
    let mut cert_pem = std::io::BufReader::new(std::fs::File::open(cert)?);
    let mut roots = rustls::RootCertStore::empty();
    for der in rustls_pemfile::certs(&mut cert_pem) {
        roots.add(der?)?;
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
    ))
}

fn content_length(header: &str) -> TestResult<usize> {
    for line in header.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("Content-Length")
        {
            return Ok(value.trim().parse()?);
        }
    }
    Ok(0)
}

fn read_http(tls: &mut impl Read, raw: &mut Vec<u8>) -> TestResult<(String, usize, usize)> {
    let mut buf = [0_u8; 512];
    loop {
        if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = std::str::from_utf8(&raw[..end])?.to_owned();
            return Ok((header, end, end + 4));
        }
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Err("headers".into());
        }
        raw.extend_from_slice(&buf[..n]);
    }
}

fn serve_pairing_https(
    store: &Mutex<PairingRelayStore>,
    mut tcp: TcpStream,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<(), String> {
    tcp.set_read_timeout(Some(Duration::from_secs(5))).map_err(|error| error.to_string())?;
    let mut conn =
        rustls::ServerConnection::new(server_config).map_err(|error| error.to_string())?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    let mut raw = Vec::new();
    let (header, _, start) = read_http(&mut tls, &mut raw).map_err(|error| error.to_string())?;
    let mut parts = header.lines().next().ok_or("line")?.split_whitespace();
    let method = parts.next().ok_or("method")?.to_owned();
    let path = parts.next().ok_or("path")?.to_owned();
    let length = content_length(&header).map_err(|error| error.to_string())?;
    while raw.len() < start + length {
        let mut buf = [0_u8; 512];
        let n = tls.read(&mut buf).map_err(|error| error.to_string())?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let reply = handle_pairing_http(
        store,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        &method,
        &path,
        &raw[start..start + length],
    );
    write!(
        tls,
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reply.body.len()
    )
    .map_err(|error| error.to_string())?;
    tls.write_all(&reply.body).map_err(|error| error.to_string())?;
    tls.conn.send_close_notify();
    tls.flush().map_err(|error| error.to_string())
}

fn read_https_response(tls: &mut impl Read) -> TestResult<Vec<u8>> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(error)
                if error.kind() == std::io::ErrorKind::UnexpectedEof
                    && response.windows(4).any(|w| w == b"\r\n\r\n") =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
        if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            let length = content_length(std::str::from_utf8(&response[..end])?)?;
            if response.len() >= end + 4 + length {
                response.truncate(end + 4 + length);
                break;
            }
        }
    }
    Ok(response)
}

fn https_exchange(
    store: Arc<Mutex<PairingRelayStore>>,
    path: &str,
    body: &[u8],
    extra_headers: &str,
) -> TestResult<Vec<u8>> {
    let store_directory_0 = temp_store_path("pairing-https")?;
    let root = store_directory_0.to_path_buf().with_extension("tls");
    std::fs::create_dir_all(&root)?;
    let (ca, cert, key) = openssl_leaf(&root)?;
    let server_config = rustls_server_config(&cert, &key)?;
    let client_config = rustls_client_config(&ca)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let worker = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().map_err(|error| error.to_string())?;
        serve_pairing_https(store.as_ref(), tcp, server_config)
    });
    let mut tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
    let mut conn = rustls::ClientConnection::new(client_config, server_name)?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    write!(
        tls,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
        body.len()
    )?;
    tls.write_all(body)?;
    tls.flush()?;
    let response = read_https_response(&mut tls)?;
    worker.join().map_err(|_| "https worker")??;
    let _ = std::fs::remove_dir_all(root);
    Ok(response)
}

fn prove_tampered_issue(
    driver: &custody_sessions::Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    relay: &Mutex<PairingRelayStore>,
) -> TestResult {
    let before = locked(relay)?.stats();
    let accounted = locked(relay)?.accounted_bytes();
    let challenge = driver.challenge(service, router, store, issue_action(driver, WALL)?)?;
    let mut bad = driver.proof(&challenge)?;
    bad.body.record_hash = encode_base64url([0; 32]);
    assert!(matches!(
        driver.attempt(service, router, store, issue_action(driver, WALL)?, bad)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused, .. }
    ));
    {
        let store = locked(relay)?;
        assert_eq!(store.stats().slots, before.slots);
        assert_eq!(store.accounted_bytes(), accounted);
        assert_eq!(store.accounted_bytes(), store.measured_bytes());
    }
    Ok(())
}

fn prove_spec_primary_mismatch(
    driver: &custody_sessions::Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    relay: &Mutex<PairingRelayStore>,
) -> TestResult {
    let before = locked(relay)?.stats();
    let accounted = locked(relay)?.accounted_bytes();
    let mut action = issue_action(driver, WALL)?;
    match &mut action {
        CustodyProofAction::PairingIssue { request } => {
            request.spec.primary_ref.device_id = "secondary".into();
        }
        other => return Err(format!("issue action: {other:?}").into()),
    }
    assert!(matches!(
        driver.run(service, router, store, action)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused, .. }
    ));
    {
        let store = locked(relay)?;
        assert_eq!(store.stats().slots, before.slots);
        assert_eq!(store.accounted_bytes(), accounted);
        assert_eq!(store.accounted_bytes(), store.measured_bytes());
    }
    Ok(())
}

struct NativeCase<'a> {
    driver: &'a custody_sessions::Driver,
    service: &'a crate::CustodyService,
    router: &'a RouterCore,
    store: &'a RouterRedbStore,
}

fn prove_closed_create_is_retired(
    case: &NativeCase<'_>,
    relay: &Mutex<PairingRelayStore>,
    created: &Created,
    ticket: ramflux_protocol::custody::Envelope<
        ramflux_protocol::custody::pairing::native::CreateTicket,
    >,
) -> TestResult {
    let closed = Close {
        schema: "ramflux.pairing.Close.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token: created.primary_token.clone(),
        reason: "done".into(),
    };
    locked(relay)?.close(&closed)?;
    let after_close = locked(relay)?.stats();
    retired_create(case.driver, case.service, case.router, case.store, ticket, WALL)?;
    assert_eq!(locked(relay)?.stats().slots, after_close.slots);
    Ok(())
}

fn prove_https_relay(relay: &Arc<Mutex<PairingRelayStore>>, created: &Created) -> TestResult {
    let claim = Claim {
        schema: "ramflux.pairing.Claim.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        recipient_token: created.recipient_token.clone(),
        claim_nonce: encode_base64url([9; 32]),
    };
    let claimed = https_exchange(
        Arc::clone(relay),
        PAIRING_CLAIM_PATH,
        &wire(&claim)?,
        "Authorization: Bearer ramflux-local-admin-token\r\nCookie: session=stolen\r\n",
    )?;
    assert!(
        std::str::from_utf8(&claimed)?.contains("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&claimed)
    );
    let send = Send {
        schema: "ramflux.pairing.Send.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "responder".into(),
        token: created.recipient_token.clone(),
        seq: 0,
        frame: RelayFrame::Confirm {
            role: "responder".into(),
            transcript_hash: encode_base64url([1; 32]),
            mac: encode_base64url([2; 32]),
        },
    };
    assert_eq!(http(relay, PAIRING_SEND_PATH, &wire(&send)?, 9).status, "200 OK");
    let poll = Poll {
        schema: "ramflux.pairing.Poll.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token: created.primary_token.clone(),
        after_seq: None,
    };
    assert_eq!(http(relay, PAIRING_POLL_PATH, &wire(&poll)?, 9).status, "200 OK");
    Ok(())
}

fn prove_token_cannot_open_session(
    driver: &custody_sessions::Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    token: &str,
) -> TestResult {
    assert!(matches!(
        driver.run(
            service,
            router,
            store,
            CustodyProofAction::Register { prekey_bundle: driver.bundle(10)? }
        )?,
        CustodyServerFrame::Registered { .. }
    ));
    let session = driver.run(service, router, store, CustodyProofAction::OpenSession)?;
    assert!(matches!(session, CustodyServerFrame::SessionEstablished { .. }), "{session:?}");
    let stolen = service.mesh(
        router,
        store,
        ramflux_protocol::custody::CustodyMeshRequest::Request {
            connection_id: driver.connection.clone(),
            session_id: token.to_owned(),
            request: Box::new(gateway_fanout_signed_request(&driver.reference.device_id)),
            action: ramflux_protocol::custody::CustodySessionAction::Close,
        },
        "ramflux-gateway",
        NOW,
    );
    assert!(
        matches!(stolen, CustodyServerFrame::Refused { .. }),
        "relay token authorized a session: {stolen:?}"
    );
    Ok(())
}

#[test]
fn pairing_root_free_routes_cannot_authorize_account() -> TestResult {
    let path = temp_store_path("pairing-root-free")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.bootstrap_router(&router)?;
    let driver = custody_sessions::Driver::new("alice", 10)?;
    let clock = TestPairingClock::new(WALL);
    let relay = Arc::new(Mutex::new(relay_store(Arc::clone(&clock))?));
    let service = crate::CustodyService::new(driver.node.clone(), false, &store, NOW)?
        .with_pairing_relay(Arc::clone(&relay));
    assert!(matches!(
        driver.run(&service, &router, &store, driver.publish())?,
        CustodyServerFrame::Published { .. }
    ));
    let before = locked(&relay)?.stats();
    prove_tampered_issue(&driver, &service, &router, &store, &relay)?;
    prove_spec_primary_mismatch(&driver, &service, &router, &store, &relay)?;
    let issued = run_issue(&driver, &service, &router, &store, WALL)?;
    let created = run_create(&driver, &service, &router, &store, issued.ticket.clone(), WALL)?;
    assert_eq!(created.request_id, issued.ticket.body.create_id);
    prove_closed_create_is_retired(
        &NativeCase { driver: &driver, service: &service, router: &router, store: &store },
        &relay,
        &created,
        issued.ticket.clone(),
    )?;

    let slots_before_expired = locked(&relay)?.stats().slots;
    let issued2 = run_issue(&driver, &service, &router, &store, WALL)?;
    clock.advance_secs(301);
    retired_create(&driver, &service, &router, &store, issued2.ticket.clone(), WALL)?;
    {
        let held = locked(&relay)?;
        assert_eq!(held.stats().slots, slots_before_expired);
        assert_eq!(held.accounted_bytes(), held.measured_bytes());
    }

    let prior = relay_store(Arc::clone(&clock))?;
    let prior_boot = prior.boot_id().to_owned();
    drop(prior);
    let issued3 = run_issue(&driver, &service, &router, &store, clock.wall_unix_secs()?)?;
    assert_ne!(issued3.ticket.body.boot_id, prior_boot);
    let restarted = Arc::new(Mutex::new(relay_store(Arc::clone(&clock))?));
    let service_boot = crate::CustodyService::new(driver.node.clone(), false, &store, NOW)?
        .with_pairing_relay(Arc::clone(&restarted));
    let slots_before = locked(&restarted)?.stats().slots;
    retired_create(
        &driver,
        &service_boot,
        &router,
        &store,
        issued3.ticket.clone(),
        clock.wall_unix_secs()?,
    )?;
    assert_eq!(locked(&restarted)?.stats().slots, slots_before);

    let issued = run_issue(&driver, &service, &router, &store, clock.wall_unix_secs()?)?;
    let created = run_create(
        &driver,
        &service,
        &router,
        &store,
        issued.ticket.clone(),
        clock.wall_unix_secs()?,
    )?;
    prove_https_relay(&relay, &created)?;
    prove_token_cannot_open_session(&driver, &service, &router, &store, &created.recipient_token)?;

    let record = router.custody_record(&driver.reference.account_anchor, NOW)?;
    assert_eq!(record.as_ref().map(|r| r.record.body.devices.len()), Some(1));
    let stats = locked(&relay)?;
    assert_eq!(stats.accounted_bytes(), stats.measured_bytes());
    assert!(stats.stats().high_water >= before.high_water);
    drop(stats);
    assert_eq!(
        handle_pairing_http(
            &Mutex::new(relay_store(TestPairingClock::new(WALL))?),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "POST",
            "/client/pairing/v1/unknown",
            b"{}",
        )
        .status,
        "404 Not Found"
    );
    Ok(())
}
