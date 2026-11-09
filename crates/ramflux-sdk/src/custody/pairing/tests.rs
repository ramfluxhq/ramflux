// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Coordinator talks to production P06 `handle_pairing_http` over a real TCP listener.
use super::{
    HttpRelay, PairingActor, PairingIdentity, PairingNative, pairing_enabled, validate_head_advance,
};
use crate::SdkError;
use ramflux_node_core::pairing_relay::{
    PairingClock, PairingRelayConfig, PairingRelayError, PairingRelayStore, TestPairingClock,
    handle_pairing_http,
};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::local_dto::{
    Approve, Begin, BeginResult, Confirm, Join, LocalResult, Outcome, StatusRequest, Update,
};
use ramflux_protocol::custody::pairing::native::{Create, CreateSpec, Created, Issued};
use ramflux_protocol::encode_base64url;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WALL: u64 = 1_760_000_000;
const ORIGIN: &str = "https://relay.example:443";

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

struct PairingHttp {
    origin: String,
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Drop for PairingHttp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(self.addr) {
            drop(stream);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct Fixture {
    primary: PairingActor,
    recipient: PairingActor,
    clock: Arc<TestPairingClock>,
    _http: PairingHttp,
    _env: PairingEnv,
    _fixed: crate::time::FixedClock,
}

struct PairingEnv {
    _guard: MutexGuard<'static, ()>,
    previous: Option<String>,
}

#[test]
fn pairing_two_local_confirmations_precede_approval() -> TestResult {
    let mut fx = Fixture::open()?;
    let begun = begin_result(fx.primary.begin(begin_body())?)?;
    let secret = begun.invite_token.recipient_token.clone();
    let op = begun.operation_id.clone();
    let generation = begun.generation;
    assert_no_token(&fx.primary.status(&status_req(&op, generation))?, &secret)?;
    fx.recipient.join(Join {
        schema: "ramflux.pairing.Join.v2".into(),
        version: 2,
        token: begun.invite_token,
        display_name: "Recipient".into(),
    })?;
    drive_sas(&mut fx, &op, generation)?;
    assert!(fx.primary.frames_seen() > 0 && fx.recipient.frames_seen() > 0);
    assert_eq!(fx.primary.unsolicited_prompts(), 0);
    assert_eq!(fx.recipient.unsolicited_prompts(), 0);
    fx.recipient.confirm(&confirm_ok(&fx.recipient, &op)?)?;
    drive_once(&mut fx)?;
    fx.primary.note_peer_confirmed_flag(true);
    assert_approve_refused(&mut fx.primary, &op)?;
    fx.primary.confirm(&confirm_ok(&fx.primary, &op)?)?;
    drive_once(&mut fx)?;
    let approved = update(fx.primary.approve(&approve_ok(&fx.primary, &op)?)?)?;
    assert_eq!(approved.phase, "proposal_pending");
    Ok(())
}

#[test]
fn pairing_mismatch_rejects_sas() -> TestResult {
    let mut fx = Fixture::open()?;
    let (op, _) = joined(&mut fx)?;
    let mut bad = confirm_ok(&fx.primary, &op)?;
    bad.r#match = false;
    let mismatch = update(fx.primary.confirm(&bad)?)?;
    assert_eq!(
        (mismatch.phase.as_str(), mismatch.result.as_deref()),
        ("rejected", Some("SasMismatch"))
    );
    Ok(())
}

#[test]
fn pairing_lock_background_and_head_change() -> TestResult {
    let mut fx = Fixture::open()?;
    let begun = begin_result(fx.primary.begin(begin_body())?)?;
    let locked = update(fx.primary.lock()?)?;
    assert_eq!((locked.phase.as_str(), locked.result.as_deref()), ("cancelled", Some("Retired")));
    assert!(fx.primary.frontend_generation() > begun.generation);
    drop(fx);
    let mut fx = Fixture::open()?;
    let _ = begin_result(fx.primary.begin(begin_body())?)?;
    let expired = update(fx.primary.background()?)?;
    assert_eq!((expired.phase.as_str(), expired.result.as_deref()), ("expired", Some("Expired")));
    drop(fx);
    let mut fx = Fixture::open()?;
    let _ = begin_result(fx.primary.begin(begin_body())?)?;
    let changed = update(fx.primary.note_head_change()?)?;
    assert_eq!(
        (changed.phase.as_str(), changed.result.as_deref()),
        ("rejected", Some("HeadChanged"))
    );
    Ok(())
}

#[test]
fn pairing_head_advance_enforces_publisher_ref() -> TestResult {
    validate_head_advance("prepared", "submitted", true)?;
    validate_head_advance("submitted", "acknowledged", true)?;
    validate_head_advance("prepared", "acknowledged", false)?;
    match validate_head_advance("prepared", "acknowledged", true) {
        Err(SdkError::PairingField("submitted_required")) => {}
        other => return Err(format!("publisher skip submitted: {other:?}").into()),
    }
    match validate_head_advance("prepared", "submitted", false) {
        Err(SdkError::PairingField("responder_submitted")) => {}
        other => return Err(format!("responder submitted: {other:?}").into()),
    }
    Ok(())
}

#[test]
#[allow(unsafe_code)]
fn pairing_disabled_without_opt_in() {
    let _guard = pairing_env_lock().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = std::env::var("RAMFLUX_DEVICE_PAIRING_ENABLED").ok();
    unsafe {
        std::env::remove_var("RAMFLUX_DEVICE_PAIRING_ENABLED");
    }
    let disabled = !pairing_enabled();
    unsafe {
        match previous {
            Some(value) => std::env::set_var("RAMFLUX_DEVICE_PAIRING_ENABLED", value),
            None => std::env::remove_var("RAMFLUX_DEVICE_PAIRING_ENABLED"),
        }
    }
    assert!(disabled);
}

fn joined(fx: &mut Fixture) -> TestResult<(String, u64)> {
    let begun = begin_result(fx.primary.begin(begin_body())?)?;
    let op = begun.operation_id.clone();
    let generation = begun.generation;
    fx.recipient.join(Join {
        schema: "ramflux.pairing.Join.v2".into(),
        version: 2,
        token: begun.invite_token,
        display_name: "Recipient".into(),
    })?;
    drive_sas(fx, &op, generation)?;
    Ok((op, generation))
}

fn drive_sas(fx: &mut Fixture, op: &str, generation: u64) -> TestResult {
    let mut last = String::new();
    for _ in 0..24 {
        drive_once(fx)?;
        let primary = phase(&mut fx.primary, op, generation)?;
        let recipient = phase(&mut fx.recipient, op, generation)?;
        last = format!(
            "primary={primary} recipient={recipient} frames={}/{}",
            fx.primary.frames_seen(),
            fx.recipient.frames_seen()
        );
        if primary == "sas_pending" && recipient == "sas_pending" {
            return Ok(());
        }
    }
    Err(last.into())
}

fn drive_once(fx: &mut Fixture) -> TestResult {
    fx.clock.advance_ms(1_001);
    let _ = fx.primary.sync_relay()?;
    fx.clock.advance_ms(1_001);
    let _ = fx.recipient.sync_relay()?;
    Ok(())
}

fn phase(actor: &mut PairingActor, op: &str, generation: u64) -> TestResult<String> {
    Ok(update(actor.status(&status_req(op, generation))?)?.phase)
}

fn assert_approve_refused(actor: &mut PairingActor, op: &str) -> TestResult {
    match actor.approve(&approve_ok(actor, op)?) {
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

fn begin_body() -> Begin {
    Begin {
        schema: "ramflux.pairing.Begin.v2".into(),
        version: 2,
        capabilities: vec!["message".into(), "register".into()],
        lease_not_before: WALL,
        lease_expires_at: WALL + 86_400,
        display_name: "Primary".into(),
    }
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

impl Fixture {
    fn open() -> TestResult<Self> {
        let env = enable_pairing();
        let fixed = crate::time::FixedClock::set(i64::try_from(WALL)?);
        let clock = TestPairingClock::new(WALL);
        let store = Arc::new(Mutex::new(PairingRelayStore::new(PairingRelayConfig {
            clock: Arc::clone(&clock) as Arc<dyn PairingClock>,
            node_seed: [7; 32],
            public_origin: ORIGIN.into(),
        })?));
        let http = spawn_http(Arc::clone(&store))?;
        let native = Arc::new(StoreNative { store });
        let relay = HttpRelay::new(http.origin.clone());
        Ok(Self {
            primary: PairingActor::new(
                identity("primary", true),
                Arc::clone(&native) as _,
                relay.clone(),
            ),
            recipient: PairingActor::new(identity("recipient", false), native, relay),
            clock,
            _http: http,
            _env: env,
            _fixed: fixed,
        })
    }
}

fn identity(device: &str, primary: bool) -> PairingIdentity {
    PairingIdentity {
        account_id: device.into(),
        local_ref: DeviceRef {
            account_anchor: encode_base64url([1u8; 32]),
            device_id: device.into(),
            device_epoch: 1,
        },
        master_public_key: encode_base64url([3u8; 32]),
        base_record_hash: encode_base64url([2u8; 32]),
        base_epoch: 1,
        is_primary: primary,
    }
}

fn spawn_http(store: Arc<Mutex<PairingRelayStore>>) -> TestResult<PairingHttp> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let join = std::thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        while !flag.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        serve_one(&store, stream, peer.ip());
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) if flag.load(Ordering::SeqCst) => break,
                Err(_) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    });
    Ok(PairingHttp { origin: format!("http://{addr}"), addr, stop, join: Some(join) })
}

fn serve_one(store: &Mutex<PairingRelayStore>, mut stream: TcpStream, source: std::net::IpAddr) {
    let Ok((method, path, body)) = read_http(&mut stream) else {
        return;
    };
    let reply = handle_pairing_http(store, source, &method, &path, &body);
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reply.body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&reply.body);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn read_http(stream: &mut TcpStream) -> TestResult<(String, String, Vec<u8>)> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&raw[..split])?.to_owned();
            let length = content_length(&head);
            let start = split + 4;
            while raw.len() < start.saturating_add(length) {
                let n = stream.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
            }
            let mut parts = head.lines().next().unwrap_or_default().split(' ');
            let method = parts.next().unwrap_or_default().to_owned();
            let path = parts.next().unwrap_or_default().to_owned();
            let body = raw.get(start..start.saturating_add(length)).unwrap_or(&[]).to_vec();
            return Ok((method, path, body));
        }
        if raw.len() > 16 * 1024 {
            break;
        }
    }
    Err("http request".into())
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().ok()).flatten()
        })
        .unwrap_or(0)
}

fn held(store: &Mutex<PairingRelayStore>) -> MutexGuard<'_, PairingRelayStore> {
    store.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn relay_err(error: PairingRelayError) -> SdkError {
    SdkError::PairingCode(error.code())
}

fn pairing_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[allow(unsafe_code)]
fn enable_pairing() -> PairingEnv {
    let guard = pairing_env_lock().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = std::env::var("RAMFLUX_DEVICE_PAIRING_ENABLED").ok();
    // SAFETY: `guard` is held for the whole set/restore window.
    unsafe {
        std::env::set_var("RAMFLUX_DEVICE_PAIRING_ENABLED", "1");
    }
    PairingEnv { _guard: guard, previous }
}

#[allow(unsafe_code)]
impl Drop for PairingEnv {
    fn drop(&mut self) {
        // SAFETY: `self._guard` is held until this drop returns.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("RAMFLUX_DEVICE_PAIRING_ENABLED", value),
                None => std::env::remove_var("RAMFLUX_DEVICE_PAIRING_ENABLED"),
            }
        }
    }
}
