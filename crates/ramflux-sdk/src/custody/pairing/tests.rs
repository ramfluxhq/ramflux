// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Coordinator unit tests. Config is injected; no process environment.
use super::{
    PairingActor, PairingConfig, PairingIdentity, PairingNative, PairingTransport,
    validate_head_advance,
};
use crate::SdkError;
use ramflux_node_core::pairing_relay::{
    PairingClock, PairingRelayConfig, PairingRelayError, PairingRelayStore, TestPairingClock,
};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::local_dto::{
    Approve, Begin, BeginResult, Confirm, Join, LocalResult, Outcome, StatusRequest, Update,
};
use ramflux_protocol::custody::pairing::native::{Create, CreateSpec, Created, Issued};
use ramflux_protocol::custody::pairing::relay::{
    Claim, Claimed, Close, Closed, Poll, Polled, RelayFrame, Send, Sent,
};
use ramflux_protocol::encode_base64url;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type BoxFut<T> = Pin<Box<dyn Future<Output = T> + std::marker::Send>>;
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

struct MemoryRelay {
    store: Arc<Mutex<PairingRelayStore>>,
}

impl PairingTransport for MemoryRelay {
    fn claim(&self, _origin: String, claim: Claim) -> BoxFut<Result<Claimed, SdkError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            held(&store).claim(IpAddr::V4(Ipv4Addr::LOCALHOST), &claim).map_err(relay_err)
        })
    }
    fn send(&self, _origin: String, send: Send) -> BoxFut<Result<Sent, SdkError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move { held(&store).send(&send).map_err(relay_err) })
    }
    fn poll(&self, _origin: String, poll: Poll) -> BoxFut<Result<Polled, SdkError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move { held(&store).poll(&poll).map_err(relay_err) })
    }
    fn close(&self, _origin: String, close: Close) -> BoxFut<Result<Closed, SdkError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move { held(&store).close(&close).map_err(relay_err) })
    }
}

struct Fixture {
    primary: PairingActor,
    recipient: PairingActor,
    clock: Arc<TestPairingClock>,
    store: Arc<Mutex<PairingRelayStore>>,
    _fixed: crate::time::FixedClock,
}

#[tokio::test]
async fn pairing_coordinator_requires_two_local_confirmations() -> TestResult {
    let mut fx = Fixture::open()?;
    let begun = begin_result(fx.primary.begin(begin_body()).await?)?;
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
    Ok(())
}

#[tokio::test]
async fn pairing_mismatch_rejects_sas() -> TestResult {
    let mut fx = Fixture::open()?;
    let (op, _) = joined(&mut fx).await?;
    let mut bad = confirm_ok(&fx.primary, &op)?;
    bad.r#match = false;
    let mismatch = update(fx.primary.confirm(&bad).await?)?;
    assert_eq!(
        (mismatch.phase.as_str(), mismatch.result.as_deref()),
        ("rejected", Some("SasMismatch"))
    );
    Ok(())
}

#[tokio::test]
async fn pairing_lock_background_and_head_change() -> TestResult {
    let mut fx = Fixture::open()?;
    let begun = begin_result(fx.primary.begin(begin_body()).await?)?;
    let locked = update(fx.primary.lock().await?)?;
    assert_eq!((locked.phase.as_str(), locked.result.as_deref()), ("cancelled", Some("Retired")));
    assert!(fx.primary.frontend_generation() > begun.generation);
    drop(fx);
    let mut fx = Fixture::open()?;
    let _ = begin_result(fx.primary.begin(begin_body()).await?)?;
    let expired = update(fx.primary.background().await?)?;
    assert_eq!((expired.phase.as_str(), expired.result.as_deref()), ("expired", Some("Expired")));
    drop(fx);
    let mut fx = Fixture::open()?;
    let _ = begin_result(fx.primary.begin(begin_body()).await?)?;
    let changed = update(fx.primary.note_head_change().await?)?;
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

#[tokio::test]
async fn pairing_disabled_without_opt_in() -> TestResult {
    let config = PairingConfig { enabled: false, extra_root_ca_pem: None };
    assert!(!config.enabled);
    let mut fx = Fixture::with_config(config)?;
    match fx.primary.begin(begin_body()).await {
        Err(SdkError::PairingCode("NotFound")) => Ok(()),
        other => Err(format!("disabled begin: {other:?}").into()),
    }
}

#[tokio::test]
async fn pairing_stale_generation_is_refused() -> TestResult {
    let mut fx = Fixture::open()?;
    let (op, generation) = joined(&mut fx).await?;
    let mut stale = confirm_ok(&fx.primary, &op)?;
    stale.generation = generation.saturating_add(1);
    match fx.primary.confirm(&stale).await {
        Err(SdkError::PairingCode("WrongContext")) => {}
        Ok(result) => return Err(format!("stale confirm {}", update(result)?.phase).into()),
        Err(error) => return Err(format!("stale confirm {error}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn pairing_forged_invitation_is_refused() -> TestResult {
    let mut fx = Fixture::open()?;
    let mut begun = begin_result(fx.primary.begin(begin_body()).await?)?;
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
async fn pairing_bad_mac_is_terminal() -> TestResult {
    let mut fx = Fixture::open()?;
    let begun = begin_result(fx.primary.begin(begin_body()).await?)?;
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

async fn joined(fx: &mut Fixture) -> TestResult<(String, u64)> {
    let begun = begin_result(fx.primary.begin(begin_body()).await?)?;
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

async fn drive_sas(fx: &mut Fixture, op: &str, generation: u64) -> TestResult {
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

async fn drive_once(fx: &mut Fixture) -> TestResult {
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

fn terminal_phase(phase: &str) -> bool {
    matches!(phase, "cancelled" | "expired" | "rejected" | "completed")
}

impl Fixture {
    fn open() -> TestResult<Self> {
        Self::with_config(PairingConfig { enabled: true, extra_root_ca_pem: None })
    }

    fn with_config(config: PairingConfig) -> TestResult<Self> {
        let fixed = crate::time::FixedClock::set(i64::try_from(WALL)?);
        let clock = TestPairingClock::new(WALL);
        let store = Arc::new(Mutex::new(PairingRelayStore::new(PairingRelayConfig {
            clock: Arc::clone(&clock) as Arc<dyn PairingClock>,
            node_seed: [7; 32],
            public_origin: ORIGIN.into(),
        })?));
        let native = Arc::new(StoreNative { store: Arc::clone(&store) });
        let relay = Arc::new(MemoryRelay { store: Arc::clone(&store) });
        Ok(Self {
            primary: PairingActor::new(
                identity("primary", true, true),
                Some(Arc::clone(&native) as _),
                Arc::clone(&relay) as _,
                config.clone(),
            ),
            recipient: PairingActor::new(identity("recipient", false, false), None, relay, config),
            clock,
            store,
            _fixed: fixed,
        })
    }
}

fn identity(device: &str, primary: bool, with_master: bool) -> PairingIdentity {
    PairingIdentity {
        account_id: device.into(),
        local_ref: DeviceRef {
            account_anchor: if primary { encode_base64url([1u8; 32]) } else { String::new() },
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
