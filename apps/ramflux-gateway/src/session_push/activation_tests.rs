// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK bytes through the production gateway handler and a separately stored router process.
use super::*;
use crate::session_push::tests::support::sink;
use ramflux_node_core::{RouterCore, RouterRedbStore, SessionDescriptor, SessionLifecycle};
use ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY;
use ramflux_sdk::{
    EphemeralReceiver, EphemeralSendError, EphemeralSendOutcome, EphemeralWire, ReceiverAdmit,
    ReceiverClock, ReceiverDequeue, send_ephemeral,
};
use ramflux_storage::{AccountDb, AccountDbKey, AccountIndex};
use std::collections::BTreeMap;
use std::path::Path;

const TARGET: &str = "alice-target";
type TestResult = anyhow::Result<()>;

fn register_source(router: &RouterCore) -> TestResult {
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let root = ramflux_crypto::create_identity_root("agent", [3; 32]);
    let branch = ramflux_crypto::create_device_branch("agent", "agent-device", 1, [4; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([5; 32]);
    let proof = ramflux_crypto::authorize_device_branch_v2(
        &root,
        &branch,
        ramflux_crypto::BranchAuthorization {
            audience: ramflux_node_core::IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.into()],
            issued_at: now - 10,
            expires_at: now + 3600,
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            agreement_identity_public_key: agreement.public,
        },
    )?;
    let public = ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let branch_public =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let (signing_key_commitment, agreement_key_commitment) =
        ramflux_crypto::device_key_commitments(
            &branch_public,
            &ramflux_protocol::encode_base64url(agreement.public),
        )?;
    let device_set = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                device_id: "agent-device".into(),
                device_epoch: 1,
                signing_key_commitment,
                agreement_key_commitment,
                status: ramflux_protocol::DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    router.mvp1_register_identity(&ramflux_node_core::IdentityRegisterRequest {
        device_set: Some(device_set),
        principal_commitment: ramflux_crypto::identity_root_commitment(
            &root.signing_key.verifying_key(),
        ),
        root_public_key: public,
        branch_public_key: branch_public,
        proof,
        target_delivery_id: "agent-target".into(),
        gateway_id: "ramflux-gateway".into(),
        session_id: "agent-session".into(),
        push_alias_hash: None,
        now,
        registration_pow: None,
        source_ip_hash: Some("activation-fixture".into()),
    })?;
    Ok(())
}

fn recipient(context: &GatewayQuicContext) -> SessionDescriptor {
    SessionDescriptor {
        target_delivery_id: TARGET.into(),
        device_id: "alice-device".into(),
        gateway_id: context.gateway_id.clone(),
        session_id: "alice-session".into(),
        device_epoch: 1,
        session_seq: ramflux_node_core::now_unix_seconds(),
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: SessionLifecycle::Live,
    }
}

async fn ready(context: &GatewayQuicContext) -> TestResult {
    context.hub.readiness.start_with_hub(&context.router, &context.hub, &context.gateway_id);
    let waited = tokio::time::timeout(Duration::from_secs(15), async {
        while !context.hub.readiness.supports() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(waited.is_ok(), "router capabilities discovery did not finish within 15s");
    Ok(())
}

/// The synchronous public SDK wire drives the actual async gateway, preserving its signature.
struct GatewayWire<'a> {
    context: &'a GatewayQuicContext,
    runtime: &'a crate::GatewaySessionRuntime,
    reply: Option<Vec<u8>>,
    result: Option<Value>,
    writes: usize,
}
impl EphemeralWire for GatewayWire<'_> {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<(), EphemeralSendError> {
        self.writes += 1;
        let frame: ramflux_node_core::GatewayClientFrame =
            ramflux_protocol::parse_i_json(bytes).map_err(|_| EphemeralSendError::Encode)?;
        let ramflux_node_core::GatewayClientFrame::Submit { submit } = frame else {
            return Err(EphemeralSendError::Encode);
        };
        let (send, captured) = sink();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(crate::ephemeral::handle_submit(
                &send,
                self.context,
                self.runtime,
                &submit,
            ))
        })
        .map_err(|_| EphemeralSendError::TransportWrite)?;
        let frames = captured.lock().map_err(|_| EphemeralSendError::TransportRead)?;
        if frames.len() != 1 {
            return Err(EphemeralSendError::TransportRead);
        }
        self.result = Some(frames[0].clone());
        self.reply = Some(serde_json::to_vec(&frames[0]).map_err(|_| EphemeralSendError::Decode)?);
        Ok(())
    }
    fn recv_frame(&mut self) -> Result<Vec<u8>, EphemeralSendError> {
        self.reply.take().ok_or(EphemeralSendError::TransportRead)
    }
}

fn send(
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    id: &str,
    caps: &[String],
) -> anyhow::Result<(EphemeralSendOutcome, usize, Option<Value>)> {
    let submit = crate::ephemeral::handler_tests::submit(runtime, id, 5, |_| {})?;
    let mut wire = GatewayWire { context, runtime, reply: None, result: None, writes: 0 };
    let outcome = send_ephemeral(
        &submit.signed_request,
        &submit.envelope,
        caps,
        crate::ephemeral::now_ms(),
        &mut wire,
    )?;
    Ok((outcome, wire.writes, wire.result))
}

fn files(root: &Path) -> anyhow::Result<BTreeMap<std::path::PathBuf, [u8; 32]>> {
    let mut result = BTreeMap::new();
    if root.exists() {
        for entry in std::fs::read_dir(root)? {
            let path = entry?.path();
            if path.is_dir() {
                result.extend(files(&path)?);
            } else if !path.to_string_lossy().ends_with("-shm") {
                result.insert(
                    path.clone(),
                    ramflux_crypto::blake3_256(
                        "ramflux.test.ephemeral.artifacts.v1",
                        &std::fs::read(path)?,
                    ),
                );
            }
        }
    }
    Ok(result)
}

fn account(root: &Path) -> anyhow::Result<AccountDb> {
    let index = AccountIndex::open(root)?;
    let identity = ramflux_crypto::create_identity_root("client", [11; 32]);
    index.create_account(
        "client",
        &ramflux_crypto::identity_root_commitment(&identity.signing_key.verifying_key()),
    )?;
    Ok(AccountDb::open(&index, "client", &AccountDbKey::from_bytes([12; 32]))?)
}
fn journal(db: &AccountDb) -> anyhow::Result<String> {
    Ok(format!(
        "{:?}|{:?}|{:?}|{:?}",
        db.journal_bounds()?,
        db.journal_after(0, 128)?,
        db.pending_outbox(256)?,
        db.list_actor_states::<Value>("")?
    ))
}

async fn issued(context: &GatewayQuicContext) -> anyhow::Result<Value> {
    Ok(crate::router_post_json_async(
        &context.router,
        "/mvp0/issued-seqs",
        &json!({"targets":[TARGET]}),
    )
    .await?)
}
async fn empty_resume(context: &GatewayQuicContext, incarnation: &str) -> TestResult {
    let page: Value = crate::router_get_json_async(
        &context.router,
        &format!(
            "/mvp1/inbox/{TARGET}?session_push=1&incarnation_id={incarnation}&after=1&limit=100"
        ),
    )
    .await?;
    assert_eq!(page["entries"], json!([]), "ephemeral appeared in Resume: {page}");
    Ok(())
}

async fn restart(child: &mut Child, context: &GatewayQuicContext) -> TestResult {
    let endpoint = &context
        .router
        .async_mesh
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("async router"))?
        .endpoint;
    child.0 = std::process::Command::new(
        std::env::var_os("RAMFLUX_P17_ROUTER_BINARY")
            .ok_or_else(|| anyhow::anyhow!("router binary"))?,
    )
    .arg("--config")
    .arg(child.1.join("router.toml"))
    .env("RUST_LOG", "info")
    .env("RAMFLUX_ROUTER_ASYNC_LISTEN_ADDR", endpoint)
    .env("RAMFLUX_ROUTER_ASYNC_INGRESS_RUNTIME", "tokio")
    .env("RAMFLUX_ROUTER_ASYNC_INGRESS_SOCKETS", "1")
    .env("RAMFLUX_ROUTER_ASYNC_WORKER_THREADS", "2")
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::inherit())
    .spawn()?;
    let stdout = child.0.stdout.take().ok_or_else(|| anyhow::anyhow!("router stdout"))?;
    let (ready, received) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let mut ready = Some(ready);
        for line in std::io::BufReader::new(stdout).lines() {
            if line.is_ok_and(|line| line.contains("router async QUIC endpoint bound"))
                && let Some(ready) = ready.take()
            {
                let _ = ready.send(());
            }
        }
    });
    let waited = tokio::time::timeout(Duration::from_secs(15), received).await;
    assert!(waited.is_ok(), "restarted router did not bind within 15s");
    waited??;
    Ok(())
}

async fn exercise_live(
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    caps: &[String],
    incarnation: &str,
    dormant: bool,
) -> TestResult {
    let (target_send, frames) = sink();
    let registration = if runtime.ephemeral {
        context
            .hub
            .register_ephemeral(
                TARGET.into(),
                "alice-session".into(),
                target_send,
                Some(incarnation.to_owned()),
                64,
            )
            .await?
    } else {
        context.hub.register(TARGET.into(), "alice-session".into(), target_send).await?
    };
    let (outcome, writes, _) = send(context, runtime, "activation-live", caps)?;
    if dormant {
        assert_eq!(outcome, EphemeralSendOutcome::Unsupported);
        assert_eq!(writes, 0);
    } else {
        assert_eq!(outcome, EphemeralSendOutcome::Delivered);
        assert_eq!(writes, 1);
        context.hub.flushed(TARGET).await?;
        let observed_frames =
            frames.lock().map_err(|_| anyhow::anyhow!("recipient frames"))?.clone();
        assert_eq!(observed_frames.len(), 1, "one actual transient delivery");
        let bytes = serde_json::to_vec(&observed_frames[0])?;
        let mut receiver = EphemeralReceiver::new();
        let now = crate::ephemeral::now_ms();
        assert!(matches!(
            receiver.admit(
                &bytes,
                ReceiverClock { local_now_ms: now, monotonic_ms: 1 },
                "agent",
                &runtime.branch_public_key
            ),
            ReceiverAdmit::Displayed { .. }
        ));
        assert!(matches!(receiver.pop(now, 1), ReceiverDequeue::Delivered { .. }));
        receiver.complete();
        assert_eq!(receiver.ledger_probe(), ramflux_sdk::LedgerProbe::default());
    }
    context.hub.unregister(TARGET, registration.token).await;
    Ok(())
}

async fn exercise_full_and_expired(
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    caps: &[String],
    incarnation: &str,
) -> TestResult {
    let (target_send, _) = sink();
    let registration = context
        .hub
        .register_ephemeral(
            TARGET.into(),
            "alice-session".into(),
            target_send,
            Some(incarnation.to_owned()),
            64,
        )
        .await?;
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let snapshot = context.hub.snapshot().await;
    snapshot
        .get(TARGET)
        .ok_or_else(|| anyhow::anyhow!("full-row registration"))?
        .queue
        .park_next_write(entered.clone(), release.clone());
    for n in 0..9 {
        let submit = crate::ephemeral::handler_tests::submit(
            runtime,
            &format!("full-{n}"),
            5,
            |envelope| envelope.encrypted_payload = "x".repeat(30_000),
        )?;
        let mut wire = GatewayWire { context, runtime, reply: None, result: None, writes: 0 };
        let outcome = send_ephemeral(
            &submit.signed_request,
            &submit.envelope,
            caps,
            crate::ephemeral::now_ms(),
            &mut wire,
        )?;
        assert_eq!(
            outcome,
            if n < 8 {
                EphemeralSendOutcome::Delivered
            } else {
                EphemeralSendOutcome::Dropped(
                    ramflux_protocol::ephemeral::EphemeralDropReason::QueueFull,
                )
            }
        );
        if n == 0 {
            let waiting = tokio::time::timeout(Duration::from_secs(10), entered.notified()).await;
            assert!(waiting.is_ok(), "full-row writer did not enter held sink");
        }
    }
    release.add_permits(1);
    context.hub.flushed(TARGET).await?;
    context.hub.unregister(TARGET, registration.token).await;
    let expired = crate::ephemeral::handler_tests::submit(runtime, "expired", 5, |envelope| {
        envelope.created_at -= 10;
    })?;
    let expires_at_ms = u64::try_from(expired.envelope.created_at + 5)? * 1000;
    let result: Value = crate::router_post_json_async(
        &context.router,
        "/mvp0/envelope-ephemeral",
        &json!({"envelope":expired.envelope,"expires_at_ms":expires_at_ms}),
    )
    .await?;
    assert_eq!(result, json!({"outcome":"dropped","reason":"expired"}));
    let mut invalid = crate::ephemeral::handler_tests::submit(runtime, "invalid", 5, |_| {})?;
    invalid.envelope.signed.signature.clear();
    let expires_at_ms = u64::try_from(invalid.envelope.created_at + 5)? * 1000;
    let result: Value = crate::router_post_json_async(
        &context.router,
        "/mvp0/envelope-ephemeral",
        &json!({"envelope":invalid.envelope,"expires_at_ms":expires_at_ms}),
    )
    .await?;
    assert_eq!(result, json!({"outcome":"dropped","reason":"invalid"}));
    Ok(())
}

async fn exercise_legacy_recipient(
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    caps: &[String],
    dormant: bool,
    root: &Path,
) -> TestResult {
    // A legacy gateway registration against the new router is refused before any fallback.
    let old = negotiate(context, &auth(true)?, &recipient(context)).await?;
    assert!(
        old.incarnation_id.is_some(),
        "old gateway retains session push without an ephemeral echo"
    );
    assert!(!old.ephemeral);
    let baseline_artifacts = files(root)?;
    let baseline_issued = issued(context).await?;
    let (local, writes, _) = send(
        context,
        runtime,
        "old-gateway-no-echo",
        &[ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into()],
    )?;
    assert_eq!(local, EphemeralSendOutcome::Unsupported);
    assert_eq!(writes, 0, "old gateway without an echo must not write a frame");
    let (legacy_outcome, _, legacy_result) =
        send(context, runtime, "activation-old-gateway", caps)?;
    assert_eq!(
        legacy_outcome,
        EphemeralSendOutcome::Unsupported,
        "legacy recipient capability must be refused before forwarding"
    );
    if !dormant {
        assert_eq!(
            legacy_result,
            Some(json!({"frame_type":"ephemeral_result",
            "envelope_id":"activation-old-gateway","outcome":"dropped","reason":"recipient_unsupported"}))
        );
    }
    assert_eq!(
        files(root)?,
        baseline_artifacts,
        "legacy recipient refusal changed durable artifacts"
    );
    assert_eq!(issued(context).await?, baseline_issued, "legacy refusal allocated a sequence");
    Ok(())
}

async fn settle_control(
    child: &mut Child,
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    incarnation: &str,
    dormant: bool,
) -> anyhow::Result<Vec<u8>> {
    // Establish a nonzero durable baseline and settle it before measuring ephemeral effects.
    let control = crate::session::submit_fixtures::signed_submit(
        runtime,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    )?;
    let submitted: Value =
        crate::router_post_json_async(&context.router, "/mvp0/envelope", &control.envelope).await?;
    assert_eq!(submitted["inbox_seq"], 1, "durable control must allocate sequence 1: {submitted}");
    let settled: Value = crate::router_post_json_async(
        &context.router,
        "/mvp0/ack-bound-batch",
        &json!({"target_delivery_id":TARGET, "incarnation_id":incarnation, "inbox_seqs":[1]}),
    )
    .await?;
    assert_eq!(
        settled["cursor"]["inbox_seq"], 1,
        "durable control must settle before the baseline: {settled}"
    );
    empty_resume(context, incarnation).await?;
    // Record the real post-control replay baseline through ordinary reopen, then resume
    // fresh processes before freezing every durable artifact for the ephemeral measurement.
    child.0.kill()?;
    child.0.wait()?;
    let baseline_replay = {
        let store = RouterRedbStore::open(child.1.join("router.redb"))?;
        store
            .load_router()?
            .ok_or_else(|| anyhow::anyhow!("baseline router missing"))?
            .ephemeral_durable_snapshot()?
            .replay
    };
    restart(child, context).await?;
    let rebound = negotiate(context, &auth_claiming_ephemeral(true)?, &recipient(context)).await?;
    assert_eq!(rebound.incarnation_id.as_deref(), Some(incarnation));
    assert_eq!(rebound.ephemeral, !dormant);
    Ok(baseline_replay)
}

async fn run_activation() -> TestResult {
    let seed = RouterCore::new();
    register_source(&seed)?;
    let (mut child, context) = real_router_with_state(Some(&seed)).await?;
    ready(&context).await?;
    let binding =
        negotiate(&context, &auth_claiming_ephemeral(true)?, &recipient(&context)).await?;
    let incarnation =
        binding.incarnation_id.clone().ok_or_else(|| anyhow::anyhow!("push not negotiated"))?;
    let dormant = std::env::var_os("RAMFLUX_EXPECT_EPHEMERAL_DORMANT").is_some();
    assert_eq!(binding.ephemeral, !dormant, "production router listing controls activation");
    let mut runtime = crate::session::submit_fixtures::test_runtime()?;
    runtime.session_push = Some(incarnation.clone());
    runtime.ephemeral = binding.ephemeral;
    assert_eq!(runtime.ephemeral_negotiated(), !dormant);
    let caps = if binding.ephemeral {
        vec![
            ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into(),
            GATEWAY_EPHEMERAL_CAPABILITY.into(),
        ]
    } else {
        vec![ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into()]
    };
    let baseline_replay =
        settle_control(&mut child, &context, &runtime, &incarnation, dormant).await?;
    let client_root = child.1.join("client");
    let db = account(&client_root)?;
    let before_client = files(&client_root)?;
    let before_journal = journal(&db)?;
    let before_gateway = serde_json::to_vec(&context.store.load_state()?)?;
    let before_issued = issued(&context).await?;
    let before_artifacts = files(&child.1)?;
    let before_control = context.notify.wake_count();
    crate::session::dispatch_offline_wake(
        &context,
        TARGET,
        &crate::session::submit_fixtures::test_envelope(i64::try_from(
            ramflux_node_core::now_unix_seconds(),
        )?)?,
    )
    .await?;
    assert_eq!(
        context.notify.wake_count(),
        before_control + 1,
        "wake observer must see the production spawn_blocking call"
    );
    let wakes = context.notify.wake_count();
    exercise_live(&context, &runtime, &caps, &incarnation, dormant).await?;
    if !dormant {
        assert_eq!(
            send(&context, &runtime, "activation-offline", &caps)?.0,
            EphemeralSendOutcome::Dropped(
                ramflux_protocol::ephemeral::EphemeralDropReason::Offline
            )
        );
    }
    if !dormant {
        exercise_full_and_expired(&context, &runtime, &caps, &incarnation).await?;
    }
    assert_eq!(issued(&context).await?, before_issued, "issued advanced for ephemeral");
    empty_resume(&context, &incarnation).await?;
    assert_eq!(
        context.notify.wake_count(),
        wakes,
        "real admission/forward path woke offline delivery"
    );
    assert_eq!(serde_json::to_vec(&context.store.load_state()?)?, before_gateway);
    assert_eq!(journal(&db)?, before_journal, "ephemeral mutated journal or durable SDK state");
    assert_eq!(files(&client_root)?, before_client, "client DB/WAL bytes changed");
    let after_artifacts = files(&child.1)?;
    exercise_legacy_recipient(&context, &runtime, &caps, dormant, &child.1).await?;
    assert_eq!(issued(&context).await?, before_issued, "legacy recipient caused durable fallback");
    // Ordinary reopen of the actual router store after process death: no replay tuple/content.
    child.0.kill()?;
    child.0.wait()?;
    let store = RouterRedbStore::open(child.1.join("router.redb"))?;
    let reopened = store.load_router()?.ok_or_else(|| anyhow::anyhow!("router state missing"))?;
    assert_eq!(reopened.pending_entries_for_target(TARGET).len(), 0);
    assert_eq!(reopened.session_push_status(TARGET).inbox_seq, 1);
    assert_eq!(reopened.cursor_state(TARGET).map(|cursor| cursor.settled_inbox_seq), Some(1));
    assert_eq!(
        reopened.ephemeral_durable_snapshot()?.replay,
        baseline_replay,
        "router reopen retained an ephemeral replay tuple"
    );
    assert_eq!(
        after_artifacts, before_artifacts,
        "ephemeral live/offline/full/expired/refused changed durable file artifacts"
    );
    drop(reopened);
    drop(store);
    restart(&mut child, &context).await?;
    assert_eq!(issued(&context).await?, before_issued, "router restart changed issued");
    empty_resume(&context, &incarnation).await?;
    // A new receiver has no queued ciphertext or ACK work after restart.
    assert_eq!(EphemeralReceiver::new().pop(crate::ephemeral::now_ms(), 1), ReceiverDequeue::Empty);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a separately built same-tree router binary on QA"]
async fn ephemeral_activation_end_to_end() -> TestResult {
    run_activation().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a separately built same-tree router binary on QA"]
async fn ephemeral_persistence_absence() -> TestResult {
    run_activation().await
}

fn receiver_admit(
    receiver: &mut EphemeralReceiver,
    frame: &Value,
    runtime: &crate::GatewaySessionRuntime,
    monotonic_ms: u64,
) -> anyhow::Result<ReceiverAdmit> {
    Ok(receiver.admit(
        &serde_json::to_vec(frame)?,
        ReceiverClock { local_now_ms: crate::ephemeral::now_ms(), monotonic_ms },
        "agent",
        &runtime.branch_public_key,
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a separately built same-tree router binary on QA"]
async fn ephemeral_router_restart_preserves_live_receiver_dedup() -> TestResult {
    let seed = RouterCore::new();
    register_source(&seed)?;
    let (mut child, context) = real_router_with_state(Some(&seed)).await?;
    ready(&context).await?;
    let binding =
        negotiate(&context, &auth_claiming_ephemeral(true)?, &recipient(&context)).await?;
    let dormant = std::env::var_os("RAMFLUX_EXPECT_EPHEMERAL_DORMANT").is_some();
    assert_eq!(binding.ephemeral, !dormant);
    if dormant {
        return Ok(());
    }
    let incarnation = binding.incarnation_id.ok_or_else(|| anyhow::anyhow!("push missing"))?;
    let mut runtime = crate::session::submit_fixtures::test_runtime()?;
    runtime.session_push = Some(incarnation.clone());
    runtime.ephemeral = true;
    let caps = vec![
        ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into(),
        GATEWAY_EPHEMERAL_CAPABILITY.into(),
    ];
    let (target_send, frames) = sink();
    let registration = context
        .hub
        .register_ephemeral(
            TARGET.into(),
            "alice-session".into(),
            target_send,
            Some(incarnation),
            64,
        )
        .await?;
    assert_eq!(
        send(&context, &runtime, "surviving-receiver", &caps)?.0,
        EphemeralSendOutcome::Delivered
    );
    context.hub.flushed(TARGET).await?;
    let first = frames
        .lock()
        .map_err(|_| anyhow::anyhow!("frames"))?
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("first transient missing"))?;
    let envelope: ramflux_protocol::Envelope = serde_json::from_value(first["envelope"].clone())?;
    let expires_at_ms =
        first["expires_at_ms"].as_u64().ok_or_else(|| anyhow::anyhow!("deadline"))?;
    let mut receiver = EphemeralReceiver::new();
    let admitted = receiver_admit(&mut receiver, &first, &runtime, 1)?;
    assert!(matches!(admitted, ReceiverAdmit::Displayed { .. }));
    assert!(matches!(
        receiver.pop(crate::ephemeral::now_ms(), 1),
        ReceiverDequeue::Delivered { .. }
    ));
    receiver.complete();
    child.0.kill()?;
    child.0.wait()?;
    restart(&mut child, &context).await?;
    negotiate(&context, &auth_claiming_ephemeral(true)?, &recipient(&context)).await?;
    assert!(
        crate::ephemeral::now_ms() < expires_at_ms,
        "router-only restart must complete before D"
    );
    let route: Value = crate::router_post_json_async(
        &context.router,
        "/mvp0/envelope-ephemeral",
        &json!({"envelope":envelope,"expires_at_ms":expires_at_ms}),
    )
    .await?;
    assert_eq!(route["outcome"], "online", "router lost only its volatile replay marker: {route}");
    let forwarded = crate::ephemeral_forward::handle(
        &context.hub,
        crate::ephemeral_forward::GatewayForwardEphemeralRequest {
            source_gateway_id: context.gateway_id.clone(),
            target_delivery_id: TARGET.into(),
            forwarded: true,
            envelope,
            expires_at_ms,
        },
    )
    .await?;
    assert!(forwarded.delivered);
    context.hub.flushed(TARGET).await?;
    let observed = frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.clone();
    assert_eq!(observed.len(), 2);
    assert_eq!(observed.first(), observed.get(1));
    let replayed = observed.get(1).ok_or_else(|| anyhow::anyhow!("replayed transient missing"))?;
    assert_eq!(receiver_admit(&mut receiver, replayed, &runtime, 2)?, ReceiverAdmit::Duplicate);
    assert_eq!(receiver.ledger_probe(), ramflux_sdk::LedgerProbe::default());
    context.hub.unregister(TARGET, registration.token).await;
    Ok(())
}
