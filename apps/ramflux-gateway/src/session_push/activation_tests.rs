// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK bytes through the production gateway handler and a separately stored router process.
use super::*;
use crate::session_push::tests::support::sink;
use ramflux_node_core::{RouterCore, RouterRedbStore, SessionDescriptor, SessionLifecycle};
use ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY;
use ramflux_sdk::{EphemeralSendError, EphemeralSendOutcome, EphemeralWire, send_ephemeral};
use ramflux_storage::{AccountDb, AccountDbKey, AccountIndex};
use std::collections::BTreeMap;
use std::path::Path;

pub(super) const TARGET: &str = "alice-target";
pub(super) type TestResult = anyhow::Result<()>;

fn register_source(router: &RouterCore) -> TestResult {
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    for (principal, device, root_seed, branch_seed, agreement_seed, target, session) in [
        ("agent", "agent-device", 3, 4, 5, "agent-target", "agent-session"),
        ("alice", "alice-device", 6, 7, 8, TARGET, "alice-session"),
    ] {
        let root = ramflux_crypto::create_identity_root(principal, [root_seed; 32]);
        let branch = ramflux_crypto::create_device_branch(principal, device, 1, [branch_seed; 32]);
        let agreement = ramflux_crypto::X25519KeyPair::from_seed([agreement_seed; 32]);
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
        let public =
            ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
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
                    device_id: device.into(),
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
            target_delivery_id: target.into(),
            gateway_id: "ramflux-gateway".into(),
            session_id: session.into(),
            push_alias_hash: None,
            now,
            registration_pow: None,
            source_ip_hash: Some("activation-fixture".into()),
        })?;
    }
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

async fn bind_source(context: &GatewayQuicContext) -> anyhow::Result<String> {
    let descriptor = SessionDescriptor {
        target_delivery_id: "agent-target".into(),
        device_id: "agent-device".into(),
        gateway_id: context.gateway_id.clone(),
        session_id: "agent-session".into(),
        device_epoch: 1,
        session_seq: ramflux_node_core::now_unix_seconds(),
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: SessionLifecycle::Live,
    };
    negotiate(context, &auth_claiming_ephemeral(true)?, &descriptor)
        .await?
        .incarnation_id
        .ok_or_else(|| anyhow::anyhow!("source push binding missing"))
}

async fn ready(context: &GatewayQuicContext) -> TestResult {
    context.hub.readiness.start_with_hub(&context.router, &context.hub, &context.gateway_id);
    crate::ephemeral::tests::guard_10s("router capability discovery", async {
        while !context.hub.readiness.supports() {
            tokio::task::yield_now().await;
        }
    })
    .await;
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

fn journal(db: &AccountDb) -> anyhow::Result<String> {
    Ok(format!(
        "{:?}|{:?}|{:?}|{:?}",
        db.journal_bounds()?,
        db.journal_after(0, 128)?,
        db.pending_outbox(256)?,
        db.list_actor_states::<Value>("")?
    ))
}

fn assert_client_reopen(root: &Path, baseline: &str) -> TestResult {
    let index = AccountIndex::open(root)?;
    let reopened = AccountDb::open(&index, "client", &AccountDbKey::from_bytes([12; 32]))?;
    assert_eq!(
        journal(&reopened)?,
        baseline,
        "ordinary client reopen retained ephemeral journal/outbox/actor state"
    );
    Ok(())
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

fn stop_router_gracefully(child: &mut Child) -> TestResult {
    let status =
        std::process::Command::new("kill").arg("-TERM").arg(child.0.id().to_string()).status()?;
    anyhow::ensure!(status.success(), "router graceful stop signal failed");
    child.0.wait()?;
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
    crate::ephemeral::tests::guard_10s("restarted router bound", received).await?;
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

async fn calibrate_account_transport(
    sender: &mut super::activation_account::Account,
    receiver: &mut super::activation_account::Account,
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    recipient_runtime: &crate::GatewaySessionRuntime,
    incarnation: &str,
) -> TestResult {
    let receiver_control_before = receiver.host.snapshot()?;
    let committed = crate::ephemeral::tests::guard_10s(
        "supported durable control submit",
        receiver.host.service_while(sender.host.durable_message(
            recipient_runtime.source_identity.root_commitment(),
            &recipient_runtime.device_id,
            TARGET,
        )),
    )
    .await?;
    assert_eq!(committed.inbox_seq, 1, "real transport durable control must issue sequence 1");
    let settled = async {
        loop {
            let mut complete = true;
            for target in [TARGET, runtime.target_delivery_id.as_str()] {
                let value: Value = crate::router_get_json_async(
                    &context.router,
                    &format!("/mvp0/cursor/{target}"),
                )
                .await
                .map_err(|error| {
                    ramflux_sdk::SdkError::GatewaySessionRejected(error.to_string())
                })?;
                complete &= value["inbox_seq"] == 1 || value["cursor"]["inbox_seq"] == 1;
            }
            if complete {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    };
    let controlled = tokio::time::timeout(
        Duration::from_secs(10),
        sender.host.service_while(receiver.host.service_while(settled)),
    )
    .await;
    match controlled {
        Ok(result) => result?,
        Err(_) => anyhow::bail!("durable receive/ACK watchdog: {}", receiver.host.diagnostics()?),
    }
    crate::ephemeral::tests::guard_10s(
        "client durable ACK result applied",
        receiver.host.settled(TARGET, 1),
    )
    .await?;
    crate::ephemeral::tests::guard_10s(
        "sender durable receipt ACK result applied",
        sender.host.settled(&runtime.target_delivery_id, 1),
    )
    .await?;
    assert_ne!(
        receiver.host.snapshot()?,
        receiver_control_before,
        "durable receive on the measured SDK path must move the account observer"
    );
    empty_resume(context, incarnation).await?;
    Ok(())
}

struct RecipientRegistration<'a> {
    incarnation: &'a str,
    token: crate::session_hub::GatewayRegistrationToken,
}

async fn account_live_and_offline(
    sender: &mut super::activation_account::Account,
    receiver: &mut super::activation_account::Account,
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    target: RecipientRegistration<'_>,
    consumer: &mut ramflux_sdk::EphemeralConsumer,
) -> anyhow::Result<crate::session_hub::GatewayRegistration> {
    let RecipientRegistration { incarnation, token } = target;
    assert_eq!(
        sender.submit(runtime, "account-live", |_| {}).await?,
        EphemeralSendOutcome::Delivered
    );
    let handed_off = crate::ephemeral::tests::guard_10s(
        "live SDK authenticated handoff",
        receiver.host.next(consumer, |_| Some(super::activation_account::source(runtime))),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("authenticated live handoff missing"))?;
    let live: Value = serde_json::from_slice(&handed_off.0)?;
    assert_eq!(
        live["envelope"]["envelope_id"], "account-live",
        "end-to-end handoff must use the real host and consumer"
    );
    assert_eq!(
        live["envelope"]["encrypted_payload"],
        super::activation_account::presealed_ciphertext()?,
        "known presealed ciphertext must survive handoff unchanged"
    );
    consumer.complete();
    context.hub.unregister(TARGET, token).await;
    assert_eq!(
        sender.submit(runtime, "account-offline", |_| {}).await?,
        EphemeralSendOutcome::Dropped(ramflux_protocol::ephemeral::EphemeralDropReason::Offline)
    );
    let registration = context
        .hub
        .register_ephemeral(
            TARGET.into(),
            "alice-session".into(),
            receiver.push_sink(),
            Some(incarnation.to_owned()),
            64,
        )
        .await?;
    Ok(registration)
}

async fn account_full_and_expired(
    sender: &mut super::activation_account::Account,
    receiver: &mut super::activation_account::Account,
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    consumer: &mut ramflux_sdk::EphemeralConsumer,
) -> TestResult {
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    context
        .hub
        .snapshot()
        .await
        .get(TARGET)
        .ok_or_else(|| anyhow::anyhow!("full-row registration"))?
        .queue
        .park_next_write(entered.clone(), release.clone());
    for n in 0..9 {
        let outcome = sender.submit_padded(runtime, &format!("account-full-{n}")).await?;
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
            crate::ephemeral::tests::guard_10s(
                "actual SDK full-row gateway writer",
                entered.notified(),
            )
            .await;
        }
    }
    release.add_permits(1);
    context.hub.flushed(TARGET).await?;
    for n in 0..8 {
        let ciphertext = crate::ephemeral::tests::guard_10s(
            &format!("full-row SDK authenticated handoff {n}"),
            receiver.host.next(consumer, |_| Some(super::activation_account::source(runtime))),
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("full-row handoff missing"))?;
        let frame: Value = serde_json::from_slice(&ciphertext.0)?;
        assert_eq!(frame["envelope"]["envelope_id"], format!("account-full-{n}"));
        consumer.complete();
    }
    assert_eq!(
        sender.submit(runtime, "account-expired", |envelope| envelope.created_at -= 10).await?,
        EphemeralSendOutcome::Invalid(ramflux_protocol::ephemeral::EphemeralModeError::Expired)
    );
    Ok(())
}

async fn account_legacy_refusal(
    sender: &mut super::activation_account::Account,
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    incarnation: &str,
    root: &Path,
    registration: crate::session_hub::GatewayRegistration,
) -> TestResult {
    let old = negotiate(context, &auth(true)?, &recipient(context)).await?;
    assert!(!old.ephemeral);
    let before_refused_artifacts = files(root)?;
    assert_eq!(
        sender.submit(runtime, "account-refused", |_| {}).await?,
        EphemeralSendOutcome::Unsupported
    );
    assert_eq!(
        files(root)?,
        before_refused_artifacts,
        "refused transport changed durable artifacts"
    );
    // Registration metadata is control-plane state, outside the transport send-effect interval.
    let rebound = negotiate(context, &auth_claiming_ephemeral(true)?, &recipient(context)).await?;
    assert_eq!(rebound.incarnation_id.as_deref(), Some(incarnation));
    context.hub.unregister(TARGET, registration.token).await;
    Ok(())
}

fn assert_transient_account_frames(
    sender: &super::activation_account::Account,
    receiver: &super::activation_account::Account,
    before_writes: (usize, usize),
) -> TestResult {
    for (account, before) in [(&sender, before_writes.0), (&receiver, before_writes.1)] {
        let writes = account.writes.lock().map_err(|_| anyhow::anyhow!("SDK writes"))?;
        assert!(
            writes
                .iter()
                .skip(before)
                .all(|frame| frame["frame_type"] != "ack" && frame["frame_type"] != "ack_batch"),
            "ephemeral handoff must emit no ACK or ledger work"
        );
        assert!(
            writes
                .iter()
                .skip(before)
                .filter(|frame| frame["frame_type"] == "submit")
                .all(|frame| frame["submit"]["envelope"]["ext"]["delivery_mode"] == "ephemeral"
                    || frame["envelope"]["ext"]["delivery_mode"] == "ephemeral"),
            "no durable fallback submit"
        );
    }
    Ok(())
}

async fn assert_account_router_reopen(
    child: &mut Child,
    context: &GatewayQuicContext,
    baseline_replay: &[u8],
    before_issued: &Value,
    incarnation: &str,
    after_artifacts: &BTreeMap<std::path::PathBuf, [u8; 32]>,
) -> TestResult {
    // Ordinary reopen of the actual router store after process death: no replay tuple/content.
    child.0.kill()?;
    child.0.wait()?;
    let store = RouterRedbStore::open(child.1.join("router.redb"))?;
    let reopened = store.load_router()?.ok_or_else(|| anyhow::anyhow!("router state missing"))?;
    assert_eq!(reopened.pending_entries_for_target(TARGET).len(), 0);
    assert_eq!(reopened.session_push_status(TARGET).inbox_seq, 1);
    assert_eq!(reopened.cursor_state(TARGET).map(|cursor| cursor.settled_inbox_seq), Some(1));
    assert_eq!(
        reopened.ephemeral_durable_snapshot()?.replay.as_slice(),
        baseline_replay,
        "router reopen retained an ephemeral replay tuple"
    );
    assert!(!after_artifacts.is_empty(), "durable artifact inventory must be nonempty");
    drop(reopened);
    drop(store);
    restart(child, context).await?;
    assert_eq!(&issued(context).await?, before_issued, "router restart changed issued");
    empty_resume(context, incarnation).await?;
    Ok(())
}

struct ActivationSetup {
    child: Child,
    context: GatewayQuicContext,
    runtime: crate::GatewaySessionRuntime,
    source_incarnation: String,
    incarnation: String,
}

async fn account_activation_setup() -> anyhow::Result<Option<ActivationSetup>> {
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
    let source_incarnation = bind_source(&context).await?;
    runtime.session_push = Some(source_incarnation.clone());
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
    if dormant {
        settle_control(&mut child, &context, &runtime, &incarnation, true).await?;
        let (outcome, writes, _) = send(&context, &runtime, "dormant", &caps)?;
        assert_eq!(outcome, EphemeralSendOutcome::Unsupported);
        assert_eq!(writes, 0);
        return Ok(None);
    }
    Ok(Some(ActivationSetup { child, context, runtime, source_incarnation, incarnation }))
}

struct AttachedAccounts {
    sender: super::activation_account::Account,
    receiver: super::activation_account::Account,
    registration: crate::session_hub::GatewayRegistration,
    source_registration: crate::session_hub::GatewayRegistration,
    recipient_runtime: crate::GatewaySessionRuntime,
}

async fn attach_account_pair(
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    source_incarnation: &str,
    incarnation: &str,
    sender_root: &Path,
    receiver_root: &Path,
) -> anyhow::Result<AttachedAccounts> {
    let mut sender = super::activation_account::Account::attach(
        sender_root,
        context,
        runtime,
        source_incarnation,
    )
    .await?;
    let recipient_runtime = super::activation_account::recipient_runtime(runtime, incarnation)?;
    let mut receiver = super::activation_account::Account::attach(
        receiver_root,
        context,
        &recipient_runtime,
        incarnation,
    )
    .await?;
    let registration = context
        .hub
        .register_ephemeral(
            TARGET.into(),
            "alice-session".into(),
            receiver.push_sink(),
            Some(incarnation.to_owned()),
            64,
        )
        .await?;
    let sender_manifest = sender.host.public_manifest()?;
    let receiver_manifest = receiver.host.public_manifest()?;
    sender
        .host
        .trust_peer(receiver_manifest, recipient_runtime.source_identity.root_commitment())?;
    receiver.host.trust_peer(sender_manifest, runtime.source_identity.root_commitment())?;
    let source_registration = context.hub.register_runtime(runtime, sender.push_sink()).await?;
    Ok(AttachedAccounts { sender, receiver, registration, source_registration, recipient_runtime })
}

struct AccountBaseline {
    baseline_replay: Vec<u8>,
    before_journal: (String, String),
    before_client: BTreeMap<std::path::PathBuf, [u8; 32]>,
    before_writes: (usize, usize),
    before_gateway: Vec<u8>,
    before_issued: Value,
    before_artifacts: BTreeMap<std::path::PathBuf, [u8; 32]>,
    wakes: u64,
}

async fn capture_account_baseline(
    child: &mut Child,
    context: &GatewayQuicContext,
    sender: &mut super::activation_account::Account,
    receiver: &mut super::activation_account::Account,
    source_incarnation: &str,
    incarnation: &str,
) -> anyhow::Result<AccountBaseline> {
    let client_root = child.1.join("client");
    // Reopen the real router after the calibrated durable control, keeping both SDK hosts alive.
    stop_router_gracefully(child)?;
    let baseline_replay = {
        let store = RouterRedbStore::open(child.1.join("router.redb"))?;
        store
            .load_router()?
            .ok_or_else(|| anyhow::anyhow!("baseline router missing"))?
            .ephemeral_durable_snapshot()?
            .replay
    };
    restart(child, context).await?;
    assert_eq!(bind_source(context).await?, source_incarnation);
    let rebound = negotiate(context, &auth_claiming_ephemeral(true)?, &recipient(context)).await?;
    assert_eq!(rebound.incarnation_id.as_deref(), Some(incarnation));
    sender.host.warm_transport().await?;
    receiver.host.warm_transport().await?;
    let before_journal = (sender.host.snapshot()?, receiver.host.snapshot()?);
    let before_client = files(&client_root)?;
    let before_writes = (
        sender.writes.lock().map_err(|_| anyhow::anyhow!("sender writes"))?.len(),
        receiver.writes.lock().map_err(|_| anyhow::anyhow!("receiver writes"))?.len(),
    );
    let before_gateway = serde_json::to_vec(&context.store.load_state()?)?;
    let before_issued = issued(context).await?;
    let before_artifacts = files(&child.1)?;
    let before_control = context.notify.wake_count();
    crate::session::dispatch_offline_wake(
        context,
        TARGET,
        &crate::session::submit_fixtures::test_envelope(i64::try_from(
            ramflux_node_core::now_unix_seconds(),
        )?)?,
    )
    .await?;
    assert_eq!(
        context.notify.wake_count(),
        before_control + 1,
        "wake observer must see production spawn_blocking"
    );
    let wakes = context.notify.wake_count();

    Ok(AccountBaseline {
        baseline_replay,
        before_journal,
        before_client,
        before_writes,
        before_gateway,
        before_issued,
        before_artifacts,
        wakes,
    })
}

fn assert_attached_client_absence(
    accounts: &AttachedAccounts,
    root: &Path,
    before: &AccountBaseline,
) -> TestResult {
    assert_eq!(
        (accounts.sender.host.snapshot()?, accounts.receiver.host.snapshot()?),
        before.before_journal,
        "attached SDK account journal changed for ephemeral transport"
    );
    assert_eq!(files(root)?, before.before_client, "attached SDK account DB/WAL bytes changed");
    Ok(())
}

async fn assert_idle_node_transport(
    context: &GatewayQuicContext,
    incarnation: &str,
    before: &AccountBaseline,
) -> TestResult {
    assert_eq!(issued(context).await?, before.before_issued, "issued advanced for ephemeral");
    empty_resume(context, incarnation).await?;
    assert_eq!(
        context.notify.wake_count(),
        before.wakes,
        "actual submit path must never wake for ephemeral"
    );
    assert_eq!(serde_json::to_vec(&context.store.load_state()?)?, before.before_gateway);
    Ok(())
}

async fn stop_account_pair(
    mut accounts: AttachedAccounts,
    consumer: ramflux_sdk::EphemeralConsumer,
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
) -> TestResult {
    context.hub.unregister(&runtime.target_delivery_id, accounts.source_registration.token).await;
    accounts.sender.stop().await;
    accounts.receiver.stop().await;
    drop(consumer);
    drop(accounts.sender);
    drop(accounts.receiver);
    Ok(())
}

async fn run_activation(measure_persistence: bool) -> TestResult {
    let Some(ActivationSetup { mut child, context, runtime, source_incarnation, incarnation }) =
        account_activation_setup().await?
    else {
        return Ok(());
    };
    let client_root = child.1.join("client");
    let sender_root = client_root.join("sender");
    let receiver_root = client_root.join("receiver");
    let mut accounts = attach_account_pair(
        &context,
        &runtime,
        &source_incarnation,
        &incarnation,
        &sender_root,
        &receiver_root,
    )
    .await?;
    calibrate_account_transport(
        &mut accounts.sender,
        &mut accounts.receiver,
        &context,
        &runtime,
        &accounts.recipient_runtime,
        &incarnation,
    )
    .await?;
    let before = capture_account_baseline(
        &mut child,
        &context,
        &mut accounts.sender,
        &mut accounts.receiver,
        &source_incarnation,
        &incarnation,
    )
    .await?;
    let mut consumer = accounts
        .receiver
        .host
        .consumer()
        .await?
        .ok_or_else(|| anyhow::anyhow!("real account consumer missing"))?;
    let registration = account_live_and_offline(
        &mut accounts.sender,
        &mut accounts.receiver,
        &context,
        &runtime,
        RecipientRegistration { incarnation: &incarnation, token: accounts.registration.token },
        &mut consumer,
    )
    .await?;
    account_full_and_expired(
        &mut accounts.sender,
        &mut accounts.receiver,
        &context,
        &runtime,
        &mut consumer,
    )
    .await?;
    if measure_persistence {
        assert_attached_client_absence(&accounts, &client_root, &before)?;
    }
    assert_eq!(
        files(&child.1)?,
        before.before_artifacts,
        "actual live/offline/full/expired transport changed durable artifacts"
    );
    account_legacy_refusal(
        &mut accounts.sender,
        &context,
        &runtime,
        &incarnation,
        &child.1,
        registration,
    )
    .await?;
    assert_idle_node_transport(&context, &incarnation, &before).await?;
    if measure_persistence {
        assert_attached_client_absence(&accounts, &client_root, &before)?;
    }
    assert_transient_account_frames(&accounts.sender, &accounts.receiver, before.before_writes)?;
    let after_artifacts = files(&child.1)?;
    // Both ordinary-live and legacy-refusal intervals are observed; control-plane reassertion
    // may legitimately refresh router metadata between them.
    stop_account_pair(accounts, consumer, &context, &runtime).await?;
    assert_account_router_reopen(
        &mut child,
        &context,
        &before.baseline_replay,
        &before.before_issued,
        &incarnation,
        &after_artifacts,
    )
    .await?;
    if measure_persistence {
        assert_client_reopen(&sender_root, &before.before_journal.0)?;
        assert_client_reopen(&receiver_root, &before.before_journal.1)?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a separately built same-tree router binary on QA"]
async fn ephemeral_activation_end_to_end() -> TestResult {
    run_activation(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a separately built same-tree router binary on QA"]
async fn ephemeral_persistence_absence() -> TestResult {
    run_activation(true).await
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
    let source_incarnation = bind_source(&context).await?;
    runtime.session_push = Some(source_incarnation.clone());
    runtime.ephemeral = true;
    let mut sender = super::activation_account::Account::attach(
        &child.1.join("sender"),
        &context,
        &runtime,
        &source_incarnation,
    )
    .await?;
    let recipient_runtime = super::activation_account::recipient_runtime(&runtime, &incarnation)?;
    let mut receiver = super::activation_account::Account::attach(
        &child.1.join("receiver"),
        &context,
        &recipient_runtime,
        &incarnation,
    )
    .await?;
    let mut consumer =
        receiver.host.consumer().await?.ok_or_else(|| anyhow::anyhow!("consumer missing"))?;
    let registration = context
        .hub
        .register_ephemeral(
            TARGET.into(),
            "alice-session".into(),
            receiver.push_sink(),
            Some(incarnation),
            64,
        )
        .await?;
    assert_eq!(
        sender.submit(&runtime, "surviving-receiver", |_| {}).await?,
        EphemeralSendOutcome::Delivered
    );
    let first = crate::ephemeral::tests::guard_10s(
        "initial live dedup handoff",
        receiver.host.next(&mut consumer, |_| Some(super::activation_account::source(&runtime))),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("first handoff missing"))?;
    let frame: Value = serde_json::from_slice(&first.0)?;
    let envelope: ramflux_protocol::Envelope = serde_json::from_value(frame["envelope"].clone())?;
    consumer.complete();
    stop_router_gracefully(&mut child)?;
    restart(&mut child, &context).await?;
    negotiate(&context, &auth_claiming_ephemeral(true)?, &recipient(&context)).await?;
    assert_eq!(bind_source(&context).await?, source_incarnation);
    sender.host.warm_transport().await?;
    receiver.host.warm_transport().await?;
    assert!(crate::ephemeral::now_ms() < first.1, "router restart fixture must finish before D");
    assert_eq!(
        sender.host.submit(envelope).await?,
        EphemeralSendOutcome::Delivered,
        "only the router's volatile replay marker is lost"
    );
    assert_eq!(
        sender.submit(&runtime, "fresh-after-router-restart", |_| {}).await?,
        EphemeralSendOutcome::Delivered
    );
    let next = crate::ephemeral::tests::guard_10s(
        "surviving consumer dedup handoff",
        receiver.host.next(&mut consumer, |_| Some(super::activation_account::source(&runtime))),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("surviving consumer closed"))?;
    let next: Value = serde_json::from_slice(&next.0)?;
    assert_eq!(
        next["envelope"]["envelope_id"], "fresh-after-router-restart",
        "live account consumer must suppress the replay across router restart"
    );
    consumer.complete();
    context.hub.unregister(TARGET, registration.token).await;
    sender.stop().await;
    receiver.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a separately built same-tree router binary on QA"]
async fn ephemeral_local_submit_rechecks_final_registration_and_deadline() -> TestResult {
    let seed = RouterCore::new();
    register_source(&seed)?;
    let (_child, context) = real_router_with_state(Some(&seed)).await?;
    ready(&context).await?;
    let binding =
        negotiate(&context, &auth_claiming_ephemeral(true)?, &recipient(&context)).await?;
    if std::env::var_os("RAMFLUX_EXPECT_EPHEMERAL_DORMANT").is_some() {
        assert!(!binding.ephemeral, "parent must not negotiate ephemeral");
        return Ok(());
    }
    let mut runtime = crate::session::submit_fixtures::test_runtime()?;
    runtime.ephemeral = binding.ephemeral;
    runtime.session_push = binding.incarnation_id.clone();
    for replacement in [true, false] {
        let (target_send, recipient_frames) = sink();
        let registration = context
            .hub
            .register_ephemeral(
                TARGET.into(),
                "alice-session".into(),
                target_send,
                binding.incarnation_id.clone(),
                64,
            )
            .await?;
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        context.hub.park_next_enqueue(entered.clone(), release.clone());
        let submit = crate::ephemeral::handler_tests::submit(
            &runtime,
            if replacement { "local-replaced" } else { "local-expired" },
            5,
            |_| {},
        )?;
        let deadline = u64::try_from(submit.envelope.created_at + 5)? * 1000;
        let (sender, sender_frames) = sink();
        let pending = {
            let context = context.clone();
            let runtime = runtime.clone();
            tokio::spawn(async move {
                crate::ephemeral::handle_submit(&sender, &context, &runtime, &submit).await
            })
        };
        crate::ephemeral::tests::guard_10s(
            "local submit reached C4 after real router Online",
            entered.notified(),
        )
        .await;
        let (replacement_send, replacement_frames) = sink();
        let token = if replacement {
            context
                .hub
                .register(TARGET.into(), "legacy-replacement".into(), replacement_send)
                .await?
                .token
        } else {
            context.hub.set_queue_clock(TARGET, deadline).await;
            registration.token
        };
        release.add_permits(1);
        crate::ephemeral::tests::guard_10s("local submit result", pending).await??;
        {
            let frames = sender_frames.lock().map_err(|_| anyhow::anyhow!("sender frames"))?;
            assert_eq!(frames.len(), 1);
            assert_eq!(
                frames[0]["reason"],
                if replacement { "recipient_unsupported" } else { "expired" },
                "local C4 must return the exact final refusal"
            );
        }
        assert!(
            recipient_frames.lock().map_err(|_| anyhow::anyhow!("recipient frames"))?.is_empty(),
            "replaced/expired recipient must receive no bytes"
        );
        assert!(
            replacement_frames
                .lock()
                .map_err(|_| anyhow::anyhow!("replacement frames"))?
                .is_empty(),
            "legacy replacement must receive no bytes"
        );
        context.hub.unregister(TARGET, token).await;
    }
    Ok(())
}

struct CrossGateway {
    child: Child,
    context: GatewayQuicContext,
    destination: GatewayQuicContext,
    remote: std::sync::Arc<crate::GatewaySessionHub>,
}

async fn cross_gateway_setup() -> anyhow::Result<CrossGateway> {
    let seed = RouterCore::new();
    register_source(&seed)?;
    let (mut child, mut context) = real_router_with_state(Some(&seed)).await?;
    let pair = crate::serve::forward_identity_tests::ephemeral_pair_for_node("node-test")
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let roots = child.1.join("roots.pem");
    std::fs::write(&roots, format!("{}\n{}", std::fs::read_to_string(&roots)?, pair.ca_pem))?;
    child.0.kill()?;
    child.0.wait()?;
    restart(&mut child, &context).await?;
    context.node_id = "node-test".into();
    context.gateway_id = "gw-a".into();
    context.router.tls = pair.peers.tls().clone();
    context.router.async_mesh.as_mut().ok_or_else(|| anyhow::anyhow!("async mesh"))?.tls =
        pair.peers.tls().clone();
    context.peers = pair.peers;
    let remote = pair.hub;
    let mut destination = context.clone();
    destination.gateway_id = "gw-b".into();
    destination.router.tls = pair.receiver_tls.clone();
    destination.router.async_mesh.as_mut().ok_or_else(|| anyhow::anyhow!("async mesh"))?.tls =
        pair.receiver_tls;
    // These two instances share a process only in this fixture. Give their global mesh
    // connection pools separate trust keys, as independent gateway processes would have.
    destination
        .router
        .async_mesh
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("async mesh"))?
        .peer_ca_pems
        .push(pair.ca_pem.clone());
    remote.probe_started.store(true, std::sync::atomic::Ordering::Release);
    destination.hub = remote.clone();
    destination.state =
        std::sync::Arc::new(std::sync::Mutex::new(ramflux_node_core::GatewayState::new()));
    destination.store = std::sync::Arc::new(ramflux_node_core::GatewayRedbStore::open(
        child.1.join("gateway-b.redb"),
    )?);
    ready(&context).await?;
    ready(&destination).await?;
    Ok(CrossGateway { child, context, destination, remote })
}

async fn calibrate_cross_gateway_wake(
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
) -> TestResult {
    // The notifier belongs to the originating submit caller; exercise that caller's durable branch.
    let (reply, _) = sink();
    let mut durable = crate::session::submit_fixtures::signed_submit(
        runtime,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    )?;
    durable.envelope.envelope_id = "cross-gateway-durable-control".into();
    durable.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&durable.envelope)?,
        [4; 32],
    );
    durable.signed_request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(&durable.envelope)?,
    );
    durable.signed_request.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(&durable.signed_request)?,
        [4; 32],
    );
    let wakes = context.notify.wake_count();
    crate::session::handle_gateway_submit(&reply, context, runtime, &durable).await?;
    assert_eq!(
        context.notify.wake_count(),
        wakes + 1,
        "same forwarding caller must wake for durable offline control"
    );
    Ok(())
}

async fn cross_gateway_full(
    context: &GatewayQuicContext,
    runtime: &crate::GatewaySessionRuntime,
    remote: &crate::GatewaySessionHub,
    caps: &[String],
) -> TestResult {
    use ramflux_protocol::ephemeral::EphemeralDropReason as Reason;
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let queue = remote
        .snapshot()
        .await
        .get(TARGET)
        .ok_or_else(|| anyhow::anyhow!("remote queue"))?
        .queue
        .clone();
    queue.park_next_write(entered.clone(), release.clone());
    for n in 0..9 {
        let submit = crate::ephemeral::handler_tests::submit(
            runtime,
            &format!("cross-full-{n}"),
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
                EphemeralSendOutcome::Dropped(Reason::QueueFull)
            }
        );
        if n == 0 {
            crate::ephemeral::tests::guard_10s("cross-gateway writer parked", entered.notified())
                .await;
        }
    }
    release.add_permits(1);
    remote.flushed(TARGET).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a separately built same-tree router binary on QA"]
async fn ephemeral_submit_originates_authenticated_cross_gateway_outcomes() -> TestResult {
    use ramflux_protocol::ephemeral::EphemeralDropReason as Reason;
    let CrossGateway { child: _child, context, destination, remote } =
        cross_gateway_setup().await?;
    let recipient = recipient(&destination);
    let binding = negotiate(&destination, &auth_claiming_ephemeral(true)?, &recipient).await?;
    if std::env::var_os("RAMFLUX_EXPECT_EPHEMERAL_DORMANT").is_some() {
        assert!(!binding.ephemeral, "parent must not negotiate ephemeral");
        return Ok(());
    }
    let mut runtime = crate::session::submit_fixtures::test_runtime()?;
    runtime.ephemeral = binding.ephemeral;
    runtime.session_push = Some(bind_source(&context).await?);
    let caps = vec![
        ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into(),
        GATEWAY_EPHEMERAL_CAPABILITY.into(),
    ];
    calibrate_cross_gateway_wake(&context, &runtime).await?;
    let before_issued = issued(&context).await?;
    let before_gateway = serde_json::to_vec(&context.store.load_state()?)?;
    let wakes = context.notify.wake_count();
    let (recipient_send, frames) = sink();
    let registration = remote
        .register_ephemeral(
            TARGET.into(),
            "alice-session".into(),
            recipient_send,
            binding.incarnation_id.clone(),
            64,
        )
        .await?;
    assert_eq!(
        send(&context, &runtime, "cross-live", &caps)?.0,
        EphemeralSendOutcome::Delivered,
        "real submit must originate cross-gateway forwarding"
    );
    remote.flushed(TARGET).await?;
    assert_eq!(frames.lock().map_err(|_| anyhow::anyhow!("recipient frames"))?.len(), 1);
    let (legacy_send, legacy_frames) = sink();
    let legacy = remote.register(TARGET.into(), "legacy".into(), legacy_send).await?;
    let unsupported = send(&context, &runtime, "cross-unsupported", &caps)?;
    assert_eq!(unsupported.0, EphemeralSendOutcome::Unsupported);
    assert_eq!(
        unsupported.2.as_ref().and_then(|v| v["reason"].as_str()),
        Some("recipient_unsupported")
    );
    assert!(legacy_frames.lock().map_err(|_| anyhow::anyhow!("legacy frames"))?.is_empty());
    remote.unregister(TARGET, legacy.token).await;
    assert_eq!(
        send(&context, &runtime, "cross-offline", &caps)?.0,
        EphemeralSendOutcome::Dropped(Reason::Offline)
    );
    let (recipient_send, _) = sink();
    let registration2 = remote
        .register_ephemeral(
            TARGET.into(),
            "alice-session".into(),
            recipient_send,
            binding.incarnation_id.clone(),
            64,
        )
        .await?;
    remote.set_queue_clock(TARGET, u64::MAX).await;
    assert_eq!(
        send(&context, &runtime, "cross-expired", &caps)?.0,
        EphemeralSendOutcome::Dropped(Reason::Expired)
    );
    remote.set_queue_clock(TARGET, crate::ephemeral::now_ms()).await;
    cross_gateway_full(&context, &runtime, &remote, &caps).await?;
    remote.unregister(TARGET, registration2.token).await;
    remote.unregister(TARGET, registration.token).await;
    assert_eq!(
        issued(&context).await?,
        before_issued,
        "cross-gateway ephemeral must never fall back durably"
    );
    assert_eq!(serde_json::to_vec(&context.store.load_state()?)?, before_gateway);
    assert_eq!(
        context.notify.wake_count(),
        wakes,
        "originating forward path must never wake for ephemeral outcomes"
    );
    Ok(())
}
