// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Activated accounts refuse every legacy receive/ACK path before any wire effect.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::native_test_support::{Fixture, TestResult};
use crate::bus::state::LocalBusAccountState;
use crate::bus::sync_driver::source::w0::{
    actor_turn, prepare_receive_turn, refuse_legacy_receive_unless_ledger_turn,
};
use crate::gateway::access::CountingGateway;
use crate::gateway::engine::TEST_CONNECT_OPENER;
use crate::gateway::session_push::{IncarnationId, SessionMode};
use crate::gateway::transport_opener::{OpenFuture, TransportOpener};
use crate::{
    GatewayInboxEntry, GatewaySessionConfig, GatewaySessionEngine, RamfluxClient, SdkError,
};
use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
use ramflux_storage::{
    LEGACY_RECEIVE_ACTIVATED, ReceiveActivation, ReceiveMigrate, ReceiveMigrateResult, StorageError,
};
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PUSH: &str = ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY;
const INCARNATION: &str = "0123456789abcdef0123456789abcdef";

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;

struct NoNetwork;
impl GatewaySessionFrameSink for NoNetwork {
    fn send_frame<'a>(&'a mut self, _: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async { Err(TransportError::Quic("legacy-guard test I/O".into())) })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for NoNetwork {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(async { Err(TransportError::Quic("legacy-guard test I/O".into())) })
    }
}

fn push_engine(config: crate::GatewaySessionConfig) -> GatewaySessionEngine {
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(NoNetwork));
    engine.mode = SessionMode::Push {
        incarnation: IncarnationId::try_from("0123456789abcdef0123456789abcdef".to_owned())
            .expect("incarnation"),
    };
    engine
}

fn legacy_engine(config: crate::GatewaySessionConfig) -> GatewaySessionEngine {
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(NoNetwork));
    engine.mode = SessionMode::Legacy;
    engine
}

fn assert_activated(error: &SdkError) {
    assert!(
        matches!(error, SdkError::Storage(StorageError::Integrity(LEGACY_RECEIVE_ACTIVATED))),
        "{error:?}"
    );
}

fn assert_session_push_scope(config: &GatewaySessionConfig, advertise: bool) {
    assert_eq!(config.session_push_advertise, advertise, "session_push_advertise={advertise}");
    let scope = crate::gateway::signed_capability_scope(config);
    assert_eq!(
        scope.iter().any(|capability| capability == PUSH),
        advertise,
        "signed scope session-push: {scope:?}"
    );
}

fn established_session() -> ramflux_node_core::GatewaySessionEstablishedFrame {
    ramflux_node_core::GatewaySessionEstablishedFrame {
        session_id: "p24b2a-session".into(),
        gateway_id: "p24b2a-gateway".into(),
        accepted_cursor: None,
        resume_token: "p24b2a-token".into(),
        resume_window_seconds: 60,
    }
}

fn legacy_established() -> Vec<u8> {
    serde_json::to_vec(&ramflux_node_core::GatewayServerFrame::SessionEstablished {
        session: established_session(),
    })
    .expect("legacy established")
}

fn push_established() -> Vec<u8> {
    serde_json::to_vec(&ramflux_node_core::SessionPushServerFrame::SessionEstablished {
        session: ramflux_node_core::SessionPushEstablishedFrame {
            session: established_session(),
            capabilities: vec![PUSH.into()],
            inbox_incarnation_id: INCARNATION.into(),
        },
    })
    .expect("push established")
}

struct Scripted {
    settled: u64,
    establishment: Mutex<Option<Vec<u8>>>,
}

impl TransportOpener for Scripted {
    fn open(&self, _config: GatewaySessionConfig, _timeout: Duration) -> OpenFuture<'_> {
        let establishment = self.establishment.lock().expect("script").take();
        Box::pin(async move {
            let gateway: Box<dyn ramflux_transport::GatewaySessionTransport + Send> =
                Box::new(Established { establishment, settled: self.settled });
            Ok((
                crate::gateway::engine::GatewaySessionClientTransport::Injected,
                gateway,
                crate::GatewaySessionTransportKind::Quic,
            ))
        })
    }
}

struct Established {
    settled: u64,
    establishment: Option<Vec<u8>>,
}

impl GatewaySessionFrameSink for Established {
    fn send_frame<'a>(&'a mut self, bytes: &'a [u8]) -> FrameFuture<'a, ()> {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes)
            && value["frame_type"] == "resume"
        {
            self.establishment = Some(serde_json::to_vec(&serde_json::json!({
                "frame_type": "resume_page", "target_delivery_id": value["resume"]["target_delivery_id"],
                "incarnation_id": INCARNATION, "after_inbox_seq": 0,
                "covered_through_seq": self.settled, "issued_inbox_seq": self.settled, "settled_through_seq": self.settled,
                "entries": [], "known_losses": [], "oversize_next": null, "more": false,
            })).expect("first page"));
        }
        Box::pin(async { Ok(()) })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for Established {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        let frame = self.establishment.take();
        Box::pin(async move {
            if let Some(frame) = frame { Ok(frame) } else { std::future::pending().await }
        })
    }
}

async fn connect_scripted(
    client: &RamfluxClient,
    config: GatewaySessionConfig,
    established: Vec<u8>,
) -> Result<GatewaySessionEngine, SdkError> {
    connect_scripted_settled(client, config, established, 0).await
}

async fn connect_scripted_settled(
    client: &RamfluxClient,
    mut config: GatewaySessionConfig,
    established: Vec<u8>,
    settled: u64,
) -> Result<GatewaySessionEngine, SdkError> {
    config.custody = None;
    let opener: Arc<dyn TransportOpener> =
        Arc::new(Scripted { settled, establishment: Mutex::new(Some(established)) });
    TEST_CONNECT_OPENER.scope(opener, client.connect_gateway_session(config)).await
}

fn entry(target: &str) -> GatewayInboxEntry {
    GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: target.to_owned(),
        envelope: Envelope {
            schema: "ramflux.envelope.v1".into(),
            version: 1,
            domain: "test".into(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "key".into(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "sig".into(),
            },
            envelope_id: "env".into(),
            source_principal_id: "source".into(),
            source_device_id: "device".into(),
            target_delivery_id: target.to_owned(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Normal,
            ttl: 60,
            created_at: 1,
            encrypted_payload: "cipher".into(),
            payload_hash: "hash".into(),
            delivery_mode: None,
            collapse_tag: None,
            report_commitment: None,
        },
    }
}

#[tokio::test]
async fn activated_ledger_refuses_legacy_receive_and_ack_paths() -> TestResult {
    let mut fixture = Fixture::new("p24b1-m1").await?;
    let target = fixture.config.target_delivery_id.clone();
    fixture.client.persist_gateway_cursor(&target, 9)?;
    assert_eq!(
        fixture
            .client
            .account_db()?
            .activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: "e" })?,
        ReceiveMigrateResult::Migrated
    );
    let mut engine = CountingGateway::new(fixture.config.clone());

    let cursor = fixture.client.persist_gateway_receive_cursor(&target, 2);
    assert_activated(cursor.as_ref().expect_err("legacy C write"));
    let seq = fixture.client.persist_gateway_cursor(&target, 10);
    assert_activated(seq.as_ref().expect_err("legacy gateway_cursor write"));

    let pull = fixture.client.receive_gateway_deliveries(&mut engine, 8).await;
    assert_activated(pull.as_ref().expect_err("legacy pull"));
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()
            .map_err(|error| SdkError::LocalBus(error.to_string()))?,
    );
    let plaintext = fixture
        .client
        .receive_gateway_plaintext_deliveries(&mut engine, &pool, 8, "conv", false, None)
        .await;
    assert_activated(plaintext.as_ref().expect_err("legacy plaintext pull"));

    let inbox = entry(&target);
    let ack_entry = fixture.client.ack_gateway_entry(&mut engine, &inbox, 1).await;
    assert_activated(ack_entry.as_ref().expect_err("legacy ack_gateway_entry"));
    let receiver = fixture.client.owned_device_identity()?;
    let ack_delivery = fixture.client.ack_gateway_delivery(&mut engine, "env", &receiver, 1).await;
    assert_activated(ack_delivery.as_ref().expect_err("legacy ack_gateway_delivery"));

    let a2i = fixture.client.receive_a2i_control_events(&mut engine, 8).await;
    assert_activated(a2i.as_ref().expect_err("legacy a2i"));

    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        fixture.manifest.principal_commitment.clone(),
    );
    match prepare_receive_turn(&account, 1, 1, crate::bus::connection_manager::ReceiveTrigger::Tick)
    {
        Ok(_) => panic!("legacy PrepareReceive succeeded on an activated ledger"),
        Err(error) => assert_activated(&error),
    }
    let turn = actor_turn(&account, 1)?;
    match refuse_legacy_receive_unless_ledger_turn(&account, turn.as_ref()) {
        Ok(()) => panic!("legacy ApplyPage succeeded on an activated ledger"),
        Err(error) => assert_activated(&error),
    }
    engine.page_losses.push(crate::gateway::session_push::KnownLoss {
        from_seq: 1,
        to_seq: 1,
        reason: crate::gateway::session_push::PageReason::Expired,
    });
    crate::bus::sync_driver::receive(&mut account, &mut engine, 1).await?;
    assert_eq!(
        crate::bus::push_receiver::executor::LedgerExecutor::last_bound_owner(),
        Some(crate::bus::push_receiver::executor::ExecutorOwner::Standalone),
        "standalone receive binds the exclusive standalone executor"
    );

    assert!(engine.resumes >= 1, "activated standalone catch-up sent a resume_page");
    assert_eq!(engine.acks, 0, "activated ACK path sent a wire ACK");
    assert_eq!(account.client.gateway_cursor(&target)?, 9);
    assert_eq!(
        account.client.account_db()?.receive_ledger_snap_for_test(&target)?.cursor,
        1,
        "standalone loss page covers C"
    );
    Ok(())
}

#[tokio::test]
async fn activated_ledger_prepare_receive_and_apply_page_are_not_refused() -> TestResult {
    let fixture = Fixture::new("p24b1-ledger-turn").await?;
    let target = fixture.config.target_delivery_id.clone();
    fixture.client.persist_gateway_cursor(&target, 9)?;
    assert_eq!(
        fixture
            .client
            .account_db()?
            .activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: "e" })?,
        ReceiveMigrateResult::Migrated
    );
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        fixture.manifest.principal_commitment.clone(),
    );
    account.install_test_session(push_engine(fixture.config.clone()));
    let turn = actor_turn(&account, 1)?;
    assert!(turn.is_some(), "activated Push session must yield a ledger turn");
    refuse_legacy_receive_unless_ledger_turn(&account, turn.as_ref())
        .expect("ledger ApplyPage (turn: Some) must not be refused");
    prepare_receive_turn(&account, 1, 1, crate::bus::connection_manager::ReceiveTrigger::Tick)
        .expect("ledger PrepareReceive (turn: Some) must not be refused");
    Ok(())
}

/// Inactive accounts advertise session-push only when first-activation is on, so handshake
/// can supply the verified node incarnation before ledger phases.
#[tokio::test]
async fn inactive_account_never_advertises_session_push() -> TestResult {
    let fixture = Fixture::new("p24b2a-inactive-advertise").await?;
    assert_eq!(fixture.client.account_db()?.receive_activation()?, ReceiveActivation::Inactive);
    let mut config = fixture.config.clone().with_session_push_advertise(true);
    config.capability_scope.push(PUSH.to_owned());
    crate::gateway::apply_session_push_advertise(&mut config, ReceiveActivation::Inactive);
    assert_session_push_scope(&config, ramflux_storage::FIRST_ACTIVATION_DEFAULT);
    Ok(())
}

/// New accounts first-activate in managed push, compat, and standalone; advertise only
/// after the discriminator is Activated. The default-off predecessor explicitly activates
/// the same ledger to keep the recovery fixtures executable.
#[tokio::test]
async fn default_activation_both_modes() -> TestResult {
    let fixture = Fixture::new("p25-default-activation").await?;
    assert_eq!(fixture.client.account_db()?.receive_activation()?, ReceiveActivation::Inactive);
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        fixture.manifest.principal_commitment.clone(),
    );
    let advertised = account.connection_config()?;
    assert_eq!(
        account.client.account_db()?.receive_activation()?,
        ReceiveActivation::Inactive,
        "advertise-before-handshake must not bind a local incarnation"
    );
    assert_session_push_scope(&advertised, ramflux_storage::FIRST_ACTIVATION_DEFAULT);
    if !ramflux_storage::FIRST_ACTIVATION_DEFAULT {
        let _ = account.client.account_db()?.activate_receive_ledger(ReceiveMigrate {
            target: &account.target_delivery_id,
            incarnation: INCARNATION,
        })?;
    }
    let advertised = account.connection_config()?;

    let push = connect_scripted(&account.client, advertised.clone(), push_established()).await?;
    assert_eq!(
        push.mode,
        SessionMode::Push { incarnation: IncarnationId::try_from(INCARNATION.to_owned())? }
    );
    assert_eq!(account.client.account_db()?.receive_activation()?, ReceiveActivation::Activated);
    let epoch = account
        .client
        .account_db()?
        .receive_epoch(&account.target_delivery_id)?
        .ok_or("first-activation writes an epoch")?;
    assert_eq!(epoch, INCARNATION, "direct migration binds the verified node incarnation");

    let compat =
        connect_scripted(&account.client, advertised.clone(), legacy_established()).await?;
    assert_eq!(compat.mode, SessionMode::Compat);
    account.install_test_session(legacy_engine(advertised.clone()));
    let turn = actor_turn(&account, 1)?;
    assert!(
        turn.as_ref().is_some_and(|turn| turn.compat),
        "activated Legacy session is a compat ledger turn"
    );
    refuse_legacy_receive_unless_ledger_turn(&account, turn.as_ref())
        .expect("compat ApplyPage (turn: Some) must not be refused");
    prepare_receive_turn(&account, 1, 1, crate::bus::connection_manager::ReceiveTrigger::Tick)
        .expect("compat PrepareReceive (turn: Some) must not be refused");

    account.engine = None;
    let mut counting = CountingGateway::new(advertised);
    counting.page_losses.push(crate::gateway::session_push::KnownLoss {
        from_seq: 1,
        to_seq: 1,
        reason: crate::gateway::session_push::PageReason::Expired,
    });
    crate::bus::sync_driver::receive(&mut account, &mut counting, 1).await?;
    assert_eq!(
        crate::bus::push_receiver::executor::LedgerExecutor::last_bound_owner(),
        Some(crate::bus::push_receiver::executor::ExecutorOwner::Standalone)
    );
    assert!(counting.resumes >= 1, "standalone row issues resume_page");
    Ok(())
}

/// Fresh default-on Push activation preserves the gateway's independently negotiated
/// incarnation through `intake::stage_on_actor`. Binding a local random E fails this row.
#[tokio::test]
async fn fresh_push_activation_binds_gateway_incarnation() -> TestResult {
    let fixture = Fixture::new("p25-h1-gateway-e").await?;
    let target = fixture.config.target_delivery_id.clone();
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        fixture.manifest.principal_commitment.clone(),
    );
    let advertised = account.connection_config()?;
    assert_eq!(account.client.account_db()?.receive_activation()?, ReceiveActivation::Inactive);
    assert_session_push_scope(&advertised, ramflux_storage::FIRST_ACTIVATION_DEFAULT);
    if !ramflux_storage::FIRST_ACTIVATION_DEFAULT {
        let _ = account.client.account_db()?.activate_receive_ledger(ReceiveMigrate {
            target: &target,
            incarnation: INCARNATION,
        })?;
    }
    let push =
        connect_scripted(&account.client, account.connection_config()?, push_established()).await?;
    assert_eq!(
        push.mode,
        SessionMode::Push { incarnation: IncarnationId::try_from(INCARNATION.to_owned())? }
    );
    assert_eq!(account.client.account_db()?.receive_epoch(&target)?.as_deref(), Some(INCARNATION));
    account.install_test_session(push);
    let turn = actor_turn(&account, 1)?.ok_or("push turn")?;
    assert_eq!(turn.incarnation, INCARNATION);
    match crate::bus::push_receiver::intake::stage_on_actor(
        &account,
        1,
        &entry(&target),
        INCARNATION,
        1_700_000_000,
    ) {
        Ok(_) => Ok(()),
        Err(SdkError::Storage(StorageError::AuthorizationRejected)) => {
            Err("fresh Push activation rejected the gateway incarnation".into())
        }
        Err(error) => Err(error.into()),
    }
}

/// Activated DB negotiates Push and never reaches a legacy receive writer.
#[tokio::test]
async fn activation_revert_preserves_ledger() -> TestResult {
    let fixture = Fixture::new("p24b2a-advertise").await?;
    let target = fixture.config.target_delivery_id.clone();
    assert_eq!(
        fixture
            .client
            .account_db()?
            .activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: "e" })?,
        ReceiveMigrateResult::Migrated
    );
    let mut config = fixture.config.clone();
    crate::gateway::apply_session_push_advertise(
        &mut config,
        fixture.client.account_db()?.receive_activation()?,
    );
    assert_session_push_scope(&config, true);

    let cursor = fixture.client.persist_gateway_receive_cursor(&target, 2);
    assert_activated(cursor.as_ref().expect_err("legacy C write"));

    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        fixture.manifest.principal_commitment.clone(),
    );
    let advertised = account.connection_config()?;
    assert_session_push_scope(&advertised, true);
    let engine = connect_scripted(&account.client, advertised.clone(), push_established()).await?;
    assert_eq!(
        engine.mode,
        SessionMode::Push { incarnation: IncarnationId::try_from(INCARNATION.to_owned())? }
    );
    match prepare_receive_turn(&account, 1, 1, crate::bus::connection_manager::ReceiveTrigger::Tick)
    {
        Ok(_) => panic!("legacy PrepareReceive succeeded on an activated ledger"),
        Err(error) => assert_activated(&error),
    }
    let turn = actor_turn(&account, 1)?;
    assert!(turn.is_none(), "activated without a Push engine is not a ledger turn");
    match refuse_legacy_receive_unless_ledger_turn(&account, turn.as_ref()) {
        Ok(()) => panic!("legacy ApplyPage succeeded on an activated ledger"),
        Err(error) => assert_activated(&error),
    }
    account.install_test_session(legacy_engine(advertised.clone()));
    let turn = actor_turn(&account, 1)?;
    assert!(
        turn.as_ref().is_some_and(|turn| turn.compat),
        "activated Legacy session must yield a compat ledger turn"
    );
    refuse_legacy_receive_unless_ledger_turn(&account, turn.as_ref())
        .expect("compat ApplyPage (turn: Some) must not be refused");
    prepare_receive_turn(&account, 1, 1, crate::bus::connection_manager::ReceiveTrigger::Tick)
        .expect("compat PrepareReceive (turn: Some) must not be refused");
    account.engine = None;
    let mut counting = crate::gateway::access::CountingGateway::new(advertised);
    counting.page_losses.push(crate::gateway::session_push::KnownLoss {
        from_seq: 1,
        to_seq: 1,
        reason: crate::gateway::session_push::PageReason::Expired,
    });
    crate::bus::sync_driver::receive(&mut account, &mut counting, 1).await?;
    assert_eq!(
        crate::bus::push_receiver::executor::LedgerExecutor::last_bound_owner(),
        Some(crate::bus::push_receiver::executor::ExecutorOwner::Standalone)
    );
    assert!(counting.resumes >= 1, "standalone row issues resume_page");
    assert_eq!(
        account.client.account_db()?.receive_ledger_snap_for_test(&target)?.cursor,
        1,
        "standalone loss page covers C"
    );
    Ok(())
}

#[tokio::test]
async fn standalone_receive_refuses_while_actor_bound() -> TestResult {
    let fixture = Fixture::new("p24b2c-d5-busy").await?;
    let target = fixture.config.target_delivery_id.clone();
    assert_eq!(
        fixture
            .client
            .account_db()?
            .activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: "e" })?,
        ReceiveMigrateResult::Migrated
    );
    let account_key = {
        let db = fixture.client.account_db()?;
        format!("{}:{}", db.path.display(), db.local_account_id)
    };
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        fixture.manifest.principal_commitment.clone(),
    );
    let mut counting = CountingGateway::new(fixture.config.clone());
    counting.page_losses.push(crate::gateway::session_push::KnownLoss {
        from_seq: 1,
        to_seq: 1,
        reason: crate::gateway::session_push::PageReason::Expired,
    });
    let _actor =
        crate::bus::push_receiver::executor::LedgerExecutor::bind_actor(account_key.clone())?;
    let Err(error) = crate::bus::sync_driver::receive(&mut account, &mut counting, 1).await else {
        panic!("standalone while actor bound");
    };
    assert!(
        matches!(
            error,
            SdkError::Storage(StorageError::AccountWriterBusy(ref id)) if *id == account_key
        ),
        "standalone must refuse while the actor owns the account: {error:?}"
    );
    assert_eq!(
        crate::bus::push_receiver::executor::LedgerExecutor::last_bound_owner(),
        Some(crate::bus::push_receiver::executor::ExecutorOwner::Actor)
    );
    Ok(())
}

/// Compat cursor/work/intents survive a Push bind through the fenced reset rules.
#[tokio::test]
async fn compat_then_push_keeps_receive_live() -> TestResult {
    use ramflux_storage::ReceiveExpectation;
    let fixture = Fixture::new("compat-then-push").await?;
    let target = fixture.config.target_delivery_id.clone();
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        fixture.manifest.principal_commitment.clone(),
    );
    let compat =
        connect_scripted(&account.client, account.connection_config()?, legacy_established())
            .await?;
    // Explicit activation also exercises this row on the default-off predecessor.
    if account.client.account_db()?.receive_activation()? == ReceiveActivation::Inactive {
        let _ = account.client.account_db()?.activate_receive_ledger(ReceiveMigrate {
            target: &target,
            incarnation: "local-compat",
        })?;
    }
    account.install_test_session(compat);
    let old = account.client.account_db()?.receive_epoch(&target)?.ok_or("old epoch")?;
    let db = account.client.account_db()?;
    let erasure = db.privacy_erasure_generation()?;
    seed_compat_pending(&account, &target, &old)?;
    let push = connect_scripted_settled(
        &account.client,
        account.connection_config()?,
        push_established(),
        2,
    )
    .await?;
    assert_eq!(account.client.account_db()?.receive_epoch(&target)?.as_deref(), Some(INCARNATION));
    assert_eq!(
        account.client.gateway_receive_cursor(&target)?,
        2,
        "first-page settled prefix owns C"
    );
    account.install_test_session(push);
    let db = account.client.account_db()?;
    let snap = db.receive_ledger_snap_for_test(&target)?;
    assert!(snap.intents.is_empty(), "old ACK intents cannot cross epochs");
    assert_eq!(snap.work, 1, "held old work remains available for local recovery");
    assert_eq!(db.receive_state_for_test(1)?.0, None, "terminal Compat work is released");
    let mut next = entry(&target);
    next.inbox_seq = 3;
    next.envelope.envelope_id = "next-env".into();
    let _ = crate::bus::push_receiver::intake::stage_on_actor(
        &account,
        1,
        &next,
        INCARNATION,
        1_700_000_000,
    )?;
    assert!(
        crate::bus::push_receiver::intake::stage_on_actor(&account, 1, &next, &old, 1_700_000_000)
            .is_err(),
        "old E cannot accept new intake"
    );
    assert!(
        db.receive_transaction(
            ReceiveExpectation {
                target: &target,
                incarnation: &old,
                cursor: 2,
                generation: 1,
                erasure_generation: erasure
            },
            1,
            |tx| tx.require_open_input(2)
        )
        .is_ok(),
        "retired E permits local recovery"
    );
    Ok(())
}

fn seed_compat_pending(account: &LocalBusAccountState, target: &str, old: &str) -> TestResult {
    use ramflux_storage::{ReceiveCover, ReceiveCoverKind, ReceiveExpectation};
    let db = account.client.account_db()?;
    let erasure = db.privacy_erasure_generation()?;
    let _ = crate::bus::push_receiver::intake::stage_on_actor(
        account,
        1,
        &entry(target),
        old,
        1_900_000_000,
    )?;
    let mut held = entry(target);
    held.inbox_seq = 2;
    held.envelope.envelope_id = "held-env".into();
    db.seed_held_receive_for_test(target, old, 2, &serde_json::to_vec(&held)?)?;
    db.receive_transaction(
        ReceiveExpectation {
            target,
            incarnation: old,
            cursor: 0,
            generation: 1,
            erasure_generation: erasure,
        },
        1,
        |tx| {
            let _ = tx.cover(ReceiveCover {
                sequence: 1,
                kind: ReceiveCoverKind::CompatTerminal,
                gaps: &[],
                retain_until: 1_900_000_000,
            })?;
            Ok(())
        },
    )?;
    assert_eq!(account.client.gateway_receive_cursor(target)?, 1);
    assert_eq!(db.receive_ledger_snap_for_test(target)?.intents, vec![1]);
    Ok(())
}

#[tokio::test]
async fn receive_epoch_reconcile_reports_typed_fences() -> TestResult {
    let fixture = Fixture::new("receive-epoch-typed-fences").await?;
    let client = &fixture.client;
    let target = &fixture.config.target_delivery_id;
    let _ = client
        .account_db()?
        .activate_receive_ledger(ReceiveMigrate { target, incarnation: "old" })?;
    let page = crate::gateway::push_resume::ResumePage {
        after_inbox_seq: 0,
        covered_through_seq: 0,
        issued_inbox_seq: 0,
        settled_through_seq: 0,
        entries: Vec::new(),
        known_losses: Vec::new(),
        oversize_next: None,
        more: false,
    };
    for i in 1..=ramflux_storage::RETIRED_FENCE_CAP {
        let next = format!("{i:032x}");
        let turn = client.prepare_receive_epoch(target, &next, 1)?.ok_or("reset turn")?;
        client.reset_receive_epoch(&turn, &next, &page, 1)?;
    }
    let next = "ffffffffffffffffffffffffffffffff";
    let turn = client.prepare_receive_epoch(target, next, 1)?.ok_or("fenced turn")?;
    let old = client.account_db()?.receive_epoch(target)?;
    assert!(
        matches!(
            client.reset_receive_epoch(&turn, next, &page, 2),
            Err(SdkError::ReceiveEpochReconcile(crate::ReceiveEpochReconcileFailure::StaleFence))
        ),
        "stale generation has a typed diagnostic"
    );
    assert!(
        matches!(
            client.reset_receive_epoch(&turn, next, &page, 1),
            Err(SdkError::ReceiveEpochReconcile(crate::ReceiveEpochReconcileFailure::PausedFence))
        ),
        "full retired fence has a typed diagnostic"
    );
    assert_eq!(client.account_db()?.receive_epoch(target)?, old, "refusals preserve E");
    assert_eq!(client.gateway_receive_cursor(target)?, 0);
    Ok(())
}
