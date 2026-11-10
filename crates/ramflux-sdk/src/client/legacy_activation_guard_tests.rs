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
    establishment: Mutex<Option<Vec<u8>>>,
}

impl TransportOpener for Scripted {
    fn open(&self, _config: GatewaySessionConfig, _timeout: Duration) -> OpenFuture<'_> {
        let establishment = self.establishment.lock().expect("script").take();
        Box::pin(async move {
            let gateway: Box<dyn ramflux_transport::GatewaySessionTransport + Send> =
                Box::new(Established { establishment });
            Ok((
                crate::gateway::engine::GatewaySessionClientTransport::Injected,
                gateway,
                crate::GatewaySessionTransportKind::Quic,
            ))
        })
    }
}

struct Established {
    establishment: Option<Vec<u8>>,
}

impl GatewaySessionFrameSink for Established {
    fn send_frame<'a>(&'a mut self, _: &'a [u8]) -> FrameFuture<'a, ()> {
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
    mut config: GatewaySessionConfig,
    established: Vec<u8>,
) -> Result<GatewaySessionEngine, SdkError> {
    config.custody = None;
    let opener: Arc<dyn TransportOpener> =
        Arc::new(Scripted { establishment: Mutex::new(Some(established)) });
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

/// Inactive accounts never advertise session-push, even when the preset is true.
#[tokio::test]
async fn inactive_account_never_advertises_session_push() -> TestResult {
    let fixture = Fixture::new("p24b2a-inactive-advertise").await?;
    assert_eq!(fixture.client.account_db()?.receive_activation()?, ReceiveActivation::Inactive);
    let mut config = fixture.config.clone().with_session_push_advertise(true);
    config.capability_scope.push(PUSH.to_owned());
    let account = LocalBusAccountState::disconnected(
        fixture.client,
        config.clone(),
        fixture.manifest.principal_commitment.clone(),
    );
    assert_session_push_scope(&account.connection_config()?, false);
    let engine = connect_scripted(&account.client, config, legacy_established()).await?;
    assert_session_push_scope(&engine.config, false);
    assert_eq!(engine.mode, SessionMode::Legacy);
    Ok(())
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
    let account_id = fixture.client.account_db()?.local_account_id.clone();
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
        crate::bus::push_receiver::executor::LedgerExecutor::bind_actor(account_id.clone())?;
    let Err(error) = crate::bus::sync_driver::receive(&mut account, &mut counting, 1).await else {
        panic!("standalone while actor bound");
    };
    assert!(
        matches!(
            error,
            SdkError::Storage(StorageError::AccountWriterBusy(ref id)) if *id == account_id
        ),
        "standalone must refuse while the actor owns the account: {error:?}"
    );
    assert_eq!(
        crate::bus::push_receiver::executor::LedgerExecutor::last_bound_owner(),
        Some(crate::bus::push_receiver::executor::ExecutorOwner::Actor)
    );
    Ok(())
}
