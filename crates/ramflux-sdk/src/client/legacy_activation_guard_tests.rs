// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Activated accounts refuse every legacy receive/ACK path before any wire effect.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::native_test_support::{Fixture, TestResult};
use crate::bus::state::LocalBusAccountState;
use crate::bus::sync_driver::source::w0::{
    prepare_receive_turn, refuse_legacy_receive_unless_ledger_turn,
};
use crate::gateway::access::CountingGateway;
use crate::gateway::session_push::{IncarnationId, SessionMode};
use crate::{GatewayInboxEntry, GatewaySessionEngine, SdkError};
use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
use ramflux_storage::{
    LEGACY_RECEIVE_ACTIVATED, ReceiveMigrate, ReceiveMigrateResult, StorageError,
};
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};

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
    match refuse_legacy_receive_unless_ledger_turn(&account, 1) {
        Ok(()) => panic!("legacy ApplyPage succeeded on an activated ledger"),
        Err(error) => assert_activated(&error),
    }
    match crate::bus::sync_driver::receive(&mut account, &mut engine, 1).await {
        Ok(_) => panic!("legacy bus receive succeeded on an activated ledger"),
        Err(error) => assert_activated(&error),
    }

    assert_eq!(engine.resumes, 0, "activated pull sent a resume");
    assert_eq!(engine.acks, 0, "activated ACK path sent a wire ACK");
    assert_eq!(account.client.gateway_cursor(&target)?, 9);
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
    refuse_legacy_receive_unless_ledger_turn(&account, 1)
        .expect("ledger ApplyPage (turn: Some) must not be refused");
    prepare_receive_turn(&account, 1, 1, crate::bus::connection_manager::ReceiveTrigger::Tick)
        .expect("ledger PrepareReceive (turn: Some) must not be refused");
    Ok(())
}
