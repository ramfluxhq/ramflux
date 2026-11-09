// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Activated-ledger refusals for the legacy ACK stage/finish path (S6b P24b1).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::ack::{AckState, finish, stage};
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::state::LocalBusAccountState;
use crate::client::native_test_support::Fixture;
use crate::gateway::access::{CountingGateway, GatewaySessionAccess};
use crate::{GatewayCursor, GatewayInboxEntry, SdkError};
use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
use ramflux_storage::{
    LEGACY_RECEIVE_ACTIVATED, ReceiveMigrate, ReceiveMigrateResult, StorageError,
};

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

fn state(target: &str) -> AckState {
    AckState {
        entry: entry(target),
        key: "k".into(),
        already_seen: true,
        strip_call_ciphertext: false,
        accepted: true,
        received_at: 1,
    }
}

#[tokio::test]
async fn activated_ledger_refuses_ack_stage_before_wire() {
    let fixture = Fixture::new("p24b1-ack-stage").await.expect("fixture");
    let target = fixture.config.target_delivery_id.clone();
    fixture.client.persist_gateway_cursor(&target, 9).expect("seed cursor");
    assert_eq!(
        fixture
            .client
            .account_db()
            .expect("db")
            .activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: "e" })
            .expect("activate"),
        ReceiveMigrateResult::Migrated
    );
    let mut engine = CountingGateway::new(fixture.config.clone());
    let account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        "principal".into(),
    );
    match stage(&account, state(&target)) {
        Ok(prepared) => {
            let _ = engine.ack(prepared.ack).await;
            panic!("legacy ACK stage succeeded on an activated ledger; acks={}", engine.acks);
        }
        Err(error) => assert!(
            matches!(error, SdkError::Storage(StorageError::Integrity(LEGACY_RECEIVE_ACTIVATED))),
            "{error:?}"
        ),
    }
    assert_eq!(engine.acks, 0, "activated ACK path sent a wire ACK");
    assert_eq!(account.client.gateway_cursor(&target).expect("cursor"), 9);
}

#[tokio::test]
async fn activated_ledger_refuses_ack_finish_before_gateway_cursor() {
    let fixture = Fixture::new("p24b1-ack-finish").await.expect("fixture");
    let target = fixture.config.target_delivery_id.clone();
    fixture.client.persist_gateway_cursor(&target, 9).expect("seed cursor");
    assert_eq!(
        fixture
            .client
            .account_db()
            .expect("db")
            .activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: "e" })
            .expect("activate"),
        ReceiveMigrateResult::Migrated
    );
    let account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config.clone(),
        "principal".into(),
    );
    let mut backpressure = Backpressure::load(&account.client, 1).expect("backpressure");
    let cursor = Ok(GatewayCursor {
        target_delivery_id: target.clone(),
        inbox_seq: 11,
        last_envelope_id: None,
        acked_envelope_ids: Vec::new(),
        nacked_envelope_ids: std::collections::BTreeMap::new(),
    });
    let error = finish(&account, &state(&target), cursor, &mut backpressure)
        .expect_err("finish must refuse");
    assert!(
        matches!(error, SdkError::Storage(StorageError::Integrity(LEGACY_RECEIVE_ACTIVATED))),
        "{error:?}"
    );
    assert_eq!(account.client.gateway_cursor(&target).expect("cursor"), 9);
}
