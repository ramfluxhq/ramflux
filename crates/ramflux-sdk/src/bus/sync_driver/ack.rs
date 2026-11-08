// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Inbox ACK transport follows the local commit and returns only local cursor checkpoints.

use super::{advance_cursor, retain_ack_retry};
use crate::prelude::*;

pub(crate) struct AckState {
    pub(crate) entry: GatewayInboxEntry,
    pub(crate) key: String,
    pub(crate) already_seen: bool,
    pub(crate) strip_call_ciphertext: bool,
    pub(crate) accepted: bool,
    pub(crate) received_at: i64,
}
pub(crate) struct PreparedAck {
    pub ack: ramflux_protocol::Ack,
    pub state: AckState,
    pub pair_reply: Option<ramflux_protocol::Envelope>,
}
pub(super) fn stage(
    account: &LocalBusAccountState,
    state: AckState,
) -> Result<PreparedAck, SdkError> {
    account.client.account_db()?.refuse_legacy_receive()?;
    let receiver = account.client.owned_device_identity()?;
    if account.gateway_config.source_identity.as_ref() != Some(&receiver)
        || state.entry.target_delivery_id != account.target_delivery_id
    {
        return Err(SdkError::InboundRejected("ACK mailbox identity mismatch".into()));
    }
    // Retain before yielding so an erasure during the exchange can remove the retry.
    // A late transport failure must never recreate that deleted retry row.
    if !state.already_seen || account.client.account_db()?.has_inbox_retry(&state.key)? {
        retain_ack_retry(
            &account.client,
            &state.entry,
            state.strip_call_ciphertext,
            &state.key,
            state.received_at,
        )?;
    }
    let mut ack =
        crate::dm::gateway_ack(&state.entry.envelope.envelope_id, &receiver, state.received_at);
    ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(state.entry.inbox_seq));
    Ok(PreparedAck { ack, state, pair_reply: None })
}
pub(crate) fn finish(
    account: &LocalBusAccountState,
    state: &AckState,
    cursor: Result<GatewayCursor, SdkError>,
    backpressure: &mut super::super::contact_backpressure::Backpressure,
) -> Result<bool, SdkError> {
    account.client.account_db()?.refuse_legacy_receive()?;
    let db = account.client.account_db()?;
    let cursor = cursor?;
    #[cfg(test)]
    let started = std::time::Instant::now();
    db.write_transaction(|| {
        account.client.persist_gateway_cursor(&cursor.target_delivery_id, cursor.inbox_seq)?;
        backpressure.completed(&account.client, &state.entry)?;
        db.remove_inbox_retry(&state.key)?;
        db.remove_unrouted(&state.key)?;
        db.remove_unrouted(&state.entry.envelope.envelope_id)?;
        advance_cursor(&account.client, &account.target_delivery_id, state.entry.inbox_seq)
    })?;
    #[cfg(test)]
    if let Some(handle) = &account.connection {
        handle.test_record_receive("ack-checkpoint", started.elapsed());
    }
    Ok(state.accepted)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::{AckState, finish, stage};
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
                matches!(
                    error,
                    SdkError::Storage(StorageError::Integrity(LEGACY_RECEIVE_ACTIVATED))
                ),
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
}
