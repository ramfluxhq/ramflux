// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable-index writer, settlement and restart coverage.
#![allow(clippy::expect_used, reason = "regression fixture assertions")]
use super::*;
use crate::router_store::{
    incarnation::test_store,
    publication::tests::{entry, fixture},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn durable_sender_assignment_writers_survive_settlement_and_restart() -> Result {
    for mode in 0..3 {
        for writer in 0..4 {
            let root = fixture(&format!("retry-index-{mode}-{writer}"));
            let store = test_store(&root, mode, 1 << 20)?;
            let mut row = entry(1);
            row.envelope.envelope_id = format!("writer-{writer}");
            let now = row.envelope.created_at;
            let expiry = now + 3600;
            match writer {
                0 => store.record_submission_increment_for_sender(
                    "replay",
                    expiry,
                    Some(&row),
                    Some("sender"),
                )?,
                1 => {
                    store
                        .record_submission_increment_for_sender_async(
                            "replay",
                            expiry,
                            Some(&row),
                            Some("sender"),
                        )
                        .await?;
                }
                2 => {
                    let lease = store.acquire_submission(&row.target_delivery_id)?;
                    store.record_leased_fanout(
                        "replay",
                        expiry,
                        "sender",
                        std::slice::from_ref(&row),
                        vec![lease],
                    )?;
                }
                _ => {
                    let lease = store.acquire_submission(&row.target_delivery_id)?;
                    store.record_forwarded_submission(
                        "replay",
                        &row,
                        "sender",
                        now + 123,
                        lease,
                    )?;
                }
            }
            let original = store
                .sender_assignment("sender", &row.envelope, now)?
                .expect("complete assignment");
            assert_eq!(original.inbox_seq, 1);
            assert_eq!(original.target_delivery_id, row.target_delivery_id);
            if writer == 3 {
                assert_eq!(original.retain_until, now + 123);
            }
            let changed = {
                let mut e = row.envelope.clone();
                e.encrypted_payload.push('x');
                e
            };
            assert!(
                store
                    .sender_assignment("sender", &changed, now)
                    .expect_err("changed content must conflict")
                    .to_string()
                    .contains("idempotency_conflict")
            );
            let cursor = crate::CursorAckState {
                target_delivery_id: row.target_delivery_id.clone(),
                inbox_seq: 1,
                issued_inbox_seq: 1,
                settled_inbox_seq: 1,
                last_acknowledged_inbox_seq: Some(1),
                ..crate::CursorAckState::default()
            };
            store.record_ack_increment(&cursor, &row.envelope.envelope_id)?;
            assert_eq!(
                store.sender_assignment("sender", &row.envelope, now)?.as_ref(),
                Some(&original)
            );
            drop(store);
            let store = test_store(&root, mode, 1 << 20)?;
            assert_eq!(
                store.sender_assignment("sender", &row.envelope, now)?.as_ref(),
                Some(&original)
            );
            assert!(store.sender_assignment("sender", &row.envelope, expiry)?.is_none());
            drop(store);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

#[test]
fn legacy_sender_receipts_do_not_invent_assignments() -> Result {
    let root = fixture("legacy-retry-index");
    let store = test_store(&root, 0, 1 << 20)?;
    let row = entry(1);
    let key =
        local_delivery_storage_key("sender", &row.envelope.envelope_id, &row.target_delivery_id);
    let tx = store.db.begin_write()?;
    {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"target_delivery_id": row.target_delivery_id, "expires_at": i64::MAX}),
        )?;
        tx.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?
            .insert(key.as_str(), bytes.as_slice())?;
    }
    tx.commit()?;
    assert!(store.sender_assignment("sender", &row.envelope, 0)?.is_none());
    assert!(store.has_local_delivery_envelope(
        "sender",
        &row.envelope.envelope_id,
        &row.target_delivery_id,
        0
    )?);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn retry_waiter_admission_is_bounded_and_cancel_safe() -> Result {
    let root = fixture("bounded-retry-waiters");
    let store = test_store(&root, 0, 1 << 20)?;
    let root_identity = ramflux_crypto::create_identity_root("sender", [0x91; 32]);
    let branch = ramflux_crypto::create_device_branch("sender", "device", 1, [0x92; 32]);
    let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root_identity, &branch)?;
    let row = entry(1);
    let available = store.submission_admission.available_permits();
    let RetryAdmission::Owner(owner) = store.admit_sender_retry(&source, &row.envelope, 0)? else {
        return Err("owner".into());
    };
    let mut waiters = Vec::new();
    for _ in 1..available {
        let RetryAdmission::Waiting(waiter) =
            store.admit_sender_retry(&source, &row.envelope, 1)?
        else {
            return Err("waiter".into());
        };
        assert_eq!(waiter.retain_until(), crate::inbox_retain_until(&row.envelope, 0));
        waiters.push(waiter);
    }
    assert!(matches!(
        store.admit_sender_retry(&source, &row.envelope, 2),
        Err(NodeCoreError::Publication(
            crate::publication::PublicationRefusal::CapacityRetryAfter { .. }
        ))
    ));
    drop(waiters.pop());
    let RetryAdmission::Waiting(replacement) =
        store.admit_sender_retry(&source, &row.envelope, 3)?
    else {
        return Err("replacement".into());
    };
    assert_eq!(store.sender_retry_registry_size(), 1);
    drop(owner);
    assert_eq!(store.sender_retry_registry_size(), 0);
    for waiter in waiters.into_iter().chain(std::iter::once(replacement)) {
        assert!(matches!(
            waiter.resolved().await,
            Err(NodeCoreError::SenderRetry(SenderRetryRefusal::AbortedRetrySafe))
        ));
    }
    assert_eq!(store.submission_admission.available_permits(), available);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
