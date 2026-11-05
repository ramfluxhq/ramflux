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

#[tokio::test]
async fn retry_admission_retains_capacity_until_publication() -> Result {
    let root = fixture("retry-published-admission");
    let mut store = test_store(&root, 0, 1 << 20)?;
    store.submission_admission = std::sync::Arc::new(tokio::sync::Semaphore::new(3));
    let identity = ramflux_crypto::create_identity_root("sender", [0x91; 32]);
    let branch = ramflux_crypto::create_device_branch("sender", "device", 1, [0x92; 32]);
    let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&identity, &branch)?;
    let id = store.initialize_inbox("target")?;
    let core = store.publication_core()?;
    let predecessor = core.reserve("target", &id, &[])?;
    let guard = core.reserve("target", &id, &[])?;
    let write = guard.hand_off().ok_or("handoff")?;
    let row = entry(2);
    store.record_submission_increment_for_sender(
        "original",
        row.envelope.created_at + 3600,
        Some(&row),
        Some(source.root_commitment()),
    )?;
    write.accepted_durable();
    assert_eq!(core.view("target", &id).0, 0);
    let mut replies = Vec::new();
    for _ in 0..3 {
        let RetryAdmission::Accepted(resolved) =
            store.admit_sender_retry(&source, &row.envelope, row.envelope.created_at)?
        else {
            return Err("durable retry".into());
        };
        replies.push(crate::publication::capture(|| {
            crate::publication::await_sender_retry(&core, resolved)
        })?);
    }
    assert_eq!(store.submission_admission.available_permits(), 0);
    assert!(matches!(
        store.admit_sender_retry(&source, &row.envelope, row.envelope.created_at),
        Err(NodeCoreError::Publication(
            crate::publication::PublicationRefusal::CapacityRetryAfter { .. }
        ))
    ));
    drop(replies.pop());
    assert_eq!(store.submission_admission.available_permits(), 1);
    let replacement = store.admit_sender_retry(&source, &row.envelope, row.envelope.created_at)?;
    assert_eq!(store.submission_admission.available_permits(), 0);
    drop(replacement);
    predecessor.definite_non_write();
    core.wait_published(&guard).await;
    for reply in replies {
        assert_eq!(reply.published().await?.inbox_seq, 2);
    }
    assert_eq!(store.submission_admission.available_permits(), 3);
    drop(predecessor);
    drop(guard);
    drop(core);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn typed_sender_refusals_preserve_existing_native_variant_numbers() -> Result {
    use ramflux_protocol::custody::CustodyRefusal::*;
    for (index, reason) in [
        Unsupported,
        InvalidInput,
        AuthorityUnavailable,
        PrincipalIdTaken,
        ChallengeUnknown,
        ChallengeExpired,
        Replay,
        BindingRefused,
        SessionRequired,
        SessionExpired,
        UpdateRequired,
        Capacity,
        Busy,
        PersistenceUnavailable,
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = postcard::to_allocvec(&reason)?;
        assert_eq!(bytes, vec![u8::try_from(index)?]);
        assert_eq!(
            postcard::from_bytes::<ramflux_protocol::custody::CustodyRefusal>(&bytes)?,
            reason
        );
    }
    for reason in
        [AbortedRetrySafe, CapacityRetryAfter { retry_after_ms: 1000 }, IdempotencyConflict]
    {
        let bytes = postcard::to_allocvec(&reason)?;
        assert_eq!(
            postcard::from_bytes::<ramflux_protocol::custody::CustodyRefusal>(&bytes)?,
            reason
        );
    }
    Ok(())
}

fn fail_reply_lookup(
    root: &std::path::Path,
) -> (std::sync::Arc<std::sync::atomic::AtomicUsize>, crate::durability_test_hooks::Registration) {
    let reached = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&reached);
    let registration = crate::durability_test_hooks::observe(
        root.to_path_buf(),
        std::sync::Arc::new(move |_, operation, _| {
            if operation == "sender_reply_lookup" {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return Err(std::io::Error::other("injected read failure after durable commit"));
            }
            Ok(())
        }),
    );
    (reached, registration)
}

#[test]
fn post_commit_retry_owner_rechecks_index() -> Result {
    for mode in 0..3 {
        for writer in 0..3 {
            let root = fixture(&format!("post-commit-{mode}-{writer}"));
            let store = test_store(&root, mode, 1 << 20)?;
            let router = crate::RouterCore::new();
            router.prepare_publication_target(&store, "target")?;
            let identity = ramflux_crypto::create_identity_root("sender", [0x91; 32]);
            let branch = ramflux_crypto::create_device_branch("sender", "device", 1, [0x92; 32]);
            let source =
                ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&identity, &branch)?;
            let row = entry(1);
            let now = row.envelope.created_at;
            let available = store.submission_admission.available_permits();
            let (reached, registration) = fail_reply_lookup(&root);
            let operation =
                crate::publication::capture(|| -> std::result::Result<_, NodeCoreError> {
                    let RetryAdmission::Owner(owner) =
                        store.admit_sender_retry(&source, &row.envelope, now)?
                    else {
                        return Err(incarnation::error("owner"));
                    };
                    owner.bind("target")?;
                    let crate::RouterSubmitOutcome::OfflineQueued(queued) =
                        router.submit_envelope_at(&source, row.envelope.clone(), now)
                    else {
                        return Err(incarnation::error("entry"));
                    };
                    let RetryAdmission::Waiting(waiter) =
                        store.admit_sender_retry(&source, &row.envelope, now)?
                    else {
                        return Err(incarnation::error("waiter"));
                    };
                    let replay = crate::envelope_replay_tuple_key(&source, &row.envelope);
                    match writer {
                        0 => store.record_submission_increment_for_sender(
                            &replay,
                            now + 3600,
                            Some(&queued.entry),
                            Some(source.root_commitment()),
                        )?,
                        1 => store.record_leased_fanout(
                            &replay,
                            now + 3600,
                            source.root_commitment(),
                            std::slice::from_ref(&queued.entry),
                            vec![store.acquire_submission("target")?],
                        )?,
                        _ => store.record_forwarded_submission(
                            &replay,
                            &queued.entry,
                            source.root_commitment(),
                            now + 123,
                            store.acquire_submission("target")?,
                        )?,
                    }
                    owner.accepted_entry(&store, source.root_commitment(), &queued.entry, now);
                    assert_eq!(
                        store.sender_retry_registry_size(),
                        0,
                        "post-commit error must release bound owner"
                    );
                    Ok((queued.entry, waiter))
                })?;
            let (original, waiter) = operation.published_blocking()??;
            assert_eq!(reached.load(std::sync::atomic::Ordering::SeqCst), 1);
            let resolved = waiter.resolved_blocking()?;
            assert_eq!(resolved.inbox_seq, original.inbox_seq);
            if writer == 2 {
                assert_eq!(resolved.retain_until, now + 123);
            }
            drop(resolved);
            assert!(matches!(
                store.admit_sender_retry(&source, &row.envelope, now)?,
                RetryAdmission::Accepted(_)
            ));
            assert_eq!(store.submission_admission.available_permits(), available);
            assert_eq!(router.resume("target", 0, 10).len(), 1);
            drop(registration);
            drop(router);
            drop(store);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn store_drop_and_remote_forward_wake_retry_waiters() -> Result {
    for remote in [false, true] {
        let root = fixture("retry-owner-lifecycle");
        let store = test_store(&root, 0, 1 << 20)?;
        let identity = ramflux_crypto::create_identity_root("sender", [0x91; 32]);
        let branch = ramflux_crypto::create_device_branch("sender", "device", 1, [0x92; 32]);
        let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&identity, &branch)?;
        let row = entry(1);
        let RetryAdmission::Owner(owner) = store.admit_sender_retry(&source, &row.envelope, 0)?
        else {
            return Err("owner".into());
        };
        let RetryAdmission::Waiting(waiter) =
            store.admit_sender_retry(&source, &row.envelope, 0)?
        else {
            return Err("waiter".into());
        };
        if remote {
            owner.forwarded();
            drop(store);
        } else {
            drop(store);
            drop(owner);
        }
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(5), waiter.resolved()).await?;
        if remote {
            assert!(matches!(
                result,
                Err(NodeCoreError::SenderRetry(SenderRetryRefusal::ForwardInProgress))
            ));
        } else {
            assert!(matches!(
                result,
                Err(NodeCoreError::Publication(
                    crate::publication::PublicationRefusal::StoreClosed
                ))
            ));
        }
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
