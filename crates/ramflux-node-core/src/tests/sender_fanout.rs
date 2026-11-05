// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Mixed child retries preserve durable siblings and allocate only missing children.
use super::*;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[tokio::test]
async fn fanout_mixed_retry_reuses_children_after_abort_and_restart() -> Result {
    for mode in 0..3 {
        let root = temp_store_path(&format!("sender-fanout-{mode}"))?;
        let store = crate::publication::open_durability_fixture(&root, mode)?;
        let router = RouterCore::new();
        store.bootstrap_router(&router)?;
        for (device, seed) in [("source", 601), ("left", 602), ("right", 603)] {
            let mut registration =
                registration_request(&router, "fanout", device, seed, None, device)?;
            registration.target_delivery_id = format!("target_{device}");
            registration.session_id = format!("session_{device}");
            router.mvp1_register_identity(&registration)?;
        }
        store.record_identity_registry(&router.mvp1_identities_snapshot())?;
        let mut unsigned = envelope("mixed-parent", "unused", DeliveryClass::SelfDeviceControl);
        unsigned.created_at = i64::try_from(crate::now_unix_seconds())?;
        let envelope = signed_registered_envelope(unsigned, "fanout", "source", 601)?;
        let request = ItestMvp10OwnDeviceFanoutRequest {
            principal_id: "fanout".into(),
            source_device_id: "source".into(),
            envelope,
        };
        let now = request.envelope.created_at;
        let source = router.authenticated_envelope_source_durable(&request.envelope, &store)?;
        let targets =
            router.mvp1_identities_snapshot().active_own_device_targets("fanout", "source");
        let (_, right_target) =
            targets.iter().find(|(device, _)| device == "right").ok_or("right")?;
        let mut right = request.envelope.clone();
        right.target_delivery_id.clone_from(right_target);
        right.envelope_id = mvp10_fanout_envelope_id(&right.envelope_id, "right");
        let crate::sender_retry::RetryAdmission::Owner(owner) =
            store.admit_sender_retry(&source, &right, now)?
        else {
            return Err("owner".into());
        };
        let first =
            crate::publication::capture(|| router.prepare_sender_fanout(&store, &request, now))?
                .published()
                .await?;
        let cancelled =
            crate::publication::capture(|| router.prepare_sender_fanout(&store, &request, now))?
                .published()
                .await?;
        drop(cancelled);
        assert_eq!(store.sender_retry_registry_size(), 1);
        drop(owner);
        let first = first.resolved().await?;
        assert_eq!(first.delivered.iter().filter(|child| child.inbox_seq == Some(1)).count(), 1);
        assert_eq!(
            first.delivered.iter().filter(|child| child.outcome == "aborted_retry_safe").count(),
            1
        );
        let retried =
            crate::publication::capture(|| router.prepare_sender_fanout(&store, &request, now))?
                .published()
                .await?
                .resolved()
                .await?;
        assert!(retried.delivered.iter().all(|child| child.inbox_seq == Some(1)), "{retried:?}");
        for (_, target) in &targets {
            assert_eq!(router.resume(target, 0, 10).len(), 1);
            assert_eq!(store.inbox_status(target)?.1, 1);
        }
        assert_eq!(store.sender_retry_registry_size(), 0);
        post_commit_siblings(&root, &store, &router, &request, now).await?;
        drop(router);
        drop(store);
        let store = crate::publication::open_durability_fixture(&root, mode)?;
        let router = store.load_router()?.ok_or("router")?;
        let restored =
            crate::publication::capture(|| router.prepare_sender_fanout(&store, &request, now))?
                .published()
                .await?
                .resolved()
                .await?;
        assert!(restored.delivered.iter().all(|child| child.inbox_seq == Some(1)));
        for (_, target) in &targets {
            assert_eq!(router.resume(target, 0, 10).len(), 2);
            assert_eq!(store.inbox_status(target)?.1, 2);
        }
        drop(router);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

async fn post_commit_siblings(
    root: &std::path::Path,
    store: &crate::RouterRedbStore,
    router: &RouterCore,
    original: &ItestMvp10OwnDeviceFanoutRequest,
    now: i64,
) -> Result {
    let mut request = original.clone();
    request.envelope.envelope_id = "post-commit-parent".into();
    request.envelope = signed_registered_envelope(request.envelope, "fanout", "source", 601)?;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&calls);
    let registration = crate::durability_test_hooks::observe(
        root.to_path_buf(),
        std::sync::Arc::new(move |_, operation, _| {
            if operation == "sender_reply_lookup"
                && counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
            {
                return Err(std::io::Error::other(
                    "one child lookup fails after all children commit",
                ));
            }
            Ok(())
        }),
    );
    let response =
        crate::publication::capture(|| router.prepare_sender_fanout(store, &request, now))?
            .published()
            .await?
            .resolved()
            .await?;
    assert!(response.delivered.iter().all(|child| child.inbox_seq == Some(2)));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2, "later sibling still completes");
    assert_eq!(store.sender_retry_registry_size(), 0);
    let retry = crate::publication::capture(|| router.prepare_sender_fanout(store, &request, now))?
        .published()
        .await?
        .resolved()
        .await?;
    assert!(retry.delivered.iter().all(|child| child.inbox_seq == Some(2)));
    drop(registration);
    Ok(())
}
