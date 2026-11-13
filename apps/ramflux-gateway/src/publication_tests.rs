// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Capture real reply-driven recipient writes behind the store publication gate.
use super::*;
use ramflux_node_core::{RouterCore, RouterSubmitOutcome, publication};

#[tokio::test]
async fn durable_view_publication() -> Result<(), Box<dyn std::error::Error>> {
    for mode in 0..=2 {
        let root = crate::clients::tests::temp_cert_root(&format!("published-push-{mode}"))?;
        let store = Arc::new(publication::open_durability_fixture(&root, mode)?);
        let router = Arc::new(RouterCore::new());
        store.initialize_inbox("alice-target")?;
        router.prepare_publication_target(&store, "alice-target")?;
        let id =
            store.inbox_status("alice-target")?.0.ok_or_else(|| anyhow::anyhow!("identity"))?;
        let core = store.publication_core()?;
        let held = core.reserve("alice-target", &id, &[])?;
        let (_fixture_directory_0, context) = super::tests::test_gateway_context()?;
        let runtime = super::submit_ack_tests::test_runtime()?;
        let envelope = super::submit_ack_tests::signed_submit(
            &runtime,
            i64::try_from(ramflux_node_core::now_unix_seconds())?,
        )?
        .envelope;
        let source = runtime.source_identity.clone();
        let saved = envelope.clone();
        let worker_router = Arc::clone(&router);
        let worker_store = Arc::clone(&store);
        let prepared = tokio::task::spawn_blocking(move || {
            publication::capture(|| -> anyhow::Result<_> {
                let outcome =
                    worker_router.submit_envelope_at(&source, saved.clone(), saved.created_at);
                let entry = match outcome {
                    RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
                    _ => anyhow::bail!("expected assignment"),
                };
                worker_store.record_submission_increment(
                    &ramflux_node_core::envelope_replay_tuple_key(&source, &saved),
                    saved.created_at + i64::from(saved.ttl),
                    Some(&entry),
                )?;
                Ok(entry)
            })
        })
        .await??;
        assert_eq!(core.view("alice-target", &id).0, 0);
        assert_eq!(store.inbox_status("alice-target")?.1, 2);
        assert_eq!(
            router.session_push_status("alice-target").inbox_seq,
            0,
            "probe cannot expose held assignments"
        );
        let page = router.resume_page(
            "alice-target",
            0,
            256,
            i64::try_from(ramflux_node_core::now_unix_seconds())?,
        )?;
        assert_eq!(page.issued_inbox_seq, 0);
        assert!(page.entries.is_empty());
        assert_eq!(
            router
                .fetch_entry(
                    "alice-target",
                    2,
                    i64::try_from(ramflux_node_core::now_unix_seconds())?
                )
                .err(),
            Some(ramflux_node_core::EntryFetchError::InvalidSeq)
        );
        let (send, sender_frames) = super::submit_ack_tests::sink();
        let (recipient, received) = super::submit_ack_tests::sink();
        context.hub.register("alice-target".into(), "recipient".into(), recipient).await?;
        let delivered_context = context.clone();
        let delivery = tokio::spawn(async move {
            let entry = prepared.published().await?;
            let response = ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "online".into(),
                target_delivery_id: entry.target_delivery_id.clone(),
                inbox_seq: Some(entry.inbox_seq),
                cursor: None,
                nack: None,
            };
            let frame = ramflux_node_core::GatewayServerFrame::Deliver { entry };
            reply_and_deliver_submitted(&send, &context, &runtime, &response, &frame, None).await
        });
        tokio::task::yield_now().await;
        assert!(!delivery.is_finished());
        assert_eq!(received.lock().map_err(|_| anyhow::anyhow!("recipient frames"))?.len(), 0);
        assert_eq!(sender_frames.lock().map_err(|_| anyhow::anyhow!("sender frames"))?.len(), 0);
        drop(held);
        tokio::time::timeout(std::time::Duration::from_secs(30), delivery).await???;
        delivered_context.hub.flushed("alice-target").await?;
        let frames = received.lock().map_err(|_| anyhow::anyhow!("recipient frames"))?;
        assert_eq!(frames.len(), 1);
        assert!(
            matches!(&frames[0], ramflux_node_core::GatewayServerFrame::Deliver { entry } if entry.inbox_seq == 2)
        );
        drop(frames);
        drop(router);
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
