// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publication/read/control-save ordering on the real router and both stores.
#![allow(clippy::expect_used, clippy::panic, reason = "regression fixture assertions")]
use super::tests::{entry, fixture};
use super::*;
use crate::router_store::incarnation::test_store;
use crate::{RouterCore, RouterRedbStore, RouterSubmitOutcome};
use std::sync::mpsc;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn source() -> ramflux_crypto::RootQualifiedDeviceRef {
    let root = ramflux_crypto::create_identity_root("sender", [0x91; 32]);
    let branch = ramflux_crypto::create_device_branch(
        "sender",
        "device",
        1,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    );
    ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch).expect("source")
}
fn submit(
    router: &RouterCore,
    store: &RouterRedbStore,
    seq: u64,
    persist: bool,
) -> crate::InboxEntry {
    let source = source();
    let envelope = entry(seq).envelope;
    let replay = crate::envelope_replay_tuple_key(&source, &envelope);
    let now = envelope.created_at;
    let outcome = router.submit_envelope_at(&source, envelope, now);
    let entry = match outcome {
        RouterSubmitOutcome::OfflineQueued(queued) => queued.entry,
        other => panic_outcome(&other),
    };
    if persist {
        store.record_submission_increment(&replay, now + 3600, Some(&entry)).expect("persist");
    }
    entry
}
fn panic_outcome(outcome: &RouterSubmitOutcome) -> crate::InboxEntry {
    // Keep the diagnostic outside the branch under test.
    panic!("expected accepted entry: {outcome:?}")
}

fn ordering(abort: bool) -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("view-{mode}-{abort}"));
        let store = Arc::new(test_store(&root, mode, 1024 * 1024)?);
        let router = Arc::new(RouterCore::new());
        router.prepare_publication_target(&store, "target")?;
        let id = store.inbox_status("target")?.0.expect("id");
        let (arrived, held) = mpsc::sync_channel(1);
        let (release, continuation) = mpsc::sync_channel(1);
        let first_router = Arc::clone(&router);
        let first_store = Arc::clone(&store);
        let first = thread::spawn(move || {
            capture(|| {
                let entry = submit(&first_router, &first_store, 1, false);
                arrived.send(()).expect("arrival");
                continuation.recv().expect("continuation");
                if !abort {
                    let replay = crate::envelope_replay_tuple_key(&source(), &entry.envelope);
                    first_store
                        .record_submission_increment(
                            &replay,
                            entry.envelope.created_at + 3600,
                            Some(&entry),
                        )
                        .expect("first commit");
                }
            })
            .expect("first scope")
            .published_blocking()
            .expect("first publication");
        });
        held.recv_timeout(Duration::from_secs(30))?;
        let second = capture(|| submit(&router, &store, 2, true))?;
        assert_eq!(store.inbox_status("target")?.1, 2, "later write really durable");
        assert_eq!(store.publication_core()?.view("target", &id).0, 0);
        assert_eq!(router.resume("target", 0, 10).len(), 0);
        assert_eq!(
            router.mvp1_inbox_at("target", 0, 10, entry(1).envelope.created_at).entries.len(),
            0
        );
        assert_eq!(router.pending_entries_for_target("target").len(), 0);
        let snapshot = router.snapshot();
        assert_eq!(snapshot.inbox.pull_after("target", 0, 10).len(), 0);
        assert!(snapshot.replay_guard_state.is_empty());
        assert!(
            !String::from_utf8(serde_json::to_vec(&snapshot)?)?
                .contains("ciphertext-must-not-enter-aborted-record")
        );
        store.save_router(&router)?;
        store.save_router(&router)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let waiter = tokio::spawn(second.published());
            tokio::task::yield_now().await;
            assert!(!waiter.is_finished(), "own-write durability cannot authorize reply");
            // This task and the heartbeat run on the only runtime worker.
            let heartbeat = tokio::spawn(async {
                tokio::task::yield_now().await;
                7
            });
            assert_eq!(heartbeat.await.expect("heartbeat"), 7);
            release.send(()).expect("release predecessor");
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(30), waiter)
                    .await
                    .expect("reply watchdog")
                    .expect("reply")
                    .inbox_seq,
                2
            );
        });
        first.join().map_err(|_| "first panic")?;
        let rows = router.resume("target", 0, 10);
        assert_eq!(rows.len(), if abort { 1 } else { 2 });
        if abort {
            let snapshot = router.snapshot();
            assert_eq!(snapshot.inbox.aborted_ranges.get("target"), Some(&vec![(1, 1)]));
            assert_eq!(snapshot.replay_guard_state.len(), 1);
        }
        store.save_router(&router)?;
        drop(router);
        drop(store);
        let reopened = test_store(&root, mode, 1024 * 1024)?;
        assert_eq!(reopened.inbox_status("target")?, (Some(id), 2));
        let recovered = reopened.load_router()?.expect("restored router");
        assert_eq!(recovered.resume("target", 0, 10).len(), if abort { 1 } else { 2 });
        drop(recovered);
        drop(reopened);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn durable_view_publication() -> Result {
    ordering(false)
}
#[test]
fn published_snapshot_control_save() -> Result {
    ordering(true)
}
pub(super) fn reply_liveness() -> Result {
    ordering(false)
}
