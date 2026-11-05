// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live publication metadata must depend on unresolved work, not historical traffic.
#![allow(clippy::expect_used, reason = "regression fixture assertions")]
use super::tests::{entry, fixture};
use super::*;
use crate::{RouterCore, router_store::incarnation::test_store};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn sizes(core: &PublicationCore) -> (usize, usize, usize, usize) {
    let registry = lock(&core.shared);
    (
        registry.resources.len(),
        registry.resources_seen.len(),
        registry.resources_published.len(),
        registry.inboxes.values().map(|inbox| inbox.accepted.len()).sum(),
    )
}

#[test]
fn publication_registry_tracks_only_unpublished_work() -> Result {
    for mode in 0..3 {
        let root = fixture(&format!("bounded-registry-{mode}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let router = RouterCore::new();
        router.prepare_publication_target(&store, "target")?;
        let core = store.publication_core()?;
        let source = super::view_tests::source();
        for seq in 1..=256 {
            capture(|| {
                let envelope = entry(seq).envelope;
                let replay = crate::envelope_replay_tuple_key(&source, &envelope);
                let outcome =
                    router.submit_envelope_at(&source, envelope.clone(), envelope.created_at);
                let crate::RouterSubmitOutcome::OfflineQueued(queued) = outcome else {
                    return Err("expected accepted assignment".into());
                };
                store.record_submission_increment(
                    &replay,
                    envelope.created_at + 3600,
                    Some(&queued.entry),
                )?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })?
            .published_blocking()??;
            assert_eq!(sizes(&core), (0, 0, 0, 0), "published request must release every owner");
        }
        // Concurrent preparations own separate markers; one rejection cannot
        // expose the other request's tentative replay record.
        core.mark_resource("concurrent");
        core.mark_resource("concurrent");
        core.release_unallocated(&["concurrent".into()]);
        assert!(!core.resource_visible("concurrent"));
        core.release_unallocated(&["concurrent".into()]);
        assert_eq!(sizes(&core), (0, 0, 0, 0));
        // A rejection before allocation must release its pre-allocation marker too.
        capture(|| operation::replay_resource(Some(&core), "unallocated"))?.published_blocking()?;
        assert_eq!(sizes(&core), (0, 0, 0, 0));
        drop(router);
        drop(core);
        drop(store);
        let store = test_store(&root, mode, 1024 * 1024)?;
        let core = store.publication_core()?;
        assert_eq!(sizes(&core), (0, 0, 0, 0), "recovery must not copy replay history");
        assert_eq!(
            store.load_router()?.expect("restored router").resume("target", 0, 300).len(),
            256
        );
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn published_sibling_survives_last_owner_abort() -> Result {
    let root = fixture("published-sibling");
    let store = test_store(&root, 0, 1024 * 1024)?;
    let core = store.publication_core()?;
    let left = store.initialize_inbox("target")?;
    let right = store.initialize_inbox("other")?;
    let cleaned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&cleaned);
    core.install_cleanup(
        Arc::new(|_, _| {}),
        Arc::new(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        }),
    );
    let resource = ["shared".to_owned()];
    let accepted = core.reserve("target", &left, &resource)?;
    let aborted = core.reserve("other", &right, &resource)?;
    let write = accepted.hand_off().expect("handoff");
    store.record_inbox_entry(&entry(accepted.sequence()))?;
    write.accepted_durable();
    assert_eq!(core.reservation_owners("shared"), 1);
    assert!(core.resource_visible("shared"));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build()?;
    aborted.definite_non_write();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), core.wait_published(&aborted)).await
    })?;
    assert_eq!(cleaned.load(Ordering::Relaxed), 0, "accepted sibling owns durable replay evidence");
    assert_eq!(sizes(&core), (0, 0, 0, 0));
    drop(accepted);
    drop(aborted);
    drop(core);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn initialization_and_first_preparation_share_one_identity() -> Result {
    for mode in 0..3 {
        let root = fixture(&format!("initialize-prepare-{mode}"));
        let store = Arc::new(test_store(&root, mode, 1024 * 1024)?);
        store.publication_core()?;
        let (entered, arrived) = std::sync::mpsc::sync_channel(1);
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let wait = Mutex::new(wait);
        let observer = crate::durability_test_hooks::observe(
            root.clone(),
            Arc::new(move |_, op, done| {
                if op == "inbox_identity_reserved" && done {
                    entered.send(()).map_err(std::io::Error::other)?;
                    wait.lock()
                        .map_err(|_| std::io::Error::other("release lock"))?
                        .recv_timeout(Duration::from_secs(30))
                        .map_err(std::io::Error::other)?;
                }
                Ok(())
            }),
        );
        let worker_store = Arc::clone(&store);
        let initialized = std::thread::spawn(move || worker_store.initialize_inbox("target"));
        arrived.recv_timeout(Duration::from_secs(30))?;
        let router = RouterCore::new();
        router.prepare_publication_target(&store, "target")?;
        let core = store.publication_core()?;
        let prepared = core.current_incarnation("target").expect("provisional identity");
        release.send(())?;
        assert_eq!(initialized.join().map_err(|_| "initializer panic")??, prepared);
        assert_eq!(store.inbox_status("target")?.0.as_deref(), Some(prepared.as_str()));
        assert_eq!(
            lock(&core.shared).inboxes.keys().filter(|key| key.target == "target").count(),
            1
        );
        drop(observer);
        drop(router);
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
