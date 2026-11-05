// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A runtime view must neither own the database nor hide committed replay state.
#![allow(clippy::expect_used, reason = "lifetime regression assertions")]
use super::tests::fixture;
use super::view_tests::{source, submit};
use super::*;
use crate::{RouterCore, router_store::incarnation::test_store};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn dropping_store_releases_database_with_bound_router() -> Result {
    for mode in 0..3 {
        let root = fixture(&format!("store-lifetime-{mode}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let router = RouterCore::new();
        router.prepare_publication_target(&store, "target")?;
        capture(|| submit(&router, &store, 1, true))?.published_blocking()?;
        let core = store.publication_core()?;
        let id = store.inbox_status("target")?.0.expect("durable identity");
        let reserved = core.reserve("target", &id, &[])?;
        drop(store);
        assert!(core.shared.db.upgrade().is_none(), "runtime view retained redb ownership");
        assert_eq!(reserved.state(), PersistenceState::AbortedDurable);
        assert_eq!(core.reserve("target", &id, &[]).err(), Some(PublicationRefusal::StoreClosed));
        let reopened = test_store(&root, mode, 1024 * 1024)?;
        assert_eq!(reopened.inbox_status("target")?, (Some(id.clone()), 2));
        let recovered = reopened.load_router()?.expect("persisted router");
        assert_eq!(recovered.resume("target", 0, 10).len(), 1);
        assert_eq!(recovered.inbox_snapshot().incarnation_id("target"), Some(id.as_str()));
        drop(recovered);
        drop(reopened);
        drop(reserved);
        drop(router);
        drop(core);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn duplicate_scope_preserves_published_replay_visibility() -> Result {
    for mode in 0..3 {
        let root = fixture(&format!("duplicate-view-{mode}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let router = RouterCore::new();
        router.prepare_publication_target(&store, "target")?;
        let row = capture(|| submit(&router, &store, 1, true))?.published_blocking()?;
        let core = store.publication_core()?;
        let source = source();
        let key = crate::envelope_replay_tuple_key(&source, &row.envelope);
        assert!(core.resource_visible(&key));
        capture(|| {
            let duplicate =
                router.submit_envelope_at(&source, row.envelope.clone(), row.envelope.created_at);
            assert!(matches!(duplicate, crate::RouterSubmitOutcome::RejectedSecurity { .. }));
            assert!(core.resource_visible(&key), "duplicate hid an already durable replay key");
            assert!(
                router
                    .snapshot()
                    .replay_guard_state
                    .accepted_entries()
                    .any(|(stored, _)| stored == &key)
            );
        })?
        .published_blocking()?;
        assert!(core.resource_visible(&key));
        drop(router);
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn retired_target_preparation_returns_typed_incarnation_mismatch() -> Result {
    let root = fixture("retired-preparation");
    let store = test_store(&root, 0, 1024 * 1024)?;
    let router = RouterCore::new();
    router.prepare_publication_target(&store, "target")?;
    let core = store.publication_core()?;
    core.retire_target("target")?.commit();
    assert!(matches!(
        router.prepare_publication_target(&store, "target"),
        Err(NodeCoreError::Publication(PublicationRefusal::IncarnationMismatch))
    ));
    drop(router);
    drop(core);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn durable_issued_floor_survives_late_registration() -> Result {
    for mode in 0..3 {
        for initialize in [false, true] {
            for provisional in [false, true] {
                let root = fixture(&format!("issued-floor-{mode}-{initialize}-{provisional}"));
                let store = test_store(&root, mode, 1024 * 1024)?;
                let core = store.publication_core()?;
                if provisional {
                    store.provisional_inbox_incarnation("target")?;
                }
                let row = super::tests::entry(5);
                store.record_submission_increment("durable-five", i64::MAX, Some(&row))?;
                let expected = store.inbox_status("target")?.0.expect("durable E");
                let id = if initialize {
                    store.initialize_inbox("target")?
                } else {
                    store.provisional_inbox_incarnation("target")?
                };
                assert_eq!(id, expected);
                assert_eq!(store.inbox_status("target")?.1, 5);
                let next = core.reserve("target", &id, &[])?;
                assert_eq!(next.sequence(), 6, "durable sequence must never be reused");
                assert_eq!(
                    core.view("target", &id).0,
                    5,
                    "durable issued floor was replaced by provisional zero"
                );

                next.definite_non_write();
                let runtime =
                    tokio::runtime::Builder::new_current_thread().enable_time().build()?;
                runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(30), core.wait_published(&next)).await
                })?;
                drop(next);
                drop(core);
                drop(store);
                std::fs::remove_dir_all(root)?;
            }
        }
    }
    Ok(())
}

#[test]
fn shutdown_snapshot_cannot_miss_a_racing_reservation() -> Result {
    const NAME: &str = "router_store::publication::lifetime_tests::shutdown_snapshot_cannot_miss_a_racing_reservation";
    if let Some(root) = std::env::var_os("RAMFLUX_PUBLICATION_SHUTDOWN_CHILD") {
        return shutdown_race_child(std::path::Path::new(&root));
    }
    let root = fixture("shutdown-race");
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", NAME, "--nocapture"])
        .env("RAMFLUX_PUBLICATION_SHUTDOWN_CHILD", &root)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("shutdown child watchdog".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    assert!(status.success(), "racing shutdown child: {status}");
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn shutdown_race_child(root: &std::path::Path) -> Result {
    let store = test_store(root, 0, 1024 * 1024)?;
    let id = store.initialize_inbox("target")?;
    let core = store.publication_core()?;
    let (entered, snapshot) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let wait = Mutex::new(wait);
    let once = AtomicBool::new(false);
    *core.shared.snapshot_hook.lock().map_err(|_| "snapshot hook")? = Some(Arc::new(move || {
        if !once.swap(true, Ordering::Relaxed) {
            entered.send(()).expect("snapshot entered");
            wait.lock()
                .expect("snapshot release")
                .recv_timeout(Duration::from_secs(10))
                .expect("snapshot watchdog");
        }
    }));
    core.shared.worker.get().expect("resolver").unpark();
    snapshot.recv_timeout(Duration::from_secs(10))?;
    let guard = core.reserve("target", &id, &[])?;
    let closing = Arc::clone(&core);
    let shutdown = std::thread::spawn(move || closing.shutdown());
    let deadline = Instant::now() + Duration::from_secs(10);
    while !core.shared.stopping.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "shutdown flag watchdog");
        std::thread::yield_now();
    }
    assert_eq!(core.reserve("target", &id, &[]).err(), Some(PublicationRefusal::StoreClosed));
    release.send(())?;
    shutdown.join().map_err(|_| "shutdown panicked")?;
    assert!(crate::fatal_durability::check().is_ok(), "shutdown fabricated uncertainty");
    assert_eq!(guard.state(), PersistenceState::AbortedDurable);
    assert_eq!(core.view("target", &id).0, 1);
    drop(guard);
    drop(core);
    drop(store);
    Ok(())
}
