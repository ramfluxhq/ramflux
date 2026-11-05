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
        assert_eq!(
            core.reserve("target", &id, &[]).err(),
            Some(PublicationRefusal::IncarnationMismatch)
        );
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
