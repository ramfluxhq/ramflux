// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! ACK commit does not hold a shard lock or copy unrelated mailboxes.
#![allow(clippy::expect_used, clippy::panic, reason = "regression assertions")]
use super::tests::ack;
use super::*;
use crate::router_store::{
    incarnation::test_store,
    publication::{
        capture,
        tests::{entry, fixture},
        view_tests::submit,
    },
};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn other_target() -> String {
    (0..4096)
        .map(|n| format!("other-{n}"))
        .find(|name| {
            super::super::target_shard_index(name) == super::super::target_shard_index("target")
        })
        .expect("colliding shard")
}
fn submit_other(router: &RouterCore, target: &str) -> crate::InboxEntry {
    let root = ramflux_crypto::create_identity_root("sender", [0x91; 32]);
    let branch = ramflux_crypto::create_device_branch(
        "sender",
        "device",
        1,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    );
    let source =
        ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch).expect("source");
    let mut envelope = entry(9999).envelope;
    envelope.target_delivery_id = target.into();
    let now = envelope.created_at;
    match router.submit_envelope_at(&source, envelope, now) {
        crate::RouterSubmitOutcome::OfflineQueued(row) => row.entry,
        other => panic!("unexpected submit {other:?}"),
    }
}
#[test]
fn ack_commit_releases_shard_and_clones_only_target() -> Result {
    let root = fixture("ack-other-shard");
    let store = Arc::new(test_store(&root, 0, 1 << 20)?);
    let router = Arc::new(RouterCore::new());
    let other = other_target();
    for seq in 1..=3 {
        router.target_shard("target").inbox.restore_pending_entry_until(entry(seq), i64::MAX);
    }
    for seq in 1..=4096 {
        let mut row = entry(seq);
        row.target_delivery_id = other.clone();
        row.envelope.target_delivery_id = other.clone();
        router.target_shard(&other).inbox.restore_pending_entry_until(row, i64::MAX);
    }
    store.bootstrap_router(&router)?;
    router.prepare_publication_target(&store, "target")?;
    router.prepare_publication_target(&store, &other)?;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let observer = crate::durability_test_hooks::observe(
        root.to_path_buf(),
        Arc::new(move |_, op, done| {
            if op == "direct_commit" && !done {
                entered_tx.send(()).map_err(std::io::Error::other)?;
                release_rx
                    .lock()
                    .map_err(|_| std::io::Error::other("release mutex"))?
                    .recv_timeout(Duration::from_secs(15))
                    .map_err(std::io::Error::other)?;
            }
            Ok(())
        }),
    );
    let r = router.clone();
    let s = store.clone();
    let ack_task = std::thread::spawn(move || {
        crate::inbox::CLONED_ENTRIES.with(|c| c.borrow_mut().clear());
        let result = r.apply_ack_batch(&s, "target", &[ack(1)]);
        let copies = crate::inbox::CLONED_ENTRIES.with(|c| c.borrow().clone());
        (result, copies)
    });
    entered_rx.recv_timeout(Duration::from_secs(5))?;
    let (progress_tx, progress_rx) = mpsc::channel();
    let r = router.clone();
    let s = store.clone();
    let t = other.clone();
    let traffic = std::thread::spawn(move || {
        let same = capture(|| submit(&r, &s, 4, false)).expect("same target submit");
        let unrelated = capture(|| submit_other(&r, &t)).expect("other submit");
        let pulled = r.resume(&t, 0, 1);
        progress_tx.send((same, unrelated, pulled)).expect("progress result");
    });
    let progress = progress_rx.recv_timeout(Duration::from_secs(5));
    // Release before asserting: the broken implementation must fail without hanging.
    release_tx.send(())?;
    let (results, copies) = ack_task.join().map_err(|_| "ACK thread")?;
    traffic.join().map_err(|_| "traffic thread")?;
    drop(observer);
    let (same, unrelated, pulled) = progress?;
    assert!(results?.iter().all(std::result::Result::is_ok));
    assert_eq!(copies.get(&other).copied().unwrap_or(0), 0, "actual unrelated entry clones");
    assert!(
        copies.get("target").copied().unwrap_or(0) <= 4,
        "three target rows plus one ACK bookkeeping row"
    );
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].target_delivery_id, other);
    assert!(
        router.target_shard("target").inbox.pending_entries().any(|row| row.inbox_seq == 4),
        "concurrent append survives candidate publication"
    );
    assert!(matches!(
        router.apply_ack_batch(&store, "target", &[]),
        Err(NodeCoreError::InvalidAckBatch(_))
    ));
    drop(same);
    drop(unrelated);
    Ok(())
}
