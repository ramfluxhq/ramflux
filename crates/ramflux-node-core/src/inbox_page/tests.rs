// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::expect_used, clippy::panic, reason = "regression assertions")]
use super::*;
use crate::{
    CursorAckState,
    router_store::{
        incarnation::test_store,
        publication::{
            capture,
            tests::{entry, fixture},
            view_tests::submit,
        },
    },
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn inbox(rows: impl IntoIterator<Item = u64>, deadline: i64) -> OpaqueDeviceInbox {
    let mut inbox = OpaqueDeviceInbox::new();
    inbox.restore_incarnation("target", "0123456789abcdef0123456789abcdef".into());
    for seq in rows {
        inbox.restore_pending_entry_until(entry(seq), Some(deadline));
    }
    inbox
}
fn check(page: &ResumePage) {
    assert!(serde_json::to_vec(page).expect("json").len() <= PAGE_BYTE_CAP);
    assert!(page.entries.len() <= 256 && page.known_losses.len() <= 64);
    assert!(
        page.after_inbox_seq <= page.covered_through_seq
            && page.covered_through_seq <= page.issued_inbox_seq
    );
    assert_eq!(page.more, page.covered_through_seq < page.issued_inbox_seq);
    assert!(
        !page.more
            || page.covered_through_seq > page.after_inbox_seq
            || page.oversize_next == page.after_inbox_seq.checked_add(1)
    );
    let mut end = page.after_inbox_seq;
    for loss in &page.known_losses {
        assert!(
            loss.from_seq > end
                && loss.to_seq >= loss.from_seq
                && loss.to_seq <= page.covered_through_seq
        );
        assert!(measured(loss).expect("reason size") <= 256);
        assert!(
            page.entries
                .iter()
                .all(|row| !(loss.from_seq..=loss.to_seq).contains(&row.entry.inbox_seq))
        );
        end = loss.to_seq;
    }
    assert!(page.entries.iter().all(|row| row.entry.inbox_seq > page.after_inbox_seq
        && row.entry.inbox_seq <= page.covered_through_seq));
}
fn seek_budget() {
    // Rust BTreeMap B=6: <=11 comparisons/node, height <= floor(log6(P))+1;
    // an exclusive lower-bound seek plus unbounded upper end uses <=11*height.
    // Both pending/dead-letter seeks are counted by SequenceKey::Ord, not labels.
    for n in [64_u64, 4096, 65536] {
        let inbox = inbox(1..=n, i64::MAX);
        for after in [n - 1, n, n + 1] {
            COMPARISONS.with(|c| c.set(0));
            let _ = inbox.resume_page("target", after, 1, 0);
            let mut height = 1;
            let mut capacity = n;
            while capacity >= 6 {
                capacity /= 6;
                height += 1;
            }
            assert!(
                COMPARISONS.with(std::cell::Cell::get) <= 11 * height,
                "actual key comparisons"
            );
        }
    }
}
fn metadata_and_live_aborts() -> Result {
    let mut metadata = inbox([10], i64::MAX);
    metadata.restore_cursor_state(CursorAckState {
        target_delivery_id: "target".into(),
        issued_inbox_seq: 10,
        dead_letters: [crate::DeadLetterRecord {
            inbox_seq: 5,
            envelope_id: "retired".into(),
            reason: DeadLetterReason::AckWindowOverflow,
            retain_until: i64::MAX,
        }]
        .into(),
        ..Default::default()
    });
    metadata.aborted_ranges.insert("target".into(), vec![(2, 3)]);
    let page = metadata.resume_page("target", 0, 256, 0)?;
    check(&page);
    assert_eq!(page.known_losses.len(), 2);
    assert_eq!(page.known_losses[0].reason, PageReason::Aborted);
    assert_eq!(page.known_losses[1].reason, PageReason::AckWindowOverflow);
    let max = inbox([u64::MAX], i64::MAX);
    let page = max.resume_page("target", u64::MAX - 1, 1, 0)?;
    check(&page);
    assert_eq!(page.entries.len(), 1);
    let page = max.resume_page("target", u64::MAX, 1, 0)?;
    check(&page);
    assert!(!page.more);
    for mode in 0..=2 {
        let root = fixture(&format!("page-live-abort-{mode}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let id = store.initialize_inbox("target")?;
        let router = RouterCore::new();
        router.prepare_publication_target(&store, "target")?;
        let core = store.publication_core()?;
        drop(core.reserve("target", &id, &[])?);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while core.view("target", &id).0 == 0 {
            assert!(std::time::Instant::now() < deadline, "abort resolver watchdog");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let page = router.resume_page("target", 0, 256, 0)?;
        check(&page);
        assert_eq!(page.known_losses.len(), 1);
        assert_eq!(page.known_losses[0].reason, PageReason::Aborted);
        assert_eq!(page.known_losses[0].from_seq, 1);
        drop(router);
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn page_sparse_coverage_and_caps() -> Result {
    let huge = 1_000_000_000_000_000;
    let sparse = inbox([1, huge, huge + 2], i64::MAX);
    assert_eq!(sparse.resume_page("target", 0, 0, 0).err(), Some(PageError::InvalidLimit));
    assert_eq!(sparse.resume_page("target", huge + 3, 1, 0).err(), Some(PageError::CursorAhead));
    let page = sparse.resume_page("target", 1, 10000, 0)?;
    check(&page);
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.covered_through_seq, huge + 2);
    assert!(page.known_losses.is_empty());
    seek_budget();
    let live = inbox(1..=600, i64::MAX);
    let page = live.resume_page("target", 0, 10000, 0)?;
    check(&page);
    assert_eq!(page.entries.len(), 256);
    let expired = inbox(1..=600, 0);
    VISITS.with(|c| c.set(0));
    let page = expired.resume_page("target", 0, 256, 1)?;
    assert_eq!(VISITS.with(std::cell::Cell::get), 512, "actual cursor yields including lookahead");
    check(&page);
    assert_eq!(page.covered_through_seq, 512);
    assert_eq!(page.known_losses.len(), 1);
    assert_eq!(expired.pending_entries().count(), 600, "page must not sweep");
    let mixed = inbox(1..=200, 0);
    let mut mixed = mixed;
    mixed
        .aborted_ranges
        .insert("target".into(), (1..=100).map(|n| (2 * n + 200, 2 * n + 200)).collect());
    mixed.observe_issued_seq("target", 401);
    let page = mixed.resume_page("target", 200, 256, 1)?;
    check(&page);
    assert_eq!(page.known_losses.len(), 64);
    metadata_and_live_aborts()?;
    let terminal = live.resume_page("target", 600, 1, 0)?;
    check(&terminal);
    assert!(!terminal.more);
    assert!(live.resume_page(&"\\\"".repeat(9000), 0, 1, 0).is_err());
    Ok(())
}
fn actual_worst_size(page: &ResumePage) -> usize {
    // Independent wire oracle: materialize JSON rather than using the counting writer.
    let mut value = serde_json::to_value(page).expect("frame JSON");
    for field in [
        "after_inbox_seq",
        "covered_through_seq",
        "issued_inbox_seq",
        "settled_through_seq",
        "oversize_next",
    ] {
        value[field] = serde_json::json!(u64::MAX);
    }
    value["more"] = serde_json::json!(false);
    serde_json::to_vec(&value).expect("wire bytes").len()
}
fn boundary_with_reason() -> Result {
    let mut source = inbox([1, 2], i64::MAX);
    source.set_deadline("target", 1, 0);
    source
        .pending
        .get_mut("target")
        .expect("rows")
        .get_mut(&2)
        .expect("row")
        .envelope
        .encrypted_payload
        .clear();
    let base = actual_worst_size(&source.resume_page("target", 0, 1, 1)?);
    for delta in [-1_i64, 0, 1] {
        let len = usize::try_from(i64::try_from(PAGE_BYTE_CAP - base)? + delta)?;
        source
            .pending
            .get_mut("target")
            .expect("rows")
            .get_mut(&2)
            .expect("row")
            .envelope
            .encrypted_payload = "x".repeat(len);
        let page = source.resume_page("target", 0, 1, 1)?;
        check(&page);
        assert_eq!(page.known_losses.len(), 1);
        if delta <= 0 {
            assert_eq!(page.entries.len(), 1);
            assert_eq!(actual_worst_size(&page), PAGE_BYTE_CAP - usize::from(delta < 0));
        } else {
            assert_eq!(page.covered_through_seq, 1);
            assert!(page.entries.is_empty());
            let next = source.resume_page("target", 1, 1, 1)?;
            check(&next);
            assert_eq!(next.entries.len(), 1);
        }
    }
    Ok(())
}
#[test]
fn page_exact_serialized_boundary() -> Result {
    // Escaped metadata/payload defeats a raw-string-length estimate.
    let mut source = inbox([1], i64::MAX);
    let row = source.pending.get_mut("target").expect("rows").get_mut(&1).expect("entry");
    row.envelope.ext.ext.insert("escaped".into(), serde_json::json!("\"\\\n".repeat(80)));
    row.envelope.encrypted_payload.clear();
    let base = actual_worst_size(&source.resume_page("target", 0, 1, 0)?);
    for delta in [-1_i64, 0, 1] {
        let len = usize::try_from(i64::try_from(PAGE_BYTE_CAP - base)? + delta)?;
        source
            .pending
            .get_mut("target")
            .expect("rows")
            .get_mut(&1)
            .expect("row")
            .envelope
            .encrypted_payload = "x".repeat(len);
        let page = source.resume_page("target", 0, 1, 0)?;
        check(&page);
        if delta <= 0 {
            assert_eq!(page.entries.len(), 1);
            assert_eq!(actual_worst_size(&page), PAGE_BYTE_CAP - usize::from(delta < 0));
        } else {
            assert_eq!(page.oversize_next, Some(1));
            assert!(page.entries.is_empty());
        }
    }
    source
        .pending
        .get_mut("target")
        .expect("rows")
        .get_mut(&1)
        .expect("row")
        .envelope
        .encrypted_payload = "\"".repeat(PAGE_BYTE_CAP / 2);
    let page = source.resume_page("target", 0, 1, 0)?;
    check(&page);
    assert_eq!(page.oversize_next, Some(1));
    boundary_with_reason()?;
    Ok(())
}
#[test]
fn inbox_incarnation_reset() -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("page-reset-{mode}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let old = store.initialize_inbox("target")?;
        let mut initial = inbox(31..=50, i64::MAX);
        initial.restore_incarnation("target", old.clone());
        initial.restore_cursor_state(CursorAckState {
            target_delivery_id: "target".into(),
            settled_inbox_seq: 30,
            issued_inbox_seq: 50,
            ..Default::default()
        });
        let mut snapshot = RouterCore::new().snapshot();
        snapshot.inbox = initial;
        let router = RouterCore::from_snapshot(snapshot);
        store.bootstrap_router(&router)?;
        let path = store.path().to_path_buf();
        drop(store);
        let backup = root.join("lower-counter-backup");
        std::fs::copy(&path, &backup)?;
        let store = test_store(&root, mode, 1024 * 1024)?;
        let mut high = inbox([500], i64::MAX);
        high.restore_incarnation("target", old.clone());
        let mut high_snapshot = RouterCore::new().snapshot();
        high_snapshot.inbox = high;
        store.bootstrap_router(&RouterCore::from_snapshot(high_snapshot))?;
        assert_eq!(store.inbox_status("target")?.1, 500);
        drop(store);
        // Restore the earlier backup: the counter falls from 500 to 50.
        std::fs::copy(&backup, &path)?;
        let wal_root = root.join("wal");
        crate::RouterRedbStore::rotate_inbox_incarnations_at(
            &path,
            if mode == 0 { None } else { Some(&wal_root) },
            None,
        )?;
        let store = test_store(&root, mode, 1024 * 1024)?;
        let router = store.load_router()?.expect("persisted router");
        let page = router.resume_page("target", 0, 256, 0)?;
        check(&page);
        assert_eq!(page.settled_through_seq, 30);
        assert_eq!(page.entries.len(), 20);
        assert_ne!(page.incarnation_id, Some(old));
        let expired = router.resume_page("target", 30, 256, i64::MAX)?;
        check(&expired);
        assert_eq!(expired.incarnation_id, page.incarnation_id);
        assert_eq!(expired.known_losses.len(), 1);
        assert_eq!((expired.known_losses[0].from_seq, expired.known_losses[0].to_seq), (31, 50));
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn out_of_order_process_crash() -> Result {
    if let Some(root) = std::env::var_os("RF_PAGE_CRASH_CHILD") {
        let root = std::path::PathBuf::from(root);
        let mode = std::env::var("RF_PAGE_CRASH_MODE")?.parse()?;
        let store = test_store(&root, mode, 1024 * 1024)?;
        let id = store.initialize_inbox("target")?;
        let router = RouterCore::new();
        router.prepare_publication_target(&store, "target")?;
        let core = store.publication_core()?;
        let _held = core.reserve("target", &id, &[])?;
        capture(|| submit(&router, &store, 2, true))?;
        assert_eq!(router.resume_page("target", 0, 256, 0)?.issued_inbox_seq, 0);
        std::process::exit(73);
    }
    for mode in 0..=2 {
        let root = fixture(&format!("page-gap-{mode}"));
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "inbox_page::tests::out_of_order_process_crash", "--nocapture"])
            .env("RF_PAGE_CRASH_CHILD", &root)
            .env("RF_PAGE_CRASH_MODE", mode.to_string())
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait()? {
                assert_eq!(status.code(), Some(73));
                break;
            }
            if std::time::Instant::now() > deadline {
                child.kill()?;
                child.wait()?;
                panic!("crash child watchdog");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let store = test_store(&root, mode, 1024 * 1024)?;
        let router = store.load_router()?.expect("persisted router");
        let page = router.resume_page("target", 0, 256, 0)?;
        check(&page);
        assert_eq!(page.issued_inbox_seq, 2);
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].entry.inbox_seq, 2);
        assert!(page.known_losses.is_empty());
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
