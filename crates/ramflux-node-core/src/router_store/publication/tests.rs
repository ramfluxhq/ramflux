// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "regression fixture assertions and injected unwind"
)]

use super::*;
use crate::router_store::incarnation::test_store;
use crate::{InboxEntry, OpaqueDeviceInbox, RouterRedbStore};
use std::sync::{Barrier, mpsc};
use tracing_subscriber::prelude::*;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

pub(crate) fn fixture(name: &str) -> ramflux_test_support::TestPath {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(format!(
        "publication-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

pub(crate) fn entry(seq: u64) -> InboxEntry {
    let envelope = ramflux_protocol::Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.into(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.into(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "fixture".into(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "signature".into(),
        },
        envelope_id: format!("entry-{seq}"),
        source_principal_id: "sender".into(),
        source_device_id: "device".into(),
        target_delivery_id: "target".into(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Normal,
        ttl: 3600,
        created_at: i64::try_from(crate::now_unix_seconds()).expect("time"),
        encrypted_payload: "ciphertext-must-not-enter-aborted-record".into(),
        payload_hash: "hash".into(),
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
    };
    let mut entry = OpaqueDeviceInbox::new().append(envelope);
    entry.inbox_seq = seq;
    entry
}

fn accept(store: &RouterRedbStore, guard: &AssignmentGuard) -> Result {
    let write = guard.hand_off().expect("hand off before store call");
    let entry = entry(guard.sequence());
    store.record_submission_increment(
        &crate::tests::request_replay_fixture(&format!("fixture/{}", guard.sequence())),
        entry.envelope.created_at + 3600,
        Some(&entry),
    )?;
    write.accepted_durable();
    Ok(())
}

fn await_p(core: &PublicationCore, id: &str, seq: u64) {
    let runtime =
        tokio::runtime::Builder::new_current_thread().enable_time().build().expect("runtime");
    runtime.block_on(async {
        // Publication notification is causal progress. This timeout only guards
        // a lost wake or hung resolver; it is not a storage speed assertion.
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let notified = core.shared.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if core.view("target", id).0 >= seq {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("resolver publication hang guard");
    });
}

#[test]
fn guard_drop_tombstone() -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("drop-{mode}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let id = store.initialize_inbox("target")?;
        let core = store.publication_core()?;
        let resources = ["shared-replay".to_owned(), "fanout".to_owned()];
        let first = core.reserve("target", &id, &resources)?;
        let later = core.reserve("target", &id, &resources)?;
        accept(&store, &later)?;
        assert_eq!(core.view("target", &id), (0, vec![]));
        assert_eq!(core.reservation_owners("shared-replay"), 2);
        // Early return owns no writer; the store must retain its mailbox.
        drop(first);
        await_p(&core, &id, later.sequence());
        assert_eq!(core.view("target", &id), (2, vec![(1, 1)]));
        assert_eq!(
            core.reservation_owners("shared-replay"),
            0,
            "published accepted sibling no longer retains registry metadata"
        );
        drop(later);
        // A typed failure before a store call detaches the reservation for resolution.
        let guard = core.reserve("target", &id, &[])?;
        let failed: std::result::Result<(), NodeCoreError> = {
            let _guard = guard;
            Err(NodeCoreError::Redb("injected pre-write failure".into()))
        };
        assert!(
            matches!(failed, Err(NodeCoreError::Redb(_))),
            "pre-write failure must return its typed error"
        );
        await_p(&core, &id, 3);
        // Validation error and the allocated should_persist=false branch.
        let rejected = core.reserve("target", &id, &[])?;
        rejected.definite_non_write();
        await_p(&core, &id, 4);
        assert_eq!(rejected.state(), PersistenceState::AbortedDurable);
        assert!(rejected.hand_off().is_none(), "abort claim must defeat late accepted hand-off");
        drop(rejected);
        let skipped = core.reserve("target", &id, &[])?;
        skipped.definite_non_write();
        await_p(&core, &id, 5);
        drop(skipped);
        // Cancellation does not depend on the request runtime continuing to poll.
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let cancelled = core.reserve("target", &id, &[])?;
        runtime.block_on(async move {
            let task = tokio::spawn(async move {
                let _guard = cancelled;
                std::future::pending::<()>().await;
            });
            tokio::task::yield_now().await;
            task.abort();
            assert!(task.await.expect_err("cancelled task").is_cancelled());
        });
        await_p(&core, &id, 6);
        assert_eq!(core.view("target", &id), (6, vec![(1, 1), (3, 6)]));
        abort_claim_race(&core, &root, &id)?;
        // The opposite winner: detachment after hand-off never tombstones it.
        let accepted = core.reserve("target", &id, &[])?;
        let write = accepted.hand_off().expect("accepted winner");
        let seq = accepted.sequence();
        drop(accepted);
        store.record_inbox_entry(&entry(seq))?;
        write.accepted_durable();
        await_p(&core, &id, seq);
        assert_eq!(core.view("target", &id), (8, vec![(1, 1), (3, 7)]));
        diagnostic_age(&core, &id)?;
        let expected = core.view("target", &id);
        drop(core);
        drop(store);
        let store = test_store(&root, mode, 1024 * 1024)?;
        assert_eq!(store.inbox_status("target")?, (Some(id.clone()), 9));
        let core = store.publication_core()?;
        assert_eq!(core.view("target", &id), expected, "unsettled reasons survive reopen");
        assert_eq!(core.metrics().in_flight_count, 0, "no descriptors restored live");
        assert_eq!(core.reservation_owners("shared-replay"), 0);
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn aborted_slot_capacity() -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("capacity-{mode}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let id = store.initialize_inbox("target")?;
        let core = store.publication_core()?;
        // A real accepted offline head pins settlement without using a range slot.
        let head = core.reserve("target", &id, &[])?;
        accept(&store, &head)?;
        drop(head);
        // Seed the large durable fixture in ONE real tombstone transaction,
        // rather than 4,096 wake/fsync cycles over a growing JSON row.
        seed_capacity(&store, &core, &id)?;
        drop(core);
        drop(store);
        let store = test_store(&root, mode, 1024 * 1024)?;
        let core = store.publication_core()?;
        assert_eq!(core.view("target", &id).1.len(), ABORTED_RANGE_CAPACITY - 1);
        let last = core.reserve("target", &id, &[])?;
        assert!(
            matches!(
                core.reserve("target", &id, &[]),
                Err(PublicationRefusal::CapacityRetryAfter { .. })
            ),
            "the final in-flight reservation already consumes the last slot"
        );
        let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let captured = Arc::clone(&commits);
        let observer = crate::durability_test_hooks::observe(
            root.to_path_buf(),
            Arc::new(move |_, op, done| {
                if op == "tombstone_commit" && done {
                    captured.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }),
        );
        last.definite_non_write();
        await_p(&core, &id, last.sequence());
        assert_eq!(last.state(), PersistenceState::AbortedDurable);
        assert_eq!(commits.load(Ordering::Relaxed), 1, "one real resolver commit crosses capacity");
        drop(last);
        drop(observer);
        let before = core.view("target", &id);
        assert_eq!(before.1.len(), ABORTED_RANGE_CAPACITY);
        let allocated_before = lock(&core.shared).inboxes.values().next().expect("inbox").allocated;
        let durable_before = store.inbox_status("target")?;
        assert!(matches!(
            core.reserve("target", &id, &["must-not-reserve".into()]),
            Err(PublicationRefusal::CapacityRetryAfter { retry_after_ms: 1000 })
        ));
        assert_eq!(
            lock(&core.shared).inboxes.values().next().expect("inbox").allocated,
            allocated_before,
            "capacity refusal allocates no sequence"
        );
        assert_eq!(core.view("target", &id), before);
        assert_eq!(store.inbox_status("target")?, durable_before);
        assert_eq!(core.reservation_owners("must-not-reserve"), 0);
        assert_eq!(core.metrics().in_flight_count, 0);
        drop(core);
        drop(store);
        // Slots are durable, not reset by a process restart.
        let store = test_store(&root, mode, 1024 * 1024)?;
        let core = store.publication_core()?;
        assert!(matches!(
            core.reserve("target", &id, &[]),
            Err(PublicationRefusal::CapacityRetryAfter { retry_after_ms: 1000 })
        ));
        let checkpoint = crate::CursorAckState {
            target_delivery_id: "target".into(),
            last_acknowledged_inbox_seq: Some(1),
            acked_inbox_seqs: [1, 2 * u64::try_from(ABORTED_RANGE_CAPACITY)?].into(),
            ..Default::default()
        };
        store.retain_cursor_checkpoint(&checkpoint)?;
        // Independent effect: a previously refused real allocation and accepted
        // row now complete, and the row survives reopen.
        let retry = core.reserve("target", &id, &[])?;
        assert_eq!(retry.sequence(), allocated_before + 1);
        accept(&store, &retry)?;
        drop(retry);
        drop(core);
        drop(store);
        let store = test_store(&root, mode, 1024 * 1024)?;
        let router = store.load_router()?.ok_or("router")?;
        assert!(
            router.resume("target", 0, 10).iter().any(|row| row.inbox_seq == allocated_before + 1)
        );
        let core = store.publication_core()?;
        assert_eq!(core.view("target", &id).1, Vec::<(u64, u64)>::new());
        assert!(core.reserve("target", &id, &[]).is_ok(), "slots stay released after reopen");
        drop(core);
        drop(router);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn single_worker_reply_and_drop() -> Result {
    super::view_tests::reply_liveness()?;
    crate::router_wal::fatal_tests::error_in_write()?;
    for mode in 0..=2 {
        let root = fixture(&format!("worker-{mode}"));
        let store = test_store(&root, mode, 1024 * 1024)?;
        let id = store.initialize_inbox("target")?;
        let core = store.publication_core()?;
        let caller = thread::current().id();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let observer = crate::durability_test_hooks::observe(
            root.to_path_buf(),
            Arc::new(move |_, op, done| {
                if matches!(op, "tombstone_checkpoint" | "begin_write" | "tombstone_commit") {
                    captured.lock().expect("events").push((
                        op.to_owned(),
                        done,
                        thread::current().id(),
                        thread::current().name().unwrap_or("").to_owned(),
                    ));
                }
                Ok(())
            }),
        );
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let guard = core.reserve("target", &id, &[]).expect("reserve");
            let failed: std::result::Result<(), NodeCoreError> = {
                let _guard = guard;
                Err(NodeCoreError::Redb("pre-write failure on Tokio worker".into()))
            };
            assert!(
                matches!(failed, Err(NodeCoreError::Redb(_))),
                "failed Tokio request must release the real publication guard"
            );
            tokio::task::yield_now().await;
        });
        await_p(&core, &id, 1);
        let events = events.lock().expect("events");
        for operation in ["tombstone_checkpoint", "begin_write", "tombstone_commit"] {
            for completed in [false, true] {
                assert!(
                    events.iter().any(|(op, done, tid, name)| op == operation
                        && *done == completed
                        && *tid != caller
                        && name == "ramflux-publication-resolver"),
                    "actual {operation} boundary must run off caller on resolver thread"
                );
            }
        }
        assert!(
            events.iter().all(|(_, _, tid, _)| *tid != caller),
            "no physical writes inside Drop"
        );
        drop(events);
        drop(observer);
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn abort_claim_race(core: &PublicationCore, root: &std::path::Path, id: &str) -> Result {
    // A resolver claim while its real checkpoint boundary is held forbids a
    // late continuation even before the tombstone becomes durable (M8b).
    let (entered, checkpoint_reached) = mpsc::sync_channel(1);
    let barrier = Arc::new(Barrier::new(2));
    let release = Arc::clone(&barrier);
    let observer = crate::durability_test_hooks::observe(
        root.to_path_buf(),
        Arc::new(move |_, op, done| {
            if op == "tombstone_checkpoint" && !done {
                entered.send(()).expect("observer channel");
                release.wait();
            }
            Ok(())
        }),
    );
    let racing = core.reserve("target", id, &[])?;
    racing.definite_non_write();
    checkpoint_reached.recv_timeout(Duration::from_secs(20))?;
    let forbidden = racing.hand_off();
    let won = forbidden.is_some();
    // Release the physical boundary even for the deliberately broken mutant.
    if let Some(write) = forbidden {
        std::mem::forget(write);
    }
    barrier.wait();
    assert!(!won, "accepted hand-off after abort claim");
    await_p(core, id, 7);
    drop(observer);
    drop(racing);
    Ok(())
}

fn seed_capacity(store: &RouterRedbStore, core: &PublicationCore, id: &str) -> Result {
    let descriptors = (0..ABORTED_RANGE_CAPACITY - 1)
        .map(|index| {
            Arc::new(Descriptor {
                retry_abort: OnceLock::new(),
                key: Key { target: "target".into(), incarnation: id.into() },
                seq: 3 + 2 * u64::try_from(index).expect("fixture index"),
                state: AtomicU8::new(PersistenceState::DefiniteNonWrite as u8 | ABORT_CLAIM),
                detached: AtomicBool::new(true),
                created: Instant::now(),
                warned: AtomicBool::new(false),
                resources: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    persistence::abort_batch(&core.shared, &descriptors)?;
    // A durable accepted separator keeps the final real abort non-coalescing.
    store.record_inbox_entry(&entry(2 * u64::try_from(ABORTED_RANGE_CAPACITY)?))?;
    Ok(())
}

struct WarningCounter(Arc<std::sync::atomic::AtomicUsize>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarningCounter {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() == tracing::Level::WARN {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn diagnostic_age(core: &PublicationCore, id: &str) -> Result {
    // Age is diagnostic, never a lease. Exercise the exact >30s condition
    // with the real monotonic creation time, without a 31-second sleep.
    let old = core.reserve("target", id, &[])?;
    let before = core.metrics();
    assert_eq!(before.in_flight_count, 1);
    let warnings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(WarningCounter(Arc::clone(&warnings)));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let metrics = diagnostics(&core.shared, Instant::now() + Duration::from_secs(31));
    assert_eq!(metrics.in_flight_count, 1);
    assert!(metrics.oldest_in_flight_age_seconds > 30.0);
    assert_eq!(metrics.warnings, 1);
    assert_eq!(warnings.load(Ordering::Relaxed), 1, "actual WARN event");
    assert_eq!(old.state(), PersistenceState::ReservedNoWrite);
    assert_eq!(core.view("target", id).0, 8);
    drop(old);
    await_p(core, id, 9);
    Ok(())
}

#[test]
fn fanout_reservation_is_atomic() -> Result {
    let root = fixture("fanout-reserve");
    let store = test_store(&root, 0, 1024 * 1024)?;
    let id = store.initialize_inbox("target")?;
    let core = store.publication_core()?;
    let resources = ["fanout".into()];
    assert!(matches!(
        core.reserve_batch(&[
            AssignmentReservation { target: "target", incarnation: &id, resources: &resources },
            AssignmentReservation { target: "unknown", incarnation: &id, resources: &resources },
        ]),
        Err(PublicationRefusal::IncarnationMismatch)
    ));
    assert_eq!(core.reservation_owners("fanout"), 0);
    assert_eq!(core.metrics().in_flight_count, 0);
    let guards = core.reserve_batch(&[
        AssignmentReservation { target: "target", incarnation: &id, resources: &resources },
        AssignmentReservation { target: "target", incarnation: &id, resources: &resources },
    ])?;
    assert_eq!(guards.iter().map(AssignmentGuard::sequence).collect::<Vec<_>>(), vec![1, 2]);
    drop(guards);
    await_p(&core, &id, 2);
    assert_eq!(core.view("target", &id), (2, vec![(1, 2)]));
    drop(core);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn request_guard_does_not_own_storage_shutdown() -> Result {
    let root = fixture("shutdown-owner");
    let store = test_store(&root, 0, 1024 * 1024)?;
    let id = store.initialize_inbox("target")?;
    let core = store.publication_core()?;
    let guard = core.reserve("target", &id, &[])?;
    let database = Arc::downgrade(&store.db);
    drop(core);
    drop(store);
    assert!(database.upgrade().is_none(), "request handle must not own database shutdown");
    assert_eq!(guard.state(), PersistenceState::AbortedDurable);
    assert!(guard.hand_off().is_none());
    drop(guard);
    let store = test_store(&root, 0, 1024 * 1024)?;
    assert_eq!(store.publication_core()?.view("target", &id), (1, vec![(1, 1)]));
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn resolver_error_fail_stops() -> Result {
    use std::os::unix::process::ExitStatusExt;
    use tokio::io::AsyncReadExt;
    const STDERR_BYTES: u64 = 64 * 1024;
    const DEADLINE: Duration = Duration::from_secs(30);
    if let Some(root) = std::env::var_os("RAMFLUX_RESOLVER_ERROR_CHILD") {
        let root = PathBuf::from(root);
        let mode = std::env::var("RAMFLUX_RESOLVER_ERROR_MODE")?.parse()?;
        let store = test_store(&root, mode, 1024 * 1024)?;
        let id = store.initialize_inbox("target")?;
        let core = store.publication_core()?;
        let _observer = crate::durability_test_hooks::observe(
            root,
            Arc::new(|_, op, done| {
                if op == "tombstone_checkpoint" && !done {
                    return Err(std::io::Error::other("injected resolver failure"));
                }
                Ok(())
            }),
        );
        drop(core.reserve("target", &id, &[])?);
        tokio::time::timeout(DEADLINE, std::future::pending::<()>()).await?;
        return Err("test: resolver error did not abort the process".into());
    }
    for mode in 0..=2 {
        let root = tempfile::tempdir()?;
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "router_store::publication::tests::resolver_error_fail_stops",
                "--nocapture",
            ])
            .env("RAMFLUX_RESOLVER_ERROR_CHILD", root.path())
            .env("RAMFLUX_RESOLVER_ERROR_MODE", mode.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stderr = child.stderr.take().ok_or("test: child stderr missing")?;
        let (status, bytes) = tokio::time::timeout(DEADLINE, async {
            let read = async {
                let mut bytes = Vec::new();
                stderr.take(STDERR_BYTES + 1).read_to_end(&mut bytes).await?;
                Ok::<_, std::io::Error>(bytes)
            };
            tokio::try_join!(child.wait(), read)
        })
        .await??;
        assert!(
            u64::try_from(bytes.len())? <= STDERR_BYTES,
            "test: resolver child exceeded the diagnostic limit"
        );
        assert_eq!(status.signal(), Some(6), "test: resolver failure must SIGABRT");
        assert!(
            String::from_utf8_lossy(&bytes).contains("fatal_tombstone_persistence"),
            "test: typed resolver failure must reach the fatal tombstone fence"
        );
    }
    Ok(())
}
