// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real async ingress attaches retries across allocation and durable-index windows.
#![allow(clippy::expect_used, reason = "cancellation assertions")]
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
type Reply = ramflux_node_core::EnvelopeSubmitResponse;
struct Fixture {
    root: std::path::PathBuf,
    state: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
    handle: RouterHandle,
}
impl Fixture {
    fn new(mode: u8, label: &str) -> anyhow::Result<Self> {
        let root = temp_store_path(label)?;
        let store = Arc::new(ramflux_node_core::publication::open_durability_fixture(&root, mode)?);
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        register_test_device(&state, "alice", "alice_phone", "target_alice", 1)?;
        store.record_identity_registry(&state.mvp1_identities_snapshot())?;
        store.initialize_inbox("target_alice")?;
        state.prepare_publication_target(&store, "target_alice")?;
        let handle = RouterHandle::tokio(Arc::clone(&state), Arc::clone(&store), None);
        Ok(Self { root, state, store, handle })
    }
    fn close(self) -> anyhow::Result<()> {
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
fn submit(
    handle: &RouterHandle,
    envelope: &ramflux_protocol::Envelope,
) -> tokio::task::JoinHandle<anyhow::Result<Reply>> {
    let handle = handle.clone();
    let envelope = envelope.clone();
    tokio::spawn(async move {
        handle
            .submit_envelope_async_from(
                envelope,
                Instant::now(),
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            )
            .await
    })
}
async fn join(task: tokio::task::JoinHandle<anyhow::Result<Reply>>) -> anyhow::Result<Reply> {
    tokio::time::timeout(Duration::from_secs(30), task).await??
}
async fn signal(notify: &tokio::sync::Notify) -> anyhow::Result<()> {
    Ok(tokio::time::timeout(Duration::from_secs(30), notify.notified()).await?)
}
struct Hold {
    entered: Arc<tokio::sync::Notify>,
    attached: Arc<tokio::sync::Notify>,
    durable: Arc<tokio::sync::Notify>,
    release: mpsc::Sender<()>,
    writes: Arc<AtomicUsize>,
    _observer: ramflux_node_core::durability_test_hooks::Registration,
}
fn hold(fixture: &Fixture, mode: u8, index: bool, abort: bool) -> Hold {
    let entered = Arc::new(tokio::sync::Notify::new());
    let attached = Arc::new(tokio::sync::Notify::new());
    let durable = Arc::new(tokio::sync::Notify::new());
    let writes = Arc::new(AtomicUsize::new(0));
    let (release, wait) = mpsc::channel();
    let wait = std::sync::Mutex::new(wait);
    let (reached, attached_signal, durable_signal, counted) =
        (Arc::clone(&entered), Arc::clone(&attached), Arc::clone(&durable), Arc::clone(&writes));
    let once = AtomicBool::new(false);
    let observer = ramflux_node_core::durability_test_hooks::observe(
        fixture.root.clone(),
        Arc::new(move |_, op, done| {
            if op == "retry_attached" && done {
                attached_signal.notify_one();
            }
            if op == "accepted_assignment" && done {
                counted.fetch_add(1, Ordering::Relaxed);
                durable_signal.notify_one();
            }
            let boundary = if index {
                if mode == 0 { op == "commit" && done } else { op == "index_update" && !done }
            } else {
                op == "reserved_assignment" && done
            };
            if boundary && !once.swap(true, Ordering::Relaxed) {
                reached.notify_one();
                wait.lock()
                    .map_err(|_| std::io::Error::other("release lock"))?
                    .recv_timeout(Duration::from_secs(30))
                    .map_err(std::io::Error::other)?;
                if abort {
                    return Err(std::io::Error::other("proved pre-handoff refusal"));
                }
            }
            Ok(())
        }),
    );
    Hold { entered, attached, durable, release, writes, _observer: observer }
}
fn changed(
    envelope: &ramflux_protocol::Envelope,
    state: &ramflux_node_core::RouterCore,
) -> anyhow::Result<ramflux_protocol::Envelope> {
    let mut changed = envelope.clone();
    changed.encrypted_payload.push('x');
    changed.ext.ext.remove("source_device_authority");
    changed.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(
        &changed,
        ramflux_crypto::blake3_256("ramflux.test.runtime.device.v1", b"alice/alice_phone"),
    )?;
    state.refresh_registered_envelope_authority(&mut changed)?;
    Ok(changed)
}

#[tokio::test]
async fn unresolved_identical_retry() -> anyhow::Result<()> {
    for mode in 0..3 {
        for index in [false, true] {
            unresolved_case(mode, index).await?;
        }
    }
    Ok(())
}
async fn unresolved_case(mode: u8, index: bool) -> anyhow::Result<()> {
    let fixture = Fixture::new(mode, &format!("retry-window-{mode}-{index}"))?;
    let core = fixture.store.publication_core()?;
    let id =
        fixture.store.inbox_status("target_alice")?.0.ok_or_else(|| anyhow::anyhow!("identity"))?;
    let predecessor = core.reserve("target_alice", &id, &[])?;
    let envelope = current_envelope("same-envelope", "target_alice")?;
    let held = hold(&fixture, mode, index, false);
    let original = submit(&fixture.handle, &envelope);
    signal(&held.entered).await?;
    let retry = submit(&fixture.handle, &envelope);
    signal(&held.attached).await?;
    let cancelled = submit(&fixture.handle, &envelope);
    signal(&held.attached).await?;
    cancelled.abort();
    assert!(cancelled.await.expect_err("cancelled waiter").is_cancelled());
    let conflict = join(submit(&fixture.handle, &changed(&envelope, &fixture.state)?)).await?;
    assert_eq!(conflict.outcome, "idempotency_conflict");
    assert!(!original.is_finished());
    assert!(!retry.is_finished());
    held.release.send(())?;
    signal(&held.durable).await?;
    let durable_retry = submit(&fixture.handle, &envelope);
    tokio::task::yield_now().await;
    assert_eq!(core.view("target_alice", &id).0, 0);
    assert!(!original.is_finished());
    assert!(!retry.is_finished());
    assert!(!durable_retry.is_finished());
    predecessor.definite_non_write();
    for reply in [join(original).await?, join(retry).await?, join(durable_retry).await?] {
        assert!(matches!(reply.outcome.as_str(), "online" | "offline_queued"));
        assert_eq!(reply.inbox_seq, Some(2));
    }
    assert_eq!(held.writes.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.store.sender_retry_registry_size(), 0);
    assert_eq!(fixture.state.resume("target_alice", 0, 10).len(), 1);
    assert_eq!(fixture.store.inbox_status("target_alice")?, (Some(id), 2));
    drop(predecessor);
    drop(held);
    drop(core);
    fixture.close()
}

#[tokio::test]
async fn aborted_and_durable_sender_retry() -> anyhow::Result<()> {
    if std::env::var_os("RAMFLUX_P7_RETRY_CHILD").is_some() {
        return crash_child().await;
    }
    for mode in 0..3 {
        for restart in [false, true] {
            aborted_case(mode, restart).await?;
        }
        crash_retry(mode).await?;
    }
    Ok(())
}
async fn aborted_case(mode: u8, restart: bool) -> anyhow::Result<()> {
    let mut fixture = Fixture::new(mode, &format!("retry-abort-{mode}-{restart}"))?;
    let envelope = current_envelope("abort-original", "target_alice")?;
    let held = hold(&fixture, mode, false, true);
    let original = submit(&fixture.handle, &envelope);
    signal(&held.entered).await?;
    let retry = submit(&fixture.handle, &envelope);
    signal(&held.attached).await?;
    held.release.send(())?;
    assert_eq!(join(original).await?.outcome, "aborted_retry_safe");
    assert_eq!(join(retry).await?.outcome, "aborted_retry_safe");
    assert_eq!(held.writes.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.store.sender_retry_registry_size(), 0);
    assert_eq!(fixture.state.resume("target_alice", 0, 10), []);
    drop(held);
    if restart {
        fixture = reopen(fixture, mode)?;
    }
    let accepted = join(submit(&fixture.handle, &envelope)).await?;
    assert_eq!(accepted.inbox_seq, Some(2));
    let root = envelope.ext.ext["source_root_commitment"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("root"))?;
    let original = fixture
        .store
        .sender_assignment(root, &envelope, envelope.created_at)?
        .ok_or_else(|| anyhow::anyhow!("assignment"))?;
    assert_eq!(join(submit(&fixture.handle, &envelope)).await?.inbox_seq, Some(2));
    fixture = reopen(fixture, mode)?;
    assert_eq!(join(submit(&fixture.handle, &envelope)).await?.inbox_seq, Some(2));
    assert_eq!(
        fixture.store.sender_assignment(root, &envelope, envelope.created_at)?,
        Some(original)
    );
    assert_eq!(fixture.state.resume("target_alice", 0, 10).len(), 1);
    fixture.close()
}
fn reopen(fixture: Fixture, mode: u8) -> anyhow::Result<Fixture> {
    let root = fixture.root.clone();
    drop(fixture);
    let store = Arc::new(ramflux_node_core::publication::open_durability_fixture(&root, mode)?);
    let state = Arc::new(store.load_router()?.ok_or_else(|| anyhow::anyhow!("restored router"))?);
    let handle = RouterHandle::tokio(Arc::clone(&state), Arc::clone(&store), None);
    Ok(Fixture { root, state, store, handle })
}
async fn crash_child() -> anyhow::Result<()> {
    let mode: u8 = std::env::var("RAMFLUX_P7_RETRY_MODE")?.parse()?;
    let fixture = Fixture::new(mode, "retry-crash-child")?;
    let root = std::path::PathBuf::from(
        std::env::var_os("RAMFLUX_P7_RETRY_CHILD").ok_or_else(|| anyhow::anyhow!("root"))?,
    );
    let core = fixture.store.publication_core()?;
    let id = fixture.store.inbox_status("target_alice")?.0.ok_or_else(|| anyhow::anyhow!("id"))?;
    let _predecessor = core.reserve("target_alice", &id, &[])?;
    let envelope = current_envelope("durable-before-loss", "target_alice")?;
    let held = hold(&fixture, mode, false, false);
    let reply = submit(&fixture.handle, &envelope);
    signal(&held.entered).await?;
    held.release.send(())?;
    signal(&held.durable).await?;
    assert!(!reply.is_finished());
    assert_eq!(core.view("target_alice", &id).0, 0);
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("proof"), serde_json::to_vec(&(fixture.root.clone(), id, envelope))?)?;
    std::process::abort();
}
async fn crash_retry(mode: u8) -> anyhow::Result<()> {
    let control = temp_store_path(&format!("retry-crash-proof-{mode}"))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "router_runtime::tests::sender_retry::aborted_and_durable_sender_retry",
            "--nocapture",
        ])
        .env("RAMFLUX_P7_RETRY_CHILD", &control)
        .env("RAMFLUX_P7_RETRY_MODE", mode.to_string())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("crash child watchdog");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6));
    }
    let (root, id, envelope): (std::path::PathBuf, String, ramflux_protocol::Envelope) =
        serde_json::from_slice(&std::fs::read(control.join("proof"))?)?;
    let store = Arc::new(ramflux_node_core::publication::open_durability_fixture(&root, mode)?);
    let state = Arc::new(store.load_router()?.ok_or_else(|| anyhow::anyhow!("recovery"))?);
    let handle = RouterHandle::tokio(Arc::clone(&state), Arc::clone(&store), None);
    let fixture = Fixture { root, state, store, handle };
    assert_eq!(join(submit(&fixture.handle, &envelope)).await?.inbox_seq, Some(2));
    assert_eq!(fixture.store.inbox_status("target_alice")?, (Some(id), 2));
    assert_eq!(fixture.state.resume("target_alice", 0, 10).len(), 1);
    fixture.close()?;
    std::fs::remove_dir_all(control)?;
    Ok(())
}

#[tokio::test]
async fn capacity_refusal_leaves_no_sender_effect() -> anyhow::Result<()> {
    let fixture = Fixture::new(0, "retry-capacity")?;
    let core = fixture.store.publication_core()?;
    let id = fixture.store.inbox_status("target_alice")?.0.ok_or_else(|| anyhow::anyhow!("id"))?;
    let guards = (0..ramflux_node_core::publication::ABORTED_RANGE_CAPACITY)
        .map(|_| core.reserve("target_alice", &id, &[]))
        .collect::<Result<Vec<_>, _>>()?;
    let envelope = current_envelope("capacity-original", "target_alice")?;
    let refused = join(submit(&fixture.handle, &envelope)).await?;
    assert_eq!(refused.outcome, "capacity_retry_after");
    assert_eq!(fixture.store.sender_retry_registry_size(), 0);
    assert_eq!(fixture.state.resume("target_alice", 0, 10), []);
    assert_eq!(fixture.store.inbox_status("target_alice")?.1, 0);
    for guard in &guards {
        guard.definite_non_write();
    }
    core.wait_published(guards.last().expect("capacity guards")).await;
    let accepted = join(submit(&fixture.handle, &envelope)).await?;
    assert_eq!(accepted.inbox_seq, Some(4097), "capacity refusal must release tentative replay");
    assert_eq!(fixture.state.resume("target_alice", 0, 10).len(), 1);
    drop(guards);
    drop(core);
    fixture.close()
}

#[test]
fn forwarded_conflict_uses_typed_refusal_reply() -> anyhow::Result<()> {
    let fixture = Fixture::new(0, "forwarded-retry-refusal")?;
    let envelope = current_envelope("forwarded-conflict", "target_alice")?;
    let source = fixture.state.authenticated_envelope_source_durable(&envelope, &fixture.store)?;
    let owner = fixture.store.admit_sender_retry(&source, &envelope, envelope.created_at)?;
    let reply = fixture.handle.submit_forwarded(ramflux_node_core::ForwardedEnvelopeRequest {
        peer_node_id: "test-peer".into(),
        envelope: changed(&envelope, &fixture.state)?,
        migration_evidence: None,
    })?;
    assert_eq!(reply["accepted"], false);
    assert_eq!(reply["retryable"], false);
    assert_eq!(reply["reason"], "idempotency_conflict");
    assert_eq!(fixture.store.inbox_status("target_alice")?.1, 0);
    drop(owner);
    fixture.close()
}
