// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Forward admission, worker completion, and restart regressions.
use super::*;

fn reservation(
    handle: &RouterHandle,
    id: &str,
) -> anyhow::Result<Box<ramflux_node_core::RouterForwardReservation>> {
    let envelope = current_envelope(id, "target_alice")?;
    let source = handle.state().authenticated_envelope_source_durable(&envelope, handle.store())?;
    match handle.state().prepare_committed_home_forward(
        handle.store(),
        &source,
        envelope,
        ramflux_node_core::now_unix_seconds(),
        20,
    )? {
        ramflux_node_core::RouterForwardPreparation::Forward(reservation) => Ok(reservation),
        ramflux_node_core::RouterForwardPreparation::Complete(_) => {
            anyhow::bail!("expected forward reservation")
        }
    }
}

#[test]
fn timeout_branch_releases_reservation_and_worker_releases_permit() -> anyhow::Result<()> {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let (handle, _) = migrated_test_handle("http://127.0.0.1:1/", 1, Duration::from_secs(20), now)?;
    runtime.block_on(async {
        let attempt = reservation(&handle, "timeout-branch")?;
        let RouterHandle::Tokio(inner) = &handle;
        let permit = Arc::clone(&inner.forward_semaphore).try_acquire_owned()?;
        let (release, receiver) = mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _ = receiver.recv_timeout(Duration::from_secs(2));
            Err(ramflux_node_core::NodeCoreError::ForwardTimeout { phase: "socket" })
        });
        let result = crate::router_engine::complete_forward_worker(
            handle.state(),
            attempt,
            Duration::from_millis(10),
            worker,
        )
        .await;
        assert!(matches!(result, ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { .. }));
        // The live blocking worker remains counted; cancellation cannot over-admit.
        assert_eq!(inner.forward_semaphore.available_permits(), 0);
        drop(reservation(&handle, "timeout-branch")?);
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while inner.forward_semaphore.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok::<(), anyhow::Error>(())
    })
}

#[test]
fn worker_join_failure_releases_reservation_and_permit() -> anyhow::Result<()> {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let (handle, _) = migrated_test_handle("http://127.0.0.1:1/", 1, Duration::from_secs(20), now)?;
    runtime.block_on(async {
        let attempt = reservation(&handle, "join-failure")?;
        let RouterHandle::Tokio(inner) = &handle;
        let permit = Arc::clone(&inner.forward_semaphore).try_acquire_owned()?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            // A resumed unwind produces a real JoinError without a panic lint allowance.
            std::panic::resume_unwind(Box::new("forward worker stopped"));
        });
        let result = crate::router_engine::complete_forward_worker(
            handle.state(),
            attempt,
            Duration::from_secs(1),
            worker,
        )
        .await;
        assert!(matches!(result, ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { .. }));
        assert_eq!(inner.forward_semaphore.available_permits(), 1);
        drop(reservation(&handle, "join-failure")?);
        Ok::<(), anyhow::Error>(())
    })
}

#[test]
fn tcp_and_async_ingress_share_exact_forward_capacity() -> anyhow::Result<()> {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/forward", listener.local_addr()?);
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let (handle, _) = migrated_test_handle(&url, 2, Duration::from_secs(20), now)?;
    let handle = Arc::new(handle);
    let (entered, receiver) = mpsc::channel();
    let mut servers = Vec::new();
    let mut releases = Vec::new();
    for _ in 0..2 {
        let listener = listener.try_clone()?;
        let entered = entered.clone();
        let (release, wait) = mpsc::channel();
        releases.push(release);
        servers.push(thread::spawn(move || run_held_forward_responder(&listener, &entered, &wait)));
    }
    let tcp_handle = Arc::clone(&handle);
    let tcp = thread::spawn(move || {
        tcp_handle.submit_envelope_from(
            current_envelope("tcp-forward", "target_alice")?,
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        )
    });
    let async_handle = Arc::clone(&handle);
    let asynchronous = runtime.spawn(async move {
        async_handle
            .submit_envelope_async_from(
                current_envelope("async-forward", "target_alice")?,
                Instant::now(),
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            )
            .await
    });
    receiver.recv_timeout(Duration::from_secs(5))?;
    receiver.recv_timeout(Duration::from_secs(5))?;
    let RouterHandle::Tokio(inner) = handle.as_ref();
    assert_eq!(inner.forward_semaphore.available_permits(), 0);
    let refused = handle.submit_envelope_from(
        current_envelope("tcp-refused", "target_alice")?,
        Instant::now(),
        ramflux_node_core::RouterEnvelopeOrigin::Gateway,
    )?;
    assert_eq!(refused.outcome, "forward_in_progress");
    assert!(refused.nack.is_none());
    assert!(receiver.try_recv().is_err());
    for release in releases {
        release.send(())?;
    }
    tcp.join().map_err(|_| anyhow::anyhow!("TCP worker failed"))??;
    runtime.block_on(asynchronous)??;
    for server in servers {
        server.join().map_err(|_| anyhow::anyhow!("server failed"))?.map_err(anyhow::Error::msg)?;
    }
    assert_eq!(inner.forward_semaphore.available_permits(), 2);
    Ok(())
}

#[test]
fn migrated_forward_remains_enabled_after_restart() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/forward", listener.local_addr()?);
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let (handle, path) = migrated_test_handle(&url, 1, Duration::from_secs(20), now)?;
    handle.store().save_router(handle.state())?;
    drop(handle);
    let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
    let state =
        Arc::new(store.load_router()?.ok_or_else(|| anyhow::anyhow!("missing restored node"))?);
    let handle = RouterHandle::tokio(
        state,
        store,
        Some(LocalFederationForwardClient {
            url,
            admin_token: Some("local-token".into()),
            source_node_id: "node-old.example".into(),
        }),
    );
    let (entered, receiver) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    release.send(())?;
    let server = thread::spawn(move || run_held_forward_responder(&listener, &entered, &wait));
    let response = handle.submit_envelope_from(
        current_envelope("after-restart", "target_alice")?,
        Instant::now(),
        ramflux_node_core::RouterEnvelopeOrigin::Gateway,
    )?;
    receiver.recv_timeout(Duration::from_secs(5))?;
    assert_eq!(response.outcome, "forward_in_progress");
    assert_eq!(handle.state().resume("target_alice", 0, 10), []);
    server.join().map_err(|_| anyhow::anyhow!("server failed"))?.map_err(anyhow::Error::msg)?;
    Ok(())
}

#[test]
fn committed_forward_checks_cutover_without_claiming_local_delivery_on_both_ingress_paths()
-> anyhow::Result<()> {
    use ramflux_protocol::home_migration::{DeliveryMapEntry, Refusal};
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    for asynchronous in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
        let (handle, _) = migrated_test_handle(
            &format!("http://{}/forward", listener.local_addr()?),
            1,
            Duration::from_secs(10),
            now,
        )?;
        let handle = Arc::new(handle);
        let envelope = current_envelope("lease-forward-persist", "target_alice")?;
        let source =
            handle.state().authenticated_envelope_source_durable(&envelope, handle.store())?;
        let map = [DeliveryMapEntry {
            device_ref: ramflux_protocol::custody::DeviceRef {
                account_anchor: "anchor".into(),
                device_id: "alice_phone".into(),
                device_epoch: 1,
            },
            target_delivery_id: "target_alice".into(),
        }];
        let cutover = handle.store().migration_submission_barrier(&map)?;
        let refused = if asynchronous {
            runtime.block_on(handle.submit_envelope_async_from(
                envelope.clone(),
                Instant::now(),
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            ))?
        } else {
            handle.submit_envelope_from(
                envelope.clone(),
                Instant::now(),
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            )?
        };
        assert_eq!(refused.migration_refusal, Some(Refusal::MigrationInProgress));
        assert_eq!(refused.inbox_seq, None);
        assert_eq!(
            listener.accept().err().map(|error| error.kind()),
            Some(std::io::ErrorKind::WouldBlock)
        );
        drop(cutover);
        listener.set_nonblocking(false)?;
        let (entered, receiver) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let server = thread::spawn(move || successful_held_forward(&listener, &entered, &wait));
        let sender = Arc::clone(&handle);
        let message = envelope.clone();
        let submit = thread::spawn(move || {
            if asynchronous {
                tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(
                    sender.submit_envelope_async_from(
                        message,
                        Instant::now(),
                        ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                    ),
                )
            } else {
                sender.submit_envelope_from(
                    message,
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                )
            }
        });
        receiver.recv_timeout(Duration::from_secs(5))?;
        let barrier = handle.store().migration_submission_barrier(&map);
        let before =
            handle.store().load_router()?.ok_or_else(|| anyhow::anyhow!("missing router"))?;
        let before_replay = before.accept_envelope_replay(&source, envelope.clone(), now);
        release.send(())?;
        let response = submit.join().map_err(|_| anyhow::anyhow!("submit worker failed"))??;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("forward worker failed"))?
            .map_err(anyhow::Error::msg)?;
        // Committed forwards do not enter the old home's mailbox or take its submission lease.
        drop(barrier?);
        assert!(before_replay.is_ok(), "in-flight forward is not durably accepted");
        assert_eq!(response.outcome, "forwarded_home_node_migrated");
        assert_eq!(response.inbox_seq, Some(37));
        assert_eq!(handle.state().resume("target_alice", 0, 10), []);
        let restored =
            handle.store().load_router()?.ok_or_else(|| anyhow::anyhow!("missing router"))?;
        assert!(
            restored.accept_envelope_replay(&source, envelope, now).is_ok(),
            "destination acceptance does not create local acceptance at the former home"
        );
        assert_eq!(restored.resume("target_alice", 0, 10), []);
        drop(handle.store().migration_submission_barrier(&map)?);
    }
    Ok(())
}

fn successful_held_forward(
    listener: &TcpListener,
    entered: &mpsc::Sender<()>,
    wait: &mpsc::Receiver<()>,
) -> Result<(), String> {
    let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    let request = ramflux_node_core::read_itest_http_request(&mut stream)
        .map_err(|e| e.to_string())?
        .ok_or("missing forward request")?;
    assert_eq!(request.path, "/forward");
    let body: serde_json::Value =
        serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
    let forward: ramflux_node_core::FederatedEnvelopeForwardRequest =
        serde_json::from_value(body["forward"].clone()).map_err(|e| e.to_string())?;
    entered.send(()).map_err(|e| e.to_string())?;
    wait.recv_timeout(Duration::from_secs(5)).map_err(|e| e.to_string())?;
    let mut response = rejected_migration_forward(forward);
    response.accepted = true;
    response.delivery.outcome = "offline_queued".into();
    response.delivery.inbox_seq = Some(37);
    ramflux_node_core::write_itest_json_response(&mut stream, "200 OK", &response)
        .map_err(|e| e.to_string())
}
