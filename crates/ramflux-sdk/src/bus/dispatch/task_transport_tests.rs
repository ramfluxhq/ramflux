// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Task carrier and own-control frame limits through the real encrypted transport adapters.
use super::*;

#[tokio::test]
async fn confirmation_preparation_allows_slow_verified_directory_refresh() {
    let outcome = super::await_preparation(
        async { Ok::<_, SdkError>(()) },
        "task confirmation preparation deferred",
    )
    .await;
    assert!(
        matches!(outcome, Ok(super::Preparation::Ready(()))),
        "a ready verified directory refresh must remain deliverable"
    );
}

#[tokio::test]
async fn manifest_worker_capacity_is_the_only_retry_neutral_preparation_outcome() {
    let deferred = super::await_preparation(
        async { Err::<(), _>(SdkError::TaskManifestWorkerCapacity) },
        "worker-cap preparation",
    )
    .await;
    assert!(matches!(deferred, Ok(super::Preparation::Deferred)));

    let charged = super::await_preparation(
        async { Err::<(), _>(SdkError::InboundPending("transport timeout".into())) },
        "charged preparation timeout",
    )
    .await;
    assert!(matches!(
        charged,
        Err(SdkError::InboundPending(_)
            | SdkError::SenderManifestRequired { .. }
            | SdkError::FreshHeadRequired { .. })
    ));
}

#[tokio::test]
async fn stalled_federated_manifest_fetch_respects_the_preparation_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpListener;
    use std::sync::mpsc;

    tokio::time::timeout(Duration::from_secs(30), async {
        let _guard = manifest_test_lock().lock().await;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let server = std::thread::spawn(move || -> Result<(), String> {
            let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
            accepted_tx.send(()).map_err(|error| error.to_string())?;
            release_rx.recv_timeout(Duration::from_secs(10)).map_err(|error| error.to_string())?;
            drop(stream);
            Ok(())
        });
        let started = std::time::Instant::now();
        let outcome = super::await_preparation(
            super::fetch_federated_manifest(&format!("http://{address}"), "stalled-root"),
            "task federated manifest preparation deferred",
        )
        .await;
        assert!(
            !matches!(outcome, Ok(super::Preparation::Ready(_))),
            "a stalled fetch must report its per-item timeout"
        );
        assert!(started.elapsed() < Duration::from_secs(7));
        accepted_rx.recv_timeout(Duration::from_secs(1))?;
        release_tx.send(())?;
        server.join().map_err(|_| "stalled manifest server panicked")??;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "stalled manifest test exceeded its outer timeout")??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_stalled_manifest_fetches_never_exceed_the_global_worker_cap()
-> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpListener;

    tokio::time::timeout(Duration::from_secs(12), async {
        let _guard = manifest_test_lock().lock().await;
        let listeners =
            (0..12).map(|_| TcpListener::bind("127.0.0.1:0")).collect::<Result<Vec<_>, _>>()?;
        let urls = listeners
            .iter()
            .map(|listener| listener.local_addr().map(|address| format!("http://{address}")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut jobs = tokio::task::JoinSet::new();
        for (index, url) in urls.into_iter().enumerate() {
            jobs.spawn(async move {
                super::fetch_federated_manifest(&url, &format!("stalled-{index}")).await
            });
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire) <= 4);
        let mut capacity_deferrals = 0;
        while let Some(result) = jobs.join_next().await {
            if matches!(result?, Err(SdkError::TaskManifestWorkerCapacity)) {
                capacity_deferrals += 1;
            }
        }
        assert!(capacity_deferrals >= 8, "excess stalled fetches must be deferred");
        drop(listeners);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "manifest worker cap regression exceeded its outer timeout")??;
    Ok(())
}

#[tokio::test]
async fn manifest_flight_guard_releases_errors_and_groups_by_full_manifest_url()
-> Result<(), Box<dyn std::error::Error>> {
    let _test_guard = manifest_test_lock().lock().await;
    let before = super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire);
    let first = match super::reserve_manifest_flight("http://node/manifest/root-a")? {
        super::ManifestReservation::Start(guard) => guard,
        super::ManifestReservation::Wait(_) => {
            return Err("unexpected existing first flight".into());
        }
    };
    let second = match super::reserve_manifest_flight("http://node/manifest/root-b")? {
        super::ManifestReservation::Start(guard) => guard,
        super::ManifestReservation::Wait(_) => {
            return Err("distinct manifest URL was grouped".into());
        }
    };
    assert!(matches!(
        super::reserve_manifest_flight("http://node/manifest/root-a")?,
        super::ManifestReservation::Wait(_)
    ));
    assert_eq!(
        super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire),
        before + 2
    );
    let failed: Result<(), SdkError> = {
        let _guard = first;
        Err(SdkError::GatewaySessionRejected("manifest worker failure".into()))
    };
    assert!(
        matches!(failed, Err(SdkError::GatewaySessionRejected(_))),
        "test: failed manifest work must return a typed error and release its flight"
    );
    assert_eq!(
        super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire),
        before + 1
    );
    drop(second);
    assert_eq!(super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire), before);
    Ok(())
}
