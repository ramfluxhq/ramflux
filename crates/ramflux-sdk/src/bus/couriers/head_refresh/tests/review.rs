// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Demand preemption, failure backoff, and timer priority under repeated wakes.
use super::*;

async fn next_work(receiver: &mut mpsc::Receiver<AccountWork>) -> TestResult<Work> {
    let AccountWork::Directory(work) =
        tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await?
            .ok_or("writer closed")?
    else {
        return Err("wrong work".into());
    };
    let super::super::super::directory::DirectoryWork::HeadRefresh(work) = *work else {
        return Err("wrong directory work".into());
    };
    Ok(work)
}

#[tokio::test]
async fn demand_during_large_connect_sweep_refreshes_before_network_wait() -> TestResult {
    let (mut account, native, _io) = account().await?;
    account.head_refresh = RefreshState::default();
    let own = account.principal_commitment.clone();
    let mut manifests =
        std::collections::BTreeMap::from([(own.clone(), serde_json::to_value(&native.manifest)?)]);
    for index in 0..64 {
        let peer = crate::client::identity_authority::test_support::remote_manifest(
            &format!("demand-sweep-{index:02}"),
            "primary",
            [index + 1; 32],
        )?;
        account.client.establish_friend_link(
            &format!("link-{index}"),
            &own,
            &peer.principal_commitment,
        )?;
        manifests.insert(peer.principal_commitment.clone(), serde_json::to_value(peer)?);
    }
    let target = manifests.keys().next_back().ok_or("target")?.clone();
    let (address, server) =
        crate::bus::dispatch::surface_transport::fixture::directory(&native.root.0, manifests)
            .await?;
    account.gateway_config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    account.gateway_config.gateway_addr = address;
    account.gateway_config.tcp_gateway_addr = Some(address);
    account.gateway_config.server_name = "test-gateway".into();
    account.gateway_config.ca_cert = native.root.0.join("ca.pem");
    let handle = account.connection.as_ref().ok_or("connection")?.clone();
    let (writer, mut receiver) = mpsc::channel(2);
    let child = tokio::spawn(run_with_triggers(handle.test_context(), writer, true, false));
    let mut fetched = BTreeSet::new();
    while fetched.len() < PASS_ROOTS {
        let work = next_work(&mut receiver).await?;
        if let Work::Apply { root, outcome, .. } = &work {
            assert!(outcome.is_ok());
            fetched.insert(root.clone());
        }
        apply_work(&mut account, work);
    }
    assert!(!fetched.contains(&target), "target must still be behind the sweep");
    let admitted = tokio::time::Instant::now();
    account.head_refresh.enqueue(target.clone());
    loop {
        let work = next_work(&mut receiver).await?;
        if let Work::Apply { root, outcome, .. } = &work {
            assert_eq!(root, &target, "a demand must precede the next sweep fetch");
            assert!(outcome.is_ok());
            apply_work(&mut account, work);
            break;
        }
        apply_work(&mut account, work);
    }
    assert!(admitted.elapsed() < Duration::from_secs(5));
    assert!(!account.head_refresh.pending.contains(&target));
    child.abort();
    let _ = child.await;
    handle.stop().await;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn repeated_demand_cannot_starve_timer_and_failed_roots_back_off() -> TestResult {
    let (mut account, _native, _io) = account().await?;
    let handle = account.connection.as_ref().ok_or("connection")?.clone();
    let root = account.principal_commitment.clone();
    let requested = fence(&account)?;
    let plan = prepare(&mut account, requested.clone())?.ok_or("plan")?;
    let wake = account.head_refresh.wake.clone();
    wake.notified().await; // consume the fixture's initial demand permit
    assert!(account.head_refresh.enqueue(root.clone()));
    assert!(
        tokio::time::timeout(Duration::from_millis(1), wake.notified()).await.is_err(),
        "duplicate demand while active must not wake the child"
    );
    tokio::time::pause();
    assert!(
        apply(
            &mut account,
            &plan,
            &root,
            Instant::now(),
            Err(ramflux_transport::TransportError::NotOpen.into())
        )
        .is_err()
    );
    drop(plan);
    assert!(prepare(&mut account, requested.clone())?.is_none(), "failed root must back off");
    assert!(account.head_refresh.enqueue(root.clone()));
    assert!(
        prepare(&mut account, requested.clone())?.is_none(),
        "polling must preserve failure backoff"
    );
    tokio::time::advance(Duration::from_secs(5)).await;
    let retry = prepare(&mut account, requested.clone())?.ok_or("retry after backoff")?;
    assert!(
        apply(
            &mut account,
            &retry,
            &root,
            Instant::now(),
            Err(ramflux_transport::TransportError::NotOpen.into())
        )
        .is_err()
    );
    drop(retry);
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(
        prepare(&mut account, requested.clone())?.is_none(),
        "repeated failures increase backoff"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    drop(prepare(&mut account, requested)?.ok_or("second retry")?);
    tokio::time::resume();

    // Hold a demand Prepare while the timer becomes due and another wake queues.
    // A Prepare error must also leave the registered child alive for that timer.
    let (writer, mut receiver) = mpsc::channel(2);
    let child = tokio::spawn(run_with_triggers(handle.test_context(), writer, false, true));
    let Work::Subscribe { reply } = next_work(&mut receiver).await? else {
        return Err("subscribe".into());
    };
    let wake = Arc::new(tokio::sync::Notify::new());
    reply.send(wake.clone()).map_err(|_| "subscribe reply")?;
    wake.notify_one();
    let Work::Prepare { reply, periodic, .. } = next_work(&mut receiver).await? else {
        return Err("demand prepare".into());
    };
    assert!(!periodic);
    tokio::time::pause();
    tokio::time::advance(REFRESH_INTERVAL).await;
    wake.notify_one();
    reply
        .send(Err(SdkError::Io(std::io::Error::other("temporary prepare failure"))))
        .map_err(|_| "prepare reply")?;
    let Work::Prepare { reply, periodic, .. } = next_work(&mut receiver).await? else {
        return Err("timer prepare".into());
    };
    assert!(periodic, "due timer must win even with a queued demand wake");
    reply.send(Ok(None)).map_err(|_| "timer reply")?;
    tokio::time::resume();
    child.abort();
    let _ = child.await;
    handle.stop().await;
    Ok(())
}
