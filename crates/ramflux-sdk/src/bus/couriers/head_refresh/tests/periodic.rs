// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Trigger isolation, actual directory fetches and fair bounded continuation.
use super::*;

async fn next_work(receiver: &mut mpsc::Receiver<AccountWork>) -> TestResult<Work> {
    let outcome = tokio::time::timeout(Duration::from_secs(1), receiver.recv()).await;
    assert!(outcome.is_ok(), "refresh trigger must produce writer work before any other trigger");
    let AccountWork::Directory(message) = outcome?.ok_or("writer closed")? else {
        return Err("wrong work".into());
    };
    let super::super::super::directory::DirectoryWork::HeadRefresh(message) = *message else {
        return Err("wrong directory work".into());
    };
    Ok(message)
}

async fn drain(
    account: &mut LocalBusAccountState,
    receiver: &mut mpsc::Receiver<AccountWork>,
    count: usize,
) -> TestResult<BTreeSet<String>> {
    let mut fetched = BTreeSet::new();
    while fetched.len() < count {
        let work = next_work(receiver).await?;
        match &work {
            Work::Apply { root, outcome, .. } => {
                assert!(outcome.is_ok(), "actual TLS directory fetch failed: {root}");
                assert!(fetched.insert(root.clone()), "root fetched twice in the same sweep");
            }
            Work::Prepare { .. } => {
                assert!(account.head_refresh.active.upgrade().is_none(), "single pass");
            }
            Work::Subscribe { .. } => {}
        }
        apply_work(account, work);
        assert!(account.head_refresh.pending.len() <= MAX_PENDING);
    }
    Ok(fetched)
}

#[tokio::test]
async fn refresh_runs_at_connect_and_half_bound() -> TestResult {
    let (mut account, native, _io) = account().await?;
    // No pending demand or stored Notify permit; only connect can start work.
    account.head_refresh = RefreshState::default();
    let own = account.principal_commitment.clone();
    let mut manifests =
        std::collections::BTreeMap::from([(own.clone(), serde_json::to_value(&native.manifest)?)]);
    for index in 0..40 {
        let peer = crate::client::identity_authority::test_support::remote_manifest(
            &format!("periodic-{index:02}"),
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
    let expected: BTreeSet<_> = manifests.keys().cloned().collect();
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
    assert_eq!(drain(&mut account, &mut receiver, expected.len()).await?, expected);
    assert!(fresh(&account, &native)?, "connect alone must fetch own head");
    assert!(account.head_refresh.pending.is_empty(), "no demand manufactured");
    child.abort();
    let _ = child.await;
    tokio::task::yield_now().await;

    // Make own head due using its conservative observation, without a real wait.
    let old = Instant::now().checked_sub(REFRESH_INTERVAL).ok_or("clock")?;
    *account.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    account.client.persist_fetched_identity_directory_at(&native.manifest, old)?;
    let (writer, mut receiver) = mpsc::channel(2);
    // Separate child: connect disabled, no demand. Only its timer may run.
    let child = tokio::spawn(run_with_triggers(handle.test_context(), writer, false, true));
    let subscribe = next_work(&mut receiver).await?;
    assert!(matches!(subscribe, Work::Subscribe { .. }));
    apply_work(&mut account, subscribe);
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(149)).await;
    tokio::task::yield_now().await;
    assert!(receiver.try_recv().is_err(), "timer must not fire before 150 seconds");
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    tokio::time::resume();
    assert_eq!(drain(&mut account, &mut receiver, expected.len()).await?, expected);
    child.abort();
    let _ = child.await;
    handle.stop().await;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn failed_pending_roots_continue_fairly_and_periodic_roots_do_not_fill_demand_capacity()
-> TestResult {
    let (mut account, _native, _io) = account().await?;
    for index in 0..MAX_PENDING + 40 {
        let root = format!("peer-{index:04}");
        account.client.establish_friend_link(
            &format!("link-{index}"),
            &account.principal_commitment,
            &root,
        )?;
        if index < MAX_PENDING - 1 {
            assert!(account.head_refresh.enqueue(root));
        }
    }
    assert_eq!(account.head_refresh.pending.len(), MAX_PENDING);
    assert!(!account.head_refresh.enqueue("overflow".into()));
    let mut demanded = BTreeSet::new();
    for _ in 0..MAX_PENDING.div_ceil(PASS_ROOTS) {
        let requested = fence(&account)?;
        let plan = prepare(&mut account, requested)?.ok_or("demand plan")?;
        demanded.extend(plan.roots.iter().cloned());
        drop(plan);
    }
    assert_eq!(demanded, account.head_refresh.pending, "failed demand prefixes must rotate too");
    let expected = eligible_roots(&account)?;
    let mut seen = BTreeSet::new();
    for _ in 0..expected.len().div_ceil(PASS_ROOTS) {
        let requested = fence(&account)?;
        let plan =
            prepare_due(&mut account, requested.clone(), true, &BTreeSet::new())?.ok_or("plan")?;
        assert!(plan.roots.len() <= PASS_ROOTS);
        assert!(
            prepare_due(&mut account, requested, true, &BTreeSet::new())?.is_none(),
            "one pass per account"
        );
        seen.extend(plan.roots.iter().cloned());
        // No Apply: every fetch fails. Cursor must still progress past this batch.
        drop(plan);
    }
    assert_eq!(seen, expected, "even failed roots and a full demand set cannot starve later peers");
    assert_eq!(account.head_refresh.pending.len(), MAX_PENDING);
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}
