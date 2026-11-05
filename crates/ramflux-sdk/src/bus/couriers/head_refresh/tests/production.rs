// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise the real cycle and fetch-pass budget through writer messages and TLS failures.
use super::*;

fn failure_backlog(account: &mut LocalBusAccountState) -> TestResult {
    account.head_refresh = RefreshState::default();
    let ready = tokio::time::Instant::now();
    for index in 0..160 {
        let root = format!("dead-{index:03}");
        account.client.establish_friend_link(
            &format!("dead-link-{index}"),
            &account.principal_commitment,
            &root,
        )?;
        account.head_refresh.enqueue(root.clone());
        account.head_refresh.failures.insert(root, (ready, 6));
        account.client.establish_friend_link(
            &format!("sweep-link-{index}"),
            &account.principal_commitment,
            &format!("sweep-{index:03}"),
        )?;
    }
    Ok(())
}

fn refresh_work(work: AccountWork) -> TestResult<Work> {
    let AccountWork::Directory(work) = work else { return Err("directory work".into()) };
    let super::super::super::directory::DirectoryWork::HeadRefresh(work) = *work else {
        return Err("head refresh work".into());
    };
    Ok(work)
}

#[tokio::test]
async fn production_cycle_decrements_retry_budget_across_fetch_passes() -> TestResult {
    let (mut account, native, _io) = Box::pin(account()).await?;
    failure_backlog(&mut account)?;
    let (address, server) = crate::bus::dispatch::surface_transport::fixture::directory(
        &native.root.0,
        BTreeMap::new(),
    )
    .await?;
    account.gateway_config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    account.gateway_config.gateway_addr = address;
    account.gateway_config.tcp_gateway_addr = Some(address);
    account.gateway_config.server_name = "test-gateway".into();
    account.gateway_config.ca_cert = native.root.0.join("ca.pem");
    let handle = account.connection.as_ref().ok_or("connection")?.clone();
    let context = handle.test_context();
    let (writer, mut receiver) = mpsc::channel(2);
    let mut child = tokio::spawn(async move { cycle(&context, &writer, true).await });
    let mut retried = 0;
    let mut swept = 0;
    let mut saw_exhausted = false;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                result = &mut child => { result??; break; }
                work = receiver.recv() => {
                    let Some(work) = work else {
                        (&mut child).await??;
                        break;
                    };
                    let work = refresh_work(work)?;
                    match &work {
                        Work::Prepare { retry_budget, .. } => {
                            saw_exhausted |= *retry_budget == 0;
                        }
                        Work::Apply { root, outcome, .. } => {
                            assert!(outcome.is_err(), "empty directory must fail actual fetches");
                            if root.starts_with("dead-") { retried += 1; }
                            else { swept += 1; }
                        }
                        Work::Subscribe { .. } => return Err("cycle must not subscribe".into()),
                    }
                    apply_work(&mut account, work);
                }
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;
    child.abort();
    server.abort();
    handle.stop().await;
    result??;
    assert_eq!(retried, RETRY_DEMAND_SHARE, "production fetch_pass must spend its retry budget");
    assert!(saw_exhausted, "writer must observe the production budget reaching zero");
    assert_eq!(swept, PASS_ROOTS * MAX_CYCLE_PASSES - RETRY_DEMAND_SHARE);
    Ok(())
}

#[test]
fn wake_then_tick_cannot_reclaim_a_grid_slot() {
    let origin = tokio::time::Instant::now();
    let mut next = origin + REFRESH_INTERVAL;
    let delivered = next + Duration::from_millis(1);
    assert!(advance_sweep(&mut next, delivered), "wake claims the due slot");
    assert!(
        !advance_sweep(&mut next, delivered),
        "late timer must not reclaim a slot already taken by a wake"
    );
    assert_eq!(next, origin + REFRESH_INTERVAL * 2);
    assert!(advance_sweep(&mut next, origin + REFRESH_INTERVAL * 2));
}
