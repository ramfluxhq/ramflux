// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unequal wake latency, persistent failed demands and public scheduling documentation.
use super::*;

#[tokio::test]
async fn periodic_schedule_keeps_grid_after_unequal_wake_delays() -> TestResult {
    let origin = tokio::time::Instant::now();
    let mut next = origin + REFRESH_INTERVAL;
    assert!(advance_sweep(&mut next, origin + Duration::from_secs(155)));
    assert_eq!(
        next,
        origin + Duration::from_secs(300),
        "wake latency must not shift the interval grid"
    );
    assert!(advance_sweep(&mut next, origin + Duration::from_secs(301)));
    assert_eq!(next, origin + Duration::from_secs(450));
    assert!(!advance_sweep(&mut next, origin + Duration::from_secs(449)));
    let (mut account, native, _io) = account().await?;
    account.head_refresh.pending.clear();
    let old = Instant::now().checked_sub(Duration::from_secs(121)).ok_or("clock")?;
    account.client.persist_fetched_identity_directory_at(&native.manifest, old)?;
    let requested = fence(&account)?;
    assert!(
        prepare_due(&mut account, requested, true, &BTreeSet::new())?.is_some(),
        "late previous fetch must be due before 150s"
    );
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}

#[tokio::test]
async fn failed_demands_reserve_periodic_sweep_share() -> TestResult {
    let (mut account, _native, _io) = account().await?;
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
    }
    for index in 0..160 {
        account.client.establish_friend_link(
            &format!("sweep-link-{index}"),
            &account.principal_commitment,
            &format!("sweep-{index:03}"),
        )?;
    }
    let mut attempted = BTreeSet::new();
    let mut budget = RETRY_DEMAND_SHARE;
    let mut retries = 0;
    let mut swept = 0;
    for _ in 0..PASS_ROOTS * MAX_CYCLE_PASSES {
        let requested = fence(&account)?;
        let plan = prepare_due_limit(&mut account, requested, true, &attempted, 1, budget)?
            .ok_or("plan")?;
        retries += plan.retried_demands;
        budget = budget.saturating_sub(plan.retried_demands);
        swept += usize::from(!account.head_refresh.pending.contains(&plan.roots[0]));
        attempted.extend(plan.roots.iter().cloned());
        drop(plan);
    }
    assert_eq!(
        retries, RETRY_DEMAND_SHARE,
        "failed demand retries must respect their trigger share"
    );
    assert_eq!(
        swept,
        PASS_ROOTS * MAX_CYCLE_PASSES - RETRY_DEMAND_SHARE,
        "periodic sweep must progress despite persistently failing demands"
    );
    account.connection.take().ok_or("connection")?.stop().await;
    Ok(())
}

#[test]
fn refresh_docs_match_absolute_schedule() {
    let docs =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/custody_networking.md"));
    let changes = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../CHANGELOG.md"));
    for text in [docs, changes] {
        let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized.contains("fixed schedule at 150-second intervals"));
    }
    assert_eq!(REFRESH_INTERVAL, Duration::from_secs(150));
}

#[test]
fn refresh_scheduler_documentation_is_wrapped() {
    let docs =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/custody_networking.md"));
    let start = docs.find("Background refresh runs").unwrap_or(docs.len());
    assert!(start < docs.len(), "refresh paragraph missing");
    let paragraph = docs[start..].split("\n\n").next().unwrap_or_default();
    assert!(
        paragraph.lines().all(|line| line.chars().count() <= 85),
        "refresh paragraph must wrap at 85 columns"
    );
}
