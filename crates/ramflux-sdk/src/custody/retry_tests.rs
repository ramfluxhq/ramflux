// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retry scheduling, typed error preservation and account lease isolation.
use super::*;

#[test]
fn busy_backoff_has_a_one_second_floor_a_sixteen_second_cap_and_jitter_at_the_cap() {
    for seconds in [1, 2, 4, 8, 16] {
        let backoff = Duration::from_secs(seconds);
        for random in [0, 1, u64::MAX] {
            let delay = jitter(backoff, random);
            assert!(delay >= Duration::from_secs(1));
            assert!(delay <= backoff);
            assert!(delay >= backoff * 3 / 4);
        }
    }
    assert_ne!(jitter(MAX_BACKOFF, 0), jitter(MAX_BACKOFF, 1));
}
#[tokio::test(start_paused = true)]
async fn all_busy_retries_stop_at_ninety_seconds_with_the_typed_refusal() {
    let started = Instant::now();
    let mut budget = Budget::new();
    let mut calls = 0;
    let result: Result<(), SdkError> = budget
        .until_ready(|| {
            calls += 1;
            std::future::ready(Err(busy()))
        })
        .await;
    assert!(matches!(result, Err(SdkError::CustodyNetwork(CustodyRefusal::Busy))));
    assert_eq!(started.elapsed(), RETRY_BUDGET);
    assert!((8..=20).contains(&calls));
}
#[tokio::test(start_paused = true)]
async fn a_stalled_attempt_does_not_extend_the_busy_retry_deadline() {
    let budget = Budget::new();
    let started = Instant::now();
    let result: Result<(), SdkError> = budget.attempt(std::future::pending()).await;
    assert!(result.is_err_and(|error| is_busy(&error)));
    assert_eq!(started.elapsed(), RETRY_BUDGET);
}
#[tokio::test(start_paused = true)]
async fn scripted_busy_then_success_retries_but_binding_refusals_never_retry()
-> Result<(), SdkError> {
    let mut budget = Budget::new();
    let mut calls = 0;
    let value = budget
        .until_ready(|| {
            calls += 1;
            std::future::ready(if calls <= 3 { Err(busy()) } else { Ok(7) })
        })
        .await?;
    assert_eq!(value, 7);
    assert_eq!(calls, 4);
    let mut fatal = 0;
    let result: Result<(), SdkError> = budget
        .until_ready(|| {
            fatal += 1;
            std::future::ready(Err(CustodyRefusal::BindingRefused.into()))
        })
        .await;
    assert!(matches!(result, Err(SdkError::CustodyNetwork(CustodyRefusal::BindingRefused))));
    assert_eq!(fatal, 1);
    Ok(())
}
#[tokio::test]
async fn account_single_flight_is_shared_across_handles_and_released_on_cancellation()
-> Result<(), SdkError> {
    let root = tempfile::tempdir()?;
    for id in ["alice", "bob"] {
        std::fs::create_dir_all(root.path().join("custody_accounts").join(id))?;
    }
    let first = single_flight(root.path(), "alice", &mut Budget::new()).await?;
    let mut waiting_budget = Budget::new();
    let mut waiter = Box::pin(single_flight(root.path(), "alice", &mut waiting_budget));
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut waiter).await.is_err());
    let bob = single_flight(root.path(), "bob", &mut Budget::new()).await?;
    drop(waiter);
    drop(first);
    let alice = single_flight(root.path(), "alice", &mut Budget::new()).await?;
    drop(alice);
    drop(bob);
    Ok(())
}

#[path = "retry_server_tests.rs"]
mod server;
