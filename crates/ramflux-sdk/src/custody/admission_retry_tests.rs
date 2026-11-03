// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scripted TLS refusals retain server deadlines across independent attempts.
use super::*;
use crate::SdkError;
use crate::custody::retry::{AdmissionRetry, Budget};
use tokio::time::Instant;

async fn connect(
    fixture: &Fixture,
    retry: &mut AdmissionRetry,
    calls: &Arc<Mutex<Vec<Instant>>>,
) -> std::result::Result<((), CustodyConnection), SdkError> {
    Box::pin(CustodyConnection::connect_with(
        fixture.config.clone(),
        fixture.vault.clone(),
        retry,
        || async {
            calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(Instant::now());
            let (_, tls) = ramflux_transport::TcpTlsGatewayClient::connect(
                "127.0.0.1:0".parse().map_err(|_| SdkError::CustodySetupInvalid)?,
                fixture.config.gateway_address,
                &fixture.config.server_name,
                &fixture.config.ca_certificate,
                fixture.config.timeout,
            )
            .await?;
            Ok(((), tls.into_tls_stream()))
        },
    ))
    .await
}
async fn turn() {
    for _ in 0..2000 {
        tokio::task::yield_now().await;
    }
}
fn keep_clock_manual() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    })
}
#[tokio::test(start_paused = true)]
async fn busy_with_server_hint_is_honored_by_retry_budget() -> Result {
    // A runnable task prevents Tokio from automatically skipping time while TLS uses OS I/O.
    let clock = keep_clock_manual();
    let fixture = Fixture::new(&[Point::Open]).await?;
    fixture.script.lock().map_err(|_| "script")?.retry =
        Some(RetryHint { scope: RetryScope::NodeCapacity, retry_after_ms: 2000 });
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut retry = AdmissionRetry::default();
    let future = connect(&fixture, &mut retry, &calls);
    tokio::pin!(future);
    loop {
        tokio::select! { result = &mut future => return Err(format!("retry returned early: {}", result.is_ok()).into()), () = turn() => {} }
        if fixture.script.lock().map_err(|_| "script")?.busy_at.len() == 1 {
            break;
        }
    }
    // Poll the client through receipt of the refusal before moving its sleep clock.
    tokio::select! { result = &mut future => return Err(format!("retry returned early: {}", result.is_ok()).into()), () = turn() => {} }
    tokio::time::advance(Duration::from_millis(1999)).await;
    tokio::select! { result = &mut future => return Err(format!("retry returned before minimum: {}", result.is_ok()).into()), () = turn() => {} }
    assert_eq!(calls.lock().map_err(|_| "calls")?.len(), 1);
    tokio::time::advance(Duration::from_millis(201)).await;
    let ((), connection) = future.await?;
    assert!(connection.session().is_some());
    let attempts = calls.lock().map_err(|_| "calls")?.clone();
    assert_eq!(attempts.len(), 2);
    assert!(
        (Duration::from_secs(2)..=Duration::from_millis(2200))
            .contains(&(attempts[1] - attempts[0]))
    );
    drop(attempts);
    // Both boundaries and the added jitter are tested at the SDK's independent clamp.
    for (raw, expected) in [(0, 1000), (u32::MAX, 3_600_000)] {
        let hint = RetryHint { scope: RetryScope::PreAuthSource, retry_after_ms: raw };
        let error = SdkError::CustodyAdmission { code: CustodyRefusal::Busy, retry: hint };
        assert_eq!(error.retry_hint().ok_or("hint")?.retry_after_ms, expected);
        let mut state = AdmissionRetry::default();
        let now = Instant::now();
        state.record(&error, now);
        let delay = state.not_before().ok_or("deadline")? - now;
        assert!(delay >= Duration::from_millis(u64::from(expected)));
        assert!(delay <= Duration::from_millis(u64::from(expected) * 11 / 10));
        let mut budget = Budget::new();
        budget.attempt::<()>(std::future::ready(Err(error))).await.err().ok_or("busy expected")?;
        if raw == u32::MAX {
            let start = Instant::now();
            let error = budget.pause().await.err().ok_or("larger than budget expected")?;
            assert_eq!(error.retry_hint().ok_or("hint")?.retry_after_ms, expected);
            assert_eq!(Instant::now(), start);
        }
    }
    fixture.server.abort();
    clock.abort();
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn admission_retry_keeps_long_hint_across_attempts() -> Result {
    let clock = keep_clock_manual();
    let fixture = Fixture::new(&[Point::Open]).await?;
    let hint = RetryHint::new(RetryScope::NodeCapacity, 120_000);
    fixture.script.lock().map_err(|_| "script")?.retry = Some(hint);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut retry = AdmissionRetry::default();
    let started = Instant::now();
    let error =
        Box::pin(connect(&fixture, &mut retry, &calls)).await.err().ok_or("long hint retried")?;
    assert_eq!(error.retry_hint(), Some(hint));
    assert_eq!(started, Instant::now(), "over-budget hint returns at once");
    let deadline = retry.not_before().ok_or("deadline")?;
    assert!(deadline >= started + Duration::from_secs(120));
    assert!(deadline <= started + Duration::from_secs(132));
    for _ in 0..100 {
        assert_eq!(retry.not_before(), Some(deadline));
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    let future = connect(&fixture, &mut retry, &calls);
    tokio::pin!(future);
    tokio::select! { result = &mut future => return Err(format!("second attempt ignored deadline: {}", result.is_ok()).into()), () = turn() => {} }
    assert_eq!(calls.lock().map_err(|_| "calls")?.len(), 1);
    assert_eq!(fixture.script.lock().map_err(|_| "script")?.accepted, 1);
    tokio::time::advance(
        deadline
            .saturating_duration_since(Instant::now())
            .checked_sub(Duration::from_millis(1))
            .ok_or("deadline elapsed")?,
    )
    .await;
    tokio::select! { result = &mut future => return Err(format!("second attempt early: {}", result.is_ok()).into()), () = turn() => {} }
    assert_eq!(calls.lock().map_err(|_| "calls")?.len(), 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    let ((), connection) = future.await?;
    assert!(connection.session().is_some());
    let attempts = calls.lock().map_err(|_| "calls")?.clone();
    assert_eq!(attempts.len(), 2);
    assert!(attempts[1] >= deadline);
    assert_eq!(fixture.script.lock().map_err(|_| "script")?.accepted, 2);
    fixture.server.abort();
    clock.abort();
    Ok(())
}
