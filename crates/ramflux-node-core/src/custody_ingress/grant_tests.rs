// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Concurrent reservation, revocation, expiry and callback failure boundaries.
use super::*;
use std::sync::mpsc;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn parked_grant_does_not_block_acquire_or_revoke() -> Result {
    let limiter = CustodyIngressLimiter::new(256);
    let permit = Arc::new(limiter.acquire("192.0.2.1".parse()?, None, Instant::now())?);
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let proving = Arc::clone(&permit);
    let grant = std::thread::spawn(move || {
        proving.try_grant("one", || {
            started_tx.send(()).map_err(|_| "started")?;
            release_rx.recv().map_err(|_| "release")?;
            Ok::<_, &'static str>(())
        })
    });
    started_rx.recv_timeout(Duration::from_secs(5))?;
    let revoking = Arc::clone(&permit);
    let accepting = Arc::clone(&limiter);
    let incoming_source = "198.51.100.1".parse()?;
    let other = std::thread::spawn(move || {
        let acquired = accepting.acquire(incoming_source, None, Instant::now());
        revoking.revoke();
        done_tx.send(acquired.is_ok()).map_err(|_| "done")?;
        Ok::<_, &'static str>(())
    });
    let progressed = done_rx.recv_timeout(Duration::from_millis(500));
    // Always release before asserting, including when testing the lock-held mutation.
    release_tx.send(())?;
    let result = grant.join().map_err(|_| "grant thread")?;
    other.join().map_err(|_| "accept thread")??;
    assert_eq!(progressed.ok(), Some(true), "acquire and revoke waited for the callback");
    assert!(result.is_err());
    assert_eq!(limiter.state.lock().map_err(|_| "state")?.authenticated, 0);
    Ok(())
}

#[test]
fn finite_pool_reservation_prevents_concurrent_oversubscription() -> Result {
    let limiter = CustodyIngressLimiter::with_authenticated_limit(256, 1);
    let first = Arc::new(limiter.acquire("192.0.2.1".parse()?, None, Instant::now())?);
    let second = limiter.acquire("192.0.2.1".parse()?, None, Instant::now())?;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let proving = Arc::clone(&first);
    let grant = std::thread::spawn(move || {
        proving.try_grant("one", || {
            started_tx.send(()).map_err(|_| "started")?;
            release_rx.recv().map_err(|_| "release")?;
            Ok::<_, &'static str>(())
        })
    });
    started_rx.recv_timeout(Duration::from_secs(5))?;
    let refused = second.grant("two", || ());
    release_tx.send(())?;
    let granted = grant.join().map_err(|_| "grant thread")?;
    granted??;
    assert_eq!(refused.err().ok_or("second grant admitted")?.retry, Some(node_retry()));
    assert_eq!(limiter.state.lock().map_err(|_| "state")?.authenticated, 1);
    Ok(())
}

#[test]
fn failed_and_panicked_callbacks_release_reservations_without_renewing_holders() -> Result {
    let limiter = CustodyIngressLimiter::with_authenticated_limit(256, 1);
    let tick = Instant::now();
    let permit = limiter.acquire("192.0.2.1".parse()?, None, tick)?;
    assert_eq!(permit.try_grant("one", || Err::<(), _>("callback"))?, Err("callback"));
    assert!(
        std::panic::catch_unwind(
            || permit.grant("one", || std::panic::resume_unwind(Box::new("callback panic")))
        )
        .is_err()
    );
    let state = limiter.state.lock().map_err(|_| "state")?;
    assert_eq!((state.handshakes, state.authenticated), (1, 0));
    assert_eq!(
        state.holders.get(&permit.holder).ok_or("holder")?.deadline,
        tick + Duration::from_secs(10)
    );
    assert!(!state.holders.get(&permit.holder).ok_or("holder")?.granting);
    drop(state);
    permit.mark_authenticated("one")?;
    Ok(())
}

#[test]
fn expiry_during_callback_rolls_back_reserved_capacity() -> Result {
    let limiter = CustodyIngressLimiter::with_authenticated_limit(256, 1);
    let tick = Instant::now();
    let permit = limiter.acquire("192.0.2.1".parse()?, None, tick)?;
    let result = permit.grant("one", || {
        let mut state = limiter.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        CustodyIngressLimiter::prune(&mut state, tick + Duration::from_secs(11));
        assert_eq!(state.authenticated, 1, "phase 3 owns the reservation");
    });
    assert!(result.is_err());
    let state = limiter.state.lock().map_err(|_| "state")?;
    assert_eq!((state.handshakes, state.authenticated), (0, 0));
    Ok(())
}

#[test]
fn second_grant_on_a_granting_holder_has_its_own_refusal_label() -> Result {
    if crate::custody_budget_log::tests::run_isolated()? {
        return Ok(());
    }
    let limiter = CustodyIngressLimiter::with_authenticated_limit(256, 1);
    let permit = limiter.acquire("192.0.2.1".parse()?, None, Instant::now())?;
    permit.grant("one", || {
        let refusal =
            crate::custody_budget_log::tests::assert_warning("grant_in_progress", 1, 0, || {
                permit.grant("one", || panic!("a second grant must not execute"))
            })
            .expect_err("second grant admitted");
        assert_eq!(refusal.code, ramflux_protocol::custody::CustodyRefusal::Busy);
        assert_eq!(refusal.retry, None);
    })?;
    assert_eq!(limiter.state.lock().map_err(|_| "state")?.authenticated, 1);
    Ok(())
}
