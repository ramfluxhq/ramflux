// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unlimited authenticated population and bounded pre-authentication bookkeeping.
use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn twenty_authenticated_accounts_from_one_ipv4_all_hold_sessions() -> Result {
    for family in 0..5 {
        let limiter = CustodyIngressLimiter::new(256);
        let mut held = Vec::new();
        for n in 1..=20 {
            let address = match family {
                0 => "192.0.2.1".to_owned(),
                1 => format!("192.0.2.{n}"),
                2 => format!("2001:db8:1::{n:x}"),
                3 => format!("2001:db8:1:{n:x}::1"),
                _ => "::ffff:192.0.2.1".to_owned(),
            };
            let permit = limiter.acquire(address.parse()?, None, Instant::now())?;
            permit.mark_authenticated(&format!("account-{n}"))?;
            held.push(permit);
        }
        assert_eq!(limiter.state.lock().map_err(|_| "state")?.authenticated, 20, "family={family}");
        assert!(held.iter().all(|p| !p.is_revoked()));
    }
    Ok(())
}
#[test]
fn one_account_ten_concurrent_sessions_all_authenticated() -> Result {
    for shared_connection in [false, true] {
        let limiter = CustodyIngressLimiter::new(256);
        let mut held = Vec::new();
        for n in 0..10 {
            let connection = if shared_connection { 1 } else { n };
            let permit = limiter.acquire("192.0.2.1".parse()?, Some(connection), Instant::now())?;
            permit.mark_authenticated("one-account")?;
            held.push(permit);
        }
        assert_eq!(held.len(), 10);
        assert!(held.iter().all(|p| !p.is_revoked()));
    }
    Ok(())
}
#[test]
fn handshake_flood_from_one_ip_is_still_refused_with_hint() -> Result {
    for address in ["192.0.2.1", "::ffff:192.0.2.1", "2001:db8:1::1"] {
        let limiter = CustodyIngressLimiter::new(256);
        let tick = Instant::now();
        let address: IpAddr = address.parse()?;
        let held: Vec<_> = (0..4)
            .map(|_| limiter.acquire(address, None, tick))
            .collect::<std::result::Result<_, _>>()?;
        let refusal = limiter
            .acquire(address, None, tick + Duration::from_secs(2))
            .err()
            .ok_or("fifth accepted")?;
        assert_eq!(refusal.retry, Some(RetryHint::new(RetryScope::PreAuthSource, 8000)));
        assert!(held.iter().all(|p| !p.is_revoked()));
    }
    Ok(())
}
#[test]
fn finite_authenticated_pool_refuses_with_node_capacity_hint() -> Result {
    let limiter = CustodyIngressLimiter::with_authenticated_limit(256, 1);
    let first = limiter.acquire("192.0.2.1".parse()?, None, Instant::now())?;
    first.mark_authenticated("one")?;
    let next = limiter.acquire("192.0.2.1".parse()?, None, Instant::now())?;
    assert_eq!(
        next.mark_authenticated("two").err().ok_or("expected refusal: finite node pool")?.retry,
        Some(node_retry())
    );
    Ok(())
}
#[test]
fn issuance_refusal_hints_match_window_remaining() -> Result {
    for (ip, prefix, node) in [(2, 3, 10), (7, 9, 32)] {
        let tick = Instant::now();
        let mut budget =
            CustodySourceBudget::with_settings(CustodyIssuanceSettings::new(ip, prefix, node)?);
        for _ in 0..ip {
            budget.admit("192.0.2.1".parse()?, tick)?;
        }
        let refused = budget
            .admit("192.0.2.1".parse()?, tick + Duration::from_secs(17))
            .err()
            .ok_or("expected refusal: ip quota")?;
        assert_eq!(refused.retry, Some(RetryHint::new(RetryScope::PreAuthSource, 43_000)));
        for _ in ip..prefix {
            budget.admit("192.0.2.2".parse()?, tick)?;
        }
        assert_eq!(
            budget
                .admit("192.0.2.3".parse()?, tick + Duration::from_secs(23))
                .err()
                .ok_or("expected refusal: prefix quota")?
                .retry,
            Some(RetryHint::new(RetryScope::PreAuthSource, 37_000))
        );
        assert!(budget.admit("192.0.2.1".parse()?, tick + Duration::from_secs(60)).is_ok());
    }
    Ok(())
}
#[test]
fn preauth_counters_decrement_once_on_promotion_or_removal() -> Result {
    let limiter = CustodyIngressLimiter::new(256);
    let tick = Instant::now();
    for sequence in 0..3 {
        let permit = limiter.acquire("2001:db8:1::1".parse()?, Some(7), tick)?;
        {
            let state = limiter.state.lock().map_err(|_| "state")?;
            assert_eq!(state.handshakes, 1);
            assert_eq!(state.preauth_deadlines.len(), 1);
            assert_eq!(state.sources.len(), 3);
            assert!(state.sources.values().all(|b| b.count == 1 && b.deadlines.len() == 1));
            assert_eq!(state.connections[&7].count, 1);
        }
        match sequence {
            0 => {
                permit.mark_authenticated("account")?;
                permit.revoke();
            }
            1 => permit.revoke(),
            _ => CustodyIngressLimiter::prune(
                &mut *limiter.state.lock().map_err(|_| "state")?,
                tick + Duration::from_secs(11),
            ),
        }
        drop(permit);
        let state = limiter.state.lock().map_err(|_| "state")?;
        assert_eq!((state.handshakes, state.authenticated), (0, 0));
        assert!(state.sources.is_empty());
        assert!(state.connections.is_empty());
        assert!(state.preauth_deadlines.is_empty());
        assert!(state.deadlines.is_empty());
    }
    Ok(())
}
