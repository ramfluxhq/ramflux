// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adversarial admission, lifetime and atomic grant regressions.
use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ip(share: u16, host: u16) -> IpAddr {
    std::net::Ipv6Addr::new(0x2001, 0xdb8, share, 0, 0, 0, 0, host).into()
}
fn counts(l: &CustodyIngressLimiter) -> (usize, usize) {
    let s = l.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(s.handshakes + s.authenticated, s.holders.len());
    assert!(s.handshakes <= l.handshake_limit);
    assert!(s.authenticated <= l.authenticated_limit);
    (s.handshakes, s.authenticated)
}
#[test]
fn two_hundred_fifty_six_shares_never_exceed_authenticated_ceiling() -> Result {
    let l = CustodyIngressLimiter::with_pools(256, 64, 4, Duration::from_secs(10));
    let mut held = Vec::new();
    for n in 0..256 {
        let p = l.acquire(ip(n, 1), None, Instant::now()).ok_or("handshake")?;
        assert_eq!(p.mark_authenticated(&format!("principal-{n}")), n < 64);
        held.push(p);
        counts(&l);
    }
    assert_eq!(counts(&l), (192, 64));
    assert!(held.iter().all(|p| !p.is_revoked()));
    Ok(())
}
#[test]
fn wall_and_eight_churn_shares_cannot_revoke_an_honest_handshake() -> Result {
    let l = CustodyIngressLimiter::with_pools(256, 512, 4, Duration::from_secs(10));
    let mut wall = Vec::new();
    for share in 0..31 {
        for n in 0..16 {
            let p = l.acquire(ip(share, n + 1), None, Instant::now()).ok_or("wall")?;
            assert!(p.mark_authenticated(&format!("wall-{share}-{}", n / 4)));
            wall.push(p);
        }
    }
    let honest = l.acquire(ip(999, 1), None, Instant::now()).ok_or("honest")?;
    let mut churn = Vec::new();
    for share in 100..108 {
        for host in 1..=2 {
            let p =
                l.acquire(ip(share, host), None, Instant::now()).ok_or("authenticated churn")?;
            assert!(p.mark_authenticated(&format!("churn-{share}-{host}")));
            churn.push(p);
        }
    }
    assert_eq!(counts(&l), (1, 512));
    for n in 0..1024 {
        let p = l.acquire(ip(100 + n % 8, 3), None, Instant::now()).ok_or("churn")?;
        assert!(!p.mark_authenticated(&format!("incoming-{n}")));
        assert!(!honest.is_revoked());
        counts(&l);
    }
    drop(churn);
    assert!(honest.mark_authenticated("honest"));
    assert_eq!(counts(&l), (0, 497));
    assert!(wall.iter().all(|p| !p.is_revoked()));
    Ok(())
}
#[test]
fn full_handshake_pool_refuses_without_revoking_and_deadline_releases_slot() -> Result {
    let l = CustodyIngressLimiter::with_pools(256, 1024, 4, Duration::from_secs(10));
    let tick = Instant::now();
    let mut held = Vec::new();
    for share in 0..64 {
        for _ in 0..4 {
            held.push(l.acquire(ip(share, 1), None, tick).ok_or("holder")?);
        }
    }
    assert!(l.acquire(ip(999, 1), None, tick).is_none());
    assert_eq!(counts(&l), (256, 0));
    assert!(held.iter().all(|p| !p.is_revoked()));
    let fresh =
        l.acquire(ip(999, 1), None, tick + Duration::from_secs(11)).ok_or("expired slot")?;
    assert!(!fresh.is_revoked());
    assert!(held.iter().all(CustodyIngressPermit::is_revoked));
    assert!(!held[0].mark_authenticated("late"));
    assert_eq!(counts(&l), (1, 0));
    Ok(())
}
#[test]
fn full_authenticated_pool_retains_handshake_until_busy_connection_closes() -> Result {
    let l = CustodyIngressLimiter::with_pools(1, 1, 4, Duration::from_secs(10));
    let first = l.acquire(ip(1, 1), None, Instant::now()).ok_or("first")?;
    assert!(first.mark_authenticated("first"));
    let next = l.acquire(ip(2, 1), None, Instant::now()).ok_or("next")?;
    let mut granted = false;
    assert!(
        next.grant("next", || {
            granted = true;
        })
        .is_none()
    );
    assert!(!granted);
    assert_eq!(counts(&l), (1, 1));
    assert!(!first.is_revoked());
    assert!(!next.is_revoked());
    drop(next);
    assert_eq!(counts(&l), (0, 1));
    Ok(())
}
#[test]
fn handshake_to_authenticated_transition_is_atomic_with_revocation_and_grant() -> Result {
    let l = CustodyIngressLimiter::with_pools(256, 1, 4, Duration::from_secs(10));
    let permits: Vec<_> = (0..64)
        .map(|n| l.acquire(ip(n, 1), None, Instant::now()).ok_or("permit"))
        .collect::<std::result::Result<_, _>>()?;
    let barrier = std::sync::Barrier::new(permits.len());
    let winners = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for (n, p) in permits.iter().enumerate() {
            let barrier = &barrier;
            let winners = &winners;
            scope.spawn(move || {
                barrier.wait();
                if p.grant(&format!("p-{n}"), || winners.fetch_add(1, Ordering::SeqCst)).is_some() {
                    assert!(!p.is_revoked());
                }
            });
        }
    });
    assert_eq!(winners.load(Ordering::SeqCst), 1);
    assert_eq!(counts(&l), (63, 1));
    let late = &permits[0];
    late.revoke();
    let mut executed = false;
    assert!(late.grant("late", || executed = true).is_none());
    assert!(!executed);
    counts(&l);
    Ok(())
}
#[test]
fn authenticated_share_principal_and_mapped_ipv4_limits_are_independent() -> Result {
    let l = CustodyIngressLimiter::with_pools(256, 1024, 4, Duration::from_secs(10));
    let mut held = Vec::new();
    for n in 0..16 {
        let address = if n % 2 == 0 { "192.0.2.1" } else { "::ffff:192.0.2.1" };
        let p = l.acquire(address.parse()?, None, Instant::now()).ok_or("holder")?;
        assert!(p.mark_authenticated(&format!("p-{}", n / 4)));
        held.push(p);
    }
    let full = l.acquire("192.0.2.2".parse()?, None, Instant::now()).ok_or("handshake")?;
    assert!(!full.mark_authenticated("new"));
    let other = l.acquire("198.51.100.1".parse()?, None, Instant::now()).ok_or("other")?;
    assert!(!other.mark_authenticated("p-0"));
    assert!(other.mark_authenticated("new"));
    Ok(())
}
#[test]
fn per_ip_prefix_and_quic_caps_release_on_disconnect() -> Result {
    let l = CustodyIngressLimiter::new(256);
    let tick = Instant::now();
    let held: Vec<_> = (0..4)
        .map(|_| l.acquire(ip(1, 1), Some(1), tick).ok_or("permit"))
        .collect::<std::result::Result<_, _>>()?;
    assert!(l.acquire(ip(2, 1), Some(1), tick).is_none());
    assert!(l.acquire(ip(1, 1), Some(2), tick).is_none());
    drop(held);
    assert!(l.acquire(ip(1, 1), Some(1), tick).is_some());
    Ok(())
}
