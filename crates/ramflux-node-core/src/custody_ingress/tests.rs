// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adversarial admission, lifetime and atomic grant regressions.
use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ip(share: u16, host: u16) -> IpAddr {
    std::net::Ipv6Addr::new(0x2001, 0xdb8, share, (host - 1) / 8, 0, 0, 0, (host - 1) % 8 + 1)
        .into()
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
    for n in 0..8 {
        let host = n / 4 + 1;
        let address =
            if n % 2 == 0 { format!("192.0.2.{host}") } else { format!("::ffff:192.0.2.{host}") };
        let p = l.acquire(address.parse()?, None, Instant::now()).ok_or("holder")?;
        assert!(p.mark_authenticated(&format!("p-{}", n / 4)));
        held.push(p);
    }
    assert!(l.acquire("192.0.2.3".parse()?, None, Instant::now()).is_none());
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

#[test]
fn fifth_handshake_in_a_prefix_is_refused_without_revoking_existing_holders() -> Result {
    for family in 0..3 {
        let l = CustodyIngressLimiter::new(256);
        let tick = Instant::now();
        let mut held = Vec::new();
        for host in 1..=4 {
            let address = match family {
                0 => format!("192.0.2.{host}"),
                1 => format!("2001:db8:1::{host}"),
                _ => format!("2001:db8:1:{host}::1"),
            };
            held.push(l.acquire(address.parse()?, None, tick).ok_or("handshake")?);
        }
        let fifth = match family {
            0 => "192.0.2.5",
            1 => "2001:db8:1::5",
            _ => "2001:db8:1:5::1",
        };
        assert!(l.acquire(fifth.parse()?, None, tick).is_none());
        if family == 0 {
            assert!(l.acquire("::ffff:192.0.2.6".parse()?, None, tick).is_none());
        }
        let fresh = if family == 0 { "198.51.100.1" } else { "2001:db8:2::1" };
        let honest = l.acquire(fresh.parse()?, None, tick).ok_or("fresh share")?;
        assert!(!honest.is_revoked());
        assert!(held.iter().all(|p| !p.is_revoked()));
        assert!(held[0].mark_authenticated("principal"));
        assert!(l.acquire(fifth.parse()?, None, tick).is_some(), "H-to-A frees handshake share");
    }
    Ok(())
}
#[test]
fn listener_outer_ipv6_limits_count_authenticated_holders_across_both_pools() -> Result {
    let l = CustodyIngressLimiter::new(256);
    let mut held = Vec::new();
    for host in 1..=16 {
        let p = l.acquire(ip(1, host), None, Instant::now()).ok_or("holder")?;
        assert!(p.mark_authenticated(&format!("principal-{host}")));
        held.push(p);
        if host == 8 {
            assert!(
                l.acquire("2001:db8:1::9".parse()?, None, Instant::now()).is_none(),
                "/64 outer cap"
            );
        }
    }
    assert!(l.acquire("2001:db8:1:2::1".parse()?, None, Instant::now()).is_none(), "/48 outer cap");
    assert!(l.acquire(ip(2, 1), None, Instant::now()).is_some());
    assert_eq!(counts(&l), (0, 16));
    Ok(())
}

#[test]
fn challenge_share_caps_cover_mapped_ipv4_ipv6_48_and_64_and_reset_after_one_minute() -> Result {
    let tick = Instant::now();
    for family in 0..3 {
        let mut budget = CustodySourceBudget::default();
        for n in 0..8 {
            let source = match family {
                0 if n % 2 == 0 => format!("::ffff:192.0.2.{}", n + 1),
                0 => format!("192.0.2.{}", n + 1),
                1 => format!("2001:db8:1::{:x}", n + 1),
                _ => format!("2001:db8:1:{n:x}::1"),
            };
            assert!(budget.admit(source.parse()?, tick).is_some());
        }
        let source = if family == 0 { "192.0.2.99" } else { "2001:db8:1::99" };
        assert!(budget.admit(source.parse()?, tick).is_none());
        assert!(budget.admit(source.parse()?, tick + Duration::from_secs(60)).is_some());
    }
    Ok(())
}
#[test]
fn filling_the_challenge_window_requires_at_least_128_shares() -> Result {
    let tick = Instant::now();
    let mut budget = CustodySourceBudget::default();
    for share in 0..128 {
        for _ in 0..8 {
            assert!(budget.admit(ip(share, 1), tick).is_some());
        }
        if share < 127 {
            // A new share can reserve its first two challenges until the hard bound.
            let reserved: u32 = budget
                .buckets
                .iter()
                .filter(|(key, _)| key.ends_with("/48"))
                .map(|(_, bucket)| bucket.count.max(2))
                .sum();
            assert!(reserved <= 1016);
        }
    }
    assert!(budget.admit(ip(999, 1), tick).is_none());
    assert!(budget.admit(ip(999, 1), tick + Duration::from_secs(60)).is_some());
    Ok(())
}
