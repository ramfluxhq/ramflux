// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session population is independent of pending proof bounds and deadline work.
use super::tests::intent;
use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn session() -> CustodySession {
    CustodySession {
        session_id: String::new(),
        target_delivery_id: "target".into(),
        device_ref: intent("192.0.2.1".into(), "holder".into()).device,
        record_hash: "record".into(),
        proof_hash: "proof".into(),
        binding_mode: BindingMode::HomeRelayReceipt,
        expires_at: 1000,
    }
}
#[test]
fn session_store_admits_more_than_4096_live_sessions() -> Result {
    let tick = Instant::now();
    let mut pool = CustodyLeases::default();
    let mut ids = Vec::new();
    for n in 0..5000 {
        let offset = n / 1000 * 60;
        let at = tick + Duration::from_secs(offset);
        let holder = format!("holder-{n}");
        let source =
            format!("198.{}.{}.{}", 18 + (n % 1000) / 512, (n % 1000) / 2 % 256, n % 2 + 1);
        let challenge = pool.issue(intent(source, holder.clone()), 100 + offset, at)?;
        pool.consume(&challenge.challenge_nonce, &format!("proof-{n}"), at)?;
        ids.push(pool.open(session(), holder, 100 + offset, at)?.session_id);
    }
    assert_eq!(pool.sessions.len(), 5000);
    assert_eq!(pool.session_by_holder.len(), 5000);
    assert_eq!(pool.session_deadlines.len(), 5000);
    for (n, id) in ids.iter().enumerate() {
        pool.session(id, &format!("holder-{n}"), 340, tick + Duration::from_secs(240))?;
    }
    // A separate pre-auth population fills the actual pending bound in five windows.
    let mut pending = CustodyLeases::default();
    for n in 0..4096 {
        let offset = n / 1000 * 60;
        let source =
            format!("198.{}.{}.{}", 18 + (n % 1000) / 512, (n % 1000) / 2 % 256, n % 2 + 1);
        pending.issue(
            intent(source, format!("pending-{n}")),
            100 + offset,
            tick + Duration::from_secs(offset),
        )?;
    }
    assert_eq!(pending.pending_count, PENDING_CHALLENGE_LIMIT);
    let refused = pending
        .issue(
            intent("203.0.113.1".into(), "pending-overflow".into()),
            340,
            tick + Duration::from_secs(240),
        )
        .err()
        .ok_or("expected refusal: global pending bound")?;
    assert_eq!(refused.code, CustodyRefusal::Busy);
    assert_eq!(refused.retry, Some(node_retry()));
    let challenge = pool.issue(
        intent("203.0.113.1".into(), "replay-holder".into()),
        340,
        tick + Duration::from_secs(240),
    )?;
    pool.consume(&challenge.challenge_nonce, "one-proof", tick + Duration::from_secs(240))?;
    assert_eq!(
        pool.consume(&challenge.challenge_nonce, "one-proof", tick + Duration::from_secs(240))
            .err()
            .ok_or("expected refusal: replay")?
            .code,
        CustodyRefusal::Replay
    );
    Ok(())
}
#[test]
fn admission_work_is_independent_of_live_authenticated_holders() -> Result {
    let limiter = crate::CustodyIngressLimiter::new(256);
    let mut held = Vec::new();
    let tick = Instant::now();
    let mut pool = CustodyLeases::default();
    for n in 0..10_000 {
        let permit = limiter.acquire("192.0.2.1".parse()?, Some(1), tick)?;
        permit.mark_authenticated(&format!("account-{n}"))?;
        held.push(permit);
        pool.open(session(), format!("holder-{n}"), 100, tick)?;
    }
    let expired = limiter.acquire("192.0.2.1".parse()?, Some(1), tick)?;
    let live = limiter.acquire("192.0.2.1".parse()?, Some(1), tick + Duration::from_secs(2))?;
    limiter.operation_count(true);
    pool.session_visits = 0;
    let incoming =
        limiter.acquire("192.0.2.1".parse()?, Some(1), tick + Duration::from_secs(11))?;
    incoming.mark_authenticated("incoming")?;
    pool.prune(tick + Duration::from_secs(11));
    pool.open(session(), "incoming".into(), 111, tick + Duration::from_secs(11))?;
    assert!(expired.is_revoked());
    assert!(!live.is_revoked());
    assert!(held.iter().all(|p| !p.is_revoked()));
    assert!(limiter.operation_count(false) <= 9, "holder work={}", limiter.operation_count(false));
    assert!(pool.session_visits <= 8, "session work={}", pool.session_visits);
    assert_eq!(pool.sessions.len(), 10_001);
    // A due session at the front is removed without visiting the future population.
    let mut short = session();
    short.expires_at = 112;
    let short = pool.open(short, "short".into(), 111, tick + Duration::from_secs(11))?;
    pool.session_visits = 0;
    pool.prune(tick + Duration::from_secs(13));
    assert!(!pool.sessions.contains_key(&short.session_id));
    assert_eq!(pool.sessions.len(), 10_001);
    assert_eq!(pool.session_visits, 1);
    Ok(())
}
