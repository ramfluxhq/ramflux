// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual pending/replay refusal producers carry the documented server scope.
use super::tests::intent;
use super::*;
use crate::custody_ingress::hint_tests::{check, exercise};
use ramflux_protocol::custody::RetryScope;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
pub(crate) fn every_admission_budget_refusal_carries_a_hint() -> Result {
    exercise()?;
    let tick = Instant::now();
    let mut pool = CustodyLeases::default();
    let refusal = pool
        .issue(intent("192.0.2.1".into(), "x".repeat(513)), 100, tick)
        .err()
        .ok_or("expected refusal: holder bytes")?;
    check("holder_bytes", &refusal, Some(RetryScope::PreAuthSource));
    for _ in 0..4 {
        pool.issue(intent("192.0.2.1".into(), "holder".into()), 100, tick)?;
    }
    check(
        "holder",
        &pool
            .issue(intent("192.0.2.1".into(), "holder".into()), 100, tick)
            .err()
            .ok_or("expected refusal: holder")?,
        Some(RetryScope::PreAuthSource),
    );
    let mut pool = CustodyLeases::default();
    pool.by_prefix
        .insert("192.0.2.0/24".into(), (0..64).map(|n| (tick, format!("pending-{n}"))).collect());
    check(
        "prefix",
        &pool
            .issue(intent("192.0.2.2".into(), "fresh".into()), 100, tick)
            .err()
            .ok_or("expected refusal: prefix")?,
        Some(RetryScope::PreAuthSource),
    );
    let mut pool =
        CustodyLeases { pending_count: PENDING_CHALLENGE_LIMIT, ..CustodyLeases::default() };
    check(
        "global",
        &pool
            .issue(intent("203.0.113.1".into(), "fresh".into()), 100, tick)
            .err()
            .ok_or("expected refusal: pending")?,
        Some(RetryScope::NodeCapacity),
    );
    let mut pool = CustodyLeases::default();
    let challenge = pool.issue(intent("192.0.2.1".into(), "holder".into()), 100, tick)?;
    for n in 0..REPLAY_LIMIT {
        pool.proofs.insert(format!("proof-{n}"), tick + Duration::from_secs(600));
    }
    check(
        "replay",
        &pool
            .consume(&challenge.challenge_nonce, "new-proof", tick)
            .err()
            .ok_or("expected refusal: replay bound")?,
        Some(RetryScope::NodeCapacity),
    );
    Ok(())
}
