// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Inventory of actual listener and issuance budget producers.
use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(crate) fn check(name: &str, refusal: &CustodyAdmissionRefusal, scope: Option<RetryScope>) {
    assert_eq!(refusal.retry.map(|hint| hint.scope), scope, "budget={name}");
    if let Some(hint) = refusal.retry {
        assert!((1000..=3_600_000).contains(&hint.retry_after_ms), "budget={name} hint={hint:?}");
    }
    eprintln!("budget hint verified: {name}");
}
pub(crate) fn exercise() -> Result {
    let tick = Instant::now();
    let source: IpAddr = "192.0.2.1".parse()?;
    for (name, handshakes, connection) in [
        ("handshake", 4, None),
        ("connection_stream", 256, Some(1)),
        ("listener_source_handshake", 256, None),
    ] {
        let limiter = CustodyIngressLimiter::new(handshakes);
        let held: Vec<_> = (0..4)
            .map(|_| limiter.acquire(source, connection, tick))
            .collect::<std::result::Result<_, _>>()?;
        check(
            name,
            &limiter.acquire(source, connection, tick).err().ok_or("not refused")?,
            Some(if name == "handshake" {
                RetryScope::NodeCapacity
            } else {
                RetryScope::PreAuthSource
            }),
        );
        assert!(held.iter().all(|p| !p.is_revoked()));
    }
    let limiter = CustodyIngressLimiter::with_authenticated_limit(256, 1);
    let first = limiter.acquire(source, None, tick)?;
    first.mark_authenticated("one")?;
    let next = limiter.acquire(source, None, tick)?;
    check(
        "authenticated",
        &next.mark_authenticated("two").err().ok_or("expected refusal: finite")?,
        Some(RetryScope::NodeCapacity),
    );
    check(
        "principal_bytes",
        &next.mark_authenticated("").err().ok_or("expected refusal: empty")?,
        None,
    );
    check(
        "principal_binding_mismatch",
        &first.mark_authenticated("two").err().ok_or("expected refusal: bound")?,
        None,
    );
    first.revoked.store(true, Ordering::Release);
    check(
        "revoked_holder",
        &first.mark_authenticated("one").err().ok_or("expected refusal: revoked")?,
        None,
    );
    first.revoke();
    check(
        "unavailable_holder",
        &first.mark_authenticated("one").err().ok_or("expected refusal: removed")?,
        None,
    );
    exercise_rates(source, tick)
}
fn exercise_rates(source: IpAddr, tick: Instant) -> Result {
    let mut rates = CustodySourceBudget::default();
    for _ in 0..16 {
        rates.admit(source, tick)?;
    }
    check(
        "source_ip_rate",
        &rates.admit(source, tick).err().ok_or("expected refusal: ip")?,
        Some(RetryScope::PreAuthSource),
    );
    for _ in 0..16 {
        rates.admit("192.0.2.2".parse()?, tick)?;
    }
    check(
        "source_prefix_rate",
        &rates.admit("192.0.2.3".parse()?, tick).err().ok_or("expected refusal: prefix")?,
        Some(RetryScope::PreAuthSource),
    );
    let mut rates = CustodySourceBudget::with_settings(CustodyIssuanceSettings::new(1, 1, 2)?);
    rates.admit(source, tick)?;
    check(
        "source_global_rate",
        &rates.admit("198.51.100.1".parse()?, tick).err().ok_or("expected refusal: global")?,
        Some(RetryScope::NodeCapacity),
    );
    let mut rates = CustodySourceBudget::default();
    for n in 0..8192 {
        rates
            .buckets
            .insert(format!("bucket-{n}"), source_budget::Bucket { started: tick, count: 0 });
    }
    check(
        "source_bucket",
        &rates.admit(source, tick).err().ok_or("expected refusal: buckets")?,
        Some(RetryScope::NodeCapacity),
    );
    for raw in [0, u32::MAX] {
        let error = refuse(
            "clamp_probe",
            1,
            1,
            CustodyRefusal::Busy,
            Some(RetryHint { scope: RetryScope::NodeCapacity, retry_after_ms: raw }),
        );
        assert_eq!(
            error.retry.ok_or("hint")?.retry_after_ms,
            if raw == 0 { 1000 } else { 3_600_000 }
        );
    }
    Ok(())
}
