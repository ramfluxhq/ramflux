// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Each lease saturation reports exactly the exhausted budget and keeps its typed category.
use super::tests::{intent, issue};
use super::*;
use crate::custody_budget_log::tests::assert_warning;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn holder_prefix_and_global_refusals_log_the_exhausted_counter() -> Result {
    if crate::custody_budget_log::tests::run_isolated()? {
        return Ok(());
    }
    let tick = Instant::now();
    let mut pool = CustodyLeases::default();
    for _ in 0..HOLDER_LIMIT {
        issue(&mut pool, tick)?;
    }
    assert_warning("holder", HOLDER_LIMIT, HOLDER_LIMIT, || {
        assert!(issue(&mut pool, tick).is_err());
    });
    // Distinct source addresses avoid the independent issuance rate limit.
    let mut pool = CustodyLeases::default();
    for index in 0..SOURCE_LIMIT {
        let tick = tick + Duration::from_secs(index as u64 * 2);
        pool.issue(intent(format!("192.0.2.{}", index + 1), format!("h-{index}")), 100, tick)?;
    }
    assert_warning("prefix", SOURCE_LIMIT, SOURCE_LIMIT, || {
        assert_eq!(
            pool.issue(
                intent("192.0.2.200".into(), "new".into()),
                100,
                tick + Duration::from_secs(128)
            )
            .err()
            .map(|e| e.code),
            Some(CustodyRefusal::Capacity)
        );
    });
    pool.pending_count = PENDING_CHALLENGE_LIMIT;
    assert_warning("global", PENDING_CHALLENGE_LIMIT, PENDING_CHALLENGE_LIMIT, || {
        assert_eq!(
            pool.issue(intent("203.0.113.1".into(), "new".into()), 100, tick).err().map(|e| e.code),
            Some(CustodyRefusal::Busy)
        );
    });
    Ok(())
}
fn session() -> CustodySession {
    CustodySession {
        session_id: String::new(),
        target_delivery_id: "target".into(),
        device_ref: intent("192.0.2.1".into(), "h".into()).device,
        record_hash: "record".into(),
        proof_hash: "proof".into(),
        binding_mode: BindingMode::HomeRelayReceipt,
        expires_at: 400,
    }
}
#[test]
fn replay_session_and_request_refusals_log_the_exhausted_counter() -> Result {
    if crate::custody_budget_log::tests::run_isolated()? {
        return Ok(());
    }
    let tick = Instant::now();
    let mut pool = CustodyLeases::default();
    let challenge = issue(&mut pool, tick)?;
    for index in 0..REPLAY_LIMIT {
        pool.proofs.insert(format!("proof-{index}"), tick + Duration::from_secs(600));
    }
    assert_warning("replay", REPLAY_LIMIT, REPLAY_LIMIT, || {
        assert_eq!(
            pool.consume(&challenge.challenge_nonce, "fresh", tick).map_err(|e| e.code),
            Err(CustodyRefusal::Capacity)
        );
    });
    // The former authenticated session ceiling is gone; pending/replay bounds remain.
    for index in 0..5000 {
        pool.open(session(), format!("holder-{index}"), 100, tick)?;
    }
    assert_eq!(pool.sessions.len(), 5000);
    let mut pool = CustodyLeases::default();
    let session = pool.open(session(), "fresh".into(), 100, tick)?;
    for index in 0..REQUEST_LIMIT {
        pool.request(
            &session.session_id,
            &ramflux_protocol::encode_base64url([u8::try_from(index)?; 32]),
        )?;
    }
    let mut fresh = [0; 32];
    fresh[0] = 1;
    assert_warning("request", REQUEST_LIMIT, REQUEST_LIMIT, || {
        assert_eq!(
            pool.request(&session.session_id, &ramflux_protocol::encode_base64url(fresh)),
            Err(CustodyRefusal::Capacity)
        );
    });
    Ok(())
}
