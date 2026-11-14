// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn full_budget_keeps_retired_inflight_buffers_charged_under_four_mib_and_metadata_bound()
-> TestResult {
    let budget = FullBodyBudget::default();
    let mut bodies = Vec::new();
    for n in 0..8 {
        let slot = budget.open_slot([n; 32], 0)?;
        let permit = slot.reserve(FullDirection::Initiator, 524_288, 0)?;
        let bytes = vec![0; 524_288];
        bodies.push(Arc::new(permit.attach(bytes)?));
        slot.close();
        drop(slot);
    }
    let stats = budget.stats()?;
    assert_eq!(stats.reserved_bytes, 4_194_304);
    assert_eq!(bodies.iter().map(|body| body.bytes.capacity()).sum::<usize>(), 4_194_304);

    assert_eq!(stats.buffers, 8);
    assert_eq!(stats.slots, 0);
    assert!(stats.metadata_bound_bytes <= 65_536);
    let slot = budget.open_slot([9; 32], 0)?;
    assert!(matches!(
        slot.reserve(FullDirection::Responder, 1, 0),
        Err(PairingRelayError::Busy { .. })
    ));
    let borrowed = Arc::clone(bodies.last().ok_or("body missing")?);
    drop(bodies);
    assert_eq!(budget.stats()?.reserved_bytes, 524_288);
    assert_eq!(borrowed.as_bytes().len(), 524_288);
    drop(borrowed);
    assert_eq!(budget.stats()?.reserved_bytes, 0);
    assert_eq!(budget.stats()?.buffers, 0);
    Ok(())
}
#[test]
fn full_budget_reserves_control_position_and_cannot_refund_a_new_slot_from_old_generation()
-> TestResult {
    let budget = FullBodyBudget::default();
    let first = budget.open_slot([1; 32], 0)?;
    assert!(budget.open_slot([1; 32], 0).is_err());
    let large = first.reserve(FullDirection::Initiator, 131_072, 0)?;
    assert!(matches!(
        first.reserve(FullDirection::Initiator, 131_072, 0),
        Err(PairingRelayError::Busy { .. })
    ));
    let control = first.reserve(FullDirection::Initiator, 128, 0)?;
    assert!(first.reserve(FullDirection::Initiator, 1, 0).is_err());
    first.close();
    let next = budget.open_slot([1; 32], 0)?;
    let next_large = next.reserve(FullDirection::Initiator, 131_072, 0)?;
    drop(large);
    drop(control);
    assert!(next.reserve(FullDirection::Initiator, 131_072, 0).is_err());
    assert_eq!(budget.stats()?.reserved_bytes, 131_072);
    drop(next_large);
    assert_eq!(budget.stats()?.reserved_bytes, 0);
    assert!(matches!(
        first.reserve(FullDirection::Responder, 1, 0),
        Err(PairingRelayError::Retired)
    ));
    Ok(())
}
#[test]
fn full_budget_two_slots_byte_rate_capacity_refusal_and_guard_failure_cleanup() -> TestResult {
    let budget = FullBodyBudget::default();
    let one = budget.open_slot([1; 32], 0)?;
    let two = budget.open_slot([2; 32], 0)?;
    assert!(budget.open_slot([3; 32], 0).is_err());
    let bulk = one.reserve(FullDirection::Initiator, 524_288, 0)?;
    drop(bulk);
    assert!(one.reserve(FullDirection::Responder, 1, 0).is_err());
    let refill = one.reserve(FullDirection::Responder, 524_288, 125)?;
    drop(refill);
    let permit = two.reserve(FullDirection::Initiator, 4, 0)?;
    let mut oversized = Vec::with_capacity(5);
    oversized.resize(4, 0);
    assert!(permit.attach(oversized).is_err());
    assert_eq!(budget.stats()?.reserved_bytes, 0);
    drop(one);
    drop(two);
    assert_eq!(budget.stats()?.slots, 0);
    Ok(())
}

#[test]
fn full_budget_shares_the_metadata_bound_with_challenges_and_lease_owners() -> TestResult {
    let budget = FullBodyBudget::default();
    let pending = budget.reserve_metadata(60_000, 0)?;
    assert!(budget.reserve_metadata(6_000, 0).is_err());
    let slot = budget.open_slot([1; 32], 0)?;
    let body = slot.reserve(FullDirection::Initiator, 128, 0)?;
    assert!(budget.stats()?.metadata_bound_bytes <= 65_536);
    drop(pending);
    let successor = budget.reserve_metadata(60_000, 0)?;
    drop(successor);
    drop(body);
    drop(slot);
    assert_eq!(budget.stats()?.reserved_bytes, 0);
    assert_eq!(budget.stats()?.slots, 0);
    Ok(())
}
