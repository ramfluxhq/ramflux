// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source submission decisions use durable committed windows, never legacy route timing.
use super::*;
use crate::{RouterForwardPreparation, RouterSubmitOutcome};

fn input(
    s: &Scenario,
) -> TestResult<(ramflux_crypto::RootQualifiedDeviceRef, ramflux_protocol::Envelope)> {
    let request = super::forwarded::sender(&s.target)?;
    let (_, source) = crate::DeviceAuthKeyResponse::forwarded_envelope_source(&request.envelope)?;
    Ok((source, request.envelope))
}
fn prepare(s: &Scenario, now: u64) -> TestResult<RouterForwardPreparation> {
    let (source, envelope) = input(s)?;
    Ok(s.a.core.prepare_committed_home_forward(s.a.store()?, &source, envelope, now, 5)?)
}
fn closed(s: &Scenario, now: u64) -> TestResult {
    let RouterForwardPreparation::Complete(outcome) = prepare(s, now)? else {
        return Err("forwarded after closure".into());
    };
    let RouterSubmitOutcome::RejectedHomeNodeMigrated(delivery) = *outcome else {
        return Err("signed refusal required".into());
    };
    assert_ne!(delivery.nack.signed.signature, "");
    assert_eq!(delivery.new_home_node_hint, "B");
    Ok(())
}
#[test]
fn submit_to_migrated_target_inside_window_forwards_with_commit_proof_and_unchanged_envelope()
-> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    s.commit(&op)?;
    let (source, envelope) = input(&s)?;
    let RouterForwardPreparation::Forward(reservation) = s.a.core.prepare_committed_home_forward(
        s.a.store()?,
        &source,
        envelope.clone(),
        NOW + 3,
        5,
    )?
    else {
        return Err("no forward".into());
    };
    let plan = reservation.plan().ok_or("plan")?;
    let evidence = plan.migration_evidence.as_ref().ok_or("evidence")?;
    crypto::verify_node(evidence.commit_proof.as_ref().ok_or("proof")?, "A", &public(8))?;
    let mut forwarded = plan.envelope.clone();
    assert_eq!(forwarded.ext.ext.remove(crate::HOME_NODE_FORWARD_COUNT_EXT_KEY), Some(json!(1)));
    assert_eq!(forwarded, envelope);
    assert_eq!(plan.federated_forward_request("A").migration_evidence, plan.migration_evidence);
    Ok(())
}
#[test]
fn submit_after_forward_until_returns_signed_migrated_refusal_and_never_forwards() -> TestResult {
    let s = Scenario::prepared()?;
    s.commit(&s.seal()?)?;
    drop(prepare(&s, NOW + 3)?); // Positive open-window arm.
    closed(&s, NOW + 2 + FORWARD_SECONDS)
}
#[test]
fn clock_rollback_after_observed_closure_never_reopens_forwarding_after_restart() -> TestResult {
    let mut s = Scenario::prepared()?;
    s.commit(&s.seal()?)?;
    let end = NOW + 2 + FORWARD_SECONDS;
    assert!(matches!(prepare(&s, end - 100)?, RouterForwardPreparation::Forward(_)));
    // No artificial floor or latch: the real submission preparation observes closure.
    closed(&s, end)?;
    s.a.restart()?;
    closed(&s, end - 100)?;
    // The drain worker must use this same store hook before selecting any forwards.
    assert!(s.a.store()?.migration_forward_window(&s.target, end - 100)?.is_none());
    assert!(s.a.store()?.acquire_home_operation(&s.anchor).is_err());
    Ok(())
}
#[test]
fn window_latch_persist_failure_fails_closed_without_forwarding() -> TestResult {
    let s = Scenario::prepared()?;
    s.commit(&s.seal()?)?;
    s.a.fail_commit()?;
    assert!(prepare(&s, NOW + 2 + FORWARD_SECONDS).is_err());
    // Failed transaction changed neither the clock nor the latch.
    assert!(matches!(prepare(&s, NOW + 3)?, RouterForwardPreparation::Forward(_)));
    closed(&s, NOW + 2 + FORWARD_SECONDS)
}
#[test]
fn forwarded_envelope_is_never_forwarded_a_second_hop() -> TestResult {
    let s = Scenario::prepared()?;
    s.commit(&s.seal()?)?;
    let (source, mut envelope) = input(&s)?;
    envelope.ext.ext.insert(crate::HOME_NODE_FORWARD_COUNT_EXT_KEY.into(), json!(1));
    assert!(matches!(
        s.a.core.prepare_committed_home_forward(s.a.store()?, &source, envelope, NOW + 3, 5)?,
        RouterForwardPreparation::Complete(outcome) if matches!(*outcome,
            RouterSubmitOutcome::RejectedSecurity { .. })
    ));
    assert!(matches!(prepare(&s, NOW + 3)?, RouterForwardPreparation::Forward(_)));
    Ok(())
}
#[test]
fn forward_failure_or_dormant_reply_is_retryable_never_success_or_terminal_nack() -> TestResult {
    let s = Scenario::prepared()?;
    s.commit(&s.seal()?)?;
    for (accepted, outcome) in [
        (false, "forward_retryable"),
        (true, "forward_retryable"),
        (false, "duplicate_federated_forward"),
        (true, "federation_spooled_offline_peer"),
    ] {
        let RouterForwardPreparation::Forward(reservation) = prepare(&s, NOW + 3)? else {
            return Err("no forward".into());
        };
        let response = crate::FederatedEnvelopeForwardResponse {
            accepted,
            source_node_id: "A".into(),
            target_node_id: "B".into(),
            delivery: crate::EnvelopeSubmitResponse {
                migration_refusal: Some(Refusal::DormantInbox),
                outcome: outcome.into(),
                target_delivery_id: s.target.clone(),
                inbox_seq: None,
                cursor: None,
                nack: None,
            },
        };
        assert!(matches!(
            s.a.core.complete_home_node_forward(reservation, Ok(response)),
            RouterSubmitOutcome::ForwardInProgress { .. }
        ));
    }
    let RouterForwardPreparation::Forward(reservation) = prepare(&s, NOW + 3)? else {
        return Err("no forward".into());
    };
    assert!(matches!(
        s.a.core.complete_home_node_forward(reservation, Err(storage("lost reply"))),
        RouterSubmitOutcome::ForwardInProgress { .. }
    ));
    let RouterForwardPreparation::Forward(reservation) = prepare(&s, NOW + 3)? else {
        return Err("no forward".into());
    };
    let response = crate::FederatedEnvelopeForwardResponse {
        accepted: true,
        source_node_id: "A".into(),
        target_node_id: "B".into(),
        delivery: crate::EnvelopeSubmitResponse {
            migration_refusal: None,
            outcome: "offline_queued".into(),
            target_delivery_id: s.target.clone(),
            inbox_seq: Some(1),
            cursor: None,
            nack: None,
        },
    };
    assert!(matches!(
        s.a.core.complete_home_node_forward(reservation, Ok(response)),
        RouterSubmitOutcome::ForwardedHomeNodeMigrated(_)
    ));
    Ok(())
}

#[test]
fn legacy_route_expiry_does_not_truncate_committed_forward_window() -> TestResult {
    let s = Scenario::prepared()?;
    s.commit(&s.seal()?)?;
    let RouterForwardPreparation::Forward(reservation) = prepare(&s, NOW + 3)? else {
        return Err("no forward".into());
    };
    let mut legacy = reservation.plan().ok_or("plan")?.route.clone();
    legacy.expires_at = i64::try_from(NOW)?;
    s.a.core
        .control
        .lock()
        .map_err(|e| e.to_string())?
        .home_node_routes
        .insert(s.anchor.clone(), legacy);
    drop(reservation);
    assert!(matches!(prepare(&s, NOW + 10)?, RouterForwardPreparation::Forward(_)));
    closed(&s, NOW + 2 + FORWARD_SECONDS)
}
