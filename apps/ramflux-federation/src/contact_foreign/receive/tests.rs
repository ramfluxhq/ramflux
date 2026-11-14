// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Relay authentication/correlation controls use a fully signed current Native submission.
use super::*;
use crate::contact_foreign::test_support::{TestResult, node, submission};

fn forward() -> TestResult<ReachForward> {
    let request = submission()?;
    let mut forward = ReachForward {
        signing_key_id: String::new(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: String::new(),
        source_node_id: node().node_id,
        target_node_id: request.target_node_id,
        delivery_class: ramflux_node_core::contact_reach::ReachDeliveryClass::Message,
        required_capability: ramflux_node_core::contact_reach::ReachCapability::V1,
        submission: request.submission,
        migration_evidence: None,
    };
    forward.sign("source.example", node().node_signing_seed)?;
    Ok(forward)
}
#[test]
fn cr_receiving_relay_requires_exact_first_hop_node_service_and_target() -> TestResult {
    let forward = forward()?;
    for uri in [
        None,
        Some("spiffe://other.example/ramflux-federation"),
        Some("spiffe://source.example/ramflux-router"),
        Some("spiffe://target.example/ramflux-federation"),
    ] {
        assert!(
            authorized(&forward, "target.example", uri).is_err(),
            "a signed body cannot replace the actual peer identity: {uri:?}"
        );
    }
    assert!(
        authorized(&forward, "wrong.example", Some("spiffe://source.example/ramflux-federation"))
            .is_err(),
        "the receiver must match the signed target"
    );
    let peer =
        authorized(&forward, "target.example", Some("spiffe://source.example/ramflux-federation"))
            .map_err(|reason| format!("current peer: {reason:?}"))?;
    assert_eq!(peer.node_id, "source.example", "only the authenticated source may relay");
    Ok(())
}
#[test]
fn cr_receiving_relay_preserves_router_result_and_rejects_uncorrelated_or_source_only_arms()
-> TestResult {
    let forward = forward()?;
    for outcome in [
        wire::SubmitOutcome::Submitted,
        wire::SubmitOutcome::Quarantined,
        wire::SubmitOutcome::Duplicate,
        wire::SubmitOutcome::Unknown,
    ] {
        let result = OperationResult::Submit {
            envelope_id: forward.submission.envelope.envelope_id.clone(),
            outcome,
            reason: None,
        };
        assert_eq!(
            checked_reply(&forward, &ramflux_protocol::canonical_json_bytes(&result)?),
            Some(result),
            "receiving replies must preserve the exact result"
        );
    }
    for (envelope_id, outcome) in
        [("other", wire::SubmitOutcome::Submitted), ("frozen-native", wire::SubmitOutcome::Spooled)]
    {
        let result =
            OperationResult::Submit { envelope_id: envelope_id.into(), outcome, reason: None };
        assert!(
            checked_reply(&forward, &ramflux_protocol::canonical_json_bytes(&result)?).is_none(),
            "the router cannot change envelope identity or claim source spooling"
        );
    }
    let result = OperationResult::Submit {
        envelope_id: forward.submission.envelope.envelope_id.clone(),
        outcome: wire::SubmitOutcome::Refused,
        reason: Some(Reason::ForeignReadRefused),
    };
    let bytes = ramflux_protocol::canonical_json_bytes(&result)?;
    assert_eq!(
        checked_reply(&forward, &bytes),
        Some(result),
        "generic policy refusal stays unchanged"
    );
    assert!(checked_reply(&forward, br#"{"kind":"challenge"}"#).is_none(), "no new result arm");
    assert!(
        matches!(
            unknown(&forward),
            OperationResult::Submit { outcome: wire::SubmitOutcome::Unknown, reason: None, .. }
        ),
        "a lost router response leaves receiving admission uncertain"
    );
    Ok(())
}
#[test]
fn cr_receiving_relay_refuses_missing_submission_and_old_envelope_carrier() -> TestResult {
    let forward = forward()?;
    let mut body = serde_json::to_value(forward)?;
    let fields = body.as_object_mut().ok_or("forward object")?;
    let submission = fields.remove("submission").ok_or("complete submission")?;
    fields.insert("envelope".into(), submission.get("envelope").ok_or("sealed envelope")?.clone());
    assert!(
        ReachForward::decode(&ramflux_protocol::canonical_json_bytes(&body)?).is_err(),
        "an old envelope carrier cannot enter the current receiving profile"
    );
    body.as_object_mut().ok_or("forward object")?.remove("envelope");
    assert!(
        ReachForward::decode(&ramflux_protocol::canonical_json_bytes(&body)?).is_err(),
        "missing Submission must refuse without another decoder"
    );
    Ok(())
}
