// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Literal carrier bytes and semantic decoding; service routing has separate integration controls.
use super::*;
use crate::contact_reach::{Challenge, CostPurpose, decode};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const REFUSALS: [&str; 11] = [
    "foreign_read_refused",
    "reach_policy_required",
    "conversation_grant_expired",
    "reach_route_invalid",
    "cost_required",
    "cost_invalid",
    "foreign_spam_limited",
    "foreign_rate_limited",
    "foreign_capacity",
    "foreign_capability_missing",
    "group_epoch_stale",
];
const ERRORS: [&str; 10] = [
    "feature_disabled",
    "foreign_invalid_frame",
    "foreign_payload_too_large",
    "foreign_policy_denied",
    "foreign_capability_missing",
    "foreign_unavailable",
    "foreign_rate_limited",
    "foreign_capacity",
    "reach_route_invalid",
    "cost_invalid",
];
fn submit(outcome: &str, reason: &str) -> String {
    format!(
        r#"{{"kind":"submit_result","request_id":"{ID}","result":{{"envelope_id":"envelope","kind":"submit","outcome":"{outcome}","reason":{reason}}}}}"#
    )
}
fn error(reason: &str, retry: &str, revision: &str) -> String {
    format!(
        r#"{{"kind":"submit_result","request_id":"{ID}","result":{{"current_revision":{revision},"kind":"error","reason":"{reason}","retry_after_ms":{retry}}}}}"#
    )
}
fn round_trip(literal: &str) -> TestResult {
    let value: SourceSubmitResponse = decode(literal.as_bytes(), MAX_SUBMIT_RESPONSE_BYTES)?;
    assert_eq!(
        crate::canonical_json_bytes(&value)?,
        literal.as_bytes(),
        "source carrier serialization must retain the independently specified canonical bytes"
    );
    let raw: serde_json::Value = crate::parse_i_json(literal.as_bytes())?;
    assert_eq!(
        serde_json::to_value(&value.result)?,
        raw.get("result").ok_or("result")?.clone(),
        "the source carrier must not introduce a second owner-result schema"
    );
    Ok(())
}

#[test]
fn cr_submit_carrier_goldens() -> TestResult {
    const OUTCOMES: [&str; 5] = ["submitted", "spooled", "quarantined", "duplicate", "unknown"];
    for outcome in OUTCOMES {
        round_trip(&submit(outcome, "null"))?;
    }
    for reason in REFUSALS {
        round_trip(&submit("refused", &format!("\"{reason}\"")))?;
    }
    for reason in ERRORS {
        round_trip(&error(
            reason,
            if reason == "foreign_rate_limited" { "1000" } else { "null" },
            "null",
        ))?;
    }
    Ok(())
}

fn refused(literal: &str) {
    assert!(
        decode::<SourceSubmitResponse>(literal.as_bytes(), MAX_SUBMIT_RESPONSE_BYTES).is_err(),
        "malformed or semantically forbidden source response was accepted: {literal}"
    );
}

#[test]
fn cr_submit_carrier_decode_rejects_invalid_nulls_reasons_and_fields() {
    let spooled = submit("spooled", "null");
    refused(&spooled.replace("\"spooled\"", "\"refused\""));
    refused(&submit("spooled", "\"cost_required\""));
    refused(&submit("refused", "\"foreign_unavailable\""));
    refused(&spooled.replace(",\"reason\":null", ""));
    refused(&spooled.replace(&format!("\"request_id\":\"{ID}\","), ""));
    refused(&spooled.replace(
        &format!("\"request_id\":\"{ID}\""),
        &format!("\"request_id\":\"{ID}\",\"request_id\":\"{ID}\""),
    ));
    refused(&spooled.replacen("\"kind\":\"submit_result\"", "\"kind\":\"query_result\"", 1));
    refused(&spooled.replacen('{', "{\"admin_token\":\"forbidden\",", 1));
    refused(&error("cost_required", "null", "null"));
    refused(&error("foreign_spam_limited", "1000", "null"));
    refused(&error("foreign_rate_limited", "null", "null"));
    refused(&error("foreign_rate_limited", "999", "null"));
    refused(&error("foreign_unavailable", "1000", "null"));
    refused(&error("foreign_unavailable", "null", "1"));
}

#[test]
fn cr_submit_carrier_decode_rejects_other_well_formed_result_arms() -> TestResult {
    let challenge = OperationResult::Challenge {
        challenge: crate::custody::Envelope {
            body: Challenge {
                version: 1,
                issuer: "node.example".into(),
                purpose: CostPurpose::Stranger,
                source_root: ID.into(),
                recipient_root: Some(ID.into()),
                operation_hash: ID.into(),
                nonce: ID.into(),
                difficulty: 20,
                issued_at: 1_700_000_000,
                expires_at: 1_700_000_300,
            },
            signature: crate::encode_base64url([0; 64]),
        },
    };
    let policy =
        OperationResult::Policy { revision: 1, outcome: super::super::super::Applied::Applied };
    for result in [challenge, policy] {
        // Prove the child arm is well formed on its owning codec before rejecting its placement.
        let child = crate::canonical_json_bytes(&result)?;
        let _: OperationResult = decode(&child, MAX_SUBMIT_RESPONSE_BYTES)?;
        let response = SourceSubmitResponse {
            kind: SourceSubmitResponseKind::SubmitResult,
            request_id: ID.into(),
            result,
        };
        refused(std::str::from_utf8(&crate::canonical_json_bytes(&response)?)?);
    }
    Ok(())
}

fn request() -> Result<SourceSubmitRequest, Box<dyn std::error::Error>> {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../sender_transcript_vectors.json"))?;
    let envelope =
        serde_json::from_value(vector.get("envelope").ok_or("envelope vector")?.clone())?;
    let root = crate::encode_base64url([1; 32]);
    let request = SourceSubmitRequest {
        kind: super::super::super::SourceSubmitKind::Submit,
        request_id: ID.into(),
        remaining_ms: 1000,
        target_node_id: "node.example".into(),
        submission: crate::contact_reach::Submission {
            envelope,
            cost: None,
            route: crate::custody::Envelope {
                body: crate::contact_reach::Route {
                    version: 1,
                    source: crate::custody::DeviceRef {
                        account_anchor: ID.into(),
                        device_id: "primary".into(),
                        device_epoch: 1,
                    },
                    recipient_root: root.clone(),
                    conversation_id: crate::message::dm_scope::derive(ID, &root)?,
                    traffic: crate::contact_reach::Traffic::Dm,
                    group: None,
                    envelope_hash: ID.into(),
                    authority_head_hash: ID.into(),
                    issued_at: 1_700_000_000,
                    expires_at: 1_700_003_600,
                },
                signature: crate::encode_base64url([0; 64]),
            },
        },
    };
    request.validate()?;
    Ok(request)
}

#[test]
fn cr_submit_carrier_correlation_maps_only_matching_inner_bytes() -> TestResult {
    let request = request()?;
    let result = OperationResult::Submit {
        envelope_id: request.submission.envelope.envelope_id.clone(),
        outcome: SubmitOutcome::Spooled,
        reason: None,
    };
    let response = SourceSubmitResponse {
        kind: SourceSubmitResponseKind::SubmitResult,
        request_id: ID.into(),
        result: result.clone(),
    };
    assert_eq!(
        request.owner_result(response.clone()),
        result,
        "a correlated inner result must reach the owner unchanged"
    );
    let mut wrong_request = response.clone();
    wrong_request.request_id = crate::encode_base64url([2; 32]);
    assert_eq!(
        request.owner_result(wrong_request),
        request.unknown_result(),
        "an unrelated service response must never settle the captured envelope"
    );
    let mut wrong_envelope = response;
    wrong_envelope.result = OperationResult::Submit {
        envelope_id: "another-envelope".into(),
        outcome: SubmitOutcome::Submitted,
        reason: None,
    };
    assert_eq!(
        request.owner_result(wrong_envelope),
        request.unknown_result(),
        "an envelope substitution must preserve unknown delivery for the original id"
    );
    let error = SourceSubmitResponse {
        kind: SourceSubmitResponseKind::SubmitResult,
        request_id: ID.into(),
        result: OperationResult::Error {
            reason: Reason::ForeignRateLimited,
            retry_after_ms: Some(1000),
            current_revision: None,
        },
    };
    assert_eq!(
        request.owner_result(error.clone()),
        error.result,
        "pre-forward error mapping must preserve its exact nulls and rate hint"
    );
    Ok(())
}

#[test]
fn cr_submit_carrier_rejects_a_complete_query_arm() -> TestResult {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    let policy = serde_json::json!({"body":{
        "version":1,"operation_id":ID,"account_anchor":ID,"home_head_hash":ID,
        "expected_revision":0,"revision":1,"mode":"contacts_only",
        "authority_head_hash":ID,"master_certificate_hash":ID,
        "actor":{"account_anchor":ID,"device_id":"phone","device_epoch":1},
        "issued_at":1_700_000_000,"expires_at":1_700_000_300},
        "signature":crate::encode_base64url([0;64])});
    let client = serde_json::json!({
        "schema":"ramflux.well_known_client.v1","node_id":"node.example",
        "node_public_key":ID,"node_ca_cert_pem":"test-shape-only",
        "gateway_quic_addr":"node.example:443","gateway_tcp_addr":"node.example:443",
        "gateway_server_name":"node.example","relay_quic_addr":"node.example:443",
        "relay_server_name":"node.example","prekey_http_url":"https://node.example/prekey",
        "signaling_turn_addr":"node.example:443","protocol_versions":[],"client_capabilities":[],
        "updated_at":1_700_000_000,"expires_at":1_700_000_060,
        "signature":crate::encode_base64url([0;64])});
    let result: OperationResult = serde_json::from_value(
        serde_json::json!({"kind":"query","reply":{
            "snapshot":{"body":{"version":1,"source_node":"node.example","target_node":"owner.example",
                "account_anchor":ID,"request_nonce":ID,"request_hash":ID,"payload_hash":ID,
                "issued_at":1_700_000_000,"expires_at":1_700_000_060},
                "signature":crate::encode_base64url([0;64])},
            "payload":{"home":{"home":vector.get("genesis").ok_or("home vector")?,"predecessors":[]},
                "discovery":{"client":client,"server":{}},"manifest":{},"prekey":null,
                "node_continuity":[],"reach":policy,"profile":null,"custodian_history":[],"directory":null}
        }}),
    )?;
    // This is a complete typed Query carrier, not a claim that its dummy discovery is trusted.
    let bytes = crate::canonical_json_bytes(&result)?;
    let _: OperationResult = decode(&bytes, crate::contact_reach::MAX_FRAME_BYTES)?;
    let response = SourceSubmitResponse {
        kind: SourceSubmitResponseKind::SubmitResult,
        request_id: ID.into(),
        result,
    };
    assert!(
        response.validate().is_err(),
        "a complete existing Query result must be forbidden in the Submit response"
    );
    let bytes = crate::canonical_json_bytes(&response)?;
    assert!(
        decode::<SourceSubmitResponse>(&bytes, crate::contact_reach::MAX_FRAME_BYTES).is_err(),
        "the deserializer must enforce the result arm even with a looser outer byte limit"
    );
    Ok(())
}
