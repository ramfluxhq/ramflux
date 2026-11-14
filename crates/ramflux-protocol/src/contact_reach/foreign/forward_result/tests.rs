// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::contact_reach::decode;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn literal(result: &str) -> String {
    format!(
        r#"{{"envelope_id":"envelope","kind":"forward_result","result":{result},"source_node_id":"a.example","target_node_id":"b.example"}}"#
    )
}

#[test]
fn cr_forward_result_goldens() -> TestResult {
    const OUTCOMES: [&str; 4] = ["submitted", "quarantined", "duplicate", "unknown"];
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
    let mut arms = Vec::new();
    for outcome in OUTCOMES {
        arms.push(format!(
            r#"{{"envelope_id":"envelope","kind":"submit","outcome":"{outcome}","reason":null}}"#
        ));
    }
    for reason in REFUSALS {
        arms.push(format!(r#"{{"envelope_id":"envelope","kind":"submit","outcome":"refused","reason":"{reason}"}}"#));
    }
    for reason in ERRORS {
        let retry = if reason == "foreign_rate_limited" { "1000" } else { "null" };
        arms.push(format!(r#"{{"current_revision":null,"kind":"error","reason":"{reason}","retry_after_ms":{retry}}}"#));
    }
    for arm in arms {
        let bytes = literal(&arm);
        let response: ForwardResult = decode(bytes.as_bytes(), 4096)?;
        assert_eq!(
            crate::canonical_json_bytes(&response)?,
            bytes.as_bytes(),
            "the peer result must match canonical literal bytes"
        );
        assert_eq!(
            ForwardResult::source_result(
                Some(&response),
                200,
                "a.example",
                "b.example",
                "envelope"
            ),
            response.result,
            "a correlated mesh result must preserve its owner arm"
        );
        let bare: OperationResult = decode(arm.as_bytes(), 4096)?;
        validate_receiving_result(&bare)?;
        assert_eq!(bare, response.result, "same-node and peer replies share the receiving arm");
    }
    let forbidden =
        literal(r#"{"envelope_id":"envelope","kind":"submit","outcome":"spooled","reason":null}"#);
    assert!(
        decode::<ForwardResult>(forbidden.as_bytes(), 4096).is_err(),
        "the receiver cannot report source-only spooling"
    );
    Ok(())
}

#[test]
fn cr_forward_result_correlation_preserves_original_identity() -> TestResult {
    let bytes = literal(
        r#"{"envelope_id":"envelope","kind":"submit","outcome":"quarantined","reason":null}"#,
    );
    let response: ForwardResult = decode(bytes.as_bytes(), 4096)?;
    let unknown = OperationResult::Submit {
        envelope_id: "envelope".into(),
        outcome: SubmitOutcome::Unknown,
        reason: None,
    };
    for (source, target, envelope, status) in [
        ("wrong.example", "b.example", "envelope", 200),
        ("a.example", "wrong.example", "envelope", 200),
        ("a.example", "b.example", "other", 200),
        ("a.example", "b.example", "envelope", 403),
    ] {
        let result =
            ForwardResult::source_result(Some(&response), status, source, target, envelope);
        assert_eq!(
            result,
            OperationResult::Submit {
                envelope_id: envelope.into(),
                outcome: SubmitOutcome::Unknown,
                reason: None,
            },
            "a substituted or uncorrelated reply cannot settle delivery"
        );
    }
    assert_eq!(
        ForwardResult::source_result(None, 200, "a.example", "b.example", "envelope"),
        unknown,
        "a timeout or undecodable response preserves the original retry identity"
    );
    for changed in [
        bytes.replace("\"reason\":null", "\"reason\":\"cost_required\""),
        bytes.replace(",\"reason\":null", ""),
        bytes.replacen('{', "{\"extra\":null,", 1),
        bytes.replace(
            "\"envelope_id\":\"envelope\",\"kind\":\"submit\"",
            "\"envelope_id\":\"other\",\"kind\":\"submit\"",
        ),
    ] {
        assert!(
            decode::<ForwardResult>(changed.as_bytes(), 4096).is_err(),
            "semantic decoding must reject invalid peer result fields"
        );
    }
    Ok(())
}
