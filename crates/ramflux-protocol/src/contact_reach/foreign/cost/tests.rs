// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::contact_reach::{CostPurpose, decode};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn request() -> SourceCostRequest {
    SourceCostRequest {
        kind: SourceCostKind::Cost,
        request_id: crate::encode_base64url([1; 32]),
        remaining_ms: 1000,
        target_node_id: "issuer.example".into(),
        request: ChallengeRequest {
            purpose: CostPurpose::Stranger,
            source_root: crate::encode_base64url([2; 32]),
            recipient_root: Some(crate::encode_base64url([3; 32])),
            operation_hash: crate::encode_base64url([4; 32]),
        },
    }
}

#[test]
fn cr_reach_error_lifting_goldens_and_cost_closed_errors() -> TestResult {
    let request = request();
    for (reason, name) in [
        (Reason::CustodyRefused, "custody_refused"),
        (Reason::ForeignStorageUnavailable, "foreign_storage_unavailable"),
        (Reason::ReachCommandExpired, "reach_command_expired"),
    ] {
        let error = OperationResult::Error { reason, retry_after_ms: None, current_revision: None };
        let literal = format!(
            r#"{{"current_revision":null,"kind":"error","reason":"{name}","retry_after_ms":null}}"#
        );
        assert_eq!(
            crate::canonical_json_bytes(&error)?,
            literal.as_bytes(),
            "executor errors must retain exact canonical null hints"
        );
        let decoded: OperationResult = decode(literal.as_bytes(), 4096)?;
        assert_eq!(decoded, error, "the appended reason must survive the owner codec");
        let response = SourceCostResponse {
            kind: SourceCostResultKind::CostResult,
            request_id: request.request_id.clone(),
            result: error,
        };
        assert_eq!(
            request.validate_response(&response).is_ok(),
            reason != Reason::ReachCommandExpired,
            "roster expiry must not be lifted as a cost issuer response"
        );
    }
    for reason in [Reason::CostRequired, Reason::ForeignSpamLimited, Reason::GroupEpochStale] {
        let response = SourceCostResponse {
            kind: SourceCostResultKind::CostResult,
            request_id: request.request_id.clone(),
            result: OperationResult::Error { reason, retry_after_ms: None, current_revision: None },
        };
        assert!(
            request.validate_response(&response).is_err(),
            "a peer's out-of-set error must not cross the cost boundary"
        );
    }
    Ok(())
}

#[test]
fn cr_cost_carriers_keep_public_body_and_correlation() -> TestResult {
    let source = request();
    source.validate()?;
    let public = source.public_request();
    let bytes = crate::canonical_json_bytes(&public)?;
    let decoded: CostRequest = decode(&bytes, MAX_COST_REQUEST_BYTES)?;
    assert_eq!(decoded, public, "peer and issuer reuse identical public body bytes");
    let response = SourceCostResponse {
        kind: SourceCostResultKind::CostResult,
        request_id: source.request_id.clone(),
        result: OperationResult::Error {
            reason: Reason::ForeignStorageUnavailable,
            retry_after_ms: None,
            current_revision: None,
        },
    };
    source.validate_response(&response)?;
    let mut wrong = response.clone();
    wrong.request_id = crate::encode_base64url([5; 32]);
    assert!(source.validate_response(&wrong).is_err(), "an unrelated response must not issue work");
    let mut expired = source;
    expired.remaining_ms = 0;
    assert!(expired.validate().is_err(), "a spent deadline cannot start another hop");
    assert!(
        decode::<CostRequest>(&crate::canonical_json_bytes(&expired)?, MAX_COST_REQUEST_BYTES)
            .is_err(),
        "the own cost carrier cannot be accepted as the closed public body"
    );
    Ok(())
}
