// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fn request() -> wire::CostRequest {
    wire::CostRequest {
        request_id: ID.into(),
        remaining_ms: 1000,
        request: wire::ChallengeRequest {
            purpose: wire::CostPurpose::Stranger,
            source_root: ID.into(),
            recipient_root: Some(ID.into()),
            operation_hash: ID.into(),
        },
    }
}
#[test]
fn cr_cost_peer_error_lifting_keeps_only_pinned_issuer_answers() -> TestResult {
    let request = request();
    for reason in [
        Reason::CustodyRefused,
        Reason::ForeignStorageUnavailable,
        Reason::ForeignReadRefused,
        Reason::ForeignRateLimited,
    ] {
        let expected = error(reason);
        let reply = wire::CostResponse { request_id: ID.into(), result: expected.clone() };
        let bytes = ramflux_protocol::canonical_json_bytes(&reply)?;
        let checked = checked_reply(&request, &bytes, "issuer.example")
            .map_err(|reason| format!("unexpected valid reply refusal: {reason:?}"))?;
        assert_eq!(
            ramflux_protocol::canonical_json_bytes(&checked)?,
            bytes,
            "valid issuer errors must cross both hops without changing their null hints"
        );
        assert_eq!(
            checked.result, expected,
            "error lifting cannot fabricate a successful challenge"
        );
    }
    for reason in [Reason::ReachCommandExpired, Reason::CostRequired, Reason::ForeignSpamLimited] {
        let reply = wire::CostResponse { request_id: ID.into(), result: error(reason) };
        assert!(
            matches!(
                checked_reply(
                    &request,
                    &ramflux_protocol::canonical_json_bytes(&reply)?,
                    "issuer.example"
                ),
                Err(Reason::ForeignUnavailable)
            ),
            "out-of-set peer errors must become foreign_unavailable"
        );
    }
    let wrong = wire::CostResponse {
        request_id: ramflux_protocol::encode_base64url([1; 32]),
        result: error(Reason::ForeignStorageUnavailable),
    };
    assert!(
        matches!(
            checked_reply(
                &request,
                &ramflux_protocol::canonical_json_bytes(&wrong)?,
                "issuer.example"
            ),
            Err(Reason::ForeignUnavailable)
        ),
        "a mismatched peer request id must not settle this cost operation"
    );
    Ok(())
}
