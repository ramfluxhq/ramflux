// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Decoder and authenticated-role controls only; live delivery is tested at service integration.
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OWN: &str = "source.example";

fn submission() -> TestResult<Vec<u8>> {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../crates/ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    let recipient = ramflux_protocol::encode_base64url([1; 32]);
    let conversation = ramflux_protocol::message::dm_scope::derive(ID, &recipient)?;
    Ok(ramflux_protocol::canonical_json_bytes(&serde_json::json!({
        "kind":"submit", "request_id":ID, "remaining_ms":1000,
        "target_node_id":"target.example",
        "submission": {"cost":null, "envelope":vector.get("envelope").ok_or("envelope vector")?,
            "route": {"signature":ramflux_protocol::encode_base64url([0;64]),
                "body": {"version":1, "source":{"account_anchor":ID,"device_id":"phone","device_epoch":1},
                    "recipient_root":recipient,"conversation_id":conversation,
                    "traffic":"dm","group":null,"envelope_hash":ID,"authority_head_hash":ID,
                    "issued_at":1_700_000_000,"expires_at":1_700_003_600}}}
    }))?)
}
fn status(bytes: &[u8], path: &str, peer: Option<&str>) -> TestResult<u16> {
    match decode("POST", path, bytes, OWN, peer) {
        Ok(_) => Err("negative control unexpectedly decoded".into()),
        Err(response) => {
            assert!(
                response.frame.body.get("request_id").is_none(),
                "uncorrelated failures must never guess or echo request identity"
            );
            Ok(response.frame.status)
        }
    }
}
#[test]
fn cr_submit_request_dispatch_requires_own_node_and_service() -> TestResult {
    let bytes = submission()?;
    for role in ["ramflux-router", "ramflux-gateway"] {
        let uri = format!("spiffe://{OWN}/{role}");
        assert!(
            matches!(
                decode("POST", wire::FOREIGN_PATH, &bytes, OWN, Some(&uri)),
                Ok(Request::Submit(_))
            ),
            "both authorized own-node roles must reach the source handler"
        );
        let foreign = format!("spiffe://other.example/{role}");
        assert_eq!(
            status(&bytes, wire::FOREIGN_PATH, Some(&foreign))?,
            403,
            "a matching service name on another node confers no source authority"
        );
    }
    assert_eq!(
        status(&bytes, wire::FOREIGN_PATH, Some("spiffe://source.example/ramflux-federation"))?,
        403,
        "an own-node certificate still needs the exact source caller role"
    );
    assert_eq!(
        status(&bytes, wire::FOREIGN_PATH, None)?,
        403,
        "missing TLS identity must not reach correlated execution"
    );
    for path in [wire::PEER_QUERY_PATH, wire::SNAPSHOT_PATH] {
        assert_eq!(
            status(&bytes, path, Some("spiffe://source.example/ramflux-router"))?,
            400,
            "Submit is forbidden on peer-query and snapshot paths"
        );
    }
    Ok(())
}
#[test]
fn cr_submit_request_dispatch_keeps_closed_fields_and_separate_query_bound() -> TestResult {
    let bytes = submission()?;
    let uri = Some("spiffe://source.example/ramflux-router");
    let raw = std::str::from_utf8(&bytes)?;
    let duplicate =
        raw.replacen("\"kind\":\"submit\"", "\"kind\":\"submit\",\"kind\":\"submit\"", 1);
    let unknown = raw.replacen('{', "{\"admin_token\":\"forbidden\",", 1);
    for malformed in [duplicate, unknown, raw.replace("\"cost\":null,", "")] {
        assert_eq!(
            status(malformed.as_bytes(), wire::FOREIGN_PATH, uri)?,
            400,
            "strict Submit decoding must precede any correlated execution"
        );
    }
    let query = serde_json::json!({"kind":"query", "request_id":ID, "remaining_ms":1000,
        "query":{"version":1,"source_node":OWN,"target_node":"target.example",
            "account_anchor":ID,"card_hash":null,"nonce":ID,"base":null,"device_ref":null}});
    let query = ramflux_protocol::canonical_json_bytes(&query)?;
    assert!(
        matches!(decode("POST", wire::FOREIGN_PATH, &query, OWN, uri), Ok(Request::Query(_))),
        "the original own-query role and grammar must remain usable"
    );
    let mut padded_query = query;
    padded_query.resize(8193, b' ');
    assert_eq!(
        status(&padded_query, wire::FOREIGN_PATH, uri)?,
        400,
        "Submit's aggregate ceiling must not enlarge the Query budget"
    );
    let mut padded_submit = bytes;
    padded_submit.resize(wire::MAX_FRAME_BYTES + 1, b' ');
    assert_eq!(
        status(&padded_submit, wire::FOREIGN_PATH, uri)?,
        413,
        "source requests above the aggregate ceiling must refuse before decoding"
    );
    Ok(())
}

#[test]
fn cr_cost_internal_hop_dispatch_has_closed_roles_and_paths() -> TestResult {
    let public = wire::CostRequest {
        request_id: ID.into(),
        remaining_ms: 1000,
        request: wire::ChallengeRequest {
            purpose: wire::CostPurpose::Stranger,
            source_root: ID.into(),
            recipient_root: Some(ID.into()),
            operation_hash: ID.into(),
        },
    };
    let source = wire::SourceCostRequest {
        kind: wire::SourceCostKind::Cost,
        request_id: ID.into(),
        remaining_ms: 1000,
        target_node_id: "target.example".into(),
        request: public.request.clone(),
    };
    let public_bytes = ramflux_protocol::canonical_json_bytes(&public)?;
    let own_bytes = ramflux_protocol::canonical_json_bytes(&source)?;
    for service in ["ramflux-router", "ramflux-gateway"] {
        let uri = format!("spiffe://{OWN}/{service}");
        assert!(
            matches!(
                decode("POST", wire::FOREIGN_PATH, &own_bytes, OWN, Some(&uri)),
                Ok(Request::Cost(_))
            ),
            "the exact own-node router/gateway role may dispatch a source cost call"
        );
        assert_eq!(
            status(&public_bytes, wire::PEER_COST_PATH, Some(&uri))?,
            403,
            "an owner service role cannot enter the public cost issuer path"
        );
    }
    let peer = "spiffe://peer.example/ramflux-federation";
    assert!(
        matches!(
            decode("POST", wire::PEER_COST_PATH, &public_bytes, OWN, Some(peer)),
            Ok(Request::PeerCost(_))
        ),
        "the public body has a separate authenticated federation-only issuer path"
    );
    assert_eq!(
        status(&own_bytes, wire::PEER_QUERY_PATH, Some(peer))?,
        400,
        "cost cannot be smuggled into the foreign query path"
    );
    assert_eq!(
        status(&public_bytes, wire::FOREIGN_PATH, Some(peer))?,
        400,
        "the public cost body cannot be reinterpreted as a source Submit or Query"
    );
    assert_eq!(
        status(&own_bytes, wire::PEER_COST_PATH, Some(peer))?,
        400,
        "the public path never accepts the own-service wrapper"
    );
    Ok(())
}
