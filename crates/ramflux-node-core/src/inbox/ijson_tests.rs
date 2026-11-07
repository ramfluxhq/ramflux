// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{TargetAckRequest, TargetNackRequest};
use ramflux_protocol::{Ack, Ext, Nack, NackReason, ProtocolError, SignatureAlg, SignedFields};
use serde::Serialize;

const SAFE: i64 = 9_007_199_254_740_991;
const UNSAFE: i64 = 9_007_199_254_740_992;

fn signed() -> SignedFields {
    SignedFields {
        signing_key_id: "key".into(),
        signature_alg: SignatureAlg::Ed25519,
        signature: "sig".into(),
    }
}

fn ack() -> Ack {
    Ack {
        schema: "ack.v1".into(),
        version: 1,
        domain: "ack".into(),
        ext: Ext::default(),
        signed: signed(),
        ack_id: "MARKER".into(),
        envelope_id: "envelope-id".into(),
        receiver_device_id: "device".into(),
        received_at: 0,
        cursor_after: None,
    }
}

fn nack() -> Nack {
    Nack {
        schema: "nack.v1".into(),
        version: 1,
        domain: "nack".into(),
        ext: Ext::default(),
        signed: signed(),
        nack_id: "nack-id".into(),
        envelope_id: "envelope-id".into(),
        receiver_device_id: "device".into(),
        reason: NackReason::Expired,
        received_at: 0,
        retry_after: None,
        proof_hash: None,
        new_home_node_hint: None,
    }
}

fn ack_request() -> TargetAckRequest {
    TargetAckRequest { target_delivery_id: "delivery".into(), ack: ack() }
}

fn nack_request() -> TargetNackRequest {
    TargetNackRequest { target_delivery_id: "delivery".into(), nack: nack() }
}

fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

fn patched(original: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let start =
        original.windows(needle.len()).position(|window| window == needle).unwrap_or_default();
    assert_eq!(
        original.windows(needle.len()).filter(|window| *window == needle).count(),
        1,
        "fixture marker is unique"
    );
    let mut result = original.to_vec();
    result.splice(start..start + needle.len(), replacement.iter().copied());
    result
}

fn assert_i_json_error<T>(result: Result<T, ProtocolError>) {
    assert_eq!(result.err().map(|error| matches!(error, ProtocolError::IJson(_))), Some(true));
}

#[test]
fn target_ack_request_ijson_predicates() -> Result<(), Box<dyn std::error::Error>> {
    let ack_bytes = bytes(&ack_request())?;
    for timestamp in [SAFE, -SAFE] {
        let fixture = patched(
            &ack_bytes,
            b"\"received_at\":0",
            format!("\"received_at\":{timestamp}").as_bytes(),
        );
        let mut expected = ack_request();
        expected.ack.received_at = timestamp;
        assert_eq!(ramflux_protocol::parse_i_json::<TargetAckRequest>(&fixture)?, expected);
    }
    for timestamp in [UNSAFE, -UNSAFE] {
        let fixture = patched(
            &ack_bytes,
            b"\"received_at\":0",
            format!("\"received_at\":{timestamp}").as_bytes(),
        );
        assert_i_json_error(ramflux_protocol::parse_i_json::<TargetAckRequest>(&fixture));
    }
    assert_eq!(ramflux_protocol::parse_i_json::<TargetAckRequest>(&ack_bytes)?, ack_request());

    let duplicate_ack_id =
        patched(&ack_bytes, b"\"ack_id\":\"MARKER\"", b"\"ack_id\":\"v\",\"ack_id\":\"v\"");
    assert_i_json_error(ramflux_protocol::parse_i_json::<TargetAckRequest>(&duplicate_ack_id));

    let mut with_ext = ack_request();
    with_ext.ack.ext.ext.insert("x_probe".into(), serde_json::json!("MARKER"));
    let ext_bytes = bytes(&with_ext)?;
    let duplicate_ext =
        patched(&ext_bytes, b"\"x_probe\":\"MARKER\"", b"\"x_probe\":\"v\",\"x_probe\":\"v\"");
    assert_i_json_error(ramflux_protocol::parse_i_json::<TargetAckRequest>(&duplicate_ext));

    let nack_bytes = bytes(&nack_request())?;
    for timestamp in [SAFE, -SAFE] {
        let fixture = patched(
            &nack_bytes,
            b"\"received_at\":0",
            format!("\"received_at\":{timestamp}").as_bytes(),
        );
        let mut expected = nack_request();
        expected.nack.received_at = timestamp;
        assert_eq!(ramflux_protocol::parse_i_json::<TargetNackRequest>(&fixture)?, expected);
    }
    for timestamp in [UNSAFE, -UNSAFE] {
        let fixture = patched(
            &nack_bytes,
            b"\"received_at\":0",
            format!("\"received_at\":{timestamp}").as_bytes(),
        );
        assert_i_json_error(ramflux_protocol::parse_i_json::<TargetNackRequest>(&fixture));
    }
    assert_eq!(ramflux_protocol::parse_i_json::<TargetNackRequest>(&nack_bytes)?, nack_request());

    let mut nack_with_ext = nack_request();
    nack_with_ext.nack.ext.ext.insert("x_probe".into(), serde_json::json!("MARKER"));
    let nack_ext_bytes = bytes(&nack_with_ext)?;
    let nack_duplicate_ext =
        patched(&nack_ext_bytes, b"\"x_probe\":\"MARKER\"", b"\"x_probe\":\"v\",\"x_probe\":\"v\"");
    assert_i_json_error(ramflux_protocol::parse_i_json::<TargetNackRequest>(&nack_duplicate_ext));
    Ok(())
}
