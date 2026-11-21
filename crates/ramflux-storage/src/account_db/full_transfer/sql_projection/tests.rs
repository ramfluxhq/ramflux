// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Excluded execution fields cannot be admitted as portable or accepted in the selected file.
use super::*;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn compact_contact_metadata_keeps_public_fields_and_excludes_reply_execution() -> TestResult {
    let projection = SqlProjection::ContactRequestMetadataV1;
    let nonce = ramflux_protocol::encode_base64url([40; 32]);
    let input =
        json!({"nonce":nonce,"issued_at":100,"note":"retained note","needs_reply":"accept"});
    let raw = serde_json::to_vec(&input)?;
    assert!(projection.portable(&raw).is_err());
    let output = projection.source(&raw)?;
    projection.portable(&output)?;
    let public: serde_json::Value = ramflux_protocol::parse_i_json(&output)?;
    assert_eq!(public, json!({"nonce":nonce,"issued_at":100,"note":"retained note"}));
    assert_eq!(projection.source(&output)?.as_slice(), output.as_slice());
    Ok(())
}

#[test]
fn compact_contact_metadata_refuses_unknown_legacy_and_oversized_shapes() -> TestResult {
    let projection = SqlProjection::ContactRequestMetadataV1;
    let nonce = ramflux_protocol::encode_base64url([41; 32]);
    let base = json!({"nonce":nonce,"issued_at":100,"note":null});
    for (name, value) in [
        ("master_key", json!("must not be copied")),
        ("body", json!({"nonce":nonce})),
        ("needs_reply", json!("another_execution_variant")),
        ("note", json!("untrusted\nsecond line")),
        ("issued_at", json!(9_007_199_254_740_992_u64)),
    ] {
        let mut changed = base.clone();
        changed[name] = value;
        assert!(projection.source(&serde_json::to_vec(&changed)?).is_err(), "accepted {name}");
    }
    assert!(projection.source(&vec![b' '; 1025]).is_err());
    assert!(projection.source(br#"{"nonce":"missing-public-fields"}"#).is_err());
    Ok(())
}

#[test]
fn compact_contact_metadata_rejects_duplicate_members_and_excluded_null_on_wire() -> TestResult {
    let projection = SqlProjection::ContactRequestMetadataV1;
    let nonce = ramflux_protocol::encode_base64url([42; 32]);
    let duplicate =
        format!(r#"{{"nonce":"{nonce}","nonce":"{nonce}","issued_at":100,"note":null}}"#);
    assert!(projection.source(duplicate.as_bytes()).is_err());
    let source =
        serde_json::to_vec(&json!({"nonce":nonce,"issued_at":100,"note":null,"needs_reply":null}))?;
    assert!(projection.portable(&source).is_err());
    projection.portable(&projection.source(&source)?)?;
    Ok(())
}
