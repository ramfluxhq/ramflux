// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn epoch_components_are_exact_at_limits_and_reject_zero_or_unsafe_values() -> Result {
    assert_eq!(encode_epoch(1, 1)?, 4_294_967_297);
    assert_eq!(encode_epoch(MAX_RANGE, MAX_REVISION)?, MAX_SAFE_JSON_INTEGER);
    assert_eq!(decode_epoch(MAX_SAFE_JSON_INTEGER)?, (MAX_RANGE, MAX_REVISION));
    for (range, revision) in [(0, 1), (1, 0), (MAX_RANGE + 1, 1), (1, MAX_REVISION + 1)] {
        assert!(encode_epoch(range, revision).is_err());
    }
    for epoch in [0, 1, 1_u64 << 32, MAX_SAFE_JSON_INTEGER + 1, u64::MAX] {
        assert!(decode_epoch(epoch).is_err());
    }
    Ok(())
}
#[test]
fn custody_transcript_keeps_nested_signatures_and_explicit_domain() -> Result {
    let body = serde_json::json!({"signature":"nested","value":1});
    assert_eq!(
        String::from_utf8(signing_bytes("example.domain", &body)?)?,
        r#"{"body":{"signature":"nested","value":1},"domain":"example.domain"}"#
    );
    assert_ne!(framed_hash("a", &body)?, framed_hash("ab", &body)?);
    Ok(())
}
#[test]
fn original_wire_rejects_missing_nulls_duplicates_depth_and_byte_overflow() -> Result {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Nullable {
        value: Option<String>,
    }
    let value: Nullable = decode(br#"{"value":null}"#, 128)?;
    assert!(value.value.is_none());
    for bytes in
        [br#"{}"#.as_slice(), br#"{"value":null,"value":null}"#, br#"{"value":null,"extra":1}"#]
    {
        assert!(decode::<Nullable>(bytes, 128).is_err());
    }
    let deep = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    assert!(decode::<serde_json::Value>(deep.as_bytes(), 1024).is_err());
    assert!(decode::<Nullable>(br#"{"value":null}"#, 2).is_err());
    Ok(())
}
#[test]
fn serialization_failure_returns_an_error_without_panicking() {
    struct Failure;
    impl serde::Serialize for Failure {
        fn serialize<S: serde::Serializer>(&self, _: S) -> std::result::Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("intentional fixture failure"))
        }
    }
    assert!(signing_bytes("example.domain", &Failure).is_err());
    assert!(framed_hash("example.domain", &Failure).is_err());
}
