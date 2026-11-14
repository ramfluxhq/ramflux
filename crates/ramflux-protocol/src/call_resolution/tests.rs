// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use serde_json::json;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn context() -> CallSubmitContext {
    CallSubmitContext {
        version: 1,
        call_ref: crate::encode_base64url([3; 16]),
        start_digest: crate::encode_base64url([4; 32]),
        request_id: "request".into(),
        envelope_id: "envelope".into(),
        session_id: "session".into(),
        session_generation: crate::encode_base64url([5; 32]),
    }
}
fn carrier() -> serde_json::Value {
    let context = context();
    json!({
        "signed_request":{"schema":"ramflux.signed_request.v1","version":1,"domain":"ramflux.signed_request.v1","signing_key_id":"branch","signature_alg":"ed25519","signature":"fixture","source_device_id":"device","request_id":"request","method":"POST","path":"/gateway/session/submit","device_proof_hash":"already_authed","body_hash":"hash","nonce":"nonce","created_at":100,"expires_at":200},
        "envelope":{"schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1","signing_key_id":"branch","signature_alg":"ed25519","signature":"fixture","envelope_id":"envelope","source_principal_id":"source","source_device_id":"device","target_delivery_id":"target","delivery_class":"opaque_event","priority":"normal","ttl":30,"created_at":100,"encrypted_payload":"opaque","payload_hash":"hash"},
        "call_intent":null,"wake_id":null,"call_ref":context.call_ref,"call_terminal":null,"call_context":context
    })
}

#[test]
fn context_and_complete_nullable_submit_have_stable_canonical_bytes() -> TestResult {
    let context = context();
    context.validate()?;
    let bytes = crate::canonical_json_bytes(&context)?;
    assert_eq!(
        String::from_utf8(bytes)?,
        r#"{"call_ref":"AwMDAwMDAwMDAwMDAwMDAw","envelope_id":"envelope","request_id":"request","session_generation":"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU","session_id":"session","start_digest":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ","version":1}"#,
        "context wire contract changed"
    );
    let raw = carrier();
    let carrier: crate::CallSubmitCarrier =
        crate::parse_i_json(&crate::canonical_json_bytes(&raw)?)?;
    let serialized = serde_json::to_value(crate::CallSubmitCarrierRef {
        signed_request: &carrier.signed_request,
        envelope: &carrier.envelope,
        call_intent: None,
        wake_id: None,
        call_ref: carrier.call_ref.as_deref(),
        call_terminal: None,
        call_context: carrier.call_context.as_ref(),
    })?;
    for field in ["call_intent", "wake_id", "call_terminal"] {
        assert_eq!(
            serialized.get(field),
            Some(&serde_json::Value::Null),
            "nullable call member was omitted: {field}"
        );
    }
    for field in ["call_intent", "wake_id", "call_ref", "call_terminal", "call_context"] {
        let mut missing = raw.clone();
        missing.as_object_mut().ok_or("test: object")?.remove(field);
        assert!(
            crate::parse_i_json::<crate::CallSubmitCarrier>(&crate::canonical_json_bytes(
                &missing
            )?)
            .is_err(),
            "missing required call member was admitted: {field}"
        );
    }
    for field in [
        "request_id",
        "envelope_id",
        "session_id",
        "session_generation",
        "start_digest",
        "call_ref",
    ] {
        let mut changed = context.clone();
        match field {
            "request_id" => changed.request_id.push('x'),
            "envelope_id" => changed.envelope_id.push('x'),
            "session_id" => changed.session_id.push('x'),
            "session_generation" => changed.session_generation = crate::encode_base64url([6; 32]),
            "start_digest" => changed.start_digest = crate::encode_base64url([6; 32]),
            _ => changed.call_ref = crate::encode_base64url([6; 16]),
        }
        let original = CallSubmitBody {
            envelope: &carrier.envelope,
            call_intent: None,
            wake_id: None,
            call_ref: &context.call_ref,
            call_terminal: None,
            call_context: &context,
        };
        let tampered = CallSubmitBody { call_context: &changed, ..original };
        assert_ne!(
            crate::canonical_json_bytes(&original)?,
            crate::canonical_json_bytes(&tampered)?,
            "context field is absent from the authenticated body: {field}"
        );
    }
    Ok(())
}

#[test]
fn closed_resolution_refuses_unknown_duplicate_null_and_oversize_context() -> TestResult {
    let value = json!({"frame_type":"call_resolved","context":context(),"state":"ringing","media_allowed":true,"wake_resolved":false});
    let good = crate::canonical_json_bytes(&value)?;
    validate_call_resolution_frame(&good)?;
    let mut extra = value.clone();
    extra
        .as_object_mut()
        .ok_or("test: decision object")?
        .insert("legacy_call_ref".into(), json!("foreign"));
    assert!(
        validate_call_resolution_frame(&crate::canonical_json_bytes(&extra)?).is_err(),
        "unknown decision member was admitted"
    );
    let text = String::from_utf8(good)?.replacen(
        "\"media_allowed\":true",
        "\"media_allowed\":true,\"media_allowed\":true",
        1,
    );
    assert!(
        validate_call_resolution_frame(text.as_bytes()).is_err(),
        "duplicate decision member was admitted"
    );
    for member in ["context", "state", "media_allowed", "wake_resolved"] {
        let mut null = value.clone();
        null.as_object_mut()
            .ok_or("test: decision object")?
            .insert(member.into(), serde_json::Value::Null);
        assert!(
            validate_call_resolution_frame(&crate::canonical_json_bytes(&null)?).is_err(),
            "null decision member was admitted: {member}"
        );
    }
    let mut large = context();
    large.request_id = "x".repeat(513);
    assert!(large.validate().is_err(), "identifier bound plus one was admitted");
    large = context();
    large.session_id = "x".repeat(512);
    large.envelope_id = "x".repeat(512);
    large.request_id = "x".repeat(512);
    assert!(large.validate().is_ok(), "valid bounded identifiers failed below the context cap");
    let mut wrong = carrier();
    wrong
        .get_mut("call_ref")
        .ok_or("test: call ref")?
        .clone_from(&json!(crate::encode_base64url([8; 16])));
    assert!(
        crate::parse_i_json::<crate::CallSubmitCarrier>(&crate::canonical_json_bytes(&wrong)?)
            .is_err(),
        "alias and context mismatch was admitted"
    );
    Ok(())
}
