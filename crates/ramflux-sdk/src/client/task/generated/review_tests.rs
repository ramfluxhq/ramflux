// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Review regressions for canonical numbers, proof refusal and approval roles.
use super::*;

fn exact_invalid<T>(result: Result<T, SdkError>, expected: &str) {
    let error = result.err();
    assert!(
        matches!(&error,Some(SdkError::TaskRefused{reason:crate::TaskRefusalCode::InvalidRequest,message}) if message==expected),
        "expected {expected}, got {error:?}"
    );
}

#[test]
fn generated_number_tokens_preserve_byte_identity_and_refuse_other_spellings() -> TestResult {
    let bytes = RamfluxClient::encode_generated_task_event(&event(body_variants().remove(0))?)?;
    assert_eq!(RamfluxClient::encode_generated_task_event(&decode(&bytes)?)?, bytes);
    for token in [" 9007199254740991", "9007199254740991 ", "9.007199254740991e15", "1E+0", "1.00"]
    {
        let mut changed = g::TaskEvent::decode(bytes.as_slice())?;
        let number = changed
            .ext
            .as_mut()
            .and_then(|v| v.ext.as_mut())
            .ok_or("extensions")?
            .members
            .iter_mut()
            .find(|v| v.key == "extra")
            .and_then(|v| v.value.as_mut())
            .ok_or("extra")?;
        let Some(g::json_value::Value::Object(object)) = number.value.as_mut() else {
            return Err("object".into());
        };
        object.members.iter_mut().find(|v| v.key == "number").ok_or("number")?.value =
            Some(g::JsonValue { value: Some(g::json_value::Value::Number(token.into())) });
        exact_invalid(decode(&changed.encode_to_vec()), "noncanonical generated task event");
        exact_invalid(
            value_json(&g::JsonValue { value: Some(g::json_value::Value::Number(token.into())) }),
            "noncanonical task extension number",
        );
    }
    Ok(())
}

#[test]
fn generated_carrier_refuses_even_resigned_unverified_decision_proof() -> TestResult {
    let mut client = RamfluxClient::new();
    client.create_device_branch("human", "device", 1, [23; 32]);
    let bytes = client
        .encode_generated_task_carrier(event(body_variants().remove(0))?, "message".into())?;
    let mut carrier = client.decode_generated_task_carrier(&bytes)?;
    let B::Resolve(resolution) = body_variants().pop().ok_or("resolution")? else {
        return Err("resolve".into());
    };
    let mut resolution = serde_json::to_value(resolution)?;
    payload_shape(&mut resolution, true)?;
    carrier.decision_proof = Some(g::TaskCertificate {
        conversation_id: "junk".into(),
        resolution: Some(serde_json::from_value(resolution)?),
        assignee: "human".into(),
        issuer_device: "device".into(),
        issued_at: 1,
        phase: Some(serde_json::from_value(json!({"reserved":{}}))?),
        decision_key: "junk".into(),
        evidence_hash: "junk".into(),
        signature: encode_base64url([0; 64]),
        ..Default::default()
    });
    carrier.signature.clear();
    carrier.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &typed_transcript("TaskCarrier", &carrier.encode_to_vec())?,
        &device(),
    );
    let bytes = g::Task { payload: Some(g::task::Payload::Carrier(carrier)) }.encode_to_vec();
    exact_invalid(
        client.decode_generated_task_carrier(&bytes),
        "generated task decision proof verification unavailable",
    );
    Ok(())
}

#[test]
fn generated_approval_request_and_distinct_endpoint_roles() -> TestResult {
    let (decision, _) = approval_packet()?;
    let Some(g::task_approval_payload::Value::Decision(value)) =
        decision.payload.as_ref().and_then(|v| v.value.as_ref())
    else {
        return Err("decision".into());
    };
    let mut request = decision.clone();
    request.payload = Some(g::TaskApprovalPayload {
        value: Some(g::task_approval_payload::Value::Request(g::TaskApprovalPayloadRequest {
            request: value.request.clone(),
        })),
    });
    request.principal = "agent".into();
    request.device = "executor".into();
    let mut executor = RamfluxClient::new();
    executor.create_device_branch("agent", "executor", 1, [24; 32]);
    let wire = executor.encode_generated_task_approval(request)?;
    let decoded = executor.decode_generated_task_approval(&wire)?;
    assert!(matches!(
        decoded.payload.as_ref().and_then(|v| v.value.as_ref()),
        Some(g::task_approval_payload::Value::Request(_))
    ));
    assert_eq!(executor.encode_generated_task_approval(decoded.clone())?, wire);
    // Semantic endpoint refusal precedes key lookup/signature checks in both variants.
    for mut wrong in [decoded.clone(), decision] {
        wrong.principal = if wrong.principal == "human" { "agent" } else { "human" }.into();
        let bytes = g::Task { payload: Some(g::task::Payload::Approval(wrong)) }.encode_to_vec();
        exact_invalid(
            executor.decode_generated_task_approval(&bytes),
            "task approval sender is not a task endpoint",
        );
    }
    let mut wrong = decoded;
    wrong.device = "other-device".into();
    let bytes = g::Task { payload: Some(g::task::Payload::Approval(wrong)) }.encode_to_vec();
    exact_invalid(
        executor.decode_generated_task_approval(&bytes),
        "task approval sender is not a task endpoint",
    );
    Ok(())
}

#[test]
fn generated_task_delivery_cap_accepts_exact_boundary() -> TestResult {
    let cap = super::super::super::MAX_DELIVERY_BYTES;
    super::super::super::check_delivery_size(cap)?;
    let mut native = event(body_variants().remove(0))?;
    let mut generated =
        g::TaskEvent::decode(RamfluxClient::encode_generated_task_event(&native)?.as_slice())?;
    generated.ext = Some(g::Ext {
        ext: Some(g::JsonObject {
            members: vec![g::JsonMember {
                key: "padding".into(),
                value: Some(g::JsonValue {
                    value: Some(g::json_value::Value::Text("x".repeat(cap))),
                }),
            }],
        }),
    });
    let padding = cap.checked_sub(generated.encoded_len() - cap).ok_or("padding overhead")?;
    native = native.with_extensions(Ext {
        ext: [("padding".into(), Value::String("x".repeat(padding)))].into(),
    })?;
    let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &native.signing_bytes()?,
        &device(),
    );
    let native = native.with_signature(signature)?;
    let bytes = RamfluxClient::encode_generated_task_event(&native)?;
    assert_eq!(bytes.len(), cap);
    assert_eq!(RamfluxClient::encode_generated_task_event(&decode(&bytes)?)?, bytes);
    Ok(())
}
