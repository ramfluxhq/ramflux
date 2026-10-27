// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Strict action-selected payload decoding rejects open objects and identifier overflow.
use super::*;
use serde_json::{Value, json};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn request() -> Result<Value, Box<dyn std::error::Error>> {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    let mut control = vectors["messages"][4]["signed"].clone();
    control["body"]["action"] = json!("status");
    Ok(
        json!({"control":control,"payload":{"account_anchor":"account","migration_id":"operation"},"evidence":{}}),
    )
}
#[test]
fn payload_shape_is_selected_by_control_action() -> TestResult {
    let mut raw = request()?;
    let decoded: Request = decode(&serde_json::to_vec(&raw)?, MAX_CONTROL_BYTES)?;
    assert!(matches!(decoded.payload, ActionPayload::Operation(_)));
    raw["payload"]["unexpected"] = json!(true);
    assert!(decode::<Request>(&serde_json::to_vec(&raw)?, MAX_CONTROL_BYTES).is_err());
    let mut raw = request()?;
    raw["control"]["body"]["action"] = json!("commit");
    assert!(decode::<Request>(&serde_json::to_vec(&raw)?, MAX_CONTROL_BYTES).is_err());
    Ok(())
}
#[test]
fn identifiers_and_server_evidence_are_bounded_and_closed() -> TestResult {
    let mut raw = request()?;
    raw["payload"]["migration_id"] = json!("a".repeat(257));
    assert!(decode::<Request>(&serde_json::to_vec(&raw)?, MAX_CONTROL_BYTES).is_err());
    let mut raw = request()?;
    raw["evidence"]["server_record"] = json!({"arbitrary":true});
    assert!(decode::<Request>(&serde_json::to_vec(&raw)?, MAX_CONTROL_BYTES).is_err());
    Ok(())
}

#[test]
fn control_payload_binding_rejects_substitution_and_mismatched_operation_owner() -> TestResult {
    let mut raw = request()?;
    raw["payload"]["account_anchor"] =
        raw["control"]["body"]["requester"]["account_anchor"].clone();
    raw["payload"]["migration_id"] = raw["control"]["body"]["migration_id"].clone();
    let mut request: Request = decode(&serde_json::to_vec(&raw)?, MAX_CONTROL_BYTES)?;
    request.control.body.payload_hash =
        control_payload_hash(Action::Status, &request.payload, None)?;
    request.validate_payload_binding()?;
    let ActionPayload::Operation(payload) = &mut request.payload else {
        return Err("operation".into());
    };
    payload.migration_id = "substituted".into();
    assert!(request.validate_payload_binding().is_err());
    request.control.body.payload_hash =
        control_payload_hash(Action::Status, &request.payload, None)?;
    assert!(request.validate_payload_binding().is_err());
    assert!(control_payload_hash(Action::Seal, &request.payload, None).is_err());
    Ok(())
}

#[test]
fn cancellation_hash_binds_authorization_even_without_a_seal_reply() -> TestResult {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    let authorization: Signed<Authorization> =
        serde_json::from_value(vectors["messages"][2]["signed"].clone())?;
    let payload = ActionPayload::Operation(OperationPayload {
        account_anchor: authorization.body.account_anchor.clone(),
        migration_id: authorization.body.migration_id.clone(),
    });
    let mut control: Signed<Control> =
        serde_json::from_value(vectors["messages"][4]["signed"].clone())?;
    control.body.action = Action::Abort;
    control.body.migration_id = authorization.body.migration_id.clone();
    control.body.payload_hash =
        control_payload_hash(Action::Abort, &payload, Some(&authorization))?;
    assert_eq!(control.body.payload_hash, message_hash(&authorization)?);
    let mut request = Request {
        control,
        payload,
        evidence: Evidence { authorization: Some(authorization), ..Evidence::default() },
    };
    request.validate_payload_binding()?;
    request.evidence.authorization.as_mut().ok_or("authorization")?.body.destination_node =
        "C".into();
    assert!(request.validate_payload_binding().is_err());
    request.evidence.authorization = None;
    assert!(request.validate_payload_binding().is_err());
    Ok(())
}
