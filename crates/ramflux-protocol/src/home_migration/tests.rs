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
