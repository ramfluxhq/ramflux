// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ProtoJSON` bodies of the agent creation bus methods (AGENT-IDENTITY-01 C3, contract 2). They
//! decode through the generated serde implementations and refuse unknown or reserved fields.
use super::{AgentCreate, AgentCreationDecide, AgentOperationGet};
use serde_json::json;

fn create_body() -> serde_json::Value {
    json!({
        "persona": {"name": "Support", "avatar": "", "responsibility": "answers questions"},
        "config": {"provider": "openai", "model": "gpt", "autonomy": "full", "tools": ["*"]},
        "confirmed": true,
        "access": {"dm": "owner", "groupInviters": "owner", "allowedHumans": []},
        "role": "named"
    })
}

#[test]
fn agent_create_protojson_decodes_and_refuses_unknown_fields() -> Result<(), serde_json::Error> {
    let body: AgentCreate = serde_json::from_value(create_body())?;
    assert_eq!(body.confirmed, Some(true));
    assert_eq!(body.role, "named");
    assert_eq!(body.persona.as_ref().map(|persona| persona.name.as_str()), Some("Support"));

    let mut unknown = create_body();
    unknown["extra"] = json!("x");
    assert!(serde_json::from_value::<AgentCreate>(unknown).is_err(), "unknown field refuses");

    let mut reserved = create_body();
    reserved["config"]["memory"] = json!("per-chat");
    assert!(
        serde_json::from_value::<AgentCreate>(reserved).is_err(),
        "the reserved memory field of AgentConfigData refuses"
    );
    Ok(())
}

#[test]
fn agent_decide_and_get_keep_presence_of_approved() -> Result<(), serde_json::Error> {
    let decide: AgentCreationDecide = serde_json::from_value(json!({
        "requestId": "req-1",
        "requestHash": "hash-1"
    }))?;
    assert_eq!(decide.approved, None, "an absent approved stays absent");
    let approve: AgentCreationDecide = serde_json::from_value(json!({
        "requestId": "req-1",
        "requestHash": "hash-1",
        "approved": false
    }))?;
    assert_eq!(approve.approved, Some(false), "an explicit false is present");
    let get: AgentOperationGet = serde_json::from_value(json!({"operationId": "op-1"}))?;
    assert_eq!(get.operation_id, "op-1");
    Ok(())
}
