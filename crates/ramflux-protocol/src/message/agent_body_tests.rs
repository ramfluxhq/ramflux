// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ProtoJSON` bodies of the agent creation bus methods (AGENT-IDENTITY-01 C3, contract 2). They
//! decode through the generated serde implementations and refuse unknown or reserved fields.
use super::{
    AgentCreate, AgentCreationDecide, AgentList, AgentMetadata, AgentOperationGet, AgentPage,
    AgentRecord,
};
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

/// The record and page bodies of the agent methods (AGENT-IDENTITY-01 E1, contract 1 and 2). The
/// later-stage record fields (`host`, `config`, `revision`) stay absent in this module.
#[test]
fn agent_record_and_page_bodies_decode_and_refuse_unknown_fields() -> Result<(), serde_json::Error>
{
    let list: AgentList = serde_json::from_value(json!({"limit": 20}))?;
    assert_eq!((list.cursor.as_deref(), list.limit), (None, 20));
    assert!(serde_json::from_value::<AgentList>(json!({"limit": 1, "extra": true})).is_err());

    let record_body = json!({
        "agentAnchor": "agent-1",
        "custodianAnchor": "owner-1",
        "persona": {"name": "Support", "avatar": "", "responsibility": "answers questions"},
        "lifecycle": "U",
        "observation": "",
        "cleanup": "",
        "role": "named",
        "access": {"dm": "owner", "groupInviters": "owner", "allowedHumans": []}
    });
    let record: AgentRecord = serde_json::from_value(record_body.clone())?;
    assert_eq!(record.lifecycle, "U");
    assert!(
        record.host.is_none() && record.config.is_none() && record.revision.is_none(),
        "the later-stage fields stay absent"
    );
    let mut unknown = record_body.clone();
    unknown["extra"] = json!("x");
    assert!(serde_json::from_value::<AgentRecord>(unknown).is_err(), "unknown field refuses");

    let page: AgentPage = serde_json::from_value(json!({
        "records": [record_body],
        "journalCursor": "c1"
    }))?;
    assert_eq!((page.records.len(), page.journal_cursor.as_str()), (1, "c1"));

    let metadata: AgentMetadata = serde_json::from_value(json!({
        "agentAnchor": "agent-1",
        "custodianAnchor": "owner-1",
        "persona": {"name": "Support", "avatar": "", "responsibility": "answers questions"},
        "role": "named",
        "access": {"dm": "owner", "groupInviters": "owner", "allowedHumans": []}
    }))?;
    assert_eq!(metadata.identity_retired, None, "an absent retirement flag stays absent");
    let retired: AgentMetadata = serde_json::from_value(json!({
        "agentAnchor": "agent-1",
        "identityRetired": true
    }))?;
    assert_eq!(retired.identity_retired, Some(true));
    Ok(())
}
