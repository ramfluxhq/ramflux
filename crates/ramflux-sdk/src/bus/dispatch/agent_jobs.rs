// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner job control. List, pause, resume, and remove call the paired PRX daemon.
//! Job-run sessions are published by the host and listed from this account.

use crate::client::agent_activity;
use crate::prelude::*;
use ramflux_prx_client::{AgentName, ApiCode, AutomationKind, PrxClient, PrxError};
use serde_json::{Value, json};

const SESSION_CAP: usize = 256;

pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "agent.job.list" => list_jobs(request, state).await,
        "agent.job.pause" => switch(request, state, false).await,
        "agent.job.resume" => switch(request, state, true).await,
        "agent.job.remove" => remove(request, state).await,
        "agent.job.session" => publish_session(request, state),
        "agent.job.sessions" => list_sessions(request, state),
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

async fn list_jobs(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = prx_client(request, state)?;
    let agent = agent_name(&request.body)?;
    let caps = client.capabilities().await.map_err(|error| map_prx(&error))?;
    let rows = client.list_automation(&caps, &agent).await.map_err(|error| map_prx(&error))?;
    let jobs: Vec<Value> = rows.iter().map(item_json).collect();
    Ok(local_bus_ok(json!({"jobs": jobs})))
}

async fn switch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    enabled: bool,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = prx_client(request, state)?;
    let _agent = agent_name(&request.body)?;
    let kind = kind_of(&request.body)?;
    let id = required(&request.body, "id")?;
    let caps = client.capabilities().await.map_err(|error| map_prx(&error))?;
    let item = if enabled {
        client.resume_automation(&caps, kind, id).await
    } else {
        client.pause_automation(&caps, kind, id).await
    }
    .map_err(|error| map_prx(&error))?;
    Ok(local_bus_ok(item_json(&item)))
}

async fn remove(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = prx_client(request, state)?;
    let _agent = agent_name(&request.body)?;
    let kind = kind_of(&request.body)?;
    let id = required(&request.body, "id")?;
    let caps = client.capabilities().await.map_err(|error| map_prx(&error))?;
    client.remove_automation(&caps, kind, id).await.map_err(|error| map_prx(&error))?;
    Ok(local_bus_ok(json!({"id": id, "removed": true})))
}

fn publish_session(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = account(request, state)?;
    let record = session_record(&request.body)?;
    let agent = required(&record, "agent")?;
    let session = required(&record, "session")?;
    let state_kind = format!("agent-job-session/{agent}/{session}");
    if state_kind.len() > 256 {
        return Err(field_invalid("session"));
    }
    stored(client, &state_kind, record.clone())?;
    Ok(local_bus_ok(record))
}

fn list_sessions(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = account(request, state)?;
    let agent = required(&request.body, "agent")?;
    let mut sessions = Vec::new();
    for key in client.account_db()?.actor_state_keys("agent-job-session/")? {
        if sessions.len() >= SESSION_CAP {
            break;
        }
        let Some(row) = client.account_db()?.load_actor_state::<Value>(&key)? else {
            continue;
        };
        if row.get("agent").and_then(Value::as_str) == Some(agent) {
            sessions.push(row);
        }
    }
    Ok(local_bus_ok(json!({"sessions": sessions})))
}

fn prx_client<'a>(
    request: &LocalBusFrame,
    state: &'a mut LocalBusDaemonState,
) -> Result<&'a PrxClient, SdkError> {
    account(request, state).map(|_| ())?;
    state
        .config
        .prx
        .as_deref()
        .ok_or_else(|| refused("prx_unconfigured", "the desktop daemon has no PRX client"))
}

fn account<'a>(
    request: &LocalBusFrame,
    state: &'a mut LocalBusDaemonState,
) -> Result<&'a RamfluxClient, SdkError> {
    Ok(&local_bus_account_mut(state, request_account_id(request)?)?.client)
}

fn stored(client: &RamfluxClient, state_kind: &str, record: Value) -> Result<(), SdkError> {
    if let Some(stored) = agent_activity::commit(client, state_kind, record)? {
        let _ = agent_activity::fan_out(client, state_kind, &stored);
    }
    Ok(())
}

fn session_record(body: &Value) -> Result<Value, SdkError> {
    if body.get("source").and_then(Value::as_str) != Some("prx") {
        return Err(field_invalid("source"));
    }
    let agent = required(body, "agent")?;
    let session = required(body, "session")?;
    let job_id = required(body, "job_id")?;
    let channel = required(body, "channel")?;
    if channel != "cron" && channel != "xin" {
        return Err(field_invalid("channel"));
    }
    if session != format!("{channel}:{job_id}") {
        return Err(field_invalid("session"));
    }
    let version = body
        .get("job_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| field_invalid("job_version"))?;
    Ok(json!({
        "source": "prx",
        "agent": agent,
        "session": session,
        "job_id": job_id,
        "job_version": version,
        "channel": channel,
        "conversation_id": agent,
    }))
}

fn item_json(item: &ramflux_prx_client::AutomationItem) -> Value {
    json!({
        "id": item.id,
        "kind": item.kind.as_str(),
        "creator_agent": item.creator_agent,
        "schedule": item.schedule,
        "next_run_at": item.next_run_at,
        "enabled": item.enabled,
        "version": item.version,
    })
}

fn agent_name(body: &Value) -> Result<AgentName, SdkError> {
    let name = required(body, "agent")?;
    AgentName::parse(name).map_err(|_| field_invalid("agent"))
}

fn kind_of(body: &Value) -> Result<AutomationKind, SdkError> {
    match required(body, "kind")? {
        "cron" => Ok(AutomationKind::Cron),
        "xin_task" => Ok(AutomationKind::XinTask),
        "xin_goal" => Ok(AutomationKind::XinGoal),
        _ => Err(field_invalid("kind")),
    }
}

fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, SdkError> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|text| id_ok(text))
        .ok_or_else(|| field_invalid(key))
}

fn id_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 180
        && !text.contains('/')
        && !text.contains("..")
        && !text.chars().any(char::is_control)
}

fn field_invalid(key: &str) -> SdkError {
    refused("field_invalid", key)
}

fn map_prx(error: &PrxError) -> SdkError {
    match error {
        PrxError::Api { code: ApiCode::CronJobUnknown, .. } => {
            refused("cron_job_unknown", "no such cron job")
        }
        PrxError::Api { code: ApiCode::XinTaskUnknown, .. } => {
            refused("xin_task_unknown", "no such xin task")
        }
        PrxError::Api { code: ApiCode::XinGoalUnknown, .. } => {
            refused("xin_goal_unknown", "no such xin goal")
        }
        PrxError::Api { code: ApiCode::AuthFailed, .. } => refused("auth_failed", "auth_failed"),
        PrxError::Api { code: ApiCode::FieldInvalid, .. } => {
            refused("field_invalid", "field_invalid")
        }
        PrxError::Api { code: ApiCode::AgentInvalid, .. } => {
            refused("agent_invalid", "agent_invalid")
        }
        PrxError::Api { code: ApiCode::StorageUnavailable, .. } => {
            refused("storage_unavailable", "storage_unavailable")
        }
        PrxError::Unsupported { .. } => refused("prx_unsupported", "prx_unsupported"),
        PrxError::Unavailable | PrxError::Timeout => refused("prx_unavailable", "prx_unavailable"),
        _ => refused("prx_rejected", "prx_rejected"),
    }
}

fn refused(code: &str, detail: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.to_owned(),
        message: code.to_owned(),
        body: Box::new(json!({"reason_code": code, "details": {"cause": detail}})),
    }
}
