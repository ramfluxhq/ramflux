// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Desktop agent management (AGENT-MGMT-01A): `agent.update`, `agent.pause`, `agent.resume` and
//! `agent.catalog`. PRX owns the config; the agent record keeps a mirror so `agent.get` can show
//! it. An update reads PRX first, refuses a stale view with `revision_conflict`, writes the merged
//! config through `apply_agent`, and only then writes the mirror. The bodies are closed JSON: an
//! unknown field is `field_invalid`. Every method needs the PRX client of the daemon.

use super::agent_prx::{account, field_invalid, map_prx, prx_client, refused, refused_with};
use crate::agent_record::{LIFECYCLE_ACTIVE, config as fields};
use crate::prelude::*;
use ramflux_prx_client::{
    AgentConfig, AgentLimits, AgentName, AgentReadback, AgentStatus, ApiCode, ApplyOutcome,
    ConfigRevision, PrxClient, PrxError,
};
use serde_json::{Map, Value, json};

const UPDATE_FIELDS: &[&str] = &[
    "agent_anchor",
    "revision",
    "provider",
    "model",
    "autonomy",
    "prompt",
    "tools",
    "enabled",
    "limits",
    "confirm_high_risk",
];
const SWITCH_FIELDS: &[&str] = &["agent_anchor", "revision"];

pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "agent.catalog" => catalog(request, state).await,
        "agent.update" => change(request, state, None).await,
        "agent.pause" => change(request, state, Some(false)).await,
        "agent.resume" => change(request, state, Some(true)).await,
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

async fn catalog(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = prx_client(request, state)?;
    closed(&request.body, &[])?;
    let catalog = client.catalog().await.map_err(|error| map_prx(&error))?;
    let models: Vec<Value> = catalog
        .models
        .iter()
        .map(|row| {
            json!({
                "provider": row.provider,
                "model": row.model,
                "credentials_ready": row.credentials_ready,
            })
        })
        .collect();
    let tools: Vec<Value> = catalog
        .tools
        .iter()
        .map(|row| json!({"name": row.name, "read_only": row.read_only}))
        .collect();
    Ok(local_bus_ok(json!({
        "prx_version": catalog.prx_version,
        "revision": catalog.revision.as_str(),
        "models": models,
        "tools": tools,
        "defaults": {"autonomy": fields::autonomy_text(catalog.defaults_autonomy)},
        "reserved_names": catalog.reserved_names,
    })))
}

/// What the request changes. Every field is optional; a field left out stays as PRX has it.
struct Change {
    provider: Option<String>,
    model: Option<String>,
    autonomy: Option<String>,
    prompt: Option<String>,
    tools: Option<Vec<String>>,
    enabled: Option<bool>,
    /// `Some(None)` clears the limits.
    limits: Option<Option<AgentLimits>>,
    confirm_high_risk: bool,
}

struct Parsed {
    anchor: String,
    revision: Option<ConfigRevision>,
    change: Change,
}

async fn change(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    switch: Option<bool>,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = prx_client(request, state)?;
    let parsed = parse(&request.body, switch)?;
    let name = name_of(&parsed.anchor)?;
    let record = load_active(request, state, &parsed.anchor)?;
    let caps = client.capabilities().await.map_err(|error| map_prx(&error))?;
    let current = read(&client, &caps, &name).await?;
    let (base, reviewed) = match &current {
        Some(readback) => {
            if readback.status == AgentStatus::Retired {
                return Err(refused("agent_retired", "retired in PRX"));
            }
            let seen = parsed.revision.as_ref() == Some(&readback.revision)
                || fields::mirror_matches(&record, &readback.config);
            if !seen {
                return Err(conflict(Some(readback)));
            }
            (readback.config.clone(), Some(readback.config.clone()))
        }
        None => {
            if parsed.revision.is_some() {
                return Err(field_invalid("revision"));
            }
            (base_from_record(&record, &parsed.change)?, None)
        }
    };
    let new = overlay(base, &parsed.change)?;
    let (readback, applied) =
        apply(&client, &caps, &name, &new, reviewed.as_ref(), &parsed).await?;
    mirror(request, state, &parsed.anchor, &readback)?;
    Ok(local_bus_ok(answer(&parsed.anchor, &readback, applied)))
}

async fn read(
    client: &PrxClient,
    caps: &ramflux_prx_client::Capabilities,
    name: &AgentName,
) -> Result<Option<AgentReadback>, SdkError> {
    match client.get(caps, name).await {
        Ok(readback) => Ok(Some(readback)),
        Err(PrxError::Api { code: ApiCode::AgentUnknown, .. }) => Ok(None),
        Err(error) => Err(map_prx(&error)),
    }
}

/// Applies `new` and returns what PRX stored. A high-risk confirmation is answered once, and only
/// when the request carried `confirm_high_risk`.
async fn apply(
    client: &PrxClient,
    caps: &ramflux_prx_client::Capabilities,
    name: &AgentName,
    new: &AgentConfig,
    reviewed: Option<&AgentConfig>,
    parsed: &Parsed,
) -> Result<(AgentReadback, &'static str), SdkError> {
    match client.apply_agent(caps, name, new, reviewed).await.map_err(|error| map_prx(&error))? {
        ApplyOutcome::Applied(outcome) => Ok((outcome.readback, "applied")),
        ApplyOutcome::AlreadyApplied(readback) => Ok((readback, "already_applied")),
        ApplyOutcome::NeedsConfirmation { revision } if parsed.change.confirm_high_risk => {
            let outcome = client
                .put(caps, name, new, &revision, true)
                .await
                .map_err(|error| map_prx(&error))?;
            Ok((outcome.readback, "applied"))
        }
        ApplyOutcome::NeedsConfirmation { revision } => {
            Err(refused_with("confirmation_required", json!({"revision": revision.as_str()})))
        }
        ApplyOutcome::NeedsReview { current } => Err(conflict(current.as_ref())),
    }
}

fn conflict(current: Option<&AgentReadback>) -> SdkError {
    refused_with(
        "revision_conflict",
        json!({
            "current_revision": current.map(|readback| readback.revision.as_str()),
            "current": current.map(|readback| config_json(&readback.config)),
        }),
    )
}

/// The local record of the agent, in lifecycle `U`.
fn load_active(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    anchor: &str,
) -> Result<crate::agent_record::StoredAgentRecord, SdkError> {
    let store = account(request, state)?.agent_record_store()?;
    let record = store.load(anchor)?.ok_or_else(|| refused("agent_unknown", "no such agent"))?;
    if record.lifecycle != LIFECYCLE_ACTIVE {
        return Err(refused("agent_retired", "the agent is retired"));
    }
    Ok(record)
}

/// Writes what PRX stored into the mirror. The record file is read again so a change made while
/// PRX was called is kept. Only config fields change: the identity stays, so no metadata is
/// broadcast.
fn mirror(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    anchor: &str,
    readback: &AgentReadback,
) -> Result<(), SdkError> {
    let store = account(request, state)?.agent_record_store()?;
    let Some(mut record) = store.load(anchor)? else {
        return Ok(());
    };
    if record.lifecycle != LIFECYCLE_ACTIVE {
        return Ok(());
    }
    fields::set_mirror(&mut record, &readback.config, readback.revision.as_str());
    store.save(&mut record)
}

/// The base of an update when PRX has no such agent: the mirror, or the given provider and model.
fn base_from_record(
    record: &crate::agent_record::StoredAgentRecord,
    change: &Change,
) -> Result<AgentConfig, SdkError> {
    if let Some(config) = fields::config_of_record(record) {
        return Ok(config);
    }
    Ok(AgentConfig {
        provider: change.provider.clone().ok_or_else(|| field_invalid("provider"))?,
        model: change.model.clone().ok_or_else(|| field_invalid("model"))?,
        prompt: None,
        autonomy: ramflux_prx_client::Autonomy::Full,
        tools: ramflux_prx_client::Tools::All,
        enabled: true,
        limits: None,
        approval_wait_secs: ramflux_prx_client::DEFAULT_APPROVAL_WAIT_SECS,
    })
}

/// `base` with the given fields set, validated as a whole before PRX is written.
fn overlay(mut config: AgentConfig, change: &Change) -> Result<AgentConfig, SdkError> {
    if let Some(provider) = &change.provider {
        config.provider.clone_from(provider);
    }
    if let Some(model) = &change.model {
        config.model.clone_from(model);
    }
    if let Some(text) = &change.autonomy {
        config.autonomy = fields::autonomy_of(text).ok_or_else(|| field_invalid("autonomy"))?;
    }
    if let Some(prompt) = &change.prompt {
        config.prompt = Some(prompt.clone());
    }
    if let Some(names) = &change.tools {
        config.tools = fields::tools_of(names);
    }
    if let Some(enabled) = change.enabled {
        config.enabled = enabled;
    }
    if let Some(limits) = &change.limits {
        config.limits.clone_from(limits);
    }
    let names = fields::tools_names(&config.tools);
    let (turns, cost) = config.limits.as_ref().map_or((None, None), |limits| {
        (limits.max_concurrent_turns, limits.max_cost_per_day_cents)
    });
    let ok = fields::fields_ok(
        Some(config.provider.as_str()),
        Some(config.model.as_str()),
        None,
        config.prompt.as_deref(),
        Some(names.as_slice()),
    ) && fields::limits_ok(turns, cost);
    if ok { Ok(config) } else { Err(field_invalid("config")) }
}

fn answer(anchor: &str, readback: &AgentReadback, applied: &str) -> Value {
    let status = match readback.status {
        AgentStatus::Active => "active",
        AgentStatus::Disabled => "disabled",
        AgentStatus::Retired => "retired",
    };
    json!({
        "agent_anchor": anchor,
        "revision": readback.revision.as_str(),
        "status": status,
        "applied": applied,
        "config": config_json(&readback.config),
    })
}

fn config_json(config: &AgentConfig) -> Value {
    let mut out = Map::new();
    out.insert("provider".into(), json!(config.provider));
    out.insert("model".into(), json!(config.model));
    if let Some(prompt) = &config.prompt {
        out.insert("prompt".into(), json!(prompt));
    }
    out.insert("autonomy".into(), json!(fields::autonomy_text(config.autonomy)));
    out.insert("tools".into(), json!(fields::tools_names(&config.tools)));
    out.insert("enabled".into(), json!(config.enabled));
    if let Some(limits) = &config.limits {
        out.insert(
            "limits".into(),
            json!({
                "max_concurrent_turns": limits.max_concurrent_turns,
                "max_cost_per_day_cents": limits.max_cost_per_day_cents,
            }),
        );
    }
    Value::Object(out)
}

fn name_of(anchor: &str) -> Result<AgentName, SdkError> {
    crate::custody::valid_id(anchor).map_err(|_| field_invalid("agent_anchor"))?;
    crate::prx_owner::name_from_anchor(anchor).map_err(|_| field_invalid("agent_anchor"))
}

fn parse(body: &Value, switch: Option<bool>) -> Result<Parsed, SdkError> {
    closed(body, if switch.is_some() { SWITCH_FIELDS } else { UPDATE_FIELDS })?;
    let anchor = text_of(body, "agent_anchor")?.ok_or_else(|| field_invalid("agent_anchor"))?;
    let revision = text_of(body, "revision")?
        .map(|text| ConfigRevision::parse(&text).map_err(|_| field_invalid("revision")))
        .transpose()?;
    let change = Change {
        provider: text_of(body, "provider")?,
        model: text_of(body, "model")?,
        autonomy: text_of(body, "autonomy")?,
        prompt: text_of(body, "prompt")?,
        tools: tools_of(body)?,
        enabled: switch.or(flag_of(body, "enabled")?),
        limits: limits_of(body)?,
        confirm_high_risk: flag_of(body, "confirm_high_risk")?.unwrap_or(false),
    };
    Ok(Parsed { anchor, revision, change })
}

/// The body is an object whose keys are all in `allowed`.
fn closed(body: &Value, allowed: &[&str]) -> Result<(), SdkError> {
    let Some(object) = body.as_object() else {
        return Err(field_invalid("body"));
    };
    match object.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(field_invalid(key)),
        None => Ok(()),
    }
}

fn text_of(body: &Value, key: &str) -> Result<Option<String>, SdkError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(field_invalid(key)),
    }
}

fn flag_of(body: &Value, key: &str) -> Result<Option<bool>, SdkError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(*flag)),
        Some(_) => Err(field_invalid(key)),
    }
}

fn tools_of(body: &Value) -> Result<Option<Vec<String>>, SdkError> {
    let Some(value) = body.get("tools") else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        return Err(field_invalid("tools"));
    };
    items
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or_else(|| field_invalid("tools")))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// `limits` replaces the whole limit pair. A key left out or null is unset; both unset clears.
fn limits_of(body: &Value) -> Result<Option<Option<AgentLimits>>, SdkError> {
    let Some(value) = body.get("limits") else {
        return Ok(None);
    };
    let Some(object) = value.as_object() else {
        return Err(field_invalid("limits"));
    };
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "max_concurrent_turns" | "max_cost_per_day_cents"))
    {
        return Err(field_invalid("limits"));
    }
    let turns = match object.get("max_concurrent_turns") {
        None | Some(Value::Null) => None,
        Some(number) => Some(
            number
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| field_invalid("limits"))?,
        ),
    };
    let cost = match object.get("max_cost_per_day_cents") {
        None | Some(Value::Null) => None,
        Some(number) => Some(number.as_u64().ok_or_else(|| field_invalid("limits"))?),
    };
    if !fields::limits_ok(turns, cost) {
        return Err(field_invalid("limits"));
    }
    let limits = AgentLimits { max_concurrent_turns: turns, max_cost_per_day_cents: cost };
    Ok(Some((turns.is_some() || cost.is_some()).then_some(limits)))
}
