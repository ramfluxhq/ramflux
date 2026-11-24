// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The agent lifecycle through `rf agent` only (AGENT-CLI-E2E-01): create on the paired desktop,
//! see the request on the primary, approve or deny it, list, show, edit, delete. The one step that
//! is not a command is the primary's user presence: integration daemons take it as the bus hook
//! `itest.agent.approve_once` (a phone asks the person to confirm).
#![cfg(unix)]

use super::{Account, Daemon, Result, rf_json_timeout};
use serde_json::Value;
use std::time::{Duration, Instant};

const CALL: Duration = Duration::from_secs(30);
const WAIT: Duration = Duration::from_secs(90);

/// What the owner reviews on the primary, read from `rf agent pending`.
#[derive(Clone, Debug)]
pub struct Pending {
    pub request_id: String,
    pub request_hash: String,
    pub agent_name: String,
    pub responsibility: String,
    pub provider: String,
    pub model: String,
    pub agent_anchor: String,
}

/// The typed result of an agent reply: `{ok, method, body}` where the body is an
/// `AgentConfigResult` whose one member (`custody`, `page`, `record`, `watch`) holds the answer.
fn result<'a>(reply: &'a Value, member: &str) -> Result<&'a Value> {
    reply
        .pointer(&format!("/body/{member}"))
        .ok_or_else(|| format!("the reply has no {member} result: {reply}").into())
}

fn field(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing {key} in {value}").into())
}

/// `rf agent create` on the desktop. Returns the operation id.
/// # Errors
/// Returns the command failure, which carries the typed refusal.
pub fn create(
    desktop: &Daemon,
    owner: &Account,
    name: &str,
    responsibility: &str,
) -> Result<String> {
    let reply = rf_json_timeout(
        &desktop.socket,
        &[
            "agent",
            "--account",
            &owner.id,
            "create",
            "--name",
            name,
            "--responsibility",
            responsibility,
            "--provider",
            "provider-e2e",
            "--model",
            "model-e2e",
            "--confirm",
        ],
        CALL,
    )?;
    let status = result(&reply, "custody")?;
    if field(status, "state")? != "authorization_pending" {
        return Err(format!("a new creation must wait for the primary: {reply}").into());
    }
    field(status, "requestId")
}

/// `rf agent status` of one operation.
/// # Errors
/// Returns the command failure.
pub fn status(daemon: &Daemon, owner: &Account, operation: &str) -> Result<Value> {
    let reply = rf_json_timeout(
        &daemon.socket,
        &["agent", "--account", &owner.id, "status", "--operation-id", operation],
        CALL,
    )?;
    Ok(result(&reply, "custody")?.clone())
}

/// Waits on the primary until `rf agent pending` shows a request.
/// # Errors
/// Returns when no request arrives in time.
pub fn wait_pending(primary: &Daemon, owner: &Account) -> Result<Pending> {
    let deadline = Instant::now() + WAIT;
    let mut last = String::new();
    while Instant::now() < deadline {
        match rf_json_timeout(&primary.socket, &["agent", "--account", &owner.id, "pending"], CALL)
        {
            Ok(reply) => {
                let review = reply.pointer("/body/review").ok_or("pending carries no review")?;
                return Ok(Pending {
                    request_id: field(review, "request_id")?,
                    request_hash: field(review, "request_hash")?,
                    agent_name: field(review, "agent_name")?,
                    responsibility: field(review, "responsibility")?,
                    provider: field(review, "provider")?,
                    model: field(review, "model")?,
                    agent_anchor: field(review, "agent_anchor")?,
                });
            }
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("no creation request reached the primary: {last}").into())
}

/// The primary's user presence for one plan, as an integration daemon takes it.
/// # Errors
/// Returns the bus failure.
pub fn confirm_presence(primary: &Daemon, owner: &Account, request_hash: &str) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let mut bus = ramflux_sdk::LocalBusClient::connect(primary.socket.clone()).await?;
        bus.request(
            Some(owner.id.clone()),
            "itest",
            "itest.agent.approve_once",
            serde_json::json!({ "plan_hash": request_hash }),
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

/// `rf agent decide` on the primary.
/// # Errors
/// Returns the command failure.
pub fn decide(
    primary: &Daemon,
    owner: &Account,
    pending: &Pending,
    approved: bool,
) -> Result<Value> {
    let reply = rf_json_timeout(
        &primary.socket,
        &[
            "agent",
            "--account",
            &owner.id,
            "decide",
            "--request-id",
            &pending.request_id,
            "--request-hash",
            &pending.request_hash,
            "--approved",
            if approved { "true" } else { "false" },
        ],
        CALL,
    )?;
    Ok(result(&reply, "custody")?.clone())
}

/// Polls `rf agent status` on the desktop until the operation reaches `state`. A completed creation
/// is advanced by the status read itself (the daemon commits and publishes on the way).
/// # Errors
/// Returns the last status when the state is not reached.
pub fn wait_state(
    desktop: &Daemon,
    owner: &Account,
    operation: &str,
    state: &str,
) -> Result<Value> {
    let deadline = Instant::now() + WAIT;
    let mut last = Value::Null;
    while Instant::now() < deadline {
        if let Ok(value) = status(desktop, owner, operation) {
            if value.get("state").and_then(Value::as_str) == Some(state) {
                return Ok(value);
            }
            last = value;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("the operation never reached {state}; last={last}").into())
}

/// `rf agent list`, every page of one.
/// # Errors
/// Returns the command failure.
pub fn list(daemon: &Daemon, owner: &Account) -> Result<Vec<Value>> {
    let reply = rf_json_timeout(&daemon.socket, &["agent", "--account", &owner.id, "list"], CALL)?;
    Ok(result(&reply, "page")?
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// Waits until `rf agent list` shows the agent, then `rf agent show` of it.
/// # Errors
/// Returns when the agent is not listed in time.
pub fn wait_listed(daemon: &Daemon, owner: &Account, anchor: &str) -> Result<Value> {
    let deadline = Instant::now() + WAIT;
    let mut last = String::new();
    while Instant::now() < deadline {
        match rf_json_timeout(&daemon.socket, &["agent", "--account", &owner.id, "list"], CALL) {
            Ok(reply) => {
                let rows = result(&reply, "page")
                    .ok()
                    .and_then(|page| page.get("records").and_then(Value::as_array).cloned())
                    .unwrap_or_default();
                if rows
                    .iter()
                    .any(|row| row.get("agentAnchor").and_then(Value::as_str) == Some(anchor))
                {
                    match show(daemon, owner, anchor) {
                        Ok(record)
                            if record
                                .get("persona")
                                .and_then(|persona| persona.get("name"))
                                .is_some() =>
                        {
                            return Ok(record);
                        }
                        Ok(record) => last = record.to_string(),
                        Err(error) => last = error.to_string(),
                    }
                } else {
                    last = reply.to_string();
                }
            }
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "the agent {anchor} is not listed on {}; last reply: {last}",
        daemon.socket.display()
    )
    .into())
}

/// `rf agent show`.
/// # Errors
/// Returns the command failure.
pub fn show(daemon: &Daemon, owner: &Account, anchor: &str) -> Result<Value> {
    let reply = rf_json_timeout(
        &daemon.socket,
        &["agent", "--account", &owner.id, "show", "--agent", anchor],
        CALL,
    )?;
    Ok(result(&reply, "record")?.clone())
}

/// `rf agent edit` on the desktop.
/// # Errors
/// Returns the command failure.
pub fn edit(
    daemon: &Daemon,
    owner: &Account,
    anchor: &str,
    name: &str,
    responsibility: &str,
) -> Result<Value> {
    let reply = rf_json_timeout(
        &daemon.socket,
        &[
            "agent",
            "--account",
            &owner.id,
            "edit",
            "--agent",
            anchor,
            "--name",
            name,
            "--responsibility",
            responsibility,
            "--confirm",
        ],
        CALL,
    )?;
    Ok(result(&reply, "record")?.clone())
}

/// `rf agent delete` on the desktop.
/// # Errors
/// Returns the command failure.
pub fn delete(daemon: &Daemon, owner: &Account, anchor: &str) -> Result<Value> {
    let reply = rf_json_timeout(
        &daemon.socket,
        &["agent", "--account", &owner.id, "delete", "--agent", anchor, "--confirm"],
        CALL,
    )?;
    Ok(result(&reply, "record")?.clone())
}
