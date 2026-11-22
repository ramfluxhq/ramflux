// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf agent` drivers. Each subcommand sends one agent bus method and prints the same
//! `{ok, method, body}` JSON as the other commands; a refusal keeps its code and fails the process.
//! Nothing secret is read or printed: the bodies carry the persona, the access policy and the
//! public creation records only.
use super::conversation_ops::commit_write;
use super::{
    AgentAccessArgs, AgentAction, AgentCommand, AgentPersonaArgs, LocalBusClient, PathBuf, RfError,
};
use ramflux_sdk::LocalBusFrame;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) async fn handle_agent(socket: PathBuf, command: AgentCommand) -> Result<(), RfError> {
    let (method, body) = request_of(command.action)?;
    let bus = LocalBusClient::connect(socket).await?;
    let frame = LocalBusFrame::request(request_id(), Some(command.account), "agent", method, body);
    let mut response = bus.request_frame_response(frame).await?;
    add_review(&mut response);
    commit_write(method, &response)
}

/// Adds the `review` object to a creation status that carries its plan, so the owner sees what is
/// decided without decoding the plan by hand. A reply without a plan is left as it is.
fn add_review(response: &mut LocalBusFrame) {
    // The reply is an `AgentConfigResult`: the creation status sits under `custody`.
    let Some(review) = response.body.get("custody").and_then(review_of) else {
        return;
    };
    if let Some(body) = response.body.as_object_mut() {
        body.insert("review".into(), review);
    }
}

/// What the owner decides on, read from the frozen plan of a creation status (`requestJson` is the
/// plan's canonical JSON as standard base64). The hash is the one `decide` must repeat.
pub(crate) fn review_of(status: &Value) -> Option<Value> {
    use base64::Engine as _;
    let text = status.get("requestJson")?.as_str()?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(text).ok()?;
    let plan = ramflux_protocol::custody::decode_register_plan(&bytes).ok()?;
    let hash = ramflux_protocol::custody::register_plan_hash(&plan).ok()?;
    Some(json!({
        "request_id": plan.request_id,
        "request_hash": hash,
        "purpose": serde_json::to_value(plan.purpose).ok()?,
        "agent_name": plan.display_name,
        "agent_anchor": plan.agent_anchor,
        "responsibility": plan.profile.responsibility,
        "provider": plan.profile.provider,
        "model": plan.profile.model,
        "requested_by_device": plan.desktop.device_id,
        "expires_at": plan.expires_at,
    }))
}

/// The bus method and the `ProtoJSON` body of one `rf agent` action. Pure: no socket, no file.
pub(crate) fn request_of(action: AgentAction) -> Result<(&'static str, Value), RfError> {
    Ok(match action {
        AgentAction::Create { persona, model, access, role, confirm } => {
            let mut config = serde_json::Map::new();
            config.insert("provider".into(), json!(model.provider));
            config.insert("model".into(), json!(model.model));
            if model.max_concurrent_turns.is_some() || model.max_cost_per_day_cents.is_some() {
                config.insert(
                    "limits".into(),
                    json!({
                        "max_concurrent_turns": model.max_concurrent_turns,
                        "max_cost_per_day_cents": model.max_cost_per_day_cents,
                    }),
                );
            }
            let mut body = json!({
                "persona": persona_value(&persona),
                "config": serde_json::Value::Object(config),
                "access": access_value(&access),
                "role": role,
            });
            confirmed(&mut body, confirm);
            ("agent.create", body)
        }
        AgentAction::Decide { request_id, request_hash, approved } => (
            "agent.creation.decide",
            json!({"request_id": request_id, "request_hash": request_hash, "approved": approved}),
        ),
        AgentAction::List { cursor, limit } => {
            ("agent.list", json!({"cursor": cursor, "limit": limit}))
        }
        AgentAction::Show { agent } => ("agent.get", json!({"agent_anchor": agent})),
        AgentAction::Edit { agent, persona, confirm } => {
            let mut body = json!({"agent_anchor": agent, "persona": persona_value(&persona)});
            confirmed(&mut body, confirm);
            ("agent.persona.edit", body)
        }
        AgentAction::Access { agent, access, base, confirm } => {
            let base: Value = serde_json::from_str(&base)
                .map_err(|_| RfError::Message("--base must be the identity JSON object".into()))?;
            if !base.is_object() {
                return Err(RfError::Message("--base must be the identity JSON object".into()));
            }
            let mut body = json!({
                "agent_anchor": agent,
                "access": access_value(&access),
                "base": base,
            });
            confirmed(&mut body, confirm);
            ("agent.access.set", body)
        }
        AgentAction::Delete { agent, confirm } => {
            let mut body = json!({"agent_anchor": agent});
            confirmed(&mut body, confirm);
            ("agent.delete", body)
        }
        AgentAction::Status { operation_id } => {
            ("agent.operation.get", json!({"operation_id": operation_id}))
        }
        // An empty operation id asks the daemon for the next request that waits for this device.
        AgentAction::Pending => ("agent.operation.get", json!({"operation_id": ""})),
    })
}

fn persona_value(args: &AgentPersonaArgs) -> Value {
    json!({"name": args.name, "avatar": args.avatar, "responsibility": args.responsibility})
}

fn access_value(args: &AgentAccessArgs) -> Value {
    json!({
        "dm": args.dm,
        "group_inviters": args.group_inviters,
        "allowed_humans": args.allowed_humans,
    })
}

/// `confirmed` is sent only when the owner confirmed on this desktop; otherwise the field is absent
/// and the SDK refuses the change.
fn confirmed(body: &mut Value, confirm: bool) {
    if confirm && let Some(object) = body.as_object_mut() {
        object.insert("confirmed".into(), Value::Bool(true));
    }
}

fn request_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("rf-agent-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod tests;
