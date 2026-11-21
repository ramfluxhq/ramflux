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
    let response = bus.request_frame_response(frame).await?;
    commit_write(method, &response)
}

/// The bus method and the `ProtoJSON` body of one `rf agent` action. Pure: no socket, no file.
pub(crate) fn request_of(action: AgentAction) -> Result<(&'static str, Value), RfError> {
    Ok(match action {
        AgentAction::Create { persona, access, role, confirm } => {
            let mut body = json!({
                "persona": persona_value(&persona),
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
