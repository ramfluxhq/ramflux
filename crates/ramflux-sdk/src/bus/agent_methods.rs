// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Connection-level entry of the agent methods (AGENT-IDENTITY-01 C3 and E4). Like `account.create.*`,
//! these frames never enter the method table: the connection layer decodes the `ProtoJSON` body, the
//! human account's runtime performs the account-scoped work by private command, and the supervisor
//! advances a creation on read (controller decision r9 item 2, r10 item 1). Remote packets cannot
//! reach this path, so no remote source can start a creation or edit a record.
use super::actor::AccountActor;
use super::supervisor::Supervisor;
use crate::{LocalBusFrame, LocalBusFrameKind, SdkError};
use ramflux_protocol::message as g;
use zeroize::Zeroizing;

/// One account-scoped call of the agent methods, run by the human account's runtime.
pub(super) enum AgentCall {
    Create(Box<g::AgentCreate>),
    Decide(Box<g::AgentCreationDecide>),
    Get(String),
    /// `agent.list` (contract 2 `AgentList`).
    List(Box<g::AgentList>),
    /// `agent.get` (contract 2 `AgentGet`): one stored record by anchor.
    Record(String),
    /// `agent.delete` (contract 2 `AgentMutation`).
    Delete(Box<g::AgentMutation>),
    /// `agent.watch` (contract 2 `AgentWatch`): the changes after a cursor.
    Watch(Box<g::AgentWatch>),
    /// `agent.persona.edit` (contract 2 `AgentPersonaEdit`).
    PersonaEdit(Box<g::AgentPersonaEdit>),
    /// `agent.access.set` (contract 2 `AgentAccessSet`).
    AccessSet(Box<g::AgentAccessSet>),
}

pub(super) fn handles(method: &str) -> bool {
    matches!(
        method,
        "agent.create"
            | "agent.creation.decide"
            | "agent.operation.get"
            | "agent.list"
            | "agent.get"
            | "agent.watch"
            | "agent.delete"
            | "agent.persona.edit"
            | "agent.access.set"
    )
}

pub(super) async fn respond(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    // Every account-scoped request starts the event router in `Supervisor::route`. An account
    // actor publishes its pending outbox through that router while it starts, so an agent call
    // that is the first request on a supervisor would otherwise wait for the actor forever.
    supervisor.start_event_router();
    match apply(request, supervisor).await {
        Ok(result) => super::custody_response::success(request, result),
        Err(error) => super::custody_response::error(request, &error),
    }
}

async fn apply(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
) -> Result<g::AgentConfigResult, SdkError> {
    super::custody_setup::validate_headers(request, &mut None)?;
    super::requests::deadline(request)?;
    if request.kind != LocalBusFrameKind::Request || request.operation_id.is_some() {
        return Err(SdkError::CustodySetupInvalid);
    }
    let account_id = request.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
    let actor = supervisor
        .account_actor(&account_id)
        .filter(AccountActor::is_open)
        .ok_or(SdkError::NetworkingPending)?;
    let body = std::mem::take(&mut request.body);
    let call = match request.method.as_str() {
        "agent.create" => AgentCall::Create(Box::new(decode(body)?)),
        "agent.creation.decide" => AgentCall::Decide(Box::new(decode(body)?)),
        "agent.operation.get" => {
            let get: g::AgentOperationGet = decode(body)?;
            AgentCall::Get(get.operation_id)
        }
        "agent.list" => AgentCall::List(Box::new(decode(body)?)),
        "agent.get" => {
            let get: g::AgentGet = decode(body)?;
            AgentCall::Record(get.agent_anchor)
        }
        "agent.watch" => AgentCall::Watch(Box::new(decode(body)?)),
        "agent.delete" => AgentCall::Delete(Box::new(decode(body)?)),
        "agent.persona.edit" => AgentCall::PersonaEdit(Box::new(decode(body)?)),
        "agent.access.set" => AgentCall::AccessSet(Box::new(decode(body)?)),
        _ => return Err(SdkError::CustodySetupInvalid),
    };
    let read_id = match &call {
        AgentCall::Get(id) => Some(id.clone()),
        _ => None,
    };
    let result = actor.agent_call(call).await?;
    match read_id {
        Some(id) if advances_on_read(&result) => {
            // A failed advance leaves the request where it was; the reread reports that state.
            let now = super::custody_setup::now()?;
            let _ = supervisor.advance_agent_creations(&account_id, now).await;
            actor.agent_call(AgentCall::Get(id)).await
        }
        _ => Ok(result),
    }
}

fn decode<T: serde::de::DeserializeOwned>(body: serde_json::Value) -> Result<T, SdkError> {
    serde_json::from_value(body).map_err(|_| SdkError::CustodySetupInvalid)
}

/// Whether an operation read advances the creation: only the custody states of contract 7.3 do.
fn advances_on_read(result: &g::AgentConfigResult) -> bool {
    match &result.value {
        Some(g::agent_config_result::Value::Custody(status)) => {
            matches!(
                status.state.as_str(),
                "authorized" | "publication_pending" | "publication_unknown"
            )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
