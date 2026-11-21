// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Connection-level entry of the agent creation methods (AGENT-IDENTITY-01 C3). Like `account.create.*`,
//! these frames never enter the method table: the connection layer decodes the `ProtoJSON` body, the
//! human account's runtime performs the account-scoped work by private command, and the supervisor
//! advances a creation on read (controller decision r9 item 2, r10 item 1). Remote packets cannot
//! reach this path, so no remote source can start a creation.
use super::actor::AccountActor;
use super::supervisor::Supervisor;
use crate::{LocalBusFrame, LocalBusFrameKind, SdkError};
use ramflux_protocol::message as g;
use zeroize::Zeroizing;

/// One account-scoped call of the agent creation methods, run by the human account's runtime.
pub(super) enum AgentCall {
    Create(Box<g::AgentCreate>),
    Decide(g::AgentCreationDecide),
    Get(String),
}

pub(super) fn handles(method: &str) -> bool {
    matches!(method, "agent.create" | "agent.creation.decide" | "agent.operation.get")
}

pub(super) async fn respond(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    match apply(request, supervisor).await {
        Ok(status) => super::custody_response::success(
            request,
            g::AgentConfigResult { value: Some(g::agent_config_result::Value::Custody(status)) },
        ),
        Err(error) => super::custody_response::error(request, &error),
    }
}

async fn apply(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
) -> Result<g::AgentCustodyStatus, SdkError> {
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
        "agent.creation.decide" => AgentCall::Decide(decode(body)?),
        "agent.operation.get" => {
            let get: g::AgentOperationGet = decode(body)?;
            AgentCall::Get(get.operation_id)
        }
        _ => return Err(SdkError::CustodySetupInvalid),
    };
    let read_id = match &call {
        AgentCall::Get(id) => Some(id.clone()),
        AgentCall::Create(_) | AgentCall::Decide(_) => None,
    };
    let status = actor.agent_call(call).await?;
    match read_id {
        Some(id) if advances_on_read_state(&status.state) => {
            // A failed advance leaves the request where it was; the reread reports that state.
            let now = super::custody_setup::now()?;
            let _ = supervisor.advance_agent_creations(&account_id, now).await;
            actor.agent_call(AgentCall::Get(id)).await
        }
        _ => Ok(status),
    }
}

fn decode<T: serde::de::DeserializeOwned>(body: serde_json::Value) -> Result<T, SdkError> {
    serde_json::from_value(body).map_err(|_| SdkError::CustodySetupInvalid)
}

/// The states in which `agent.operation.get` advances the creation (contract 7.3).
fn advances_on_read_state(state: &str) -> bool {
    matches!(state, "authorized" | "publication_pending" | "publication_unknown")
}

#[cfg(test)]
mod tests;
