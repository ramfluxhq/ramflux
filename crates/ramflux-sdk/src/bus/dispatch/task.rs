// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-authorized task authoring; ingress is a typed local request, never a peer event map.
use crate::client::task::{invalid, require_local_human};
use crate::prelude::*;
use ramflux_protocol::{
    TaskAccept, TaskCancel, TaskDecline, TaskEvent, TaskEventBody, TaskProposal, TaskResolve,
    TaskStart, TaskUpdate,
};
use serde_json::{Value, json};

pub(crate) async fn dispatch_task(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let id = request_account_id(request)?;
    if matches!(request.method.as_str(), "task.get" | "task.list") {
        return Ok(local_bus_ok(read_task(&local_bus_account(state, id)?.client, request)?));
    }
    if request.method == "task.decision.prove" {
        return prove_decision(request, state);
    }
    authorize_local_task_sender(request, state, id)?;
    let account = local_bus_account_mut(state, id)?;
    let device = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let principal = device.principal_id.clone();
    let conversation = if let Some(conversation) = request.body["conversation_id"].as_str() {
        conversation.to_owned()
    } else if request.method == "task.cancel" {
        account.client.task_get(None, required(&request.body, "task_id")?)?["conversation_id"]
            .as_str()
            .ok_or_else(|| invalid("task not found"))?
            .to_owned()
    } else {
        return Err(invalid("task conversation_id required"));
    };
    let task_id = request.body["task_id"]
        .as_str()
        .map_or_else(crate::new_surface_message_id, |id| Ok(id.to_owned()))?;
    let mut body = request.body.clone();
    let object = body.as_object_mut().ok_or_else(|| invalid("task request must be an object"))?;
    object.remove("message_id");
    object.remove("proposal_id");
    object.remove("decision_proof_base64");
    let message = request.body["message_id"]
        .as_str()
        .map_or_else(crate::new_surface_message_id, |id| Ok(id.to_owned()))?;
    object.insert("task_id".into(), json!(task_id));
    let event = build_event(request, account, &conversation, &principal, body)?;
    let event =
        TaskEvent::new(conversation, event, sdk_device_signed_fields(&device.device_id, ""))
            .map_err(|e| invalid(e.to_string()))?;
    let carrier = account.client.sign_task_event(
        event,
        message,
        request.body["decision_proof_base64"].as_str().map(str::to_owned),
    )?;
    if account.client.task_delivery_receipt(&carrier)?.is_none() {
        if matches!(carrier.event()?.event(), TaskEventBody::Resolve(_)) {
            account.client.preflight_task_intent(&carrier)?;
        } else {
            account.client.preflight_task(&carrier)?;
        }
    }
    let response = super::task_transport::send(account, &carrier).await?;
    Ok(local_bus_ok(response))
}
pub(crate) fn read_task(
    client: &RamfluxClient,
    request: &LocalBusFrame,
) -> Result<Value, SdkError> {
    match request.method.as_str() {
        "task.get" => client.task_get(
            request.body["conversation_id"].as_str(),
            required(&request.body, "task_id")?,
        ),
        "task.list" => client.task_list(
            required(&request.body, "conversation_id")?,
            request.body["state"].as_str(),
            request.body["cursor"].as_str().unwrap_or(""),
            request.body["limit"]
                .as_u64()
                .map(u32::try_from)
                .transpose()
                .map_err(|_| invalid("invalid task list limit"))?
                .unwrap_or(50),
        ),
        _ => Err(invalid("unsupported task read")),
    }
}
fn required<'a>(body: &'a Value, name: &str) -> Result<&'a str, SdkError> {
    body[name]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid(format!("task {name} required")))
}

fn prove_decision(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    use crate::client::task::decision::Evidence;
    use ramflux_protocol::NeedsMe;
    let account = local_bus_account(state, request_account_id(request)?)?;
    let conversation = required(&request.body, "conversation_id")?;
    let resolution: TaskResolve = serde_json::from_value(request.body["resolution"].clone())?;
    let evidence = match &resolution.target {
        NeedsMe::Approval { .. } if resolution.decision == ramflux_protocol::TaskDecision::Deny => {
            Evidence::Denied {
                record: Box::new(
                    account
                        .client
                        .account_db()?
                        .load_actor_state(&format!("mcp/denied/{}", resolution.decision_id))?
                        .ok_or_else(|| invalid("verified task MCP denial not found"))?,
                ),
            }
        }
        NeedsMe::Approval { grant_id } => Evidence::Grant {
            record: Box::new(
                account
                    .mcp_grants
                    .get(grant_id)
                    .cloned()
                    .ok_or_else(|| invalid("verified task MCP grant not found"))?,
            ),
        },
        NeedsMe::Choice { surface_id } | NeedsMe::Input { surface_id } => {
            let principal = &account
                .client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .principal_id;
            Evidence::Surface {
                receipt_base64: account.client.task_surface_receipt(
                    conversation,
                    surface_id,
                    principal,
                    &resolution.decision_id,
                )?,
            }
        }
    };
    let proof = account.client.witness_task_decision(conversation, resolution, evidence)?;
    Ok(local_bus_ok(json!({"decision_proof_base64":proof.encoded()?})))
}

fn authorize_local_task_sender(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
    id: &str,
) -> Result<(), SdkError> {
    let human = matches!(
        request.method.as_str(),
        "task.start" | "task.accept" | "task.decline" | "task.resolve" | "task.cancel"
    );
    if human || request.method == "task.propose" {
        let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
            &state.config.data_root,
            id,
        ))?;
        let default_kind = if manifest.client_mode == LocalBusClientMode::HeadlessAi {
            "headless_ai"
        } else {
            "human"
        };
        if request.method == "task.propose" {
            if manifest.client_mode != LocalBusClientMode::HeadlessAi
                || manifest.kind.as_deref().unwrap_or(default_kind) != "headless_ai"
            {
                return Err(invalid("task proposal requires a headless AI account"));
            }
        } else {
            require_local_human(
                &manifest.client_mode,
                manifest.kind.as_deref().or(Some(default_kind)),
            )?;
        }
    }
    Ok(())
}

fn build_event(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
    conversation: &str,
    principal: &str,
    mut body: Value,
) -> Result<TaskEventBody, SdkError> {
    let object = body.as_object_mut().ok_or_else(|| invalid("task request must be an object"))?;
    Ok(match request.method.as_str() {
        "task.start" if request.body["proposal_id"].is_string() => {
            let proposal = required(&request.body, "proposal_id")?;
            let current = account.client.task_get(Some(conversation), proposal)?;
            if current.is_null()
                || current["assignee"] != request.body["assignee"]
                || request.body["constraints"].as_str().is_some_and(|v| !v.is_empty())
                || request.body["text"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty() && current["title"].as_str() != Some(v))
            {
                return Err(invalid(
                    "proposal acceptance requires unchanged proposal; use task.accept without text or constraints",
                ));
            }
            TaskEventBody::Accept(TaskAccept {
                task_id: proposal.into(),
                version: current["version"]
                    .as_u64()
                    .ok_or_else(|| invalid("proposal revision missing"))?
                    + 1,
            })
        }
        "task.start" => {
            object.insert("requester".into(), json!(principal));
            TaskEventBody::Start(serde_json::from_value::<TaskStart>(body)?)
        }
        "task.propose" => {
            object.insert("proposer".into(), json!(principal));
            TaskEventBody::Proposal(serde_json::from_value::<TaskProposal>(body)?)
        }
        method => {
            object.remove("conversation_id");
            match method {
                "task.accept" => TaskEventBody::Accept(serde_json::from_value::<TaskAccept>(body)?),
                "task.decline" => {
                    TaskEventBody::Decline(serde_json::from_value::<TaskDecline>(body)?)
                }
                "task.update" => TaskEventBody::Update(serde_json::from_value::<TaskUpdate>(body)?),
                "task.cancel" => {
                    if let Some(version) = object.remove("version")
                        && object.insert("base_revision".into(), version).is_some()
                    {
                        return Err(invalid("specify version or base_revision, not both"));
                    }
                    TaskEventBody::Cancel(serde_json::from_value::<TaskCancel>(body)?)
                }
                "task.resolve" => {
                    TaskEventBody::Resolve(serde_json::from_value::<TaskResolve>(body)?)
                }
                _ => return Err(invalid("unsupported task method")),
            }
        }
    })
}

#[cfg(test)]
#[path = "tests/task_authority.rs"]
mod tests;
