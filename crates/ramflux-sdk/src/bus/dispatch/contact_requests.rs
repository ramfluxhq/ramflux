// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account policy and explicit inbound request decisions through the authenticated local bus.
use crate::prelude::*;
use serde_json::json;
pub(super) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    id: &str,
) -> Result<Option<LocalBusDispatchResult>, SdkError> {
    let account = local_bus_account_mut(state, id)?;
    let method = match request.method.as_str() {
        "contact.request.accept" => "contact.accept",
        "contact.request.decline" => "contact.decline",
        "contact.request.block" => "contact.block",
        other => other,
    };
    match method {
        "contact.requests.list" => {
            return Ok(Some(local_bus_ok(account.client.contact_requests_list()?)));
        }
        "contact.requests.policy.get" => {
            return Ok(Some(local_bus_ok(
                json!({"contact_requests":account.client.contact_request_policy()?}),
            )));
        }
        "contact.requests.policy.set" => {
            let policy = request.body["contact_requests"]
                .as_str()
                .ok_or_else(|| SdkError::LocalBus("contact_requests is required".into()))?;
            account.client.set_contact_request_policy(policy)?;
            return Ok(Some(local_bus_ok(json!({"contact_requests":policy}))));
        }
        "contact.accept" | "contact.decline" | "contact.block" => {}
        _ => return Ok(None),
    }
    account.client.maintain_contact_requests()?;
    let selector = ["request_id", "link_id", "root_commitment", "principal_id"]
        .iter()
        .find_map(|key| request.body[*key].as_str().map(|value| (*key, value)));
    let selected = if let Some((field, selector)) = selector {
        account.client.account_db()?.select_inbound_contact_request(field, selector)?
    } else {
        None
    };
    let Some(record) = selected else {
        if method == "contact.decline" || request.body.get("request_id").is_some() {
            return Err(crate::ContactReason::RequestNotFound.into());
        }
        return Ok(None);
    };
    let decision = match method {
        "contact.accept" => "accepted",
        "contact.decline" => "declined",
        _ => "blocked",
    };
    if decision == "accepted" && record.state == "pending" {
        let engine = account.take_live_engine().await?;
        let manifest = crate::client::contact::fetch_verified_device_manifest(
            &engine.config,
            &record.contact_identity_commitment,
        )
        .await;
        account.put_engine(engine);
        account.client.persist_fetched_identity_directory(&manifest?)?;
    }
    account.client.decide_inbound_contact(&record, decision)?;
    let mut response = json!({"request_id":record.request_id,"root_commitment":record.contact_identity_commitment,"state":decision,"principal_id":record.principal_id,"direction":"inbound"});
    if decision == "accepted" {
        response["contact"] = account.client.contact_entry(&record.principal_id)?;
    }
    Ok(Some(local_bus_ok(response)))
}
