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
    let method = request.method.as_str();
    match method {
        "contact.requests.list" => {
            return Ok(Some(local_bus_ok(account.client.contact_requests_list()?)));
        }
        "contact.requests.policy.get" => {
            return Ok(Some(local_bus_ok(
                json!({"contact_requests":account.client.contact_request_policy()?,"authority_floors":account.client.contact_request_floor_status()?}),
            )));
        }
        "contact.requests.policy.set" => {
            let policy = request.body["contact_requests"]
                .as_str()
                .ok_or_else(|| SdkError::LocalBus("contact_requests is required".into()))?;
            let clear = match request.body.get("clear_retired_authority_floors") {
                None => false,
                Some(serde_json::Value::Bool(clear)) => *clear,
                Some(_) => {
                    return Err(SdkError::LocalBus(
                        "clear_retired_authority_floors must be boolean".into(),
                    ));
                }
            };
            let db = account.client.account_db()?;
            let removed = db.write_transaction(|| -> Result<_, SdkError> {
                account.client.set_contact_request_policy(policy)?;
                if clear {
                    Ok(db.clear_retired_contact_request_authority_floors(now_unix_timestamp())?)
                } else {
                    Ok(0)
                }
            })?;
            return Ok(Some(local_bus_ok(json!({"contact_requests":policy,
                "authority_floors":account.client.contact_request_floor_status()?,
                "cleared_authority_floors":removed}))));
        }
        "contact.requests.decline" => return Ok(Some(decline_batch(account, request)?)),
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
        let engine = account.session_client().await?;
        let manifest = account
            .client
            .peer_device_manifest(&engine.config, &record.contact_identity_commitment)
            .await;
        account.apply_session_metadata(engine);
        account.client.persist_fetched_identity_directory(&manifest?)?;
    }
    let response = account.client.account_db()?.write_transaction(|| {
        account.client.decide_inbound_contact(&record, decision)?;
        let mut response = json!({"request_id":record.request_id,"root_commitment":record.contact_identity_commitment,"state":decision,"principal_id":record.principal_id,"direction":"inbound"});
        if decision == "accepted" {
            // A pending request keeps strict first-accept semantics. An already accepted
            // request repairs its cache best-effort and must remain idempotent.
            let contact = if record.state == "pending" {
                account.client.accepted_contact_first_accept(&record.principal_id)?
            } else {
                account.client.accepted_contact_retry(&record.principal_id, None)?
            };
            response["contact"] = contact.ok_or(crate::ContactReason::RequestClosed)?;
        }
        Ok::<_, SdkError>(response)
    })?;
    Ok(Some(local_bus_ok(response)))
}

fn decline_batch(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let ids = request.body["request_ids"]
        .as_array()
        .ok_or_else(|| SdkError::LocalBus("request_ids is required".into()))?;
    if ids.is_empty() || ids.len() > 32 {
        return Err(SdkError::LocalBus("request_ids must contain 1..=32 ids".into()));
    }
    account.client.maintain_contact_requests()?;
    let mut records = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(id) = id.as_str().filter(|id| !id.is_empty() && id.len() <= 256) else {
            return Err(SdkError::LocalBus("request_ids entries must be short strings".into()));
        };
        let record = account
            .client
            .account_db()?
            .select_inbound_contact_request("request_id", id)?
            .ok_or(crate::ContactReason::RequestNotFound)?;
        records.push(record);
    }
    let mut declined = Vec::with_capacity(records.len());
    for record in &records {
        account.client.decide_inbound_contact(record, "declined")?;
        declined.push(json!({"request_id":record.request_id,"root_commitment":record.contact_identity_commitment,"state":"declined","principal_id":record.principal_id,"direction":"inbound"}));
    }
    Ok(local_bus_ok(json!({"declined": declined})))
}
