#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) async fn dispatch_contact_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    match request.method.as_str() {
        "contact.add" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusContactAddRequest = serde_json::from_value(request.body.clone())?;
            let link = account.client.establish_friend_link(
                &body.link_id,
                &body.requester_id,
                &body.target_id,
            )?;
            Ok(local_bus_ok(serde_json::to_value(link)?))
        }
        "contact.accept" => {
            if let Ok(body) =
                serde_json::from_value::<LocalBusContactFederatedRequest>(request.body.clone())
            {
                let account = local_bus_account_mut(state, account_id)?;
                let link = account.client.establish_friend_link(
                    &body.link_id,
                    &body.requester_id,
                    &body.target_id,
                )?;
                let engine = account.take_live_engine().await?;
                let response = account.client.send_plaintext_federated_contact_event(
                    &engine,
                    "friend.accepted",
                    &body,
                );
                account.put_engine(engine);
                let response = response?;
                Ok(local_bus_ok(serde_json::json!({
                    "link": link,
                    "delivery": response,
                })))
            } else {
                let account = local_bus_account(state, account_id)?;
                let body: LocalBusContactAddRequest = serde_json::from_value(request.body.clone())?;
                let link = account.client.establish_friend_link(
                    &body.link_id,
                    &body.requester_id,
                    &body.target_id,
                )?;
                Ok(local_bus_ok(serde_json::to_value(link)?))
            }
        }
        "contact.request" => {
            let body: LocalBusContactFederatedRequest =
                serde_json::from_value(request.body.clone())?;
            let account = local_bus_account_mut(state, account_id)?;
            let engine = account.take_live_engine().await?;
            let response = account.client.send_plaintext_federated_contact_event(
                &engine,
                "friend.requested",
                &body,
            );
            account.put_engine(engine);
            let response = response?;
            Ok(local_bus_ok(serde_json::to_value(response)?))
        }
        "contact.list" => {
            let account = local_bus_account(state, account_id)?;
            let links = account.client.friend_links()?;
            Ok(local_bus_ok(serde_json::json!({ "contacts": links })))
        }
        "contact.safety_number" => dispatch_contact_safety_number(request, state, account_id).await,
        "contact.verify" => dispatch_contact_verify(request, state, account_id).await,
        "contact.verification.status" => {
            dispatch_contact_verification_status(request, state, account_id).await
        }
        "contact.remove" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusContactRemoveRequest = serde_json::from_value(request.body.clone())?;
            let link = account.client.remove_friend_link(&body.link_id, &body.scope)?;
            Ok(local_bus_ok(serde_json::to_value(link)?))
        }
        "contact.block" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusContactLinkRequest = serde_json::from_value(request.body.clone())?;
            let link = account.client.block_friend_link(&body.link_id)?;
            Ok(local_bus_ok(serde_json::to_value(link)?))
        }
        "contact.unblock" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusContactLinkRequest = serde_json::from_value(request.body.clone())?;
            let link = account.client.unblock_friend_link(&body.link_id)?;
            Ok(local_bus_ok(serde_json::to_value(link)?))
        }
        "contact.rejected" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusConversationRequest = serde_json::from_value(request.body.clone())?;
            let rejected = account.client.rejected_inbox(&body.conversation_id)?;
            Ok(local_bus_ok(serde_json::json!({ "rejected": rejected })))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn contact_safety_request(
    request: &LocalBusFrame,
) -> Result<LocalBusContactSafetyRequest, SdkError> {
    Ok(serde_json::from_value(request.body.clone())?)
}

async fn dispatch_contact_safety_number(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body = contact_safety_request(request)?;
    let account = local_bus_account_mut(state, account_id)?;
    let engine = account.take_live_engine().await?;
    let safety = account
        .client
        .contact_safety_number_via_gateway(&engine.config, &body.contact_identity_commitment)
        .await;
    account.put_engine(engine);
    let safety = safety?;
    Ok(local_bus_ok(serde_json::to_value(safety)?))
}

async fn dispatch_contact_verify(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, account_id)?;
    let body = contact_safety_request(request)?;
    let engine = account.take_live_engine().await?;
    let safety = account
        .client
        .contact_safety_number_via_gateway(&engine.config, &body.contact_identity_commitment)
        .await;
    account.put_engine(engine);
    let safety = safety?;
    let record = account.client.account_db()?.mark_contact_verified(ContactVerificationUpdate {
        contact_identity_commitment: &body.contact_identity_commitment,
        safety_number_hash: &safety.safety_number_hash,
        device_set_hash: &safety.contact_device_set_hash,
        lineage_head: &safety.contact_lineage_head,
        verified_at: now_unix_timestamp(),
        verified_by_device_id: &account.gateway_config.device_id,
    })?;
    Ok(local_bus_ok(serde_json::json!({
        "contact_identity_commitment": record.contact_identity_commitment,
        "verification_state": record.verification_state,
        "verified_at": record.verified_at,
        "verified_by_device_id": record.verified_by_device_id,
        "safety_number": safety.safety_number,
        "fingerprint_hex": safety.fingerprint_hex,
    })))
}

async fn dispatch_contact_verification_status(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, account_id)?;
    let body = contact_safety_request(request)?;
    let engine = account.take_live_engine().await?;
    let safety = account
        .client
        .contact_safety_number_via_gateway(&engine.config, &body.contact_identity_commitment)
        .await;
    account.put_engine(engine);
    let safety = safety?;
    let status = account.client.contact_verification_status(&body.contact_identity_commitment)?;
    Ok(local_bus_ok(serde_json::json!({
        "contact_identity_commitment": body.contact_identity_commitment,
        "verification_state": safety.verification_state,
        "stored_verification_state": status
            .as_ref()
            .map_or("unverified", |record| record.verification_state.as_str()),
        "verified_at": status.as_ref().map(|record| record.verified_at),
        "verified_by_device_id": status
            .as_ref()
            .map(|record| record.verified_by_device_id.clone()),
        "safety_number": safety.safety_number,
        "fingerprint_hex": safety.fingerprint_hex,
    })))
}
