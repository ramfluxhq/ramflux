// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) fn hydrate_local_object_state(
    account: &mut LocalBusAccountState,
) -> Result<(), SdkError> {
    account.client.hydrate_object_store_from_account_db()
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch_object_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account_mut(state, account_id)?;
    match request.method.as_str() {
        "object.put" => {
            let body: LocalBusObjectPutRequest = serde_json::from_value(request.body.clone())?;
            let relay_options = parse_relay_transfer_options(
                body.relay_endpoint.clone(),
                body.relay_service_key_base64.clone(),
                body.relay_interrupt_after_chunks,
            )?;
            let plaintext = ramflux_protocol::decode_base64url(&body.plaintext_base64)
                .map_err(|error| SdkError::LocalBus(format!("invalid object body: {error}")))?;
            let object = account.client.put_encrypted_object(&body.object_id, &plaintext)?;
            let chunks = object_chunks(&object, body.chunk_size);
            let transfer = if let Some(options) = relay_options.as_ref() {
                Some(account.client.upload_object_to_relay(
                    &object.object_id,
                    body.chunk_size,
                    options,
                )?)
            } else {
                None
            };
            Ok(local_bus_ok(serde_json::json!({
                "object": object,
                "chunks": chunks,
                "transfer": transfer,
                "node_visible_plaintext": false,
                "node_visible_object_key": false,
            })))
        }
        "object.get" => {
            let body: LocalBusObjectGetRequest = serde_json::from_value(request.body.clone())?;
            let relay_options = parse_relay_transfer_options(
                body.relay_endpoint.clone(),
                body.relay_service_key_base64.clone(),
                body.relay_interrupt_after_chunks,
            )?;
            let plaintext = if let Some(options) = relay_options.as_ref() {
                account.client.download_object_from_relay(
                    &body.object_id,
                    options,
                    body.relay_ack,
                )?
            } else {
                account.client.decrypt_object(&body.object_id)?
            };
            Ok(local_bus_ok(serde_json::json!({
                "object_id": body.object_id,
                "plaintext_base64": ramflux_protocol::encode_base64url(&plaintext),
            })))
        }
        "object.transfer.status" => {
            let body: LocalBusObjectTransferStatusRequest =
                serde_json::from_value(request.body.clone())?;
            let status = account
                .client
                .object_transfer_status(&body.object_id, body.direction.as_deref())?;
            Ok(local_bus_ok(serde_json::json!({ "transfer": status })))
        }
        "object.transfer.resume" => {
            let body: LocalBusObjectTransferResumeRequest =
                serde_json::from_value(request.body.clone())?;
            let relay_options = parse_relay_transfer_options(
                body.relay_endpoint.clone(),
                body.relay_service_key_base64.clone(),
                body.relay_interrupt_after_chunks,
            )?
            .ok_or_else(|| {
                SdkError::LocalBus("object resume requires relay_endpoint".to_owned())
            })?;
            let status = match body.direction.as_str() {
                OBJECT_TRANSFER_UPLOAD => {
                    let existing = account
                        .client
                        .account_db()?
                        .object_transfer(&body.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
                        .ok_or_else(|| SdkError::LocalBus("missing upload transfer".to_owned()))?;
                    account.client.upload_object_to_relay(
                        &body.object_id,
                        usize::try_from(existing.chunk_size.max(1)).unwrap_or(64 * 1024),
                        &relay_options,
                    )?
                }
                OBJECT_TRANSFER_DOWNLOAD => {
                    let _plaintext = account.client.download_object_from_relay(
                        &body.object_id,
                        &relay_options,
                        false,
                    )?;
                    account
                        .client
                        .object_transfer_status(&body.object_id, Some(OBJECT_TRANSFER_DOWNLOAD))?
                        .ok_or_else(|| SdkError::LocalBus("missing download transfer".to_owned()))?
                }
                other => {
                    return Err(SdkError::LocalBus(format!(
                        "unsupported object transfer direction: {other}"
                    )));
                }
            };
            Ok(local_bus_ok(serde_json::json!({ "transfer": status })))
        }
        "object.list" => Ok(local_bus_ok(serde_json::json!({
            "objects": account.client.object_store.objects(),
        }))),
        "object.share" => {
            let body: LocalBusObjectShareRequest = serde_json::from_value(request.body.clone())?;
            let conversation_id = body.conversation_id.clone();
            let recipient_device_id = body.recipient_device_id.clone().ok_or_else(|| {
                SdkError::LocalBus("object.share requires recipient_device_id".to_owned())
            })?;
            let target_delivery_id = body.target_delivery_id.clone().ok_or_else(|| {
                SdkError::LocalBus("object.share requires target_delivery_id".to_owned())
            })?;
            let mut engine = account.take_live_engine().await?;
            let recipient_principal_commitment = account
                .client
                .resolve_target_principal_commitment(
                    &engine.config,
                    body.recipient_principal_commitment.as_deref(),
                    &recipient_device_id,
                )
                .await?;
            let recipient_device = account
                .client
                .assert_manifest_active_device_cached(
                    &engine.config,
                    &recipient_principal_commitment,
                    &recipient_device_id,
                    "object_share_friend_gate",
                )
                .await?;
            account.client.require_accepted_friend_link_for_dm_send(
                &account.gateway_config.principal_id,
                &account.principal_commitment,
                Some(&recipient_device.principal_id),
                &recipient_principal_commitment,
            )?;
            let package =
                account.client.share_object_key_with_dm_recipient(&mut engine, body).await;
            account.put_engine(engine);
            let package = package?;
            account.client.account_db()?.record_object_share_grant(&ObjectShareGrantWrite {
                object_id: &package.object.object_id,
                recipient_principal_id: &recipient_device.principal_id,
                recipient_principal_commitment: Some(&recipient_principal_commitment),
                recipient_device_id: Some(&recipient_device_id),
                conversation_id: Some(&conversation_id),
                shared_at: now_unix_timestamp(),
            })?;
            Ok(local_bus_ok(serde_json::json!({
                "object_id": package.object.object_id,
                "conversation_id": package.key_slot.conversation_id,
                "recipient_device_id": recipient_device_id,
                "target_delivery_id": target_delivery_id,
                "package": package,
                "node_visible_object_key": false,
            })))
        }
        "object.import" => {
            let body: LocalBusObjectImportRequest = serde_json::from_value(request.body.clone())?;
            let object = account.client.import_shared_object(&body.package)?;
            Ok(local_bus_ok(serde_json::json!({
                "object": object,
                "imported": true,
            })))
        }
        "object.delete" => {
            let body: LocalBusObjectDeleteRequest = serde_json::from_value(request.body.clone())?;
            account.client.tombstone_object(&body.object_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "object_id": body.object_id,
                "tombstoned": true,
            })))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}
