#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) fn hydrate_local_object_state(
    account: &mut LocalBusAccountState,
) -> Result<(), SdkError> {
    account.client.hydrate_object_store_from_account_db()
}

pub(crate) async fn dispatch_object_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account_mut(state, account_id)?;
    match request.method.as_str() {
        "object.put" => {
            let body: LocalBusObjectPutRequest = serde_json::from_value(request.body.clone())?;
            let plaintext = ramflux_protocol::decode_base64url(&body.plaintext_base64)
                .map_err(|error| SdkError::LocalBus(format!("invalid object body: {error}")))?;
            let object = account.client.put_encrypted_object(&body.object_id, &plaintext)?;
            let chunks = object_chunks(&object, body.chunk_size);
            Ok(local_bus_ok(serde_json::json!({
                "object": object,
                "chunks": chunks,
                "node_visible_plaintext": false,
                "node_visible_object_key": false,
            })))
        }
        "object.get" => {
            let body: LocalBusObjectGetRequest = serde_json::from_value(request.body.clone())?;
            let plaintext = account.client.decrypt_object(&body.object_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "object_id": body.object_id,
                "plaintext_base64": ramflux_protocol::encode_base64url(&plaintext),
            })))
        }
        "object.list" => Ok(local_bus_ok(serde_json::json!({
            "objects": account.client.object_store.objects(),
        }))),
        "object.share" => {
            let body: LocalBusObjectShareRequest = serde_json::from_value(request.body.clone())?;
            let recipient_device_id = body.recipient_device_id.clone().ok_or_else(|| {
                SdkError::LocalBus("object.share requires recipient_device_id".to_owned())
            })?;
            let target_delivery_id = body.target_delivery_id.clone().ok_or_else(|| {
                SdkError::LocalBus("object.share requires target_delivery_id".to_owned())
            })?;
            let mut engine = account.take_live_engine().await?;
            let package =
                account.client.share_object_key_with_dm_recipient(&mut engine, body).await;
            account.put_engine(engine);
            let package = package?;
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
