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
        "object.put.status" => {
            // T25-A2 (OBJ-IPC-01): read-only reconciliation status for a logical PUT.
            let body: LocalBusObjectPutStatusRequest =
                serde_json::from_value(request.body.clone())?;
            let record = account.client.object_operation(&body.object_id)?;
            let (state, terminal) = match record {
                Some(record) if record.operation_id == body.operation_id => {
                    let terminal = if record.state == OBJECT_OPERATION_COMMITTED {
                        record.terminal_result.clone()
                    } else {
                        None
                    };
                    (record.state, terminal)
                }
                _ => (OBJECT_OPERATION_UNKNOWN.to_owned(), None),
            };
            Ok(local_bus_ok(serde_json::json!({
                "object_id": body.object_id,
                "operation_id": body.operation_id,
                "state": state,
                "terminal": terminal,
            })))
        }
        "object.put" => {
            let body: LocalBusObjectPutRequest = serde_json::from_value(request.body.clone())?;
            // T25-A2 (OBJ-IPC-01): when the caller supplies an operation_id, run the durable
            // reconciliation state machine. Absent it, keep the A1 straight-line path (no A2
            // guarantee) — the capability is explicit and version-gated.
            if let Some(operation_id) = body.operation_id.clone() {
                return dispatch_object_put_reconciled(account, body, operation_id).await;
            }
            let relay_options = parse_relay_transfer_options(
                body.relay_endpoint.clone(),
                body.relay_service_key_base64.clone(),
                body.relay_interrupt_after_chunks,
            )?;
            let plaintext = ramflux_protocol::decode_base64url(&body.plaintext_base64)
                .map_err(|error| SdkError::LocalBus(format!("invalid object body: {error}")))?;
            let object = account.client.put_encrypted_object(&body.object_id, &plaintext)?;
            let transfer = if let Some(options) = relay_options.as_ref() {
                Some(
                    dispatch_object_upload_to_relay(
                        account,
                        &object.object_id,
                        body.chunk_size,
                        options,
                    )
                    .await?,
                )
            } else {
                None
            };
            // T25-A1 (OBJ-IPC-01): compact response only. The old `object`/`chunks` echo re-serialised
            // the whole ciphertext (Vec<u8> JSON number-array + base64 chunks, ~4.9x) and overflowed the
            // 1 MiB frame AFTER the write committed = ambiguous success. Return identifiers/hashes/status
            // only — never ciphertext — so the response stays far below the frame cap.
            let transfer_id = transfer.as_ref().map(|status| status.transfer_id.clone());
            Ok(local_bus_ok(serde_json::json!({
                "object_id": object.object_id,
                "manifest_hash": object.manifest_hash,
                "plaintext_hash": object.plaintext_hash,
                "committed": true,
                "transfer_id": transfer_id,
                "transfer": transfer,
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
                dispatch_object_download_from_relay(
                    account,
                    &body.object_id,
                    options,
                    body.relay_ack,
                )
                .await?
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
                    dispatch_object_upload_to_relay(
                        account,
                        &body.object_id,
                        usize::try_from(existing.chunk_size.max(1)).unwrap_or(64 * 1024),
                        &relay_options,
                    )
                    .await?
                }
                OBJECT_TRANSFER_DOWNLOAD => {
                    let _plaintext = dispatch_object_download_from_relay(
                        account,
                        &body.object_id,
                        &relay_options,
                        false,
                    )
                    .await?;
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
            let relay_options = parse_relay_transfer_options(
                body.relay_endpoint,
                body.relay_service_key_base64,
                None,
            )?;
            if let Some(options) = relay_options.as_ref() {
                let mut engine = account.take_live_engine().await?;
                let pool = account.relay_quic_pool()?;
                let result = account
                    .client
                    .tombstone_object_to_relay_via_gateway(
                        &mut engine,
                        &pool,
                        &body.object_id,
                        options,
                    )
                    .await;
                account.put_engine(engine);
                result?;
            } else {
                account.client.tombstone_object(&body.object_id)?;
            }
            Ok(local_bus_ok(serde_json::json!({
                "object_id": body.object_id,
                "tombstoned": true,
            })))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

/// T25-A2 (OBJ-IPC-01) P0-1: durable `object.put` reconciliation state machine.
///
/// Ordering: persist `Pending` → prepare (no publish) → ONE atomic `SQLCipher` txn
/// ({object row + key} + `LocalCommitted`) → install in-memory → relay upload/resume → persist
/// `Committed` → response. Crash windows W1–W4 are marked with the default-off `itest-rfd-fault`
/// barrier. Recovery ADOPTS a `local_committed`/`committed` object (never re-encrypts); only a
/// `pending` record (nothing durably committed) may re-derive. Fail-closed on a conflicting
/// `operation_id`/`request_hash` or an adoption hash mismatch. A retryable relay error keeps the
/// operation at `LocalCommitted` (records `last_error`) so it is resumable — it is NOT `failed`.
enum ReconcilePlan {
    Fresh { created_at: i64 },
    Adopt,
}

#[allow(clippy::too_many_lines)]
async fn dispatch_object_put_reconciled(
    account: &mut LocalBusAccountState,
    body: LocalBusObjectPutRequest,
    operation_id: String,
) -> Result<LocalBusDispatchResult, SdkError> {
    let relay_options = parse_relay_transfer_options(
        body.relay_endpoint.clone(),
        body.relay_service_key_base64.clone(),
        body.relay_interrupt_after_chunks,
    )?;
    let plaintext = ramflux_protocol::decode_base64url(&body.plaintext_base64)
        .map_err(|error| SdkError::LocalBus(format!("invalid object body: {error}")))?;
    let plaintext_hash =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);
    let request_hash = object_put_request_hash(&body, &operation_id, &plaintext_hash)?;
    let now = now_unix_timestamp();

    let existing = account.client.object_operation(&body.object_id)?;

    let plan = match &existing {
        Some(record) if record.operation_id == operation_id => match record.state.as_str() {
            OBJECT_OPERATION_COMMITTED => {
                // Idempotent reconnect: return the stored compact terminal, reconciled=true.
                let terminal = record.terminal_result.clone().unwrap_or_else(
                    || serde_json::json!({ "object_id": body.object_id, "committed": true }),
                );
                return Ok(local_bus_ok(with_reconciled(terminal, true)));
            }
            OBJECT_OPERATION_FAILED => {
                return Err(SdkError::LocalBus(format!(
                    "object.put operation {operation_id} previously failed: {}",
                    record.last_error.clone().unwrap_or_default()
                )));
            }
            OBJECT_OPERATION_LOCAL_COMMITTED => {
                if record.request_hash != request_hash {
                    return fail_closed(
                        account,
                        &body.object_id,
                        &operation_id,
                        &request_hash,
                        record.manifest_hash.as_deref(),
                        record.plaintext_hash.as_deref(),
                        now,
                        "request hash changed for a local_committed operation",
                    );
                }
                ReconcilePlan::Adopt
            }
            OBJECT_OPERATION_PENDING => {
                if record.request_hash != request_hash {
                    return fail_closed(
                        account,
                        &body.object_id,
                        &operation_id,
                        &request_hash,
                        None,
                        None,
                        now,
                        "request hash changed for a pending operation",
                    );
                }
                // W1: nothing durably committed yet — safe to re-derive; keep created_at.
                ReconcilePlan::Fresh { created_at: record.created_at }
            }
            other => {
                return Err(SdkError::LocalBus(format!(
                    "object.put unknown operation state: {other}"
                )));
            }
        },
        Some(record) => match record.state.as_str() {
            OBJECT_OPERATION_PENDING | OBJECT_OPERATION_LOCAL_COMMITTED => {
                // A different operation is in flight for this object — fail closed WITHOUT
                // clobbering the legitimate in-flight record.
                return Err(SdkError::LocalBus(format!(
                    "object.put conflict (fail closed): object {} has an in-flight operation {}",
                    body.object_id, record.operation_id
                )));
            }
            // Terminal record under a different operation_id: a new revision is allowed.
            _ => ReconcilePlan::Fresh { created_at: now },
        },
        None => ReconcilePlan::Fresh { created_at: now },
    };

    let reconciled = matches!(plan, ReconcilePlan::Adopt);

    match plan {
        ReconcilePlan::Fresh { created_at } => {
            // 1. persist Pending (durable SQL write).
            account.client.upsert_object_operation(&ObjectOperationWrite {
                object_id: &body.object_id,
                operation_id: &operation_id,
                state: OBJECT_OPERATION_PENDING,
                request_hash: &request_hash,
                manifest_hash: None,
                plaintext_hash: None,
                terminal_result: None,
                last_error: None,
                created_at,
                updated_at: now,
            })?;
            // W1: after Pending, before the atomic local commit.
            #[cfg(feature = "itest-rfd-fault")]
            crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::PutAfterPending).await?;
            // 2. prepare (fresh key + AEAD) WITHOUT publishing.
            let prepared = account.client.prepare_encrypted_object(&body.object_id, &plaintext)?;
            // 3. ONE atomic SQLCipher txn {object+key upsert, operation=LocalCommitted}, then
            //    4. install into the in-memory store.
            account.client.commit_prepared_object_local(
                prepared,
                &operation_id,
                &request_hash,
                created_at,
                now,
            )?;
        }
        ReconcilePlan::Adopt => {
            // Recovery: ADOPT the already-stored object; never re-encrypt. Verify the stored
            // object matches the record binding AND the resent plaintext — else fail closed.
            let record = existing
                .as_ref()
                .ok_or_else(|| SdkError::LocalBus("adopt without a record".to_owned()))?;
            let object = account.client.object_store_object(&body.object_id).ok_or_else(|| {
                SdkError::LocalBus("local_committed object missing from the store".to_owned())
            })?;
            let bound = record.manifest_hash.as_deref() == Some(object.manifest_hash.as_str())
                && record.plaintext_hash.as_deref() == Some(object.plaintext_hash.as_str())
                && object.plaintext_hash == plaintext_hash;
            if !bound {
                return fail_closed(
                    account,
                    &body.object_id,
                    &operation_id,
                    &request_hash,
                    record.manifest_hash.as_deref(),
                    record.plaintext_hash.as_deref(),
                    now,
                    "adoption hash mismatch",
                );
            }
        }
    }

    // W2: after LocalCommitted, before relay.
    #[cfg(feature = "itest-rfd-fault")]
    crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::PutAfterLocalCommitted).await?;

    let object = account.client.object_store_object(&body.object_id).ok_or_else(|| {
        SdkError::LocalBus("object missing from the store after local commit".to_owned())
    })?;
    let manifest_hash = object.manifest_hash.clone();

    // 5. relay upload / resume. A relay error is RETRYABLE: keep LocalCommitted + last_error and
    //    return the error so the CLI can reconnect and resume — do NOT mark Failed.
    let transfer = if let Some(options) = relay_options.as_ref() {
        match dispatch_object_upload_to_relay(account, &object.object_id, body.chunk_size, options)
            .await
        {
            Ok(status) => Some(status),
            Err(error) => {
                let message = error.to_string();
                let _ = account.client.upsert_object_operation(&ObjectOperationWrite {
                    object_id: &body.object_id,
                    operation_id: &operation_id,
                    state: OBJECT_OPERATION_LOCAL_COMMITTED,
                    request_hash: &request_hash,
                    manifest_hash: Some(&manifest_hash),
                    plaintext_hash: Some(&plaintext_hash),
                    terminal_result: None,
                    last_error: Some(&message),
                    created_at: now,
                    updated_at: now_unix_timestamp(),
                });
                return Err(error);
            }
        }
    } else {
        None
    };

    // W3: relay complete, before Committed.
    #[cfg(feature = "itest-rfd-fault")]
    crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::PutBeforeCommitted).await?;

    // 6. persist Committed (compact terminal — identifiers/hashes/transfer only; never ciphertext
    //    or key).
    let transfer_id = transfer.as_ref().map(|status| status.transfer_id.clone());
    let terminal = serde_json::json!({
        "object_id": object.object_id,
        "manifest_hash": manifest_hash,
        "plaintext_hash": plaintext_hash,
        "committed": true,
        "transfer_id": transfer_id,
        "transfer": transfer,
        "operation_id": operation_id,
    });
    let terminal_bytes = serde_json::to_vec(&terminal)?;
    account.client.upsert_object_operation(&ObjectOperationWrite {
        object_id: &body.object_id,
        operation_id: &operation_id,
        state: OBJECT_OPERATION_COMMITTED,
        request_hash: &request_hash,
        manifest_hash: Some(&manifest_hash),
        plaintext_hash: Some(&plaintext_hash),
        terminal_result: Some(&terminal_bytes),
        last_error: None,
        created_at: now,
        updated_at: now_unix_timestamp(),
    })?;

    // W4: after Committed, before the local-bus response.
    #[cfg(feature = "itest-rfd-fault")]
    crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::PutAfterCommitted).await?;

    Ok(local_bus_ok(with_reconciled(terminal, reconciled)))
}

/// Persists a `Failed` terminal for a permanent conflict and returns a fail-closed error. Only used
/// for same-operation request-hash changes and adoption hash mismatches (never to clobber a
/// legitimate different in-flight operation).
#[allow(clippy::too_many_arguments)]
fn fail_closed(
    account: &LocalBusAccountState,
    object_id: &str,
    operation_id: &str,
    request_hash: &str,
    manifest_hash: Option<&str>,
    plaintext_hash: Option<&str>,
    now: i64,
    message: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    account.client.upsert_object_operation(&ObjectOperationWrite {
        object_id,
        operation_id,
        state: OBJECT_OPERATION_FAILED,
        request_hash,
        manifest_hash,
        plaintext_hash,
        terminal_result: None,
        last_error: Some(message),
        created_at: now,
        updated_at: now,
    })?;
    Err(SdkError::LocalBus(format!("object.put conflict (fail closed): {message}")))
}

/// Binds the content-and-intent of a PUT: `object_id` + `plaintext_hash` + `chunk_size` +
/// normalized relay endpoint + `operation_id` + protocol version. Contains NO secret.
fn object_put_request_hash(
    body: &LocalBusObjectPutRequest,
    operation_id: &str,
    plaintext_hash: &str,
) -> Result<String, SdkError> {
    let descriptor = serde_json::json!({
        "schema": OBJECT_PUT_REQUEST_HASH_DOMAIN,
        "protocol_version": OBJECT_PUT_PROTOCOL_VERSION,
        "object_id": body.object_id,
        "plaintext_hash": plaintext_hash,
        "chunk_size": body.chunk_size,
        "relay_endpoint": normalize_relay_endpoint(body.relay_endpoint.as_deref()),
        "operation_id": operation_id,
    });
    Ok(ramflux_crypto::blake3_256_base64url(
        OBJECT_PUT_REQUEST_HASH_DOMAIN,
        &ramflux_protocol::canonical_json_bytes(&descriptor)?,
    ))
}

fn normalize_relay_endpoint(endpoint: Option<&str>) -> String {
    endpoint.map(|value| value.trim().to_ascii_lowercase()).unwrap_or_default()
}

fn with_reconciled(mut terminal: serde_json::Value, reconciled: bool) -> serde_json::Value {
    if let Some(map) = terminal.as_object_mut() {
        map.insert("reconciled".to_owned(), serde_json::Value::Bool(reconciled));
    }
    terminal
}

// T22-A1 / RQ-04: object upload/download relay dispatch. Production builds always use the async v3
// GatewayIssued path; the synchronous LocalMint (v2 shared-HMAC) branch is compiled only under the
// `itest-local-mint` feature so the default binary contains no v2 mint code.
#[cfg(not(feature = "itest-local-mint"))]
async fn dispatch_object_upload_to_relay(
    account: &mut LocalBusAccountState,
    object_id: &str,
    chunk_size: usize,
    options: &RelayTransferOptions,
) -> Result<SdkObjectTransferStatus, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let pool = account.relay_quic_pool()?;
    let result = account
        .client
        .upload_object_to_relay_via_gateway(&mut engine, &pool, object_id, chunk_size, options)
        .await;
    account.put_engine(engine);
    result
}

#[cfg(feature = "itest-local-mint")]
async fn dispatch_object_upload_to_relay(
    account: &mut LocalBusAccountState,
    object_id: &str,
    chunk_size: usize,
    options: &RelayTransferOptions,
) -> Result<SdkObjectTransferStatus, SdkError> {
    if matches!(options.token_provider, RelayTokenProvider::LocalMint { .. }) {
        return account.client.upload_object_to_relay(object_id, chunk_size, options);
    }
    let mut engine = account.take_live_engine().await?;
    let pool = account.relay_quic_pool()?;
    let result = account
        .client
        .upload_object_to_relay_via_gateway(&mut engine, &pool, object_id, chunk_size, options)
        .await;
    account.put_engine(engine);
    result
}

#[cfg(not(feature = "itest-local-mint"))]
async fn dispatch_object_download_from_relay(
    account: &mut LocalBusAccountState,
    object_id: &str,
    options: &RelayTransferOptions,
    ack: bool,
) -> Result<Vec<u8>, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let pool = account.relay_quic_pool()?;
    let result = account
        .client
        .download_object_from_relay_via_gateway(&mut engine, &pool, object_id, options, ack)
        .await;
    account.put_engine(engine);
    result
}

#[cfg(feature = "itest-local-mint")]
async fn dispatch_object_download_from_relay(
    account: &mut LocalBusAccountState,
    object_id: &str,
    options: &RelayTransferOptions,
    ack: bool,
) -> Result<Vec<u8>, SdkError> {
    if matches!(options.token_provider, RelayTokenProvider::LocalMint { .. }) {
        return account.client.download_object_from_relay(object_id, options, ack);
    }
    let mut engine = account.take_live_engine().await?;
    let pool = account.relay_quic_pool()?;
    let result = account
        .client
        .download_object_from_relay_via_gateway(&mut engine, &pool, object_id, options, ack)
        .await;
    account.put_engine(engine);
    result
}

#[cfg(test)]
mod tests {
    use super::{normalize_relay_endpoint, object_put_request_hash, with_reconciled};
    use crate::bus::protocol::LocalBusObjectPutRequest;

    fn put_request(chunk_size: usize, relay: Option<&str>) -> LocalBusObjectPutRequest {
        LocalBusObjectPutRequest {
            object_id: "object_hash_1".to_owned(),
            plaintext_base64: String::new(),
            chunk_size,
            relay_endpoint: relay.map(str::to_owned),
            relay_service_key_base64: None,
            relay_interrupt_after_chunks: None,
            operation_id: Some("op-1".to_owned()),
        }
    }

    #[test]
    fn request_hash_is_stable_and_binds_content_and_intent() -> Result<(), crate::error::SdkError> {
        let base = put_request(1024, Some("http://relay:1"));
        let hash = object_put_request_hash(&base, "op-1", "plain-hash")?;
        // Deterministic for the same inputs (idempotent retry).
        assert_eq!(hash, object_put_request_hash(&base, "op-1", "plain-hash")?);
        // Normalized relay endpoint: trailing space / case does not change identity.
        let normalized = put_request(1024, Some("HTTP://RELAY:1 "));
        assert_eq!(hash, object_put_request_hash(&normalized, "op-1", "plain-hash")?);
        // A different plaintext, chunk size, operation id, or endpoint IS a conflict (new hash).
        assert_ne!(hash, object_put_request_hash(&base, "op-1", "OTHER-plain")?);
        assert_ne!(
            hash,
            object_put_request_hash(
                &put_request(2048, Some("http://relay:1")),
                "op-1",
                "plain-hash"
            )?
        );
        assert_ne!(hash, object_put_request_hash(&base, "op-2", "plain-hash")?);
        assert_ne!(
            hash,
            object_put_request_hash(
                &put_request(1024, Some("http://relay:2")),
                "op-1",
                "plain-hash"
            )?
        );
        Ok(())
    }

    #[test]
    fn normalize_relay_endpoint_trims_and_lowercases() {
        assert_eq!(normalize_relay_endpoint(Some("  HTTP://X ")), "http://x");
        assert_eq!(normalize_relay_endpoint(None), "");
    }

    #[test]
    fn with_reconciled_sets_flag() {
        let value = with_reconciled(serde_json::json!({ "committed": true }), true);
        assert_eq!(value["reconciled"], serde_json::Value::Bool(true));
        let value = with_reconciled(serde_json::json!({ "committed": true }), false);
        assert_eq!(value["reconciled"], serde_json::Value::Bool(false));
    }
}
