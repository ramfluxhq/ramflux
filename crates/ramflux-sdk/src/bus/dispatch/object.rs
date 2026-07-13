// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

// T25-A3 (CTRL-102 / OBJ-IPC-01): the bounded UPLOAD spool wiring.
use std::io::Write as _;

use crate::bus::daemon::local_bus_accounts_dir;
use crate::bus::io::{MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES, MAX_LOCAL_BUS_OBJECT_BYTES};
use crate::bus::protocol::{
    LocalBusObjectPutBeginRequest, LocalBusObjectPutChunkRequest, LocalBusObjectPutFinishRequest,
};
use crate::bus::state::ObjectPutSpoolSession;

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
    // T25-A3 (OBJ-IPC-01): the bounded UPLOAD spool lives under the daemon data_root; capture it
    // before the mutable account borrow (data_root is an immutable read of the same state).
    let data_root = state.config.data_root.clone();
    let account = local_bus_account_mut(state, account_id)?;
    match request.method.as_str() {
        "object.put.begin" => object_put_begin(&data_root, account_id, account, request),
        "object.put.chunk" => object_put_chunk(account, request),
        "object.put.finish" => object_put_finish(account, request).await,
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

/// Decodes the inline base64 plaintext (one-shot `object.put` path) then runs the shared durable
/// reconciliation core. The T25-A3 spool `finish` path bypasses this and calls the core directly
/// with the spool plaintext, so a 16 MiB object never becomes a resident base64 string.
async fn dispatch_object_put_reconciled(
    account: &mut LocalBusAccountState,
    body: LocalBusObjectPutRequest,
    operation_id: String,
) -> Result<LocalBusDispatchResult, SdkError> {
    let plaintext = ramflux_protocol::decode_base64url(&body.plaintext_base64)
        .map_err(|error| SdkError::LocalBus(format!("invalid object body: {error}")))?;
    dispatch_object_put_reconciled_core(account, &body, plaintext, operation_id).await
}

#[allow(clippy::too_many_lines)]
async fn dispatch_object_put_reconciled_core(
    account: &mut LocalBusAccountState,
    body: &LocalBusObjectPutRequest,
    plaintext: Vec<u8>,
    operation_id: String,
) -> Result<LocalBusDispatchResult, SdkError> {
    let relay_options = parse_relay_transfer_options(
        body.relay_endpoint.clone(),
        body.relay_service_key_base64.clone(),
        body.relay_interrupt_after_chunks,
    )?;
    let plaintext_hash =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);
    let request_hash = object_put_request_hash(body, &operation_id, &plaintext_hash)?;
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

// ---- T25-A3 (CTRL-102 / OBJ-IPC-01): bounded local-bus UPLOAD spool (begin / chunk / finish) ----

/// The private, account-scoped, owner-only (0700) directory that holds in-flight UPLOAD spool files
/// under the daemon `data_root`. Swept on daemon startup (orphans from a prior crash).
pub(crate) fn object_put_spool_dir(data_root: &Path) -> PathBuf {
    local_bus_accounts_dir(data_root).join("object_put_spool")
}

/// The deterministic, filename-safe spool path for one `(account_id, operation_id)`. base64url is
/// filename-safe (no `/`), and the hash avoids leaking the object/account ids into the filename.
fn object_put_spool_path(data_root: &Path, account_id: &str, operation_id: &str) -> PathBuf {
    let name = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_put_spool.v1",
        format!("{account_id}\u{0}{operation_id}").as_bytes(),
    );
    object_put_spool_dir(data_root).join(format!("{name}.spool"))
}

/// Removes an in-flight spool session (dropping its file handle) AND its on-disk file. Idempotent —
/// a no-op for an unknown `operation_id`. This is the single fail-closed cleanup used on begin
/// re-entry, any chunk error, and every finish (success or failure).
fn object_put_spool_discard(account: &mut LocalBusAccountState, operation_id: &str) {
    if let Some(session) = account.object_put_spools.remove(operation_id) {
        let path = session.path.clone();
        drop(session);
        let _ = std::fs::remove_file(&path);
    }
}

/// `object.put.begin`: open a bounded UPLOAD spool. Fails closed BEFORE creating any file on a wrong
/// protocol version or an oversize (> 16 MiB) declared length, so oversize never enters the pipeline.
fn object_put_begin(
    data_root: &Path,
    account_id: &str,
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectPutBeginRequest = serde_json::from_value(request.body.clone())?;
    if body.protocol_version != OBJECT_PUT_PROTOCOL_VERSION {
        return Err(SdkError::LocalBus(format!(
            "object.put.begin unsupported protocol_version {} (expected {OBJECT_PUT_PROTOCOL_VERSION})",
            body.protocol_version
        )));
    }
    if body.total_len > MAX_LOCAL_BUS_OBJECT_BYTES {
        // Fail closed before touching disk: an oversize object never opens a spool or commits.
        return Err(SdkError::LocalBus(format!(
            "object too large for local-bus upload: {} > {MAX_LOCAL_BUS_OBJECT_BYTES}",
            body.total_len
        )));
    }
    // Idempotent re-begin (a retry with the same operation_id): drop any prior in-flight session +
    // file so we always start from a clean, empty spool.
    object_put_spool_discard(account, &body.operation_id);
    let path = object_put_spool_path(data_root, account_id, &body.operation_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        set_owner_only_dir_permissions(parent)?;
    }
    // Sweep any cross-restart orphan at this deterministic path, then create_new (O_EXCL): never
    // reuse a pre-existing file and never follow a symlink into an attacker-chosen target.
    let _ = std::fs::remove_file(&path);
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    set_owner_only_file_permissions(&path)?;
    account.object_put_spools.insert(
        body.operation_id.clone(),
        ObjectPutSpoolSession {
            object_id: body.object_id,
            total_len: body.total_len,
            plaintext_hash: body.plaintext_hash,
            chunk_size: body.chunk_size,
            relay_endpoint: body.relay_endpoint,
            relay_service_key_base64: body.relay_service_key_base64,
            relay_interrupt_after_chunks: body.relay_interrupt_after_chunks,
            path,
            file,
            written: 0,
        },
    );
    Ok(local_bus_ok(serde_json::json!({
        "operation_id": body.operation_id,
        "accepted": true,
        "max_chunk_payload_bytes": MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES,
    })))
}

/// `object.put.chunk`: append one bounded plaintext chunk at the verified offset, fsync'd before the
/// ack. ANY validation failure (oversize chunk / offset gap / overlap / duplicate / exceeds declared
/// or 16 MiB total) OR an fsync failure destroys the spool (fail closed) so a garbled or
/// non-durable upload can never reach the object commit.
fn object_put_chunk(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectPutChunkRequest = serde_json::from_value(request.body.clone())?;
    let data = ramflux_protocol::decode_base64url(&body.data_base64)
        .map_err(|error| SdkError::LocalBus(format!("object.put.chunk invalid data: {error}")))?;
    match object_put_chunk_apply(account, &body, &data) {
        Ok(written) => Ok(local_bus_ok(serde_json::json!({
            "operation_id": body.operation_id,
            "written": written,
            "received": true,
        }))),
        Err(error) => {
            object_put_spool_discard(account, &body.operation_id);
            Err(error)
        }
    }
}

/// Pure append-with-validation core (no cleanup — the caller fails closed on `Err`). Returns the new
/// total written length on success.
fn object_put_chunk_apply(
    account: &mut LocalBusAccountState,
    body: &LocalBusObjectPutChunkRequest,
    data: &[u8],
) -> Result<usize, SdkError> {
    let session = account.object_put_spools.get_mut(&body.operation_id).ok_or_else(|| {
        SdkError::LocalBus(format!(
            "object.put.chunk: unknown or closed upload session {}",
            body.operation_id
        ))
    })?;
    if data.len() > MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES {
        return Err(SdkError::LocalBus(format!(
            "object.put.chunk payload {} exceeds the {MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES}-byte bound",
            data.len()
        )));
    }
    if body.offset != session.written {
        // Gap, overlap, OR duplicate: the only accepted offset is exactly the bytes written so far.
        return Err(SdkError::LocalBus(format!(
            "object.put.chunk offset {} != expected {} (gap/overlap/duplicate)",
            body.offset, session.written
        )));
    }
    let end = session
        .written
        .checked_add(data.len())
        .ok_or_else(|| SdkError::LocalBus("object.put.chunk offset overflow".to_owned()))?;
    if end > session.total_len {
        return Err(SdkError::LocalBus(format!(
            "object.put.chunk exceeds declared total_len: {end} > {}",
            session.total_len
        )));
    }
    if end > MAX_LOCAL_BUS_OBJECT_BYTES {
        return Err(SdkError::LocalBus(format!(
            "object.put.chunk exceeds the {MAX_LOCAL_BUS_OBJECT_BYTES}-byte object limit: {end}"
        )));
    }
    session.file.write_all(data)?;
    // T25-A3 (CTRL-102): durably fsync the appended chunk (data + size) BEFORE the chunk is acked, so
    // a crash after the ack cannot lose spooled bytes. A sync failure propagates as Err, and the
    // caller (`object_put_chunk`) destroys the spool and fails closed — the upload never commits.
    session.file.sync_data()?;
    session.written = end;
    Ok(end)
}

/// `object.put.finish`: verify completeness + hash, then REUSE the A2 durable reconciliation core
/// under the SAME `operation_id`. The spool file is removed on EVERY path (success and failure).
async fn object_put_finish(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectPutFinishRequest = serde_json::from_value(request.body.clone())?;
    // Take the session OUT so cleanup is guaranteed regardless of how the finish resolves.
    let mut session = account.object_put_spools.remove(&body.operation_id).ok_or_else(|| {
        SdkError::LocalBus(format!(
            "object.put.finish: unknown or closed upload session {}",
            body.operation_id
        ))
    })?;
    let path = session.path.clone();
    let result = object_put_finish_inner(account, &body, &mut session).await;
    drop(session); // close the file handle before removing the file
    let _ = std::fs::remove_file(&path);
    result
}

async fn object_put_finish_inner(
    account: &mut LocalBusAccountState,
    body: &LocalBusObjectPutFinishRequest,
    session: &mut ObjectPutSpoolSession,
) -> Result<LocalBusDispatchResult, SdkError> {
    if body.object_id != session.object_id {
        return Err(SdkError::LocalBus(format!(
            "object.put.finish object_id mismatch: begin={} finish={}",
            session.object_id, body.object_id
        )));
    }
    if session.written != session.total_len {
        return Err(SdkError::LocalBus(format!(
            "object.put.finish incomplete: {} of {} bytes present",
            session.written, session.total_len
        )));
    }
    session.file.flush()?;
    session.file.sync_all()?;
    let plaintext = std::fs::read(&session.path)?;
    if plaintext.len() != session.total_len {
        return Err(SdkError::LocalBus(format!(
            "object.put.finish spool length mismatch: {} != {}",
            plaintext.len(),
            session.total_len
        )));
    }
    if plaintext.len() > MAX_LOCAL_BUS_OBJECT_BYTES {
        return Err(SdkError::LocalBus(format!(
            "object.put.finish spool exceeds the {MAX_LOCAL_BUS_OBJECT_BYTES}-byte object limit"
        )));
    }
    // Fail closed on a plaintext hash mismatch: never commit tampered/garbled content.
    let actual_hash =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);
    if actual_hash != session.plaintext_hash {
        return Err(SdkError::LocalBus(format!(
            "object.put.finish plaintext hash mismatch: expected {} got {actual_hash}",
            session.plaintext_hash
        )));
    }
    // Reuse the A2 durable reconciliation with the SAME operation_id and IDENTICAL semantics as the
    // one-shot path — so a lost finish response reconciles via object.put.status with no new
    // ambiguous-success window. The plaintext is passed directly (no resident base64 round-trip).
    let put = LocalBusObjectPutRequest {
        object_id: session.object_id.clone(),
        plaintext_base64: String::new(),
        chunk_size: session.chunk_size,
        relay_endpoint: session.relay_endpoint.clone(),
        relay_service_key_base64: session.relay_service_key_base64.clone(),
        relay_interrupt_after_chunks: session.relay_interrupt_after_chunks,
        operation_id: Some(body.operation_id.clone()),
    };
    dispatch_object_put_reconciled_core(account, &put, plaintext, body.operation_id.clone()).await
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

// T25-A3 (CTRL-102 / OBJ-IPC-01): pure tests for the bounded UPLOAD spool (begin/chunk/finish),
// driven entirely in-process (relay_endpoint=None so no network) against a real unlocked account.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::large_futures)]
mod spool_tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const ACCOUNT: &str = "acct";
    const OPERATION: &str = "op-spool-1";
    const OBJECT_ID: &str = "object_spool_1";

    fn temp_data_root(test: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("ramflux-spool-{test}-{}-{nanos}", std::process::id()))
    }

    fn make_state(data_root: PathBuf) -> LocalBusDaemonState {
        let mut client = RamfluxClient::new();
        client.create_identity_root("principal_spool_test", [0x51; 32]);
        client.create_device_branch("principal_spool_test", "device_spool_test", 1, [0x52; 32]);
        client.open_account_index(&data_root).expect("open account index");
        client.create_account(ACCOUNT, "principal_spool_test").expect("create account");
        client.set_active_account(ACCOUNT).expect("set active account");
        client.unlock_account(ACCOUNT, b"spool-test-secret").expect("unlock account");
        let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
            gateway_addr: "127.0.0.1:1".parse().expect("gateway addr"),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_spool_test".to_owned(),
            device_id: "device_spool_test".to_owned(),
            target_delivery_id: "target_spool_test".to_owned(),
            prekey_http_url: None,
        });
        LocalBusDaemonState {
            config: LocalBusConfig::new(data_root.join("bus.sock"), data_root),
            accounts: BTreeMap::from([(
                ACCOUNT.to_owned(),
                LocalBusAccountState::disconnected(
                    client,
                    gateway,
                    "principal_spool_test".to_owned(),
                ),
            )]),
            active_account_id: Some(ACCOUNT.to_owned()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        }
    }

    async fn dispatch(
        state: &mut LocalBusDaemonState,
        method: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        let frame = LocalBusFrame::request("req", Some(ACCOUNT.to_owned()), "object", method, body);
        Ok(dispatch_object_bus_request(&frame, state).await?.response_body)
    }

    fn begin_body(total_len: usize, plaintext_hash: &str) -> serde_json::Value {
        serde_json::to_value(LocalBusObjectPutBeginRequest {
            object_id: OBJECT_ID.to_owned(),
            operation_id: OPERATION.to_owned(),
            total_len,
            plaintext_hash: plaintext_hash.to_owned(),
            chunk_size: 65_536,
            protocol_version: OBJECT_PUT_PROTOCOL_VERSION,
            relay_endpoint: None,
            relay_service_key_base64: None,
            relay_interrupt_after_chunks: None,
        })
        .expect("begin body")
    }

    fn chunk_body(offset: usize, data: &[u8]) -> serde_json::Value {
        serde_json::to_value(LocalBusObjectPutChunkRequest {
            operation_id: OPERATION.to_owned(),
            offset,
            data_base64: ramflux_protocol::encode_base64url(data),
        })
        .expect("chunk body")
    }

    fn finish_body() -> serde_json::Value {
        serde_json::to_value(LocalBusObjectPutFinishRequest {
            object_id: OBJECT_ID.to_owned(),
            operation_id: OPERATION.to_owned(),
        })
        .expect("finish body")
    }

    fn plaintext_hash(bytes: &[u8]) -> String {
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, bytes)
    }

    fn spool_path(state: &LocalBusDaemonState) -> PathBuf {
        object_put_spool_path(&state.config.data_root, ACCOUNT, OPERATION)
    }

    #[tokio::test]
    async fn begin_chunk_finish_commits_compact_terminal_and_cleans_up() {
        let root = temp_data_root("happy");
        let mut state = make_state(root.clone());
        let plaintext = vec![0xA5_u8; 3 * 1024]; // three 1 KiB chunks
        let hash = plaintext_hash(&plaintext);
        dispatch(&mut state, "object.put.begin", begin_body(plaintext.len(), &hash))
            .await
            .expect("begin");
        assert!(spool_path(&state).exists(), "begin must create the spool file");
        let mut offset = 0;
        for chunk in plaintext.chunks(1024) {
            let response = dispatch(&mut state, "object.put.chunk", chunk_body(offset, chunk))
                .await
                .expect("chunk");
            offset += chunk.len();
            assert_eq!(response["written"], offset);
        }
        let terminal =
            dispatch(&mut state, "object.put.finish", finish_body()).await.expect("finish");
        // Compact terminal — NO ciphertext echo.
        assert_eq!(terminal["object_id"], OBJECT_ID);
        assert_eq!(terminal["committed"], true);
        assert_eq!(terminal["plaintext_hash"], serde_json::Value::String(hash.clone()));
        assert!(terminal.get("object").is_none(), "no object echo");
        assert!(terminal.get("chunks").is_none(), "no chunks echo");
        assert!(terminal.get("ciphertext").is_none(), "no ciphertext echo");
        // Spool file removed on success.
        assert!(!spool_path(&state).exists(), "finish must remove the spool file");
        // A2 object.put.status must report committed on the spool path.
        let status = dispatch(
            &mut state,
            "object.put.status",
            serde_json::json!({ "object_id": OBJECT_ID, "operation_id": OPERATION }),
        )
        .await
        .expect("status");
        assert_eq!(status["state"], "committed");
        assert!(status["terminal"]["committed"].as_bool().unwrap_or(false));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn oversize_begin_is_rejected_before_creating_a_file() {
        let root = temp_data_root("oversize");
        let mut state = make_state(root.clone());
        let error = dispatch(
            &mut state,
            "object.put.begin",
            begin_body(MAX_LOCAL_BUS_OBJECT_BYTES + 1, "hash"),
        )
        .await
        .expect_err("oversize begin must fail closed");
        assert!(error.to_string().contains("too large"), "{error}");
        assert!(!spool_path(&state).exists(), "no spool file on an oversize reject");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn offset_gap_fails_closed_and_destroys_the_spool() {
        let root = temp_data_root("gap");
        let mut state = make_state(root.clone());
        let plaintext = vec![0x11_u8; 2048];
        dispatch(
            &mut state,
            "object.put.begin",
            begin_body(plaintext.len(), &plaintext_hash(&plaintext)),
        )
        .await
        .expect("begin");
        // A chunk at offset 1 (a gap — expected 0) must fail closed and delete the spool.
        let error = dispatch(&mut state, "object.put.chunk", chunk_body(1, &plaintext[..1024]))
            .await
            .expect_err("gap chunk must fail");
        assert!(error.to_string().contains("gap/overlap/duplicate"), "{error}");
        assert!(!spool_path(&state).exists(), "a gap must destroy the spool (fail closed)");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn duplicate_offset_fails_closed() {
        let root = temp_data_root("dup");
        let mut state = make_state(root.clone());
        let plaintext = vec![0x22_u8; 2048];
        dispatch(
            &mut state,
            "object.put.begin",
            begin_body(plaintext.len(), &plaintext_hash(&plaintext)),
        )
        .await
        .expect("begin");
        dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext[..1024]))
            .await
            .expect("first chunk");
        // Re-sending offset 0 (duplicate) — expected is now 1024 — must fail closed.
        let error = dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext[..1024]))
            .await
            .expect_err("duplicate chunk must fail");
        assert!(error.to_string().contains("gap/overlap/duplicate"), "{error}");
        assert!(!spool_path(&state).exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn chunk_beyond_total_len_fails_closed() {
        let root = temp_data_root("overrun");
        let mut state = make_state(root.clone());
        dispatch(&mut state, "object.put.begin", begin_body(1024, &plaintext_hash(&[0x33; 1024])))
            .await
            .expect("begin");
        // 2048 bytes at offset 0 exceeds the declared total_len of 1024.
        let error = dispatch(&mut state, "object.put.chunk", chunk_body(0, &[0x33_u8; 2048]))
            .await
            .expect_err("overrun chunk must fail");
        assert!(error.to_string().contains("exceeds declared total_len"), "{error}");
        assert!(!spool_path(&state).exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn hash_mismatch_at_finish_fails_closed_and_cleans_up() {
        let root = temp_data_root("hashmismatch");
        let mut state = make_state(root.clone());
        let plaintext = vec![0x44_u8; 1024];
        // Bind a hash that does NOT match the streamed bytes.
        let wrong_hash = plaintext_hash(&[0x99_u8; 1024]);
        dispatch(&mut state, "object.put.begin", begin_body(plaintext.len(), &wrong_hash))
            .await
            .expect("begin");
        dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext)).await.expect("chunk");
        let error = dispatch(&mut state, "object.put.finish", finish_body())
            .await
            .expect_err("finish must fail");
        assert!(error.to_string().contains("hash mismatch"), "{error}");
        // Spool removed even on a failed finish.
        assert!(!spool_path(&state).exists(), "failed finish must still remove the spool file");
        // Nothing was committed — status is unknown (no durable object operation).
        let status = dispatch(
            &mut state,
            "object.put.status",
            serde_json::json!({ "object_id": OBJECT_ID, "operation_id": OPERATION }),
        )
        .await
        .expect("status");
        assert_eq!(status["state"], "unknown");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn oversize_chunk_payload_fails_closed() {
        let root = temp_data_root("bigchunk");
        let mut state = make_state(root.clone());
        let total = MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 4096;
        dispatch(
            &mut state,
            "object.put.begin",
            begin_body(total, &plaintext_hash(&vec![0; total])),
        )
        .await
        .expect("begin");
        // A single chunk larger than the payload bound must fail closed (rf clamps; daemon defends).
        let oversized = vec![0x55_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 1];
        let error = dispatch(&mut state, "object.put.chunk", chunk_body(0, &oversized))
            .await
            .expect_err("oversize chunk must fail");
        assert!(error.to_string().contains("exceeds the"), "{error}");
        assert!(!spool_path(&state).exists());
        std::fs::remove_dir_all(&root).ok();
    }
}
