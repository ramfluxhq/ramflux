// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

// T25-A3 (CTRL-102 / OBJ-IPC-01): the bounded UPLOAD spool wiring.
use std::io::Write as _;

use crate::bus::daemon::local_bus_accounts_dir;
use crate::bus::io::{
    MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES, MAX_LOCAL_BUS_OBJECT_BYTES,
    MAX_LOCAL_BUS_ONE_SHOT_OBJECT_BYTES,
};
use crate::bus::protocol::{
    LocalBusObjectGetBeginRequest, LocalBusObjectGetFinishRequest, LocalBusObjectGetReadRequest,
    LocalBusObjectGetStatusRequest, LocalBusObjectPutBeginRequest, LocalBusObjectPutChunkRequest,
    LocalBusObjectPutFinishRequest,
};
use crate::bus::state::{ObjectGetSpoolSession, ObjectPutSpoolSession};

pub(crate) fn hydrate_local_object_state(
    account: &mut LocalBusAccountState,
) -> Result<(), SdkError> {
    account.client.hydrate_object_store_from_account_db()
}

/// T25-A5 (OBJ-IPC-01): rehydrate durable-journaled in-flight UPLOAD spools for one account on daemon
/// startup (this REPLACES the old blanket sweep of the upload spool dir). For each `(spool, journal)`
/// pair under the account's subdir it decides — fail-closed on any doubt — whether to RESUME the
/// chunk-phase upload or delete both files:
///   * unreadable/corrupt journal, TTL-expired (> 24h), or an identity mismatch -> delete both.
///   * the A2 record for `operation_id` is terminal (`committed`/`local_committed`) or `pending`
///     -> the object is already durably owned by A2 (never resume/re-commit) -> delete both.
///   * the A2 record is ABSENT (crash was in the chunk phase) -> a resume candidate: verify the spool
///     exists, `spool_size >= journal.written`, and the CONTENT `BLAKE3(spool[0..written])` equals
///     `journal.prefix_hash` (rfcc HARD CONSTRAINT — content, not just length); on success truncate
///     the spool to `written`, reopen an append handle, rebuild the incremental hasher, and reinstall
///     the session. Any verification failure deletes both files (fail closed).
pub(crate) fn rehydrate_object_put_spools(
    account: &mut LocalBusAccountState,
    data_root: &Path,
    account_id: &str,
) -> Result<(), SdkError> {
    let account_dir = object_put_account_dir(data_root, account_id);
    let entries = match std::fs::read_dir(&account_dir) {
        Ok(entries) => entries,
        // No per-account spool dir -> nothing durable to rehydrate.
        Err(_error) => return Ok(()),
    };
    for entry in entries {
        let entry = entry?;
        let journal_path = entry.path();
        if journal_path.extension().and_then(std::ffi::OsStr::to_str) != Some("journal") {
            continue;
        }
        let spool_path = journal_path.with_extension("spool");
        rehydrate_one_object_put_spool(account, account_id, &spool_path, &journal_path);
    }
    Ok(())
}

/// Deletes a spool + journal pair (fail-closed cleanup used throughout rehydrate).
fn discard_object_put_files(spool_path: &Path, journal_path: &Path) {
    let _ = std::fs::remove_file(spool_path);
    let _ = std::fs::remove_file(journal_path);
}

/// Returns true when either file's mtime is older than the abandoned-spool TTL (bounded disk).
fn object_put_pair_expired(spool_path: &Path, journal_path: &Path) -> bool {
    let older_than_ttl = |path: &Path| -> bool {
        std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|elapsed| elapsed.as_secs() > OBJECT_PUT_JOURNAL_TTL_SECONDS)
    };
    older_than_ttl(journal_path) || older_than_ttl(spool_path)
}

/// Streams the persisted spool prefix `spool[0..written]` through a fresh prefix hasher, returning the
/// rebuilt hasher (to continue the incremental chain) and its finalize (for content verification).
fn rebuild_object_put_prefix_hasher(
    spool_path: &Path,
    written: usize,
) -> Result<(ramflux_crypto::Blake3DomainHasher, String), SdkError> {
    let mut file = std::fs::File::open(spool_path)?;
    let mut hasher = ramflux_crypto::Blake3DomainHasher::new(OBJECT_PUT_JOURNAL_PREFIX_DOMAIN);
    let mut remaining = written;
    let mut buffer = vec![0_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        std::io::Read::read_exact(&mut file, &mut buffer[..take])?;
        hasher.update(&buffer[..take]);
        remaining -= take;
    }
    let digest = hasher.finalize_base64url();
    Ok((hasher, digest))
}

/// Truncates the spool to the durable `written` length and returns a fresh append handle so resumed
/// chunks land exactly at the verified frontier.
fn reopen_object_put_append_handle(
    spool_path: &Path,
    written: usize,
) -> Result<std::fs::File, SdkError> {
    let truncator = std::fs::OpenOptions::new().write(true).open(spool_path)?;
    truncator.set_len(written as u64)?;
    truncator.sync_all()?;
    drop(truncator);
    let append = std::fs::OpenOptions::new().append(true).open(spool_path)?;
    Ok(append)
}

/// Rehydrates (or fail-closed deletes) a single spool/journal pair. Errors are treated as fail-closed:
/// the pair is deleted and no session is installed.
fn rehydrate_one_object_put_spool(
    account: &mut LocalBusAccountState,
    account_id: &str,
    spool_path: &Path,
    journal_path: &Path,
) {
    // Parse the journal; missing/corrupt -> fail closed.
    let journal: ObjectPutJournal = match std::fs::read(journal_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(journal) => journal,
        None => return discard_object_put_files(spool_path, journal_path),
    };
    // TTL: abandoned pair -> delete (bounded disk).
    if object_put_pair_expired(spool_path, journal_path) {
        return discard_object_put_files(spool_path, journal_path);
    }
    // Identity sanity.
    if journal.account_id != account_id
        || journal.operation_id.is_empty()
        || journal.object_id.is_empty()
        || journal.total_len > MAX_LOCAL_BUS_OBJECT_BYTES
        || journal.written > journal.total_len
    {
        return discard_object_put_files(spool_path, journal_path);
    }
    // No-double-commit interlock: consult the A2 record FIRST. A terminal (committed/local_committed)
    // or pending record means A2 already owns the object — never resume, never re-commit.
    match account.client.object_operation(&journal.object_id) {
        Ok(Some(record)) if record.operation_id == journal.operation_id => {
            // committed | local_committed | pending | failed | anything -> A2 owns it, drop the spool.
            return discard_object_put_files(spool_path, journal_path);
        }
        Ok(_) => {}
        // DB error: fail closed (do not resume against an unknown durable state).
        Err(_error) => return discard_object_put_files(spool_path, journal_path),
    }
    // Resume candidate: verify the spool exists and is at least as long as the durable offset.
    let spool_size = match std::fs::metadata(spool_path) {
        Ok(meta) => usize::try_from(meta.len()).unwrap_or(usize::MAX),
        Err(_error) => return discard_object_put_files(spool_path, journal_path),
    };
    if spool_size < journal.written {
        return discard_object_put_files(spool_path, journal_path);
    }
    // CONTENT verification (rfcc HARD CONSTRAINT): BLAKE3(spool[0..written]) must equal prefix_hash.
    let (prefix_hasher, digest) =
        match rebuild_object_put_prefix_hasher(spool_path, journal.written) {
            Ok(pair) => pair,
            Err(_error) => return discard_object_put_files(spool_path, journal_path),
        };
    if digest != journal.prefix_hash {
        return discard_object_put_files(spool_path, journal_path);
    }
    // Truncate to the verified frontier and reopen an append handle.
    let file = match reopen_object_put_append_handle(spool_path, journal.written) {
        Ok(file) => file,
        Err(_error) => return discard_object_put_files(spool_path, journal_path),
    };
    account.object_put_spools.insert(
        journal.operation_id.clone(),
        ObjectPutSpoolSession {
            account_id: account_id.to_owned(),
            operation_id: journal.operation_id,
            object_id: journal.object_id,
            total_len: journal.total_len,
            plaintext_hash: journal.plaintext_hash,
            chunk_size: journal.chunk_size,
            relay_endpoint: journal.relay_endpoint,
            relay_service_key_base64: journal.relay_service_key_base64,
            relay_interrupt_after_chunks: journal.relay_interrupt_after_chunks,
            path: spool_path.to_path_buf(),
            journal_path: journal_path.to_path_buf(),
            file,
            written: journal.written,
            prefix_hasher,
        },
    );
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
        // T25-A5: the spool session now carries an incremental hasher, so its finish future is boxed
        // to keep the dispatch future small.
        "object.put.finish" => Box::pin(object_put_finish(account, request)).await,
        "object.get.begin" => object_get_begin(&data_root, account_id, account, request).await,
        "object.get.read" => object_get_read(account, request),
        "object.get.finish" => {
            let body: LocalBusObjectGetFinishRequest =
                serde_json::from_value(request.body.clone())?;
            let removed = object_get_spool_discard(account, &body.operation_id);
            Ok(local_bus_ok(serde_json::json!({
                "operation_id": body.operation_id,
                "removed": removed,
            })))
        }
        "object.get.status" => object_get_status(account, request),
        "object.put.status" => {
            // T25-A2 (OBJ-IPC-01): read-only reconciliation status for a logical PUT.
            // T25-A5 (OBJ-IPC-01): ALSO reports a chunk-phase `resumable` state + `resume_offset` (the
            // live/rehydrated spool session's durable `written`), so a CLI whose mid-upload transport
            // failed can resume from the durable offset instead of re-uploading from zero.
            let body: LocalBusObjectPutStatusRequest =
                serde_json::from_value(request.body.clone())?;
            let record = account.client.object_operation(&body.object_id)?;
            let session_written =
                account.object_put_spools.get(&body.operation_id).map(|session| session.written);
            let (state, terminal, resume_offset) = match record {
                Some(record) if record.operation_id == body.operation_id => {
                    match record.state.as_str() {
                        OBJECT_OPERATION_COMMITTED => {
                            (OBJECT_OPERATION_COMMITTED.to_owned(), record.terminal_result, None)
                        }
                        OBJECT_OPERATION_FAILED => (OBJECT_OPERATION_FAILED.to_owned(), None, None),
                        // pending / local_committed: the finish/commit phase. Keep the raw state so the
                        // A2 finish reconcile is unchanged; expose an offset only if a session survives.
                        _ => (record.state, None, session_written),
                    }
                }
                // No matching durable record: a live/rehydrated chunk-phase spool is `resumable`.
                _ => match session_written {
                    Some(written) => (OBJECT_PUT_STATE_RESUMABLE.to_owned(), None, Some(written)),
                    None => (OBJECT_OPERATION_UNKNOWN.to_owned(), None, None),
                },
            };
            let mut response = serde_json::json!({
                "object_id": body.object_id,
                "operation_id": body.operation_id,
                "state": state,
                "terminal": terminal,
            });
            if let Some(offset) = resume_offset
                && let Some(map) = response.as_object_mut()
            {
                map.insert("resume_offset".to_owned(), serde_json::json!(offset));
            }
            Ok(local_bus_ok(response))
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
            // T25-A4 (OBJ-IPC-01): the one-shot GET carries the whole plaintext in ONE response
            // frame, so it is only valid for a small object. Fail closed above the one-shot bound
            // BEFORE building an oversized (>1 MiB) response — an oversized frame would otherwise be
            // rejected on the write path AFTER this read-only decrypt, closing the connection with an
            // opaque transport error. The public `rf object get` never hits this: it always routes
            // through the bounded DOWNLOAD spool (begin/read/finish). This arm stays for small SDK
            // callers and is the one-shot path the pure tests exercise.
            if plaintext.len() > MAX_LOCAL_BUS_ONE_SHOT_OBJECT_BYTES {
                return Err(SdkError::LocalBus(format!(
                    "object too large for one-shot object.get: {} > {MAX_LOCAL_BUS_ONE_SHOT_OBJECT_BYTES}; use object.get.begin",
                    plaintext.len()
                )));
            }
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
/// under the daemon `data_root`. T25-A5: rehydrated per-account on startup (no longer blanket-swept).
pub(crate) fn object_put_spool_dir(data_root: &Path) -> PathBuf {
    local_bus_accounts_dir(data_root).join("object_put_spool")
}

/// T25-A5 (OBJ-IPC-01): `object.put.status` state for a live/rehydrated chunk-phase spool that has no
/// durable A2 record yet — the CLI resumes chunks from the reported `resume_offset`.
const OBJECT_PUT_STATE_RESUMABLE: &str = "resumable";
/// T25-A5 (OBJ-IPC-01): the BLAKE3 domain framing the durable-prefix journal hash. Distinct from the
/// object plaintext hash domain so the two never collide.
const OBJECT_PUT_JOURNAL_PREFIX_DOMAIN: &str = "ramflux.object_put_journal.prefix.v1";
/// T25-A5: abandoned (orphaned) spool/journal pairs older than this are swept on startup so disk stays
/// bounded even if a resume never arrives.
const OBJECT_PUT_JOURNAL_TTL_SECONDS: u64 = 24 * 60 * 60;

/// T25-A5 (OBJ-IPC-01): the standalone durable crash-resume journal sidecar for one in-flight upload.
/// Written atomically (temp + fsync + rename + parent-dir fsync) AFTER the spool bytes are fsync'd, so
/// `written` never exceeds the durable spool length. On restart the daemon verifies the persisted
/// prefix content (BLAKE3) matches `prefix_hash` before resuming.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ObjectPutJournal {
    account_id: String,
    operation_id: String,
    object_id: String,
    total_len: usize,
    plaintext_hash: String,
    chunk_size: usize,
    relay_endpoint: Option<String>,
    relay_service_key_base64: Option<String>,
    relay_interrupt_after_chunks: Option<u32>,
    written: usize,
    prefix_hash: String,
}

/// The per-account subdirectory that routes an account's upload spools without a cross-account scan.
/// `account_hash` = base64url BLAKE3 of a stable domain + `account_id` (filename-safe, no leak).
fn object_put_account_dir(data_root: &Path, account_id: &str) -> PathBuf {
    let account_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_put_spool.account.v1",
        account_id.as_bytes(),
    );
    object_put_spool_dir(data_root).join(account_hash)
}

/// The deterministic, filename-safe `<op_hash>` for one `(account_id, operation_id)`. base64url is
/// filename-safe (no `/`), and the hash avoids leaking the object/account ids into the filename.
fn object_put_op_hash(account_id: &str, operation_id: &str) -> String {
    ramflux_crypto::blake3_256_base64url(
        "ramflux.object_put_spool.v1",
        format!("{account_id}\u{0}{operation_id}").as_bytes(),
    )
}

/// The spool file path `object_put_spool/<account_hash>/<op_hash>.spool`.
fn object_put_spool_path(data_root: &Path, account_id: &str, operation_id: &str) -> PathBuf {
    object_put_account_dir(data_root, account_id)
        .join(format!("{}.spool", object_put_op_hash(account_id, operation_id)))
}

/// The journal sidecar path `object_put_spool/<account_hash>/<op_hash>.journal`.
fn object_put_journal_path(data_root: &Path, account_id: &str, operation_id: &str) -> PathBuf {
    object_put_account_dir(data_root, account_id)
        .join(format!("{}.journal", object_put_op_hash(account_id, operation_id)))
}

/// T25-A5 (OBJ-IPC-01) rfcc HARD CONSTRAINT: every journal write is temp + `sync_all` + rename +
/// parent-dir `sync_all`, NEVER an in-place rewrite. This makes the durable-offset record atomic and
/// crash-safe: a torn write leaves the prior journal intact, and the rename itself is durable.
fn write_object_put_journal_atomic(
    journal_path: &Path,
    journal: &ObjectPutJournal,
) -> Result<(), SdkError> {
    let parent = journal_path
        .parent()
        .ok_or_else(|| SdkError::LocalBus("object put journal path has no parent".to_owned()))?;
    std::fs::create_dir_all(parent)?;
    set_owner_only_dir_permissions(parent)?;
    let tmp_path = journal_path.with_extension("journal.tmp");
    let bytes = serde_json::to_vec(journal)?;
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut tmp = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        tmp.write_all(&bytes)?;
        tmp.sync_all()?;
    }
    set_owner_only_file_permissions(&tmp_path)?;
    std::fs::rename(&tmp_path, journal_path)?;
    // fsync the PARENT DIR so the rename that publishes the new journal is itself durable.
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()?;
    Ok(())
}

/// Removes an in-flight spool session (dropping its file handle) AND both its on-disk files (spool +
/// journal). Idempotent — a no-op for an unknown `operation_id`. This is the single fail-closed
/// cleanup used on begin re-entry, any chunk error, and every finish (success or failure).
fn object_put_spool_discard(account: &mut LocalBusAccountState, operation_id: &str) {
    if let Some(session) = account.object_put_spools.remove(operation_id) {
        let path = session.path.clone();
        let journal_path = session.journal_path.clone();
        drop(session);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&journal_path);
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
    let journal_path = object_put_journal_path(data_root, account_id, &body.operation_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        set_owner_only_dir_permissions(parent)?;
    }
    // Sweep any cross-restart orphan at these deterministic paths, then create_new (O_EXCL): never
    // reuse a pre-existing file and never follow a symlink into an attacker-chosen target.
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&journal_path);
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    set_owner_only_file_permissions(&path)?;
    // T25-A5 (OBJ-IPC-01): the incremental prefix hasher over the durably-written spool bytes. Its
    // finalize (of the empty prefix) is bound into the initial journal so a resumed session's
    // identity is durably established BEFORE the first chunk is accepted.
    let prefix_hasher = ramflux_crypto::Blake3DomainHasher::new(OBJECT_PUT_JOURNAL_PREFIX_DOMAIN);
    let initial_journal = ObjectPutJournal {
        account_id: account_id.to_owned(),
        operation_id: body.operation_id.clone(),
        object_id: body.object_id.clone(),
        total_len: body.total_len,
        plaintext_hash: body.plaintext_hash.clone(),
        chunk_size: body.chunk_size,
        relay_endpoint: body.relay_endpoint.clone(),
        relay_service_key_base64: body.relay_service_key_base64.clone(),
        relay_interrupt_after_chunks: body.relay_interrupt_after_chunks,
        written: 0,
        prefix_hash: prefix_hasher.finalize_base64url(),
    };
    if let Err(error) = write_object_put_journal_atomic(&journal_path, &initial_journal) {
        // Fail closed: the initial journal must be durable before any chunk is accepted.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&journal_path);
        return Err(error);
    }
    account.object_put_spools.insert(
        body.operation_id.clone(),
        ObjectPutSpoolSession {
            account_id: account_id.to_owned(),
            operation_id: body.operation_id.clone(),
            object_id: body.object_id,
            total_len: body.total_len,
            plaintext_hash: body.plaintext_hash,
            chunk_size: body.chunk_size,
            relay_endpoint: body.relay_endpoint,
            relay_service_key_base64: body.relay_service_key_base64,
            relay_interrupt_after_chunks: body.relay_interrupt_after_chunks,
            path,
            journal_path,
            file,
            written: 0,
            prefix_hasher,
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
    // T25-A5 (OBJ-IPC-01) rfcc HARD CONSTRAINT — the crash-safe ack ordering:
    //   a) write the chunk bytes
    session.file.write_all(data)?;
    //   b) durably fsync the spool bytes (data + size) — durable spool BEFORE the durable offset.
    session.file.sync_data()?;
    //   c) advance the incremental prefix hasher and finalize the new durable-prefix hash.
    session.prefix_hasher.update(data);
    let prefix_hash = session.prefix_hasher.finalize_base64url();
    //   d) atomically persist the durable offset {written=end, prefix_hash} AFTER the spool fsync, so
    //      the INVARIANT journal.written <= durable spool bytes holds by construction. Any error here
    //      propagates as Err and the caller (`object_put_chunk`) destroys the spool + journal.
    let journal = ObjectPutJournal {
        account_id: session.account_id.clone(),
        operation_id: session.operation_id.clone(),
        object_id: session.object_id.clone(),
        total_len: session.total_len,
        plaintext_hash: session.plaintext_hash.clone(),
        chunk_size: session.chunk_size,
        relay_endpoint: session.relay_endpoint.clone(),
        relay_service_key_base64: session.relay_service_key_base64.clone(),
        relay_interrupt_after_chunks: session.relay_interrupt_after_chunks,
        written: end,
        prefix_hash,
    };
    write_object_put_journal_atomic(&session.journal_path, &journal)?;
    // T25-A5 test-only seam: crash HERE — after the durable spool fsync + durable journal fsync but
    // BEFORE the ack (the d->e boundary). Compiled only under `object-ipc-crash-seam`; marker=0 in
    // production. A restart then resumes from the durable journal offset.
    #[cfg(feature = "object-ipc-crash-seam")]
    crate::itest_crash_seam::maybe_abort_upload_before_ack(end);
    //   e) only now advance the in-memory frontier and return the ack.
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
    let journal_path = session.journal_path.clone();
    let result = object_put_finish_inner(account, &body, &mut session).await;
    drop(session); // close the file handle before removing the files
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&journal_path);
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

// ---- T25-A4 (CTRL-104 / OBJ-IPC-01): bounded local-bus DOWNLOAD spool (begin / read / finish) ----

/// The private, account-scoped, owner-only (0700) directory that holds in-flight DOWNLOAD spool
/// files under the daemon `data_root`. Swept on daemon startup (orphans from a prior crash).
pub(crate) fn object_get_spool_dir(data_root: &Path) -> PathBuf {
    local_bus_accounts_dir(data_root).join("object_get_spool")
}

/// The deterministic, filename-safe spool path for one `(account_id, operation_id)`. Mirrors the
/// UPLOAD spool: base64url is filename-safe and the hash avoids leaking the object/account ids.
fn object_get_spool_path(data_root: &Path, account_id: &str, operation_id: &str) -> PathBuf {
    let name = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_get_spool.v1",
        format!("{account_id}\u{0}{operation_id}").as_bytes(),
    );
    object_get_spool_dir(data_root).join(format!("{name}.spool"))
}

/// Removes an in-flight DOWNLOAD spool session (dropping its file handle) AND its on-disk file.
/// Idempotent — returns `false` for an unknown `operation_id`. This is the single fail-closed cleanup
/// used on begin re-entry, any begin error, and every finish.
fn object_get_spool_discard(account: &mut LocalBusAccountState, operation_id: &str) -> bool {
    if let Some(session) = account.object_get_spools.remove(operation_id) {
        let path = session.path.clone();
        drop(session);
        let _ = std::fs::remove_file(&path);
        true
    } else {
        false
    }
}

/// `object.get.begin`: decrypt the whole object (relay download when a relay endpoint is present,
/// else a local `decrypt_object`), verify size <= 16 MiB, spool the plaintext to a private
/// (`create_new`, 0600) file, and return a COMPACT response — never the plaintext. Any failure
/// removes the (possibly partial) spool so no partial download is ever presented.
async fn object_get_begin(
    data_root: &Path,
    account_id: &str,
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectGetBeginRequest = serde_json::from_value(request.body.clone())?;
    if body.protocol_version != OBJECT_PUT_PROTOCOL_VERSION {
        return Err(SdkError::LocalBus(format!(
            "object.get.begin unsupported protocol_version {} (expected {OBJECT_PUT_PROTOCOL_VERSION})",
            body.protocol_version
        )));
    }
    // Idempotent re-begin (a retry/restart with the same operation_id): drop any prior in-flight
    // session + file so we always start from a clean, freshly decrypted spool.
    object_get_spool_discard(account, &body.operation_id);

    let relay_options = parse_relay_transfer_options(
        body.relay_endpoint.clone(),
        body.relay_service_key_base64.clone(),
        body.relay_interrupt_after_chunks,
    )?;
    // A4 accepts an O(16 MiB) resident plaintext at the decrypt boundary (A5 will optimize); the
    // whole-object AEAD / relay wire is UNCHANGED — this is the same decrypt the one-shot GET used.
    let plaintext = if let Some(options) = relay_options.as_ref() {
        dispatch_object_download_from_relay(account, &body.object_id, options, body.relay_ack)
            .await?
    } else {
        account.client.decrypt_object(&body.object_id)?
    };
    if plaintext.len() > MAX_LOCAL_BUS_OBJECT_BYTES {
        return Err(SdkError::LocalBus(format!(
            "object too large for local-bus download: {} > {MAX_LOCAL_BUS_OBJECT_BYTES}",
            plaintext.len()
        )));
    }
    let total_len = plaintext.len();
    let plaintext_hash =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);

    let path = object_get_spool_path(data_root, account_id, &body.operation_id);
    let result = object_get_spool_write(&path, &plaintext);
    // Zeroize-friendly: drop the resident plaintext as soon as it is spooled (never echoed).
    drop(plaintext);
    let file = match result {
        Ok(file) => file,
        Err(error) => {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
    };

    // T25-A5 test-only seam: crash HERE — after the download spool is written + fsynced but BEFORE any
    // read is served (so the streaming client can never verify-then-rename a partial into place).
    // Compiled only under `object-ipc-crash-seam`; marker=0 in production. A restart re-begins the
    // download from offset 0.
    #[cfg(feature = "object-ipc-crash-seam")]
    crate::itest_crash_seam::maybe_abort_download_after_write();

    account.object_get_spools.insert(
        body.operation_id.clone(),
        ObjectGetSpoolSession {
            object_id: body.object_id.clone(),
            total_len,
            plaintext_hash: plaintext_hash.clone(),
            path,
            file,
            read_offset: 0,
        },
    );
    Ok(local_bus_ok(serde_json::json!({
        "operation_id": body.operation_id,
        "object_id": body.object_id,
        "total_len": total_len,
        "plaintext_hash": plaintext_hash,
    })))
}

/// Writes the spooled plaintext to a fresh private file (`create_new`/`O_EXCL`, 0600), fsync'd, and
/// returns a read handle positioned at the start. Sweeps any cross-restart orphan first and never
/// follows a symlink into an attacker-chosen target.
fn object_get_spool_write(path: &Path, plaintext: &[u8]) -> Result<std::fs::File, SdkError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        set_owner_only_dir_permissions(parent)?;
    }
    let _ = std::fs::remove_file(path);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    set_owner_only_file_permissions(path)?;
    file.write_all(plaintext)?;
    file.flush()?;
    // Durably fsync the whole spooled plaintext before any read is served (a crash cannot present a
    // truncated download as complete — the streamed hash is verified client-side regardless).
    file.sync_all()?;
    drop(file);
    // Reopen read-only, positioned at the start, for the sequential read path.
    let read = std::fs::OpenOptions::new().read(true).open(path)?;
    Ok(read)
}

/// `object.get.read`: serve one bounded slice `[offset, offset + len)` of the spooled plaintext as
/// base64. Fails closed on an oversize `len`, a forward gap / overlap / duplicate offset, or an
/// out-of-range end. The response frame stays < 1 MiB (same compile-time proof as `object.put.chunk`).
fn object_get_read(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectGetReadRequest = serde_json::from_value(request.body.clone())?;
    let session = account.object_get_spools.get_mut(&body.operation_id).ok_or_else(|| {
        SdkError::LocalBus(format!(
            "object.get.read: unknown or closed download session {}",
            body.operation_id
        ))
    })?;
    if body.len > MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES {
        return Err(SdkError::LocalBus(format!(
            "object.get.read len {} exceeds the {MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES}-byte bound",
            body.len
        )));
    }
    if body.offset != session.read_offset {
        // The only accepted offset is exactly the sequential frontier: a forward gap, an overlap, or
        // a duplicate all fail closed (a dropped-read reconcile RESTARTS via object.get.begin).
        return Err(SdkError::LocalBus(format!(
            "object.get.read offset {} != expected {} (gap/overlap/duplicate)",
            body.offset, session.read_offset
        )));
    }
    let end = body
        .offset
        .checked_add(body.len)
        .ok_or_else(|| SdkError::LocalBus("object.get.read offset overflow".to_owned()))?;
    if end > session.total_len {
        return Err(SdkError::LocalBus(format!(
            "object.get.read exceeds total_len: {end} > {}",
            session.total_len
        )));
    }
    let mut buffer = vec![0_u8; body.len];
    std::io::Seek::seek(&mut session.file, std::io::SeekFrom::Start(body.offset as u64))?;
    std::io::Read::read_exact(&mut session.file, &mut buffer)?;
    session.read_offset = end;
    let eof = end == session.total_len;
    let response = serde_json::json!({
        "operation_id": body.operation_id,
        "offset": body.offset,
        "len": body.len,
        "eof": eof,
        "data_base64": ramflux_protocol::encode_base64url(&buffer),
    });
    Ok(local_bus_ok(response))
}

/// `object.get.status`: read-only reconciliation for a DOWNLOAD spool. Reports `reading` / `complete`
/// / `unknown` plus `total_len`, `read_offset`, and `plaintext_hash` when a session exists.
fn object_get_status(
    account: &LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectGetStatusRequest = serde_json::from_value(request.body.clone())?;
    let response = match account.object_get_spools.get(&body.operation_id) {
        Some(session) => {
            let state =
                if session.read_offset == session.total_len { "complete" } else { "reading" };
            serde_json::json!({
                "operation_id": body.operation_id,
                "object_id": session.object_id,
                "state": state,
                "total_len": session.total_len,
                "read_offset": session.read_offset,
                "plaintext_hash": session.plaintext_hash,
            })
        }
        None => serde_json::json!({
            "operation_id": body.operation_id,
            "state": OBJECT_OPERATION_UNKNOWN,
        }),
    };
    Ok(local_bus_ok(response))
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

    // ---- T25-A5 (OBJ-IPC-01): durable upload journal crash-resume rehydration ----

    #[tokio::test]
    async fn rehydrate_resumes_a_chunk_phase_spool_after_restart() {
        let root = temp_data_root("rehydrate_resume");
        let mut state = make_state(root.clone());
        let plaintext = vec![0xB3_u8; 4096];
        let hash = plaintext_hash(&plaintext);
        dispatch(&mut state, "object.put.begin", begin_body(plaintext.len(), &hash))
            .await
            .expect("begin");
        // Stream only the first half, then simulate an rfd crash mid-upload.
        dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext[..2048]))
            .await
            .expect("chunk 0");
        // "Crash": drop the in-memory session but keep the durable spool + journal on disk.
        state.accounts.get_mut(ACCOUNT).expect("account").object_put_spools.clear();
        // Restart: rehydrate from the durable journal; the resume offset is journal.written.
        {
            let data_root = state.config.data_root.clone();
            let account = state.accounts.get_mut(ACCOUNT).expect("account");
            rehydrate_object_put_spools(account, &data_root, ACCOUNT).expect("rehydrate");
            let session = account.object_put_spools.get(OPERATION).expect("rehydrated session");
            assert_eq!(session.written, 2048, "resume offset = durable journal.written");
        }
        // Resume the remaining half from the durable offset, then finish -> commits byte-identical.
        dispatch(&mut state, "object.put.chunk", chunk_body(2048, &plaintext[2048..]))
            .await
            .expect("resume chunk");
        let terminal =
            dispatch(&mut state, "object.put.finish", finish_body()).await.expect("finish");
        assert_eq!(terminal["committed"], true, "resumed upload commits: {terminal}");
        assert_eq!(terminal["plaintext_hash"], serde_json::Value::String(hash));
        assert!(!spool_path(&state).exists(), "finish removes the spool");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn rehydrate_fails_closed_on_prefix_hash_mismatch() {
        use std::io::{Seek as _, SeekFrom, Write as _};
        let root = temp_data_root("rehydrate_mismatch");
        let mut state = make_state(root.clone());
        let plaintext = vec![0xC4_u8; 4096];
        let hash = plaintext_hash(&plaintext);
        dispatch(&mut state, "object.put.begin", begin_body(plaintext.len(), &hash))
            .await
            .expect("begin");
        dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext[..2048]))
            .await
            .expect("chunk 0");
        let spool = spool_path(&state);
        let journal = object_put_journal_path(&state.config.data_root, ACCOUNT, OPERATION);
        state.accounts.get_mut(ACCOUNT).expect("account").object_put_spools.clear();
        // Tamper the durable spool prefix so BLAKE3(spool[0..written]) != journal.prefix_hash.
        {
            let mut file =
                std::fs::OpenOptions::new().write(true).open(&spool).expect("open spool");
            file.seek(SeekFrom::Start(0)).expect("seek");
            file.write_all(&[0x00_u8; 16]).expect("tamper");
            file.sync_all().expect("sync");
        }
        {
            let data_root = state.config.data_root.clone();
            let account = state.accounts.get_mut(ACCOUNT).expect("account");
            rehydrate_object_put_spools(account, &data_root, ACCOUNT).expect("rehydrate");
            assert!(account.object_put_spools.is_empty(), "a tampered prefix must not resume");
        }
        assert!(!spool.exists(), "fail-closed deletes the tampered spool");
        assert!(!journal.exists(), "fail-closed deletes the journal");
        std::fs::remove_dir_all(&root).ok();
    }

    // ---- T25-A4 (CTRL-104 / OBJ-IPC-01): bounded DOWNLOAD spool (begin/read/finish) ----

    const GET_OPERATION: &str = "op-get-1";
    const GET_OBJECT_ID: &str = "object_get_1";

    fn get_spool_path(state: &LocalBusDaemonState) -> PathBuf {
        object_get_spool_path(&state.config.data_root, ACCOUNT, GET_OPERATION)
    }

    fn get_begin_body(object_id: &str) -> serde_json::Value {
        serde_json::to_value(LocalBusObjectGetBeginRequest {
            object_id: object_id.to_owned(),
            operation_id: GET_OPERATION.to_owned(),
            protocol_version: OBJECT_PUT_PROTOCOL_VERSION,
            relay_endpoint: None,
            relay_service_key_base64: None,
            relay_ack: false,
            relay_interrupt_after_chunks: None,
        })
        .expect("get begin body")
    }

    fn get_read_body(offset: usize, len: usize) -> serde_json::Value {
        serde_json::to_value(LocalBusObjectGetReadRequest {
            operation_id: GET_OPERATION.to_owned(),
            offset,
            len,
        })
        .expect("get read body")
    }

    /// Commits a local object (no relay) so a subsequent GET can decrypt it.
    async fn put_local_object(state: &mut LocalBusDaemonState, object_id: &str, plaintext: &[u8]) {
        dispatch(
            state,
            "object.put",
            serde_json::json!({
                "object_id": object_id,
                "plaintext_base64": ramflux_protocol::encode_base64url(plaintext),
                "chunk_size": 65_536,
            }),
        )
        .await
        .expect("put local object");
    }

    #[tokio::test]
    async fn get_begin_read_finish_streams_bounded_and_cleans_up() {
        let root = temp_data_root("get_happy");
        let mut state = make_state(root.clone());
        // 3 * 512 KiB + a partial tail: forces multiple bounded reads and a final short read.
        let plaintext = vec![0xC7_u8; 3 * MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 4096];
        let hash = plaintext_hash(&plaintext);
        put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;

        let begin = dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID))
            .await
            .expect("get begin");
        // Compact begin response — NO plaintext echo.
        assert_eq!(begin["operation_id"], GET_OPERATION);
        assert_eq!(begin["object_id"], GET_OBJECT_ID);
        assert_eq!(begin["total_len"], plaintext.len());
        assert_eq!(begin["plaintext_hash"], serde_json::Value::String(hash.clone()));
        assert!(begin.get("plaintext_base64").is_none(), "begin must not echo plaintext");
        assert!(begin.get("data_base64").is_none(), "begin must not echo data");
        assert!(get_spool_path(&state).exists(), "begin must create the spool file");

        // Stream bounded reads until eof; reassemble and compare.
        let mut reassembled = Vec::new();
        let mut offset = 0;
        loop {
            let len = (plaintext.len() - offset).min(MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES);
            let read = dispatch(&mut state, "object.get.read", get_read_body(offset, len))
                .await
                .expect("get read");
            assert_eq!(read["offset"], offset);
            assert_eq!(read["len"], len);
            let data = ramflux_protocol::decode_base64url(
                read["data_base64"].as_str().expect("data_base64"),
            )
            .expect("decode");
            assert_eq!(data.len(), len);
            reassembled.extend_from_slice(&data);
            offset += len;
            if read["eof"].as_bool().unwrap_or(false) {
                assert_eq!(offset, plaintext.len(), "eof only at total_len");
                break;
            }
        }
        assert_eq!(reassembled, plaintext, "streamed plaintext must match byte-for-byte");
        assert_eq!(plaintext_hash(&reassembled), hash, "streamed hash must match begin");

        // Status reports complete before finish.
        let status = dispatch(
            &mut state,
            "object.get.status",
            serde_json::json!({ "operation_id": GET_OPERATION }),
        )
        .await
        .expect("status");
        assert_eq!(status["state"], "complete");
        assert_eq!(status["read_offset"], plaintext.len());

        // Finish removes the spool.
        let finish = dispatch(
            &mut state,
            "object.get.finish",
            serde_json::json!({ "operation_id": GET_OPERATION }),
        )
        .await
        .expect("finish");
        assert_eq!(finish["removed"], true);
        assert!(!get_spool_path(&state).exists(), "finish must remove the spool file");
        // Status after finish is unknown.
        let status = dispatch(
            &mut state,
            "object.get.status",
            serde_json::json!({ "operation_id": GET_OPERATION }),
        )
        .await
        .expect("status");
        assert_eq!(status["state"], "unknown");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn get_read_frame_stays_below_cap_for_a_maximal_read() {
        let root = temp_data_root("get_framecap");
        let mut state = make_state(root.clone());
        let plaintext = vec![0x5A_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES];
        put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
        dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID))
            .await
            .expect("begin");
        // A maximal read (512 KiB raw). Serialize the full response frame and prove it is < 1 MiB.
        let read = dispatch(
            &mut state,
            "object.get.read",
            get_read_body(0, MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES),
        )
        .await
        .expect("read");
        let frame = crate::bus::protocol::LocalBusFrame::request(
            "req",
            Some(ACCOUNT.to_owned()),
            "object",
            "object.get.read",
            read,
        );
        let bytes = ramflux_protocol::canonical_json_bytes(&frame).expect("frame bytes");
        assert!(
            bytes.len() < crate::bus::io::MAX_LOCAL_BUS_FRAME_BYTES,
            "a maximal object.get.read frame {} must stay below the 1 MiB cap",
            bytes.len()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn get_read_gap_overlap_and_out_of_range_fail_closed() {
        let root = temp_data_root("get_faults");
        let mut state = make_state(root.clone());
        let plaintext = vec![0x33_u8; 4096];
        put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
        dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID))
            .await
            .expect("begin");
        // Forward gap: offset 1 with nothing served yet (expected 0).
        let gap = dispatch(&mut state, "object.get.read", get_read_body(1, 1024))
            .await
            .expect_err("gap must fail");
        assert!(gap.to_string().contains("gap/overlap/duplicate"), "{gap}");
        // Serve the first slice, then re-read offset 0 (overlap/duplicate) — expected is now 1024.
        dispatch(&mut state, "object.get.read", get_read_body(0, 1024)).await.expect("first read");
        let dup = dispatch(&mut state, "object.get.read", get_read_body(0, 1024))
            .await
            .expect_err("duplicate must fail");
        assert!(dup.to_string().contains("gap/overlap/duplicate"), "{dup}");
        // Out of range: from the current frontier (1024), a read that runs past total_len.
        let oor = dispatch(&mut state, "object.get.read", get_read_body(1024, 4096))
            .await
            .expect_err("out of range must fail");
        assert!(oor.to_string().contains("exceeds total_len"), "{oor}");
        // The session survives fail-closed reads (they do not corrupt the spool).
        assert!(get_spool_path(&state).exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn get_read_oversize_len_fails_closed() {
        let root = temp_data_root("get_biglen");
        let mut state = make_state(root.clone());
        let plaintext = vec![0x44_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 8192];
        put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
        dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID))
            .await
            .expect("begin");
        let error = dispatch(
            &mut state,
            "object.get.read",
            get_read_body(0, MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 1),
        )
        .await
        .expect_err("oversize len must fail");
        assert!(error.to_string().contains("exceeds the"), "{error}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn get_begin_of_unknown_object_fails_and_leaves_no_spool() {
        let root = temp_data_root("get_missing");
        let mut state = make_state(root.clone());
        let error =
            dispatch(&mut state, "object.get.begin", get_begin_body("object_does_not_exist"))
                .await
                .expect_err("begin of a missing object must fail");
        assert!(!error.to_string().is_empty(), "{error}");
        assert!(!get_spool_path(&state).exists(), "a failed begin must leave no spool file");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn get_begin_reentry_restarts_from_a_clean_spool() {
        let root = temp_data_root("get_reentry");
        let mut state = make_state(root.clone());
        let plaintext = vec![0x77_u8; 2048];
        put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
        dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID))
            .await
            .expect("begin");
        // Advance the read frontier, then re-begin (a restart) — the session must reset to offset 0.
        dispatch(&mut state, "object.get.read", get_read_body(0, 1024)).await.expect("read");
        dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID))
            .await
            .expect("re-begin");
        let status = dispatch(
            &mut state,
            "object.get.status",
            serde_json::json!({ "operation_id": GET_OPERATION }),
        )
        .await
        .expect("status");
        assert_eq!(status["read_offset"], 0, "re-begin resets the read frontier");
        assert_eq!(status["state"], "reading");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn small_one_shot_get_still_returns_plaintext() {
        let root = temp_data_root("get_oneshot");
        let mut state = make_state(root.clone());
        let plaintext = vec![0x9E_u8; 4096];
        put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
        let response =
            dispatch(&mut state, "object.get", serde_json::json!({ "object_id": GET_OBJECT_ID }))
                .await
                .expect("one-shot get");
        let decoded = ramflux_protocol::decode_base64url(
            response["plaintext_base64"].as_str().expect("plaintext_base64"),
        )
        .expect("decode");
        assert_eq!(decoded, plaintext, "one-shot get must round-trip the small object");
        std::fs::remove_dir_all(&root).ok();
    }
}
