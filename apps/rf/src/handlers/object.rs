// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

#[allow(clippy::too_many_lines)]
pub(crate) async fn handle_object(socket: PathBuf, command: ObjectCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(&socket).await?;
    match command.action {
        ObjectAction::Put(put) => handle_object_put(&mut bus, socket.as_path(), put).await,
        ObjectAction::Get(get) => handle_object_get(socket.as_path(), get).await,
        ObjectAction::Status(status) => {
            let request = LocalBusObjectTransferStatusRequest {
                object_id: status.object,
                direction: status.direction,
            };
            print_json(
                &bus.request(Some(status.account), "object", "object.transfer.status", &request)
                    .await?,
            )
        }
        ObjectAction::Resume(resume) => {
            let request = LocalBusObjectTransferResumeRequest {
                object_id: resume.object,
                direction: resume.direction,
                relay_endpoint: Some(resume.relay_url),
                #[cfg(feature = "itest-local-mint")]
                relay_service_key_base64: resume.relay_service_key,
                #[cfg(not(feature = "itest-local-mint"))]
                relay_service_key_base64: None,
                relay_interrupt_after_chunks: resume.relay_interrupt_after_chunks,
            };
            print_json(
                &bus.request(Some(resume.account), "object", "object.transfer.resume", &request)
                    .await?,
            )
        }
        ObjectAction::Import(import) => {
            let package = serde_json::from_slice(&std::fs::read(&import.package)?)?;
            let request = LocalBusObjectImportRequest { package };
            print_json(
                &bus.request(Some(import.account), "object", "object.import", &request).await?,
            )
        }
        ObjectAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "object", "object.list", &serde_json::json!({}))
                .await?,
        ),
        ObjectAction::Share(share) => {
            let request = LocalBusObjectShareRequest {
                object_id: share.object,
                conversation_id: share.to,
                sender_id: share.sender,
                recipient_device_id: share.recipient_device,
                recipient_principal_commitment: share.recipient_principal_commitment,
                target_delivery_id: share.target,
            };
            let response =
                bus.request(Some(share.account), "object", "object.share", &request).await?;
            if let Some(out_package) = share.out_package {
                let package = response
                    .get("package")
                    .ok_or_else(|| RfError::Message("object.share missing package".to_owned()))?;
                std::fs::write(out_package, serde_json::to_vec_pretty(package)?)?;
            }
            print_json(&response)
        }
        ObjectAction::Delete(delete) => {
            let request = LocalBusObjectDeleteRequest {
                object_id: delete.object,
                relay_endpoint: delete.relay_url,
                #[cfg(feature = "itest-local-mint")]
                relay_service_key_base64: delete.relay_service_key,
                #[cfg(not(feature = "itest-local-mint"))]
                relay_service_key_base64: None,
            };
            print_json(
                &bus.request(Some(delete.account), "object", "object.delete", &request).await?,
            )
        }
    }
}

/// T25-A4 (CTRL-104 / OBJ-IPC-01): the number of full restart attempts a streaming GET makes. A
/// dropped local-bus read/finish response (a transport failure, NOT a structured daemon rejection)
/// is reconciled by RESTARTING the whole download — `object.get.begin` re-decrypts into a fresh
/// daemon spool and the client re-streams from offset 0. The temp output is only renamed into place
/// after the whole streamed plaintext hash-matches begin's, so no partial file is ever presented.
const OBJECT_GET_MAX_ATTEMPTS: usize = 3;

/// A streaming-GET attempt outcome: a structured daemon rejection (missing/tombstoned object, hash
/// mismatch) is `Fatal` (surfaced immediately, no restart); a transport failure (a dropped local-bus
/// response) is `Retryable` (restart via a fresh `object.get.begin`).
enum GetStreamError {
    Fatal(RfError),
    Retryable(RfError),
}

/// T25-A4 (CTRL-104 / OBJ-IPC-01): the streaming DOWNLOAD spool path. A public `rf object get` ALWAYS routes
/// through the bounded `object.get.begin` -> `object.get.read`* -> `object.get.finish` protocol so a
/// large (<= 16 MiB) object round-trips with every local-bus frame < 1 MiB and the 16 MiB plaintext
/// is NEVER held resident as one base64 string — it is streamed incrementally to the output file. The
/// user needs no flag: the daemon decrypts once, the client streams bounded reads. The one-shot
/// `object.get` request stays for small SDK callers (and its size guard fails closed above the
/// one-shot bound).
async fn handle_object_get(socket: &std::path::Path, get: ObjectGet) -> Result<(), RfError> {
    let operation_id = logical_object_get_operation_id(&get.object, get.relay_url.as_deref());
    let mut last_error: Option<RfError> = None;
    for _attempt in 0..OBJECT_GET_MAX_ATTEMPTS {
        match object_get_stream_attempt(socket, &get, &operation_id).await {
            Ok(response) => return print_json(&response),
            Err(GetStreamError::Fatal(error)) => return Err(error),
            Err(GetStreamError::Retryable(error)) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| RfError::Message("object.get exhausted restart attempts".to_owned())))
}

/// One streaming attempt: connect, `begin` (decrypt + spool), stream bounded reads into a sibling
/// temp file while hashing, verify the streamed hash matches `begin`, `finish` (best-effort daemon
/// cleanup), then atomically rename the temp into the output path. Any failure removes the temp so a
/// partial download is never left in place. A transport failure is `Retryable`; a structured daemon
/// error is `Fatal`.
#[allow(clippy::too_many_lines)]
async fn object_get_stream_attempt(
    socket: &std::path::Path,
    get: &ObjectGet,
    operation_id: &str,
) -> Result<serde_json::Value, GetStreamError> {
    let mut bus = LocalBusClient::connect(socket)
        .await
        .map_err(|error| GetStreamError::Retryable(error.into()))?;
    let account = get.account.clone();

    let begin = LocalBusObjectGetBeginRequest {
        object_id: get.object.clone(),
        operation_id: operation_id.to_owned(),
        protocol_version: OBJECT_PUT_PROTOCOL_VERSION,
        relay_endpoint: get.relay_url.clone(),
        #[cfg(feature = "itest-local-mint")]
        relay_service_key_base64: get.relay_service_key.clone(),
        #[cfg(not(feature = "itest-local-mint"))]
        relay_service_key_base64: None,
        relay_ack: get.relay_ack,
        relay_interrupt_after_chunks: get.relay_interrupt_after_chunks,
    };
    let begin = bus
        .request(Some(account.clone()), "object", "object.get.begin", &begin)
        .await
        .map_err(classify_get_error)?;
    let total_len = begin
        .get("total_len")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            GetStreamError::Fatal(RfError::Message("object.get.begin missing total_len".to_owned()))
        })?;
    let expected_hash = begin
        .get("plaintext_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            GetStreamError::Fatal(RfError::Message(
                "object.get.begin missing plaintext_hash".to_owned(),
            ))
        })?
        .to_owned();

    // Stream into a sibling temp file so the final rename is atomic and same-filesystem, and the
    // output path only ever holds a complete, hash-verified object.
    let temp_path = object_get_temp_path(&get.out);
    let stream = object_get_stream_to_file(
        &mut bus,
        &account,
        operation_id,
        total_len,
        &expected_hash,
        &temp_path,
    )
    .await;
    if let Err(error) = stream {
        // Any streaming failure removes the temp so a partial download is never left in place.
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }

    // Best-effort daemon spool cleanup. A dropped finish response is harmless — the client already
    // holds the whole hash-verified plaintext — so a finish failure does NOT fail the download.
    let finish = LocalBusObjectGetFinishRequest { operation_id: operation_id.to_owned() };
    let _ = bus.request(Some(account.clone()), "object", "object.get.finish", &finish).await;

    // Atomically publish the complete, verified object.
    std::fs::rename(&temp_path, &get.out).map_err(|error| {
        let _ = std::fs::remove_file(&temp_path);
        GetStreamError::Fatal(RfError::Message(format!("object.get output rename failed: {error}")))
    })?;

    Ok(serde_json::json!({
        "object_id": get.object,
        "out": get.out.display().to_string(),
        "total_len": total_len,
        "plaintext_hash": expected_hash,
        "streamed": true,
    }))
}

/// Streams bounded `object.get.read` slices into `temp_path`, hashing as it goes, and verifies the
/// streamed plaintext hash matches `expected_hash` before returning. Fails closed on a hash mismatch.
async fn object_get_stream_to_file(
    bus: &mut LocalBusClient,
    account: &str,
    operation_id: &str,
    total_len: usize,
    expected_hash: &str,
    temp_path: &std::path::Path,
) -> Result<(), GetStreamError> {
    let mut file = object_get_open_temp(temp_path)
        .map_err(|error| GetStreamError::Fatal(RfError::Io(error)))?;
    let mut hasher = ramflux_crypto::Blake3DomainHasher::new(ramflux_protocol::domain::OBJECT);
    let mut offset = 0_usize;
    while offset < total_len {
        let len = (total_len - offset).min(MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES);
        let read =
            LocalBusObjectGetReadRequest { operation_id: operation_id.to_owned(), offset, len };
        let response = bus
            .request(Some(account.to_owned()), "object", "object.get.read", &read)
            .await
            .map_err(classify_get_error)?;
        let data = response
            .get("data_base64")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                GetStreamError::Fatal(RfError::Message("object.get.read missing data".to_owned()))
            })
            .and_then(|value| {
                ramflux_protocol::decode_base64url(value).map_err(|error| {
                    GetStreamError::Fatal(RfError::Message(format!(
                        "invalid object slice: {error}"
                    )))
                })
            })?;
        if data.len() != len {
            return Err(GetStreamError::Fatal(RfError::Message(format!(
                "object.get.read returned {} bytes, expected {len}",
                data.len()
            ))));
        }
        std::io::Write::write_all(&mut file, &data)
            .map_err(|error| GetStreamError::Fatal(RfError::Io(error)))?;
        hasher.update(&data);
        offset += len;
    }
    std::io::Write::flush(&mut file).map_err(|error| GetStreamError::Fatal(RfError::Io(error)))?;
    file.sync_all().map_err(|error| GetStreamError::Fatal(RfError::Io(error)))?;
    let streamed_hash = hasher.finalize_base64url();
    if streamed_hash != expected_hash {
        return Err(GetStreamError::Fatal(RfError::Message(format!(
            "object.get streamed hash mismatch: expected {expected_hash} got {streamed_hash}"
        ))));
    }
    Ok(())
}

/// A dropped local-bus response closes the connection, surfacing as an I/O error — that is the ONLY
/// retryable (restart) class. A structured daemon rejection (missing/tombstoned object, protocol
/// desync) is fatal and surfaced immediately.
fn classify_get_error(error: ramflux_sdk::SdkError) -> GetStreamError {
    match error {
        ramflux_sdk::SdkError::Io(_) => GetStreamError::Retryable(error.into()),
        other => GetStreamError::Fatal(other.into()),
    }
}

/// A deterministic sibling temp path for the streamed download, so the final rename is atomic and on
/// the same filesystem as the output. Includes the pid to avoid collisions between concurrent gets.
fn object_get_temp_path(out: &std::path::Path) -> PathBuf {
    let file_name = out
        .file_name()
        .map_or_else(|| std::ffi::OsString::from("object"), std::ffi::OsStr::to_os_string);
    let mut temp_name = file_name;
    temp_name.push(format!(".rfget-{}.partial", std::process::id()));
    match out.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(temp_name),
        _ => PathBuf::from(temp_name),
    }
}

/// T25-A4 (CTRL-105): opens the client temp output with `O_EXCL` + 0600. Refuses a pre-existing path
/// or a final symlink (`create_new`/`O_EXCL` never follows or truncates), so a symlink or clobber planted
/// in the output directory cannot redirect or destroy the download. The caller fails closed and
/// removes the temp on any error; the temp is renamed into place only after the streamed hash checks.
fn object_get_open_temp(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

/// A stable `operation_id` for a logical `object.get`, bound to `object_id` + normalized relay
/// endpoint (no secret). Deterministic so a restart of the same GET carries the SAME id — a re-begin
/// then discards the prior daemon spool and re-decrypts into a clean one.
fn logical_object_get_operation_id(object_id: &str, relay_endpoint: Option<&str>) -> String {
    let relay = relay_endpoint.map(|value| value.trim().to_ascii_lowercase()).unwrap_or_default();
    let descriptor = serde_json::json!({
        "schema": "ramflux.object_get.operation_id.v1",
        "object_id": object_id,
        "relay_endpoint": relay,
    });
    let bytes = ramflux_protocol::canonical_json_bytes(&descriptor).unwrap_or_default();
    format!(
        "op-get-{}",
        ramflux_crypto::blake3_256_base64url("ramflux.object_get.operation_id.v1", &bytes)
    )
}

/// Routes a `rf object put` by file size: a file at/below the one-shot threshold keeps the small
/// inline `object.put` request; a larger file (up to 16 MiB) auto-routes to the bounded local-bus
/// UPLOAD spool (begin/chunk/finish), so the user never needs a flag to make a large PUT succeed
/// and no local-bus frame ever exceeds 1 MiB. Above 16 MiB is rejected client-side (fail closed).
async fn handle_object_put(
    bus: &mut LocalBusClient,
    socket: &std::path::Path,
    put: ObjectPut,
) -> Result<(), RfError> {
    let total_len = usize::try_from(std::fs::metadata(&put.file)?.len())
        .map_err(|_error| RfError::Message("object file too large to address".to_owned()))?;
    if total_len > MAX_LOCAL_BUS_OBJECT_BYTES {
        return Err(RfError::Message(format!(
            "object file is {total_len} bytes, exceeding the {MAX_LOCAL_BUS_OBJECT_BYTES}-byte local-bus object limit"
        )));
    }
    if total_len <= MAX_LOCAL_BUS_ONE_SHOT_OBJECT_BYTES {
        handle_object_put_one_shot(bus, socket, put).await
    } else {
        handle_object_put_spooled(bus, socket, put, total_len).await
    }
}

/// The small one-shot path (T25-A2): read the whole (<= 512 KiB) file, inline it as base64 in a
/// single `object.put` request, and reconcile a lost response via `object.put.status`.
async fn handle_object_put_one_shot(
    bus: &mut LocalBusClient,
    socket: &std::path::Path,
    put: ObjectPut,
) -> Result<(), RfError> {
    let bytes = std::fs::read(&put.file)?;
    // T25-A2 (OBJ-IPC-01): a stable per-logical-PUT operation_id derived from the content and
    // intent. Deterministic so a retry (even a fresh CLI invocation after a daemon crash/restart, or
    // after a lost response) carries the SAME id and reconciles/adopts instead of colliding.
    let operation_id = logical_object_put_operation_id(
        &put.object,
        &bytes,
        put.chunk_size,
        put.relay_url.as_deref(),
    );
    let account = put.account.clone();
    let request = LocalBusObjectPutRequest {
        object_id: put.object,
        plaintext_base64: ramflux_protocol::encode_base64url(&bytes),
        chunk_size: put.chunk_size,
        relay_endpoint: put.relay_url,
        #[cfg(feature = "itest-local-mint")]
        relay_service_key_base64: put.relay_service_key,
        #[cfg(not(feature = "itest-local-mint"))]
        relay_service_key_base64: None,
        relay_interrupt_after_chunks: put.relay_interrupt_after_chunks,
        operation_id: Some(operation_id.clone()),
    };
    let object_id = request.object_id.clone();
    match bus.request(Some(account.clone()), "object", "object.put", &request).await {
        Ok(response) => print_json(&response),
        Err(error) => {
            // A transport/response-read failure MAY have followed a durable commit. Reconnect with
            // the SAME operation_id and reconcile via object.put.status. If the operation is
            // `unknown` (never persisted — e.g. an oversized request rejected client-side BEFORE the
            // write), the reconcile surfaces this ORIGINAL error unchanged.
            reconcile_object_put(socket, &account, &object_id, &operation_id, &request, error).await
        }
    }
}

/// T25-A3 (OBJ-IPC-01) the streaming UPLOAD spool path: STREAM the file — never load it whole as a
/// resident base64 string. First stream-compute `total_len` + `plaintext_hash` + the deterministic
/// `operation_id`, then `object.put.begin`, then read+send the file in bounded (<= 512 KiB raw)
/// chunks, then `object.put.finish` (which reuses the A2 durable commit under the same id).
async fn handle_object_put_spooled(
    bus: &mut LocalBusClient,
    socket: &std::path::Path,
    put: ObjectPut,
    total_len: usize,
) -> Result<(), RfError> {
    // 1. stream-hash the plaintext WITHOUT resident base64 to derive plaintext_hash + operation_id.
    let mut hasher = ramflux_crypto::Blake3DomainHasher::new(ramflux_protocol::domain::OBJECT);
    let mut buffer = vec![0_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES];
    let mut file = std::fs::File::open(&put.file)?;
    let mut hashed_len = 0_usize;
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        hashed_len += read;
    }
    if hashed_len != total_len {
        return Err(RfError::Message("object file changed size during upload".to_owned()));
    }
    let plaintext_hash = hasher.finalize_base64url();
    let operation_id = logical_object_put_operation_id_from_hash(
        &put.object,
        &plaintext_hash,
        put.chunk_size,
        put.relay_url.as_deref(),
    );
    let account = put.account.clone();

    // 2. begin: bind the whole content-and-intent up front (carries no plaintext).
    let begin = LocalBusObjectPutBeginRequest {
        object_id: put.object.clone(),
        operation_id: operation_id.clone(),
        total_len,
        plaintext_hash,
        chunk_size: put.chunk_size,
        protocol_version: OBJECT_PUT_PROTOCOL_VERSION,
        relay_endpoint: put.relay_url.clone(),
        #[cfg(feature = "itest-local-mint")]
        relay_service_key_base64: put.relay_service_key.clone(),
        #[cfg(not(feature = "itest-local-mint"))]
        relay_service_key_base64: None,
        relay_interrupt_after_chunks: put.relay_interrupt_after_chunks,
    };
    bus.request(Some(account.clone()), "object", "object.put.begin", &begin).await?;

    // 3. stream the file in bounded chunks; each frame is < 1 MiB by construction.
    let mut file = std::fs::File::open(&put.file)?;
    let mut offset = 0_usize;
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        let chunk = LocalBusObjectPutChunkRequest {
            operation_id: operation_id.clone(),
            offset,
            data_base64: ramflux_protocol::encode_base64url(&buffer[..read]),
        };
        bus.request(Some(account.clone()), "object", "object.put.chunk", &chunk).await?;
        offset += read;
    }
    if offset != total_len {
        return Err(RfError::Message("object file changed size during upload".to_owned()));
    }

    // 4. finish: reuse the A2 durable commit. A lost finish response reconciles via
    //    object.put.status under the SAME operation_id (no new ambiguous-success window).
    let finish = LocalBusObjectPutFinishRequest {
        object_id: put.object.clone(),
        operation_id: operation_id.clone(),
    };
    match bus.request(Some(account.clone()), "object", "object.put.finish", &finish).await {
        Ok(response) => print_json(&response),
        Err(error) => {
            reconcile_object_put_finish(socket, &account, &put.object, &operation_id, error).await
        }
    }
}

/// Reconciles a lost `object.put.finish` response. A finish-response drop happens AFTER the
/// operation is durably `Committed`, so `object.put.status` returns `committed` and we print the
/// stored compact terminal with `reconciled=true` (the relay committed exactly once). `unknown`
/// surfaces the original error (nothing persisted); any other state means the durable object exists
/// but the commit/relay is incomplete and resumable — surfaced clearly (the spool is one-shot).
async fn reconcile_object_put_finish(
    socket: &std::path::Path,
    account: &str,
    object_id: &str,
    operation_id: &str,
    original_error: ramflux_sdk::SdkError,
) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    let status_request = LocalBusObjectPutStatusRequest {
        object_id: object_id.to_owned(),
        operation_id: operation_id.to_owned(),
    };
    let status = bus
        .request(Some(account.to_owned()), "object", "object.put.status", &status_request)
        .await?;
    let state = status.get("state").and_then(serde_json::Value::as_str).unwrap_or("unknown");
    match state {
        "committed" => {
            let mut terminal =
                status.get("terminal").cloned().unwrap_or_else(|| serde_json::json!({}));
            if let Some(map) = terminal.as_object_mut() {
                map.insert("reconciled".to_owned(), serde_json::Value::Bool(true));
            }
            print_json(&terminal)
        }
        "unknown" => Err(original_error.into()),
        other => Err(RfError::Message(format!(
            "object.put finish reconcile: state={other}; the object is durably staged but its commit is incomplete (resume it); original error: {original_error}"
        ))),
    }
}

/// T25-A2 (OBJ-IPC-01): a stable `operation_id` for a logical `object.put`, bound to `object_id` +
/// `plaintext_hash` + `chunk_size` + normalized relay endpoint (no secret). Deterministic so retries
/// of the same logical PUT reconcile idempotently; different content yields a different id.
fn logical_object_put_operation_id(
    object_id: &str,
    plaintext: &[u8],
    chunk_size: usize,
    relay_endpoint: Option<&str>,
) -> String {
    let plaintext_hash =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, plaintext);
    logical_object_put_operation_id_from_hash(
        object_id,
        &plaintext_hash,
        chunk_size,
        relay_endpoint,
    )
}

/// The `operation_id` derivation from a PRECOMPUTED `plaintext_hash` — used by the streaming spool
/// path so a 16 MiB object is never held resident to derive its id.
fn logical_object_put_operation_id_from_hash(
    object_id: &str,
    plaintext_hash: &str,
    chunk_size: usize,
    relay_endpoint: Option<&str>,
) -> String {
    let relay = relay_endpoint.map(|value| value.trim().to_ascii_lowercase()).unwrap_or_default();
    let descriptor = serde_json::json!({
        "schema": "ramflux.object_put.operation_id.v1",
        "object_id": object_id,
        "plaintext_hash": plaintext_hash,
        "chunk_size": chunk_size,
        "relay_endpoint": relay,
    });
    let bytes = ramflux_protocol::canonical_json_bytes(&descriptor).unwrap_or_default();
    format!(
        "op-{}",
        ramflux_crypto::blake3_256_base64url("ramflux.object_put.operation_id.v1", &bytes)
    )
}

/// Reconnects after a lost `object.put` response and reconciles by the SAME `operation_id`: if the
/// operation is `committed`, prints the compact terminal with `reconciled=true` (the durable state
/// exists exactly once); if still `pending`/`local_committed`, re-issues the PUT (adopts/resumes);
/// otherwise surfaces the failure.
async fn reconcile_object_put(
    socket: &std::path::Path,
    account: &str,
    object_id: &str,
    operation_id: &str,
    put_request: &LocalBusObjectPutRequest,
    original_error: ramflux_sdk::SdkError,
) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    let status_request = LocalBusObjectPutStatusRequest {
        object_id: object_id.to_owned(),
        operation_id: operation_id.to_owned(),
    };
    let status = bus
        .request(Some(account.to_owned()), "object", "object.put.status", &status_request)
        .await?;
    let state = status.get("state").and_then(serde_json::Value::as_str).unwrap_or("unknown");
    match state {
        "committed" => {
            let mut terminal =
                status.get("terminal").cloned().unwrap_or_else(|| serde_json::json!({}));
            if let Some(map) = terminal.as_object_mut() {
                map.insert("reconciled".to_owned(), serde_json::Value::Bool(true));
            }
            print_json(&terminal)
        }
        "pending" | "local_committed" => {
            let response =
                bus.request(Some(account.to_owned()), "object", "object.put", put_request).await?;
            print_json(&response)
        }
        "unknown" => {
            // No durable operation record exists: the PUT never persisted anything (a pre-commit
            // failure such as an oversized request rejected before the write). The original error is
            // the truth — surface it unchanged rather than masking it as a reconcile failure.
            Err(original_error.into())
        }
        other => Err(RfError::Message(format!("object.put reconcile failed: state={other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::object_get_open_temp;

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rf-object-get-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    // T25-A4 (CTRL-105): a fresh temp is created 0600.
    #[test]
    fn open_temp_creates_fresh_0600() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = unique_dir("fresh");
        let path = dir.join("out.partial");
        drop(object_get_open_temp(&path)?);
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "temp output must be created 0600");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    // A pre-existing regular file is refused and NOT truncated (create_new/O_EXCL).
    #[test]
    fn open_temp_refuses_existing_file_without_truncating() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = unique_dir("existing");
        let path = dir.join("out.partial");
        std::fs::write(&path, b"pre-existing")?;
        assert!(object_get_open_temp(&path).is_err(), "must refuse a pre-existing temp path");
        assert_eq!(
            std::fs::read(&path)?,
            b"pre-existing",
            "a refused open must NOT truncate the existing file"
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    // A symlink at the temp path is refused and its target is NOT followed/clobbered.
    #[test]
    fn open_temp_refuses_symlink_without_following() -> Result<(), Box<dyn std::error::Error>> {
        let dir = unique_dir("symlink");
        let target = dir.join("victim");
        std::fs::write(&target, b"victim-content")?;
        let link = dir.join("out.partial");
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(
            object_get_open_temp(&link).is_err(),
            "must refuse a symlink (O_EXCL never follows the final component)"
        );
        assert_eq!(
            std::fs::read(&target)?,
            b"victim-content",
            "the symlink target must be untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
