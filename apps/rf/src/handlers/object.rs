// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

#[allow(clippy::too_many_lines)]
pub(crate) async fn handle_object(socket: PathBuf, command: ObjectCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(&socket).await?;
    match command.action {
        ObjectAction::Put(put) => {
            let bytes = std::fs::read(&put.file)?;
            // T25-A2 (OBJ-IPC-01): a stable per-logical-PUT operation_id derived from the content
            // and intent. Deterministic so a retry (even a fresh CLI invocation after a daemon
            // crash/restart, or after a lost response) carries the SAME id and reconciles/adopts
            // instead of colliding as a new operation.
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
                    // A transport/response-read failure MAY have followed a durable commit. Reconnect
                    // with the SAME operation_id and reconcile via object.put.status. If the operation
                    // is `unknown` (never persisted — e.g. an oversized request rejected client-side
                    // BEFORE the write), the reconcile surfaces this ORIGINAL error unchanged.
                    reconcile_object_put(
                        socket.as_path(),
                        &account,
                        &object_id,
                        &operation_id,
                        &request,
                        error,
                    )
                    .await
                }
            }
        }
        ObjectAction::Get(get) => {
            let request = LocalBusObjectGetRequest {
                object_id: get.object,
                relay_endpoint: get.relay_url,
                #[cfg(feature = "itest-local-mint")]
                relay_service_key_base64: get.relay_service_key,
                #[cfg(not(feature = "itest-local-mint"))]
                relay_service_key_base64: None,
                relay_ack: get.relay_ack,
                relay_interrupt_after_chunks: get.relay_interrupt_after_chunks,
            };
            let response = bus.request(Some(get.account), "object", "object.get", &request).await?;
            let plaintext = response
                .get("plaintext_base64")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| RfError::Message("object.get response missing plaintext".to_owned()))
                .and_then(|value| {
                    ramflux_protocol::decode_base64url(value)
                        .map_err(|error| RfError::Message(format!("invalid object body: {error}")))
                })?;
            std::fs::write(&get.out, plaintext)?;
            print_json(&response)
        }
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
