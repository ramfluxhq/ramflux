// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Relay v3 QUIC chunk transport for objects and DM attachments: token issue, requester
//! proof of possession, one same-frame retry and the typed error mapping.
use super::*;

pub(super) async fn fetch_dm_attachment_chunk_via_gateway(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    ctx: &DmAttachmentFetch<'_>,
    chunk_index: u32,
) -> Result<DmAttachmentChunk, SdkError> {
    // T21-A2: grantee GatewayIssued GET is v3 QUIC only — no implicit HTTP/v2 fallback. The QUIC
    // helper fails closed on missing/partial QUIC configuration or grants.

    fetch_dm_attachment_chunk_via_relay_quic(engine, pool, ctx, chunk_index).await
}

async fn fetch_dm_attachment_chunk_via_relay_quic(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    ctx: &DmAttachmentFetch<'_>,
    chunk_index: u32,
) -> Result<DmAttachmentChunk, SdkError> {
    let attachment = ctx.attachment.ok_or_else(|| {
        SdkError::CapabilityDenied("v3 relay GET requires the signed attachment grant".to_owned())
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let expires_at = issued_at.saturating_add(120);
    let chunk_id =
        object_relay_chunk_id(&ctx.object.object_id, &ctx.object.manifest_hash, chunk_index);
    let body_descriptor = serde_json::json!({
        "capability": "get",
        "chunk_id": chunk_id,
        "manifest_hash": ctx.object.manifest_hash,
        "object_id": ctx.object.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.get.body",
        &ramflux_protocol::canonical_json_bytes(&body_descriptor)?,
    );
    let issue_body = build_v3_get_token_issue_body(
        attachment.access_grant.as_ref(),
        attachment,
        ctx.branch,
        engine.config().source_identity.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &chunk_id,
        issued_at,
        expires_at,
        &format!("sdk-get-{issued_at}-{chunk_index}"),
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let pop = build_signed_requester_pop(
        ctx.branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Get,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-{issued_at}-{chunk_index}"),
        body_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "grant": attachment.access_grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "get",
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, ctx.options, "/relay/v1/object/get_chunk", body).await?,
    )?;
    let response: SdkObjectRelayGetResponse = serde_json::from_value(response)?;
    let expected_hash = object_relay_chunk_cipher_hash(
        &ctx.object.manifest_hash,
        chunk_index,
        &response.chunk.encrypted_chunk,
    );
    if response.chunk.chunk_cipher_hash != expected_hash {
        return Err(SdkError::LocalBus("object relay chunk hash mismatch".to_owned()));
    }
    let payload: ChunkPayload = serde_json::from_slice(&response.chunk.encrypted_chunk)?;
    let plaintext_chunk = decrypt_chunk_payload(&ctx.object_key, ctx.manifest, &payload)?;
    Ok(DmAttachmentChunk { payload, len: u64::try_from(plaintext_chunk.len()).unwrap_or(0) })
}

// T21-A2: a distinct grantee (B) acknowledges a chunk using the SAME A-signed grant it received in
// the attachment — B never re-signs the grant, it only signs its own requester PoP. The grant must
// authorize Ack; `build_v3_ack_token_issue_body` reuses the grant's canonical bytes and rejects a
// grant that does not carry the Ack capability. GatewayIssued v3 QUIC only, no HTTP fallback.
pub(super) async fn ack_dm_attachment_chunk_via_relay_quic(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    ctx: &DmAttachmentFetch<'_>,
    chunk_index: u32,
) -> Result<SdkObjectRelayAckResponse, SdkError> {
    let attachment = ctx.attachment.ok_or_else(|| {
        SdkError::CapabilityDenied("v3 relay ACK requires the signed attachment grant".to_owned())
    })?;
    let started = std::time::Instant::now();
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let expires_at = issued_at.saturating_add(120);
    let chunk_id =
        object_relay_chunk_id(&ctx.object.object_id, &ctx.object.manifest_hash, chunk_index);
    let body_descriptor = serde_json::json!({
        "capability": "ack",
        "chunk_id": chunk_id,
        "manifest_hash": ctx.object.manifest_hash,
        "object_id": ctx.object.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.ack.body",
        &ramflux_protocol::canonical_json_bytes(&body_descriptor)?,
    );
    let issue_body = build_v3_ack_token_issue_body(
        attachment.access_grant.as_ref(),
        attachment,
        ctx.branch,
        engine.config().source_identity.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &chunk_id,
        issued_at,
        expires_at,
        &format!("sdk-ack-{issued_at}-{chunk_index}"),
    )?;
    let prepared = std::time::Instant::now();
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let token_issued = std::time::Instant::now();
    let pop = build_signed_requester_pop(
        ctx.branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Ack,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-ack-{issued_at}-{chunk_index}"),
        body_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "grant": attachment.access_grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "ack",
    });
    let request_ready = std::time::Instant::now();
    let response = relay_quic_success_body(
        relay_quic_request(pool, ctx.options, "/relay/v1/object/ack", body).await?,
    )?;
    tracing::debug!(
        target: "ramflux_sdk::attachment_timing",
        object_id = %attachment.object_id,
        chunk_index,
        prepare_ms = prepared.duration_since(started).as_secs_f64() * 1000.0,
        gateway_ms = token_issued.duration_since(prepared).as_secs_f64() * 1000.0,
        requester_ms = request_ready.duration_since(token_issued).as_secs_f64() * 1000.0,
        relay_ms = request_ready.elapsed().as_secs_f64() * 1000.0,
        "attachment ACK round trips confirmed"
    );
    Ok(serde_json::from_value(response)?)
}

// T24-A2: relay requests now ride the account's persistent `RelayQuicPool` instead of a fresh
// per-request QUIC handshake. The token/PoP/nonce and `body` are built exactly once by the caller;
// this fn constructs the `GatewayQuicRequest` once and issues it via `request_once`. A single
// same-frame retry is attempted ONLY when the first failure is a transport-level
// `is_reconnect_retryable()` (no complete application response AND the connection was closed +
// evicted) — the identical request value is re-sent (no re-issued token, no regenerated nonce, no
// re-entry of the upper helper). A complete `GatewayQuicResponse` of any HTTP status is returned
// as-is for the caller's business-status handling; the pool never retries on HTTP status.
pub(super) async fn relay_quic_request(
    pool: &ramflux_transport::RelayQuicPool,
    options: &RelayTransferOptions,
    path: &str,
    body: serde_json::Value,
) -> Result<ramflux_transport::GatewayQuicResponse, SdkError> {
    let config = relay_quic_config(options)?
        .ok_or_else(|| SdkError::LocalBus("relay QUIC configuration is missing".to_owned()))?;
    let request = ramflux_transport::GatewayQuicRequest {
        method: "POST".to_owned(),
        path: path.to_owned(),
        body,
    };
    issue_relay_request_with_single_retry(&request, |frame| pool.request_once(&config, frame)).await
}

/// The same-frame single-retry decision, factored out so it can be unit-tested without a live
/// relay. `attempt` is invoked with the identical `request` value each time — the token/PoP/nonce
/// live inside `request.body` and are never rebuilt here. A first failure is retried **once** iff
/// it is a transport-level `is_reconnect_retryable()` (no complete application response + the
/// connection was closed/evicted); the second outcome is returned verbatim (no third attempt). Any
/// other first failure, and any complete `GatewayQuicResponse` (all HTTP statuses, including 4xx
/// and 5xx), returns immediately.
pub(super) async fn issue_relay_request_with_single_retry<'a, F, Fut>(
    request: &'a ramflux_transport::GatewayQuicRequest,
    attempt: F,
) -> Result<ramflux_transport::GatewayQuicResponse, SdkError>
where
    F: Fn(&'a ramflux_transport::GatewayQuicRequest) -> Fut,
    Fut: std::future::Future<
            Output = Result<
                ramflux_transport::GatewayQuicResponse,
                ramflux_transport::RelayQuicRequestError,
            >,
        >,
{
    match attempt(request).await {
        Ok(response) => Ok(response),
        Err(first) if first.is_reconnect_retryable() => {
            attempt(request).await.map_err(relay_pool_error_to_sdk)
        }
        Err(other) => Err(relay_pool_error_to_sdk(other)),
    }
}

/// Maps a transport-layer relay pool error to `SdkError`. Backpressure is preserved as an explicit
/// transport/capacity error (never collapsed into `CapabilityDenied` or a faked HTTP status).
/// Peer-auth/protocol failures retain their permanent classification. Complete HTTP responses never reach here —
/// they are returned `Ok` and handled by the caller's business-status logic.
fn relay_pool_error_to_sdk(error: ramflux_transport::RelayQuicRequestError) -> SdkError {
    match error {
        ramflux_transport::RelayQuicRequestError::Backpressure { capacity, in_flight } => {
            SdkError::Transport(ramflux_transport::TransportError::BackpressureRejected {
                capacity,
                in_flight,
            })
        }
        ramflux_transport::RelayQuicRequestError::PeerAuth(message) => {
            SdkError::Transport(ramflux_transport::TransportError::Tls(message))
        }
        ramflux_transport::RelayQuicRequestError::Protocol(message)
        | ramflux_transport::RelayQuicRequestError::Config(message) => {
            SdkError::Transport(ramflux_transport::TransportError::Protocol(
                ramflux_protocol::ProtocolError::TransportProtocol(message),
            ))
        }
        other => SdkError::Transport(ramflux_transport::TransportError::Quic(other.to_string())),
    }
}

pub(super) fn relay_quic_success_body(
    response: ramflux_transport::GatewayQuicResponse,
) -> Result<serde_json::Value, SdkError> {
    if response.status != 200 {
        return Err(SdkError::CapabilityDenied(format!(
            "relay v3 request rejected with HTTP status {}: {}",
            response.status, response.body
        )));
    }
    Ok(response.body)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn get_object_chunk_via_relay_quic(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    options: &RelayTransferOptions,
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_index: u32,
    expires_at: u64,
) -> Result<SdkObjectRelayGetResponse, SdkError> {
    let owner_home_node_id = options.relay_owner_home_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner GET requires RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(),
        )
    })?;
    let owner_principal_id = options.relay_owner_principal_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner GET requires RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(),
        )
    })?;
    let audience_node_id = options.relay_audience_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner GET requires RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(),
        )
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let chunk_id = object_relay_chunk_id(&object.object_id, &object.manifest_hash, chunk_index);
    let nonce = format!("sdk-get-{issued_at}-{chunk_index}");
    let grant = build_signed_object_access_grant(
        branch,
        object.object_id.clone(),
        object.manifest_hash.clone(),
        recipient_device_hash(
            engine.config().source_identity.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        ),
        vec![ramflux_protocol::ObjectRelayCapability::Get],
        issued_at,
        expires_at,
    )?;
    let issue_body = build_v3_grant_token_issue_body(
        &grant,
        branch,
        engine.config().source_identity.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &object.object_id,
        &object.manifest_hash,
        &chunk_id,
        ramflux_protocol::ObjectRelayCapability::Get,
        owner_home_node_id,
        owner_principal_id,
        branch.device_epoch,
        audience_node_id,
        issued_at,
        expires_at,
        &nonce,
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let body_descriptor = serde_json::json!({
        "capability": "get",
        "chunk_id": chunk_id,
        "manifest_hash": object.manifest_hash,
        "object_id": object.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.get.body",
        &ramflux_protocol::canonical_json_bytes(&body_descriptor)?,
    );
    let pop = build_signed_requester_pop(
        branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Get,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-{issued_at}-{chunk_index}"),
        body_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "grant": grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "get",
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, options, "/relay/v1/object/get_chunk", body).await?,
    )?;
    Ok(serde_json::from_value(response)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn ack_object_chunk_via_relay_quic(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    options: &RelayTransferOptions,
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_index: u32,
    expires_at: u64,
) -> Result<SdkObjectRelayAckResponse, SdkError> {
    let owner_home_node_id = options.relay_owner_home_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner ACK requires RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(),
        )
    })?;
    let owner_principal_id = options.relay_owner_principal_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner ACK requires RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(),
        )
    })?;
    let audience_node_id = options.relay_audience_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner ACK requires RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(),
        )
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let chunk_id = object_relay_chunk_id(&object.object_id, &object.manifest_hash, chunk_index);
    let nonce = format!("sdk-ack-{issued_at}-{chunk_index}");
    let grant = build_signed_object_access_grant(
        branch,
        object.object_id.clone(),
        object.manifest_hash.clone(),
        recipient_device_hash(
            engine.config().source_identity.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        ),
        vec![ramflux_protocol::ObjectRelayCapability::Ack],
        issued_at,
        expires_at,
    )?;
    let issue_body = build_v3_grant_token_issue_body(
        &grant,
        branch,
        engine.config().source_identity.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &object.object_id,
        &object.manifest_hash,
        &chunk_id,
        ramflux_protocol::ObjectRelayCapability::Ack,
        owner_home_node_id,
        owner_principal_id,
        branch.device_epoch,
        audience_node_id,
        issued_at,
        expires_at,
        &nonce,
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let body_descriptor = serde_json::json!({
        "capability": "ack",
        "chunk_id": chunk_id,
        "manifest_hash": object.manifest_hash,
        "object_id": object.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.ack.body",
        &ramflux_protocol::canonical_json_bytes(&body_descriptor)?,
    );
    let pop = build_signed_requester_pop(
        branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Ack,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-{issued_at}-{chunk_index}"),
        body_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "grant": grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "ack",
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, options, "/relay/v1/object/ack", body).await?,
    )?;
    Ok(serde_json::from_value(response)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn put_object_chunk_via_relay_quic(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    options: &RelayTransferOptions,
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_index: u32,
    encrypted_chunk: Vec<u8>,
    expires_at: u64,
) -> Result<SdkObjectRelayPutResponse, SdkError> {
    let owner_home_node_id = options.relay_owner_home_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner PUT requires RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(),
        )
    })?;
    let owner_principal_id = options.relay_owner_principal_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner PUT requires RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(),
        )
    })?;
    let audience_node_id = options.relay_audience_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner PUT requires RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(),
        )
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let chunk_id = object_relay_chunk_id(&object.object_id, &object.manifest_hash, chunk_index);
    let chunk_cipher_hash =
        object_relay_chunk_cipher_hash(&object.manifest_hash, chunk_index, &encrypted_chunk);
    let nonce = format!("sdk-put-{issued_at}-{chunk_index}");
    let owner_proof = build_signed_owner_authorization_proof(
        branch,
        ramflux_protocol::ObjectRelayCapability::Put,
        object.object_id.clone(),
        Some(object.manifest_hash.clone()),
        Some(chunk_id.clone()),
        owner_home_node_id.to_owned(),
        owner_principal_id.to_owned(),
        branch.device_epoch,
        nonce.clone(),
        chunk_cipher_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let authorization_binding_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.owner_authorization_proof.binding.v3",
        &ramflux_protocol::canonical_json_bytes(&owner_proof)?,
    );
    let issue_body = build_v3_owner_session_token_issue_body(
        branch,
        engine.config().source_identity.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        object,
        &chunk_id,
        ramflux_protocol::ObjectRelayCapability::Put,
        owner_home_node_id,
        audience_node_id,
        owner_principal_id,
        &authorization_binding_hash,
        issued_at,
        expires_at,
        &nonce,
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let pop = build_signed_requester_pop(
        branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Put,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-{issued_at}-{chunk_index}"),
        chunk_cipher_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "owner_proof": owner_proof,
        "pop": pop,
        "body_hash": chunk_cipher_hash.clone(),
        "capability": "put",
        "chunk_index": chunk_index,
        "chunk_cipher_hash": chunk_cipher_hash,
        "encrypted_chunk": encrypted_chunk,
        "expires_at": expires_at,
        "delete_after_ack": false,
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, options, "/relay/v1/object/put_chunk", body).await?,
    )?;
    Ok(serde_json::from_value(response)?)
}
