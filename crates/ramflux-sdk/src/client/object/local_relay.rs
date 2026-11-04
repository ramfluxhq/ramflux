// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cancellable HTTP steps for the explicitly enabled local-mint fixture transport.

use super::{DmAttachmentChunk, DmAttachmentFetch, local_relay_token_for_chunk};
use crate::prelude::{
    ChunkPayload, SdkError, SdkObjectRelayAck, SdkObjectRelayAckResponse, SdkObjectRelayCapability,
    SdkObjectRelayGetRequest, SdkObjectRelayGetResponse, decrypt_chunk_payload, now_unix_timestamp,
    object_permission_for_chunk, object_relay_chunk_cipher_hash,
};
use serde::{Serialize, de::DeserializeOwned};
use std::{sync::OnceLock, time::Duration};

pub(super) async fn post<T: Serialize, R: DeserializeOwned>(
    endpoint: &str,
    path: &str,
    value: &T,
    timeout: Duration,
) -> Result<R, SdkError> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    let client = CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(0)
                .build()
                .map_err(|error| error.without_url().to_string())
        })
        .as_ref()
        .map_err(|error| SdkError::LocalBus(error.clone()))?;
    tokio::time::timeout(timeout, async {
        let host = crate::prekey::sdk_http_host_port(endpoint)?;
        let response = client
            .post(format!("http://{host}{path}"))
            .header(reqwest::header::CONNECTION, "close")
            .json(value)
            .send()
            .await
            .map_err(http_error)?;
        let status = response.status();
        if response.content_length().is_none() {
            return Err(SdkError::LocalBus("SDK HTTP response missing Content-Length".into()));
        }
        let body = response.bytes().await.map_err(http_error)?;
        if status != reqwest::StatusCode::OK {
            return Err(SdkError::LocalBus(format!(
                "SDK HTTP request failed: {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(serde_json::from_slice(&body)?)
    })
    .await
    .map_err(|_| {
        SdkError::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "relay HTTP step deadline expired",
        ))
    })?
}

pub(super) async fn get(
    ctx: &DmAttachmentFetch<'_>,
    index: u32,
    timeout: Duration,
) -> Result<DmAttachmentChunk, SdkError> {
    let permission = object_permission_for_chunk(
        ctx.branch,
        ctx.object,
        index,
        SdkObjectRelayCapability::Get,
        ctx.expires_at,
    )?;
    let token = local_relay_token_for_chunk(
        ctx.options,
        ctx.branch,
        ctx.object,
        index,
        SdkObjectRelayCapability::Get,
        ctx.expires_at,
    )?;
    let response: SdkObjectRelayGetResponse = post(
        &ctx.options.relay_endpoint,
        "/relay/v1/object/get_chunk",
        &SdkObjectRelayGetRequest {
            chunk_id: token.chunk_id.clone(),
            relay_token: token,
            object_permission_envelope: permission,
        },
        timeout,
    )
    .await?;
    if response.chunk.chunk_cipher_hash
        != object_relay_chunk_cipher_hash(
            &ctx.object.manifest_hash,
            index,
            &response.chunk.encrypted_chunk,
        )
    {
        return Err(SdkError::LocalBus("object relay chunk hash mismatch".into()));
    }
    let payload: ChunkPayload = serde_json::from_slice(&response.chunk.encrypted_chunk)?;
    let plaintext = decrypt_chunk_payload(&ctx.object_key, ctx.manifest, &payload)?;
    Ok(DmAttachmentChunk { payload, len: u64::try_from(plaintext.len()).unwrap_or(0) })
}

pub(super) async fn ack(
    ctx: &DmAttachmentFetch<'_>,
    index: u32,
    timeout: Duration,
) -> Result<SdkObjectRelayAckResponse, SdkError> {
    let token = local_relay_token_for_chunk(
        ctx.options,
        ctx.branch,
        ctx.object,
        index,
        SdkObjectRelayCapability::Ack,
        ctx.expires_at,
    )?;
    let permission = object_permission_for_chunk(
        ctx.branch,
        ctx.object,
        index,
        SdkObjectRelayCapability::Ack,
        ctx.expires_at,
    )?;
    post(
        &ctx.options.relay_endpoint,
        "/relay/v1/object/ack",
        &SdkObjectRelayAck {
            object_id: ctx.object.object_id.clone(),
            manifest_hash: ctx.object.manifest_hash.clone(),
            chunk_id: token.chunk_id.clone(),
            recipient_device_hash: token.recipient_device_hash.clone(),
            relay_token: token,
            object_permission_envelope: permission,
            acked_at: u64::try_from(now_unix_timestamp()).unwrap_or(0),
        },
        timeout,
    )
    .await
}
fn http_error(error: reqwest::Error) -> SdkError {
    ramflux_transport::TransportError::HttpClient(error.without_url()).into()
}

#[cfg(test)]
mod tests;
