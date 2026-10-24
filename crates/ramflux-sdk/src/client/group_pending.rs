// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retain the original signed carrier separately from the decrypted group ciphertext.
use crate::{GatewayInboxEntry, SdkError};
#[derive(serde::Serialize, serde::Deserialize)]
struct PendingGroupPayload {
    schema: String,
    entry: GatewayInboxEntry,
    group_body: Vec<u8>,
}
pub(super) fn encode(entry: &GatewayInboxEntry, body: &[u8]) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(&PendingGroupPayload {
        schema: "ramflux.sdk.pending_group_payload.v2".into(),
        entry: entry.clone(),
        group_body: body.to_vec(),
    })?)
}
pub(super) fn decode(bytes: &[u8]) -> Result<(GatewayInboxEntry, Vec<u8>), SdkError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value.get("schema").is_some() {
        let payload: PendingGroupPayload = serde_json::from_value(value)?;
        if payload.schema != "ramflux.sdk.pending_group_payload.v2" {
            return Err(SdkError::InboundRejected("unsupported pending group payload".into()));
        }
        return Ok((payload.entry, payload.group_body));
    }
    let entry: GatewayInboxEntry = serde_json::from_value(value)?;
    let body = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| SdkError::InboundRejected("invalid legacy pending group body".into()))?;
    Ok((entry, body))
}
