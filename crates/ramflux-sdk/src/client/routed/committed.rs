// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replay receipts retain authenticated attribution and are scoped by sender device and envelope.
use super::{Deserialize, GatewayInboxEntry, RamfluxClient, Routing, SdkError, Serialize};
#[derive(Serialize, Deserialize)]
pub(super) struct Committed {
    pub routing: Routing,
    pub entry: GatewayInboxEntry,
}
pub(crate) fn committed_key(entry: &GatewayInboxEntry) -> Result<String, SdkError> {
    let bytes = ramflux_protocol::canonical_json_bytes(&(
        &entry.envelope.source_device_id,
        &entry.envelope.envelope_id,
    ))?;
    Ok(format!(
        "routed/committed/{}",
        ramflux_crypto::blake3_256_base64url("ramflux.sdk.receipt.v2", &bytes)
    ))
}
impl RamfluxClient {
    pub(crate) fn committed_routing(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<Routing>, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<Committed>(&committed_key(entry)?)?
            .map(|receipt| receipt.routing))
    }
}

/// Read-model metadata only; this index is never consulted as a replay receipt.
impl RamfluxClient {
    pub(crate) fn routed_message_metadata(&self, id: &str) -> Result<Option<Routing>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&format!("routed/message-metadata/{id}"))?)
    }
}
pub(crate) fn conversation_watermark(conversation: &str) -> String {
    format!(
        "routed/commit-watermark/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.sdk.receive.watermark.v2",
            conversation.as_bytes()
        )
    )
}
pub(crate) fn object_watermark(object: &str, recipient: &str) -> Result<String, SdkError> {
    let bytes = ramflux_protocol::canonical_json_bytes(&(object, recipient))?;
    Ok(format!(
        "routed/slot-watermark/{}",
        ramflux_crypto::blake3_256_base64url("ramflux.sdk.slot.watermark.v2", &bytes)
    ))
}
