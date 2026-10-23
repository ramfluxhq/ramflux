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

impl RamfluxClient {
    pub(super) fn projection_id(&self, entry: &GatewayInboxEntry) -> Result<String, SdkError> {
        let db = self.account_db()?;
        let wire = &entry.envelope.envelope_id;
        let scoped =
            format!("routed:{}", committed_key(entry)?.trim_start_matches("routed/committed/"));
        let key = format!("routed/projection/{scoped}");
        if let Some(id) = db.load_actor_state::<String>(&key)? {
            return Ok(id);
        }
        // Callers cannot pre-claim reserved identifiers: their wire IDs are escaped again.
        if !wire.starts_with("routed:")
            && self.direct_message_by_id(wire)?.is_none()
            && db.load_actor_state::<String>(&format!("routed/message-owner/{wire}"))?.is_none()
        {
            return Ok(wire.clone());
        }
        Ok(scoped)
    }
    pub(super) fn persist_projection_owner(
        &self,
        entry: &GatewayInboxEntry,
        id: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let scoped =
            format!("routed:{}", committed_key(entry)?.trim_start_matches("routed/committed/"));
        db.persist_actor_state(&format!("routed/projection/{scoped}"), &id)?;
        db.persist_actor_state(
            &format!("routed/message-owner/{id}"),
            &entry.envelope.source_device_id,
        )?;
        Ok(())
    }
}
