// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replay receipts retain authenticated attribution and are scoped by sender device and envelope.
use super::{Deserialize, GatewayInboxEntry, RamfluxClient, Routing, SdkError, Serialize};
#[derive(Serialize, Deserialize)]
pub(super) struct Committed {
    pub routing: Routing,
    pub entry: GatewayInboxEntry,
    #[serde(default = "already_projected")]
    pub projected: bool,
}
fn already_projected() -> bool {
    true
}

pub(crate) fn committed_key(
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &str,
) -> Result<String, SdkError> {
    let bytes = ramflux_protocol::canonical_json_bytes(&(
        source.root_commitment(),
        source.device_id(),
        envelope,
    ))?;
    Ok(format!(
        "routed/committed/{}",
        ramflux_crypto::blake3_256_base64url("ramflux.sdk.receipt.v3", &bytes)
    ))
}

impl RamfluxClient {
    pub(crate) fn authenticated_committed_key(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        committed_key(&self.authenticated_device_identity(entry)?, &entry.envelope.envelope_id)
    }
    /// Unauthenticated inputs have no device identity and cannot reserve a device's retry bucket.
    /// They use an opaque, globally bounded quarantine key until manifest discovery authenticates them.
    pub(crate) fn inbox_admission_key(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        if let Ok(key) = self.authenticated_committed_key(entry) {
            return Ok(key);
        }
        Ok(format!(
            "inbox/unverified/{}",
            ramflux_protocol::hash_base64url(
                "ramflux.sdk.unverified_inbox.v1",
                &ramflux_protocol::canonical_json_bytes(&entry.envelope)?
            )
        ))
    }
    pub(crate) fn persist_legacy_committed(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
    ) -> Result<(), SdkError> {
        let key = self.legacy_committed_key(entry)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            let new = db.load_actor_state::<String>(&key)?.is_none();
            db.persist_actor_state(&key, &conversation)?;
            if new {
                db.persist_actor_state(&format!("{key}/projected"), &false)?;
            }
            Ok(())
        })
    }
    /// Claim the application projection durably before ACK, independent of the bounded RAM cache.
    pub(crate) fn claim_inbox_projection(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let key = self.authenticated_committed_key(entry)?;
        db.write_transaction(|| {
            if let Some(mut receipt) = db.load_actor_state::<Committed>(&key)? {
                if receipt.projected {
                    return Ok(false);
                }
                receipt.projected = true;
                db.persist_actor_state(&key, &receipt)?;
                return Ok(true);
            }
            let legacy = self.legacy_committed_key(entry)?;
            if db.load_actor_state::<String>(&legacy)?.is_none() {
                return Ok(false);
            }
            let marker = format!("{legacy}/projected");
            if db.load_actor_state::<bool>(&marker)?.unwrap_or(true) {
                return Ok(false);
            }
            db.persist_actor_state(&marker, &true)?;
            Ok(true)
        })
    }
    pub(crate) fn committed_routing(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<Routing>, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<Committed>(&self.authenticated_committed_key(entry)?)?
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
pub(crate) fn object_watermark(
    object: &str,
    recipient: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<String, SdkError> {
    let bytes = ramflux_protocol::canonical_json_bytes(&(object, recipient.storage_key()))?;
    Ok(format!(
        "routed/slot-watermark/{}",
        ramflux_crypto::blake3_256_base64url("ramflux.sdk.slot.watermark.v2", &bytes)
    ))
}

impl RamfluxClient {
    pub(super) fn projection_id(
        &self,
        entry: &GatewayInboxEntry,
        route: &Routing,
    ) -> Result<String, SdkError> {
        self.projection_id_for(
            entry,
            route.group_message_id.as_deref().unwrap_or(&entry.envelope.envelope_id),
        )
    }
    pub(super) fn projection_id_for(
        &self,
        entry: &GatewayInboxEntry,
        wire: &str,
    ) -> Result<String, SdkError> {
        let db = self.account_db()?;
        let scoped = format!(
            "routed:{}",
            self.authenticated_committed_key(entry)?.trim_start_matches("routed/committed/")
        );
        let key = format!("routed/projection/{scoped}");
        if let Some(id) = db.load_actor_state::<String>(&key)? {
            return Ok(id);
        }
        // Callers cannot pre-claim reserved identifiers: their wire IDs are escaped again.
        if !wire.starts_with("routed:")
            && self.direct_message_by_id(wire)?.is_none()
            && db.load_actor_state::<String>(&format!("routed/message-owner/{wire}"))?.is_none()
        {
            return Ok(wire.to_owned());
        }
        if self.direct_message_by_id(&scoped)?.is_some()
            || db.load_actor_state::<String>(&format!("routed/message-owner/{scoped}"))?.is_some()
        {
            return Ok(format!(
                "{scoped}:{}",
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
            ));
        }
        Ok(scoped)
    }
    pub(super) fn persist_projection_owner(
        &self,
        entry: &GatewayInboxEntry,
        id: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let scoped = format!(
            "routed:{}",
            self.authenticated_committed_key(entry)?.trim_start_matches("routed/committed/")
        );
        db.persist_actor_state(&format!("routed/projection/{scoped}"), &id)?;
        db.persist_actor_state(
            &format!("routed/message-owner/{id}"),
            &self.authenticated_device_identity(entry)?.storage_key(),
        )?;
        Ok(())
    }
}

impl RamfluxClient {
    pub(crate) fn committed_direct_context(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<(String, String)>, SdkError> {
        if let Some(route) = self.committed_routing(entry)? {
            return Ok((route.kind == super::Kind::Direct)
                .then_some((route.conversation_id, route.message_id)));
        }
        Ok(self
            .account_db()?
            .load_actor_state::<String>(&self.legacy_committed_key(entry)?)?
            .map(|conversation| (conversation, entry.envelope.envelope_id.clone())))
    }

    pub(crate) fn legacy_committed_key(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        Ok(format!("legacy/committed-root/{}", self.authenticated_committed_key(entry)?))
    }
}
