// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact sealed retry packets commit atomically with the pair ratchet and retire with content.
use super::{GatewayDirectMessage, RamfluxClient, SdkError, SealedRouted, invalid};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct CachedSeal {
    digest: String,
    recipient_epoch: u64,
    /// Envelope time and TTL the cached packet was sealed with.
    created_at: i64,
    lifetime: u32,
    packet: super::SdkDmEncryptedEnvelope,
    committed_a0: Option<Vec<u8>>,
    metadata_commitment: Option<String>,
}

pub(super) struct Binding {
    recipient_epoch: u64,
    owner: String,
    key: String,
    digest: String,
    is_receipt: bool,
    created_at: i64,
    lifetime: u32,
}
impl Binding {
    pub(super) fn new(
        message: &GatewayDirectMessage,
        body: &[u8],
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        recipient: &ramflux_crypto::RootQualifiedDeviceRef,
        recipient_epoch: u64,
    ) -> Result<Option<Self>, SdkError> {
        // Receive adversaries deliberately reuse transport IDs or unsupported bodies.
        // This existing fixture hook never changes the production sender contract.
        #[cfg(test)]
        if super::report::allows_invalid_header_fixture() {
            return Ok(None);
        }
        let (identity, content) = RamfluxClient::decode_generated_inner(body)?;
        // Delete contains no erased body. Its own event owns the retry packet so
        // erasing the target cannot discard a peer tombstone awaiting delivery.
        let target = match content.value.as_ref() {
            Some(ramflux_protocol::message::content::Value::Edit(value)) => value.target.as_ref(),
            Some(ramflux_protocol::message::content::Value::Reaction(value)) => {
                value.target.as_ref()
            }
            Some(ramflux_protocol::message::content::Value::Receipt(value)) => {
                value.targets.first()
            }
            _ => None,
        };
        let owner =
            ramflux_protocol::encode_base64url(target.map_or(&identity.id, |target| &target.id));
        let key = format!(
            "routed/sealed-send/{}",
            ramflux_protocol::hash_base64url(
                "ramflux.message.sealed-send.key.v1",
                &ramflux_protocol::canonical_json_bytes(&(
                    &message.envelope_id,
                    source.storage_key(),
                    recipient.storage_key(),
                    &message.target_delivery_id
                ))?,
            )
        );
        let digest = ramflux_protocol::hash_base64url(
            "ramflux.message.sealed-send.binding.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &message.conversation_id,
                &message.message_id,
                &message.envelope_id,
                &message.sender_id,
                &message.source_principal_id,
                &message.recipient_device_id,
                &message.recipient_principal_commitment,
                &message.target_delivery_id,
                message.created_at,
                message.ttl,
                body,
            ))?,
        );
        let is_receipt = matches!(
            content.value.as_ref(),
            Some(ramflux_protocol::message::content::Value::Receipt(_))
        );
        Ok(Some(Self {
            recipient_epoch,
            owner,
            key,
            digest,
            is_receipt,
            created_at: message.created_at,
            lifetime: message.ttl,
        }))
    }
    pub(super) fn load(&self, client: &RamfluxClient) -> Result<Option<SealedRouted>, SdkError> {
        let db = client.account_db()?;
        if db.message_is_deleted(&self.owner)? {
            return Err(invalid("cannot resend erased content"));
        }
        let Some(cached) = db.load_actor_state::<CachedSeal>(&self.key)? else { return Ok(None) };
        if cached.recipient_epoch != self.recipient_epoch {
            return Err(SdkError::GeneratedRefused {
                code: crate::GeneratedRefusalCode::Authority,
                reason: "recipient incarnation changed; cached transport cannot be rebound".into(),
            });
        }
        if cached.digest != self.digest {
            // A receipt keeps its logical identity but its transport envelope is re-sealed with a
            // new `created_at` once the cached envelope is past its own TTL.
            if self.is_receipt
                && self.created_at > cached.created_at.saturating_add(i64::from(cached.lifetime))
            {
                return Ok(None);
            }
            return Err(SdkError::ReplayMismatch);
        }
        Ok(Some(SealedRouted {
            packet: cached.packet,
            committed_a0: cached.committed_a0,
            metadata_commitment: cached.metadata_commitment,
            suppress_wake: false,
        }))
    }
    pub(super) fn persist(
        &self,
        client: &RamfluxClient,
        sealed: &SealedRouted,
    ) -> Result<(), SdkError> {
        client.account_db()?.persist_message_actor_state(
            &self.owner,
            &self.key,
            &CachedSeal {
                digest: self.digest.clone(),
                recipient_epoch: self.recipient_epoch,
                created_at: self.created_at,
                lifetime: self.lifetime,
                packet: sealed.packet.clone(),
                committed_a0: sealed.committed_a0.clone(),
                metadata_commitment: sealed.metadata_commitment.clone(),
            },
        )?;
        Ok(())
    }
}
