// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authoritative outbound wire-to-logical bindings; receipt routing never parses ID suffixes.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
struct Binding {
    conversation: String,
    message: String,
    recipient_root: Option<String>,
}
fn key(
    local: &ramflux_crypto::RootQualifiedDeviceRef,
    recipient: &ramflux_crypto::RootQualifiedDeviceRef,
    wire: &str,
) -> Result<String, SdkError> {
    Ok(format!(
        "delivery-receipt/outbound/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.delivery-receipt.outbound.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                local.storage_key(),
                recipient.storage_key(),
                wire
            ))?
        )
    ))
}
impl RamfluxClient {
    pub(crate) fn bind_outgoing_delivery(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        message: &GatewayDirectMessage,
        kind: &crate::client::routed::Kind,
    ) -> Result<(), SdkError> {
        if !matches!(
            kind,
            crate::client::routed::Kind::Direct | crate::client::routed::Kind::GroupMessage
        ) {
            return Ok(());
        }
        let recipient = self.device_identity(&Self::qualified_recipient(message)?)?;
        let db = self.account_db()?;
        let storage = key(local, &recipient, &message.envelope_id)?;
        let root = Some(recipient.root_commitment().to_owned());
        let old = db.load_actor_state::<Binding>(&storage)?;
        if let Some(old) = &old
            && (old.conversation != message.conversation_id
                || old.message != message.message_id
                || old.recipient_root.as_ref().zip(root.as_ref()).is_some_and(|(a, b)| a != b))
        {
            return Err(SdkError::InboundRejected("outbound receipt binding conflict".into()));
        }
        db.persist_actor_state(
            &storage,
            &Binding {
                conversation: message.conversation_id.clone(),
                message: message.message_id.clone(),
                recipient_root: root.or_else(|| old.and_then(|old| old.recipient_root)),
            },
        )?;
        Ok(())
    }
    pub(crate) fn resolve_delivery_receipt_message(
        &self,
        recipient: &ramflux_crypto::RootQualifiedDeviceRef,
        conversation: &str,
        wire: &str,
    ) -> Result<String, SdkError> {
        let db = self.account_db()?;
        let bound = if let Some(local) = &self.device_branch {
            db.load_actor_state::<Binding>(&key(
                &self.local_device_identity(&local.device_id)?,
                recipient,
                wire,
            )?)?
        } else {
            None
        };
        let message = if let Some(binding) = bound {
            if binding.conversation != conversation {
                return Err(SdkError::InboundRejected(
                    "receipt differs from outbound conversation".into(),
                ));
            }
            if let Some(expected) = &binding.recipient_root {
                let current = Some(recipient.root_commitment().to_owned());
                if current.as_ref() != Some(expected) {
                    return Err(SdkError::InboundRejected(
                        "receipt root differs from outbound binding".into(),
                    ));
                }
            }
            binding.message
        } else {
            wire.to_owned()
        };
        if db.direct_message_by_id(&message)?.is_none_or(|row| {
            row.conversation_id != conversation
                || self.device_branch.as_ref().is_some_and(|local| {
                    row.sender_id != local.device_id && row.sender_id != local.principal_id
                })
        }) {
            return Err(SdkError::InboundRejected(
                "delivery receipt does not name a stored message".into(),
            ));
        }
        Ok(message)
    }
}
