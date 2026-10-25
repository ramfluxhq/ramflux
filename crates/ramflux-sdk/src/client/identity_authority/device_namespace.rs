// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-qualified durable device references, with literal names kept on the wire.
use super::invalid;
use crate::{GatewayDirectMessage, GatewayInboxEntry, RamfluxClient, SdkError};
pub(crate) fn wire_device_id(reference: &str) -> Result<String, SdkError> {
    Ok(ramflux_protocol::parse_qualified_device_id(reference)?
        .map_or_else(|| reference.to_owned(), |(_, device)| device))
}
impl RamfluxClient {
    pub(crate) fn local_device_reference(&self, raw: &str) -> Result<String, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if local.device_id != raw {
            return Err(invalid("local device context mismatch"));
        }
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(ramflux_protocol::qualified_device_id(
            &ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key()),
            raw,
        )?)
    }
    pub(crate) fn device_reference(&self, device: &str) -> Result<String, SdkError> {
        if ramflux_protocol::parse_qualified_device_id(device)?.is_some() {
            return Ok(device.into());
        }
        if let Some(local) = &self.device_branch
            && local.device_id == device
        {
            let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            return Ok(ramflux_protocol::qualified_device_id(
                &ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key()),
                device,
            )?);
        }
        // Bare names never select a directory root. Historical orphan metadata remains
        // addressable solely so lifecycle cleanup can erase it alongside current sessions.
        Ok(device.into())
    }
    pub(crate) fn device_root(&self, reference: &str) -> Result<String, SdkError> {
        let reference = self.device_reference(reference)?;
        ramflux_protocol::parse_qualified_device_id(&reference)?
            .map(|(root, _)| root)
            .ok_or_else(|| invalid("root-qualified device required"))
    }
    pub(crate) fn device_revocation_key(device: &ramflux_crypto::RootQualifiedDeviceRef) -> String {
        format!("device/revoked/{}", device.storage_key())
    }
    pub(crate) fn normalize_recipient(message: &mut GatewayDirectMessage) -> Result<(), SdkError> {
        if message.recipient_principal_commitment.is_none()
            && let Some(reference) = message.recipient_device_id.as_deref()
            && let Some((root, raw)) = ramflux_protocol::parse_qualified_device_id(reference)?
        {
            message.recipient_principal_commitment = Some(root);
            message.recipient_device_id = Some(raw);
        }
        Ok(())
    }
    pub(crate) fn qualified_recipient(message: &GatewayDirectMessage) -> Result<String, SdkError> {
        let raw = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("recipient device required"))?;
        let root = message
            .recipient_principal_commitment
            .as_deref()
            .filter(|root| !root.is_empty())
            .ok_or_else(|| invalid("recipient root commitment required"))?;
        Ok(ramflux_protocol::qualified_device_id(root, raw)?)
    }
    pub(crate) fn inbound_device_reference(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        let owner = &entry.envelope.source_principal_id;
        let hint = super::super::routed::decode(&entry.envelope)
            .ok()
            .and_then(|packet| packet.source_principal_commitment);
        let signed_hint = match entry.envelope.ext.ext.get("source_root_commitment") {
            Some(serde_json::Value::String(root)) => Some(root.as_str()),
            Some(_) => return Err(invalid("invalid sender root hint")),
            None => None,
        };
        for root in hint.as_deref().into_iter().chain(signed_hint) {
            let bytes = ramflux_protocol::decode_base64url(root)
                .map_err(|_| invalid("invalid sender root hint"))?;
            if bytes.len() != 32 || ramflux_protocol::encode_base64url(&bytes) != root {
                return Err(invalid("invalid sender root hint"));
            }
        }
        if hint.as_deref().zip(signed_hint).is_some_and(|(body, envelope)| body != envelope) {
            return Err(invalid("sender root claims disagree"));
        }
        let hint = hint.or_else(|| signed_hint.map(str::to_owned));
        let pinned = self
            .account_db()?
            .client_record("identity", owner)?
            .and_then(|row| row["contact_identity_commitment"].as_str().map(str::to_owned));
        let own = self
            .device_branch
            .as_ref()
            .filter(|branch| branch.principal_id == *owner)
            .and(self.identity_root.as_ref())
            .map(|root| {
                ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key())
            });
        let expected = if let Some(root) = own.or(pinned) {
            Some(root)
        } else {
            let roots = self
                .account_db()?
                .pinned_group_root_metadata(owner, &entry.envelope.source_device_id)?;
            if roots.len() > 1 {
                return Err(invalid("ambiguous group sender root context"));
            }
            roots.into_iter().next()
        };
        if hint.as_ref().zip(expected.as_ref()).is_some_and(|(hint, expected)| hint != expected) {
            return Err(invalid("sender root differs from pinned relationship"));
        }
        let root = expected.or(hint).ok_or_else(|| invalid("sender root context required"))?;
        Ok(ramflux_protocol::qualified_device_id(&root, &entry.envelope.source_device_id)?)
    }
    pub(crate) fn inbound_relationship_names_root(
        &self,
        principal: &str,
        root: &str,
        device: &str,
    ) -> Result<bool, SdkError> {
        if let Some(local) = &self.device_branch
            && local.principal_id == principal
        {
            let own = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            return Ok(
                ramflux_crypto::identity_root_commitment(&own.signing_key.verifying_key()) == root
            );
        }
        if self.friend_link_peer_is_accepted(root)? {
            return Ok(true);
        }
        let pinned = self
            .account_db()?
            .client_record("identity", principal)?
            .is_some_and(|row| row["contact_identity_commitment"] == root);
        if pinned && self.friend_link_peer_is_accepted(principal)? {
            return Ok(true);
        }
        // Selecting a manifest to fetch is not device authentication. A saved root-bound
        // relationship/offer constrains the claim; the complete record and envelope signature
        // must still verify before a RootQualifiedDeviceRef can authorize any operation.
        Ok(self.pending_own_group_names_root(principal, root, device)?
            || self
                .account_db()?
                .pinned_group_root_metadata(principal, device)?
                .iter()
                .any(|expected| expected == root)
            || self.account_db()?.pending_group_invite_root_metadata(
                device,
                root,
                crate::prelude::now_unix_timestamp(),
            )?)
    }
}
