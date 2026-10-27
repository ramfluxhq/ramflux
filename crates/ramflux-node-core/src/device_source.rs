// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recover root-qualified sender context from existing signed device authority and possession.
use crate::{DeviceAuthKeyResponse, NodeCoreError};
use ramflux_crypto::RootQualifiedDeviceRef;

impl DeviceAuthKeyResponse {
    /// Recover identity only from a verified, active root-signed device entry.
    /// The registry supplies its highest accepted record; callers must also verify possession
    /// of the committed branch signing key before using this identity for request admission.
    /// # Errors
    /// Rejects legacy unsigned records, revoked entries, or inconsistent principal, epoch and key.
    pub fn authenticated_device_identity(
        &self,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        self.authenticated_device_identity_for("register", crate::now_unix_seconds())
    }

    /// Authenticate native authority for the operation's required branch capability.
    /// The registry remains responsible for supplying its current unfenced head.
    /// # Errors
    /// Rejects mixed identity modes, expired/revoked branches, wrong keys and missing scopes.
    pub fn authenticated_device_identity_for(
        &self,
        capability: &str,
        now: u64,
    ) -> Result<RootQualifiedDeviceRef, NodeCoreError> {
        if let Some(evidence) = &self.custody_authority {
            if self.root_public_key.is_some() || self.signed_device_set.is_some() || self.revoked {
                return Err(NodeCoreError::ItestHttp("mixed or revoked custody authority".into()));
            }
            let authority = ramflux_crypto::custody::verify_publication(evidence, now)
                .map_err(|error| NodeCoreError::ItestHttp(error.to_string()))?;
            let reference = ramflux_protocol::custody::DeviceRef {
                account_anchor: authority.envelope().body.account_anchor.clone(),
                device_id: self.device_id.clone(),
                device_epoch: self.device_epoch,
            };
            let cert = authority
                .authorize(&reference, capability, now)
                .map_err(|error| NodeCoreError::ItestHttp(error.to_string()))?;
            let source = RootQualifiedDeviceRef::from_custody_record(&authority, &self.device_id)
                .map_err(|error| NodeCoreError::ItestHttp(error.to_string()))?;
            if self.principal_id != authority.envelope().body.principal_id
                || self.branch_public_key != cert.branch_signing_public_key
                || self.target_delivery_id != source.storage_key()
            {
                return Err(NodeCoreError::ItestHttp("custody device authority mismatch".into()));
            }
            return Ok(source);
        }
        self.legacy_authenticated_device_identity()
    }

    fn legacy_authenticated_device_identity(
        &self,
    ) -> Result<RootQualifiedDeviceRef, NodeCoreError> {
        let reject =
            || NodeCoreError::ItestHttp("device requires current root-signed authority".into());
        let record = self.signed_device_set.as_ref().ok_or_else(reject)?;
        let root = ramflux_crypto::verifying_key_from_base64url(
            self.root_public_key.as_deref().ok_or_else(reject)?,
        )
        .map_err(|_| reject())?;
        let identity = ramflux_crypto::RootQualifiedDeviceRef::from_signed_device_set(
            &root,
            record,
            &self.device_id,
        )
        .map_err(|_| reject())?;
        let entry = record
            .devices
            .iter()
            .find(|entry| entry.device_id == self.device_id)
            .ok_or_else(reject)?;
        let key = ramflux_crypto::verifying_key_from_base64url(&self.branch_public_key)
            .map_err(|_| reject())?;
        let commitment = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::DEVICE_SIGNING_KEY_COMMITMENT,
            &key.to_bytes(),
        );
        if self.revoked
            || record.principal_id != self.principal_id
            || entry.device_epoch != self.device_epoch
            || entry.status != ramflux_protocol::DeviceSetStatus::Active
            || entry.signing_key_commitment != commitment
        {
            return Err(reject());
        }
        Ok(identity)
    }
}

impl DeviceAuthKeyResponse {
    /// Verify the sender's root claim, principal, device name and branch signature.
    /// # Errors
    /// Rejects an invalid or revoked root-signed entry and inconsistent or forged envelopes.
    pub fn verify_envelope_source(
        &self,
        envelope: &ramflux_protocol::Envelope,
    ) -> Result<RootQualifiedDeviceRef, NodeCoreError> {
        let reject = || NodeCoreError::SourceAuthorityRefused {
            reason_code: crate::EnvelopeAuthorityReason::AuthorityMismatch,
        };
        if self.revoked {
            return Err(NodeCoreError::SourceAuthorityRefused {
                reason_code: crate::EnvelopeAuthorityReason::Revoked,
            });
        }
        let source = self
            .authenticated_device_identity_for("message", crate::now_unix_seconds())
            .map_err(|_| reject())?;
        if envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
            != Some(source.root_commitment())
            || envelope.source_device_id != source.device_id()
            || envelope.source_principal_id != self.principal_id
        {
            return Err(reject());
        }
        let bytes =
            ramflux_protocol::envelope_sender_signed_bytes(envelope).map_err(|_| reject())?;
        ramflux_crypto::verify_canonical_signature(
            &bytes,
            &envelope.signed.signature,
            &self.branch_public_key,
        )
        .map_err(|_| reject())?;
        Ok(source)
    }
    /// Read forwarded public authority only after independently verifying root and sender signatures.
    /// # Errors
    /// Rejects missing or malformed evidence and invalid source attribution.
    pub fn forwarded_envelope_source(
        envelope: &ramflux_protocol::Envelope,
    ) -> Result<(Self, RootQualifiedDeviceRef), NodeCoreError> {
        let value =
            envelope.ext.ext.get("source_device_authority").ok_or_else(|| {
                NodeCoreError::ItestHttp("forwarded source authority missing".into())
            })?;
        let authority: Self = if value.get("custody_authority").is_some_and(|v| !v.is_null()) {
            let bytes = ramflux_protocol::canonical_json_bytes(value)
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
            ramflux_protocol::custody::decode(&bytes, 5 * 1024 * 1024)
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?
        } else {
            serde_json::from_value(value.clone())
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?
        };
        let source = authority.verify_envelope_source(envelope)?;
        Ok((authority, source))
    }
}
