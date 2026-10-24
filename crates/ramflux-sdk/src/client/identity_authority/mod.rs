// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-authenticated device authority, monotonic observation and local root publication.
mod device_identity;
pub(crate) mod device_namespace;
mod directory;
mod owned;
mod publication;
mod reconcile;
pub(crate) mod registration;
mod verify;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{PrincipalKind, SignedDeviceSetRecord};
pub(crate) use verify::{verify_manifest, verify_manifest_authority};
pub(crate) fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(format!("identity authority: {reason}"))
}
pub(crate) fn record_key(commitment: &str) -> String {
    format!("identity/signed_set/{commitment}")
}
pub(crate) fn set_fingerprint(record: &SignedDeviceSetRecord) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.sdk.verified_device_authority.v1",
        &ramflux_protocol::canonical_json_bytes(&(
            &record.principal_commitment,
            record.principal_kind,
            &record.devices,
        ))?,
    ))
}
impl RamfluxClient {
    /// Returns an authenticated root assertion. It does not attest that a root holder is human.
    /// # Errors
    /// Returns storage errors. Unknown/legacy identities return None.
    pub fn root_asserted_principal_kind(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalKind>, SdkError> {
        let Some(identity) = self.account_db()?.client_record("identity", principal)? else {
            return Ok(None);
        };
        let Some(commitment) = identity["contact_identity_commitment"].as_str() else {
            return Ok(None);
        };
        let record = self
            .account_db()?
            .load_actor_state::<SignedDeviceSetRecord>(&record_key(commitment))?;
        Ok(record.filter(|r| r.principal_id == principal).map(|r| r.principal_kind))
    }
    /// Returns a signed kind only after the user verified this contact's current safety material.
    /// # Errors
    /// Returns storage errors. An unverified, stale or legacy contact returns None.
    pub fn verified_principal_kind(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalKind>, SdkError> {
        let Some(identity) = self.account_db()?.client_record("identity", principal)? else {
            return Ok(None);
        };
        let Some(commitment) = identity["contact_identity_commitment"].as_str() else {
            return Ok(None);
        };
        let verified = self.account_db()?.contact_verification(commitment)?.is_some_and(|v| {
            v.verification_state == "verified"
                && identity["device_set_hash"].as_str() == Some(v.verified_device_set_hash.as_str())
        });
        let record = self.observed_device_set(commitment)?;
        let stamp = self
            .account_db()?
            .load_actor_state::<String>(&format!("identity/safety_verified_set/{commitment}"))?;
        let authority_verified = record
            .as_ref()
            .map(set_fingerprint)
            .transpose()?
            .is_some_and(|hash| stamp.as_ref() == Some(&hash));
        if verified && authority_verified {
            self.root_asserted_principal_kind(principal)
        } else {
            Ok(None)
        }
    }
    /// Verify and atomically cache a live manifest, including rollback and key lifecycle checks.
    /// # Errors
    /// Rejects legacy authority, substitution, rollback, ownership changes or storage failures.
    pub fn observe_device_manifest_json(
        &self,
        value: serde_json::Value,
        expected: &str,
    ) -> Result<(), SdkError> {
        let manifest = serde_json::from_value(value)?;
        verify::verify_manifest_authority(&manifest, expected)?;
        self.persist_identity_directory(&manifest)
    }
}

impl RamfluxClient {
    pub(crate) fn root_qualified_device_lookup(&self, device: &str) -> Result<String, SdkError> {
        let identity = self.device_identity(device)?;
        self.require_cached_root_authority(&identity)?;
        Ok(identity.storage_key().into())
    }

    pub(crate) fn require_cached_root_authority(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        let device = identity.storage_key();
        let raw = identity.device_id();
        let db = self.account_db()?;
        if db.load_actor_state::<bool>(&Self::device_revocation_key(identity))?.unwrap_or(false) {
            return Err(invalid("device is locally fenced by a pending root revocation"));
        }
        let row =
            db.client_record("device", device)?.ok_or_else(|| invalid("device metadata absent"))?;
        let commitment = row["principal_commitment"]
            .as_str()
            .ok_or_else(|| invalid("legacy device has no root authority"))?;
        let record = db
            .load_actor_state::<SignedDeviceSetRecord>(&record_key(commitment))?
            .ok_or_else(|| invalid("legacy device is read-only; refresh root-bound manifest"))?;
        let signing =
            row["signing_public_key"].as_str().ok_or_else(|| invalid("device key unavailable"))?;
        let agreement: [u8; 32] = serde_json::from_value(row["x25519_identity_public"].clone())?;
        let keys = ramflux_crypto::device_key_commitments(
            signing,
            &ramflux_protocol::encode_base64url(agreement),
        )?;
        if record.principal_id != row["principal_id"]
            || !record.devices.iter().any(|e| {
                e.device_id == raw
                    && e.status == ramflux_protocol::DeviceSetStatus::Active
                    && e.signing_key_commitment == keys.0
                    && e.agreement_key_commitment == keys.1
                    && row["device_epoch"] == e.device_epoch
            })
        {
            return Err(invalid("device key is revoked or superseded"));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
