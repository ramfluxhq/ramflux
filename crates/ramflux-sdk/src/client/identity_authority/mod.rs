// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-authenticated device authority, monotonic observation and local root publication.
mod directory;
mod owned;
mod publication;
mod verify;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{PrincipalKind, SignedDeviceSetRecord};
pub(crate) use verify::verify_manifest;
pub(crate) fn invalid(reason: &str) -> SdkError {
    SdkError::InboundRejected(format!("identity authority: {reason}"))
}
pub(crate) fn record_key(commitment: &str) -> String {
    format!("identity/signed_set/{commitment}")
}
impl RamfluxClient {
    /// Returns only an authenticated, persisted root assertion, never a display label or mode.
    /// # Errors
    /// Returns storage errors. Unknown/legacy identities return None.
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
        let record = self
            .account_db()?
            .load_actor_state::<SignedDeviceSetRecord>(&record_key(commitment))?;
        Ok(record.filter(|r| r.principal_id == principal).map(|r| r.principal_kind))
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
        verify_manifest(&manifest, expected)?;
        self.persist_identity_directory(&manifest)
    }
}

impl RamfluxClient {
    pub(crate) fn require_cached_root_authority(&self, device: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
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
                e.device_id == device
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
