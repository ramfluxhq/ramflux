// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-signed public profile publication and verified read-model access.
use super::{invalid, record_key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{PrincipalKind, SignedDeviceSetRecord, SignedIdentityProfile};
const DESIRED: &str = "identity/owned_public_profile";
impl RamfluxClient {
    /// Changes the public name, distinct from private account labels. The next device-set
    /// publication carries it; this call does not acknowledge a server publication.
    /// # Errors
    /// Requires the current root signer; rejects unsafe names, exhausted epochs or storage errors.
    pub fn set_identity_display_name(&self, name: &str) -> Result<SignedIdentityProfile, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let commitment =
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
        let old = self.observed_device_set(&commitment)?;
        let desired = self.account_db()?.load_actor_state::<SignedIdentityProfile>(DESIRED)?;
        let epoch = old
            .as_ref()
            .and_then(|r| r.profile.as_ref())
            .map_or(0, |p| p.epoch)
            .max(desired.as_ref().map_or(0, |p| p.epoch))
            .checked_add(1)
            .ok_or_else(|| invalid("profile epoch exhausted"))?;
        let profile =
            ramflux_crypto::sign_identity_profile(root, self.local_principal_kind()?, name, epoch)?;
        self.account_db()?.persist_actor_state(DESIRED, &profile)?;
        Ok(profile)
    }
    pub(super) fn owned_public_profile(
        &self,
        previous: Option<&SignedDeviceSetRecord>,
    ) -> Result<Option<SignedIdentityProfile>, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let kind = self.local_principal_kind()?;
        // Legacy workflow principals have no profile in this version of the public contract.
        if kind == PrincipalKind::Workflow {
            return Ok(None);
        }
        let old = previous.and_then(|r| r.profile.as_deref());
        if let Some(profile) =
            self.account_db()?.load_actor_state::<SignedIdentityProfile>(DESIRED)?
        {
            ramflux_crypto::verify_identity_profile(&root.signing_key.verifying_key(), &profile)?;
            if profile.principal_id != root.principal_id || profile.kind != kind {
                return Err(invalid("owned profile owner or kind mismatch"));
            }
            if old.is_some_and(|old| profile.epoch == old.epoch && &profile != old) {
                return Err(invalid(
                    "owned profile epoch conflicts with an acknowledged publication",
                ));
            }
            if old.is_none_or(|old| profile.epoch > old.epoch) {
                return Ok(Some(profile));
            }
        }
        if let Some(old) = old {
            return Ok(Some(old.clone()));
        }
        let name = ramflux_protocol::normalize_profile_display_name(&root.principal_id)
            .unwrap_or_else(|_| "Account".to_owned());
        Ok(Some(ramflux_crypto::sign_identity_profile(root, kind, &name, 1)?))
    }
    pub(super) fn persist_owned_profile_metadata(
        &self,
        record: &SignedDeviceSetRecord,
    ) -> Result<(), SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let db = self.account_db()?;
        db.persist_actor_state(
            &format!("identity/root_public/{}", record.principal_commitment),
            &ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes()),
        )?;
        let mut row=db.client_record("identity",&record.principal_id)?.unwrap_or_else(||serde_json::json!({"id":record.principal_id,"principal_id":record.principal_id,"is_self":true,"contact_identity_commitment":record.principal_commitment}));
        if let Some(profile) = &record.profile {
            row["display_name"] = serde_json::json!(profile.display_name);
            row["kind"] = serde_json::json!(profile.kind);
            row["kind_asserted"] = serde_json::json!(profile.kind);
            row["kind_verified"] = serde_json::json!(true);
        }
        db.persist_client_record("identity", &record.principal_id, &row)?;
        Ok(())
    }
    /// Returns a cryptographically authenticated root statement. It is independent of manual
    /// contact verification and is not proof that a human claim describes a biological human.
    /// # Errors
    /// Returns storage/authentication errors. Legacy or unknown profiles return None.
    pub fn verified_identity_profile(
        &self,
        principal: &str,
    ) -> Result<Option<SignedIdentityProfile>, SdkError> {
        let db = self.account_db()?;
        let Some(row) = db.client_record("identity", principal)? else { return Ok(None) };
        let Some(commitment) = row["contact_identity_commitment"].as_str() else { return Ok(None) };
        let Some(record) = db.load_actor_state::<SignedDeviceSetRecord>(&record_key(commitment))?
        else {
            return Ok(None);
        };
        if record.principal_id != principal || record.principal_commitment != commitment {
            return Err(invalid("profile cache ownership mismatch"));
        }
        let Some(profile) = record.profile.as_deref() else { return Ok(None) };
        let public = if let Some(root) =
            self.identity_root.as_ref().filter(|r| r.principal_id == principal)
        {
            root.signing_key.verifying_key()
        } else {
            let encoded = if let Some(manifest) = db
                .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
                    "identity/manifest-root/{commitment}"
                ))? {
                manifest.root_public_key
            } else if let Some(public) =
                db.load_actor_state::<String>(&format!("identity/root_public/{commitment}"))?
            {
                public
            } else {
                return Ok(None);
            };
            ramflux_crypto::verifying_key_from_base64url(&encoded)?
        };
        ramflux_crypto::verify_signed_device_set(&public, &record)?;
        Ok(Some(profile.clone()))
    }
}
