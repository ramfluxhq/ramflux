// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Construct device identities only at the account's authenticated authority boundary.
use super::{invalid, record_key};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError, prekey::SdkDeviceManifestResponse};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::SignedDeviceSetRecord;
impl RamfluxClient {
    /// Return the current device identity authenticated by this account's owned root.
    /// # Errors
    /// Rejects missing owned root/branch state or inconsistent account ownership.
    pub fn owned_device_identity(&self) -> Result<RootQualifiedDeviceRef, SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if let Some(device) = self.own_custody_device(&branch.device_id)? {
            return Ok(device);
        }
        Ok(RootQualifiedDeviceRef::for_owned_device(
            self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            branch,
        )?)
    }
    pub(crate) fn read_device_identity(&self) -> Result<Option<RootQualifiedDeviceRef>, SdkError> {
        if (self.born_v3_account.is_some() || self.identity_root.is_some())
            && self.device_branch.is_some()
        {
            return self.owned_device_identity().map(Some);
        }
        Ok(self.reader_device_identity.clone())
    }
    pub(crate) fn owned_account_device_identity(
        &self,
        selector: &str,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        if let Some(account) = &self.born_v3_account {
            let device = match ramflux_protocol::parse_qualified_device_id(selector)? {
                Some((root, name)) if root == account.record().body.account_anchor => name,
                Some(_) => return Err(invalid("own account device root mismatch")),
                None => selector.to_owned(),
            };
            return self.own_custody_device(&device)?.ok_or(SdkError::IdentityRootMissing);
        }
        let owner = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let device = if let Some((root, name)) =
            ramflux_protocol::parse_qualified_device_id(selector)?
        {
            if root != ramflux_crypto::identity_root_commitment(&owner.signing_key.verifying_key())
            {
                return Err(invalid("own account device root mismatch"));
            }
            name
        } else {
            selector.to_owned()
        };
        Ok(RootQualifiedDeviceRef::for_owned_account_device(owner, &device)?)
    }
    pub(crate) fn local_device_identity(
        &self,
        device: &str,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if branch.device_id != device {
            return Err(invalid("local device context mismatch"));
        }
        self.owned_device_identity()
    }
    pub(crate) fn peer_device_identity(
        &self,
        principal: &str,
        name: &str,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        if self.device_branch.as_ref().is_some_and(|b| b.principal_id == principal) {
            return self.owned_account_device_identity(name);
        }
        if let Some(root) = self
            .account_db()?
            .client_record("identity", principal)?
            .and_then(|record| record["contact_identity_commitment"].as_str().map(str::to_owned))
        {
            if self.observed_device_set(&root)?.is_none_or(|set| set.principal_id != principal) {
                return Err(invalid("peer signed-set principal mismatch"));
            }
            return self.device_identity_for_root(&root, name);
        }
        let manifest: crate::prekey::SdkDeviceManifestResponse = self
            .account_db()?
            .load_actor_state(&format!("identity/manifest/{principal}"))?
            .ok_or_else(|| SdkError::InboundPending("surface peer manifest unavailable".into()))?;
        if manifest.principal_id != principal {
            return Err(invalid("surface peer principal mismatch"));
        }
        self.device_identity_for_root(&manifest.principal_commitment, name)
    }
    pub(crate) fn device_identity(
        &self,
        reference: &str,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        if let Some((root, device)) = ramflux_protocol::parse_qualified_device_id(reference)? {
            self.device_identity_for_root(&root, &device)
        } else {
            self.local_device_identity(reference)
        }
    }
    pub(crate) fn device_identity_for_root(
        &self,
        root: &str,
        device: &str,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        if self.born_v3_account.as_ref().is_some_and(|a| a.record().body.account_anchor == root) {
            return self.own_custody_device(device)?.ok_or(SdkError::IdentityRootMissing);
        }
        if let (Some(own), Some(branch)) = (&self.identity_root, &self.device_branch)
            && branch.device_id == device
            && ramflux_crypto::identity_root_commitment(&own.signing_key.verifying_key()) == root
        {
            return Ok(RootQualifiedDeviceRef::for_owned_device(own, branch)?);
        }
        if let Some(own) = &self.identity_root
            && ramflux_crypto::identity_root_commitment(&own.signing_key.verifying_key()) == root
        {
            return Ok(RootQualifiedDeviceRef::for_owned_account_device(own, device)?);
        }
        let now = u64::try_from(crate::time::now_unix_timestamp())
            .map_err(|_| invalid("invalid authority clock"))?;
        if let Some(authority) = self.current_custody_authority(root, now)? {
            return Ok(RootQualifiedDeviceRef::from_custody_record(&authority, device)?);
        }
        let db = self.account_db()?;
        let record: SignedDeviceSetRecord =
            db.load_actor_state(&record_key(root))?.ok_or_else(|| {
                SdkError::InboundPending("signed device authority unavailable".into())
            })?;
        let public = if let Some(own) = &self.identity_root
            && ramflux_crypto::identity_root_commitment(&own.signing_key.verifying_key()) == root
        {
            own.signing_key.verifying_key()
        } else {
            let manifest: SdkDeviceManifestResponse = if let Some(manifest) =
                db.load_actor_state(&format!("identity/manifest-root/{root}"))?
            {
                manifest
            } else {
                self.legacy_root_manifest(root, &record.principal_id)?.ok_or_else(|| {
                    SdkError::InboundPending("verified root manifest unavailable".into())
                })?
            };
            if manifest.principal_commitment != root {
                return Err(invalid("manifest root mismatch"));
            }
            ramflux_crypto::verifying_key_from_base64url(&manifest.root_public_key)?
        };
        if record.principal_commitment != root {
            return Err(invalid("signed authority root mismatch"));
        }
        Ok(RootQualifiedDeviceRef::from_signed_device_set(&public, &record, device)?)
    }
    fn legacy_root_manifest(
        &self,
        root: &str,
        principal: &str,
    ) -> Result<Option<SdkDeviceManifestResponse>, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<SdkDeviceManifestResponse>(&format!(
                "identity/manifest/{principal}"
            ))?
            .filter(|manifest| manifest.principal_commitment == root))
    }
    pub(crate) fn device_identity_from_manifest(
        manifest: &SdkDeviceManifestResponse,
        name: &str,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        super::verify_manifest(manifest, &manifest.principal_commitment)?;
        let public = ramflux_crypto::verifying_key_from_base64url(&manifest.root_public_key)?;
        Ok(RootQualifiedDeviceRef::from_signed_device_set(
            &public,
            manifest.signed_device_set.as_ref().ok_or_else(|| invalid("missing signed set"))?,
            name,
        )?)
    }
    pub(crate) fn authenticated_device_identity(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        self.authenticated_envelope_sender(entry)?;
        let encoded = self.inbound_device_reference(entry)?;
        let (root, device) = ramflux_protocol::parse_qualified_device_id(&encoded)?
            .ok_or_else(|| invalid("authenticated device requires root authority"))?;
        self.device_identity_for_root(&root, &device)
    }
}
