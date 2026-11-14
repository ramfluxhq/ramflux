// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified out-of-band safety material without changing an existing contact pin.
use crate::ContactReason;
use crate::prelude::*;
impl RamfluxClient {
    pub(crate) fn resolve_contact_safety(
        &self,
        identity: &mut serde_json::Value,
        own: &SdkDeviceManifestResponse,
        peer: &SdkDeviceManifestResponse,
        verification: Option<&SdkContactSafetyNumber>,
        device: &str,
    ) -> Result<(), SdkError> {
        let own_material = super::contact::contact_safety_material_from_manifest(own)?;
        let peer_material = super::contact::contact_safety_material_from_manifest(peer)?;
        self.capture_contact_safety(
            identity,
            &peer.principal_commitment,
            &own_material,
            &peer_material,
        )?;
        if let Some(safety) = verification {
            self.commit_contact_safety(safety, &own_material, &peer_material, device)?;
            identity["root_source"] = serde_json::json!(crate::ContactRootSource::Verified);
        }
        Ok(())
    }

    pub(crate) fn capture_contact_safety(
        &self,
        identity: &mut serde_json::Value,
        peer: &str,
        own_material: &ramflux_crypto::ContactSafetyMaterial,
        peer_material: &ramflux_crypto::ContactSafetyMaterial,
    ) -> Result<(), SdkError> {
        let (number, version) = if self.born_v3_account.is_some() {
            (self.native_safety_number(peer)?.safety_number, 2)
        } else {
            (ramflux_crypto::safety_number(own_material, peer_material), 1)
        };
        identity["safety_number"] = serde_json::json!(number);
        identity["safety_number_algorithm_version"] = serde_json::json!(version);
        Ok(())
    }
    pub(crate) fn commit_contact_safety(
        &self,
        safety: &SdkContactSafetyNumber,
        own: &ramflux_crypto::ContactSafetyMaterial,
        peer: &ramflux_crypto::ContactSafetyMaterial,
        device: &str,
    ) -> Result<(), SdkError> {
        if self.born_v3_account.is_some() {
            let current = self.native_safety_number(&safety.contact_identity_commitment)?;
            if safety.algorithm_version != 2
                || safety.self_identity_commitment != current.self_identity_commitment
                || safety.safety_number_hash != current.safety_number_hash
                || safety.contact_device_set_hash != current.contact_device_set_hash
            {
                return Err(ContactReason::RootConflict.into());
            }
            Self::record_contact_safety_verified(
                &safety.contact_identity_commitment,
                device,
                &current,
            )?;
            return Ok(());
        }
        let hash =
            ramflux_protocol::encode_base64url(ramflux_crypto::safety_fingerprint(own, peer));
        let device_set =
            ramflux_protocol::encode_base64url(ramflux_crypto::device_set_hash(&peer.devices));
        if hash != safety.safety_number_hash || device_set != safety.contact_device_set_hash {
            return Err(ContactReason::RootConflict.into());
        }
        // The shared writer records the confirmation and complete authority stamp atomically.
        Self::record_contact_safety_verified(&safety.contact_identity_commitment, device, safety)?;
        Ok(())
    }

    pub(crate) async fn preview_contact_safety(
        &self,
        gateway: &GatewaySessionConfig,
        principal: &str,
        root: &str,
    ) -> Result<serde_json::Value, SdkError> {
        let old = self
            .account_db()?
            .client_record("identity", principal)?
            .ok_or(ContactReason::UnknownPrincipal)?;
        if old["contact_identity_commitment"].as_str() != Some(root)
            && self.contact_root_source(&old)? != crate::ContactRootSource::Lookup
        {
            return Err(ContactReason::RootConflict.into());
        }
        let own_root = self.own_account_anchor()?;
        let fetch = |root: String| async move {
            let manifest: Option<SdkDeviceManifestResponse> =
                sdk_gateway_get_json(gateway, &format!("/mvp1/device-manifest/{root}"))
                    .await
                    .map_err(super::contact_resolution::lookup_failure)?;
            let manifest = manifest.ok_or(ContactReason::UnknownPrincipal)?;
            super::contact::verify_device_manifest(&manifest, &root)
                .map_err(|_| SdkError::ContactInput(ContactReason::ManifestInvalid))?;
            Ok::<_, SdkError>(manifest)
        };
        let peer = fetch(root.to_owned()).await?;
        if peer.principal_id != principal {
            return Err(ContactReason::RootConflict.into());
        }
        let own = fetch(own_root.clone()).await?;
        if self.born_v3_account.is_some() {
            let verify = |manifest: &SdkDeviceManifestResponse| -> Result<_, SdkError> {
                let native = manifest.custody.as_ref().ok_or(SdkError::CustodyModeDowngrade)?;
                ramflux_crypto::custody::verify_publication(
                    &ramflux_protocol::custody::CustodyAuthority {
                        publication: native.publication.clone(),
                        custodian_publication: native.custodian_publication.clone(),
                    },
                    crate::custody::network_now()?,
                )
                .map_err(SdkError::from)
            };
            let _ = verify(&own)?;
            let _ = verify(&peer)?;
        }
        // Nothing is stored until compare-and-record commits. The expectation is computed
        // from these held manifests.
        self.held_manifests.borrow_mut().insert(own.principal_commitment.clone(), own);
        self.held_manifests.borrow_mut().insert(peer.principal_commitment.clone(), peer);
        super::contact_verification_cas::compared_safety_json(self, root)
    }
}
