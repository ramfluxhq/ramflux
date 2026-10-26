// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified out-of-band safety material without changing an existing contact pin.
use crate::ContactReason;
use crate::prelude::*;
impl RamfluxClient {
    // Reader pools have no private keys or gateway access. Use only the exact cached
    // root-authenticated sets, never the synthetic legacy safety material fallback.
    pub(crate) fn cached_contact_safety_digits(
        &self,
        peer: &str,
    ) -> Result<Option<Vec<String>>, SdkError> {
        let Some(own) = self.read_device_identity()? else {
            return Ok(None);
        };
        if peer == own.root_commitment() {
            return Ok(None);
        }
        let material =
            |root: &str| -> Result<Option<ramflux_crypto::ContactSafetyMaterial>, SdkError> {
                let Some(manifest) =
                    self.account_db()?.load_actor_state::<SdkDeviceManifestResponse>(&format!(
                        "identity/manifest-root/{root}"
                    ))?
                else {
                    return Ok(None);
                };
                super::identity_authority::verify_manifest_authority(&manifest, root)?;
                if manifest.signed_device_set != self.observed_device_set(root)? {
                    return Ok(None);
                }
                super::contact::contact_safety_material_from_manifest(&manifest).map(Some)
            };
        let (Some(own), Some(peer)) = (material(own.root_commitment())?, material(peer)?) else {
            return Ok(None);
        };
        Ok(Some(ramflux_crypto::safety_number(&own, &peer)))
    }

    pub(crate) fn commit_contact_safety(
        &self,
        safety: &SdkContactSafetyNumber,
        own: &ramflux_crypto::ContactSafetyMaterial,
        peer: &ramflux_crypto::ContactSafetyMaterial,
        device: &str,
    ) -> Result<(), SdkError> {
        let hash =
            ramflux_protocol::encode_base64url(ramflux_crypto::safety_fingerprint(own, peer));
        let device_set =
            ramflux_protocol::encode_base64url(ramflux_crypto::device_set_hash(&peer.devices));
        if hash != safety.safety_number_hash || device_set != safety.contact_device_set_hash {
            return Err(ContactReason::RootConflict.into());
        }
        // The shared writer records the confirmation and complete authority stamp atomically.
        self.record_contact_safety_verified(&safety.contact_identity_commitment, device, safety)?;
        Ok(())
    }

    pub(crate) async fn preview_contact_safety(
        &self,
        gateway: &GatewaySessionConfig,
        principal: &str,
        root: &str,
    ) -> Result<SdkContactSafetyNumber, SdkError> {
        let old = self
            .account_db()?
            .client_record("identity", principal)?
            .ok_or(ContactReason::UnknownPrincipal)?;
        if old["contact_identity_commitment"].as_str() != Some(root)
            && self.contact_root_source(&old)? != crate::ContactRootSource::Lookup
        {
            return Err(ContactReason::RootConflict.into());
        }
        let own = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let own_root = identity_root_public_key_commitment(&ramflux_protocol::encode_base64url(
            own.signing_key.verifying_key().to_bytes(),
        ))?;
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
        let a = super::contact::contact_safety_material_from_manifest(&own)?;
        let b = super::contact::contact_safety_material_from_manifest(&peer)?;
        let fingerprint = ramflux_crypto::safety_fingerprint(&a, &b);
        Ok(SdkContactSafetyNumber {
            contact_identity_commitment: root.into(),
            self_identity_commitment: own_root,
            safety_number: ramflux_crypto::safety_number(&a, &b),
            fingerprint_hex: super::contact::bytes_to_hex(&fingerprint),
            safety_number_hash: ramflux_protocol::encode_base64url(fingerprint),
            self_device_count: a.devices.len(),
            contact_device_count: b.devices.len(),
            contact_device_set_hash: ramflux_protocol::encode_base64url(
                ramflux_crypto::device_set_hash(&b.devices),
            ),
            contact_lineage_head: ramflux_protocol::encode_base64url(&b.lineage_head),
            verification_state: "unverified".into(),
        })
    }
}
