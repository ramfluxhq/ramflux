// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified out-of-band safety material without changing an existing contact pin.
use crate::ContactReason;
use crate::prelude::*;

/// Unconfirmed previews keep at most this many manifests until release or commit.
pub(crate) const HELD_MANIFEST_CAP: usize = 32;

impl RamfluxClient {
    pub(crate) fn resolve_contact_safety(
        &self,
        identity: &mut serde_json::Value,
        _own: &SdkDeviceManifestResponse,
        peer: &SdkDeviceManifestResponse,
        verification: Option<&SdkContactSafetyNumber>,
        device: &str,
    ) -> Result<(), SdkError> {
        self.capture_contact_safety(identity, &peer.principal_commitment)?;
        if let Some(safety) = verification {
            self.commit_contact_safety(safety, device)?;
            identity["root_source"] = serde_json::json!(crate::ContactRootSource::Verified);
        }
        Ok(())
    }

    pub(crate) fn capture_contact_safety(
        &self,
        identity: &mut serde_json::Value,
        peer: &str,
    ) -> Result<(), SdkError> {
        if self.born_v3_account.is_none() {
            return Err(SdkError::CustodyModeDowngrade);
        }
        let number = self.native_safety_number(peer)?.safety_number;
        identity["safety_number"] = serde_json::json!(number);
        identity["safety_number_algorithm_version"] = serde_json::json!(2);
        Ok(())
    }
    pub(crate) fn commit_contact_safety(
        &self,
        safety: &SdkContactSafetyNumber,
        device: &str,
    ) -> Result<(), SdkError> {
        if self.born_v3_account.is_none() {
            return Err(SdkError::CustodyModeDowngrade);
        }
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
        Ok(())
    }

    pub(crate) fn hold_compared_manifests(
        &self,
        manifests: impl IntoIterator<Item = SdkDeviceManifestResponse>,
    ) -> Result<(), SdkError> {
        let incoming = manifests.into_iter().collect::<Vec<_>>();
        let mut held = self.held_manifests.borrow_mut();
        let extra = incoming
            .iter()
            .filter(|manifest| !held.contains_key(&manifest.principal_commitment))
            .count();
        if held.len().saturating_add(extra) > HELD_MANIFEST_CAP {
            return Err(SdkError::InboundRejected("held manifest cap exceeded".into()));
        }
        for manifest in incoming {
            held.insert(manifest.principal_commitment.clone(), manifest);
        }
        Ok(())
    }

    /// Drop every unconfirmed hold so a later preview can use the cap again.
    pub(crate) fn release_held_manifests(&self) {
        self.held_manifests.borrow_mut().clear();
    }

    pub(crate) async fn preview_contact_safety(
        &self,
        gateway: &GatewaySessionConfig,
        principal: &str,
        root: &str,
    ) -> Result<serde_json::Value, SdkError> {
        if self.born_v3_account.is_none() {
            return Err(SdkError::CustodyModeDowngrade);
        }
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
        let peer = self.peer_device_manifest(gateway, root).await.map_err(|error| {
            if peer_manifest_missing(&error) {
                SdkError::from(ContactReason::UnknownPrincipal)
            } else {
                super::contact_resolution::lookup_failure(error)
            }
        })?;
        if peer.principal_id != principal {
            return Err(ContactReason::RootConflict.into());
        }
        let own = own_safety_manifest(gateway, &own_root).await?;
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
        // Nothing is stored until compare-and-record commits. The expectation is computed
        // from these held manifests.
        self.hold_compared_manifests([own, peer])?;
        super::contact_verification_cas::compared_safety_json(self, root)
    }
}

fn peer_manifest_missing(error: &SdkError) -> bool {
    match error {
        SdkError::LocalBus(message) => message.starts_with("missing device manifest for "),
        SdkError::InboundRejected(message) => message == "device manifest unavailable",
        _ => false,
    }
}

async fn own_safety_manifest(
    gateway: &GatewaySessionConfig,
    root: &str,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    let started = std::time::Instant::now();
    let manifest: Option<SdkDeviceManifestResponse> =
        sdk_gateway_get_json(gateway, &format!("/mvp1/device-manifest/{root}"))
            .await
            .map_err(super::contact_resolution::lookup_failure)?;
    let manifest = manifest.ok_or(ContactReason::UnknownPrincipal)?.fetched_from(started);
    super::contact::verify_device_manifest(&manifest, root)
        .map_err(|_| SdkError::ContactInput(ContactReason::ManifestInvalid))?;
    Ok(manifest)
}
