// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current native authority for the ordinary registry's device and session interfaces.
use super::{CustodyPublication, IdentityRegistry, NodeCoreError, crypto};
use ramflux_crypto::{RootQualifiedDeviceRef, custody::VerifiedRecord};
use ramflux_protocol::custody::{CustodyAuthority, DeviceRef, Publication};

fn publication(value: &CustodyPublication) -> Publication {
    Publication { record: value.record.clone(), compacted_ids: value.compacted_ids.clone() }
}
impl IdentityRegistry {
    pub(crate) fn custody_anchor_known(&self, anchor: &str) -> bool {
        !self.custody.permits_legacy(anchor)
    }

    pub(crate) fn custody_anchor_for_principal(&self, principal: &str) -> Option<&str> {
        let public =
            ramflux_crypto::verifying_key_from_base64url(self.bound_principal_root(principal)?)
                .ok()?;
        let anchor = ramflux_crypto::identity_root_commitment(&public);
        let (anchor, publication) = self.custody.records.get_key_value(&anchor)?;
        (publication.record.body.principal_id == principal).then_some(anchor.as_str())
    }

    pub(crate) fn custody_authority(
        &self,
        anchor: &str,
        now: u64,
    ) -> Result<Option<(CustodyAuthority, VerifiedRecord)>, NodeCoreError> {
        let Some(record) = self.custody.records.get(anchor) else { return Ok(None) };
        let verified = self.verify_custody(record, now)?;
        self.custody.require_current(&verified).map_err(|error| crypto(&error))?;
        let master = &record.record.body.master_certificate.body;
        let custodian =
            if master.custody_kind == ramflux_protocol::custody::CustodyKind::ExternalHuman {
                Some(publication(
                    self.custody
                        .records
                        .get(&master.primary_device_ref.account_anchor)
                        .ok_or_else(|| super::reject("current human custodian unavailable"))?,
                ))
            } else {
                None
            };
        Ok(Some((
            CustodyAuthority { publication: publication(record), custodian_publication: custodian },
            verified,
        )))
    }

    pub(crate) fn custody_device_auth_key(
        &self,
        identity: &RootQualifiedDeviceRef,
        now: u64,
    ) -> Result<Option<crate::DeviceAuthKeyResponse>, NodeCoreError> {
        let Some((evidence, verified)) = self.custody_authority(identity.root_commitment(), now)?
        else {
            return Ok(None);
        };
        let Some(entry) = verified
            .envelope()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == identity.device_id())
        else {
            return Ok(None);
        };
        let reference = DeviceRef {
            account_anchor: identity.root_commitment().into(),
            device_id: identity.device_id().into(),
            device_epoch: entry.device_epoch,
        };
        let cert =
            verified.authorize(&reference, "register", now).map_err(|error| crypto(&error))?;
        Ok(Some(crate::DeviceAuthKeyResponse {
            custody_authority: Some(Box::new(evidence)),
            root_public_key: None,
            signed_device_set: None,
            principal_id: verified.envelope().body.principal_id.clone(),
            device_id: identity.device_id().into(),
            device_epoch: reference.device_epoch,
            branch_public_key: cert.branch_signing_public_key.clone(),
            target_delivery_id: identity.storage_key().into(),
            revoked: false,
        }))
    }

    pub(crate) fn custody_device_identity(
        &self,
        anchor: &str,
        name: &str,
    ) -> Option<RootQualifiedDeviceRef> {
        let (_, verified) = self.custody_authority(anchor, crate::now_unix_seconds()).ok()??;
        RootQualifiedDeviceRef::from_custody_record(&verified, name).ok()
    }
}

impl super::RouterCore {
    /// Resolve an exact retained public head for delayed consent, never for current authorization.
    /// # Errors
    /// Rejects fenced current authority, malformed selectors and durable store failures.
    pub fn custody_consent_history(
        &self,
        anchor: &str,
        record_hash: &str,
        now: u64,
        store: &super::RouterRedbStore,
    ) -> Result<Option<CustodyPublication>, NodeCoreError> {
        let Some(current) = self.custody_record(anchor, now)? else {
            return Ok(None);
        };
        if ramflux_protocol::custody::object_hash(&current.record)
            .map_err(|e| super::reject(&e.to_string()))?
            == record_hash
        {
            return Ok(Some(current));
        }
        store.custody_historical_publication(anchor, record_hash, now)
    }

    /// Fetch native current authority and registered prekeys for an account anchor.
    /// # Errors
    /// Rejects fenced authority, substituted prekeys, excessive response size and store failure.
    pub fn custody_manifest(
        &self,
        anchor: &str,
        now: u64,
        store: &super::RouterRedbStore,
    ) -> Result<Option<ramflux_protocol::custody::CustodyManifest>, NodeCoreError> {
        use ramflux_protocol::custody::{CustodyManifest, CustodyManifestDevice};
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((authority, verified)) = control.mvp1_identities.custody_authority(anchor, now)?
        else {
            return Ok(None);
        };
        let mut manifest = CustodyManifest {
            publication: authority.publication,
            custodian_publication: authority.custodian_publication,
            devices: Vec::new(),
        };
        let mut bytes = ramflux_protocol::canonical_json_bytes(&manifest)
            .map_err(|error| super::reject(&error.to_string()))?
            .len();
        for entry in &verified.envelope().body.devices {
            let reference = DeviceRef {
                account_anchor: anchor.into(),
                device_id: entry.device_id.clone(),
                device_epoch: entry.device_epoch,
            };
            let Ok(certificate) = verified.authorize(&reference, "message", now) else { continue };
            let identity = RootQualifiedDeviceRef::from_custody_record(&verified, &entry.device_id)
                .map_err(|error| crypto(&error))?;
            let Some(bundle) = store.custody_prekey(identity.storage_key())? else { continue };
            verify_bundle(&verified, certificate, &reference, &bundle)?;
            let device = CustodyManifestDevice {
                device_ref: reference,
                target_delivery_id: identity.storage_key().into(),
                prekey_bundle: bundle,
            };
            bytes = bytes
                .checked_add(
                    ramflux_protocol::canonical_json_bytes(&device)
                        .map_err(|error| super::reject(&error.to_string()))?
                        .len()
                        + 1,
                )
                .ok_or(NodeCoreError::Capacity { resource: "custody directory manifest" })?;
            if bytes > ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES - 16 * 1024 {
                return Err(NodeCoreError::Capacity { resource: "custody directory manifest" });
            }
            manifest.devices.push(device);
        }
        Ok(Some(manifest))
    }

    /// Fetch an account's ordinary directory view from its current authority scheme.
    /// # Errors
    /// Rejects native authority and storage errors without falling back to a legacy view.
    pub fn ordinary_device_manifest(
        &self,
        anchor: &str,
        now: u64,
        store: &super::RouterRedbStore,
    ) -> Result<Option<crate::DeviceManifestResponse>, NodeCoreError> {
        if let Some(native) = self.custody_manifest(anchor, now, store)? {
            return Ok(Some(crate::DeviceManifestResponse {
                signed_device_set: None,
                principal_id: native.publication.record.body.principal_id.clone(),
                principal_commitment: native.publication.record.body.account_anchor.clone(),
                root_public_key: native
                    .publication
                    .record
                    .body
                    .master_certificate
                    .body
                    .master_public_key
                    .clone(),
                devices: Vec::new(),
                custody: Some(Box::new(native)),
            }));
        }
        let native = self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .mvp1_identities
            .custody_anchor_known(anchor);
        if native {
            return Err(super::reject("native account authority unavailable"));
        }
        Ok(self.mvp1_device_manifest(anchor))
    }

    /// Use the ordinary authenticated lookup and quotas for either current authority scheme.
    /// # Errors
    /// Rejects native authority or storage failure without reporting a missing principal.
    pub fn authenticated_principal_lookup(
        &self,
        request: &crate::PrincipalLookupRequest,
        now: u64,
        store: &super::RouterRedbStore,
    ) -> Result<
        ramflux_protocol::PrincipalLookupResponse<crate::DeviceManifestResponse>,
        NodeCoreError,
    > {
        let mut response = self.mvp1_authenticated_principal_lookup(request, now);
        if response.reason_code.is_some() {
            return Ok(response);
        }
        let anchor = {
            let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            control
                .mvp1_identities
                .custody_anchor_for_principal(&request.principal_id)
                .map(str::to_owned)
        };
        if let Some(anchor) = anchor {
            response.manifest = self.ordinary_device_manifest(&anchor, now, store)?;
        }
        Ok(response)
    }
}

fn verify_bundle(
    authority: &VerifiedRecord,
    certificate: &ramflux_protocol::custody::BranchCertificate,
    reference: &DeviceRef,
    value: &serde_json::Value,
) -> Result<(), NodeCoreError> {
    let bytes = ramflux_protocol::canonical_json_bytes(value)
        .map_err(|error| super::reject(&error.to_string()))?;
    let bundle: ramflux_crypto::PrekeyBundle = ramflux_protocol::custody::decode(&bytes, 64 * 1024)
        .map_err(|error| super::reject(&error.to_string()))?;
    if bundle.device_id != reference.device_id
        || bundle.device_epoch != reference.device_epoch
        || bundle.identity_commitment != authority.envelope().body.principal_id
        || bundle.device_identity_ed25519_public != certificate.branch_signing_public_key
        || bundle.identity_key != bundle.device_agreement_x25519_public
        || ramflux_protocol::encode_base64url(bundle.identity_key)
            != certificate.agreement_identity_public_key
    {
        return Err(super::reject("custody directory prekey binding mismatch"));
    }
    let key = ramflux_crypto::verifying_key_from_base64url(&certificate.branch_signing_public_key)
        .map_err(|error| crypto(&error))?;
    ramflux_crypto::verify_prekey_bundle(&key, &bundle).map_err(|error| crypto(&error))
}

impl super::RouterCore {
    /// Read a branch's native prekey material through the ordinary prekey endpoint.
    /// # Errors
    /// Rejects revoked/expired authority, inconsistent key material and storage failure.
    pub fn custody_prekey_response(
        &self,
        selector: &str,
        now: u64,
        store: &super::RouterRedbStore,
    ) -> Result<Option<crate::PrekeyResponse>, NodeCoreError> {
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let registry = &control.mvp1_identities;
        let Some(identity) = registry.resolve_device_selector(selector) else { return Ok(None) };
        let Some((_, authority)) = registry.custody_authority(identity.root_commitment(), now)?
        else {
            return Ok(None);
        };
        let entry = authority
            .envelope()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == identity.device_id())
            .ok_or_else(|| super::reject("custody branch missing"))?;
        let reference = DeviceRef {
            account_anchor: identity.root_commitment().into(),
            device_id: identity.device_id().into(),
            device_epoch: entry.device_epoch,
        };
        let cert =
            authority.authorize(&reference, "message", now).map_err(|error| crypto(&error))?;
        let bundle = store
            .custody_prekey(identity.storage_key())?
            .map(|value| {
                verify_bundle(&authority, cert, &reference, &value)?;
                serde_json::from_value(value).map_err(|error| super::reject(&error.to_string()))
            })
            .transpose()?;
        Ok(Some(crate::PrekeyResponse {
            device_id: identity.device_id().into(),
            principal_commitment: identity.root_commitment().into(),
            target_delivery_id: Some(identity.storage_key().into()),
            bundle,
        }))
    }

    /// Publish a branch-signed bundle only under its current native authority.
    /// # Errors
    /// Rejects key/epoch substitution, missing registration capability and storage failure.
    pub fn publish_custody_prekey(
        &self,
        request: &crate::PrekeyPublishRequest,
        now: u64,
        store: &super::RouterRedbStore,
    ) -> Result<Option<crate::PrekeyResponse>, NodeCoreError> {
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let registry = &control.mvp1_identities;
        let Some(anchor) =
            registry.custody_anchor_for_principal(&request.bundle.identity_commitment)
        else {
            return Ok(None);
        };
        let (_, authority) = registry
            .custody_authority(anchor, now)?
            .ok_or_else(|| super::reject("custody publication unavailable"))?;
        let reference = DeviceRef {
            account_anchor: anchor.into(),
            device_id: request.device_id.clone(),
            device_epoch: request.bundle.device_epoch,
        };
        let cert =
            authority.authorize(&reference, "register", now).map_err(|error| crypto(&error))?;
        let value = serde_json::to_value(&request.bundle)
            .map_err(|error| super::reject(&error.to_string()))?;
        verify_bundle(&authority, cert, &reference, &value)?;
        let identity = RootQualifiedDeviceRef::from_custody_record(&authority, &request.device_id)
            .map_err(|error| crypto(&error))?;
        store.record_custody_prekey(identity.storage_key(), &value)?;
        Ok(Some(crate::PrekeyResponse {
            device_id: request.device_id.clone(),
            principal_commitment: anchor.into(),
            target_delivery_id: Some(identity.storage_key().into()),
            bundle: Some(request.bundle.clone()),
        }))
    }
}
