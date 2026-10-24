// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Construct device identities only at the account's authenticated authority boundary.
use super::{invalid, record_key};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError, prekey::SdkDeviceManifestResponse};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::SignedDeviceSetRecord;
impl RamfluxClient {
    pub(crate) fn device_identity_for_root(
        &self,
        root: &str,
        device: &str,
    ) -> Result<RootQualifiedDeviceRef, SdkError> {
        if let (Some(own), Some(branch)) = (&self.identity_root, &self.device_branch)
            && branch.device_id == device
            && ramflux_crypto::identity_root_commitment(&own.signing_key.verifying_key()) == root
        {
            return Ok(RootQualifiedDeviceRef::for_owned_device(own, branch)?);
        }
        let db = self.account_db()?;
        let record: SignedDeviceSetRecord = db
            .load_actor_state(&record_key(root))?
            .ok_or_else(|| invalid("signed device authority unavailable"))?;
        let public = if let Some(own) = &self.identity_root
            && ramflux_crypto::identity_root_commitment(&own.signing_key.verifying_key()) == root
        {
            own.signing_key.verifying_key()
        } else {
            let manifest: SdkDeviceManifestResponse = db
                .load_actor_state(&format!("identity/manifest/{}", record.principal_id))?
                .ok_or_else(|| invalid("verified root manifest unavailable"))?;
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
