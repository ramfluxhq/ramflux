// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-manifest trust anchors for inbound identity, principal and envelope signatures.
use super::{
    GatewayInboxEntry, GatewaySessionConfig, RamfluxClient, SdkDmX3dhHeader, SdkError, decode,
    invalid, now_unix_timestamp,
};
use crate::client::identity_authority::HeadUse;
use serde_json::Value;

pub(crate) type InboundManifest =
    Result<Option<crate::prekey::SdkDeviceManifestResponse>, SdkError>;

pub(crate) struct PreparedInbound {
    pub manifest: Option<crate::prekey::SdkDeviceManifestResponse>,
    pub native_prepared: bool,
    pub history: Option<crate::client::own_device_sync::receive_job::HistoryCompletion>,
    pub group_directory: Option<super::ReceiveGroupDirectory>,
    pub candidate: Option<crate::prekey::SdkDeviceManifestResponse>,
    pub own_copy_manifest: Option<crate::prekey::SdkDeviceManifestResponse>,
}

#[derive(Clone, Copy)]
enum Observation {
    Preview,
    Commit,
}

impl RamfluxClient {
    pub(super) async fn ensure_prepared_inbound_device(
        &self,
        gateway: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
        prepared: Option<InboundManifest>,
    ) -> Result<(), SdkError> {
        if let Some(result) = prepared {
            return self.apply_inbound_device_manifest(entry, result?.as_ref());
        }
        let request = self.inbound_device_manifest_request(entry)?;
        let manifest = if let Some(root) = request {
            Some(
                crate::client::contact::fetch_verified_device_manifest(gateway, &root)
                    .await
                    .map_err(|source| SdkError::DirectoryAuthorityUnavailable {
                        root,
                        source: Box::new(source),
                    })?,
            )
        } else {
            None
        };
        self.apply_inbound_device_manifest(entry, manifest.as_ref())
    }

    pub(crate) async fn ensure_inbound_device(
        &self,
        gateway: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let request = self.inbound_device_manifest_request(entry)?;
        let manifest = if let Some(root) = request {
            Some(crate::client::contact::fetch_verified_device_manifest(gateway, &root).await?)
        } else {
            None
        };
        self.apply_inbound_device_manifest(entry, manifest.as_ref())
    }

    pub(crate) fn inbound_device_manifest_request(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<String>, SdkError> {
        let remote = &entry.envelope.source_device_id;
        let reference = self.inbound_device_reference(entry)?;
        let (commitment, _) = ramflux_protocol::parse_qualified_device_id(&reference)?
            .ok_or_else(|| invalid("sender root address required"))?;
        if self.observed_device_set(&commitment)?.is_some_and(|set| {
            set.devices.iter().any(|device| {
                device.device_id == *remote
                    && device.status == ramflux_protocol::DeviceSetStatus::Revoked
            })
        }) {
            return Err(invalid("sender device is revoked"));
        }
        if self
            .device_identity(&reference)
            .and_then(|identity| {
                self.require_cached_root_authority(HeadUse::NewAuthorization, &identity)
            })
            .is_ok()
        {
            return Ok(None);
        }
        if !self.inbound_relationship_names_root(
            &entry.envelope.source_principal_id,
            &commitment,
            remote,
        )? {
            return Err(invalid("unsolicited sender root has no accepted relationship"));
        }
        Ok(Some(commitment))
    }

    pub(crate) fn apply_inbound_device_manifest(
        &self,
        entry: &GatewayInboxEntry,
        manifest: Option<&crate::prekey::SdkDeviceManifestResponse>,
    ) -> Result<(), SdkError> {
        self.validate_inbound_device_manifest(entry, manifest, Observation::Commit)
    }

    /// Prepare verified authority and lazy group pins without recording a second receive observation.
    /// Final application repeats the checks and records its own current timestamp.
    pub(crate) fn prepare_inbound_device_manifest(
        &self,
        entry: &GatewayInboxEntry,
        manifest: Option<&crate::prekey::SdkDeviceManifestResponse>,
    ) -> Result<(), SdkError> {
        self.validate_inbound_device_manifest(entry, manifest, Observation::Preview)
    }

    fn validate_inbound_device_manifest(
        &self,
        entry: &GatewayInboxEntry,
        manifest: Option<&crate::prekey::SdkDeviceManifestResponse>,
        observation: Observation,
    ) -> Result<(), SdkError> {
        let remote = &entry.envelope.source_device_id;
        if let Some(commitment) = self.inbound_device_manifest_request(entry)? {
            let manifest = manifest
                .filter(|manifest| manifest.principal_commitment == commitment)
                .ok_or_else(|| SdkError::SenderManifestRequired { root: commitment.clone() })?;
            let device = manifest
                .devices
                .iter()
                .find(|device| device.device_id == *remote)
                .ok_or_else(|| invalid("sender absent from active root manifest"))?;
            let record = serde_json::json!({"principal_id":manifest.principal_id,"signing_public_key":device.branch_public_key,"x25519_identity_public":device.prekey_bundle.identity_key});
            verify_sender_record(entry, &record)?;
            if let Ok(packet) = decode(&entry.envelope)
                && let Some(header) = packet.x3dh
                && header.initiator_identity_public != device.prekey_bundle.identity_key
            {
                return Err(invalid("X3DH initiator differs from verified device identity"));
            }
            // Relationship, signature and X3DH identity are rechecked at the writer checkpoint.
            self.persist_fetched_identity_directory(manifest)?;
        }
        let reference = self.inbound_device_reference(entry)?;
        let (commitment, _) = ramflux_protocol::parse_qualified_device_id(&reference)?
            .ok_or_else(|| invalid("sender root address required"))?;
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, entry)?;
        if matches!(observation, Observation::Commit) {
            self.account_db()?.upsert_device_directory_entry(
                remote,
                &commitment,
                "inbound_signature",
                now_unix_timestamp(),
            )?;
        }
        self.finish_lazy_own_group_pins(&entry.envelope.source_principal_id, &commitment, remote)?;
        Ok(())
    }

    pub(crate) fn trusted_device(
        &self,
        purpose: HeadUse,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Value, SdkError> {
        if self
            .account_db()?
            .load_actor_state::<bool>(&Self::device_revocation_key(identity))?
            .unwrap_or(false)
        {
            return Err(SdkError::InboundRejected("revoked device".to_owned()));
        }

        self.require_cached_root_authority(purpose, identity).map_err(|error| {
            crate::client::inbox_failure::lookup_error(
                error,
                "cached sender directory is incomplete",
            )
        })?;
        self.account_db()?.client_record("device", identity.storage_key())?.ok_or_else(|| {
            SdkError::InboundPending("sender device has no verified manifest".to_owned())
        })
    }

    pub(crate) fn authenticated_envelope_sender(
        &self,
        purpose: HeadUse,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        let record = self.authenticated_sender_record(purpose, entry)?;
        Ok(record["principal_id"]
            .as_str()
            .ok_or_else(|| invalid("sender principal missing"))?
            .to_owned())
    }

    pub(crate) fn authenticated_sender_record(
        &self,
        purpose: HeadUse,
        entry: &GatewayInboxEntry,
    ) -> Result<Value, SdkError> {
        let record = self.trusted_device(
            purpose,
            &self.device_identity(&self.inbound_device_reference(entry)?)?,
        )?;
        if let Some(hint) =
            decode(&entry.envelope).ok().and_then(|wrapper| wrapper.source_principal_commitment)
            && record["principal_commitment"] != hint
        {
            return Err(invalid("sender Root hint differs from verified device owner"));
        }
        verify_sender_record(entry, &record)?;
        Ok(record)
    }

    pub(super) fn authenticated_direct_participant(
        &self,
        thread: &Value,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        let principal = self.authenticated_envelope_sender(HeadUse::NewAuthorization, entry)?;
        Ok(thread["participants"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(&principal))))
    }

    pub(super) fn verify_initiator_identity(
        &self,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        header: &SdkDmX3dhHeader,
    ) -> Result<(), SdkError> {
        let record = self.trusted_device(HeadUse::NewAuthorization, remote)?;
        let expected: [u8; 32] = serde_json::from_value(
            record
                .get("x25519_identity_public")
                .cloned()
                .ok_or_else(|| invalid("sender X3DH identity key missing"))?,
        )?;
        if header.initiator_identity_public != expected {
            return Err(invalid("X3DH initiator differs from verified device identity"));
        }
        Ok(())
    }
}

pub(crate) fn verify_sender_record(
    entry: &GatewayInboxEntry,
    record: &Value,
) -> Result<String, SdkError> {
    let envelope = &entry.envelope;
    let principal = record
        .get("principal_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("sender principal missing"))?;
    if envelope.source_principal_id != principal {
        return Err(invalid("sender principal differs from verified device owner"));
    }
    let key = record
        .get("signing_public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("sender signing key missing"))?;
    ramflux_protocol::verify_envelope_sender_signature(envelope, key)?;
    let hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        envelope.encrypted_payload.as_bytes(),
    );
    if envelope.payload_hash != hash {
        return Err(invalid("envelope payload hash mismatch"));
    }
    Ok(principal.to_owned())
}
