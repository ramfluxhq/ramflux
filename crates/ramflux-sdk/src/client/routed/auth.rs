// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-manifest trust anchors for inbound identity, principal and envelope signatures.
use super::{
    GatewayInboxEntry, GatewaySessionConfig, RamfluxClient, SdkDmX3dhHeader, SdkError, decode,
    invalid, now_unix_timestamp,
};
use serde_json::Value;

impl RamfluxClient {
    pub(crate) async fn ensure_inbound_device(
        &self,
        gateway: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
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
            .and_then(|identity| self.require_cached_root_authority(&identity))
            .is_err()
        {
            if !self.inbound_relationship_names_root(
                &entry.envelope.source_principal_id,
                &commitment,
                remote,
            )? {
                return Err(invalid("unsolicited sender root has no accepted relationship"));
            }
            let manifest =
                crate::client::contact::fetch_verified_device_manifest(gateway, &commitment)
                    .await?;
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
            // Both the signature chain and the accepted root relationship precede persistence.
            self.persist_identity_directory(&manifest)?;
        }
        self.authenticated_envelope_sender(entry)?;
        // A verified cached manifest must populate the same storage identity directory as a fetch.
        self.account_db()?.upsert_device_directory_entry(
            remote,
            &commitment,
            "inbound_signature",
            now_unix_timestamp(),
        )?;
        self.finish_lazy_own_group_pins(&entry.envelope.source_principal_id, &commitment, remote)?;
        Ok(())
    }

    pub(crate) fn trusted_device(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Value, SdkError> {
        if self
            .account_db()?
            .load_actor_state::<bool>(&Self::device_revocation_key(identity))?
            .unwrap_or(false)
        {
            return Err(SdkError::InboundRejected("revoked device".to_owned()));
        }

        self.require_cached_root_authority(identity).map_err(|error| {
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
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        let record =
            self.trusted_device(&self.device_identity(&self.inbound_device_reference(entry)?)?)?;
        if let Some(hint) =
            decode(&entry.envelope).ok().and_then(|wrapper| wrapper.source_principal_commitment)
            && record["principal_commitment"] != hint
        {
            return Err(invalid("sender Root hint differs from verified device owner"));
        }
        verify_sender_record(entry, &record)
    }

    pub(super) fn authenticated_direct_participant(
        &self,
        thread: &Value,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        let principal = self.authenticated_envelope_sender(entry)?;
        Ok(thread["participants"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(&principal))))
    }

    pub(super) fn verify_initiator_identity(
        &self,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        header: &SdkDmX3dhHeader,
    ) -> Result<(), SdkError> {
        let record = self.trusted_device(remote)?;
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
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::envelope_sender_signed_bytes(envelope)?,
        &envelope.signed.signature,
        key,
    )?;
    let hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        envelope.encrypted_payload.as_bytes(),
    );
    if envelope.payload_hash != hash {
        return Err(invalid("envelope payload hash mismatch"));
    }
    Ok(principal.to_owned())
}
