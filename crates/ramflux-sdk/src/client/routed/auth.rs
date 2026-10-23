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
        let known = self.account_db()?.client_record("device", remote)?;
        if known.as_ref().is_none_or(|record| record.get("x25519_identity_public").is_none()) {
            let pinned = self
                .account_db()?
                .device_directory_entry(remote)?
                .map(|entry| entry.principal_commitment)
                .or(self
                    .account_db()?
                    .client_record("identity", &entry.envelope.source_principal_id)?
                    .and_then(|record| {
                        record
                            .get("contact_identity_commitment")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    }));
            let commitment = if let Some(commitment) = pinned {
                commitment
            } else {
                let prekey: crate::prekey::SdkPrekeyResponse =
                    crate::prelude::sdk_gateway_get_json(
                        gateway,
                        &format!("/mvp1/prekey/{remote}"),
                    )
                    .await?;
                prekey.principal_commitment
            };
            let manifest =
                crate::client::contact::fetch_verified_device_manifest(gateway, &commitment)
                    .await?;
            let device = manifest
                .devices
                .iter()
                .find(|device| device.device_id == *remote)
                .ok_or_else(|| invalid("sender device absent from verified manifest"))?;
            let record = serde_json::json!({"principal_id":manifest.principal_id,"signing_public_key":device.branch_public_key,"x25519_identity_public":device.prekey_bundle.identity_key});
            verify_sender_record(entry, &record)?;
            if let Ok(wrapper) = decode(&entry.envelope)
                && let Some(header) = wrapper.x3dh
            {
                let expected = serde_json::to_value(device.prekey_bundle.identity_key)?;
                if serde_json::to_value(header.initiator_identity_public)? != expected {
                    return Err(invalid("X3DH initiator differs from verified device identity"));
                }
            }
            self.persist_identity_directory(&manifest)?;
            self.account_db()?.upsert_device_directory_entry(
                remote,
                &commitment,
                "inbound_signature",
                now_unix_timestamp(),
            )?;
        }
        self.authenticated_envelope_sender(entry)?;
        Ok(())
    }

    pub(super) fn trusted_device(&self, remote: &str) -> Result<Value, SdkError> {
        self.account_db()?
            .client_record("device", remote)?
            .ok_or_else(|| invalid("sender device has no verified manifest"))
    }

    pub(super) fn authenticated_envelope_sender(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        let record = self.trusted_device(&entry.envelope.source_device_id)?;
        verify_sender_record(entry, &record)
    }

    pub(super) fn verify_initiator_identity(
        &self,
        remote: &str,
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

fn verify_sender_record(entry: &GatewayInboxEntry, record: &Value) -> Result<String, SdkError> {
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
    let mut sender_envelope = envelope.clone();
    if let Some(receipt) =
        sender_envelope.ext.ext.get_mut("franking").and_then(Value::as_object_mut)
    {
        // The gateway appends exactly these receipt fields after sender signing.
        for field in ["franking_tag", "node_id", "accepted_at"] {
            receipt.remove(field);
        }
    }
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(&sender_envelope)?,
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
