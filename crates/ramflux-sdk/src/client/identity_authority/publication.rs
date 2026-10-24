// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit root-signed revocation publication, with exact ACK and local rollback protection.
use super::{invalid, record_key};
use crate::prelude::*;
use ramflux_protocol::{DeviceSetStatus, SignedDeviceSetRecord};
use serde::Serialize;
#[derive(Serialize)]
struct Publication<'a> {
    root_public_key: String,
    record: &'a SignedDeviceSetRecord,
}
impl RamfluxClient {
    pub(crate) async fn revoke_owned_device(
        &self,
        gateway: &GatewaySessionConfig,
        device: &str,
    ) -> Result<SignedDeviceSetRecord, SdkError> {
        let owned = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let device = if let Some((root, raw)) = ramflux_protocol::parse_qualified_device_id(device)?
        {
            if root != ramflux_crypto::identity_root_commitment(&owned.signing_key.verifying_key())
            {
                return Err(invalid("revocation address belongs to another root"));
            }
            raw
        } else {
            device.to_owned()
        };
        let device = device.as_str();
        let mut last = None;
        for _ in 0..3 {
            match self.revoke_owned_device_once(gateway, device).await {
                Ok(record)
                    if record.devices.iter().any(|entry| {
                        entry.device_id == device && entry.status == DeviceSetStatus::Revoked
                    }) =>
                {
                    return Ok(record);
                }
                Ok(_) => {}
                Err(error @ SdkError::InboundRejected(_)) => return Err(error),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| invalid("own publication reconciliation retry limit reached")))
    }
    async fn revoke_owned_device_once(
        &self,
        gateway: &GatewaySessionConfig,
        device: &str,
    ) -> Result<SignedDeviceSetRecord, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let commitment =
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
        let remote: Option<SignedDeviceSetRecord> =
            sdk_gateway_get_json(gateway, &format!("/mvp2/device-set/{commitment}")).await?;
        let old =
            remote.ok_or_else(|| invalid("migrate legacy identity before signed revocation"))?;
        ramflux_crypto::verify_signed_device_set(&root.signing_key.verifying_key(), &old)?;
        self.accept_owned_record(&old)?;
        let mut entries = old.devices.clone();
        self.apply_owned_revocation_intents(&mut entries)?;
        let entry = entries
            .iter_mut()
            .find(|e| e.device_id == device)
            .ok_or_else(|| invalid("device not in own signed set"))?;
        if entry.status != DeviceSetStatus::Revoked {
            entry.status = DeviceSetStatus::Revoked;
            entry.revoked_at = Some(now_unix_timestamp());
        }
        let mut next = if entries == old.devices {
            old.clone()
        } else {
            ramflux_crypto::sign_device_set(
                root,
                ramflux_crypto::DeviceSetSigningInput {
                    principal_kind: old.principal_kind,
                    device_set_epoch: old
                        .device_set_epoch
                        .checked_add(1)
                        .ok_or_else(|| invalid("epoch exhausted"))?,
                    devices: entries,
                },
            )?
        };
        ramflux_crypto::validate_device_set_transition(&old, &next)?;
        if let Some(pending) = self
            .account_db()?
            .load_actor_state::<SignedDeviceSetRecord>("identity/owned_pending_set")?
        {
            ramflux_crypto::validate_device_set_transition(&old, &pending)?;
            next = pending;
        }
        self.retain_owned_revocation_proposal(&next)?;
        let ack: SignedDeviceSetRecord = sdk_gateway_post_json(
            gateway,
            "/mvp2/device-set",
            &Publication {
                root_public_key: ramflux_protocol::encode_base64url(
                    root.signing_key.verifying_key().to_bytes(),
                ),
                record: &next,
            },
        )
        .await?;
        if ack != next {
            return Err(invalid("signed publication ACK mismatch"));
        }
        self.accept_owned_record(&ack)?;
        Ok(ack)
    }
    fn retain_owned_revocation_proposal(
        &self,
        record: &SignedDeviceSetRecord,
    ) -> Result<(), SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        ramflux_crypto::verify_signed_device_set(&root.signing_key.verifying_key(), record)?;
        if record.principal_id != root.principal_id {
            return Err(invalid("own revocation principal mismatch"));
        }
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
        let db = self.account_db()?;
        db.write_transaction(|| {
            db.persist_actor_state("identity/owned_pending_set", record)?;
            for entry in record.devices.iter().filter(|e| e.status == DeviceSetStatus::Revoked) {
                if &entry.device_id == local {
                    for peer in db.pair_peer_devices(local)? {
                        self.remove_device_pair(&peer, "root_signed_revocation_pending")?;
                    }
                } else {
                    self.remove_device_pair(&entry.device_id, "root_signed_revocation_pending")?;
                }
                db.persist_actor_state(
                    &self.device_revocation_key(&ramflux_protocol::qualified_device_id(
                        &record.principal_commitment,
                        &entry.device_id,
                    )?)?,
                    &true,
                )?;
            }
            Ok::<_, SdkError>(())
        })?;
        self.finish_pair_retirement()
    }
    /// Read the highest accepted signed record for an observed identity, including tombstones.
    /// # Errors
    /// Returns storage errors; an unknown/legacy identity returns None.
    pub fn observed_device_set(
        &self,
        commitment: &str,
    ) -> Result<Option<SignedDeviceSetRecord>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&record_key(commitment))?)
    }
}
