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
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let commitment =
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
        let remote: Option<SignedDeviceSetRecord> =
            sdk_gateway_get_json(gateway, &format!("/mvp2/device-set/{commitment}")).await?;
        let old =
            remote.ok_or_else(|| invalid("migrate legacy identity before signed revocation"))?;
        ramflux_crypto::verify_signed_device_set(&root.signing_key.verifying_key(), &old)?;
        self.check_observed_set(&old)?;
        let mut entries = old.devices.clone();
        let entry = entries
            .iter_mut()
            .find(|e| e.device_id == device)
            .ok_or_else(|| invalid("device not in own signed set"))?;
        let next = if entry.status == DeviceSetStatus::Revoked {
            old.clone()
        } else {
            entry.status = DeviceSetStatus::Revoked;
            entry.revoked_at = Some(now_unix_timestamp());
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
