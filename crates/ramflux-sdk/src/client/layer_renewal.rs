// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary side of secondary layer renewal (SECONDARY-LAYER-01).
//!
//! A secondary device sends its own branch-signed declaration to the current primary over the
//! authenticated own-device Control. The primary authenticates it against the current roster
//! and stores one pending request for the layer-publish courier. Receipt never publishes.
use crate::SdkError;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::DeviceSetStatus;
use ramflux_protocol::canonical_json_bytes;
use ramflux_protocol::custody::{DeviceRef, SignedLayerDeclaration};
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

/// Pending request held per exact account/device/epoch until the courier endorses it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PendingLayerRenewal {
    pub(crate) declaration_sequence: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) signed: SignedLayerDeclaration,
}

/// Actor-state key for the one pending request of one exact device epoch.
pub(crate) fn pending_key(device: &DeviceRef) -> String {
    format!(
        "layer-renewal/pending/{}/{}/{}",
        device.account_anchor, device.device_id, device.device_epoch
    )
}

impl super::RamfluxClient {
    /// Authenticate and store one renewal request. Siblings that are not the current primary
    /// ignore it without writes.
    /// # Errors
    /// Refuses a request whose sender, epochs, roster endorsement, lease, sequence or
    /// signature does not match the current authority.
    pub(crate) fn receive_own_layer_renewal(
        &self,
        source: &RootQualifiedDeviceRef,
        renewal: &g::OwnLayerRenewal,
    ) -> Result<(), SdkError> {
        let own_anchor = self.own_account_anchor()?;
        let born = self.born_v3_account.as_deref().ok_or(SdkError::NetworkingPending)?;
        let record = born.record();
        let primary = &record.body.master_certificate.body.primary_device_ref;
        let primary_named = renewal.primary.as_ref().is_some_and(|reference| {
            reference.account_anchor == own_anchor
                && reference.device_id == primary.device_id
                && reference.device_epoch == primary.device_epoch
        });
        if !primary_named || born.local_device_id()? != primary.device_id {
            return Ok(());
        }
        let bytes = renewal.signed_declaration_json.as_slice();
        let signed: SignedLayerDeclaration = ramflux_protocol::parse_i_json(bytes)
            .map_err(|_| refused("own layer renewal declaration malformed"))?;
        if canonical_json_bytes(&signed)? != bytes {
            return Err(refused("own layer renewal declaration is not canonical"));
        }
        let declaration = &signed.declaration;
        let db = self.account_db()?;
        let sender_epoch =
            db.client_device_record(source)?.and_then(|record| record["device_epoch"].as_u64());
        if declaration.device.account_anchor != own_anchor
            || declaration.device.device_id != source.device_id()
            || Some(declaration.device.device_epoch) != sender_epoch
        {
            return Err(refused("own layer renewal sender mismatch"));
        }
        let now = crate::custody::network_now()?;
        if now >= declaration.expires_at {
            return Err(refused("own layer renewal declaration expired"));
        }
        let row = record
            .body
            .devices
            .iter()
            .find(|device| {
                device.device_id == declaration.device.device_id
                    && device.device_epoch == declaration.device.device_epoch
                    && device.status == DeviceSetStatus::Active
            })
            .ok_or_else(|| refused("own layer renewal device not active"))?;
        let certificate = row
            .branch_certificate
            .as_ref()
            .ok_or_else(|| refused("own layer renewal has no branch"))?;
        ramflux_crypto::custody::verify_enrollment_layer(certificate, &signed, now)
            .map_err(|_| refused("own layer renewal declaration rejected"))?;
        if let Some(endorsed) = &row.message_layer {
            let current = endorsed.declaration.declaration_sequence;
            if declaration.declaration_sequence < current
                || (declaration.declaration_sequence == current && endorsed != &signed)
            {
                return Err(refused("own layer renewal sequence is not newer"));
            }
            if endorsed == &signed {
                return Ok(());
            }
        }
        let digest = *blake3::hash(bytes).as_bytes();
        let key = pending_key(&declaration.device);
        let sequence = declaration.declaration_sequence;
        db.write_transaction(|| {
            if let Some(old) = db.load_actor_state::<PendingLayerRenewal>(&key)? {
                if sequence < old.declaration_sequence
                    || (sequence == old.declaration_sequence && old.digest != digest)
                {
                    return Err(refused("own layer renewal conflicts with a pending request"));
                }
                if sequence == old.declaration_sequence {
                    return Ok(());
                }
            }
            db.persist_actor_state(
                &key,
                &PendingLayerRenewal { declaration_sequence: sequence, digest, signed },
            )?;
            Ok(())
        })
    }
}

fn refused(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}
