// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate message-layer declarations and rollback-resistant directory pins.
use crate::SdkError;
use ramflux_protocol::custody::{
    Device, DeviceRef, LayerDeclaration, MAX_LAYER_DECLARATION_VALIDITY_SECONDS, MAX_MESSAGE_LAYER,
    MESSAGE_LAYER_FLOOR, SignedLayerDeclaration,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn invalid() -> SdkError {
    SdkError::CustodySetupInvalid
}

/// Requested validity interval for a signed message-layer declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeclarationValidity {
    /// Signed issue time in Unix seconds.
    pub issued_at: u64,
    /// Signed expiry time in Unix seconds.
    pub expires_at: u64,
}

/// Sign a capability statement for inclusion in a later endorsed custody publication.
/// This does not publish or activate the candidate.
/// # Errors
/// Rejects unsupported layers, invalid sequence/time bounds, or signing failures.
pub(crate) fn candidate(
    branch: &ramflux_crypto::DeviceBranch,
    device: DeviceRef,
    max_layer: u32,
    declaration_sequence: u64,
    issued_at: u64,
    expires_at: u64,
) -> Result<SignedLayerDeclaration, SdkError> {
    let validity = expires_at.checked_sub(issued_at).ok_or_else(invalid)?;
    if declaration_sequence == 0
        || issued_at == 0
        || expires_at == 0
        || validity == 0
        || validity > MAX_LAYER_DECLARATION_VALIDITY_SECONDS
        || max_layer < MESSAGE_LAYER_FLOOR
        || max_layer > MAX_MESSAGE_LAYER
        || expires_at > ramflux_protocol::MAX_SAFE_JSON_INTEGER
    {
        return Err(invalid());
    }
    let declaration =
        LayerDeclaration { device, max_layer, declaration_sequence, issued_at, expires_at };
    let bytes = ramflux_protocol::custody::signing_bytes(
        ramflux_protocol::domain::CUSTODY_MESSAGE_LAYER_DECLARATION,
        &declaration,
    )?;
    Ok(SignedLayerDeclaration {
        branch_signature: ramflux_crypto::sign_canonical_bytes_with_device_branch(&bytes, branch),
        declaration,
    })
}

/// Highest accepted signed layer statement for one exact account/device epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeclarationPin {
    account_anchor: String,
    device_id: String,
    device_epoch: u64,
    native_epoch: u64,
    native_head: String,
    declaration_sequence: u64,
    declaration_hash: String,
    max_layer: u32,
    #[serde(default)]
    present: bool,
}

/// Persisted independently from the current publication so expiry or restore cannot roll it back.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeclarationPins {
    #[serde(default)]
    devices: Vec<DeclarationPin>,
}

impl DeclarationPins {
    pub(crate) fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    pub(crate) fn observe_roster(
        &mut self,
        account_anchor: &str,
        devices: &[Device],
        native_epoch: u64,
        native_head: &str,
    ) -> Result<(), SdkError> {
        let current = devices
            .iter()
            .map(|device| (device.device_id.as_str(), device.device_epoch))
            .collect::<BTreeSet<_>>();
        for pin in &mut self.devices {
            if pin.account_anchor == account_anchor
                && !current.contains(&(pin.device_id.as_str(), pin.device_epoch))
            {
                if native_epoch < pin.native_epoch
                    || (native_epoch == pin.native_epoch && native_head != pin.native_head)
                {
                    return Err(SdkError::CustodyForkFenced);
                }
                pin.native_epoch = native_epoch;
                native_head.clone_into(&mut pin.native_head);
                pin.present = false;
            }
        }
        for device in devices {
            self.observe(account_anchor, device, native_epoch, native_head)?;
        }
        Ok(())
    }

    pub(crate) fn observe(
        &mut self,
        account_anchor: &str,
        device: &Device,
        native_epoch: u64,
        native_head: &str,
    ) -> Result<(), SdkError> {
        let old_pin = self.devices.iter().position(|pin| {
            pin.account_anchor == account_anchor
                && pin.device_id == device.device_id
                && pin.device_epoch == device.device_epoch
        });
        let Some(signed) = &device.message_layer else {
            if let Some(old) = old_pin.and_then(|index| self.devices.get_mut(index)) {
                if native_epoch < old.native_epoch
                    || (native_epoch == old.native_epoch && native_head != old.native_head)
                {
                    return Err(SdkError::CustodyForkFenced);
                }
                old.native_epoch = native_epoch;
                native_head.clone_into(&mut old.native_head);
                old.present = false;
            }
            return Ok(());
        };
        let declaration = &signed.declaration;
        if declaration.device.account_anchor != account_anchor
            || declaration.device.device_id != device.device_id
            || declaration.device.device_epoch != device.device_epoch
            || declaration.declaration_sequence == 0
            || declaration.max_layer < MESSAGE_LAYER_FLOOR
            || declaration.max_layer > MAX_MESSAGE_LAYER
        {
            return Err(invalid());
        }
        let declaration_hash = ramflux_protocol::custody::framed_hash(
            ramflux_protocol::domain::CUSTODY_MESSAGE_LAYER_DECLARATION,
            signed,
        )?;
        if let Some(old) = old_pin.and_then(|index| self.devices.get(index))
            && (native_epoch < old.native_epoch
                || (native_epoch == old.native_epoch && native_head != old.native_head)
                || device.device_epoch != old.device_epoch
                || declaration.declaration_sequence < old.declaration_sequence
                || (declaration.declaration_sequence == old.declaration_sequence
                    && (!old.present
                        || declaration_hash != old.declaration_hash
                        || declaration.max_layer != old.max_layer)))
        {
            return Err(SdkError::CustodyForkFenced);
        }
        let pin = DeclarationPin {
            account_anchor: account_anchor.to_owned(),
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
            native_epoch,
            native_head: native_head.to_owned(),
            declaration_sequence: declaration.declaration_sequence,
            declaration_hash,
            max_layer: declaration.max_layer,
            present: true,
        };
        if let Some(index) = old_pin {
            self.devices[index] = pin;
        } else {
            self.devices.push(pin);
        }
        self.devices.sort_by(|left, right| {
            (&left.account_anchor, &left.device_id, left.device_epoch).cmp(&(
                &right.account_anchor,
                &right.device_id,
                right.device_epoch,
            ))
        });
        Ok(())
    }
}

pub(crate) fn sequence_high_water(
    account_anchor: &str,
    devices: &[Device],
) -> Result<BTreeMap<String, u64>, SdkError> {
    let mut sequences = BTreeMap::new();
    remember_sequences(&mut sequences, account_anchor, devices)?;
    Ok(sequences)
}

pub(crate) fn remember_sequences(
    sequences: &mut BTreeMap<String, u64>,
    account_anchor: &str,
    devices: &[Device],
) -> Result<(), SdkError> {
    for device in devices {
        if let Some(declaration) = &device.message_layer {
            let reference =
                ramflux_protocol::qualified_device_id(account_anchor, &device.device_id)?;
            sequences
                .entry(reference)
                .and_modify(|high| {
                    *high = (*high).max(declaration.declaration.declaration_sequence);
                })
                .or_insert(declaration.declaration.declaration_sequence);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_protocol::custody::MigrationState;

    fn device(sequence: u64, max_layer: u32, expires_at: u64) -> Device {
        Device {
            device_id: "phone".into(),
            device_epoch: 7,
            signing_key_commitment: "signing".into(),
            agreement_key_commitment: "agreement".into(),
            status: ramflux_protocol::DeviceSetStatus::Active,
            revoked_at: None,
            branch_certificate: None,
            message_layer: Some(SignedLayerDeclaration {
                declaration: LayerDeclaration {
                    device: DeviceRef {
                        account_anchor: "anchor".into(),
                        device_id: "phone".into(),
                        device_epoch: 7,
                    },
                    max_layer,
                    declaration_sequence: sequence,
                    issued_at: 100,
                    expires_at,
                },
                branch_signature: "signature".into(),
            }),
            migration_state: MigrationState::Native,
        }
    }

    #[test]
    fn declaration_pin_rejects_rollback() -> Result<(), Box<dyn std::error::Error>> {
        let mut pins = DeclarationPins::default();
        pins.observe("anchor", &device(4, 2, 86_500), 11, "head-11")?;
        let saved = serde_json::to_vec(&pins)?;
        let mut restored: DeclarationPins = serde_json::from_slice(&saved)?;

        // A newer native head can preserve the exact declaration, including after expiry.
        restored.observe("anchor", &device(4, 2, 86_500), 12, "head-12")?;
        assert_eq!(restored.devices.first().map(|pin| pin.native_epoch), Some(12));

        // Lower declaration sequence, stale native head, foreign device epoch, and equal-sequence
        // conflict each fail independently and leave the pin unchanged.
        let before = restored.clone();
        assert!(matches!(
            restored.observe("anchor", &device(3, 2, 200), 13, "head-13"),
            Err(SdkError::CustodyForkFenced)
        ));
        assert_eq!(restored, before);
        assert!(matches!(
            restored.observe("anchor", &device(4, 2, 86_500), 11, "head-11"),
            Err(SdkError::CustodyForkFenced)
        ));
        assert_eq!(restored, before);
        assert!(matches!(
            restored.observe("anchor", &device(4, 2, 86_500), 12, "fork-head-12"),
            Err(SdkError::CustodyForkFenced)
        ));
        assert_eq!(restored, before);
        assert!(matches!(
            restored.observe("anchor", &device(4, 2, 86_499), 13, "head-13"),
            Err(SdkError::CustodyForkFenced)
        ));
        assert_eq!(restored, before);
        let mut foreign = device(5, 2, 200);
        foreign
            .message_layer
            .as_mut()
            .ok_or("fixture declaration")?
            .declaration
            .device
            .device_epoch = 8;
        assert!(matches!(
            restored.observe("anchor", &foreign, 13, "head-13"),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert_eq!(restored, before);
        let mut wrong_account = device(5, 2, 200);
        wrong_account
            .message_layer
            .as_mut()
            .ok_or("fixture declaration")?
            .declaration
            .device
            .account_anchor = "foreign-anchor".into();
        assert!(matches!(
            restored.observe("anchor", &wrong_account, 13, "head-13"),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert_eq!(restored, before);
        assert!(matches!(
            restored.observe("anchor", &device(5, 1, 200), 13, "head-13"),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert_eq!(restored, before);

        let mut withdrawn = before.clone();
        let mut absent = device(4, 2, 86_500);
        absent.message_layer = None;
        withdrawn.observe("anchor", &absent, 12, "head-12")?;
        assert!(matches!(
            withdrawn.observe("anchor", &device(4, 2, 86_500), 13, "head-13"),
            Err(SdkError::CustodyForkFenced)
        ));

        // A genuinely higher sequence may lower only within the declared supported range;
        // S10a's floor equals its maximum, so the floor is the sole admissible value here.
        restored.observe("anchor", &device(5, MESSAGE_LAYER_FLOOR, 200), 13, "head-13")?;
        assert_eq!(restored.devices.first().map(|pin| pin.declaration_sequence), Some(5));
        Ok(())
    }

    #[test]
    fn candidate_layer_declaration_enforces_inclusive_expiry_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let branch = ramflux_crypto::create_device_branch("principal", "phone", 7, [3; 32]);
        let reference = DeviceRef {
            account_anchor: "anchor".into(),
            device_id: "phone".into(),
            device_epoch: 7,
        };
        let signed = candidate(&branch, reference.clone(), MESSAGE_LAYER_FLOOR, 1, 100, 86_500)?;
        let bytes = ramflux_protocol::custody::signing_bytes(
            ramflux_protocol::domain::CUSTODY_MESSAGE_LAYER_DECLARATION,
            &signed.declaration,
        )?;
        ramflux_crypto::verify_canonical_signature(
            &bytes,
            &signed.branch_signature,
            &ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes()),
        )?;
        candidate(&branch, reference.clone(), MESSAGE_LAYER_FLOOR, 1, 100, 101)?;
        candidate(&branch, reference.clone(), MAX_MESSAGE_LAYER, 1, 100, 86_500)?;
        assert!(matches!(
            candidate(&branch, reference.clone(), MESSAGE_LAYER_FLOOR, 1, 0, 1),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(matches!(
            candidate(&branch, reference.clone(), MESSAGE_LAYER_FLOOR, 1, 1, 0),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(matches!(
            candidate(
                &branch,
                reference.clone(),
                MESSAGE_LAYER_FLOOR,
                1,
                1,
                ramflux_protocol::MAX_SAFE_JSON_INTEGER + 1
            ),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(matches!(
            candidate(&branch, reference.clone(), MESSAGE_LAYER_FLOOR - 1, 1, 100, 101),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(matches!(
            candidate(&branch, reference.clone(), MAX_MESSAGE_LAYER + 1, 1, 100, 101),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(matches!(
            candidate(&branch, reference.clone(), MESSAGE_LAYER_FLOOR, 0, 100, 101),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(matches!(
            candidate(&branch, reference.clone(), MESSAGE_LAYER_FLOOR, 1, 100, 100),
            Err(SdkError::CustodySetupInvalid)
        ));
        assert!(matches!(
            candidate(&branch, reference, MESSAGE_LAYER_FLOOR, 1, 100, 86_501),
            Err(SdkError::CustodySetupInvalid)
        ));
        Ok(())
    }
}
