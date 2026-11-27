// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The own device identity for MLS device credentials: root key, signed device set and the device
//! signing key of the account.
use ed25519_dalek::Signer;
use ramflux_crypto::DeviceBranch;
use ramflux_mls::{DeviceCertSigner, DeviceIdentity, MlsError};
use ramflux_protocol::custody::CustodyKind;
use ramflux_protocol::{DeviceSetStatus, decode_base64url};

use crate::{RamfluxClient, SdkError};

/// Signs leaf certificates with the account's device signing key (zeroized on drop).
struct BranchCertSigner {
    branch: DeviceBranch,
}

impl DeviceCertSigner for BranchCertSigner {
    fn sign_cert(&self, message: &[u8]) -> Result<[u8; 64], MlsError> {
        self.branch
            .signing_key
            .try_sign(message)
            .map(|signature| signature.to_bytes())
            .map_err(|_| MlsError::Internal("device certificate signing failed".to_owned()))
    }
}

impl RamfluxClient {
    /// The own MLS device identity of a custody-native account.
    ///
    /// Sources: the verified custody record of the selected born-v3 account (`born_v3_account`,
    /// loaded by `custody::load_account`, whose `record()` is the `Envelope<DeviceSet>` signed by
    /// the self-signing key and carrying the master certificate) and the leased branch signing
    /// key unlocked from the vault by `initialize_born_v3_branch` (`device_branch`). The primary
    /// (self-signing) key is not needed: the leaf certificate is signed by the branch key.
    ///
    /// `Ok(None)` when no native account is selected, its branch key is not unlocked, or this
    /// device is not an active, leased device of the record (a `dm` group then fails with a typed
    /// error and pseudonym groups are unaffected).
    ///
    /// # Errors
    /// A stored record or key that cannot be encoded.
    pub(crate) fn mls_device_identity(&self) -> Result<Option<DeviceIdentity>, SdkError> {
        let (Some(account), Some(branch)) = (&self.born_v3_account, &self.device_branch) else {
            return Ok(None);
        };
        let record = account.record();
        let master = &record.body.master_certificate.body;
        // Only a human account with local custody carries a self-contained chain; a hosted
        // agent needs its custodian's record as well and is not a DM identity in MLS-0.
        if master.custody_kind != CustodyKind::LocalHuman {
            return Ok(None);
        }
        let device_id = account.local_device_id()?;
        if branch.device_id != device_id {
            return Ok(None);
        }
        let device_signing_pk = branch.signing_key.verifying_key().to_bytes();
        let active_with_key = record.body.devices.iter().any(|entry| {
            entry.device_id == device_id
                && entry.status == DeviceSetStatus::Active
                && entry.branch_certificate.as_ref().is_some_and(|cert| {
                    decode_base64url(&cert.body.branch_signing_public_key)
                        .is_ok_and(|key| key == device_signing_pk)
                })
        });
        if !active_with_key {
            return Ok(None);
        }
        let root_vk: [u8; 32] = decode_base64url(&master.master_public_key)
            .ok()
            .and_then(|key| key.try_into().ok())
            .ok_or(SdkError::CustodySetupInvalid)?;
        // The credential carries the canonical I-JSON of the record; the verifier re-parses it
        // strictly and re-verifies every signature.
        let device_set_record = ramflux_protocol::canonical_json_bytes(record)?;
        Ok(Some(DeviceIdentity {
            root_vk,
            device_id: device_id.to_owned(),
            device_set_record,
            device_signing_pk,
            signer: Box::new(BranchCertSigner { branch: branch.clone() }),
        }))
    }
}
