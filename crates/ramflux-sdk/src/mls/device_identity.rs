// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The own device identity for MLS device credentials (v2): account anchor, device id and epoch,
//! the device-set epoch and the device signing key of the account. The credential carries no
//! record; peers look the record up through the custody directory.
use ed25519_dalek::Signer;
use ramflux_crypto::DeviceBranch;
use ramflux_mls::{DeviceCertSigner, DeviceIdentity, MlsError};
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
    /// the self-signing key) and the leased branch signing key unlocked from the vault by
    /// `initialize_born_v3_branch` (`device_branch`). The primary (self-signing) key is not
    /// needed: the leaf certificate is signed by the branch key. A hosted agent
    /// (`ExternalHuman` custody) has the same identity: the credential no longer embeds the
    /// record, so no custodian chain travels with it.
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
        let device_id = account.local_device_id()?;
        if branch.device_id != device_id {
            return Ok(None);
        }
        let device_signing_pk = branch.signing_key.verifying_key().to_bytes();
        let Some(entry) = record.body.devices.iter().find(|entry| {
            entry.device_id == device_id
                && entry.status == DeviceSetStatus::Active
                && entry.branch_certificate.as_ref().is_some_and(|cert| {
                    decode_base64url(&cert.body.branch_signing_public_key)
                        .is_ok_and(|key| key == device_signing_pk)
                })
        }) else {
            return Ok(None);
        };
        Ok(Some(DeviceIdentity {
            account_anchor: record.body.account_anchor.clone(),
            device_id: device_id.to_owned(),
            device_epoch: entry.device_epoch,
            device_set_epoch: record.body.device_set_epoch,
            device_signing_pk,
            signer: Box::new(BranchCertSigner { branch: branch.clone() }),
        }))
    }
}
