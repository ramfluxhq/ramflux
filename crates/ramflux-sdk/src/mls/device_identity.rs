// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The own device identity for MLS device credentials: root key, signed device set and the device
//! signing key of the account.
use ed25519_dalek::Signer;
use ramflux_crypto::DeviceBranch;
use ramflux_mls::{DeviceCertSigner, DeviceIdentity, MlsError};
use ramflux_protocol::SignedDeviceSetRecord;

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
    /// The own MLS device identity, from the account's signed device set and device key.
    ///
    /// `Ok(None)` when this account has no raw root or device key or no accepted device set
    /// (for example a custody-native account); a `dm` group then fails with a typed error and
    /// pseudonym groups are unaffected.
    ///
    /// # Errors
    /// Storage failures and a stored record that cannot be encoded.
    pub(crate) fn mls_device_identity(&self) -> Result<Option<DeviceIdentity>, SdkError> {
        let (Some(root), Some(branch)) = (&self.identity_root, &self.device_branch) else {
            return Ok(None);
        };
        let root_key = root.signing_key.verifying_key();
        let commitment = ramflux_crypto::identity_root_commitment(&root_key);
        let db = self.account_db()?;
        let key = super::super::client::identity_authority::record_key(&commitment);
        let record: Option<SignedDeviceSetRecord> = db.load_actor_state(&key)?;
        let Some(record) = record else {
            return Ok(None);
        };
        // The credential carries the record as I-JSON bytes; the verifier re-parses and checks the
        // root signature, so the serialization of the stored record is the wire form.
        let device_set_record = serde_json::to_vec(&record)?;
        Ok(Some(DeviceIdentity {
            root_vk: root_key.to_bytes(),
            device_id: branch.device_id.clone(),
            device_set_record,
            device_signing_pk: branch.signing_key.verifying_key().to_bytes(),
            signer: Box::new(BranchCertSigner { branch: branch.clone() }),
        }))
    }
}
