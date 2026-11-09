// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P04-verified custody roster. Layer declarations exist only after `verify_native_authority`.
use super::invalid;
use crate::SdkError;
use crate::prekey::SdkDeviceManifestResponse;
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::custody::Device;

/// Directory roster whose nested signatures and layer bounds have passed P04.
///
/// The only constructor from directory bytes is [`Self::verify`]. An unverified
/// [`SdkDeviceManifestResponse`] cannot manufacture this type.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedLayerRoster {
    record: VerifiedRecord,
}

impl VerifiedLayerRoster {
    /// Run the P04 `verify_manifest` native-authority path.
    ///
    /// # Errors
    /// Rejects legacy unsigned directories and any record `verify_native_authority` refuses,
    /// including a swapped branch key, a validity window above 24 h, a forged layer
    /// signature, and a foreign or wrong-epoch declaration.
    pub(crate) fn verify(manifest: &SdkDeviceManifestResponse, now: u64) -> Result<Self, SdkError> {
        let native =
            manifest.custody.as_ref().ok_or_else(|| invalid("legacy unsigned directory"))?;
        let record = super::custody_directory::verify_native_authority(
            native,
            &manifest.principal_commitment,
            now,
        )?;
        Ok(Self { record })
    }

    /// Wrap a record that already came from P04 `verify_record` / `verify_publication`.
    #[must_use]
    pub(crate) fn from_verified(record: VerifiedRecord) -> Self {
        Self { record }
    }

    #[must_use]
    pub(crate) fn device(&self, device_id: &str) -> Option<&Device> {
        self.record.envelope().body.devices.iter().find(|row| row.device_id == device_id)
    }
}
