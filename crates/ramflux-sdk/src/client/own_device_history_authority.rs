// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Freshness of a verified peer directory snapshot against the newest observed authority.
use crate::prekey::SdkDeviceManifestResponse;
use crate::{RamfluxClient, SdkError};

impl RamfluxClient {
    pub(super) fn directory_snapshot_is_obsolete(
        &self,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<bool, SdkError> {
        if let Some(native) = &manifest.custody {
            return Ok(self
                .custody_epoch_floor(&manifest.principal_commitment)?
                .is_some_and(|floor| floor > native.publication.record.body.device_set_epoch));
        }
        Ok(self
            .observed_device_set(&manifest.principal_commitment)?
            .zip(manifest.signed_device_set.as_ref())
            .is_some_and(|(current, old)| current.device_set_epoch > old.device_set_epoch))
    }
}
