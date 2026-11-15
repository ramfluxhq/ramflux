// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read the highest independently observed signed publication, including tombstones.
use super::record_key;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::SignedDeviceSetRecord;

impl RamfluxClient {
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
