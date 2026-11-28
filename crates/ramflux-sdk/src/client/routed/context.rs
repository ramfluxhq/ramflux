// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only pairing helper for the routed client.
use super::RamfluxClient;
#[cfg(test)]
use super::SdkError;
impl RamfluxClient {
    #[cfg(test)]
    pub(crate) fn v2_blocks_legacy(&self, remote: &str) -> Result<bool, SdkError> {
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
        Ok(self
            .active_pair(&self.local_device_identity(local)?, &self.device_identity(remote)?)?
            .is_some())
    }
}
