// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resolve carrier signers under verified principal/root authority, never a shared device name.
use super::invalid;
use crate::{RamfluxClient, SdkError};
impl RamfluxClient {
    pub(super) fn surface_signer_record(
        &self,
        principal: &str,
        device: &str,
    ) -> Result<serde_json::Value, SdkError> {
        let identity = self.peer_device_identity(principal, device)?;
        let record = self
            .account_db()?
            .client_device_record(&identity)?
            .ok_or_else(|| invalid("surface signer has no verified device record"))?;
        if record["principal_id"] != principal {
            return Err(invalid("surface signer principal mismatch"));
        }
        Ok(record)
    }
}
