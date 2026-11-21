// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded account-journal reference to separately encrypted full-transfer stage metadata.
//! A reference alone never restores SAS consent, data-resume trust or native authority.
use crate::{LiveRow, StorageError};
use ramflux_protocol::custody::pairing::{PairingWire, WireError, full_transfer::U64};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct ReferenceHeader {
    kind: Option<String>,
}

pub const FULL_STAGE_REFERENCE_KIND: &str = "full_transfer_stage_ref_v1";
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullStageReference {
    pub kind: String,
    pub lease_expires_at: U64,
    pub record_digest: String,
    pub stage_id: String,
}
impl PairingWire for FullStageReference {
    const LIMIT: usize = 1024;
    fn validate(&self) -> Result<(), WireError> {
        if self.kind != FULL_STAGE_REFERENCE_KIND
            || self.lease_expires_at.0 == 0
            || self.lease_expires_at.0 > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        {
            return Err(WireError::Field("full_stage_ref"));
        }
        for value in [&self.record_digest, &self.stage_id] {
            if value.len() != 43
                || !ramflux_protocol::decode_base64url(value).is_ok_and(|bytes| {
                    bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == *value
                })
            {
                return Err(WireError::Field("full_stage_ref"));
            }
        }
        Ok(())
    }
}
/// Inspect a local row discriminator, then decode its exact closed reference arm. A legacy
/// context is still checked by its original closed decoder; null/unknown/extra kinds cannot pass.
pub(super) fn decode_reference(bytes: &[u8]) -> Result<Option<FullStageReference>, StorageError> {
    if bytes.len() > 57_344 {
        return Err(StorageError::PairingField("context"));
    }
    let header: ReferenceHeader =
        ramflux_protocol::parse_i_json(bytes).map_err(|_| StorageError::PairingField("context"))?;
    let Some(kind) = header.kind else { return Ok(None) };
    if kind != FULL_STAGE_REFERENCE_KIND {
        return Err(StorageError::PairingField("context"));
    }
    FullStageReference::from_wire_bytes(bytes)
        .map(Some)
        .map_err(|_| StorageError::PairingField("full_stage_ref"))
}
impl LiveRow {
    /// Read a data-only stage reference. The encrypted stage owner must independently verify
    /// its exact digest/expiry/account before data resume; missing stages stay fenced.
    /// # Errors
    /// Refuses malformed or over-size local reference bytes.
    pub fn full_stage_reference(&self) -> Result<Option<FullStageReference>, StorageError> {
        self.context.as_deref().map(decode_reference).transpose().map(Option::flatten)
    }
}
