// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-authenticated identity kind, device keys and complete device-set publication.
use serde::{Deserialize, Serialize};
/// An immutable root assertion about the principal; it is not a proof of a biological human.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    HeadlessAi,
    Bot,
    Workflow,
}
/// Present only on a v2 branch proof; both keys and the principal kind are root-signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeyBinding {
    pub version: u32,
    pub principal_kind: PrincipalKind,
    pub branch_signing_public_key: String,
    pub agreement_identity_public_key: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceSetStatus {
    Active,
    Revoked,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeviceSetEntry {
    pub device_id: String,
    pub device_epoch: u64,
    pub signing_key_commitment: String,
    pub agreement_key_commitment: String,
    pub status: DeviceSetStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}
/// The entire sorted device set, including permanent revocation tombstones. Never filter entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeviceSetRecord {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    pub principal_id: String,
    pub principal_commitment: String,
    pub principal_kind: PrincipalKind,
    pub device_set_epoch: u64,
    pub devices: Vec<SignedDeviceSetEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Box<crate::SignedIdentityProfile>>,
    pub signature: String,
}
impl SignedDeviceSetRecord {
    /// Decode the original I-JSON bytes within a finite wire budget. Cryptographic verification
    /// and monotonic comparison are mandatory after decoding.
    /// # Errors
    /// Rejects oversized, duplicate-key or non-I-JSON input and invalid field types.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, crate::ProtocolError> {
        if bytes.len() > 512 * 1024 {
            return Err(crate::ProtocolError::InvalidIdentityRecord(
                "device set exceeds byte budget",
            ));
        }
        crate::parse_i_json(bytes)
    }
}
/// Canonical v1/v2 device-set signing bytes, with signature excluded and domain included.
/// # Errors
/// Rejects non-I-JSON values or serialization errors.
pub fn signed_device_set_signing_bytes(
    record: &SignedDeviceSetRecord,
) -> Result<Vec<u8>, crate::ProtocolError> {
    #[derive(Serialize)]
    struct Body<'a> {
        schema: &'a str,
        version: u32,
        domain: &'a str,
        principal_id: &'a str,
        principal_commitment: &'a str,
        principal_kind: PrincipalKind,
        device_set_epoch: u64,
        devices: &'a [SignedDeviceSetEntry],
        #[serde(skip_serializing_if = "Option::is_none")]
        profile: Option<&'a crate::SignedIdentityProfile>,
    }
    crate::canonical_json_bytes(&Body {
        schema: &record.schema,
        version: record.version,
        domain: &record.domain,
        principal_id: &record.principal_id,
        principal_commitment: &record.principal_commitment,
        principal_kind: record.principal_kind,
        device_set_epoch: record.device_set_epoch,
        devices: &record.devices,
        profile: record.profile.as_deref(),
    })
}
