// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant `device_pairing_v2` codecs and preimages. These grant no authority.
//! Certificate/head, invitation projection and live ceremony checks belong to callers.
use super::{DeviceRef, MAX_BRANCH_LEASE_SECONDS};
use crate::{
    MAX_SAFE_JSON_INTEGER, canonical_json_bytes, decode_base64url, domain, encode_base64url,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const MAX_COMMON_BYTES: usize = 15_872;
pub const MAX_ROLE_BYTES: usize = 20_480;
pub const MAX_TRANSCRIPT_BYTES: usize = 2 * MAX_ROLE_BYTES + 512;
pub mod native;
pub mod relay;

pub const PROFILE: &str = "device_pairing_v2";

/// Stable codec errors; field names never contain peer-provided diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("invalid pairing field: {0}")]
    Field(&'static str),
    #[error("invalid pairing JSON")]
    Json,
    #[error("pairing fields must be explicit and exact")]
    Shape,
    #[error("pairing byte budget exceeded")]
    Size,
    #[error("noncanonical pairing bytes")]
    NonCanonical,
}
type Result<T> = std::result::Result<T, WireError>;
fn require(ok: bool, field: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(WireError::Field(field)) }
}
fn b32(value: &str, field: &'static str) -> Result<()> {
    require(
        value.len() == 43
            && decode_base64url(value).is_ok_and(|v| v.len() == 32 && encode_base64url(v) == value),
        field,
    )
}
fn integer(value: u64, field: &'static str) -> Result<()> {
    require(value <= MAX_SAFE_JSON_INTEGER, field)
}
fn text(value: &str, nonempty: bool, field: &'static str) -> Result<()> {
    require(
        (!nonempty || !value.is_empty())
            && value.len() <= 128
            && !value.chars().any(char::is_control),
        field,
    )
}
fn reference(value: &DeviceRef) -> Result<()> {
    b32(&value.account_anchor, "ref.account_anchor")?;
    text(&value.device_id, true, "ref.device_id")?;
    integer(value.device_epoch, "ref.device_epoch")?;
    require(value.device_epoch >= 1, "ref.device_epoch")
}
fn header(schema: &str, version: u32, name: &str) -> Result<()> {
    require(schema == format!("ramflux.pairing.{name}.v2"), "schema")?;
    require(version == 2, "version")
}
fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    canonical_json_bytes(value).map_err(|_| WireError::Json)
}
fn budget<T: Serialize>(value: &T, max: usize) -> Result<()> {
    if bytes(value)?.len() > max { Err(WireError::Size) } else { Ok(()) }
}

/// Shared canonical codec. Only encoders sort ordered collections.
pub trait PairingWire: Serialize + DeserializeOwned + Clone {
    const LIMIT: usize;
    /// Validate all local schema rules, without granting current-head authority.
    /// # Errors
    /// Returns the exact invalid field or size error.
    fn validate(&self) -> Result<()>;
    fn normalize(&mut self) {}
    /// Encode, sorting declared ordered collections without dropping duplicates.
    /// # Errors
    /// Rejects invalid fields, duplicates and excess bytes.
    fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        let mut value = self.clone();
        value.normalize();
        value.validate()?;
        budget(&value, Self::LIMIT)?;
        bytes(&value)
    }
    /// Decode original bytes without sorting, clamping or filling nullable fields.
    /// # Errors
    /// Rejects non-I-JSON, unknown/missing fields, noncanonical bytes and invalid values.
    fn from_wire_bytes(input: &[u8]) -> Result<Self> {
        if input.len() > Self::LIMIT {
            return Err(WireError::Size);
        }
        let raw: serde_json::Value = crate::parse_i_json(input).map_err(|_| WireError::Json)?;
        let value: Self = serde_json::from_value(raw.clone()).map_err(|_| WireError::Shape)?;
        if serde_json::to_value(&value).map_err(|_| WireError::Json)? != raw {
            return Err(WireError::Shape);
        }
        value.validate()?;
        if bytes(&value)? != input {
            return Err(WireError::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataSelection {
    pub key_id: String,
    pub purpose: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Common {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub account_anchor: String,
    pub master_public_key: String,
    pub record_hash: String,
    pub device_set_epoch: u64,
    pub principal_kind: String,
    pub sas_suite: String,
    pub hpke_suite: Option<String>,
    pub purpose: String,
    pub requested_role: String,
    pub recipient_mode: String,
    pub destination_ref: Option<DeviceRef>,
    pub capabilities: Vec<String>,
    pub lease_not_before: u64,
    pub lease_expires_at: u64,
    pub expires_at: u64,
    pub transfer_id: Option<String>,
    pub data_selection: Vec<DataSelection>,
}
impl Common {
    /// Check invitation creation and authority lease bounds from verified evidence.
    /// # Errors
    /// Rejects a lifetime beyond 300 seconds or a lease outside current authority.
    pub fn validate_bounds(
        &self,
        created_at: u64,
        authority_start: u64,
        authority_end: u64,
    ) -> Result<()> {
        self.validate()?;
        integer(created_at, "created_at")?;
        require(
            self.expires_at >= created_at && self.expires_at - created_at <= 300,
            "invitation_lifetime",
        )?;
        require(
            self.lease_not_before >= authority_start && self.lease_expires_at <= authority_end,
            "authority_lease",
        )
    }
}
impl PairingWire for Common {
    const LIMIT: usize = MAX_COMMON_BYTES;
    fn normalize(&mut self) {
        self.capabilities.sort();
        self.data_selection.sort();
    }
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Common")?;
        for (v, field) in [
            (&self.invitation_id, "invitation_id"),
            (&self.account_anchor, "account_anchor"),
            (&self.master_public_key, "master_public_key"),
            (&self.record_hash, "record_hash"),
        ] {
            b32(v, field)?;
        }
        integer(self.issuer_seq, "issuer_seq")?;
        require(self.issuer_seq >= 1, "issuer_seq")?;
        integer(self.device_set_epoch, "device_set_epoch")?;
        require(self.principal_kind == "human", "principal_kind")?;
        require(self.sas_suite == domain::CUSTODY_PAIRING_EMOJI_SUITE, "sas_suite")?;
        require(matches!(self.purpose.as_str(), "enroll" | "primary_transfer"), "purpose")?;
        require(matches!(self.requested_role.as_str(), "secondary" | "primary"), "requested_role")?;
        require(matches!(self.recipient_mode.as_str(), "new" | "existing"), "recipient_mode")?;
        require(
            !self.capabilities.is_empty()
                && self.capabilities.len() <= 5
                && self.capabilities.iter().all(|c| {
                    matches!(c.as_str(), "call" | "group" | "message" | "register" | "sync")
                })
                && self.capabilities.windows(2).all(|w| w[0] < w[1]),
            "capabilities",
        )?;
        for (v, f) in [
            (self.lease_not_before, "lease_not_before"),
            (self.lease_expires_at, "lease_expires_at"),
            (self.expires_at, "expires_at"),
        ] {
            integer(v, f)?;
        }
        require(
            self.lease_expires_at > self.lease_not_before
                && self.lease_expires_at - self.lease_not_before <= MAX_BRANCH_LEASE_SECONDS,
            "lease",
        )?;
        require(
            self.destination_ref.is_some() == (self.recipient_mode == "existing"),
            "destination_ref",
        )?;
        if let Some(v) = &self.destination_ref {
            reference(v)?;
            require(v.account_anchor == self.account_anchor, "destination_anchor")?;
        }
        if let Some(v) = &self.transfer_id {
            b32(v, "transfer_id")?;
        }
        require(
            self.data_selection.len() <= 32 && self.data_selection.windows(2).all(|w| w[0] < w[1]),
            "data_selection",
        )?;
        for v in &self.data_selection {
            text(&v.key_id, true, "selection.key_id")?;
            require(matches!(v.purpose.as_str(), "history" | "attachment"), "selection.purpose")?;
            budget(v, 384)?;
        }
        if self.purpose == "enroll" {
            require(
                self.requested_role == "secondary"
                    && self.recipient_mode == "new"
                    && self.transfer_id.is_none()
                    && self.hpke_suite.is_none()
                    && self.data_selection.is_empty(),
                "enroll_context",
            )?;
        } else {
            require(
                self.requested_role == "primary"
                    && self.transfer_id.is_some()
                    && self.hpke_suite.as_deref() == Some(domain::CUSTODY_TRANSFER_HPKE_SUITE),
                "transfer_context",
            )?;
        }
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleContext {
    pub schema: String,
    pub version: u32,
    pub role: String,
    pub common: Common,
    pub device_ref: DeviceRef,
    pub branch_key: String,
    pub agreement_key: String,
    pub sas_key: String,
    pub hpke_key: Option<String>,
    pub display_name: String,
}
impl PairingWire for RoleContext {
    const LIMIT: usize = MAX_ROLE_BYTES;
    fn normalize(&mut self) {
        self.common.normalize();
    }
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "RoleContext")?;
        require(matches!(self.role.as_str(), "initiator" | "responder"), "role")?;
        self.common.validate()?;
        reference(&self.device_ref)?;
        require(self.device_ref.account_anchor == self.common.account_anchor, "device_anchor")?;
        for (v, f) in [
            (&self.branch_key, "branch_key"),
            (&self.agreement_key, "agreement_key"),
            (&self.sas_key, "sas_key"),
        ] {
            b32(v, f)?;
        }
        require(
            self.hpke_key.is_some() == (self.common.purpose == "primary_transfer"),
            "hpke_key",
        )?;
        if let Some(v) = &self.hpke_key {
            b32(v, "hpke_key")?;
        }
        require(
            self.display_name.len() <= 128
                && crate::text_safety::free_text_is_safe(&self.display_name),
            "display_name",
        )?;
        if self.role == "responder"
            && let Some(v) = &self.common.destination_ref
        {
            require(v == &self.device_ref, "destination_device")?;
        }
        if self.role == "initiator"
            && let Some(v) = &self.common.destination_ref
        {
            require(v.device_id != self.device_ref.device_id, "destination_is_primary")?;
        }
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transcript {
    pub schema: String,
    pub version: u32,
    pub initiator: RoleContext,
    pub responder: RoleContext,
}
impl PairingWire for Transcript {
    const LIMIT: usize = MAX_TRANSCRIPT_BYTES;
    fn normalize(&mut self) {
        self.initiator.normalize();
        self.responder.normalize();
    }
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Transcript")?;
        self.initiator.validate()?;
        self.responder.validate()?;
        require(
            self.initiator.role == "initiator" && self.responder.role == "responder",
            "role_slots",
        )?;
        require(self.initiator.common == self.responder.common, "common_binding")?;
        require(
            self.initiator.device_ref.device_id != self.responder.device_ref.device_id,
            "distinct_devices",
        )?;
        budget(self, Self::LIMIT)
    }
}
/// SHA-256 input only. Hashing and secret-key operations belong to crypto adapters.
/// # Errors
/// Rejects invalid or unsorted frozen context. No normalization occurs here.
pub fn context_commitment_preimage(context: &RoleContext, salt: &[u8; 32]) -> Result<Vec<u8>> {
    context.validate()?;
    let mut out = domain::CUSTODY_PAIRING_CONTEXT_COMMITMENT_V2.as_bytes().to_vec();
    out.push(0);
    out.push(u8::from(context.role == "responder"));
    out.extend_from_slice(salt);
    out.extend(bytes(context)?);
    Ok(out)
}
/// Exact transcript SHA-256 input, preserving both complete role objects.
/// # Errors
/// Rejects invalid or unsorted frozen transcript.
pub fn transcript_preimage(transcript: &Transcript) -> Result<Vec<u8>> {
    transcript.validate()?;
    let mut out = domain::CUSTODY_PAIRING_TRANSCRIPT_V2.as_bytes().to_vec();
    out.push(0);
    out.extend(bytes(transcript)?);
    Ok(out)
}

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextOffer {
    pub schema: String,
    pub version: u32,
    pub common: Common,
}
impl PairingWire for ContextOffer {
    const LIMIT: usize = 16_384;
    fn normalize(&mut self) {
        self.common.normalize();
    }
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "ContextOffer")?;
        self.common.validate()?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub role: String,
    pub commitment: String,
}
impl PairingWire for Commit {
    const LIMIT: usize = 512;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Commit")?;
        b32(&self.invitation_id, "invitation_id")?;
        require(matches!(self.role.as_str(), "initiator" | "responder"), "role")?;
        b32(&self.commitment, "commitment")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reveal {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub role: String,
    pub salt: String,
    pub context: RoleContext,
}
impl PairingWire for Reveal {
    const LIMIT: usize = 24_576;
    fn normalize(&mut self) {
        self.context.normalize();
    }
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Reveal")?;
        b32(&self.invitation_id, "invitation_id")?;
        b32(&self.salt, "salt")?;
        self.context.validate()?;
        require(self.role == self.context.role, "reveal_role")?;
        require(self.invitation_id == self.context.common.invitation_id, "reveal_invitation")?;
        budget(self, Self::LIMIT)
    }
}
