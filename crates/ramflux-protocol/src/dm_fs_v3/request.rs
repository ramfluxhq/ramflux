// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant canonical public service documents; authentication belongs to consumers.
use super::lease::encode_fields;
use super::publication::{field, fixed, owned_text as text, scan_publication, unsigned_body};
use super::{DecodeError, QualifiedBranch, WireType};
/// Closed stable wire values for `NativePrekeyAction`; unknown and empty codes reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePrekeyAction {
    /// Wire code `lease`.
    Lease,
    /// Wire code `publish`.
    Publish,
    /// Wire code `status`.
    Status,
}
impl NativePrekeyAction {
    /// Stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lease => "lease",
            Self::Publish => "publish",
            Self::Status => "status",
        }
    }
}
impl TryFrom<&str> for NativePrekeyAction {
    type Error = DecodeError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "lease" => Ok(Self::Lease),
            "publish" => Ok(Self::Publish),
            "status" => Ok(Self::Status),
            _ => Err(DecodeError::Value),
        }
    }
}
/// Canonical `NativePrekeyRequest` public fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrekeyRequest {
    pub profile: String,
    pub action: NativePrekeyAction,
    pub argument_hash: [u8; 32],
    pub source: QualifiedBranch,
    pub target: QualifiedBranch,
    pub home_generation: u64,
    pub node_id: String,
    pub node_record_hash: [u8; 32],
    pub gateway_id: String,
    pub session_id: String,
    pub nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: [u8; 64],
}
impl NativePrekeyRequest {
    /// Encode canonical bytes.
    /// # Errors
    /// Rejects sizes, invalid values and incompatible field combinations.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        encode_fields(
            WireType::NativePrekeyRequest,
            &[
                self.profile.as_bytes(),
                self.action.as_str().as_bytes(),
                &self.argument_hash,
                &self.source.to_bytes()?,
                &self.target.to_bytes()?,
                &self.home_generation.to_be_bytes(),
                self.node_id.as_bytes(),
                &self.node_record_hash,
                self.gateway_id.as_bytes(),
                self.session_id.as_bytes(),
                &self.nonce,
                &self.issued_at.to_be_bytes(),
                &self.expires_at.to_be_bytes(),
                &self.signature,
            ],
        )
    }
    /// Decode bounded canonical bytes before allocation.
    /// # Errors
    /// Rejects malformed framing, counts, codes and incompatible fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let view = scan_publication(WireType::NativePrekeyRequest, bytes)?;
        let value = Self {
            profile: text(field(view, 1)?)?,
            action: NativePrekeyAction::try_from(text(field(view, 2)?)?.as_str())?,
            argument_hash: fixed(field(view, 3)?)?,
            source: QualifiedBranch::from_bytes(field(view, 4)?)?,
            target: QualifiedBranch::from_bytes(field(view, 5)?)?,
            home_generation: u64::from_be_bytes(fixed(field(view, 6)?)?),
            node_id: text(field(view, 7)?)?,
            node_record_hash: fixed(field(view, 8)?)?,
            gateway_id: text(field(view, 9)?)?,
            session_id: text(field(view, 10)?)?,
            nonce: fixed(field(view, 11)?)?,
            issued_at: u64::from_be_bytes(fixed(field(view, 12)?)?),
            expires_at: u64::from_be_bytes(fixed(field(view, 13)?)?),
            signature: fixed(field(view, 14)?)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), DecodeError> {
        if self.expires_at.checked_sub(self.issued_at).is_none_or(|ttl| ttl > 300) {
            return Err(DecodeError::Value);
        }
        Ok(())
    }
    /// Canonical signing body, excluding the signature TLV.
    /// # Errors
    /// Returns the canonical encoding failure.
    pub fn signing_body(&self) -> Result<Vec<u8>, DecodeError> {
        unsigned_body(self.to_bytes()?)
    }
}
