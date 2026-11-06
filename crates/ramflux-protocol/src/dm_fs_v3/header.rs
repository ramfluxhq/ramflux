// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant canonical public service documents; authentication belongs to consumers.
use super::frames::{decode_optional, encode_optional};
use super::lease::encode_fields;
use super::publication::{field, fixed, owned_text as text, scan_publication};
use super::{DecodeError, QualifiedBranch, SignedNativePrekeyBase, WireType};
/// Canonical `BootstrapHeader` public fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapHeader {
    pub profile: String,
    pub source: QualifiedBranch,
    pub target: QualifiedBranch,
    pub base: SignedNativePrekeyBase,
    pub base_hash: [u8; 32],
    pub bundle_hash: [u8; 32],
    pub spk_id: [u8; 32],
    pub spk_serial: u64,
    pub generation: u64,
    pub opk_id: Option<[u8; 32]>,
    pub opk_key: Option<[u8; 32]>,
    pub ephemeral_key: [u8; 32],
    pub ratchet_key: [u8; 32],
    pub operation_id: [u8; 32],
    pub issued_at: u64,
    pub leased_at: u64,
    pub conversation_id: [u8; 32],
    pub session_id: String,
    pub sequence: u64,
    pub sequence_version: u64,
    pub deadline: u64,
    pub routed_ad: Vec<u8>,
}
impl BootstrapHeader {
    /// Encode canonical bytes.
    /// # Errors
    /// Rejects sizes, invalid values and incompatible field combinations.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        encode_fields(
            WireType::BootstrapHeader,
            &[
                self.profile.as_bytes(),
                &self.source.to_bytes()?,
                &self.target.to_bytes()?,
                &self.base.to_bytes()?,
                &self.base_hash,
                &self.bundle_hash,
                &self.spk_id,
                &self.spk_serial.to_be_bytes(),
                &self.generation.to_be_bytes(),
                &encode_optional(self.opk_id.as_ref(), |v| Ok(v.to_vec()))?,
                &encode_optional(self.opk_key.as_ref(), |v| Ok(v.to_vec()))?,
                &self.ephemeral_key,
                &self.ratchet_key,
                &self.operation_id,
                &self.issued_at.to_be_bytes(),
                &self.leased_at.to_be_bytes(),
                &self.conversation_id,
                self.session_id.as_bytes(),
                &self.sequence.to_be_bytes(),
                &self.sequence_version.to_be_bytes(),
                &self.deadline.to_be_bytes(),
                &self.routed_ad,
            ],
        )
    }
    /// Decode bounded canonical bytes before allocation.
    /// # Errors
    /// Rejects malformed framing, counts, codes and incompatible fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let view = scan_publication(WireType::BootstrapHeader, bytes)?;
        let value = Self {
            profile: text(field(view, 1)?)?,
            source: QualifiedBranch::from_bytes(field(view, 2)?)?,
            target: QualifiedBranch::from_bytes(field(view, 3)?)?,
            base: SignedNativePrekeyBase::from_bytes(field(view, 4)?)?,
            base_hash: fixed(field(view, 5)?)?,
            bundle_hash: fixed(field(view, 6)?)?,
            spk_id: fixed(field(view, 7)?)?,
            spk_serial: u64::from_be_bytes(fixed(field(view, 8)?)?),
            generation: u64::from_be_bytes(fixed(field(view, 9)?)?),
            opk_id: decode_optional(field(view, 10)?, fixed)?,
            opk_key: decode_optional(field(view, 11)?, fixed)?,
            ephemeral_key: fixed(field(view, 12)?)?,
            ratchet_key: fixed(field(view, 13)?)?,
            operation_id: fixed(field(view, 14)?)?,
            issued_at: u64::from_be_bytes(fixed(field(view, 15)?)?),
            leased_at: u64::from_be_bytes(fixed(field(view, 16)?)?),
            conversation_id: fixed(field(view, 17)?)?,
            session_id: text(field(view, 18)?)?,
            sequence: u64::from_be_bytes(fixed(field(view, 19)?)?),
            sequence_version: u64::from_be_bytes(fixed(field(view, 20)?)?),
            deadline: u64::from_be_bytes(fixed(field(view, 21)?)?),
            routed_ad: field(view, 22)?.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), DecodeError> {
        if self.opk_id.is_some() != self.opk_key.is_some() {
            return Err(DecodeError::Value);
        }
        Ok(())
    }
}
/// Canonical `BootstrapTranscript` public fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapTranscript {
    pub profile: String,
    pub header: BootstrapHeader,
    pub envelope_created_at: u64,
    pub envelope_ttl: u64,
    pub routed_ad: Vec<u8>,
}
impl BootstrapTranscript {
    /// Encode canonical bytes.
    /// # Errors
    /// Rejects sizes, invalid values and incompatible field combinations.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        encode_fields(
            WireType::BootstrapTranscript,
            &[
                self.profile.as_bytes(),
                &self.header.to_bytes()?,
                &self.envelope_created_at.to_be_bytes(),
                &self.envelope_ttl.to_be_bytes(),
                &self.routed_ad,
            ],
        )
    }
    /// Decode bounded canonical bytes before allocation.
    /// # Errors
    /// Rejects malformed framing, counts, codes and incompatible fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let view = scan_publication(WireType::BootstrapTranscript, bytes)?;
        let value = Self {
            profile: text(field(view, 1)?)?,
            header: BootstrapHeader::from_bytes(field(view, 2)?)?,
            envelope_created_at: u64::from_be_bytes(fixed(field(view, 3)?)?),
            envelope_ttl: u64::from_be_bytes(fixed(field(view, 4)?)?),
            routed_ad: field(view, 5)?.to_vec(),
        };
        Ok(value)
    }
}
