// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public lease/status documents. Canonical codecs do not establish signatures,
//! current authority, operation-hash validity or lease-directory admission.
use super::{
    DecodeError, QualifiedBranch, RetirementRef, SignedNativeOpk, SignedNativePrekeyBase, WireType,
    scan,
};

/// Maximum entries in an owner status query or response.
pub const MAX_OWNER_STATUS_ENTRIES: usize = 200;
use super::publication::{
    decode_list, encode_list, field, fixed, owned_text as text, scan_publication,
    unsigned_body as unsigned,
};
type Result<T> = std::result::Result<T, DecodeError>;

/// Closed `LeaseFallback` wire codes; the authenticated directory owns their semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseFallback {
    /// Wire code `none`.
    None,
    /// Wire code `requester_quota`.
    RequesterQuota,
    /// Wire code `pair_quota`.
    PairQuota,
    /// Wire code `target_quota`.
    TargetQuota,
    /// Wire code `prefix_quota`.
    PrefixQuota,
    /// Wire code `pool_exhausted`.
    PoolExhausted,
    /// Wire code `storage_capacity`.
    StorageCapacity,
}
impl LeaseFallback {
    /// Stable lower-snake wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::RequesterQuota => "requester_quota",
            Self::PairQuota => "pair_quota",
            Self::TargetQuota => "target_quota",
            Self::PrefixQuota => "prefix_quota",
            Self::PoolExhausted => "pool_exhausted",
            Self::StorageCapacity => "storage_capacity",
        }
    }
}
impl TryFrom<&str> for LeaseFallback {
    type Error = DecodeError;
    fn try_from(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "requester_quota" => Ok(Self::RequesterQuota),
            "pair_quota" => Ok(Self::PairQuota),
            "target_quota" => Ok(Self::TargetQuota),
            "prefix_quota" => Ok(Self::PrefixQuota),
            "pool_exhausted" => Ok(Self::PoolExhausted),
            "storage_capacity" => Ok(Self::StorageCapacity),
            _ => Err(DecodeError::Value),
        }
    }
}

/// Closed `OwnerPrekeyState` wire codes; the authenticated directory owns their semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerPrekeyState {
    /// Wire code `unleased`.
    Unleased,
    /// Wire code `leased`.
    Leased,
    /// Wire code `retired`.
    Retired,
    /// Wire code `unknown`.
    Unknown,
}
impl OwnerPrekeyState {
    /// Stable lower-snake wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unleased => "unleased",
            Self::Leased => "leased",
            Self::Retired => "retired",
            Self::Unknown => "unknown",
        }
    }
}
impl TryFrom<&str> for OwnerPrekeyState {
    type Error = DecodeError;
    fn try_from(value: &str) -> Result<Self> {
        match value {
            "unleased" => Ok(Self::Unleased),
            "leased" => Ok(Self::Leased),
            "retired" => Ok(Self::Retired),
            "unknown" => Ok(Self::Unknown),
            _ => Err(DecodeError::Value),
        }
    }
}

/// Public `PublicPrekeyView` wire fields; authenticated verification belongs to its consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicPrekeyView {
    pub profile: String,
    pub base: SignedNativePrekeyBase,
    pub authority: QualifiedBranch,
    pub home_generation: u64,
}

impl PublicPrekeyView {
    /// Encode the bounded canonical document, including nested public signatures.
    /// # Errors
    /// Rejects noncanonical values, counts, field sizes and total byte sizes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_fields(
            WireType::PublicPrekeyView,
            &[
                self.profile.as_bytes(),
                &self.base.to_bytes()?,
                &self.authority.to_bytes()?,
                &self.home_generation.to_be_bytes(),
            ],
        )
    }

    /// Scan the full input before allocating any owned fields.
    /// # Errors
    /// Rejects malformed canonical framing, nested payloads, values and bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::PublicPrekeyView, bytes)?;
        Ok(Self {
            profile: text(field(view, 1)?)?,
            base: SignedNativePrekeyBase::from_bytes(field(view, 2)?)?,
            authority: QualifiedBranch::from_bytes(field(view, 3)?)?,
            home_generation: u64::from_be_bytes(fixed(field(view, 4)?)?),
        })
    }
}

/// Public `PrekeyLeaseIntent` wire fields; authenticated verification belongs to its consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyLeaseIntent {
    pub profile: String,
    pub requester: QualifiedBranch,
    pub target: QualifiedBranch,
    pub base_hash: [u8; 32],
    pub home_generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 32],
}

impl PrekeyLeaseIntent {
    /// Encode the bounded canonical document, including nested public signatures.
    /// # Errors
    /// Rejects noncanonical values, counts, field sizes and total byte sizes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_fields(
            WireType::PrekeyLeaseIntent,
            &[
                self.profile.as_bytes(),
                &self.requester.to_bytes()?,
                &self.target.to_bytes()?,
                &self.base_hash,
                &self.home_generation.to_be_bytes(),
                &self.issued_at.to_be_bytes(),
                &self.expires_at.to_be_bytes(),
                &self.nonce,
            ],
        )
    }

    /// Scan the full input before allocating any owned fields.
    /// # Errors
    /// Rejects malformed canonical framing, nested payloads, values and bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::PrekeyLeaseIntent, bytes)?;
        Ok(Self {
            profile: text(field(view, 1)?)?,
            requester: QualifiedBranch::from_bytes(field(view, 2)?)?,
            target: QualifiedBranch::from_bytes(field(view, 3)?)?,
            base_hash: fixed(field(view, 4)?)?,
            home_generation: u64::from_be_bytes(fixed(field(view, 5)?)?),
            issued_at: u64::from_be_bytes(fixed(field(view, 6)?)?),
            expires_at: u64::from_be_bytes(fixed(field(view, 7)?)?),
            nonce: fixed(field(view, 8)?)?,
        })
    }

    /// Exact operation-ID canonical input, excluding the separately carried ID.
    /// The P06 crypto layer adds the locked domain/NUL framing and BLAKE3 digest.
    /// # Errors
    /// Returns canonical encoding errors.
    pub fn operation_id_input_bytes(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }
}

/// Public `PrekeyLeaseResult` wire fields; authenticated verification belongs to its consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyLeaseResult {
    pub profile: String,
    pub base: SignedNativePrekeyBase,
    pub opk: Option<SignedNativeOpk>,
    pub requester: QualifiedBranch,
    pub target: QualifiedBranch,
    pub operation_id: [u8; 32],
    pub issued_at: u64,
    pub leased_at: u64,
    pub deadline: u64,
    pub fallback: LeaseFallback,
    pub signature: [u8; 64],
}

impl PrekeyLeaseResult {
    /// Encode the bounded canonical document, including nested public signatures.
    /// # Errors
    /// Rejects noncanonical values, counts, field sizes and total byte sizes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        validate_opk_fallback(self.opk.is_some(), self.fallback)?;
        encode_fields(
            WireType::PrekeyLeaseResult,
            &[
                self.profile.as_bytes(),
                &self.base.to_bytes()?,
                &encode_opk(self.opk.as_ref())?,
                &self.requester.to_bytes()?,
                &self.target.to_bytes()?,
                &self.operation_id,
                &self.issued_at.to_be_bytes(),
                &self.leased_at.to_be_bytes(),
                &self.deadline.to_be_bytes(),
                self.fallback.as_str().as_bytes(),
                &self.signature,
            ],
        )
    }

    /// Scan the full input before allocating any owned fields.
    /// # Errors
    /// Rejects malformed canonical framing, nested payloads, values and bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::PrekeyLeaseResult, bytes)?;
        let fallback = LeaseFallback::try_from(wire_code(field(view, 10)?)?)?;
        validate_opk_fallback(field(view, 3)?.first() == Some(&1), fallback)?;
        Ok(Self {
            profile: text(field(view, 1)?)?,
            base: SignedNativePrekeyBase::from_bytes(field(view, 2)?)?,
            opk: decode_opk(field(view, 3)?)?,
            requester: QualifiedBranch::from_bytes(field(view, 4)?)?,
            target: QualifiedBranch::from_bytes(field(view, 5)?)?,
            operation_id: fixed(field(view, 6)?)?,
            issued_at: u64::from_be_bytes(fixed(field(view, 7)?)?),
            leased_at: u64::from_be_bytes(fixed(field(view, 8)?)?),
            deadline: u64::from_be_bytes(fixed(field(view, 9)?)?),
            fallback,
            signature: fixed(field(view, 11)?)?,
        })
    }

    /// Exact unsigned RFS1 body; signature TLV omitted and field count decremented.
    /// # Errors
    /// Returns canonical encoding errors.
    pub fn signing_body_bytes(&self) -> Result<Vec<u8>> {
        unsigned(self.to_bytes()?)
    }
}

/// Public `OwnerStatusQuery` wire fields; authenticated verification belongs to its consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerStatusQuery {
    pub profile: String,
    pub owner: QualifiedBranch,
    pub requested_ids: Vec<RetirementRef>,
}

impl OwnerStatusQuery {
    /// Encode the bounded canonical document, including nested public signatures.
    /// # Errors
    /// Rejects noncanonical values, counts, field sizes and total byte sizes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_fields(
            WireType::OwnerStatusQuery,
            &[
                self.profile.as_bytes(),
                &self.owner.to_bytes()?,
                &encode_list(
                    &self.requested_ids,
                    MAX_OWNER_STATUS_ENTRIES,
                    RetirementRef::to_bytes,
                )?,
            ],
        )
    }

    /// Scan the full input before allocating any owned fields.
    /// # Errors
    /// Rejects malformed canonical framing, nested payloads, values and bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan_publication(WireType::OwnerStatusQuery, bytes)?;
        Ok(Self {
            profile: text(field(view, 1)?)?,
            owner: QualifiedBranch::from_bytes(field(view, 2)?)?,
            requested_ids: decode_list(
                field(view, 3)?,
                MAX_OWNER_STATUS_ENTRIES,
                RetirementRef::from_bytes,
            )?,
        })
    }
}

/// Public `OwnerStatusEntry` wire fields; authenticated verification belongs to its consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerStatusEntry {
    pub key_id: [u8; 32],
    pub generation: u64,
    pub serial: u64,
    pub leased_at: u64,
    pub deadline: u64,
    pub state: OwnerPrekeyState,
}

impl OwnerStatusEntry {
    /// Encode the bounded canonical document, including nested public signatures.
    /// # Errors
    /// Rejects noncanonical values, counts, field sizes and total byte sizes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate_times()?;
        encode_fields(
            WireType::OwnerStatusEntry,
            &[
                &self.key_id,
                &self.generation.to_be_bytes(),
                &self.serial.to_be_bytes(),
                &self.leased_at.to_be_bytes(),
                &self.deadline.to_be_bytes(),
                self.state.as_str().as_bytes(),
            ],
        )
    }

    /// Scan the full input before allocating any owned fields.
    /// # Errors
    /// Rejects malformed canonical framing, nested payloads, values and bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::OwnerStatusEntry, bytes)?;
        let value = Self {
            key_id: fixed(field(view, 1)?)?,
            generation: u64::from_be_bytes(fixed(field(view, 2)?)?),
            serial: u64::from_be_bytes(fixed(field(view, 3)?)?),
            leased_at: u64::from_be_bytes(fixed(field(view, 4)?)?),
            deadline: u64::from_be_bytes(fixed(field(view, 5)?)?),
            state: OwnerPrekeyState::try_from(wire_code(field(view, 6)?)?)?,
        };
        value.validate_times()?;
        Ok(value)
    }
    fn validate_times(&self) -> Result<()> {
        if self.state == OwnerPrekeyState::Unleased && (self.leased_at != 0 || self.deadline != 0) {
            return Err(DecodeError::Value);
        }
        Ok(())
    }
}

/// Public `OwnerPrekeyStatus` wire fields; authenticated verification belongs to its consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerPrekeyStatus {
    pub profile: String,
    pub owner: QualifiedBranch,
    pub base_hash: [u8; 32],
    pub publication_counter: u64,
    pub generation_floor: u64,
    pub activation: u64,
    pub retirement_ack: [u8; 32],
    pub unleased_count: u64,
    pub entries: Vec<OwnerStatusEntry>,
    pub signature: [u8; 64],
}

impl OwnerPrekeyStatus {
    /// Encode the bounded canonical document, including nested public signatures.
    /// # Errors
    /// Rejects noncanonical values, counts, field sizes and total byte sizes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_fields(
            WireType::OwnerPrekeyStatus,
            &[
                self.profile.as_bytes(),
                &self.owner.to_bytes()?,
                &self.base_hash,
                &self.publication_counter.to_be_bytes(),
                &self.generation_floor.to_be_bytes(),
                &self.activation.to_be_bytes(),
                &self.retirement_ack,
                &self.unleased_count.to_be_bytes(),
                &encode_list(&self.entries, MAX_OWNER_STATUS_ENTRIES, OwnerStatusEntry::to_bytes)?,
                &self.signature,
            ],
        )
    }

    /// Scan the full input before allocating any owned fields.
    /// # Errors
    /// Rejects malformed canonical framing, nested payloads, values and bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan_publication(WireType::OwnerPrekeyStatus, bytes)?;
        Ok(Self {
            profile: text(field(view, 1)?)?,
            owner: QualifiedBranch::from_bytes(field(view, 2)?)?,
            base_hash: fixed(field(view, 3)?)?,
            publication_counter: u64::from_be_bytes(fixed(field(view, 4)?)?),
            generation_floor: u64::from_be_bytes(fixed(field(view, 5)?)?),
            activation: u64::from_be_bytes(fixed(field(view, 6)?)?),
            retirement_ack: fixed(field(view, 7)?)?,
            unleased_count: u64::from_be_bytes(fixed(field(view, 8)?)?),
            entries: decode_list(
                field(view, 9)?,
                MAX_OWNER_STATUS_ENTRIES,
                OwnerStatusEntry::from_bytes,
            )?,
            signature: fixed(field(view, 10)?)?,
        })
    }

    /// Exact unsigned RFS1 body; signature TLV omitted and field count decremented.
    /// # Errors
    /// Returns canonical encoding errors.
    pub fn signing_body_bytes(&self) -> Result<Vec<u8>> {
        unsigned(self.to_bytes()?)
    }
}

pub(super) fn encode_fields(kind: WireType, fields: &[&[u8]]) -> Result<Vec<u8>> {
    let specs = kind.specs();
    if fields.len() != specs.len() {
        return Err(DecodeError::Fields);
    }
    let mut total = 8usize;
    for (value, spec) in fields.iter().zip(specs) {
        if value.len() > spec.max {
            return Err(DecodeError::FieldCeiling);
        }
        total = total
            .checked_add(6)
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(DecodeError::TypeCeiling)?;
    }
    if total > kind.ceiling() {
        return Err(DecodeError::TypeCeiling);
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(b"RFS1");
    bytes.extend_from_slice(&[kind as u8, 1]);
    bytes.extend_from_slice(
        &u16::try_from(fields.len()).map_err(|_| DecodeError::Fields)?.to_be_bytes(),
    );
    for (value, spec) in fields.iter().zip(specs) {
        bytes.extend_from_slice(&spec.id.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(value.len()).map_err(|_| DecodeError::FieldCeiling)?.to_be_bytes(),
        );
        bytes.extend_from_slice(value);
    }
    scan(kind, &bytes)?;
    Ok(bytes)
}
fn encode_opk(value: Option<&SignedNativeOpk>) -> Result<Vec<u8>> {
    match value {
        None => Ok(vec![0]),
        Some(opk) => {
            let mut bytes = vec![1];
            bytes.extend_from_slice(&opk.to_bytes()?);
            Ok(bytes)
        }
    }
}
fn decode_opk(bytes: &[u8]) -> Result<Option<SignedNativeOpk>> {
    match bytes.split_first() {
        Some((0, [])) => Ok(None),
        Some((1, body)) => SignedNativeOpk::from_bytes(body).map(Some),
        _ => Err(DecodeError::Value),
    }
}

fn wire_code(value: &[u8]) -> Result<&str> {
    std::str::from_utf8(value).map_err(|_| DecodeError::Value)
}
fn validate_opk_fallback(present: bool, fallback: LeaseFallback) -> Result<()> {
    if present == (fallback == LeaseFallback::None) { Ok(()) } else { Err(DecodeError::Value) }
}
