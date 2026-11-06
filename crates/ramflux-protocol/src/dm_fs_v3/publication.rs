// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned public publication documents and strict RFS1 codecs.
//! These types contain no secret keys and perform no signing or authority checks.
use super::{DecodeError, Scanned, WireType, scan, valid_custody_id};

/// The only profile accepted by these dormant components.
pub const NATIVE_PREKEY_PROFILE: &str = "ramflux.dm.bootstrap.fs.v1";
/// Maximum additive OPKs per owner update.
pub const MAX_ADDITIVE_OPKS: usize = 64;
/// Maximum retirement references in one update or snapshot.
pub const MAX_RETIREMENT_REFS: usize = 400;
type Result<T> = std::result::Result<T, DecodeError>;

/// Public `QualifiedBranch` fields; signature validity is checked by the crypto layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedBranch {
    pub account_anchor: [u8; 32],
    pub principal_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub certificate_hash: [u8; 32],
    pub record_hash: [u8; 32],
    pub signing_key: [u8; 32],
    pub agreement_key: [u8; 32],
}

impl QualifiedBranch {
    /// Encode the exact canonical RFS1 document.
    /// # Errors
    /// Rejects invalid profiles/identifiers, count limits, field sizes or total size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new(WireType::QualifiedBranch);
        writer.push(1, &self.account_anchor)?;
        writer.push(2, id_bytes(&self.principal_id)?)?;
        writer.push(3, id_bytes(&self.device_id)?)?;
        writer.push(4, &self.device_epoch.to_be_bytes())?;
        writer.push(5, &self.certificate_hash)?;
        writer.push(6, &self.record_hash)?;
        writer.push(7, &self.signing_key)?;
        writer.push(8, &self.agreement_key)?;
        writer.finish()
    }

    /// Decode only after the complete document passes the borrowed scanner.
    /// # Errors
    /// Rejects every noncanonical field, nested object, count, size or trailing byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::QualifiedBranch, bytes)?;
        Ok(Self {
            account_anchor: fixed(field(view, 1)?)?,
            principal_id: owned_text(field(view, 2)?)?,
            device_id: owned_text(field(view, 3)?)?,
            device_epoch: u64::from_be_bytes(fixed(field(view, 4)?)?),
            certificate_hash: fixed(field(view, 5)?)?,
            record_hash: fixed(field(view, 6)?)?,
            signing_key: fixed(field(view, 7)?)?,
            agreement_key: fixed(field(view, 8)?)?,
        })
    }
}

/// Public `SignedNativePrekeyBase` fields; signature validity is checked by the crypto layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedNativePrekeyBase {
    pub profile: String,
    pub branch: QualifiedBranch,
    pub generation: u64,
    pub spk_id: [u8; 32],
    pub spk_serial: u64,
    pub spk_key: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub update_counter: u64,
    pub capabilities: String,
    pub signature: [u8; 64],
}

impl SignedNativePrekeyBase {
    /// Encode the exact canonical RFS1 document.
    /// # Errors
    /// Rejects invalid profiles/identifiers, count limits, field sizes or total size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new(WireType::SignedNativePrekeyBase);
        writer.push(1, profile_bytes(&self.profile)?)?;
        writer.push(2, &self.branch.to_bytes()?)?;
        writer.push(3, &self.generation.to_be_bytes())?;
        writer.push(4, &self.spk_id)?;
        writer.push(5, &self.spk_serial.to_be_bytes())?;
        writer.push(6, &self.spk_key)?;
        writer.push(7, &self.issued_at.to_be_bytes())?;
        writer.push(8, &self.expires_at.to_be_bytes())?;
        writer.push(9, &self.update_counter.to_be_bytes())?;
        writer.push(10, self.capabilities.as_bytes())?;
        writer.push(11, &self.signature)?;
        writer.finish()
    }

    /// Decode only after the complete document passes the borrowed scanner.
    /// # Errors
    /// Rejects every noncanonical field, nested object, count, size or trailing byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::SignedNativePrekeyBase, bytes)?;
        Ok(Self {
            profile: owned_text(field(view, 1)?)?,
            branch: QualifiedBranch::from_bytes(field(view, 2)?)?,
            generation: u64::from_be_bytes(fixed(field(view, 3)?)?),
            spk_id: fixed(field(view, 4)?)?,
            spk_serial: u64::from_be_bytes(fixed(field(view, 5)?)?),
            spk_key: fixed(field(view, 6)?)?,
            issued_at: u64::from_be_bytes(fixed(field(view, 7)?)?),
            expires_at: u64::from_be_bytes(fixed(field(view, 8)?)?),
            update_counter: u64::from_be_bytes(fixed(field(view, 9)?)?),
            capabilities: owned_text(field(view, 10)?)?,
            signature: fixed(field(view, 11)?)?,
        })
    }

    /// Canonical unsigned body: same type/version, signature field omitted and
    /// field count decremented. The crypto layer adds its domain and NUL byte.
    /// # Errors
    /// Returns the same validation errors as `to_bytes`.
    pub fn signing_body_bytes(&self) -> Result<Vec<u8>> {
        unsigned_body(self.to_bytes()?)
    }
}

/// Public `SignedNativeOpk` fields; signature validity is checked by the crypto layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedNativeOpk {
    pub profile: String,
    pub branch_binding: [u8; 32],
    pub generation: u64,
    pub serial: u64,
    pub opk_id: [u8; 32],
    pub opk_key: [u8; 32],
    pub signature: [u8; 64],
}

impl SignedNativeOpk {
    /// Encode the exact canonical RFS1 document.
    /// # Errors
    /// Rejects invalid profiles/identifiers, count limits, field sizes or total size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new(WireType::SignedNativeOpk);
        writer.push(1, profile_bytes(&self.profile)?)?;
        writer.push(2, &self.branch_binding)?;
        writer.push(3, &self.generation.to_be_bytes())?;
        writer.push(4, &self.serial.to_be_bytes())?;
        writer.push(5, &self.opk_id)?;
        writer.push(6, &self.opk_key)?;
        writer.push(7, &self.signature)?;
        writer.finish()
    }

    /// Decode only after the complete document passes the borrowed scanner.
    /// # Errors
    /// Rejects every noncanonical field, nested object, count, size or trailing byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::SignedNativeOpk, bytes)?;
        Ok(Self {
            profile: owned_text(field(view, 1)?)?,
            branch_binding: fixed(field(view, 2)?)?,
            generation: u64::from_be_bytes(fixed(field(view, 3)?)?),
            serial: u64::from_be_bytes(fixed(field(view, 4)?)?),
            opk_id: fixed(field(view, 5)?)?,
            opk_key: fixed(field(view, 6)?)?,
            signature: fixed(field(view, 7)?)?,
        })
    }

    /// Canonical unsigned body: same type/version, signature field omitted and
    /// field count decremented. The crypto layer adds its domain and NUL byte.
    /// # Errors
    /// Returns the same validation errors as `to_bytes`.
    pub fn signing_body_bytes(&self) -> Result<Vec<u8>> {
        unsigned_body(self.to_bytes()?)
    }
}

/// Public `RetirementRef` fields; signature validity is checked by the crypto layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementRef {
    pub generation: u64,
    pub serial: u64,
    pub key_id: [u8; 32],
}

impl RetirementRef {
    /// Encode the exact canonical RFS1 document.
    /// # Errors
    /// Rejects invalid profiles/identifiers, count limits, field sizes or total size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new(WireType::RetirementRef);
        writer.push(1, &self.generation.to_be_bytes())?;
        writer.push(2, &self.serial.to_be_bytes())?;
        writer.push(3, &self.key_id)?;
        writer.finish()
    }

    /// Decode only after the complete document passes the borrowed scanner.
    /// # Errors
    /// Rejects every noncanonical field, nested object, count, size or trailing byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::RetirementRef, bytes)?;
        Ok(Self {
            generation: u64::from_be_bytes(fixed(field(view, 1)?)?),
            serial: u64::from_be_bytes(fixed(field(view, 2)?)?),
            key_id: fixed(field(view, 3)?)?,
        })
    }
}

/// Public `OwnerPrekeyUpdate` fields; signature validity is checked by the crypto layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerPrekeyUpdate {
    pub profile: String,
    pub base: SignedNativePrekeyBase,
    pub update_counter: u64,
    pub additive_opks: Vec<SignedNativeOpk>,
    pub retirements: Vec<RetirementRef>,
    pub signature: [u8; 64],
}

impl OwnerPrekeyUpdate {
    /// Encode the exact canonical RFS1 document.
    /// # Errors
    /// Rejects invalid profiles/identifiers, count limits, field sizes or total size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new(WireType::OwnerPrekeyUpdate);
        writer.push(1, profile_bytes(&self.profile)?)?;
        writer.push(2, &self.base.to_bytes()?)?;
        writer.push(3, &self.update_counter.to_be_bytes())?;
        writer.push(
            4,
            &encode_list(&self.additive_opks, MAX_ADDITIVE_OPKS, SignedNativeOpk::to_bytes)?,
        )?;
        writer.push(
            5,
            &encode_list(&self.retirements, MAX_RETIREMENT_REFS, RetirementRef::to_bytes)?,
        )?;
        writer.push(6, &self.signature)?;
        writer.finish()
    }

    /// Decode only after the complete document passes the borrowed scanner.
    /// # Errors
    /// Rejects every noncanonical field, nested object, count, size or trailing byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::OwnerPrekeyUpdate, bytes)?;
        Ok(Self {
            profile: owned_text(field(view, 1)?)?,
            base: SignedNativePrekeyBase::from_bytes(field(view, 2)?)?,
            update_counter: u64::from_be_bytes(fixed(field(view, 3)?)?),
            additive_opks: decode_list(
                field(view, 4)?,
                MAX_ADDITIVE_OPKS,
                SignedNativeOpk::from_bytes,
            )?,
            retirements: decode_list(
                field(view, 5)?,
                MAX_RETIREMENT_REFS,
                RetirementRef::from_bytes,
            )?,
            signature: fixed(field(view, 6)?)?,
        })
    }

    /// Canonical unsigned body: same type/version, signature field omitted and
    /// field count decremented. The crypto layer adds its domain and NUL byte.
    /// # Errors
    /// Returns the same validation errors as `to_bytes`.
    pub fn signing_body_bytes(&self) -> Result<Vec<u8>> {
        unsigned_body(self.to_bytes()?)
    }
}

/// Public `PrekeyPublicationSnapshot` fields; signature validity is checked by the crypto layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyPublicationSnapshot {
    pub profile: String,
    pub update: OwnerPrekeyUpdate,
    pub counter: u64,
    pub epoch: u64,
    pub generation: u64,
    pub pending_retirements: Vec<RetirementRef>,
    pub retirement_digest: [u8; 32],
}

impl PrekeyPublicationSnapshot {
    /// Encode the exact canonical RFS1 document.
    /// # Errors
    /// Rejects invalid profiles/identifiers, count limits, field sizes or total size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new(WireType::PrekeyPublicationSnapshot);
        writer.push(1, profile_bytes(&self.profile)?)?;
        writer.push(2, &self.update.to_bytes()?)?;
        writer.push(3, &self.counter.to_be_bytes())?;
        writer.push(4, &self.epoch.to_be_bytes())?;
        writer.push(5, &self.generation.to_be_bytes())?;
        writer.push(
            6,
            &encode_list(&self.pending_retirements, MAX_RETIREMENT_REFS, RetirementRef::to_bytes)?,
        )?;
        writer.push(7, &self.retirement_digest)?;
        writer.finish()
    }

    /// Decode only after the complete document passes the borrowed scanner.
    /// # Errors
    /// Rejects every noncanonical field, nested object, count, size or trailing byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let view = scan(WireType::PrekeyPublicationSnapshot, bytes)?;
        Ok(Self {
            profile: owned_text(field(view, 1)?)?,
            update: OwnerPrekeyUpdate::from_bytes(field(view, 2)?)?,
            counter: u64::from_be_bytes(fixed(field(view, 3)?)?),
            epoch: u64::from_be_bytes(fixed(field(view, 4)?)?),
            generation: u64::from_be_bytes(fixed(field(view, 5)?)?),
            pending_retirements: decode_list(
                field(view, 6)?,
                MAX_RETIREMENT_REFS,
                RetirementRef::from_bytes,
            )?,
            retirement_digest: fixed(field(view, 7)?)?,
        })
    }
}

struct Writer {
    kind: WireType,
    count: usize,
    bytes: Vec<u8>,
}

impl Writer {
    fn new(kind: WireType) -> Self {
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(b"RFS1");
        bytes.extend_from_slice(&[kind as u8, 1, 0, 0]);
        Self { kind, count: 0, bytes }
    }

    fn push(&mut self, id: u16, value: &[u8]) -> Result<()> {
        let spec = self.kind.specs().get(self.count).ok_or(DecodeError::Fields)?;
        if spec.id != id {
            return Err(DecodeError::Fields);
        }
        if value.len() > spec.max {
            return Err(DecodeError::FieldCeiling);
        }
        let size = self
            .bytes
            .len()
            .checked_add(6)
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(DecodeError::TypeCeiling)?;
        if size > self.kind.ceiling() {
            return Err(DecodeError::TypeCeiling);
        }
        self.bytes.extend_from_slice(&id.to_be_bytes());
        self.bytes.extend_from_slice(
            &u32::try_from(value.len()).map_err(|_| DecodeError::FieldCeiling)?.to_be_bytes(),
        );
        self.bytes.extend_from_slice(value);
        self.count += 1;
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        if self.count != self.kind.specs().len() {
            return Err(DecodeError::Fields);
        }
        let count = u16::try_from(self.count).map_err(|_| DecodeError::Fields)?;
        self.bytes
            .get_mut(6..8)
            .ok_or(DecodeError::Truncated)?
            .copy_from_slice(&count.to_be_bytes());
        Ok(self.bytes)
    }
}

fn profile_bytes(value: &str) -> Result<&[u8]> {
    if value == NATIVE_PREKEY_PROFILE { Ok(value.as_bytes()) } else { Err(DecodeError::Value) }
}

fn id_bytes(value: &str) -> Result<&[u8]> {
    if valid_custody_id(value) { Ok(value.as_bytes()) } else { Err(DecodeError::Value) }
}

fn field(view: Scanned<'_>, id: u16) -> Result<&[u8]> {
    view.field(id).ok_or(DecodeError::Fields)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| DecodeError::Value)
}

fn owned_text(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| DecodeError::Value)
}

fn unsigned_body(mut bytes: Vec<u8>) -> Result<Vec<u8>> {
    // All three signed publication types end with one fixed 64-byte signature TLV.
    let body_length = bytes.len().checked_sub(6 + 64).ok_or(DecodeError::Truncated)?;
    let count = u16::from_be_bytes(fixed(bytes.get(6..8).ok_or(DecodeError::Truncated)?)?)
        .checked_sub(1)
        .ok_or(DecodeError::Fields)?;
    bytes.truncate(body_length);
    bytes.get_mut(6..8).ok_or(DecodeError::Truncated)?.copy_from_slice(&count.to_be_bytes());
    Ok(bytes)
}

fn encode_list<T>(
    values: &[T],
    limit: usize,
    encode: fn(&T) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    if values.len() > limit {
        return Err(DecodeError::Count);
    }
    let count = u16::try_from(values.len()).map_err(|_| DecodeError::Count)?;
    let mut bytes = count.to_be_bytes().to_vec();
    for value in values {
        let item = encode(value)?;
        let length = u32::try_from(item.len()).map_err(|_| DecodeError::FieldCeiling)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&item);
    }
    Ok(bytes)
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    if length > bytes.len() {
        return Err(DecodeError::Truncated);
    }
    let (value, remaining) = bytes.split_at(length);
    *bytes = remaining;
    Ok(value)
}

fn decode_list<T>(
    mut bytes: &[u8],
    limit: usize,
    decode: fn(&[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    let count = usize::from(u16::from_be_bytes(fixed(take(&mut bytes, 2)?)?));
    if count > limit {
        return Err(DecodeError::Count);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::try_from(u32::from_be_bytes(fixed(take(&mut bytes, 4)?)?))
            .map_err(|_| DecodeError::FieldCeiling)?;
        values.push(decode(take(&mut bytes, length)?)?);
    }
    if !bytes.is_empty() {
        return Err(DecodeError::Trailing);
    }
    Ok(values)
}
