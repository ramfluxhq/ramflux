// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Borrowed RFS1 scanner. Static layout tables mirror the immutable P01 manifest;
//! `codec_tests` checks every type code, ceiling, field ID, kind and field limit.

/// Profile carried by every native prekey document.
const PROFILE: &[u8] = b"ramflux.dm.bootstrap.fs.v1";

/// Canonical framing failure. No input bytes or identifiers enter error messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("RFS1 type ceiling exceeded")]
    TypeCeiling,
    #[error("truncated RFS1 input")]
    Truncated,
    #[error("unknown RFS1 magic, type or version")]
    Header,
    #[error("unknown, missing, duplicate or unordered RFS1 field")]
    Fields,
    #[error("RFS1 field ceiling exceeded")]
    FieldCeiling,
    #[error("invalid RFS1 scalar or optional value")]
    Value,
    #[error("RFS1 collection count exceeded")]
    Count,
    #[error("trailing RFS1 bytes")]
    Trailing,
}

/// Type codes and total encoded-byte ceilings fixed by the P01 wire manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType {
    /// `QualifiedBranch` canonical document.
    QualifiedBranch = 1,
    /// `SignedNativePrekeyBase` canonical document.
    SignedNativePrekeyBase = 2,
    /// `SignedNativeOpk` canonical document.
    SignedNativeOpk = 3,
    /// `RetirementRef` canonical document.
    RetirementRef = 4,
    /// `OwnerPrekeyUpdate` canonical document.
    OwnerPrekeyUpdate = 5,
    /// `PrekeyPublicationSnapshot` canonical document.
    PrekeyPublicationSnapshot = 6,
    /// `PublicPrekeyView` canonical document.
    PublicPrekeyView = 7,
    /// `PrekeyLeaseIntent` canonical document.
    PrekeyLeaseIntent = 8,
    /// `PrekeyLeaseResult` canonical document.
    PrekeyLeaseResult = 9,
    /// `OwnerStatusQuery` canonical document.
    OwnerStatusQuery = 10,
    /// `OwnerStatusEntry` canonical document.
    OwnerStatusEntry = 11,
    /// `OwnerPrekeyStatus` canonical document.
    OwnerPrekeyStatus = 12,
    /// `NativePrekeyRequest` canonical document.
    NativePrekeyRequest = 13,
    /// `NativePrekeyLease` canonical document.
    NativePrekeyLease = 14,
    /// `NativePrekeyPublish` canonical document.
    NativePrekeyPublish = 15,
    /// `NativePrekeyStatus` canonical document.
    NativePrekeyStatus = 16,
    /// `NativePrekeyResult` canonical document.
    NativePrekeyResult = 17,
    /// `BootstrapHeader` canonical document.
    BootstrapHeader = 18,
    /// `BootstrapTranscript` canonical document.
    BootstrapTranscript = 19,
}

impl TryFrom<u8> for WireType {
    type Error = DecodeError;
    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            1 => Ok(Self::QualifiedBranch),
            2 => Ok(Self::SignedNativePrekeyBase),
            3 => Ok(Self::SignedNativeOpk),
            4 => Ok(Self::RetirementRef),
            5 => Ok(Self::OwnerPrekeyUpdate),
            6 => Ok(Self::PrekeyPublicationSnapshot),
            7 => Ok(Self::PublicPrekeyView),
            8 => Ok(Self::PrekeyLeaseIntent),
            9 => Ok(Self::PrekeyLeaseResult),
            10 => Ok(Self::OwnerStatusQuery),
            11 => Ok(Self::OwnerStatusEntry),
            12 => Ok(Self::OwnerPrekeyStatus),
            13 => Ok(Self::NativePrekeyRequest),
            14 => Ok(Self::NativePrekeyLease),
            15 => Ok(Self::NativePrekeyPublish),
            16 => Ok(Self::NativePrekeyStatus),
            17 => Ok(Self::NativePrekeyResult),
            18 => Ok(Self::BootstrapHeader),
            19 => Ok(Self::BootstrapTranscript),
            _ => Err(DecodeError::Header),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Fixed(usize),
    Text,
    Profile,
    // Control-free UTF-8; P03-P05 typed codecs own code sets and empty-value rules.
    Code,
    Bytes,
    Nested(WireType),
    OptionalFixed(usize),
    OptionalNested(WireType),
    List(usize, WireType),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Spec {
    pub id: u16,
    pub max: usize,
    pub kind: Kind,
}

impl WireType {
    /// Maximum complete canonical encoding, checked before any field is visited.
    #[must_use]
    pub const fn ceiling(self) -> usize {
        match self {
            Self::QualifiedBranch
            | Self::SignedNativeOpk
            | Self::RetirementRef
            | Self::OwnerStatusEntry => 1_024,
            Self::SignedNativePrekeyBase | Self::PublicPrekeyView | Self::PrekeyLeaseIntent => {
                2_048
            }
            Self::OwnerPrekeyUpdate => 50_176,
            Self::PrekeyPublicationSnapshot => 81_920,
            Self::PrekeyLeaseResult => 4_096,
            Self::OwnerStatusQuery => 17_408,
            Self::OwnerPrekeyStatus => 25_600,
            Self::NativePrekeyRequest => 3_072,
            Self::NativePrekeyLease => 5_120,
            Self::NativePrekeyPublish => 53_248,
            Self::NativePrekeyStatus => 19_456,
            Self::NativePrekeyResult => 26_624,
            Self::BootstrapHeader => 8_192,
            Self::BootstrapTranscript => 12_288,
        }
    }

    pub(super) const fn specs(self) -> &'static [Spec] {
        match self {
            Self::QualifiedBranch => QUALIFIED_BRANCH_FIELDS,
            Self::SignedNativePrekeyBase => SIGNED_NATIVE_PREKEY_BASE_FIELDS,
            Self::SignedNativeOpk => SIGNED_NATIVE_OPK_FIELDS,
            Self::RetirementRef => RETIREMENT_REF_FIELDS,
            Self::OwnerPrekeyUpdate => OWNER_PREKEY_UPDATE_FIELDS,
            Self::PrekeyPublicationSnapshot => PREKEY_PUBLICATION_SNAPSHOT_FIELDS,
            Self::PublicPrekeyView => PUBLIC_PREKEY_VIEW_FIELDS,
            Self::PrekeyLeaseIntent => PREKEY_LEASE_INTENT_FIELDS,
            Self::PrekeyLeaseResult => PREKEY_LEASE_RESULT_FIELDS,
            Self::OwnerStatusQuery => OWNER_STATUS_QUERY_FIELDS,
            Self::OwnerStatusEntry => OWNER_STATUS_ENTRY_FIELDS,
            Self::OwnerPrekeyStatus => OWNER_PREKEY_STATUS_FIELDS,
            Self::NativePrekeyRequest => NATIVE_PREKEY_REQUEST_FIELDS,
            Self::NativePrekeyLease => NATIVE_PREKEY_LEASE_FIELDS,
            Self::NativePrekeyPublish => NATIVE_PREKEY_PUBLISH_FIELDS,
            Self::NativePrekeyStatus => NATIVE_PREKEY_STATUS_FIELDS,
            Self::NativePrekeyResult => NATIVE_PREKEY_RESULT_FIELDS,
            Self::BootstrapHeader => BOOTSTRAP_HEADER_FIELDS,
            Self::BootstrapTranscript => BOOTSTRAP_TRANSCRIPT_FIELDS,
        }
    }
}

const QUALIFIED_BRANCH_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 2, max: 256, kind: Kind::Text },
    Spec { id: 3, max: 256, kind: Kind::Text },
    Spec { id: 4, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 5, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 6, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 7, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 8, max: 32, kind: Kind::Fixed(32) },
];

const SIGNED_NATIVE_PREKEY_BASE_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 3, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 4, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 5, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 6, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 7, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 8, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 9, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 10, max: 64, kind: Kind::Code },
    Spec { id: 11, max: 64, kind: Kind::Fixed(64) },
];

const SIGNED_NATIVE_OPK_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 3, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 4, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 5, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 6, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 7, max: 64, kind: Kind::Fixed(64) },
];

const RETIREMENT_REF_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 2, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 3, max: 32, kind: Kind::Fixed(32) },
];

const OWNER_PREKEY_UPDATE_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 2048, kind: Kind::Nested(WireType::SignedNativePrekeyBase) },
    Spec { id: 3, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 4, max: 16386, kind: Kind::List(64, WireType::SignedNativeOpk) },
    Spec { id: 5, max: 31202, kind: Kind::List(400, WireType::RetirementRef) },
    Spec { id: 6, max: 64, kind: Kind::Fixed(64) },
];

const PREKEY_PUBLICATION_SNAPSHOT_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 50176, kind: Kind::Nested(WireType::OwnerPrekeyUpdate) },
    Spec { id: 3, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 4, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 5, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 6, max: 31202, kind: Kind::List(400, WireType::RetirementRef) },
    Spec { id: 7, max: 32, kind: Kind::Fixed(32) },
];

const PUBLIC_PREKEY_VIEW_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 2048, kind: Kind::Nested(WireType::SignedNativePrekeyBase) },
    Spec { id: 3, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 4, max: 8, kind: Kind::Fixed(8) },
];

const PREKEY_LEASE_INTENT_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 3, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 4, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 5, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 6, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 7, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 8, max: 32, kind: Kind::Fixed(32) },
];

const PREKEY_LEASE_RESULT_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 2048, kind: Kind::Nested(WireType::SignedNativePrekeyBase) },
    Spec { id: 3, max: 1025, kind: Kind::OptionalNested(WireType::SignedNativeOpk) },
    Spec { id: 4, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 5, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 6, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 7, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 8, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 9, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 10, max: 64, kind: Kind::Code },
    Spec { id: 11, max: 64, kind: Kind::Fixed(64) },
];

const OWNER_STATUS_QUERY_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 3, max: 15602, kind: Kind::List(200, WireType::RetirementRef) },
];

const OWNER_STATUS_ENTRY_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 2, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 3, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 4, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 5, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 6, max: 64, kind: Kind::Code },
];

const OWNER_PREKEY_STATUS_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 3, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 4, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 5, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 6, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 7, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 8, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 9, max: 24002, kind: Kind::List(200, WireType::OwnerStatusEntry) },
    Spec { id: 10, max: 64, kind: Kind::Fixed(64) },
];

const NATIVE_PREKEY_REQUEST_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 64, kind: Kind::Code },
    Spec { id: 3, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 4, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 5, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 6, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 7, max: 256, kind: Kind::Text },
    Spec { id: 8, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 9, max: 256, kind: Kind::Text },
    Spec { id: 10, max: 256, kind: Kind::Text },
    Spec { id: 11, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 12, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 13, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 14, max: 64, kind: Kind::Fixed(64) },
];

const NATIVE_PREKEY_LEASE_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 2, max: 3072, kind: Kind::Nested(WireType::NativePrekeyRequest) },
    Spec { id: 3, max: 2048, kind: Kind::Nested(WireType::PrekeyLeaseIntent) },
];

const NATIVE_PREKEY_PUBLISH_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 2, max: 3072, kind: Kind::Nested(WireType::NativePrekeyRequest) },
    Spec { id: 3, max: 50176, kind: Kind::Nested(WireType::OwnerPrekeyUpdate) },
];

const NATIVE_PREKEY_STATUS_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 2, max: 3072, kind: Kind::Nested(WireType::NativePrekeyRequest) },
    Spec { id: 3, max: 17408, kind: Kind::Nested(WireType::OwnerStatusQuery) },
];

const NATIVE_PREKEY_RESULT_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 2, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 3, max: 64, kind: Kind::Code },
    Spec { id: 4, max: 4097, kind: Kind::OptionalNested(WireType::PrekeyLeaseResult) },
    Spec { id: 5, max: 25601, kind: Kind::OptionalNested(WireType::OwnerPrekeyStatus) },
    Spec { id: 6, max: 64, kind: Kind::Code },
    Spec { id: 7, max: 64, kind: Kind::Code },
    Spec { id: 8, max: 4, kind: Kind::Fixed(4) },
    Spec { id: 9, max: 256, kind: Kind::Text },
    Spec { id: 10, max: 256, kind: Kind::Text },
];

const BOOTSTRAP_HEADER_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 3, max: 1024, kind: Kind::Nested(WireType::QualifiedBranch) },
    Spec { id: 4, max: 2048, kind: Kind::Nested(WireType::SignedNativePrekeyBase) },
    Spec { id: 5, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 6, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 7, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 8, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 9, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 10, max: 33, kind: Kind::OptionalFixed(32) },
    Spec { id: 11, max: 33, kind: Kind::OptionalFixed(32) },
    Spec { id: 12, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 13, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 14, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 15, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 16, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 17, max: 32, kind: Kind::Fixed(32) },
    Spec { id: 18, max: 256, kind: Kind::Text },
    Spec { id: 19, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 20, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 21, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 22, max: 4096, kind: Kind::Bytes },
];

const BOOTSTRAP_TRANSCRIPT_FIELDS: &[Spec] = &[
    Spec { id: 1, max: 64, kind: Kind::Profile },
    Spec { id: 2, max: 8192, kind: Kind::Nested(WireType::BootstrapHeader) },
    Spec { id: 3, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 4, max: 8, kind: Kind::Fixed(8) },
    Spec { id: 5, max: 4096, kind: Kind::Bytes },
];

/// An inherited custody identifier, using the private custody verifier's predicate.
/// Byte length is UTF-8 length; Rust's Unicode control predicate includes C0/C1.
#[must_use]
pub(crate) fn valid_custody_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        if length > self.remaining.len() {
            return Err(DecodeError::Truncated);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| DecodeError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| DecodeError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.remaining.is_empty() { Ok(()) } else { Err(DecodeError::Trailing) }
    }
}

/// A validated complete document borrowing its caller's bytes.
#[derive(Clone, Copy, Debug)]
pub struct Scanned<'a> {
    kind: WireType,
    bytes: &'a [u8],
}

impl<'a> Scanned<'a> {
    #[must_use]
    pub const fn kind(self) -> WireType {
        self.kind
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Iterate over validated top-level fields, without copying nested values.
    #[must_use]
    pub fn fields(self) -> Fields<'a> {
        Fields { cursor: Cursor { remaining: &self.bytes[8..] } }
    }

    /// Return a top-level field's exact value bytes.
    #[must_use]
    pub fn field(self, id: u16) -> Option<&'a [u8]> {
        self.fields().find(|field| field.id == id).map(|field| field.value)
    }
}

/// One canonical field, retaining the original value bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    pub id: u16,
    pub value: &'a [u8],
}

/// Borrowed field iterator; construction requires a successfully scanned document.
pub struct Fields<'a> {
    cursor: Cursor<'a>,
}

impl<'a> Iterator for Fields<'a> {
    type Item = Field<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.remaining.is_empty() {
            return None;
        }
        let id = self.cursor.u16().ok()?;
        let length = usize::try_from(self.cursor.u32().ok()?).ok()?;
        Some(Field { id, value: self.cursor.take(length).ok()? })
    }
}

/// Validate a complete RFS1 document and every nested value without allocating.
/// Layout nesting is static and acyclic (maximum four documents on the stack).
/// No collection count or attacker-selected type can introduce recursive layouts.
///
/// # Errors
/// Rejects noncanonical headers, fields, lengths, scalars, identifiers, optional
/// tags, collection counts, nested encodings, total size and trailing bytes.
pub fn scan(kind: WireType, bytes: &[u8]) -> Result<Scanned<'_>, DecodeError> {
    if bytes.len() > kind.ceiling() {
        return Err(DecodeError::TypeCeiling);
    }
    let mut cursor = Cursor { remaining: bytes };
    if cursor.take(6)? != [b'R', b'F', b'S', b'1', kind as u8, 1] {
        return Err(DecodeError::Header);
    }
    let specs = kind.specs();
    if usize::from(cursor.u16()?) != specs.len() {
        return Err(DecodeError::Fields);
    }
    for spec in specs {
        if cursor.u16()? != spec.id {
            return Err(DecodeError::Fields);
        }
        let length = usize::try_from(cursor.u32()?).map_err(|_| DecodeError::FieldCeiling)?;
        if length > spec.max {
            return Err(DecodeError::FieldCeiling);
        }
        validate_value(spec.kind, cursor.take(length)?)?;
    }
    cursor.finish()?;
    Ok(Scanned { kind, bytes })
}

fn validate_value(kind: Kind, value: &[u8]) -> Result<(), DecodeError> {
    match kind {
        Kind::Fixed(width) if value.len() == width => Ok(()),
        Kind::Profile if value == PROFILE => Ok(()),
        Kind::Fixed(_) | Kind::Profile => Err(DecodeError::Value),
        Kind::Text => {
            let text = std::str::from_utf8(value).map_err(|_| DecodeError::Value)?;
            if super::valid_custody_id(text) { Ok(()) } else { Err(DecodeError::Value) }
        }
        Kind::Code => {
            let text = std::str::from_utf8(value).map_err(|_| DecodeError::Value)?;
            if text.chars().any(char::is_control) { Err(DecodeError::Value) } else { Ok(()) }
        }
        Kind::Bytes => Ok(()),
        Kind::Nested(nested) => scan(nested, value).map(|_| ()),
        Kind::OptionalFixed(width) => optional(Kind::Fixed(width), value),
        Kind::OptionalNested(nested) => optional(Kind::Nested(nested), value),
        Kind::List(max_count, nested) => {
            let mut cursor = Cursor { remaining: value };
            let count = usize::from(cursor.u16()?);
            if count > max_count {
                return Err(DecodeError::Count);
            }
            for _ in 0..count {
                let length =
                    usize::try_from(cursor.u32()?).map_err(|_| DecodeError::FieldCeiling)?;
                // A nested value's ceiling and remaining bytes precede any interpretation.
                if length > nested.ceiling() {
                    return Err(DecodeError::FieldCeiling);
                }
                scan(nested, cursor.take(length)?)?;
            }
            cursor.finish()
        }
    }
}

fn optional(kind: Kind, value: &[u8]) -> Result<(), DecodeError> {
    match value.split_first() {
        Some((0, [])) => Ok(()),
        Some((1, body)) => validate_value(kind, body),
        _ => Err(DecodeError::Value),
    }
}
