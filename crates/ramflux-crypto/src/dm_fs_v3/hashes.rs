// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Decision-r5 hash-role domains and exact canonical public preimages.
use super::NativePrekeyError;
use ramflux_protocol::{
    dm_fs_v3::{
        BootstrapTranscript, DecodeError, MAX_RETIREMENT_REFS, NativePrekeyRequest,
        NativePrekeyResult, OwnerPrekeyUpdate, OwnerStatusQuery, PrekeyLeaseIntent,
        PrekeyLeaseResult, PrekeyPublicationSnapshot, QualifiedBranch, RetirementRef,
        SignedNativePrekeyBase,
    },
    domain,
};
type Result<T> = std::result::Result<T, NativePrekeyError>;
/// One native hash role in the normative decision-r5 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeHashRule {
    /// Stable role name (not a wire enum).
    pub role: &'static str,
    /// Exact unique domain for this role.
    pub domain: &'static str,
    /// Exact preimage grammar after `UTF8(domain) || NUL`.
    pub canonical: &'static str,
}
/// Native roles only; existing custody JCS hashes remain in their existing owners.
pub const NATIVE_HASH_RULES: [NativeHashRule; 10] = [
    NativeHashRule {
        role: "branch_binding",
        domain: domain::DM_FS_V3_BRANCH_BINDING,
        canonical: "complete QualifiedBranch RFS1",
    },
    NativeHashRule {
        role: "base_hash",
        domain: domain::DM_FS_V3_BASE_HASH,
        canonical: "complete SignedNativePrekeyBase RFS1",
    },
    NativeHashRule {
        role: "lease_operation_id",
        domain: domain::DM_FS_V3_LEASE_OPERATION_ID,
        canonical: "complete PrekeyLeaseIntent RFS1",
    },
    NativeHashRule {
        role: "request_hash",
        domain: domain::DM_FS_V3_REQUEST_HASH,
        canonical: "complete NativePrekeyRequest RFS1",
    },
    NativeHashRule {
        role: "bundle_hash",
        domain: domain::DM_FS_V3_BUNDLE_HASH,
        canonical: "complete PrekeyLeaseResult RFS1",
    },
    NativeHashRule {
        role: "publication_snapshot_hash",
        domain: domain::DM_FS_V3_PUBLICATION_SNAPSHOT,
        canonical: "complete PrekeyPublicationSnapshot RFS1",
    },
    NativeHashRule {
        role: "frame_result_hash",
        domain: domain::DM_FS_V3_FRAME_RESULT,
        canonical: "complete NativePrekeyResult RFS1",
    },
    NativeHashRule {
        role: "transcript_hash",
        domain: domain::DM_FS_V3_TRANSCRIPT,
        canonical: "complete BootstrapTranscript RFS1",
    },
    NativeHashRule {
        role: "retirement_digest",
        domain: domain::DM_FS_V3_RETIREMENT_LIST,
        canonical: "u16_be(count) || (u32_be(element_length) || complete RetirementRef RFS1)* in list order",
    },
    NativeHashRule {
        role: "request_argument",
        domain: domain::DM_FS_V3_REQUEST_ARGUMENT,
        canonical: "complete PrekeyLeaseIntent / OwnerPrekeyUpdate / OwnerStatusQuery RFS1 selected by action",
    },
];
fn framed_hash(domain: &str, canonical: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(domain.as_bytes());
    hash.update(&[0]);
    hash.update(canonical);
    *hash.finalize().as_bytes()
}
/// Hash the complete bounded canonical `QualifiedBranch` under its dedicated role domain.
/// # Errors
/// Rejects invalid canonical values, combinations or bounds before hashing.
pub fn branch_binding(value: &QualifiedBranch) -> Result<[u8; 32]> {
    Ok(framed_hash(domain::DM_FS_V3_BRANCH_BINDING, &value.to_bytes()?))
}
/// Hash the complete bounded canonical `SignedNativePrekeyBase` under its dedicated role domain.
/// # Errors
/// Rejects invalid canonical values, combinations or bounds before hashing.
pub fn base_hash(value: &SignedNativePrekeyBase) -> Result<[u8; 32]> {
    Ok(framed_hash(domain::DM_FS_V3_BASE_HASH, &value.to_bytes()?))
}
/// Hash the complete bounded canonical `PrekeyLeaseIntent` under its dedicated role domain.
/// # Errors
/// Rejects invalid canonical values, combinations or bounds before hashing.
pub fn lease_operation_id(value: &PrekeyLeaseIntent) -> Result<[u8; 32]> {
    Ok(framed_hash(domain::DM_FS_V3_LEASE_OPERATION_ID, &value.to_bytes()?))
}
/// Hash the complete bounded canonical `NativePrekeyRequest` under its dedicated role domain.
/// # Errors
/// Rejects invalid canonical values, combinations or bounds before hashing.
pub fn request_hash(value: &NativePrekeyRequest) -> Result<[u8; 32]> {
    Ok(framed_hash(domain::DM_FS_V3_REQUEST_HASH, &value.to_bytes()?))
}
/// Hash the complete bounded canonical `PrekeyLeaseResult` under its dedicated role domain.
/// # Errors
/// Rejects invalid canonical values, combinations or bounds before hashing.
pub fn bundle_hash(value: &PrekeyLeaseResult) -> Result<[u8; 32]> {
    Ok(framed_hash(domain::DM_FS_V3_BUNDLE_HASH, &value.to_bytes()?))
}
/// Hash the complete bounded canonical `PrekeyPublicationSnapshot` under its dedicated role domain.
/// # Errors
/// Rejects invalid canonical values, combinations or bounds before hashing.
pub fn publication_snapshot_hash(value: &PrekeyPublicationSnapshot) -> Result<[u8; 32]> {
    Ok(framed_hash(domain::DM_FS_V3_PUBLICATION_SNAPSHOT, &value.to_bytes()?))
}
/// Hash the complete bounded canonical `NativePrekeyResult` under its dedicated role domain.
/// # Errors
/// Rejects invalid canonical values, combinations or bounds before hashing.
pub fn frame_result_hash(value: &NativePrekeyResult) -> Result<[u8; 32]> {
    Ok(framed_hash(domain::DM_FS_V3_FRAME_RESULT, &value.to_bytes()?))
}
/// Hash the complete bounded canonical `BootstrapTranscript` under its dedicated role domain.
/// # Errors
/// Rejects invalid canonical values, combinations or bounds before hashing.
pub fn transcript_hash(value: &BootstrapTranscript) -> Result<[u8; 32]> {
    Ok(framed_hash(domain::DM_FS_V3_TRANSCRIPT, &value.to_bytes()?))
}
/// Canonical request arguments; each action selects exactly one existing wire type.
#[derive(Clone, Copy, Debug)]
pub enum NativePrekeyArgument<'a> {
    /// Lease intent.
    Lease(&'a PrekeyLeaseIntent),
    /// Complete owner update.
    Publish(&'a OwnerPrekeyUpdate),
    /// Owner status query.
    Status(&'a OwnerStatusQuery),
}
/// Hash one argument under the request-argument domain, never the signed-request domain.
/// # Errors
/// Returns canonical encoding/bounds errors.
pub fn request_argument_hash(value: NativePrekeyArgument<'_>) -> Result<[u8; 32]> {
    let bytes = match value {
        NativePrekeyArgument::Lease(v) => v.to_bytes()?,
        NativePrekeyArgument::Publish(v) => v.to_bytes()?,
        NativePrekeyArgument::Status(v) => v.to_bytes()?,
    };
    Ok(framed_hash(domain::DM_FS_V3_REQUEST_ARGUMENT, &bytes))
}
/// Hash the complete ordered canonical list, including count and every length.
/// # Errors
/// Rejects more than 400 references before encoding or hashing any element.
pub fn retirement_digest(values: &[RetirementRef]) -> Result<[u8; 32]> {
    if values.len() > MAX_RETIREMENT_REFS {
        return Err(DecodeError::Count.into());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(domain::DM_FS_V3_RETIREMENT_LIST.as_bytes());
    hash.update(&[0]);
    hash.update(&u16::try_from(values.len()).map_err(|_| DecodeError::Count)?.to_be_bytes());
    for value in values {
        let bytes = value.to_bytes()?;
        hash.update(
            &u32::try_from(bytes.len()).map_err(|_| DecodeError::FieldCeiling)?.to_be_bytes(),
        );
        hash.update(&bytes);
    }
    Ok(*hash.finalize().as_bytes())
}
