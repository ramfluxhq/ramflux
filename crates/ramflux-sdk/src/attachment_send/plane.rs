// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner and reader wire seam. Production code does not name the relay ledger.

use super::codes::{CODE_LAYOUT_INVALID, CODE_MANIFEST_TOO_LARGE, CODE_STREAM_OFFSET, Refusal};

/// One authenticated owner transcript plus its body and requester proof.
pub(crate) struct OwnerCall<'a> {
    pub operation: &'a [u8],
    pub body: &'a [u8],
    pub proof: &'a [u8],
    pub signature: &'a [u8; 64],
}

/// Signed manifest and owner-signed grant for one committed upload.
pub(crate) struct RegisterCall<'a> {
    pub upload_id: &'a [u8; 32],
    pub manifest: &'a [u8],
    pub grant: &'a [u8],
}

/// One ciphertext range. The caller already checked that it is the grantee.
pub(crate) struct ReadCall<'a> {
    pub capability: &'a [u8],
    pub object_id: &'a [u8; 32],
    pub manifest_hash: &'a [u8; 32],
    pub index: u64,
    pub offset: u64,
    pub length: u64,
}

/// # Errors
/// Returns `layout_invalid` when the transcript or proof is empty, and `manifest_too_large` past 1 MiB.
pub(crate) fn owner_ready(call: &OwnerCall<'_>) -> Result<(), Refusal> {
    if call.operation.is_empty()
        || call.proof.is_empty()
        || call.signature.iter().all(|byte| *byte == 0)
    {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    if call.body.len() > 1_048_576 {
        return Err(Refusal::new(CODE_MANIFEST_TOO_LARGE));
    }
    Ok(())
}

/// # Errors
/// Returns `layout_invalid` when the upload, manifest, or grant is empty.
pub(crate) fn register_ready(call: &RegisterCall<'_>) -> Result<(), Refusal> {
    if call.upload_id.iter().all(|byte| *byte == 0)
        || call.manifest.is_empty()
        || call.grant.is_empty()
    {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    Ok(())
}

/// # Errors
/// Returns `layout_invalid` or `stream_offset` when the range is not one segment.
pub(crate) fn read_bounded(call: &ReadCall<'_>) -> Result<(), Refusal> {
    if call.capability.is_empty()
        || call.object_id.iter().all(|byte| *byte == 0)
        || call.manifest_hash.iter().all(|byte| *byte == 0)
        || call.index > u64::from(u32::MAX)
    {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    if call.length == 0 || call.offset > call.length {
        return Err(Refusal::new(CODE_STREAM_OFFSET));
    }
    Ok(())
}

/// Speaks Reserve, registration, and ranged read. A missing plane is `authority_unavailable`.
pub(crate) trait Plane: Send + Sync {
    /// # Errors
    /// Returns a stable refusal when the listener rejects the operation.
    fn owner(&self, call: &OwnerCall<'_>) -> Result<Vec<u8>, Refusal>;

    /// # Errors
    /// Returns a stable refusal when registration is refused. The bytes are the tag-5 capability.
    fn register(&self, call: &RegisterCall<'_>) -> Result<Vec<u8>, Refusal>;

    /// # Errors
    /// Returns `not_grantee` before any read when the session is not the grantee.
    fn read(&self, call: &ReadCall<'_>) -> Result<Vec<u8>, Refusal>;
}
