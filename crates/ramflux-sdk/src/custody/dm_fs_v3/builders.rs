// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public-input builders delegate the locked crypto and canonical codec contracts.
use ramflux_crypto::dm_fs_v3 as c;
use ramflux_protocol::dm_fs_v3 as p;
type Result<T> = std::result::Result<T, c::NativePrekeyError>;
/// Sign a bounded public base with a caller-supplied capability.
/// # Errors
/// Rejects malformed public inputs, signer mismatch or invalid signatures.
pub fn build_base(
    value: p::SignedNativePrekeyBase,
    signer: &dyn c::NativePrekeySigner,
) -> Result<p::SignedNativePrekeyBase> {
    c::sign_base(value, signer)
}
/// Sign an OPK bound to the supplied public branch.
/// # Errors
/// Rejects malformed inputs, branch mismatch or invalid signatures.
pub fn build_opk(
    value: p::SignedNativeOpk,
    branch: &p::QualifiedBranch,
    signer: &dyn c::NativePrekeySigner,
) -> Result<p::SignedNativeOpk> {
    c::sign_opk(value, signer, branch)
}
/// Sign an owner update with its independently verified base and OPKs.
/// # Errors
/// Rejects malformed inputs, inconsistent bindings or invalid signatures.
pub fn build_owner_update(
    value: p::OwnerPrekeyUpdate,
    signer: &dyn c::NativePrekeySigner,
) -> Result<p::OwnerPrekeyUpdate> {
    c::sign_owner_update(value, signer)
}
/// Sign a public request; the caller supplies authenticated session bindings.
/// # Errors
/// Rejects malformed inputs, signer mismatch or invalid signatures.
pub fn build_request(
    value: p::NativePrekeyRequest,
    signer: &dyn c::NativePrekeySigner,
) -> Result<p::NativePrekeyRequest> {
    c::sign_request(value, signer)
}
/// Encode a public snapshot after checking its signed update and metadata.
/// # Errors
/// Rejects malformed data, invalid signatures or inconsistent metadata/digest.
pub fn build_publication_snapshot(value: &p::PrekeyPublicationSnapshot) -> Result<Vec<u8>> {
    c::verify_owner_update(&value.update)?;
    if value.counter != value.update.update_counter
        || value.generation != value.update.base.generation
        || value.epoch != value.update.base.branch.device_epoch
        || value.retirement_digest != c::retirement_digest(&value.pending_retirements)?
    {
        return Err(c::NativePrekeyError::Binding);
    }
    Ok(value.to_bytes()?)
}
/// Encode a lease intent and compute its separate operation ID over every field.
/// # Errors
/// Rejects noncanonical values or bounds.
pub fn build_lease_intent(value: &p::PrekeyLeaseIntent) -> Result<(Vec<u8>, [u8; 32])> {
    if value.expires_at.checked_sub(value.issued_at).is_none_or(|ttl| ttl > 300) {
        return Err(p::DecodeError::Value.into());
    }
    Ok((value.to_bytes()?, c::lease_operation_id(value)?))
}
