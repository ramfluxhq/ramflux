// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify received canonical bytes, never a re-encoded substitute for received input.
use ramflux_crypto::dm_fs_v3 as c;
use ramflux_protocol::dm_fs_v3 as p;
type Result<T> = std::result::Result<T, c::NativePrekeyError>;
fn identity(received: &[u8], encoded: &[u8]) -> Result<()> {
    if received == encoded { Ok(()) } else { Err(c::NativePrekeyError::Binding) }
}
/// Verify a received public view against the caller's current authenticated branch/home.
/// # Errors
/// Rejects noncanonical bytes, signatures or authority/home disagreement.
pub fn verify_public_view(
    bytes: &[u8],
    authority: &p::QualifiedBranch,
    home_generation: u64,
) -> Result<p::PublicPrekeyView> {
    let value = p::PublicPrekeyView::from_bytes(bytes)?;
    identity(bytes, &value.to_bytes()?)?;
    c::verify_base(&value.base)?;
    if value.authority != *authority
        || value.base.branch != *authority
        || value.home_generation != home_generation
    {
        return Err(c::NativePrekeyError::Binding);
    }
    Ok(value)
}
/// Verify a received signed lease bound to the caller's original intent and node key.
/// Clock trust and exclusive bootstrap deadline enforcement remain with bootstrap/consumer.
/// # Errors
/// Rejects noncanonical bytes, signatures or intent bindings.
pub fn verify_lease_result(
    bytes: &[u8],
    intent: &p::PrekeyLeaseIntent,
    node_key: &[u8; 32],
) -> Result<p::PrekeyLeaseResult> {
    super::build_lease_intent(intent)?;
    let value = p::PrekeyLeaseResult::from_bytes(bytes)?;
    identity(bytes, &value.to_bytes()?)?;
    c::verify_lease_result(&value, node_key)?;
    if value.requester != intent.requester
        || value.target != intent.target
        || c::base_hash(&value.base)? != intent.base_hash
        || value.operation_id != c::lease_operation_id(intent)?
    {
        return Err(c::NativePrekeyError::Binding);
    }
    Ok(value)
}
/// Verify received owner status against the requested owner/key IDs and pinned base.
/// Publication floors/activation interpretation remain consumer-owned.
/// # Errors
/// Rejects noncanonical bytes, signatures, unrequested entries or owner/base mismatch.
pub fn verify_owner_status(
    bytes: &[u8],
    query: &p::OwnerStatusQuery,
    base_hash: &[u8; 32],
    node_key: &[u8; 32],
) -> Result<p::OwnerPrekeyStatus> {
    query.to_bytes()?;
    let value = p::OwnerPrekeyStatus::from_bytes(bytes)?;
    identity(bytes, &value.to_bytes()?)?;
    c::verify_owner_status(&value, node_key)?;
    if value.owner != query.owner
        || value.base_hash != *base_hash
        || value.entries.iter().any(|e| {
            !query.requested_ids.iter().any(|r| {
                r.key_id == e.key_id && r.generation == e.generation && r.serial == e.serial
            })
        })
    {
        return Err(c::NativePrekeyError::Binding);
    }
    Ok(value)
}
