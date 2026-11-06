// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical transcript construction and authenticated public bundle binding.
use super::{NativePrekeyError, base_hash, bundle_hash, verify_lease_result};
use ramflux_protocol::dm_fs_v3::{BootstrapHeader, BootstrapTranscript, PrekeyLeaseResult};

/// Construct the exact public transcript, retaining the raw header and routed AD.
/// # Errors
/// Rejects mismatched routed AD and every canonical size/value failure.
pub fn bootstrap_transcript(
    header: BootstrapHeader,
    envelope_created_at: u64,
    envelope_ttl: u64,
    routed_ad: Vec<u8>,
) -> Result<BootstrapTranscript, NativePrekeyError> {
    if header.routed_ad != routed_ad {
        return Err(NativePrekeyError::Binding);
    }
    let value = BootstrapTranscript {
        profile: header.profile.clone(),
        header,
        envelope_created_at,
        envelope_ttl,
        routed_ad,
    };
    value.to_bytes()?;
    Ok(value)
}
/// Verify the node's lease proof and every corresponding header commitment.
/// The caller owns current authority, fresh time/deadline acceptance and envelope AD authenticity.
/// # Errors
/// Rejects invalid signatures, canonical bounds or mismatched public commitments.
pub fn verify_bootstrap_transcript(
    value: &BootstrapTranscript,
    lease: &PrekeyLeaseResult,
    node_key: &[u8; 32],
) -> Result<(), NativePrekeyError> {
    value.to_bytes()?;
    verify_lease_result(lease, node_key)?;
    let h = &value.header;
    if h.source != lease.requester
        || h.target != lease.target
        || h.base != lease.base
        || h.base_hash != base_hash(&lease.base)?
        || h.bundle_hash != bundle_hash(lease)?
        || h.spk_id != lease.base.spk_id
        || h.spk_serial != lease.base.spk_serial
        || h.generation != lease.base.generation
        || h.operation_id != lease.operation_id
        || h.issued_at != lease.issued_at
        || h.leased_at != lease.leased_at
        || h.deadline > lease.deadline
        || h.opk_id != lease.opk.as_ref().map(|v| v.opk_id)
        || h.opk_key != lease.opk.as_ref().map(|v| v.opk_key)
        || h.routed_ad != value.routed_ad
    {
        return Err(NativePrekeyError::Binding);
    }
    Ok(())
}
