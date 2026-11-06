// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant publication guard shared by local and S3 data paths after operation admission.
//! Native token/PoP verification and nonce consumption must precede this helper.
use ramflux_node_core::attachment::{
    AttachmentReplayError, AttachmentReplayProof, GrantPublicationLease, ScopedGrantRegistry,
    backend::{AttachmentBackend, BackendError, BackendSegment},
};
use ramflux_protocol::large_attachment::{VerifiedContentManifest, VerifiedScopedGrant};
use std::io::{self, Write};
pub struct ScopedAttachmentRange<'a> {
    pub grant: &'a VerifiedScopedGrant,
    pub manifest: &'a VerifiedContentManifest,
    pub generation: u64,
    pub segment: u32,
    pub offset: u64,
    pub length: u64,
}
struct PublicationWriter<'a> {
    output: &'a mut dyn Write,
    lease: &'a GrantPublicationLease,
    clock: &'a dyn Fn() -> u64,
    remaining: u64,
}
impl Write for PublicationWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining || bytes.len() > 1_048_576 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.lease
            .check_current((self.clock)())
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let n = self.output.write(bytes)?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.lease
            .check_current((self.clock)())
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
        self.output.flush()
    }
}
/// Holds the registered grant lease across backend I/O and the final bounded output flush.
/// This is not an endpoint and does not replace native operation authentication.
/// # Errors
/// Refuses scope/range substitution, live grant denial, backend failures and incomplete output.
pub fn read_after_operation_admission(
    registry: &ScopedGrantRegistry,
    backend: &dyn AttachmentBackend,
    request: &ScopedAttachmentRange<'_>,
    proof: &AttachmentReplayProof,
    output: &mut dyn Write,
    clock: &dyn Fn() -> u64,
) -> Result<(), BackendError> {
    let g = request.grant.grant();
    let m = request.manifest.manifest();
    if g.object_id != m.object_id
        || g.manifest_hash != m.hash().map_err(|_| BackendError::Integrity)?
    {
        return Err(BackendError::Conflict);
    }
    let spec =
        BackendSegment::from_manifest(request.manifest, request.generation, request.segment)?;
    if request.length == 0
        || request.length > 1_048_576
        || request.offset.checked_add(request.length).is_none_or(|end| end > spec.length())
    {
        return Err(BackendError::Bounds);
    }
    let lease = registry
        .admit_operation_after_authentication(request.grant, 1, proof, clock())
        .map_err(|e| match e {
            AttachmentReplayError::ReplayProtectionCapacity
            | AttachmentReplayError::Ledger(
                ramflux_node_core::attachment::AttachmentLedgerError::Capacity,
            ) => BackendError::Busy,
            _ => BackendError::Retired,
        })?;
    let mut writer = PublicationWriter { output, lease: &lease, clock, remaining: request.length };
    backend.read_range(&spec, request.offset, request.length, &mut writer)?;
    if writer.remaining != 0 {
        return Err(BackendError::Integrity);
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests;
