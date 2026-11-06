// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receive Bytes owner envelopes, charged until their actual final deallocation.
use super::metadata_credit::{AllocationCharge, MetadataClass, MetadataCredit, ResourceExhausted};
use bytes::{Bytes, OwnerAllocationError};
use std::sync::Arc;

pub(super) struct PayloadBacking {
    // Destroy payload storage before its separate payload credit returns.
    bytes: Vec<u8>,
    _raw_owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
    _charge: Option<AllocationCharge>,
}
impl PayloadBacking {
    pub(super) fn new(
        bytes: Vec<u8>,
        raw_owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
        charge: Option<AllocationCharge>,
    ) -> Self {
        Self { bytes, _raw_owner: raw_owner, _charge: charge }
    }
}
impl AsRef<[u8]> for PayloadBacking {
    fn as_ref(&self) -> &[u8] { &self.bytes }
}

pub(super) fn into_bytes(
    owner: PayloadBacking,
    credit: &Arc<MetadataCredit>,
    class: MetadataClass,
) -> Result<Bytes, ResourceExhausted> {
    // The patched Bytes constructor supplies its actual wrapper Layout before
    // allocation. Its unique AllocationCharge survives payload Drop AND Box free.
    let bytes = Bytes::try_from_owner_with_guard(owner, |layout| {
        credit.receive_owner_layout(layout.size());
        credit.reserve(layout.size(), class)
    }).map_err(|error| match error {
        OwnerAllocationError::Reservation { error, .. } => error,
        OwnerAllocationError::Allocation { .. } => credit.fail(class),
    })?;
    credit.allocated();
    credit.receive_owner_allocated();
    Ok(bytes)
}

/// Ask the actual constructor for this production owner's layout without allocating.
#[cfg(any(test, feature="__control-test"))]
pub(super) fn owner_layout() -> std::alloc::Layout {
    let mut observed = None;
    let refused = Bytes::try_from_owner_with_guard(
        PayloadBacking::new(Vec::new(), None, None),
        |layout| -> Result<AllocationCharge, ()> { observed = Some(layout); Err(()) },
    );
    assert!(refused.is_err());
    observed.unwrap()
}

#[cfg(test)]
mod tests;
