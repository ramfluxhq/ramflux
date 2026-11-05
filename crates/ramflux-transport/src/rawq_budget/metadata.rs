// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared metadata byte-credit sizing only; runtime allocation hooks are not implemented here.
use super::{Result, add, mul, platform_size};

/// Sizing reference, not a minimum legal packet size or a packet-count bound.
pub const METADATA_REFERENCE_BYTES: u64 = 1200;
/// Metadata bytes per sizing reference before the common factor two.
pub const METADATA_UNIT_BYTES: u64 = 512;
/// Fixed metadata allowance per final owner before the common factor two.
pub const METADATA_FIXED_BYTES: u64 = 65_536;

/// One shared metadata credit across all packet spaces, streams, builders and scratch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataBudget {
    /// Checked ceil((send window + connection receive window)/1200).
    pub reference_units: u64,
    /// Undoubled metadata contribution to the complete listener unit.
    pub base: u64,
    /// Actual shared byte credit, already doubled; never multiply it by two again.
    pub ceiling: u64,
}
impl MetadataBudget {
    /// Derive the frozen credit without allocating a runtime or certifying its layouts.
    ///
    /// # Errors
    /// Refuses arithmetic overflow or a credit that cannot fit the target platform.
    pub fn derive(send_window: u64, receive_window: u64) -> Result<Self> {
        let windows = add(send_window, receive_window)?;
        let reference_units = add(
            windows / METADATA_REFERENCE_BYTES,
            u64::from(!windows.is_multiple_of(METADATA_REFERENCE_BYTES)),
        )?;
        let base = add(mul(reference_units, METADATA_UNIT_BYTES)?, METADATA_FIXED_BYTES)?;
        let ceiling = mul(2, base)?;
        platform_size(ceiling, usize::MAX as u64)?;
        Ok(Self { reference_units, base, ceiling })
    }
    pub(super) fn scalars(&self) -> impl Iterator<Item = u64> {
        [
            METADATA_REFERENCE_BYTES,
            METADATA_UNIT_BYTES,
            METADATA_FIXED_BYTES,
            self.reference_units,
            self.base,
            self.ceiling,
        ]
        .into_iter()
    }
}
