// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Frozen r6 metadata capacities. R1/R7 must hook growth and certify layouts.
use super::{AllocationClass, Result, add, allocation_charge, mul};

/// One metadata allocation shape; each item includes its own alignment/header charge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataCharge {
    pub class: AllocationClass,
    pub count: u64,
    pub capacity: u64,
    pub item_charge: u64,
    pub bytes: u64,
}
/// Item-3 capacities, shared through transfers until final destruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataBudget {
    /// Aggregate STREAM and boxed retransmit descriptors per tracked packet.
    pub frames_per_packet: u64,
    /// Each send ACK/loss set and receive reassembly range set.
    pub ranges_per_stream: u64,
    /// Independent send/receive segment descriptor caps per stream.
    pub segments_per_stream: u64,
    /// Shared simultaneous ACK/loss scratch entries across the connection.
    pub scratch_entries: u64,
    pub charges: [MetadataCharge; 7],
    /// `D_meta` before the common outer factor two.
    pub total: u64,
}
impl MetadataBudget {
    pub(super) fn derive(records: u64, streams: u64) -> Result<Self> {
        use AllocationClass as A;
        let frames_per_packet = 32;
        let ranges_per_stream = 64;
        let segments_per_stream = 64;
        let ranges = mul(streams, ranges_per_stream)?;
        let segments = mul(streams, segments_per_stream)?;
        let shape = |class, count, capacity| -> Result<MetadataCharge> {
            let item_charge = u64::try_from(allocation_charge(capacity)?)
                .map_err(|_| super::BudgetError::Overflow)?;
            Ok(MetadataCharge {
                class,
                count,
                capacity,
                item_charge,
                bytes: mul(count, item_charge)?,
            })
        };
        let charges = [
            shape(A::SentFrameMetadata, mul(records, frames_per_packet)?, 64)?,
            shape(A::RetransmitOwner, records, 512)?,
            shape(A::SendRanges, mul(2, ranges)?, 32)?,
            shape(A::SendSegments, segments, 64)?,
            shape(A::ReceiveRanges, ranges, 32)?,
            shape(A::ReceiveSegments, segments, 64)?,
            shape(A::AckLossScratch, records, 32)?,
        ];
        let total = charges.iter().try_fold(0, |sum, charge| add(sum, charge.bytes))?;
        Ok(Self {
            frames_per_packet,
            ranges_per_stream,
            segments_per_stream,
            scratch_entries: records,
            charges,
            total,
        })
    }
    pub(super) fn scalars(&self) -> impl Iterator<Item = u64> + '_ {
        [
            self.frames_per_packet,
            self.ranges_per_stream,
            self.segments_per_stream,
            self.scratch_entries,
            self.total,
        ]
        .into_iter()
        .chain(self.charges.iter().flat_map(|c| [c.count, c.capacity, c.item_charge, c.bytes]))
    }
}
/// `T_np` is a frozen policy over the runtime's current PTO, not a keepalive timer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoProgressDeadline {
    pub pto_multiple: u64,
    pub minimum_ms: u64,
}
impl NoProgressDeadline {
    /// Compute `T_np`; only ACK retirement of at least one record may reset it.
    /// # Errors
    /// Refuses PTO multiplication overflow.
    pub fn timeout_ms(&self, pto_ms: u64) -> Result<u64> {
        Ok(mul(self.pto_multiple, pto_ms)?.max(self.minimum_ms))
    }
}
