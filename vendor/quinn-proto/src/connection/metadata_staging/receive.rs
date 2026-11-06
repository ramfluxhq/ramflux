// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dormant STREAM preparation. The aggregate exports no owning views or delivery API.
use super::*;
use crate::connection::{assembler::Buffer, metadata_heap::MetadataHeap, metadata_owned_bytes};
use bytes::Bytes;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ReceiveRecord {
    pub(crate) stream_id: u64,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) backing: AllocationId,
    pub(crate) view_start: u64,
    pub(crate) view_end: u64,
    pub(crate) descriptor_count: u64,
    pub(crate) prepared_slots: u64,
    pub(crate) stream_owner: OwnerId,
}
pub(crate) struct ReceiveRequest<'a> {
    pub(crate) shared: Request<'a>,
    pub(crate) frames: &'a [ReceiveRecord],
    pub(crate) frame_count: u64,
}
/// Independently parsed semantic scan and allocator observations. No packet setters.
pub(crate) struct ReceiveContext<'a> {
    pub(crate) shared: Context<'a>,
    pub(crate) scan: &'a [ReceiveRecord],
    pub(crate) physical: &'a [ReceiveRecord],
    pub(crate) backing: AllocationId,
    pub(crate) backing_capacity: u64,
    pub(crate) payload_class: MetadataClass,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedReceive {
    metadata: u64,
}
fn receive_role(role: Role) -> bool {
    matches!(role, Role::StreamPayload | Role::StreamWrapper | Role::StreamHeap | Role::ReceivePlan)
}
pub(crate) fn validate_e2(
    r: &ReceiveRequest<'_>,
    c: &ReceiveContext<'_>,
) -> Result<ValidatedReceive, StageError> {
    use StageError::*;
    if binding(&r.shared, &c.shared)?.phase_tag != 0 {
        return Err(PhaseMismatch);
    }
    let (metadata, _) = validate_batch_for(r.shared.batch, &c.shared, receive_role, None)?;
    validate_owners(&r.shared, &c.shared)?;
    representable(r.frame_count, Field::FrameCount, &c.shared)?;
    if usize::try_from(r.frame_count).ok() != Some(r.frames.len()) {
        return Err(CountMismatch(Count::ReceiveFrames));
    }
    if r.shared.batch.into_iter().flat_map(|b| b.rows).any(|row| {
        matches!(Role::decode(row.role, 0), Ok(Role::StreamPayload | Role::StreamWrapper))
    }) && c.payload_class != MetadataClass::StreamAssemblers
    {
        return Err(SharedPayloadFamilyMismatch);
    }
    for (i, f) in r.frames.iter().enumerate() {
        for (field, value) in [
            (Field::Length, f.length),
            (Field::ViewStart, f.view_start),
            (Field::ViewEnd, f.view_end),
            (Field::DescriptorCount, f.descriptor_count),
            (Field::PreparedSlots, f.prepared_slots),
        ] {
            representable(value, field, &c.shared)?;
        }
        if f.stream_id > ((1 << 62) - 1) {
            return Err(StreamIdOutOfRange);
        }
        let end =
            f.offset.checked_add(f.length).ok_or(ArithmeticOverflow(Arithmetic::StreamEnd(i)))?;
        if end > ((1 << 62) - 1) {
            return Err(StreamEndOutOfRange(i));
        }
        let Some(expected) = c.scan.get(i) else {
            return Err(CountMismatch(Count::ReceiveFrames));
        };
        for (field, a, b) in [
            (Field::StreamId, f.stream_id, expected.stream_id),
            (Field::Offset, f.offset, expected.offset),
            (Field::Length, f.length, expected.length),
        ] {
            if a != b {
                return Err(FrameMismatch(field, i));
            }
        }
        if f.backing != c.backing {
            return Err(ReceiveBackingMismatch(i));
        }
        if f.view_start > f.view_end {
            return Err(InvalidViewOrder(i));
        }
        if f.view_end > c.backing_capacity {
            return Err(ViewOutOfBounds(i));
        }
        if f.view_end - f.view_start != f.length {
            return Err(ViewLengthMismatch(i));
        }
        if f.descriptor_count != expected.descriptor_count {
            return Err(DescriptorCountMismatch(i));
        }
        if f.prepared_slots < f.descriptor_count {
            return Err(ReceiveSlotsInsufficient(i));
        }
        let physical = c
            .physical
            .iter()
            .find(|p| p.stream_id == f.stream_id)
            .ok_or(StreamPreparationMissing(f.stream_id))?;
        if f.prepared_slots != physical.prepared_slots {
            return Err(ReceiveSlotObservationMismatch(i));
        }
        if f.stream_owner != physical.stream_owner {
            return Err(StreamOwnerMismatch(i));
        }
    }
    for expected in c.scan {
        if !r.frames.iter().any(|f| f.stream_id == expected.stream_id) {
            return Err(StreamPreparationMissing(expected.stream_id));
        }
    }
    if r.frames.len() != c.scan.len() {
        return Err(CountMismatch(Count::ReceiveFrames));
    }
    Ok(ValidatedReceive { metadata })
}

/// Inline owner/plan storage. Descriptor backing and shared Bytes wrapper are real
/// allocations covered by the final aggregate lease, never charged once per view.
pub(crate) struct PreparedStream {
    stream_id: u64,
    owner: OwnerId,
    heap: MetadataHeap<Buffer>,
}
pub(crate) struct PreparedReceive<'a, const N: usize, const R: usize> {
    // A cloned old view cannot outlive the old aggregate's allocation lease.
    _live: &'a [&'a PreparedStream],
    streams: [Option<PreparedStream>; N],
    _plans: [Option<Vec<ReceiveRecord>>; R],
    payload: Bytes,
    _retained_datagram: Bytes,
    // All views/heaps above are physically destroyed before refund.
    _lease: StageLease<R>,
}
/// No live queue is mutable through this API. Existing heaps are borrowed and
/// copied into replacement storage, preserving original owners on every refusal.
pub(crate) fn prepare_receive<'a, const N: usize, const R: usize>(
    r: &ReceiveRequest<'_>,
    c: &ReceiveContext<'_>,
    credit: &Arc<StageCredit>,
    datagram: Bytes,
    live: &'a [&'a PreparedStream],
) -> Result<PreparedReceive<'a, N, R>, StageError> {
    validate_e2(r, c)?;
    let mut request = r.shared;
    request.action_tag = Action::Reserve as u8;
    request.reservation = None;
    request.reservation_state_tag = ReservationState::Unused as u8;
    let batch = request.batch.ok_or(StageError::MissingBatch)?;
    request.expected_charge = batch.batch_charge;
    request.reserved_charge = batch.batch_charge;
    if r.frames.is_empty() && N == 0 && R == 0 && batch.rows.is_empty() {
        let lease = credit.reserve::<R>(&request, &c.shared)?;
        return Ok(PreparedReceive {
            _live: live,
            streams: std::array::from_fn(|_| None),
            _plans: std::array::from_fn(|_| None),
            payload: Bytes::new(),
            _retained_datagram: datagram,
            _lease: lease,
        });
    }
    // Match the borrowed admission inventory to actual constructor layouts before
    // touching the allocator. The minimal two-stream plan lives inline, no A row.
    let wrapper = metadata_owned_bytes::staged_owner_layout();
    let mut distinct = 0;
    for (i, row) in batch.rows.iter().enumerate() {
        let (capacity, size, align) = match Role::decode(row.role, i)? {
            Role::StreamPayload => (datagram.len(), 1, 1),
            Role::StreamWrapper => (wrapper.size(), wrapper.size(), wrapper.align()),
            Role::StreamHeap => {
                let frame = r
                    .frames
                    .iter()
                    .enumerate()
                    .filter(|(i, f)| !r.frames[..*i].iter().any(|p| p.stream_id == f.stream_id))
                    .nth(distinct)
                    .map(|(_, f)| f)
                    .ok_or(StageError::CapacityObservationMismatch(i))?;
                distinct += 1;
                (
                    usize::try_from(frame.prepared_slots)
                        .map_err(|_| StageError::NotRepresentable(Field::PreparedSlots))?
                        .checked_mul(std::mem::size_of::<Buffer>())
                        .ok_or(StageError::ArithmeticOverflow(Arithmetic::AllocationProduct(i)))?,
                    std::mem::size_of::<Buffer>(),
                    std::mem::align_of::<Buffer>(),
                )
            }
            Role::ReceivePlan => (
                usize::try_from(row.count)
                    .map_err(|_| StageError::NotRepresentable(Field::Count))?
                    .checked_mul(std::mem::size_of::<ReceiveRecord>())
                    .ok_or(StageError::ArithmeticOverflow(Arithmetic::AllocationProduct(i)))?,
                std::mem::size_of::<ReceiveRecord>(),
                std::mem::align_of::<ReceiveRecord>(),
            ),
            _ => return Err(StageError::RoleNotAllowed(i)),
        };
        if (row.capacity, row.element_size, row.alignment)
            != (capacity as u64, size as u64, align as u64)
        {
            return Err(StageError::CapacityObservationMismatch(i));
        }
    }
    if distinct != N || batch.rows.len() != R || R < N + 2 {
        return Err(StageError::StreamPreparationMissing(c.scan.last().map_or(0, |f| f.stream_id)));
    }
    let lease = credit.reserve::<R>(&request, &c.shared)?;
    let fail = || StageError::Resource(credit.metadata.fail(MetadataClass::StreamAssemblers));
    let mut payload = Vec::new();
    payload.try_reserve_exact(datagram.len()).map_err(|_| fail())?;
    assert_eq!(payload.capacity(), datagram.len());
    payload.extend_from_slice(&datagram);
    credit.metadata.allocated();
    let payload = metadata_owned_bytes::into_staged_bytes(payload).map_err(|_| fail())?;
    credit.metadata.allocated();
    let mut plans: [Option<Vec<ReceiveRecord>>; R] = std::array::from_fn(|_| None);
    for (i, row) in
        batch.rows.iter().enumerate().filter(|(_, row)| row.role == Role::ReceivePlan as u8)
    {
        let mut plan = Vec::new();
        let count =
            usize::try_from(row.count).map_err(|_| StageError::NotRepresentable(Field::Count))?;
        plan.try_reserve_exact(count).map_err(|_| fail())?;
        assert_eq!(plan.capacity(), count);
        if count < r.frames.len() {
            return Err(StageError::CapacityInsufficient(i));
        }
        plan.extend_from_slice(r.frames);
        plans[i] = Some(plan);
        credit.metadata.allocated();
    }
    let mut streams: [Option<PreparedStream>; N] = std::array::from_fn(|_| None);
    for (slot, frame) in r
        .frames
        .iter()
        .enumerate()
        .filter(|(i, f)| !r.frames[..*i].iter().any(|p| p.stream_id == f.stream_id))
        .map(|(_, f)| f)
        .enumerate()
    {
        #[cfg(test)]
        if tests::refuse_stream(slot) {
            return Err(fail());
        }
        let mut heap =
            MetadataHeap::prepare_staged(frame.prepared_slots as usize).map_err(|_| fail())?;
        credit.metadata.allocated();
        if let Some(old) = live.iter().find(|old| old.stream_id == frame.stream_id) {
            for buffer in &old.heap {
                if heap.len() == heap.capacity() {
                    return Err(StageError::ReceiveSlotsInsufficient(slot));
                }
                heap.push_reserved(buffer.clone());
            }
        }
        for f in r.frames.iter().filter(|f| f.stream_id == frame.stream_id) {
            if heap.len() == heap.capacity() {
                return Err(StageError::ReceiveSlotsInsufficient(slot));
            }
            if f.length == 0 {
                continue;
            }
            heap.push_reserved(Buffer::new(
                f.offset,
                payload.slice(f.view_start as usize..f.view_end as usize),
                payload.len(),
            ));
        }
        let final_descriptors = r
            .frames
            .iter()
            .rev()
            .find(|f| f.stream_id == frame.stream_id)
            .expect("current stream has a frame")
            .descriptor_count;
        if heap.len() as u64 != final_descriptors {
            return Err(StageError::DescriptorCountMismatch(slot));
        }
        streams[slot] =
            Some(PreparedStream { stream_id: frame.stream_id, owner: frame.stream_owner, heap });
    }
    Ok(PreparedReceive {
        _live: live,
        streams,
        _plans: plans,
        payload,
        _retained_datagram: datagram,
        _lease: lease,
    })
}
