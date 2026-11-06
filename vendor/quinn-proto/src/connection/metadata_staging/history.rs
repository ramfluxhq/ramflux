// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dormant history, compaction and CRYPTO preparation; no publication entrypoint.
use super::*;
use crate::connection::{assembler::Buffer, metadata_heap::MetadataHeap, metadata_owned_bytes};
use crate::packet::SpaceId;
use bytes::Bytes;
fn space_id(tag: u8) -> SpaceId {
    match tag {
        0 => SpaceId::Initial,
        1 => SpaceId::Handshake,
        2 => SpaceId::Data,
        _ => unreachable!("recognized CRYPTO space"),
    }
}
#[cfg(test)]
mod tests;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RangeRecord {
    pub(crate) start: u64,
    pub(crate) end: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CryptoReceiveField {
    Offset,
    Length,
    Owner,
    PreparedSlots,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CryptoReceiveRecord {
    pub(crate) space_tag: u8,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) owner: OwnerId,
    pub(crate) prepared_slots: u64,
}
pub(crate) struct HistoryRequest<'a> {
    pub(crate) shared: Request<'a>,
    pub(crate) ranges: &'a [RangeRecord],
    pub(crate) range_count: u64,
    pub(crate) replacement_slots: u64,
    pub(crate) copy_length: u64,
    pub(crate) copy_capacity: u64,
    pub(crate) crypto: &'a [CryptoReceiveRecord],
}
/// Borrowed trusted sequential scan and actual-storage observations, never wire claims.
pub(crate) struct HistoryContext<'a> {
    pub(crate) shared: Context<'a>,
    pub(crate) ranges: &'a [RangeRecord],
    pub(crate) replacement_slots: u64,
    pub(crate) copy: &'a [u8],
    pub(crate) expected_copy: &'a [u8],
    pub(crate) old_retained: bool,
    pub(crate) crypto: &'a [CryptoReceiveRecord; 3],
    pub(crate) required_slots: [u64; 3],
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedHistory;
fn history_role(role: Role) -> bool {
    matches!(
        role,
        Role::HistoryOld
            | Role::HistoryReplacement
            | Role::StreamCompactionCopy
            | Role::CryptoHeap
            | Role::CryptoPayload
            | Role::CryptoWrapper
            | Role::HistoryPlan
    )
}
pub(crate) fn validate_e2h(
    r: &HistoryRequest<'_>,
    c: &HistoryContext<'_>,
) -> Result<ValidatedHistory, StageError> {
    use StageError::*;
    if binding(&r.shared, &c.shared)?.phase_tag != 0 {
        return Err(PhaseMismatch);
    }
    validate_batch_for(r.shared.batch, &c.shared, history_role, None)?;
    validate_owners(&r.shared, &c.shared)?;
    for (f, v) in [
        (Field::RangeCount, r.range_count),
        (Field::ReplacementSlots, r.replacement_slots),
        (Field::CopyLength, r.copy_length),
        (Field::CopyCapacity, r.copy_capacity),
    ] {
        representable(v, f, &c.shared)?;
    }
    if usize::try_from(r.range_count).ok() != Some(r.ranges.len()) {
        return Err(CountMismatch(Count::HistoryRanges));
    }
    for (i, range) in r.ranges.iter().enumerate() {
        if range.start >= range.end {
            return Err(HistoryRangeOrder(i));
        }
        if range.start >= (1 << 62) || range.end >= (1 << 62) {
            return Err(HistoryEndpointOutOfRange(i));
        }
        if i > 0 && r.ranges[i - 1].end >= range.start {
            return Err(HistoryNotNormalized(i));
        }
    }
    if r.ranges != c.ranges {
        return Err(HistoryContentsMismatch);
    }
    if r.replacement_slots < c.ranges.len() as u64 {
        return Err(HistoryCapacityInsufficient);
    }
    if r.replacement_slots != c.replacement_slots {
        return Err(HistoryCapacityObservationMismatch);
    }
    if r.copy_length != c.expected_copy.len() as u64 {
        return Err(CompactionLengthMismatch);
    }
    if r.copy_length > r.copy_capacity {
        return Err(CompactionCapacityInsufficient);
    }
    if c.copy != c.expected_copy {
        return Err(CompactionContentsMismatch);
    }
    if !c.old_retained {
        return Err(OldHistoryNotRetained);
    }
    let mut seen = [false; 3];
    for record in r.crypto {
        if record.space_tag > 2 {
            return Err(InvalidCryptoSpace(record.space_tag));
        }
        let space = usize::from(record.space_tag);
        if seen[space] {
            return Err(CryptoSpaceDuplicate(space_id(record.space_tag)));
        }
        seen[space] = true;
    }
    for (space, present) in seen.iter().enumerate() {
        if !present {
            return Err(CryptoSpaceMissing(space_id(space as u8)));
        }
    }
    for (i, record) in r.crypto.iter().enumerate() {
        representable(record.length, Field::CryptoLength, &c.shared)?;
        representable(record.prepared_slots, Field::CryptoPreparedSlots, &c.shared)?;
        let end = record
            .offset
            .checked_add(record.length)
            .ok_or(ArithmeticOverflow(Arithmetic::CryptoReceiveEnd(i)))?;
        if end >= (1 << 62) {
            return Err(CryptoReceiveEndOutOfRange(i));
        }
        let space = usize::from(record.space_tag);
        let actual = &c.crypto[space];
        for (f, equal) in [
            (CryptoReceiveField::Offset, record.offset == actual.offset),
            (CryptoReceiveField::Length, record.length == actual.length),
            (CryptoReceiveField::Owner, record.owner == actual.owner),
            (CryptoReceiveField::PreparedSlots, record.prepared_slots == actual.prepared_slots),
        ] {
            if !equal {
                return Err(CryptoReceiveMismatch(space_id(record.space_tag), f));
            }
        }
        if actual.prepared_slots < c.required_slots[space] {
            return Err(CryptoReceiveCapacityInsufficient(space_id(record.space_tag)));
        }
    }
    Ok(ValidatedHistory)
}
/// Old storage stays borrowed for the entire replacement lifetime. Fields destroy
/// actual buffers, wrappers and plans before returning the aggregate debit.
pub(crate) struct PreparedHistory<'a, const R: usize> {
    _old: Option<&'a Self>,
    ranges: Vec<RangeRecord>,
    copy: Vec<u8>,
    crypto: [MetadataHeap<Buffer>; 3],
    payload: Bytes,
    _payload_source: &'a Bytes,
    plans: [Option<Vec<RangeRecord>>; R],
    _lease: StageLease<R>,
}
pub(crate) fn prepare_history<'a, const R: usize>(
    r: &HistoryRequest<'_>,
    c: &HistoryContext<'_>,
    credit: &Arc<StageCredit>,
    old: Option<&'a PreparedHistory<'a, R>>,
    payload: &'a Bytes,
) -> Result<PreparedHistory<'a, R>, StageError> {
    use StageError::*;
    validate_e2h(r, c)?;
    let mut request = r.shared;
    request.action_tag = Action::Reserve as u8;
    request.reservation = None;
    request.reservation_state_tag = ReservationState::Unused as u8;
    let batch = request.batch.ok_or(StageError::MissingBatch)?;
    request.expected_charge = batch.batch_charge;
    request.reserved_charge = batch.batch_charge;
    // Layouts are actual constructor layouts. Retained old rows belong to O only.
    let wrapper = metadata_owned_bytes::staged_owner_layout();
    let mut heaps = 0;
    let mut history = 0;
    let mut copies = 0;
    let mut payloads = 0;
    let mut wrappers = 0;
    for (i, row) in batch.rows.iter().enumerate() {
        let (count, size, align) = match Role::decode(row.role, i)? {
            Role::HistoryReplacement => {
                history += 1;
                (
                    r.replacement_slots as usize,
                    std::mem::size_of::<RangeRecord>(),
                    std::mem::align_of::<RangeRecord>(),
                )
            }
            Role::StreamCompactionCopy => {
                copies += 1;
                (r.copy_capacity as usize, 1, 1)
            }
            Role::CryptoPayload => {
                payloads += 1;
                (payload.len(), 1, 1)
            }
            Role::CryptoWrapper => {
                wrappers += 1;
                (1, wrapper.size(), wrapper.align())
            }
            Role::CryptoHeap => {
                let record = c
                    .crypto
                    .iter()
                    .filter(|r| r.prepared_slots > 0)
                    .nth(heaps)
                    .ok_or(CryptoSpaceDuplicate(space_id(2)))?;
                heaps += 1;
                (
                    record.prepared_slots as usize,
                    std::mem::size_of::<Buffer>(),
                    std::mem::align_of::<Buffer>(),
                )
            }
            Role::HistoryPlan => (
                row.count as usize,
                std::mem::size_of::<RangeRecord>(),
                std::mem::align_of::<RangeRecord>(),
            ),
            _ => return Err(StageError::RoleNotAllowed(i)),
        };
        if row.count != count as u64
            || row.element_size != size as u64
            || row.alignment != align as u64
            || row.capacity
                != count
                    .checked_mul(size)
                    .ok_or(ArithmeticOverflow(Arithmetic::AllocationProduct(i)))?
                    as u64
        {
            return Err(CapacityObservationMismatch(i));
        }
    }
    if history != usize::from(r.replacement_slots > 0) {
        return Err(HistoryCapacityInsufficient);
    }
    if copies != usize::from(r.copy_capacity > 0) {
        return Err(CompactionCapacityInsufficient);
    }
    if heaps != c.crypto.iter().filter(|r| r.prepared_slots > 0).count()
        || payloads > 1
        || wrappers != payloads
        || (payload.is_empty() && payloads != 0)
    {
        return Err(CryptoSpaceMissing(space_id(2)));
    }
    if c.crypto.iter().map(|x| u128::from(x.length)).sum::<u128>() != payload.len() as u128 {
        return Err(CryptoReceiveMismatch(space_id(0), CryptoReceiveField::Length));
    }
    let lease = credit.reserve_for::<R>(&request, &c.shared, history_role)?;
    let mut ranges = Vec::new();
    let mut copy = Vec::new();
    let mut data = Vec::new();
    let mut crypto = std::array::from_fn(|_| MetadataHeap::default());
    let mut plans = std::array::from_fn(|_| None);
    let mut heap_slot = 0;
    // With no payload/wrapper A rows, reuse the packet's already prepared shared
    // backing. This borrow prevents its source aggregate lease from ending first.
    let mut bytes = if payloads == 0 { payload.clone() } else { Bytes::new() };
    // Inline fields precede lease at every failure and successful destruction.
    for (i, row) in batch.rows.iter().enumerate() {
        let class = Role::decode(row.role, i)?.assignment().1;
        let fail = || StageError::Resource(credit.metadata.fail(class));
        #[cfg(test)]
        if tests::refuses(i) {
            return Err(fail());
        }
        match Role::decode(row.role, i)? {
            Role::HistoryReplacement => {
                ranges.try_reserve_exact(row.count as usize).map_err(|_| fail())?;
                assert_eq!(ranges.capacity(), row.count as usize);
                ranges.extend_from_slice(r.ranges);
            }
            Role::StreamCompactionCopy => {
                copy.try_reserve_exact(row.capacity as usize).map_err(|_| fail())?;
                assert_eq!(copy.capacity(), row.capacity as usize);
                copy.extend_from_slice(c.copy);
            }
            Role::CryptoPayload => {
                data.try_reserve_exact(payload.len()).map_err(|_| fail())?;
                assert_eq!(data.capacity(), payload.len());
                data.extend_from_slice(payload);
            }
            Role::CryptoWrapper => {
                continue;
            }
            Role::CryptoHeap => {
                let space = c
                    .crypto
                    .iter()
                    .filter(|r| r.prepared_slots > 0)
                    .nth(heap_slot)
                    .expect("validated CRYPTO heap count")
                    .space_tag as usize;
                crypto[space] =
                    MetadataHeap::prepare_staged(row.count as usize).map_err(|_| fail())?;
                heap_slot += 1;
            }
            Role::HistoryPlan => {
                let mut plan = Vec::new();
                plan.try_reserve_exact(row.count as usize).map_err(|_| fail())?;
                assert_eq!(plan.capacity(), row.count as usize);
                if plan.capacity() < r.ranges.len() {
                    return Err(CapacityInsufficient(i));
                }
                plan.extend_from_slice(r.ranges);
                plans[i] = Some(plan);
            }
            _ => return Err(RoleNotAllowed(i)),
        }
        credit.metadata.allocated();
    }
    if payloads != 0 {
        bytes = metadata_owned_bytes::into_staged_bytes(data).map_err(|_| {
            StageError::Resource(credit.metadata.fail(MetadataClass::CryptoAssemblers))
        })?;
        credit.metadata.allocated();
    }
    let mut cursor = 0;
    for (space, record) in c.crypto.iter().enumerate() {
        if let Some(old) = old {
            for buffer in &old.crypto[space] {
                if crypto[space].len() == crypto[space].capacity() {
                    return Err(CryptoReceiveCapacityInsufficient(space_id(space as u8)));
                }
                crypto[space].push_reserved(buffer.clone());
            }
        }
        let length = record.length as usize;
        if length > 0 {
            if crypto[space].len() == crypto[space].capacity() {
                return Err(CryptoReceiveCapacityInsufficient(space_id(space as u8)));
            }
            crypto[space].push_reserved(Buffer::new(
                record.offset,
                bytes.slice(cursor..cursor + length),
                bytes.len(),
            ));
        }
        cursor += length;
    }
    Ok(PreparedHistory {
        _old: old,
        ranges,
        copy,
        crypto,
        payload: bytes,
        _payload_source: payload,
        plans,
        _lease: lease,
    })
}
