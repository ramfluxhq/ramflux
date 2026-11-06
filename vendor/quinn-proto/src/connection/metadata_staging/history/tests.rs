// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent E2H validation oracle and physical storage witnesses.
use super::super::tests::{Fixture, completed_free};
use super::*;
static PAYLOAD: Bytes = Bytes::from_static(b"123456");
static EMPTY_PAYLOAD: Bytes = Bytes::new();
use std::sync::atomic::Ordering;
thread_local! {static REFUSE:std::cell::Cell<Option<usize>>=const{std::cell::Cell::new(None)};}
pub(super) fn refuses(row: usize) -> bool {
    REFUSE.with(|f| f.get() == Some(row))
}
const EMPTY_CRYPTO: [CryptoReceiveRecord; 3] = [
    CryptoReceiveRecord {
        space_tag: 0,
        offset: 0,
        length: 0,
        owner: OwnerId(20),
        prepared_slots: 0,
    },
    CryptoReceiveRecord {
        space_tag: 1,
        offset: 0,
        length: 0,
        owner: OwnerId(20),
        prepared_slots: 0,
    },
    CryptoReceiveRecord {
        space_tag: 2,
        offset: 0,
        length: 0,
        owner: OwnerId(20),
        prepared_slots: 0,
    },
];
fn empty_request(shared: Request<'_>) -> HistoryRequest<'_> {
    HistoryRequest {
        shared,
        ranges: &[],
        range_count: 0,
        replacement_slots: 0,
        copy_length: 0,
        copy_capacity: 0,
        crypto: &EMPTY_CRYPTO,
    }
}
fn empty_context(shared: Context<'_>) -> HistoryContext<'_> {
    HistoryContext {
        shared,
        ranges: &[],
        replacement_slots: 0,
        copy: &[],
        expected_copy: &[],
        old_retained: true,
        crypto: &EMPTY_CRYPTO,
        required_slots: [0; 3],
    }
}
macro_rules! negative {
    ($name:ident,$setup:expr,$error:expr) => {
        #[test]
        fn $name() {
            let mut f = Fixture::valid();
            f.prepare();
            f.rows[0].role = Role::HistoryReplacement as u8;
            f.rows[0].class_tag = 7;
            ($setup)(&mut f);
            assert_eq!(f.violations_with_debit(true), vec![$error], "one independent shared-rule failure");
            let before = format!("{:?}{:?}", f.owners, f.ledgers);
            let session = tls_contract::tests::CountingSession::default();
            let result = validate_e2h(&empty_request(f.request()), &empty_context(f.context()));
            assert_eq!(result, Err($error));
            assert_eq!(session.calls.load(Ordering::SeqCst), 0);
            assert_eq!(format!("{:?}{:?}", f.owners, f.ledgers), before);
        }
    };
}
negative!(
    inventory_e2h_missing_binding,
    |f: &mut Fixture| {
        f.binding = None;
    },
    StageError::MissingBinding
);
negative!(
    inventory_e2h_empty_binding_connection,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().connection = ConnectionId(0);
    },
    StageError::EmptyBinding(Field::Connection)
);
negative!(
    inventory_e2h_wrong_binding_connection,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().connection = ConnectionId(99);
    },
    StageError::BindingMismatch(Field::Connection)
);
negative!(
    inventory_e2h_empty_binding_credit,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().credit = CreditId(0);
    },
    StageError::EmptyBinding(Field::Credit)
);
negative!(
    inventory_e2h_wrong_binding_credit,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().credit = CreditId(99);
    },
    StageError::BindingMismatch(Field::Credit)
);
negative!(
    inventory_e2h_empty_binding_configuration,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().configuration = ConfigurationId(0);
    },
    StageError::EmptyBinding(Field::Configuration)
);
negative!(
    inventory_e2h_wrong_binding_configuration,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().configuration = ConfigurationId(99);
    },
    StageError::BindingMismatch(Field::Configuration)
);
negative!(
    inventory_e2h_empty_binding_layout,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().layout = LayoutId(0);
    },
    StageError::EmptyBinding(Field::Layout)
);
negative!(
    inventory_e2h_wrong_binding_layout,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().layout = LayoutId(99);
    },
    StageError::BindingMismatch(Field::Layout)
);
negative!(
    inventory_e2h_unknown_space,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().space_tag = 9;
    },
    StageError::InvalidSpace(9)
);
negative!(
    inventory_e2h_wrong_space,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().space_tag = 2;
    },
    StageError::SpaceMismatch
);
negative!(
    inventory_e2h_pn_out_of_range,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().pn = 1 << 62;
    },
    StageError::PacketNumberOutOfRange
);
negative!(
    inventory_e2h_wrong_pn,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().pn = 18;
    },
    StageError::PacketNumberMismatch
);
negative!(
    inventory_e2h_stale_generation,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().generation = 4;
    },
    StageError::GenerationMismatch
);
negative!(
    inventory_e2h_wrong_stage,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().stage_id = 99;
    },
    StageError::StageMismatch
);
negative!(
    inventory_e2h_unknown_phase,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().phase_tag = 9;
    },
    StageError::InvalidPhase(9)
);
negative!(
    inventory_e2h_wrong_phase,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().phase_tag = 1;
    },
    StageError::PhaseMismatch
);
negative!(
    inventory_e2h_terminal_binding,
    |f: &mut Fixture| {
        f.terminal = true;
    },
    StageError::TerminalFenced
);
negative!(
    inventory_e2h_missing_batch,
    |f: &mut Fixture| {
        f.batch_present = false;
    },
    StageError::MissingBatch
);
negative!(
    inventory_e2h_wrong_row_count,
    |f: &mut Fixture| {
        f.row_count = 2;
    },
    StageError::CountMismatch(Count::Rows)
);
negative!(
    inventory_e2h_empty_allocation_id,
    |f: &mut Fixture| {
        f.rows[0].allocation = AllocationId(0);
    },
    StageError::EmptyAllocationId(0)
);
negative!(
    inventory_e2h_duplicate_allocation_id,
    |f: &mut Fixture| {
        f.second();
        f.rows[1].allocation = AllocationId(10);
    },
    StageError::DuplicateAllocation(1)
);
negative!(
    inventory_e2h_already_live_allocation_id,
    |f: &mut Fixture| {
        f.registry.push(f.owners[0]);
    },
    StageError::AllocationAlreadyLive(0)
);
negative!(
    inventory_e2h_unknown_allocation_role,
    |f: &mut Fixture| {
        f.rows[0].role = 255;
    },
    StageError::InvalidRole(0)
);
negative!(
    inventory_e2h_foreign_allocation_role,
    |f: &mut Fixture| {
        f.rows[0].role = Role::TerminalOwner as u8;
    },
    StageError::RoleNotAllowed(0)
);
negative!(
    inventory_e2h_unknown_domain,
    |f: &mut Fixture| {
        f.rows[0].domain_tag = 9;
    },
    StageError::InvalidDomain(0, 9)
);
negative!(
    inventory_e2h_unknown_class,
    |f: &mut Fixture| {
        f.rows[0].class_tag = 12;
    },
    StageError::InvalidClass(0, 12)
);
negative!(
    inventory_e2h_wrong_role_domain,
    |f: &mut Fixture| {
        f.rows[0].domain_tag = 1;
    },
    StageError::RoleDomainMismatch(0)
);
negative!(
    inventory_e2h_wrong_role_class,
    |f: &mut Fixture| {
        f.rows[0].class_tag = 6;
    },
    StageError::RoleClassMismatch(0)
);
negative!(
    inventory_e2h_wrong_element_size,
    |f: &mut Fixture| {
        f.rows[0].element_size = 4;
    },
    StageError::LayoutMismatch(0, Field::ElementSize)
);
negative!(
    inventory_e2h_wrong_alignment,
    |f: &mut Fixture| {
        f.rows[0].alignment = 4;
    },
    StageError::LayoutMismatch(0, Field::Alignment)
);
negative!(
    inventory_e2h_allocation_product_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(u64::MAX - 127, 1 << 63, 2);
    },
    StageError::ArithmeticOverflow(Arithmetic::AllocationProduct(0))
);
negative!(
    inventory_e2h_allocation_capacity_too_small,
    |f: &mut Fixture| {
        f.rows[0].count = 9;
    },
    StageError::CapacityInsufficient(0)
);
negative!(
    inventory_e2h_false_observed_capacity,
    |f: &mut Fixture| {
        f.rows[0].capacity = 65;
        f.rows[0].charge = 192;
        f.batch_charge = 192;
        f.expected_charge = 192;
        f.reserved_charge = 192;
    },
    StageError::CapacityObservationMismatch(0)
);
negative!(
    inventory_e2h_allocation_charge_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(u64::MAX, 1, 1);
    },
    StageError::ArithmeticOverflow(Arithmetic::AllocationCharge(0))
);
negative!(
    inventory_e2h_wrong_allocation_charge,
    |f: &mut Fixture| {
        f.rows[0].charge = 192;
        f.batch_charge = 192;
        f.expected_charge = 192;
        f.reserved_charge = 192;
    },
    StageError::ChargeMismatch(0)
);
negative!(
    inventory_e2h_metadata_sum_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(1 << 63, 8, 8);
        f.second();
    },
    StageError::ArithmeticOverflow(Arithmetic::MetadataSum)
);
negative!(
    inventory_e2h_wrong_batch_charge,
    |f: &mut Fixture| {
        f.batch_charge = 192;
        f.expected_charge = 192;
        f.reserved_charge = 192;
    },
    StageError::BatchChargeMismatch(Domain::Metadata)
);
negative!(
    inventory_e2h_wrong_raw_charge,
    |f: &mut Fixture| {
        f.raw_charge = 64;
    },
    StageError::BatchChargeMismatch(Domain::RawBase)
);
negative!(
    inventory_e2h_metadata_overlap_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.ledgers.metadata_used = u64::MAX - 63;
    },
    StageError::ArithmeticOverflow(Arithmetic::MetadataOverlap)
);
negative!(
    inventory_e2h_slice_overlap_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.ledgers.slice_used = u64::MAX - 63;
    },
    StageError::ArithmeticOverflow(Arithmetic::SliceOverlap)
);
negative!(
    inventory_e2h_overlap_exceeds_metadata,
    |f: &mut Fixture| {
        f.ledgers.metadata_limit = 192;
    },
    StageError::Resource(ResourceExhausted { class: MetadataClass::UnorderedHistory })
);
negative!(
    inventory_e2h_overlap_exceeds_slice,
    |f: &mut Fixture| {
        f.ledgers.slice_limit = 4160;
    },
    StageError::Resource(ResourceExhausted { class: MetadataClass::UnorderedHistory })
);
negative!(
    inventory_e2h_missing_owners,
    |f: &mut Fixture| {
        f.prepare();
        f.owners_present = false;
    },
    StageError::MissingOwners
);
negative!(
    inventory_e2h_wrong_owner_count,
    |f: &mut Fixture| {
        f.prepare();
        f.owner_count = 2;
    },
    StageError::CountMismatch(Count::Owners)
);
negative!(
    inventory_e2h_duplicate_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].owner = OwnerId(20);
    },
    StageError::DuplicateOwner(1)
);
negative!(
    inventory_e2h_unknown_owner_allocation,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].allocation = AllocationId(99);
    },
    StageError::UnknownAllocation(0)
);
negative!(
    inventory_e2h_wrong_owner_lease,
    |f: &mut Fixture| {
        f.prepare();
        let mut o = f.owners[0];
        o.owner = OwnerId(99);
        o.allocation = AllocationId(99);
        o.lease = LeaseId(99);
        f.registry.push(o);
        f.owners[0].lease = LeaseId(99);
    },
    StageError::LeaseMismatch(0)
);
negative!(
    inventory_e2h_double_charged_backing,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].allocation = AllocationId(10);
    },
    StageError::DuplicateBackingCharge(1)
);
negative!(
    inventory_e2h_aliased_distinct_allocations,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].lease = LeaseId(30);
    },
    StageError::LeaseAliased(1)
);
negative!(
    inventory_e2h_unknown_owner_location,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].location_tag = 9;
    },
    StageError::InvalidOwnerLocation(0, 9)
);
negative!(
    inventory_e2h_wrong_owner_location,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].location_tag = 0;
    },
    StageError::OwnerLocationMismatch(0)
);
negative!(
    inventory_e2h_wrong_owner_references,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 2;
    },
    StageError::ReferenceCountMismatch(0)
);
negative!(
    inventory_e2h_missing_physical_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.owners.clear();
        f.owner_count = 0;
    },
    StageError::OwnerMissing(OwnerId(20))
);
negative!(
    inventory_e2h_extra_physical_owner,
    |f: &mut Fixture| {
        f.prepare();
        let mut o = f.owners[0];
        o.owner = OwnerId(99);
        o.allocation = AllocationId(99);
        o.lease = LeaseId(99);
        f.registry.push(o);
        f.owners.push(o);
        f.owner_count = 2;
    },
    StageError::OwnerUnexpected(OwnerId(99))
);
negative!(
    inventory_e2h_refund_before_free,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].release_requested = true;
    },
    StageError::FreeNotCompleted(0)
);
negative!(
    inventory_e2h_foreign_free_witness,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].free = Some(completed_free(AllocationId(99), LeaseId(99), false));
    },
    StageError::FreeWitnessMismatch(0)
);
negative!(
    inventory_e2h_reused_free_witness,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].free = Some(completed_free(AllocationId(10), LeaseId(30), true));
    },
    StageError::FreeWitnessConsumed(0)
);
negative!(
    inventory_e2h_unrepresentable_capacity,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].capacity = 8193;
    },
    StageError::NotRepresentable(Field::Capacity)
);
negative!(
    inventory_e2h_unrepresentable_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].count = 8193;
    },
    StageError::NotRepresentable(Field::Count)
);
negative!(
    inventory_e2h_unrepresentable_element_size,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].element_size = 8193;
    },
    StageError::NotRepresentable(Field::ElementSize)
);
negative!(
    inventory_e2h_unrepresentable_alignment,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].alignment = 8193;
    },
    StageError::NotRepresentable(Field::Alignment)
);
negative!(
    inventory_e2h_unrepresentable_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].charge = 8193;
    },
    StageError::NotRepresentable(Field::Charge)
);
negative!(
    inventory_e2h_unrepresentable_row_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.row_count = 8193;
    },
    StageError::NotRepresentable(Field::RowCount)
);
negative!(
    inventory_e2h_unrepresentable_batch_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.batch_charge = 8193;
    },
    StageError::NotRepresentable(Field::BatchCharge)
);
negative!(
    inventory_e2h_unrepresentable_raw_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.raw_charge = 8193;
    },
    StageError::NotRepresentable(Field::RawCharge)
);
negative!(
    inventory_e2h_unrepresentable_metadata_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.metadata_limit = 8193;
    },
    StageError::NotRepresentable(Field::MetadataLimit)
);
negative!(
    inventory_e2h_unrepresentable_metadata_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.metadata_used = 8193;
    },
    StageError::NotRepresentable(Field::MetadataUsed)
);
negative!(
    inventory_e2h_unrepresentable_slice_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.slice_limit = 8193;
    },
    StageError::NotRepresentable(Field::SliceLimit)
);
negative!(
    inventory_e2h_unrepresentable_slice_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.slice_used = 8193;
    },
    StageError::NotRepresentable(Field::SliceUsed)
);
negative!(
    inventory_e2h_unrepresentable_raw_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.raw_limit = 8193;
    },
    StageError::NotRepresentable(Field::RawLimit)
);
negative!(
    inventory_e2h_unrepresentable_raw_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.raw_used = 8193;
    },
    StageError::NotRepresentable(Field::RawUsed)
);
negative!(
    inventory_e2h_unrepresentable_owner_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.prepare();
        f.owner_count = 8193;
    },
    StageError::NotRepresentable(Field::OwnerCount)
);
negative!(
    inventory_e2h_invalid_used_metadata,
    |f: &mut Fixture| {
        f.ledgers.metadata_used = f.ledgers.metadata_limit + 1;
    },
    StageError::InvalidLedger(Domain::Metadata)
);
negative!(
    inventory_e2h_invalid_used_slice,
    |f: &mut Fixture| {
        f.ledgers.slice_used = f.ledgers.slice_limit + 1;
    },
    StageError::InvalidLedger(Domain::Slice)
);
negative!(
    inventory_e2h_invalid_used_raw,
    |f: &mut Fixture| {
        f.ledgers.raw_used = f.ledgers.raw_limit + 1;
    },
    StageError::InvalidLedger(Domain::RawBase)
);
negative!(
    inventory_e2h_empty_owner_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].owner = OwnerId(0);
    },
    StageError::EmptyOwnerField(Field::Owner, 0)
);
negative!(
    inventory_e2h_empty_owner_allocation,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].allocation = AllocationId(0);
    },
    StageError::EmptyOwnerField(Field::Allocation, 0)
);
negative!(
    inventory_e2h_empty_owner_lease,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].lease = LeaseId(0);
    },
    StageError::EmptyOwnerField(Field::Lease, 0)
);

struct HistoryFixture {
    shared: Fixture,
    ranges: Vec<RangeRecord>,
    expected: Vec<RangeRecord>,
    range_count: u64,
    slots: u64,
    actual_slots: u64,
    copy: Vec<u8>,
    expected_copy: Vec<u8>,
    length: u64,
    capacity: u64,
    retained: bool,
    crypto: Vec<CryptoReceiveRecord>,
    actual: [CryptoReceiveRecord; 3],
    required: [u64; 3],
}
impl HistoryFixture {
    fn valid() -> Self {
        let mut shared = Fixture::valid();
        shared.prepare();
        shared.rows[0].role = Role::HistoryReplacement as u8;
        shared.rows[0].class_tag = 7;
        let ranges = vec![RangeRecord { start: 0, end: 3 }, RangeRecord { start: 6, end: 9 }];
        let actual = std::array::from_fn(|i| CryptoReceiveRecord {
            space_tag: i as u8,
            offset: 0,
            length: 2,
            owner: OwnerId(20),
            prepared_slots: 2,
        });
        Self {
            shared,
            expected: ranges.clone(),
            ranges,
            range_count: 2,
            slots: 3,
            actual_slots: 3,
            copy: b"abcdef".to_vec(),
            expected_copy: b"abcdef".to_vec(),
            length: 6,
            capacity: 8,
            retained: true,
            crypto: actual.to_vec(),
            actual,
            required: [1; 3],
        }
    }
    fn request(&self) -> HistoryRequest<'_> {
        HistoryRequest {
            shared: self.shared.request(),
            ranges: &self.ranges,
            range_count: self.range_count,
            replacement_slots: self.slots,
            copy_length: self.length,
            copy_capacity: self.capacity,
            crypto: &self.crypto,
        }
    }
    fn context(&self) -> HistoryContext<'_> {
        HistoryContext {
            shared: self.shared.context(),
            ranges: &self.expected,
            replacement_slots: self.actual_slots,
            copy: &self.copy,
            expected_copy: &self.expected_copy,
            old_retained: self.retained,
            crypto: &self.actual,
            required_slots: self.required,
        }
    }
    // Independent wide arithmetic, complete rule collection, structural prerequisites.
    fn violations(&self) -> Vec<StageError> {
        use StageError::*;
        let mut e = self.shared.violations_with_debit(true);
        if !e.is_empty() {
            return e;
        }
        for (f, v) in [
            (Field::RangeCount, self.range_count),
            (Field::ReplacementSlots, self.slots),
            (Field::CopyLength, self.length),
            (Field::CopyCapacity, self.capacity),
        ] {
            if v > self.shared.target_max {
                e.push(NotRepresentable(f));
            }
        }
        if !e.is_empty() {
            return e;
        }
        if self.range_count as u128 != self.ranges.len() as u128 {
            return vec![CountMismatch(Count::HistoryRanges)];
        }
        for (i, r) in self.ranges.iter().enumerate() {
            if r.start >= r.end {
                e.push(HistoryRangeOrder(i));
                continue;
            }
            if u128::from(r.start) >= 1 << 62 || u128::from(r.end) >= 1 << 62 {
                e.push(HistoryEndpointOutOfRange(i));
                continue;
            }
            if i > 0 && self.ranges[i - 1].end >= r.start {
                e.push(HistoryNotNormalized(i));
            }
        }
        if !e.is_empty() {
            return e;
        }
        if self.ranges != self.expected {
            e.push(HistoryContentsMismatch);
        }
        if (self.slots as u128) < self.expected.len() as u128 {
            e.push(HistoryCapacityInsufficient);
        } else if self.slots != self.actual_slots {
            e.push(HistoryCapacityObservationMismatch);
        }
        if self.length as u128 != self.expected_copy.len() as u128 {
            e.push(CompactionLengthMismatch);
        }
        if self.length > self.capacity {
            e.push(CompactionCapacityInsufficient);
        }
        if self.copy != self.expected_copy {
            e.push(CompactionContentsMismatch);
        }
        if !self.retained {
            e.push(OldHistoryNotRetained);
        }
        let mut seen = [false; 3];
        for r in &self.crypto {
            if r.space_tag > 2 {
                return vec![InvalidCryptoSpace(r.space_tag)];
            }
            let i = r.space_tag as usize;
            if seen[i] {
                return vec![CryptoSpaceDuplicate(space_id(r.space_tag))];
            }
            seen[i] = true;
        }
        for (i, b) in seen.iter().enumerate() {
            if !b {
                return vec![CryptoSpaceMissing(space_id(i as u8))];
            }
        }
        for (i, r) in self.crypto.iter().enumerate() {
            let before = e.len();
            for (f, v) in
                [(Field::CryptoLength, r.length), (Field::CryptoPreparedSlots, r.prepared_slots)]
            {
                if v > self.shared.target_max {
                    e.push(NotRepresentable(f));
                }
            }
            if e.len() != before {
                continue;
            }
            let end = u128::from(r.offset) + u128::from(r.length);
            if end > u128::from(u64::MAX) {
                e.push(ArithmeticOverflow(Arithmetic::CryptoReceiveEnd(i)));
                continue;
            }
            if end >= 1 << 62 {
                e.push(CryptoReceiveEndOutOfRange(i));
                continue;
            }
            let a = &self.actual[r.space_tag as usize];
            for (f, b) in [
                (CryptoReceiveField::Offset, r.offset == a.offset),
                (CryptoReceiveField::Length, r.length == a.length),
                (CryptoReceiveField::Owner, r.owner == a.owner),
                (CryptoReceiveField::PreparedSlots, r.prepared_slots == a.prepared_slots),
            ] {
                if !b {
                    e.push(CryptoReceiveMismatch(space_id(r.space_tag), f));
                }
            }
            if a.prepared_slots < self.required[r.space_tag as usize] {
                e.push(CryptoReceiveCapacityInsufficient(space_id(r.space_tag)));
            }
        }
        e
    }
    fn reject(&self, error: StageError) {
        assert_eq!(self.violations(), vec![error], "one independent rule");
        let before = format!("{:?}{:?}", self.shared.owners, self.shared.ledgers);
        let session = tls_contract::tests::CountingSession::default();
        assert_eq!(validate_e2h(&self.request(), &self.context()), Err(error));
        assert_eq!(session.calls.load(Ordering::SeqCst), 0);
        assert_eq!(format!("{:?}{:?}", self.shared.owners, self.shared.ledgers), before);
    }
}
macro_rules! local_negative {
    ($name:ident,$setup:expr,$error:expr) => {
        #[test]
        fn $name() {
            let mut f = HistoryFixture::valid();
            ($setup)(&mut f);
            f.reject($error);
        }
    };
}
local_negative!(
    inventory_e2h_wrong_range_count,
    |f: &mut HistoryFixture| {
        f.range_count = 1;
    },
    StageError::CountMismatch(Count::HistoryRanges)
);
local_negative!(
    inventory_e2h_empty_or_reversed_history_range,
    |f: &mut HistoryFixture| {
        f.ranges[0].end = 0;
    },
    StageError::HistoryRangeOrder(0)
);
local_negative!(
    inventory_e2h_history_endpoint_out_of_range,
    |f: &mut HistoryFixture| {
        f.ranges[1].end = 1 << 62;
    },
    StageError::HistoryEndpointOutOfRange(1)
);
local_negative!(
    inventory_e2h_history_ranges_not_normalized,
    |f: &mut HistoryFixture| {
        f.ranges[1].start = 3;
    },
    StageError::HistoryNotNormalized(1)
);
local_negative!(
    inventory_e2h_wrong_history_split,
    |f: &mut HistoryFixture| {
        f.ranges[1].end = 10;
    },
    StageError::HistoryContentsMismatch
);
local_negative!(
    inventory_e2h_short_history_replacement,
    |f: &mut HistoryFixture| {
        f.slots = 1;
        f.actual_slots = 1;
    },
    StageError::HistoryCapacityInsufficient
);
local_negative!(
    inventory_e2h_false_history_replacement,
    |f: &mut HistoryFixture| {
        f.slots = 4;
    },
    StageError::HistoryCapacityObservationMismatch
);
local_negative!(
    inventory_e2h_wrong_compaction_length,
    |f: &mut HistoryFixture| {
        f.length = 5;
    },
    StageError::CompactionLengthMismatch
);
local_negative!(
    inventory_e2h_short_compaction_copy,
    |f: &mut HistoryFixture| {
        f.capacity = 5;
    },
    StageError::CompactionCapacityInsufficient
);
local_negative!(
    inventory_e2h_wrong_compaction_contents,
    |f: &mut HistoryFixture| {
        f.copy[0] = 0;
    },
    StageError::CompactionContentsMismatch
);
local_negative!(
    inventory_e2h_old_history_released_during_prepare,
    |f: &mut HistoryFixture| {
        f.retained = false;
    },
    StageError::OldHistoryNotRetained
);
local_negative!(
    inventory_e2h_unknown_crypto_space,
    |f: &mut HistoryFixture| {
        f.crypto[0].space_tag = 3;
    },
    StageError::InvalidCryptoSpace(3)
);
local_negative!(
    inventory_e2h_missing_crypto_space,
    |f: &mut HistoryFixture| {
        f.crypto.remove(1);
    },
    StageError::CryptoSpaceMissing(space_id(1))
);
local_negative!(
    inventory_e2h_duplicate_crypto_space,
    |f: &mut HistoryFixture| {
        f.crypto.push(f.crypto[0]);
    },
    StageError::CryptoSpaceDuplicate(space_id(0))
);
local_negative!(
    inventory_e2h_crypto_receive_end_overflow,
    |f: &mut HistoryFixture| {
        f.crypto[0].offset = u64::MAX;
        f.actual[0].offset = u64::MAX;
    },
    StageError::ArithmeticOverflow(Arithmetic::CryptoReceiveEnd(0))
);
local_negative!(
    inventory_e2h_crypto_receive_end_out_of_range,
    |f: &mut HistoryFixture| {
        f.crypto[0].offset = (1 << 62) - 1;
        f.actual[0].offset = (1 << 62) - 1;
    },
    StageError::CryptoReceiveEndOutOfRange(0)
);
local_negative!(
    inventory_e2h_short_crypto_receive_slots,
    |f: &mut HistoryFixture| {
        f.required[0] = 3;
    },
    StageError::CryptoReceiveCapacityInsufficient(space_id(0))
);
local_negative!(
    inventory_e2h_wrong_crypto_receive_record_offset,
    |f: &mut HistoryFixture| {
        f.crypto[0].offset = 1;
    },
    StageError::CryptoReceiveMismatch(space_id(0), CryptoReceiveField::Offset)
);
local_negative!(
    inventory_e2h_wrong_crypto_receive_record_length,
    |f: &mut HistoryFixture| {
        f.crypto[0].length = 3;
    },
    StageError::CryptoReceiveMismatch(space_id(0), CryptoReceiveField::Length)
);
local_negative!(
    inventory_e2h_wrong_crypto_receive_record_owner,
    |f: &mut HistoryFixture| {
        f.crypto[0].owner = OwnerId(21);
        f.shared.second();
        f.shared.second_owner();
    },
    StageError::CryptoReceiveMismatch(space_id(0), CryptoReceiveField::Owner)
);
local_negative!(
    inventory_e2h_wrong_crypto_receive_record_prepared_slots,
    |f: &mut HistoryFixture| {
        f.crypto[0].prepared_slots = 3;
    },
    StageError::CryptoReceiveMismatch(space_id(0), CryptoReceiveField::PreparedSlots)
);
local_negative!(
    inventory_e2h_unrepresentable_range_count,
    |f: &mut HistoryFixture| {
        f.shared.target_max = 8192;
        f.range_count = 8193;
    },
    StageError::NotRepresentable(Field::RangeCount)
);
local_negative!(
    inventory_e2h_unrepresentable_replacement_slots,
    |f: &mut HistoryFixture| {
        f.shared.target_max = 8192;
        f.slots = 8193;
    },
    StageError::NotRepresentable(Field::ReplacementSlots)
);
local_negative!(
    inventory_e2h_unrepresentable_copy_length,
    |f: &mut HistoryFixture| {
        f.shared.target_max = 8192;
        f.length = 8193;
    },
    StageError::NotRepresentable(Field::CopyLength)
);
local_negative!(
    inventory_e2h_unrepresentable_copy_capacity,
    |f: &mut HistoryFixture| {
        f.shared.target_max = 8192;
        f.capacity = 8193;
    },
    StageError::NotRepresentable(Field::CopyCapacity)
);
local_negative!(
    inventory_e2h_unrepresentable_crypto_length,
    |f: &mut HistoryFixture| {
        f.shared.target_max = 8192;
        f.crypto[0].length = 8193;
    },
    StageError::NotRepresentable(Field::CryptoLength)
);
local_negative!(
    inventory_e2h_unrepresentable_crypto_prepared_slots,
    |f: &mut HistoryFixture| {
        f.shared.target_max = 8192;
        f.crypto[0].prepared_slots = 8193;
    },
    StageError::NotRepresentable(Field::CryptoPreparedSlots)
);

fn physical_fixture() -> HistoryFixture {
    let mut f = HistoryFixture::valid();
    let wrapper = metadata_owned_bytes::staged_owner_layout();
    let layouts = [
        (
            Role::HistoryReplacement,
            3,
            std::mem::size_of::<RangeRecord>(),
            std::mem::align_of::<RangeRecord>(),
        ),
        (Role::StreamCompactionCopy, 8, 1, 1),
        (Role::CryptoPayload, 6, 1, 1),
        (Role::CryptoWrapper, 1, wrapper.size(), wrapper.align()),
        (Role::CryptoHeap, 2, std::mem::size_of::<Buffer>(), std::mem::align_of::<Buffer>()),
        (Role::CryptoHeap, 2, std::mem::size_of::<Buffer>(), std::mem::align_of::<Buffer>()),
        (Role::CryptoHeap, 2, std::mem::size_of::<Buffer>(), std::mem::align_of::<Buffer>()),
        (
            Role::HistoryPlan,
            3,
            std::mem::size_of::<RangeRecord>(),
            std::mem::align_of::<RangeRecord>(),
        ),
    ];
    f.shared.rows.clear();
    f.shared.observations.clear();
    f.shared.owners.clear();
    f.shared.expected.clear();
    let mut charge = 0;
    for (i, (role, count, size, align)) in layouts.into_iter().enumerate() {
        let cap = count * size;
        let q = ((cap + 63) & !63) + 64;
        charge += q;
        let allocation = AllocationId(10 + i as u64);
        f.shared.rows.push(AllocationRow {
            allocation,
            role: role as u8,
            domain_tag: 0,
            class_tag: role.assignment().1 as u8,
            capacity: cap as u64,
            count: count as u64,
            element_size: size as u64,
            alignment: align as u64,
            charge: q as u64,
        });
        f.shared.observations.push(AllocationObservation {
            allocation,
            capacity: cap as u64,
            element_size: size as u64,
            alignment: align as u64,
        });
        let owner = OwnerRecord {
            owner: OwnerId(20 + i as u64),
            allocation,
            lease: LeaseId(30 + i as u64),
            location_tag: 1,
            references: 1,
            free: None,
            release_requested: false,
        };
        f.shared.owners.push(owner);
        f.shared.expected.push(owner);
    }
    f.shared.row_count = 8;
    f.shared.owner_count = 8;
    f.shared.batch_charge = charge as u64;
    f.shared.expected_charge = charge as u64;
    f.shared.reserved_charge = charge as u64;
    f.shared.ledgers.metadata_used = 0;
    for i in 0..3 {
        f.crypto[i].owner = OwnerId(24 + i as u64);
        f.actual[i].owner = f.crypto[i].owner;
    }
    f
}
fn credit(f: &HistoryFixture) -> Arc<StageCredit> {
    StageCredit::new(
        MetadataCredit::new(f.shared.ledgers.metadata_limit as usize),
        f.shared.ledgers,
    )
}
#[test]
fn inventory_e2h_valid_contract_accepts_once() {
    let f = HistoryFixture::valid();
    assert!(f.violations().is_empty());
    assert_eq!(validate_e2h(&f.request(), &f.context()), Ok(ValidatedHistory));
}
#[test]
fn inventory_e2h_exact_capacity_accepts() {
    let mut f = HistoryFixture::valid();
    f.slots = 2;
    f.actual_slots = 2;
    f.capacity = f.length;
    f.required = [2; 3];
    assert!(f.violations().is_empty());
    assert_eq!(validate_e2h(&f.request(), &f.context()), Ok(ValidatedHistory));
}
#[test]
fn inventory_e2h_zero_raw_debit_preserves_base() {
    let f = physical_fixture();
    let credit = credit(&f);
    let before = credit.snapshot();
    let stage = prepare_history::<8>(&f.request(), &f.context(), &credit, None, &PAYLOAD).unwrap();
    let after = credit.snapshot();
    assert_eq!(after.raw_used, before.raw_used);
    assert_eq!(after.raw_limit, before.raw_limit);
    assert_eq!(after.slice_used - before.slice_used, f.shared.batch_charge);
    drop(stage);
    assert_eq!(credit.snapshot().slice_used, before.slice_used);
}
#[test]
fn inventory_e2h_allocator_refuses_after_reservation() {
    let f = physical_fixture();
    let credit = credit(&f);
    let before = credit.snapshot();
    REFUSE.with(|g| g.set(Some(4)));
    let error = prepare_history::<8>(&f.request(), &f.context(), &credit, None, &PAYLOAD).err();
    REFUSE.with(|g| g.set(None));
    assert_eq!(
        error,
        Some(StageError::Resource(ResourceExhausted { class: MetadataClass::CryptoAssemblers }))
    );
    assert_eq!(credit.snapshot().slice_used, before.slice_used);
}
#[test]
fn history_split_and_compaction_prepare_without_delivery() {
    let mut f = physical_fixture();
    let credit = credit(&f);
    let before = credit.snapshot();
    let mut old_f = physical_fixture();
    old_f.ranges = vec![RangeRecord { start: 0, end: 9 }];
    old_f.expected = old_f.ranges.clone();
    old_f.range_count = 1;
    for row in &mut old_f.shared.rows {
        row.allocation.0 += 100;
    }
    for observation in &mut old_f.shared.observations {
        observation.allocation.0 += 100;
    }
    for owner in &mut old_f.shared.owners {
        owner.owner.0 += 100;
        owner.allocation.0 += 100;
        owner.lease.0 += 100;
    }
    old_f.shared.expected = old_f.shared.owners.clone();
    for record in &mut old_f.crypto {
        record.owner.0 += 100;
    }
    old_f.actual.copy_from_slice(&old_f.crypto);
    let mut semantic = crate::range_set::RangeSet::new();
    semantic.insert(0..9);
    semantic.remove(3..6);
    assert_eq!(
        semantic.iter().map(|r| RangeRecord { start: r.start, end: r.end }).collect::<Vec<_>>(),
        f.expected
    );
    let mut live = crate::connection::assembler::Assembler::new();
    live.insert(0, Bytes::from_static(b"live"), 4).unwrap();
    let old =
        prepare_history::<8>(&old_f.request(), &old_f.context(), &credit, None, &PAYLOAD).unwrap();
    let old_ptr = old.ranges.as_ptr();
    let old_payload = old.payload.as_ptr();
    let old_charge = credit.snapshot().metadata_used;
    for mut owner in old_f.shared.owners.iter().copied() {
        owner.location_tag = 0;
        f.shared.registry.push(owner);
        f.shared.owners.push(owner);
        f.shared.expected.push(owner);
    }
    f.shared.owner_count = f.shared.owners.len() as u64;
    f.shared.ledgers = credit.snapshot();
    let stage =
        prepare_history::<8>(&f.request(), &f.context(), &credit, Some(&old), &PAYLOAD).unwrap();
    assert_eq!(stage.ranges, f.expected);
    assert_eq!(stage.ranges.capacity(), 3);
    assert_ne!(stage.ranges.as_ptr(), old_ptr);
    assert_eq!(old.ranges.as_ptr(), old_ptr);
    assert_eq!(old.payload.as_ptr(), old_payload);
    assert_eq!(stage.copy, f.expected_copy);
    assert_eq!(stage.copy.capacity(), 8);
    assert_eq!(stage.payload.as_ref(), &PAYLOAD);
    assert_eq!(stage.plans[7].as_ref().unwrap().capacity(), 3);
    for (i, heap) in stage.crypto.iter().enumerate() {
        assert_eq!(heap.capacity(), 2);
        assert_eq!(heap.len(), 2);
        let expected = &b"123456"[i * 2..i * 2 + 2];
        for buffer in heap {
            assert_eq!(buffer.bytes.as_ref(), expected);
        }
    }
    assert_eq!(credit.snapshot().metadata_used, old_charge * 2);
    drop(stage);
    assert_eq!(credit.snapshot().metadata_used, old_charge);
    REFUSE.with(|g| g.set(Some(0)));
    let error =
        prepare_history::<8>(&f.request(), &f.context(), &credit, Some(&old), &PAYLOAD).err();
    REFUSE.with(|g| g.set(None));
    assert_eq!(
        error,
        Some(StageError::Resource(ResourceExhausted { class: MetadataClass::UnorderedHistory }))
    );
    assert_eq!(old.ranges, old_f.expected);
    assert_eq!(old.ranges.as_ptr(), old_ptr);
    assert_eq!(credit.snapshot().metadata_used, old_charge);
    assert_eq!(live.read(usize::MAX, true).unwrap().bytes.as_ref(), b"live");
    assert!(live.read(usize::MAX, true).is_none());
    drop(old);
    assert_eq!(credit.snapshot().slice_used, before.slice_used);
}

#[test]
fn empty_history_and_three_empty_crypto_spaces_need_no_fresh_allocation() {
    let mut f = Fixture::valid();
    f.prepare();
    f.rows.clear();
    f.observations.clear();
    f.owners.clear();
    f.expected.clear();
    f.row_count = 0;
    f.owner_count = 0;
    f.batch_charge = 0;
    f.expected_charge = 0;
    f.reserved_charge = 0;
    f.ledgers.metadata_used = 0;
    let credit =
        StageCredit::new(MetadataCredit::new(f.ledgers.metadata_limit as usize), f.ledgers);
    let before = credit.snapshot();
    let stage = prepare_history::<0>(
        &empty_request(f.request()),
        &empty_context(f.context()),
        &credit,
        None,
        &EMPTY_PAYLOAD,
    )
    .unwrap();
    assert_eq!(stage.ranges.capacity(), 0);
    assert_eq!(stage.copy.capacity(), 0);
    assert!(stage.crypto.iter().all(|h| h.capacity() == 0));
    assert_eq!(credit.snapshot(), before);
    drop(stage);
    assert_eq!(credit.snapshot(), before);
}

#[test]
fn retained_shared_payload_is_not_copied_or_charged_again() {
    let source_f = physical_fixture();
    let credit = credit(&source_f);
    let source =
        prepare_history::<8>(&source_f.request(), &source_f.context(), &credit, None, &PAYLOAD)
            .unwrap();
    let mut f = physical_fixture();
    // Fresh history/heaps get new registry identities; the original payload family
    // remains retained through O, irrespective of which first frame selected it.
    for row in &mut f.shared.rows {
        row.allocation.0 += 100;
    }
    for observation in &mut f.shared.observations {
        observation.allocation.0 += 100;
    }
    for owner in &mut f.shared.owners {
        owner.owner.0 += 100;
        owner.allocation.0 += 100;
        owner.lease.0 += 100;
    }
    f.shared.rows.drain(2..4);
    f.shared.observations.drain(2..4);
    f.shared.owners.drain(2..4);
    for mut owner in source_f.shared.owners[2..4].iter().copied() {
        owner.location_tag = 0;
        f.shared.registry.push(owner);
        f.shared.owners.push(owner);
    }
    f.shared.expected = f.shared.owners.clone();
    f.shared.row_count = 6;
    f.shared.owner_count = 8;
    f.shared.batch_charge = f.shared.rows.iter().map(|r| r.charge).sum();
    f.shared.expected_charge = f.shared.batch_charge;
    f.shared.reserved_charge = f.shared.batch_charge;
    f.shared.ledgers = credit.snapshot();
    for i in 0..3 {
        f.crypto[i].owner.0 += 100;
        f.actual[i].owner = f.crypto[i].owner;
    }
    let before = credit.snapshot();
    let stage =
        prepare_history::<6>(&f.request(), &f.context(), &credit, None, &source.payload).unwrap();
    assert_eq!(stage.payload.as_ptr(), source.payload.as_ptr());
    assert_eq!(credit.snapshot().metadata_used - before.metadata_used, f.shared.batch_charge);
    drop(stage);
    assert_eq!(credit.snapshot(), before);
    drop(source);
}
