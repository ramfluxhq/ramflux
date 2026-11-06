// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent E2 contracts and actual typed-storage witnesses.
use super::super::tests::{completed_free, Fixture};
use super::*;
use std::sync::atomic::Ordering;
thread_local! { static REFUSE: std::cell::Cell<Option<usize>> = const {std::cell::Cell::new(None)}; }
pub(super) fn refuse_stream(slot: usize) -> bool {
    REFUSE.with(|gate| gate.get() == Some(slot))
}
fn empty_context<'a>(shared: Context<'a>) -> ReceiveContext<'a> {
    ReceiveContext {
        shared,
        scan: &[],
        physical: &[],
        backing: AllocationId(90),
        backing_capacity: 64,
        payload_class: MetadataClass::StreamAssemblers,
    }
}
macro_rules! negative {
    ($name:ident,$setup:expr,$error:expr) => {
        #[test]
        fn $name() {
            let mut f = Fixture::valid();
            f.prepare();
            ($setup)(&mut f);
            assert_eq!(f.violations_with_debit(true), vec![$error], "one independent shared-rule failure");
            let before = format!("{:?}{:?}", f.owners, f.ledgers);
            let session = tls_contract::tests::CountingSession::default();
            let result = validate_e2(
                &ReceiveRequest { shared: f.request(), frames: &[], frame_count: 0 },
                &empty_context(f.context()),
            );
            assert_eq!(result, Err($error));
            assert_eq!(session.calls.load(Ordering::SeqCst), 0);
            assert_eq!(format!("{:?}{:?}", f.owners, f.ledgers), before);
        }
    };
}
negative!(
    inventory_e2_missing_binding,
    |f: &mut Fixture| {
        f.binding = None;
    },
    StageError::MissingBinding
);
negative!(
    inventory_e2_empty_binding_connection,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().connection = ConnectionId(0);
    },
    StageError::EmptyBinding(Field::Connection)
);
negative!(
    inventory_e2_wrong_binding_connection,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().connection = ConnectionId(99);
    },
    StageError::BindingMismatch(Field::Connection)
);
negative!(
    inventory_e2_empty_binding_credit,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().credit = CreditId(0);
    },
    StageError::EmptyBinding(Field::Credit)
);
negative!(
    inventory_e2_wrong_binding_credit,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().credit = CreditId(99);
    },
    StageError::BindingMismatch(Field::Credit)
);
negative!(
    inventory_e2_empty_binding_configuration,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().configuration = ConfigurationId(0);
    },
    StageError::EmptyBinding(Field::Configuration)
);
negative!(
    inventory_e2_wrong_binding_configuration,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().configuration = ConfigurationId(99);
    },
    StageError::BindingMismatch(Field::Configuration)
);
negative!(
    inventory_e2_empty_binding_layout,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().layout = LayoutId(0);
    },
    StageError::EmptyBinding(Field::Layout)
);
negative!(
    inventory_e2_wrong_binding_layout,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().layout = LayoutId(99);
    },
    StageError::BindingMismatch(Field::Layout)
);
negative!(
    inventory_e2_unknown_space,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().space_tag = 9;
    },
    StageError::InvalidSpace(9)
);
negative!(
    inventory_e2_wrong_space,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().space_tag = 2;
    },
    StageError::SpaceMismatch
);
negative!(
    inventory_e2_pn_out_of_range,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().pn = 1 << 62;
    },
    StageError::PacketNumberOutOfRange
);
negative!(
    inventory_e2_wrong_pn,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().pn = 18;
    },
    StageError::PacketNumberMismatch
);
negative!(
    inventory_e2_stale_generation,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().generation = 4;
    },
    StageError::GenerationMismatch
);
negative!(
    inventory_e2_wrong_stage,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().stage_id = 99;
    },
    StageError::StageMismatch
);
negative!(
    inventory_e2_unknown_phase,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().phase_tag = 9;
    },
    StageError::InvalidPhase(9)
);
negative!(
    inventory_e2_wrong_phase,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().phase_tag = 1;
    },
    StageError::PhaseMismatch
);
negative!(
    inventory_e2_terminal_binding,
    |f: &mut Fixture| {
        f.terminal = true;
    },
    StageError::TerminalFenced
);
negative!(
    inventory_e2_missing_batch,
    |f: &mut Fixture| {
        f.batch_present = false;
    },
    StageError::MissingBatch
);
negative!(
    inventory_e2_wrong_row_count,
    |f: &mut Fixture| {
        f.row_count = 2;
    },
    StageError::CountMismatch(Count::Rows)
);
negative!(
    inventory_e2_empty_allocation_id,
    |f: &mut Fixture| {
        f.rows[0].allocation = AllocationId(0);
    },
    StageError::EmptyAllocationId(0)
);
negative!(
    inventory_e2_duplicate_allocation_id,
    |f: &mut Fixture| {
        f.second();
        f.rows[1].allocation = AllocationId(10);
    },
    StageError::DuplicateAllocation(1)
);
negative!(
    inventory_e2_already_live_allocation_id,
    |f: &mut Fixture| {
        f.registry.push(f.owners[0]);
    },
    StageError::AllocationAlreadyLive(0)
);
negative!(
    inventory_e2_unknown_allocation_role,
    |f: &mut Fixture| {
        f.rows[0].role = 255;
    },
    StageError::InvalidRole(0)
);
negative!(
    inventory_e2_foreign_allocation_role,
    |f: &mut Fixture| {
        f.rows[0].role = Role::TerminalOwner as u8;
    },
    StageError::RoleNotAllowed(0)
);
negative!(
    inventory_e2_unknown_domain,
    |f: &mut Fixture| {
        f.rows[0].domain_tag = 9;
    },
    StageError::InvalidDomain(0, 9)
);
negative!(
    inventory_e2_unknown_class,
    |f: &mut Fixture| {
        f.rows[0].class_tag = 12;
    },
    StageError::InvalidClass(0, 12)
);
negative!(
    inventory_e2_wrong_role_domain,
    |f: &mut Fixture| {
        f.rows[0].domain_tag = 1;
    },
    StageError::RoleDomainMismatch(0)
);
negative!(
    inventory_e2_wrong_role_class,
    |f: &mut Fixture| {
        f.rows[0].class_tag = 6;
    },
    StageError::RoleClassMismatch(0)
);
negative!(
    inventory_e2_wrong_element_size,
    |f: &mut Fixture| {
        f.rows[0].element_size = 4;
    },
    StageError::LayoutMismatch(0, Field::ElementSize)
);
negative!(
    inventory_e2_wrong_alignment,
    |f: &mut Fixture| {
        f.rows[0].alignment = 4;
    },
    StageError::LayoutMismatch(0, Field::Alignment)
);
negative!(
    inventory_e2_allocation_product_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(u64::MAX - 127, 1 << 63, 2);
    },
    StageError::ArithmeticOverflow(Arithmetic::AllocationProduct(0))
);
negative!(
    inventory_e2_allocation_capacity_too_small,
    |f: &mut Fixture| {
        f.rows[0].count = 9;
    },
    StageError::CapacityInsufficient(0)
);
negative!(
    inventory_e2_false_observed_capacity,
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
    inventory_e2_allocation_charge_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(u64::MAX, 1, 1);
    },
    StageError::ArithmeticOverflow(Arithmetic::AllocationCharge(0))
);
negative!(
    inventory_e2_wrong_allocation_charge,
    |f: &mut Fixture| {
        f.rows[0].charge = 192;
        f.batch_charge = 192;
        f.expected_charge = 192;
        f.reserved_charge = 192;
    },
    StageError::ChargeMismatch(0)
);
negative!(
    inventory_e2_metadata_sum_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(1 << 63, 8, 8);
        f.second();
    },
    StageError::ArithmeticOverflow(Arithmetic::MetadataSum)
);
negative!(
    inventory_e2_wrong_batch_charge,
    |f: &mut Fixture| {
        f.batch_charge = 192;
        f.expected_charge = 192;
        f.reserved_charge = 192;
    },
    StageError::BatchChargeMismatch(Domain::Metadata)
);
negative!(
    inventory_e2_wrong_raw_charge,
    |f: &mut Fixture| {
        f.raw_charge = 64;
    },
    StageError::BatchChargeMismatch(Domain::RawBase)
);
negative!(
    inventory_e2_metadata_overlap_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.ledgers.metadata_used = u64::MAX - 63;
    },
    StageError::ArithmeticOverflow(Arithmetic::MetadataOverlap)
);
negative!(
    inventory_e2_slice_overlap_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.ledgers.slice_used = u64::MAX - 63;
    },
    StageError::ArithmeticOverflow(Arithmetic::SliceOverlap)
);
negative!(
    inventory_e2_overlap_exceeds_metadata,
    |f: &mut Fixture| {
        f.ledgers.metadata_limit = 192;
    },
    StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })
);
negative!(
    inventory_e2_overlap_exceeds_slice,
    |f: &mut Fixture| {
        f.ledgers.slice_limit = 4160;
    },
    StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })
);
negative!(
    inventory_e2_missing_owners,
    |f: &mut Fixture| {
        f.prepare();
        f.owners_present = false;
    },
    StageError::MissingOwners
);
negative!(
    inventory_e2_wrong_owner_count,
    |f: &mut Fixture| {
        f.prepare();
        f.owner_count = 2;
    },
    StageError::CountMismatch(Count::Owners)
);
negative!(
    inventory_e2_duplicate_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].owner = OwnerId(20);
    },
    StageError::DuplicateOwner(1)
);
negative!(
    inventory_e2_unknown_owner_allocation,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].allocation = AllocationId(99);
    },
    StageError::UnknownAllocation(0)
);
negative!(
    inventory_e2_wrong_owner_lease,
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
    inventory_e2_double_charged_backing,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].allocation = AllocationId(10);
    },
    StageError::DuplicateBackingCharge(1)
);
negative!(
    inventory_e2_aliased_distinct_allocations,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].lease = LeaseId(30);
    },
    StageError::LeaseAliased(1)
);
negative!(
    inventory_e2_unknown_owner_location,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].location_tag = 9;
    },
    StageError::InvalidOwnerLocation(0, 9)
);
negative!(
    inventory_e2_wrong_owner_location,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].location_tag = 0;
    },
    StageError::OwnerLocationMismatch(0)
);
negative!(
    inventory_e2_wrong_owner_references,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 2;
    },
    StageError::ReferenceCountMismatch(0)
);
negative!(
    inventory_e2_missing_physical_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.owners.clear();
        f.owner_count = 0;
    },
    StageError::OwnerMissing(OwnerId(20))
);
negative!(
    inventory_e2_extra_physical_owner,
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
    inventory_e2_refund_before_free,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].release_requested = true;
    },
    StageError::FreeNotCompleted(0)
);
negative!(
    inventory_e2_foreign_free_witness,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].free = Some(completed_free(AllocationId(99), LeaseId(99), false));
    },
    StageError::FreeWitnessMismatch(0)
);
negative!(
    inventory_e2_reused_free_witness,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].free = Some(completed_free(AllocationId(10), LeaseId(30), true));
    },
    StageError::FreeWitnessConsumed(0)
);
negative!(
    inventory_e2_unrepresentable_capacity,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].capacity = 8193;
    },
    StageError::NotRepresentable(Field::Capacity)
);
negative!(
    inventory_e2_unrepresentable_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].count = 8193;
    },
    StageError::NotRepresentable(Field::Count)
);
negative!(
    inventory_e2_unrepresentable_element_size,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].element_size = 8193;
    },
    StageError::NotRepresentable(Field::ElementSize)
);
negative!(
    inventory_e2_unrepresentable_alignment,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].alignment = 8193;
    },
    StageError::NotRepresentable(Field::Alignment)
);
negative!(
    inventory_e2_unrepresentable_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].charge = 8193;
    },
    StageError::NotRepresentable(Field::Charge)
);
negative!(
    inventory_e2_unrepresentable_row_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.row_count = 8193;
    },
    StageError::NotRepresentable(Field::RowCount)
);
negative!(
    inventory_e2_unrepresentable_batch_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.batch_charge = 8193;
    },
    StageError::NotRepresentable(Field::BatchCharge)
);
negative!(
    inventory_e2_unrepresentable_raw_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.raw_charge = 8193;
    },
    StageError::NotRepresentable(Field::RawCharge)
);
negative!(
    inventory_e2_unrepresentable_metadata_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.metadata_limit = 8193;
    },
    StageError::NotRepresentable(Field::MetadataLimit)
);
negative!(
    inventory_e2_unrepresentable_metadata_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.metadata_used = 8193;
    },
    StageError::NotRepresentable(Field::MetadataUsed)
);
negative!(
    inventory_e2_unrepresentable_slice_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.slice_limit = 8193;
    },
    StageError::NotRepresentable(Field::SliceLimit)
);
negative!(
    inventory_e2_unrepresentable_slice_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.slice_used = 8193;
    },
    StageError::NotRepresentable(Field::SliceUsed)
);
negative!(
    inventory_e2_unrepresentable_raw_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.raw_limit = 8193;
    },
    StageError::NotRepresentable(Field::RawLimit)
);
negative!(
    inventory_e2_unrepresentable_raw_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.raw_used = 8193;
    },
    StageError::NotRepresentable(Field::RawUsed)
);
negative!(
    inventory_e2_unrepresentable_owner_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.prepare();
        f.owner_count = 8193;
    },
    StageError::NotRepresentable(Field::OwnerCount)
);
negative!(
    inventory_e2_invalid_used_metadata,
    |f: &mut Fixture| {
        f.ledgers.metadata_used = f.ledgers.metadata_limit + 1;
    },
    StageError::InvalidLedger(Domain::Metadata)
);
negative!(
    inventory_e2_invalid_used_slice,
    |f: &mut Fixture| {
        f.ledgers.slice_used = f.ledgers.slice_limit + 1;
    },
    StageError::InvalidLedger(Domain::Slice)
);
negative!(
    inventory_e2_invalid_used_raw,
    |f: &mut Fixture| {
        f.ledgers.raw_used = f.ledgers.raw_limit + 1;
    },
    StageError::InvalidLedger(Domain::RawBase)
);
negative!(
    inventory_e2_empty_owner_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].owner = OwnerId(0);
    },
    StageError::EmptyOwnerField(Field::Owner, 0)
);
negative!(
    inventory_e2_empty_owner_allocation,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].allocation = AllocationId(0);
    },
    StageError::EmptyOwnerField(Field::Allocation, 0)
);
negative!(
    inventory_e2_empty_owner_lease,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].lease = LeaseId(0);
    },
    StageError::EmptyOwnerField(Field::Lease, 0)
);
struct ReceiveFixture {
    shared: Fixture,
    frames: Vec<ReceiveRecord>,
    scan: Vec<ReceiveRecord>,
    physical: Vec<ReceiveRecord>,
    frame_count: u64,
    backing_capacity: u64,
    payload_class: MetadataClass,
}
impl ReceiveFixture {
    fn valid() -> Self {
        let wrapper = metadata_owned_bytes::staged_owner_layout();
        let layouts = [
            (Role::StreamPayload, 6, 6, 1, 1),
            (Role::StreamWrapper, wrapper.size(), 1, wrapper.size(), wrapper.align()),
            (
                Role::StreamHeap,
                std::mem::size_of::<Buffer>(),
                1,
                std::mem::size_of::<Buffer>(),
                std::mem::align_of::<Buffer>(),
            ),
            (
                Role::StreamHeap,
                std::mem::size_of::<Buffer>(),
                1,
                std::mem::size_of::<Buffer>(),
                std::mem::align_of::<Buffer>(),
            ),
        ];
        let mut shared = Fixture::valid();
        shared.prepare();
        shared.rows.clear();
        shared.observations.clear();
        shared.owners.clear();
        shared.expected.clear();
        shared.batch_charge = 0;
        for (i, (role, capacity, count, size, alignment)) in layouts.into_iter().enumerate() {
            let id = AllocationId(10 + i as u64);
            let charge = (((capacity as u128 + 63) & !63) + 64) as u64;
            shared.rows.push(AllocationRow {
                allocation: id,
                role: role as u8,
                domain_tag: 0,
                class_tag: 5,
                capacity: capacity as u64,
                count: count as u64,
                element_size: size as u64,
                alignment: alignment as u64,
                charge,
            });
            shared.observations.push(AllocationObservation {
                allocation: id,
                capacity: capacity as u64,
                element_size: size as u64,
                alignment: alignment as u64,
            });
            shared.owners.push(OwnerRecord {
                owner: OwnerId(20 + i as u64),
                allocation: id,
                lease: LeaseId(30 + i as u64),
                location_tag: 1,
                references: 1,
                free: None,
                release_requested: false,
            });
            shared.batch_charge += charge;
        }
        let raw = OwnerRecord {
            owner: OwnerId(90),
            allocation: AllocationId(90),
            lease: LeaseId(90),
            location_tag: 0,
            references: 1,
            free: None,
            release_requested: false,
        };
        shared.registry.push(raw);
        shared.owners.push(raw);
        shared.expected = shared.owners.clone();
        shared.owner_count = 5;
        shared.row_count = 4;
        shared.expected_charge = shared.batch_charge;
        shared.reserved_charge = shared.batch_charge;
        let frames = vec![
            ReceiveRecord {
                stream_id: 2,
                offset: 0,
                length: 3,
                backing: AllocationId(90),
                view_start: 0,
                view_end: 3,
                descriptor_count: 1,
                prepared_slots: 1,
                stream_owner: OwnerId(22),
            },
            ReceiveRecord {
                stream_id: 6,
                offset: 0,
                length: 3,
                backing: AllocationId(90),
                view_start: 3,
                view_end: 6,
                descriptor_count: 1,
                prepared_slots: 1,
                stream_owner: OwnerId(23),
            },
        ];
        Self {
            shared,
            scan: frames.clone(),
            physical: frames.clone(),
            frames,
            frame_count: 2,
            backing_capacity: 6,
            payload_class: MetadataClass::StreamAssemblers,
        }
    }
    fn request(&self) -> ReceiveRequest<'_> {
        ReceiveRequest {
            shared: self.shared.request(),
            frames: &self.frames,
            frame_count: self.frame_count,
        }
    }
    fn context(&self) -> ReceiveContext<'_> {
        ReceiveContext {
            shared: self.shared.context(),
            scan: &self.scan,
            physical: &self.physical,
            backing: AllocationId(90),
            backing_capacity: self.backing_capacity,
            payload_class: self.payload_class,
        }
    }
    // Wide reference equations and independent scan/storage comparisons. Structural
    // children are evaluated only when the corresponding parent arithmetic exists.
    fn violations(&self) -> Vec<StageError> {
        use StageError::*;
        let mut errors = self.shared.violations_with_debit(true);
        if !errors.is_empty() {
            return errors;
        }
        if self.frame_count > self.shared.target_max {
            return vec![NotRepresentable(Field::FrameCount)];
        }
        if self.frame_count as u128 != self.frames.len() as u128 {
            return vec![CountMismatch(Count::ReceiveFrames)];
        }
        if self.payload_class != MetadataClass::StreamAssemblers {
            return vec![SharedPayloadFamilyMismatch];
        }
        for (i, f) in self.frames.iter().enumerate() {
            let start_errors = errors.len();
            for (field, value) in [
                (Field::Length, f.length),
                (Field::ViewStart, f.view_start),
                (Field::ViewEnd, f.view_end),
                (Field::DescriptorCount, f.descriptor_count),
                (Field::PreparedSlots, f.prepared_slots),
            ] {
                if value > self.shared.target_max {
                    errors.push(NotRepresentable(field));
                }
            }
            if errors.len() != start_errors {
                continue;
            }
            if f.stream_id >= 1 << 62 {
                errors.push(StreamIdOutOfRange);
                continue;
            }
            let end = u128::from(f.offset) + u128::from(f.length);
            if end > u128::from(u64::MAX) {
                errors.push(ArithmeticOverflow(Arithmetic::StreamEnd(i)));
                continue;
            }
            if end >= 1 << 62 {
                errors.push(StreamEndOutOfRange(i));
                continue;
            }
            let expected = &self.scan[i];
            for (field, a, b) in [
                (Field::StreamId, f.stream_id, expected.stream_id),
                (Field::Offset, f.offset, expected.offset),
                (Field::Length, f.length, expected.length),
            ] {
                if a != b {
                    errors.push(FrameMismatch(field, i));
                }
            }
            if f.stream_id != expected.stream_id {
                continue;
            }
            if f.backing != AllocationId(90) {
                errors.push(ReceiveBackingMismatch(i));
            }
            if f.view_start > f.view_end {
                errors.push(InvalidViewOrder(i));
            } else if f.view_end > self.backing_capacity {
                errors.push(ViewOutOfBounds(i));
            } else if u128::from(f.view_end) - u128::from(f.view_start) != u128::from(f.length) {
                errors.push(ViewLengthMismatch(i));
            }
            if f.descriptor_count != expected.descriptor_count {
                errors.push(DescriptorCountMismatch(i));
            }
            if f.prepared_slots < f.descriptor_count {
                errors.push(ReceiveSlotsInsufficient(i));
            } else if let Some(actual) = self.physical.iter().find(|p| p.stream_id == f.stream_id) {
                if f.prepared_slots != actual.prepared_slots {
                    errors.push(ReceiveSlotObservationMismatch(i));
                }
                if f.stream_owner != actual.stream_owner {
                    errors.push(StreamOwnerMismatch(i));
                }
            } else {
                errors.push(StreamPreparationMissing(f.stream_id));
            }
        }
        if errors.is_empty() {
            for f in &self.scan {
                if !self.frames.iter().any(|p| p.stream_id == f.stream_id) {
                    errors.push(StreamPreparationMissing(f.stream_id));
                }
            }
        }
        errors
    }
    fn reject(&self, error: StageError) {
        assert_eq!(self.violations(), vec![error], "one independent local rule");
        let before = format!("{:?}{:?}", self.shared.owners, self.shared.ledgers);
        let session = tls_contract::tests::CountingSession::default();
        assert_eq!(validate_e2(&self.request(), &self.context()), Err(error));
        assert_eq!(session.calls.load(Ordering::SeqCst), 0);
        assert_eq!(format!("{:?}{:?}", self.shared.owners, self.shared.ledgers), before);
    }
    fn credit(&self) -> Arc<StageCredit> {
        StageCredit::new(
            MetadataCredit::new(self.shared.ledgers.metadata_limit as usize),
            Ledgers { metadata_used: 0, ..self.shared.ledgers },
        )
    }
}
macro_rules! receive_negative {
    ($name:ident,$setup:expr,$error:expr) => {
        #[test]
        fn $name() {
            let mut f = ReceiveFixture::valid();
            ($setup)(&mut f);
            f.reject($error);
        }
    };
}
receive_negative!(
    inventory_e2_wrong_frame_count,
    |f: &mut ReceiveFixture| f.frame_count = 1,
    StageError::CountMismatch(Count::ReceiveFrames)
);
receive_negative!(
    inventory_e2_stream_id_out_of_range,
    |f: &mut ReceiveFixture| f.frames[0].stream_id = 1 << 62,
    StageError::StreamIdOutOfRange
);
receive_negative!(
    inventory_e2_wrong_frame_stream_id,
    |f: &mut ReceiveFixture| f.frames[0].stream_id = 10,
    StageError::FrameMismatch(Field::StreamId, 0)
);
receive_negative!(
    inventory_e2_wrong_frame_offset,
    |f: &mut ReceiveFixture| f.frames[0].offset = 1,
    StageError::FrameMismatch(Field::Offset, 0)
);
receive_negative!(
    inventory_e2_wrong_frame_length,
    |f: &mut ReceiveFixture| {
        f.frames[0].length = 2;
        f.frames[0].view_end = 2;
    },
    StageError::FrameMismatch(Field::Length, 0)
);
receive_negative!(
    inventory_e2_stream_end_overflow,
    |f: &mut ReceiveFixture| {
        f.frames[0].offset = u64::MAX;
        f.scan[0].offset = u64::MAX;
    },
    StageError::ArithmeticOverflow(Arithmetic::StreamEnd(0))
);
receive_negative!(
    inventory_e2_stream_end_out_of_range,
    |f: &mut ReceiveFixture| {
        f.frames[0].offset = (1 << 62) - 2;
        f.scan[0].offset = (1 << 62) - 2;
    },
    StageError::StreamEndOutOfRange(0)
);
receive_negative!(
    inventory_e2_wrong_receive_backing,
    |f: &mut ReceiveFixture| f.frames[0].backing = AllocationId(91),
    StageError::ReceiveBackingMismatch(0)
);
receive_negative!(
    inventory_e2_reversed_receive_view,
    |f: &mut ReceiveFixture| f.frames[0].view_start = 4,
    StageError::InvalidViewOrder(0)
);
receive_negative!(
    inventory_e2_receive_view_exceeds_backing,
    |f: &mut ReceiveFixture| {
        f.frames[0].view_start = 4;
        f.frames[0].view_end = 7;
    },
    StageError::ViewOutOfBounds(0)
);
receive_negative!(
    inventory_e2_receive_view_length_mismatch,
    |f: &mut ReceiveFixture| f.frames[0].view_end = 4,
    StageError::ViewLengthMismatch(0)
);
receive_negative!(
    inventory_e2_wrong_descriptor_count,
    |f: &mut ReceiveFixture| {
        f.frames[0].descriptor_count = 0;
    },
    StageError::DescriptorCountMismatch(0)
);
receive_negative!(
    inventory_e2_short_receive_slots,
    |f: &mut ReceiveFixture| {
        f.frames[0].prepared_slots = 0;
        f.physical[0].prepared_slots = 0;
    },
    StageError::ReceiveSlotsInsufficient(0)
);
receive_negative!(
    inventory_e2_false_receive_slots,
    |f: &mut ReceiveFixture| f.frames[0].prepared_slots = 2,
    StageError::ReceiveSlotObservationMismatch(0)
);
receive_negative!(
    inventory_e2_wrong_stream_owner,
    |f: &mut ReceiveFixture| f.frames[0].stream_owner = OwnerId(23),
    StageError::StreamOwnerMismatch(0)
);
receive_negative!(
    inventory_e2_missing_second_stream_preparation,
    |f: &mut ReceiveFixture| {
        f.frames.pop();
        f.frame_count = 1;
    },
    StageError::StreamPreparationMissing(6)
);
#[test]
fn inventory_e2_wrong_shared_payload_family() {
    // CRYPTO(offset=0,len=1,"c"), STREAM(id=2,len=1,"s").
    let mixed = Bytes::from_static(&[6, 0, 1, b'c', 10, 2, 1, b's']);
    let mut f = ReceiveFixture::valid();
    f.payload_class = crate::connection::metadata_backing::payload_class(&mixed).unwrap();
    assert_eq!(f.payload_class, MetadataClass::CryptoAssemblers);
    f.reject(StageError::SharedPayloadFamilyMismatch);
}

receive_negative!(
    inventory_e2_unrepresentable_frame_count,
    |f: &mut ReceiveFixture| {
        f.shared.target_max = 8192;
        f.frame_count = 8193;
    },
    StageError::NotRepresentable(Field::FrameCount)
);

receive_negative!(
    inventory_e2_unrepresentable_length,
    |f: &mut ReceiveFixture| {
        f.shared.target_max = 8192;
        f.frames[0].length = 8193;
    },
    StageError::NotRepresentable(Field::Length)
);

receive_negative!(
    inventory_e2_unrepresentable_view_start,
    |f: &mut ReceiveFixture| {
        f.shared.target_max = 8192;
        f.frames[0].view_start = 8193;
    },
    StageError::NotRepresentable(Field::ViewStart)
);

receive_negative!(
    inventory_e2_unrepresentable_view_end,
    |f: &mut ReceiveFixture| {
        f.shared.target_max = 8192;
        f.frames[0].view_end = 8193;
    },
    StageError::NotRepresentable(Field::ViewEnd)
);

receive_negative!(
    inventory_e2_unrepresentable_descriptor_count,
    |f: &mut ReceiveFixture| {
        f.shared.target_max = 8192;
        f.frames[0].descriptor_count = 8193;
    },
    StageError::NotRepresentable(Field::DescriptorCount)
);

receive_negative!(
    inventory_e2_unrepresentable_prepared_slots,
    |f: &mut ReceiveFixture| {
        f.shared.target_max = 8192;
        f.frames[0].prepared_slots = 8193;
    },
    StageError::NotRepresentable(Field::PreparedSlots)
);

fn assert_physical(stage: &PreparedReceive<'_, 2, 4>) {
    // Expectations come from the input, not the stage plan's own count.
    for (slot, id, owner) in [(0, 2, OwnerId(22)), (1, 6, OwnerId(23))] {
        let stream =
            stage.streams[slot].as_ref().expect("every input stream needs an actual owner");
        assert_eq!(stream.stream_id, id);
        assert_eq!(stream.owner, owner);
        assert_eq!(stream.heap.capacity(), 1);
        assert_eq!(stream.heap.len(), 1);
    }
    assert_ne!(
        stage.streams[0].as_ref().unwrap().heap.as_slice().as_ptr(),
        stage.streams[1].as_ref().unwrap().heap.as_slice().as_ptr()
    );
    assert_eq!(&stage.payload[..], b"abcdef");
}
#[test]
fn two_stream_frames_prepare_without_delivery() {
    let f = ReceiveFixture::valid();
    let credit = f.credit();
    let before = credit.snapshot();
    let live = Bytes::from_static(b"committed-head");
    let pointer = live.as_ptr();
    let mut queue = crate::connection::assembler::Assembler::new();
    queue.insert(0, live.clone(), live.len()).unwrap();
    let queue_before = queue.metadata_storage();
    let stage = prepare_receive::<2, 4>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    )
    .unwrap();
    assert_physical(&stage);
    assert_eq!(queue.metadata_storage(), queue_before);
    let committed = queue.read(usize::MAX, true).unwrap();
    assert_eq!(committed.bytes.as_ptr(), pointer);
    assert_eq!(&committed.bytes[..], b"committed-head");
    assert_eq!(live.as_ptr(), pointer);
    assert_eq!(&live[..], b"committed-head");
    assert_eq!(credit.snapshot().raw_used, before.raw_used);
    assert_eq!(credit.metadata.stats().used as u64, f.shared.batch_charge);
    // Both real heap descriptors reference exactly this one actual payload backing.
    let first = stage.streams[0].as_ref().unwrap().heap.peek().unwrap();
    let second = stage.streams[1].as_ref().unwrap().heap.peek().unwrap();
    assert_eq!(first.bytes.as_ptr(), stage.payload.as_ptr());
    assert_eq!(second.bytes.as_ptr(), stage.payload.as_ptr().wrapping_add(3));
    drop(stage);
    assert_eq!(credit.metadata.stats().used, 0);
}
#[test]
fn receive_preparation_failure_preserves_original_owners() {
    let f = ReceiveFixture::valid();
    let credit = f.credit();
    let live = prepare_receive::<2, 4>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    )
    .unwrap();
    let before = credit.metadata.stats().used;
    let ptr = live.payload.as_ptr();
    REFUSE.with(|gate| gate.set(Some(1)));
    let result = prepare_receive::<2, 4>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    );
    REFUSE.with(|gate| gate.set(None));
    assert!(matches!(
        result,
        Err(StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers }))
    ));
    assert_eq!(credit.metadata.stats().used, before);
    assert_eq!(live.payload.as_ptr(), ptr);
    assert_physical(&live);
    drop(live);
    assert_eq!(credit.metadata.stats().used, 0);
}
#[test]
fn inventory_e2_allocator_refuses_after_reservation() {
    receive_preparation_failure_preserves_original_owners();
}
#[test]
fn inventory_e2_valid_contract_accepts_once() {
    let f = ReceiveFixture::valid();
    assert!(f.violations().is_empty());
    assert!(validate_e2(&f.request(), &f.context()).is_ok());
    two_stream_frames_prepare_without_delivery();
}
#[test]
fn inventory_e2_exact_capacity_accepts() {
    let mut f = ReceiveFixture::valid();
    f.shared.ledgers.metadata_used = 0;
    f.shared.ledgers.metadata_limit = f.shared.batch_charge;
    f.shared.ledgers.slice_limit = f.shared.ledgers.slice_used + f.shared.batch_charge;
    let credit = f.credit();
    let stage = prepare_receive::<2, 4>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    )
    .unwrap();
    assert_physical(&stage);
    assert_eq!(credit.snapshot().metadata_used, f.shared.batch_charge);
}
#[test]
fn inventory_e2_zero_raw_debit_preserves_base() {
    let f = ReceiveFixture::valid();
    let credit = f.credit();
    let before = credit.snapshot();
    let stage = prepare_receive::<2, 4>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    )
    .unwrap();
    assert_eq!(f.shared.raw_charge, 0);
    assert_eq!(credit.snapshot().raw_used, before.raw_used);
    assert_eq!(stage._retained_datagram.as_ptr(), b"abcdef".as_ptr());
    assert_eq!(credit.snapshot().slice_used, before.slice_used + f.shared.batch_charge);
    drop(stage);
    assert_eq!(credit.snapshot(), before);
}

#[test]
fn repeated_stream_frames_share_one_prepared_assembler() {
    let mut f = ReceiveFixture::valid();
    f.frames[1].stream_id = 2;
    f.frames[1].offset = 3;
    f.frames[1].stream_owner = OwnerId(22);
    f.frames[1].descriptor_count = 2;
    for frame in &mut f.frames {
        frame.prepared_slots = 2;
    }
    f.scan = f.frames.clone();
    f.physical = f.frames.clone();
    f.shared.rows.pop();
    f.shared.observations.pop();
    f.shared.owners.remove(3);
    f.shared.expected = f.shared.owners.clone();
    let row = &mut f.shared.rows[2];
    row.count = 2;
    row.capacity *= 2;
    row.charge = (((u128::from(row.capacity) + 63) & !63) + 64) as u64;
    f.shared.observations[2].capacity = row.capacity;
    f.shared.batch_charge = f.shared.rows.iter().map(|row| row.charge).sum();
    f.shared.row_count = 3;
    f.shared.owner_count = 4;
    f.shared.expected_charge = f.shared.batch_charge;
    f.shared.reserved_charge = f.shared.batch_charge;
    let credit = f.credit();
    let stage = prepare_receive::<1, 3>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    )
    .unwrap();
    let stream = stage.streams[0].as_ref().unwrap();
    assert_eq!(stream.stream_id, 2);
    assert_eq!(stream.heap.capacity(), 2);
    assert_eq!(stream.heap.len(), 2);
    drop(stage);
    assert_eq!(credit.metadata.stats().used, 0);
}
#[test]
fn empty_semantic_scan_needs_no_new_allocation() {
    let mut f = ReceiveFixture::valid();
    f.frames.clear();
    f.scan.clear();
    f.physical.clear();
    f.frame_count = 0;
    f.shared.rows.clear();
    f.shared.observations.clear();
    f.shared.row_count = 0;
    f.shared.owners.retain(|owner| owner.owner == OwnerId(90));
    f.shared.expected = f.shared.owners.clone();
    f.shared.owner_count = 1;
    f.shared.batch_charge = 0;
    f.shared.expected_charge = 0;
    f.shared.reserved_charge = 0;
    let credit = f.credit();
    let before = credit.snapshot();
    let stage = prepare_receive::<0, 0>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    )
    .unwrap();
    assert!(stage.payload.is_empty());
    assert_eq!(credit.snapshot(), before);
    assert_eq!(credit.metadata.stats().allocations, 0);
    drop(stage);
    assert_eq!(credit.snapshot(), before);
}

#[test]
fn allocated_receive_plan_has_real_capacity_and_lease() {
    let mut f = ReceiveFixture::valid();
    let size = std::mem::size_of::<ReceiveRecord>();
    let alignment = std::mem::align_of::<ReceiveRecord>();
    let capacity = 2 * size;
    let charge = (((capacity as u128 + 63) & !63) + 64) as u64;
    f.shared.rows.push(AllocationRow {
        allocation: AllocationId(14),
        role: Role::ReceivePlan as u8,
        domain_tag: 0,
        class_tag: 5,
        capacity: capacity as u64,
        count: 2,
        element_size: size as u64,
        alignment: alignment as u64,
        charge,
    });
    f.shared.observations.push(AllocationObservation {
        allocation: AllocationId(14),
        capacity: capacity as u64,
        element_size: size as u64,
        alignment: alignment as u64,
    });
    f.shared.owners.push(OwnerRecord {
        owner: OwnerId(24),
        allocation: AllocationId(14),
        lease: LeaseId(34),
        location_tag: 1,
        references: 1,
        free: None,
        release_requested: false,
    });
    f.shared.expected = f.shared.owners.clone();
    f.shared.row_count = 5;
    f.shared.owner_count = 6;
    f.shared.batch_charge += charge;
    f.shared.expected_charge = f.shared.batch_charge;
    f.shared.reserved_charge = f.shared.batch_charge;
    let credit = f.credit();
    let stage = prepare_receive::<2, 5>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    )
    .unwrap();
    let plan = stage._plans[4].as_ref().unwrap();
    assert_eq!(plan.capacity(), 2);
    assert_eq!(plan.iter().map(|frame| frame.stream_id).collect::<Vec<_>>(), vec![2, 6]);
    assert_eq!(credit.metadata.stats().used as u64, f.shared.batch_charge);
    drop(stage);
    assert_eq!(credit.metadata.stats().used, 0);
}

#[test]
fn replacement_heaps_retain_borrowed_live_owners_and_overlap_credit() {
    let f = ReceiveFixture::valid();
    let credit = f.credit();
    let original = prepare_receive::<2, 4>(
        &f.request(),
        &f.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &[],
    )
    .unwrap();
    let old_used = credit.metadata.stats().used;
    let owners = [original.streams[0].as_ref().unwrap(), original.streams[1].as_ref().unwrap()];
    let mut next = ReceiveFixture::valid();
    for frame in &mut next.frames {
        frame.prepared_slots = 2;
        frame.descriptor_count = 2;
    }
    next.scan = next.frames.clone();
    next.physical = next.frames.clone();
    for i in [2, 3] {
        let row = &mut next.shared.rows[i];
        row.count = 2;
        row.capacity *= 2;
        row.charge = (((u128::from(row.capacity) + 63) & !63) + 64) as u64;
        next.shared.observations[i].capacity = row.capacity;
    }
    next.shared.batch_charge = next.shared.rows.iter().map(|r| r.charge).sum();
    next.shared.expected_charge = next.shared.batch_charge;
    next.shared.reserved_charge = next.shared.batch_charge;
    let replacement = prepare_receive::<2, 4>(
        &next.request(),
        &next.context(),
        &credit,
        Bytes::from_static(b"abcdef"),
        &owners,
    )
    .unwrap();
    for stream in replacement.streams.iter().flatten() {
        assert_eq!(stream.heap.len(), 2);
        assert_eq!(stream.heap.capacity(), 2);
    }
    assert_eq!(credit.metadata.stats().used, old_used + next.shared.batch_charge as usize);
    assert_physical(&original);
    drop(replacement);
    assert_eq!(credit.metadata.stats().used, old_used);
    drop(original);
    assert_eq!(credit.metadata.stats().used, 0);
}
