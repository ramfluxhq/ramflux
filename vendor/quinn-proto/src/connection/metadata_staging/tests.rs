// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent contract fixtures and causal backing-free observations.
use super::*;
use std::sync::{
    Condvar,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

struct Fixture {
    binding: Option<Binding>,
    rows: Vec<AllocationRow>,
    observations: Vec<AllocationObservation>,
    owners: Vec<OwnerRecord>,
    expected: Vec<OwnerRecord>,
    registry: Vec<OwnerRecord>,
    batch_present: bool,
    owners_present: bool,
    row_count: u64,
    owner_count: u64,
    batch_charge: u64,
    raw_charge: u64,
    ledgers: Ledgers,
    target_max: u64,
    action: u8,
    state: u8,
    reservation: Option<ReservationId>,
    target: Option<OwnerId>,
    expected_charge: u64,
    reserved_charge: u64,
    terminal: bool,
    actual_allocated: bool,
}
fn canonical_binding() -> Binding {
    Binding {
        connection: ConnectionId(1),
        credit: CreditId(2),
        configuration: ConfigurationId(3),
        layout: LayoutId(4),
        space_tag: 1,
        pn: 17,
        generation: 5,
        stage_id: 6,
        phase_tag: 0,
    }
}
impl Fixture {
    fn valid() -> Self {
        let rows = vec![AllocationRow {
            allocation: AllocationId(10),
            role: Role::StreamPayload as u8,
            domain_tag: 0,
            class_tag: 5,
            capacity: 64,
            count: 8,
            element_size: 8,
            alignment: 8,
            charge: 128,
        }];
        let owners = vec![OwnerRecord {
            owner: OwnerId(20),
            allocation: AllocationId(10),
            lease: LeaseId(30),
            location_tag: 1,
            references: 1,
            free: None,
            release_requested: false,
        }];
        Self {
            binding: Some(canonical_binding()),
            observations: vec![AllocationObservation {
                allocation: AllocationId(10),
                capacity: 64,
                element_size: 8,
                alignment: 8,
            }],
            rows,
            expected: owners.clone(),
            owners,
            registry: vec![],
            batch_present: true,
            owners_present: true,
            row_count: 1,
            owner_count: 1,
            batch_charge: 128,
            raw_charge: 0,
            ledgers: Ledgers {
                metadata_limit: 4096,
                metadata_used: 128,
                slice_limit: 8192,
                slice_used: 4096,
                raw_limit: 2048,
                raw_used: 0,
            },
            target_max: u64::MAX,
            action: 0,
            state: 0,
            reservation: None,
            target: None,
            expected_charge: 128,
            reserved_charge: 128,
            terminal: false,
            actual_allocated: false,
        }
    }
    fn request(&self) -> Request<'_> {
        Request {
            binding: self.binding,
            batch: self.batch_present.then_some(Batch {
                rows: &self.rows,
                row_count: self.row_count,
                batch_charge: self.batch_charge,
                raw_charge: self.raw_charge,
            }),
            owners: self.owners_present.then_some(self.owners.as_slice()),
            owner_count: self.owner_count,
            action_tag: self.action,
            reservation_state_tag: self.state,
            reservation: self.reservation,
            target: self.target,
            expected_charge: self.expected_charge,
            reserved_charge: self.reserved_charge,
        }
    }
    fn context(&self) -> Context<'_> {
        Context {
            binding: canonical_binding(),
            terminal: self.terminal,
            target_max: self.target_max,
            ledgers: self.ledgers,
            observations: &self.observations,
            registry: &self.registry,
            expected_owners: &self.expected,
            reservation: Some((ReservationId(40), 128, 0)),
            target: Some(OwnerId(20)),
            actual_allocated: self.actual_allocated,
        }
    }
    fn prepare(&mut self) {
        self.action = 1;
        self.reservation = Some(ReservationId(40));
    }
    fn lifecycle(&mut self, action: u8, state: u8) {
        self.action = action;
        self.state = state;
        self.reservation = if action == 0 { None } else { Some(ReservationId(40)) };
        self.binding.as_mut().unwrap().phase_tag = if action == 2 { 1 } else { 0 };
        self.target = Some(OwnerId(20));
        if action == 2 {
            self.owners[0].location_tag = 2;
            self.expected[0].location_tag = 2;
        }
    }
    // Reference arithmetic uses u128; derive all capacities and charges before altering
    // exactly the named observation. Wide synthetic fixtures never allocate those sizes.
    fn resize(&mut self, capacity: u64, element_size: u64, count: u64) {
        let r = &mut self.rows[0];
        r.capacity = capacity;
        r.element_size = element_size;
        r.count = count;
        self.observations[0].capacity = capacity;
        self.observations[0].element_size = element_size;
        r.charge = if r.domain_tag == 0 {
            (((u128::from(capacity) + 63) & !63) + 64) as u64
        } else {
            capacity
        };
        self.batch_charge = if r.domain_tag == 0 { r.charge } else { 0 };
        self.raw_charge = if r.domain_tag == 1 { r.charge } else { 0 };
        self.expected_charge = self.batch_charge;
        self.reserved_charge = self.batch_charge;
    }
    fn raw(&mut self) {
        self.rows[0].role = Role::KeyOwner as u8;
        self.rows[0].domain_tag = 1;
        self.rows[0].class_tag = 6;
        self.resize(64, 8, 8);
    }
    fn wide(&mut self) {
        self.ledgers = Ledgers {
            metadata_limit: u64::MAX,
            metadata_used: 0,
            slice_limit: u64::MAX,
            slice_used: 0,
            raw_limit: u64::MAX,
            raw_used: 0,
        };
    }
    fn second(&mut self) {
        let mut r = self.rows[0];
        r.allocation = AllocationId(11);
        self.rows.push(r);
        let mut o = self.observations[0];
        o.allocation = AllocationId(11);
        self.observations.push(o);
        self.row_count = 2;
        self.batch_charge = self.batch_charge.wrapping_mul(2);
        self.raw_charge = self.raw_charge.wrapping_mul(2);
        self.expected_charge = self.batch_charge;
        self.reserved_charge = self.batch_charge;
    }
    fn second_owner(&mut self) {
        let mut o = self.owners[0];
        o.owner = OwnerId(21);
        o.allocation = AllocationId(11);
        o.lease = LeaseId(31);
        self.owners.push(o);
        self.expected.push(o);
        self.owner_count = 2;
    }
    // Independent reference evaluator: u128 byte equations, explicit role table,
    // and full-rule collection within each structurally applicable validation level.
    // It does not call any production validator, q(), or role decoder.
    fn violations(&self) -> Vec<StageError> {
        use StageError::*;
        let mut errors = Vec::new();
        if self.terminal {
            return vec![TerminalFenced];
        }
        let Some(b) = self.binding else { return vec![MissingBinding] };
        let expected = canonical_binding();
        for (field, a, e) in [
            (Field::Connection, b.connection.0, expected.connection.0),
            (Field::Credit, b.credit.0, expected.credit.0),
            (Field::Configuration, b.configuration.0, expected.configuration.0),
            (Field::Layout, b.layout.0, expected.layout.0),
        ] {
            if a == 0 {
                errors.push(EmptyBinding(field));
            } else if a != e {
                errors.push(BindingMismatch(field));
            }
        }
        if b.space_tag > 2 {
            errors.push(InvalidSpace(b.space_tag));
        } else if b.space_tag != expected.space_tag {
            errors.push(SpaceMismatch);
        }
        if b.pn >= (1 << 62) {
            errors.push(PacketNumberOutOfRange);
        } else if b.pn != expected.pn {
            errors.push(PacketNumberMismatch);
        }
        if b.generation != expected.generation {
            errors.push(GenerationMismatch);
        }
        if b.stage_id != expected.stage_id {
            errors.push(StageMismatch);
        }
        if b.phase_tag > 4 {
            errors.push(InvalidPhase(b.phase_tag));
        }
        if !errors.is_empty() {
            return errors;
        }
        let actions = [
            Action::Reserve,
            Action::Prepare,
            Action::Transfer,
            Action::Discard,
            Action::CancelUnused,
        ];
        let states = [
            ReservationState::Unused,
            ReservationState::Allocated,
            ReservationState::Moved,
            ReservationState::Refunded,
        ];
        let Some(&action) = actions.get(usize::from(self.action)) else {
            return vec![InvalidAction(self.action)];
        };
        let Some(&state) = states.get(usize::from(self.state)) else {
            return vec![InvalidReservationState(self.state)];
        };
        if self.state >= 2 {
            return vec![ReservationConsumed];
        }
        if self.action == 0 {
            if self.reservation.is_some() {
                return vec![UnexpectedReservation];
            }
        } else {
            match self.reservation {
                None => return vec![MissingReservation],
                Some(ReservationId(40)) => {}
                _ => return vec![ReservationMismatch],
            }
        }
        let phases: &[u8] = match self.action {
            2 => &[1],
            3 => &[0, 1],
            _ => &[0],
        };
        if !phases.contains(&b.phase_tag) {
            return vec![PhaseMismatch];
        }
        // All twenty cells are represented directly, independently of the implementation match.
        const ACCEPT: [[bool; 4]; 5] = [
            [true, false, false, false],
            [true, false, false, false],
            [false, true, false, false],
            [true, true, false, false],
            [true, false, false, false],
        ];
        if !ACCEPT[usize::from(self.action)][usize::from(self.state)] {
            return vec![ReservationStateMismatch(action, state)];
        }
        let mut debit = 128u128;
        if self.action <= 1 {
            if !self.batch_present {
                return vec![MissingBatch];
            }
            for (f, v) in [
                (Field::RowCount, self.row_count),
                (Field::BatchCharge, self.batch_charge),
                (Field::RawCharge, self.raw_charge),
                (Field::MetadataLimit, self.ledgers.metadata_limit),
                (Field::MetadataUsed, self.ledgers.metadata_used),
                (Field::SliceLimit, self.ledgers.slice_limit),
                (Field::SliceUsed, self.ledgers.slice_used),
                (Field::RawLimit, self.ledgers.raw_limit),
                (Field::RawUsed, self.ledgers.raw_used),
            ] {
                if v > self.target_max {
                    errors.push(NotRepresentable(f));
                }
            }
            if !errors.is_empty() {
                return errors;
            }
            if u128::from(self.row_count) != self.rows.len() as u128 {
                return vec![CountMismatch(Count::Rows)];
            }
            let mut sums = [0u128; 2];
            for (i, r) in self.rows.iter().enumerate() {
                if r.allocation.0 == 0 {
                    errors.push(EmptyAllocationId(i));
                    continue;
                }
                if self.rows[..i].iter().any(|x| x.allocation == r.allocation) {
                    errors.push(DuplicateAllocation(i));
                    continue;
                }
                if self.registry.iter().any(|x| x.allocation == r.allocation) {
                    errors.push(AllocationAlreadyLive(i));
                    continue;
                }
                // The inventory's E1 subset, by sealed role tag. Specialized roles
                // outside this list are recognized but not dispatched by E1.
                let assignment = match r.role {
                    0..=3 => Some((0, 5)),
                    5..=8 => Some((0, 6)),
                    10 | 11 => Some((0, 7)),
                    17 | 23..=26 => Some((0, 8)),
                    19 | 20 => Some((0, 10)),
                    21 | 22 => Some((0, 11)),
                    27 => Some((0, 6)),
                    31 => Some((1, 6)),
                    4 | 9 | 12..=16 | 18 | 28..=30 | 32 => None,
                    _ => {
                        errors.push(InvalidRole(i));
                        continue;
                    }
                };
                let Some((domain, class)) = assignment else {
                    errors.push(RoleNotAllowed(i));
                    continue;
                };
                if r.domain_tag > 1 {
                    errors.push(InvalidDomain(i, r.domain_tag));
                    continue;
                }
                if r.class_tag > 11 {
                    errors.push(InvalidClass(i, r.class_tag));
                    continue;
                }
                if r.domain_tag != domain {
                    errors.push(RoleDomainMismatch(i));
                    continue;
                }
                if r.class_tag != class {
                    errors.push(RoleClassMismatch(i));
                    continue;
                }
                for (f, v) in [
                    (Field::Capacity, r.capacity),
                    (Field::Count, r.count),
                    (Field::ElementSize, r.element_size),
                    (Field::Alignment, r.alignment),
                    (Field::Charge, r.charge),
                ] {
                    if v > self.target_max {
                        errors.push(NotRepresentable(f));
                    }
                }
                if !errors.is_empty() {
                    continue;
                }
                let o = self.observations.iter().find(|o| o.allocation == r.allocation).unwrap();
                if r.element_size == 0 || r.element_size != o.element_size {
                    errors.push(LayoutMismatch(i, Field::ElementSize));
                }
                if r.alignment == 0
                    || (r.alignment & (r.alignment - 1)) != 0
                    || r.alignment != o.alignment
                {
                    errors.push(LayoutMismatch(i, Field::Alignment));
                }
                if !errors.is_empty() {
                    continue;
                }
                let product = u128::from(r.count) * u128::from(r.element_size);
                if product > u128::from(u64::MAX) {
                    errors.push(ArithmeticOverflow(Arithmetic::AllocationProduct(i)));
                    continue;
                }
                if product > u128::from(r.capacity) {
                    errors.push(CapacityInsufficient(i));
                    continue;
                }
                if r.capacity != o.capacity {
                    errors.push(CapacityObservationMismatch(i));
                    continue;
                }
                let charge = if domain == 0 {
                    u128::from(r.capacity).div_ceil(64) * 64 + 64
                } else {
                    u128::from(r.capacity)
                };
                if charge > u128::from(u64::MAX) {
                    errors.push(ArithmeticOverflow(Arithmetic::AllocationCharge(i)));
                    continue;
                }
                if charge != u128::from(r.charge) {
                    errors.push(ChargeMismatch(i));
                    continue;
                }
                sums[usize::from(domain)] += charge;
            }
            if !errors.is_empty() {
                return errors;
            }
            for (sum, op) in [(sums[0], Arithmetic::MetadataSum), (sums[1], Arithmetic::RawSum)] {
                if sum > u128::from(u64::MAX) {
                    errors.push(ArithmeticOverflow(op));
                }
            }
            if !errors.is_empty() {
                return errors;
            }
            if sums[0] != u128::from(self.batch_charge) {
                errors.push(BatchChargeMismatch(Domain::Metadata));
            }
            if sums[1] != u128::from(self.raw_charge) {
                errors.push(BatchChargeMismatch(Domain::RawBase));
            }
            if !errors.is_empty() {
                return errors;
            }
            debit = sums[0];
            for (domain, used, limit, amount, op) in [
                (
                    Domain::Metadata,
                    self.ledgers.metadata_used,
                    self.ledgers.metadata_limit,
                    sums[0],
                    Arithmetic::MetadataOverlap,
                ),
                (
                    Domain::RawBase,
                    self.ledgers.raw_used,
                    self.ledgers.raw_limit,
                    sums[1],
                    Arithmetic::RawOverlap,
                ),
                (
                    Domain::Slice,
                    self.ledgers.slice_used,
                    self.ledgers.slice_limit,
                    sums[0],
                    Arithmetic::SliceOverlap,
                ),
            ] {
                if used > limit {
                    errors.push(InvalidLedger(domain));
                    continue;
                }
                if self.action == 1 && amount > u128::from(used) {
                    errors.push(InvalidLedger(domain));
                    continue;
                }
                let total = u128::from(used) + if self.action == 1 { 0 } else { amount };
                if total > u128::from(u64::MAX) {
                    errors.push(ArithmeticOverflow(op));
                    continue;
                }
                if total > u128::from(limit) {
                    errors.push(if domain == Domain::RawBase {
                        BaseEnvelopeExceeded
                    } else {
                        Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })
                    });
                }
            }
        }
        if !errors.is_empty() {
            return errors;
        }
        for (f, v) in [
            (Field::ExpectedCharge, self.expected_charge),
            (Field::ReservedCharge, self.reserved_charge),
        ] {
            if v > self.target_max {
                errors.push(NotRepresentable(f));
            }
        }
        if !errors.is_empty() {
            return errors;
        }
        if u128::from(self.expected_charge) != debit {
            errors.push(ExpectedChargeMismatch);
        }
        if u128::from(self.reserved_charge) != debit {
            errors.push(ReservedChargeMismatch);
        }
        if !errors.is_empty() {
            return errors;
        }
        if matches!(self.action, 1..=3) {
            if !self.owners_present {
                return vec![MissingOwners];
            }
            if self.owner_count > self.target_max {
                return vec![NotRepresentable(Field::OwnerCount)];
            }
            if u128::from(self.owner_count) != self.owners.len() as u128 {
                return vec![CountMismatch(Count::Owners)];
            }
            for (i, o) in self.owners.iter().enumerate() {
                for (f, v) in [
                    (Field::Owner, o.owner.0),
                    (Field::Allocation, o.allocation.0),
                    (Field::Lease, o.lease.0),
                ] {
                    if v == 0 {
                        errors.push(EmptyOwnerField(f, i));
                    }
                }
                for previous in &self.owners[..i] {
                    if previous.owner == o.owner {
                        errors.push(DuplicateOwner(i));
                    }
                    if previous.allocation == o.allocation && previous.lease != o.lease {
                        errors.push(DuplicateBackingCharge(i));
                    }
                    if previous.allocation != o.allocation && previous.lease == o.lease {
                        errors.push(LeaseAliased(i));
                    }
                }
            }
            if !errors.is_empty() {
                return errors;
            }
            for (i, o) in self.owners.iter().enumerate() {
                let known = self
                    .registry
                    .iter()
                    .chain(&self.expected)
                    .find(|e| e.allocation == o.allocation);
                let Some(known) = known else {
                    errors.push(UnknownAllocation(i));
                    continue;
                };
                if known.lease != o.lease {
                    errors.push(LeaseMismatch(i));
                    continue;
                }
                if o.location_tag > 2 {
                    errors.push(InvalidOwnerLocation(i, o.location_tag));
                    continue;
                }
                let Some(expected) = self.expected.iter().find(|e| e.owner == o.owner) else {
                    errors.push(OwnerUnexpected(o.owner));
                    continue;
                };
                if o.allocation != expected.allocation {
                    errors.push(OwnerAllocationMismatch(i));
                }
                if o.lease != expected.lease {
                    errors.push(LeaseMismatch(i));
                }
                if o.location_tag != expected.location_tag {
                    errors.push(OwnerLocationMismatch(i));
                }
                if o.references != expected.references {
                    errors.push(ReferenceCountMismatch(i));
                }
                if o.release_requested && o.free.is_none() {
                    errors.push(FreeNotCompleted(i));
                }
                if let Some(f) = o.free {
                    if f.allocation != o.allocation || f.lease != o.lease {
                        errors.push(FreeWitnessMismatch(i));
                    } else if f.consumed {
                        errors.push(FreeWitnessConsumed(i));
                    }
                }
            }
            if !errors.is_empty() {
                return errors;
            }
            for expected in &self.expected {
                if !self.owners.iter().any(|o| {
                    o.owner == expected.owner && o.allocation == expected.allocation && o.lease == expected.lease
                }) {
                    errors.push(OwnerMissing(expected.owner));
                }
            }
        }
        if self.action == 2 {
            match self.target {
                None => errors.push(MissingTransferTarget),
                Some(OwnerId(20)) => {}
                _ => errors.push(TransferTargetMismatch),
            }
        }
        if self.action == 4 && self.actual_allocated {
            errors.push(ReservationHasAllocation);
        }
        errors
    }
    fn reject(&self, error: StageError) {
        assert_eq!(
            self.violations(),
            vec![error],
            "exactly one independently evaluated applicable rule must fail"
        );
        // Borrow-only API has no Session or publication capability; these canaries
        // also observe that input owner/ledger state is untouched on every rejection.
        let before = format!("{:?}{:?}{:?}", self.owners, self.ledgers, self.binding);
        let session = tls_contract::tests::CountingSession::default();
        let result = validate_e1(&self.request(), &self.context());
        if result.is_ok() {
            let _ = crate::crypto::Session::is_handshaking(&session);
        }
        assert_eq!(result, Err(error));
        assert_eq!(session.calls.load(Ordering::SeqCst), 0, "all Session methods remain untouched");
        assert_eq!(format!("{:?}{:?}{:?}", self.owners, self.ledgers, self.binding), before);
    }
}
macro_rules! negative {
    ($name:ident,$setup:expr,$error:expr) => {
        #[test]
        fn $name() {
            let mut f = Fixture::valid();
            ($setup)(&mut f);
            f.reject($error);
        }
    };
}
negative!(
    inventory_e1_missing_binding,
    |f: &mut Fixture| {
        f.binding = None;
    },
    StageError::MissingBinding
);
negative!(
    inventory_e1_empty_binding_connection,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().connection = ConnectionId(0);
    },
    StageError::EmptyBinding(Field::Connection)
);
negative!(
    inventory_e1_wrong_binding_connection,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().connection = ConnectionId(99);
    },
    StageError::BindingMismatch(Field::Connection)
);
negative!(
    inventory_e1_empty_binding_credit,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().credit = CreditId(0);
    },
    StageError::EmptyBinding(Field::Credit)
);
negative!(
    inventory_e1_wrong_binding_credit,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().credit = CreditId(99);
    },
    StageError::BindingMismatch(Field::Credit)
);
negative!(
    inventory_e1_empty_binding_configuration,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().configuration = ConfigurationId(0);
    },
    StageError::EmptyBinding(Field::Configuration)
);
negative!(
    inventory_e1_wrong_binding_configuration,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().configuration = ConfigurationId(99);
    },
    StageError::BindingMismatch(Field::Configuration)
);
negative!(
    inventory_e1_empty_binding_layout,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().layout = LayoutId(0);
    },
    StageError::EmptyBinding(Field::Layout)
);
negative!(
    inventory_e1_wrong_binding_layout,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().layout = LayoutId(99);
    },
    StageError::BindingMismatch(Field::Layout)
);
negative!(
    inventory_e1_unknown_space,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().space_tag = 9;
    },
    StageError::InvalidSpace(9)
);
negative!(
    inventory_e1_wrong_space,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().space_tag = 2;
    },
    StageError::SpaceMismatch
);
negative!(
    inventory_e1_pn_out_of_range,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().pn = 1 << 62;
    },
    StageError::PacketNumberOutOfRange
);
negative!(
    inventory_e1_wrong_pn,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().pn = 18;
    },
    StageError::PacketNumberMismatch
);
negative!(
    inventory_e1_stale_generation,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().generation = 4;
    },
    StageError::GenerationMismatch
);
negative!(
    inventory_e1_wrong_stage,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().stage_id = 99;
    },
    StageError::StageMismatch
);
negative!(
    inventory_e1_unknown_phase,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().phase_tag = 9;
    },
    StageError::InvalidPhase(9)
);
negative!(
    inventory_e1_wrong_phase,
    |f: &mut Fixture| {
        f.binding.as_mut().unwrap().phase_tag = 1;
    },
    StageError::PhaseMismatch
);
negative!(
    inventory_e1_terminal_binding,
    |f: &mut Fixture| {
        f.terminal = true;
    },
    StageError::TerminalFenced
);
negative!(
    inventory_e1_missing_batch,
    |f: &mut Fixture| {
        f.batch_present = false;
    },
    StageError::MissingBatch
);
negative!(
    inventory_e1_wrong_row_count,
    |f: &mut Fixture| {
        f.row_count = 2;
    },
    StageError::CountMismatch(Count::Rows)
);
negative!(
    inventory_e1_empty_allocation_id,
    |f: &mut Fixture| {
        f.rows[0].allocation = AllocationId(0);
    },
    StageError::EmptyAllocationId(0)
);
negative!(
    inventory_e1_duplicate_allocation_id,
    |f: &mut Fixture| {
        f.second();
        f.rows[1].allocation = AllocationId(10);
    },
    StageError::DuplicateAllocation(1)
);
negative!(
    inventory_e1_already_live_allocation_id,
    |f: &mut Fixture| {
        f.registry.push(f.owners[0]);
    },
    StageError::AllocationAlreadyLive(0)
);
negative!(
    inventory_e1_unknown_allocation_role,
    |f: &mut Fixture| {
        f.rows[0].role = 255;
    },
    StageError::InvalidRole(0)
);
negative!(
    inventory_e1_foreign_allocation_role,
    |f: &mut Fixture| {
        f.rows[0].role = Role::TerminalOwner as u8;
    },
    StageError::RoleNotAllowed(0)
);
negative!(
    inventory_e1_unknown_domain,
    |f: &mut Fixture| {
        f.rows[0].domain_tag = 9;
    },
    StageError::InvalidDomain(0, 9)
);
negative!(
    inventory_e1_unknown_class,
    |f: &mut Fixture| {
        f.rows[0].class_tag = 12;
    },
    StageError::InvalidClass(0, 12)
);
negative!(
    inventory_e1_wrong_role_domain,
    |f: &mut Fixture| {
        f.rows[0].domain_tag = 1;
    },
    StageError::RoleDomainMismatch(0)
);
negative!(
    inventory_e1_wrong_role_class,
    |f: &mut Fixture| {
        f.rows[0].class_tag = 6;
    },
    StageError::RoleClassMismatch(0)
);
negative!(
    inventory_e1_wrong_element_size,
    |f: &mut Fixture| {
        f.rows[0].element_size = 4;
    },
    StageError::LayoutMismatch(0, Field::ElementSize)
);
negative!(
    inventory_e1_wrong_alignment,
    |f: &mut Fixture| {
        f.rows[0].alignment = 4;
    },
    StageError::LayoutMismatch(0, Field::Alignment)
);
negative!(
    inventory_e1_allocation_product_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(u64::MAX - 127, 1 << 63, 2);
    },
    StageError::ArithmeticOverflow(Arithmetic::AllocationProduct(0))
);
negative!(
    inventory_e1_allocation_capacity_too_small,
    |f: &mut Fixture| {
        f.rows[0].count = 9;
    },
    StageError::CapacityInsufficient(0)
);
negative!(
    inventory_e1_false_observed_capacity,
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
    inventory_e1_allocation_charge_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(u64::MAX, 1, 1);
    },
    StageError::ArithmeticOverflow(Arithmetic::AllocationCharge(0))
);
negative!(
    inventory_e1_wrong_allocation_charge,
    |f: &mut Fixture| {
        f.rows[0].charge = 192;
        f.batch_charge = 192;
        f.expected_charge = 192;
        f.reserved_charge = 192;
    },
    StageError::ChargeMismatch(0)
);
negative!(
    inventory_e1_metadata_sum_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.resize(1 << 63, 8, 8);
        f.second();
    },
    StageError::ArithmeticOverflow(Arithmetic::MetadataSum)
);
negative!(
    inventory_e1_raw_sum_overflow,
    |f: &mut Fixture| {
        f.raw();
        f.wide();
        f.resize(1 << 63, 8, 8);
        f.second();
    },
    StageError::ArithmeticOverflow(Arithmetic::RawSum)
);
negative!(
    inventory_e1_wrong_batch_charge,
    |f: &mut Fixture| {
        f.batch_charge = 192;
        f.expected_charge = 192;
        f.reserved_charge = 192;
    },
    StageError::BatchChargeMismatch(Domain::Metadata)
);
negative!(
    inventory_e1_wrong_raw_charge,
    |f: &mut Fixture| {
        f.raw_charge = 64;
    },
    StageError::BatchChargeMismatch(Domain::RawBase)
);
negative!(
    inventory_e1_metadata_overlap_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.ledgers.metadata_used = u64::MAX - 63;
    },
    StageError::ArithmeticOverflow(Arithmetic::MetadataOverlap)
);
negative!(
    inventory_e1_raw_overlap_overflow,
    |f: &mut Fixture| {
        f.raw();
        f.wide();
        f.ledgers.raw_used = u64::MAX - 31;
    },
    StageError::ArithmeticOverflow(Arithmetic::RawOverlap)
);
negative!(
    inventory_e1_slice_overlap_overflow,
    |f: &mut Fixture| {
        f.wide();
        f.ledgers.slice_used = u64::MAX - 63;
    },
    StageError::ArithmeticOverflow(Arithmetic::SliceOverlap)
);
negative!(
    inventory_e1_overlap_exceeds_metadata,
    |f: &mut Fixture| {
        f.ledgers.metadata_limit = 192;
    },
    StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })
);
negative!(
    inventory_e1_overlap_exceeds_slice,
    |f: &mut Fixture| {
        f.ledgers.slice_limit = 4160;
    },
    StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })
);
negative!(
    inventory_e1_overlap_exceeds_raw,
    |f: &mut Fixture| {
        f.raw();
        f.ledgers.raw_limit = 32;
    },
    StageError::BaseEnvelopeExceeded
);
negative!(
    inventory_e1_missing_owners,
    |f: &mut Fixture| {
        f.prepare();
        f.owners_present = false;
    },
    StageError::MissingOwners
);
negative!(
    inventory_e1_wrong_owner_count,
    |f: &mut Fixture| {
        f.prepare();
        f.owner_count = 2;
    },
    StageError::CountMismatch(Count::Owners)
);
negative!(
    inventory_e1_duplicate_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].owner = OwnerId(20);
    },
    StageError::DuplicateOwner(1)
);
negative!(
    inventory_e1_unknown_owner_allocation,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].allocation = AllocationId(99);
    },
    StageError::UnknownAllocation(0)
);
negative!(
    inventory_e1_wrong_owner_lease,
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
    inventory_e1_double_charged_backing,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].allocation = AllocationId(10);
    },
    StageError::DuplicateBackingCharge(1)
);
negative!(
    inventory_e1_aliased_distinct_allocations,
    |f: &mut Fixture| {
        f.prepare();
        f.second_owner();
        f.owners[1].lease = LeaseId(30);
    },
    StageError::LeaseAliased(1)
);
negative!(
    inventory_e1_unknown_owner_location,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].location_tag = 9;
    },
    StageError::InvalidOwnerLocation(0, 9)
);
negative!(
    inventory_e1_wrong_owner_location,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].location_tag = 0;
    },
    StageError::OwnerLocationMismatch(0)
);
negative!(
    inventory_e1_wrong_owner_references,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 2;
    },
    StageError::ReferenceCountMismatch(0)
);
negative!(
    inventory_e1_missing_physical_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.owners.clear();
        f.owner_count = 0;
    },
    StageError::OwnerMissing(OwnerId(20))
);
negative!(
    inventory_e1_extra_physical_owner,
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
    inventory_e1_refund_before_free,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].release_requested = true;
    },
    StageError::FreeNotCompleted(0)
);
negative!(
    inventory_e1_foreign_free_witness,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].free = Some(completed_free(AllocationId(99), LeaseId(99), false));
    },
    StageError::FreeWitnessMismatch(0)
);
negative!(
    inventory_e1_reused_free_witness,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].references = 0;
        f.expected[0].references = 0;
        f.owners[0].free = Some(completed_free(AllocationId(10), LeaseId(30), true));
    },
    StageError::FreeWitnessConsumed(0)
);
negative!(
    inventory_e1_unknown_action,
    |f: &mut Fixture| {
        f.action = 9;
    },
    StageError::InvalidAction(9)
);
negative!(
    inventory_e1_unknown_reservation_state,
    |f: &mut Fixture| {
        f.state = 9;
    },
    StageError::InvalidReservationState(9)
);
negative!(
    inventory_e1_missing_reservation,
    |f: &mut Fixture| {
        f.prepare();
        f.reservation = None;
    },
    StageError::MissingReservation
);
negative!(
    inventory_e1_foreign_reservation,
    |f: &mut Fixture| {
        f.prepare();
        f.reservation = Some(ReservationId(99));
    },
    StageError::ReservationMismatch
);
negative!(
    inventory_e1_reserve_with_existing_reservation,
    |f: &mut Fixture| {
        f.reservation = Some(ReservationId(40));
    },
    StageError::UnexpectedReservation
);
negative!(
    inventory_e1_wrong_expected_charge,
    |f: &mut Fixture| {
        f.expected_charge = 192;
    },
    StageError::ExpectedChargeMismatch
);
negative!(
    inventory_e1_short_reserved_charge,
    |f: &mut Fixture| {
        f.reserved_charge = 64;
    },
    StageError::ReservedChargeMismatch
);
negative!(
    inventory_e1_missing_transfer_target,
    |f: &mut Fixture| {
        f.lifecycle(2, 1);
        f.target = None;
    },
    StageError::MissingTransferTarget
);
negative!(
    inventory_e1_wrong_transfer_target,
    |f: &mut Fixture| {
        f.lifecycle(2, 1);
        f.target = Some(OwnerId(99));
    },
    StageError::TransferTargetMismatch
);
negative!(
    inventory_e1_cancel_allocated_reservation,
    |f: &mut Fixture| {
        f.lifecycle(4, 0);
        f.actual_allocated = true;
    },
    StageError::ReservationHasAllocation
);
negative!(
    inventory_e1_unrepresentable_capacity,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].capacity = 8193;
    },
    StageError::NotRepresentable(Field::Capacity)
);
negative!(
    inventory_e1_unrepresentable_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].count = 8193;
    },
    StageError::NotRepresentable(Field::Count)
);
negative!(
    inventory_e1_unrepresentable_element_size,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].element_size = 8193;
    },
    StageError::NotRepresentable(Field::ElementSize)
);
negative!(
    inventory_e1_unrepresentable_alignment,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].alignment = 8193;
    },
    StageError::NotRepresentable(Field::Alignment)
);
negative!(
    inventory_e1_unrepresentable_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.rows[0].charge = 8193;
    },
    StageError::NotRepresentable(Field::Charge)
);
negative!(
    inventory_e1_unrepresentable_row_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.row_count = 8193;
    },
    StageError::NotRepresentable(Field::RowCount)
);
negative!(
    inventory_e1_unrepresentable_batch_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.batch_charge = 8193;
    },
    StageError::NotRepresentable(Field::BatchCharge)
);
negative!(
    inventory_e1_unrepresentable_raw_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.raw_charge = 8193;
    },
    StageError::NotRepresentable(Field::RawCharge)
);
negative!(
    inventory_e1_unrepresentable_metadata_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.metadata_limit = 8193;
    },
    StageError::NotRepresentable(Field::MetadataLimit)
);
negative!(
    inventory_e1_unrepresentable_metadata_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.metadata_used = 8193;
    },
    StageError::NotRepresentable(Field::MetadataUsed)
);
negative!(
    inventory_e1_unrepresentable_slice_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.slice_limit = 8193;
    },
    StageError::NotRepresentable(Field::SliceLimit)
);
negative!(
    inventory_e1_unrepresentable_slice_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.slice_used = 8193;
    },
    StageError::NotRepresentable(Field::SliceUsed)
);
negative!(
    inventory_e1_unrepresentable_raw_limit,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.raw_limit = 8193;
    },
    StageError::NotRepresentable(Field::RawLimit)
);
negative!(
    inventory_e1_unrepresentable_raw_used,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.ledgers.raw_used = 8193;
    },
    StageError::NotRepresentable(Field::RawUsed)
);
negative!(
    inventory_e1_unrepresentable_owner_count,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.prepare();
        f.owner_count = 8193;
    },
    StageError::NotRepresentable(Field::OwnerCount)
);
negative!(
    inventory_e1_unrepresentable_expected_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.expected_charge = 8193;
    },
    StageError::NotRepresentable(Field::ExpectedCharge)
);
negative!(
    inventory_e1_unrepresentable_reserved_charge,
    |f: &mut Fixture| {
        f.target_max = 8192;
        f.reserved_charge = 8193;
    },
    StageError::NotRepresentable(Field::ReservedCharge)
);
negative!(
    inventory_e1_invalid_used_metadata,
    |f: &mut Fixture| {
        f.ledgers.metadata_used = f.ledgers.metadata_limit + 1;
    },
    StageError::InvalidLedger(Domain::Metadata)
);
negative!(
    inventory_e1_invalid_used_slice,
    |f: &mut Fixture| {
        f.ledgers.slice_used = f.ledgers.slice_limit + 1;
    },
    StageError::InvalidLedger(Domain::Slice)
);
negative!(
    inventory_e1_invalid_used_raw,
    |f: &mut Fixture| {
        f.ledgers.raw_used = f.ledgers.raw_limit + 1;
    },
    StageError::InvalidLedger(Domain::RawBase)
);
negative!(
    inventory_e1_empty_owner_owner,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].owner = OwnerId(0);
    },
    StageError::EmptyOwnerField(Field::Owner, 0)
);
negative!(
    inventory_e1_empty_owner_allocation,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].allocation = AllocationId(0);
    },
    StageError::EmptyOwnerField(Field::Allocation, 0)
);
negative!(
    inventory_e1_empty_owner_lease,
    |f: &mut Fixture| {
        f.prepare();
        f.owners[0].lease = LeaseId(0);
    },
    StageError::EmptyOwnerField(Field::Lease, 0)
);
negative!(
    inventory_e1_action_state_mismatch_reserve_allocated,
    |f: &mut Fixture| {
        f.lifecycle(0, 1);
    },
    StageError::ReservationStateMismatch(Action::Reserve, ReservationState::Allocated)
);
negative!(
    inventory_e1_action_state_mismatch_prepare_allocated,
    |f: &mut Fixture| {
        f.lifecycle(1, 1);
    },
    StageError::ReservationStateMismatch(Action::Prepare, ReservationState::Allocated)
);
negative!(
    inventory_e1_action_state_mismatch_transfer_unused,
    |f: &mut Fixture| {
        f.lifecycle(2, 0);
    },
    StageError::ReservationStateMismatch(Action::Transfer, ReservationState::Unused)
);
negative!(
    inventory_e1_action_state_mismatch_cancel_unused_allocated,
    |f: &mut Fixture| {
        f.lifecycle(4, 1);
    },
    StageError::ReservationStateMismatch(Action::CancelUnused, ReservationState::Allocated)
);
negative!(
    inventory_e1_reused_reservation_reserve_moved,
    |f: &mut Fixture| {
        f.lifecycle(0, 2);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_reserve_refunded,
    |f: &mut Fixture| {
        f.lifecycle(0, 3);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_prepare_moved,
    |f: &mut Fixture| {
        f.lifecycle(1, 2);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_prepare_refunded,
    |f: &mut Fixture| {
        f.lifecycle(1, 3);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_transfer_moved,
    |f: &mut Fixture| {
        f.lifecycle(2, 2);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_transfer_refunded,
    |f: &mut Fixture| {
        f.lifecycle(2, 3);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_discard_moved,
    |f: &mut Fixture| {
        f.lifecycle(3, 2);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_discard_refunded,
    |f: &mut Fixture| {
        f.lifecycle(3, 3);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_cancel_unused_moved,
    |f: &mut Fixture| {
        f.lifecycle(4, 2);
    },
    StageError::ReservationConsumed
);
negative!(
    inventory_e1_reused_reservation_cancel_unused_refunded,
    |f: &mut Fixture| {
        f.lifecycle(4, 3);
    },
    StageError::ReservationConsumed
);

#[test]
fn inventory_e1_valid_contract_accepts_once() {
    let f = Fixture::valid();
    assert_eq!(
        validate_e1(&f.request(), &f.context()),
        Ok(ValidatedE1 { metadata: 128, raw: 0, next: ReservationState::Unused })
    );
}
#[test]
fn inventory_e1_exact_capacity_accepts() {
    let mut raw = Fixture::valid();
    raw.raw();
    raw.ledgers.raw_limit = 64;
    assert!(raw.violations().is_empty());
    let c = StageCredit::new(
        MetadataCredit::new(128),
        Ledgers {
            metadata_limit: 128,
            metadata_used: 0,
            slice_limit: 4096,
            slice_used: 4096,
            raw_limit: 64,
            raw_used: 0,
        },
    );
    let baseline = c.snapshot();
    let lease = c.reserve::<1>(&raw.request(), &raw.context()).unwrap();
    assert_eq!(c.snapshot().raw_used, 64);
    assert_eq!(c.snapshot().slice_used, 4096);
    let stage = PreparedStage::prepare(lease).unwrap();
    assert_eq!(stage.capacity(0), 64);
    drop(stage);
    assert_eq!(c.snapshot(), baseline);

    let mut f = Fixture::valid();
    f.ledgers.metadata_limit = 256;
    f.ledgers.slice_limit = 4224;
    assert_eq!(
        validate_e1(&f.request(), &f.context()),
        Ok(ValidatedE1 { metadata: 128, raw: 0, next: ReservationState::Unused })
    );
}
#[test]
fn inventory_e1_action_state_accepts_reserve_unused() {
    observe_accepting_cell(Action::Reserve, ReservationState::Unused);
    let mut f = Fixture::valid();
    f.lifecycle(0, 0);
    assert_eq!(validate_e1(&f.request(), &f.context()).unwrap().next, ReservationState::Unused);
}
#[test]
fn inventory_e1_action_state_accepts_prepare_unused() {
    observe_accepting_cell(Action::Prepare, ReservationState::Unused);
    let mut f = Fixture::valid();
    f.lifecycle(1, 0);
    assert_eq!(validate_e1(&f.request(), &f.context()).unwrap().next, ReservationState::Allocated);
}
#[test]
fn inventory_e1_action_state_accepts_transfer_allocated() {
    observe_accepting_cell(Action::Transfer, ReservationState::Allocated);
    let mut f = Fixture::valid();
    f.lifecycle(2, 1);
    assert_eq!(validate_e1(&f.request(), &f.context()).unwrap().next, ReservationState::Moved);
}
#[test]
fn inventory_e1_action_state_accepts_discard_unused() {
    observe_accepting_cell(Action::Discard, ReservationState::Unused);
    let mut f = Fixture::valid();
    f.lifecycle(3, 0);
    assert_eq!(validate_e1(&f.request(), &f.context()).unwrap().next, ReservationState::Refunded);
}
#[test]
fn inventory_e1_action_state_accepts_discard_allocated() {
    observe_accepting_cell(Action::Discard, ReservationState::Allocated);
    let mut f = Fixture::valid();
    f.lifecycle(3, 1);
    assert_eq!(validate_e1(&f.request(), &f.context()).unwrap().next, ReservationState::Refunded);
}
#[test]
fn inventory_e1_action_state_accepts_cancel_unused_unused() {
    observe_accepting_cell(Action::CancelUnused, ReservationState::Unused);
    let mut f = Fixture::valid();
    f.lifecycle(4, 0);
    assert_eq!(validate_e1(&f.request(), &f.context()).unwrap().next, ReservationState::Refunded);
}

fn credit(limit: usize) -> Arc<StageCredit> {
    StageCredit::new(
        MetadataCredit::new(limit),
        Ledgers {
            metadata_limit: limit as u64,
            metadata_used: 0,
            slice_limit: 8192,
            slice_used: 4096,
            raw_limit: 2048,
            raw_used: 0,
        },
    )
}
#[test]
fn packet_reservation_is_all_or_nothing() {
    let mut f = Fixture::valid();
    f.second();
    let c = credit(128);
    let before = c.snapshot();
    let error = c.reserve::<2>(&f.request(), &f.context()).unwrap_err();
    assert_eq!(
        error,
        StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })
    );
    assert_eq!(c.snapshot(), before);
}
#[test]
fn unused_and_prepared_leases_return_once() {
    let f = Fixture::valid();
    let c = credit(256);
    let before = c.snapshot();
    let lease = c.reserve::<1>(&f.request(), &f.context()).unwrap();
    assert_eq!(c.snapshot().metadata_used, 128);
    drop(lease);
    assert_eq!(c.snapshot(), before);
    let lease = c.reserve::<1>(&f.request(), &f.context()).unwrap();
    let stage = PreparedStage::prepare(lease).unwrap();
    assert_eq!(stage.capacity(0), 64);
    let pointer = stage.backing[0].as_ref().unwrap().pointer.as_ptr();
    let moved = stage.transfer();
    assert_eq!(moved.backing[0].as_ref().unwrap().pointer.as_ptr(), pointer);
    assert_eq!(c.snapshot().metadata_used, 128);
    drop(moved);
    assert_eq!(c.snapshot(), before);
}
#[derive(Default)]
struct FreeGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
    pointer: AtomicUsize,
    completed: AtomicUsize,
}
impl FreeGate {
    fn wait_for_free(&self) {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self.changed
            .wait_timeout_while(state, Duration::from_secs(10), |s| !s.0).unwrap();
        let reached = state.0;
        drop(state);
        assert!(!timeout.timed_out() && reached, "actual backing free was not reached");
    }
    fn release(&self) {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).1 = true;
        self.changed.notify_all();
    }
}
struct ReleaseFree(Arc<FreeGate>);
impl Drop for ReleaseFree {
    fn drop(&mut self) { self.0.release(); }
}
thread_local! {
    static FREE_CONTROL: std::cell::RefCell<Option<Arc<FreeGate>>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn before_backing_free(pointer: *const u8) {
    FREE_CONTROL.with(|control| {
        let control = control.borrow();
        let Some(gate) = control.as_ref() else { return; };
        gate.pointer.store(pointer as usize, Ordering::SeqCst);
        let mut state = gate.state.lock().unwrap();
        state.0 = true;
        gate.changed.notify_all();
        let (next, timeout) = gate.changed
            .wait_timeout_while(state, Duration::from_secs(10), |s| !s.1).unwrap();
        state = next;
        let released = state.1;
        drop(state);
        assert!(!timeout.timed_out() && released, "backing free gate was not released");
    });
}
fn guarded_join<T>(worker: std::thread::JoinHandle<T>) -> T {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !worker.is_finished() {
        assert!(std::time::Instant::now() < deadline, "worker completion timed out");
        std::thread::yield_now();
    }
    worker.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}
#[test]
fn discard_frees_all_packet_stages_after_actual_drop() {
    let f = Fixture::valid();
    let c = credit(128);
    let stage = PreparedStage::prepare(c.reserve::<1>(&f.request(), &f.context()).unwrap()).unwrap();
    let pointer = stage.backing[0].as_ref().unwrap().pointer.as_ptr() as usize;
    let gate = Arc::new(FreeGate::default());
    let release = ReleaseFree(gate.clone());
    let worker_gate = gate.clone();
    let worker = std::thread::spawn(move || {
        FREE_CONTROL.with(|control| *control.borrow_mut() = Some(worker_gate));
        drop(stage);
    });
    gate.wait_for_free();
    assert_eq!(gate.pointer.load(Ordering::SeqCst), pointer);
    assert_eq!(gate.completed.load(Ordering::SeqCst), 0);
    assert_eq!(c.snapshot().metadata_used, 128, "stage returned credit before freeing backing");
    let other = c.clone();
    let request = std::thread::spawn(move || {
        let f = Fixture::valid();
        other.reserve::<1>(&f.request(), &f.context()).map(|_| ())
    });
    assert_eq!(guarded_join(request),
        Err(StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })),
        "concurrent request spent live backing credit");
    drop(release);
    guarded_join(worker);
    assert_eq!(gate.completed.load(Ordering::SeqCst), pointer,
        "exact backing deallocation completed before final ledger observation");
    assert_eq!(c.snapshot().metadata_used, 0);
    assert_eq!(c.snapshot().slice_used, 4096);
}
#[test]
fn partial_prepare_keeps_credit_until_actual_backing_free() {
    let mut f = Fixture::valid();
    f.second();
    let c = credit(256);
    let before = c.snapshot();
    let lease = c.reserve::<2>(&f.request(), &f.context()).unwrap();
    let gate = Arc::new(FreeGate::default());
    let release = ReleaseFree(gate.clone());
    let worker_gate = gate.clone();
    let worker = std::thread::spawn(move || {
        FREE_CONTROL.with(|control| *control.borrow_mut() = Some(worker_gate));
        REFUSE_ALLOCATION.with(|r| r.set(Some(1)));
        PreparedStage::prepare(lease).map(|_| ())
    });
    gate.wait_for_free();
    let pointer = gate.pointer.load(Ordering::SeqCst);
    assert_ne!(pointer, 0, "row zero must have real allocator backing");
    assert_eq!(gate.completed.load(Ordering::SeqCst), 0);
    assert_eq!(c.metadata.stats().allocations, 1, "row zero allocated, row one refused");
    assert_eq!(c.snapshot().metadata_used, 256, "partial Prepare refunded before free");
    let other = c.clone();
    let contender = std::thread::spawn(move || {
        let f = Fixture::valid();
        other.reserve::<1>(&f.request(), &f.context()).map(|_| ())
    });
    assert_eq!(guarded_join(contender),
        Err(StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })));
    drop(release);
    assert_eq!(guarded_join(worker),
        Err(StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })));
    assert_eq!(gate.completed.load(Ordering::SeqCst), pointer);
    assert_eq!(c.snapshot(), before);
}
#[test]
fn inventory_e1_discard_unused_without_backing() {
    let mut f = Fixture::valid();
    f.lifecycle(3, 0);
    assert_eq!(validate_e1(&f.request(), &f.context()).unwrap().next, ReservationState::Refunded);
    let c = credit(128);
    let fresh = Fixture::valid();
    let lease = c.reserve::<1>(&fresh.request(), &fresh.context()).unwrap();
    drop(lease);
    assert_eq!(c.snapshot().metadata_used, 0);
}
#[test]
fn inventory_e1_discard_unused_with_backing() {
    let mut f = Fixture::valid();
    f.lifecycle(3, 0);
    f.actual_allocated = true;
    assert_eq!(validate_e1(&f.request(), &f.context()).unwrap().next, ReservationState::Refunded);
}
#[test]
fn inventory_e1_allocator_refuses_after_reservation() {
    let f = Fixture::valid();
    let c = credit(128);
    let lease = c.reserve::<1>(&f.request(), &f.context()).unwrap();
    REFUSE_ALLOCATION.with(|r| r.set(Some(0)));
    let result = PreparedStage::prepare(lease);
    REFUSE_ALLOCATION.with(|r| r.set(None));
    assert_eq!(
        result.unwrap_err(),
        StageError::Resource(ResourceExhausted { class: MetadataClass::StreamAssemblers })
    );
    assert_eq!(c.snapshot().metadata_used, 0);
}

thread_local! {static REFUSE_ALLOCATION: std::cell::Cell<Option<usize>>=const {std::cell::Cell::new(None)};}
pub(super) fn allocator_refuses(row: usize) -> bool {
    REFUSE_ALLOCATION.with(|r| r.get() == Some(row))
}

pub(super) fn after_backing_free(pointer: *const u8) {
    FREE_CONTROL.with(|control| {
        if let Some(gate) = control.borrow().as_ref() {
            gate.completed.store(pointer as usize, Ordering::SeqCst);
        }
    });
}

fn observe_accepting_cell(action: Action, state: ReservationState) {
    let f = Fixture::valid();
    let c = credit(256);
    let initial = c.snapshot();
    let lease = c.reserve::<1>(&f.request(), &f.context()).unwrap();
    assert_eq!(c.snapshot().metadata_used, 128);
    assert_eq!(c.snapshot().slice_used, initial.slice_used + 128);
    if action == Action::Reserve
        || action == Action::CancelUnused
        || (action == Action::Discard && state == ReservationState::Unused)
    {
        drop(lease);
    } else {
        let stage = PreparedStage::prepare(lease).unwrap();
        assert_eq!(stage.capacity(0), 64);
        assert_eq!(stage.backing[0].as_ref().unwrap().layout.align(), 8);
        let pointer = stage.backing[0].as_ref().unwrap().pointer;
        let destination = stage.transfer();
        assert_eq!(destination.backing[0].as_ref().unwrap().pointer, pointer);
        assert_eq!(c.snapshot().metadata_used, 128);
        drop(destination);
    }
    assert_eq!(c.snapshot(), initial);
}

fn completed_free(allocation: AllocationId, lease: LeaseId, consumed: bool) -> FreeWitness {
    // The borrowed validation seam observes genuine allocator completion. These
    // test-only registry keys never issue a production lease or byte allowance.
    let physical = StageAllocation::allocate(8, 8).unwrap();
    drop(physical);
    FreeWitness { allocation, lease, consumed }
}

#[test]
fn owner_cannot_substitute_unrelated_registered_allocation_and_lease() {
    let mut f = Fixture::valid();
    f.prepare();
    let mut unrelated = f.owners[0];
    unrelated.owner = OwnerId(99);
    unrelated.allocation = AllocationId(99);
    unrelated.lease = LeaseId(99);
    f.registry.push(unrelated);
    f.owners[0].allocation = unrelated.allocation;
    f.owners[0].lease = unrelated.lease;
    assert_eq!(validate_e1(&f.request(), &f.context()), Err(StageError::OwnerAllocationMismatch(0)));
    // A registry entry sharing the expected allocation cannot replace its observed lease.
    f.lifecycle(2, 1);
    f.registry[0].allocation = AllocationId(10);
    f.owners[0].allocation = AllocationId(10);
    assert_eq!(validate_e1(&f.request(), &f.context()), Err(StageError::LeaseMismatch(0)));
}
#[test]
fn prepare_validates_retained_metadata_and_raw_grants_without_second_debit() {
    let mut f = Fixture::valid();
    f.prepare();
    f.ledgers.metadata_limit = 128;
    f.ledgers.metadata_used = 128;
    f.ledgers.slice_limit = 128;
    f.ledgers.slice_used = 128;
    let mut context = f.context();
    context.reservation = Some((ReservationId(40), 64, 0));
    assert_eq!(validate_e1(&f.request(), &context),
        Err(StageError::ReservationChargeMismatch(Domain::Metadata)));
    context.reservation = Some((ReservationId(40), 128, 0));
    assert_eq!(validate_e1(&f.request(), &context),
        Ok(ValidatedE1 { metadata: 128, raw: 0, next: ReservationState::Allocated }));
    f.raw();
    f.ledgers.raw_limit = 64;
    f.ledgers.raw_used = 64;
    let mut context = f.context();
    context.reservation = Some((ReservationId(40), 0, 32));
    assert_eq!(validate_e1(&f.request(), &context),
        Err(StageError::ReservationChargeMismatch(Domain::RawBase)));
    context.reservation = Some((ReservationId(40), 0, 64));
    assert_eq!(validate_e1(&f.request(), &context),
        Ok(ValidatedE1 { metadata: 0, raw: 64, next: ReservationState::Allocated }));
}
#[test]
fn packet_number_and_target_usize_exact_equality_accept() {
    let mut f = Fixture::valid();
    f.binding.as_mut().unwrap().pn = (1u64 << 62) - 1;
    let mut context = f.context();
    context.binding.pn = (1u64 << 62) - 1;
    assert!(validate_e1(&f.request(), &context).is_ok());
    // Simulate a narrow target: each ledger value is representable, with the
    // maximum itself accepted and every sibling field internally consistent.
    f.ledgers.slice_limit = u32::MAX as u64;
    f.target_max = u32::MAX as u64;
    context = f.context();
    context.binding.pn = (1u64 << 62) - 1;
    assert!(validate_e1(&f.request(), &context).is_ok());
}

#[test]
fn owner_completeness_requires_every_expected_allocation() {
    let mut f = Fixture::valid();
    f.lifecycle(2, 1);
    let mut another = f.expected[0];
    another.allocation = AllocationId(99);
    another.lease = LeaseId(99);
    f.expected.push(another);
    assert_eq!(validate_e1(&f.request(), &f.context()),
        Err(StageError::OwnerMissing(OwnerId(20))));
}
