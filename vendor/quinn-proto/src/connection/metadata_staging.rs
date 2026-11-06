// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dormant packet-private reservations. No constructor or packet path selects this API.
//! Trusted observations must originate in physical storage, never packet claims.
use super::metadata_credit::{MetadataClass, MetadataCredit, ResourceExhausted};
use std::sync::{Arc, Mutex};
#[cfg(test)]
mod tests;
pub(crate) mod tls_contract;

// IDs are nominal, opaque registry keys. Zero encodes an absent/uninitialized key
// only at the borrowed validation seam; no key is interpreted as a byte allowance.
macro_rules! identity {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) struct $name(u64);
    };
}
identity!(ConnectionId);
identity!(CreditId);
identity!(ConfigurationId);
identity!(LayoutId);
identity!(AllocationId);
identity!(OwnerId);
identity!(LeaseId);
identity!(ReservationId);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    Connection,
    Credit,
    Configuration,
    Layout,
    Capacity,
    Count,
    ElementSize,
    Alignment,
    Charge,
    RowCount,
    BatchCharge,
    RawCharge,
    MetadataLimit,
    MetadataUsed,
    SliceLimit,
    SliceUsed,
    RawLimit,
    RawUsed,
    OwnerCount,
    Owner,
    Allocation,
    Lease,
    ExpectedCharge,
    ReservedCharge,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Domain {
    Metadata,
    Slice,
    RawBase,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Count {
    Rows,
    Owners,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arithmetic {
    AllocationProduct(usize),
    AllocationCharge(usize),
    MetadataSum,
    RawSum,
    MetadataOverlap,
    RawOverlap,
    SliceOverlap,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Action {
    Reserve,
    Prepare,
    Transfer,
    Discard,
    CancelUnused,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ReservationState {
    Unused,
    Allocated,
    Moved,
    Refunded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Role {
    StreamPayload,
    StreamWrapper,
    StreamHeap,
    ReceivePlan,
    StreamCompactionCopy,
    CryptoPayload,
    CryptoWrapper,
    CryptoHeap,
    CryptoReceivePlan,
    HistoryOld,
    HistoryReplacement,
    HistoryPlan,
    SentMap,
    FrameHeap,
    RetransmitOwner,
    SendDeque,
    SendRange,
    PendingDestination,
    AckHeap,
    AckScratch,
    AckPlan,
    LossScratch,
    LossPlan,
    EventDestination,
    CidDestination,
    ControlDestination,
    ControlPlan,
    TlsPlan,
    TlsOutputBacking,
    TlsOutputWrapper,
    PendingCrypto,
    KeyOwner,
    TerminalOwner,
}
impl Role {
    fn decode(tag: u8, row: usize) -> Result<Self, StageError> {
        const ROLES: &[Role] = &[
            Role::StreamPayload,
            Role::StreamWrapper,
            Role::StreamHeap,
            Role::ReceivePlan,
            Role::StreamCompactionCopy,
            Role::CryptoPayload,
            Role::CryptoWrapper,
            Role::CryptoHeap,
            Role::CryptoReceivePlan,
            Role::HistoryOld,
            Role::HistoryReplacement,
            Role::HistoryPlan,
            Role::SentMap,
            Role::FrameHeap,
            Role::RetransmitOwner,
            Role::SendDeque,
            Role::SendRange,
            Role::PendingDestination,
            Role::AckHeap,
            Role::AckScratch,
            Role::AckPlan,
            Role::LossScratch,
            Role::LossPlan,
            Role::EventDestination,
            Role::CidDestination,
            Role::ControlDestination,
            Role::ControlPlan,
            Role::TlsPlan,
            Role::TlsOutputBacking,
            Role::TlsOutputWrapper,
            Role::PendingCrypto,
            Role::KeyOwner,
            Role::TerminalOwner,
        ];
        ROLES.get(usize::from(tag)).copied().ok_or(StageError::InvalidRole(row))
    }
    fn assignment(self) -> (u8, MetadataClass) {
        use MetadataClass::{
            CryptoAssemblers, PendingAcks, PendingRetransmits, RetransmitOwners, SendRanges,
            SendSegments, SentFrameMetadata, SentRecords, StreamAssemblers, UnorderedHistory,
        };
        use Role::*;
        match self {
            StreamPayload | StreamWrapper | StreamHeap | ReceivePlan | StreamCompactionCopy => {
                (0, StreamAssemblers)
            }
            CryptoPayload | CryptoWrapper | CryptoHeap | CryptoReceivePlan | TlsPlan
            | TlsOutputBacking | TlsOutputWrapper | PendingCrypto => (0, CryptoAssemblers),
            HistoryOld | HistoryReplacement | HistoryPlan => (0, UnorderedHistory),
            SentMap => (0, SentRecords),
            FrameHeap => (0, SentFrameMetadata),
            RetransmitOwner => (0, RetransmitOwners),
            SendDeque => (0, SendSegments),
            SendRange => (0, SendRanges),
            AckHeap => (0, PendingAcks),
            AckScratch | AckPlan => (0, MetadataClass::AckScratch),
            LossScratch | LossPlan => (0, MetadataClass::LossScratch),
            PendingDestination | EventDestination | CidDestination | ControlDestination
            | ControlPlan => (0, PendingRetransmits),
            KeyOwner => (1, CryptoAssemblers),
            TerminalOwner => (1, PendingRetransmits),
        }
    }
    fn e1(self) -> bool {
        matches!(
            self,
            Self::StreamPayload
                | Self::StreamWrapper
                | Self::StreamHeap
                | Self::ReceivePlan
                | Self::CryptoPayload
                | Self::CryptoWrapper
                | Self::CryptoHeap
                | Self::CryptoReceivePlan
                | Self::HistoryReplacement
                | Self::HistoryPlan
                | Self::AckPlan
                | Self::LossPlan
                | Self::ControlPlan
                | Self::TlsPlan
                | Self::AckScratch
                | Self::LossScratch
                | Self::PendingDestination
                | Self::EventDestination
                | Self::CidDestination
                | Self::ControlDestination
                | Self::KeyOwner
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StageError {
    MissingBinding,
    EmptyBinding(Field),
    BindingMismatch(Field),
    InvalidSpace(u8),
    SpaceMismatch,
    PacketNumberOutOfRange,
    PacketNumberMismatch,
    GenerationMismatch,
    StageMismatch,
    InvalidPhase(u8),
    PhaseMismatch,
    TerminalFenced,
    MissingBatch,
    CountMismatch(Count),
    EmptyAllocationId(usize),
    DuplicateAllocation(usize),
    AllocationAlreadyLive(usize),
    InvalidRole(usize),
    RoleNotAllowed(usize),
    InvalidDomain(usize, u8),
    InvalidClass(usize, u8),
    RoleDomainMismatch(usize),
    RoleClassMismatch(usize),
    NotRepresentable(Field),
    LayoutMismatch(usize, Field),
    ArithmeticOverflow(Arithmetic),
    CapacityInsufficient(usize),
    CapacityObservationMismatch(usize),
    ChargeMismatch(usize),
    BatchChargeMismatch(Domain),
    InvalidLedger(Domain),
    Resource(ResourceExhausted),
    BaseEnvelopeExceeded,
    MissingOwners,
    EmptyOwnerField(Field, usize),
    DuplicateOwner(usize),
    UnknownAllocation(usize),
    LeaseMismatch(usize),
    DuplicateBackingCharge(usize),
    LeaseAliased(usize),
    InvalidOwnerLocation(usize, u8),
    OwnerLocationMismatch(usize),
    ReferenceCountMismatch(usize),
    OwnerMissing(OwnerId),
    OwnerUnexpected(OwnerId),
    FreeNotCompleted(usize),
    FreeWitnessMismatch(usize),
    FreeWitnessConsumed(usize),
    InvalidAction(u8),
    InvalidReservationState(u8),
    MissingReservation,
    ReservationMismatch,
    UnexpectedReservation,
    ReservationStateMismatch(Action, ReservationState),
    ExpectedChargeMismatch,
    ReservedChargeMismatch,
    MissingTransferTarget,
    TransferTargetMismatch,
    ReservationHasAllocation,
    ReservationConsumed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) connection: ConnectionId,
    pub(crate) credit: CreditId,
    pub(crate) configuration: ConfigurationId,
    pub(crate) layout: LayoutId,
    pub(crate) space_tag: u8,
    pub(crate) pn: u64,
    pub(crate) generation: u64,
    pub(crate) stage_id: u64,
    pub(crate) phase_tag: u8,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct AllocationRow {
    pub(crate) allocation: AllocationId,
    pub(crate) role: u8,
    pub(crate) domain_tag: u8,
    pub(crate) class_tag: u8,
    pub(crate) capacity: u64,
    pub(crate) count: u64,
    pub(crate) element_size: u64,
    pub(crate) alignment: u64,
    pub(crate) charge: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Batch<'a> {
    pub(crate) rows: &'a [AllocationRow],
    pub(crate) row_count: u64,
    pub(crate) batch_charge: u64,
    pub(crate) raw_charge: u64,
}
/// Borrowed allocator observation, not a token authorizing a refund.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FreeWitness {
    allocation: AllocationId,
    lease: LeaseId,
    consumed: bool,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct OwnerRecord {
    pub(crate) owner: OwnerId,
    pub(crate) allocation: AllocationId,
    pub(crate) lease: LeaseId,
    pub(crate) location_tag: u8,
    pub(crate) references: u64,
    pub(crate) free: Option<FreeWitness>,
    pub(crate) release_requested: bool,
}
/// Trusted physical observations supplied by storage adapters; no packet setters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AllocationObservation {
    pub(crate) allocation: AllocationId,
    pub(crate) capacity: u64,
    pub(crate) element_size: u64,
    pub(crate) alignment: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ledgers {
    pub(crate) metadata_limit: u64,
    pub(crate) metadata_used: u64,
    pub(crate) slice_limit: u64,
    pub(crate) slice_used: u64,
    pub(crate) raw_limit: u64,
    pub(crate) raw_used: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Context<'a> {
    pub(crate) binding: Binding,
    pub(crate) terminal: bool,
    pub(crate) target_max: u64,
    pub(crate) ledgers: Ledgers,
    pub(crate) observations: &'a [AllocationObservation],
    pub(crate) registry: &'a [OwnerRecord],
    pub(crate) expected_owners: &'a [OwnerRecord],
    pub(crate) reservation: Option<(ReservationId, u64, u64)>,
    pub(crate) target: Option<OwnerId>,
    pub(crate) actual_allocated: bool,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Request<'a> {
    pub(crate) binding: Option<Binding>,
    pub(crate) batch: Option<Batch<'a>>,
    pub(crate) owners: Option<&'a [OwnerRecord]>,
    pub(crate) owner_count: u64,
    pub(crate) action_tag: u8,
    pub(crate) reservation_state_tag: u8,
    pub(crate) reservation: Option<ReservationId>,
    pub(crate) target: Option<OwnerId>,
    pub(crate) expected_charge: u64,
    pub(crate) reserved_charge: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedE1 {
    metadata: u64,
    raw: u64,
    next: ReservationState,
}
fn representable(value: u64, field: Field, c: &Context<'_>) -> Result<(), StageError> {
    if value > c.target_max { Err(StageError::NotRepresentable(field)) } else { Ok(()) }
}
fn q(capacity: u64, row: usize) -> Result<u64, StageError> {
    capacity
        .checked_add(63)
        .map(|n| n & !63)
        .and_then(|n| n.checked_add(64))
        .ok_or(StageError::ArithmeticOverflow(Arithmetic::AllocationCharge(row)))
}
fn binding(r: &Request<'_>, c: &Context<'_>) -> Result<Binding, StageError> {
    use StageError::*;
    if c.terminal {
        return Err(TerminalFenced);
    }
    let b = r.binding.ok_or(MissingBinding)?;
    for (f, a, e) in [
        (Field::Connection, b.connection.0, c.binding.connection.0),
        (Field::Credit, b.credit.0, c.binding.credit.0),
        (Field::Configuration, b.configuration.0, c.binding.configuration.0),
        (Field::Layout, b.layout.0, c.binding.layout.0),
    ] {
        if a == 0 {
            return Err(EmptyBinding(f));
        }
        if a != e {
            return Err(BindingMismatch(f));
        }
    }
    if b.space_tag > 2 {
        return Err(InvalidSpace(b.space_tag));
    }
    if b.space_tag != c.binding.space_tag {
        return Err(SpaceMismatch);
    }
    if b.pn > ((1 << 62) - 1) {
        return Err(PacketNumberOutOfRange);
    }
    if b.pn != c.binding.pn {
        return Err(PacketNumberMismatch);
    }
    if b.generation != c.binding.generation {
        return Err(GenerationMismatch);
    }
    if b.stage_id != c.binding.stage_id {
        return Err(StageMismatch);
    }
    if b.phase_tag > 4 {
        return Err(InvalidPhase(b.phase_tag));
    }
    Ok(b)
}
fn validate_batch(batch: Option<Batch<'_>>, c: &Context<'_>) -> Result<(u64, u64), StageError> {
    use StageError::*;
    let b = batch.ok_or(MissingBatch)?;
    for (f, v) in [
        (Field::RowCount, b.row_count),
        (Field::BatchCharge, b.batch_charge),
        (Field::RawCharge, b.raw_charge),
        (Field::MetadataLimit, c.ledgers.metadata_limit),
        (Field::MetadataUsed, c.ledgers.metadata_used),
        (Field::SliceLimit, c.ledgers.slice_limit),
        (Field::SliceUsed, c.ledgers.slice_used),
        (Field::RawLimit, c.ledgers.raw_limit),
        (Field::RawUsed, c.ledgers.raw_used),
    ] {
        representable(v, f, c)?;
    }
    if usize::try_from(b.row_count).ok() != Some(b.rows.len()) {
        return Err(CountMismatch(Count::Rows));
    }
    let (mut metadata, mut raw) = (0u64, 0u64);
    for (i, r) in b.rows.iter().enumerate() {
        if r.allocation.0 == 0 {
            return Err(EmptyAllocationId(i));
        }
        if b.rows[..i].iter().any(|x| x.allocation == r.allocation) {
            return Err(DuplicateAllocation(i));
        }
        if c.registry.iter().any(|x| x.allocation == r.allocation) {
            return Err(AllocationAlreadyLive(i));
        }
        let role = Role::decode(r.role, i)?;
        if !role.e1() {
            return Err(RoleNotAllowed(i));
        }
        if r.domain_tag > 1 {
            return Err(InvalidDomain(i, r.domain_tag));
        }
        if r.class_tag > 11 {
            return Err(InvalidClass(i, r.class_tag));
        }
        let (domain, class) = role.assignment();
        if domain != r.domain_tag {
            return Err(RoleDomainMismatch(i));
        }
        if class as u8 != r.class_tag {
            return Err(RoleClassMismatch(i));
        }
        for (f, v) in [
            (Field::Capacity, r.capacity),
            (Field::Count, r.count),
            (Field::ElementSize, r.element_size),
            (Field::Alignment, r.alignment),
            (Field::Charge, r.charge),
        ] {
            representable(v, f, c)?;
        }
        let observed = c
            .observations
            .iter()
            .find(|x| x.allocation == r.allocation)
            .ok_or(CapacityObservationMismatch(i))?;
        if r.element_size == 0 || r.element_size != observed.element_size {
            return Err(LayoutMismatch(i, Field::ElementSize));
        }
        if !r.alignment.is_power_of_two() || r.alignment != observed.alignment {
            return Err(LayoutMismatch(i, Field::Alignment));
        }
        let product = r
            .count
            .checked_mul(r.element_size)
            .ok_or(ArithmeticOverflow(Arithmetic::AllocationProduct(i)))?;
        if product > r.capacity {
            return Err(CapacityInsufficient(i));
        }
        if r.capacity != observed.capacity {
            return Err(CapacityObservationMismatch(i));
        }
        let charge = if domain == 0 { q(r.capacity, i)? } else { r.capacity };
        if charge != r.charge {
            return Err(ChargeMismatch(i));
        }
        let (sum, error) = if domain == 0 {
            (&mut metadata, Arithmetic::MetadataSum)
        } else {
            (&mut raw, Arithmetic::RawSum)
        };
        *sum = sum.checked_add(charge).ok_or(ArithmeticOverflow(error))?;
    }
    if metadata != b.batch_charge {
        return Err(BatchChargeMismatch(Domain::Metadata));
    }
    if raw != b.raw_charge {
        return Err(BatchChargeMismatch(Domain::RawBase));
    }
    for (domain, used, limit, debit, overflow) in [
        (
            Domain::Metadata,
            c.ledgers.metadata_used,
            c.ledgers.metadata_limit,
            metadata,
            Arithmetic::MetadataOverlap,
        ),
        (Domain::RawBase, c.ledgers.raw_used, c.ledgers.raw_limit, raw, Arithmetic::RawOverlap),
        (
            Domain::Slice,
            c.ledgers.slice_used,
            c.ledgers.slice_limit,
            metadata,
            Arithmetic::SliceOverlap,
        ),
    ] {
        if used > limit {
            return Err(InvalidLedger(domain));
        }
        let total = used.checked_add(debit).ok_or(ArithmeticOverflow(overflow))?;
        if total > limit {
            if domain == Domain::RawBase {
                return Err(BaseEnvelopeExceeded);
            }
            let mut subtotal = used;
            for r in b.rows.iter().filter(|r| r.domain_tag == 0) {
                subtotal += r.charge;
                if subtotal > limit {
                    return Err(Resource(ResourceExhausted {
                        class: Role::decode(r.role, 0)?.assignment().1,
                    }));
                }
            }
        }
    }
    Ok((metadata, raw))
}
fn validate_owners(r: &Request<'_>, c: &Context<'_>) -> Result<(), StageError> {
    use StageError::*;
    let owners = r.owners.ok_or(MissingOwners)?;
    representable(r.owner_count, Field::OwnerCount, c)?;
    if usize::try_from(r.owner_count).ok() != Some(owners.len()) {
        return Err(CountMismatch(Count::Owners));
    }
    for (i, o) in owners.iter().enumerate() {
        for (f, v) in [
            (Field::Owner, o.owner.0),
            (Field::Allocation, o.allocation.0),
            (Field::Lease, o.lease.0),
        ] {
            if v == 0 {
                return Err(EmptyOwnerField(f, i));
            }
        }
        for previous in &owners[..i] {
            if previous.owner == o.owner {
                return Err(DuplicateOwner(i));
            }
            if previous.allocation == o.allocation && previous.lease != o.lease {
                return Err(DuplicateBackingCharge(i));
            }
            if previous.allocation != o.allocation && previous.lease == o.lease {
                return Err(LeaseAliased(i));
            }
        }
    }
    for (i, o) in owners.iter().enumerate() {
        let known = c
            .registry
            .iter()
            .chain(c.expected_owners)
            .find(|x| x.allocation == o.allocation)
            .ok_or(UnknownAllocation(i))?;
        if known.lease != o.lease {
            return Err(LeaseMismatch(i));
        }
        if o.location_tag > 2 {
            return Err(InvalidOwnerLocation(i, o.location_tag));
        }
        let expected = c
            .expected_owners
            .iter()
            .find(|x| x.owner == o.owner)
            .ok_or(OwnerUnexpected(o.owner))?;
        if o.location_tag != expected.location_tag {
            return Err(OwnerLocationMismatch(i));
        }
        if o.references != expected.references {
            return Err(ReferenceCountMismatch(i));
        }
        if o.release_requested && o.free.is_none() {
            return Err(FreeNotCompleted(i));
        }
        if let Some(free) = o.free {
            if free.allocation != o.allocation || free.lease != o.lease {
                return Err(FreeWitnessMismatch(i));
            }
            if free.consumed {
                return Err(FreeWitnessConsumed(i));
            }
        }
    }
    for expected in c.expected_owners {
        if !owners.iter().any(|o| o.owner == expected.owner) {
            return Err(OwnerMissing(expected.owner));
        }
    }
    Ok(())
}
/// Validate a borrowed packet-private contract without allocation, publication or TLS.
pub(crate) fn validate_e1(r: &Request<'_>, c: &Context<'_>) -> Result<ValidatedE1, StageError> {
    use StageError::*;
    let b = binding(r, c)?;
    let action = match r.action_tag {
        0 => Action::Reserve,
        1 => Action::Prepare,
        2 => Action::Transfer,
        3 => Action::Discard,
        4 => Action::CancelUnused,
        t => return Err(InvalidAction(t)),
    };
    let state = match r.reservation_state_tag {
        0 => ReservationState::Unused,
        1 => ReservationState::Allocated,
        2 => ReservationState::Moved,
        3 => ReservationState::Refunded,
        t => return Err(InvalidReservationState(t)),
    };
    if matches!(state, ReservationState::Moved | ReservationState::Refunded) {
        return Err(ReservationConsumed);
    }
    if action == Action::Reserve {
        if r.reservation.is_some() {
            return Err(UnexpectedReservation);
        }
    } else {
        let reservation = r.reservation.ok_or(MissingReservation)?;
        if Some(reservation) != c.reservation.map(|v| v.0) {
            return Err(ReservationMismatch);
        }
    }
    let allowed = match action {
        Action::Transfer => b.phase_tag == 1,
        Action::Discard => b.phase_tag <= 1,
        _ => b.phase_tag == 0,
    };
    if !allowed {
        return Err(PhaseMismatch);
    }
    let next = match (action, state) {
        (Action::Reserve, ReservationState::Unused) => ReservationState::Unused,
        (Action::Prepare, ReservationState::Unused) => ReservationState::Allocated,
        (Action::Transfer, ReservationState::Allocated) => ReservationState::Moved,
        (Action::Discard, _) | (Action::CancelUnused, ReservationState::Unused) => {
            ReservationState::Refunded
        }
        _ => return Err(ReservationStateMismatch(action, state)),
    };
    let (metadata, raw) = if matches!(action, Action::Reserve | Action::Prepare) {
        validate_batch(r.batch, c)?
    } else {
        let (_, metadata, raw) = c.reservation.ok_or(MissingReservation)?;
        (metadata, raw)
    };
    for (f, v) in
        [(Field::ExpectedCharge, r.expected_charge), (Field::ReservedCharge, r.reserved_charge)]
    {
        representable(v, f, c)?;
    }
    if r.expected_charge != metadata {
        return Err(ExpectedChargeMismatch);
    }
    if r.reserved_charge != metadata {
        return Err(ReservedChargeMismatch);
    }
    if matches!(action, Action::Prepare | Action::Transfer | Action::Discard) {
        validate_owners(r, c)?;
    }
    if action == Action::Transfer {
        let target = r.target.ok_or(MissingTransferTarget)?;
        if Some(target) != c.target {
            return Err(TransferTargetMismatch);
        }
    }
    if action == Action::CancelUnused && c.actual_allocated {
        return Err(ReservationHasAllocation);
    }
    Ok(ValidatedE1 { metadata, raw, next })
}

/// One lock owns the slice/base suballocation ledger. Lock order is this, then metadata.
/// The base grant is already part of slice_used and is never refunded here.
#[derive(Debug)]
pub(crate) struct StageCredit {
    metadata: Arc<MetadataCredit>,
    state: Mutex<Ledgers>,
}
impl StageCredit {
    pub(crate) fn new(metadata: Arc<MetadataCredit>, ledgers: Ledgers) -> Arc<Self> {
        Arc::new(Self { metadata, state: Mutex::new(ledgers) })
    }
    pub(crate) fn snapshot(&self) -> Ledgers {
        let state=self.state.lock().unwrap();
        let mut s = *state;
        let metadata_used = self.metadata.stats().used as u64;
        s.slice_used = s
            .slice_used
            .checked_sub(s.metadata_used)
            .and_then(|base| base.checked_add(metadata_used))
            .expect("trusted slice must contain its metadata debit");
        s.metadata_used = metadata_used;
        s
    }
    /// Reserve the whole batch with no prefix debit, plan allocation, or raw regrant.
    /// N is the actual inline plan storage supplied by the adapter, never a packet cap.
    pub(crate) fn reserve<const N: usize>(
        self: &Arc<Self>,
        request: &Request<'_>,
        context: &Context<'_>,
    ) -> Result<StageLease<N>, StageError> {
        let mut state = self.state.lock().unwrap();
        self.metadata.reserve_stage_batch(|used, limit, exhausted| {
            let mut c = *context;
            c.ledgers = *state;
            c.ledgers.slice_used = c
                .ledgers
                .slice_used
                .checked_sub(c.ledgers.metadata_used)
                .and_then(|base| base.checked_add(used as u64))
                .ok_or(StageError::ArithmeticOverflow(Arithmetic::SliceOverlap))?;
            c.ledgers.metadata_used = used as u64;
            c.ledgers.metadata_limit = limit as u64;
            let validated = validate_e1(request, &c)?;
            // Only the Reserve entrypoint creates a fresh lease; all later transitions
            // consume the move-only lease rather than re-debiting validated records.
            assert_eq!(
                request.action_tag,
                Action::Reserve as u8,
                "reserve entrypoint requires a reserve operation"
            );
            let batch = request.batch.ok_or(StageError::MissingBatch)?;
            assert_eq!(batch.rows.len(), N, "adapter must supply complete inline plan storage");
            let mut capacities = [0; N];
            let mut classes = [MetadataClass::StreamAssemblers; N];
            let mut alignments = [1; N];
            for (i, row) in batch.rows.iter().enumerate() {
                capacities[i] = usize::try_from(row.capacity)
                    .map_err(|_| StageError::NotRepresentable(Field::Capacity))?;
                classes[i] = Role::decode(row.role, i)?.assignment().1;
                alignments[i] = usize::try_from(row.alignment)
                    .map_err(|_| StageError::NotRepresentable(Field::Alignment))?;
            }
            let metadata = usize::try_from(validated.metadata)
                .map_err(|_| StageError::NotRepresentable(Field::BatchCharge))?;
            if exhausted {
                return Err(StageError::Resource(ResourceExhausted {
                    class: classes.first().copied().unwrap_or(MetadataClass::StreamAssemblers),
                }));
            }
            state.slice_used = c.ledgers.slice_used + validated.metadata;
            state.metadata_used = c.ledgers.metadata_used + validated.metadata;
            state.raw_used += validated.raw;
            Ok((
                metadata,
                StageLease {
                    credit: self.clone(),
                    metadata: validated.metadata,
                    raw: validated.raw,
                    capacities,
                    classes,
                    alignments,
                },
            ))
        })
    }
}
/// Move-only debit. Keeping it outside the backing ensures refund follows allocator free.
#[derive(Debug)]
pub(crate) struct StageLease<const N: usize> {
    credit: Arc<StageCredit>,
    metadata: u64,
    raw: u64,
    capacities: [usize; N],
    classes: [MetadataClass; N],
    alignments: [usize; N],
}
impl<const N: usize> Drop for StageLease<N> {
    fn drop(&mut self) {
        let mut s = self.credit.state.lock().unwrap();
        self.credit.metadata.release_stage_batch(self.metadata as usize);
        s.slice_used -= self.metadata;
        s.metadata_used -= self.metadata;
        s.raw_used -= self.raw;
    }
}
/// A unique stage owner; transfer moves this entire value without refund/recharge.
/// No owning view escapes. Borrowed views cannot outlive the one batch lease.
#[derive(Debug)]
pub(crate) struct PreparedStage<const N: usize> {
    backing: [Option<StageAllocation>; N],
    lease: Option<StageLease<N>>,
}
impl<const N: usize> PreparedStage<N> {
    pub(crate) fn prepare(lease: StageLease<N>) -> Result<Self, StageError> {
        let mut backing = std::array::from_fn(|_| None);
        for i in 0..N {
            #[cfg(test)]
            if tests::allocator_refuses(i) {
                // Free any earlier allocations before the debit can be returned.
                drop(backing);
                return Err(StageError::Resource(lease.credit.metadata.fail(lease.classes[i])));
            }
            let Some(allocation) =
                StageAllocation::allocate(lease.capacities[i], lease.alignments[i])
            else {
                drop(backing);
                return Err(StageError::Resource(lease.credit.metadata.fail(lease.classes[i])));
            };
            backing[i] = Some(allocation);
            lease.credit.metadata.allocated();
        }
        Ok(Self { backing, lease: Some(lease) })
    }
    pub(crate) fn capacity(&self, row: usize) -> usize {
        self.backing[row].as_ref().unwrap().layout.size()
    }
    pub(crate) fn transfer(self) -> Self {
        self
    }
}
impl<const N: usize> Drop for PreparedStage<N> {
    fn drop(&mut self) {
        for backing in &mut self.backing {
            #[cfg(test)]
            tests::before_backing_free(backing.as_ref().unwrap().pointer.as_ptr());
            drop(backing.take());
        }
        drop(self.lease.take());
    }
}

/// Physical layout allocation, kept separate from its debit. No owning aliases exist.
#[derive(Debug)]
struct StageAllocation {
    pointer: std::ptr::NonNull<u8>,
    layout: std::alloc::Layout,
}
// SAFETY: the allocation is uniquely owned, has no thread-local allocator state,
// and exports no references. Moving it changes neither pointer nor allocator.
unsafe impl Send for StageAllocation {}
impl StageAllocation {
    fn allocate(capacity: usize, alignment: usize) -> Option<Self> {
        let layout = std::alloc::Layout::from_size_align(capacity, alignment).ok()?;
        let pointer = if capacity == 0 {
            // A zero-sized request has no allocator allocation or free operation.
            std::ptr::NonNull::new(alignment as *mut u8)?
        } else {
            // SAFETY: Layout is nonzero and valid; null is handled without dereference.
            std::ptr::NonNull::new(unsafe { std::alloc::alloc(layout) })?
        };
        Some(Self { pointer, layout })
    }
}
impl Drop for StageAllocation {
    fn drop(&mut self) {
        if self.layout.size() != 0 {
            // SAFETY: this exact pointer/Layout pair was allocated above; ownership
            // is unique and this destructor runs once, before the enclosing lease.
            unsafe { std::alloc::dealloc(self.pointer.as_ptr(), self.layout) };
            #[cfg(test)]
            tests::after_backing_free(self.pointer.as_ptr());
        }
    }
}
