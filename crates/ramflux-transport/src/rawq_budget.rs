// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant resource planning. No listener, socket, task or dependency is constructed here.
//! Runtime integration must obtain all allocation certificates before using these ceilings.

mod census;
mod metadata;
mod reservation;
pub use census::{
    AllocationCertificate, AllocationClass, AllocationLayout, CENSUS, CensusEntry, Pool,
};
pub use metadata::{MetadataBudget, MetadataCharge, NoProgressDeadline};
pub use reservation::{HostReservation, reserve_host_slice};

/// Configuration or reservation refusal, always before runtime construction.
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    /// Invalid, impossible or over-budget configuration.
    #[error("invalid QUIC budget: {0}")]
    Invalid(&'static str),
    /// Checked arithmetic or platform conversion failed.
    #[error("QUIC budget arithmetic overflow")]
    Overflow,
    /// Host ledger cannot be safely read or updated.
    #[error("QUIC host reservation I/O: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, BudgetError>;
pub(crate) const KIB: u64 = 1024;
pub(crate) const MIB: u64 = 1024 * KIB;
/// Completely charged fixed endpoint slab.
pub const ENDPOINT_BYTES: u64 = 4 * MIB;
/// E components: scratch, receive/send kernel caps, routes, bookkeeping, runtime, residual.
pub const ENDPOINT_COMPONENTS: [u64; 7] =
    [128 * KIB, 512 * KIB, 512 * KIB, 512 * KIB, 512 * KIB, MIB, 896 * KIB];

pub(crate) fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(BudgetError::Overflow)
}
pub(crate) fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or(BudgetError::Overflow)
}
fn sum(values: &[u64]) -> Result<u64> {
    values.iter().try_fold(0, |a, &b| add(a, b))
}
/// Charge actual backing capacity, including alignment and allocation header.
///
/// # Errors
/// Refuses arithmetic overflow and charges that cannot fit the platform.
pub fn allocation_charge(capacity: u64) -> Result<usize> {
    let rounded = add(capacity, 63)? & !63;
    platform_size(add(rounded, 64)?, usize::MAX as u64)
}
pub(crate) fn platform_size(value: u64, maximum: u64) -> Result<usize> {
    if value > maximum {
        return Err(BudgetError::Overflow);
    }
    usize::try_from(value).map_err(|_| BudgetError::Overflow)
}

fn slab_and_frame(slice: u64, frame: Option<u64>) -> Result<(u64, u64)> {
    let base = slice / 512;
    if base == 0 {
        return Err(BudgetError::Invalid("zero slab"));
    }
    let z = (1u64 << base.ilog2()).min(MIB);
    if z < 128 * KIB {
        return Err(BudgetError::Invalid("minimum slab"));
    }
    let frame = frame.unwrap_or(z);
    if frame == 0 || frame > z {
        return Err(BudgetError::Invalid("frame override"));
    }
    Ok((z, frame))
}

fn owner_cost(
    crypto: u64,
    window: u64,
    delta_unit: u64,
    streams: u64,
    raw: u64,
    control: u64,
) -> Result<u64> {
    sum(&[
        crypto,
        window,
        window,
        delta_unit,
        256 * KIB,
        mul(streams, 4 * KIB)?,
        raw,
        control,
        2048,
        4 * 512,
        8 * 4 * KIB,
        64 * KIB,
    ])
}

/// Each enabled runtime endpoint needs a separate listener slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ListenerRole {
    Mesh,
    Gateway,
}
/// Frozen listener identity. A second runtime must use a different identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerRequest {
    /// Canonical service/runtime identity, at most 128 ASCII bytes.
    pub id: String,
    /// Transport role.
    pub role: ListenerRole,
    /// Explicit slice; either every listener supplies one or none does.
    pub slice: Option<u64>,
    /// Optional smaller frame ceiling. Other ceilings cannot be overridden.
    pub frame_ceiling: Option<u64>,
}

/// All scalar ceilings derived from one listener slice, in bytes unless named otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Listener slice b.
    pub slice: u64,
    /// z and retained frame/conversion capacities F/A.
    pub z: u64,
    /// Crypto and Incoming retained caps C/I.
    pub crypto: u64,
    /// Receive and send windows (each).
    pub window: u64,
    /// Shared tracked-record credit, including two ACK-only records; builders count.
    pub sent_records: u64,
    /// PTO records per round (`S_pto`), above ordinary shared credit.
    pub s_pto: u64,
    /// Consecutive PTO overshoot rounds (`K_pto`).
    pub k_pto: u64,
    /// Fixed ACK-only allowance inside ordinary credit; ACK service never blocks.
    pub ack_only_records: u64,
    /// Independent no-progress policy (`T_np`), reset only by record-freeing ACKs.
    pub t_np: NoProgressDeadline,
    /// Total record backing including `S_pto`*`K_pto` overshoot.
    pub tracked_records: u64,
    /// Item-3 metadata capacities and charged shapes.
    pub metadata: MetadataBudget,
    /// Exact `DeltaUnit` added to the original Unit before deriving N.
    pub delta_unit: u64,
    /// Sent-record backing allowance before the factor two.
    pub sent_record_bytes: u64,
    /// Steady ACK ranges per space; transient insertion also reserves one entry.
    pub ack_ranges_per_space: u64,
    /// ACK-range backing allowance across all packet-number spaces.
    pub ack_range_bytes: u64,
    /// Complete doubled window pool: both payload windows and packet/range metadata.
    pub window_pool: u64,
    /// Per-stream receive window.
    pub stream_window: u64,
    /// Bidirectional streams per owner; unidirectional streams are disabled.
    pub streams: u64,
    /// Actual admitted frame ceiling (at most z).
    pub frame: u64,
    /// Authentication/conversion buffer A.
    pub auth: u64,
    /// Output buffer O.
    pub output: u64,
    /// Raw items per owner.
    pub raw_items: u64,
    /// Ordinary control items per owner.
    pub control_items: u64,
    /// Raw payload and metadata pool.
    pub raw: u64,
    /// Control payload and metadata pool.
    pub control: u64,
    /// Full retained owner cost.
    pub owner: u64,
    /// Initial datagram and Incoming cost.
    pub incoming: u64,
    /// Stateless response cost.
    pub response: u64,
    /// Gateway pre-auth cost (zero for mesh).
    pub preauth: u64,
    /// Complete unit cost.
    pub unit: u64,
    /// Final owners, Incoming slots, response slots and total protocol entries.
    pub owners: u64,
    /// Total/per-source lifetime, handshake, ready, unframed and preauth limits.
    pub phases: [(u64, u64); 5],
    /// Primary, alternative and idle source arena records.
    pub sources: [u64; 3],
    /// Active CIDs per owner.
    pub active_cids: u64,
    /// Endpoint raw payload/items and control payload/items.
    pub queues: [u64; 4],
    /// Stateless datagram payload/items.
    pub responses: [u64; 2],
    /// Checked full envelope, including layout allowance.
    pub derived: u64,
}
impl Profile {
    /// Derive ceilings using checked arithmetic; this does not certify any runtime.
    ///
    /// # Errors
    /// Refuses impossible minima, over-budget layouts and platform conversion overflow.
    pub fn derive(slice: u64, role: ListenerRole, frame: Option<u64>) -> Result<Self> {
        let (z, frame) = slab_and_frame(slice, frame)?;
        let crypto = z / 4;
        let window = mul(4, z)?;
        let sent_records = add(window / 600, u64::from(!window.is_multiple_of(600)))?;
        let streams = (z / (32 * KIB)).min(64);
        let s_pto = 2;
        let k_pto = 3;
        let ack_only_records = 2;
        let t_np = NoProgressDeadline { pto_multiple: 3, minimum_ms: 10_000 };
        let tracked_records = add(sent_records, mul(s_pto, k_pto)?)?;
        let sent_record_bytes = mul(tracked_records, 256)?;
        let ack_ranges_per_space = 64;
        let ack_range_bytes = mul(mul(3, add(ack_ranges_per_space, 1)?)?, 32)?;
        let metadata = MetadataBudget::derive(tracked_records, streams)?;
        let delta_unit = sum(&[sent_record_bytes, ack_range_bytes, metadata.total])?;
        let window_pool = mul(2, add(mul(2, window)?, delta_unit)?)?;
        let output = (z / 4).min(64 * KIB);
        let raw_items = (z / (4 * KIB)).min(64);
        let control_items = (crypto / 512).min(256);
        let raw = add(z, mul(256, raw_items)?)?;
        let control = add(crypto, mul(512, control_items)?)?;
        let owner = owner_cost(crypto, window, delta_unit, streams, raw, control)?;
        let incoming = sum(&[65_535, crypto, 1024])?;
        let response = 65_536 + 512;
        let gateway = role == ListenerRole::Gateway;
        // A lower frame override does not reduce the certified backing pools.
        let preauth = if gateway { sum(&[mul(4, z)?, z, output, 8, 64 * KIB])? } else { 0 };
        let unit = sum(&[incoming, owner, response, preauth])?;
        let available =
            slice.checked_sub(ENDPOINT_BYTES).ok_or(BudgetError::Invalid("endpoint slab"))?;
        let owners = (available / mul(2, unit)?).min(if gateway { 128 } else { 64 });
        if owners < 2 {
            return Err(BudgetError::Invalid("minimum owners"));
        }
        let derived = add(ENDPOINT_BYTES, mul(mul(2, owners)?, unit)?)?;
        if derived > slice {
            return Err(BudgetError::Invalid("derived envelope"));
        }
        let h = owners.min(64);
        let r = h.min(16);
        let u = if gateway { owners } else { 0 };
        let profile = Self {
            slice,
            z,
            crypto,
            window,
            sent_records,
            s_pto,
            k_pto,
            ack_only_records,
            t_np,
            tracked_records,
            metadata,
            delta_unit,
            sent_record_bytes,
            ack_ranges_per_space,
            ack_range_bytes,
            window_pool,
            stream_window: z,
            streams,
            frame,
            auth: z,
            output,
            raw_items,
            control_items,
            raw,
            control,
            owner,
            incoming,
            response,
            preauth,
            unit,
            owners,
            phases: [
                (owners, owners.min(8)),
                (h, h.min(4)),
                (r, r.min(4)),
                (u, u.min(4)),
                (u, u.min(4)),
            ],
            sources: [owners, mul(2, owners)?, owners],
            active_cids: 8,
            queues: [
                mul(owners, z)?,
                mul(owners, raw_items)?,
                mul(owners, crypto)?,
                mul(owners, control_items)?,
            ],
            responses: [mul(owners, 65_536)?, owners],
            derived,
        };
        profile.validate_platform()?;
        Ok(profile)
    }
    fn validate_platform(&self) -> Result<()> {
        for value in [
            self.slice,
            self.z,
            self.crypto,
            self.window,
            self.window_pool,
            self.owner,
            self.incoming,
            self.response,
            self.preauth,
            self.unit,
            self.derived,
        ]
        .into_iter()
        .chain(self.queues)
        .chain(self.responses)
        {
            platform_size(value, usize::MAX as u64)?;
        }
        Ok(())
    }
}

/// Immutable process listener list and one host budget; getters cannot change admission.
#[derive(Debug)]
pub struct FrozenBudget {
    ram: u64,
    host: u64,
    reserved: u64,
    listeners: Vec<(String, ListenerRole, Profile)>,
    digest: [u8; 32],
}
impl FrozenBudget {
    /// Read physical RAM exactly once and freeze all identities and ceilings.
    /// A platform adapter must return physical RAM bytes, never available memory.
    ///
    /// # Errors
    /// Refuses RAM-read failure, invalid host limits, duplicate identities, mixed slice
    /// modes, impossible profiles and checked sums above the host budget.
    pub fn prepare(
        read_ram: impl FnOnce() -> Result<u64>,
        explicit_host: Option<u64>,
        mut requests: Vec<ListenerRequest>,
    ) -> Result<Self> {
        let ram = read_ram()?;
        let maximum = ram / 4;
        let host = explicit_host.unwrap_or(maximum);
        if ram == 0 || host == 0 || host > maximum {
            return Err(BudgetError::Invalid("host limit"));
        }
        if requests.is_empty() || requests.len() > 64 {
            return Err(BudgetError::Invalid("listener count"));
        }
        requests.sort_by(|a, b| a.id.cmp(&b.id));
        if requests.windows(2).any(|w| w[0].id == w[1].id)
            || requests.iter().any(|r| r.id.is_empty() || r.id.len() > 128 || !r.id.is_ascii())
        {
            return Err(BudgetError::Invalid("listener identity"));
        }
        let explicit = requests[0].slice.is_some();
        if requests.iter().any(|r| r.slice.is_some() != explicit) {
            return Err(BudgetError::Invalid("mixed slices"));
        }
        let default = host / u64::try_from(requests.len()).map_err(|_| BudgetError::Overflow)?;
        // Sum every slice before comparing against B, so overflow at this entrypoint
        // is distinguished from an individually over-budget but representable sum.
        let reserved = requests
            .iter()
            .try_fold(0, |total, request| add(total, request.slice.unwrap_or(default)))?;
        if reserved > host {
            return Err(BudgetError::Invalid("listener sum"));
        }
        let mut listeners = Vec::with_capacity(requests.len());
        let mut digest = blake3::Hasher::new();
        digest.update(b"rawq-budget-v2-r6");
        for component in ENDPOINT_COMPONENTS {
            digest.update(&component.to_le_bytes());
        }
        digest.update(&ram.to_le_bytes());
        digest.update(&host.to_le_bytes());
        for request in requests {
            let slice = request.slice.unwrap_or(default);
            if slice == 0 {
                return Err(BudgetError::Invalid("listener sum"));
            }
            let profile = Profile::derive(slice, request.role, request.frame_ceiling)?;
            digest.update(
                &u64::try_from(request.id.len()).map_err(|_| BudgetError::Overflow)?.to_le_bytes(),
            );
            digest.update(request.id.as_bytes());
            digest.update(&[u8::from(request.role == ListenerRole::Gateway)]);
            for value in [
                profile.slice,
                profile.z,
                profile.crypto,
                profile.window,
                profile.sent_records,
                profile.s_pto,
                profile.k_pto,
                profile.ack_only_records,
                profile.t_np.pto_multiple,
                profile.t_np.minimum_ms,
                profile.tracked_records,
                profile.delta_unit,
                profile.sent_record_bytes,
                profile.ack_ranges_per_space,
                profile.ack_range_bytes,
                profile.window_pool,
                profile.stream_window,
                profile.streams,
                profile.frame,
                profile.auth,
                profile.output,
                profile.raw_items,
                profile.control_items,
                profile.raw,
                profile.control,
                profile.owner,
                profile.incoming,
                profile.response,
                profile.preauth,
                profile.unit,
                profile.owners,
                profile.active_cids,
                profile.derived,
            ]
            .into_iter()
            .chain(profile.metadata.scalars())
            .chain(profile.phases.into_iter().flat_map(|(total, source)| [total, source]))
            .chain(profile.sources)
            .chain(profile.queues)
            .chain(profile.responses)
            {
                digest.update(&value.to_le_bytes());
            }
            listeners.push((request.id, request.role, profile));
        }
        Ok(Self { ram, host, reserved, listeners, digest: *digest.finalize().as_bytes() })
    }
    /// The single host B.
    #[must_use]
    pub fn host_bytes(&self) -> u64 {
        self.host
    }
    /// Reserved process slice, including unused profile headroom.
    #[must_use]
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved
    }
    /// Canonical frozen listeners (runtime variants occupy separate entries).
    #[must_use]
    pub fn listeners(&self) -> &[(String, ListenerRole, Profile)] {
        &self.listeners
    }
    /// Frozen effective configuration digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
