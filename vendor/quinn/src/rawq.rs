// SPDX-License-Identifier: MIT OR Apache-2.0
//! Credits held by packet backing, independently of queue dequeue or protocol retirement.
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

/// Dormant per-endpoint raw packet allocation ceilings.
#[derive(Clone, Copy, Debug)]
pub struct PacketQueueLimits {
    /// Maximum number of indexed protocol owners.
    pub owners: usize,
    /// Shared established-packet backing ceiling (at most owners times the owner ceiling).
    pub bytes_total: usize,
    /// Shared established-packet item ceiling.
    pub items_total: usize,
    /// Charged allocation bytes per owner.
    pub bytes_per_owner: usize,
    /// Retained packet items per owner.
    pub items_per_owner: usize,
    /// Aggregate charged bytes per normalized source.
    pub bytes_per_source: usize,
    /// Aggregate packet items per normalized source.
    pub items_per_source: usize,
}

/// Fixed, typed refusal classes for bounded packet admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum RawQueueRefusal {
    /// Owner backing byte ceiling.
    OwnerBytes,
    /// Owner packet-item ceiling.
    OwnerItems,
    /// Normalized-source backing ceiling.
    SourceBytes,
    /// Normalized-source item ceiling.
    SourceItems,
    /// Shared endpoint backing ceiling.
    EndpointBytes,
    /// Shared endpoint item ceiling.
    EndpointItems,
    /// No bounded protocol-owner slot is available.
    OwnerSlotsFull,
    /// All bounded source records are retained.
    SourceSlotsFull,
    /// An invalid owner slot was supplied.
    InvalidOwner,
    /// Allocation charge arithmetic overflowed.
    ChargeOverflow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    Established(usize),
    Incoming,
}
impl From<usize> for Owner {
    fn from(slot: usize) -> Self {
        Self::Established(slot)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Count {
    pub(crate) bytes: usize,
    pub(crate) items: usize,
}
#[derive(Debug, Default)]
struct Source {
    key: Option<IpAddr>,
    count: Count,
}
#[derive(Debug)]
struct State {
    owners: Box<[Count]>,
    incoming: Count,
    sources: Box<[Source]>,
    total: Count,
    allocations: u64,
    refusals: u64,
    refusal_class: [u64; 10],
    established: Count,
}
#[derive(Debug)]
pub(crate) struct Pool {
    limits: PacketQueueLimits,
    state: Mutex<State>,
}
#[derive(Debug)]
pub(crate) struct Credit {
    pool: Arc<Pool>,
    owner: Owner,
    source: usize,
    bytes: usize,
}

impl Pool {
    pub(crate) fn new(limits: PacketQueueLimits) -> Result<Arc<Self>, &'static str> {
        if limits.owners == 0
            || limits.owners > 128
            || limits.bytes_total == 0
            || limits.items_total == 0
            || limits
                .owners
                .checked_mul(limits.bytes_per_owner)
                .is_none_or(|n| limits.bytes_total > n)
            || limits
                .owners
                .checked_mul(limits.items_per_owner)
                .is_none_or(|n| limits.items_total > n)
            || limits.bytes_per_owner == 0
            || limits.items_per_owner == 0
            || limits.bytes_per_source == 0
            || limits.items_per_source == 0
            || limits.owners.checked_mul(limits.bytes_per_owner).is_none()
            || limits.owners.checked_mul(limits.items_per_owner).is_none()
            || limits.owners.checked_mul(4).is_none()
            || limits
                .bytes_per_owner
                .checked_add(65536)
                .and_then(|n| n.checked_mul(limits.owners))
                .is_none()
            || limits
                .items_per_owner
                .checked_add(1)
                .and_then(|n| n.checked_mul(limits.owners))
                .is_none()
        {
            return Err("invalid packet queue limits");
        }
        Ok(Arc::new(Self {
            limits,
            state: Mutex::new(State {
                owners: vec![Count::default(); limits.owners].into_boxed_slice(),
                incoming: Count::default(),
                sources: (0..limits.owners * 4)
                    .map(|_| Source::default())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                total: Count::default(),
                allocations: 0,
                refusals: 0,
                refusal_class: [0; 10],
                established: Count::default(),
            }),
        }))
    }
    pub(crate) fn owner_capacity(&self) -> usize {
        self.limits.owners
    }
    pub(crate) fn owner_free(&self, slot: usize) -> bool {
        self.state
            .lock()
            .unwrap()
            .owners
            .get(slot)
            .is_some_and(|c| c.items == 0)
    }
    pub(crate) fn refused(&self, class: RawQueueRefusal) {
        let mut s = self.state.lock().unwrap();
        Self::record_refusal(&mut s, class);
    }
    fn record_refusal(state: &mut State, class: RawQueueRefusal) {
        state.refusals = state.refusals.saturating_add(1);
        state.refusal_class[class as usize] = state.refusal_class[class as usize].saturating_add(1);
    }
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> (Count, u64, u64) {
        let state = self.state.lock().unwrap();
        (state.total, state.allocations, state.refusals)
    }
    #[cfg(test)]
    pub(crate) fn refusal_classes(&self) -> [u64; 10] {
        self.state.lock().unwrap().refusal_class
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        owner: impl Into<Owner>,
        source: IpAddr,
        capacity: usize,
    ) -> Result<Arc<Credit>, RawQueueRefusal> {
        let owner = owner.into();
        let source = match source {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(source, IpAddr::V4),
            _ => source,
        };
        let bytes = match capacity
            .checked_add(63)
            .and_then(|n| n.checked_div(64))
            .and_then(|n| n.checked_mul(64))
            .and_then(|n| n.checked_add(64))
        {
            Some(bytes) => bytes,
            None => {
                self.refused(RawQueueRefusal::ChargeOverflow);
                return Err(RawQueueRefusal::ChargeOverflow);
            }
        };
        let mut state = self.state.lock().unwrap();
        let owner_count = match owner {
            Owner::Established(slot) => match state.owners.get(slot) {
                Some(count) => *count,
                None => {
                    Self::record_refusal(&mut state, RawQueueRefusal::InvalidOwner);
                    return Err(RawQueueRefusal::InvalidOwner);
                }
            },
            Owner::Incoming => state.incoming,
        };
        let slot = match state
            .sources
            .iter()
            .position(|s| s.key == Some(source))
            .or_else(|| state.sources.iter().position(|s| s.key.is_none()))
        {
            Some(slot) => slot,
            None => {
                Self::record_refusal(&mut state, RawQueueRefusal::SourceSlotsFull);
                return Err(RawQueueRefusal::SourceSlotsFull);
            }
        };
        let source_count = state.sources[slot].count;
        let limits = self.limits;
        let owner_bytes = if owner == Owner::Incoming {
            limits.owners * 65536
        } else {
            limits.bytes_per_owner
        };
        let owner_items = if owner == Owner::Incoming {
            limits.owners
        } else {
            limits.items_per_owner
        };
        let refusal = if bytes > owner_bytes.saturating_sub(owner_count.bytes) {
            Some(RawQueueRefusal::OwnerBytes)
        } else if owner_count.items >= owner_items {
            Some(RawQueueRefusal::OwnerItems)
        } else if bytes > limits.bytes_per_source.saturating_sub(source_count.bytes) {
            Some(RawQueueRefusal::SourceBytes)
        } else if source_count.items >= limits.items_per_source {
            Some(RawQueueRefusal::SourceItems)
        } else if matches!(owner, Owner::Established(_))
            && bytes > limits.bytes_total.saturating_sub(state.established.bytes)
        {
            Some(RawQueueRefusal::EndpointBytes)
        } else if matches!(owner, Owner::Established(_))
            && state.established.items >= limits.items_total
        {
            Some(RawQueueRefusal::EndpointItems)
        } else {
            None
        };
        if let Some(reason) = refusal {
            Self::record_refusal(&mut state, reason);
            return Err(reason);
        }
        if matches!(owner, Owner::Established(_)) {
            state.established.bytes += bytes;
            state.established.items += 1;
        }
        state.allocations = state.allocations.saturating_add(1);
        let count = match owner {
            Owner::Established(slot) => &mut state.owners[slot],
            Owner::Incoming => &mut state.incoming,
        };
        count.bytes += bytes;
        count.items += 1;
        state.sources[slot].key = Some(source);
        state.sources[slot].count.bytes += bytes;
        state.sources[slot].count.items += 1;
        state.total.bytes += bytes;
        state.total.items += 1;
        Ok(Arc::new(Credit {
            pool: self.clone(),
            owner,
            source: slot,
            bytes,
        }))
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock().unwrap();
        let count = match self.owner {
            Owner::Established(slot) => &mut state.owners[slot],
            Owner::Incoming => &mut state.incoming,
        };
        count.bytes -= self.bytes;
        count.items -= 1;
        state.sources[self.source].count.bytes -= self.bytes;
        state.sources[self.source].count.items -= 1;
        if state.sources[self.source].count.items == 0 {
            state.sources[self.source].key = None;
        }
        if matches!(self.owner, Owner::Established(_)) {
            state.established.bytes -= self.bytes;
            state.established.items -= 1;
        }
        state.total.bytes -= self.bytes;
        state.total.items -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocation_credit_stays_with_shared_backing_owner() {
        let pool = Pool::new(PacketQueueLimits {
            owners: 2,
            bytes_total: 512,
            items_total: 4,
            bytes_per_owner: 256,
            items_per_owner: 2,
            bytes_per_source: 256,
            items_per_source: 2,
        })
        .unwrap();
        let source = "127.0.0.1".parse().unwrap();
        let first = pool.reserve(0, source, 64).unwrap();
        let clone = first.clone();
        let second = pool.reserve(0, source, 64).unwrap();
        assert!(pool.reserve(0, source, 1).is_err());
        assert!(pool.reserve(1, source, 1).is_err());
        drop(first);
        assert_eq!(pool.state.lock().unwrap().total.bytes, 256);
        drop(clone);
        assert_eq!(pool.state.lock().unwrap().total.bytes, 128);
        drop(second);
        assert_eq!(pool.state.lock().unwrap().total.items, 0);
        assert!(pool.reserve(0, source, 64).is_ok());
    }
}

#[cfg(test)]
mod slot_tests {
    use super::*;
    #[test]
    fn incoming_is_separate_and_source_exhaustion_has_a_typed_class() {
        let pool = Pool::new(PacketQueueLimits {
            owners: 1,
            bytes_total: 1024,
            items_total: 8,
            bytes_per_owner: 1024,
            items_per_owner: 8,
            bytes_per_source: 1024,
            items_per_source: 8,
        })
        .unwrap();
        let held: Vec<_> = (1..=4)
            .map(|n| pool.reserve(0, IpAddr::from([127, 0, 0, n]), 64).unwrap())
            .collect();
        assert!(matches!(
            pool.reserve(0, IpAddr::from([127, 0, 0, 5]), 64),
            Err(RawQueueRefusal::SourceSlotsFull)
        ));
        assert!(matches!(
            pool.reserve(1, IpAddr::from([127, 0, 0, 1]), 64),
            Err(RawQueueRefusal::InvalidOwner)
        ));
        let incoming = pool
            .reserve(Owner::Incoming, IpAddr::from([127, 0, 0, 1]), 64)
            .unwrap();
        {
            let state = pool.state.lock().unwrap();
            assert_eq!(state.owners.len(), 1);
            assert_eq!(state.incoming.items, 1);
            assert_eq!(state.established.items, 4);
        }
        assert_eq!(pool.refusal_classes()[7], 1);
        assert_eq!(pool.refusal_classes()[8], 1);
        drop((incoming, held));
        assert_eq!(pool.snapshot().0.items, 0);
    }
}

pub(crate) mod stateless_response;
