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
    sources: Box<[Source]>,
    total: Count,
    allocations: u64,
    refusals: u64,
    refusal_class: [u64; 6],
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
    owner: usize,
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
                owners: vec![Count::default(); limits.owners + 1].into_boxed_slice(),
                sources: (0..limits.owners * 4)
                    .map(|_| Source::default())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                total: Count::default(),
                allocations: 0,
                refusals: 0,
                refusal_class: [0; 6],
                established: Count::default(),
            }),
        }))
    }
    pub(crate) fn incoming_owner(&self) -> usize {
        self.limits.owners
    }
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> (Count, u64, u64) {
        let state = self.state.lock().unwrap();
        (state.total, state.allocations, state.refusals)
    }
    #[cfg(test)]
    pub(crate) fn refusal_classes(&self) -> [u64; 6] {
        self.state.lock().unwrap().refusal_class
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        owner: usize,
        source: IpAddr,
        capacity: usize,
    ) -> Option<Arc<Credit>> {
        let source = match source {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(source, IpAddr::V4),
            _ => source,
        };
        let bytes = capacity
            .checked_add(63)?
            .checked_div(64)?
            .checked_mul(64)?
            .checked_add(64)?;
        let mut state = self.state.lock().unwrap();
        let owner_count = *state.owners.get(owner)?;
        let slot = state
            .sources
            .iter()
            .position(|s| s.key == Some(source))
            .or_else(|| state.sources.iter().position(|s| s.key.is_none()))?;
        let source_count = state.sources[slot].count;
        let limits = self.limits;
        let owner_bytes = if owner == limits.owners {
            limits.owners * 65536
        } else {
            limits.bytes_per_owner
        };
        let owner_items = if owner == limits.owners {
            limits.owners
        } else {
            limits.items_per_owner
        };
        let refusal = if bytes > owner_bytes.saturating_sub(owner_count.bytes) {
            Some(0)
        } else if owner_count.items >= owner_items {
            Some(1)
        } else if bytes > limits.bytes_per_source.saturating_sub(source_count.bytes) {
            Some(2)
        } else if source_count.items >= limits.items_per_source {
            Some(3)
        } else if owner < limits.owners
            && bytes > limits.bytes_total.saturating_sub(state.established.bytes)
        {
            Some(4)
        } else if owner < limits.owners && state.established.items >= limits.items_total {
            Some(5)
        } else {
            None
        };
        if let Some(reason) = refusal {
            state.refusals = state.refusals.saturating_add(1);
            state.refusal_class[reason] = state.refusal_class[reason].saturating_add(1);
            return None;
        }
        if owner < limits.owners {
            state.established.bytes += bytes;
            state.established.items += 1;
        }
        state.allocations = state.allocations.saturating_add(1);
        state.owners[owner].bytes += bytes;
        state.owners[owner].items += 1;
        state.sources[slot].key = Some(source);
        state.sources[slot].count.bytes += bytes;
        state.sources[slot].count.items += 1;
        state.total.bytes += bytes;
        state.total.items += 1;
        Some(Arc::new(Credit {
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
        state.owners[self.owner].bytes -= self.bytes;
        state.owners[self.owner].items -= 1;
        state.sources[self.source].count.bytes -= self.bytes;
        state.sources[self.source].count.items -= 1;
        if state.sources[self.source].count.items == 0 {
            state.sources[self.source].key = None;
        }
        if self.owner < self.pool.limits.owners {
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
        assert!(pool.reserve(0, source, 1).is_none());
        assert!(pool.reserve(1, source, 1).is_none());
        drop(first);
        assert_eq!(pool.state.lock().unwrap().total.bytes, 256);
        drop(clone);
        assert_eq!(pool.state.lock().unwrap().total.bytes, 128);
        drop(second);
        assert_eq!(pool.state.lock().unwrap().total.items, 0);
        assert!(pool.reserve(0, source, 64).is_some());
    }
}
