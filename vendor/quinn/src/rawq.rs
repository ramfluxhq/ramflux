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
struct Count {
    bytes: usize,
    items: usize,
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
            || limits.bytes_per_owner == 0
            || limits.items_per_owner == 0
            || limits.bytes_per_source == 0
            || limits.items_per_source == 0
            || limits.owners.checked_mul(limits.bytes_per_owner).is_none()
            || limits.owners.checked_mul(limits.items_per_owner).is_none()
            || limits.owners.checked_mul(4).is_none()
        {
            return Err("invalid packet queue limits");
        }
        Ok(Arc::new(Self {
            limits,
            state: Mutex::new(State {
                owners: vec![Count::default(); limits.owners].into_boxed_slice(),
                sources: (0..limits.owners * 4)
                    .map(|_| Source::default())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                total: Count::default(),
            }),
        }))
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
        if bytes > limits.bytes_per_owner.checked_sub(owner_count.bytes)?
            || owner_count.items >= limits.items_per_owner
            || bytes > limits.bytes_per_source.checked_sub(source_count.bytes)?
            || source_count.items >= limits.items_per_source
            || bytes > (limits.owners * limits.bytes_per_owner).checked_sub(state.total.bytes)?
            || state.total.items >= limits.owners * limits.items_per_owner
        {
            return None;
        }
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
