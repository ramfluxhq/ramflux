// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Four 16-MiB read reservations; public peers cannot consume the two foreground reserves.
use ramflux_protocol::contact_reach::Reason;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, OnceLock},
};
#[derive(Default)]
struct State {
    total: usize,
    public: usize,
    peers: BTreeSet<String>,
}
#[derive(Clone, Default)]
pub(super) struct Budget(Arc<Mutex<State>>);
pub(super) struct Permit {
    budget: Budget,
    peer: String,
    public: bool,
}
impl Budget {
    pub(super) fn reserve(&self, peer: &str, public: bool) -> Result<Permit, Reason> {
        let mut state = self.0.lock().map_err(|_| Reason::ForeignCapacity)?;
        if state.total >= 4 || public && state.public >= 2 || state.peers.contains(peer) {
            return Err(Reason::ForeignCapacity);
        }
        state.total += 1;
        state.public += usize::from(public);
        state.peers.insert(peer.into());
        Ok(Permit { budget: self.clone(), peer: peer.into(), public })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.budget.0.lock() {
            state.peers.remove(&self.peer);
            state.total = state.total.saturating_sub(1);
            state.public = state.public.saturating_sub(usize::from(self.public));
        }
    }
}
pub(super) fn reserve(peer: &str, public: bool) -> Result<Permit, Reason> {
    static BUDGET: OnceLock<Budget> = OnceLock::new();
    BUDGET.get_or_init(Budget::default).reserve(peer, public)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_public_read_saturation_preserves_foreground_and_per_peer_reserves()
    -> Result<(), Box<dyn std::error::Error>> {
        let budget = Budget::default();
        let first = budget.reserve("peer-a.example", true).map_err(|_| "first public read")?;
        let second = budget.reserve("peer-b.example", true).map_err(|_| "second public read")?;
        assert!(
            budget.reserve("peer-c.example", true).is_err(),
            "public reads stop at half of the global read budget"
        );
        assert!(
            budget.reserve("peer-a.example", false).is_err(),
            "a foreground label cannot bypass the 16-MiB per-peer reservation"
        );
        let third = budget.reserve("peer-c.example", false).map_err(|_| "first foreground read")?;
        let fourth =
            budget.reserve("peer-d.example", false).map_err(|_| "second foreground read")?;
        assert!(
            budget.reserve("peer-e.example", false).is_err(),
            "all read reservations remain bounded at 64 MiB"
        );
        drop((first, second, third, fourth));
        budget.reserve("peer-a.example", true).map_err(|_| "released reservation")?;
        Ok(())
    }
}
