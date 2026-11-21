// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Roots whose current native manifest should be fetched now, not at the next sweep.
//!
//! The client records the demand; the account writer drains it into the bounded head-refresh
//! queue, which keeps its own capacity, backoff and eligibility rules.
use std::{cell::RefCell, collections::BTreeSet, sync::Arc};
use tokio::sync::Notify;

const MAX_DEMAND: usize = 64;

#[derive(Default)]
pub(crate) struct ManifestDemand {
    roots: RefCell<BTreeSet<String>>,
    pub(crate) wake: Arc<Notify>,
}

impl ManifestDemand {
    pub(crate) fn request(&self, root: &str) {
        let mut roots = self.roots.borrow_mut();
        if roots.len() < MAX_DEMAND || roots.contains(root) {
            roots.insert(root.to_owned());
            self.wake.notify_one();
        }
    }

    pub(crate) fn take(&self) -> BTreeSet<String> {
        std::mem::take(&mut *self.roots.borrow_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demand_is_bounded_and_drains_once() {
        let demand = ManifestDemand::default();
        for index in 0..(MAX_DEMAND + 10) {
            demand.request(&format!("root-{index}"));
        }
        demand.request("root-0");
        let taken = demand.take();
        assert_eq!(taken.len(), MAX_DEMAND, "demand set must stay bounded");
        assert!(demand.take().is_empty(), "a drained demand set must stay empty");
    }
}
