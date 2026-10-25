// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-qualified active lease counters; UDP admission never scans all leases.
use super::{BTreeMap, CallEndpoint, Lease};
#[derive(Default)]
pub(super) struct Usage(BTreeMap<(String, String), usize>);
fn key(account: &CallEndpoint) -> (String, String) {
    (account.principal_id.clone(), account.root_public_key.clone())
}
impl Usage {
    pub(super) fn count(&self, account: &CallEndpoint) -> usize {
        self.0.get(&key(account)).copied().unwrap_or(0)
    }
    pub(super) fn charge(&mut self, account: &CallEndpoint) {
        *self.0.entry(key(account)).or_default() += 1;
    }
    fn uncharge(&mut self, account: &CallEndpoint) {
        let key = key(account);
        if let Some(count) = self.0.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.0.remove(&key);
            }
        }
    }
    pub(super) fn release(&mut self, lease: &Lease) {
        self.uncharge(&lease.scope.caller);
        if lease.consent.is_some() {
            self.uncharge(&lease.scope.callee);
        }
    }
}
