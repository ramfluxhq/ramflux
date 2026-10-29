// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded lease quotas: table pressure evicts old identities instead of denying new ones.
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    events: Vec<i64>,
    last_use: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PrekeyBudgetTable {
    entries: BTreeMap<String, Entry>,
    capacity: usize,
    clock: u64,
}
impl Default for PrekeyBudgetTable {
    fn default() -> Self {
        Self { entries: BTreeMap::new(), capacity: 4096, clock: 0 }
    }
}
impl PrekeyBudgetTable {
    pub(super) fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.max(1);
        while self.entries.len() > self.capacity {
            self.evict_oldest();
        }
    }
    fn evict_oldest(&mut self) {
        if let Some(key) =
            self.entries.iter().min_by_key(|(_, entry)| entry.last_use).map(|(key, _)| key.clone())
        {
            self.entries.remove(&key);
        }
    }
    pub(super) fn available(&mut self, key: &str, now: i64, limit: usize, window: i64) -> bool {
        self.clock = self.clock.saturating_add(1);
        let Some(entry) = self.entries.get_mut(key) else { return true };
        entry.last_use = self.clock;
        entry.events.retain(|seen| now.saturating_sub(*seen) < window);
        entry.events.len() < limit
    }
    pub(super) fn record(&mut self, key: &str, now: i64, window: i64) {
        self.entries.retain(|_, entry| {
            entry.events.retain(|seen| now.saturating_sub(*seen) < window);
            !entry.events.is_empty()
        });
        if !self.entries.contains_key(key) && self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        self.clock = self.clock.saturating_add(1);
        let entry = self
            .entries
            .entry(key.into())
            .or_insert_with(|| Entry { events: Vec::new(), last_use: self.clock });
        entry.last_use = self.clock;
        entry.events.push(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn five_thousand_pairs_admit_newcomers_and_retain_recent_limits() {
        let mut table = PrekeyBudgetTable::default();
        for i in 0..5000 {
            let pair = format!("pair-{i}");
            assert!(table.available(&pair, i, 1, 86400));
            table.record(&pair, i, 86400);
            assert!(!table.available(&pair, i, 1, 86400));
            assert!(table.entries.len() <= 4096);
        }
        assert!(!table.available("pair-4999", 5000, 1, 86400));
        assert!(table.available("pair-0", 5000, 1, 86400));
        table.record("new-day", 100_000, 86400);
        assert_eq!(table.entries.len(), 1);
    }
    #[test]
    fn access_including_denied_access_updates_lru_and_capacity_is_configurable() {
        let mut table = PrekeyBudgetTable::default();
        table.set_capacity(2);
        table.record("a", 1, 86400);
        table.record("b", 1, 86400);
        assert!(!table.available("a", 1, 1, 86400));
        table.record("c", 1, 86400);
        assert!(!table.available("a", 1, 1, 86400));
        assert!(table.available("b", 1, 1, 86400));
        table.set_capacity(0);
        assert_eq!(table.entries.len(), 1);
    }
}
