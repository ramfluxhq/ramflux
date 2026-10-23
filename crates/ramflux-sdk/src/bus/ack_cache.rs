// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded LRU hint for acknowledgements; encrypted storage remains authoritative.

use std::collections::{BTreeSet, VecDeque};

pub(crate) struct AckCache {
    entries: BTreeSet<String>,
    recent: VecDeque<String>,
}
impl AckCache {
    pub(crate) fn new() -> Self {
        Self { entries: BTreeSet::new(), recent: VecDeque::new() }
    }
    pub(crate) fn contains(&mut self, id: &str) -> bool {
        if !self.entries.contains(id) {
            return false;
        }
        self.recent.retain(|entry| entry != id);
        self.recent.push_back(id.to_owned());
        true
    }
    pub(crate) fn insert(&mut self, id: String) {
        if self.contains(&id) {
            return;
        }
        self.entries.insert(id.clone());
        self.recent.push_back(id);
        if self.entries.len() > 256
            && let Some(oldest) = self.recent.pop_front()
        {
            self.entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AckCache;
    #[test]
    fn acknowledgement_hints_are_bounded_and_lru() {
        let mut cache = AckCache::new();
        for index in 0..256 {
            cache.insert(index.to_string());
        }
        assert!(cache.contains("0"));
        cache.insert("new".to_owned());
        assert!(cache.contains("0"));
        assert!(!cache.contains("1"));
        assert_eq!(cache.entries.len(), 256);
        assert_eq!(cache.recent.len(), 256);
    }
}
