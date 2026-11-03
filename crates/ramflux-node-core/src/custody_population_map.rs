// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Count population entries at the collection boundary in test builds.
#[cfg(not(test))]
pub(crate) type PopulationMap<K, V> = std::collections::BTreeMap<K, V>;

#[cfg(test)]
mod counting {
    use std::{borrow::Borrow, cell::Cell, collections::BTreeMap};

    pub(crate) struct PopulationMap<K, V> {
        entries: BTreeMap<K, V>,
        visits: Cell<usize>,
    }
    impl<K, V> Default for PopulationMap<K, V> {
        fn default() -> Self {
            Self { entries: BTreeMap::new(), visits: Cell::new(0) }
        }
    }
    // Keep scan APIs instrumented even when the indexed implementation does not use them.
    #[allow(dead_code)]
    impl<K: Ord, V> PopulationMap<K, V> {
        pub(crate) fn visits(&self, reset: bool) -> usize {
            if reset { self.visits.replace(0) } else { self.visits.get() }
        }
        pub(crate) fn len(&self) -> usize {
            self.entries.len()
        }
        pub(crate) fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }
        pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
            let previous = self.entries.insert(key, value);
            self.visits.set(self.visits.get() + usize::from(previous.is_some()));
            previous
        }
        pub(crate) fn get<Q: Ord + ?Sized>(&self, key: &Q) -> Option<&V>
        where
            K: Borrow<Q>,
        {
            let value = self.entries.get(key);
            self.visits.set(self.visits.get() + usize::from(value.is_some()));
            value
        }
        pub(crate) fn get_mut<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<&mut V>
        where
            K: Borrow<Q>,
        {
            let value = self.entries.get_mut(key);
            self.visits.set(self.visits.get() + usize::from(value.is_some()));
            value
        }
        pub(crate) fn contains_key<Q: Ord + ?Sized>(&self, key: &Q) -> bool
        where
            K: Borrow<Q>,
        {
            self.get(key).is_some()
        }
        pub(crate) fn remove<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<V>
        where
            K: Borrow<Q>,
        {
            let value = self.entries.remove(key);
            self.visits.set(self.visits.get() + usize::from(value.is_some()));
            value
        }
        pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
            self.entries.iter().inspect(|_| self.visits.set(self.visits.get() + 1))
        }
        pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
            self.entries.values().inspect(|_| self.visits.set(self.visits.get() + 1))
        }
        pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
            self.entries.values_mut().inspect(|_| self.visits.set(self.visits.get() + 1))
        }
        pub(crate) fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
            self.entries.retain(|key, value| {
                self.visits.set(self.visits.get() + 1);
                keep(key, value)
            });
        }
    }
}
#[cfg(test)]
pub(crate) use counting::PopulationMap;
