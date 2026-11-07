// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sorted immutable hub snapshots. Search <= ceil(log2(n)) + 1 comparisons.
//! Churn copies O(n) entries outside the publication mutex before a short CAS.
#[derive(Clone)]
pub(crate) struct Index<V> {
    rows: Vec<(Key, V)>,
    #[cfg(test)]
    comparisons: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
#[derive(Clone)]
struct Key {
    text: String,
    #[cfg(test)]
    comparisons: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl Key {
    fn compare(&self, target: &str) -> std::cmp::Ordering {
        #[cfg(test)]
        self.comparisons.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.text.as_str().cmp(target)
    }
}
impl<V> Default for Index<V> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            #[cfg(test)]
            comparisons: std::sync::Arc::default(),
        }
    }
}
impl<V> Index<V> {
    fn locate(&self, target: &str) -> Result<usize, usize> {
        self.rows.binary_search_by(|(key, _)| key.compare(target))
    }
    pub(crate) fn get(&self, key: &str) -> Option<&V> {
        self.locate(key).ok().map(|at| &self.rows[at].1)
    }
    pub(crate) fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        let at = self.locate(key).ok()?;
        Some(&mut self.rows[at].1)
    }
    pub(crate) fn insert(&mut self, key: String, value: V) -> Option<V> {
        match self.locate(&key) {
            Ok(at) => Some(std::mem::replace(&mut self.rows[at].1, value)),
            Err(at) => {
                self.rows.insert(
                    at,
                    (
                        Key {
                            text: key,
                            #[cfg(test)]
                            comparisons: self.comparisons.clone(),
                        },
                        value,
                    ),
                );
                None
            }
        }
    }
    pub(crate) fn remove(&mut self, key: &str) -> Option<V> {
        self.locate(key).ok().map(|at| self.rows.remove(at).1)
    }
    pub(crate) fn page(&self, offset: usize) -> Vec<(String, V)>
    where
        V: Clone,
    {
        self.rows.iter().skip(offset).take(1024).map(|(k, v)| (k.text.clone(), v.clone())).collect()
    }
    pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
        self.rows.iter().map(|(_, v)| v)
    }
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.rows.iter().map(|(key, value)| (key.text.as_str(), value))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    #[test]
    fn hub_lookup_work_budget() {
        for n in [64_usize, 4096, 40960, 65536] {
            for order in 0..3 {
                let mut keys: Vec<_> = (0..n).collect();
                if order == 1 {
                    keys.reverse();
                }
                if order == 2 {
                    keys.sort_by_key(|k| k.wrapping_mul(7919) % n);
                }
                let mut index = Index::<usize>::default();
                // Batch construction uses the same key ordering; avoid O(n^2) fixture churn.
                let mut rows: Vec<_> = keys
                    .into_iter()
                    .map(|k| {
                        (
                            Key {
                                text: format!("key-{k:08}"),
                                comparisons: index.comparisons.clone(),
                            },
                            k,
                        )
                    })
                    .collect();
                rows.sort_by(|a, b| a.0.compare(&b.0.text));
                index.rows = rows;
                for target in [
                    format!("key-{:08}", n - 1),
                    format!("key-{:08}x", n - 2),
                    format!("key-{n:08}"),
                ] {
                    index.comparisons.store(0, Ordering::Relaxed);
                    let _ = index.get(&target);
                    let visits = index.comparisons.load(Ordering::Relaxed);
                    let log = n.next_power_of_two().ilog2() as usize;
                    assert!(visits <= log + 1, "n={n} order={order} visits={visits}");
                    assert!(visits <= 2 * log + 8);
                    index.comparisons.store(0, Ordering::Relaxed);
                    let _ = index.rows.iter().find(|(key, _)| key.compare(&target).is_eq());
                    assert!(index.comparisons.load(Ordering::Relaxed) > 2 * log + 8);
                }
            }
        }
    }
}
