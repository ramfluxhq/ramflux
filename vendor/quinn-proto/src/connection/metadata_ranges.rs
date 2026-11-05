// SPDX-License-Identifier: MIT OR Apache-2.0
//! Allocation-visible send ACK/loss ranges; default mode keeps the upstream tree.
use super::metadata_credit::{MetadataClass, MetadataCredit, ResourceExhausted};
use crate::range_set::{ArrayRangeSet, RangeSet};
use std::{ops::Range, sync::Arc};

#[derive(Debug)]
pub(crate) enum SendRanges {
    Legacy(RangeSet),
    Bounded(ArrayRangeSet),
}

impl Default for SendRanges {
    fn default() -> Self { Self::Legacy(RangeSet::new()) }
}

impl SendRanges {
    pub(crate) fn bind(&mut self, credit: Option<Arc<MetadataCredit>>) -> Result<(), ResourceExhausted> {
        let Some(credit) = credit else { return Ok(()); };
        if let Self::Legacy(old) = self {
            let mut next = ArrayRangeSet::with_metadata(Some(credit), MetadataClass::SendRanges);
            for range in old.iter() {
                next.reserve_insert(&range)?;
                next.insert(range);
            }
            *self = Self::Bounded(next);
        }
        Ok(())
    }

    pub(crate) fn insert(&mut self, range: Range<u64>) -> bool {
        match self { Self::Legacy(s) => s.insert(range), Self::Bounded(s) => s.insert(range) }
    }
    pub(crate) fn min(&self) -> Option<u64> {
        match self { Self::Legacy(s) => s.min(), Self::Bounded(s) => s.min() }
    }
    pub(crate) fn pop_min(&mut self) -> Option<Range<u64>> {
        match self { Self::Legacy(s) => s.pop_min(), Self::Bounded(s) => s.pop_min() }
    }
    pub(crate) fn is_empty(&self) -> bool {
        match self { Self::Legacy(s) => s.is_empty(), Self::Bounded(s) => s.is_empty() }
    }
    #[cfg(any(test, feature = "__control-test"))]
    pub(crate) fn len(&self) -> usize {
        match self { Self::Legacy(s) => s.len(), Self::Bounded(s) => s.len() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_ranges_preserve_tree_union_order_and_retained_capacity() {
        let credit = MetadataCredit::new(1024);
        let mut bounded = SendRanges::default();
        bounded.bind(Some(credit.clone())).unwrap();
        let mut tree = RangeSet::new();
        for range in [9..10, 1..2, 5..6, 3..4, 2..5, 10..12, 8..9, 4..8] {
            assert_eq!(bounded.insert(range.clone()), tree.insert(range));
            assert_eq!(bounded.len(), tree.len());
            assert_eq!(bounded.min(), tree.min());
        }
        while !tree.is_empty() { assert_eq!(bounded.pop_min(), tree.pop_min()); }
        assert!(bounded.is_empty());
        assert!(matches!(&bounded, SendRanges::Bounded(set) if set.heap_capacity_bytes() == 64));
        assert_eq!(credit.stats().used, 128, "empty heap capacity remains allocated");
        assert_eq!(credit.stats().allocations, 1);
        drop(bounded);
        assert_eq!(credit.stats().used, 0);
    }

    #[test]
    fn refused_late_binding_preserves_legacy_ranges() {
        let mut ranges = SendRanges::default();
        for range in [1..2, 3..4, 5..6] { ranges.insert(range); }
        let credit = MetadataCredit::new(0);
        assert!(ranges.bind(Some(credit.clone())).is_err());
        assert!(matches!(ranges, SendRanges::Legacy(_)));
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges.pop_min(), Some(1..2));
        assert_eq!(credit.stats().allocations, 0);
        assert_eq!(credit.stats().used, 0);
    }
}
