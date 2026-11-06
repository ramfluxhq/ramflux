// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receive history whose charged range storage outlives consumed application chunks.
use super::metadata_credit::{MetadataClass, MetadataCredit, ResourceExhausted};
use crate::range_set::{ArrayRangeSet, RangeSet, Replace};
use std::{ops::Range, sync::Arc};

#[derive(Debug)]
pub(super) enum ReceiveHistory {
    Legacy(RangeSet),
    Bounded { ranges: ArrayRangeSet, credit: Arc<MetadataCredit> },
}
impl ReceiveHistory {
    pub(super) fn new(credit: Option<Arc<MetadataCredit>>) -> Self {
        match credit {
            Some(credit)=>Self::Bounded { ranges:ArrayRangeSet::with_metadata(Some(credit.clone()),MetadataClass::UnorderedHistory),credit },
            None=>Self::Legacy(RangeSet::new()),
        }
    }
    pub(super) fn bind(&mut self, credit: Option<Arc<MetadataCredit>>) -> Result<(),ResourceExhausted> {
        if let (Self::Legacy(old),Some(credit))=(&*self,credit) {
            let mut next=Self::new(Some(credit));
            for range in old.iter() { next.insert(range)?; }
            *self=next; // Old tree stays live until the complete conversion is admitted.
        }
        Ok(())
    }
    pub(super) fn insert(&mut self, range: Range<u64>) -> Result<bool,ResourceExhausted> {
        match self {
            Self::Legacy(set)=>Ok(set.insert(range)),
            Self::Bounded {ranges,credit}=>{
                if credit.stats().exhausted { return Err(ResourceExhausted {class:MetadataClass::UnorderedHistory}); }
                ranges.reserve_insert(&range)?;
                Ok(ranges.insert_reserved(range))
            }
        }
    }
    pub(super) fn replace(&mut self, range: Range<u64>) -> Result<HistoryReplace<'_>,ResourceExhausted> {
        match self {
            Self::Legacy(set)=>Ok(HistoryReplace::Legacy(set.replace(range))),
            Self::Bounded {ranges,credit}=>{
                if credit.stats().exhausted { return Err(ResourceExhausted {class:MetadataClass::UnorderedHistory}); }
                ranges.reserve_insert(&range)?;
                let index=ranges.first_intersection_index(range.start);
                Ok(HistoryReplace::Bounded {ranges,range,index})
            }
        }
    }
    #[cfg(any(test,feature="__control-test"))]
    pub(super) fn storage(&self) -> (usize,usize) {
        match self { Self::Legacy(set)=>(0,set.len()),Self::Bounded {ranges,..}=>(ranges.heap_capacity_bytes(),ranges.len()) }
    }
}

pub(super) enum HistoryReplace<'a> {
    Legacy(Replace<'a>),
    Bounded { ranges:&'a mut ArrayRangeSet, range:Range<u64>, index:usize },
}
impl Iterator for HistoryReplace<'_> {
    type Item=Range<u64>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Legacy(iter)=>iter.next(),
            Self::Bounded {ranges,range,index}=>{
                while let Some(old)=ranges.range_at(*index) {
                    *index+=1;
                    if old.start>=range.end { return None; }
                    let start=old.start.max(range.start);let end=old.end.min(range.end);
                    if start<end { return Some(start..end); }
                }
                None
            }
        }
    }
}
impl Drop for HistoryReplace<'_> {
    fn drop(&mut self) {
        if let Self::Bounded {ranges,range,..}=self {
            // Exclusive borrow prevents changes between reserve and commit. Iteration
            // reads the original intersections; union cannot require another slot.
            ranges.insert_reserved(range.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_replacement_matches_tree_intersections_and_retains_capacity() {
        let credit=MetadataCredit::new(1<<20);let mut bounded=ReceiveHistory::new(Some(credit.clone()));let mut tree=RangeSet::new();
        for range in [1..2,3..4,5..6,7..8,9..10,2..5,0..11,4..4,20..22] {
            let expected=tree.replace(range.clone()).collect::<Vec<_>>();
            let actual=bounded.replace(range).unwrap().collect::<Vec<_>>();assert_eq!(actual,expected);
            let ReceiveHistory::Bounded {ranges,..}=&bounded else {panic!("bounded history");};
            assert_eq!(ranges.iter().collect::<Vec<_>>(),tree.iter().collect::<Vec<_>>());
        }
        { let mut replace=bounded.replace(0..30).unwrap();assert_eq!(replace.next(),Some(0..11)); }
        assert_eq!(bounded.storage().1,1,"dropping a partial intersection iterator still commits the complete union");
        let capacity=bounded.storage().0;assert!(capacity>0);
        let ReceiveHistory::Bounded {ranges,..}=&mut bounded else {unreachable!()};
        assert!(ranges.remove(4..8)); // Split a union without losing its range storage.
        ranges.remove(0..u64::MAX);assert!(ranges.is_empty());
        assert_eq!(bounded.storage(),(capacity,0));
        assert_eq!(credit.stats().used,((capacity+63)&!63)+64);
        drop(bounded);assert_eq!(credit.stats().used,0);
    }
    #[test]
    fn refused_split_and_legacy_transition_preserve_original_ranges() {
        let credit=MetadataCredit::new(128);let mut history=ReceiveHistory::new(Some(credit.clone()));
        for range in [0..10,20..21,30..31,40..41] { history.insert(range).unwrap(); }
        assert_eq!(history.storage(),(64,4));
        let ReceiveHistory::Bounded {ranges,..}=&mut history else {unreachable!()};
        assert!(!ranges.remove(3..4));assert!(ranges.contains(3));assert_eq!(ranges.len(),4);
        assert_eq!(credit.stats().failed_class,Some(MetadataClass::UnorderedHistory));
        drop(history);assert_eq!(credit.stats().used,0);
        let mut legacy=ReceiveHistory::new(None);for range in [1..2,3..4,5..6] {legacy.insert(range).unwrap();}
        let credit=MetadataCredit::new(0);assert!(legacy.bind(Some(credit.clone())).is_err());
        let ReceiveHistory::Legacy(ranges)=legacy else {panic!("refused conversion replaced original tree")};
        assert_eq!(ranges.len(),3);assert!(ranges.contains(3));assert_eq!(credit.stats().used,0);
    }
}

#[cfg(test)]
mod partition_tests {
    use super::*;
    #[test]
    fn gapped_history_starts_at_the_relevant_suffix() {
        let credit=MetadataCredit::new(1<<20);let mut history=ReceiveHistory::new(Some(credit.clone()));
        for index in 0..256 { history.insert(index*4+1..index*4+2).unwrap(); }
        {
            let mut tail=history.replace(1025..1026).unwrap();
            let HistoryReplace::Bounded {index,..}=&tail else {unreachable!()};
            assert_eq!(*index,256,"new tail must skip every earlier range before iteration");
            assert_eq!(tail.next(),None);
        }
        {
            let mut last=history.replace(1021..1022).unwrap();
            let HistoryReplace::Bounded {index,..}=&last else {unreachable!()};
            assert_eq!(*index,255);assert_eq!(last.next(),Some(1021..1022));assert_eq!(last.next(),None);
        }
        drop(history);assert_eq!(credit.stats().used,0);
    }
    #[test]
    fn inline_adjacency_and_empty_ranges_do_not_require_growth() {
        let credit=MetadataCredit::new(0);let mut history=ReceiveHistory::new(Some(credit.clone()));
        for range in [1..2,5..6,2..3,3..5,0..1] { assert!(history.insert(range).unwrap()); }
        assert!(!history.insert(7..7).unwrap());assert!(!history.insert(Range {start:9,end:8}).unwrap());
        assert!(history.replace(3..3).unwrap().next().is_none());
        let ReceiveHistory::Bounded {ranges,..}=&history else {unreachable!()};
        let mut actual=ranges.iter();assert_eq!(actual.next(),Some(0..6));assert_eq!(actual.next(),None);
        assert_eq!(history.storage(),(0,1));assert_eq!(credit.stats().used,0);assert!(!credit.stats().exhausted);
    }
}


#[cfg(test)]
mod endpoint_tests {
    use super::*;
    #[test]
    fn maximum_endpoints_preserve_exclusive_intersections_and_adjacency() {
        let credit=MetadataCredit::new(0);let mut history=ReceiveHistory::new(Some(credit.clone()));
        history.insert(u64::MAX-2..u64::MAX).unwrap();
        let replaced=history.replace(u64::MAX-1..u64::MAX).unwrap().collect::<Vec<_>>();
        assert_eq!(replaced.len(),1);assert_eq!(replaced[0],u64::MAX-1..u64::MAX);
        assert!(!history.insert(u64::MAX..u64::MAX).unwrap());history.insert(0..1).unwrap();
        assert!(history.replace(1..u64::MAX-2).unwrap().next().is_none());
        let ReceiveHistory::Bounded {ranges,..}=&history else {unreachable!()};
        assert_eq!(ranges.len(),1);assert_eq!(ranges.min(),Some(0));assert_eq!(ranges.max(),Some(u64::MAX-1));
        assert_eq!(credit.stats().used,0);assert!(!credit.stats().exhausted);
    }
}
