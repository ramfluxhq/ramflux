// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receive descriptor heaps with actual-capacity reservations and replacement overlap.
use super::{assembler::TooManyChunks, metadata_credit::{AllocationCharge, MetadataClass, MetadataCredit}};
use std::{collections::{BinaryHeap, binary_heap::{Iter, PeekMut}}, ops::Deref, sync::Arc};

#[derive(Debug)]
pub(super) struct MetadataHeap<T> {
    pub(super) values: BinaryHeap<T>,
    charge: Option<AllocationCharge>,
    context: Option<(Arc<MetadataCredit>, MetadataClass)>,
}
impl<T> Default for MetadataHeap<T> {
    fn default() -> Self { Self { values: BinaryHeap::new(), charge: None, context: None } }
}
impl<T: Ord> MetadataHeap<T> {
    /// Allocate real descriptor storage under an already held aggregate stage lease.
    pub(super) fn prepare_staged(capacity: usize) -> Result<Self, TooManyChunks> {
        let mut values=BinaryHeap::new();
        values.try_reserve_exact(capacity).map_err(|_|TooManyChunks)?;
        assert_eq!(values.capacity(),capacity);
        Ok(Self { values, ..Self::default() })
    }
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self { values: BinaryHeap::with_capacity(capacity), ..Self::default() }
    }
    pub(super) fn bind(&mut self, credit: Option<Arc<MetadataCredit>>, class: MetadataClass) -> Result<(), TooManyChunks> {
        if self.context.is_none() {
            if let Some(credit)=credit {
                if self.capacity()!=0 { self.charge=Some(credit.reserve(self.capacity_bytes(),class).map_err(|_|TooManyChunks)?); }
                self.context=Some((credit,class));
            }
        }
        Ok(())
    }
    pub(super) fn context(&self) -> Option<(Arc<MetadataCredit>,MetadataClass)> { self.context.clone() }
    pub(super) fn capacity_bytes(&self) -> usize { self.capacity()*std::mem::size_of::<T>() }
    pub(super) fn replacement(&self, capacity: usize) -> Result<Self,TooManyChunks> {
        let Some((credit,class))=&self.context else { return Ok(Self::with_capacity(capacity)); };
        let bytes=capacity.checked_mul(std::mem::size_of::<T>()).ok_or_else(||{credit.fail(*class);TooManyChunks})?;
        let charge=credit.reserve(bytes,*class).map_err(|_|TooManyChunks)?;
        let mut values=BinaryHeap::new();
        values.try_reserve_exact(capacity).map_err(|_|{credit.fail(*class);TooManyChunks})?;
        assert_eq!(values.capacity(),capacity);
        credit.allocated();
        Ok(Self { values, charge:Some(charge), context:self.context.clone() })
    }
    pub(super) fn push(&mut self, value: T) -> Result<(),TooManyChunks> {
        if self.context.as_ref().is_some_and(|(credit,_)|credit.stats().exhausted) { return Err(TooManyChunks); }
        if self.context.is_some() && self.len()==self.capacity() {
            let capacity=self.capacity().checked_mul(2).map(|n|n.max(4)).ok_or_else(||{
                let(credit,class)=self.context.as_ref().unwrap();credit.fail(*class);TooManyChunks
            })?;
            let mut next=self.replacement(capacity)?;
            while let Some(value)=self.values.pop() { next.values.push(value); }
            let old=std::mem::replace(self,next);
            drop(old); // Old allocation is destroyed before its charge.
        }
        self.values.push(value);Ok(())
    }
    pub(super) fn push_reserved(&mut self, value: T) {
        assert!(self.len()<self.capacity(),"compaction exceeded its admitted descriptor plan");
        self.values.push(value);
    }
    pub(super) fn peek_mut(&mut self) -> Option<PeekMut<'_,T>> { self.values.peek_mut() }
    pub(super) fn clear(&mut self) { self.values.clear(); }
    pub(super) fn into_sorted_vec(self) -> Vec<T> {
        assert!(self.context.is_none(),"bounded sorted backing must retain its heap lease");
        self.values.into_sorted_vec()
    }
}
impl<T> Deref for MetadataHeap<T> { type Target=BinaryHeap<T>; fn deref(&self)->&Self::Target { &self.values } }
impl<'a,T> IntoIterator for &'a MetadataHeap<T> { type Item=&'a T; type IntoIter=Iter<'a,T>;fn into_iter(self)->Self::IntoIter { self.values.iter() } }
