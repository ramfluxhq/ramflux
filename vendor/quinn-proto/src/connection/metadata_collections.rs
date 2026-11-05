// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual-capacity retransmit collections and retained transfer iterators.
use super::metadata_credit::{AllocationCharge, MetadataClass, MetadataCredit, ResourceExhausted};
use std::{collections::VecDeque, hash::Hash, ops::Deref, sync::Arc};
use rustc_hash::FxHashSet;

macro_rules! sequence {
    ($name:ident, $backing:ident, $iter:ty) => {
        #[derive(Debug)]
        pub(super) struct $name<T> {
            values: $backing<T>,
            charge: Option<AllocationCharge>,
            context: Option<(Arc<MetadataCredit>, MetadataClass)>,
        }
        impl<T> Default for $name<T> {
            fn default() -> Self { Self { values: $backing::new(), charge: None, context: None } }
        }
        impl<T> $name<T> {
            pub(super) fn bind(&mut self, credit: Option<Arc<MetadataCredit>>, class: MetadataClass) -> Result<(), ResourceExhausted> {
                if self.context.is_none() {
                    if let Some(credit) = credit {
                        if self.values.capacity() != 0 { self.charge = Some(credit.reserve(self.capacity_bytes(), class)?); }
                        self.context = Some((credit, class));
                    }
                }
                Ok(())
            }
            pub(super) fn reserve(&mut self, extra: usize) -> Result<(), ResourceExhausted> {
                let Some((credit, class)) = &self.context else { return Ok(()); };
                if credit.stats().exhausted { return Err(ResourceExhausted { class: *class }); }
                let needed = self.values.len().checked_add(extra).ok_or_else(||credit.fail(*class))?;
                if needed <= self.values.capacity() { return Ok(()); }
                let capacity = self.values.capacity().checked_mul(2).map(|n|n.max(4).max(needed)).ok_or_else(||credit.fail(*class))?;
                let bytes = capacity.checked_mul(std::mem::size_of::<T>()).ok_or_else(||credit.fail(*class))?;
                let charge = credit.reserve(bytes, *class)?;
                let mut next = $backing::new();
                next.try_reserve_exact(capacity).map_err(|_|credit.fail(*class))?;
                assert_eq!(next.capacity(), capacity);
                credit.allocated();
                next.append(&mut self.values);
                let old = std::mem::replace(&mut self.values, next);
                drop(old);
                self.charge = Some(charge);
                Ok(())
            }
            pub(super) fn capacity_bytes(&self) -> usize { self.values.capacity()*std::mem::size_of::<T>() }
        }
        impl<T> IntoIterator for $name<T> {
            type Item = T;
            type IntoIter = ChargedIter<$iter>;
            fn into_iter(self) -> Self::IntoIter { ChargedIter { iter: self.values.into_iter(), _charge: self.charge } }
        }
    }
}
sequence!(MetadataVec, Vec, std::vec::IntoIter<T>);
sequence!(MetadataDeque, VecDeque, std::collections::vec_deque::IntoIter<T>);

impl<T> Deref for MetadataVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] { &self.values }
}
impl<T> MetadataVec<T> {
    pub(super) fn push(&mut self, value: T) -> Result<(), ResourceExhausted> { self.reserve(1)?; self.values.push(value); Ok(()) }
    pub(super) fn pop(&mut self) -> Option<T> { self.values.pop() }
    pub(super) fn clear(&mut self) { self.values.clear(); }
    pub(super) fn extend_from_slice(&mut self, values: &[T]) -> Result<(), ResourceExhausted> where T: Clone {
        self.reserve(values.len())?; self.values.extend_from_slice(values); Ok(())
    }
}
impl<T> MetadataDeque<T> {
    pub(super) fn push_back(&mut self, value: T) -> Result<(), ResourceExhausted> { self.reserve(1)?; self.values.push_back(value); Ok(()) }
    pub(super) fn push_front(&mut self, value: T) -> Result<(), ResourceExhausted> { self.reserve(1)?; self.values.push_front(value); Ok(()) }
    pub(super) fn pop_front(&mut self) -> Option<T> { self.values.pop_front() }
    pub(super) fn is_empty(&self) -> bool { self.values.is_empty() }
    pub(super) fn len(&self) -> usize { self.values.len() }
}

#[derive(Debug)]
pub(super) struct ChargedIter<I> { iter: I, _charge: Option<AllocationCharge> }
impl<I: Iterator> Iterator for ChargedIter<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> { self.iter.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}
impl<I: DoubleEndedIterator> DoubleEndedIterator for ChargedIter<I> {
    fn next_back(&mut self) -> Option<Self::Item> { self.iter.next_back() }
}

#[derive(Debug)]
pub(super) enum MetadataSet<T> { Legacy(FxHashSet<T>), Bounded(MetadataVec<T>) }
impl<T> Default for MetadataSet<T> { fn default() -> Self { Self::Legacy(FxHashSet::default()) } }
impl<T: Eq + Hash + Copy> MetadataSet<T> {
    pub(super) fn bind(&mut self, credit: Option<Arc<MetadataCredit>>, class: MetadataClass) -> Result<(), ResourceExhausted> {
        if let Self::Legacy(old) = self {
            if credit.is_some() {
                let mut next = MetadataVec::default(); next.bind(credit, class)?; if !old.is_empty(){next.reserve(old.len())?;}
                for &value in old.iter() { next.push(value)?; }
                *self = Self::Bounded(next);
            }
        }
        Ok(())
    }
    pub(super) fn insert(&mut self, value: T) -> Result<bool, ResourceExhausted> {
        match self {
            Self::Legacy(s) => Ok(s.insert(value)),
            Self::Bounded(s) => { if s.contains(&value) { return Ok(false); } s.push(value)?; Ok(true) }
        }
    }
    pub(super) fn remove(&mut self, value: &T) -> bool {
        match self { Self::Legacy(s) => s.remove(value), Self::Bounded(s) => {
            if let Some(i) = s.values.iter().position(|v|v==value) { s.values.swap_remove(i); true } else { false }
        } }
    }
    pub(super) fn iter(&self) -> impl Iterator<Item=&T> { match self { Self::Legacy(s) => SetIter::Legacy(s.iter()), Self::Bounded(s) => SetIter::Bounded(s.iter()) } }
    pub(super) fn reserve_union(&mut self, other: &Self) -> Result<(), ResourceExhausted> {
        if let Self::Bounded(s) = self { let extra = other.iter().filter(|v|!s.contains(v)).count(); s.reserve(extra)?; }
        Ok(())
    }
    #[cfg(any(test,feature="__control-test"))]
    pub(super) fn capacity_bytes(&self) -> usize { match self { Self::Legacy(_) => 0, Self::Bounded(s) => s.capacity_bytes() } }
}

enum SetIter<'a,T> { Legacy(std::collections::hash_set::Iter<'a,T>), Bounded(std::slice::Iter<'a,T>) }
impl<'a,T> Iterator for SetIter<'a,T> {
    type Item=&'a T;
    fn next(&mut self)->Option<Self::Item>{match self{Self::Legacy(i)=>i.next(),Self::Bounded(i)=>i.next()}}
}
