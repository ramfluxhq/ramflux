// SPDX-License-Identifier: MIT OR Apache-2.0
//! Allocation-visible ordered packet storage. Legacy mode retains the upstream BTreeMap.
use super::metadata_credit::{AllocationCharge, MetadataClass, MetadataCredit, ResourceExhausted};
use std::{collections::{BTreeMap,btree_map}, ops::{Bound,Index,RangeBounds}, sync::Arc};

#[derive(Debug)]
pub(crate) struct Slot<V> { key:u64, value:Option<V> }
#[derive(Debug)]
pub(crate) enum MetadataMap<V> {
    Legacy(BTreeMap<u64,V>),
    Bounded { values:Vec<Slot<V>>, charge:Option<AllocationCharge>, live:usize },
}
impl<V> Default for MetadataMap<V> {fn default()->Self{Self::Legacy(BTreeMap::new())}}
impl<V> MetadataMap<V> {
    pub(crate) fn len(&self)->usize {match self{Self::Legacy(m)=>m.len(),Self::Bounded{live,..}=>*live}}
    #[cfg(any(test,feature="__control-test"))]
    pub(crate) fn capacity_bytes(&self)->usize {match self{Self::Legacy(_)=>0,Self::Bounded{values,..}=>values.capacity()*std::mem::size_of::<Slot<V>>()}}
    #[cfg(feature="__control-test")]
    pub(crate) fn next_allocation_bytes(&self)->usize {let n=match self{Self::Legacy(m)=>m.len()+1,Self::Bounded{values,..}=>values.capacity().saturating_mul(2)};n.next_power_of_two().max(4)*std::mem::size_of::<Slot<V>>()}
    pub(crate) fn reserve_insert(&mut self, credit:Option<&Arc<MetadataCredit>>)->Result<(),ResourceExhausted> {
        let Some(credit)=credit else{return Ok(());};
        if let Self::Bounded{values,live,..}=self {
            if values.len()==values.capacity() && *live<values.len(){values.retain(|s|s.value.is_some());}
            if values.len()<values.capacity(){return Ok(());}
        }
        let capacity=match self{Self::Legacy(m)=>m.len().checked_add(1).and_then(usize::checked_next_power_of_two),Self::Bounded{values,..}=>values.capacity().checked_mul(2)}
            .map(|n|n.max(4)).ok_or_else(||credit.fail(MetadataClass::SentRecords))?;
        let bytes=capacity.checked_mul(std::mem::size_of::<Slot<V>>()).ok_or_else(||credit.fail(MetadataClass::SentRecords))?;
        let charge=credit.reserve(bytes,MetadataClass::SentRecords)?;
        let mut next=Vec::new();next.try_reserve_exact(capacity).map_err(|_|credit.fail(MetadataClass::SentRecords))?;
        assert_eq!(next.capacity(),capacity,"metadata map capacity differs from reserved layout");credit.allocated();
        let old=std::mem::take(self);
        let live=old.len();
        match old {
            Self::Legacy(map)=>{for(key,value)in map{next.push(Slot{key,value:Some(value)});}},
            Self::Bounded{mut values,charge:old_charge,..}=>{next.append(&mut values);drop(values);drop(old_charge);},
        }
        *self=Self::Bounded{values:next,charge:Some(charge),live};Ok(())
    }
    pub(crate) fn insert(&mut self,key:u64,value:V)->Option<V>{match self{
        Self::Legacy(m)=>m.insert(key,value),
        Self::Bounded{values,live,..}=>match values.binary_search_by_key(&key,|s|s.key){
            Ok(i)=>{let old=values[i].value.replace(value);if old.is_none(){*live+=1;}old},
            Err(i)=>{assert!(values.len()<values.capacity(),"sent record insertion was not preflighted");values.insert(i,Slot{key,value:Some(value)});*live+=1;None},
        }
    }}
    pub(crate) fn remove(&mut self,key:&u64)->Option<V>{match self{Self::Legacy(m)=>m.remove(key),Self::Bounded{values,live,..}=>{let i=values.binary_search_by_key(key,|s|s.key).ok()?;let value=values[i].value.take();if value.is_some(){*live-=1;}value}}}
    pub(crate) fn get(&self,key:&u64)->Option<&V>{match self{Self::Legacy(m)=>m.get(key),Self::Bounded{values,..}=>values.binary_search_by_key(key,|s|s.key).ok().and_then(|i|values[i].value.as_ref())}}
    pub(crate) fn range<R:RangeBounds<u64>>(&self,bounds:R)->MapRange<'_,V>{match self{
        Self::Legacy(m)=>MapRange::Legacy(m.range(bounds)),
        Self::Bounded{values,..}=>{
            let lo=match bounds.start_bound(){Bound::Unbounded=>0,Bound::Included(k)=>values.partition_point(|s|s.key<*k),Bound::Excluded(k)=>values.partition_point(|s|s.key<=*k)};
            let hi=match bounds.end_bound(){Bound::Unbounded=>values.len(),Bound::Included(k)=>values.partition_point(|s|s.key<=*k),Bound::Excluded(k)=>values.partition_point(|s|s.key<*k)};
            MapRange::Bounded(values[lo..hi].iter())
        }
    }}
    pub(crate) fn values(&self)->impl Iterator<Item=&V>{self.range(..).map(|(_,v)|v)}
    pub(crate) fn values_mut(&mut self)->MapValuesMut<'_,V>{match self{Self::Legacy(m)=>MapValuesMut::Legacy(m.values_mut()),Self::Bounded{values,..}=>MapValuesMut::Bounded(values.iter_mut())}}
    pub(crate) fn into_values(self)->impl Iterator<Item=V>{self.into_iter().map(|(_,v)|v)}
}
impl<V> Index<&u64> for MetadataMap<V>{type Output=V;fn index(&self,key:&u64)->&V{self.get(key).expect("missing packet")}}
pub(crate) enum MapRange<'a,V>{Legacy(btree_map::Range<'a,u64,V>),Bounded(std::slice::Iter<'a,Slot<V>>)}
impl<'a,V> Iterator for MapRange<'a,V>{type Item=(&'a u64,&'a V);fn next(&mut self)->Option<Self::Item>{match self{Self::Legacy(i)=>i.next(),Self::Bounded(i)=>i.find_map(|s|s.value.as_ref().map(|v|(&s.key,v)))}}}
impl<V> DoubleEndedIterator for MapRange<'_,V>{fn next_back(&mut self)->Option<Self::Item>{match self{Self::Legacy(i)=>i.next_back(),Self::Bounded(i)=>i.rev().find_map(|s|s.value.as_ref().map(|v|(&s.key,v)))}}}
pub(crate) enum MapValuesMut<'a,V>{Legacy(btree_map::ValuesMut<'a,u64,V>),Bounded(std::slice::IterMut<'a,Slot<V>>)}
impl<'a,V> Iterator for MapValuesMut<'a,V>{type Item=&'a mut V;fn next(&mut self)->Option<Self::Item>{match self{Self::Legacy(i)=>i.next(),Self::Bounded(i)=>i.find_map(|s|s.value.as_mut())}}}
pub(crate) enum MapIntoIter<V>{Legacy(btree_map::IntoIter<u64,V>),Bounded{values:std::vec::IntoIter<Slot<V>>,_charge:Option<AllocationCharge>}}
impl<V> Iterator for MapIntoIter<V>{type Item=(u64,V);fn next(&mut self)->Option<Self::Item>{match self{Self::Legacy(i)=>i.next(),Self::Bounded{values,..}=>values.find_map(|s|s.value.map(|v|(s.key,v)))}}}
impl<V> IntoIterator for MetadataMap<V>{type Item=(u64,V);type IntoIter=MapIntoIter<V>;fn into_iter(self)->Self::IntoIter{match self{Self::Legacy(m)=>MapIntoIter::Legacy(m.into_iter()),Self::Bounded{values,charge,..}=>MapIntoIter::Bounded{values:values.into_iter(),_charge:charge}}}}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_ordered_records_keep_capacity_until_iterator_drop() {
        let credit=MetadataCredit::new(4096);
        let mut map=MetadataMap::default();let mut model=BTreeMap::new();
        for key in 0..32 {map.reserve_insert(Some(&credit)).unwrap();map.insert(key,key*3);model.insert(key,key*3);}
        for key in (0..32).step_by(2) {assert_eq!(map.remove(&key),model.remove(&key));}
        assert_eq!(map.range(3..27).map(|(k,v)|(*k,*v)).collect::<Vec<_>>(),model.range(3..27).map(|(k,v)|(*k,*v)).collect::<Vec<_>>());
        for key in 32..48 {map.reserve_insert(Some(&credit)).unwrap();map.insert(key,key*3);model.insert(key,key*3);}
        assert_eq!(map.values().copied().collect::<Vec<_>>(),model.values().copied().collect::<Vec<_>>());
        let bytes=map.capacity_bytes();assert_eq!(credit.stats().used,((bytes+63)&!63)+64);
        let mut retired=map.into_values();retired.next();assert!(credit.stats().used>0);
        drop(retired);assert_eq!(credit.stats().used,0);
    }
}
