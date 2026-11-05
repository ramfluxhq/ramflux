// SPDX-License-Identifier: MIT OR Apache-2.0
//! STREAM frame metadata backing which carries its capacity charge through packet retirement.
use super::metadata_credit::{AllocationCharge, MetadataClass, MetadataCredit, ResourceExhausted};
use crate::frame::StreamMeta;
use std::{ops::{Deref,DerefMut}, sync::Arc};
use tinyvec::TinyVec;

#[derive(Debug)]
pub(crate) enum StreamMetaVec {
    Legacy(TinyVec<[StreamMeta;1]>),
    Bounded { values: TinyVec<[StreamMeta;1]>, charge: Option<AllocationCharge>, credit: Arc<MetadataCredit> },
}
impl Default for StreamMetaVec { fn default() -> Self { Self::Legacy(TinyVec::new()) } }
impl StreamMetaVec {
    #[cfg(feature="__control-test")]
    pub(crate) fn heap_capacity_bytes(&self) -> usize {
        match self {
            Self::Legacy(v)=>if v.is_heap(){v.capacity()*std::mem::size_of::<StreamMeta>()}else{0},
            Self::Bounded {values,..}=>if values.is_heap(){values.capacity()*std::mem::size_of::<StreamMeta>()}else{0},
        }
    }

    pub(crate) fn with_metadata(credit: Option<Arc<MetadataCredit>>) -> Self {
        match credit { None=>Self::default(),Some(credit)=>Self::Bounded {values:TinyVec::new(),charge:None,credit} }
    }
    pub(crate) fn reserve_frame(&mut self) -> Result<(),ResourceExhausted> {
        let Self::Bounded {values,charge,credit}=self else {return Ok(());};
        if values.len()<values.capacity() {return Ok(());}
        let capacity=values.capacity().checked_mul(2).map(|n|n.max(4)).ok_or_else(||credit.fail(MetadataClass::SentFrameMetadata))?;
        let bytes=capacity.checked_mul(std::mem::size_of::<StreamMeta>()).ok_or_else(||credit.fail(MetadataClass::SentFrameMetadata))?;
        let next_charge=credit.reserve(bytes,MetadataClass::SentFrameMetadata)?;
        let mut next=Vec::new();
        next.try_reserve_exact(capacity).map_err(|_|credit.fail(MetadataClass::SentFrameMetadata))?;
        assert_eq!(next.capacity(),capacity,"metadata allocation layout differs from requested capacity");
        credit.allocated();next.extend(values.drain(..));
        let old=std::mem::replace(values,TinyVec::Heap(next));drop(old);*charge=Some(next_charge);
        Ok(())
    }
    pub(crate) fn push(&mut self, value: StreamMeta) {
        match self {Self::Legacy(v)=>v.push(value),Self::Bounded {values,..}=>{assert!(values.len()<values.capacity());values.push(value);}}
    }
}
impl Deref for StreamMetaVec {
    type Target=[StreamMeta];
    fn deref(&self) -> &Self::Target {match self {Self::Legacy(v)=>v.as_slice(),Self::Bounded {values,..}=>values.as_slice()}}
}
impl DerefMut for StreamMetaVec {
    fn deref_mut(&mut self) -> &mut Self::Target {match self {Self::Legacy(v)=>v.as_mut_slice(),Self::Bounded {values,..}=>values.as_mut_slice()}}
}
pub(crate) struct StreamMetaIntoIter { inner: StreamMetaVec, next: usize }
impl Iterator for StreamMetaIntoIter {
    type Item=StreamMeta;
    fn next(&mut self)->Option<StreamMeta> {if self.next==self.inner.len(){return None;}let n=self.next;self.next+=1;Some(std::mem::take(&mut self.inner[n]))}
    fn size_hint(&self)->(usize,Option<usize>) {let n=self.inner.len()-self.next;(n,Some(n))}
}
impl ExactSizeIterator for StreamMetaIntoIter {}
impl IntoIterator for StreamMetaVec {
    type Item=StreamMeta;type IntoIter=StreamMetaIntoIter;
    fn into_iter(self)->Self::IntoIter {StreamMetaIntoIter {inner:self,next:0}}
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_capacity_charge_follows_iterator_and_overlap() {
        let credit=MetadataCredit::new(512);
        let mut frames=StreamMetaVec::with_metadata(Some(credit.clone()));
        for _ in 0..5 {frames.reserve_frame().unwrap();frames.push(StreamMeta::default());}
        let StreamMetaVec::Bounded {values,..}=&frames else {panic!("bounded");};
        assert_eq!(values.capacity()*std::mem::size_of::<StreamMeta>(),256);
        assert_eq!(credit.stats().used,320);
        assert_eq!(credit.stats().peak,512);
        let mut consumed=frames.into_iter();
        consumed.next();
        assert_eq!(credit.stats().used,320,"iterator still owns backing after a partial consume");
        drop(consumed);
        assert_eq!(credit.stats().used,0);
    }
}
