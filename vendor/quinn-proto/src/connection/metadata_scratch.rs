// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fallible scratch backing, charged with concurrent old/new allocation overlap.
use super::metadata_credit::{AllocationCharge,MetadataClass,MetadataCredit,ResourceExhausted};
use std::{ops::Deref,sync::Arc};
#[derive(Debug)]
pub(crate) struct ScratchVec<T>{values:Vec<T>,charge:Option<AllocationCharge>,credit:Option<Arc<MetadataCredit>>,class:MetadataClass}
impl<T> ScratchVec<T>{
    pub(crate) fn new(credit:Option<Arc<MetadataCredit>>,class:MetadataClass)->Self{Self{values:Vec::new(),charge:None,credit,class}}
    pub(crate) fn try_push(&mut self,value:T)->Result<(),ResourceExhausted>{
        if let Some(credit)=&self.credit {
            if self.values.len()==self.values.capacity(){
                let n=self.values.capacity().checked_mul(2).map(|n|n.max(4)).ok_or_else(||credit.fail(self.class))?;
                let bytes=n.checked_mul(std::mem::size_of::<T>()).ok_or_else(||credit.fail(self.class))?;
                let charge=credit.reserve(bytes,self.class)?;let mut next=Vec::new();
                next.try_reserve_exact(n).map_err(|_|credit.fail(self.class))?;assert_eq!(next.capacity(),n);credit.allocated();
                next.append(&mut self.values);let old=std::mem::replace(&mut self.values,next);drop(old);self.charge=Some(charge);
            }
        }
        self.values.push(value);Ok(())
    }
}
impl<T> Deref for ScratchVec<T>{type Target=[T];fn deref(&self)->&[T]{&self.values}}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scratch_growth_charges_actual_overlap_and_returns_on_drop(){
        let credit=MetadataCredit::new(320);let mut values=ScratchVec::new(Some(credit.clone()),MetadataClass::LossScratch);
        for n in 0..9 {values.try_push(n as u64).unwrap();}
        assert_eq!(values.values.capacity()*std::mem::size_of::<u64>(),128);assert_eq!(credit.stats().used,192);assert_eq!(credit.stats().peak,320);
        drop(values);assert_eq!(credit.stats().used,0);
    }
}
