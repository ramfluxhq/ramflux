// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fallible receive compaction retaining old descriptor and payload allocations.
use super::*;
use crate::connection::metadata_backing::copy_payload_with;

impl Assembler {
    pub(super) fn defragment_metadata(&mut self) -> Result<(),TooManyChunks> {
        if self.data.is_empty() { return Ok(()); }
        let(credit,class)=self.data.context().unwrap();
        let min_size=max(self.buffered.div_ceil(MAX_CHUNKS),MIN_RETAINED_CHUNK_SIZE);
        // Reserve a destination while the complete old heap is still charged.
        let next=self.data.replacement(self.data.len())?;
        let mut old=mem::replace(&mut self.data,next);
        // `old` holds the lease; buffers is declared after it and freed first on unwind.
        let buffers=mem::take(&mut old.values).into_sorted_vec();
        let mut end=0;let mut fragmented=0usize;let mut buffered=0usize;
        for original in buffers.iter().rev() {
            let mut chunk=original.clone();chunk.try_mark_defragment(end);
            end=chunk.offset+chunk.bytes.len() as u64;
            buffered+=chunk.bytes.len();
            if !chunk.defragmented || chunk.bytes.len()<min_size { fragmented+=chunk.bytes.len(); }
        }
        let copied=if fragmented==0 { Ok(Bytes::new()) } else {
            copy_payload_with(fragmented,None,&credit,class,|bytes| {
                let mut end=0;
                for original in buffers.iter().rev() {
                    let mut chunk=original.clone();chunk.try_mark_defragment(end);
                    end=chunk.offset+chunk.bytes.len() as u64;
                    if !chunk.defragmented || chunk.bytes.len()<min_size { bytes.extend_from_slice(&chunk.bytes); }
                }
            })
        };
        let copied=match copied {
            Ok(bytes)=>bytes,
            Err(_)=>{
                old.values=std::collections::BinaryHeap::from(buffers);
                let refused=mem::replace(&mut self.data,old);drop(refused);
                return Err(TooManyChunks);
            }
        };
        let mut end=0;let mut cursor=0;let mut group_start=0;let mut group_offset=0;let mut group_len=0;
        for original in buffers.iter().rev() {
            let mut chunk=original.clone();chunk.try_mark_defragment(end);
            end=chunk.offset+chunk.bytes.len() as u64;
            if chunk.bytes.is_empty() { continue; }
            let keep=chunk.defragmented && chunk.bytes.len()>=min_size;
            if group_len!=0 && (keep || chunk.offset!=group_offset+group_len as u64) {
                self.data.push_reserved(Buffer::new_defragmented(group_offset,copied.slice(group_start..group_start+group_len)));
                group_len=0;
            }
            if keep { self.data.push_reserved(chunk);continue; }
            if group_len==0 { group_start=cursor;group_offset=chunk.offset; }
            group_len+=chunk.bytes.len();cursor+=chunk.bytes.len();
        }
        if group_len!=0 { self.data.push_reserved(Buffer::new_defragmented(group_offset,copied.slice(group_start..group_start+group_len))); }
        assert_eq!(cursor,fragmented);
        self.buffered=buffered;self.allocated=buffered;
        drop(buffers);drop(old); // Actual old descriptor storage before its lease.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receive_heap_compaction_overlap_and_retained_reinitialization() {
        for class in [MetadataClass::StreamAssemblers,MetadataClass::CryptoAssemblers] {
            let credit=MetadataCredit::new(1<<20);
            let mut assembler=Assembler::new();assembler.bind(Some(credit.clone()),class).unwrap();
            assembler.insert(0,Bytes::from_static(b"abc"),3).unwrap();
            assembler.insert(3,Bytes::from_static(b"def"),3).unwrap();
            let old_capacity=assembler.metadata_storage().0;
            assert!(old_capacity>=2*std::mem::size_of::<Buffer>());
            let old_charge=((old_capacity+63)&!63)+64;
            assert_eq!(credit.stats().used,old_charge);
            assembler.defragment().unwrap();
            let new_capacity=assembler.metadata_storage().0;
            assert_eq!(assembler.metadata_storage().1,1);
            assert_eq!(new_capacity,2*std::mem::size_of::<Buffer>());
            let descriptor_charge=((new_capacity+63)&!63)+64;
            assert!(credit.stats().peak>old_charge+descriptor_charge,"replacement and copy overlap old descriptors");
            let chunk=assembler.read(usize::MAX,true).unwrap();assert_eq!(&chunk.bytes[..],b"abcdef");
            assembler.clear();assembler.reinit();
            assert_eq!(assembler.metadata_storage(),(new_capacity,0));
            drop(chunk);assert_eq!(credit.stats().used,descriptor_charge,"empty retained descriptor backing stays charged");
            drop(assembler);assert_eq!(credit.stats().used,0);
        }
    }
    #[test]
    fn refused_compaction_copy_restores_old_heap_and_exact_bytes() {
        let mut initial=Assembler::new();let generous=MetadataCredit::new(1<<20);
        initial.bind(Some(generous.clone()),MetadataClass::StreamAssemblers).unwrap();
        initial.insert(0,Bytes::from_static(b"abc"),3).unwrap();initial.insert(3,Bytes::from_static(b"def"),3).unwrap();
        let old_capacity=initial.metadata_storage().0;drop(initial);
        let old_charge=((old_capacity+63)&!63)+64;
        let next_capacity=2*std::mem::size_of::<Buffer>();let next_charge=((next_capacity+63)&!63)+64;
        // The replacement heap fits exactly, leaving no credit for the compaction copy.
        let credit=MetadataCredit::new(old_charge+next_charge);
        let mut assembler=Assembler::new();assembler.bind(Some(credit.clone()),MetadataClass::StreamAssemblers).unwrap();
        assembler.insert(0,Bytes::from_static(b"abc"),3).unwrap();assembler.insert(3,Bytes::from_static(b"def"),3).unwrap();
        assert!(assembler.defragment().is_err());assert_eq!(assembler.metadata_storage(),(old_capacity,2));
        assert_eq!(credit.stats().used,old_charge);
        assert_eq!(&assembler.read(usize::MAX,true).unwrap().bytes[..],b"abc");
        assert_eq!(&assembler.read(usize::MAX,true).unwrap().bytes[..],b"def");
        drop(assembler);assert_eq!(credit.stats().used,0);
    }
}

#[cfg(test)]
mod space_tests {
    use super::*;
    #[test]
    fn all_three_crypto_spaces_hold_descriptor_credit_until_destroyed() {
        use crate::connection::spaces::PacketSpace;
        let credit=MetadataCredit::new(1<<20);
        let mut spaces=std::array::from_fn::<_,3,_>(|_|PacketSpace::new(crate::Instant::now()));
        for space in &mut spaces {
            space.crypto_stream.bind(Some(credit.clone()),MetadataClass::CryptoAssemblers).unwrap();
            space.crypto_stream.insert(0,Bytes::from_static(b"crypto"),6).unwrap();
            assert_eq!(&space.crypto_stream.read(usize::MAX,true).unwrap().bytes[..],b"crypto");
            space.crypto_stream.clear();space.crypto_stream.reinit();
            assert!(space.crypto_stream.metadata_storage().0>0);
        }
        let capacities:usize=spaces.iter().map(|s|((s.crypto_stream.metadata_storage().0+63)&!63)+64).sum();
        assert_eq!(credit.stats().used,capacities);
        drop(spaces);assert_eq!(credit.stats().used,0);
    }
}
