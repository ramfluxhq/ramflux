// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receipt history remains after data ownership has moved to the application.
use super::*;
#[test]
fn history_survives_consumption_duplicate_retransmit_clear_and_reinit() {
    let credit=MetadataCredit::new(1<<20);let mut assembler=Assembler::new();
    assembler.bind(Some(credit.clone()),MetadataClass::StreamAssemblers).unwrap();assembler.ensure_ordering(false).unwrap();
    for offset in [1,3,5] {assembler.insert(offset,Bytes::from_static(b"x"),1).unwrap();assert_eq!(&assembler.read(1,false).unwrap().bytes[..],b"x");}
    assert_eq!(assembler.metadata_history_storage(),(64,3));
    let descriptor=assembler.metadata_storage().0;
    let descriptor_charge=((descriptor+63)&!63)+64;
    assert_eq!(credit.stats().used,descriptor_charge+128);
    assembler.insert(3,Bytes::from_static(b"x"),1).unwrap();assert!(assembler.read(1,false).is_none());
    assembler.insert(7,Bytes::from_static(b"y"),1).unwrap();assert_eq!(&assembler.read(1,false).unwrap().bytes[..],b"y");
    assembler.clear();assert_eq!(assembler.metadata_history_storage(),(64,4));
    assembler.reinit();assert_eq!(assembler.metadata_history_storage(),(0,0));
    assert_eq!(credit.stats().used,descriptor_charge);drop(assembler);assert_eq!(credit.stats().used,0);
}
#[test]
fn refused_unordered_transition_preserves_ordered_heap_and_bytes() {
    let generous=MetadataCredit::new(1<<20);let mut probe=Assembler::new();probe.bind(Some(generous),MetadataClass::StreamAssemblers).unwrap();
    probe.insert(1,Bytes::from_static(b"x"),1).unwrap();let descriptor=probe.metadata_storage().0;drop(probe);
    let credit=MetadataCredit::new(((descriptor+63)&!63)+64);let mut assembler=Assembler::new();assembler.bind(Some(credit.clone()),MetadataClass::StreamAssemblers).unwrap();
    for offset in [1,3,5] {assembler.insert(offset,Bytes::from_static(b"x"),1).unwrap();}
    let before=assembler.metadata_storage();assert!(assembler.ensure_ordering(false).is_err());
    assert!(assembler.state.is_ordered());assert_eq!(assembler.metadata_storage(),before);
    assert_eq!(&assembler.data.peek().unwrap().bytes[..],b"x");
    assert_eq!(credit.stats().failed_class,Some(MetadataClass::UnorderedHistory));drop(assembler);assert_eq!(credit.stats().used,0);
}
