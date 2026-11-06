// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared actual-capacity metadata reservations. Unimplemented classes remain uncertified.
use std::sync::{Arc, Mutex};

/// Allocation family; these are diagnostics, never independent item caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum MetadataClass {
    /// Sent packet map and in-progress builders.
    SentRecords,
    /// STREAM metadata heap capacity.
    SentFrameMetadata,
    /// Boxed retransmit owners and children.
    RetransmitOwners,
    /// Send-buffer deque backing.
    SendSegments,
    /// Send ACK and retransmit ranges.
    SendRanges,
    /// STREAM receive assembler state.
    StreamAssemblers,
    /// CRYPTO receive assembler state.
    CryptoAssemblers,
    /// Consumed unordered receive history.
    UnorderedHistory,
    /// Loss-to-pending ownership transfers.
    PendingRetransmits,
    /// Pending ACK heap capacity.
    PendingAcks,
    /// ACK processing scratch.
    AckScratch,
    /// Loss processing scratch.
    LossScratch,
}
/// Attempted metadata growth which cannot be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceExhausted { pub(crate) class: MetadataClass }
impl ResourceExhausted {
    /// Allocation family which could not grow.
    pub const fn class(&self) -> MetadataClass { self.class }
}
/// Credit observation; capacity is charged once, with no second factor-two multiplier.
#[derive(Clone, Copy, Debug, Default)]
pub struct MetadataStats {
    /// Decrypted packet payload length observed at admission, before copy reservation/allocation.
    pub receive_payload_len: usize,
    /// Actual capacity of the most recent admitted receive payload copy.
    /// Owner/refcount-envelope allocation is not included or certified by this component.
    pub receive_backing_capacity: usize,
    /// Frozen byte ceiling.
    pub limit: usize,
    /// Live allocation charges.
    pub used: usize,
    /// Maximum simultaneous old/new allocation charges.
    pub peak: usize,
    /// Refused allocation attempts.
    pub refusals: u64,
    /// Actual successful allocation sites reached after admission.
    pub allocations: u64,
    /// Whether a producer requires terminal resource-close.
    pub exhausted: bool,
    /// Family of the first refused growth.
    pub failed_class: Option<MetadataClass>,
}
#[derive(Debug)]
pub(crate) struct MetadataCredit { state: Mutex<MetadataStats> }
#[derive(Debug)]
pub(crate) struct AllocationCharge { credit: Arc<MetadataCredit>, bytes: usize }
impl MetadataCredit {
    #[cfg(any(test,feature="__control-test"))]
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self { state: Mutex::new(MetadataStats { limit, ..MetadataStats::default() }) })
    }
    pub(crate) fn stats(&self) -> MetadataStats { *self.state.lock().unwrap() }
    pub(crate) fn fail(&self, class: MetadataClass) -> ResourceExhausted {
        let mut s=self.state.lock().unwrap(); if !s.exhausted{s.failed_class=Some(class);} s.exhausted=true; s.refusals=s.refusals.saturating_add(1); ResourceExhausted { class }
    }
    pub(crate) fn reserve(self: &Arc<Self>, capacity: usize, class: MetadataClass) -> Result<AllocationCharge, ResourceExhausted> {
        let bytes=capacity.checked_add(63).map(|n|n&!63).and_then(|n|n.checked_add(64));
        let mut s=self.state.lock().unwrap();
        if s.exhausted || bytes.is_none_or(|n|n>s.limit.saturating_sub(s.used)) {
            if !s.exhausted{s.failed_class=Some(class);} s.exhausted=true; s.refusals=s.refusals.saturating_add(1);return Err(ResourceExhausted { class });
        }
        let bytes=bytes.unwrap();s.used+=bytes;s.peak=s.peak.max(s.used);
        Ok(AllocationCharge { credit:self.clone(), bytes })
    }
    pub(crate) fn observe_receive_payload_len(&self, length:usize){self.state.lock().unwrap().receive_payload_len=length;}
    pub(crate) fn receive_backing_capacity(&self, capacity:usize){self.state.lock().unwrap().receive_backing_capacity=capacity;}
    pub(crate) fn allocated(&self) { let mut s=self.state.lock().unwrap();s.allocations=s.allocations.saturating_add(1); }
}
impl Drop for AllocationCharge {
    fn drop(&mut self) { self.credit.state.lock().unwrap().used-=self.bytes; }
}
/// Test observer retains the credit ledger, never the allocations it observes.
#[cfg(feature="__control-test")]
#[derive(Clone, Debug)]
pub struct MetadataProbe(pub(crate) Arc<MetadataCredit>);
#[cfg(feature="__control-test")]
impl MetadataProbe {
    /// Dependency-test fault injection: freeze the ceiling at actual currently live charges.
    pub fn freeze_at_live_allocations(&self) {let mut s=self.0.state.lock().unwrap();assert!(!s.exhausted);s.limit=s.used;}

    /// Current shared capacity and allocation-site counters.
    pub fn stats(&self) -> MetadataStats { self.0.stats() }
}

impl super::Connection {
    /// Whether a fallible metadata producer has requested the terminal adapter.
    pub fn metadata_exhausted(&self) -> bool { self.metadata.as_ref().is_some_and(|m|m.stats().exhausted) }
    /// Configure dormant send metadata hooks in dependency tests only.
    /// Receive payload hooks are partial; no complete receive class, activation or certificate.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_limit(&mut self, limit: usize) -> MetadataProbe {
        assert!(self.metadata.is_none());
        assert_eq!(self.streams.metadata_send_storage().0,0,"test hooks must precede send backing allocation");
        let credit=MetadataCredit::new(limit);
        for space in self.spaces.iter_mut(){
            if space.pending.is_empty(&self.streams){space.pending=super::spaces::Retransmits::with_metadata(Some(credit.clone()),MetadataClass::PendingRetransmits);}
            else {let _=space.pending.bind(Some(credit.clone()),MetadataClass::PendingRetransmits);}
        }
        self.streams.metadata=Some(credit.clone());
        self.metadata=Some(credit.clone());
        MetadataProbe(credit)
    }
    /// Actual pending descriptor backing across packet spaces, independent of the ledger.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_pending_storage(&self)->usize{self.spaces.iter().map(|s|s.pending.capacity_bytes()).sum()}
    /// Actual sent boxed-owner and child backing sizes.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_retransmit_storage(&self)->(usize,usize){self.spaces.iter().flat_map(|s|s.sent_packets.values()).map(|p|p.retransmits.storage()).fold((0,0),|(a,b),(c,d)|(a+c,b+d))}
    /// Layout-derived optional owner allocation charge.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_box_charge(&self)->usize{super::spaces::ThinRetransmits::box_charge()}
    /// Destroy empty pending reset backing before forcing a real PTO transfer.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_release_empty_pending_reset(&mut self){
        let pending=&mut self.spaces[super::SpaceId::Data].pending;
        assert!(pending.reset_stream.is_empty());
        pending.reset_stream=Default::default();
        pending.reset_stream.bind(self.metadata.clone(),MetadataClass::PendingRetransmits).unwrap();
    }
    /// Actual retained send deque capacity and queued byte offsets, independent of credit counters.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_send_storage(&self) -> (usize,u64) { self.streams.metadata_send_storage() }




    /// Force an ordinary peer ACK after a controlled ACK in the driver race regression.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_force_ack(&mut self){self.spaces[super::SpaceId::Data].pending_acks.set_immediate_ack_required();}
    /// Actual retained pending-ACK heap backing across packet spaces.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_ack_storage(&self)->usize{self.spaces.iter().map(|s|s.pending_acks.ranges().heap_capacity_bytes()).sum()}
    /// Actual retained Data ACK range count, independent of metadata credit.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_ack_ranges(&self)->usize{self.spaces[super::SpaceId::Data].pending_acks.ranges().len()}

    /// Actual send ACK/retransmit range counts for driver tests.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_send_ranges(&self)->(usize,usize){self.streams.metadata_send_ranges()}
    /// Actual STREAM offsets retained under Data packet numbers.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_stream_packets(&self)->Vec<(u64,u64)>{self.spaces[super::SpaceId::Data].sent_packets.range(..).flat_map(|(n,p)|p.stream_frames.iter().map(move|f|(*n,f.offsets.start))).collect()}
    /// Actual live Data packet numbers for driver-level ACK/loss fault injection.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_sent_numbers(&self)->Vec<u64>{self.spaces[super::SpaceId::Data].sent_packets.range(..).map(|(n,_)|*n).collect()}
    /// Next nonduplicate incoming Data number used by wire-level test injection.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_next_received(&self)->u64{self.spaces[super::SpaceId::Data].rx_packet+1}
    /// Actual retained packet record-table capacity, independent of ledger counters.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_record_storage(&self)->usize {self.spaces.iter().map(|s|s.sent_packets.capacity_bytes()).sum()}
    /// Layout-derived charge for the next Data-space record-table allocation.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_next_record_charge(&self)->usize {((self.spaces[super::SpaceId::Data].sent_packets.next_allocation_bytes()+63)&!63)+64}
    /// Actual sent packet STREAM metadata heap capacity, independent of credit counters.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_frame_storage(&self) -> usize {
        self.spaces.iter().flat_map(|s|s.sent_packets.values()).map(|p|p.stream_frames.heap_capacity_bytes()).sum()
    }
}

impl std::fmt::Display for ResourceExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f,"metadata capacity exhausted: {:?}",self.class) }
}
impl std::error::Error for ResourceExhausted {}
