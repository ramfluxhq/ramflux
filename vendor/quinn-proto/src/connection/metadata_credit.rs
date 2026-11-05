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
    /// Family of the most recent refused growth.
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
        let mut s=self.state.lock().unwrap(); s.exhausted=true; s.failed_class=Some(class); s.refusals=s.refusals.saturating_add(1); ResourceExhausted { class }
    }
    pub(crate) fn reserve(self: &Arc<Self>, capacity: usize, class: MetadataClass) -> Result<AllocationCharge, ResourceExhausted> {
        let bytes=capacity.checked_add(63).map(|n|n&!63).and_then(|n|n.checked_add(64));
        let mut s=self.state.lock().unwrap();
        if s.exhausted || bytes.is_none_or(|n|n>s.limit.saturating_sub(s.used)) {
            s.exhausted=true; s.failed_class=Some(class); s.refusals=s.refusals.saturating_add(1);return Err(ResourceExhausted { class });
        }
        let bytes=bytes.unwrap();s.used+=bytes;s.peak=s.peak.max(s.used);
        Ok(AllocationCharge { credit:self.clone(), bytes })
    }
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
    /// Current shared capacity and allocation-site counters.
    pub fn stats(&self) -> MetadataStats { self.0.stats() }
}

impl super::Connection {
    /// Whether a fallible metadata producer has requested the terminal adapter.
    pub fn metadata_exhausted(&self) -> bool { self.metadata.as_ref().is_some_and(|m|m.stats().exhausted) }
    /// Configure the partial send-segment hook in dependency tests only.
    /// Other metadata classes have no activation API or certificate yet.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_limit(&mut self, limit: usize) -> MetadataProbe {
        assert!(self.metadata.is_none());
        assert_eq!(self.streams.metadata_send_storage().0,0,"test hooks must precede send backing allocation");
        let credit=MetadataCredit::new(limit);
        self.streams.metadata=Some(credit.clone());
        self.metadata=Some(credit.clone());
        MetadataProbe(credit)
    }
    /// Actual retained send deque capacity and queued byte offsets, independent of credit counters.
    #[cfg(feature="__control-test")]
    pub fn metadata_test_send_storage(&self) -> (usize,u64) { self.streams.metadata_send_storage() }
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
