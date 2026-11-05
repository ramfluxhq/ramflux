// SPDX-License-Identifier: MIT OR Apache-2.0
//! Connectionless response allocation permits, paired with their backing until destruction.
use std::sync::{Arc, Mutex};
use crate::Transmit;

/// Maximum stateless response datagram backing.
pub const RESPONSE_SLAB: usize = 65536;
/// Endpoint-owned stateless response allocation pool.
#[derive(Debug)]
pub struct ResponsePool { items: usize, bytes: usize, state: Mutex<ResponseStats>, closed: std::sync::atomic::AtomicBool }
/// Fixed-label response allocation diagnostics.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResponseStats {
    /// Queue plus active response owners.
    pub items: usize,
    /// Reserved slab bytes.
    pub bytes: usize,
    /// Reserved per-item metadata allowance.
    pub metadata_bytes: usize,
    /// Successful slab allocation count.
    pub allocations: u64,
    /// stateless_response_full drops.
    pub full: u64,
    /// stateless_response_closed drops after sender cancellation.
    pub closed: u64,
    /// stateless_response_oversize drops.
    pub oversize: u64,
}
#[derive(Debug)]
struct Permit { pool: Arc<ResponsePool> }
impl Drop for Permit { fn drop(&mut self) { let mut s=self.pool.state.lock().unwrap(); s.items-=1; s.bytes-=RESPONSE_SLAB; s.metadata_bytes-=512; } }
impl ResponsePool {
    /// Construct a frozen pool. Byte overrides may only lower the item-derived ceiling.
    /// # Errors
    /// Rejects zero, impossible, overflowing or out-of-range limits.
    pub fn new(items: usize, bytes: usize) -> Result<Arc<Self>, &'static str> {
        if !(1..=128).contains(&items) || bytes < RESPONSE_SLAB || items.checked_mul(RESPONSE_SLAB).is_none_or(|n| bytes>n) { return Err("invalid stateless response limits"); }
        Ok(Arc::new(Self {items, bytes, state: Mutex::new(ResponseStats::default()), closed: std::sync::atomic::AtomicBool::new(false)}))
    }
    /// Current bounded owners and fixed-label counters.
    pub fn stats(&self) -> ResponseStats { *self.state.lock().unwrap() }
    /// Maximum number of responses; useful for sizing a fixed send ring.
    pub fn capacity(&self) -> usize { self.items.min(self.bytes / RESPONSE_SLAB) }
    /// Refuse all future response allocations after endpoint cancellation.
    pub fn close(&self) { self.closed.store(true, std::sync::atomic::Ordering::SeqCst); }
    fn reserve(self: &Arc<Self>) -> Option<Permit> {
        let mut s=self.state.lock().unwrap();
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) { s.closed=s.closed.saturating_add(1); return None; }
        if s.items==self.items || RESPONSE_SLAB > self.bytes-s.bytes { s.full=s.full.saturating_add(1); return None; }
        s.items+=1; s.bytes+=RESPONSE_SLAB; s.metadata_bytes+=512;
        Some(Permit {pool:self.clone()})
    }
}
/// Builder which allocates no backing until a concrete response producer reserves its pool.
#[derive(Debug)]
pub struct ResponseBuffer { pool: Arc<ResponsePool>, bytes: Vec<u8>, permit: Option<Permit> }
impl ResponseBuffer {
    /// Empty response builder, with no slab allocated or item reserved.
    pub fn new(pool: Arc<ResponsePool>) -> Self { Self {pool, bytes:Vec::new(), permit:None} }
    fn prepare(&mut self, bound: usize) -> Option<&mut Vec<u8>> {
        if bound>RESPONSE_SLAB { let mut s=self.pool.state.lock().unwrap(); s.oversize=s.oversize.saturating_add(1); return None; }
        if self.permit.is_none() {
            let permit=self.pool.reserve()?;
            if self.bytes.try_reserve_exact(RESPONSE_SLAB).is_err() { drop(permit); let mut s=self.pool.state.lock().unwrap(); s.full=s.full.saturating_add(1); return None; }
            self.permit=Some(permit);
            let mut s=self.pool.state.lock().unwrap(); s.allocations=s.allocations.saturating_add(1);
        }
        Some(&mut self.bytes)
    }
    /// Finish a constructed response without detaching backing from its permit.
    pub fn finish(mut self, transmit: Transmit) -> Option<Response> {
        let permit=self.permit.take()?;
        assert!(transmit.size<=self.bytes.len() && self.bytes.capacity()==RESPONSE_SLAB);
        Some(Response {transmit, bytes:self.bytes, _permit:permit})
    }
}
/// A complete stateless datagram and its allocation owner.
#[derive(Debug)]
pub struct Response { transmit: Transmit, bytes: Vec<u8>, _permit: Permit }
impl Response {
    /// Wire transmit metadata.
    pub fn transmit(&self) -> &Transmit { &self.transmit }
    /// Initialized wire bytes; backing capacity remains charged separately.
    pub fn bytes(&self) -> &[u8] { &self.bytes[..self.transmit.size] }
}
pub(crate) enum Output<'a> { Legacy(&'a mut Vec<u8>), Bounded(&'a mut ResponseBuffer) }
impl Output<'_> {
    pub(crate) fn prepare(&mut self, bound: usize) -> Option<&mut Vec<u8>> { match self { Self::Legacy(buf)=>Some(buf), Self::Bounded(buf)=>buf.prepare(bound) } }
}
