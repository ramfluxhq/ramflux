// SPDX-License-Identifier: MIT OR Apache-2.0
//! Observe the production payload and wrapper allocator boundaries independently.
use super::*;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{atomic::{AtomicBool, AtomicUsize, Ordering::*}, Condvar, Mutex},
};
thread_local! { static CAPTURE: Cell<usize> = const { Cell::new(0) }; }
static PAYLOAD: AtomicUsize = AtomicUsize::new(0);
static WRAPPER: AtomicUsize = AtomicUsize::new(0);
static PAYLOAD_LIVE: AtomicUsize = AtomicUsize::new(0);
static WRAPPER_LIVE: AtomicUsize = AtomicUsize::new(0);
static REQUEST: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static GATE: (Mutex<(bool, bool)>, Condvar) = (Mutex::new((false, false)), Condvar::new());
fn gate() -> &'static (Mutex<(bool, bool)>, Condvar) { &GATE }
struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
#[cfg(target_os="linux")]
extern "C" { fn malloc_usable_size(p: *mut std::ffi::c_void) -> usize; }
#[cfg(target_os="macos")]
extern "C" { fn malloc_size(p: *const std::ffi::c_void) -> usize; }
unsafe fn usable(p: *mut u8, layout: Layout) -> usize {
    #[cfg(target_os="linux")]
    { let _=layout; malloc_usable_size(p.cast()) }
    #[cfg(target_os="macos")]
    { let _=layout; malloc_size(p.cast()) }
    #[cfg(not(any(target_os="linux",target_os="macos")))]
    { let _=p; layout.size() }
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let index = CAPTURE.try_with(|capture| {
                let index=capture.get();
                if index>0 { capture.set(index+1); }
                index
            }).unwrap_or(0);
            if index>0 {
                COUNT.fetch_add(1,SeqCst);
                let actual=usable(ptr,layout);
                if index==1 { PAYLOAD.store(ptr as usize,SeqCst); PAYLOAD_LIVE.store(actual,SeqCst); }
                if index==2 { WRAPPER.store(ptr as usize,SeqCst); WRAPPER_LIVE.store(actual,SeqCst); REQUEST.store(layout.size(),SeqCst); }
                PEAK.fetch_max(PAYLOAD_LIVE.load(SeqCst)+WRAPPER_LIVE.load(SeqCst),SeqCst);
            }
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if PAYLOAD.compare_exchange(ptr as usize,usize::MAX,SeqCst,SeqCst).is_ok() {
            System.dealloc(ptr,layout);
            PAYLOAD_LIVE.store(0,SeqCst);PAYLOAD.store(0,SeqCst);
        } else if WRAPPER.compare_exchange(ptr as usize,usize::MAX,SeqCst,SeqCst).is_ok() {
            if ARMED.load(SeqCst) {
            let mut state=gate().0.lock().unwrap();
            state.0=true;gate().1.notify_all();
            while !state.1 { state=gate().1.wait(state).unwrap(); }
            drop(state);
            }
            System.dealloc(ptr,layout);
            WRAPPER_LIVE.store(0,SeqCst);WRAPPER.store(0,SeqCst);
        } else { System.dealloc(ptr,layout); }
    }
}
#[test]
#[cfg(any(target_os="linux",target_os="macos"))]
fn production_owner_credit_outlives_actual_wrapper_free() {
    drop(gate().0.lock().unwrap()); // Warm the platform mutex outside allocation tracking.
    let layout=owner_layout();
    let owner_charge=((layout.size()+63)&!63)+64;
    let credit=MetadataCredit::new(128+owner_charge);
    struct RawOwner(Arc<AtomicBool>);
    impl Drop for RawOwner {
        fn drop(&mut self) { self.0.store(true,SeqCst); }
    }
    let raw_dropped=Arc::new(AtomicBool::new(false));
    let raw_owner=Arc::new(RawOwner(raw_dropped.clone()));
    let _=credit.stats(); // Initialize the fixed ledger mutex outside backing-allocation observation.
    CAPTURE.with(|c|c.set(1));
    let bytes=super::super::metadata_backing::copy_payload(&[0x5a],Some(raw_owner),&credit,MetadataClass::StreamAssemblers).unwrap();
    CAPTURE.with(|c|c.set(0));
    assert_eq!(COUNT.load(SeqCst),2,"one payload and one owner allocation");
    assert_eq!(REQUEST.load(SeqCst),layout.size(),"constructor layout matches the allocator request");
    assert!(PEAK.load(SeqCst)<=credit.stats().limit,"actual usable extents fit admitted allowance on this allocator");
    CAPTURE.with(|c|c.set(3));
    let slice=bytes.slice(..);let clone=slice.clone();
    CAPTURE.with(|c|c.set(0));
    assert_eq!(COUNT.load(SeqCst),2,"clones and slices allocate no wrapper");
    drop((bytes,slice));
    assert_eq!(&clone[..],&[0x5a]);assert!(WRAPPER_LIVE.load(SeqCst)>0);
    ARMED.store(true,SeqCst);
    let worker=std::thread::spawn(move || drop(clone));
    let mut state=gate().0.lock().unwrap();
    while !state.0 { state=gate().1.wait(state).unwrap(); }
    let payload_live=PAYLOAD_LIVE.load(SeqCst);
    let wrapper_live=WRAPPER_LIVE.load(SeqCst);
    let used=credit.stats().used;
    let raw_retained=!raw_dropped.load(SeqCst);
    let refused=credit.reserve(layout.size(),MetadataClass::StreamAssemblers).is_err();
    state.1=true;gate().1.notify_all();drop(state);worker.join().unwrap();
    assert_eq!(payload_live,0,"payload is physically freed before its refund");
    assert!(wrapper_live>0);
    assert!(raw_retained,"raw permit returned before actual wrapper free");
    assert!(raw_dropped.load(SeqCst));
    assert_eq!(used,owner_charge,"wrapper credit returned before actual free");
    assert!(refused,"replacement wrapper reused still-live credit");
    assert_eq!(WRAPPER_LIVE.load(SeqCst),0);assert_eq!(credit.stats().used,0);
}
