// SPDX-License-Identifier: MIT
//! Allocator-observed wrapper lifetime, isolated from the product allocator.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use bytes::{Bytes, OwnerAllocationError};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::*},
        Arc, Condvar, Mutex, Once,
    },
};

thread_local! { static CAPTURE: Cell<bool> = Cell::new(false); }
static CAPTURE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static PTR: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static REQUEST: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED: AtomicBool = AtomicBool::new(false);
static FREED: AtomicBool = AtomicBool::new(false);
static EARLY: AtomicBool = AtomicBool::new(false);
static PANIC_DROP: AtomicBool = AtomicBool::new(false);
static OWNER_DROPPED: AtomicBool = AtomicBool::new(false);
static PAUSE: AtomicBool = AtomicBool::new(false);
static ENTERED: AtomicBool = AtomicBool::new(false);
static FAIL: AtomicBool = AtomicBool::new(false);
static INIT: Once = Once::new();
static mut STATE: *const (Mutex<bool>, Condvar) = std::ptr::null();

fn gate() -> &'static (Mutex<bool>, Condvar) {
    INIT.call_once(|| {
        // Test fixture initialized before tracking. Once publishes the immutable
        // pointer; the fixed synchronization fixture lives for the process.
        unsafe { STATE = Box::into_raw(Box::new((Mutex::new(false), Condvar::new()))); }
    });
    unsafe { &*STATE }
}

struct Counting;
#[global_allocator]
static ALLOC: Counting = Counting;

#[cfg(target_os = "linux")]
extern "C" { fn malloc_usable_size(p: *mut std::ffi::c_void) -> usize; }
#[cfg(target_os = "macos")]
extern "C" { fn malloc_size(p: *const std::ffi::c_void) -> usize; }

unsafe fn usable(p: *mut u8) -> usize {
    #[cfg(target_os = "linux")]
    { malloc_usable_size(p.cast()) }
    #[cfg(target_os = "macos")]
    { malloc_size(p.cast()) }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let capture = CAPTURE.try_with(|c| c.get()).unwrap_or(false);
        if capture && FAIL.load(SeqCst) {
            return std::ptr::null_mut();
        }
        let ptr = System.alloc(layout);
        if capture && !ptr.is_null() {
            CAPTURE_ALLOCATIONS.fetch_add(1, SeqCst);
            // Track the wrapper, not panic-runtime allocations during AsRef unwind.
            // Normal construction independently asserts exactly one allocation.
            if !ALLOCATED.load(SeqCst) {
                PTR.store(ptr as usize, SeqCst);
                let actual = usable(ptr);
                REQUEST.store(layout.size(), SeqCst);
                LIVE.store(actual, SeqCst);
                PEAK.fetch_max(actual, SeqCst);
                ALLOCATED.store(true, SeqCst);
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if PTR.compare_exchange(ptr as usize, usize::MAX, SeqCst, SeqCst).is_ok() {
            if PAUSE.load(SeqCst) {
                let mut allowed = gate().0.lock().unwrap();
                ENTERED.store(true, SeqCst);
                gate().1.notify_all();
                while !*allowed {
                    allowed = gate().1.wait(allowed).unwrap();
                }
            } else {
                ENTERED.store(true, SeqCst);
            }
            System.dealloc(ptr, layout);
            // Keep physical bytes live until the real allocator has returned.
            LIVE.store(0, SeqCst);
            FREED.store(true, SeqCst);
            PTR.store(0, SeqCst);
        } else {
            System.dealloc(ptr, layout);
        }
    }
}

fn capture<T>(f: impl FnOnce() -> T) -> T {
    struct Off;
    impl Drop for Off {
        fn drop(&mut self) { CAPTURE.with(|c| c.set(false)); }
    }
    CAPTURE.with(|c| c.set(true));
    let off = Off;
    let result = f();
    drop(off);
    result
}

fn reset() {
    assert_eq!(PTR.load(SeqCst), 0);
    CAPTURE_ALLOCATIONS.store(0, SeqCst);
    LIVE.store(0, SeqCst);
    PEAK.store(0, SeqCst);
    REQUEST.store(0, SeqCst);
    ALLOCATED.store(false, SeqCst);
    FREED.store(false, SeqCst);
    EARLY.store(false, SeqCst);
    OWNER_DROPPED.store(false, SeqCst);
    PAUSE.store(false, SeqCst);
    ENTERED.store(false, SeqCst);
    FAIL.store(false, SeqCst);
    *gate().0.lock().unwrap() = false;
}

struct Owner { panic: bool }
impl AsRef<[u8]> for Owner {
    fn as_ref(&self) -> &[u8] {
        assert!(!self.panic, "constructor AsRef panic");
        b"abcdef"
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        OWNER_DROPPED.store(true, SeqCst);
        assert!(!PANIC_DROP.swap(false, SeqCst), "owner Drop panic");
    }
}

struct Guard(Arc<AtomicUsize>);
impl Drop for Guard {
    fn drop(&mut self) {
        if ALLOCATED.load(SeqCst) && !FREED.load(SeqCst) {
            EARLY.store(true, SeqCst);
        }
        self.0.store(0, SeqCst);
    }
}

fn create(held: &Arc<AtomicUsize>, panic: bool) -> Result<Bytes, OwnerAllocationError<Owner, ()>> {
    capture(|| Bytes::try_from_owner_with_guard(Owner { panic }, |layout| {
        assert_eq!(LIVE.load(SeqCst), 0, "reservation precedes wrapper allocation");
        // Test allowance, validated against actual usable size on these identities;
        // this is not a certificate for production owner layouts or other allocators.
        let charge = ((layout.size() + 63) & !63) + 64;
        held.compare_exchange(0, charge, SeqCst, SeqCst).map_err(|_| ())?;
        Ok(Guard(held.clone()))
    }))
}

#[test]
fn allocator_real_guard_lifetime_refusal_clone_slice_and_unwind() {
    reset();
    let held = Arc::new(AtomicUsize::new(0));
    let bytes = create(&held, false).unwrap();
    assert_eq!(CAPTURE_ALLOCATIONS.load(SeqCst), 1, "exactly one wrapper allocation");
    assert!(REQUEST.load(SeqCst) > 0);
    assert!(LIVE.load(SeqCst) >= REQUEST.load(SeqCst));
    assert!(PEAK.load(SeqCst) <= held.load(SeqCst), "actual extent fits charged allowance");
    let allocations = CAPTURE_ALLOCATIONS.load(SeqCst);
    let slice = capture(|| bytes.slice(1..5));
    drop(bytes);
    let clone = capture(|| slice.clone());
    drop(slice);
    assert!(!FREED.load(SeqCst));
    assert_eq!(&clone[..], b"bcde");
    assert_eq!(CAPTURE_ALLOCATIONS.load(SeqCst), allocations, "views allocate no wrapper");

    PAUSE.store(true, SeqCst);
    let worker = std::thread::spawn(move || drop(clone));
    let mut allowed = gate().0.lock().unwrap();
    while !ENTERED.load(SeqCst) {
        allowed = gate().1.wait(allowed).unwrap();
    }
    let destroyed = OWNER_DROPPED.load(SeqCst);
    let physical = LIVE.load(SeqCst);
    // Force the competing reservation into the owner-destroyed, not-freed window.
    let refused = held.compare_exchange(0, 1, SeqCst, SeqCst).is_err();
    *allowed = true;
    gate().1.notify_all();
    drop(allowed);
    worker.join().unwrap();
    assert!(destroyed && physical > 0);
    assert!(refused, "credit was reused before actual wrapper deallocation");
    assert!(!EARLY.load(SeqCst));
    assert_eq!(held.load(SeqCst), 0);
    assert_eq!(LIVE.load(SeqCst), 0);

    reset();
    held.store(1, SeqCst);
    let denied = create(&held, false);
    assert!(matches!(denied, Err(OwnerAllocationError::Reservation { .. })));
    assert!(!ALLOCATED.load(SeqCst));
    drop(denied);
    held.store(0, SeqCst);

    reset();
    FAIL.store(true, SeqCst);
    let failed = create(&held, false);
    assert!(matches!(failed, Err(OwnerAllocationError::Allocation { .. })));
    assert_eq!(held.load(SeqCst), 0);
    assert!(!ALLOCATED.load(SeqCst));
    drop(failed);

    reset();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| create(&held, true)));
    assert!(panic.is_err());
    assert!(OWNER_DROPPED.load(SeqCst));
    assert!(FREED.load(SeqCst));
    assert!(!EARLY.load(SeqCst));
    assert_eq!(held.load(SeqCst), 0);

    reset();
    let bytes = create(&held, false).unwrap();
    PANIC_DROP.store(true, SeqCst);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(bytes)));
    assert!(panic.is_err());
    assert!(FREED.load(SeqCst));
    assert!(!EARLY.load(SeqCst));
    assert_eq!(held.load(SeqCst), 0);

    reset();
    let bytes = create(&held, false).unwrap().try_into_mut().unwrap_err();
    assert!(!FREED.load(SeqCst));
    let vec = Vec::<u8>::from(bytes);
    assert_eq!(vec, b"abcdef");
    assert!(FREED.load(SeqCst));
    assert!(!EARLY.load(SeqCst));

    reset();
    let mutable = bytes::BytesMut::from(create(&held, false).unwrap());
    assert_eq!(&mutable[..], b"abcdef");
    assert!(FREED.load(SeqCst));
    assert!(!EARLY.load(SeqCst));
    assert_eq!(held.load(SeqCst), 0);
}
