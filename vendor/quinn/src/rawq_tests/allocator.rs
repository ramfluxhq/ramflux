// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent allocation observation for a synchronous, gated driver operation.
use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell};
thread_local! { static OBSERVER: Cell<(usize,usize)> = const { Cell::new((0,0)) }; }
struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr=System.alloc(layout);
        if !ptr.is_null() {
            let _=OBSERVER.try_with(|observer| {
                let(wanted,count)=observer.get();
                if wanted!=0 && layout.size()==wanted { observer.set((wanted,count.saturating_add(1))); }
            });
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { System.dealloc(ptr,layout); }
}
/// Observe actual successful allocator calls with the destination heap's layout size.
/// No await/task switch occurs inside the supplied operation; the driver is gated.
pub(super) fn heap_allocations<T>(bytes: usize, operation: impl FnOnce() -> T) -> (T,usize) {
    struct Reset;
    impl Drop for Reset { fn drop(&mut self) { OBSERVER.with(|observer|observer.set((0,0))); } }
    OBSERVER.with(|observer| { assert_eq!(observer.get().0,0);observer.set((bytes,0)); });
    let reset=Reset;let result=operation();
    let count=OBSERVER.with(|observer|observer.get().1);drop(reset);(result,count)
}
