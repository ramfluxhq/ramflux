// SPDX-License-Identifier: MIT
//! Owner allocation with reservation before allocation and guard release after free.
use super::*;

/// Fallible guarded-owner construction preserves the input owner on refusal.
pub enum OwnerAllocationError<T, E> {
    /// The caller refused the actual wrapper layout before allocation.
    Reservation {
        /// Input owner, preserved on refusal.
        owner: T,
        /// Reservation failure.
        error: E,
    },
    /// Allocation failed after admission; the unused guard has been returned.
    Allocation {
        /// Input owner, preserved on allocation failure.
        owner: T,
        /// Allocation failure.
        error: alloc::collections::TryReserveError,
    },
}

impl<T, E: fmt::Debug> fmt::Debug for OwnerAllocationError<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reservation { error, .. } => f.debug_tuple("Reservation").field(error).finish(),
            Self::Allocation { error, .. } => f.debug_tuple("Allocation").field(error).finish(),
        }
    }
}

impl Bytes {
    /// Construct shared bytes after reserving the actual guarded-wrapper layout.
    ///
    /// The unique guard is returned only after the payload owner is destroyed and
    /// the wrapper allocation is freed, including constructor panic unwinding.
    /// Cloning, slicing and splitting share the wrapper without another allocation.
    /// Forced Vec/BytesMut conversions copy first: managed callers must budget that
    /// overlap separately or exclude those conversions. `try_into_mut` returns Err.
    ///
    /// # Errors
    /// Returns the input owner with a reservation or allocation error.
    pub fn try_from_owner_with_guard<T, G, E, F>(
        owner: T,
        reserve: F,
    ) -> Result<Self, OwnerAllocationError<T, E>>
    where
        T: AsRef<[u8]> + Send + 'static,
        G: Send + 'static,
        F: FnOnce(Layout) -> Result<G, E>,
    {
        let guard = match reserve(Layout::new::<GuardedOwned<T, G>>()) {
            Ok(guard) => guard,
            Err(error) => return Err(OwnerAllocationError::Reservation { owner, error }),
        };
        let mut slot = Vec::new();
        if let Err(error) = slot.try_reserve_exact(1) {
            drop(guard);
            return Err(OwnerAllocationError::Allocation { owner, error });
        }
        assert_eq!(slot.capacity(), 1);
        slot.push(GuardedOwned {
            ref_cnt: AtomicUsize::new(1),
            owner,
            guard: Some(guard),
        });
        // Capacity and length are one, so conversion does not allocate or shrink.
        let boxed = slot.into_boxed_slice();
        let owned = Box::into_raw(boxed).cast::<GuardedOwned<T, G>>();
        let mut bytes = Bytes {
            ptr: NonNull::dangling().as_ptr(),
            len: 0,
            data: AtomicPtr::new(owned.cast()),
            vtable: &GuardedOwned::<T, G>::VTABLE,
        };
        // Safety: Bytes already owns the one-element allocation. AsRef panic uses
        // the guarded drop path; the boxed owner stays pinned for returned views.
        let buf = unsafe { &*owned }.owner.as_ref();
        bytes.ptr = buf.as_ptr();
        bytes.len = buf.len();
        Ok(bytes)
    }
}

#[repr(C)]
struct GuardedOwned<T, G> {
    ref_cnt: AtomicUsize,
    owner: T,
    guard: Option<G>,
}

impl<T, G> GuardedOwned<T, G> {
    const VTABLE: Vtable = Vtable {
        clone: guarded_clone::<T, G>,
        into_vec: guarded_to_vec::<T, G>,
        into_mut: guarded_to_mut::<T, G>,
        is_unique: guarded_is_unique,
        drop: guarded_drop::<T, G>,
    };
}

unsafe fn guarded_clone<T, G>(data: &AtomicPtr<()>, ptr: *const u8, len: usize) -> Bytes {
    let owned = data.load(Ordering::Relaxed);
    // repr(C) places the shared count first, as in the upstream owned vtable.
    let count = (*owned.cast::<AtomicUsize>()).fetch_add(1, Ordering::Relaxed);
    if count > usize::MAX >> 1 {
        crate::abort();
    }
    Bytes {
        ptr,
        len,
        data: AtomicPtr::new(owned),
        vtable: &GuardedOwned::<T, G>::VTABLE,
    }
}

fn guarded_is_unique(_: &AtomicPtr<()>) -> bool {
    false
}

unsafe fn guarded_drop_impl<T, G>(owned: *mut ()) {
    let count = &*owned.cast::<AtomicUsize>();
    let old = count.fetch_sub(1, Ordering::Release);
    debug_assert!(old > 0 && old <= usize::MAX >> 1);
    if old != 1 {
        return;
    }
    count.load(Ordering::Acquire);
    // A one-element boxed slice has exactly this allocation layout and drop glue.
    let mut boxed = Box::from_raw(owned.cast::<GuardedOwned<T, G>>());
    let guard = boxed.guard.take();
    // The guard is outside Box: owner panic cleanup also deallocates Box before
    // unwinding reaches this local guard. Never refund from owner Drop.
    drop(boxed);
    drop(guard);
}

unsafe fn guarded_to_vec<T, G>(data: &AtomicPtr<()>, ptr: *const u8, len: usize) -> Vec<u8> {
    let owned = data.load(Ordering::Relaxed);
    let copy = slice::from_raw_parts(ptr, len).to_vec();
    guarded_drop_impl::<T, G>(owned);
    copy
}

unsafe fn guarded_to_mut<T, G>(data: &AtomicPtr<()>, ptr: *const u8, len: usize) -> BytesMut {
    BytesMut::from_vec(guarded_to_vec::<T, G>(data, ptr, len))
}

unsafe fn guarded_drop<T, G>(data: &mut AtomicPtr<()>, _ptr: *const u8, _len: usize) {
    let owned = data.load(Ordering::Relaxed);
    guarded_drop_impl::<T, G>(owned);
}
