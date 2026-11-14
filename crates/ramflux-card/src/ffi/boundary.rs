// SPDX-License-Identifier: BSD-3-Clause
//! Fail closed at native renderer entry points; no renderer state is reused after an unwind.
use super::{IN_CALLBACK, SESSIONS};
#[allow(
    clippy::disallowed_methods,
    reason = "Native C boundary defence; abort-mode C builds are refused"
)]
pub(super) fn status(action: impl FnOnce() -> i32) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[cfg(test)]
        maybe_panic();
        action()
    })) {
        Ok(status) => status,
        Err(payload) => {
            std::mem::forget(payload);
            let _ = IN_CALLBACK.try_with(|active| active.set(false));
            // No registry borrow is retained across the boundary catch.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = SESSIONS.try_with(|sessions| {
                    if let Ok(mut sessions) = sessions.try_borrow_mut() {
                        sessions.clear();
                    }
                });
            }))
            .map_err(std::mem::forget);
            4
        }
    }
}
#[cfg(test)]
thread_local! {static PANIC:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};}
#[cfg(test)]
fn maybe_panic() {
    assert!(!PANIC.with(|flag| flag.replace(false)), "test: native renderer boundary unwind");
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exported_dispose_contains_unwind_and_invalidates_handles() {
        PANIC.with(|flag| flag.set(true));
        assert_eq!(
            crate::ffi::ramflux_card_dispose(0),
            4,
            "native caller receives Engine status instead of an unwind"
        );
        assert_eq!(
            crate::ffi::ramflux_card_dispose(0),
            7,
            "renderer remains callable with no stale sessions"
        );
        assert_eq!(
            crate::ffi::ramflux_card_abi_version(),
            crate::HOST_ABI,
            "version query is constant and infallible"
        );
    }
}
