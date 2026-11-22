// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-account session thread. The gateway session host, its children and the receive tasks run
//! here, so synchronous account work (database commits) on the account thread cannot delay their
//! timers, keepalive or receipts. All account state stays on the account thread: the two sides
//! talk only through the existing channels.

use crate::SdkError;
use std::cell::Cell;
use std::time::Duration;
use tokio::runtime::Handle;

/// Bound on waiting for blocking signing work when the thread stops.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

thread_local! {
    static INSTALLED: Cell<Option<Handle>> = const { Cell::new(None) };
}

/// The session runtime installed on this (account) thread, if any.
pub(crate) fn installed() -> Option<Handle> {
    INSTALLED.with(|slot| {
        let handle = slot.take();
        slot.set(handle.clone());
        handle
    })
}

pub(super) struct SessionThread {
    handle: Handle,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SessionThread {
    pub(super) fn start() -> Result<Self, SdkError> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread =
            std::thread::Builder::new().name("ramflux-session".to_owned()).spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
                // Tasks that outlived their connection are dropped here.
                runtime.shutdown_timeout(SHUTDOWN_GRACE);
            })?;
        Ok(Self { handle, stop: Some(stop), thread: Some(thread) })
    }

    /// Runs `body` with this session thread as the spawn target for new account connections.
    pub(super) fn install<T>(&self, body: impl FnOnce() -> T) -> T {
        struct Restore(Option<Handle>);
        impl Drop for Restore {
            fn drop(&mut self) {
                let previous = self.0.take();
                INSTALLED.with(|slot| slot.set(previous));
            }
        }
        let _restore = Restore(INSTALLED.with(|slot| slot.replace(Some(self.handle.clone()))));
        body()
    }
}

impl Drop for SessionThread {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!("account session thread ended abnormally");
        }
    }
}
