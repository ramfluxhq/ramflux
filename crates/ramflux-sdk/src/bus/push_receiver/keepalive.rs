// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session-child keepalive: Heartbeat after 25 s idle, 10 s call, retire at 35 s.

use crate::SdkError;
use crate::bus::connection_manager::SessionContext;
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

const TRANSIENT_BACKOFF: Duration = Duration::from_secs(1);

fn stop_on_error(context: &SessionContext, error: &SdkError) -> bool {
    context.generation != context.connection_generation()
        || matches!(error, SdkError::NetworkingPendingContext { .. } | SdkError::NetworkingPending)
}

pub(crate) async fn run(context: SessionContext) {
    #[cfg(test)]
    struct Running(SessionContext);
    #[cfg(test)]
    impl Drop for Running {
        fn drop(&mut self) {
            self.0.set_keepalive_running(false);
        }
    }
    #[cfg(test)]
    context.set_keepalive_running(true);
    #[cfg(test)]
    let _running = Running(context.clone());
    let mut cancel = context.cancel.clone();
    if *cancel.borrow() {
        return;
    }
    loop {
        let due = context.last_read_at() + context.keepalive_idle();
        tokio::select! {
            biased;
            _ = cancel.changed() => return,
            () = sleep_until(due) => {}
        }
        if Instant::now() < context.last_read_at() + context.keepalive_idle() {
            continue;
        }
        match context.keepalive_heartbeat().await {
            Ok(()) => {}
            Err(error) if stop_on_error(&context, &error) => return,
            Err(_) => {
                let retry = (context.last_read_at() + context.keepalive_idle())
                    .max(Instant::now() + TRANSIENT_BACKOFF);
                tokio::select! {
                    biased;
                    _ = cancel.changed() => return,
                    () = sleep_until(retry) => {}
                }
            }
        }
    }
}
