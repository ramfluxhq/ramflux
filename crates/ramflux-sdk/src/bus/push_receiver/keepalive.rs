// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session-child keepalive: Heartbeat after 25 s idle, 10 s call, retire at 35 s.

use crate::bus::connection_manager::SessionContext;
use tokio::time::{Instant, sleep_until};

pub(crate) async fn run(context: SessionContext) {
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
        if context.keepalive_heartbeat().await.is_err() {
            return;
        }
    }
}
