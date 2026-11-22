// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refresh a ready data epoch while this task is inside a local section.
//! The relay drops the epoch after 10s without a touch. A probe uses an empty
//! acknowledgement so a queued frame stays for the real poll.

use super::TailJob;
use crate::custody::pairing::FullPairingTransport;
use ramflux_protocol::custody::pairing::full_transfer::relay::PollFull;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

const REFRESH: Duration = Duration::from_secs(3);

impl TailJob {
    pub(super) fn activity_inputs(
        &self,
    ) -> (Arc<dyn FullPairingTransport>, String, Option<PollFull>) {
        (
            Arc::clone(&self.relay),
            self.origin.clone(),
            self.packet.as_ref().and_then(|packet| packet.activity_probe().ok()),
        )
    }
}

pub(super) async fn retain_relay_activity<T>(
    relay: Arc<dyn FullPairingTransport>,
    origin: String,
    probe: Option<PollFull>,
    work: impl Future<Output = T>,
) -> T {
    let Some(probe) = probe else {
        return work.await;
    };
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REFRESH);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                changed = stopped.changed() => {
                    if changed.is_err() || *stopped.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let _ = relay.poll_full(&origin, &probe).await;
                }
            }
        }
    });
    let output = work.await;
    let _ = stop.send(true);
    let _ = task.await;
    output
}
