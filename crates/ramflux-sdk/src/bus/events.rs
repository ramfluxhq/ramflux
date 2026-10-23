// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit-first handoff from account outboxes to the subscription router.

use crate::prelude::*;
use tokio::sync::oneshot;

pub(super) struct EventBatch {
    pub events: Vec<LocalBusFrame>,
    pub accepted: oneshot::Sender<()>,
}

pub(super) fn broadcast(
    subscribers: &mut BTreeMap<u64, LocalBusSubscriber>,
    events: &[LocalBusFrame],
) {
    for event in events {
        subscribers.retain(|_, subscriber| {
            if event.account_id.as_deref() == Some(&subscriber.account_id)
                && subscriber.topics.contains(&event.method)
            {
                subscriber.outbound.try_send(event.clone()).is_ok()
            } else {
                true
            }
        });
    }
}

pub(super) async fn publish(
    db: &AccountDb,
    account_id: &str,
    request: &LocalBusFrame,
    sender: &mpsc::Sender<EventBatch>,
) -> Result<(), SdkError> {
    loop {
        let entries = db.pending_outbox(256)?;
        let Some(last) = entries.last() else {
            return Ok(());
        };
        let last_sequence = last.sequence;
        let mut events = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut frame = local_bus_event(
                request,
                account_id,
                "account",
                "state.changed",
                serde_json::to_value(&entry)?,
            );
            frame.frame_id = format!("outbox_{}", entry.sequence);
            events.push(frame);
        }
        let (accepted, done) = oneshot::channel();
        sender.send(EventBatch { events, accepted }).await.map_err(|_| closed())?;
        done.await.map_err(|_| closed())?;
        db.mark_outbox_published(last_sequence)?;
    }
}

fn closed() -> SdkError {
    SdkError::LocalBus("subscription router stopped before outbox acceptance".to_owned())
}
