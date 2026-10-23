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
    client: &RamfluxClient,
    account_id: &str,
    request: &LocalBusFrame,
    sender: &mpsc::Sender<EventBatch>,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    loop {
        let entries = db.pending_outbox(256)?;
        let Some(last) = entries.last() else {
            return Ok(());
        };
        let last_sequence = last.sequence;
        let mut events = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.table_name == "direct_message_projection"
                && let (Some(conversation), Some(message)) =
                    (entry.keys["conversation_id"].as_str(), entry.keys["message_id"].as_str())
            {
                client.project_deferred_surface(conversation, message)?;
            }
            let projected = super::journal::project(client, &entry)?;
            db.journal_outbox(entry.sequence, &projected, now_unix_timestamp())?;
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
        if matches!(request.method.as_str(), "contact.verify" | "grant.approve" | "grant.deny")
            && let Some(subject) = request
                .body
                .get("contact_identity_commitment")
                .or_else(|| request.body.get("approval_id"))
                .and_then(serde_json::Value::as_str)
        {
            db.acknowledge_journal_subject(subject)?;
        }
        super::journal::retention(db)?;
    }
}

fn closed() -> SdkError {
    SdkError::LocalBus("subscription router stopped before outbox acceptance".to_owned())
}
