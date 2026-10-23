// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Snapshot-based journal replay and bounded live tailing independent of the account writer.
use super::readers::AccountReaders;
use crate::prelude::*;
use ramflux_storage::{JournalBounds, JournalEvent};

#[derive(serde::Deserialize)]
struct Subscribe {
    topics: BTreeSet<String>,
    since_seq: Option<u64>,
}

pub(super) fn read(db: &AccountDb, request: &LocalBusFrame) -> Result<serde_json::Value, SdkError> {
    let bounds = db.journal_bounds()?;
    let cursor = request
        .body
        .get("since_seq")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(bounds.head_seq);
    let resync =
        cursor < bounds.floor_seq || cursor < bounds.pruned_through || cursor > bounds.head_seq;
    let events = if resync { Vec::new() } else { db.journal_after(cursor, 128)? };
    Ok(
        serde_json::json!({"bounds":bounds,"cursor":cursor,"resync_required":resync,"events":events}),
    )
}

pub(super) async fn start(
    readers: AccountReaders,
    request: LocalBusFrame,
    outbound: mpsc::Sender<LocalBusFrame>,
) -> Result<Option<tokio::task::JoinHandle<()>>, SdkError> {
    let body: Subscribe = serde_json::from_value(request.body.clone())?;
    if body.topics.len() > 64
        || body.topics.iter().any(|topic| topic.is_empty() || topic.len() > 128)
    {
        return Err(SdkError::LocalBus("invalid subscription topics".to_owned()));
    }
    let mut query = request.clone();
    "stream.read".clone_into(&mut query.method);
    query.body = serde_json::json!({"since_seq":body.since_seq});
    let first = readers.request(query.clone()).await?;
    let bounds: JournalBounds = serde_json::from_value(first["bounds"].clone())?;
    if first["resync_required"] == true {
        let mut error =
            local_bus_error(&request, &SdkError::LocalBus("resync_required".to_owned()));
        error.body = serde_json::json!({"floor_seq":bounds.floor_seq,"head_seq":bounds.head_seq});
        if let Some(body) = &mut error.error {
            "resync_required".clone_into(&mut body.code);
        }
        outbound.send(error).await.map_err(|_| closed())?;
        return Ok(None);
    }
    let cursor = body.since_seq.unwrap_or(bounds.head_seq);
    // Queue the acknowledgement before the first replay event on this same FIFO.
    outbound.send(local_bus_response(&request, serde_json::json!({"subscribed":true,"head_seq":bounds.head_seq,"floor_seq":bounds.floor_seq}))).await.map_err(|_|closed())?;
    Ok(Some(tokio::task::spawn_local(async move {
        let _ = tail(readers, query, request, outbound, body.topics, cursor).await;
    })))
}

async fn tail(
    readers: AccountReaders,
    mut query: LocalBusFrame,
    request: LocalBusFrame,
    outbound: mpsc::Sender<LocalBusFrame>,
    topics: BTreeSet<String>,
    mut cursor: u64,
) -> Result<(), SdkError> {
    let mut delivered = cursor;
    loop {
        query.body = serde_json::json!({"since_seq":cursor});
        let Ok(page) = readers.request(query.clone()).await else {
            lagged(&outbound, &request, delivered);
            return Ok(());
        };
        if page["resync_required"] == true {
            lagged(&outbound, &request, delivered);
            return Ok(());
        }
        let events: Vec<JournalEvent> = serde_json::from_value(page["events"].clone())?;
        let empty = events.is_empty();
        for event in events {
            cursor = event.seq;
            if topics.contains(&event.topic) || topics.contains("*") {
                // Leave a slot for the final lagged frame; never block the writer or grow a queue.
                if outbound.capacity() <= 1 {
                    lagged(&outbound, &request, delivered);
                    return Ok(());
                }
                let seq = event.seq;
                let account = request.account_id.as_deref().ok_or_else(closed)?;
                if outbound.try_send(super::journal::frame(&request, account, event)).is_err() {
                    lagged(&outbound, &request, delivered);
                    return Ok(());
                }
                delivered = seq;
            }
        }
        if empty {
            tokio::select! {
                () = outbound.closed() => return Ok(()),
                () = tokio::time::sleep(Duration::from_millis(50)) => {},
            }
        }
    }
}

pub(super) fn lagged(outbound: &mpsc::Sender<LocalBusFrame>, request: &LocalBusFrame, seq: u64) {
    let frame = local_bus_event(
        request,
        request.account_id.as_deref().unwrap_or_default(),
        "stream",
        "stream.lagged",
        serde_json::json!({"last_delivered_seq":seq}),
    );
    let _ = outbound.try_send(frame);
}
fn closed() -> SdkError {
    SdkError::LocalBus("subscription closed".to_owned())
}
