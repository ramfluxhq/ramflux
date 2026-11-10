// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Activated Deliver/Resync intake: durable W0, then RAM reorder, then contiguous `ApplyPage`.

use super::reorder::{AdmitOutcome, CatchUpHint, DurableW0};
use crate::SdkError;
use crate::bus::connection_manager::subscriptions::SessionEvent;
use crate::bus::connection_manager::{
    AccountWork, ConnectionHandle, NetworkingState, ReceiveEntry, ReceiveTurn,
};
use crate::gateway::frame_dispatch::FrameKind;
use crate::gateway::session_push::CapableEvent;
use crate::{GatewayInboxEntry, time::now_unix_timestamp};
use ramflux_storage::ReceiveStage;
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot, watch};

/// Wait until Live (the worker replaces the hub in `announce_live`), then subscribe.
pub(crate) async fn run(handle: ConnectionHandle, work: mpsc::Sender<AccountWork>) {
    let mut stop = handle.stopping();
    while wait_live(&handle, &mut stop).await {
        run_session(&handle, &work, &mut stop).await;
    }
}

async fn wait_live(handle: &ConnectionHandle, stop: &mut watch::Receiver<bool>) -> bool {
    let mut changed = handle.snapshot_watch();
    loop {
        if *stop.borrow() {
            return false;
        }
        if handle.snapshot().state == NetworkingState::Live {
            return true;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => return false,
            result = changed.changed() => {
                if result.is_err() {
                    return false;
                }
            }
        }
    }
}

async fn run_session(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    stop: &mut watch::Receiver<bool>,
) {
    let mut events = handle.subscribe([FrameKind::Deliver, FrameKind::Resync]);
    let mut pending = BTreeMap::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => return,
            event = events.recv() => {
                let Some(event) = event else {
                    return;
                };
                if matches!(event, SessionEvent::Disconnected { .. })
                    || handle.snapshot().state != NetworkingState::Live
                {
                    return;
                }
                if let Err(error) = handle_event(handle, work, &mut pending, event).await {
                    tracing::debug!(%error, "deliver intake deferred");
                }
            }
        }
    }
}

async fn handle_event(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    pending: &mut BTreeMap<u64, GatewayInboxEntry>,
    event: SessionEvent,
) -> Result<(), SdkError> {
    match event {
        SessionEvent::Capable { event, generation } => {
            if generation != handle.generation() {
                return Ok(());
            }
            apply_capable(handle, work, pending, event).await
        }
        SessionEvent::Lagged { generation, .. } => {
            if generation == handle.generation() {
                handle.reorder().note_hint(CatchUpHint::Lagged);
                handle.wake_receive();
            }
            Ok(())
        }
        SessionEvent::Disconnected { .. } | SessionEvent::Frame { .. } => Ok(()),
    }
}

async fn apply_capable(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    pending: &mut BTreeMap<u64, GatewayInboxEntry>,
    event: std::sync::Arc<CapableEvent>,
) -> Result<(), SdkError> {
    match &*event {
        CapableEvent::Deliver { entry, incarnation_id, retain_until } => {
            stage_and_admit(
                handle,
                work,
                pending,
                entry.clone(),
                incarnation_id.as_str(),
                *retain_until,
            )
            .await
        }
        CapableEvent::Resync { .. } => {
            handle.reorder().note_hint(CatchUpHint::Resync);
            handle.wake_receive();
            Ok(())
        }
    }
}

async fn stage_and_admit(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    pending: &mut BTreeMap<u64, GatewayInboxEntry>,
    entry: GatewayInboxEntry,
    incarnation: &str,
    retain_until: i64,
) -> Result<(), SdkError> {
    let seq = entry.inbox_seq;
    let Some((witness, turn)) =
        request_stage(handle, work, entry.clone(), incarnation, retain_until).await?
    else {
        return Ok(());
    };
    let json = serde_json::to_vec(&entry).unwrap_or_default();
    let outcome = handle.reorder().admit(handle.receive_now_ms(), seq, json.len(), witness);
    match outcome {
        AdmitOutcome::ReadyToApply { seq } => {
            pending.insert(seq, entry);
            handle.reorder().note_local_work();
            apply_ready(handle, work, pending, turn, seq).await
        }
        AdmitOutcome::Buffered { seq, evicted } => {
            pending.insert(seq, entry);
            for dropped in evicted {
                pending.remove(&dropped);
            }
            handle.wake_receive();
            Ok(())
        }
        AdmitOutcome::Evicted { evicted, .. } => {
            for dropped in evicted {
                pending.remove(&dropped);
            }
            handle.wake_receive();
            Ok(())
        }
        AdmitOutcome::Duplicate { .. } | AdmitOutcome::Refused { .. } => Ok(()),
    }
}

async fn request_stage(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    entry: GatewayInboxEntry,
    incarnation: &str,
    retain_until: i64,
) -> Result<Option<(DurableW0, ReceiveTurn)>, SdkError> {
    let (reply, response) = oneshot::channel();
    work.send(AccountWork::StageIntake {
        generation: handle.generation(),
        entry: Box::new(entry),
        incarnation: incarnation.to_owned(),
        retain_until,
        reply,
    })
    .await
    .map_err(|_| handle.pending())?;
    response.await.map_err(|_| handle.pending())?
}

async fn apply_ready(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    pending: &mut BTreeMap<u64, GatewayInboxEntry>,
    mut turn: ReceiveTurn,
    seq: u64,
) -> Result<(), SdkError> {
    apply_one(handle, work, pending, &turn, seq).await?;
    turn.cursor = seq;
    let contiguous = handle.reorder().peek_contiguous();
    for next in contiguous {
        apply_one(handle, work, pending, &turn, next).await?;
        turn.cursor = next;
    }
    Ok(())
}

async fn apply_one(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    pending: &mut BTreeMap<u64, GatewayInboxEntry>,
    turn: &ReceiveTurn,
    seq: u64,
) -> Result<(), SdkError> {
    let Some(entry) = pending.remove(&seq) else {
        return Ok(());
    };
    let _ = crate::bus::connection_manager::receive::apply_entry(
        handle,
        work,
        handle.generation(),
        ReceiveEntry { entry, retry_key: None, replay: false, turn: Some(turn.clone()) },
        handle.call_timeout(),
        Box::default(),
    )
    .await?;
    handle
        .reorder()
        .applied(handle.receive_now_ms(), seq)
        .map_err(|error| SdkError::InboundRejected(error.to_string()))?;
    Ok(())
}

/// Actor-side W0 stage. Pause/erase produce no witness; conflict is a typed refusal.
pub(crate) fn stage_on_actor(
    account: &crate::bus::state::LocalBusAccountState,
    generation: u64,
    entry: &GatewayInboxEntry,
    incarnation: &str,
    retain_until: i64,
) -> Result<Option<(DurableW0, ReceiveTurn)>, SdkError> {
    let Some(turn) = crate::bus::sync_driver::source::w0::actor_turn(account, generation)? else {
        return Ok(None);
    };
    if turn.incarnation != incarnation {
        return Err(SdkError::InboundRejected("receive intake incarnation mismatch".into()));
    }
    let json = serde_json::to_vec(entry)?;
    let key = account.client.inbox_admission_key(entry)?;
    let result = crate::bus::sync_driver::source::w0::SourceW0::from_actor(&turn, generation)
        .stage(
            account.client.account_db()?,
            ReceiveStage {
                target: &turn.target,
                incarnation: &turn.incarnation,
                sequence: entry.inbox_seq,
                entry_json: &json,
                admission_key: &key,
                retain_until,
                first_seen: now_unix_timestamp(),
            },
        )?;
    match DurableW0::from_stage(entry.inbox_seq, result) {
        Some(witness) => Ok(Some((witness, turn))),
        None => match result {
            ramflux_storage::ReceiveStageResult::Conflict { .. } => {
                Err(SdkError::InboundRejected("receive stage conflict".into()))
            }
            _ => Ok(None),
        },
    }
}
