// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded receive using the ordinary fenced W1/W2 and durable WA intent owners.

use crate::bus::connection_manager::{ReceiveEntry, ReceiveTurn};
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::push_receiver::ack_batch::SourceWa;
use crate::bus::push_receiver::apply::{self, ApplyLoss, ApplyOutcome, ApplyPage};
use crate::bus::push_receiver::apply_w1;
use crate::bus::push_receiver::executor::LedgerExecutor;
use crate::bus::state::LocalBusAccountState;
use crate::gateway::push_resume::{PageReply, ResumePage};
use crate::{GatewayInboxEntry, GatewaySessionEngine, SdkError};
use ramflux_storage::ReceiveAckApply;

// No handle replacement is possible while this synchronous host owns the S14 lease.
const GENERATION: u64 = 0;

pub(super) async fn run(
    account: &mut LocalBusAccountState,
) -> Result<Vec<GatewayInboxEntry>, SdkError> {
    let db = account.client.account_db()?;
    let _owner =
        LedgerExecutor::bind_standalone(format!("{}:{}", db.path.display(), db.local_account_id))?;
    let incarnation = engine(account)?
        .mode
        .push_incarnation()
        .ok_or_else(|| {
            SdkError::GatewaySessionRejected("wake receive requires a negotiated inbox".into())
        })?
        .to_owned();
    account
        .client
        .first_activate_receive_ledger(&account.target_delivery_id, Some(&incarnation))?;
    if let Some(turn) = account.client.prepare_receive_epoch(
        &account.target_delivery_id,
        &incarnation,
        GENERATION,
    )? {
        let page = resume(account, 0).await?;
        account.client.reset_receive_epoch(&turn, &incarnation, &page, GENERATION)?;
    }
    // A previous process may have committed W1 and died before sending or settling WA.
    flush_acks(account).await?;
    let turn = capture(account)?;
    let page = resume(account, turn.cursor).await?;
    if page.entries.len() > super::PAGE_LIMIT {
        return Err(SdkError::GatewaySessionRejected("wake page exceeds requested limit".into()));
    }
    let result = apply_page(account, &page, turn).await;
    // Even a later per-entry refusal must not discard earlier committed ACK intents.
    // Cancellation here retains them for the next wake/app receive pass.
    flush_acks(account).await?;
    result?;
    Ok(page.entries.into_iter().map(|record| record.entry).collect())
}

fn engine(account: &mut LocalBusAccountState) -> Result<&mut GatewaySessionEngine, SdkError> {
    account.engine.as_mut().ok_or(SdkError::GatewaySessionNotEstablished)
}

fn capture(account: &LocalBusAccountState) -> Result<ReceiveTurn, SdkError> {
    apply_w1::capture_turn(account.client.account_db()?, GENERATION, &account.target_delivery_id)
}

async fn resume(account: &mut LocalBusAccountState, after: u64) -> Result<ResumePage, SdkError> {
    match engine(account)?.resume_page(after, super::PAGE_LIMIT).await? {
        PageReply::Page(page) => Ok(*page),
        PageReply::Refused(reason) => Err(SdkError::GatewaySessionRejected(reason.as_str().into())),
    }
}

async fn apply_page(
    account: &mut LocalBusAccountState,
    page: &ResumePage,
    mut turn: ReceiveTurn,
) -> Result<(), SdkError> {
    let mut backpressure =
        Box::new(Backpressure::load(&account.client, crate::time::now_unix_timestamp())?);
    // One W1 per record, plus a final reconciliation of known losses and coverage.
    for _ in 0..=super::PAGE_LIMIT {
        apply_w1::refresh_cursor(account.client.account_db()?, &mut turn)?;
        match reconcile(account, page, &turn)? {
            ApplyOutcome::Covered { .. } | ApplyOutcome::AlreadyCovered { .. } => return Ok(()),
            ApplyOutcome::NeedStage { sequence, .. } => {
                let entry =
                    page.entries.iter().find(|row| row.entry.inbox_seq == sequence).ok_or_else(
                        || SdkError::InboundPending("wake page needs retained input".into()),
                    )?;
                let prepared = ReceiveEntry {
                    entry: entry.entry.clone(),
                    retry_key: None,
                    replay: false,
                    turn: Some(turn.clone()),
                };
                let (_, next) = Box::pin(apply_w1::apply_page(
                    account,
                    &turn,
                    &|| GENERATION,
                    prepared,
                    None,
                    backpressure,
                ))
                .await?;
                backpressure = next;
                // Replies stay in their durable outboxes; this host never runs a courier.
                let _ = apply_w1::take_pair_reply();
            }
            ApplyOutcome::NeedPoint { .. }
            | ApplyOutcome::NeedFetch { .. }
            | ApplyOutcome::Paused { .. } => {
                return Err(SdkError::InboundPending(
                    "wake page requires further receive work".into(),
                ));
            }
        }
    }
    Err(SdkError::InboundPending("wake page did not reach durable coverage".into()))
}

fn reconcile(
    account: &LocalBusAccountState,
    page: &ResumePage,
    turn: &ReceiveTurn,
) -> Result<ApplyOutcome, SdkError> {
    let sequences: Vec<_> = page.entries.iter().map(|row| row.entry.inbox_seq).collect();
    let losses: Vec<_> = page
        .known_losses
        .iter()
        .map(|loss| ApplyLoss {
            from_seq: loss.from_seq,
            to_seq: loss.to_seq,
            reason: loss.reason.as_str(),
        })
        .collect();
    apply::apply_page(
        account.client.account_db()?,
        turn.expected(),
        GENERATION,
        ApplyPage {
            target: &turn.target,
            incarnation: &turn.incarnation,
            after: page.after_inbox_seq,
            covered: page.covered_through_seq,
            issued: page.issued_inbox_seq,
            settled: page.settled_through_seq,
            entries: &sequences,
            known_losses: &losses,
            oversize_next: page.oversize_next,
            more: page.more,
        },
    )
    .map_err(|error| match error {
        apply::ApplyError::Protocol(text) => SdkError::InboundRejected(text.into()),
        apply::ApplyError::Storage(error) => error.into(),
    })
}

async fn flush_acks(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    let turn = capture(account)?;
    let wa = SourceWa { expected: turn.expected(), generation: GENERATION };
    let sequences =
        wa.select(account.client.account_db()?, crate::time::now_unix_timestamp(), true)?;
    if sequences.is_empty() {
        return Ok(());
    }
    let batch = engine(account)?.ack_batch(sequences.clone()).await;
    let failed =
        batch.is_err() || matches!(batch, Ok(crate::gateway::push_point::BatchReply::Refused(_)));
    let results = crate::bus::connection_manager::receive::map_batch_results(&sequences, batch);
    wa.apply(
        account.client.account_db()?,
        ReceiveAckApply {
            incarnation: &turn.incarnation,
            sequences: &sequences,
            results: &results,
            now: crate::time::now_unix_timestamp(),
        },
    )?;
    if failed {
        return Err(SdkError::InboundPending("wake ACK outcome is uncertain".into()));
    }
    Ok(())
}
