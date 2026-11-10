// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Standalone public receive: the same ledger pass under `bind_standalone` (D5).

use super::super::connection_manager::receive::entry_id;
use super::super::connection_manager::{ReceiveEntry, ReceiveTurn};
use super::super::push_receiver::apply::{self, ApplyLoss, ApplyOutcome, ApplyPage, ApplyPoint};
use super::super::push_receiver::apply_w1;
use super::super::push_receiver::executor::LedgerExecutor;
use crate::SdkError;
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::state::LocalBusAccountState;
use crate::gateway::access::GatewayPushAccess;
use crate::gateway::push_point::PointReply;
use crate::gateway::push_resume::{PageReply, ResumePage};
use std::collections::BTreeMap;

const PAGE_LIMIT: usize = super::super::connection_manager::receive::RECEIVE_PAGE_LIMIT;
const YIELD_AFTER: u32 = super::super::connection_manager::receive::RECEIVE_YIELD_AFTER_PAGES;

pub(super) async fn receive(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    now: i64,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    let db = account.client.account_db()?;
    let key = format!("{}:{}", db.path.display(), db.local_account_id);
    let _exec = LedgerExecutor::bind_standalone(key)?;
    account.client.prune_surface_resync_state()?;
    let generation = account
        .connection
        .as_ref()
        .map_or(1, super::super::connection_manager::ConnectionHandle::generation);
    let mut turn = apply_w1::capture_turn(
        account.client.account_db()?,
        generation,
        &account.target_delivery_id,
    )?;
    let recovered = super::source::w0::recover_standalone_retries(account, &turn, generation)?;
    let mut retries: BTreeMap<_, _> =
        recovered.into_iter().map(|prepared| (entry_id(&prepared.entry), prepared)).collect();
    let mut backpressure = Box::new(Backpressure::load(&account.client, now)?);
    let mut applied = 0_usize;
    let mut pages = 0_u32;
    loop {
        let page = match engine.resume_page(turn.cursor, PAGE_LIMIT).await? {
            PageReply::Page(page) => *page,
            PageReply::Refused(reason) => {
                return Err(SdkError::GatewaySessionRejected(format!(
                    "resume_page refused: {}",
                    reason.as_str()
                )));
            }
        };
        pages = pages.saturating_add(1);
        if pages >= YIELD_AFTER {
            tokio::task::yield_now().await;
            pages = 0;
        }
        let more = page.more;
        match drive_page(
            account,
            engine,
            &mut turn,
            generation,
            &page,
            &mut retries,
            backpressure,
            applied,
        )
        .await?
        {
            PageDrive::Paused { applied } => {
                flush_live_acks(account, generation).await?;
                return Ok((applied, Vec::new()));
            }
            PageDrive::Continue { backpressure: next, applied: next_applied } => {
                backpressure = next;
                applied = next_applied;
            }
        }
        if !more {
            break;
        }
    }
    applied =
        apply_leftover(account, &mut turn, generation, retries, backpressure, applied).await?;
    let _ = now;
    flush_live_acks(account, generation).await?;
    Ok((applied, Vec::new()))
}

enum PageDrive {
    Paused { applied: usize },
    Continue { backpressure: Box<Backpressure>, applied: usize },
}

#[allow(clippy::too_many_arguments, reason = "standalone page drive shares the live handles")]
async fn drive_page(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    turn: &mut ReceiveTurn,
    generation: u64,
    page: &ResumePage,
    retries: &mut BTreeMap<(String, u64, String), ReceiveEntry>,
    mut backpressure: Box<Backpressure>,
    mut applied: usize,
) -> Result<PageDrive, SdkError> {
    let records = page.entries.clone();
    loop {
        let outcome = apply_owned(account, turn, generation, page)?;
        match outcome {
            ApplyOutcome::Covered { cursor } | ApplyOutcome::AlreadyCovered { cursor } => {
                let high = records
                    .iter()
                    .map(|row| row.entry.inbox_seq)
                    .max()
                    .unwrap_or(page.covered_through_seq);
                apply_w1::map_page_outcome(outcome, high)?;
                turn.cursor = cursor;
                break;
            }
            ApplyOutcome::Paused { cursor } => {
                turn.cursor = cursor;
                return Ok(PageDrive::Paused { applied });
            }
            ApplyOutcome::NeedStage { sequence, cursor } => {
                turn.cursor = cursor;
                let record = records.iter().find(|row| row.entry.inbox_seq == sequence).ok_or(
                    SdkError::InboundRejected("receive page need-stage missing entry".into()),
                )?;
                let retry_key = take_page_retry(retries, &record.entry);
                let entry = ReceiveEntry {
                    entry: record.entry.clone(),
                    retry_key,
                    replay: false,
                    turn: Some(turn.clone()),
                };
                let handle_generation = || generation;
                let (_, next) = apply_w1::apply_page(
                    account,
                    turn,
                    &handle_generation,
                    entry,
                    None,
                    backpressure,
                )
                .await?;
                backpressure = next;
                applied = applied.saturating_add(1);
                apply_w1::refresh_cursor(account.client.account_db()?, turn)?;
            }
            ApplyOutcome::NeedFetch { after } => {
                turn.cursor = after;
                backpressure = cover_point(
                    account,
                    engine,
                    turn,
                    generation,
                    after.saturating_add(1),
                    backpressure,
                )
                .await?;
            }
            ApplyOutcome::NeedPoint { seq, cursor } => {
                turn.cursor = cursor;
                backpressure =
                    cover_point(account, engine, turn, generation, seq, backpressure).await?;
            }
        }
    }
    Ok(PageDrive::Continue { backpressure, applied })
}

fn take_page_retry(
    retries: &mut BTreeMap<(String, u64, String), ReceiveEntry>,
    entry: &crate::GatewayInboxEntry,
) -> Option<String> {
    retries.remove(&entry_id(entry)).and_then(|prepared| prepared.retry_key)
}

async fn apply_leftover(
    account: &mut LocalBusAccountState,
    turn: &mut ReceiveTurn,
    generation: u64,
    retries: BTreeMap<(String, u64, String), ReceiveEntry>,
    mut backpressure: Box<Backpressure>,
    mut applied: usize,
) -> Result<usize, SdkError> {
    let mut leftover: Vec<_> = retries.into_values().collect();
    leftover.sort_by_key(|entry| entry.entry.inbox_seq);
    crate::bus::connection_manager::receive::bind_retry_turns(&mut leftover, Some(turn));
    for mut prepared in leftover {
        prepared.turn = Some(turn.clone());
        let handle_generation = || generation;
        let (_, next) =
            apply_w1::apply_page(account, turn, &handle_generation, prepared, None, backpressure)
                .await?;
        backpressure = next;
        applied = applied.saturating_add(1);
        apply_w1::refresh_cursor(account.client.account_db()?, turn)?;
    }
    let _ = backpressure;
    Ok(applied)
}

async fn flush_live_acks(account: &LocalBusAccountState, generation: u64) -> Result<(), SdkError> {
    let Some((handle, work)) = (account.connection.clone()).zip(account.connection_work.clone())
    else {
        return Ok(());
    };
    crate::bus::connection_manager::receive::flush_acks(
        &handle,
        &work,
        generation,
        true,
        account.timeouts.call,
    )
    .await
}

fn apply_owned(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    generation: u64,
    page: &ResumePage,
) -> Result<ApplyOutcome, SdkError> {
    let seqs: Vec<u64> = page.entries.iter().map(|row| row.entry.inbox_seq).collect();
    let reasons: Vec<&'static str> =
        page.known_losses.iter().map(|loss| loss.reason.as_str()).collect();
    let losses: Vec<ApplyLoss<'_>> = page
        .known_losses
        .iter()
        .zip(reasons.iter())
        .map(|(loss, reason)| ApplyLoss { from_seq: loss.from_seq, to_seq: loss.to_seq, reason })
        .collect();
    match apply::apply_page(
        account.client.account_db()?,
        turn.expected(),
        generation,
        ApplyPage {
            target: &turn.target,
            incarnation: &turn.incarnation,
            after: page.after_inbox_seq,
            covered: page.covered_through_seq,
            issued: page.issued_inbox_seq,
            settled: page.settled_through_seq,
            entries: &seqs,
            known_losses: &losses,
            oversize_next: page.oversize_next,
            more: page.more,
        },
    ) {
        Ok(outcome) => Ok(outcome),
        Err(apply::ApplyError::Protocol(text)) => Err(SdkError::InboundRejected(text.into())),
        Err(apply::ApplyError::Storage(error)) => Err(error.into()),
    }
}

async fn cover_point(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    turn: &mut ReceiveTurn,
    generation: u64,
    seq: u64,
    backpressure: Box<Backpressure>,
) -> Result<Box<Backpressure>, SdkError> {
    let reply = engine.fetch_entry(seq).await?;
    let target = turn.target.clone();
    let incarnation = turn.incarnation.clone();
    let gone_reason;
    let fetched = match &reply {
        PointReply::Entry(record) => Some(record.entry.clone()),
        _ => None,
    };
    let point = match &reply {
        PointReply::Entry(record) => ApplyPoint::Entry {
            seq: record.entry.inbox_seq,
            target: &target,
            incarnation: &incarnation,
        },
        PointReply::TooLarge { retain_until } => {
            ApplyPoint::TooLarge { seq, retain_until: *retain_until, incarnation: &incarnation }
        }
        PointReply::Gone { observed_issued_inbox_seq, reason } => {
            gone_reason = reason.as_str();
            ApplyPoint::Gone {
                seq,
                observed_issued: *observed_issued_inbox_seq,
                reason: gone_reason,
                incarnation: &incarnation,
            }
        }
        PointReply::Refused(reason) => {
            return Err(SdkError::GatewaySessionRejected(format!(
                "fetch_entry refused: {}",
                reason.as_str()
            )));
        }
    };
    let outcome = match apply::apply_point(
        account.client.account_db()?,
        turn.expected(),
        generation,
        seq,
        point,
    ) {
        Ok(outcome) => apply_w1::map_page_outcome(outcome, seq)?,
        Err(apply::ApplyError::Protocol(text)) => {
            return Err(SdkError::InboundRejected(text.into()));
        }
        Err(apply::ApplyError::Storage(error)) => return Err(error.into()),
    };
    match outcome {
        ApplyOutcome::NeedStage { sequence, cursor } if sequence == seq => {
            turn.cursor = cursor;
            let Some(entry) = fetched else {
                return Err(SdkError::InboundRejected(
                    "receive point need-stage missing entry".into(),
                ));
            };
            let handle_generation = || generation;
            let (_, next) = apply_w1::apply_page(
                account,
                turn,
                &handle_generation,
                ReceiveEntry { entry, retry_key: None, replay: false, turn: Some(turn.clone()) },
                None,
                backpressure,
            )
            .await?;
            apply_w1::refresh_cursor(account.client.account_db()?, turn)?;
            Ok(next)
        }
        ApplyOutcome::Covered { cursor }
        | ApplyOutcome::AlreadyCovered { cursor }
        | ApplyOutcome::Paused { cursor }
        | ApplyOutcome::NeedStage { cursor, .. }
        | ApplyOutcome::NeedPoint { cursor, .. }
        | ApplyOutcome::NeedFetch { after: cursor } => {
            turn.cursor = cursor;
            Ok(backpressure)
        }
    }
}

#[cfg(test)]
mod retry_key_tests {
    use super::*;
    use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};

    fn inbox(seq: u64) -> crate::GatewayInboxEntry {
        crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: seq,
            target_delivery_id: "t".into(),
            envelope: Envelope {
                schema: "ramflux.envelope.v1".into(),
                version: 1,
                domain: "test".into(),
                ext: Ext::default(),
                signed: SignedFields {
                    signing_key_id: "key".into(),
                    signature_alg: SignatureAlg::Ed25519,
                    signature: "sig".into(),
                },
                envelope_id: format!("env-{seq}"),
                source_principal_id: "source".into(),
                source_device_id: "device".into(),
                target_delivery_id: "t".into(),
                routing_set_id: None,
                delivery_class: DeliveryClass::OpaqueEvent,
                priority: Priority::Normal,
                ttl: 60,
                created_at: 1,
                encrypted_payload: "cipher".into(),
                payload_hash: "hash".into(),
                delivery_mode: None,
                collapse_tag: None,
                report_commitment: None,
            },
        }
    }

    #[test]
    fn page_served_retry_keeps_key() {
        let entry = inbox(1);
        let mut retries = BTreeMap::from([(
            entry_id(&entry),
            ReceiveEntry {
                entry: entry.clone(),
                retry_key: Some("retry-1".into()),
                replay: false,
                turn: None,
            },
        )]);
        assert_eq!(take_page_retry(&mut retries, &entry).as_deref(), Some("retry-1"));
        assert_eq!(retries.len(), 0, "page-served retry must not remain as leftover");
    }

    #[test]
    fn unknown_page_entry_has_no_retry_key() {
        let entry = inbox(2);
        let mut retries = BTreeMap::new();
        assert_eq!(take_page_retry(&mut retries, &entry), None);
    }
}
