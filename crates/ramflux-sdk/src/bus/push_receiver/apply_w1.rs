// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant `ApplyPage` → W1 adapters. Unactivated accounts (no epoch row) stay on the live path.
#![allow(dead_code)]

use super::apply::cover_held_in;
use crate::bus::account_runtime::lifecycle_fence;
use crate::bus::connection_manager::{ReceiveApplied, ReceiveEntry};
use crate::bus::state::LocalBusAccountState;
use crate::bus::sync_driver::source::PreparedSource;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ProjectionStore, ReceiveCoverResult, ReceiveExpectation, ReceiveTransaction,
    StorageError,
};

/// True when `target` has a receive-epoch row. Missing table or row is the live unactivated path.
pub(crate) fn is_active(db: &AccountDb, target: &str) -> Result<bool, SdkError> {
    Ok(db.receive_epoch(target)?.is_some())
}

/// W1 + held W2 for one `ApplyPage` entry. No ACK intent (WA is P21).
pub(crate) async fn apply_page(
    account: &mut LocalBusAccountState,
    generation: u64,
    prepared: ReceiveEntry,
    source: PreparedSource,
    backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
) -> Result<ReceiveApplied, SdkError> {
    let mut source = source.map(|prepared| *prepared).transpose()?;
    match Box::pin(apply_once(account, generation, &prepared, source.as_mut())).await {
        Err(SdkError::LegacyBindingChanged) => {
            Box::pin(apply_once(account, generation, &prepared, source.as_mut())).await?;
        }
        Err(SdkError::PairRecoveryRequired) => {
            recover_own_copy(account, generation, &prepared.entry)?;
        }
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    Ok((None, backpressure))
}

async fn apply_once(
    account: &mut LocalBusAccountState,
    generation: u64,
    prepared: &ReceiveEntry,
    source: Option<&mut crate::client::routed::PreparedInbound>,
) -> Result<(), SdkError> {
    let entry = &prepared.entry;
    let sequence = entry.inbox_seq;
    let target = entry.target_delivery_id.clone();
    let local_device = account.gateway_config.device_id.clone();
    let kind = classify(account, entry, source).await?;
    let held = kind.is_held(account, entry, &local_device)?;
    match kind {
        Kind::Routed => {
            let mut engine = account.live_session_client()?;
            let pool = account.relay_quic_pool()?;
            account.client.apply_routed_entry(&mut engine, &pool, entry, false).await?;
            account.apply_session_metadata(engine);
        }
        Kind::OwnCopy(manifest) => {
            let message = entry.envelope.envelope_id.clone();
            let client = &account.client;
            run_fenced(client.account_db()?, generation, &target, |tx, expected| {
                client.apply_own_copy_w1_in(tx, entry, &manifest, expected, sequence, &message)?;
                cover_if_held(tx, sequence, held)
            })?;
        }
        Kind::LegacyDm { conversation } => {
            let client = &account.client;
            run_fenced(client.account_db()?, generation, &target, |tx, expected| {
                client.apply_legacy_success_w1_in(
                    tx,
                    entry,
                    &local_device,
                    &conversation,
                    expected,
                    generation,
                )?;
                cover_if_held(tx, sequence, held)
            })?;
        }
        Kind::LegacyA2i => {
            let client = &account.client;
            run_fenced(client.account_db()?, generation, &target, |tx, expected| {
                client.apply_legacy_a2i_w1_in(tx, entry, &local_device, expected, generation)?;
                cover_if_held(tx, sequence, held)
            })?;
        }
        Kind::LegacyHold => {
            let client = &account.client;
            run_fenced(client.account_db()?, generation, &target, |tx, expected| {
                client.apply_legacy_group_hold_w1_in(tx, entry, expected, generation)?;
                cover_if_held(tx, sequence, held)
            })?;
        }
    }
    Ok(())
}

enum Kind {
    OwnCopy(Box<crate::SdkDeviceManifestResponse>),
    Routed,
    LegacyDm { conversation: String },
    LegacyA2i,
    LegacyHold,
}

impl Kind {
    fn is_held(
        &self,
        account: &LocalBusAccountState,
        entry: &GatewayInboxEntry,
        local_device: &str,
    ) -> Result<bool, SdkError> {
        Ok(match self {
            Self::LegacyHold => true,
            Self::LegacyA2i => account.client.legacy_a2i_is_unbound(local_device, entry)?,
            Self::OwnCopy(_) | Self::Routed | Self::LegacyDm { .. } => false,
        })
    }
}

async fn classify(
    account: &LocalBusAccountState,
    entry: &GatewayInboxEntry,
    source: Option<&mut crate::client::routed::PreparedInbound>,
) -> Result<Kind, SdkError> {
    if let Some(manifest) = source.and_then(|prepared| prepared.own_copy_manifest.take()) {
        return Ok(Kind::OwnCopy(Box::new(manifest)));
    }
    if let Some(root) = account.client.own_device_receive_manifest_request(entry)? {
        let manifest = account
            .client
            .cache_verified_device_manifest(
                &account.gateway_config,
                &root,
                "own_device_message_receive",
            )
            .await?;
        return Ok(Kind::OwnCopy(Box::new(manifest)));
    }
    if crate::client::routed::decode(&entry.envelope).is_ok() {
        return Ok(Kind::Routed);
    }
    let reference = account.client.inbound_device_reference(entry)?;
    if account.client.v2_blocks_legacy(&reference)? {
        return Ok(Kind::LegacyHold);
    }
    if let Some(conversation) =
        account.client.legacy_routing_binding(&account.gateway_config.device_id, entry)?
    {
        return Ok(Kind::LegacyDm { conversation });
    }
    if account.client.legacy_a2i_is_unbound(&account.gateway_config.device_id, entry)?
        || account.client.load_legacy_a2i_receipt(entry)?.is_some()
    {
        return Ok(Kind::LegacyA2i);
    }
    Ok(Kind::LegacyHold)
}

fn recover_own_copy(
    account: &LocalBusAccountState,
    generation: u64,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let incarnation = owned_incarnation(db, &entry.target_delivery_id)?;
    let expected = expectation(db, generation, &entry.target_delivery_id, &incarnation)?;
    account.client.recover_own_copy_w1(entry, expected, entry.inbox_seq, now_unix_timestamp())?;
    Ok(())
}

fn run_fenced(
    db: &AccountDb,
    generation: u64,
    target: &str,
    write: impl FnOnce(&ReceiveTransaction<'_>, ReceiveExpectation<'_>) -> Result<(), SdkError>,
) -> Result<(), SdkError> {
    let incarnation = owned_incarnation(db, target)?;
    let expected = expectation(db, generation, target, &incarnation)?;
    let mut outcome = None;
    let fenced =
        lifecycle_fence::commit(db, generation, expected, |tx| match write(tx, expected) {
            Ok(()) => Ok(()),
            Err(error) => {
                outcome = Some(error);
                Err(StorageError::Integrity("apply page w1 failed"))
            }
        });
    match (fenced, outcome) {
        (_, Some(error)) => Err(error),
        (Err(error), _) => Err(error.into()),
        (Ok(()), None) => Ok(()),
    }
}

fn cover_if_held(tx: &ReceiveTransaction<'_>, sequence: u64, held: bool) -> Result<(), SdkError> {
    if !held {
        return Ok(());
    }
    match cover_held_in(tx, sequence)? {
        ReceiveCoverResult::Covered | ReceiveCoverResult::Paused => Ok(()),
    }
}

fn owned_incarnation(db: &AccountDb, target: &str) -> Result<String, SdkError> {
    db.receive_epoch(target)?
        .ok_or_else(|| SdkError::LocalBus("receive epoch missing for dormant apply".into()))
}

fn expectation<'a>(
    db: &'a AccountDb,
    generation: u64,
    target: &'a str,
    incarnation: &'a str,
) -> Result<ReceiveExpectation<'a>, SdkError> {
    let cursor = db
        .projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
    Ok(ReceiveExpectation {
        target,
        incarnation,
        cursor,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}
