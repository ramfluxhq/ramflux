// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Coalesced group-state delivery with bounded retries and idempotent state application.
use crate::prelude::*;
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::group_state::GroupStateSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
mod delivery;

const PREFIX: &str = "group-state/send/";
const MAX_GROUPS: usize = 32;
const MAX_DEVICES: usize = 1024;
const ROOTS_PER_DRAIN: usize = 4;
const DEVICES_PER_DRAIN: usize = 4;
const DRIVER_PROGRESS: &str = "group-state/driver-progress";
const MAX_PENDING_BYTES: usize = 32 * 1024 * 1024;
#[derive(Clone, Deserialize, Serialize)]
struct Intent {
    snapshot: GroupStateSnapshot,
    eligible: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    terminal: Vec<TerminalSnapshot>,
    created_at: i64,
    active: Option<StagedEnvelope>,
    delivered: BTreeSet<(String, String)>,
    attempt: u8,
    next_at: i64,
    expires_at: i64,
    #[serde(default)]
    round_active: bool,
    #[serde(default)]
    round_failed: bool,
    #[serde(default)]
    round_devices: usize,
    #[serde(default)]
    cursor: Option<RecipientCursor>,
}
#[derive(Clone, Deserialize, Serialize)]
struct RecipientCursor {
    root: String,
    after_device: Option<String>,
    complete: bool,
}
// A removed recipient receives its removal boundary, never subsequent roster or name changes.
#[derive(Clone, Deserialize, Serialize)]
struct TerminalSnapshot {
    root: String,
    device: Option<String>,
    snapshot: GroupStateSnapshot,
}
#[derive(Clone, Deserialize, Serialize)]
struct StagedEnvelope {
    #[serde(default)]
    federation: Option<LocalBusFederationRoute>,
    root: String,
    device: String,
    envelope: ramflux_protocol::Envelope,
}
fn merge_eligible(
    into: &mut BTreeMap<String, BTreeSet<String>>,
    incoming: BTreeMap<String, BTreeSet<String>>,
) {
    for (root, excluded) in incoming {
        into.entry(root)
            .and_modify(|old| old.retain(|device| excluded.contains(device)))
            .or_insert(excluded);
    }
}
fn eligibility(state: &VerifiedGroupState) -> BTreeMap<String, BTreeSet<String>> {
    state
        .view()
        .members
        .iter()
        .map(|member| {
            let root = member.identity.root_commitment.clone();
            let excluded = state
                .view()
                .excluded
                .iter()
                .filter(|e| e.root_commitment == root)
                .map(|e| e.device_id.clone())
                .collect();
            (root, excluded)
        })
        .collect()
}

fn freeze_removals(intent: &mut Intent, previous: &VerifiedGroupState, state: &VerifiedGroupState) {
    for root in eligibility(previous).keys() {
        if !eligibility(state).contains_key(root) {
            intent.terminal.retain(|entry| entry.root != *root || entry.device.is_some());
            intent.terminal.push(TerminalSnapshot {
                root: root.clone(),
                device: None,
                snapshot: state.snapshot().clone(),
            });
        }
    }
    for excluded in &state.view().excluded {
        if previous.view().effective_role(&excluded.root_commitment, &excluded.device_id).is_some()
            && eligibility(state).contains_key(&excluded.root_commitment)
        {
            intent.terminal.retain(|entry| {
                entry.root != excluded.root_commitment
                    || entry.device.as_deref() != Some(&excluded.device_id)
            });
            intent.terminal.push(TerminalSnapshot {
                root: excluded.root_commitment.clone(),
                device: Some(excluded.device_id.clone()),
                snapshot: state.snapshot().clone(),
            });
        }
    }
}
fn recipient_snapshot<'a>(
    intent: &'a Intent,
    state: &'a VerifiedGroupState,
    root: &str,
    device: &str,
) -> Option<&'a GroupStateSnapshot> {
    if state.view().effective_role(root, device).is_some() {
        return Some(state.snapshot());
    }
    intent
        .terminal
        .iter()
        .find(|entry| entry.root == root && entry.device.as_deref() == Some(device))
        .or_else(|| {
            intent.terminal.iter().find(|entry| entry.root == root && entry.device.is_none())
        })
        .map(|entry| &entry.snapshot)
}

fn key(group: &str) -> String {
    format!("{PREFIX}{}", ramflux_protocol::encode_base64url(group))
}
pub(crate) fn enqueue(
    client: &RamfluxClient,
    state: &VerifiedGroupState,
    previous: Option<&VerifiedGroupState>,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let id = key(&state.view().group_id);
    let pending = db.load_actor_state::<Intent>(&id)?;
    let mut eligible = eligibility(state);
    if let Some(old) = previous {
        merge_eligible(&mut eligible, eligibility(old));
    }
    let now = now_unix_timestamp();
    let mut intent = if let Some(mut old) = pending.filter(|old| old.expires_at > now) {
        merge_eligible(&mut eligible, old.eligible);
        old.snapshot = state.snapshot().clone();
        old.eligible = eligible;
        old.delivered.clear();
        old.cursor = None;
        old.round_devices = 0;
        old
    } else {
        Intent {
            snapshot: state.snapshot().clone(),
            eligible,
            terminal: Vec::new(),
            created_at: now,
            active: None,
            delivered: BTreeSet::new(),
            attempt: 0,
            next_at: now,
            expires_at: now.saturating_add(3600),
            round_active: false,
            round_failed: false,
            round_devices: 0,
            cursor: None,
        }
    };
    if let Some(previous) = previous {
        freeze_removals(&mut intent, previous, state);
    }
    // A new mutation must not bypass an existing outage's backoff or extend its retry window.
    intent.snapshot = state.snapshot().clone();
    let mut all = db.list_actor_states::<Intent>(PREFIX)?;
    all.retain(|row| row.snapshot.group_id != state.view().group_id);
    if all.len() >= MAX_GROUPS {
        return Err(SdkError::LocalBus("group state queue is full".into()));
    }
    all.push(intent.clone());
    if serde_json::to_vec(&all)?.len() > MAX_PENDING_BYTES {
        return Err(SdkError::LocalBus("group state queue byte budget exceeded".into()));
    }
    db.persist_actor_state(&id, &intent)?;
    Ok(())
}
pub(in crate::bus) async fn flush(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let pending = account.client.account_db()?.list_actor_states::<Intent>(PREFIX)?;
    let after = account
        .client
        .account_db()?
        .load_actor_state::<String>(DRIVER_PROGRESS)?
        .unwrap_or_default();
    let mut pending = pending;
    pending.sort_by_key(|intent| key(&intent.snapshot.group_id));
    let selected = pending
        .iter()
        .find(|intent| key(&intent.snapshot.group_id) > after)
        .or_else(|| pending.first())
        .cloned();
    let Some(intent) = selected else {
        return Ok(0);
    };
    drive_one(account, intent).await
}
async fn drive_one(
    account: &mut LocalBusAccountState,
    mut intent: Intent,
) -> Result<usize, SdkError> {
    let mut delivered = 0;
    let now = now_unix_timestamp();
    let id = key(&intent.snapshot.group_id);
    account.client.account_db()?.persist_actor_state(DRIVER_PROGRESS, &id)?;
    if now < intent.next_at {
        return Ok(0);
    }
    if now >= intent.expires_at || (!intent.round_active && intent.attempt >= 8) {
        account.client.account_db()?.append_journal(&id,"group.state.delivery_failed",
                &serde_json::json!({"group_id":intent.snapshot.group_id,"epoch":intent.snapshot.epoch,"reason":"retry_budget_exhausted"}),now,None)?;
        account.client.account_db()?.remove_actor_state(&id)?;
        return Ok(0);
    }
    if !intent.round_active {
        intent.attempt += 1;
        intent.round_active = true;
        intent.round_failed = false;
        intent.round_devices = 0;
        intent.cursor = None;
    }
    account.client.account_db()?.persist_actor_state(&id, &intent)?;
    let state = match prepare_intent(&account.client, &mut intent, &account.target_delivery_id) {
        Ok(Some(state)) => state,
        Ok(None) => return Ok(0),
        Err(error) => {
            defer_round(&account.client, &mut intent)?;
            tracing::warn!(%error, group_id = %intent.snapshot.group_id,
                    "group state preparation deferred; other groups remain eligible");
            return Ok(0);
        }
    };
    let mut engine = account.take_live_engine().await?;
    let outcome = delivery::deliver(&account.client, &mut engine, &mut intent, &state).await;
    account.put_engine(engine);
    match outcome {
        Ok((count, progress)) => {
            delivered += count;
            match progress {
                DeliveryProgress::Complete => {
                    account.client.account_db()?.remove_actor_state(&id)?;
                }
                DeliveryProgress::Continue => {
                    persist_intent(&account.client, &intent)?;
                }
                DeliveryProgress::Retry => {
                    defer_round(&account.client, &mut intent)?;
                }
            }
        }
        Err(error) => {
            defer_round(&account.client, &mut intent)?;
            tracing::debug!(%error, group_id = %intent.snapshot.group_id,
                    "group state batch remains pending");
        }
    }
    Ok(delivered)
}
fn prepare_intent(
    client: &RamfluxClient,
    intent: &mut Intent,
    target: &str,
) -> Result<Option<VerifiedGroupState>, SdkError> {
    let state = ramflux_crypto::verify_group_state_snapshot(intent.snapshot.clone())?;
    let latest = client.account_db()?.shared_group_state(&intent.snapshot.group_id)?;
    let Some(latest) = latest else {
        client.account_db()?.remove_actor_state(&key(&intent.snapshot.group_id))?;
        return Ok(None);
    };
    if !latest.extends(&state) {
        return Err(StorageError::GroupPermissionDenied.into());
    }
    let state = latest;
    let own = client.owned_device_identity()?;
    let revoked = client.observed_device_set(own.root_commitment())?.is_some_and(|set| {
        !set.devices.iter().any(|device| {
            device.device_id == own.device_id()
                && device.status == ramflux_protocol::DeviceSetStatus::Active
        })
    });
    if revoked || state.view().effective_role(own.root_commitment(), own.device_id()).is_none() {
        client.account_db()?.remove_actor_state(&key(&intent.snapshot.group_id))?;
        return Ok(None);
    }
    let state = ramflux_crypto::resign_group_state_snapshot(
        client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &client.owned_group_actor(target)?,
        &state,
    )?;
    if intent.snapshot.state_hash != state.snapshot().state_hash {
        intent.delivered.clear();
        intent.cursor = None;
        intent.round_devices = 0;
    }
    intent.snapshot = state.snapshot().clone();
    // A retry uses a fresh carrier ID; the state and sender-key import remain idempotent.
    intent.active = None;
    merge_eligible(&mut intent.eligible, eligibility(&state));
    persist_intent(client, intent)?;
    Ok(Some(state))
}
enum DeliveryProgress {
    Complete,
    Continue,
    Retry,
}
fn defer_round(client: &RamfluxClient, intent: &mut Intent) -> Result<(), SdkError> {
    intent.round_active = false;
    intent.next_at = now_unix_timestamp().saturating_add((1_i64 << intent.attempt).min(60));
    persist_intent(client, intent)
}
fn persist_intent(client: &RamfluxClient, intent: &Intent) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let mut pending = db.list_actor_states::<Intent>(PREFIX)?;
    pending.retain(|row| row.snapshot.group_id != intent.snapshot.group_id);
    pending.push(intent.clone());
    if serde_json::to_vec(&pending)?.len() > MAX_PENDING_BYTES {
        return Err(SdkError::LocalBus("group state queue byte budget exceeded".into()));
    }
    db.persist_actor_state(&key(&intent.snapshot.group_id), intent)?;
    Ok(())
}
async fn submit_staged(
    client: &RamfluxClient,
    engine: &mut GatewaySessionEngine,
    intent: &mut Intent,
) -> Result<(), SdkError> {
    if let Some(staged) = &intent.active {
        if let Some(federation) = &staged.federation {
            let response =
                RamfluxClient::forward_federated_envelope(federation, staged.envelope.clone())?;
            if !response.accepted {
                return Err(SdkError::InboundPending(
                    "group state federation submission refused".into(),
                ));
            }
        } else {
            engine.submit_envelope(staged.envelope.clone()).await?;
        }
        intent.delivered.insert((staged.root.clone(), staged.device.clone()));
        intent.active = None;
        persist_intent(client, intent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
