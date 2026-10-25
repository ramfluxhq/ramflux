// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Coalesced group-state delivery intents with stable ids, backoff and finite budgets.
use crate::prelude::*;
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::group_state::GroupStateSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const PREFIX: &str = "group-state/send/";
const MAX_GROUPS: usize = 32;
const MAX_DEVICES: usize = 1024;
const MAX_PENDING_BYTES: usize = 32 * 1024 * 1024;
#[derive(Clone, Deserialize, Serialize)]
struct Intent {
    snapshot: GroupStateSnapshot,
    eligible: BTreeMap<String, BTreeSet<String>>,
    created_at: i64,
    active: Option<StagedEnvelope>,
    delivered: BTreeSet<(String, String)>,
    attempt: u8,
    next_at: i64,
    expires_at: i64,
}
#[derive(Clone, Deserialize, Serialize)]
struct StagedEnvelope {
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

fn key(group: &str) -> String {
    format!("{PREFIX}{}", ramflux_protocol::encode_base64url(group))
}
pub(super) fn enqueue(
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
    if let Some(old) = pending {
        merge_eligible(&mut eligible, old.eligible);
    }
    let now = now_unix_timestamp();
    let intent = Intent {
        snapshot: state.snapshot().clone(),
        eligible,
        created_at: now,
        active: None,
        delivered: BTreeSet::new(),
        attempt: 0,
        next_at: now,
        expires_at: now.saturating_add(3600),
    };
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
    let mut delivered = 0;
    for mut intent in pending.into_iter().take(MAX_GROUPS) {
        let now = now_unix_timestamp();
        let id = key(&intent.snapshot.group_id);
        if now < intent.next_at {
            continue;
        }
        if now >= intent.expires_at || intent.attempt >= 8 {
            account.client.account_db()?.append_journal(&id,"group.state.delivery_failed",
                &serde_json::json!({"group_id":intent.snapshot.group_id,"epoch":intent.snapshot.epoch,"reason":"retry_budget_exhausted"}),now,None)?;
            account.client.account_db()?.remove_actor_state(&id)?;
            continue;
        }
        intent.attempt += 1;
        intent.next_at = now.saturating_add((1_i64 << intent.attempt).min(60));
        account.client.account_db()?.persist_actor_state(&id, &intent)?;
        let state = ramflux_crypto::verify_group_state_snapshot(intent.snapshot.clone())?;
        let mut engine = account.take_live_engine().await?;
        let outcome = deliver(&account.client, &mut engine, &mut intent, &state).await;
        account.put_engine(engine);
        if let Ok(count) = outcome {
            delivered += count;
            account.client.account_db()?.remove_actor_state(&id)?;
        }
    }
    Ok(delivered)
}
async fn deliver(
    client: &RamfluxClient,
    engine: &mut GatewaySessionEngine,
    intent: &mut Intent,
    state: &VerifiedGroupState,
) -> Result<usize, SdkError> {
    let mut recipients = Vec::new();
    if intent.active.is_some() {
        submit_staged(client, engine, intent).await?;
    }
    for (root, excluded) in &intent.eligible {
        let manifest =
            crate::client::contact::fetch_verified_device_manifest(&engine.config, root).await?;
        client.persist_identity_directory(&manifest)?;
        recipients.extend(
            manifest
                .devices
                .into_iter()
                .filter(|device| !excluded.contains(&device.device_id))
                .map(|device| (root.clone(), device)),
        );
        if recipients.len() > MAX_DEVICES {
            return Err(SdkError::LocalBus("group state device fanout budget exceeded".into()));
        }
    }
    let mut delivered = 0;
    for (root, device) in recipients {
        if (device.device_id == engine.config.device_id
            && device.principal_id == engine.config.principal_id)
            || intent.delivered.contains(&(root.clone(), device.device_id.clone()))
        {
            continue;
        }
        let bytes = client.shared_group_packet(
            state,
            state.view().effective_role(&root, &device.device_id).is_some(),
        )?;
        let state = &intent.snapshot;
        let envelope = format!(
            "group_state_{}",
            ramflux_crypto::blake3_256_base64url(
                "ramflux.group_state.delivery.v1",
                &ramflux_protocol::canonical_json_bytes(&(
                    &state.state_hash,
                    &root,
                    &device.device_id
                ))?
            )
        );
        let mut message = GatewayDirectMessage {
            conversation_id: state
                .operations
                .first()
                .and_then(|op| match &op.change {
                    ramflux_protocol::group_state::GroupStateChange::Create {
                        conversation_id,
                        ..
                    } => Some(conversation_id.clone()),
                    _ => None,
                })
                .or_else(|| state.checkpoint.as_ref().map(|c| c.state.conversation_id.clone()))
                .ok_or_else(|| SdkError::LocalBus("group state conversation is absent".into()))?,
            message_id: envelope.clone(),
            envelope_id: envelope,
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: engine.config.device_id.clone(),
            recipient_device_id: Some(device.device_id.clone()),
            recipient_principal_commitment: Some(root.clone()),
            target_delivery_id: device.target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: intent.created_at,
            ttl: 3600,
        };
        let sealed = client
            .seal_routed_as(
                engine,
                &message,
                &bytes,
                crate::client::routed::Route::group_control(&state.group_id),
            )
            .await?;
        message.encrypted_body = serde_json::to_vec(&sealed)?;
        intent.active = Some(StagedEnvelope {
            root: root.clone(),
            device: device.device_id.clone(),
            envelope: crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?,
        });
        // Persist the exact ciphertext before submit; a lost ACK cannot advance the ratchet again.
        persist_intent(client, intent)?;
        submit_staged(client, engine, intent).await?;
        delivered += 1;
    }
    Ok(delivered)
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
        engine.submit_envelope(staged.envelope.clone()).await?;
        intent.delivered.insert((staged.root.clone(), staged.device.clone()));
        intent.active = None;
        persist_intent(client, intent)?;
    }
    Ok(())
}
