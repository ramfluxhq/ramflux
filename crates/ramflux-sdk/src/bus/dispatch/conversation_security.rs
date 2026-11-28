// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DM lifecycle on the bus (MLS D5): first-send establish, Welcome fan-out, the pending-send
//! queue, stranger Welcomes, `conversation.security`, and the unlock / wake / daily tick.
//!
//! A Welcome is fanned only after `merge_own` (`EstablishOutcome::Established`). Fan-out failure
//! does not roll the merge back. The same operation id replays `identity_change_pending`.

use crate::client::trust_pins::{self, SendGate};
use crate::mls::SqlMlsKv;
use crate::mls::key_packages::{self, FetchOutcome, FetchedKeyPackage};
use crate::mls::lifecycle::{self, DeviceAdder, UpdateContext};
use crate::mls::order::{
    self, CommitOutcome, ConvStore, EstablishKind, EstablishOutcome, ReconcileOutcome, Scope,
};
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Pending outbound sends kept per conversation. The 257th is `rate_limited` and is not stored.
pub(crate) const PENDING_CAP: usize = 256;
/// Stranger Welcomes kept before accept. The 101st is not stored.
pub(crate) const STRANGER_CAP: usize = 100;
/// A stored stranger Welcome is dropped after 30 days.
pub(crate) const STRANGER_TTL: u64 = 30 * 86_400;
const DAY_SECS: i64 = 86_400;
const QUEUE_PREFIX: &str = "mls-pending-send/";
const STRANGER_PREFIX: &str = "mls-stranger-welcome/";
const SCOPE_PREFIX: &str = "mls-scope/";
const EVENT_PREFIX: &str = "mls-event/";
const FORK_PREFIX: &str = "mls-fork/";
const DEVICE_ADD_PREFIX: &str = "mls-device-add/";
const PIN_SYNC_KEY: &str = "mls-pin-sync/pending";
const LAST_DAILY_KEY: &str = "mls-daemon/last-daily";
const CUSTODY_FLAG_KEY: &str = "mls-daemon/custody-head-changed";
const RECOVERY_DIR: &str = "mls-recovery";

/// Whether the send can seal now or must wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreparedSend {
    /// The DM group is the orderer's current group.
    Ready,
    /// The operation is queued. `reason` is `creating`, `orderer_unreachable`, or `awaiting_welcome`.
    Held { reason: &'static str },
}

/// Inputs of [`security_view`]. The queue and stranger caps are decided beside it.
pub(crate) struct ViewInput<'a> {
    pub phase: &'a str,
    pub reason: Option<&'a str>,
    pub epoch: u64,
    pub members: &'a [Value],
    pub fork_at: Option<u64>,
}

/// `true` when another pending send still fits. `stored == 256` is the 257th and is refused.
pub(crate) fn admit_pending(stored: usize) -> Result<(), ()> {
    if stored >= PENDING_CAP { Err(()) } else { Ok(()) }
}

/// `true` when another stranger Welcome still fits. `stored == 100` is the 101st and is dropped.
pub(crate) fn admit_stranger(stored: usize) -> Result<(), ()> {
    if stored >= STRANGER_CAP { Err(()) } else { Ok(()) }
}

/// `{state, reason?, epoch, members, warning?}`. `fork_recovered` is set only for a real fork.
pub(crate) fn security_view(input: &ViewInput<'_>) -> Value {
    let mut body = json!({
        "state": input.phase,
        "epoch": input.epoch,
        "members": input.members,
    });
    if let Some(reason) = input.reason {
        body["reason"] = json!(reason);
    }
    if let Some(at) = input.fork_at {
        body["warning"] = json!({ "code": "fork_recovered", "params": { "at": at } });
    }
    body
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingSend {
    operation: String,
    reason: String,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StrangerWelcome {
    welcome_b64: String,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ScopeRow {
    kind: String,
    anchors: Vec<String>,
    last_used: u64,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeviceAdd {
    device_id: String,
    anchor: String,
    missing_since: u64,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ForkMark {
    at: u64,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EventRow {
    body: Value,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PinSync {
    bytes: Vec<u8>,
    anchor: String,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DailyMark {
    at: i64,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Flag {
    changed: bool,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ForeignKp {
    packages: Vec<FetchedKeyPackage>,
    expires_at: i64,
}

fn now_u64() -> u64 {
    u64::try_from(now_unix_timestamp()).unwrap_or(0)
}

fn far() -> i64 {
    i64::MAX / 4
}

fn later(now: u64, secs: u64) -> i64 {
    i64::try_from(now.saturating_add(secs)).unwrap_or(far())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn refused(code: &str, message: &str, details: &Value) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.to_owned(),
        message: message.to_owned(),
        body: Box::new(json!({ "reason_code": code, "details": details })),
    }
}

fn not_member(conversation_id: &str) -> SdkError {
    refused(
        "not_member",
        "this device was removed from the conversation",
        &json!({ "conversation_id": conversation_id }),
    )
}

fn rate_limited(message: &str) -> SdkError {
    refused("rate_limited", message, &json!({}))
}

/// Direct-conversation peer anchor. Groups are left to the caller.
fn direct_peer_anchor(
    client: &RamfluxClient,
    thread: &Value,
    principal: &str,
) -> Result<Option<String>, SdkError> {
    if thread.get("kind").and_then(Value::as_str) != Some("direct") {
        return Ok(None);
    }
    let participants = thread
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| SdkError::LocalBus("direct participants absent".into()))?;
    if participants.len() != 2 || !participants.iter().any(|id| id.as_str() == Some(principal)) {
        return Err(SdkError::LocalBus("direct conversation membership mismatch".into()));
    }
    let peer = participants
        .iter()
        .filter_map(Value::as_str)
        .find(|id| *id != principal)
        .ok_or_else(|| SdkError::LocalBus("direct peer absent".into()))?;
    if let Some(identity) = client.account_db()?.client_record("identity", peer)? {
        let root = identity
            .get("contact_identity_commitment")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::LocalBus("direct peer commitment absent".into()))?;
        return Ok(Some(root.to_owned()));
    }
    let own = client.own_account_anchor()?;
    let mut foreign = thread
        .get("participant_roots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|root| *root != own);
    let root =
        foreign.next().ok_or_else(|| SdkError::LocalBus("direct peer identity absent".into()))?;
    if foreign.next().is_some() {
        return Err(SdkError::LocalBus("direct peer identity absent".into()));
    }
    Ok(Some(root.to_owned()))
}

/// Identity gate. A stored operation id replays; a new one against a pending pin is refused.
pub(crate) fn gate_anchor(
    client: &RamfluxClient,
    anchor: &str,
    operation: &str,
) -> Result<(), SdkError> {
    let pin = trust_pins::load_pin(client, anchor)?;
    let stored = trust_pins::terminal_stored(client, operation)?;
    match trust_pins::send_gate(pin.as_ref(), stored) {
        SendGate::Proceed => Ok(()),
        SendGate::Replay => Err(trust_pins::identity_pending(anchor)),
        SendGate::Refuse => {
            trust_pins::store_terminal(client, operation, anchor, now_unix_timestamp())?;
            Err(trust_pins::identity_pending(anchor))
        }
    }
}

/// Identity gate for a conversation mutation. Non-DM conversations are unchanged.
pub(crate) fn gate_mutation(
    account: &LocalBusAccountState,
    request: &LocalBusFrame,
    operation: &str,
) -> Result<(), SdkError> {
    let Some(conversation_id) = request.body.get("conversation_id").and_then(Value::as_str) else {
        return Ok(());
    };
    let Some(thread) =
        account.client.account_db()?.client_record("conversation", conversation_id)?
    else {
        return Ok(());
    };
    let Some(principal) =
        account.client.device_branch.as_ref().map(|branch| branch.principal_id.clone())
    else {
        return Ok(());
    };
    let Some(anchor) = direct_peer_anchor(&account.client, &thread, &principal)? else {
        return Ok(());
    };
    gate_anchor(&account.client, &anchor, operation)
}

/// `conversation.start`: the caller already ran `note_lookup`.
pub(crate) fn gate_resolved(
    client: &RamfluxClient,
    anchor: &str,
    operation: &str,
) -> Result<(), SdkError> {
    gate_anchor(client, anchor, operation)
}

fn queue_prefix(conversation: &str) -> String {
    format!("{QUEUE_PREFIX}{conversation}/")
}

fn queue_key(conversation: &str, operation: &str) -> String {
    format!(
        "{}{}",
        queue_prefix(conversation),
        ramflux_crypto::blake3_256_base64url("ramflux.mls.pending-send.v1", operation.as_bytes())
    )
}

fn enqueue(
    client: &RamfluxClient,
    conversation: &str,
    operation: &str,
    reason: &str,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let prefix = queue_prefix(conversation);
    db.expire_actor_states(&prefix, now_unix_timestamp())?;
    let key = queue_key(conversation, operation);
    if db.load_actor_state::<PendingSend>(&key)?.is_some() {
        return Ok(());
    }
    let stored = db.actor_state_keys(&prefix)?.len();
    if admit_pending(stored).is_err() {
        return Err(rate_limited("the pending send queue is full"));
    }
    db.persist_actor_state(
        &key,
        &PendingSend {
            operation: operation.to_owned(),
            reason: reason.to_owned(),
            expires_at: later(now_u64(), STRANGER_TTL),
        },
    )?;
    Ok(())
}

fn pending_reason(client: &RamfluxClient, conversation: &str) -> Result<Option<String>, SdkError> {
    let db = client.account_db()?;
    let prefix = queue_prefix(conversation);
    for key in db.actor_state_keys(&prefix)? {
        if let Some(row) = db.load_actor_state::<PendingSend>(&key)? {
            return Ok(Some(row.reason));
        }
    }
    Ok(None)
}

fn remember_scope(client: &RamfluxClient, scope: &Scope, now: u64) -> Result<(), SdkError> {
    let kind = match scope.kind {
        order::DmGroupKind::Dm => "dm",
        order::DmGroupKind::SelfGroup => "self",
    };
    client.account_db()?.persist_actor_state(
        &format!("{SCOPE_PREFIX}{}", hex(&scope.conversation_id)),
        &ScopeRow {
            kind: kind.to_owned(),
            anchors: scope.anchors.clone(),
            last_used: now,
            expires_at: far(),
        },
    )?;
    Ok(())
}

fn scope_of_row(row: &ScopeRow) -> Option<Scope> {
    if row.kind.as_str() == "self" {
        row.anchors.first().filter(|anchor| !anchor.is_empty()).map(|anchor| Scope::own(anchor))
    } else {
        let own = row.anchors.first().filter(|anchor| !anchor.is_empty())?;
        let peer = row.anchors.get(1).filter(|anchor| !anchor.is_empty())?;
        Scope::dm(own, peer).ok()
    }
}

/// Persist an outbox-visible event. Recovery and a new device use `devices-changed` only.
pub(crate) fn store_event(
    client: &RamfluxClient,
    kind: &str,
    id: &str,
    body: Value,
) -> Result<(), SdkError> {
    let key = format!("{EVENT_PREFIX}{kind}/{id}");
    client
        .account_db()?
        .persist_actor_state(&key, &EventRow { body, expires_at: later(now_u64(), 7 * 86_400) })?;
    Ok(())
}

pub(crate) fn event_kind(state_kind: &str) -> Option<(&'static str, &str)> {
    if let Some(id) = state_kind.strip_prefix("mls-event/identity-changed/") {
        Some(("contact.identity_changed", id))
    } else {
        state_kind
            .strip_prefix("mls-event/devices-changed/")
            .map(|id| ("conversation.devices_changed", id))
    }
}

pub(crate) fn load_event(
    client: &RamfluxClient,
    state_kind: &str,
) -> Result<Option<Value>, SdkError> {
    let Some(row) = client.account_db()?.load_actor_state::<EventRow>(state_kind)? else {
        return Ok(None);
    };
    Ok(Some(row.body))
}

fn store_fork(client: &RamfluxClient, scope: &Scope, now: u64) -> Result<(), SdkError> {
    client.account_db()?.persist_actor_state(
        &format!("{FORK_PREFIX}{}", hex(&scope.conversation_id)),
        &ForkMark { at: now, expires_at: far() },
    )?;
    Ok(())
}

fn fork_at(client: &RamfluxClient, scope: &Scope) -> Result<Option<u64>, SdkError> {
    Ok(client
        .account_db()?
        .load_actor_state::<ForkMark>(&format!("{FORK_PREFIX}{}", hex(&scope.conversation_id)))?
        .map(|mark| mark.at))
}

/// Accept does not send. The pin sync is one self-group application message, or it waits for the tick.
pub(crate) fn accept_trust(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, account_id)?;
    let contact = request
        .body
        .get("contact")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SdkError::LocalBus("contact required".into()))?;
    let pending = request
        .body
        .get("pending_anchor")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SdkError::LocalBus("pending_anchor required".into()))?;
    let pin = trust_pins::accept_change(&account.client, contact, pending, now_u64())?;
    let bytes = trust_pins::pin_sync_json(&pin, contact, pending)?;
    queue_pin_sync(&account.client, &pin.previous_anchor, bytes)?;
    Ok(local_bus_ok(json!({ "accepted": true, "contact": pin.previous_anchor })))
}

fn queue_pin_sync(client: &RamfluxClient, anchor: &str, bytes: Vec<u8>) -> Result<(), SdkError> {
    client.account_db()?.persist_actor_state(
        PIN_SYNC_KEY,
        &PinSync { bytes, anchor: anchor.to_owned(), expires_at: far() },
    )?;
    Ok(())
}

/// Schedule the device that just became an unlocked account. The tick adds it where it is due.
pub(crate) fn schedule_new_device(
    client: &RamfluxClient,
    device_id: &str,
    anchor: &str,
) -> Result<(), SdkError> {
    if device_id.is_empty() || anchor.is_empty() {
        return Ok(());
    }
    client.account_db()?.persist_actor_state(
        &format!("{DEVICE_ADD_PREFIX}{device_id}"),
        &DeviceAdd {
            device_id: device_id.to_owned(),
            anchor: anchor.to_owned(),
            missing_since: now_u64(),
            expires_at: far(),
        },
    )?;
    Ok(())
}

fn marker_path(root: &Path, account_id: &str) -> Option<PathBuf> {
    if account_id.is_empty()
        || account_id.contains(['/', '\\'])
        || account_id == "."
        || account_id == ".."
    {
        return None;
    }
    Some(root.join(RECOVERY_DIR).join(account_id))
}

/// Recovery cannot emit from the supervisor. The next unlock tick consumes this marker.
pub(crate) fn mark_recovery_marker(root: &Path, account_id: &str) -> Result<(), SdkError> {
    let Some(path) = marker_path(root, account_id) else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"1")?;
    Ok(())
}

fn take_recovery_marker(root: &Path, account_id: &str) -> bool {
    let Some(path) = marker_path(root, account_id) else {
        return false;
    };
    std::fs::remove_file(path).is_ok()
}

/// Note a stranger Welcome seen before routed decode. Open accounts join immediately.
pub(crate) fn note_stranger_welcome(
    account: &mut LocalBusAccountState,
    welcome: &[u8],
) -> Result<(), SdkError> {
    if welcome.len() < 4 || welcome.len() > 1024 * 1024 {
        return Ok(());
    }
    let client = &account.client;
    if client.contact_request_policy().ok().as_deref() == Some("open")
        && join_welcome(client, welcome).is_ok()
    {
        return Ok(());
    }
    let db = client.account_db()?;
    db.expire_actor_states(STRANGER_PREFIX, now_unix_timestamp())?;
    let key = format!(
        "{STRANGER_PREFIX}{}",
        ramflux_crypto::blake3_256_base64url("ramflux.mls.stranger-welcome.v1", welcome)
    );
    if db.load_actor_state::<StrangerWelcome>(&key)?.is_some() {
        return Ok(());
    }
    if admit_stranger(db.actor_state_keys(STRANGER_PREFIX)?.len()).is_err() {
        return Ok(());
    }
    db.persist_actor_state(
        &key,
        &StrangerWelcome {
            welcome_b64: ramflux_protocol::encode_base64url(welcome),
            expires_at: later(now_u64(), STRANGER_TTL),
        },
    )?;
    Ok(())
}

fn join_welcome(client: &RamfluxClient, welcome: &[u8]) -> Result<(), SdkError> {
    let mut slot = None;
    let runtime = client.mls_runtime(&mut slot)?;
    runtime.mls().join(welcome)?.commit_plain().map_err(ramflux_mls::MlsError::from)?;
    Ok(())
}

/// Join one stored stranger Welcome. Missing rows are `no_pending_change`.
pub(crate) fn accept_stranger_welcome(
    client: &RamfluxClient,
    key_suffix: &str,
) -> Result<(), SdkError> {
    let key = format!("{STRANGER_PREFIX}{key_suffix}");
    let Some(row) = client.account_db()?.load_actor_state::<StrangerWelcome>(&key)? else {
        return Err(refused("no_pending_change", "no stranger welcome is stored", &json!({})));
    };
    let welcome = ramflux_protocol::decode_base64url(&row.welcome_b64)
        .map_err(|_| SdkError::LocalBus("stored welcome is not base64url".into()))?;
    join_welcome(client, &welcome)?;
    client.account_db()?.remove_actor_state(&key)?;
    Ok(())
}

fn welcome_ciphertext(payload: &str) -> Option<Vec<u8>> {
    let raw = ramflux_protocol::decode_base64url(payload).ok()?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&raw).ok()?;
    let bytes = compact.ciphertext;
    if bytes.len() >= 4 && bytes[0] == 0 && bytes[1] == 1 && bytes[2] == 0 && bytes[3] == 3 {
        Some(bytes.to_vec())
    } else {
        None
    }
}

/// Peek a compact cryptobox. A Welcome is consumed here and never reaches routed decode.
pub(crate) fn stranger_welcome_bytes(payload: &str) -> Option<Vec<u8>> {
    welcome_ciphertext(payload)
}

fn evict_forgotten(client: &RamfluxClient, forgotten: &[Vec<u8>]) {
    for id in forgotten {
        client.seal_cache.borrow_mut().evict_group(id);
    }
}

fn welcome_envelope(
    client: &RamfluxClient,
    target_delivery_id: &str,
    welcome: &[u8],
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let branch = client
        .device_branch
        .as_ref()
        .ok_or_else(|| SdkError::GatewaySessionRejected("sealing config incomplete".into()))?;
    let nested = crate::dm::SdkDmEncryptedEnvelope {
        source_principal_commitment: Some(client.own_account_anchor()?),
        schema: "ramflux.sdk.dm_x3dh_envelope.v2".to_owned(),
        version: 2,
        x3dh: None,
        ciphertext: ramflux_crypto::DmCiphertext {
            session_id: String::new(),
            counter: 0,
            nonce: [0; 12],
            ciphertext: welcome.to_vec(),
            ratchet_public_key: None,
            previous_chain_length: 0,
            sender_device_id_hash: [0; 32],
            recipient_device_id_hash: [0; 32],
            device_epoch: 0,
            message_event_id: String::new(),
            canonical_header_bytes: Vec::new(),
            header_hash: String::new(),
            key_commitment: String::new(),
            franking_commitment: String::new(),
            commitment: String::new(),
            ciphertext_hash: String::new(),
        },
        collapse_tag: None,
        report_commitment: None,
    };
    let encrypted_payload =
        ramflux_protocol::message::outer::wire_encrypted_payload(&serde_json::to_vec(&nested)?)
            .map_err(|error| SdkError::InboundRejected(error.to_string()))?;
    let payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        encrypted_payload.as_bytes(),
    );
    let envelope_id = ramflux_crypto::blake3_256_base64url(
        "ramflux.mls.welcome.v1",
        &ramflux_protocol::canonical_json_bytes(&(target_delivery_id, welcome))?,
    );
    let mut envelope = ramflux_protocol::Envelope {
        schema: ramflux_protocol::message::outer::CANDIDATE_ENVELOPE_SCHEMA.to_owned(),
        version: 2,
        domain: ramflux_protocol::message::outer::CANDIDATE_ENVELOPE_SCHEMA.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: crate::gateway::helpers::sdk_device_signed_fields(&branch.device_id, ""),
        envelope_id,
        source_principal_id: branch.principal_id.clone(),
        source_device_id: branch.device_id.clone(),
        target_delivery_id: target_delivery_id.to_owned(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::Message,
        priority: ramflux_protocol::Priority::Normal,
        ttl: client.content_ttl()?,
        created_at: now_unix_timestamp(),
        encrypted_payload,
        payload_hash,
        delivery_mode: Some("durable".into()),
        collapse_tag: None,
        report_commitment: None,
    };
    crate::dm::apply_candidate_named_fields_with(&mut envelope, None, None);
    if let Ok(anchor) = client.own_account_anchor() {
        envelope.ext.ext.insert("source_root_commitment".into(), Value::String(anchor));
    }
    envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &envelope)?;
    Ok(envelope)
}

async fn fan_welcome(
    client: &RamfluxClient,
    engine: &mut impl crate::gateway::access::GatewaySessionAccess,
    anchor: &str,
    welcome: &[u8],
) -> Result<(), SdkError> {
    if welcome.is_empty() {
        return Ok(());
    }
    let manifest =
        match client.cache_verified_device_manifest(engine.config(), anchor, "mls_welcome").await {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(%error, "mls welcome fan-out manifest");
                return Ok(());
            }
        };
    for device in manifest.devices {
        let envelope = match welcome_envelope(client, &device.target_delivery_id, welcome) {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::warn!(%error, "mls welcome envelope");
                continue;
            }
        };
        if let Err(error) =
            crate::client::recipient_home::submit_addressed(client, engine, envelope, Some(anchor))
                .await
        {
            tracing::warn!(%error, "mls welcome fan-out");
        }
    }
    Ok(())
}

fn open_kv(client: &RamfluxClient) -> Result<SqlMlsKv, SdkError> {
    Ok(SqlMlsKv::new(client.account_db()?.mls_kv()))
}

async fn fetch_packages(
    client: &RamfluxClient,
    engine: &mut impl crate::gateway::access::MlsFrameAccess,
    anchor: &str,
) -> Result<FetchOutcome, SdkError> {
    if crate::client::recipient_home::foreign_target(client, anchor)?.is_some() {
        let packages = fetch_foreign(client, anchor, std::time::Duration::from_secs(10)).await?;
        return Ok(FetchOutcome::Fetched(packages));
    }
    key_packages::fetch(engine, anchor).await
}

async fn fetch_foreign(
    client: &RamfluxClient,
    anchor: &str,
    timeout: std::time::Duration,
) -> Result<Vec<FetchedKeyPackage>, SdkError> {
    let key = format!("mls-foreign-kp/{anchor}");
    if let Some(row) = client.account_db()?.load_actor_state::<ForeignKp>(&key)? {
        return Ok(row.packages);
    }
    let base = crate::client::recipient_home::required_public_base(client, anchor, None).await?;
    let body = serde_json::to_vec(&json!({ "anchor": anchor }))?;
    let response: key_packages::KeyPackageFetchResponse =
        crate::prekey::http_async::post_json(&base, "/mvp1/key-package/fetch", body, timeout)
            .await?;
    let packages = key_packages::check_fetched(response);
    client
        .account_db()?
        .persist_actor_state(&key, &ForeignKp { packages: packages.clone(), expires_at: far() })?;
    Ok(packages)
}

/// Cache a foreign home's `KeyPackages`. A local peer, or a DM group that already exists, is a no-op.
pub(crate) async fn cache_foreign_key_packages(
    client: &RamfluxClient,
    anchor: &str,
    timeout: std::time::Duration,
) -> Result<(), SdkError> {
    if crate::client::recipient_home::foreign_target(client, anchor)?.is_none() {
        return Ok(());
    }
    let own = client.own_account_anchor()?;
    let scope = Scope::dm(&own, anchor)?;
    let kv = open_kv(client)?;
    if ConvStore::new(&kv).get(&scope.conversation_id)?.is_some() {
        return Ok(());
    }
    let _ = fetch_foreign(client, anchor, timeout).await?;
    Ok(())
}

struct HeldOrReady {
    prepared: PreparedSend,
    welcome: Option<Vec<u8>>,
    forgotten: Vec<Vec<u8>>,
    anchor: String,
}

async fn establish_dm(
    account: &mut LocalBusAccountState,
    engine: &mut (
             impl crate::gateway::access::MlsFrameAccess + crate::gateway::access::GatewaySessionAccess
         ),
    scope: &Scope,
    anchor: &str,
    conversation: &str,
    operation: &str,
) -> Result<HeldOrReady, SdkError> {
    let now = now_u64();
    let packages = match fetch_packages(&account.client, engine, anchor).await? {
        FetchOutcome::NotYetAvailable => {
            enqueue(&account.client, conversation, operation, "orderer_unreachable")?;
            return Ok(HeldOrReady {
                prepared: PreparedSend::Held { reason: "orderer_unreachable" },
                welcome: None,
                forgotten: Vec::new(),
                anchor: anchor.to_owned(),
            });
        }
        FetchOutcome::Fetched(packages) if packages.is_empty() => {
            return Err(SdkError::Mls {
                code: "policy_rejected",
                detail: "a group needs at least one device to add".to_owned(),
            });
        }
        FetchOutcome::Fetched(packages) => packages,
    };
    let outcome = {
        let kv = open_kv(&account.client)?;
        let mut slot = None;
        let runtime = account.client.mls_runtime(&mut slot)?;
        let store = ConvStore::new(&kv);
        order::establish(
            engine,
            runtime.mls(),
            &store,
            order::Establish { scope, key_packages: &packages, kind: EstablishKind::Create },
            now,
        )
        .await?
    };
    let prepared = match outcome {
        EstablishOutcome::Established { welcome, forgotten, .. } => {
            remember_scope(&account.client, scope, now)?;
            HeldOrReady {
                prepared: PreparedSend::Ready,
                welcome: Some(welcome),
                forgotten,
                anchor: anchor.to_owned(),
            }
        }
        EstablishOutcome::LostRace(
            ReconcileOutcome::InSync { .. } | ReconcileOutcome::Switched { .. },
        ) => {
            remember_scope(&account.client, scope, now)?;
            HeldOrReady {
                prepared: PreparedSend::Ready,
                welcome: None,
                forgotten: Vec::new(),
                anchor: anchor.to_owned(),
            }
        }
        EstablishOutcome::LostRace(ReconcileOutcome::WaitingForWelcome { .. }) => {
            enqueue(&account.client, conversation, operation, "awaiting_welcome")?;
            HeldOrReady {
                prepared: PreparedSend::Held { reason: "awaiting_welcome" },
                welcome: None,
                forgotten: Vec::new(),
                anchor: anchor.to_owned(),
            }
        }
        EstablishOutcome::NotYetAvailable
        | EstablishOutcome::LostRace(ReconcileOutcome::NotYetAvailable) => {
            enqueue(&account.client, conversation, operation, "orderer_unreachable")?;
            HeldOrReady {
                prepared: PreparedSend::Held { reason: "orderer_unreachable" },
                welcome: None,
                forgotten: Vec::new(),
                anchor: anchor.to_owned(),
            }
        }
        EstablishOutcome::RateLimited { .. }
        | EstablishOutcome::LostRace(ReconcileOutcome::UnknownScope) => {
            enqueue(&account.client, conversation, operation, "creating")?;
            HeldOrReady {
                prepared: PreparedSend::Held { reason: "creating" },
                welcome: None,
                forgotten: Vec::new(),
                anchor: anchor.to_owned(),
            }
        }
    };
    Ok(prepared)
}

/// Identity-gate a DM send and establish the group before the message is sealed.
pub(crate) async fn prepare_dm(
    account: &mut LocalBusAccountState,
    conversation: &str,
    thread: &Value,
    principal: &str,
    operation: &str,
) -> Result<PreparedSend, SdkError> {
    let Some(anchor) = direct_peer_anchor(&account.client, thread, principal)? else {
        return Ok(PreparedSend::Ready);
    };
    gate_anchor(&account.client, &anchor, operation)?;
    let own = account.client.own_account_anchor()?;
    let scope = Scope::dm(&own, &anchor)?;
    let removed = {
        let kv = open_kv(&account.client)?;
        ConvStore::new(&kv).get(&scope.conversation_id)?.is_some_and(|state| state.removed)
    };
    if removed {
        return Err(not_member(conversation));
    }
    let exists = {
        let kv = open_kv(&account.client)?;
        ConvStore::new(&kv).get(&scope.conversation_id)?.is_some()
    };
    if exists {
        remember_scope(&account.client, &scope, now_u64())?;
        return Ok(PreparedSend::Ready);
    }
    let mut engine = match account.session_client().await {
        Ok(engine) => engine,
        Err(error) if order::is_not_yet_available(&error) => {
            enqueue(&account.client, conversation, operation, "orderer_unreachable")?;
            return Ok(PreparedSend::Held { reason: "orderer_unreachable" });
        }
        Err(error) => return Err(error),
    };
    let result = establish_dm(account, &mut engine, &scope, &anchor, conversation, operation).await;
    let held = match result {
        Ok(held) => held,
        Err(error) => {
            account.apply_session_metadata(engine);
            return Err(error);
        }
    };
    evict_forgotten(&account.client, &held.forgotten);
    if let Some(welcome) = held.welcome.as_deref() {
        let _ = fan_welcome(&account.client, &mut engine, &held.anchor, welcome).await;
    }
    account.apply_session_metadata(engine);
    Ok(held.prepared)
}

fn member_json(member: &ramflux_mls::MemberSummary) -> Value {
    json!({
        "anchor": member.root_commitment.clone().unwrap_or_default(),
        "device_id": member.device_id.clone().unwrap_or_default(),
        "ai_flag": false,
    })
}

/// Reader body of `conversation.security`. A removed device is `not_member`.
pub(crate) fn view(client: &RamfluxClient, request: &LocalBusFrame) -> Result<Value, SdkError> {
    let conversation = request
        .body
        .get("conversation_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| SdkError::LocalBus("conversation_id required".into()))?;
    let Some(thread) = client.account_db()?.client_record("conversation", conversation)? else {
        return Err(SdkError::LocalBus("conversation absent".into()));
    };
    let principal = client
        .device_branch
        .as_ref()
        .map(|branch| branch.principal_id.clone())
        .ok_or(SdkError::IdentityRootMissing)?;
    let Some(anchor) = direct_peer_anchor(client, &thread, &principal)? else {
        return Ok(security_view(&ViewInput {
            phase: "ok",
            reason: None,
            epoch: 0,
            members: &[],
            fork_at: None,
        }));
    };
    let own = client.own_account_anchor()?;
    let scope = Scope::dm(&own, &anchor)?;
    let kv = open_kv(client)?;
    let mut slot = None;
    let runtime = client.mls_runtime(&mut slot)?;
    let store = ConvStore::new(&kv);
    let state = store.get(&scope.conversation_id)?;
    if state.as_ref().is_some_and(|state| state.removed) {
        return Err(not_member(conversation));
    }
    let reason = pending_reason(client, conversation)?;
    let (epoch, members, phase) = if let Some(state) = state.as_ref() {
        let status = runtime.mls().status(&state.group_id)?;
        let members: Vec<Value> = status.members.iter().map(member_json).collect();
        let phase = if reason.is_some() { "pending" } else { "ok" };
        (status.epoch, members, phase)
    } else {
        (0, Vec::new(), "pending")
    };
    let fork = fork_at(client, &scope)?;
    let reason_str = reason.as_deref().or(if phase == "pending" { Some("creating") } else { None });
    Ok(security_view(&ViewInput {
        phase,
        reason: reason_str,
        epoch,
        members: &members,
        fork_at: fork,
    }))
}

fn custody_changed(client: &RamfluxClient) -> Result<bool, SdkError> {
    Ok(client
        .account_db()?
        .load_actor_state::<Flag>(CUSTODY_FLAG_KEY)?
        .is_some_and(|flag| flag.changed))
}

pub(crate) fn mark_custody_head_changed(client: &RamfluxClient) -> Result<(), SdkError> {
    client
        .account_db()?
        .persist_actor_state(CUSTODY_FLAG_KEY, &Flag { changed: true, expires_at: far() })?;
    Ok(())
}

fn clear_custody(client: &RamfluxClient) -> Result<(), SdkError> {
    client.account_db()?.remove_actor_state(CUSTODY_FLAG_KEY)?;
    Ok(())
}

fn daily_due(client: &RamfluxClient, now: i64) -> Result<bool, SdkError> {
    let last =
        client.account_db()?.load_actor_state::<DailyMark>(LAST_DAILY_KEY)?.map(|mark| mark.at);
    Ok(last.is_none_or(|at| now.saturating_sub(at) >= DAY_SECS))
}

fn mark_daily(client: &RamfluxClient, now: i64) -> Result<(), SdkError> {
    client
        .account_db()?
        .persist_actor_state(LAST_DAILY_KEY, &DailyMark { at: now, expires_at: far() })?;
    Ok(())
}

fn scopes(client: &RamfluxClient) -> Result<Vec<ScopeRow>, SdkError> {
    let db = client.account_db()?;
    let mut rows = Vec::new();
    for key in db.actor_state_keys(SCOPE_PREFIX)? {
        if let Some(row) = db.load_actor_state::<ScopeRow>(&key)? {
            rows.push(row);
        }
    }
    Ok(rows)
}

fn doomed_old(client: &RamfluxClient, scope: &Scope, now: u64) -> Result<Vec<Vec<u8>>, SdkError> {
    let kv = open_kv(client)?;
    let Some(state) = ConvStore::new(&kv).get(&scope.conversation_id)? else {
        return Ok(Vec::new());
    };
    Ok(state
        .old
        .into_iter()
        .filter(|old| now >= old.read_only_until)
        .map(|old| old.group_id)
        .collect())
}

async fn ensure_self_group(
    account: &mut LocalBusAccountState,
    engine: &mut (
             impl crate::gateway::access::MlsFrameAccess + crate::gateway::access::GatewaySessionAccess
         ),
) -> Result<(), SdkError> {
    let anchor = account.client.own_account_anchor()?;
    let scope = Scope::own(&anchor);
    let exists = {
        let kv = open_kv(&account.client)?;
        ConvStore::new(&kv).get(&scope.conversation_id)?.is_some()
    };
    if exists {
        remember_scope(&account.client, &scope, now_u64())?;
        return Ok(());
    }
    let packages = match key_packages::fetch(engine, &anchor).await? {
        FetchOutcome::NotYetAvailable => return Ok(()),
        FetchOutcome::Fetched(packages) if packages.is_empty() => return Ok(()),
        FetchOutcome::Fetched(packages) => packages,
    };
    let now = now_u64();
    let outcome = {
        let kv = open_kv(&account.client)?;
        let mut slot = None;
        let runtime = account.client.mls_runtime(&mut slot)?;
        let store = ConvStore::new(&kv);
        match order::establish(
            engine,
            runtime.mls(),
            &store,
            order::Establish {
                scope: &scope,
                key_packages: &packages,
                kind: EstablishKind::Create,
            },
            now,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) if order::is_not_yet_available(&error) => return Ok(()),
            Err(SdkError::Mls { code: "policy_rejected", .. }) => return Ok(()),
            Err(error) => return Err(error),
        }
    };
    if let EstablishOutcome::Established { welcome, forgotten, .. } = outcome {
        evict_forgotten(&account.client, &forgotten);
        let _ = fan_welcome(&account.client, engine, &anchor, &welcome).await;
        remember_scope(&account.client, &scope, now)?;
    }
    Ok(())
}

async fn tick_scopes(
    account: &mut LocalBusAccountState,
    engine: &mut (
             impl crate::gateway::access::MlsFrameAccess + crate::gateway::access::GatewaySessionAccess
         ),
    daily: bool,
) -> Result<(), SdkError> {
    let now = now_u64();
    let context = UpdateContext {
        membership_changed_by_us: false,
        custody_head_changed: custody_changed(&account.client)?,
    };
    let rows = scopes(&account.client)?;
    for row in &rows {
        let Some(scope) = scope_of_row(row) else { continue };
        let outcome = {
            let kv = open_kv(&account.client)?;
            let mut slot = None;
            let runtime = account.client.mls_runtime(&mut slot)?;
            let store = ConvStore::new(&kv);
            lifecycle::update_if_due(engine, runtime.mls(), &store, &scope, now, context).await?
        };
        if matches!(outcome, Some(CommitOutcome::Forked)) {
            store_fork(&account.client, &scope, now)?;
        }
        if !daily {
            continue;
        }
        match order::status(engine, &scope).await {
            Ok(_) => {}
            Err(error) if order::is_not_yet_available(&error) => {}
            Err(error) => tracing::warn!(%error, "mls daily status"),
        }
        let doomed = doomed_old(&account.client, &scope, now)?;
        let welcome_out = {
            let kv = open_kv(&account.client)?;
            let mut slot = None;
            let runtime = account.client.mls_runtime(&mut slot)?;
            let store = ConvStore::new(&kv);
            order::expire_old_group(runtime.mls(), &store, &scope, now)?;
            let pending = store
                .get(&scope.conversation_id)?
                .is_some_and(|state| state.pending_lookup_due(now));
            if pending {
                match order::retry_pending(engine, runtime.mls(), &store, &scope, now).await {
                    Ok(Some(CommitOutcome::Accepted { extra: Some(welcome), .. })) => Some(welcome),
                    Ok(Some(CommitOutcome::Forked)) => {
                        store_fork(&account.client, &scope, now)?;
                        None
                    }
                    _ => None,
                }
            } else {
                None
            }
        };
        if let Some(welcome) = welcome_out {
            let anchor = scope.anchors.first().map_or("", String::as_str);
            if !anchor.is_empty() {
                let _ = fan_welcome(&account.client, engine, anchor, &welcome).await;
            }
        }
        evict_forgotten(&account.client, &doomed);
    }
    clear_custody(&account.client)?;
    if daily {
        mark_daily(&account.client, now_unix_timestamp())?;
        drain_device_adds(account, engine).await?;
        drain_pin_sync(account)?;
    }
    Ok(())
}

async fn drain_device_adds(
    account: &mut LocalBusAccountState,
    engine: &mut (
             impl crate::gateway::access::MlsFrameAccess + crate::gateway::access::GatewaySessionAccess
         ),
) -> Result<(), SdkError> {
    let now = now_u64();
    let due = {
        let db = account.client.account_db()?;
        let mut due = Vec::new();
        for key in db.actor_state_keys(DEVICE_ADD_PREFIX)? {
            if let Some(row) = db.load_actor_state::<DeviceAdd>(&key)? {
                let draw = row.device_id.bytes().next().map_or(0, u64::from);
                if lifecycle::add_due(DeviceAdder::Approver, row.missing_since, now, draw) {
                    due.push(row);
                }
            }
        }
        due
    };
    let scope_rows = scopes(&account.client)?;
    for add in due {
        let Ok(FetchOutcome::Fetched(packages)) = key_packages::fetch(engine, &add.anchor).await
        else {
            continue;
        };
        let one: Vec<FetchedKeyPackage> =
            packages.into_iter().filter(|package| package.device_id == add.device_id).collect();
        if one.is_empty() {
            continue;
        }
        for row in &scope_rows {
            let Some(scope) = scope_of_row(row) else { continue };
            if !lifecycle::add_eagerly(row.last_used, now)
                && scope.kind != order::DmGroupKind::SelfGroup
            {
                continue;
            }
            let outcome = {
                let kv = open_kv(&account.client)?;
                let mut slot = None;
                let runtime = account.client.mls_runtime(&mut slot)?;
                let store = ConvStore::new(&kv);
                lifecycle::add_devices(engine, runtime.mls(), &store, &scope, &one, now).await
            };
            match outcome {
                Ok(CommitOutcome::Accepted { extra: welcome, .. }) => {
                    let target = scope
                        .anchors
                        .iter()
                        .find(|item| item.as_str() != add.anchor)
                        .map(String::as_str);
                    if let Some(anchor) = target.or(scope.anchors.first().map(String::as_str)) {
                        let _ = fan_welcome(&account.client, engine, anchor, &welcome).await;
                    }
                    let _ = store_event(
                        &account.client,
                        "devices-changed",
                        &hex(&scope.conversation_id),
                        json!({
                            "conversation_id": hex(&scope.conversation_id),
                            "added": [{ "anchor": add.anchor, "device_id": add.device_id, "ai_flag": false }],
                            "removed": [],
                        }),
                    );
                    let _ = account
                        .client
                        .account_db()?
                        .remove_actor_state(&format!("{DEVICE_ADD_PREFIX}{}", add.device_id));
                }
                Ok(CommitOutcome::Forked) => store_fork(&account.client, &scope, now)?,
                _ => {}
            }
        }
    }
    Ok(())
}

fn drain_pin_sync(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    let Some(pending) = account.client.account_db()?.load_actor_state::<PinSync>(PIN_SYNC_KEY)?
    else {
        return Ok(());
    };
    let anchor = account.client.own_account_anchor()?;
    let scope = Scope::own(&anchor);
    let kv = open_kv(&account.client)?;
    let mut slot = None;
    let runtime = account.client.mls_runtime(&mut slot)?;
    let store = ConvStore::new(&kv);
    let Some(state) = store.get(&scope.conversation_id)? else {
        return Ok(());
    };
    {
        let mut cache = account.client.seal_cache.borrow_mut();
        crate::mls::channel::seal_once(runtime.mls(), &mut cache, &state.group_id, &pending.bytes)?;
    }
    account.client.account_db()?.remove_actor_state(PIN_SYNC_KEY)?;
    Ok(())
}

fn note_recovery_if_marked(account: &LocalBusAccountState) {
    let Ok(root) = account.client.account_index().map(|index| index.root().to_path_buf()) else {
        return;
    };
    let Ok(id) = account.client.account_db().map(|db| db.local_account_id.clone()) else {
        return;
    };
    if !take_recovery_marker(&root, &id) {
        return;
    }
    let anchor = account.client.own_account_anchor().unwrap_or_default();
    let device = account
        .client
        .device_branch
        .as_ref()
        .map(|branch| branch.device_id.clone())
        .unwrap_or_default();
    let _ = store_event(
        &account.client,
        "devices-changed",
        &id,
        json!({
            "conversation_id": anchor,
            "added": [{ "anchor": anchor, "device_id": device, "ai_flag": false }],
            "removed": [],
        }),
    );
}

fn drain_open_strangers(client: &RamfluxClient) -> Result<(), SdkError> {
    if client.contact_request_policy().ok().as_deref() != Some("open") {
        return Ok(());
    }
    let keys = client.account_db()?.actor_state_keys(STRANGER_PREFIX)?;
    for key in keys {
        let Some(suffix) = key.strip_prefix(STRANGER_PREFIX) else {
            continue;
        };
        if suffix.is_empty() {
            continue;
        }
        let _ = accept_stranger_welcome(client, suffix);
    }
    Ok(())
}

/// Unlock tick. `NotYetAvailable` does not fail the unlock. The caller logs anything else.
pub(crate) async fn on_unlock(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    note_recovery_if_marked(account);
    drain_open_strangers(&account.client)?;
    let mut engine = match account.session_client().await {
        Ok(engine) => engine,
        Err(error) if order::is_not_yet_available(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let daily = daily_due(&account.client, now_unix_timestamp()).unwrap_or(false);
    let tick = async {
        let now = now_u64();
        let topped_up = {
            let mut slot = None;
            let runtime = account.client.mls_runtime(&mut slot)?;
            key_packages::top_up(&mut engine, runtime.mls(), now).await
        };
        match topped_up {
            Ok(_) => {}
            Err(error) if order::is_not_yet_available(&error) => {}
            Err(error) => tracing::warn!(%error, "mls key package top-up"),
        }
        if let Err(error) = ensure_self_group(account, &mut engine).await
            && !order::is_not_yet_available(&error)
        {
            tracing::warn!(%error, "mls self group");
        }
        tick_scopes(account, &mut engine, daily).await
    }
    .await;
    account.apply_session_metadata(engine);
    match tick {
        Err(error) if order::is_not_yet_available(&error) => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_view_refuses_the_257th_and_the_101st_stranger() {
        let members = Vec::new();
        let view = security_view(&ViewInput {
            phase: "pending",
            reason: Some("creating"),
            epoch: 1,
            members: &members,
            fork_at: None,
        });
        assert_eq!(view["state"], "pending", "a held send is pending");
        assert_eq!(view["reason"], "creating");
        assert_eq!(view["epoch"], 1);
        assert!(admit_pending(PENDING_CAP).is_err(), "the 257th pending send is rate_limited");
        assert!(admit_pending(PENDING_CAP - 1).is_ok(), "256 pending sends fit");
        assert!(admit_stranger(STRANGER_CAP).is_err(), "the 101st stranger welcome is not stored");
        assert!(admit_stranger(STRANGER_CAP - 1).is_ok(), "100 stranger welcomes fit");
        let forked = security_view(&ViewInput {
            phase: "re_established",
            reason: None,
            epoch: 2,
            members: &members,
            fork_at: Some(30),
        });
        assert_eq!(forked["warning"]["code"], "fork_recovered");
        assert_eq!(forked["warning"]["params"]["at"], 30);
    }
}
