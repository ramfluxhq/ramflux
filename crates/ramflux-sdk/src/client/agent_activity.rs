// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner-visible agent progress and run approvals.
//! A row is an actor-state record plus one journal event. The same source key is inserted once.
//! Sibling delivery uses a point-to-point custody packet on the rf conversation, not the creation scope.

use crate::client::own_device_copy::{OwnMessageInput, OwnPayloadKind};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use serde_json::{Value, json};

const MARKER_KIND: &str = "ramflux.agent_activity";
const MARKER_VERSION: u64 = 1;
const DOMAIN: &str = "ramflux.sdk.agent_activity.v1";
const MAX_MARKER: usize = 16 * 1024;
const MAX_APPROVALS: usize = 256;
const MAX_PROGRESS: usize = 128;
const MAX_SIBLINGS: usize = 16;

pub(crate) struct ActivityPacket {
    pub conversation_id: String,
    pub state_kind: String,
    pub record: Value,
}

/// `None` when the bytes are not an activity marker. A marker with a bad shape is refused.
pub(crate) fn parse_marker(bytes: &[u8]) -> Result<Option<ActivityPacket>, SdkError> {
    if bytes.len() > MAX_MARKER {
        return Ok(None);
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Ok(None);
    };
    if value.get("kind").and_then(Value::as_str) != Some(MARKER_KIND) {
        return Ok(None);
    }
    if value.get("v").and_then(Value::as_u64) != Some(MARKER_VERSION) {
        return Err(invalid("agent activity version is not 1"));
    }
    let conversation_id = text(&value, "conversation_id")
        .ok_or_else(|| invalid("agent activity conversation missing"))?;
    let state_kind =
        text(&value, "state_kind").ok_or_else(|| invalid("agent activity key missing"))?;
    if !state_kind_ok(&state_kind) || !id_ok(&conversation_id) {
        return Err(invalid("agent activity key is invalid"));
    }
    let record =
        value.get("record").cloned().ok_or_else(|| invalid("agent activity record missing"))?;
    if !record.is_object() || message_id_key(&record) {
        return Err(invalid("agent activity record is invalid"));
    }
    Ok(Some(ActivityPacket { conversation_id, state_kind, record }))
}

/// Stores one record when this device should accept it, then appends the journal event.
/// `None` means a later decision lost to the row already stored here.
pub(crate) fn commit(
    client: &RamfluxClient,
    state_kind: &str,
    mut record: Value,
) -> Result<Option<Value>, SdkError> {
    if !state_kind_ok(state_kind) || !record.is_object() || message_id_key(&record) {
        return Err(invalid("agent activity record is invalid"));
    }
    let db = client.account_db()?;
    if state_kind.starts_with("agent-approval/") && !accept_approval(db, state_kind, &record)? {
        return Ok(None);
    }
    trim(db, state_kind)?;
    let source = source_key(state_kind, &record);
    record["source_key"] = json!(source);
    db.persist_actor_state(state_kind, &record)?;
    let topic =
        if state_kind.starts_with("agent-approval/") { "agent.approval" } else { "agent.progress" };
    let subject = text(&record, "approval_id").or_else(|| text(&record, "run_id"));
    db.append_journal(
        &source,
        topic,
        &record,
        crate::time::now_unix_timestamp(),
        subject.as_deref(),
    )?;
    Ok(Some(record))
}

/// Sends the stored record to other devices of this root. A stage failure does not undo the row.
pub(crate) fn fan_out(
    client: &RamfluxClient,
    state_kind: &str,
    record: &Value,
) -> Result<(), SdkError> {
    let Some(conversation) = text(record, "conversation_id") else {
        return Ok(());
    };
    if conversation.is_empty() {
        return Ok(());
    }
    let marker = json!({
        "kind": MARKER_KIND,
        "v": MARKER_VERSION,
        "conversation_id": conversation,
        "state_kind": state_kind,
        "record": record,
    });
    let bytes = serde_json::to_vec(&marker).map_err(|_| invalid("agent activity marker"))?;
    if bytes.len() > MAX_MARKER {
        return Ok(());
    }
    let own = client.own_account_anchor()?;
    let me = client.owned_device_identity()?;
    let now = crate::time::now_unix_timestamp();
    let mut sent = 0_usize;
    for key in client.account_db()?.actor_state_keys("directory/device/")? {
        if sent >= MAX_SIBLINGS {
            break;
        }
        let Some(device) = key.strip_prefix("directory/device/") else {
            continue;
        };
        if device == me.device_id() || !sibling_of(client, device, &own)? {
            continue;
        }
        let Ok(target) = client.device_identity_for_root(&own, device) else {
            continue;
        };
        if stage_one(client, &target, &conversation, &bytes, now).is_ok() {
            sent = sent.saturating_add(1);
        }
    }
    Ok(())
}

/// `Some(true)` when `expires_at` is a UTC timestamp at or before `now`.
/// `None` means the local clock check is skipped.
#[must_use]
pub(crate) fn approval_expired(expires_at: &str, now: i64) -> Option<bool> {
    rfc3339_unix(expires_at).map(|expires| expires <= now)
}

fn accept_approval(
    db: &ramflux_storage::AccountDb,
    key: &str,
    incoming: &Value,
) -> Result<bool, SdkError> {
    let Some(existing) = db.load_actor_state::<Value>(key)? else {
        return Ok(true);
    };
    if existing.get("status").and_then(Value::as_str) != Some("decided") {
        return Ok(true);
    }
    if incoming.get("source").and_then(Value::as_str) == Some("prx") {
        return Ok(incoming.get("status").and_then(Value::as_str) != Some("pending"));
    }
    if incoming.get("status").and_then(Value::as_str) == Some("pending") {
        return Ok(false);
    }
    Ok(existing.get("decision") == incoming.get("decision"))
}

fn trim(db: &ramflux_storage::AccountDb, keep: &str) -> Result<(), SdkError> {
    let (prefix, cap) = if keep.starts_with("agent-approval/") {
        ("agent-approval/", MAX_APPROVALS)
    } else {
        ("agent-progress/", MAX_PROGRESS)
    };
    if db.actor_state_exists(keep)? {
        return Ok(());
    }
    let keys = db.actor_state_keys(prefix)?;
    if keys.len() < cap {
        return Ok(());
    }
    let drop_key = keys.iter().find(|key| key.as_str() != keep && pending_key(db, key)).cloned();
    if let Some(drop_key) = drop_key.or_else(|| keys.into_iter().find(|key| key != keep)) {
        db.remove_actor_state(&drop_key)?;
    }
    Ok(())
}

fn pending_key(db: &ramflux_storage::AccountDb, key: &str) -> bool {
    db.load_actor_state::<Value>(key)
        .ok()
        .flatten()
        .is_some_and(|row| row.get("status").and_then(Value::as_str) == Some("pending"))
}

fn source_key(state_kind: &str, record: &Value) -> String {
    if state_kind.starts_with("agent-approval/") {
        let id = text(record, "approval_id").unwrap_or_default();
        let status = text(record, "status").unwrap_or_default();
        let decision = text(record, "decision").unwrap_or_default();
        let source = text(record, "source").unwrap_or_default();
        return format!("agent-approval:{id}:{status}:{decision}:{source}");
    }
    let run = text(record, "run_id").unwrap_or_default();
    let kind = text(record, "kind").unwrap_or_default();
    let idx = record.get("idx").and_then(Value::as_u64).unwrap_or(0);
    format!("agent-progress:{run}:{kind}:{idx}")
}

fn sibling_of(client: &RamfluxClient, device: &str, own: &str) -> Result<bool, SdkError> {
    let Some(record) = client.account_db()?.client_record("device", device)? else {
        return Ok(false);
    };
    Ok(record.get("principal_commitment").and_then(Value::as_str) == Some(own))
}

fn stage_one(
    client: &RamfluxClient,
    target: &ramflux_crypto::RootQualifiedDeviceRef,
    conversation: &str,
    marker: &[u8],
    now: i64,
) -> Result<(), SdkError> {
    let own = client.owned_device_identity()?;
    let packet = g::AgentHostPacket {
        owner_anchor: client.own_account_anchor()?,
        source: Some(qualified(client, &own)?),
        recipient: Some(qualified(client, target)?),
        correlation_id: "agent-activity".into(),
        body: Some(g::agent_host_packet::Body::Custody(g::AgentCustodyPacket {
            value: Some(g::agent_custody_packet::Value::RequestJson(marker.to_vec())),
        })),
    };
    let body = crate::client::generated_control::control_from_payload(
        g::control::Payload::AgentSync(packet),
    )?
    .encode_to_vec();
    let id = ramflux_protocol::hash_base64url(DOMAIN, &body);
    let created_at = now;
    crate::bus::own_device_copy::stage_to(
        client,
        OwnMessageInput {
            payload_kind: OwnPayloadKind::Control,
            id: &id,
            created_at,
            conversation,
            group: None,
            body: &body,
        },
        target,
    )
}

fn qualified(
    client: &RamfluxClient,
    device: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<g::QualifiedDevice, SdkError> {
    let epoch = client
        .account_db()?
        .client_device_record(device)?
        .and_then(|record| record.get("device_epoch").and_then(Value::as_u64))
        .filter(|epoch| *epoch != 0)
        .ok_or_else(|| invalid("agent activity device epoch missing"))?;
    Ok(g::QualifiedDevice {
        account_anchor: device.root_commitment().to_owned(),
        device_id: device.device_id().to_owned(),
        device_epoch: epoch,
    })
}

fn state_kind_ok(kind: &str) -> bool {
    (kind.starts_with("agent-approval/") || kind.starts_with("agent-progress/"))
        && kind.len() <= 256
        && !kind.contains("..")
        && !kind.contains("//")
        && !kind.chars().any(char::is_control)
}

fn message_id_key(value: &Value) -> bool {
    let Some(map) = value.as_object() else {
        return true;
    };
    ["message_id", "own_copy_message_id", "target_message_id"]
        .into_iter()
        .any(|key| map.contains_key(key))
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn id_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn rfc3339_unix(raw: &str) -> Option<i64> {
    let raw = raw.strip_suffix('Z').or_else(|| raw.strip_suffix("+00:00"))?;
    let (date, time) = raw.split_once('T')?;
    let time = time.split_once('.').map_or(time, |(head, _)| head);
    let mut dates = date.split('-');
    let year: i32 = dates.next()?.parse().ok()?;
    let month: u32 = dates.next()?.parse().ok()?;
    let day: u32 = dates.next()?.parse().ok()?;
    if dates.next().is_some() {
        return None;
    }
    let mut times = time.split(':');
    let hour: u32 = times.next()?.parse().ok()?;
    let minute: u32 = times.next()?.parse().ok()?;
    let second: u32 = times.next()?.parse().ok()?;
    if times.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    days.checked_mul(86_400)?.checked_add(i64::from(hour * 3_600 + minute * 60 + second))
}

fn days_from_civil(mut year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    year -= i32::from(month <= 2);
    let era = if year >= 0 { year } else { year.checked_sub(399)? } / 400;
    let yoe = u32::try_from(year.checked_sub(era.checked_mul(400)?)?).ok()?;
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = yoe * 365 + yoe / 4 - yoe / 100 + day_of_year;
    i64::from(era).checked_mul(146_097)?.checked_add(i64::from(day_of_era))?.checked_sub(719_468)
}

fn invalid(reason: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: "field_invalid".into(),
        message: "field_invalid".into(),
        body: Box::new(json!({"reason_code":"field_invalid","details":{"cause":reason}})),
    }
}
