// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! JSON frames on `GET /api/sync/ws`. The host masks and writes the bytes.

use super::cursor::{epoch_ok, parse_cursor};
use super::op::{MirrorOp, op_from_kind};
use crate::error::{PrxError, decode_ok, protocol};
use serde::Deserialize;
use serde_json::{Value, json};

/// Client pong for the server's JSON ping. Sent as one text frame.
pub const PONG_FRAME: &str = r#"{"type":"pong"}"#;

/// One decoded server frame.
#[derive(Clone, PartialEq, Eq)]
pub enum ServerFrame {
    /// The journal replay starts after `head_seq` only for events the server still holds.
    Welcome { epoch: String, head_seq: i64 },
    /// Epoch mismatch or an expired cursor. The host takes a fresh snapshot.
    Resync,
    /// JSON ping. The host answers with [`PONG_FRAME`].
    Ping,
    /// One durable journal event. Boxed so the other frame variants stay small.
    Event(Box<JournalEvent>),
    /// A stream frame or another live frame this card does not store.
    Ignored,
}

/// A durable journal event and the mirror change it produces.
#[derive(Clone, PartialEq, Eq)]
pub struct JournalEvent {
    /// Journal sequence. The host acks this after the cursor is durable.
    pub seq: i64,
    /// Stable id. A repeat is not applied twice.
    pub event_id: String,
    /// Journal kind, for the host log. No message text.
    pub kind: String,
    /// The local change. `Skip` still advances the cursor.
    pub op: MirrorOp,
}

/// Builds the hello frame. `cursor` is `None` only before the first snapshot.
///
/// # Errors
/// Returns `PrxError::Protocol` when `cursor` is set and is not a valid cursor.
pub fn hello_frame(cursor: Option<&str>) -> Result<String, PrxError> {
    if let Some(cursor) = cursor {
        parse_cursor(cursor)?;
    }
    let body = match cursor {
        Some(cursor) => json!({"type":"hello","proto":1,"cursor":cursor}),
        None => json!({"type":"hello","proto":1,"cursor":null}),
    };
    serde_json::to_string(&body).map_err(|_| protocol("sync frame could not be encoded"))
}

/// Builds an ack for one applied sequence.
///
/// # Errors
/// Returns `PrxError::Protocol` when `seq` is negative.
pub fn ack_frame(seq: i64) -> Result<String, PrxError> {
    if seq < 0 {
        return Err(protocol("sync cursor is invalid"));
    }
    serde_json::to_string(&json!({"type":"ack","seq":seq}))
        .map_err(|_| protocol("sync frame could not be encoded"))
}

/// Decodes one server text frame. The bytes are I-JSON.
///
/// # Errors
/// Returns `PrxError::Protocol` when the frame is not a documented shape.
pub fn decode_server(bytes: &[u8]) -> Result<ServerFrame, PrxError> {
    if bytes.len() > 1024 * 1024 {
        return Err(protocol("sync frame exceeds the client bound"));
    }
    let value: Value = decode_ok(bytes)?;
    let kind =
        value.get("type").and_then(Value::as_str).ok_or(protocol("sync frame has no type"))?;
    match kind {
        "ping" => ping(&value),
        "welcome" => welcome(&value),
        "resync_required" => resync(&value),
        "stream" => Ok(ServerFrame::Ignored),
        "event" => Ok(ServerFrame::Event(Box::new(event(&value)?))),
        _ => Err(protocol("sync frame type is unknown")),
    }
}

fn ping(value: &Value) -> Result<ServerFrame, PrxError> {
    let map = value.as_object().ok_or(protocol("sync frame is not an object"))?;
    if map.len() == 1 { Ok(ServerFrame::Ping) } else { Err(protocol("sync frame is not a ping")) }
}

fn welcome(value: &Value) -> Result<ServerFrame, PrxError> {
    let wire: WireWelcome =
        serde_json::from_value(value.clone()).map_err(|_| protocol("sync welcome is invalid"))?;
    if wire.frame_type != "welcome" || !epoch_ok(&wire.epoch) || wire.head_seq < 0 {
        return Err(protocol("sync welcome is invalid"));
    }
    Ok(ServerFrame::Welcome { epoch: wire.epoch, head_seq: wire.head_seq })
}

fn resync(value: &Value) -> Result<ServerFrame, PrxError> {
    let wire: WireResync =
        serde_json::from_value(value.clone()).map_err(|_| protocol("sync resync is invalid"))?;
    if wire.frame_type != "resync_required" || !epoch_ok(&wire.epoch) {
        return Err(protocol("sync resync is invalid"));
    }
    Ok(ServerFrame::Resync)
}

fn event(value: &Value) -> Result<JournalEvent, PrxError> {
    let wire: WireEvent =
        serde_json::from_value(value.clone()).map_err(|_| protocol("sync event is invalid"))?;
    if wire.frame_type != "event" || wire.seq < 0 || !kind_ok(&wire.kind) || !id_ok(&wire.event_id)
    {
        return Err(protocol("sync event is invalid"));
    }
    check_label(&wire.session)?;
    check_label(&wire.agent)?;
    check_label(&wire.incarnation)?;
    links_ok(&wire)?;
    let run_id = wire.run_id;
    if let Some(run) = &run_id {
        check_id(run)?;
    }
    let op = op_from_kind(
        &wire.kind,
        &wire.session,
        &wire.agent,
        &wire.incarnation,
        run_id,
        &wire.payload,
    )?;
    Ok(JournalEvent { seq: wire.seq, event_id: wire.event_id, kind: wire.kind, op })
}

fn links_ok(wire: &WireEvent) -> Result<(), PrxError> {
    let present = [
        wire.parent_session.as_ref(),
        wire.parent_run_id.as_ref(),
        wire.root_session.as_ref(),
        wire.root_run_id.as_ref(),
    ];
    let count = present.iter().filter(|item| item.is_some()).count();
    if count != 0 && count != 4 {
        return Err(protocol("sync event links are incomplete"));
    }
    for item in present.into_iter().flatten() {
        check_id(item)?;
    }
    Ok(())
}

fn check_label(value: &str) -> Result<(), PrxError> {
    if value.len() <= 512 && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(protocol("sync id is invalid"))
    }
}

fn check_id(value: &str) -> Result<(), PrxError> {
    if id_ok(value) { Ok(()) } else { Err(protocol("sync id is invalid")) }
}

fn id_ok(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn kind_ok(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= 64
        && kind.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWelcome {
    #[serde(rename = "type")]
    frame_type: String,
    epoch: String,
    head_seq: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResync {
    #[serde(rename = "type")]
    frame_type: String,
    epoch: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    seq: i64,
    event_id: String,
    kind: String,
    session: String,
    agent: String,
    incarnation: String,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    parent_session: Option<String>,
    #[serde(default)]
    parent_run_id: Option<String>,
    #[serde(default)]
    root_session: Option<String>,
    #[serde(default)]
    root_run_id: Option<String>,
    #[serde(rename = "type")]
    frame_type: String,
    payload: Value,
}
