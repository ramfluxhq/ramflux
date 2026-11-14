// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Emit typing through `message.focus` and `message.submit`, and observe `message.transient`.

use super::output::local_refusal;
use super::{LocalBusClient, RfError, call, print_json};
use crate::cli::{TypingAction, TypingCommand, TypingEmit, TypingWatch};
use ramflux_protocol::message::{self as schema, Content, MessageRequest, SendMessage, Typing};
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use serde_json::{Value, json};

const MAX_INDICATORS: usize = 64;
const TYPING_OPERATION_MIN: usize = 16;
const TYPING_OPERATION_MAX: usize = 64;

pub(super) fn preflight(command: &TypingCommand) -> Option<Value> {
    let (TypingAction::Start(emit) | TypingAction::Stop(emit)) = &command.action else {
        return None;
    };
    if (TYPING_OPERATION_MIN..=TYPING_OPERATION_MAX).contains(&emit.operation_id.len()) {
        return None;
    }
    Some(local_refusal(
        "message.submit",
        "invalid_argument",
        "typing operation_id must be 16 to 64 bytes",
    ))
}

pub(super) async fn handle(
    bus: &mut LocalBusClient,
    command: TypingCommand,
) -> Result<(), RfError> {
    match command.action {
        TypingAction::Start(emit) => emit_typing(bus, emit, true).await,
        TypingAction::Stop(emit) => emit_typing(bus, emit, false).await,
        TypingAction::Watch(watch) => print_json(&watch_indicators(bus, &watch).await?),
    }
}

async fn emit_typing(
    bus: &mut LocalBusClient,
    emit: TypingEmit,
    active: bool,
) -> Result<(), RfError> {
    if active {
        let focused = focus(bus, &emit.account, Some(emit.conversation.as_str())).await?;
        if !accepted(&focused) {
            return print_json(&focused);
        }
    }
    let body = submit_body(&emit.account, &emit.conversation, &emit.operation_id, active)?;
    let submitted = call(bus, &emit.account, "message.submit", None, body).await?;
    if active {
        return print_json(&submitted);
    }
    let blurred = focus(bus, &emit.account, None).await?;
    if !accepted(&submitted) {
        return print_json(&submitted);
    }
    if !accepted(&blurred) {
        return print_json(&blurred);
    }
    print_json(&submitted)
}

async fn focus(
    bus: &mut LocalBusClient,
    account: &str,
    conversation: Option<&str>,
) -> Result<Value, RfError> {
    call(bus, account, "message.focus", None, json!({"conversation_id": conversation})).await
}

fn submit_body(
    account: &str,
    conversation: &str,
    operation_id: &str,
    active: bool,
) -> Result<Value, RfError> {
    let request = MessageRequest {
        request_id: String::new(),
        account_id: account.to_owned(),
        action: Some(schema::message_request::Action::Send(SendMessage {
            conversation_id: conversation.to_owned(),
            content: Some(Content {
                value: Some(schema::content::Value::Typing(Typing { active, expires_at: 0 })),
            }),
            operation_id: operation_id.as_bytes().to_vec(),
            reply_to: None,
        })),
    };
    Ok(serde_json::to_value(request)?)
}

async fn watch_indicators(bus: &mut LocalBusClient, watch: &TypingWatch) -> Result<Value, RfError> {
    let subscribed = call(
        bus,
        &watch.account,
        "bus.subscribe",
        None,
        json!({"topics": [schema::TRANSIENT_TOPIC]}),
    )
    .await?;
    if !accepted(&subscribed) {
        return Ok(subscribed);
    }
    if let Some(path) = &watch.ready_file {
        // The file is the condition a caller waits on. It appears only after the
        // transient subscriber is installed, and before any typing event can be missed.
        std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    }
    let started_at_ms = unix_ms();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(watch.for_secs);
    let mut indicators = Vec::new();
    while indicators.len() < MAX_INDICATORS {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, bus.next_event()).await {
            Ok(Ok(event)) => {
                if let Some(row) = indicator(&watch.conversation, &event, unix_ms()) {
                    indicators.push(row);
                }
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_elapsed) => break,
        }
    }
    Ok(json!({
        "ok": true,
        "method": schema::TRANSIENT_TOPIC,
        "conversation_id": watch.conversation,
        "started_at_ms": started_at_ms,
        "indicators": indicators,
    }))
}

fn indicator(conversation: &str, event: &LocalBusFrame, observed_at_ms: u64) -> Option<Value> {
    if event.kind != LocalBusFrameKind::Event || event.method != schema::TRANSIENT_TOPIC {
        return None;
    }
    let update = ramflux_sdk::bindings::decode_message_update(&event.body).ok()?;
    let identity = update.identity.as_ref()?;
    if identity.conversation_id != conversation {
        return None;
    }
    let schema::message_update::State::Content(content) = update.state.as_ref()? else {
        return None;
    };
    let schema::content::Value::Typing(typing) = content.value.as_ref()? else {
        return None;
    };
    let author = identity.author.as_ref().map_or("", |author| author.account_anchor.as_str());
    Some(json!({
        "active": typing.active,
        "observed_at_ms": observed_at_ms,
        "expires_at": typing.expires_at,
        "author_anchor": author,
        "seq": event.seq.unwrap_or(0),
    }))
}

fn accepted(value: &Value) -> bool {
    value.get("ok").and_then(Value::as_bool) == Some(true)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::{TYPING_OPERATION_MAX, TYPING_OPERATION_MIN, indicator, preflight};
    use crate::cli::{TypingAction, TypingCommand, TypingEmit};
    use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
    use serde_json::json;

    fn emit(operation_id: &str) -> TypingCommand {
        TypingCommand {
            action: TypingAction::Start(TypingEmit {
                account: "alice".to_owned(),
                conversation: "thread".to_owned(),
                operation_id: operation_id.to_owned(),
            }),
        }
    }

    #[test]
    fn typing_operation_id_outside_16_to_64_bytes_is_a_local_refusal() {
        let short = preflight(&emit(&"x".repeat(TYPING_OPERATION_MIN - 1))).expect("short id");
        assert_eq!(short["error"]["code"], "invalid_argument");
        assert!(preflight(&emit(&"x".repeat(TYPING_OPERATION_MIN))).is_none());
        assert!(preflight(&emit(&"x".repeat(TYPING_OPERATION_MAX))).is_none());
        assert!(preflight(&emit(&"x".repeat(TYPING_OPERATION_MAX + 1))).is_some());
    }

    #[test]
    fn non_typing_event_is_not_an_indicator() {
        let mut frame = LocalBusFrame::request(
            "evt",
            Some("bob".to_owned()),
            "message",
            "message.transient",
            json!({"text": "durable"}),
        );
        frame.kind = LocalBusFrameKind::Event;
        assert!(indicator("thread", &frame, 1).is_none());
    }
}
