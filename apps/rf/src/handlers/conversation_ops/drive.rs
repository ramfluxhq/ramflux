// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Call the existing conversation bus methods. Typing stays in its own module.

use super::super::{LocalBusClient, RfError, print_json};
use super::output;
use super::typing;
use crate::cli::{
    ConversationAction, ConversationCommand, ConversationDelete, ConversationReact,
    ConversationSend, ConversationText,
};
use ramflux_sdk::LocalBusFrame;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) async fn handle(socket: PathBuf, command: ConversationCommand) -> Result<(), RfError> {
    if let Some(refusal) = typing_preflight(&command) {
        return print_json(&refusal);
    }
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        ConversationAction::Send(send) => send_text(&mut bus, send).await,
        ConversationAction::Reply(text) => mutate(&mut bus, "conversation.reply", text).await,
        ConversationAction::Edit(text) => mutate(&mut bus, "conversation.edit", text).await,
        ConversationAction::React(react) => react_to(&mut bus, react).await,
        ConversationAction::Delete(delete) => delete_message(&mut bus, delete).await,
        ConversationAction::Typing(command) => typing::handle(&mut bus, command).await,
    }
}

fn typing_preflight(command: &ConversationCommand) -> Option<Value> {
    let ConversationAction::Typing(typing_command) = &command.action else {
        return None;
    };
    typing::preflight(typing_command)
}

async fn send_text(bus: &mut LocalBusClient, send: ConversationSend) -> Result<(), RfError> {
    let value = call(
        bus,
        &send.account,
        "conversation.send",
        Some(send.operation_id),
        json!({"conversation_id": send.conversation, "text": send.text}),
    )
    .await?;
    print_json(&value)
}

async fn mutate(
    bus: &mut LocalBusClient,
    method: &str,
    text: ConversationText,
) -> Result<(), RfError> {
    let value = call(
        bus,
        &text.account,
        method,
        Some(text.operation_id),
        json!({
            "conversation_id": text.conversation,
            "message_id": text.message,
            "text": text.text,
        }),
    )
    .await?;
    print_json(&value)
}

async fn react_to(bus: &mut LocalBusClient, react: ConversationReact) -> Result<(), RfError> {
    let value = call(
        bus,
        &react.account,
        "conversation.react",
        Some(react.operation_id),
        json!({
            "conversation_id": react.conversation,
            "message_id": react.message,
            "token": react.token,
            "remove": react.remove,
        }),
    )
    .await?;
    print_json(&value)
}

async fn delete_message(
    bus: &mut LocalBusClient,
    delete: ConversationDelete,
) -> Result<(), RfError> {
    let value = call(
        bus,
        &delete.account,
        "conversation.delete",
        Some(delete.operation_id),
        json!({
            "conversation_id": delete.conversation,
            "message_id": delete.message,
            "scope": delete.scope.as_wire(),
        }),
    )
    .await?;
    print_json(&value)
}

pub(super) async fn call(
    bus: &mut LocalBusClient,
    account: &str,
    method: &str,
    operation_id: Option<String>,
    body: Value,
) -> Result<Value, RfError> {
    let sdk_api = if method.starts_with("conversation.") {
        "conversation"
    } else if method == "bus.subscribe" {
        "stream"
    } else {
        "message"
    };
    let mut frame =
        LocalBusFrame::request(request_id(), Some(account.to_owned()), sdk_api, method, body);
    frame.operation_id = operation_id;
    let response = bus.request_frame_response(frame).await?;
    Ok(output::outcome(method, &response))
}

fn request_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("rf-conv-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}
