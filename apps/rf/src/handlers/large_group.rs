// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::cli::large_group::{
    DebugAction, DebugCommand, DebugKatAction, DebugLgAction, LargeAction, LargeCommand,
};
use serde_json::json;

pub(crate) async fn handle_large(socket: PathBuf, command: LargeCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    let (account, method, body) = match command.action {
        LargeAction::Create(a) => (
            a.account,
            "group.large.create",
            json!({"approval_on": a.approval != "off", "host": a.host}),
        ),
        LargeAction::Invite(a) => (
            a.account,
            "group.large.invite",
            json!({"group_id": a.group, "max_uses": a.max_uses, "ttl_ms": a.ttl_ms}),
        ),
        LargeAction::Join(a) => (a.account, "group.large.join", json!({"link": a.link})),
        LargeAction::Ratchet(a) => (a.account, "group.large.ratchet", json!({"group_id": a.group})),
        LargeAction::Tokens(a) => {
            (a.account, "group.large.tokens", json!({"group_id": a.group, "force": a.force}))
        }
        LargeAction::Post(a) => {
            (a.account, "group.large.post", json!({"group_id": a.group, "text": a.text}))
        }
        LargeAction::Read(a) => {
            (a.account, "group.large.read", json!({"group_id": a.group, "limit": a.limit}))
        }
        LargeAction::Status(a) => (a.account, "group.large.status", json!({"group_id": a.group})),
        LargeAction::Admin(a) => (
            a.account,
            "group.large.admin",
            json!({"group_id": a.group, "action": a.action, "target": a.target}),
        ),
    };
    let value = request_body(&mut bus, Some(account), "group", method, body).await?;
    print_json(&value)
}

pub(crate) async fn handle_debug(socket: PathBuf, command: DebugCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    let (account, method, body) = match command.action {
        DebugAction::Kat(kat) => match kat.action {
            DebugKatAction::Poprf => (None, "debug.lg.kat_poprf", json!({})),
        },
        DebugAction::Lg(lg) => match lg.action {
            DebugLgAction::Clock(a) => (
                Some(a.account),
                "debug.lg.clock",
                json!({"client_offset_ms": a.client_offset_ms, "host_offset_ms": a.host_offset_ms}),
            ),
            DebugLgAction::Fault(a) => (
                Some(a.account),
                "debug.lg.fault",
                json!({
                    "group_id": a.group, "kind": a.kind, "reason": a.reason,
                    "from_seq": a.from_seq, "ms": a.ms, "n": a.n, "p": a.p, "except": a.except,
                }),
            ),
            DebugLgAction::BulkJoin(a) => {
                (Some(a.account), "debug.lg.bulk_join", json!({"link": a.link, "count": a.count}))
            }
        },
    };
    let value = request_body(&mut bus, account, "debug", method, body).await?;
    print_json(&value)
}
