// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reproducible native-account seed using only ordinary CLI writes and reads.
use super::{
    Account, Daemon, Result, Stack, configure_node, create_account, exchange_contacts, rf_json,
    unique, wait_json,
};
use serde_json::Value;

pub struct Seed {
    pub source: Daemon,
    pub peer: Daemon,
    pub account: Account,
    pub peer_account: Account,
    pub conversation: String,
    pub authored: String,
    pub received: String,
    pub erased: String,
    pub original_views: [Value; 2],
    pub recovery_phrase: zeroize::Zeroizing<String>,
}

impl Seed {
    /// Background SDK couriers deliver every message; this helper never flushes them.
    pub fn create(stack: &Stack) -> Result<Self> {
        let source = super::primary_transfer_pairing::start_device(stack, "transfer-source")?;
        let peer = super::primary_transfer_pairing::start_device(stack, "transfer-peer")?;
        configure_node(&source, &stack.discovery_url)?;
        configure_node(&peer, &stack.discovery_url)?;
        let (account, recovery_phrase) = super::primary_transfer_pairing::create_source(&source)?;
        let peer_account = create_account(&peer, "Transfer contact")?;
        exchange_contacts(&source, &account, &peer, &peer_account)?;
        for (daemon, owner) in [(&source, &account), (&peer, &peer_account)] {
            wait_json(daemon, &["contact", "list", "--account", &owner.id], |value| {
                value.pointer("/contacts/0/request_state").and_then(Value::as_str)
                    == Some("accepted")
            })?;
        }
        let conversation = ramflux_protocol::message::dm_scope::derive(
            &account.principal_commitment,
            &peer_account.principal_commitment,
        )?;
        let authored = send(&source, &account, &conversation, "transfer own native body")?;
        read(&peer, &peer_account, &conversation, &authored, "transfer own native body")?;
        let received = send(&peer, &peer_account, &conversation, "transfer peer native body")?;
        read(&source, &account, &conversation, &received, "transfer peer native body")?;
        let erased = send(&peer, &peer_account, &conversation, "transfer erased native body")?;
        read(&source, &account, &conversation, &erased, "transfer erased native body")?;
        erase(&source, &account, &conversation, &erased)?;
        // The peer's independently retained local content must survive a local erasure.
        read(&peer, &peer_account, &conversation, &erased, "transfer erased native body")?;
        let own = read(&source, &account, &conversation, &authored, "transfer own native body")?;
        let incoming =
            read(&source, &account, &conversation, &received, "transfer peer native body")?;
        for (view, expected, is_own) in [(&own, &account, true), (&incoming, &peer_account, false)]
        {
            if view.pointer("/message/is_own").and_then(Value::as_bool) != Some(is_own)
                || view.pointer("/message/author/account_anchor").and_then(Value::as_str)
                    != Some(expected.principal_commitment.as_str())
                || view.pointer("/message/author/device_id").and_then(Value::as_str)
                    != Some(expected.device_id.as_str())
            {
                return Err("seed lost original native authorship before transfer".into());
            }
        }
        Ok(Self {
            source,
            peer,
            account,
            peer_account,
            conversation,
            authored,
            received,
            erased,
            original_views: [own, incoming],
            recovery_phrase,
        })
    }
}

pub fn send(daemon: &Daemon, account: &Account, conversation: &str, text: &str) -> Result<String> {
    let operation = unique("transfer-send");
    let sent = wait_json(
        daemon,
        &[
            "conversation",
            "send",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--text",
            text,
            "--operation-id",
            &operation,
        ],
        |value| value.pointer("/body/delivery_state").and_then(Value::as_str) == Some("submitted"),
    )?;
    sent.pointer("/body/message_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "native send returned no message id".into())
}

pub fn read(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    message: &str,
    text: &str,
) -> Result<Value> {
    let value = wait_json(
        daemon,
        &[
            "dm",
            "list",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--message",
            message,
        ],
        |value| value.pointer("/message/text").and_then(Value::as_str) == Some(text),
    )?;
    if value["schema"] != "ramflux.message.read_model.v1"
        || value.pointer("/message/state").and_then(Value::as_str) != Some("content")
    {
        return Err("native seed did not use the durable product read model".into());
    }
    Ok(value)
}

/// Observe automatic receipt delivery through the same durable product reader.
pub fn delivered(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    message: &str,
    receiver: &Account,
) -> Result<Value> {
    wait_json(
        daemon,
        &[
            "dm",
            "list",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--message",
            message,
        ],
        |value| {
            value.pointer("/message/receipts").and_then(Value::as_array).is_some_and(|receipts| {
                receipts.iter().any(|receipt| {
                    receipt.get("device_id").and_then(Value::as_str)
                        == Some(receiver.device_id.as_str())
                        && receipt.get("principal_commitment").and_then(Value::as_str)
                            == Some(receiver.principal_commitment.as_str())
                        && receipt.get("state").and_then(Value::as_str) == Some("delivered")
                        && receipt.get("delivered_at").and_then(Value::as_i64).is_some()
                })
            })
        },
    )
}

pub fn erase(daemon: &Daemon, account: &Account, conversation: &str, message: &str) -> Result<()> {
    rf_json(
        &daemon.socket,
        &[
            "conversation",
            "delete",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--message",
            message,
            "--scope",
            "local",
            "--operation-id",
            &unique("transfer-erase"),
        ],
    )?;
    wait_json(
        daemon,
        &[
            "dm",
            "list",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--message",
            message,
        ],
        |value| value.pointer("/message/state").and_then(Value::as_str) == Some("tombstone"),
    )?;
    Ok(())
}
