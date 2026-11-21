// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent recipient state and a retained ordinary product read connection.
use super::primary_transfer::{Seed, erase, read, send};
use super::{Account, Daemon, Result, rf_json, wait_json};
use ramflux_sdk::LocalBusClient;
use serde_json::{Value, json};

/// The client and its local cursor exist before the recipient generation is replaced.
pub struct Consumer {
    client: LocalBusClient,
    runtime: tokio::runtime::Runtime,
    account: String,
    conversation: String,
    pub cursor: u64,
}

impl Consumer {
    pub fn connect(daemon: &Daemon, account: &Account, conversation: &str) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let client = runtime.block_on(LocalBusClient::connect(&daemon.socket))?;
        let mut consumer = Self {
            client,
            runtime,
            account: account.id.clone(),
            conversation: conversation.into(),
            cursor: 0,
        };
        let initial = consumer.changes()?;
        if initial.get("more").and_then(Value::as_bool) != Some(false) {
            return Err("B seed did not consume a complete initial change batch".into());
        }
        consumer.cursor = initial
            .get("next_after")
            .and_then(Value::as_u64)
            .ok_or("B product reader returned no change cursor")?;
        if consumer.cursor == 0 {
            return Err("B seed must have committed native changes before transfer".into());
        }
        Ok(consumer)
    }

    pub fn changes(&mut self) -> Result<Value> {
        self.request(
            "message",
            "message.read",
            json!({
                "conversation_id": self.conversation, "after_sequence": self.cursor, "limit": 100,
            }),
        )
    }

    pub fn conversations(&mut self) -> Result<Value> {
        self.request("conversation", "conversation.list", json!({}))
    }

    fn request(&mut self, api: &str, method: &str, body: Value) -> Result<Value> {
        let mut frame = ramflux_sdk::LocalBusFrame::request(
            super::unique("transfer-consumer"),
            Some(self.account.clone()),
            api,
            method,
            body,
        );
        let now = u64::try_from(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis(),
        )?;
        frame.deadline_ms = Some(now.checked_add(15_000).ok_or("consumer deadline overflow")?);
        Ok(self.runtime.block_on(self.client.request_frame(frame))?)
    }
}

pub struct Independent {
    pub reverse_erased: String,
    pub authored: String,
    pub mute_until: i64,
    pub consumer: Consumer,
}

impl Independent {
    pub fn populate(
        stack: &super::Stack,
        seed: &Seed,
        target: &Daemon,
        account: &Account,
    ) -> Result<Self> {
        // A already accepted this peer before enrollment. The normal directory
        // courier must backfill that accepted contact to the newly linked B.
        for (daemon, owner, request_state) in
            [(target, account, None), (&seed.peer, &seed.peer_account, Some("accepted"))]
        {
            wait_json(daemon, &["contact", "list", "--account", &owner.id], |value| {
                value.pointer("/contacts/0/state").and_then(Value::as_str) == Some("accepted")
                    && value.pointer("/contacts/0/blocked").and_then(Value::as_bool) == Some(false)
                    && match request_state {
                        Some(expected) => {
                            value.pointer("/contacts/0/request_state").and_then(Value::as_str)
                                == Some(expected)
                        }
                        None => {
                            value.pointer("/contacts/0/request_state").is_some_and(Value::is_null)
                        }
                    }
            })
            .map_err(|error| {
                format!("{error}; {}", super::dump_logs(stack, &[&seed.source, target, &seed.peer]))
            })?;
        }
        let reverse_erased = send(
            &seed.peer,
            &seed.peer_account,
            &seed.conversation,
            "B erases this while A retains it",
        )?;
        read(
            target,
            account,
            &seed.conversation,
            &reverse_erased,
            "B erases this while A retains it",
        )?;
        read(
            &seed.source,
            &seed.account,
            &seed.conversation,
            &reverse_erased,
            "B erases this while A retains it",
        )?;
        erase(target, account, &seed.conversation, &reverse_erased)?;
        // This is the independent restriction that the reverse union must later apply to A.
        read(
            &seed.source,
            &seed.account,
            &seed.conversation,
            &reverse_erased,
            "B erases this while A retains it",
        )?;
        let authored = send(target, account, &seed.conversation, "B independent authored body")?;
        read(
            &seed.peer,
            &seed.peer_account,
            &seed.conversation,
            &authored,
            "B independent authored body",
        )?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let mute_until = i64::try_from(now)?.checked_add(7200).ok_or("seed mute overflow")?;
        let muted = rf_json(
            &target.socket,
            &[
                "dm",
                "mute",
                "--account",
                &account.id,
                "--conversation",
                &seed.conversation,
                "--mute-until",
                &mute_until.to_string(),
            ],
        )?;
        if muted.get("mute_until").and_then(Value::as_i64) != Some(mute_until) {
            return Err("B's independent mute was not committed by the product writer".into());
        }
        let mut consumer = Consumer::connect(target, account, &seed.conversation)?;
        require_mute(&consumer.conversations()?, &seed.conversation, Some(mute_until))?;
        let mut source = Consumer::connect(&seed.source, &seed.account, &seed.conversation)?;
        require_mute(&source.conversations()?, &seed.conversation, None)?;
        Ok(Self { reverse_erased, authored, mute_until, consumer })
    }
}

pub fn require_mute(value: &Value, conversation: &str, expected: Option<i64>) -> Result<()> {
    let row = value
        .get("conversations")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("conversation_id").and_then(Value::as_str) == Some(conversation)
            })
        })
        .ok_or("conversation missing from the ordinary product list")?;
    let expected = expected.map(|deadline| deadline.to_string());
    let matches = match expected.as_deref() {
        Some(deadline) => row.get("mute_until").and_then(Value::as_str) == Some(deadline),
        None => row.get("mute_until").is_some_and(Value::is_null),
    };
    if !matches {
        return Err("ordinary conversation reader lost independent mute state".into());
    }
    Ok(())
}

/// Ask the actual current primary to transfer to B's certified existing branch.
pub fn begin_transfer(stack: &super::Stack, seed: &Seed, target: &Account) -> Result<Value> {
    let roster = rf_json(&seed.source.socket, &["device", "list", "--account", &seed.account.id])?;
    let destination = roster
        .get("devices")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("device_id").and_then(Value::as_str) == Some(target.device_id.as_str())
            })
        })
        .ok_or("current primary roster does not certify B")?;
    let epoch = destination
        .get("device_epoch")
        .and_then(Value::as_u64)
        .ok_or("certified destination epoch missing")?
        .to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let expiry = now.checked_add(604_800).ok_or("seed branch lease overflow")?;
    let invitation = stack.root.join("primary-transfer.invitation");
    let begun = rf_json(
        &seed.source.socket,
        &[
            "transfer",
            "--account",
            &seed.account.id,
            "begin",
            "--display-name",
            "New primary",
            "--lease-not-before",
            &now.to_string(),
            "--lease-expires-at",
            &expiry.to_string(),
            "--destination-device",
            &target.device_id,
            "--destination-epoch",
            &epoch,
            "--account-anchor",
            &seed.account.principal_commitment,
            "--invitation-out",
            invitation.to_str().ok_or("full invitation path")?,
        ],
    )?;
    if begun.get("operation_id").and_then(Value::as_str).is_none() || !invitation.is_file() {
        return Err("populated source did not produce a full-transfer invitation".into());
    }
    Ok(begun)
}
