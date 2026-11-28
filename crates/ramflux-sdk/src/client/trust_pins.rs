// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact trust pins and the identity-change gate on a send operation.
//!
//! A pin is `{previous_anchor, pending_anchor, username, changed_at, ai_flag}`.
//! `contact` is the account root commitment. The same operation id replays
//! `identity_change_pending` and does not send. Accepting the change never sends;
//! the client must use a new operation id.

use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Actor-state prefix of a pin, keyed by the anchor the conversation still names.
pub(crate) const PIN_PREFIX: &str = "contact-trust-pin/";
/// Username index: `contact-trust-name/<name>` stores the anchor the pin is under.
const NAME_PREFIX: &str = "contact-trust-name/";
/// Terminal identity refusals. Not part of the send journal, so this store prunes itself.
pub(crate) const TERMINAL_PREFIX: &str = "conversation-send-terminal/";
/// Same cap as `conversation_journal::LIMIT`.
pub(crate) const TERMINAL_LIMIT: u32 = 1024;

/// What [`send_gate`] tells the send path to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendGate {
    /// No pending change for this operation. Send.
    Proceed,
    /// A pending change, and this operation has not been refused before. Do not send.
    Refuse,
    /// This operation id was already refused. Replay `identity_change_pending`. Do not send.
    Replay,
}

/// `verified` when the contact is verified and stable, `tofu` on first sight, `changed` while a
/// new anchor is pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityState {
    Verified,
    Tofu,
    Changed,
}

impl IdentityState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Tofu => "tofu",
            Self::Changed => "changed",
        }
    }
}

/// One contact's pin. `pending_anchor` is set only while the user has not accepted the change.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PinRow {
    pub previous_anchor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_anchor: Option<String>,
    pub username: String,
    pub changed_at: u64,
    #[serde(default)]
    pub ai_flag: bool,
    /// Far future so actor-state expiry does not drop a live pin.
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TerminalRow {
    contact: String,
    expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NameIndex {
    anchor: String,
    expires_at: i64,
}

fn far_expiry() -> i64 {
    i64::MAX / 4
}

fn pin_key(anchor: &str) -> String {
    format!("{PIN_PREFIX}{anchor}")
}

fn name_key(username: &str) -> String {
    format!("{NAME_PREFIX}{username}")
}

pub(crate) fn terminal_key(operation: &str) -> String {
    format!(
        "{TERMINAL_PREFIX}{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.conversation.send.terminal.v1",
            operation.as_bytes(),
        )
    )
}

/// Decide a send from the pin and whether this operation id was already refused.
pub(crate) fn send_gate(pin: Option<&PinRow>, same_op_stored: bool) -> SendGate {
    if same_op_stored {
        return SendGate::Replay;
    }
    match pin {
        Some(pin) if pin.pending_anchor.is_some() => SendGate::Refuse,
        _ => SendGate::Proceed,
    }
}

pub(crate) fn identity_state(pin: Option<&PinRow>, verified: bool) -> IdentityState {
    if pin.is_some_and(|pin| pin.pending_anchor.is_some()) {
        IdentityState::Changed
    } else if verified {
        IdentityState::Verified
    } else {
        IdentityState::Tofu
    }
}

pub(crate) fn identity_state_name(pin: Option<&PinRow>, verified: bool) -> &'static str {
    identity_state(pin, verified).as_str()
}

pub(crate) fn load_pin(client: &RamfluxClient, anchor: &str) -> Result<Option<PinRow>, SdkError> {
    Ok(client.account_db()?.load_actor_state(&pin_key(anchor))?)
}

pub(crate) fn load_pin_by_username(
    client: &RamfluxClient,
    username: &str,
) -> Result<Option<PinRow>, SdkError> {
    let Some(index) = client.account_db()?.load_actor_state::<NameIndex>(&name_key(username))?
    else {
        return Ok(None);
    };
    load_pin(client, &index.anchor)
}

fn save_pin(client: &RamfluxClient, pin: &PinRow) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.persist_actor_state(&pin_key(&pin.previous_anchor), pin)?;
    db.persist_actor_state(
        &name_key(&pin.username),
        &NameIndex { anchor: pin.previous_anchor.clone(), expires_at: far_expiry() },
    )?;
    Ok(())
}

/// `@username` lookup returned `anchor`. A different anchor than the pin sets `pending_anchor`
/// and is the only path that emits `contact.identity_changed`.
pub(crate) fn note_lookup(
    client: &RamfluxClient,
    username: &str,
    anchor: &str,
    ai_flag: bool,
    now: u64,
) -> Result<Option<Value>, SdkError> {
    if username.is_empty() || anchor.is_empty() {
        return Ok(None);
    }
    let Some(mut pin) = load_pin_by_username(client, username)? else {
        save_pin(
            client,
            &PinRow {
                previous_anchor: anchor.to_owned(),
                pending_anchor: None,
                username: username.to_owned(),
                changed_at: now,
                ai_flag,
                expires_at: far_expiry(),
            },
        )?;
        return Ok(None);
    };
    if pin.pending_anchor.as_deref() == Some(anchor) || pin.previous_anchor == anchor {
        return Ok(None);
    }
    pin.pending_anchor = Some(anchor.to_owned());
    pin.changed_at = now;
    pin.ai_flag = ai_flag;
    save_pin(client, &pin)?;
    Ok(Some(json!({
        "contact": pin.previous_anchor,
        "username": pin.username,
        "previous_anchor": pin.previous_anchor,
        "pending_anchor": anchor,
        "ai_flag": pin.ai_flag,
        "changed_at": now,
    })))
}

/// Accept `pending_anchor` for `contact`. Does not send. A mismatch or a missing pin is refused.
pub(crate) fn accept_change(
    client: &RamfluxClient,
    contact: &str,
    pending_anchor: &str,
    now: u64,
) -> Result<PinRow, SdkError> {
    let Some(mut pin) = load_pin(client, contact)? else {
        return Err(refused("no_pending_change", "no identity change is pending", json!({})));
    };
    if pin.pending_anchor.as_deref() != Some(pending_anchor) {
        let code =
            if pin.pending_anchor.is_none() { "no_pending_change" } else { "anchor_mismatch" };
        return Err(refused(
            code,
            "the pending anchor does not match",
            json!({ "contact": contact }),
        ));
    }
    let accepted = PinRow {
        previous_anchor: pending_anchor.to_owned(),
        pending_anchor: None,
        username: pin.username.clone(),
        changed_at: now,
        ai_flag: pin.ai_flag,
        expires_at: far_expiry(),
    };
    pin.pending_anchor = None;
    save_pin(client, &pin)?;
    save_pin(client, &accepted)?;
    Ok(accepted)
}

/// UTF-8 JSON sealed into the self group after accept. Hidden from DM history.
pub(crate) fn pin_sync_json(
    pin: &PinRow,
    contact: &str,
    pending_anchor: &str,
) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(&json!({
        "contact": contact,
        "previous_anchor": pin.previous_anchor,
        "pending_anchor": pending_anchor,
        "username": pin.username,
        "changed_at": pin.changed_at,
        "accepted": true,
    }))?)
}

pub(crate) fn terminal_stored(client: &RamfluxClient, operation: &str) -> Result<bool, SdkError> {
    Ok(client.account_db()?.load_actor_state::<TerminalRow>(&terminal_key(operation))?.is_some())
}

/// Remember that `operation` was refused for `contact`. The 1025th live row is `rate_limited`.
pub(crate) fn store_terminal(
    client: &RamfluxClient,
    operation: &str,
    contact: &str,
    now: i64,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.expire_actor_states(TERMINAL_PREFIX, now)?;
    let key = terminal_key(operation);
    if db.load_actor_state::<TerminalRow>(&key)?.is_some() {
        return Ok(());
    }
    if db.actor_state_usage(TERMINAL_PREFIX)?.0 >= u64::from(TERMINAL_LIMIT) {
        return Err(refused("rate_limited", "identity refusal retention is full", json!({})));
    }
    let expires_at = now.saturating_add(i64::from(client.content_ttl()?));
    db.persist_actor_state(&key, &TerminalRow { contact: contact.to_owned(), expires_at })?;
    Ok(())
}

pub(crate) fn changed_fields(pin: &PinRow) -> Value {
    json!({
        "username": pin.username,
        "previous_anchor": pin.previous_anchor,
        "pending_anchor": pin.pending_anchor,
        "changed_at": pin.changed_at,
    })
}

/// `identity_change_pending` for `contact`. The same shape as every other pin refusal.
pub(crate) fn identity_pending(contact: &str) -> SdkError {
    refused(
        "identity_change_pending",
        "an identity change is pending for this contact",
        json!({ "contact": contact }),
    )
}

/// Write `identity_state` onto a contact JSON object. A pending pin also adds the changed fields.
pub(crate) fn apply_identity(
    entry: &mut Value,
    client: &RamfluxClient,
    anchor: Option<&str>,
    verified: bool,
) -> Result<(), SdkError> {
    let pin = match anchor {
        Some(anchor) if !anchor.is_empty() => load_pin(client, anchor)?,
        _ => None,
    };
    let Some(object) = entry.as_object_mut() else {
        return Ok(());
    };
    object.insert("identity_state".into(), json!(identity_state_name(pin.as_ref(), verified)));
    if let Some(pin) = pin.as_ref().filter(|pin| pin.pending_anchor.is_some())
        && let Some(fields) = changed_fields(pin).as_object()
    {
        for (key, value) in fields {
            object.insert(key.clone(), value.clone());
        }
    }
    Ok(())
}

fn refused(code: &str, message: &str, mut details: Value) -> SdkError {
    if details.is_null() {
        details = json!({});
    }
    SdkError::LocalBusRefused {
        code: code.to_owned(),
        message: message.to_owned(),
        body: Box::new(json!({ "reason_code": code, "details": details })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(pending: bool) -> PinRow {
        PinRow {
            previous_anchor: "anchor-old".into(),
            pending_anchor: pending.then(|| "anchor-new".into()),
            username: "ada".into(),
            changed_at: 10,
            ai_flag: false,
            expires_at: far_expiry(),
        }
    }

    #[test]
    fn send_gate_replays_the_stored_op_and_refuses_a_new_one() {
        assert_eq!(send_gate(Some(&pin(true)), true), SendGate::Replay, "the same op id replays");
        assert_eq!(
            send_gate(Some(&pin(true)), false),
            SendGate::Refuse,
            "a new op id still refuses until accept"
        );
        assert_eq!(send_gate(Some(&pin(false)), false), SendGate::Proceed, "accept clears the pin");
        assert_eq!(send_gate(None, false), SendGate::Proceed, "no pin proceeds");
        assert_eq!(
            send_gate(Some(&pin(false)), true),
            SendGate::Replay,
            "the stored op stays a replay after accept"
        );
    }
}
