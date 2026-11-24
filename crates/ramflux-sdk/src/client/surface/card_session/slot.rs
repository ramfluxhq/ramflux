// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host slot replies. Link completion is local. Approval ids come from task state.
use super::approval::{self, Hint};
use super::body::{self, MAX_BODY};
use super::gate::card_err;
use super::guard::{Kept, keep};
use super::respond::{self, Shown, shown, stale};
use super::store;
use crate::{RamfluxClient, SdkError};
use ramflux_card::{EventResult, EventToken, HostSlotReply, SlotOutcome, SlotRequest};
use ramflux_protocol::SurfaceState;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotBody {
    session: u64,
    token: EventToken,
    slot_id: String,
    request_id: String,
    outcome: SlotOutcome,
}

pub(super) fn apply(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let parsed: SlotBody = body::parse(body, MAX_BODY)?;
    let reply = HostSlotReply {
        token: parsed.token,
        slot_id: parsed.slot_id,
        request_id: parsed.request_id,
        outcome: parsed.outcome,
    };
    match keep(client, account, parsed.session)? {
        Kept::Stopped(value) => Ok(value),
        Kept::Ready { stored, state, fallback } => {
            store::with_session(account, parsed.session, |held| {
                let mut sheet = Sheet {
                    client,
                    held,
                    session: parsed.session,
                    state: &state,
                    fallback: &fallback,
                    author: &stored.author_principal_id,
                };
                finish(&mut sheet, &reply)
            })
        }
    }
}

struct Sheet<'a> {
    client: &'a RamfluxClient,
    held: &'a mut store::Held,
    session: u64,
    state: &'a SurfaceState,
    fallback: &'a str,
    author: &'a str,
}

fn finish(sheet: &mut Sheet<'_>, reply: &HostSlotReply) -> Result<Value, SdkError> {
    if !sheet.held.matches(sheet.state) {
        return Ok(stale(sheet.session, sheet.fallback));
    }
    match slot_kind(sheet.held, reply)? {
        Kind::Link => finish_link(sheet.held, sheet.session, sheet.fallback, reply),
        Kind::Approval { request_ref, task_binding } => {
            decide(sheet, reply, &request_ref, task_binding.as_ref())
        }
        Kind::Image => Err(super::super::invalid("card_session_image_native")),
        Kind::Modal => Err(super::super::invalid("card_session_refused")),
    }
}

fn decide(
    sheet: &mut Sheet<'_>,
    reply: &HostSlotReply,
    hint_ref: &str,
    hint_task: Option<&ramflux_protocol::a2ui::TaskBinding>,
) -> Result<Value, SdkError> {
    if reply.token.signed_version != sheet.state.version() {
        return Ok(stale(sheet.session, sheet.fallback));
    }
    let Some(conversation) = sheet.state.conversation_id() else {
        return Ok(refused(sheet));
    };
    let found = approval::lookup(
        sheet.client,
        &Hint { author: sheet.author, conversation, request_ref: hint_ref, task: hint_task },
    )?;
    let Some(found) = found else {
        return Ok(refused(sheet));
    };
    let fence = format!(
        "{}:{}:{}",
        reply.token.signed_version, reply.token.edit_seq, reply.token.tree_version
    );
    if !sheet.held.consume_binding(&found.request_ref, &reply.slot_id, &fence) {
        return Ok(stale(sheet.session, sheet.fallback));
    }
    Ok(shown(Shown {
        result: "approval_decision",
        session: sheet.session,
        fallback: sheet.fallback,
        batch: None,
        host_request: Some(json!({
            "kind": "approval_decision",
            "outcome": &reply.outcome,
            "request_ref": found.request_ref,
            "task_binding": found.task_binding,
        })),
        submit: None,
        draft_conflict: false,
        action_outcome: None,
    }))
}

fn refused(sheet: &Sheet<'_>) -> Value {
    respond::view(respond::View {
        result: "refused",
        allowed: true,
        session: Some(sheet.session),
        fallback: sheet.fallback,
        reason: Some("card_session_refused"),
        batch: None,
        host_request: None,
        submit: None,
        draft_conflict: false,
        action_outcome: None,
    })
}

enum Kind {
    Link,
    Approval { request_ref: String, task_binding: Option<ramflux_protocol::a2ui::TaskBinding> },
    Image,
    Modal,
}

fn slot_kind(held: &store::Held, reply: &HostSlotReply) -> Result<Kind, SdkError> {
    let request = held
        .session_ref()
        .tree()
        .and_then(|tree| {
            tree.host_slots
                .iter()
                .find(|slot| slot.id == reply.slot_id && slot.token == reply.token)
        })
        .map(|slot| slot.request.clone())
        .ok_or_else(|| super::super::invalid("card_session_stale"))?;
    let matches_request = match &request {
        SlotRequest::LinkOpen { request_id, .. }
        | SlotRequest::Image { request_id, .. }
        | SlotRequest::Approval { request_id, .. } => request_id == &reply.request_id,
        SlotRequest::Modal { .. } => true,
    };
    if !matches_request {
        return Err(super::super::invalid("card_session_stale"));
    }
    Ok(match request {
        SlotRequest::LinkOpen { .. } => Kind::Link,
        SlotRequest::Image { .. } => Kind::Image,
        SlotRequest::Modal { .. } => Kind::Modal,
        SlotRequest::Approval { request_ref, task_binding, .. } => {
            Kind::Approval { request_ref, task_binding }
        }
    })
}

fn finish_link(
    held: &mut store::Held,
    session: u64,
    fallback: &str,
    reply: &HostSlotReply,
) -> Result<Value, SdkError> {
    let result = match &reply.outcome {
        SlotOutcome::Confirm => "opened",
        SlotOutcome::Cancel => "cancelled",
        SlotOutcome::Unavailable => "unavailable",
        SlotOutcome::Deny => return Err(super::super::invalid("card_session_refused")),
    };
    match held.session().complete_link(reply).map_err(card_err)? {
        EventResult::StaleDropped => Ok(stale(session, fallback)),
        EventResult::Refused { reason } => Ok(respond::view(respond::View {
            result: "refused",
            allowed: true,
            session: Some(session),
            fallback,
            reason: Some(reason),
            batch: None,
            host_request: None,
            submit: None,
            draft_conflict: false,
            action_outcome: Some(respond::action_outcome(
                if reason == "card_superseded" { "superseded" } else { "refused" },
                Some(reason),
                None,
            )),
        })),
        EventResult::Edited { batch } => Ok(shown(Shown {
            result,
            session,
            fallback,
            batch: Some(respond::batch_value(&batch)?),
            host_request: None,
            submit: None,
            draft_conflict: false,
            action_outcome: None,
        })),
        EventResult::Validation { .. } | EventResult::Submit { .. } => {
            Err(super::super::invalid("card_session_refused"))
        }
    }
}
