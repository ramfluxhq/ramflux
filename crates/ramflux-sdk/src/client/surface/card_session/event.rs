// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One host event. A submit is signed here and sent only by card.session.submit.
use super::body::{self, MAX_BODY};
use super::gate::card_err;
use super::guard::{Kept, keep};
use super::host_view;
use super::respond::{self, Shown, shown, stale};
use super::sign;
use super::store;
use crate::{RamfluxClient, SdkError};
use ramflux_card::{EventResult, EventToken, HostEvent, HostEventKind, MutationBatch, SlotRequest};
use ramflux_protocol::SurfaceState;
use ramflux_protocol::a2ui::validate_url;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventBody {
    session: u64,
    token: EventToken,
    event: HostEventKind,
}

pub(super) fn apply(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let parsed: EventBody = body::parse(body, MAX_BODY)?;
    match keep(client, account, parsed.session)? {
        Kept::Stopped(value) => Ok(value),
        Kept::Ready { stored, state, fallback } => deliver(
            &Drive {
                client,
                account,
                session: parsed.session,
                author: &stored.author_principal_id,
                state: &state,
                fallback: &fallback,
            },
            HostEvent { token: parsed.token, event: parsed.event },
        ),
    }
}

struct Drive<'a> {
    client: &'a RamfluxClient,
    account: &'a str,
    session: u64,
    author: &'a str,
    state: &'a SurfaceState,
    fallback: &'a str,
}

fn deliver(drive: &Drive<'_>, event: HostEvent) -> Result<Value, SdkError> {
    let account = drive.account;
    let session = drive.session;
    store::with_session(account, session, |held| {
        if let Some(block) =
            host_view::seal_if_blocked(drive.client, held, drive.state, drive.fallback)?
        {
            let batch = mounted_batch(held)?;
            return Ok(respond::stopped(
                drive.session,
                drive.fallback,
                block.status,
                block.reason,
                block.replacement_ref.as_deref(),
                batch,
            ));
        }
        if !held.matches(drive.state) {
            return Ok(stale(drive.session, drive.fallback));
        }
        held.session().enqueue(event).map_err(card_err)?;
        match held.session().next_event().map_err(card_err)? {
            None => Err(super::super::invalid("card_session_inactive")),
            Some(EventResult::StaleDropped) => Ok(stale(drive.session, drive.fallback)),
            Some(EventResult::Refused { reason }) => {
                let replacement =
                    held.session().tree().and_then(|tree| tree.replacement_ref.clone());
                let status = if reason == "card_superseded" { "superseded" } else { "refused" };
                let batch = mounted_batch(held)?;
                Ok(respond::stopped(
                    drive.session,
                    drive.fallback,
                    status,
                    reason,
                    replacement.as_deref(),
                    batch,
                ))
            }
            Some(EventResult::Validation { batch }) => {
                edited(drive.session, drive.fallback, "validation", &batch, None)
            }
            Some(EventResult::Edited { batch }) => {
                let host_request = link_request(&batch)?;
                let result = if host_request.is_some() { "open_url" } else { "edited" };
                edited(drive.session, drive.fallback, result, &batch, host_request)
            }
            Some(EventResult::Submit { action, batch }) => {
                submit_result(drive, held, &action, &batch)
            }
        }
    })
}

fn mounted_batch(held: &store::Held) -> Result<Option<Value>, SdkError> {
    match held.session_ref().shown_batch() {
        Ok(batch) => Ok(Some(respond::batch_value(&batch)?)),
        Err(ramflux_card::CardError::Inactive) => Ok(None),
        Err(error) => Err(card_err(error)),
    }
}

fn edited(
    session: u64,
    fallback: &str,
    result: &str,
    batch: &MutationBatch,
    host_request: Option<Value>,
) -> Result<Value, SdkError> {
    Ok(shown(Shown {
        result,
        session,
        fallback,
        batch: Some(respond::batch_value(batch)?),
        host_request,
        submit: None,
        draft_conflict: false,
        action_outcome: None,
    }))
}

fn submit_result(
    drive: &Drive<'_>,
    held: &mut store::Held,
    action: &ramflux_protocol::a2ui::ResolvedAction,
    batch: &MutationBatch,
) -> Result<Value, SdkError> {
    let session = held.session().id();
    let resolved = held.session().resolved().map_err(card_err)?;
    let batch_value = respond::batch_value(batch)?;
    match sign::sign_action(drive.client, drive.state, drive.author, &resolved, action) {
        Ok(pending) => {
            let submit = json!({
                "message_id": pending.message_id,
                "surface_version": pending.surface_version,
                "surface_hash": pending.surface_hash,
            });
            held.set_pending(Some(pending));
            Ok(shown(Shown {
                result: "pending_submit",
                session,
                fallback: drive.fallback,
                batch: Some(batch_value),
                host_request: None,
                submit: Some(submit),
                draft_conflict: false,
                action_outcome: None,
            }))
        }
        Err(error) => {
            let reason = error_reason(&error);
            Ok(respond::view(respond::View {
                result: "refused",
                allowed: true,
                session: Some(session),
                fallback: drive.fallback,
                reason: Some(reason),
                batch: Some(batch_value),
                host_request: None,
                submit: None,
                draft_conflict: false,
                action_outcome: Some(respond::action_outcome("refused", Some(reason), None)),
            }))
        }
    }
}

fn error_reason(error: &SdkError) -> &'static str {
    match error {
        SdkError::SurfaceProtocol(
            ramflux_protocol::Reject::Conflict
            | ramflux_protocol::Reject::Version { .. }
            | ramflux_protocol::Reject::Closed,
        )
        | SdkError::SurfaceRefused {
            reason:
                crate::SurfaceRefusalCode::StaleVersion
                | crate::SurfaceRefusalCode::StaleHash
                | crate::SurfaceRefusalCode::Closed,
            ..
        } => "card_session_stale",
        _ => "card_session_refused",
    }
}

fn link_request(batch: &MutationBatch) -> Result<Option<Value>, SdkError> {
    for slot in &batch.host_slots {
        let SlotRequest::LinkOpen { request_id, url } = &slot.request else {
            continue;
        };
        let url = validate_url(url).map_err(card_err)?;
        return Ok(Some(json!({
            "kind": "open_url",
            "request_id": request_id,
            "url": url,
            "slot_id": slot.id,
            "token": slot.token,
        })));
    }
    Ok(None)
}
