// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Send the carrier signed by the event. A failed send keeps the same message id.
use super::body::{self, SessionBody};
use super::guard::{Kept, keep};
use super::host_view;
use super::respond::{self, stale};
use super::store;
use super::{SubmitPrep, submitted};
use crate::{RamfluxClient, SdkError, SurfaceRefusalCode};
use ramflux_protocol::SurfaceState;
use serde_json::Value;

use super::super::Outcome;

pub(super) fn admit_send(
    client: &RamfluxClient,
    account: &str,
    session: u64,
    version: u64,
    hash: &str,
) -> Result<Option<Value>, SdkError> {
    match keep(client, account, session)? {
        Kept::Stopped(value) => Ok(Some(value)),
        Kept::Ready { state, fallback, .. } => {
            if let Some(value) = blocked(client, account, session, &state, &fallback)? {
                return Ok(Some(value));
            }
            if state.version() == version && state.hash() == Some(hash) {
                return Ok(None);
            }
            let _ = store::with_session(account, session, |held| {
                held.set_pending(None);
                Ok(())
            });
            Ok(Some(stale(session, &fallback)))
        }
    }
}

pub(super) fn prepare(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<SubmitPrep, SdkError> {
    let parsed: SessionBody = body::parse(body, body::MAX_BODY)?;
    match keep(client, account, parsed.session)? {
        Kept::Stopped(value) => Ok(SubmitPrep::Done(value)),
        Kept::Ready { state, fallback, .. } => {
            take(client, account, parsed.session, &state, &fallback)
        }
    }
}

fn take(
    client: &RamfluxClient,
    account: &str,
    session: u64,
    state: &SurfaceState,
    fallback: &str,
) -> Result<SubmitPrep, SdkError> {
    if let Some(value) = blocked(client, account, session, state, fallback)? {
        return Ok(SubmitPrep::Done(value));
    }
    let pending = store::with_session(account, session, |held| {
        if !held.matches(state) {
            held.set_pending(None);
            return Ok(None);
        }
        Ok(held.pending().cloned())
    })?;
    let Some(pending) = pending else {
        return if store::with_session(account, session, |held| Ok(held.matches(state)))? {
            Err(super::super::invalid("card_session_inactive"))
        } else {
            Ok(SubmitPrep::Done(stale(session, fallback)))
        };
    };
    if client.surface_outgoing_submitted(&pending.carrier)? {
        store::clear_pending(account, session, &pending.message_id)?;
        return Ok(SubmitPrep::Done(submitted(
            session,
            &pending.message_id,
            pending.surface_version,
            &pending.surface_hash,
            fallback,
        )));
    }
    let preflight = client.preflight_surface(&pending.carrier)?;
    if !preflight.accepted {
        store::with_session(account, session, |held| {
            held.set_pending(None);
            Ok(())
        })?;
        let reason = refusal_token(&preflight);
        return Ok(SubmitPrep::Done(respond::stopped(
            session,
            &preflight.fallback_text,
            "refused",
            reason,
            None,
            None,
        )));
    }
    Ok(SubmitPrep::Send {
        session,
        message_id: pending.message_id,
        carrier: Box::new(pending.carrier),
        surface_version: pending.surface_version,
        surface_hash: pending.surface_hash,
        fallback: fallback.to_owned(),
    })
}

fn blocked(
    client: &RamfluxClient,
    account: &str,
    session: u64,
    state: &SurfaceState,
    fallback: &str,
) -> Result<Option<Value>, SdkError> {
    let blocked = store::with_session(account, session, |held| {
        host_view::seal_if_blocked(client, held, state, fallback)
    })?;
    let Some(block) = blocked else {
        return Ok(None);
    };
    host_view::forget_pending(account, session)?;
    let batch = store::with_session(account, session, |held| mounted(held))?;
    Ok(Some(respond::stopped(
        session,
        fallback,
        block.status,
        block.reason,
        block.replacement_ref.as_deref(),
        batch,
    )))
}

fn mounted(held: &store::Held) -> Result<Option<Value>, SdkError> {
    match held.session_ref().shown_batch() {
        Ok(batch) => Ok(Some(respond::batch_value(&batch)?)),
        Err(ramflux_card::CardError::Inactive) => Ok(None),
        Err(error) => Err(super::gate::card_err(error)),
    }
}

fn refusal_token(outcome: &Outcome) -> &'static str {
    match outcome.reason_code {
        Some(
            SurfaceRefusalCode::StaleVersion
            | SurfaceRefusalCode::StaleHash
            | SurfaceRefusalCode::Closed,
        ) => "card_session_stale",
        _ => "card_session_refused",
    }
}
