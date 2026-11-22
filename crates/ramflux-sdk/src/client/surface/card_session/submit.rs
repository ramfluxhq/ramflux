// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Send the carrier signed by the event. A failed send keeps the same message id.
use super::body::{self, SessionBody};
use super::guard::{Kept, keep};
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
        return Ok(SubmitPrep::Done(respond::refused(
            refusal_token(&preflight),
            &preflight.fallback_text,
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
