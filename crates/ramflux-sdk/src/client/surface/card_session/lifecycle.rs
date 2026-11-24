// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publication refresh and host presentation. Suspend drops an unsent action.
use super::body::{self, PresentBody, SessionBody};
use super::gate::card_err;
use super::guard::{Kept, keep};
use super::respond::{self, Shown, shown, stale};
use super::spec_build;
use super::store;
use crate::{RamfluxClient, SdkError};
use ramflux_card::Presentation;
use ramflux_protocol::SurfaceState;
use serde_json::Value;

use super::super::StoredSurface;

pub(super) fn update(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let parsed: SessionBody = body::parse(body, body::MAX_BODY)?;
    match keep(client, account, parsed.session)? {
        Kept::Stopped(value) => Ok(value),
        Kept::Ready { stored, state, fallback } => {
            refresh(client, account, parsed.session, &stored, &state, &fallback)
        }
    }
}

fn refresh(
    client: &RamfluxClient,
    account: &str,
    session: u64,
    stored: &StoredSurface,
    state: &SurfaceState,
    fallback: &str,
) -> Result<Value, SdkError> {
    let (locale, dark) =
        store::with_session(account, session, |held| Ok((held.locale().to_owned(), held.dark())))?;
    let spec = spec_build::authorized(stored, state, &locale, dark)?;
    let spec = super::host_view::stamp(client, spec, state)?;
    store::with_session(account, session, |held| {
        let batch = held.session().update(spec).map_err(card_err)?;
        let conflict = held.session().draft_conflict();
        held.adopt(state, fallback);
        Ok(shown(Shown {
            result: "updated",
            session,
            fallback,
            batch: Some(respond::batch_value(&batch)?),
            host_request: None,
            submit: None,
            draft_conflict: conflict,
            action_outcome: None,
        }))
    })
}

pub(super) fn present(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let parsed: PresentBody = body::parse(body, body::MAX_BODY)?;
    let (locale, dark) = body::presentation(parsed.locale.as_deref(), parsed.dark);
    match keep(client, account, parsed.session)? {
        Kept::Stopped(value) => Ok(value),
        Kept::Ready { state, fallback, .. } => {
            change(account, parsed.session, &state, &fallback, locale, dark)
        }
    }
}

fn change(
    account: &str,
    session: u64,
    state: &SurfaceState,
    fallback: &str,
    locale: &str,
    dark: bool,
) -> Result<Value, SdkError> {
    let presentation = Presentation::bundled(locale, dark).map_err(card_err)?;
    store::with_session(account, session, |held| {
        if !held.matches(state) {
            return Ok(stale(session, fallback));
        }
        held.set_presentation(locale, dark);
        let batch = held.session().present(presentation).map_err(card_err)?;
        Ok(shown(Shown {
            result: "presented",
            session,
            fallback,
            batch: Some(respond::batch_value(&batch)?),
            host_request: None,
            submit: None,
            draft_conflict: false,
            action_outcome: None,
        }))
    })
}

pub(super) fn suspend(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let parsed: SessionBody = body::parse(body, body::MAX_BODY)?;
    match keep(client, account, parsed.session)? {
        Kept::Stopped(value) => Ok(value),
        Kept::Ready { state, fallback, .. } => {
            pause(account, parsed.session, &state, &fallback, true)
        }
    }
}

pub(super) fn resume(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let parsed: SessionBody = body::parse(body, body::MAX_BODY)?;
    match keep(client, account, parsed.session)? {
        Kept::Stopped(value) => Ok(value),
        Kept::Ready { state, fallback, .. } => {
            pause(account, parsed.session, &state, &fallback, false)
        }
    }
}

fn pause(
    account: &str,
    session: u64,
    state: &SurfaceState,
    fallback: &str,
    suspending: bool,
) -> Result<Value, SdkError> {
    store::with_session(account, session, |held| {
        if !held.matches(state) {
            return Ok(stale(session, fallback));
        }
        let batch = if suspending {
            held.set_pending(None);
            held.clear_consumed();
            held.session().suspend().map_err(card_err)?
        } else {
            held.session().resume().map_err(card_err)?
        };
        let id = held.session().id();
        let result = if suspending { "suspended" } else { "resumed" };
        Ok(shown(Shown {
            result,
            session: id,
            fallback,
            batch: Some(respond::batch_value(&batch)?),
            host_request: None,
            submit: None,
            draft_conflict: false,
            action_outcome: None,
        }))
    })
}

pub(super) fn dispose(
    client: &RamfluxClient,
    account: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let parsed: SessionBody = body::parse(body, body::MAX_BODY)?;
    match keep(client, account, parsed.session)? {
        Kept::Stopped(value) => Ok(value),
        Kept::Ready { fallback, .. } => {
            store::remove(account, parsed.session)?;
            Ok(shown(Shown {
                result: "disposed",
                session: parsed.session,
                fallback: &fallback,
                batch: None,
                host_request: None,
                submit: None,
                draft_conflict: false,
                action_outcome: None,
            }))
        }
    }
}
