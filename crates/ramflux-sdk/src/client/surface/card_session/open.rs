// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Open one session from the current publication of a surface reference.
use super::body::{self, OpenBody};
use super::gate::{Admission, admit, card_err, refused};
use super::package;
use super::respond::{View, view};
use super::spec_build;
use super::store;
use crate::{RamfluxClient, SdkError};
use ramflux_card::CardSession;
use serde_json::Value;

pub(super) fn open(client: &RamfluxClient, account: &str, body: &Value) -> Result<Value, SdkError> {
    let parsed: OpenBody = body::parse(body, 4 * 1024)?;
    let (locale, dark) = body::presentation(parsed.locale.as_deref(), parsed.dark);
    match admit(client, &parsed.surface_ref)? {
        Admission::Missing => Ok(refused("card_session_refused", "")),
        Admission::Closed { fallback } => Ok(refused("card_session_inactive", &fallback)),
        Admission::Ready { stored, state } => {
            let fallback =
                state.content().map(|content| content.fallback_text.clone()).unwrap_or_default();
            let spec = spec_build::authorized(&stored, &state, locale, dark)?;
            let spec = super::host_view::stamp(client, spec, &state)?;
            let (session, batch) =
                CardSession::open(spec, package::bundled()?).map_err(card_err)?;
            let hash = state.hash().ok_or_else(|| super::super::invalid("card_session_refused"))?;
            let id = store::insert(
                account,
                &parsed.surface_ref,
                session,
                &fallback,
                state.version(),
                hash,
            )?;
            store::with_session(account, id, |held| {
                held.set_presentation(locale, dark);
                Ok(())
            })?;
            let batch = super::respond::batch_value(&batch)?;
            Ok(view(View {
                result: "opened",
                allowed: true,
                session: Some(id),
                fallback: &fallback,
                reason: None,
                batch: Some(batch),
                host_request: None,
                submit: None,
                draft_conflict: false,
                action_outcome: None,
            }))
        }
    }
}
