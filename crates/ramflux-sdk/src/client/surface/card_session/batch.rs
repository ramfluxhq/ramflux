// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Every `event` and `slot` reply with `render_allowed:true` carries a `batch`. Where the call
//! changes nothing, the batch is the mounted tree (empty `mutations`, current `host_slots`).
use super::gate::card_err;
use super::respond::{self, View};
use super::store::Held;
use crate::{RamfluxClient, SdkError};
use serde_json::Value;

/// The mounted tree as a batch, or `None` when the session has no tree.
pub(super) fn mounted(client: &RamfluxClient, held: &Held) -> Result<Option<Value>, SdkError> {
    match held.session_ref().shown_batch() {
        Ok(batch) => Ok(Some(respond::batch_value(client, held.conversation(), &batch)?)),
        Err(ramflux_card::CardError::Inactive) => Ok(None),
        Err(error) => Err(card_err(error)),
    }
}

/// No tree to show: the host must not render.
pub(super) fn inactive(session: u64, fallback: &str) -> Value {
    respond::view(View {
        result: "refused",
        allowed: false,
        session: Some(session),
        fallback,
        reason: Some("card_session_inactive"),
        batch: None,
        host_request: None,
        submit: None,
        draft_conflict: false,
        action_outcome: None,
    })
}

pub(super) fn stale(
    client: &RamfluxClient,
    held: &Held,
    session: u64,
    fallback: &str,
) -> Result<Value, SdkError> {
    Ok(match mounted(client, held)? {
        Some(batch) => respond::stale(session, fallback, Some(batch)),
        None => inactive(session, fallback),
    })
}
