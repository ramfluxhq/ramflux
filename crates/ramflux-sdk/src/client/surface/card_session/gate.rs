// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-agent publication gate. A snapshot alone is not authorization.
use super::super::{StoredSurface, invalid};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::SurfaceState;

pub(super) enum Admission {
    Missing,
    Foreign { fallback: String },
    Closed { fallback: String },
    Ready { stored: StoredSurface, state: Box<SurfaceState> },
}

pub(super) fn admit(client: &RamfluxClient, surface_ref: &str) -> Result<Admission, SdkError> {
    let Some((stored, state)) = client.surface_state_ref(surface_ref)? else {
        return Ok(Admission::Missing);
    };
    let fallback = state.content().map(|content| content.fallback_text.clone()).unwrap_or_default();
    if !client.surface_author_is_own_agent(&stored.author_principal_id)? {
        return Ok(Admission::Foreign { fallback });
    }
    if state.is_closed()
        || state.version() == 0
        || state.hash().is_none()
        || state.content().is_none()
    {
        return Ok(Admission::Closed { fallback });
    }
    Ok(Admission::Ready { stored, state: Box::new(state) })
}

pub(super) fn refused(reason: &str, fallback: &str) -> serde_json::Value {
    super::respond::refused(reason, fallback)
}

pub(super) fn card_err(error: impl std::fmt::Display) -> SdkError {
    invalid(&error.to_string())
}
