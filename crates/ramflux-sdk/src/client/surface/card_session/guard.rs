// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recheck authority on every call and destroy the session when it is lost.
use super::super::StoredSurface;
use super::super::foreign_refusal::FOREIGN_CARD_REASON;
use super::gate::{Admission, admit, refused};
use super::store;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::SurfaceState;

pub(super) enum Kept {
    Ready { stored: StoredSurface, state: Box<SurfaceState>, fallback: String },
    Stopped(serde_json::Value),
}

pub(super) fn keep(client: &RamfluxClient, account: &str, session: u64) -> Result<Kept, SdkError> {
    let surface_ref =
        store::with_session(account, session, |held| Ok(held.surface_ref().to_owned()))?;
    match admit(client, &surface_ref)? {
        Admission::Ready { stored, state } => {
            let fallback =
                state.content().map(|content| content.fallback_text.clone()).unwrap_or_default();
            store::with_session(account, session, |held| {
                held.set_fallback(&fallback);
                Ok(())
            })?;
            Ok(Kept::Ready { stored, state, fallback })
        }
        Admission::Missing => {
            store::remove(account, session)?;
            Ok(Kept::Stopped(refused("card_session_refused", "")))
        }
        Admission::Foreign { fallback } => {
            store::remove(account, session)?;
            Ok(Kept::Stopped(refused(FOREIGN_CARD_REASON, &fallback)))
        }
        Admission::Closed { fallback } => {
            store::remove(account, session)?;
            Ok(Kept::Stopped(refused("card_session_inactive", &fallback)))
        }
    }
}
