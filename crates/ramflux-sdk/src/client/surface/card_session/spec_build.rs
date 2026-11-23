// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Build an authorized envelope from the stored publication. The host supplies no snapshot.
use super::super::{StoredSurface, invalid};
use super::gate::card_err;
use crate::SdkError;
use ramflux_card::{CardSpec, Presentation};
use ramflux_protocol::SurfaceState;
use ramflux_protocol::a2ui::SurfaceSnapshot;
use serde::Serialize;

#[derive(Serialize)]
struct Envelope<'a> {
    conversation_id: &'a str,
    author_principal_id: &'a str,
    surface_ref: &'a str,
    signed_version: u64,
    signed_hash: &'a str,
    render_allowed: bool,
    snapshot: &'a SurfaceSnapshot,
}

pub(super) fn authorized(
    stored: &StoredSurface,
    state: &SurfaceState,
    locale: &str,
    dark: bool,
) -> Result<CardSpec, SdkError> {
    let snapshot = state.content().ok_or_else(|| invalid("card_session_refused"))?;
    let conversation = state.conversation_id().ok_or_else(|| invalid("card_session_refused"))?;
    let hash = state.hash().ok_or_else(|| invalid("card_session_refused"))?;
    let bytes = ramflux_protocol::canonical_json_bytes(&Envelope {
        conversation_id: conversation,
        author_principal_id: &stored.author_principal_id,
        surface_ref: &snapshot.surface_id,
        signed_version: state.version(),
        signed_hash: hash,
        render_allowed: true,
        snapshot,
    })?;
    if bytes.len() > 32 * 1024 {
        return Err(invalid("card_session_limit"));
    }
    let spec = CardSpec::parse(&bytes).map_err(card_err)?;
    spec.with_presentation(Presentation::bundled(locale, dark).map_err(card_err)?).map_err(card_err)
}
