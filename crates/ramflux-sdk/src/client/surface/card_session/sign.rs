// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sign one resolver action inside the SDK. The author remains the acceptor.
use super::super::{Carrier, PayloadKind, invalid};
use super::gate::card_err;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::a2ui::{ResolvedAction, ResolvedSurface, SurfaceState};
use ramflux_protocol::{SurfaceAction, domain};

#[derive(Clone)]
pub(super) struct Pending {
    pub message_id: String,
    pub carrier: Carrier,
    pub surface_version: u64,
    pub surface_hash: String,
}

pub(super) fn sign_action(
    client: &RamfluxClient,
    state: &SurfaceState,
    author: &str,
    resolved: &ResolvedSurface,
    action: &ResolvedAction,
) -> Result<Pending, SdkError> {
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| invalid("card action timestamp"))?;
    let frame = resolved.action_frame(state, action, &timestamp).map_err(card_err)?;
    let wire = frame.wire_bytes().map_err(card_err)?;
    let parsed = SurfaceAction::from_wire_bytes(&wire).map_err(card_err)?;
    state.validate_action(&parsed).map_err(card_err)?;
    let conversation =
        state.conversation_id().ok_or_else(|| invalid("card_session_refused"))?.to_owned();
    let surface_hash = state.hash().ok_or_else(|| invalid("card_session_refused"))?.to_owned();
    let device = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let message_id = crate::new_surface_message_id()?;
    let carrier = client.sign_surface_carrier(Carrier {
        typed: None,
        schema: domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: PayloadKind::Action,
        conversation_id: conversation,
        surface_id: parsed.surface_id().to_owned(),
        message_id: message_id.clone(),
        sender_principal_id: device.principal_id.clone(),
        sender_device_id: device.device_id.clone(),
        author_principal_id: author.to_owned(),
        wire_base64: ramflux_protocol::encode_base64url(&wire),
        signature: String::new(),
        snapshot: None,
    })?;
    Ok(Pending { message_id, carrier, surface_version: state.version(), surface_hash })
}
