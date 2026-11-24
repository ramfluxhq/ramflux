// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host-only lifecycle. Signed snapshot bytes and the proof check stay unchanged.
use super::approval;
use super::gate::card_err;
use super::spec_build;
use super::store::{self, Held};
use crate::{RamfluxClient, SdkError};
use ramflux_card::{CardLifecycle, CardSpec};
use ramflux_protocol::SurfaceState;
use ramflux_protocol::a2ui::{SurfaceSnapshot, SurfaceStreamState, validate_identifier};

const SURFACE_SCAN: u32 = 32;

pub(super) struct Block {
    pub status: &'static str,
    pub reason: &'static str,
    pub replacement_ref: Option<String>,
}

pub(super) fn stamp(
    client: &RamfluxClient,
    mut spec: CardSpec,
    state: &SurfaceState,
) -> Result<CardSpec, SdkError> {
    spec.generating = generating(state);
    spec.lifecycle = CardLifecycle::Open;
    spec.replacement_ref = None;
    if let Some(link) = replacement(client, &spec)? {
        spec.lifecycle = CardLifecycle::Superseded;
        spec.replacement_ref = Some(link);
        spec.generating = false;
    } else if state.is_closed() {
        spec.lifecycle = CardLifecycle::Closed;
        spec.generating = false;
    }
    spec.approval_facts = approval::verified_facts(client, &spec)?;
    Ok(spec)
}

pub(super) fn block_state(
    client: &RamfluxClient,
    surface_ref: &str,
    state: &SurfaceState,
) -> Result<Option<Block>, SdkError> {
    let Some((stored, _)) = client.surface_state_ref(surface_ref)? else {
        return Ok(None);
    };
    let Some(snapshot) = state.content() else {
        return Ok(None);
    };
    let Some(conversation) = state.conversation_id() else {
        return Ok(None);
    };
    if let Some(link) = find_replacement(
        client,
        conversation,
        &stored.author_principal_id,
        &snapshot.surface_id,
        surface_ref,
    )? {
        return Ok(Some(Block {
            status: "superseded",
            reason: "card_superseded",
            replacement_ref: Some(link),
        }));
    }
    if state.is_closed() {
        return Ok(Some(Block { status: "refused", reason: "card_closed", replacement_ref: None }));
    }
    Ok(None)
}

/// Project a closed or replaced publication onto the live session before refusing.
pub(super) fn seal_if_blocked(
    client: &RamfluxClient,
    held: &mut Held,
    state: &SurfaceState,
    fallback: &str,
) -> Result<Option<Block>, SdkError> {
    let Some(block) = block_state(client, held.surface_ref(), state)? else {
        return Ok(None);
    };
    if held.session().refusal().is_none() {
        seal_session(client, held, state, fallback)?;
    }
    Ok(Some(block))
}

fn seal_session(
    client: &RamfluxClient,
    held: &mut Held,
    state: &SurfaceState,
    fallback: &str,
) -> Result<(), SdkError> {
    let Some((stored, _)) = client.surface_state_ref(held.surface_ref())? else {
        return Ok(());
    };
    let spec = spec_build::authorized(&stored, state, held.locale(), held.dark())?;
    let spec = stamp(client, spec, state)?;
    held.session().update(spec).map_err(card_err)?;
    held.adopt(state, fallback);
    Ok(())
}

fn generating(state: &SurfaceState) -> bool {
    if state.is_closed() {
        return false;
    }
    state.stream_states().values().any(|stream| *stream == SurfaceStreamState::Open)
}

fn replacement(client: &RamfluxClient, spec: &CardSpec) -> Result<Option<String>, SdkError> {
    if spec.conversation_id.is_empty() {
        return Ok(None);
    }
    find_replacement(
        client,
        &spec.conversation_id,
        &spec.author_principal_id,
        &spec.snapshot.surface_id,
        &spec.surface_ref,
    )
}

fn find_replacement(
    client: &RamfluxClient,
    conversation: &str,
    author: &str,
    surface_id: &str,
    surface_ref: &str,
) -> Result<Option<String>, SdkError> {
    let listed = client.surface_list(conversation, "", SURFACE_SCAN)?;
    let Some(rows) = listed.get("surfaces").and_then(|value| value.as_array()) else {
        return Ok(None);
    };
    let mut best_version = 0_u64;
    let mut best_ref: Option<String> = None;
    for row in rows.iter().take(SURFACE_SCAN as usize) {
        let Some(candidate) = row.get("surface_ref").and_then(|value| value.as_str()) else {
            continue;
        };
        if candidate == surface_ref {
            continue;
        }
        let Some(row_author) = row.get("author_principal_id").and_then(|value| value.as_str())
        else {
            continue;
        };
        if row_author != author {
            continue;
        }
        consider_candidate(
            client,
            candidate,
            author,
            surface_id,
            &mut best_version,
            &mut best_ref,
        )?;
    }
    Ok(best_ref)
}

fn consider_candidate(
    client: &RamfluxClient,
    candidate: &str,
    author: &str,
    surface_id: &str,
    best_version: &mut u64,
    best_ref: &mut Option<String>,
) -> Result<(), SdkError> {
    let Some((stored, state)) = client.surface_state_ref(candidate)? else {
        return Ok(());
    };
    if stored.author_principal_id != author {
        return Ok(());
    }
    let Some(snapshot) = state.content() else {
        return Ok(());
    };
    if snapshot.surface_id == surface_id || !names_predecessor(snapshot, surface_id) {
        return Ok(());
    }
    let version = state.version();
    let take = best_ref.as_deref().is_none_or(|current| {
        version > *best_version || (version == *best_version && candidate > current)
    });
    if take {
        *best_version = version;
        *best_ref = Some(candidate.to_owned());
    }
    Ok(())
}

fn names_predecessor(snapshot: &SurfaceSnapshot, surface_id: &str) -> bool {
    let Some(metadata) = snapshot.metadata.as_ref() else {
        return false;
    };
    let Some(value) = metadata.extensions.get("replaces").and_then(|value| value.as_str()) else {
        return false;
    };
    validate_identifier(value).is_ok() && value == surface_id
}

pub(super) fn forget_pending(account: &str, session: u64) -> Result<(), SdkError> {
    store::with_session(account, session, |held| {
        held.set_pending(None);
        Ok(())
    })
}
