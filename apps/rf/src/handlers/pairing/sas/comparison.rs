// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private out-of-band comparison record; a role or transcript from another ceremony refuses.
use super::{RfError, invalid};
use ramflux_protocol::custody::pairing::local_dto::Update;
use serde::{Deserialize, Serialize};
const MAX_BYTES: usize = 4096;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Comparison {
    schema: String,
    version: u32,
    operation_id: String,
    generation: u64,
    transcript_hash: String,
    role: String,
    names: Vec<String>,
}
fn names(update: &Update) -> Result<Vec<String>, RfError> {
    let indices = update.emoji_indices.as_ref().ok_or_else(invalid)?;
    if indices.len() != 7 || !matches!(update.phase.as_str(), "sas_pending" | "mutually_confirmed")
    {
        return Err(invalid());
    }
    indices
        .iter()
        .map(|index| {
            usize::try_from(*index)
                .ok()
                .and_then(|index| ramflux_crypto::custody::pairing::SAS_EMOJI.get(index))
                .map(|(_, name)| (*name).into())
                .ok_or_else(invalid)
        })
        .collect()
}
fn local(update: &Update, role: &str) -> Result<Comparison, RfError> {
    if !matches!(role, "initiator" | "responder") {
        return Err(invalid());
    }
    Ok(Comparison {
        schema: "ramflux.pairing.SasComparison.v1".into(),
        version: 1,
        operation_id: update.operation_id.clone(),
        generation: update.generation,
        transcript_hash: update.transcript_hash.clone().ok_or_else(invalid)?,
        role: role.into(),
        names: names(update)?,
    })
}
pub(super) fn encode(update: &Update, role: &str) -> Result<Vec<u8>, RfError> {
    let bytes = ramflux_protocol::canonical_json_bytes(&local(update, role)?)?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}
pub(super) fn peer_matches(update: &Update, own_role: &str, bytes: &[u8]) -> Result<bool, RfError> {
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    let peer: Comparison = ramflux_protocol::parse_i_json(bytes).map_err(|_| invalid())?;
    let local = local(update, own_role)?;
    if peer.schema != "ramflux.pairing.SasComparison.v1"
        || peer.version != 1
        || peer.operation_id != local.operation_id
        || peer.transcript_hash != local.transcript_hash
        || peer.generation == 0
        || peer.generation > 9_007_199_254_740_991
        || peer.names.len() != 7
        || !matches!(
            (own_role, peer.role.as_str()),
            ("initiator", "responder") | ("responder", "initiator")
        )
    {
        return Err(invalid());
    }
    // Frontend generations are local to each store. Both must be valid; their
    // shared ceremony identity is the exact operation and committed transcript.
    Ok(peer.names == local.names)
}
