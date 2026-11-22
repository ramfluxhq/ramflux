// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded snapshot assembly from existing native owners, never a SQL BLOB fallback.
use super::{FullDirectHistory, native_selection::Selected};
use crate::{AccountDb, StorageError};
use prost::Message as _;
use ramflux_crypto::native_origin::{
    OriginalHeader, OwnAuthoredCapture, OwnSentAttestation, RetainedOrigin,
};
use ramflux_protocol::message as g;
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::de::DeserializeOwned;
use zeroize::{Zeroize as _, Zeroizing};
const HISTORY_LIMIT: usize = super::super::raw_inner::MAX_HISTORY_CONTAINER_BYTES;
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
impl AccountDb {
    /// Assemble one native record under one account read snapshot. The full source owner
    /// must still pin its exact cut, apply erasure union and authenticate its contribution.
    /// # Errors
    /// Refuses noncanonical ids/scopes, incomplete proofs, ambiguous rows and oversized state.
    pub fn read_full_direct_history(
        &self,
        message: &str,
    ) -> Result<Option<FullDirectHistory>, StorageError> {
        let decoded = ramflux_protocol::decode_base64url(message).map_err(|_| invalid())?;
        if decoded.len() != 32 || ramflux_protocol::encode_base64url(&decoded) != message {
            return Err(invalid());
        }
        self.read_snapshot(|| {
            let own = self.principal_commitment.clone();
            let message = message.to_owned();
            self.connection.call(move |db| Ok(read(db, &own, &message)))?
        })
    }
}

pub(super) fn read(
    db: &Connection,
    own: &str,
    message: &str,
) -> Result<Option<FullDirectHistory>, StorageError> {
    let stored: String = db.query_row("SELECT CASE WHEN length(principal_commitment)=43 THEN principal_commitment END FROM runtime_account_identity WHERE singleton=1",[],|row|row.get(0))?;
    if stored != own {
        return Err(invalid());
    }
    let Some((conversation, deleted)) = projection(db, message)? else { return Ok(None) };
    if deleted {
        return Ok(None);
    }
    let peer = peer(db, own, &conversation)?;
    let body = body(db, message, &conversation)?.ok_or_else(invalid)?;
    let mut inner = g::Inner::decode(body.as_slice()).map_err(|_| invalid())?;
    inner.body.zeroize();
    let current = inner.identity.as_ref().ok_or_else(invalid)?;
    let original = actor::<g::EventIdentity>(db, &format!("routed/generated-identity/{message}"))?
        .ok_or_else(invalid)?;
    let capture = actor::<OwnAuthoredCapture>(db, &format!("own-history/capture/{message}"))?;
    if capture.as_ref().is_some_and(|capture| capture.sent.exact_inner != body.as_slice()) {
        return Err(invalid());
    }
    let key = format!(
        "routed/own-sent-attestation/{message}/{}",
        ramflux_protocol::encode_base64url(&current.id)
    );
    let attestation = actor::<OwnSentAttestation>(db, &key)?;
    let selected = super::native_selection::read(db, message, &body)?.unwrap_or_else(|| {
        if capture.is_some() {
            Selected::Authored
        } else if attestation.is_some() {
            Selected::OwnCopy
        } else {
            Selected::Received
        }
    });
    let value = match selected {
        Selected::Authored => {
            FullDirectHistory::authored(own, &peer, capture.as_ref().ok_or_else(invalid)?)?
        }
        Selected::OwnCopy => FullDirectHistory::own_copy(
            own,
            &peer,
            body.to_vec(),
            &original,
            attestation.ok_or_else(invalid)?,
        )?,
        Selected::Received => received(db, own, &peer, message, &body, &inner)?,
    };
    let version = value.verify(own)?;
    if version.original() != &original
        || ramflux_protocol::encode_base64url(&version.original().id) != message
        || version.original().conversation_id != conversation
    {
        return Err(invalid());
    }
    Ok(Some(value))
}
fn projection(db: &Connection, message: &str) -> Result<Option<(String, bool)>, StorageError> {
    let mut query=db.prepare("SELECT CASE WHEN length(conversation_id)<=256 THEN conversation_id END,deleted FROM direct_message_projection WHERE message_id=?1 LIMIT 2")?;
    let mut rows = query.query([message])?;
    let Some(row) = rows.next()? else { return Ok(None) };
    let conversation: String = row.get(0)?;
    let deleted = match row.get::<_, i64>(1)? {
        0 => false,
        1 => true,
        _ => return Err(invalid()),
    };
    if rows.next()?.is_some() {
        return Err(invalid());
    }
    Ok(Some((conversation, deleted)))
}
pub(super) fn peer(db: &Connection, own: &str, conversation: &str) -> Result<String, StorageError> {
    // This is only the explicit root-pair context. It does not admit the enclosing
    // directory actor variant or any of its other fields into transfer.
    let mut query=db.prepare("SELECT json_extract(CAST(state_json AS TEXT),'$.participant_roots[0]'),json_extract(CAST(state_json AS TEXT),'$.participant_roots[1]') FROM runtime_actor_state WHERE state_kind=?1 AND length(state_json)<=?2 AND CASE WHEN json_valid(CAST(state_json AS TEXT)) THEN json_extract(CAST(state_json AS TEXT),'$.kind')='direct' AND json_extract(CAST(state_json AS TEXT),'$.group_id') IS NULL AND json_array_length(CAST(state_json AS TEXT),'$.participant_roots')=2 AND length(json_extract(CAST(state_json AS TEXT),'$.participant_roots[0]'))=43 AND length(json_extract(CAST(state_json AS TEXT),'$.participant_roots[1]'))=43 ELSE 0 END")?;
    let roots: (String, String) = query.query_row(
        params![
            format!("directory/conversation/{conversation}"),
            super::record_profile::METADATA_LIMIT
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let peer = if roots.0 == own {
        roots.1
    } else if roots.1 == own {
        roots.0
    } else {
        return Err(invalid());
    };
    if g::dm_scope::derive(own, &peer).map_err(|_| invalid())? != conversation {
        return Err(invalid());
    }
    Ok(peer)
}
pub(super) fn require_peer(
    db: &Connection,
    own: &str,
    conversation: &str,
    expected: &str,
) -> Result<(), StorageError> {
    if peer(db, own, conversation)? != expected {
        return Err(invalid());
    }
    Ok(())
}
fn body(
    db: &Connection,
    message: &str,
    conversation: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
    let value:Option<Option<Vec<u8>>>=db.query_row("SELECT CASE WHEN conversation_id=?2 AND typeof(body)='blob' AND length(body)<=?3 THEN body END FROM runtime_message_content WHERE message_id=?1",params![message,conversation,g::validation::MAX_INNER_BYTES],|row|row.get(0)).optional()?;
    match value {
        None => Ok(None),
        Some(Some(bytes)) => Ok(Some(Zeroizing::new(bytes))),
        Some(None) => Err(invalid()),
    }
}
pub(super) fn actor<T: DeserializeOwned>(
    db: &Connection,
    key: &str,
) -> Result<Option<T>, StorageError> {
    let value:Option<Option<Vec<u8>>>=db.query_row("SELECT CASE WHEN typeof(state_json)='blob' AND length(state_json)<=?2 THEN state_json END FROM runtime_actor_state WHERE state_kind=?1",params![key,HISTORY_LIMIT],|row|row.get(0)).optional()?;
    match value {
        None => Ok(None),
        Some(None) => Err(invalid()),
        Some(Some(bytes)) => Ok(Some(
            ramflux_protocol::parse_i_json_secret(&Zeroizing::new(bytes)).map_err(|_| invalid())?,
        )),
    }
}
fn received(
    db: &Connection,
    own: &str,
    peer: &str,
    message: &str,
    body: &[u8],
    inner: &g::Inner,
) -> Result<FullDirectHistory, StorageError> {
    let current = inner.identity.as_ref().ok_or_else(invalid)?;
    let item = match inner.kind {
        1 => {
            let origin = actor::<RetainedOrigin>(db, &format!("routed/origin-evidence/{message}"))?
                .ok_or_else(invalid)?;
            origin.verify(current, body).map_err(|_| invalid())?;
            g::HistoryItem {
                exact_inner: body.to_vec(),
                source_evidence: Some(origin.evidence.clone()),
                ..Default::default()
            }
        }
        3 => {
            let header = actor::<OriginalHeader>(db, &format!("routed/original-header/{message}"))?
                .ok_or_else(invalid)?;
            let proof = actor::<Option<g::HistoryOriginEvidence>>(
                db,
                &format!("routed/current-edit-proof/{message}"),
            )?
            .flatten()
            .ok_or_else(invalid)?;
            g::HistoryItem {
                exact_inner: body.to_vec(),
                source_evidence: Some(proof),
                exact_original_identity: header.exact_identity,
                original_metadata_evidence: Some(header.evidence),
                ..Default::default()
            }
        }
        _ => return Err(invalid()),
    };
    FullDirectHistory::received(own, peer, item)
}
