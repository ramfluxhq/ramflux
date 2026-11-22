// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Snapshot assembly of one original raw own-copy proof, independent of preferred body selection.
use super::{FullDirectHistory, FullRawOwnProof, direct_source};
use crate::{AccountDb, StorageError};
use prost::Message as _;
use ramflux_crypto::native_origin::OwnSentAttestation;
use ramflux_protocol::message as g;
use rusqlite::{Connection, params};
use zeroize::{Zeroize as _, Zeroizing};

fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
impl AccountDb {
    /// Retain one original own-copy proof from the same account read snapshot.
    /// This does not activate raw transfer, install it or grant replay authority.
    /// # Errors
    /// Refuses another raw class, metadata without an owner, malformed evidence or missing context.
    pub fn read_full_raw_own_proof(
        &self,
        copy_id: &str,
    ) -> Result<Option<FullRawOwnProof>, StorageError> {
        if copy_id.is_empty() || copy_id.len() > 256 || copy_id.chars().any(char::is_control) {
            return Err(invalid());
        }
        let copy = copy_id.to_owned();
        let own = self.principal_commitment.clone();
        self.read_snapshot(|| self.connection.call(move |db| Ok(read(db, &own, &copy)))?)
    }
}
fn read(db: &Connection, own: &str, copy: &str) -> Result<Option<FullRawOwnProof>, StorageError> {
    let stored:String=db.query_row("SELECT CASE WHEN length(principal_commitment)=43 THEN principal_commitment END FROM runtime_account_identity WHERE singleton=1",[],|row|row.get(0))?;
    if stored != own {
        return Err(invalid());
    }
    let mut query=db.prepare("SELECT CASE WHEN length(c.owner_id)=43 THEN c.owner_id END,CASE WHEN length(c.raw_digest)=32 THEN c.raw_digest END,CASE WHEN c.copy_kind='source_evidence' AND length(c.copy_metadata)=0 AND length(o.metadata)=0 AND o.source_anchor=?2 AND length(c.raw_bytes)<=?3 AND length(CAST(c.attempted_decoder AS BLOB))<=256 THEN c.raw_bytes END FROM raw_inner_copy c LEFT JOIN raw_inner_owner o USING(owner_id) WHERE c.copy_id=?1")?;
    let mut rows =
        query.query(params![copy, own, super::super::raw_inner::MAX_HISTORY_CONTAINER_BYTES])?;
    let Some(row) = rows.next()? else { return Ok(None) };
    let owner = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
    let digest = row.get_ref(1)?.as_blob().map_err(|_| invalid())?;
    let raw = Zeroizing::new(row.get_ref(2)?.as_blob().map_err(|_| invalid())?.to_vec());
    let attestation: OwnSentAttestation =
        ramflux_protocol::parse_i_json_secret(&raw).map_err(|_| invalid())?;
    let enclosing = attestation.enclosing_copy().map_err(|_| invalid())?;
    let Some(g::own_message_copy::Payload::Sent(mut sent)) = enclosing.payload else {
        return Err(invalid());
    };
    attestation.verify(&sent.exact_inner, own).map_err(|_| invalid())?;
    let exact = Zeroizing::new(std::mem::take(&mut sent.exact_inner));
    let mut inner = g::Inner::decode(exact.as_slice()).map_err(|_| invalid())?;
    inner.body.zeroize();
    let current = inner.identity.as_ref().ok_or_else(invalid)?;
    let original = direct_source::actor::<g::EventIdentity>(
        db,
        &format!("routed/generated-identity/{owner}"),
    )?
    .ok_or_else(invalid)?;
    let peer = direct_source::peer(db, own, &current.conversation_id)?;
    let history = FullDirectHistory::own_copy(own, &peer, exact.to_vec(), &original, attestation)?;
    let version = history.verify(own)?;
    if ramflux_protocol::encode_base64url(&version.original().id) != owner {
        return Err(invalid());
    }
    let mut bindings=db.prepare("SELECT CASE WHEN length(CAST(message_id AS BLOB))<=64 THEN message_id END FROM message_copy_binding WHERE copy_id=?1 ORDER BY message_id COLLATE BINARY LIMIT 9")?;
    let mut bound = bindings.query([format!("raw:{copy}")])?;
    let mut owners = Vec::new();
    while let Some(row) = bound.next()? {
        if owners.len() == 8 {
            return Err(invalid());
        }
        owners.push(row.get::<_, String>(0)?);
    }
    let value = FullRawOwnProof::from_parts(own, copy.to_owned(), history, raw.to_vec(), owners)?;
    for owner in value.erasure_owners(own)? {
        if super::super::deleted_messages::message_is_deleted_on(db, &owner)? {
            return Err(invalid());
        }
    }
    if super::super::raw_inner::raw_copy_deleted(db, copy)? {
        return Err(invalid());
    }
    if value.raw_digest().as_slice() != digest || rows.next()?.is_some() {
        return Err(invalid());
    }
    Ok(Some(value))
}
