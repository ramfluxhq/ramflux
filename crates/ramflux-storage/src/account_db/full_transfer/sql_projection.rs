// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed small SQL metadata projections; excluded execution fields never survive selection.
use super::catalog::{CodecRule, FamilyRule, FamilySelector, FieldRule, MergeRule, SqlProjection};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{CellType, Disposition, U64};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

const fn field(
    name: &'static str,
    nullable: bool,
    disposition: Disposition,
    codec: CodecRule,
) -> FieldRule {
    FieldRule { name, nullable, disposition, merge: MergeRule::Immutable, codec }
}
pub(super) const CONTACT_REQUEST_FIELDS: &[FieldRule] = &[
    field(
        "nonce",
        false,
        Disposition::Transfer,
        CodecRule::EncodedBytes { decoded_bytes: Some(U64(32)) },
    ),
    field(
        "issued_at",
        false,
        Disposition::Transfer,
        CodecRule::Scalar { cell_type: CellType::I64 },
    ),
    field("note", true, Disposition::Transfer, CodecRule::Scalar { cell_type: CellType::Utf8 }),
    field(
        "needs_reply",
        true,
        Disposition::Exclude,
        CodecRule::Enum { values: &["request", "accept", "decline"] },
    ),
];
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicContactMetadata {
    pub(super) nonce: String,
    pub(super) issued_at: i64,
    #[serde(deserialize_with = "required_note")]
    pub(super) note: Option<String>,
}
fn required_note<'de, D: serde::Deserializer<'de>>(input: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(input)
}
impl Drop for PublicContactMetadata {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.note.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalContactMetadata {
    nonce: String,
    issued_at: i64,
    #[serde(deserialize_with = "required_note")]
    note: Option<String>,
    #[serde(default)]
    needs_reply: Option<ramflux_protocol::custody::ContactDecision>,
}
impl Drop for LocalContactMetadata {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.note.zeroize();
    }
}
impl PublicContactMetadata {
    fn validate(&self) -> Result<(), StorageError> {
        let nonce =
            Zeroizing::new(ramflux_protocol::decode_base64url(&self.nonce).map_err(|_| invalid())?);
        let issued = u64::try_from(self.issued_at).map_err(|_| invalid())?;
        if nonce.len() != 32
            || ramflux_protocol::encode_base64url(&nonce) != self.nonce
            || issued > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || self.note.as_ref().is_some_and(|note| {
                note.chars().count() > 140
                    || !ramflux_protocol::text_safety::single_line_is_safe(note)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl SqlProjection {
    pub(super) const fn max_bytes(self) -> usize {
        match self {
            Self::ContactRequestMetadataV1 => 1024,
            Self::MessageDenialV1 => super::actor_denial::LIMIT,
            Self::DirectConversationMetadataV1 => super::conversation_directory::LIMIT,
        }
    }
    pub(super) fn require_fields(self, fields: &[FieldRule]) -> Result<(), StorageError> {
        let expected = match self {
            Self::ContactRequestMetadataV1 => CONTACT_REQUEST_FIELDS,
            Self::MessageDenialV1 => super::actor_denial::FIELDS,
            Self::DirectConversationMetadataV1 => super::conversation_directory::FIELDS,
        };
        if ramflux_protocol::canonical_json_bytes(&fields)?
            != ramflux_protocol::canonical_json_bytes(&expected)?
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn source(self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        if bytes.is_empty() || bytes.len() > self.max_bytes() {
            return Err(invalid());
        }
        match self {
            Self::MessageDenialV1 => super::actor_denial::source(bytes),
            Self::DirectConversationMetadataV1 => super::conversation_directory::source(bytes),
            Self::ContactRequestMetadataV1 => {
                let local: LocalContactMetadata =
                    ramflux_protocol::parse_i_json(bytes).map_err(|_| invalid())?;
                // Only this closed execution field is omitted, including explicit null.
                let _execution = local.needs_reply;
                let public = PublicContactMetadata {
                    nonce: local.nonce.clone(),
                    issued_at: local.issued_at,
                    note: local.note.clone(),
                };
                public.validate()?;
                let bytes = Zeroizing::new(ramflux_protocol::canonical_json_bytes(&public)?);
                if bytes.len() > self.max_bytes() {
                    return Err(invalid());
                }
                Ok(bytes)
            }
        }
    }
    pub(super) fn portable(self, bytes: &[u8]) -> Result<(), StorageError> {
        if bytes.is_empty() || bytes.len() > self.max_bytes() {
            return Err(invalid());
        }
        match self {
            Self::MessageDenialV1 => super::actor_denial::portable(bytes)?,
            Self::DirectConversationMetadataV1 => super::conversation_directory::portable(bytes)?,
            Self::ContactRequestMetadataV1 => {
                read_contact_metadata(bytes)?;
            }
        }
        Ok(())
    }
}

pub(super) fn read_contact_metadata(bytes: &[u8]) -> Result<PublicContactMetadata, StorageError> {
    if bytes.is_empty() || bytes.len() > SqlProjection::ContactRequestMetadataV1.max_bytes() {
        return Err(invalid());
    }
    let public: PublicContactMetadata =
        ramflux_protocol::parse_i_json(bytes).map_err(|_| invalid())?;
    public.validate()?;
    if ramflux_protocol::canonical_json_bytes(&public)?.as_slice() != bytes {
        return Err(invalid());
    }
    Ok(public)
}

/// Reset only explicitly declared execution fields in the private own-B copy.
/// The original public contribution must be captured first; the caller owns a transaction.
pub(super) fn canonicalize_private(
    db: &Connection,
    rules: &[FamilyRule],
) -> Result<(), StorageError> {
    if db.is_autocommit() {
        return Err(StorageError::PairingField("WrongContext"));
    }
    visit_private(db, rules, true)
}
/// A source projection must never hide leftover execution state from actual-file verification.
pub(super) fn require_private(db: &Connection, rules: &[FamilyRule]) -> Result<(), StorageError> {
    visit_private(db, rules, false)
}
fn visit_private(db: &Connection, rules: &[FamilyRule], rewrite: bool) -> Result<(), StorageError> {
    for rule in rules {
        rule.validate()?;
        for field in rule.codec {
            let CodecRule::SqlJsonProjection { projection, .. } = field.codec else {
                continue;
            };
            let FamilySelector::Table(table) = rule.selector else {
                return Err(invalid());
            };
            let mut query = db.prepare(&format!("SELECT rowid,CASE WHEN length(\"{}\")<=?1 THEN \"{}\" ELSE NULL END FROM \"{table}\" WHERE {} ORDER BY rowid",field.name,field.name,super::owner_sql::row_filter(rule)))?;
            let mut rows = query.query([projection.max_bytes()])?;
            while let Some(row) = rows.next()? {
                let bytes = row.get_ref(1)?.as_blob().map_err(|_| invalid())?;
                if rewrite {
                    let public = projection.source(bytes)?;
                    if db.execute(
                        &format!("UPDATE \"{table}\" SET \"{}\"=?1 WHERE rowid=?2", field.name),
                        params![public.as_slice(), row.get::<_, i64>(0)?],
                    )? != 1
                    {
                        return Err(invalid());
                    }
                } else {
                    projection.portable(bytes)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
