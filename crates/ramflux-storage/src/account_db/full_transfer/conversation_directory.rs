// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical direct-conversation presentation; no route, device pin or contact authorization.
use super::{CodecRule, FieldRule, fixed_union::Cells};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{CellType, Disposition, U64};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

pub(super) const FAMILY: &str = "sql/runtime_actor_state/direct_conversations";
pub(super) const PREFIX: &str = "directory/conversation/";
pub(super) const LIMIT: usize = 8192;
const TEXT: CodecRule = CodecRule::Scalar { cell_type: CellType::Utf8 };
const ROOT: CodecRule = CodecRule::EncodedBytes { decoded_bytes: Some(U64(32)) };
const fn field(
    name: &'static str,
    nullable: bool,
    disposition: Disposition,
    merge: super::MergeRule,
    codec: CodecRule,
) -> FieldRule {
    FieldRule { name, nullable, disposition, codec, merge }
}
pub(super) const FIELDS: &[FieldRule] = &[
    field("id", false, Disposition::Transfer, super::MergeRule::Immutable, TEXT),
    field(
        "kind",
        false,
        Disposition::Transfer,
        super::MergeRule::Immutable,
        CodecRule::Enum { values: &["direct"] },
    ),
    field("group_id", true, Disposition::Transfer, super::MergeRule::Immutable, TEXT),
    field("title", true, Disposition::Transfer, super::MergeRule::PreferLocal, TEXT),
    field(
        "participants",
        false,
        Disposition::Transfer,
        super::MergeRule::PreferLocal,
        CodecRule::Array { element: &TEXT },
    ),
    field(
        "participant_roots",
        false,
        Disposition::Transfer,
        super::MergeRule::Immutable,
        CodecRule::Array { element: &ROOT },
    ),
    field("direct_route", true, Disposition::Exclude, super::MergeRule::PreferLocal, TEXT),
];
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Public {
    id: String,
    kind: String,
    #[serde(deserialize_with = "required_option")]
    group_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    title: Option<String>,
    participants: [String; 2],
    participant_roots: [String; 2],
}
impl Drop for Public {
    fn drop(&mut self) {
        self.id.zeroize();
        self.kind.zeroize();
        self.group_id.zeroize();
        self.title.zeroize();
        self.participants.zeroize();
        self.participant_roots.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Local {
    id: String,
    kind: String,
    group_id: Option<String>,
    title: Option<String>,
    participants: [String; 2],
    participant_roots: [String; 2],
    #[serde(default)]
    direct_route: Option<String>,
}
impl Drop for Local {
    fn drop(&mut self) {
        self.id.zeroize();
        self.kind.zeroize();
        self.group_id.zeroize();
        self.title.zeroize();
        self.participants.zeroize();
        self.participant_roots.zeroize();
        self.direct_route.zeroize();
    }
}
fn required_option<'de, D: serde::Deserializer<'de>>(input: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(input)
}
impl Public {
    fn validate(&self) -> Result<(), StorageError> {
        let [first, second] = &self.participant_roots;
        if self.kind != "direct"
            || self.group_id.is_some()
            || self.id
                != ramflux_protocol::message::dm_scope::derive(first, second)
                    .map_err(|_| invalid())?
            || self.participants.iter().any(|value| {
                value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
            || self.participants.first() == self.participants.get(1)
            || self.title.as_ref().is_some_and(|value| value.len() > 4096)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn require_key(&self, key: &str) -> Result<(), StorageError> {
        if key != format!("{PREFIX}{}", self.id) {
            return Err(invalid());
        }
        Ok(())
    }
    fn require_account(&self, own: &str) -> Result<(), StorageError> {
        if !self.participant_roots.iter().any(|root| root == own) {
            return Err(invalid());
        }
        Ok(())
    }
}
fn require_size(bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err(invalid());
    }
    Ok(())
}
fn public(bytes: &[u8]) -> Result<Public, StorageError> {
    require_size(bytes)?;
    let value: Public = ramflux_protocol::parse_i_json_secret(bytes).map_err(|_| invalid())?;
    value.validate()?;
    if ramflux_protocol::canonical_json_bytes(&value)?.as_slice() != bytes {
        return Err(invalid());
    }
    Ok(value)
}
pub(super) fn source(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    require_size(bytes)?;
    let local: Local = ramflux_protocol::parse_i_json_secret(bytes).map_err(|_| invalid())?;
    // Current native root-pair conversations have no executable direct route.
    // A different route shape must get its own typed owner, never be silently discarded.
    if local.direct_route.is_some() {
        return Err(invalid());
    }
    let value = Public {
        id: local.id.clone(),
        kind: local.kind.clone(),
        group_id: local.group_id.clone(),
        title: local.title.clone(),
        participants: local.participants.clone(),
        participant_roots: local.participant_roots.clone(),
    };
    value.validate()?;
    let bytes = Zeroizing::new(ramflux_protocol::canonical_json_bytes(&value)?);
    require_size(&bytes)?;
    Ok(bytes)
}
pub(super) fn portable(bytes: &[u8]) -> Result<(), StorageError> {
    public(bytes).map(|_| ())
}
pub(super) fn validate(value: &Cells) -> Result<(), StorageError> {
    public(value.bytes(1)?)?.require_key(value.text(0)?)
}
pub(super) fn require_account(db: &Connection, value: &Cells) -> Result<(), StorageError> {
    let own: String = db.query_row("SELECT CASE WHEN length(principal_commitment)=43 THEN principal_commitment END FROM runtime_account_identity WHERE singleton=1", [], |row| row.get(0))?;
    public(value.bytes(1)?)?.require_account(&own)
}
pub(super) fn resolve(left: &Cells, right: &Cells) -> Result<Cells, StorageError> {
    let a = public(left.bytes(1)?)?;
    let b = public(right.bytes(1)?)?;
    let mut first = a.participant_roots.each_ref();
    let mut second = b.participant_roots.each_ref();
    first.sort_unstable();
    second.sort_unstable();
    if a.id != b.id || first != second {
        return Err(StorageError::PairingField("TransferConflict"));
    }
    Ok(left.clone())
}
pub(super) fn require_source(key: &str, bytes: &[u8], own: &str) -> Result<(), StorageError> {
    let encoded = source(bytes)?;
    let value = public(&encoded)?;
    value.require_key(key)?;
    value.require_account(own)
}
pub(super) fn rows(db: &Connection) -> Result<u64, StorageError> {
    let mut statement = db.prepare("SELECT CASE WHEN length(CAST(state_kind AS BLOB))<=256 THEN state_kind END,CASE WHEN typeof(state_json)='blob' AND length(state_json)<=?1 THEN state_json END FROM runtime_actor_state WHERE substr(state_kind,1,23)='directory/conversation/'")?;
    let mut rows = statement.query([LIMIT])?;
    let mut count = 0_u64;
    let mut own = None;
    while let Some(row) = rows.next()? {
        if own.is_none() {
            let root: String = db.query_row("SELECT CASE WHEN length(principal_commitment)=43 THEN principal_commitment END FROM runtime_account_identity WHERE singleton=1", [], |row| row.get(0)).map_err(|_| invalid())?;
            own = Some(root);
        }
        let root = own.as_deref().ok_or_else(invalid)?;
        require_source(
            row.get_ref(0)?.as_str().map_err(|_| invalid())?,
            row.get_ref(1)?.as_blob().map_err(|_| invalid())?,
            root,
        )?;
        count = count.checked_add(1).ok_or_else(invalid)?;
    }
    Ok(count)
}
