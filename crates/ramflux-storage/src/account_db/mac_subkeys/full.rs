// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed source-qualified data verifiers. They never replace B's current MAC bundle.
use super::{BUNDLE_BYTES, Bundle, LABELS, RAW_COPY_MARKER_LABEL, bundle_id};
use crate::{AccountDb, BackupDatabase, StorageError};
use ramflux_protocol::{
    MAX_SAFE_JSON_INTEGER, canonical_json_bytes, custody::DeviceRef, decode_base64url,
    encode_base64url, parse_i_json,
};
use rusqlite::params;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS full_imported_mac_bundle(source_ref TEXT NOT NULL CHECK(length(CAST(source_ref AS BLOB)) BETWEEN 1 AND 512),bundle_id TEXT NOT NULL CHECK(length(bundle_id)=43),subkeys BLOB NOT NULL CHECK(length(subkeys)=192),PRIMARY KEY(source_ref,bundle_id)) WITHOUT ROWID;";

/// Existing marker domains only. A matching MAC is data evidence, never author ownership.
#[derive(Clone, Copy)]
pub enum FullImportedMacDomain {
    Tombstone,
    DeletedEnvelope,
    OwnSentIndex,
    OwnSentReplay,
    OwnSentReceipt,
    Replay,
    DeletedRawCopy,
}
impl FullImportedMacDomain {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Tombstone => LABELS[0],
            Self::DeletedEnvelope => LABELS[1],
            Self::OwnSentIndex => LABELS[2],
            Self::OwnSentReplay => LABELS[3],
            Self::OwnSentReceipt => LABELS[4],
            Self::Replay => LABELS[5],
            Self::DeletedRawCopy => RAW_COPY_MARKER_LABEL,
        }
    }
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}

pub(in crate::account_db) fn source_key(source: &DeviceRef) -> Result<String, StorageError> {
    if source.account_anchor.len() != 43 {
        return Err(invalid());
    }
    let anchor = decode_base64url(&source.account_anchor).map_err(|_| invalid())?;
    if anchor.len() != 32
        || encode_base64url(&anchor) != source.account_anchor
        || source.device_id.is_empty()
        || source.device_id.len() > 128
        || source.device_id.chars().any(char::is_control)
        || !(1..=MAX_SAFE_JSON_INTEGER).contains(&source.device_epoch)
    {
        return Err(invalid());
    }
    let bytes = canonical_json_bytes(source).map_err(|_| invalid())?;
    if bytes.len() > 512 {
        return Err(invalid());
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}
pub(in crate::account_db) fn decode_source_ref(bytes: &[u8]) -> Result<DeviceRef, StorageError> {
    if bytes.is_empty() || bytes.len() > 512 {
        return Err(invalid());
    }
    let source: DeviceRef = parse_i_json(bytes).map_err(|_| invalid())?;
    if source_key(&source)?.as_bytes() != bytes {
        return Err(invalid());
    }
    Ok(source)
}

impl BackupDatabase {
    /// Insert data-only verifier material into this PRIVATE prepared generation.
    /// The caller must already verify the manifest and original association under its
    /// typed semantic owner. This method alone grants no receipt, install or ownership.
    /// It does not load or modify `account_mac_bundle`/`is_current` or a vault key.
    /// # Errors
    /// Refuses another account, malformed refs/keys, key-ID mismatch or conflicting retry.
    pub fn import_full_mac_verifier(
        &mut self,
        source: &DeviceRef,
        id: &str,
        keys: &[u8],
    ) -> Result<(), StorageError> {
        import_into_private_generation(&self.db, source, id, keys)
    }
}

impl BackupDatabase {
    pub(in crate::account_db) fn merge_full_imported_mac_verifiers(
        &self,
        progress: &mut impl FnMut() -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let present:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name='full_imported_mac_bundle')",[],|row|row.get(0))?;
        if !present {
            return Ok(());
        }
        let mut statement=self.db.prepare("SELECT source_ref,bundle_id,subkeys FROM incoming.full_imported_mac_bundle ORDER BY source_ref,bundle_id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            progress()?;
            let source =
                decode_source_ref(row.get_ref(0)?.as_str().map_err(|_| invalid())?.as_bytes())?;
            let id = row.get_ref(1)?.as_str().map_err(|_| invalid())?;
            let keys = row.get_ref(2)?.as_blob().map_err(|_| invalid())?;
            import_into_private_generation(&self.db, &source, id, keys)?;
        }
        Ok(())
    }
}

pub(in crate::account_db) fn import_into_private_generation(
    db: &rusqlite::Connection,
    source: &DeviceRef,
    id: &str,
    keys: &[u8],
) -> Result<(), StorageError> {
    let source_key = source_key(source)?;
    let root: String = db.query_row(
        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if root != source.account_anchor || keys.len() != BUNDLE_BYTES || bundle_id(keys) != id {
        return Err(invalid());
    }
    let changed=db.execute("INSERT INTO full_imported_mac_bundle(source_ref,bundle_id,subkeys) VALUES(?1,?2,?3) ON CONFLICT(source_ref,bundle_id) DO UPDATE SET subkeys=excluded.subkeys WHERE full_imported_mac_bundle.subkeys=excluded.subkeys",params![source_key,id,keys])?;
    if changed != 1 {
        return Err(StorageError::PairingField("TransferConflict"));
    }
    Ok(())
}

impl AccountDb {
    /// Verify only an explicitly source-qualified marker bundle from the unlocked owner.
    /// The input buffer is moved onto the worker, with no additional plaintext input copy.
    /// One indexed row and at most 192 key bytes are resident regardless of bundle count.
    /// Original-author/denial/native provenance checks remain the typed marker owner's duty.
    /// # Errors
    /// Refuses stale/read-only/locked accounts, foreign sources, malformed inputs or corrupt keys.
    pub fn verify_full_imported_mac(
        &self,
        source: &DeviceRef,
        id: &str,
        domain: FullImportedMacDomain,
        input: Zeroizing<Vec<u8>>,
        expected: &str,
    ) -> Result<bool, StorageError> {
        self.require_selected_transfer_source()?;
        if self.connection.downgrade().upgrade_account_writer().is_none() {
            return Err(StorageError::AuthorizationRejected);
        }
        if source.account_anchor != self.principal_commitment {
            return Err(invalid());
        }
        if id.len() != 43 || expected.len() != 43 {
            return Err(invalid());
        }
        let source = source_key(source)?;
        let id_bytes = decode_base64url(id).map_err(|_| invalid())?;
        if id_bytes.len() != 32 || encode_base64url(&id_bytes) != id {
            return Err(invalid());
        }
        let decoded = decode_base64url(expected).map_err(|_| invalid())?;
        if decoded.len() != 32 || encode_base64url(&decoded) != expected {
            return Err(invalid());
        }
        let id = id.to_owned();
        let expected = expected.to_owned();
        let result=self.connection.call(move|db| {
            let check=||->Result<bool,StorageError> {
                let mut statement=db.prepare("SELECT subkeys FROM full_imported_mac_bundle WHERE source_ref=?1 AND bundle_id=?2")?;
                let mut rows=statement.query(params![source,id])?;
                let Some(row)=rows.next()? else {return Ok(false)};
                let bytes=row.get_ref(0)?.as_blob().map_err(|_|invalid())?;
                if bytes.len()!=BUNDLE_BYTES || bundle_id(bytes)!=id {return Err(invalid());}
                let mut keys=Zeroizing::new(vec![0;BUNDLE_BYTES].into_boxed_slice());
                keys.copy_from_slice(bytes);
                let bundle=Bundle{id,keys,current:false};
                let actual=bundle.mac(domain.label(),&input)?;
                Ok(bool::from(actual.as_bytes().ct_eq(expected.as_bytes())))
            };
            Ok(check())
        })??;
        self.require_selected_transfer_source()?;
        if self.connection.downgrade().upgrade_account_writer().is_none() {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(result)
    }
}
