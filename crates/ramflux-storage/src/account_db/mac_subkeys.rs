// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted, bounded MAC authority independent of database encryption keys.

use crate::{AccountDbKey, StorageError};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::Sha256;
use zeroize::Zeroizing;

pub(crate) const VERSION: i64 = 14;
const CHECKSUM: &str = "2026-11-05-account-mac-subkeys-v1";
const LABELS: [&[u8]; 6] = [
    b"ramflux/tombstone-key/v1",
    b"ramflux/deleted-envelope/v1",
    b"ramflux/own-sent-index/v1",
    b"ramflux/own-sent-replay/v1",
    b"ramflux/own-sent-receipt/v1",
    b"ramflux/replay-key/v1",
];
const BUNDLE_BYTES: usize = 192;
const LIMIT: usize = 16;
const MARKER_FILTER: &str = "state_kind GLOB 'message/deleted/*' OR state_kind GLOB 'message/deleted-envelope/*' OR state_kind GLOB 'routed/seen/*' OR state_kind GLOB 'own-device/sent-*' OR state_kind GLOB 'own-device/imported-ciphertext/*'";
const SCHEMA: &str = "CREATE TABLE account_mac_bundle (
    bundle_id TEXT PRIMARY KEY,
    subkeys BLOB NOT NULL CHECK(length(subkeys)=192),
    is_current INTEGER NOT NULL CHECK(is_current IN (0,1))
); CREATE UNIQUE INDEX account_mac_current ON account_mac_bundle(is_current) WHERE is_current=1;
CREATE TABLE account_mac_marker_bundle(state_kind TEXT PRIMARY KEY,bundle_id TEXT NOT NULL REFERENCES account_mac_bundle(bundle_id));
CREATE TRIGGER account_mac_marker_insert AFTER INSERT ON runtime_actor_state
WHEN NEW.state_kind GLOB 'message/deleted/*' OR NEW.state_kind GLOB 'message/deleted-envelope/*' OR NEW.state_kind GLOB 'routed/seen/*' OR NEW.state_kind GLOB 'own-device/sent-*' OR NEW.state_kind GLOB 'own-device/imported-ciphertext/*'
BEGIN INSERT OR IGNORE INTO account_mac_marker_bundle SELECT NEW.state_kind,bundle_id FROM account_mac_bundle WHERE is_current=1; END;
CREATE TRIGGER account_mac_marker_delete AFTER DELETE ON runtime_actor_state
BEGIN DELETE FROM account_mac_marker_bundle WHERE state_kind=OLD.state_kind; END;";

type HmacSha256 = Hmac<Sha256>;

struct Bundle {
    id: String,
    keys: Zeroizing<[u8; BUNDLE_BYTES]>,
    current: bool,
}

impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MacSubkeyBundle([redacted])")
    }
}

impl Bundle {
    fn derive(seed: &[u8; 32]) -> Result<Self, StorageError> {
        // RFC 5869 extract and single-block expand. Own all exported KDF buffers
        // through Zeroizing, including the PRK and each expansion output.
        let mut extract = HmacSha256::new_from_slice(&[0; 32])
            .map_err(|_| StorageError::AuthorizationRejected)?;
        extract.update(seed);
        let prk = Zeroizing::new(<[u8; 32]>::from(extract.finalize().into_bytes()));
        let mut keys = Zeroizing::new([0; BUNDLE_BYTES]);
        for (index, label) in LABELS.iter().enumerate() {
            let mut expand = HmacSha256::new_from_slice(prk.as_ref())
                .map_err(|_| StorageError::AuthorizationRejected)?;
            expand.update(label);
            expand.update(&[1]);
            let output = Zeroizing::new(<[u8; 32]>::from(expand.finalize().into_bytes()));
            keys[index * 32..(index + 1) * 32].copy_from_slice(output.as_ref());
        }
        Ok(Self { id: bundle_id(keys.as_ref()), keys, current: true })
    }

    fn mac(&self, label: &[u8], value: &[u8]) -> Result<String, StorageError> {
        let index = LABELS
            .iter()
            .position(|known| *known == label)
            .ok_or(StorageError::AuthorizationRejected)?;
        let mut mac = HmacSha256::new_from_slice(&self.keys[index * 32..(index + 1) * 32])
            .map_err(|_| StorageError::AuthorizationRejected)?;
        mac.update(value);
        Ok(ramflux_protocol::encode_base64url(mac.finalize().into_bytes()))
    }
}

fn bundle_id(keys: &[u8]) -> String {
    ramflux_crypto::blake3_256_base64url("ramflux.account-mac-bundle.v1", keys)
}

fn load(db: &Connection, schema: &str) -> Result<Vec<Bundle>, StorageError> {
    // Only fixed, internal schema names can enter SQL identifiers.
    let table = match schema {
        "main" => "main.account_mac_bundle",
        "incoming" => "incoming.account_mac_bundle",
        _ => return Err(StorageError::AuthorizationRejected),
    };
    let valid: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.schema_migration WHERE schema_version=14 AND checksum=?1)"), [CHECKSUM], |r| r.get(0))?;
    if !valid {
        return Err(StorageError::AuthorizationRejected);
    }
    let mut query = db.prepare(&format!("SELECT bundle_id,subkeys,is_current FROM {table} ORDER BY is_current DESC,bundle_id LIMIT 17"))?;
    let mut rows = query.query([])?;
    let mut bundles = Vec::new();
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        // Borrow SQLite's encrypted-page result rather than creating an ordinary Vec.
        let bytes = row.get_ref(1)?.as_blob().map_err(|_| StorageError::AuthorizationRejected)?;
        if bytes.len() != BUNDLE_BYTES || bundle_id(bytes) != id {
            return Err(StorageError::AuthorizationRejected);
        }
        let flag: i64 = row.get(2)?;
        if !matches!(flag, 0 | 1) {
            return Err(StorageError::AuthorizationRejected);
        }
        let mut keys = Zeroizing::new([0; BUNDLE_BYTES]);
        keys.copy_from_slice(bytes);
        bundles.push(Bundle { id, keys, current: flag == 1 });
    }
    if bundles.is_empty()
        || bundles.len() > LIMIT
        || bundles.iter().filter(|b| b.current).count() != 1
    {
        return Err(StorageError::AuthorizationRejected);
    }
    let malformed: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.account_mac_marker_bundle m LEFT JOIN {table} b USING(bundle_id) WHERE b.bundle_id IS NULL)"), [], |r| r.get(0))?;
    if malformed {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(bundles)
}

pub(super) fn initialize(
    db: &mut Connection,
    key: &AccountDbKey,
    fresh: bool,
) -> Result<(), StorageError> {
    initialize_with_fault(db, key, fresh, false)
}

pub(super) fn initialize_managed(
    db: &crate::database::Connection,
    key: &AccountDbKey,
    fresh: bool,
) -> Result<(), StorageError> {
    let transaction = db.immediate_transaction()?;
    let key = key.clone();
    db.call(move |raw| Ok(initialize_inner(raw, &key, fresh, false)))??;
    transaction.commit()?;
    Ok(())
}

fn initialize_with_fault(
    db: &mut Connection,
    key: &AccountDbKey,
    fresh: bool,
    interrupt: bool,
) -> Result<(), StorageError> {
    let transaction = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    initialize_inner(&transaction, key, fresh, interrupt)?;
    transaction.commit()?;
    Ok(())
}

fn initialize_inner(
    db: &Connection,
    key: &AccountDbKey,
    fresh: bool,
    interrupt: bool,
) -> Result<(), StorageError> {
    let version: Option<String> = db
        .query_row("SELECT checksum FROM schema_migration WHERE schema_version=14", [], |r| {
            r.get(0)
        })
        .optional()?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='account_mac_bundle')",
        [],
        |r| r.get(0),
    )?;
    if let Some(checksum) = version {
        if checksum != CHECKSUM || !exists {
            return Err(StorageError::AuthorizationRejected);
        }
        load(db, "main")?;
        return Ok(());
    }
    // A half-initialized or malformed account must never acquire replacement authority.
    if exists {
        return Err(StorageError::AuthorizationRejected);
    }
    let bundle = if fresh {
        let seed = Zeroizing::new(ramflux_crypto::random_32()?);
        Bundle::derive(&seed)?
    } else {
        Bundle::derive(key.bytes())?
    };
    db.execute_batch(SCHEMA)?;
    db.execute(
        "INSERT INTO account_mac_bundle VALUES(?1,?2,1)",
        params![bundle.id, bundle.keys.as_slice()],
    )?;
    db.execute(&format!("INSERT INTO account_mac_marker_bundle SELECT state_kind,?1 FROM runtime_actor_state WHERE {MARKER_FILTER}"), [&bundle.id])?;
    if interrupt {
        return Err(StorageError::AuthorizationRejected);
    }
    db.execute(
        "INSERT INTO schema_migration VALUES(14,?1,'account-mac-v1',?2,'independent MAC subkeys')",
        params![crate::unix_now(), CHECKSUM],
    )?;
    Ok(())
}

pub(super) fn current_mac(
    db: &Connection,
    label: &[u8],
    value: &[u8],
) -> Result<String, StorageError> {
    load(db, "main")?
        .into_iter()
        .find(|b| b.current)
        .ok_or(StorageError::AuthorizationRejected)?
        .mac(label, value)
}

pub(super) fn all_macs(
    db: &Connection,
    label: &[u8],
    value: &[u8],
) -> Result<Vec<String>, StorageError> {
    load(db, "main")?.iter().map(|b| b.mac(label, value)).collect()
}

/// Called inside the enclosing merge transaction, before any generic row import.
pub(super) fn merge(db: &Connection) -> Result<(), StorageError> {
    let local = load(db, "main")?;
    let incoming = load(db, "incoming")?;
    let additional = incoming.iter().filter(|b| !local.iter().any(|l| l.id == b.id)).count();
    if local.len() + additional > LIMIT {
        return Err(StorageError::AuthorizationRejected);
    }
    let conflict: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM main.account_mac_marker_bundle l JOIN incoming.account_mac_marker_bundle r USING(state_kind) WHERE l.bundle_id<>r.bundle_id)", [], |r| r.get(0))?;
    if conflict {
        return Err(StorageError::AuthorizationRejected);
    }
    for bundle in incoming {
        // Ids authenticate complete ordered bundles, including transitive authority.
        db.execute(
            "INSERT OR IGNORE INTO main.account_mac_bundle VALUES(?1,?2,0)",
            params![bundle.id, bundle.keys.as_slice()],
        )?;
    }
    db.execute_batch("INSERT OR IGNORE INTO main.account_mac_marker_bundle SELECT * FROM incoming.account_mac_marker_bundle")?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests;
