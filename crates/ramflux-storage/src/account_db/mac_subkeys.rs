// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted account MAC authority independent of database encryption keys.

use crate::{AccountDbKey, StorageError};
#[cfg(test)]
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
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
const SCHEMA: &str = "CREATE TABLE account_mac_bundle (
    bundle_id TEXT PRIMARY KEY,
    subkeys BLOB NOT NULL CHECK(length(subkeys)=192),
    is_current INTEGER NOT NULL CHECK(is_current IN (0,1))
); CREATE UNIQUE INDEX account_mac_current ON account_mac_bundle(is_current) WHERE is_current=1;";

#[cfg(test)]
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
    fn derive(seed: &[u8; 32]) -> Self {
        // RFC 5869 extract and single-block expand. Keep PRK, expansion output
        // and HMAC key pads in zeroizing storage, including early returns.
        let prk = keyed_hash(&[0; 32], &[seed]);
        let mut keys = Zeroizing::new([0; BUNDLE_BYTES]);
        for (index, label) in LABELS.iter().enumerate() {
            let output = keyed_hash(&prk, &[label, &[1]]);
            keys[index * 32..(index + 1) * 32].copy_from_slice(output.as_ref());
        }
        Self { id: bundle_id(keys.as_ref()), keys, current: true }
    }

    fn mac(&self, label: &[u8], value: &[u8]) -> Result<String, StorageError> {
        let index = LABELS
            .iter()
            .position(|known| *known == label)
            .ok_or(StorageError::AuthorizationRejected)?;
        let key: &[u8; 32] = self.keys[index * 32..(index + 1) * 32]
            .try_into()
            .map_err(|_| StorageError::AuthorizationRejected)?;
        let output = keyed_hash(key, &[value]);
        Ok(ramflux_protocol::encode_base64url(output.as_ref()))
    }
}

// HMAC-SHA256 for the fixed 32-byte keys used here. Explicit pads avoid
// unprotected key-pad temporaries in generic HMAC initialization. SHA-256's
// state and block buffer also zeroize on drop through the dependency feature.
fn keyed_hash(key: &[u8; 32], chunks: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut inner_pad = Zeroizing::new([0x36; 64]);
    let mut outer_pad = Zeroizing::new([0x5c; 64]);
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad.as_slice());
    for chunk in chunks {
        inner.update(chunk);
    }
    let mut inner_hash = Zeroizing::new([0; 32]);
    sha2::digest::FixedOutput::finalize_into(inner, (&mut *inner_hash).into());
    let mut outer = Sha256::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_hash.as_slice());
    let mut output = Zeroizing::new([0; 32]);
    sha2::digest::FixedOutput::finalize_into(outer, (&mut *output).into());
    output
}

fn bundle_id(keys: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"ramflux.account-mac-bundle.v1");
    hash.update(keys);
    ramflux_protocol::encode_base64url(hash.finalize())
}

fn load(db: &Connection) -> Result<Bundle, StorageError> {
    merge::load_set(db, "main")?
        .into_iter()
        .find(|b| b.current)
        .ok_or(StorageError::AuthorizationRejected)
}

pub(super) fn all_macs(
    db: &Connection,
    label: &[u8],
    value: &[u8],
) -> Result<Vec<String>, StorageError> {
    merge::load_set(db, "main")?.iter().map(|b| b.mac(label, value)).collect()
}

pub(super) mod merge;

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
        merge::validate(db)?;
        return Ok(());
    }
    // A half-initialized or malformed account must never acquire replacement authority.
    if exists {
        return Err(StorageError::AuthorizationRejected);
    }
    let bundle = if fresh {
        let seed = Zeroizing::new(ramflux_crypto::random_32()?);
        Bundle::derive(&seed)
    } else {
        Bundle::derive(key.bytes())
    };
    db.execute_batch(SCHEMA)?;
    db.execute(
        "INSERT INTO account_mac_bundle VALUES(?1,?2,1)",
        params![bundle.id, bundle.keys.as_slice()],
    )?;
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
    load(db)?.mac(label, value)
}

#[cfg(test)]
pub(super) mod tests;

#[cfg(test)]
mod restore_tests;
