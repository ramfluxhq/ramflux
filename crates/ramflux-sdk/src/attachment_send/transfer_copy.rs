// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-sent attachment plaintext that moves with the account snapshot.
//! The sealed prepare stays on the source device. A file over 1 MiB is left there.

use std::path::Path;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use ramflux_storage::{AccountDb, VaultSecretSource};

use crate::SdkError;
use crate::client::device_unlock::{DeviceBoundVaultSecret, DeviceSecret};
use crate::custody::PrimaryVault;

use super::budget::Meter;
use super::codes::{CODE_LAYOUT_INVALID, CODE_SEAL_FAILED, Refusal};
use super::import_job;
use super::store::Store;

/// `directory/attachment-own/{message}`: files this account sent, in media order.
pub(crate) const OWN_DIRECTORY: &str = "attachment-own";
const SENT_PREFIX: &str = "directory/attachment-send/";
/// Matches the export codec. A larger plaintext is not copied.
const MAX_BODY: u64 = 1_048_576;

/// Copies each own-sent file that fits into `directory/attachment-own/` before the snapshot pin.
///
/// # Errors
/// Returns the open or store error when a fitting file cannot be read. No sent files is success.
pub(crate) fn stage(
    db: &AccountDb,
    root: &Path,
    vault: &dyn PrimaryVault,
    account_id: &str,
) -> Result<(), SdkError> {
    let ids = db.list_actor_ids(SENT_PREFIX)?;
    if ids.is_empty() {
        return Ok(());
    }
    let secret = open_secret(root, vault, account_id)?;
    let parent = db.path.parent().ok_or(SdkError::AccountDbNotUnlocked)?;
    let store = Store::open(parent, account_id, *secret)?;
    for id in ids {
        if id.is_empty() || id.contains('/') {
            return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
        }
        write_message(db, &store, &id)?;
    }
    Ok(())
}

/// The copied plaintext for media `index`, when the snapshot carried one.
///
/// # Errors
/// `seal_failed` when the stored body does not match the message digest. Absence is `Ok(None)`.
pub(crate) fn copied(
    db: &AccountDb,
    message_id: &str,
    index: u64,
    length: u64,
    digest: &[u8; 32],
) -> Result<Option<Vec<u8>>, SdkError> {
    let Some(row) = db.client_record(OWN_DIRECTORY, message_id)? else {
        return Ok(None);
    };
    let Some(body) = file_body(&row, index) else {
        return Ok(None);
    };
    let Ok(expected) = usize::try_from(length) else {
        return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
    };
    if body.len() != expected {
        return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
    }
    if blake3::hash(&body).as_bytes() != digest {
        return Err(Refusal::new(CODE_SEAL_FAILED).into());
    }
    Ok(Some(body))
}

fn open_secret(
    root: &Path,
    vault: &dyn PrimaryVault,
    account_id: &str,
) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let bound = DeviceBoundVaultSecret::bind(root, vault, account_id, DeviceSecret::Load)?;
    Ok(Zeroizing::new(bound.vault_secret(account_id)?))
}

fn write_message(db: &AccountDb, store: &Store, message_id: &str) -> Result<(), SdkError> {
    let Some(record) = db.client_record("attachment-send", message_id)? else {
        return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
    };
    let prepares = prepare_ids(&record)?;
    let mut files = Vec::with_capacity(prepares.len());
    for (index, prepare_id) in prepares.iter().enumerate() {
        let row = store.load(prepare_id)?;
        let Some(length) = row.plaintext_length else {
            return Err(Refusal::new(CODE_SEAL_FAILED).into());
        };
        if length > MAX_BODY {
            return Ok(());
        }
        let plain = read_loaded(store, &row)?;
        let index = u64::try_from(index).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
        files.push(json!({ "index": index, "body": hex_encode(&plain) }));
    }
    if files.is_empty() {
        return Ok(());
    }
    db.persist_client_record(OWN_DIRECTORY, message_id, &json!({ "files": files }))?;
    Ok(())
}

fn prepare_ids(record: &Value) -> Result<Vec<String>, SdkError> {
    let Some(rows) = record.get("prepares").and_then(Value::as_array) else {
        return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
    };
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(id) = row.as_str() else {
            return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
        };
        if id.is_empty() {
            return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
        }
        ids.push(id.to_owned());
    }
    Ok(ids)
}

fn read_loaded(store: &Store, row: &super::meta::Row) -> Result<Vec<u8>, SdkError> {
    let mut plain = Vec::new();
    import_job::stream_owned(store, row, &mut plain, &|| false, &Meter::default())?;
    Ok(plain)
}

fn file_body(row: &Value, index: u64) -> Option<Vec<u8>> {
    let files = row.get("files")?.as_array()?;
    let position = usize::try_from(index).ok()?;
    let file = files.get(position)?;
    if file.get("index").and_then(Value::as_u64) != Some(index) {
        return None;
    }
    hex_decode(file.get("body").and_then(Value::as_str)?)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    out
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => '0',
    }
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    let mut index = 0;
    while index < raw.len() {
        let high = hex_value(*raw.get(index)?)?;
        let low = hex_value(*raw.get(index + 1)?)?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
