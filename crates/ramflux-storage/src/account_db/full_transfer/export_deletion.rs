// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Open deletion section after a tail's framed export. No new manifest field.
//! The bytes are domain, a count, then entries sorted by table name then key.
use crate::StorageError;
use crate::account_db::transfer_export::digest;

/// `ramflux.transfer.deletion.v1` — 28 bytes, same width as the snapshot domain.
pub(super) const DELETION_DOMAIN: &[u8; 28] = b"ramflux.transfer.deletion.v1";
const HEADER: usize = 28 + 8;
const ROW_LIMIT: usize = 1_048_576;
const KEY_LIMIT: usize = 2048;

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}

/// Parent keys that the tail file does not contain. An empty set is still 36 bytes.
/// # Errors
/// `ManifestMismatch` when a name is not exported or the keys are not strictly ordered.
pub(super) fn encode(keys: &[(String, Vec<u8>)]) -> Result<Vec<u8>, StorageError> {
    if keys.len() > ROW_LIMIT {
        return Err(mismatch());
    }
    let mut ordered = keys.to_vec();
    ordered.sort();
    ordered.dedup();
    if ordered.len() != keys.len() {
        return Err(mismatch());
    }
    let mut out = Vec::with_capacity(HEADER.saturating_add(ordered.len().saturating_mul(16)));
    out.extend_from_slice(DELETION_DOMAIN);
    let count = u64::try_from(ordered.len()).map_err(|_| mismatch())?;
    out.extend_from_slice(&count.to_be_bytes());
    let mut previous: Option<(&[u8], &[u8])> = None;
    for (table, key) in &ordered {
        push_entry(&mut out, table, key, &mut previous)?;
    }
    Ok(out)
}

fn push_entry<'a>(
    out: &mut Vec<u8>,
    table: &'a str,
    key: &'a [u8],
    previous: &mut Option<(&'a [u8], &'a [u8])>,
) -> Result<(), StorageError> {
    if digest::row_sql(table).is_err()
        || key.is_empty()
        || key.len() > KEY_LIMIT
        || table.len() > usize::from(u16::MAX)
    {
        return Err(mismatch());
    }
    if let Some((prev_table, prev_key)) = *previous
        && (table.as_bytes(), key) <= (prev_table, prev_key)
    {
        return Err(mismatch());
    }
    let name_len = u16::try_from(table.len()).map_err(|_| mismatch())?;
    let key_len = u16::try_from(key.len()).map_err(|_| mismatch())?;
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(table.as_bytes());
    out.extend_from_slice(&key_len.to_be_bytes());
    out.extend_from_slice(key);
    *previous = Some((table.as_bytes(), key));
    Ok(())
}

/// Decode a deletion section. The count is refused before the vector is allocated
/// when the remaining bytes cannot hold that many entries.
/// # Errors
/// `ManifestMismatch` for a short, unordered, duplicate, or unknown-table section.
pub(super) fn decode(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, StorageError> {
    if bytes.len() < HEADER || bytes.get(..28) != Some(DELETION_DOMAIN.as_slice()) {
        return Err(mismatch());
    }
    let count_bytes: [u8; 8] =
        bytes.get(28..36).ok_or_else(mismatch)?.try_into().map_err(|_| mismatch())?;
    let count = u64::from_be_bytes(count_bytes);
    if count > u64::try_from(ROW_LIMIT).map_err(|_| mismatch())? {
        return Err(mismatch());
    }
    let count = usize::try_from(count).map_err(|_| mismatch())?;
    let rest = bytes.len().saturating_sub(HEADER);
    if count > 0 && rest / 6 < count {
        return Err(mismatch());
    }
    let mut out = Vec::with_capacity(count);
    let mut at = HEADER;
    let mut previous: Option<(String, Vec<u8>)> = None;
    for _ in 0..count {
        let (table, key) = take_entry(bytes, &mut at)?;
        if previous.as_ref().is_some_and(|(prev_table, prev_key)| {
            (table.as_str(), key.as_slice()) <= (prev_table.as_str(), prev_key.as_slice())
        }) {
            return Err(mismatch());
        }
        previous = Some((table.clone(), key.clone()));
        out.push((table, key));
    }
    if at == bytes.len() { Ok(out) } else { Err(mismatch()) }
}

fn take_entry(bytes: &[u8], at: &mut usize) -> Result<(String, Vec<u8>), StorageError> {
    let name_len = u16::from_be_bytes(take(bytes, at, 2)?.try_into().map_err(|_| mismatch())?);
    let name = take(bytes, at, usize::from(name_len))?;
    let table = std::str::from_utf8(name).map_err(|_| mismatch())?;
    if digest::row_sql(table).is_err() {
        return Err(mismatch());
    }
    let key_len = u16::from_be_bytes(take(bytes, at, 2)?.try_into().map_err(|_| mismatch())?);
    if key_len == 0 || usize::from(key_len) > KEY_LIMIT {
        return Err(mismatch());
    }
    let key = take(bytes, at, usize::from(key_len))?.to_vec();
    Ok((table.to_owned(), key))
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, len: usize) -> Result<&'a [u8], StorageError> {
    let end = at.checked_add(len).ok_or_else(mismatch)?;
    let slice = bytes.get(*at..end).ok_or_else(mismatch)?;
    *at = end;
    Ok(slice)
}
