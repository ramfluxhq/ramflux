// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic public own-head adoption keeps independently held credentials and mode immutable.
use super::{MAX_STORED_AUTHORITY_BYTES, directory, invalid, load_data_account, write_public};
use crate::SdkError;
use ramflux_crypto::custody::PinOutcome;
use ramflux_protocol::custody::CustodyAuthority;
use std::{fs, os::unix::fs::OpenOptionsExt, path::Path};

pub(crate) fn accept_publication(
    root: &Path,
    id: &str,
    authority: &CustodyAuthority,
    now: u64,
) -> Result<PinOutcome, SdkError> {
    let verified = ramflux_crypto::custody::verify_publication(authority, now)?;
    let dir = directory(root, id)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(".authority.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let mut account = load_data_account(root, id, now)?;
    if verified.envelope().body.account_anchor != account.record().body.account_anchor {
        return Err(invalid());
    }
    let outcome = account.stored.pins.observe(&verified)?;
    if outcome == PinOutcome::Unchanged
        && account.stored.compacted_ids == authority.publication.compacted_ids
        && account.stored.custodian_publication.as_deref()
            == authority.custodian_publication.as_ref()
    {
        return Ok(outcome);
    }
    if outcome != PinOutcome::Fenced {
        account.stored.record = authority.publication.record.clone();
        account.stored.compacted_ids.clone_from(&authority.publication.compacted_ids);
        account.stored.custodian_publication =
            authority.custodian_publication.clone().map(Box::new);
        account.verified = verified;
    }
    let bytes = ramflux_protocol::canonical_json_bytes(&account.stored)?;
    if bytes.len() > MAX_STORED_AUTHORITY_BYTES {
        return Err(invalid());
    }
    let temp = dir.join(format!(
        ".authority-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let result = (|| -> Result<(), SdkError> {
        write_public(&temp, &bytes)?;
        fs::rename(&temp, dir.join("authority.json"))?;
        fs::File::open(&dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    Ok(outcome)
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;
