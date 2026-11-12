// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic public own-head adoption keeps independently held credentials and mode immutable.
use super::{
    MAX_STORED_AUTHORITY_BYTES, create_private_temp, directory, invalid, load_data_account,
};
use crate::SdkError;
use ramflux_crypto::custody::PinOutcome;
use ramflux_protocol::custody::CustodyAuthority;
use std::{fs, path::Path};

/// Durable `pairing_head` is a fence: another operation must not mint a second candidate.
#[must_use]
pub(crate) fn pending_head_fence_blocks(
    pending_operation: Option<&str>,
    writer_operation: &str,
) -> bool {
    pending_operation.is_some_and(|operation| operation != writer_operation)
}

pub(crate) fn accept_publication(
    root: &Path,
    id: &str,
    authority: &CustodyAuthority,
    now: u64,
) -> Result<PinOutcome, SdkError> {
    let verified = ramflux_crypto::custody::verify_publication(authority, now)?;
    let dir = directory(root, id)?;
    let lock = crate::platform::fs::open_owner_only_read_write(&dir.join(".authority.lock"))?;
    crate::platform::fs::lock_exclusive(&lock)?;
    let mut account = load_data_account(root, id, now)?;
    if verified.envelope().body.account_anchor != account.record().body.account_anchor {
        return Err(invalid());
    }
    let outcome =
        account.stored.pins.observe_with_previous(&verified, Some(&account.stored.record))?;
    super::super::layer_declaration::remember_sequences(
        &mut account.stored.message_layer_sequences,
        &account.stored.record.body.account_anchor,
        &account.stored.record.body.devices,
    )?;
    if outcome == PinOutcome::Unchanged
        && account.stored.compacted_ids == authority.publication.compacted_ids
        && account.stored.custodian_publication.as_deref()
            == authority.custodian_publication.as_ref()
    {
        return Ok(outcome);
    }
    if !matches!(outcome, PinOutcome::Fenced(_)) {
        super::super::layer_declaration::remember_sequences(
            &mut account.stored.message_layer_sequences,
            &authority.publication.record.body.account_anchor,
            &authority.publication.record.body.devices,
        )?;
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
        create_private_temp(&temp, &bytes)?;
        fs::rename(&temp, dir.join("authority.json"))?;
        crate::platform::fs::sync_path(&dir)?;
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
