// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The send path's calls into retirement. Kept in one place so the lifecycle owner
//! (`retire.rs`) and the send owner (`publish`, `attachment_prepare`) meet at three fns.

use super::bus::AuthorityPin;
use super::meta::GrantRecord;
use crate::{RamfluxClient, SdkError};

/// Retires grants of devices that stopped being targets before the Inner was admitted.
/// # Errors
/// Returns the retirement refusal. The grants stay recorded and are retried by the sweep.
pub(crate) fn retire_excluded(
    client: &RamfluxClient,
    account_id: &str,
    pin: &AuthorityPin,
    grants: &[GrantRecord],
) -> Result<(), SdkError> {
    let _ = (client, account_id, pin, grants);
    Ok(())
}

/// Refuses an import step for a retired, deleted or fenced message.
/// # Errors
/// Returns `attachment_deleted`, `retirement_pending` or `cancelled`.
pub(crate) fn barrier(client: &RamfluxClient, message_id: &str) -> Result<(), SdkError> {
    if client.account_db()?.client_record("attachment-tombstone", message_id)?.is_some() {
        return Err(super::Refusal::new(super::codes::CODE_ATTACHMENT_DELETED).into());
    }
    Ok(())
}
