// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retire a delivered intent only from a verified live result. Expired uncertain bytes remain
//! inactive candidates; retaining them never retries a mutation or authorizes publication.
use super::SignedUsernameChange;
use crate::SdkError;
use ramflux_protocol::username_directory as w;
use ramflux_storage::AccountDb;

pub(crate) fn settle_local_intent(
    db: &AccountDb,
    root: &str,
    status: &w::NativeUsernameStatus,
    now: u64,
) -> Result<(), SdkError> {
    let key = format!("username/intent/{root}");
    let Some(intent) = db.load_actor_state::<SignedUsernameChange>(&key)? else {
        return Ok(());
    };
    let confirmed = status.operation_receipt.as_ref().is_some_and(|receipt| {
        matches!(receipt.body.state, w::ReceiptState::Committed | w::ReceiptState::Aborted)
            && receipt.body.operation_id == intent.operation.body.operation_id
            && ramflux_crypto::username_directory::operation_hash(&intent.operation)
                .is_ok_and(|hash| hash == receipt.body.operation_hash)
    });
    if confirmed {
        db.remove_actor_state(&key)?;
        return Ok(());
    }
    if now < intent.operation.body.expires_at || status.state == w::NativeUsernameState::Pending {
        return Ok(());
    }
    db.write_transaction(|| {
        db.retain_username_candidate(&intent)?;
        db.remove_actor_state(&key)?;
        Ok::<_, SdkError>(())
    })
}
