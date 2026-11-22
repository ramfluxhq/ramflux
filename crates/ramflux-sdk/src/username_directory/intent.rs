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
    let inactive_key = format!("username/inactive/{root}");
    db.write_transaction(|| {
        let mut candidates =
            db.load_actor_state::<Vec<SignedUsernameChange>>(&inactive_key)?.unwrap_or_default();
        if let Some(old) = candidates
            .iter()
            .find(|old| old.operation.body.operation_id == intent.operation.body.operation_id)
        {
            if old.operation != intent.operation
                || old.profile != intent.profile
                || old.center != intent.center
            {
                return Err(w::DirectoryCode::ProfileEquivocation.into());
            }
        } else {
            if candidates.len() >= 8 {
                return Err(w::DirectoryCode::Capacity.into());
            }
            candidates.push(intent);
        }
        if serde_json::to_vec(&candidates)?.len() > 131_072 {
            return Err(w::DirectoryCode::Capacity.into());
        }
        db.persist_actor_state(&inactive_key, &candidates)?;
        db.remove_actor_state(&key)?;
        Ok::<_, SdkError>(())
    })
}
