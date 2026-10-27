// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attribution follows the message lifetime, independently of receipt bookkeeping.
use super::super::AccountDb;
use crate::StorageError;

pub(in crate::account_db) fn message_origin_key(
    conversation: &str,
    message: &str,
) -> Result<String, StorageError> {
    Ok(format!(
        "message/origin/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.delivery-receipt.v1",
            &ramflux_protocol::canonical_json_bytes(&(conversation, message, ""))?
        )
    ))
}

impl AccountDb {
    pub(in crate::account_db) fn remove_message_origin(
        &self,
        conversation: &str,
        message: &str,
    ) -> Result<(), StorageError> {
        let key = message_origin_key(conversation, message)?;
        self.remove_actor_state(&key)?;
        self.connection.execute(
            "DELETE FROM runtime_receipt_retention WHERE state_kind=?1",
            rusqlite::params![key],
        )?;
        Ok(())
    }
}
