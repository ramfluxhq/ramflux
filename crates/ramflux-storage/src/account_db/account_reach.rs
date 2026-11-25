// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed reach observation floors; cache contents never enable inbound traffic.
use super::AccountDb;
use crate::StorageError;
use ramflux_protocol::account_reach::ReachRecord;

impl AccountDb {
    /// # Errors
    /// Refuses invalid signatures, rollback, equivocation and unavailable encrypted storage.
    pub fn observe_account_reach(&self, record: &ReachRecord) -> Result<(), StorageError> {
        ramflux_crypto::account_reach::verify_reach_policy(&record.policy, &record.authority)
            .map_err(|_| StorageError::AuthorizationRejected)?;
        let key = format!("reach/floor/{}", record.policy.body.account_anchor);
        let fence = format!("reach/fence/{}", record.policy.body.account_anchor);
        let conflicted = self.write_transaction(|| {
            if self.load_actor_state::<bool>(&fence)?.unwrap_or(false) {
                return Err(StorageError::AuthorizationRejected);
            }
            if let Some(old) = self.load_actor_state::<ReachRecord>(&key)? {
                if record.policy.body.revision < old.policy.body.revision {
                    return Err(StorageError::AuthorizationRejected);
                }
                if record.policy.body.revision == old.policy.body.revision && record != &old {
                    self.persist_actor_state(&fence, &true)?;
                    return Ok(true);
                }
            }
            self.persist_actor_state(&key, record)?;
            Ok(false)
        })?;
        if conflicted {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(())
    }
}
