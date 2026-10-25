// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A restored archive can read immediately, but never sends under saved outbound chains.
use crate::{RamfluxClient, SdkError};
impl RamfluxClient {
    pub(crate) fn require_backup_outbound_ready(&self) -> Result<(), SdkError> {
        if self.account_db()?.load_actor_state::<bool>("backup/reestablishing")?.unwrap_or(false) {
            return Err(SdkError::InboundPending("re-establishing secure sessions".into()));
        }
        Ok(())
    }
    /// Called only after the fresh root-bound gateway activation has succeeded.
    pub(crate) fn complete_backup_activation(&self) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if !db.load_actor_state::<bool>("backup/reestablishing")?.unwrap_or(false) {
            return Ok(());
        }
        let previous = db
            .load_actor_state::<u64>("backup/previous-device-epoch")?
            .ok_or_else(|| SdkError::InboundPending("restore activation epoch missing".into()))?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if branch.device_epoch <= previous {
            return Err(SdkError::InboundPending(
                "restore requires fresh device activation".into(),
            ));
        }
        self.require_cached_root_authority(&self.owned_device_identity()?)?;
        db.write_transaction(||->Result<(),SdkError>{
            db.persist_actor_state("backup/reestablishing",&false)?;
            db.append_journal("backup:secure-sessions-ready","account.secure_sessions.changed",&serde_json::json!({"local_account_id":db.local_account_id,"secure_sessions":"ready"}),crate::prelude::now_unix_timestamp(),None)?;Ok(())
        })
    }
}
