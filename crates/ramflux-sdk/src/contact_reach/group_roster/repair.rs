// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded restart/restore bookkeeping repair after a complete authenticated state installation.
use super::{RamfluxClient, SdkError, StateRecord, Subject, pending};
use std::collections::BTreeSet;

const BATCH: usize = 32;
impl RamfluxClient {
    /// Stage a bounded page of roster/own-kick repairs from the verified mirror and adopted heads.
    /// Returns whether another page remains. A maintenance owner may call again to finish the
    /// cycle; no signature, RPC or allow is produced by this account-writer work.
    /// # Errors
    /// Keeps forked or missing authority pending; returns local storage and capacity failures.
    pub fn stage_reach_group_repairs(&self) -> Result<bool, SdkError> {
        let Some(mirror) = self.group_reach_mirror()? else {
            return Ok(false);
        };
        if mirror.conflict {
            return Err(pending());
        }
        let groups: BTreeSet<_> = mirror
            .records
            .iter()
            .filter_map(|record| match record {
                StateRecord::Grant { subject: Subject::Group { group_id, .. }, .. } => {
                    Some(group_id.clone())
                }
                _ => None,
            })
            .collect();
        if groups.is_empty() {
            return Ok(false);
        }
        let db = self.account_db()?;
        let cursor = db
            .client_record("reach", "group-repair-cursor")?
            .map(serde_json::from_value::<String>)
            .transpose()?
            .unwrap_or_default();
        let page: Vec<_> =
            groups.iter().filter(|group| *group > &cursor).take(BATCH).cloned().collect();
        for group in &page {
            db.write_transaction(|| {
                if let Some(state) = db.shared_group_state(group)? {
                    self.enqueue_reach_group_kick(&state)?;
                    self.enqueue_reach_group_roster(&state)?;
                }
                db.persist_client_record(
                    "reach",
                    "group-repair-cursor",
                    &serde_json::to_value(group)?,
                )?;
                Ok::<_, SdkError>(())
            })?;
        }
        let more = page.last().is_some_and(|last| groups.iter().any(|group| group > last));
        if !more {
            db.persist_client_record("reach", "group-repair-cursor", &serde_json::json!(""))?;
        }
        Ok(more)
    }
}
