// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-wide retained event budgets reclaim history from its largest authenticated signer.
use super::{carrier::Carrier, lifecycle::Lifecycle, quota::Usage, scoped};
use crate::{RamfluxClient, SdkError, TaskRefusalCode};
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVENTS: u64 = 32768;
impl RamfluxClient {
    pub(super) fn admit_global_task_history(
        &self,
        c: &Carrier,
        current: &std::collections::BTreeMap<String, Usage>,
        control: bool,
    ) -> Result<(), SdkError> {
        if control {
            return Ok(());
        }
        let task = c.event()?.event().task_id().to_owned();
        let exclude = scoped("lifecycle", &c.conversation_id, &task)?;
        let bytes = current.values().map(|u| u.bytes).sum::<u64>();
        let events = current.values().map(|u| u.events).sum::<u64>();
        let db = self.account_db()?;
        let (retained_bytes, retained_events, _) = db.task_aggregate_history_usage(&exclude)?;
        if retained_bytes.saturating_add(bytes) <= MAX_BYTES
            && retained_events.saturating_add(events) <= MAX_EVENTS
        {
            return Ok(());
        }
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id;
        let mut candidates = Vec::new();
        for value in db.task_lifecycle_rows(None, None, false)? {
            let warning_key = crate::task_warnings::row_key(&value);
            let row: Lifecycle = match serde_json::from_value(value) {
                Ok(row) => row,
                Err(error) => {
                    crate::task_warnings::warn(
                        &warning_key,
                        &SdkError::from(error),
                        "malformed lifecycle row skipped during compaction",
                    );
                    continue;
                }
            };
            if row.compacted || row.conversation_id == c.conversation_id && row.task_id == task {
                continue;
            }
            let view = db
                .load_actor_state::<serde_json::Value>(&scoped(
                    "view",
                    &row.conversation_id,
                    &row.task_id,
                )?)?
                .unwrap_or_default();
            if !row.terminal && (view["requester"] == *local || view["assignee"] == *local) {
                continue;
            }
            candidates.push(row);
        }
        for _ in 0..512 {
            let (retained_bytes, retained_events, largest) =
                db.task_aggregate_history_usage(&exclude)?;
            if retained_bytes.saturating_add(bytes) <= MAX_BYTES
                && retained_events.saturating_add(events) <= MAX_EVENTS
            {
                return Ok(());
            }
            let victim = candidates.iter().enumerate().max_by_key(|(_, row)| {
                (
                    row.terminal,
                    largest.as_ref().is_some_and(|source| {
                        row.usage.get(source).is_some_and(|u| u.bytes > 0 || u.events > 0)
                    }),
                    row.bytes,
                )
            });
            let Some((index, _)) = victim else { break };
            let victim = candidates.swap_remove(index);
            crate::error_policy::task_scan(
                &scoped("lifecycle", &victim.conversation_id, &victim.task_id)?,
                self.compact_task(&victim, false),
            )?;
        }
        Err(crate::task_refusal::refused(
            TaskRefusalCode::TaskQuotaExhausted,
            "task aggregate history quota reached",
        ))
    }
}
