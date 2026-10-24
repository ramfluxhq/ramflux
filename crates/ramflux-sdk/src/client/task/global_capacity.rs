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
        for _ in 0..512 {
            let (retained_bytes, retained_events, largest) =
                db.task_aggregate_history_usage(&exclude)?;
            if retained_bytes.saturating_add(bytes) <= MAX_BYTES
                && retained_events.saturating_add(events) <= MAX_EVENTS
            {
                return Ok(());
            }
            let Some(largest) = largest else { break };
            let victim = db
                .task_lifecycle_rows(None, None, false)?
                .into_iter()
                .filter_map(|v| serde_json::from_value::<Lifecycle>(v).ok())
                .filter(|r| {
                    !(r.compacted || r.conversation_id == c.conversation_id && r.task_id == task)
                        && r.usage.get(&largest).is_some_and(|u| u.bytes > 0 || u.events > 0)
                })
                .max_by_key(|r| r.usage.get(&largest).map_or(0, |u| u.bytes));
            let Some(victim) = victim else { break };
            self.compact_task(&victim, false)?;
        }
        Err(crate::task_refusal::refused(
            TaskRefusalCode::TaskQuotaExhausted,
            "task aggregate history quota reached",
        ))
    }
}
