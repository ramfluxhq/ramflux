// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Event-signer resource accounting and independent requester recovery headroom.
use super::{TaskHistory, carrier::Carrier, lifecycle::Lifecycle, scoped};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::TaskEventBody;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
const SIGNER_QUOTA: &str = "task signer history quota reached";
#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct Usage {
    pub(super) bytes: u64,
    pub(super) events: u64,
    decisions: u64,
    decision_bytes: u64,
    cancel_bytes: u64,
}
impl Usage {
    pub(super) fn charge(
        &mut self,
        carrier: &Carrier,
        bytes: u64,
        requester: Option<&str>,
    ) -> Result<(), SdkError> {
        match carrier.event()?.event() {
            TaskEventBody::Cancel(_) if requester == Some(&carrier.principal_id) => {
                self.cancel_bytes = self.cancel_bytes.saturating_add(bytes);
            }
            TaskEventBody::Resolve(_) if requester == Some(&carrier.principal_id) => {
                self.decisions += 1;
                self.decision_bytes = self.decision_bytes.saturating_add(bytes);
            }
            _ => {
                self.events += 1;
                self.bytes = self.bytes.saturating_add(bytes);
            }
        }
        Ok(())
    }
    fn add(&mut self, other: &Self) {
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.events = self.events.saturating_add(other.events);
        self.decisions = self.decisions.saturating_add(other.decisions);
        self.decision_bytes = self.decision_bytes.saturating_add(other.decision_bytes);
    }
}
// Histories reaching accounting have already passed reduction and signature verification.
// Recover the requester from accepted signer metadata, never an unsigned role claim.
fn history_requester(history: &TaskHistory) -> Result<Option<String>, SdkError> {
    if let Some(checkpoint) = &history.checkpoint {
        return Ok(checkpoint.state.task().and_then(|t| t.requester.clone()));
    }
    for accepted in &history.events {
        if matches!(
            accepted.carrier.event()?.event(),
            TaskEventBody::Start(_) | TaskEventBody::Accept(_)
        ) {
            return Ok(Some(accepted.carrier.principal_id.clone()));
        }
    }
    Ok(None)
}
pub(super) fn history_usage(history: &TaskHistory) -> Result<BTreeMap<String, Usage>, SdkError> {
    let requester = history_requester(history)?;
    let mut usage = BTreeMap::<String, Usage>::new();
    for accepted in &history.events {
        usage.entry(accepted.carrier.principal_id.clone()).or_default().charge(
            &accepted.carrier,
            u64::try_from(serde_json::to_vec(accepted)?.len()).unwrap_or(u64::MAX),
            requester.as_deref(),
        )?;
    }
    Ok(usage)
}
impl RamfluxClient {
    pub(super) fn is_requester_task_control(
        c: &Carrier,
        history: &TaskHistory,
    ) -> Result<bool, SdkError> {
        Ok(matches!(c.event()?.event(), TaskEventBody::Cancel(_) | TaskEventBody::Resolve(_))
            && history
                .state()?
                .task()
                .is_some_and(|t| t.requester.as_deref() == Some(&c.principal_id)))
    }
    pub(super) fn check_task_capacity(
        &self,
        c: &Carrier,
        history: &TaskHistory,
    ) -> Result<(), SdkError> {
        let id = c.event()?.event().task_id().to_owned();
        let control = Self::is_requester_task_control(c, history)?;
        let db = self.account_db()?;
        let existing =
            db.load_actor_state::<Lifecycle>(&scoped("lifecycle", &c.conversation_id, &id)?)?;
        if existing.as_ref().is_some_and(|r| r.compaction_eligible)
            && matches!(c.event()?.event(), TaskEventBody::Update(_))
        {
            return Err(crate::task_refusal::refused(
                crate::TaskRefusalCode::TaskStalled,
                SIGNER_QUOTA,
            ));
        }
        if existing.as_ref().is_some_and(|r| r.compacted) && !control {
            return Err(crate::task_refusal::refused(
                crate::TaskRefusalCode::TaskStalled,
                "task history has been archived",
            ));
        }
        let mut usage = history_usage(history)?;
        if !history.events.iter().any(|e| {
            e.carrier.message_id == c.message_id && e.carrier.principal_id == c.principal_id
        }) {
            let requester = history_requester(history)?;
            usage.entry(c.principal_id.clone()).or_default().charge(
                c,
                u64::try_from(c.bytes()?.len()).unwrap_or(u64::MAX),
                requester.as_deref(),
            )?;
        }
        let current = usage.get(&c.principal_id).cloned().unwrap_or_default();
        // Cancellation has its own small, event-local bound, never the executor's history quota.
        if control && matches!(c.event()?.event(), TaskEventBody::Cancel(_)) {
            return if current.cancel_bytes <= 16 * 1024 {
                Ok(())
            } else {
                Err(crate::task_refusal::refused(
                    crate::TaskRefusalCode::TaskQuotaExhausted,
                    "task cancel byte quota reached",
                ))
            };
        }
        let index = scoped("lifecycle", &c.conversation_id, &id)?;
        let totals = |conversation| -> Result<Usage, SdkError> {
            let [bytes, events, decisions, decision_bytes] =
                db.task_signer_usage(&c.principal_id, conversation, &index)?.ok_or_else(|| {
                    SdkError::InboundPending(
                        "task signer accounting upgrade awaits its remaining histories".into(),
                    )
                })?;
            let mut total = current.clone();
            total.add(&Usage { bytes, events, decisions, decision_bytes, cancel_bytes: 0 });
            Ok(total)
        };
        let total = totals(None)?;
        let conversation = totals(Some(c.conversation_id.as_str()))?;
        let active = db
            .task_lifecycle_rows(Some(&c.principal_id), None, false)?
            .into_iter()
            .filter(|r| {
                r["terminal"] == false
                    && !(r["task_id"] == id && r["conversation_id"] == c.conversation_id)
            })
            .collect::<Vec<_>>();
        let local_active =
            active.iter().filter(|r| r["conversation_id"] == c.conversation_id).count();
        if control {
            if current.decisions > 32
                || current.decision_bytes > 64 * 1024
                || total.decisions > 512
                || total.decision_bytes > 1024 * 1024
            {
                return Err(crate::task_refusal::refused(
                    crate::TaskRefusalCode::SignerQuotaExhausted,
                    "task requester decision quota reached",
                ));
            }
        } else if total.bytes > 8 * 1024 * 1024
            || conversation.bytes > 8 * 1024 * 1024
            || total.events > 8192
            || conversation.events > 4096
            || (matches!(c.event()?.event(), TaskEventBody::Start(_) | TaskEventBody::Proposal(_))
                && (active.len() >= 32 || local_active >= 16))
        {
            return Err(crate::task_refusal::refused(
                crate::TaskRefusalCode::SignerQuotaExhausted,
                SIGNER_QUOTA,
            ));
        }
        self.admit_global_task_history(c, history)
    }
    pub(super) fn record_task_capacity_rejection(
        &self,
        c: &Carrier,
        error: &SdkError,
    ) -> Result<(), SdkError> {
        let all = match error {
            SdkError::TaskRefused {
                reason: crate::TaskRefusalCode::SignerQuotaExhausted, ..
            } => true,
            SdkError::TaskRefused {
                reason: crate::TaskRefusalCode::TaskQuotaExhausted, ..
            } => false,
            _ => return Ok(()),
        };
        if !matches!(c.event()?.event(), TaskEventBody::Update(_)) {
            return Ok(());
        }
        let rejected_id = c.event()?.event().task_id().to_owned();
        let db = self.account_db()?;
        for value in db.task_lifecycle_rows(None, None, false)? {
            let mut row: Lifecycle = serde_json::from_value(value)?;
            let view_key = scoped("view", &row.conversation_id, &row.task_id)?;
            let Some(mut view) = db.load_actor_state::<Value>(&view_key)? else { continue };
            if row.terminal
                || row.compacted
                || row.compaction_eligible
                || view["assignee"] != c.principal_id
                || (!all
                    && (row.task_id != rejected_id || row.conversation_id != c.conversation_id))
            {
                continue;
            }
            if row.usage.is_empty() && row.bytes > 0 {
                row.usage = history_usage(&self.task_history(&row.conversation_id, &row.task_id)?)?;
            }
            row.compaction_eligible = true;
            view["stalled_by_assignee"] = json!(true);
            view["progress_state"] = json!("stalled by assignee");
            db.persist_actor_state(
                &scoped("lifecycle", &row.conversation_id, &row.task_id)?,
                &row,
            )?;
            db.persist_actor_state(&view_key, &view)?;
            db.append_journal(&format!("task-stalled:{}:{}", c.principal_id, scoped("event", &row.conversation_id, &row.task_id)?), "task.changed", &json!({"conversation_id":row.conversation_id,"task_id":row.task_id,"stalled_by_assignee":true}), crate::time::now_unix_timestamp(), None)?;
        }
        Ok(())
    }
    pub(super) fn admit_task_event(&self, c: &Carrier, now: i64) -> Result<(), SdkError> {
        let history = self.task_history(&c.conversation_id, c.event()?.event().task_id())?;
        let recovery = Self::is_requester_task_control(c, &history)?;
        let scopes = if recovery {
            let class = if matches!(c.event()?.event(), TaskEventBody::Cancel(_)) {
                "cancel"
            } else {
                "resolve"
            };
            vec![
                (format!("{class}:{}", c.principal_id), 64),
                (
                    format!(
                        "{class}:{}:{}:{}",
                        c.principal_id,
                        c.conversation_id,
                        c.event()?.event().task_id()
                    ),
                    8,
                ),
            ]
        } else {
            vec![
                (format!("account:{}", c.principal_id), 512),
                (format!("principal:{}", c.principal_id), 128),
                (
                    format!(
                        "task:{}:{}:{}",
                        c.conversation_id,
                        c.event()?.event().task_id(),
                        c.principal_id
                    ),
                    64,
                ),
            ]
        };
        let db = self.account_db()?;
        for (scope, maximum) in scopes {
            let key = super::key("rate", &scope);
            let mut rate = db
                .load_actor_state::<Value>(&key)?
                .unwrap_or_else(|| json!({"start":now,"count":0}));
            if now.saturating_sub(rate["start"].as_i64().unwrap_or(now)) >= 60 {
                rate = json!({"start":now,"count":0});
            }
            let count = rate["count"].as_u64().unwrap_or(0);
            if count >= maximum {
                return Err(crate::task_refusal::refused(
                    crate::TaskRefusalCode::RateLimited,
                    "task admission rate exceeded",
                ));
            }
            rate["count"] = json!(count + 1);
            db.persist_actor_state(&key, &rate)?;
        }
        db.prune_task_diagnostics("task/rate/", 2048)?;
        Ok(())
    }
}
