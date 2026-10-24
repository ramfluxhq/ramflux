// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer-scoped task capacity and terminal compaction without forgetting consumed decisions.
use super::{TaskHistory, invalid, scoped};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::Task;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
const DAY: i64 = 24 * 60 * 60;
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Lifecycle {
    pub conversation_id: String,
    pub task_id: String,
    pub source: String,
    #[serde(default)]
    pub retention_source: Option<String>,
    pub terminal: bool,
    pub compacted: bool,
    pub updated_at: i64,
    pub bytes: u64,
    pub related: Vec<String>,
    #[serde(default)]
    pub usage: std::collections::BTreeMap<String, super::quota::Usage>,
    #[serde(default)]
    pub compaction_eligible: bool,
}
impl RamfluxClient {
    pub(super) fn task_is_archived(&self, conversation: &str, id: &str) -> Result<bool, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<Lifecycle>(&scoped("lifecycle", conversation, id)?)?
            .is_some_and(|row| row.compacted && row.terminal))
    }
    pub(super) fn record_task_lifecycle(
        &self,
        task: &Task,
        history: &TaskHistory,
    ) -> Result<(), SdkError> {
        let first = history.events.first().ok_or_else(|| invalid("task history is empty"))?;
        let mut related = Vec::new();
        for event in &history.events {
            let c = &event.carrier;
            related.push(scoped(
                "receipt",
                &c.conversation_id,
                &serde_json::to_string(&(&c.principal_id, &c.message_id))?,
            )?);
            related.push(scoped("message", &c.conversation_id, &c.message_id)?);
            related.push(scoped("message", &c.conversation_id, &super::timeline_id(c)?)?);
            if let Some(cert) = &event.decision_certificate {
                related.push(super::certificate::committed_key(
                    c,
                    &cert.assignee,
                    &cert.issuer_device,
                )?);
            }
        }
        let previous = self.account_db()?.load_actor_state::<Lifecycle>(&scoped(
            "lifecycle",
            &task.conversation_id,
            &task.task_id,
        )?)?;
        let row = Lifecycle {
            conversation_id: task.conversation_id.clone(),
            task_id: task.task_id.clone(),
            source: previous
                .as_ref()
                .map_or_else(|| first.carrier.principal_id.clone(), |row| row.source.clone()),
            retention_source: Some({
                let local =
                    &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id;
                if task.requester.as_deref() == Some(local)
                    || (task.assignee == *local
                        && history.events.iter().any(|e| e.carrier.principal_id == *local))
                {
                    local.clone()
                } else {
                    previous
                        .as_ref()
                        .and_then(|r| r.retention_source.clone())
                        .unwrap_or_else(|| first.carrier.principal_id.clone())
                }
            }),
            terminal: task.state.is_terminal(),
            compacted: false,
            updated_at: crate::time::now_unix_timestamp(),
            bytes: u64::try_from(serde_json::to_vec(history)?.len()).unwrap_or(u64::MAX),
            related,
            usage: super::quota::history_usage(history)?,
            compaction_eligible: previous.as_ref().is_some_and(|row| row.compaction_eligible),
        };
        self.account_db()?.persist_actor_state(
            &scoped("lifecycle", &task.conversation_id, &task.task_id)?,
            &row,
        )?;
        if row.terminal
            && (history.checkpoint.is_some() || previous.is_some_and(|r| r.compaction_eligible))
        {
            self.compact_task(&row, false)?;
        }
        self.maintain_task_conversation(
            &task.conversation_id,
            row.updated_at,
            row.retention_source.as_deref(),
        )?;
        self.maintain_task_source(row.retention_source.as_deref().unwrap_or(&row.source))?;
        self.account_db()?.prune_task_certificates(row.updated_at)?;
        Ok(())
    }
    fn task_retention_source(&self, row: &mut Lifecycle) -> Result<String, SdkError> {
        if let Some(source) = &row.retention_source {
            return Ok(source.clone());
        }
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id;
        let view = self
            .account_db()?
            .load_actor_state::<Value>(&scoped("view", &row.conversation_id, &row.task_id)?)?
            .unwrap_or(Value::Null);
        let participated = view["requester"] == *local
            || (view["assignee"] == *local
                && self
                    .task_history(&row.conversation_id, &row.task_id)?
                    .events
                    .iter()
                    .any(|e| e.carrier.principal_id == *local));
        let source = if participated { local.clone() } else { row.source.clone() };
        if row.usage.is_empty() && row.bytes > 0 {
            row.usage = super::quota::history_usage(
                &self.task_history(&row.conversation_id, &row.task_id)?,
            )?;
        }
        row.retention_source = Some(source.clone());
        self.account_db()?
            .persist_actor_state(&scoped("lifecycle", &row.conversation_id, &row.task_id)?, row)?;
        Ok(source)
    }
    fn maintain_task_source(&self, source: &str) -> Result<(), SdkError> {
        let rows = self.account_db()?.task_retention_rows(Some(source), None)?;
        let mut rank = 0;
        for value in rows {
            let mut row: Lifecycle = serde_json::from_value(value)?;
            if self.task_retention_source(&mut row)? != source {
                continue;
            }
            if rank >= 128 {
                self.compact_task(&row, true)?;
            } else if rank >= 32 && !row.compacted {
                self.compact_task(&row, false)?;
            }
            rank += 1;
        }
        Ok(())
    }
    fn maintain_task_conversation(
        &self,
        conversation: &str,
        now: i64,
        owner: Option<&str>,
    ) -> Result<(), SdkError> {
        let mut owners = std::collections::BTreeSet::new();
        if let Some(owner) = owner {
            owners.insert(owner.to_owned());
        } else {
            for value in self.account_db()?.task_retention_rows(None, Some(conversation))? {
                let mut row: Lifecycle = serde_json::from_value(value)?;
                owners.insert(self.task_retention_source(&mut row)?);
            }
        }
        for owner in owners {
            let mut rank = 0;
            for value in self.account_db()?.task_retention_rows(Some(&owner), Some(conversation))? {
                let mut row: Lifecycle = serde_json::from_value(value)?;
                if self.task_retention_source(&mut row)? != owner {
                    continue;
                }
                if rank >= 128 || now.saturating_sub(row.updated_at) >= 90 * DAY {
                    self.compact_task(&row, true)?;
                } else if !row.compacted
                    && (rank >= 16 || now.saturating_sub(row.updated_at) >= 7 * DAY)
                {
                    self.compact_task(&row, false)?;
                }
                rank += 1;
            }
        }
        Ok(())
    }
    pub(super) fn migrate_task_lifecycle(&self, now: i64) -> Result<(), SdkError> {
        for history in self.account_db()?.unindexed_task_histories::<TaskHistory>()? {
            if let Some(task) = history.state()?.task() {
                self.record_task_lifecycle(task, &history)?;
                let key = scoped("lifecycle", &task.conversation_id, &task.task_id)?;
                if let Some(mut row) = self.account_db()?.load_actor_state::<Lifecycle>(&key)? {
                    row.updated_at = history.updated_at.min(now);
                    self.account_db()?.persist_actor_state(&key, &row)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn maintain_task_lifecycle(&self, now: i64) -> Result<(), SdkError> {
        self.migrate_task_lifecycle(now)?;
        let rows = self.account_db()?.task_lifecycle_rows(None, None, false)?;
        for value in &rows {
            let row: Lifecycle = serde_json::from_value(value.clone())?;
            if row.compaction_eligible && !row.compacted {
                self.compact_task(&row, false)?;
            }
        }
        let conversations = rows
            .iter()
            .filter_map(|r| r["conversation_id"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for conversation in conversations {
            self.maintain_task_conversation(conversation, now, None)?;
        }
        self.account_db()?.prune_task_certificates(now)?;
        Ok(())
    }
    fn compact_task(&self, row: &Lifecycle, prune: bool) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let history = self.task_history(&row.conversation_id, &row.task_id)?;
            let checkpoint = scoped("checkpoint", &row.conversation_id, &row.task_id)?;
            if row.terminal {
                db.delete_task_state(&checkpoint)?;
            } else {
                db.persist_actor_state(&checkpoint, &history.local_checkpoint()?)?;
            }
            let hashes = history.certificate_hashes()?;
            for related in &row.related {
                db.delete_task_state(related)?;
            }
            db.delete_task_state(&scoped("history", &row.conversation_id, &row.task_id)?)?;
            let view_key = scoped("view", &row.conversation_id, &row.task_id)?;
            let index_key = scoped("lifecycle", &row.conversation_id, &row.task_id)?;
            if prune {
                db.delete_task_state(&view_key)?;
                db.delete_task_state(&index_key)?;
            } else {
                let mut view = db.load_actor_state::<Value>(&view_key)?.unwrap_or(Value::Null);
                view["compacted"] = json!(true);
                view["certificate_hashes"] = json!(hashes);
                db.persist_actor_state(&view_key, &view)?;
                let mut compact = row.clone();
                compact.compacted = true;
                compact.bytes = 0;
                compact.related.clear();
                compact.usage.clear();
                compact.compaction_eligible = false;
                db.persist_actor_state(&index_key, &compact)?;
            }
            Ok(())
        })
    }
}
