// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer-scoped task capacity and terminal compaction without forgetting consumed decisions.
use super::{TaskHistory, carrier::Carrier, invalid, scoped};
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
    pub terminal: bool,
    pub compacted: bool,
    pub updated_at: i64,
    pub bytes: u64,
    pub related: Vec<String>,
}
impl RamfluxClient {
    pub(super) fn task_is_archived(&self, conversation: &str, id: &str) -> Result<bool, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<Lifecycle>(&scoped("lifecycle", conversation, id)?)?
            .is_some_and(|row| row.compacted))
    }
    pub(super) fn check_task_capacity(
        &self,
        carrier: &Carrier,
        history: &TaskHistory,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let id = carrier.event()?.event().task_id().to_owned();
        if self.task_is_archived(&carrier.conversation_id, &id)? {
            return Err(invalid("task history has been archived"));
        }
        let first = history.events.first().map_or(carrier, |e| &e.carrier);
        let rows = db.task_lifecycle_rows(Some(&first.principal_id), None, false)?;
        let others = rows
            .iter()
            .filter(|r| !(r["task_id"] == id && r["conversation_id"] == carrier.conversation_id))
            .collect::<Vec<_>>();
        let active = others.iter().filter(|r| r["terminal"] == false).collect::<Vec<_>>();
        let bytes: u64 = others.iter().map(|r| r["bytes"].as_u64().unwrap_or(0)).sum();
        if (history.events.len() <= 1
            && (active.len() >= 32
                || active
                    .iter()
                    .filter(|r| r["conversation_id"] == carrier.conversation_id)
                    .count()
                    >= 16))
            || bytes.saturating_add(
                u64::try_from(serde_json::to_vec(history)?.len()).unwrap_or(u64::MAX),
            ) > 8 * 1024 * 1024
        {
            return Err(invalid("task source history quota reached"));
        }
        Ok(())
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
        let row = Lifecycle {
            conversation_id: task.conversation_id.clone(),
            task_id: task.task_id.clone(),
            source: first.carrier.principal_id.clone(),
            terminal: task.state.is_terminal(),
            compacted: false,
            updated_at: crate::time::now_unix_timestamp(),
            bytes: u64::try_from(serde_json::to_vec(history)?.len()).unwrap_or(u64::MAX),
            related,
        };
        self.account_db()?.persist_actor_state(
            &scoped("lifecycle", &task.conversation_id, &task.task_id)?,
            &row,
        )?;
        self.maintain_task_conversation(&task.conversation_id, row.updated_at)?;
        self.maintain_task_source(&row.source)?;
        self.account_db()?.prune_task_certificates(row.updated_at)?;
        Ok(())
    }
    fn maintain_task_source(&self, source: &str) -> Result<(), SdkError> {
        let rows = self.account_db()?.task_lifecycle_rows(Some(source), None, true)?;
        for (rank, value) in rows.into_iter().enumerate() {
            let row: Lifecycle = serde_json::from_value(value)?;
            if rank >= 128 {
                self.compact_task(&row, true)?;
            } else if rank >= 32 && !row.compacted {
                self.compact_task(&row, false)?;
            }
        }
        Ok(())
    }
    fn maintain_task_conversation(&self, conversation: &str, now: i64) -> Result<(), SdkError> {
        let rows = self.account_db()?.task_lifecycle_rows(None, Some(conversation), true)?;
        for (rank, value) in rows.into_iter().enumerate() {
            let row: Lifecycle = serde_json::from_value(value)?;
            if rank >= 128 || now.saturating_sub(row.updated_at) >= 90 * DAY {
                self.compact_task(&row, true)?;
            } else if !row.compacted
                && (rank >= 16 || now.saturating_sub(row.updated_at) >= 7 * DAY)
            {
                self.compact_task(&row, false)?;
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
        let rows = self.account_db()?.task_lifecycle_rows(None, None, true)?;
        let conversations = rows
            .iter()
            .filter_map(|r| r["conversation_id"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for conversation in conversations {
            self.maintain_task_conversation(conversation, now)?;
        }
        self.account_db()?.prune_task_certificates(now)?;
        Ok(())
    }
    fn compact_task(&self, row: &Lifecycle, prune: bool) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let history = self.task_history(&row.conversation_id, &row.task_id)?;
            let hashes = history
                .events
                .iter()
                .filter_map(|e| e.decision_certificate.as_ref())
                .map(|c| {
                    Ok(ramflux_protocol::hash_base64url(
                        "ramflux.task.archived_certificate.v1",
                        &serde_json::to_vec(c)?,
                    ))
                })
                .collect::<Result<Vec<_>, SdkError>>()?;
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
                db.persist_actor_state(&index_key, &compact)?;
            }
            Ok(())
        })
    }
}
