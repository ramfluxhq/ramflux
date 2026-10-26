// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fair peer holdback and independent durable local decision intents.
use super::{carrier::Carrier, invalid, pending::Pending, projection::Outcome};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::TaskEventBody;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Serialize, Deserialize)]
pub(super) struct LocalIntentStatus {
    pub message: String,
    pub at: i64,
    executor: String,
    task_id: String,
    #[serde(default)]
    step_id: Option<String>,
    conversation_id: String,
    pub(super) carrier_hash: String,
    pending: bool,
    start: i64,
}
impl RamfluxClient {
    fn announce_task_pending(
        &self,
        c: &Carrier,
        key: &str,
        state: &str,
        pending: bool,
        now: i64,
    ) -> Result<(), SdkError> {
        self.account_db()?.append_journal(
            &format!("task-pending:{key}:{state}"), "task.changed",
            &serde_json::json!({"kind":ramflux_protocol::TaskChangeKind::Updated,"conversation_id":c.conversation_id,"task_id":c.event()?.event().task_id(),"pending":pending,"pending_state":state,"actor_kind":super::carrier_actor_kind(self, c),"actor_kind_verified":super::carrier_kind_verified(self, c)}), now, None,
        )?;
        Ok(())
    }
    pub(super) fn check_task_pending_collision(&self, c: &Carrier) -> Result<(), SdkError> {
        let chosen = self.task_pending_key(c)?;
        let peer = chosen.replace("task/local_pending/", "task/pending/");
        let local = peer.replace("task/pending/", "task/local_pending/");
        let db = self.account_db()?;
        for key in [peer, local.clone()] {
            if let Some(pending) = db.load_actor_state::<Pending>(&key)?
                && pending.carrier.bytes()? != c.bytes()?
            {
                return Err(invalid("task pending message id collision"));
            }
        }
        if let Some(status) = db.load_actor_state::<LocalIntentStatus>(
            &local.replace("task/local_pending/", "task/local_intent_status/"),
        )? && status.carrier_hash != super::certificate::carrier_hash(c)?
        {
            return Err(invalid("task pending message id collision"));
        }
        Ok(())
    }
    pub(super) fn is_local_task_intent(&self, c: &Carrier) -> Result<bool, SdkError> {
        Ok(self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id
            == c.principal_id
            && matches!(c.event()?.event(), TaskEventBody::Resolve(_)))
    }
    pub(super) fn admit_peer_task_hold(&self, c: &Carrier) -> Result<(), SdkError> {
        self.require_task_member(&c.conversation_id, &c.principal_id, Some(&c.device_id))?;
        let db = self.account_db()?;
        let rows = db.task_record_page::<Pending>("task/pending/", "task/pending/", 33)?;
        let mut buckets = BTreeMap::new();
        for (_, row) in &rows {
            *buckets.entry(row.carrier.principal_id.as_str()).or_insert(0usize) += 1;
        }
        let source = buckets.get(c.principal_id.as_str()).copied().unwrap_or(0);
        let own = rows
            .iter()
            .filter(|(_, p)| {
                p.carrier.principal_id == c.principal_id && p.conversation == c.conversation_id
            })
            .count();
        if own >= 8 || source >= 16 || c.bytes()?.len() > 128 * 1024 {
            return Err(SdkError::InboundPending("task peer holdback quota reached".into()));
        }
        let bytes = db.task_state_usage("task/pending/")?.1;
        if rows.len() >= 32
            || bytes.saturating_add(u64::try_from(c.bytes()?.len()).unwrap_or(u64::MAX))
                > 5 * 1024 * 1024
        {
            let maximum = buckets.values().copied().max().unwrap_or(0);
            let victim = rows
                .iter()
                .filter(|(_, p)| buckets.get(p.carrier.principal_id.as_str()) == Some(&maximum))
                .filter(|(_, p)| source != maximum || p.carrier.principal_id == c.principal_id)
                .min_by_key(|(key, p)| (p.at, key.as_str()));
            if let Some((key, pending)) = victim {
                let outcome = Outcome {
                    task_id: Some(pending.carrier.event()?.event().task_id().into()),
                    reason_code: None,
                    accepted: false,
                    pending: false,
                    fallback_text: "[Task requires resync: fair holdback capacity]".into(),
                    reject: Some("task_holdback_rebalanced".into()),
                };
                self.store_task_message_metadata(
                    &super::Delivery {
                        conversation: &pending.conversation,
                        message: &pending.message,
                        principal: &pending.carrier.principal_id,
                        device: &pending.carrier.device_id,
                        at: pending.at,
                    },
                    &outcome,
                    &pending.carrier,
                )?;
                self.replace_task_pending_fallback(pending, &outcome)?;
                db.delete_task_state(key)?;
                self.announce_task_pending(
                    &pending.carrier,
                    key,
                    "rebalanced",
                    false,
                    crate::time::now_unix_timestamp(),
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn local_task_executor(&self, c: &Carrier) -> Result<String, SdkError> {
        let task = self.task_history(&c.conversation_id, c.event()?.event().task_id())?.state()?;
        Ok(task.task().ok_or_else(|| invalid("local task intent has no task"))?.assignee.clone())
    }
    pub(super) fn admit_local_task_intent(&self, c: &Carrier) -> Result<(), SdkError> {
        self.preflight_task_intent(c)?;
        self.release_local_task_slots(crate::time::now_unix_timestamp())?;
        let db = self.account_db()?;
        let mut cursor = "task/local_pending/".to_owned();
        let mut rows = Vec::new();
        for _ in 0..6 {
            let page = db.task_record_page::<Pending>("task/local_pending/", &cursor, 101)?;
            let done = page.len() < 101;
            if let Some((key, _)) = page.last() {
                cursor.clone_from(key);
            }
            rows.extend(page);
            if done {
                break;
            }
        }
        let executor = self.local_task_executor(c)?;
        let same = rows.iter().filter(|(_, p)| p.executor.as_deref() == Some(&executor)).count();
        if same >= 8 || rows.len() >= 512 {
            return Err(SdkError::InboundPending("local task intent quota reached".into()));
        }
        if db
            .task_state_usage("task/local_pending/")?
            .1
            .saturating_add(u64::try_from(c.bytes()?.len()).unwrap_or(u64::MAX))
            > 8 * 1024 * 1024
        {
            return Err(SdkError::InboundPending("local task intent byte quota reached".into()));
        }
        Ok(())
    }
    fn migrate_local_task_holds(&self, now: i64) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let rows = db.task_record_page::<Pending>("task/pending/", "task/pending/", 33)?;
        for (key, mut p) in rows {
            if !self.is_local_task_intent(&p.carrier)? {
                continue;
            }
            let target = self.task_pending_key(&p.carrier)?;
            if let Some(existing) = db.load_actor_state::<Pending>(&target)? {
                if existing.carrier.bytes()? != p.carrier.bytes()? {
                    return Err(invalid("task pending message id collision"));
                }
                db.delete_task_state(&key)?;
                continue;
            }
            let executor = match self.local_task_executor(&p.carrier) {
                Ok(id) => id,
                Err(SdkError::Storage(error)) => return Err(SdkError::Storage(error)),
                Err(_) => "unavailable".into(),
            };
            let local =
                db.task_record_page::<Pending>("task/local_pending/", "task/local_pending/", 101)?;
            let full =
                local.iter().filter(|(_, p)| p.executor.as_deref() == Some(&executor)).count() >= 8
                    || db.task_state_usage("task/local_pending/")?.0 >= 512
                    || db.task_state_usage("task/local_pending/")?.1.saturating_add(
                        u64::try_from(p.carrier.bytes()?.len()).unwrap_or(u64::MAX),
                    ) > 8 * 1024 * 1024;
            p.executor = Some(executor);
            p.expires_at = p.expires_at.min(if full { now } else { now.saturating_add(60) });
            db.persist_actor_state(&target, &p)?;
            db.delete_task_state(&key)?;
        }
        Ok(())
    }
    pub(super) fn release_local_task_slots(&self, now: i64) -> Result<(), SdkError> {
        self.migrate_local_task_holds(now)?;
        let db = self.account_db()?;
        let mut cursor = "task/local_pending/".to_owned();
        for _ in 0..6 {
            let page = db.task_record_page::<Pending>("task/local_pending/", &cursor, 101)?;
            let done = page.len() < 101;
            for (key, p) in page {
                cursor.clone_from(&key);
                if now >= p.expires_at {
                    let status = LocalIntentStatus {
                        message: p.message.clone(),
                        at: p.at,
                        executor: p
                            .executor
                            .clone()
                            .ok_or_else(|| invalid("local intent executor missing"))?,
                        task_id: p.carrier.event()?.event().task_id().to_owned(),
                        step_id: match p.carrier.event()?.event() {
                            TaskEventBody::Resolve(r) => Some(r.step_id.clone()),
                            _ => None,
                        },
                        conversation_id: p.conversation.clone(),
                        carrier_hash: super::certificate::carrier_hash(&p.carrier)?,
                        pending: true,
                        start: now,
                    };
                    db.persist_actor_state(
                        &key.replace("task/local_pending/", "task/local_intent_status/"),
                        &status,
                    )?;
                    db.delete_task_state(&key)?;
                    let outcome = Outcome {
                        task_id: Some(p.carrier.event()?.event().task_id().into()),
                        reason_code: None,
                        accepted: false,
                        pending: true,
                        fallback_text: "[Task decision pending: executor confirmation timed out]"
                            .into(),
                        reject: None,
                    };
                    self.store_task_message_metadata(
                        &super::Delivery {
                            conversation: &p.conversation,
                            message: &p.message,
                            principal: &p.carrier.principal_id,
                            device: &p.carrier.device_id,
                            at: p.at,
                        },
                        &outcome,
                        &p.carrier,
                    )?;
                    self.replace_task_pending_fallback(&p, &outcome)?;
                    self.announce_task_pending(&p.carrier, &key, "executor_timeout", true, now)?;
                }
            }
            if done {
                break;
            }
        }
        db.prune_local_task_intent_status(now)?;
        Ok(())
    }
}
