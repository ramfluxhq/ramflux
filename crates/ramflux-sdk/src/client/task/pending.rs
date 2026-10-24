// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded durable task holdback; future revisions never become permanent rejection receipts.
use super::{Delivery, carrier::Carrier, projection::Outcome, scoped};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::TaskEventBody;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub(super) struct Pending {
    #[serde(default)]
    pub task_id: String,
    #[serde(default)]
    pub(super) step_id: Option<String>,
    pub carrier: Carrier,
    pub(super) conversation: String,
    pub(super) message: String,
    pub(super) at: i64,
    pub(super) expires_at: i64,
    #[serde(default)]
    pub(super) executor: Option<String>,
}
impl RamfluxClient {
    pub(super) fn task_pending_key(&self, c: &Carrier) -> Result<String, SdkError> {
        scoped(
            if self.is_local_task_intent(c)? { "local_pending" } else { "pending" },
            &c.conversation_id,
            &serde_json::to_string(&(&c.principal_id, &c.message_id))?,
        )
    }
    pub(super) fn task_event_is_future(&self, c: &Carrier) -> Result<bool, SdkError> {
        let event = c.event()?;
        if self.task_has_no_local_role(c)? {
            return Ok(false);
        }
        if self.task_is_archived(&c.conversation_id, event.event().task_id())? {
            return Ok(false);
        }
        let state = self.task_history(&c.conversation_id, event.event().task_id())?.state()?;
        let Some(task) = state.task() else {
            return Ok(!matches!(
                event.event(),
                TaskEventBody::Start(_) | TaskEventBody::Proposal(_)
            ));
        };
        if task.state.is_terminal() {
            return Ok(false);
        }
        if let Err(error) = self.authorize_task_relations(c, Some(task)) {
            return match error {
                SdkError::LocalBus(_)
                | SdkError::TaskRefused { .. }
                | SdkError::InboundPending(_)
                | SdkError::InboundRejected(_) => Ok(false),
                other => Err(other),
            };
        }
        if let Some(base) = event.event().base_revision()
            && base > task.version
        {
            return Ok(true);
        }
        if let TaskEventBody::Resolve(resolution) = event.event() {
            match self.task_decision_is_waiting(c, task, resolution) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(_) => return Ok(false),
            }
        }
        Ok(if let Some(base) = event.event().base_revision() {
            base > task.version
        } else {
            event.event().version() > task.version.saturating_add(1)
        })
    }
    pub(super) fn hold_task_message(
        &self,
        delivery: &Delivery<'_>,
        c: &Carrier,
        existing: bool,
    ) -> Result<Outcome, SdkError> {
        let db = self.account_db()?;
        if !existing {
            let local = self.is_local_task_intent(c)?;
            if local {
                self.admit_local_task_intent(c)?;
            } else {
                self.admit_peer_task_hold(c)?;
            }
            let pending = Pending {
                task_id: c.event()?.event().task_id().into(),
                step_id: match c.event()?.event() {
                    TaskEventBody::Resolve(r) => Some(r.step_id.clone()),
                    _ => None,
                },
                carrier: c.clone(),
                conversation: delivery.conversation.into(),
                message: delivery.message.into(),
                at: delivery.at,
                expires_at: crate::time::now_unix_timestamp().saturating_add(if local {
                    60
                } else {
                    600
                }),
                executor: if local { Some(self.local_task_executor(c)?) } else { None },
            };
            db.persist_actor_state(&self.task_pending_key(c)?, &pending)?;
        }
        let outcome = Outcome {
            task_id: Some(c.event()?.event().task_id().into()),
            reason_code: None,
            accepted: false,
            pending: true,
            fallback_text: if matches!(c.event()?.event(), TaskEventBody::Resolve(_)) {
                "[Task decision awaiting approval confirmation]"
            } else {
                "[Task waiting for earlier revisions]"
            }
            .into(),
            reject: None,
        };
        self.store_task_message_metadata(delivery, &outcome)?;
        Ok(outcome)
    }
    pub(crate) fn retry_pending_tasks(&self, now: i64) -> Result<usize, SdkError> {
        self.maintain_task_lifecycle(now)?;
        self.release_local_task_slots(now)?;
        let mut rows =
            self.account_db()?.task_record_page::<Pending>("task/pending/", "task/pending/", 33)?;
        rows.extend(self.account_db()?.task_record_page::<Pending>(
            "task/local_pending/",
            "task/local_pending/",
            101,
        )?);
        let mut applied = 0;
        for (key, p) in rows {
            if applied >= 8 {
                break;
            }
            if now >= p.expires_at {
                self.account_db()?.delete_task_state(&key)?;
                let outcome = Outcome {
                    task_id: Some(p.carrier.event()?.event().task_id().into()),
                    reason_code: None,
                    accepted: false,
                    pending: false,
                    fallback_text: "[Task requires resync: earlier revisions unavailable]".into(),
                    reject: Some("task_holdback_expired".into()),
                };
                self.store_task_message_metadata(
                    &Delivery {
                        conversation: &p.conversation,
                        message: &p.message,
                        principal: &p.carrier.principal_id,
                        device: &p.carrier.device_id,
                        at: p.at,
                    },
                    &outcome,
                )?;
                self.replace_task_pending_fallback(&p, &outcome)?;
                self.account_db()?.append_journal(&format!("task-hold-expired:{key}"),"task.changed",&serde_json::json!({"conversation_id":p.conversation,"task_id":p.carrier.event()?.event().task_id(),"resync_required":true,"actor_kind_verified":super::actor_kind_verified(self, &p.carrier.principal_id, &p.carrier.device_id)}),now,None)?;
                continue;
            }
            if self.task_event_is_future(&p.carrier)? {
                continue;
            }
            let result = self.project_task_message(
                &Delivery {
                    conversation: &p.conversation,
                    message: &p.message,
                    principal: &p.carrier.principal_id,
                    device: &p.carrier.device_id,
                    at: p.at,
                },
                &p.carrier.bytes()?,
            );
            match result {
                Ok(Some(outcome)) if !outcome.pending => {
                    self.replace_task_pending_fallback(&p, &outcome)?;
                    applied += 1;
                }
                Ok(_) | Err(SdkError::InboundPending(_)) => {}
                Err(error) => {
                    self.account_db()?.delete_task_state(&key)?;
                    let outcome = Outcome {
                        task_id: Some(p.carrier.event()?.event().task_id().into()),
                        reason_code: None,
                        accepted: false,
                        pending: false,
                        fallback_text: "[Task rejected]".into(),
                        reject: Some(error.to_string()),
                    };
                    self.store_task_message_metadata(
                        &Delivery {
                            conversation: &p.conversation,
                            message: &p.message,
                            principal: &p.carrier.principal_id,
                            device: &p.carrier.device_id,
                            at: p.at,
                        },
                        &outcome,
                    )?;
                    self.replace_task_pending_fallback(&p, &outcome)?;
                }
            }
        }
        Ok(applied)
    }
    pub(super) fn replace_task_pending_fallback(
        &self,
        p: &Pending,
        outcome: &Outcome,
    ) -> Result<(), SdkError> {
        if self.direct_message_by_id(&p.message)?.is_some_and(|message| !message.deleted) {
            self.account_db()?.replace_surface_message_content(
                &p.conversation,
                &p.message,
                outcome.fallback_text.as_bytes(),
            )?;
        }
        Ok(())
    }
}
