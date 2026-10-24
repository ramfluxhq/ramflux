// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded durable task holdback; future revisions never become permanent rejection receipts.
use super::{Delivery, carrier::Carrier, projection::Outcome, scoped};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::TaskEventBody;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub(super) struct Pending {
    pub carrier: Carrier,
    conversation: String,
    message: String,
    at: i64,
    expires_at: i64,
}
pub(super) fn pending_key(c: &Carrier) -> Result<String, SdkError> {
    scoped(
        "pending",
        &c.conversation_id,
        &serde_json::to_string(&(&c.principal_id, &c.message_id))?,
    )
}
impl RamfluxClient {
    pub(super) fn task_event_is_future(&self, c: &Carrier) -> Result<bool, SdkError> {
        let event = c.event()?;
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
                | SdkError::InboundPending(_)
                | SdkError::InboundRejected(_) => Ok(false),
                other => Err(other),
            };
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
        let (count, bytes) = db.task_state_usage("task/pending/")?;
        if !existing {
            let rows = db.task_record_page::<Pending>("task/pending/", "task/pending/", 33)?;
            if count >= 32
                || bytes.saturating_add(u64::try_from(c.bytes()?.len()).unwrap_or(u64::MAX))
                    > 5 * 1024 * 1024
                || rows.iter().filter(|(_, p)| p.carrier.principal_id == c.principal_id).count()
                    >= 8
            {
                return Err(SdkError::InboundPending("task holdback capacity reached".into()));
            }
            let pending = Pending {
                carrier: c.clone(),
                conversation: delivery.conversation.into(),
                message: delivery.message.into(),
                at: delivery.at,
                expires_at: crate::time::now_unix_timestamp().saturating_add(600),
            };
            db.persist_actor_state(&pending_key(c)?, &pending)?;
        }
        let outcome = Outcome {
            accepted: false,
            pending: true,
            fallback_text: "[Task waiting for earlier revisions]".into(),
            reject: None,
        };
        self.store_task_message_metadata(delivery, &outcome)?;
        Ok(outcome)
    }
    pub(crate) fn retry_pending_tasks(&self, now: i64) -> Result<usize, SdkError> {
        let rows =
            self.account_db()?.task_record_page::<Pending>("task/pending/", "task/pending/", 33)?;
        let mut applied = 0;
        for (key, p) in rows {
            if applied >= 8 {
                break;
            }
            if now >= p.expires_at {
                self.account_db()?.delete_task_state(&key)?;
                let outcome = Outcome {
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
                self.account_db()?.append_journal(&format!("task-hold-expired:{key}"),"task.changed",&serde_json::json!({"conversation_id":p.conversation,"task_id":p.carrier.event()?.event().task_id(),"resync_required":true,"actor_kind_verified":false}),now,None)?;
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
    fn replace_task_pending_fallback(
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
