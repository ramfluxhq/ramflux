// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transactional task reduction with scoped replay receipts and metadata-only journal rows.
use super::{AcceptedEvent, TaskHistory, carrier::Carrier, invalid, scoped};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{Task, TaskEvent, TaskEventBody, TaskState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Outcome {
    pub accepted: bool,
    pub fallback_text: String,
    pub reject: Option<String>,
    #[serde(default)]
    pub pending: bool,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Receipt {
    pub(super) fingerprint: String,
    pub(super) outcome: Outcome,
}
pub(crate) struct Delivery<'a> {
    pub conversation: &'a str,
    pub message: &'a str,
    pub principal: &'a str,
    pub device: &'a str,
    pub at: i64,
}
impl TaskHistory {
    pub(crate) fn state(&self) -> Result<TaskState, SdkError> {
        if self.events.len() > 256 {
            return Err(invalid("task event history limit reached"));
        }
        let mut state = TaskState::default();
        for accepted in &self.events {
            let event = accepted.carrier.verify(&accepted.public_key)?;
            state
                .apply(&event, &accepted.carrier.signer(&accepted.public_key, &event)?)
                .map_err(|e| invalid(e.to_string()))?;
        }
        Ok(state)
    }
}
struct Applied {
    history: TaskHistory,
    event: TaskEvent,
    public: String,
    task: Task,
    decision_key: Option<String>,
}
impl RamfluxClient {
    pub(crate) fn task_history(
        &self,
        conversation: &str,
        id: &str,
    ) -> Result<TaskHistory, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state(&scoped("history", conversation, id)?)?
            .unwrap_or_default())
    }
    fn evaluate_task(&self, carrier: &Carrier) -> Result<Applied, SdkError> {
        let public = self.task_signer_key(&carrier.principal_id, &carrier.device_id)?;
        let event = carrier.verify(&public)?;
        let history = self.task_history(&carrier.conversation_id, event.event().task_id())?;
        if history.events.len() >= 256 {
            return Err(invalid("task event history limit reached"));
        }
        let mut state = history.state()?;
        self.authorize_task_relations(carrier, state.task())?;
        let decision_key = if let TaskEventBody::Resolve(resolution) = event.event() {
            let task = state.task().ok_or_else(|| invalid("task not found"))?;
            let key = self.verify_task_decision(carrier, task, resolution)?;
            if self.account_db()?.load_actor_state::<Value>(&key)?.is_some() {
                return Err(invalid("external task decision has already been consumed"));
            }
            Some(key)
        } else {
            if carrier.decision_proof_base64.is_some() {
                return Err(invalid("unexpected task decision proof"));
            }
            None
        };
        state
            .apply(&event, &carrier.signer(&public, &event)?)
            .map_err(|e| invalid(e.to_string()))?;
        let task = state.task().cloned().ok_or_else(|| invalid("task missing after apply"))?;
        Ok(Applied { history, event, public, task, decision_key })
    }
    pub(crate) fn task_delivery_receipt(&self, c: &Carrier) -> Result<Option<Outcome>, SdkError> {
        let receipt = scoped(
            "receipt",
            &c.conversation_id,
            &serde_json::to_string(&(&c.principal_id, &c.message_id))?,
        )?;
        let fingerprint = ramflux_protocol::hash_base64url("ramflux.task.delivery.v1", &c.bytes()?);
        for key in [&receipt, &receipt.replace("task/receipt/", "task/rejected/")] {
            if let Some(old) = self.account_db()?.load_actor_state::<Receipt>(key)? {
                if old.fingerprint != fingerprint {
                    return Err(invalid("task message id collision"));
                }
                return Ok(Some(old.outcome));
            }
        }
        Ok(None)
    }
    pub(crate) fn set_task_delivery_state(
        &self,
        conversation: &str,
        id: &str,
        state: &str,
        error: Option<&str>,
    ) -> Result<(), SdkError> {
        let key = scoped("view", conversation, id)?;
        if let Some(mut row) = self.account_db()?.load_actor_state::<Value>(&key)? {
            row["delivery_state"] = json!(state);
            row["delivery_error"] = json!(error);
            self.account_db()?.persist_actor_state(&key, &row)?;
        }
        Ok(())
    }
    pub(crate) fn preflight_task(&self, carrier: &Carrier) -> Result<Task, SdkError> {
        Ok(self.evaluate_task(carrier)?.task)
    }
    pub(crate) fn project_task_message(
        &self,
        delivery: &Delivery<'_>,
        body: &[u8],
    ) -> Result<Option<Outcome>, SdkError> {
        if !body.starts_with(super::carrier::PREFIX) {
            return Ok(None);
        }
        self.account_db()?.write_transaction(|| self.apply_task_message(delivery, body).map(Some))
    }
    fn apply_task_message(
        &self,
        delivery: &Delivery<'_>,
        body: &[u8],
    ) -> Result<Outcome, SdkError> {
        let carrier = Carrier::decode(body)?.ok_or_else(|| invalid("task carrier missing"))?;
        if carrier.conversation_id != delivery.conversation
            || carrier.principal_id != delivery.principal
            || carrier.device_id != delivery.device
        {
            return Err(invalid("task source or conversation mismatch"));
        }
        let public = self.task_signer_key(delivery.principal, delivery.device)?;
        carrier.verify(&public)?;
        let db = self.account_db()?;
        let receipt_key = scoped(
            "receipt",
            delivery.conversation,
            &serde_json::to_string(&(delivery.principal, &carrier.message_id))?,
        )?;
        let fingerprint = ramflux_protocol::hash_base64url("ramflux.task.delivery.v1", body);
        let rejected_key = receipt_key.replace("task/receipt/", "task/rejected/");
        if let Some(receipt) =
            db.load_actor_state::<Receipt>(&receipt_key)?.or(db.load_actor_state(&rejected_key)?)
        {
            if receipt.fingerprint != fingerprint {
                return Err(invalid("task message id collision"));
            }
            self.store_task_message_metadata(delivery, &receipt.outcome)?;
            return Ok(receipt.outcome);
        }
        self.require_task_member(
            &carrier.conversation_id,
            &carrier.principal_id,
            Some(&carrier.device_id),
        )?;
        let pending_key = super::pending::pending_key(&carrier)?;
        let already_pending = db.load_actor_state::<super::pending::Pending>(&pending_key)?;
        if let Some(old) = &already_pending {
            if old.carrier.bytes()? != body {
                return Err(invalid("task pending message id collision"));
            }
        } else {
            self.admit_task_event(&carrier, crate::time::now_unix_timestamp())?;
        }
        if self.task_event_is_future(&carrier)? {
            return self.hold_task_message(delivery, &carrier, already_pending.is_some());
        }
        let outcome = match self.evaluate_task(&carrier) {
            Ok(Applied { mut history, event, public, task, decision_key }) => {
                if history.events.is_empty() {
                    history.created_at = delivery.at;
                }
                history.updated_at = delivery.at;
                let fallback = format!("{} (actor kind unverified)", event.fallback_text());
                history.events.push(AcceptedEvent {
                    carrier,
                    public_key: public,
                    actor_kind_verified: false,
                    received_at: delivery.at,
                });
                if serde_json::to_vec(&history)?.len() > 2 * 1024 * 1024 {
                    return Err(invalid("task history byte budget exceeded"));
                }
                let history_key = scoped("history", &task.conversation_id, &task.task_id)?;
                let (count, bytes) = db.task_state_usage("task/history/")?;
                let old_bytes = db
                    .load_actor_state::<TaskHistory>(&history_key)?
                    .map(|h| serde_json::to_vec(&h))
                    .transpose()?
                    .map_or(0, |b| b.len());
                let new_bytes = serde_json::to_vec(&history)?.len();
                if (count >= 1000 && old_bytes == 0)
                    || bytes
                        .saturating_sub(u64::try_from(old_bytes).unwrap_or(u64::MAX))
                        .saturating_add(u64::try_from(new_bytes).unwrap_or(u64::MAX))
                        > 32 * 1024 * 1024
                {
                    return Err(invalid("account task history capacity reached"));
                }
                db.persist_actor_state(&history_key, &history)?;
                if let Some(key) = decision_key {
                    db.persist_actor_state(&key,&json!({"conversation_id":task.conversation_id,"task_id":task.task_id,"version":task.version}))?;
                }
                let mut view = serde_json::to_value(&task)?;
                view["id"] = json!(task.task_id);
                view["actor_kind_verified"] = json!(false);
                view["created_at"] = json!(history.created_at);
                view["updated_at"] = json!(history.updated_at);
                db.persist_actor_state(
                    &scoped("view", &task.conversation_id, &task.task_id)?,
                    &view,
                )?;
                db.append_journal(&format!("task:{}:{}",scoped("event",&task.conversation_id,&task.task_id)?,task.version),"task.changed",&json!({"task_id":task.task_id,"conversation_id":task.conversation_id,"version":task.version,"state":task.state,"actor_kind_verified":false}),delivery.at,None)?;
                Outcome { accepted: true, fallback_text: fallback, reject: None, pending: false }
            }
            Err(error) => Outcome {
                accepted: false,
                fallback_text: "[Task rejected]".into(),
                reject: Some(error.to_string()),
                pending: false,
            },
        };
        db.delete_task_state(&pending_key)?;
        db.persist_actor_state(
            if outcome.accepted { &receipt_key } else { &rejected_key },
            &Receipt { fingerprint, outcome: outcome.clone() },
        )?;
        if !outcome.accepted {
            db.prune_task_diagnostics("task/rejected/", 256)?;
        }
        self.store_task_message_metadata(delivery, &outcome)?;
        Ok(outcome)
    }
    fn admit_task_event(&self, carrier: &Carrier, now: i64) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let task = carrier.event()?.event().task_id().to_owned();
        for (scope, maximum) in [
            ("account".to_owned(), 512),
            (format!("principal:{}", carrier.principal_id), 128),
            (format!("task:{}:{}:{}", carrier.conversation_id, task, carrier.principal_id), 64),
        ] {
            let id = super::key("rate", &scope);
            let mut rate = db
                .load_actor_state::<Value>(&id)?
                .unwrap_or_else(|| json!({"start":now,"count":0}));
            if now.saturating_sub(rate["start"].as_i64().unwrap_or(now)) >= 60 {
                rate = json!({"start":now,"count":0});
            }
            let count = rate["count"].as_u64().unwrap_or(0);
            if count >= maximum {
                return Err(invalid("task admission rate exceeded"));
            }
            rate["count"] = json!(count + 1);
            db.persist_actor_state(&id, &rate)?;
        }
        db.prune_task_diagnostics("task/rate/", 2048)?;
        Ok(())
    }
    pub(super) fn store_task_message_metadata(
        &self,
        delivery: &Delivery<'_>,
        outcome: &Outcome,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_actor_state(&scoped("message",delivery.conversation,delivery.message)?,&json!({"content_type":"task","accepted":outcome.accepted,"fallback_text":outcome.fallback_text,"reject":outcome.reject,"pending":outcome.pending,"actor_kind_verified":false}))?;
        Ok(())
    }
    pub(crate) fn task_message_metadata(
        &self,
        conversation: &str,
        message: &str,
    ) -> Result<Option<Value>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&scoped("message", conversation, message)?)?)
    }
}
