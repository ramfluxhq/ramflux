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
}
#[derive(Serialize, Deserialize)]
struct Receipt {
    fingerprint: String,
    outcome: Outcome,
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
                .apply(&event, &accepted.carrier.signer(&accepted.public_key)?)
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
        state.apply(&event, &carrier.signer(&public)?).map_err(|e| invalid(e.to_string()))?;
        let task = state.task().cloned().ok_or_else(|| invalid("task missing after apply"))?;
        Ok(Applied { history, event, public, task, decision_key })
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
        self.account_db()?.task_transaction(|| self.apply_task_message(delivery, body).map(Some))
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
        if let Some(receipt) = db.load_actor_state::<Receipt>(&receipt_key)? {
            if receipt.fingerprint != fingerprint {
                return Err(invalid("task message id collision"));
            }
            self.store_task_message_metadata(delivery, &receipt.outcome)?;
            return Ok(receipt.outcome);
        }
        self.admit_task_event(&carrier, delivery.at)?;
        let outcome = match self.evaluate_task(&carrier) {
            Ok(Applied { mut history, event, public, task, decision_key }) => {
                if history.events.is_empty() {
                    history.created_at = delivery.at;
                }
                history.updated_at = delivery.at;
                let fallback = event.fallback_text();
                history.events.push(AcceptedEvent { carrier, public_key: public });
                if serde_json::to_vec(&history)?.len() > 2 * 1024 * 1024 {
                    return Err(invalid("task history byte budget exceeded"));
                }
                db.persist_actor_state(
                    &scoped("history", &task.conversation_id, &task.task_id)?,
                    &history,
                )?;
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
                Outcome { accepted: true, fallback_text: fallback, reject: None }
            }
            Err(error) => Outcome {
                accepted: false,
                fallback_text: "[Task rejected]".into(),
                reject: Some(error.to_string()),
            },
        };
        db.persist_actor_state(&receipt_key, &Receipt { fingerprint, outcome: outcome.clone() })?;
        self.store_task_message_metadata(delivery, &outcome)?;
        Ok(outcome)
    }
    fn admit_task_event(&self, carrier: &Carrier, now: i64) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let id = scoped(
            "rate",
            &carrier.conversation_id,
            &serde_json::to_string(&(carrier.event()?.event().task_id(), &carrier.principal_id))?,
        )?;
        let mut rate =
            db.load_actor_state::<Value>(&id)?.unwrap_or_else(|| json!({"start":now,"count":0}));
        if now.saturating_sub(rate["start"].as_i64().unwrap_or(now)) >= 60 {
            rate = json!({"start":now,"count":0});
        }
        let count = rate["count"].as_u64().unwrap_or(0);
        if count >= 32 {
            return Err(invalid("task sender rate exceeded"));
        }
        rate["count"] = json!(count + 1);
        db.persist_actor_state(&id, &rate)?;
        Ok(())
    }
    fn store_task_message_metadata(
        &self,
        delivery: &Delivery<'_>,
        outcome: &Outcome,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_actor_state(&scoped("message",delivery.conversation,delivery.message)?,&json!({"content_type":"task","accepted":outcome.accepted,"fallback_text":outcome.fallback_text,"reject":outcome.reject,"actor_kind_verified":false}))?;
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
