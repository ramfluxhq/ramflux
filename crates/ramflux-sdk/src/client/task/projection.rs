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
        if self.events.len() > 289 {
            return Err(invalid("task event history limit reached"));
        }
        let mut state = self.checkpoint.as_ref().map(|c| c.state.clone()).unwrap_or_default();
        let mut regular = 0;
        let mut controls = 0;
        for accepted in &self.events {
            let event = accepted.carrier.verify(&accepted.public_key)?;
            if matches!(event.event(), TaskEventBody::Cancel(_) | TaskEventBody::Resolve(_))
                && state
                    .task()
                    .is_some_and(|t| t.requester.as_deref() == Some(&accepted.carrier.principal_id))
            {
                controls += 1;
            } else {
                regular += 1;
            }
            if regular > 256 || controls > 33 {
                return Err(invalid("task event history limit reached"));
            }
            state
                .apply(&event, &accepted.carrier.signer(&accepted.public_key, &event))
                .map_err(|e| invalid(e.to_string()))?;
        }
        Ok(state)
    }
}
pub(super) struct Applied {
    pub(super) history: TaskHistory,
    pub(super) event: TaskEvent,
    pub(super) public: String,
    pub(super) task: Task,
    pub(super) decision_key: Option<String>,
    pub(super) decision_proof: Option<super::certificate::Certificate>,
    pub(super) membership: Option<super::historical::Membership>,
}
impl RamfluxClient {
    pub(crate) fn task_history(
        &self,
        conversation: &str,
        id: &str,
    ) -> Result<TaskHistory, SdkError> {
        let db = self.account_db()?;
        let mut history: TaskHistory =
            db.load_actor_state(&scoped("history", conversation, id)?)?.unwrap_or_default();
        history.checkpoint = db.load_actor_state(&scoped("checkpoint", conversation, id)?)?;
        if history.events.is_empty()
            && let Some(checkpoint) = &history.checkpoint
        {
            history.created_at = checkpoint.created_at;
            history.updated_at = checkpoint.updated_at;
        }
        Ok(history)
    }
    fn evaluate_task(&self, carrier: &Carrier) -> Result<Applied, SdkError> {
        let public = self.task_signer_key(&carrier.principal_id, &carrier.device_id)?;
        let event = carrier.verify(&public)?;
        if self.task_has_no_local_role(carrier)? {
            return Err(invalid("local account has no role in this task"));
        }
        let history = self.task_history(&carrier.conversation_id, event.event().task_id())?;
        let state = history.state()?;
        let control = Self::is_requester_task_control(carrier, &history)?;
        self.authorize_task_relations(carrier, state.task())?;
        let mut candidate = state.clone();
        candidate
            .apply(&event, &carrier.signer(&public, &event))
            .map_err(|e| invalid(e.to_string()))?;
        if history.events.len() >= if control { 289 } else { 256 } {
            return Err(invalid("task event history limit reached"));
        }
        self.check_task_capacity(carrier, &history)?;
        let (decision_key, decision_proof) =
            if let TaskEventBody::Resolve(resolution) = event.event() {
                let task = state.task().ok_or_else(|| invalid("task not found"))?;
                let (key, proof) = self.verify_task_decision(carrier, task, resolution)?;
                if self.account_db()?.load_actor_state::<Value>(&key)?.is_some() {
                    return Err(invalid("external task decision has already been consumed"));
                }
                (Some(key), Some(proof))
            } else {
                if carrier.decision_proof_base64.is_some() {
                    return Err(invalid("unexpected task decision proof"));
                }
                (None, None)
            };
        let task = candidate.task().cloned().ok_or_else(|| invalid("task missing after apply"))?;
        Ok(Applied { history, event, public, task, decision_key, decision_proof, membership: None })
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
    pub(crate) fn preflight_task_intent(&self, c: &Carrier) -> Result<(), SdkError> {
        let public = self.task_signer_key(&c.principal_id, &c.device_id)?;
        let event = c.verify(&public)?;
        let mut state = self.task_history(&c.conversation_id, event.event().task_id())?.state()?;
        self.authorize_task_relations(c, state.task())?;
        state.apply(&event, &c.signer(&public, &event)).map_err(|e| invalid(e.to_string()))?;
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
        self.account_db()?
            .write_transaction(|| self.apply_task_message(delivery, body, true).map(Some))
    }
    fn apply_task_message(
        &self,
        delivery: &Delivery<'_>,
        body: &[u8],
        forward_owned: bool,
    ) -> Result<Outcome, SdkError> {
        let carrier = Carrier::decode(body)?.ok_or_else(|| invalid("task carrier missing"))?;
        if carrier.conversation_id != delivery.conversation
            || carrier.principal_id != delivery.principal
            || carrier.device_id != delivery.device
        {
            return Err(invalid("task source or conversation mismatch"));
        }
        self.migrate_task_lifecycle(crate::time::now_unix_timestamp())?;
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
            if receipt.outcome.accepted
                && matches!(carrier.event()?.event(), TaskEventBody::Resolve(_))
            {
                self.require_task_member(
                    &carrier.conversation_id,
                    &carrier.principal_id,
                    Some(&carrier.device_id),
                )?;
                let history = self
                    .task_history(&carrier.conversation_id, carrier.event()?.event().task_id())?;
                if let Some(certificate) = history
                    .events
                    .iter()
                    .find(|e| {
                        e.carrier.message_id == carrier.message_id
                            && e.carrier.principal_id == carrier.principal_id
                    })
                    .and_then(|e| e.decision_certificate.as_ref())
                {
                    self.queue_task_decision_ack(&carrier, certificate)?;
                }
            }
            self.store_task_message_metadata(delivery, &receipt.outcome)?;
            return Ok(receipt.outcome);
        }
        self.require_task_member(
            &carrier.conversation_id,
            &carrier.principal_id,
            Some(&carrier.device_id),
        )?;
        self.check_task_pending_collision(&carrier)?;
        let pending_key = self.task_pending_key(&carrier)?;
        let already_pending = db.load_actor_state::<super::pending::Pending>(&pending_key)?;
        if let Some(old) = &already_pending {
            if old.carrier.bytes()? != body {
                return Err(invalid("task pending message id collision"));
            }
        } else if forward_owned {
            // Same-root history has separate page, count and byte bounds. Charging old
            // verified events as new peer traffic would make long histories unrestorable.
            self.admit_task_event(&carrier, crate::time::now_unix_timestamp())?;
        }
        if self.task_event_is_future(&carrier)? {
            return self.hold_task_message(delivery, &carrier, already_pending.is_some());
        }
        let applied = db.write_transaction(|| {
            let applied = self.evaluate_task(&carrier)?;
            self.record_task_applied(delivery, carrier.clone(), applied, forward_owned)
        });
        let outcome = match applied {
            Ok(outcome) => outcome,
            Err(SdkError::InboundPending(_)) => {
                return self.hold_task_message(delivery, &carrier, already_pending.is_some());
            }
            Err(SdkError::Storage(error)) => return Err(SdkError::Storage(error)),
            Err(SdkError::Io(error)) => return Err(SdkError::Io(error)),
            Err(error) => self.rejected_task_outcome(&carrier, &error)?,
        };
        db.delete_task_state(&pending_key)?;
        if pending_key.starts_with("task/local_pending/") {
            db.delete_task_state(
                &pending_key.replace("task/local_pending/", "task/local_intent_status/"),
            )?;
        }
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
    fn rejected_task_outcome(
        &self,
        carrier: &Carrier,
        error: &SdkError,
    ) -> Result<Outcome, SdkError> {
        self.record_task_capacity_rejection(carrier, error)?;
        if error.to_string().contains("local account has no role in this task") {
            self.remember_task_no_role(carrier)?;
        }
        Ok(Outcome {
            accepted: false,
            fallback_text: "[Task rejected]".into(),
            reject: Some(error.to_string()),
            pending: false,
        })
    }
    pub(super) fn record_task_applied(
        &self,
        delivery: &Delivery<'_>,
        carrier: Carrier,
        applied: Applied,
        forward_owned: bool,
    ) -> Result<Outcome, SdkError> {
        let Applied { mut history, event, public, task, decision_key, decision_proof, membership } =
            applied;
        let db = self.account_db()?;
        if history.events.is_empty() && history.checkpoint.is_none() {
            history.created_at = delivery.at;
        }
        history.updated_at = delivery.at;
        let kind_verified =
            super::actor_kind_verified(self, &carrier.principal_id, &carrier.device_id);
        let mut fallback = event.fallback_text_with_actor_kind(kind_verified);
        if !kind_verified && !fallback.contains("(actor kind unverified)") {
            fallback.push_str(" (actor kind unverified)");
        }
        if forward_owned && let Some(proof) = &decision_proof {
            self.queue_task_decision_ack(&carrier, proof)?;
            self.save_task_commit_certificate(&carrier, proof)?;
        }
        let membership = if forward_owned {
            Some(self.task_membership_witness(&carrier, &task, delivery.at)?)
        } else {
            membership
        };
        history.events.push(AcceptedEvent {
            carrier,
            public_key: public,
            actor_kind_verified: kind_verified,
            received_at: delivery.at,
            decision_certificate: decision_proof,
            membership,
        });
        self.check_task_capacity(
            &history.events.last().ok_or_else(|| invalid("empty history"))?.carrier,
            &history,
        )?;
        let last = &history.events.last().ok_or_else(|| invalid("empty history"))?.carrier;
        let recovery = Self::is_requester_task_control(last, &history)?;
        let reserve = if recovery {
            match last.event()?.event() {
                TaskEventBody::Cancel(_) => 80 * 1024 + 4096,
                _ => 64 * 1024 + 4096,
            }
        } else {
            0
        };
        let maximum = 2 * 1024 * 1024 + reserve;
        if serde_json::to_vec(&history)?.len() > maximum {
            return Err(invalid("task history byte budget exceeded"));
        }
        let history_key = scoped("history", &task.conversation_id, &task.task_id)?;
        db.persist_actor_state(&history_key, &history)?;
        if let Some(key) = decision_key {
            db.delete_task_state(&super::key("decision_reserved", &key))?;
            db.persist_actor_state(&key,&json!({"conversation_id":task.conversation_id,"task_id":task.task_id,"version":task.version}))?;
        }
        let mut view = serde_json::to_value(&task)?;
        if !task.state.is_terminal()
            && db
                .load_actor_state::<Value>(&scoped("view", &task.conversation_id, &task.task_id)?)?
                .is_some_and(|v| v["stalled_by_assignee"] == true)
        {
            view["stalled_by_assignee"] = json!(true);
            view["progress_state"] = json!("stalled by assignee");
        }
        view["id"] = json!(task.task_id);
        if history.checkpoint.is_some() {
            view["compacted"] = json!(true);
            view["certificate_hashes"] = json!(history.certificate_hashes()?);
        }
        view["actor_kind_verified"] = json!(kind_verified);
        view["created_at"] = json!(history.created_at);
        view["updated_at"] = json!(history.updated_at);
        db.persist_actor_state(&scoped("view", &task.conversation_id, &task.task_id)?, &view)?;
        db.append_journal(&format!("task:{}:{}",scoped("event",&task.conversation_id,&task.task_id)?,task.version),"task.changed",&json!({"task_id":task.task_id,"conversation_id":task.conversation_id,"version":task.version,"state":task.state,"actor_kind_verified":kind_verified}),delivery.at,None)?;
        self.record_task_lifecycle(&task, &history)?;
        if forward_owned {
            self.queue_task_owned_forward(
                &task.conversation_id,
                &task.task_id,
                delivery.principal,
                delivery.device,
            )?;
        }
        Ok(Outcome { accepted: true, fallback_text: fallback, reject: None, pending: false })
    }
    pub(super) fn store_task_message_metadata(
        &self,
        delivery: &Delivery<'_>,
        outcome: &Outcome,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_actor_state(&scoped("message",delivery.conversation,delivery.message)?,&json!({"content_type":"task","accepted":outcome.accepted,"fallback_text":outcome.fallback_text,"reject":outcome.reject,"pending":outcome.pending,"actor_kind_verified":super::actor_kind_verified(self, delivery.principal, delivery.device)}))?;
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
