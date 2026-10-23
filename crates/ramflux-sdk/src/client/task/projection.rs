// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transactional task state replay, durable receipts and metadata-only change events.
use super::{AcceptedEvent, TaskHistory, carrier::Carrier, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{Task, TaskState};
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
        let mut state = TaskState::default();
        for accepted in &self.events {
            let event = accepted.carrier.verify(&accepted.public_key)?;
            state
                .apply(&event, &accepted.carrier.signer(&accepted.public_key))
                .map_err(|e| invalid(e.to_string()))?;
        }
        Ok(state)
    }
}
impl RamfluxClient {
    pub(crate) fn task_history(&self, id: &str) -> Result<TaskHistory, SdkError> {
        Ok(self.account_db()?.load_actor_state(&key("history", id))?.unwrap_or_default())
    }
    pub(crate) fn task_get(&self, id: &str) -> Result<Value, SdkError> {
        let history = self.task_history(id)?;
        let state = history.state()?;
        let task = state.task().ok_or_else(|| invalid("task not found"))?;
        let mut value = serde_json::to_value(task)?;
        value["id"] = json!(task.task_id);
        value["created_at"] = json!(history.created_at);
        value["updated_at"] = json!(history.updated_at);
        Ok(value)
    }
    pub(crate) fn task_list(
        &self,
        conversation: &str,
        filter: Option<&str>,
    ) -> Result<Vec<Value>, SdkError> {
        let mut rows = Vec::new();
        for history in self.account_db()?.list_actor_states::<TaskHistory>("task/history/")? {
            let state = history.state()?;
            if let Some(task) = state.task()
                && task.conversation_id == conversation
            {
                let value = serde_json::to_value(task)?;
                if filter.is_none_or(|status| value["state"] == status) {
                    let mut row = value;
                    row["id"] = json!(task.task_id);
                    row["created_at"] = json!(history.created_at);
                    row["updated_at"] = json!(history.updated_at);
                    rows.push(row);
                }
            }
        }
        Ok(rows)
    }
    pub(crate) fn preflight_task(&self, carrier: &Carrier) -> Result<Task, SdkError> {
        let public = self.task_signer_key(&carrier.principal_id, &carrier.device_id)?;
        let event = carrier.verify(&public)?;
        let mut state = self.task_history(event.event.task_id())?.state()?;
        state.apply(&event, &carrier.signer(&public)).map_err(|e| invalid(e.to_string()))?;
        state.task().cloned().ok_or_else(|| invalid("task missing after apply"))
    }
    pub(crate) fn project_task_message(
        &self,
        delivery: &Delivery<'_>,
        body: &[u8],
    ) -> Result<Option<Outcome>, SdkError> {
        if !body.starts_with(super::carrier::PREFIX) {
            return Ok(None);
        }
        self.account_db()?.task_transaction(||{
            let parsed=Carrier::decode(body);
            let fingerprint=ramflux_protocol::hash_base64url("ramflux.task.delivery.v1",body);
            let receipt_key=key("receipt",&serde_json::to_string(&(delivery.principal,delivery.message))?);
            if let Some(old)=self.account_db()?.load_actor_state::<Receipt>(&receipt_key)?{
                if old.fingerprint==fingerprint{return Ok(Some(old.outcome));}
                return Ok(Some(Outcome{accepted:false,fallback_text:"[Task rejected]".into(),reject:Some("task message id collision".into())}));
            }
            let checked=(||->Result<_,SdkError>{
                let carrier=parsed?.ok_or_else(||invalid("task carrier missing"))?;
                if carrier.conversation_id!=delivery.conversation||carrier.principal_id!=delivery.principal||carrier.device_id!=delivery.device{return Err(invalid("task source or conversation mismatch"));}
                let public=self.task_signer_key(delivery.principal,delivery.device)?;
                let event=carrier.verify(&public)?;
                let mut history=self.task_history(event.event.task_id())?;
                let mut state=history.state()?;
                state.apply(&event,&carrier.signer(&public)).map_err(|e|invalid(e.to_string()))?;
                let task=state.task().cloned().ok_or_else(||invalid("task missing after apply"))?;
                Ok((carrier,public,event,task,history))
            })();
            let outcome=match checked {
                Ok((carrier,public,event,task,mut history))=>{
                    let fallback=event.fallback_text();
                    if history.events.is_empty(){history.created_at=delivery.at;}
                    history.updated_at=delivery.at;
                    history.events.push(AcceptedEvent{carrier,public_key:public});
                    self.account_db()?.persist_actor_state(&key("history",&task.task_id),&history)?;
                    self.account_db()?.append_journal(&format!("task:{}:{}",task.task_id,task.version),"task.changed",&json!({"task_id":task.task_id,"conversation_id":task.conversation_id,"version":task.version,"state":task.state}),delivery.at,None)?;
                    Outcome{accepted:true,fallback_text:fallback,reject:None}
                }
                Err(error)=>{
                    let reason=error.to_string();
                    self.account_db()?.persist_actor_state(&key("reject",&fingerprint),&json!({"conversation_id":delivery.conversation,"message_id":delivery.message,"reason":reason,"at":delivery.at}))?;
                    Outcome{accepted:false,fallback_text:"[Task rejected]".into(),reject:Some(reason)}
                }
            };
            self.account_db()?.persist_actor_state(&receipt_key,&Receipt{fingerprint,outcome:outcome.clone()})?;
            self.account_db()?.persist_actor_state(&key("message",delivery.message),&json!({"content_type":"task","accepted":outcome.accepted,"fallback_text":outcome.fallback_text,"reject":outcome.reject}))?;
            Ok(Some(outcome))
        })
    }
    pub(crate) fn task_message_metadata(&self, message: &str) -> Result<Option<Value>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&key("message", message))?)
    }
}
