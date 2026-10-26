// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded task read models served directly from account reader snapshots.
use super::{invalid, scoped};
use crate::{RamfluxClient, SdkError};
use serde_json::{Value, json};
impl RamfluxClient {
    pub(crate) fn task_get(&self, conversation: Option<&str>, id: &str) -> Result<Value, SdkError> {
        self.with_profile_read_scope(|| self.task_get_inner(conversation, id))
    }
    fn task_get_inner(&self, conversation: Option<&str>, id: &str) -> Result<Value, SdkError> {
        if let Some(conversation) = conversation {
            let mut row = self
                .account_db()?
                .load_actor_state(&scoped("view", conversation, id)?)?
                .unwrap_or(Value::Null);
            attach_pending(&mut row, &self.account_db()?.task_pending_metadata()?);
            if !row.is_null() {
                row["approval_decisions"] = json!(
                    self.task_approval_decision_rows()?
                        .into_iter()
                        .filter(|r| r["task_binding"]["conversation_id"] == conversation
                            && r["task_binding"]["task_id"] == id)
                        .collect::<Vec<_>>()
                );
            }
            refresh_actors(self, &mut row);
            return Ok(row);
        }
        let mut found = None;
        let mut cursor = "task/view/".to_owned();
        for _ in 0..10 {
            let rows = self.account_db()?.task_record_page::<Value>("task/view/", &cursor, 101)?;
            let done = rows.len() < 101;
            for (key, row) in rows {
                cursor = key;
                if row["task_id"] == id {
                    if found.is_some() {
                        return Err(invalid("ambiguous task id; conversation_id is required"));
                    }
                    found = Some(row);
                }
            }
            if done {
                let mut row = found.unwrap_or(Value::Null);
                attach_pending(&mut row, &self.account_db()?.task_pending_metadata()?);
                refresh_actors(self, &mut row);
                return Ok(row);
            }
        }
        Err(invalid("task lookup budget exceeded; conversation_id is required"))
    }
    pub(crate) fn task_list(
        &self,
        conversation: &str,
        filter: Option<&str>,
        cursor: &str,
        limit: u32,
    ) -> Result<Value, SdkError> {
        self.with_profile_read_scope(|| self.task_list_inner(conversation, filter, cursor, limit))
    }
    fn task_list_inner(
        &self,
        conversation: &str,
        filter: Option<&str>,
        cursor: &str,
        limit: u32,
    ) -> Result<Value, SdkError> {
        let limit =
            usize::try_from(limit.clamp(1, 100)).map_err(|_| invalid("invalid task list limit"))?;
        let mut after = if cursor.is_empty() { "task/view/".to_owned() } else { cursor.to_owned() };
        if !after.starts_with("task/view/") {
            return Err(invalid("invalid task list cursor"));
        }
        let pending = self.account_db()?.task_pending_metadata()?;
        let mut result = Vec::new();
        let mut next = None;
        // Fixed scan budget bounds each read even when many other conversations exist.
        for _ in 0..10 {
            let rows = self.account_db()?.task_record_page::<Value>("task/view/", &after, 101)?;
            let done = rows.len() < 101;
            for (key, mut row) in rows {
                after = key;
                if row["conversation_id"] == conversation
                    && filter.is_none_or(|s| row["state"] == s)
                {
                    attach_pending(&mut row, &pending);
                    refresh_actors(self, &mut row);
                    result.push(row);
                }
                if result.len() == limit {
                    next = Some(after.clone());
                    break;
                }
            }
            if result.len() == limit || done {
                return Ok(json!({"tasks":result,"next_cursor":next}));
            }
        }
        Ok(json!({"tasks":result,"next_cursor":after}))
    }
}

fn attach_pending(row: &mut Value, pending: &[Value]) {
    if row.is_null() {
        return;
    }
    row["pending_resolution"] = pending
        .iter()
        .find(|p| p["task_id"] == row["task_id"] && p["conversation_id"] == row["conversation_id"])
        .cloned()
        .unwrap_or(Value::Null);
}
pub(super) fn actor_metadata(
    client: &RamfluxClient,
    task: &ramflux_protocol::Task,
    history: &super::TaskHistory,
) -> Result<Value, SdkError> {
    client.with_profile_read_scope(|| actor_metadata_inner(client, task, history))
}
fn actor_metadata_inner(
    client: &RamfluxClient,
    task: &ramflux_protocol::Task,
    history: &super::TaskHistory,
) -> Result<Value, SdkError> {
    let old = client
        .account_db()?
        .load_actor_state::<Value>(&scoped("view", &task.conversation_id, &task.task_id)?)?
        .unwrap_or(Value::Null);
    let acceptor = history
        .events
        .iter()
        .rev()
        .find(|e| {
            e.carrier.event().is_ok_and(|event| {
                matches!(event.event(), ramflux_protocol::TaskEventBody::Accept(_))
            })
        })
        .map(|e| e.carrier.principal_id.as_str())
        .or_else(|| old["actors"]["acceptor"]["principal_id"].as_str());
    let mut actors = json!({});
    for (role, principal) in [
        ("requester", task.requester.as_deref()),
        ("assignee", Some(task.assignee.as_str())),
        ("acceptor", acceptor),
    ] {
        let device = principal
            .and_then(|id| history.events.iter().rev().find(|e| e.carrier.principal_id == id))
            .map_or("", |e| e.carrier.device_id.as_str());
        let facts = principal.and_then(|p| client.read_profile_facts(p));
        let kind_verified =
            facts.as_ref().is_some_and(|f| f.matches_role(device, relation_role(role)));
        actors[role] = json!({"principal_id":principal,"device_id":device,"actor_kind_verified":kind_verified,"actor_kind":facts.map(|f|f.profile.kind)});
    }
    Ok(actors)
}

fn relation_role(role: &str) -> ramflux_protocol::ActorType {
    if role == "assignee" {
        ramflux_protocol::ActorType::Bot
    } else {
        ramflux_protocol::ActorType::Human
    }
}
fn refresh_actors(client: &RamfluxClient, row: &mut Value) {
    if row.is_null() {
        return;
    }
    for role in ["requester", "assignee", "acceptor"] {
        let actor = &mut row["actors"][role];
        if actor.is_null() {
            continue;
        }
        let facts = actor["principal_id"].as_str().and_then(|p| client.read_profile_facts(p));
        actor["actor_kind_verified"] = json!(facts.as_ref().is_some_and(|f| {
            f.matches_role(actor["device_id"].as_str().unwrap_or(""), relation_role(role))
        }));
        actor["actor_kind"] = json!(facts.map(|f| f.profile.kind));
    }
}
