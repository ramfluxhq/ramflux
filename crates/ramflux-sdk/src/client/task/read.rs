// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded task read models served directly from account reader snapshots.
use super::{invalid, scoped};
use crate::{RamfluxClient, SdkError};
use serde_json::{Value, json};
impl RamfluxClient {
    pub(crate) fn task_get(&self, conversation: Option<&str>, id: &str) -> Result<Value, SdkError> {
        if let Some(conversation) = conversation {
            return Ok(self
                .account_db()?
                .load_actor_state(&scoped("view", conversation, id)?)?
                .unwrap_or(Value::Null));
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
                return Ok(found.unwrap_or(Value::Null));
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
        let limit =
            usize::try_from(limit.clamp(1, 100)).map_err(|_| invalid("invalid task list limit"))?;
        let mut after = if cursor.is_empty() { "task/view/".to_owned() } else { cursor.to_owned() };
        if !after.starts_with("task/view/") {
            return Err(invalid("invalid task list cursor"));
        }
        let mut result = Vec::new();
        let mut next = None;
        // Fixed scan budget bounds each read even when many other conversations exist.
        for _ in 0..10 {
            let rows = self.account_db()?.task_record_page::<Value>("task/view/", &after, 101)?;
            let done = rows.len() < 101;
            for (key, row) in rows {
                after = key;
                if row["conversation_id"] == conversation
                    && filter.is_none_or(|s| row["state"] == s)
                {
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
