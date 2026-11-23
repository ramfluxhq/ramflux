// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner job inventory. Cron rows are the full stored job plus the contract fields, so this module
//! copies only `{id, kind, creator_agent, schedule, next_run_at, enabled, version}` and drops the
//! rest. A cron 404 is the uncoded sentence `Job '{id}' not found`; xin 404 is coded.

use crate::capabilities::{Capabilities, HOST_BOOTSTRAP_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, protocol};
use crate::name::AgentName;
use crate::transport::Transport;
use reqwest::Method;
use serde_json::Value;

const LIST_CAP: usize = 1024;

/// Which owner-job store a row came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomationKind {
    /// `GET /api/cron/jobs`.
    Cron,
    /// `GET /api/xin/tasks`.
    XinTask,
    /// `GET /api/xin/goals`.
    XinGoal,
}

impl AutomationKind {
    /// The `kind` string PRX puts on the row.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cron => "cron",
            Self::XinTask => "xin_task",
            Self::XinGoal => "xin_goal",
        }
    }

    fn list_key(self) -> &'static str {
        match self {
            Self::Cron => "jobs",
            Self::XinTask => "tasks",
            Self::XinGoal => "goals",
        }
    }

    fn is_cron(self) -> bool {
        matches!(self, Self::Cron)
    }
}

/// One cron job, xin task, or xin goal. Extra wire fields are not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomationItem {
    /// Job or task id.
    pub id: String,
    /// Which store the row came from.
    pub kind: AutomationKind,
    /// Creating agent, when PRX recorded one.
    pub creator_agent: Option<String>,
    /// Schedule text. Goals send null.
    pub schedule: Option<String>,
    /// Next run, RFC3339. Goals send null.
    pub next_run_at: Option<String>,
    /// False after pause or retire.
    pub enabled: bool,
    /// Store version. Retire increments it.
    pub version: u64,
}

impl PrxClient {
    /// Lists cron jobs, xin tasks, and xin goals for one agent. Needs `host_bootstrap_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported` when the token is absent, or the API error of any of the three reads.
    pub async fn list_automation(
        &self,
        caps: &Capabilities,
        agent: &AgentName,
    ) -> Result<Vec<AutomationItem>, PrxError> {
        require(caps, HOST_BOOTSTRAP_V1)?;
        let mut rows = Vec::new();
        for kind in [AutomationKind::Cron, AutomationKind::XinTask, AutomationKind::XinGoal] {
            let body = self.exchange(Method::GET, &list_path(kind, agent), kind.is_cron()).await?;
            rows.extend(take_list(&body, kind)?);
        }
        Ok(rows)
    }

    /// `POST .../{id}/pause`. The body is empty. Needs `host_bootstrap_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, a local `field_invalid`, or the API error. A cron 404 is
    /// `cron_job_unknown`.
    pub async fn pause_automation(
        &self,
        caps: &Capabilities,
        kind: AutomationKind,
        id: &str,
    ) -> Result<AutomationItem, PrxError> {
        self.switch_automation(caps, kind, id, false).await
    }

    /// `POST .../{id}/resume`. The body is empty. Needs `host_bootstrap_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, a local `field_invalid`, or the API error. A cron 404 is
    /// `cron_job_unknown`.
    pub async fn resume_automation(
        &self,
        caps: &Capabilities,
        kind: AutomationKind,
        id: &str,
    ) -> Result<AutomationItem, PrxError> {
        self.switch_automation(caps, kind, id, true).await
    }

    /// `DELETE .../{id}`. Needs `host_bootstrap_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, a local `field_invalid`, or the API error. A cron 404 is
    /// `cron_job_unknown`.
    pub async fn remove_automation(
        &self,
        caps: &Capabilities,
        kind: AutomationKind,
        id: &str,
    ) -> Result<(), PrxError> {
        require(caps, HOST_BOOTSTRAP_V1)?;
        let id = job_id(id)?;
        let path = item_path(kind, id);
        let body = self.exchange(Method::DELETE, &path, kind.is_cron()).await?;
        removed(&body, id)
    }

    async fn switch_automation(
        &self,
        caps: &Capabilities,
        kind: AutomationKind,
        id: &str,
        enabled: bool,
    ) -> Result<AutomationItem, PrxError> {
        require(caps, HOST_BOOTSTRAP_V1)?;
        let id = job_id(id)?;
        let suffix = if enabled { "resume" } else { "pause" };
        let path = format!("{}/{suffix}", item_path(kind, id));
        let body = self.exchange(Method::POST, &path, kind.is_cron()).await?;
        let item = one_item(&json_value(&body)?, kind.as_str())?;
        if item.id != id || item.enabled != enabled {
            return Err(protocol("automation row does not match the request"));
        }
        Ok(item)
    }

    async fn exchange(&self, method: Method, path: &str, cron: bool) -> Result<Vec<u8>, PrxError> {
        let raw = self.transport.call_raw(method, path, None).await?;
        if cron && raw.status == 404 {
            return Err(PrxError::Api {
                status: 404,
                code: ApiCode::CronJobUnknown,
                current_revision: None,
                revision: None,
                current_incarnation: None,
            });
        }
        Ok(Transport::check_status(raw)?.body)
    }
}

fn list_path(kind: AutomationKind, agent: &AgentName) -> String {
    let root = match kind {
        AutomationKind::Cron => "/api/cron/jobs",
        AutomationKind::XinTask => "/api/xin/tasks",
        AutomationKind::XinGoal => "/api/xin/goals",
    };
    format!("{root}?agent={}", agent.as_str())
}

fn item_path(kind: AutomationKind, id: &str) -> String {
    match kind {
        AutomationKind::Cron => format!("/api/cron/jobs/{id}"),
        AutomationKind::XinTask => format!("/api/xin/tasks/{id}"),
        AutomationKind::XinGoal => format!("/api/xin/goals/{id}"),
    }
}

fn job_id(id: &str) -> Result<&str, PrxError> {
    if id_ok(id) { Ok(id) } else { Err(local_field()) }
}

fn local_field() -> PrxError {
    PrxError::Api {
        status: 400,
        code: ApiCode::FieldInvalid,
        current_revision: None,
        revision: None,
        current_incarnation: None,
    }
}

fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn take_list(body: &[u8], kind: AutomationKind) -> Result<Vec<AutomationItem>, PrxError> {
    let value = json_value(body)?;
    let Some(items) = value.get(kind.list_key()).and_then(Value::as_array) else {
        return Err(protocol("automation list is missing its array"));
    };
    if items.len() > LIST_CAP {
        return Err(protocol("automation list is too long"));
    }
    items.iter().map(|item| one_item(item, kind.as_str())).collect()
}

fn one_item(value: &Value, expect: &str) -> Result<AutomationItem, PrxError> {
    let Some(map) = value.as_object() else {
        return Err(protocol("automation row is not an object"));
    };
    let id = required_text(map.get("id"))?;
    if !id_ok(&id) || required_text(map.get("kind"))? != expect {
        return Err(protocol("automation row does not match the route"));
    }
    let kind = match expect {
        "cron" => AutomationKind::Cron,
        "xin_task" => AutomationKind::XinTask,
        "xin_goal" => AutomationKind::XinGoal,
        _ => return Err(protocol("automation row does not match the route")),
    };
    Ok(AutomationItem {
        id,
        kind,
        creator_agent: optional_text(map.get("creator_agent"), 64)?,
        schedule: optional_text(map.get("schedule"), 128)?,
        next_run_at: optional_text(map.get("next_run_at"), 40)?,
        enabled: map
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or(protocol("automation row is missing enabled"))?,
        version: map
            .get("version")
            .and_then(Value::as_u64)
            .ok_or(protocol("automation row is missing version"))?,
    })
}

fn required_text(value: Option<&Value>) -> Result<String, PrxError> {
    match value {
        Some(Value::String(text)) if text_ok(text, 128) => Ok(text.clone()),
        _ => Err(protocol("automation row has a bad field")),
    }
}

fn optional_text(value: Option<&Value>, max: usize) -> Result<Option<String>, PrxError> {
    match value {
        None => Err(protocol("automation row is missing a field")),
        Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text_ok(text, max) => Ok(Some(text.clone())),
        Some(_) => Err(protocol("automation row has a bad field")),
    }
}

fn text_ok(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

fn removed(body: &[u8], id: &str) -> Result<(), PrxError> {
    let value = json_value(body)?;
    let got = value.get("id").and_then(Value::as_str);
    let flag = value.get("removed").and_then(Value::as_bool);
    if got == Some(id) && flag == Some(true) {
        Ok(())
    } else {
        Err(protocol("automation remove does not match the request"))
    }
}

fn json_value(body: &[u8]) -> Result<Value, PrxError> {
    serde_json::from_slice(body).map_err(|_| protocol("automation body is not json"))
}
