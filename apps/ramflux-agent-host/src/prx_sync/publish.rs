// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publishes live PRX frames and approval rows on the local bus.
//! A failed publish drops the bus and leaves the WebSocket up.

use super::store::{ApprovalRow, Mirror};
use crate::{AgentBus, Error, RfdBus};
use ramflux_prx_client::{ApprovalCopy, LiveBody, LiveNotice, MirrorOp, SnapshotPage, TurnCopy};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub(super) struct Publisher {
    socket: PathBuf,
    account: String,
    bus: Option<RfdBus>,
}

impl Publisher {
    pub(super) fn new(socket: &Path, account: &str) -> Self {
        Self { socket: socket.to_path_buf(), account: account.to_owned(), bus: None }
    }

    pub(super) async fn stored(&mut self, mirror: &Mirror) {
        let rows: Vec<(String, ApprovalRow)> =
            mirror.approvals.iter().map(|(id, row)| (id.clone(), row.clone())).collect();
        for (id, row) in rows {
            self.approval(&stored_copy(&id, &row)).await;
        }
        let sessions: Vec<(String, String, String, u64, String)> = mirror
            .sessions
            .iter()
            .filter_map(|(key, row)| {
                let job_id = row.job_id.clone()?;
                let version = row.job_version?;
                let channel = row.channel.clone()?;
                Some((key.clone(), row.agent.clone(), job_id, version, channel))
            })
            .collect();
        for (session, agent, job_id, version, channel) in sessions {
            self.job_session(&session, &agent, &job_id, version, &channel).await;
        }
    }

    pub(super) async fn page(&mut self, page: &SnapshotPage) {
        for row in &page.rows {
            if let MirrorOp::Approval(copy) = &row.op {
                self.approval(copy).await;
            }
            self.mirror_session(&row.op).await;
        }
    }

    pub(super) async fn mirror_session(&mut self, op: &MirrorOp) {
        let MirrorOp::Session { session_key, agent, channel, job_id, job_version, deleted, .. } =
            op
        else {
            return;
        };
        if *deleted {
            return;
        }
        let (Some(job_id), Some(version), Some(channel)) = (job_id, job_version, channel) else {
            return;
        };
        self.job_session(session_key, agent, job_id, *version, channel).await;
    }

    async fn job_session(
        &mut self,
        session: &str,
        agent: &str,
        job_id: &str,
        version: u64,
        channel: &str,
    ) {
        if let Some(body) = job_body(session, agent, job_id, version, channel) {
            self.send("agent.job.session", body).await;
        }
    }

    pub(super) async fn approval(&mut self, copy: &ApprovalCopy) {
        if let Some(body) = approval_body(copy) {
            self.send("agent.approval.publish", body).await;
        }
    }

    pub(super) async fn progress(&mut self, notice: &LiveNotice) {
        if let Some(body) = progress_body(notice) {
            self.send("agent.progress", body).await;
        }
    }

    pub(super) async fn final_text(&mut self, copy: &TurnCopy, text: &str) {
        if let Some(body) = final_body(copy, text) {
            self.send("agent.progress", body).await;
        }
    }

    async fn send(&mut self, method: &str, body: Value) {
        if self.socket.as_os_str().is_empty() || self.account.is_empty() {
            return;
        }
        if self.bus.is_none() {
            let Ok(bus) = RfdBus::connect(&self.socket, &self.account).await else {
                eprintln!("prx sync bus is unavailable");
                return;
            };
            self.bus = Some(bus);
        }
        let Some(bus) = self.bus.as_mut() else { return };
        match bus.request(method, body, None).await {
            Ok(_) => {}
            Err(error @ (Error::Bus | Error::Resync | Error::IdentityLost)) => {
                eprintln!("prx sync bus publish failed: {error}");
                self.bus = None;
            }
            Err(error) => eprintln!("prx sync bus publish refused: {error}"),
        }
    }
}

fn stored_copy(id: &str, row: &ApprovalRow) -> ApprovalCopy {
    ApprovalCopy {
        approval_id: id.to_owned(),
        session: row.session.clone(),
        agent: row.agent.clone(),
        run_id: row.run_id.clone(),
        tool: row.tool.clone(),
        preview: row.preview.clone(),
        expires_at: row.expires_at.clone(),
        status: row.status.clone(),
        decision: row.decision.clone(),
        cause: row.cause.clone(),
    }
}

fn job_body(
    session: &str,
    agent: &str,
    job_id: &str,
    version: u64,
    channel: &str,
) -> Option<Value> {
    let prefix = match channel {
        "cron" => "cron:",
        "xin" => "xin:",
        _ => return None,
    };
    if !path_id(agent) || !path_id(job_id) || session != format!("{prefix}{job_id}") {
        return None;
    }
    Some(json!({
        "source": "prx",
        "agent": agent,
        "session": session,
        "job_id": job_id,
        "job_version": version,
        "channel": channel,
        "conversation_id": agent,
    }))
}

fn approval_body(copy: &ApprovalCopy) -> Option<Value> {
    if !path_id(&copy.session) || !path_id(&copy.approval_id) {
        return None;
    }
    if copy.status != "pending" && copy.status != "decided" {
        return None;
    }
    if copy.status == "decided" && !copy.decision.as_deref().is_some_and(decision_token) {
        return None;
    }
    let mut body = json!({
        "source": "prx",
        "approval_id": copy.approval_id,
        "conversation_id": copy.session,
        "session": copy.session,
        "status": copy.status,
        "tool": label(&copy.tool),
        "preview": preview(&copy.preview),
        "expires_at": expiry(&copy.expires_at),
    });
    put_id(&mut body, "agent", &copy.agent);
    if let Some(run_id) = copy.run_id.as_deref() {
        put_id(&mut body, "run_id", run_id);
    }
    if let Some(decision) = copy.decision.as_deref() {
        body["decision"] = json!(decision);
    }
    if let Some(cause) = copy.cause.as_deref() {
        put_id(&mut body, "cause", cause);
    }
    Some(body)
}

fn progress_body(notice: &LiveNotice) -> Option<Value> {
    if !path_id(&notice.session) {
        return None;
    }
    let run =
        notice.root_run_id.as_deref().filter(|id| path_id(id)).unwrap_or(notice.run_id.as_str());
    if !path_id(run) {
        return None;
    }
    let mut body = json!({
        "conversation_id": notice.session,
        "session": notice.session,
        "run_id": run,
        "idx": safe_idx(notice.idx),
    });
    put_id(&mut body, "agent", &notice.agent);
    match &notice.body {
        LiveBody::Typing => {
            body["kind"] = json!("typing");
            body["state"] = json!("thinking");
        }
        LiveBody::Delta(text) => {
            if notice.child_run_id.is_some() {
                return None;
            }
            body["kind"] = json!("delta");
            body["text"] = json!(cap(text, 4096));
        }
        LiveBody::Tool { tool, phase, cause } => {
            if !path_id(phase) {
                return None;
            }
            body["kind"] = json!("tool");
            body["phase"] = json!(phase);
            put_id(&mut body, "tool", tool);
            if let Some(cause) = cause.as_deref() {
                put_id(&mut body, "cause", cause);
            }
            if let Some(child) = notice.child_run_id.as_deref() {
                put_id(&mut body, "child_run_id", child);
            }
        }
        LiveBody::Gap => body["kind"] = json!("gap"),
    }
    Some(body)
}

fn final_body(copy: &TurnCopy, text: &str) -> Option<Value> {
    if copy.origin.is_some() {
        return None;
    }
    let run = copy.run_id.as_deref().filter(|id| path_id(id))?;
    if !path_id(&copy.session) {
        return None;
    }
    let mut body = json!({
        "conversation_id": copy.session,
        "session": copy.session,
        "run_id": run,
        "idx": stable_idx(&copy.message_id),
        "kind": "final",
        "text": cap(text, 4096),
    });
    put_id(&mut body, "agent", &copy.agent);
    Some(body)
}

fn put_id(body: &mut Value, key: &str, value: &str) {
    if path_id(value) {
        body[key] = json!(value);
    }
}

fn label(value: &str) -> String {
    if path_id(value) { value.to_owned() } else { String::new() }
}

fn preview(value: &str) -> String {
    if value.chars().any(char::is_control) { String::new() } else { cap(value, 512) }
}

fn expiry(value: &str) -> String {
    let legal = value.len() <= 40
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'T' | b'Z' | b'+' | b'.')
        });
    if value.is_empty() || legal { value.to_owned() } else { String::new() }
}

/// Any decision id is stored. Only the exact token `approved` continues tools.
fn decision_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn path_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn cap(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("").to_owned()
}

fn stable_idx(text: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    safe_idx(hash)
}

fn safe_idx(value: u64) -> u64 {
    value & ramflux_protocol::MAX_SAFE_JSON_INTEGER
}
