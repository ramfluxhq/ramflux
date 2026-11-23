// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Applies one decoded mirror change. Unknown kinds are skips.

use super::store::{
    AgentRow, FailureNote, MAX_AGENTS, MAX_ERASES, MAX_RUNS, MAX_SESSIONS, MAX_TURNS, Mirror,
    RunRow, RunStatus, SessionRow, StoreError, TURN_TEXT_CAP, TurnRow,
};
use ramflux_prx_client::{EraseCopy, MirrorOp, TurnBody, TurnCopy};

impl Mirror {
    pub(super) fn apply_op(&mut self, op: &MirrorOp) -> Result<Option<FailureNote>, StoreError> {
        match op {
            MirrorOp::Session {
                session_key,
                agent,
                incarnation,
                channel,
                created_at,
                child,
                deleted,
                job_id,
                job_version,
            } => {
                let row = SessionRow {
                    agent: agent.clone(),
                    incarnation: incarnation.clone(),
                    channel: channel.clone(),
                    created_at: created_at.clone(),
                    child: *child,
                    job_id: job_id.clone(),
                    job_version: *job_version,
                };
                self.apply_session(session_key, row, *deleted)?;
                Ok(None)
            }
            MirrorOp::Agent { name, incarnation, revision, enabled, deleted } => {
                self.apply_agent(name, incarnation, revision.clone(), *enabled, *deleted)?;
                Ok(None)
            }
            MirrorOp::Turn(copy) => {
                self.apply_turn(copy)?;
                Ok(None)
            }
            MirrorOp::Started { run_id, session, agent } => {
                self.note_run(run_id, session, agent, RunUpdate::started())?;
                Ok(None)
            }
            MirrorOp::Failed { run_id, session, agent, reason, retryable } => {
                let update = RunUpdate::failed(reason.clone(), *retryable);
                let stored =
                    self.note_run(run_id.as_deref().unwrap_or(""), session, agent, update)?;
                if stored {
                    Ok(Some(FailureNote { reason: reason.clone(), retryable: *retryable }))
                } else {
                    Ok(None)
                }
            }
            MirrorOp::Cancelled { run_id, session, agent } => {
                self.note_run(
                    run_id.as_deref().unwrap_or(""),
                    session,
                    agent,
                    RunUpdate::cancelled(),
                )?;
                Ok(None)
            }
            MirrorOp::DeleteMessage { message_id } => {
                self.turns.remove(message_id);
                Ok(None)
            }
            MirrorOp::Erase(erase) => {
                self.apply_erase(erase)?;
                Ok(None)
            }
            MirrorOp::Approval(copy) => {
                self.remember_approval(copy);
                Ok(None)
            }
            MirrorOp::Skip => Ok(None),
        }
    }

    fn apply_session(
        &mut self,
        session_key: &str,
        row: SessionRow,
        deleted: bool,
    ) -> Result<(), StoreError> {
        if deleted {
            self.sessions.remove(session_key);
            self.turns.retain(|_, turn| turn.session != session_key);
            return Ok(());
        }
        if !self.sessions.contains_key(session_key) && self.sessions.len() >= MAX_SESSIONS {
            return Err(StoreError::Full);
        }
        self.sessions.insert(session_key.to_owned(), row);
        Ok(())
    }

    fn apply_agent(
        &mut self,
        name: &str,
        incarnation: &str,
        revision: Option<String>,
        enabled: bool,
        deleted: bool,
    ) -> Result<(), StoreError> {
        if deleted {
            self.agents.remove(name);
            return Ok(());
        }
        if !self.agents.contains_key(name) && self.agents.len() >= MAX_AGENTS {
            return Err(StoreError::Full);
        }
        self.agents.insert(
            name.to_owned(),
            AgentRow { incarnation: incarnation.to_owned(), revision, enabled },
        );
        Ok(())
    }

    fn apply_turn(&mut self, copy: &TurnCopy) -> Result<(), StoreError> {
        if matches!(copy.body, TurnBody::Deleted) {
            self.turns.remove(&copy.message_id);
            return Ok(());
        }
        if !self.turns.contains_key(&copy.message_id) && self.turns.len() >= MAX_TURNS {
            return Err(StoreError::Full);
        }
        self.turns.insert(copy.message_id.clone(), turn_row(copy));
        Ok(())
    }

    fn apply_erase(&mut self, erase: &EraseCopy) -> Result<(), StoreError> {
        if self.erases.iter().any(|id| id == &erase.erase_id) {
            return Ok(());
        }
        if self.erases.len() >= MAX_ERASES {
            return Err(StoreError::Full);
        }
        self.erases.push(erase.erase_id.clone());
        match &erase.session {
            None => {
                self.turns.retain(|_, row| row.agent != erase.agent);
                self.sessions.retain(|_, row| row.agent != erase.agent);
                self.agents.remove(&erase.agent);
            }
            Some(session) => {
                self.turns.retain(|_, row| !(row.session == *session && row.agent == erase.agent));
            }
        }
        Ok(())
    }

    fn note_run(
        &mut self,
        run_id: &str,
        session: &str,
        agent: &str,
        update: RunUpdate,
    ) -> Result<bool, StoreError> {
        let key = run_key(run_id, session, agent);
        if let Some(existing) = self.runs.get(&key) {
            if existing.status != RunStatus::Started || update.status == RunStatus::Started {
                return Ok(false);
            }
        } else if self.runs.len() >= MAX_RUNS {
            return Err(StoreError::Full);
        }
        let new_key = !self.runs.contains_key(&key);
        self.runs.insert(key.clone(), update.into_row(session, agent));
        if new_key {
            self.run_order.push(key);
        }
        Ok(true)
    }
}

struct RunUpdate {
    status: RunStatus,
    reason: Option<String>,
    retryable: Option<bool>,
}

impl RunUpdate {
    fn started() -> Self {
        Self { status: RunStatus::Started, reason: None, retryable: None }
    }

    fn failed(reason: String, retryable: bool) -> Self {
        Self { status: RunStatus::Failed, reason: Some(reason), retryable: Some(retryable) }
    }

    fn cancelled() -> Self {
        Self { status: RunStatus::Cancelled, reason: None, retryable: None }
    }

    fn into_row(self, session: &str, agent: &str) -> RunRow {
        RunRow {
            session: session.to_owned(),
            agent: agent.to_owned(),
            status: self.status,
            reason: self.reason,
            retryable: self.retryable,
        }
    }
}

fn turn_row(copy: &TurnCopy) -> TurnRow {
    let mut row = TurnRow {
        session: copy.session.clone(),
        agent: copy.agent.clone(),
        incarnation: copy.incarnation.clone(),
        role: copy.role.clone(),
        run_id: copy.run_id.clone(),
        client_message_id: copy.client_message_id.clone(),
        content: None,
        bytes: None,
        final_reply: false,
        content_omitted: false,
        oversized: false,
    };
    match &copy.body {
        TurnBody::Text { content, final_reply } => {
            row.final_reply = *final_reply;
            if content.len() > TURN_TEXT_CAP {
                row.bytes = u64::try_from(content.len()).ok();
                row.content_omitted = true;
            } else {
                row.content = Some(content.clone());
            }
        }
        TurnBody::Oversized { bytes } => {
            row.bytes = Some(*bytes);
            row.content_omitted = true;
            row.oversized = true;
        }
        TurnBody::Deleted => {}
    }
    row
}

fn run_key(run_id: &str, session: &str, agent: &str) -> String {
    if run_id.is_empty() { format!("no-run:{session}:{agent}") } else { run_id.to_owned() }
}
