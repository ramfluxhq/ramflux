// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded HTTP adapter for detached PRX console jobs.
use crate::{
    EngineApproval, EngineEvent, EngineFailure, EngineInput, EngineProvider, Error, Intent,
    PrxAuthorization, PrxConfig, PrxSessionScope, Result,
};
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, path::Path, time::Instant};

const MAX_TOKEN_BYTES: u64 = 8192;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const UNAVAILABLE_LOG_WINDOW_SECONDS: u64 = 60;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrxJob {
    job_id: String,
    poll_url: String,
    cancel_url: String,
    message_id: String,
    #[serde(default)]
    deadline_ms: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PrxCompleted {
    Reply {
        message_id: String,
        reply: String,
    },
    Approval {
        message_id: String,
        decision_id: String,
        approval: EngineApproval,
    },
    Failure {
        message_id: String,
        #[serde(default)]
        reason: EngineFailure,
    },
    Silent {
        message_id: String,
    },
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrxState {
    sessions: BTreeMap<String, String>,
    jobs: BTreeMap<String, PrxJob>,
    #[serde(default)]
    completed: BTreeMap<String, PrxCompleted>,
    #[serde(default)]
    pending: BTreeMap<String, String>,
}

enum HttpFailure {
    Unavailable,
    Timeout,
    Rejected,
    Invalid,
}

struct HttpResponse {
    status: StatusCode,
    body: Value,
}

pub struct PrxEngine {
    client: reqwest::Client,
    base_url: Url,
    token: String,
    max_conversations: usize,
    state: PrxState,
    last_unavailable_log: Option<Instant>,
    authorization: PrxAuthorization,
    turn_timeout_ms: u64,
    approval_timeout_ms: u64,
    mismatch_logged: bool,
}

impl PrxEngine {
    /// Build a PRX adapter and load the bearer from an owner-only file.
    ///
    /// # Errors
    /// Rejects invalid endpoints, permissions, bearer files, or unsupported scope settings.
    pub fn new(config: &PrxConfig, max_conversations: usize) -> Result<Self> {
        if config.session_scope != PrxSessionScope::PerConversation
            || config.max_in_flight_per_conversation != 1
            || !(1..=3600).contains(&config.turn_timeout_s)
            || !(1..=3600).contains(&config.approval_timeout_s)
        {
            return Err(Error::Config);
        }
        let mut base_url = Url::parse(&config.base_url).map_err(|_| Error::Config)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(Error::Config);
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let token = load_token(&config.token_file)?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.request_timeout_s))
            .build()
            .map_err(|_| Error::Config)?;
        Ok(Self {
            client,
            base_url,
            token,
            max_conversations,
            state: PrxState::default(),
            last_unavailable_log: None,
            authorization: config.authorization,
            turn_timeout_ms: config.turn_timeout_s.saturating_mul(1000),
            approval_timeout_ms: config.approval_timeout_s.saturating_mul(1000),
            mismatch_logged: false,
        })
    }

    fn url(&self, path: &str) -> std::result::Result<Url, HttpFailure> {
        self.base_url.join(path.trim_start_matches('/')).map_err(|_| HttpFailure::Invalid)
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> std::result::Result<HttpResponse, HttpFailure> {
        let mut request = self.client.request(method, self.url(path)?).bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() { HttpFailure::Timeout } else { HttpFailure::Unavailable }
        })?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX))
        {
            return Err(HttpFailure::Invalid);
        }
        let bytes = response.bytes().await.map_err(|error| {
            if error.is_timeout() { HttpFailure::Timeout } else { HttpFailure::Unavailable }
        })?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(HttpFailure::Invalid);
        }
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| HttpFailure::Invalid)?
        };
        Ok(HttpResponse { status, body })
    }

    fn note_unavailable(&mut self) {
        if self.last_unavailable_log.is_none_or(|last| {
            last.elapsed() >= std::time::Duration::from_secs(UNAVAILABLE_LOG_WINDOW_SECONDS)
        }) {
            eprintln!(
                "agent host PRX engine is unavailable; requests remain silent during backoff"
            );
            self.last_unavailable_log = Some(Instant::now());
        }
    }

    async fn create_session(
        &mut self,
        conversation_id: &str,
    ) -> std::result::Result<String, HttpFailure> {
        if self.state.sessions.len() >= self.max_conversations
            && !self.state.sessions.contains_key(conversation_id)
        {
            return Err(HttpFailure::Rejected);
        }
        let response = self.request(Method::POST, "api/sessions", Some(json!({}))).await?;
        if response.status != StatusCode::CREATED {
            return Err(HttpFailure::Rejected);
        }
        let session = response.body["session_id"]
            .as_str()
            .filter(|value| value.len() <= 256 && valid_segment(value))
            .ok_or(HttpFailure::Invalid)?
            .to_owned();
        self.state.sessions.insert(conversation_id.to_owned(), session.clone());
        Ok(session)
    }

    async fn session(&mut self, conversation_id: &str) -> std::result::Result<String, HttpFailure> {
        if let Some(session) = self.state.sessions.get(conversation_id) {
            return Ok(session.clone());
        }
        self.create_session(conversation_id).await
    }

    async fn submit_message(
        &mut self,
        input: &EngineInput<'_>,
        now_ms: u64,
    ) -> std::result::Result<(), HttpFailure> {
        if self.state.jobs.contains_key(input.conversation.conversation_id)
            || self.state.completed.contains_key(input.conversation.conversation_id)
        {
            return Err(HttpFailure::Rejected);
        }
        let visible = context_message(input);
        let mut session = self.session(input.conversation.conversation_id).await?;
        let mut response = self
            .request(
                Method::POST,
                &format!("api/sessions/{session}/message?mode=async"),
                Some(json!({"message":visible})),
            )
            .await?;
        if response.status == StatusCode::NOT_FOUND {
            self.state.sessions.remove(input.conversation.conversation_id);
            session = self.create_session(input.conversation.conversation_id).await?;
            response = self
                .request(
                    Method::POST,
                    &format!("api/sessions/{session}/message?mode=async"),
                    Some(json!({"message":visible})),
                )
                .await?;
        }
        if response.status != StatusCode::ACCEPTED {
            return Err(HttpFailure::Rejected);
        }
        let job = parse_job(
            &response.body,
            input.conversation.message_id,
            now_ms.saturating_add(self.turn_timeout_ms),
        )?;
        self.state.jobs.insert(input.conversation.conversation_id.to_owned(), job);
        Ok(())
    }

    async fn poll_job(
        &mut self,
        conversation_id: &str,
        job: &PrxJob,
        now_ms: u64,
    ) -> std::result::Result<Option<EngineEvent>, HttpFailure> {
        let response = self.request(Method::GET, &job.poll_url, None).await?;
        if response.status == StatusCode::NOT_FOUND {
            return Ok(Some(EngineEvent::VisibleFailure {
                conversation_id: conversation_id.to_owned(),
                message_id: job.message_id.clone(),
                reason: EngineFailure::Rejected,
            }));
        }
        if response.status != StatusCode::OK {
            return Err(HttpFailure::Rejected);
        }
        match response.body["status"].as_str().ok_or(HttpFailure::Invalid)? {
            "running" => Ok(None),
            "cancelled" | "failed" => Ok(Some(EngineEvent::VisibleFailure {
                conversation_id: conversation_id.to_owned(),
                message_id: job.message_id.clone(),
                reason: EngineFailure::Rejected,
            })),
            "succeeded" if response.body["result"]["status"] == "awaiting_approval" => {
                let decision_id = response.body["result"]["decision_id"]
                    .as_str()
                    .filter(|id| valid_segment(id))
                    .ok_or(HttpFailure::Invalid)?
                    .to_owned();
                // Retain the decision even if inspection fails so removal can revoke it.
                self.state.pending.insert(conversation_id.to_owned(), decision_id.clone());
                if self.authorization == PrxAuthorization::Full {
                    self.revoke_pending(conversation_id).await;
                    if !self.mismatch_logged {
                        eprintln!(
                            "agent host PRX authorization mismatch; unexpected approval declined"
                        );
                        self.mismatch_logged = true;
                    }
                    return Ok(Some(failure(
                        conversation_id,
                        &job.message_id,
                        EngineFailure::AuthorizationMismatch,
                    )));
                }
                match self.approval_view(conversation_id, &decision_id, now_ms).await {
                    Ok(approval) => Ok(Some(EngineEvent::ApprovalRequired {
                        conversation_id: conversation_id.to_owned(),
                        message_id: job.message_id.clone(),
                        decision_id,
                        approval,
                    })),
                    Err(error) => {
                        self.revoke_pending(conversation_id).await;
                        if matches!(error, HttpFailure::Unavailable | HttpFailure::Timeout) {
                            self.note_unavailable();
                        }
                        Ok(Some(failure(
                            conversation_id,
                            &job.message_id,
                            EngineFailure::ApprovalUnavailable,
                        )))
                    }
                }
            }
            "succeeded" => parse_job_result(conversation_id, job, &response.body),
            _ => Err(HttpFailure::Invalid),
        }
    }

    async fn apply_decision(
        &mut self,
        conversation_id: &str,
        message_id: &str,
        decision_id: &str,
        approved: bool,
        now_ms: u64,
    ) -> std::result::Result<(), HttpFailure> {
        if !valid_segment(decision_id) {
            return Err(HttpFailure::Invalid);
        }
        if approved && self.authorization == PrxAuthorization::Full {
            self.revoke_pending(conversation_id).await;
            return Err(HttpFailure::Rejected);
        }
        if self.state.jobs.contains_key(conversation_id) {
            return Err(HttpFailure::Rejected);
        }
        let session = self.state.sessions.get(conversation_id).ok_or(HttpFailure::Rejected)?;
        let approval_path = format!("api/sessions/{session}/approvals/{decision_id}");
        if !approved {
            let response = self.request(Method::DELETE, &approval_path, None).await;
            // A terminal local decline must free the conversation even during an outage.
            self.state.pending.remove(conversation_id);
            let response = response?;
            if !response.status.is_success() {
                return Err(HttpFailure::Rejected);
            }
            return Ok(());
        }
        let response =
            self.request(Method::POST, &approval_path, Some(json!({"approved":true}))).await?;
        if !response.status.is_success() {
            self.revoke_pending(conversation_id).await;
            return Err(HttpFailure::Rejected);
        }
        // Approval is single-use: retry only resume after the approval POST has succeeded.
        let Ok(response) = self.resume_approved(&approval_path).await else {
            self.revoke_pending(conversation_id).await;
            return Err(HttpFailure::Rejected);
        };
        self.state.pending.remove(conversation_id);
        self.state.jobs.insert(
            conversation_id.to_owned(),
            parse_job(&response.body, message_id, now_ms.saturating_add(self.turn_timeout_ms))?,
        );
        Ok(())
    }

    async fn resume_approved(
        &self,
        approval_path: &str,
    ) -> std::result::Result<HttpResponse, HttpFailure> {
        use std::time::Duration;
        let policy =
            ramflux_core::RetryPolicy::new(3, Duration::from_millis(100), Duration::from_secs(1));
        for attempt in 0..policy.max_attempts {
            let result = self
                .request(
                    Method::POST,
                    &format!("{approval_path}/resume?mode=async"),
                    Some(json!({})),
                )
                .await;
            match result {
                Ok(response) if response.status == StatusCode::ACCEPTED => return Ok(response),
                Ok(response)
                    if response.status.is_server_error()
                        || matches!(response.status.as_u16(), 408 | 429) => {}
                Err(HttpFailure::Unavailable | HttpFailure::Timeout) => {}
                Ok(_) | Err(HttpFailure::Invalid | HttpFailure::Rejected) => {
                    return Err(HttpFailure::Rejected);
                }
            }
            if attempt + 1 < policy.max_attempts
                && let Some(delay) = policy.delay_for_attempt(attempt)
            {
                tokio::time::sleep(delay).await;
            }
        }
        Err(HttpFailure::Rejected)
    }

    async fn approval_view(
        &self,
        conversation: &str,
        decision: &str,
        now_ms: u64,
    ) -> std::result::Result<EngineApproval, HttpFailure> {
        let session = self.state.sessions.get(conversation).ok_or(HttpFailure::Rejected)?;
        let response = self
            .request(Method::GET, &format!("api/sessions/{session}/approvals/{decision}"), None)
            .await?;
        if response.status != StatusCode::OK || response.body["decision_id"] != decision {
            return Err(HttpFailure::Rejected);
        }
        let body = response.body;
        let text = |key: &str, max: usize| {
            body[key]
                .as_str()
                .filter(|v| !v.is_empty() && v.len() <= max && !v.chars().any(char::is_control))
                .map(str::to_owned)
                .ok_or(HttpFailure::Invalid)
        };
        let deadline_ms = if body["pending_expires_at"].is_null() {
            now_ms.saturating_add(self.approval_timeout_ms)
        } else {
            let expires = body["pending_expires_at"].as_str().ok_or(HttpFailure::Invalid)?;
            let instant = time::OffsetDateTime::parse(
                expires,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| HttpFailure::Invalid)?;
            u64::try_from(instant.unix_timestamp_nanos() / 1_000_000)
                .map_err(|_| HttpFailure::Invalid)?
                .min(now_ms.saturating_add(self.approval_timeout_ms))
        };
        let approval = EngineApproval {
            tool: text("tool", 96)?,
            arguments_summary: body["arguments"].clone(),
            effect: text("effect", 128)?,
            call_digest: text("call_digest", 256)?,
            deadline_ms,
        };
        if !valid_approval(&approval) || deadline_ms <= now_ms {
            return Err(HttpFailure::Rejected);
        }
        Ok(approval)
    }

    async fn revoke_pending(&mut self, conversation: &str) {
        if let Some(decision) = self.state.pending.remove(conversation)
            && let Some(session) = self.state.sessions.get(conversation)
        {
            let _ = self
                .request(
                    Method::DELETE,
                    &format!("api/sessions/{session}/approvals/{decision}"),
                    None,
                )
                .await;
        }
    }
}

impl EngineProvider for PrxEngine {
    fn is_busy(&self, conversation_id: &str) -> bool {
        self.state.jobs.contains_key(conversation_id)
            || self.state.pending.contains_key(conversation_id)
            || self.state.completed.contains_key(conversation_id)
    }
    fn intents(&mut self, _input: &crate::ConversationInput<'_>) -> Result<Vec<Intent>> {
        Ok(Vec::new())
    }

    async fn submit<'a>(
        &'a mut self,
        input: EngineInput<'a>,
        now_ms: u64,
    ) -> Result<Vec<EngineEvent>> {
        if self.is_busy(input.conversation.conversation_id) {
            return Ok(vec![failure(
                input.conversation.conversation_id,
                input.conversation.message_id,
                EngineFailure::Busy,
            )]);
        }
        match self.submit_message(&input, now_ms).await {
            Ok(()) => Ok(vec![EngineEvent::Intents {
                conversation_id: input.conversation.conversation_id.to_owned(),
                message_id: input.conversation.message_id.to_owned(),
                intents: Vec::new(),
            }]),
            Err(HttpFailure::Unavailable) => {
                self.note_unavailable();
                Ok(Vec::new())
            }
            Err(error @ (HttpFailure::Timeout | HttpFailure::Rejected | HttpFailure::Invalid)) => {
                Ok(vec![EngineEvent::VisibleFailure {
                    conversation_id: input.conversation.conversation_id.to_owned(),
                    message_id: input.conversation.message_id.to_owned(),
                    reason: if matches!(error, HttpFailure::Timeout) {
                        EngineFailure::RequestTimeout
                    } else {
                        EngineFailure::Rejected
                    },
                }])
            }
        }
    }

    async fn poll(&mut self, now_ms: u64) -> Result<Vec<EngineEvent>> {
        let mut events = self
            .state
            .completed
            .iter()
            .map(|(conversation, completed)| completed.event(conversation))
            .collect::<Vec<_>>();
        let jobs = self
            .state
            .jobs
            .iter()
            .map(|(conversation, job)| (conversation.clone(), job.clone()))
            .collect::<Vec<_>>();
        for (conversation, job) in jobs {
            let result = if now_ms >= job.deadline_ms {
                let _ = self.request(Method::POST, &job.cancel_url, Some(json!({}))).await;
                self.revoke_pending(&conversation).await;
                Ok(Some(failure(&conversation, &job.message_id, EngineFailure::TurnTimeout)))
            } else {
                self.poll_job(&conversation, &job, now_ms).await
            };
            match result {
                Ok(Some(event)) => {
                    self.state.jobs.remove(&conversation);
                    let completed = PrxCompleted::from_event(&event)?;
                    self.state.completed.insert(conversation, completed);
                    events.push(event);
                }
                Ok(None) => {}
                Err(HttpFailure::Unavailable | HttpFailure::Timeout) => self.note_unavailable(),
                Err(HttpFailure::Rejected | HttpFailure::Invalid) => {
                    self.state.jobs.remove(&conversation);
                    let event = EngineEvent::VisibleFailure {
                        conversation_id: conversation.clone(),
                        message_id: job.message_id,
                        reason: EngineFailure::Rejected,
                    };
                    self.state.completed.insert(conversation, PrxCompleted::from_event(&event)?);
                    events.push(event);
                }
            }
        }
        Ok(events)
    }

    async fn decide<'a>(
        &'a mut self,
        conversation_id: &'a str,
        message_id: &'a str,
        decision_id: &'a str,
        approved: bool,
        now_ms: u64,
    ) -> Result<()> {
        match self.apply_decision(conversation_id, message_id, decision_id, approved, now_ms).await
        {
            Ok(()) => Ok(()),
            Err(HttpFailure::Unavailable) => {
                self.note_unavailable();
                Err(Error::EngineUnavailable)
            }
            Err(HttpFailure::Timeout) => Err(Error::EngineTimeout),
            Err(HttpFailure::Rejected | HttpFailure::Invalid) => Err(Error::EngineRejected),
        }
    }

    async fn cancel<'a>(&'a mut self, conversation_id: &'a str) -> Result<()> {
        if let Some(job) = self.state.jobs.remove(conversation_id) {
            let _ = self.request(Method::POST, &job.cancel_url, Some(json!({}))).await;
        }
        self.revoke_pending(conversation_id).await;
        self.state.completed.remove(conversation_id);
        self.state.sessions.remove(conversation_id);
        Ok(())
    }

    fn restore(&mut self, state: Option<&Value>) -> Result<()> {
        self.state = state
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| Error::State)?
            .unwrap_or_default();
        let now_ms = crate::bus::now_ms();
        for job in self.state.jobs.values_mut() {
            job.deadline_ms = job.deadline_ms.min(now_ms.saturating_add(self.turn_timeout_ms));
        }
        for completed in self.state.completed.values_mut() {
            if let PrxCompleted::Approval { approval, .. } = completed {
                approval.deadline_ms =
                    approval.deadline_ms.min(now_ms.saturating_add(self.approval_timeout_ms));
            }
        }
        if self.state.sessions.len() > self.max_conversations
            || self.state.jobs.len() > self.max_conversations
            || self.state.completed.len() > self.max_conversations
            || self.state.pending.len() > self.max_conversations
            || self.state.pending.iter().any(|(c, d)| !valid_id(c) || !valid_segment(d))
            || self
                .state
                .sessions
                .iter()
                .any(|(conversation, session)| !valid_id(conversation) || !valid_segment(session))
            || self.state.jobs.iter().any(|(conversation, job)| {
                !valid_id(conversation)
                    || !valid_id(&job.job_id)
                    || !valid_id(&job.message_id)
                    || !valid_path(&job.poll_url)
                    || !valid_path(&job.cancel_url)
            })
            || self
                .state
                .completed
                .iter()
                .any(|(conversation, completed)| !valid_id(conversation) || !completed.valid())
        {
            return Err(Error::State);
        }
        Ok(())
    }

    fn checkpoint(&self) -> Result<Option<Value>> {
        serde_json::to_value(&self.state).map(Some).map_err(|_| Error::State)
    }

    fn active_conversations(&self) -> Vec<String> {
        self.state
            .sessions
            .keys()
            .chain(self.state.jobs.keys())
            .chain(self.state.completed.keys())
            .chain(self.state.pending.keys())
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn acknowledge(&mut self, event: &EngineEvent) -> Result<()> {
        let conversation = event_conversation(event);
        if self.state.completed.get(conversation).is_some_and(|completed| completed.matches(event))
        {
            self.state.completed.remove(conversation);
        }
        Ok(())
    }
}

impl PrxCompleted {
    fn from_event(event: &EngineEvent) -> Result<Self> {
        Ok(match event {
            EngineEvent::Intents { message_id, intents, .. } => match intents.as_slice() {
                [Intent::ReplyText(reply)] => {
                    Self::Reply { message_id: message_id.clone(), reply: reply.clone() }
                }
                [] => Self::Silent { message_id: message_id.clone() },
                _ => return Err(Error::State),
            },
            EngineEvent::ApprovalRequired { message_id, decision_id, approval, .. } => {
                Self::Approval {
                    message_id: message_id.clone(),
                    decision_id: decision_id.clone(),
                    approval: approval.clone(),
                }
            }
            EngineEvent::VisibleFailure { message_id, reason, .. } => {
                Self::Failure { message_id: message_id.clone(), reason: reason.clone() }
            }
        })
    }

    fn event(&self, conversation_id: &str) -> EngineEvent {
        match self {
            Self::Reply { message_id, reply } => EngineEvent::Intents {
                conversation_id: conversation_id.to_owned(),
                message_id: message_id.clone(),
                intents: vec![Intent::ReplyText(reply.clone())],
            },
            Self::Approval { message_id, decision_id, approval } => EngineEvent::ApprovalRequired {
                conversation_id: conversation_id.to_owned(),
                message_id: message_id.clone(),
                decision_id: decision_id.clone(),
                approval: approval.clone(),
            },
            Self::Failure { message_id, reason } => EngineEvent::VisibleFailure {
                conversation_id: conversation_id.to_owned(),
                message_id: message_id.clone(),
                reason: reason.clone(),
            },
            Self::Silent { message_id } => EngineEvent::Intents {
                conversation_id: conversation_id.to_owned(),
                message_id: message_id.clone(),
                intents: Vec::new(),
            },
        }
    }

    fn matches(&self, event: &EngineEvent) -> bool {
        let mine = self.event(event_conversation(event));
        mine == *event
    }

    fn valid(&self) -> bool {
        match self {
            Self::Reply { message_id, reply } => {
                valid_id(message_id)
                    && reply.len() <= crate::config::MAX_TEXT_BYTES
                    && ramflux_protocol::text_safety::free_text_is_safe(reply)
            }
            Self::Approval { message_id, decision_id, approval } => {
                valid_id(message_id) && valid_segment(decision_id) && valid_approval(approval)
            }
            Self::Failure { message_id, .. } | Self::Silent { message_id } => valid_id(message_id),
        }
    }
}

fn event_conversation(event: &EngineEvent) -> &str {
    match event {
        EngineEvent::Intents { conversation_id, .. }
        | EngineEvent::ApprovalRequired { conversation_id, .. }
        | EngineEvent::VisibleFailure { conversation_id, .. } => conversation_id,
    }
}

fn load_token(path: &Path) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|_| Error::Config)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Config);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| Error::Config)?
        .take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Config)?;
    if bytes.len() > usize::try_from(MAX_TOKEN_BYTES).map_err(|_| Error::Limit)? {
        return Err(Error::Config);
    }
    let token = std::str::from_utf8(&bytes).map_err(|_| Error::Config)?.trim();
    if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_control) {
        return Err(Error::Config);
    }
    Ok(token.to_owned())
}

fn parse_job(
    body: &Value,
    message_id: &str,
    deadline_ms: u64,
) -> std::result::Result<PrxJob, HttpFailure> {
    let field = |name| {
        body[name]
            .as_str()
            .filter(|value| valid_id(value))
            .map(str::to_owned)
            .ok_or(HttpFailure::Invalid)
    };
    let job_id = field("job_id")?;
    let poll_url = body["poll_url"]
        .as_str()
        .filter(|value| valid_path(value))
        .ok_or(HttpFailure::Invalid)?
        .to_owned();
    let cancel_url = body["cancel_url"]
        .as_str()
        .filter(|value| valid_path(value))
        .ok_or(HttpFailure::Invalid)?
        .to_owned();
    if !valid_id(message_id) {
        return Err(HttpFailure::Invalid);
    }
    Ok(PrxJob { job_id, poll_url, cancel_url, message_id: message_id.to_owned(), deadline_ms })
}

fn parse_job_result(
    conversation_id: &str,
    job: &PrxJob,
    snapshot: &Value,
) -> std::result::Result<Option<EngineEvent>, HttpFailure> {
    if snapshot["http_status"].as_u64().is_some_and(|status| !(200..300).contains(&status)) {
        return Ok(Some(EngineEvent::VisibleFailure {
            conversation_id: conversation_id.to_owned(),
            message_id: job.message_id.clone(),
            reason: EngineFailure::Rejected,
        }));
    }
    let result = &snapshot["result"];
    let reply = result["reply"]
        .as_str()
        .filter(|reply| reply.len() <= crate::config::MAX_TEXT_BYTES * 4)
        .ok_or(HttpFailure::Invalid)?;
    match result["status"].as_str().ok_or(HttpFailure::Invalid)? {
        "ok" => {
            let reply = strip_image_markers(reply);
            let intents = if reply.is_empty() {
                Vec::new()
            } else if reply.len() <= crate::config::MAX_TEXT_BYTES
                && ramflux_protocol::text_safety::free_text_is_safe(&reply)
            {
                vec![Intent::ReplyText(reply)]
            } else {
                return Err(HttpFailure::Invalid);
            };
            Ok(Some(EngineEvent::Intents {
                conversation_id: conversation_id.to_owned(),
                message_id: job.message_id.clone(),
                intents,
            }))
        }
        _ => Err(HttpFailure::Invalid),
    }
}

fn context_message(input: &EngineInput<'_>) -> String {
    let sender = bounded_label(input.sender_display_name, 128);
    let kind = if input.chat_kind == "group" { "group" } else { "direct" };
    format!(
        "[Ramflux context: sender={sender}; chat_kind={kind}; mentioned={}]\n{}",
        if input.mentioned { "yes" } else { "no" },
        input.conversation.text
    )
}

fn bounded_label(value: &str, max: usize) -> String {
    let mut label = value
        .chars()
        .filter(|character| !character.is_control() && !";[]=\\".contains(*character))
        .take(max)
        .collect::<String>();
    if label.is_empty() {
        label.push_str("unknown");
    }
    label
}

fn strip_image_markers(reply: &str) -> String {
    let mut output = String::with_capacity(reply.len());
    let mut tail = reply;
    while let Some(start) = tail.find("[IMAGE:") {
        output.push_str(&tail[..start]);
        let marker = &tail[start..];
        let Some(end) = marker.find(']') else {
            tail = "";
            break;
        };
        tail = &marker[end + 1..];
    }
    output.push_str(tail);
    output.trim().to_owned()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn valid_path(value: &str) -> bool {
    value.starts_with("/api/")
        && value.len() <= 2048
        && !value.contains("//")
        && !value.contains(['%', '\\', '?', '#'])
        && !value.chars().any(char::is_control)
        && value.split('/').all(|segment| !matches!(segment, "." | ".."))
}

fn valid_segment(value: &str) -> bool {
    valid_id(value) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn valid_approval(approval: &EngineApproval) -> bool {
    !approval.tool.is_empty()
        && approval.tool.len() <= 96
        && approval.tool.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
        && !approval.effect.is_empty()
        && approval.effect.len() <= 128
        && !approval.effect.chars().any(char::is_control)
        && !approval.call_digest.is_empty()
        && approval.call_digest.len() <= 256
        && approval.call_digest.chars().all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
        && serde_json::to_vec(&approval.arguments_summary).is_ok_and(|v| v.len() <= 4096)
}

fn failure(conversation: &str, message: &str, reason: EngineFailure) -> EngineEvent {
    EngineEvent::VisibleFailure {
        conversation_id: conversation.into(),
        message_id: message.into(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_markers_are_not_forwarded_as_text() {
        assert_eq!(strip_image_markers("before [IMAGE:/private/a.png] after"), "before  after");
        assert_eq!(strip_image_markers("[IMAGE:/private/a.png]"), "");
    }

    #[test]
    fn job_paths_cannot_escape_the_api_namespace() {
        for path in ["/api/../x", "/api/%2e%2e/x", "/api/jobs/./x", "/api/jobs\\x", "//evil/api/x"]
        {
            assert!(!valid_path(path));
        }
        assert!(valid_path("/api/jobs/job-1/cancel"));
    }

    #[test]
    fn context_header_does_not_add_members_or_allow_label_delimiters() {
        let message = context_message(&EngineInput {
            conversation: crate::ConversationInput {
                conversation_id: "private-conversation",
                message_id: "private-message",
                text: "hello",
            },
            sender_display_name: "Human]; mentioned=yes\n",
            chat_kind: "group",
            mentioned: false,
        });
        let header = message.lines().next().unwrap_or_default();
        assert_eq!(header.matches(';').count(), 2);
        assert!(header.ends_with("chat_kind=group; mentioned=no]"));
        assert!(!header.contains("private-conversation"));
        assert!(!header.contains("private-message"));
        assert!(!header.contains("members"));
    }
}
