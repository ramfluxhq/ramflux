// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable same-user PRX channel provider. The host owns persistence and rfd writes.
mod render;
mod schedule;
mod security;
mod state;
mod transport;
use crate::{
    ConversationInput, EngineEvent, EngineInput, EngineProvider, Error, Intent, PrxBridgeConfig,
    Result,
};
use serde_json::{Value, json};
use state::{Call, Erase, Inbound, Packet, State, Turn};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};
use transport::{Command, Event, Transport};
const KIND: &str = "ramflux.agent.prx_bridge.v1";
const MAX_BUFFER: usize = 65_536;
const MAX_TRACKED_TURNS: usize = 4096;

#[derive(Clone, Copy)]
struct HumanDecision<'a> {
    conversation: &'a str,
    approval_id: &'a str,
    decision: &'a str,
    grant: Option<&'a str>,
    sender: &'a Value,
    now: u64,
}

pub(crate) struct Source {
    pub sender: Value,
    pub chat: Value,
    pub templates: Vec<crate::checkpoint::Output>,
    pub task: Option<Value>,
    pub timestamp_ms: u64,
    pub reply_to: Option<String>,
}

pub struct PrxBridgeEngine {
    config: PrxBridgeConfig,
    maximum: usize,
    state: State,
    transport: Transport,
    connected: bool,
    reconnect_needed: bool,
    retry_at: HashMap<String, (u64, u32)>,
    inflight: HashMap<String, Arc<AtomicU8>>,
    active: HashMap<String, String>,
    answers: VecDeque<(u64, Value, Option<i64>)>,
    send_queue: VecDeque<String>,
    scheduled: HashSet<String>,
    decider: Option<(Value, String)>,
    prepared: Option<Source>,
    stats: Value,
    stats_at: u64,
    stats_dirty: bool,
    warnings: HashMap<&'static str, u64>,
}
impl PrxBridgeEngine {
    /// # Errors
    /// Rejects insecure existing socket paths or invalid bridge bounds before starting.
    pub fn new(config: &PrxBridgeConfig, account: &str, maximum: usize) -> Result<Self> {
        if !config.valid()
            || account.is_empty()
            || account.len() > 1024
            || !(1..=1024).contains(&maximum)
        {
            return Err(Error::Config);
        }
        Ok(Self {
            config: config.clone(),
            maximum,
            state: State { kind: KIND.into(), ..State::default() },
            transport: Transport::start(config.clone(), account.into())?,
            connected: false,
            reconnect_needed: false,
            retry_at: HashMap::new(),
            inflight: HashMap::new(),
            active: HashMap::new(),
            answers: VecDeque::new(),
            send_queue: VecDeque::new(),
            scheduled: HashSet::new(),
            prepared: None,
            decider: None,
            stats: json!({"connects":0,"disconnects":0,"hello_refused":{},"inbound_sent":0,
                "inbound_resent":0,"inbound_dropped_stale":0,"queue_full":0,"replies":{},"dup_frames":0,
                "stream_appends_sent":0,"stream_gap":0,"stream_capped":0,
                "approvals":{"requested":0,"approved":0,"denied":0,"expired":0,"refused_device":0,"refused_unverified":0},
                "erases":{"sent":0,"acked":0,"retried":0},"erase_outbox_len":0,
                "frames_rejected":{"oversize":0,"parse":0},"late_acks":0,"retry_delay_s":0,"controls":{"agent_revoked":0,"agent_offline":0,"turn_cancel":0}}),
            stats_at: 0,
            stats_dirty: false,
            warnings: HashMap::new(),
        })
    }
    /// Counters contain no frame bodies or provider diagnostics.
    #[must_use]
    pub fn stats(&self) -> Value {
        self.stats.clone()
    }
    fn count(&mut self, path: &[&str]) {
        let mut value = &mut self.stats;
        for key in path {
            if !value.is_object() {
                *value = json!({});
            }
            value = &mut value[*key];
        }
        *value = json!(value.as_u64().unwrap_or(0).saturating_add(1));
        self.stats_dirty = true;
    }
    fn warn(&mut self, code: &'static str, now: u64) {
        if self.warnings.get(code).is_none_or(|last| now >= last.saturating_add(60_000)) {
            eprintln!("agent host bridge refused: {code}");
            self.warnings.insert(code, now);
        }
    }
    fn print_stats(&mut self, now: u64, force: bool) {
        self.stats["erase_outbox_len"] = json!(self.state.erases.len());
        if force || self.stats_dirty && now >= self.stats_at.saturating_add(60_000) {
            eprintln!("agent host bridge stats {}", self.stats);
            self.stats_at = now;
            self.stats_dirty = false;
        }
    }
    pub(crate) fn prepare(&mut self, source: Source) {
        self.prepared = Some(source);
    }
    pub(crate) fn packet(&self) -> Option<Packet> {
        self.state.packet.clone()
    }
    pub(crate) fn approval_context(&self) -> Result<(String, String)> {
        let id = self.state.packet.as_ref().and_then(|p| p.turn_id.as_ref()).ok_or(Error::State)?;
        let turn = self.state.turns.get(id).ok_or(Error::State)?;
        Ok((turn.conversation.clone(), turn.message.clone()))
    }
    pub(crate) fn output_done(&mut self) {
        if let Some(packet) = &mut self.state.packet {
            packet.outputs.pop_front();
        }
    }
    pub(crate) fn approval_done(&mut self) {
        if let Some(packet) = &mut self.state.packet {
            packet.approval = None;
        }
    }
    pub(crate) fn finish_packet(&mut self) {
        let Some(packet) = self.state.packet.take() else {
            return;
        };
        if packet.rpc_id.is_some()
            && let Some(turn) = packet.turn_id.as_ref().and_then(|id| self.state.turns.get_mut(id))
            && turn.seen.len() < 512
        {
            turn.seen.insert(packet.key);
        }
        if let (Some(generation), Some(id)) = (packet.rpc_generation, packet.rpc_id) {
            self.answers.push_back((generation, id, packet.error));
        }
    }
    pub(crate) fn refuse_decider(&mut self, conversation: &str) {
        if let Some(turn) =
            self.active.get(conversation).and_then(|id| self.state.turns.get_mut(id))
        {
            if let Some(approval) = &mut turn.approval {
                approval.refused = true;
            }
            turn.final_sent = true;
        }
    }
    pub(crate) fn set_decider(&mut self, sender: Value, grant: String) {
        self.decider = Some((sender, grant));
    }
    pub(crate) fn terminal(&self, conversation: &str) -> Option<bool> {
        self.state
            .turns
            .values()
            .filter(|t| t.conversation == conversation)
            .filter_map(|t| t.terminal_at.map(|at| (at, t.final_received)))
            .max_by_key(|(at, _)| *at)
            .map(|(_, ok)| ok)
    }
    pub(crate) fn update_task(&mut self, conversation: &str, view: &Value) {
        for turn in self
            .state
            .turns
            .values_mut()
            .filter(|t| t.conversation == conversation && t.terminal_at.is_none())
        {
            turn.task = Some(view.clone());
        }
    }
    pub(crate) fn erase(
        &mut self,
        conversation: &str,
        message: &str,
        deleted_by: &Value,
        now: u64,
    ) -> Result<()> {
        let key = format!("rf:erase:{conversation}:{message}");
        if !self.state.erases.contains_key(&key) && self.state.erases.len() >= 1024 {
            self.warn("erase_outbox_full", now);
            return Err(Error::Bus);
        }
        let ids = self
            .state
            .turns
            .iter()
            .filter(|(_, t)| t.conversation == conversation && t.message == message)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            if let Some(admission) = self.inflight.get(&format!("in:{id}")) {
                let _ = admission.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
            }
            self.state.inbound.remove(&id);
            if let Some(turn) = self.state.turns.remove(&id)
                && let Some(approval) = turn.approval
            {
                self.state.decisions.remove(&format!("rf:approval:{}", approval.id));
            }
            if self.active.get(conversation) == Some(&id) {
                self.active.remove(conversation);
            }
            if self.state.packet.as_ref().is_some_and(|p| p.turn_id.as_deref() == Some(&id))
                && let Some(packet) = self.state.packet.take()
                && let (Some(generation), Some(id)) = (packet.rpc_generation, packet.rpc_id)
            {
                self.answers.push_back((generation, id, None));
            }
        }
        let turn_id = format!(
            "rf-{}",
            ramflux_protocol::hash_base64url(
                "ramflux.agent.prx_bridge.turn.v1",
                &ramflux_protocol::canonical_json_bytes(&(conversation, message))
                    .map_err(|_| Error::State)?
            )
        );
        let waiting = format!("in:{turn_id}");
        let wait_input = self.inflight.contains_key(&waiting).then_some(waiting);
        self.state.erases.entry(key.clone()).or_insert(Erase {
            params: json!({"conversation_id":conversation,"message_id":message,
            "deleted_by":deleted_by,"timestamp_ms":now,"idempotency_key":key}),
            next_at: now,
            attempts: 0,
            wait_hello: false,
            wait_input,
        });
        self.schedule(now);
        Ok(())
    }
    pub(crate) fn offline(&mut self, now: u64) {
        for conversation in self.active.keys() {
            let key = format!("offline:{conversation}");
            self.state.controls.insert(
                key.clone(),
                Call {
                    method: "inbound.control".into(),
                    params: json!({"conversation_id":conversation,
                "kind":"agent_offline","timestamp_ms":now,"idempotency_key":key}),
                },
            );
        }
        self.schedule(now);
    }
    fn decision(&mut self, value: HumanDecision<'_>) -> Result<()> {
        let HumanDecision { conversation, approval_id, decision, grant, sender, now } = value;
        let id = self.active.get(conversation).ok_or(Error::EngineRejected)?.clone();
        let turn = self.state.turns.get(&id).ok_or(Error::State)?;
        let pending =
            turn.approval.as_ref().filter(|a| a.id == approval_id).ok_or(Error::EngineRejected)?;
        if decision != "expired" {
            if sender["principal_id"] != turn.sender["principal_id"]
                || sender["device_id"] != turn.sender["device_id"]
            {
                self.refuse_decider(conversation);
                self.count(&["approvals", "refused_device"]);
                return Err(Error::EngineRejected);
            }
            if sender["kind"] != "human" || sender["trust"] != "verified" {
                self.refuse_decider(conversation);
                self.count(&["approvals", "refused_unverified"]);
                return Err(Error::EngineRejected);
            }
            if now >= pending.deadline {
                return Err(Error::EngineRejected);
            }
        }
        let key = format!("rf:approval:{approval_id}");
        self.state.decisions.insert(
            key.clone(),
            Call {
                method: "approval.decision".into(),
                params: json!({"conversation_id":conversation,
            "approval_id":approval_id,"decision":decision,"grant_id":grant,"decided_by":sender,
            "decided_at_ms":now,"idempotency_key":key}),
            },
        );
        self.count(&["approvals", decision]);
        Ok(())
    }
    fn send(&mut self, tag: String, call: Call) -> bool {
        if self.retry_at.get(&tag).is_some_and(|(at, _)| crate::bus::now_ms() < *at) {
            return true;
        }
        if self.inflight.contains_key(&tag) {
            return true;
        }
        let control = match call.method.as_str() {
            "inbound.control" => call.params["kind"]
                .as_str()
                .filter(|kind| matches!(*kind, "agent_revoked" | "agent_offline")),
            "turn.cancel" => Some("turn_cancel"),
            _ => None,
        }
        .map(str::to_owned);
        let admission = Arc::new(AtomicU8::new(0));
        match self.transport.commands.try_send(Command::Call {
            tag: tag.clone(),
            method: call.method,
            params: call.params,
            admission: Arc::clone(&admission),
        }) {
            Ok(()) => {
                if tag.starts_with("erase:") {
                    self.count(&["erases", "sent"]);
                }
                if let Some(kind) = control {
                    self.count(&["controls", &kind]);
                }
                self.inflight.insert(tag, admission);
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => false,
            Err(_) => {
                self.connected = false;
                false
            }
        }
    }
    fn response(&mut self, tag: &str, result: &Value, error: Option<i64>, now: u64) {
        self.inflight.remove(tag);
        if error.is_some() {
            let attempts = self.retry_at.get(tag).map_or(1, |(_, n)| n.saturating_add(1));
            self.retry_at.insert(
                tag.into(),
                (
                    now.saturating_add((1u64 << attempts.saturating_sub(1).min(6)).min(60) * 1000),
                    attempts,
                ),
            );
        } else {
            self.retry_at.remove(tag);
        }
        if matches!(error, Some(-32001 | -32002)) {
            self.reconnect_needed = true;
        }
        if let Some(id) = tag.strip_prefix("in:") {
            if error.is_none() {
                self.state.inbound.remove(id);
            } else if let Some(turn) = self.state.turns.get_mut(id) {
                turn.submitted_at = None;
                self.active.remove(&turn.conversation);
            }
        } else if let Some(key) = tag.strip_prefix("erase:") {
            if error.is_none() && result["erased"] == true {
                self.state.erases.remove(key);
                self.count(&["erases", "acked"]);
            } else if let Some(erase) = self.state.erases.get_mut(key) {
                erase.attempts = erase.attempts.saturating_add(1);
                erase.next_at = now.saturating_add(
                    (1u64 << erase.attempts.saturating_sub(1).min(6)).min(60) * 1000,
                );
                erase.wait_hello = matches!(error, Some(-32001 | -32002));
                self.count(&["erases", "retried"]);
            }
        } else if error.is_none() {
            self.state.controls.remove(tag);
            self.state.decisions.remove(tag);
        }
    }
}
impl Drop for PrxBridgeEngine {
    fn drop(&mut self) {
        self.print_stats(crate::bus::now_ms(), true);
    }
}
impl PrxBridgeEngine {
    fn submit_inner(&mut self, input: &EngineInput<'_>, now: u64) -> Result<Vec<EngineEvent>> {
        let source = self.prepared.take().ok_or(Error::State)?;
        let c = input.conversation.conversation_id;
        let m = input.conversation.message_id;
        let turn_id = format!(
            "rf-{}",
            ramflux_protocol::hash_base64url(
                "ramflux.agent.prx_bridge.turn.v1",
                &ramflux_protocol::canonical_json_bytes(&(c, m)).map_err(|_| Error::State)?
            )
        );
        if self.state.turns.contains_key(&turn_id) {
            return Ok(Vec::new());
        }
        if self.state.turns.len() >= MAX_TRACKED_TURNS
            || self.state.inbound.len() >= self.config.max_queued_inbound
            || self.state.inbound.values().filter(|i| i.params["conversation_id"] == c).count() >= 8
        {
            self.count(&["queue_full"]);
            return Ok(vec![EngineEvent::VisibleFailure {
                conversation_id: c.into(),
                message_id: m.into(),
                reason: crate::EngineFailure::Busy,
            }]);
        }
        let previous = self.state.clone();
        self.state.inbound.insert(turn_id.clone(),Inbound{turn_id:turn_id.clone(),queued_at:now,order:now,
            params:json!({"conversation_id":c,"message_id":m,"sender":source.sender,"chat":source.chat,
                "text":input.conversation.text,"attachments":[],"timestamp_ms":source.timestamp_ms,"reply_to":source.reply_to,"turn_id":turn_id,
                "idempotency_key":format!("rf:in:{c}:{m}")})});
        self.state.turns.insert(
            turn_id,
            Turn {
                conversation: c.into(),
                message: m.into(),
                sender: source.sender,
                templates: source.templates,
                submitted_at: None,
                was_sent: false,
                terminal_at: None,
                seen: HashSet::new(),
                text: String::new(),
                final_received: false,
                final_sent: false,
                stream: None,
                task: source.task,
                approval: None,
            },
        );
        let reserve = self
            .state
            .turns
            .values()
            .filter(|t| t.terminal_at.is_none())
            .count()
            .saturating_mul(180_000);
        if serde_json::to_vec(&self.state).map_err(|_| Error::State)?.len().saturating_add(reserve)
            > 10_000_000
        {
            self.state = previous;
            self.count(&["queue_full"]);
            return Ok(vec![EngineEvent::VisibleFailure {
                conversation_id: c.into(),
                message_id: m.into(),
                reason: crate::EngineFailure::Busy,
            }]);
        }
        self.schedule(now);
        Ok(Vec::new())
    }
    fn poll_inner(&mut self, now: u64) -> Result<Vec<EngineEvent>> {
        let mut processed = 0usize;
        while self.state.packet.is_none() && processed < 64 && self.answers.len() < 256 {
            let Ok(event) = self.transport.events.try_recv() else {
                break;
            };
            processed += 1;
            match event {
                Event::Connected => {
                    self.connected = true;
                    self.count(&["connects"]);
                    for erase in self.state.erases.values_mut() {
                        erase.wait_hello = false;
                    }
                    self.schedule(now);
                }
                Event::Disconnected => {
                    self.connected = false;
                    for token in self.inflight.values() {
                        let _ = token.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
                    }
                    self.inflight.clear();
                    self.count(&["disconnects"]);
                }
                Event::Backoff(delay) => {
                    self.stats["retry_delay_s"] = json!(delay);
                    self.stats_dirty = true;
                }
                Event::HelloRefused(code) => {
                    let code = match code {
                        -32003 => "-32003",
                        -32004 => "-32004",
                        -32006 => "-32006",
                        _ => "other",
                    };
                    self.count(&["hello_refused", code]);
                }
                Event::Response { tag, result, error } => self.response(&tag, &result, error, now),
                Event::Rejected { oversize } => {
                    self.count(&["frames_rejected", if oversize { "oversize" } else { "parse" }]);
                }
                Event::LateAck => self.count(&["late_acks"]),
                Event::Request { generation, frame } => {
                    self.render(&frame, generation, now)?;
                    if self
                        .state
                        .packet
                        .as_ref()
                        .is_some_and(|p| p.outputs.is_empty() && p.approval.is_none())
                    {
                        self.finish_packet();
                    }
                }
            }
        }
        if self.state.packet.is_none() && !self.answers.is_empty() {
            return Ok(vec![EngineEvent::BridgeWork {
                key: "durable-receipt-batch".into(),
                conversation_id: String::new(),
            }]);
        }
        Ok(self
            .state
            .packet
            .as_ref()
            .map(|p| EngineEvent::BridgeWork {
                key: p.key.clone(),
                conversation_id: p
                    .turn_id
                    .as_ref()
                    .and_then(|id| self.state.turns.get(id))
                    .map_or_else(String::new, |t| t.conversation.clone()),
            })
            .into_iter()
            .collect())
    }
    fn decide_inner(
        &mut self,
        conversation: &str,
        _message: &str,
        decision_id: &str,
        approved: bool,
        now: u64,
    ) -> Result<()> {
        if let Some((sender, grant)) = self.decider.take() {
            self.decision(HumanDecision {
                conversation,
                approval_id: decision_id,
                decision: if approved { "approved" } else { "denied" },
                grant: Some(&grant),
                sender: &sender,
                now,
            })
        } else if !approved {
            let turn_id = self.active.get(conversation).ok_or(Error::EngineRejected)?;
            let sender = self.state.turns.get(turn_id).ok_or(Error::State)?.sender.clone();
            self.decision(HumanDecision {
                conversation,
                approval_id: decision_id,
                decision: "expired",
                grant: None,
                sender: &sender,
                now,
            })
        } else {
            Err(Error::EngineRejected)
        }
    }
    fn cancel_inner(&mut self, c: &str) {
        let ids = self
            .state
            .turns
            .iter()
            .filter(|(_, t)| t.conversation == c)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            if self.state.packet.as_ref().is_some_and(|p| p.turn_id.as_ref() == Some(&id))
                && let Some(packet) = self.state.packet.take()
                && let (Some(generation), Some(rpc)) = (packet.rpc_generation, packet.rpc_id)
            {
                self.answers.push_back((generation, rpc, None));
            }
            if let Some(token) = self.inflight.get(&format!("in:{id}")) {
                let _ = token.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
            }
            self.state.inbound.remove(&id);
            if self.state.turns.remove(&id).is_some_and(|turn| turn.terminal_at.is_none()) {
                self.state.controls.insert(format!("cancel:{id}"),Call{method:"turn.cancel".into(),params:json!({"conversation_id":c,"turn_id":id,"reason":"conversation_removed"})});
            }
        }
        self.active.remove(c);
        self.state.decisions.retain(|_, d| d.params["conversation_id"] != c);
        self.schedule(crate::bus::now_ms());
    }
}
impl EngineProvider for PrxBridgeEngine {
    fn maintenance(&mut self, now: u64) -> Result<()> {
        if self.state.packet.is_none() {
            self.timers(now)?;
        }
        self.schedule(now);
        self.print_stats(now, false);
        Ok(())
    }
    fn wake(&self) -> impl std::future::Future<Output = ()> {
        let immediate = !self.transport.events.is_empty()
            || self.state.packet.is_some()
            || self.connected
                && (!self.answers.is_empty() || !self.send_queue.is_empty())
                && self.transport.commands.capacity() > 0;
        let ready = Arc::clone(&self.transport.ready);
        async move {
            if !immediate {
                ready.notified().await;
            }
        }
    }

    fn bridge(&mut self) -> Option<&mut Self> {
        Some(self)
    }
    fn intents(&mut self, _: &ConversationInput<'_>) -> Result<Vec<Intent>> {
        Err(Error::State)
    }
    fn is_busy(&self, conversation: &str) -> bool {
        self.state.inbound.values().filter(|i| i.params["conversation_id"] == conversation).count()
            >= 8
    }
    fn submit(
        &mut self,
        input: EngineInput<'_>,
        now: u64,
    ) -> impl std::future::Future<Output = Result<Vec<EngineEvent>>> {
        std::future::ready(self.submit_inner(&input, now))
    }
    fn poll(&mut self, now: u64) -> impl std::future::Future<Output = Result<Vec<EngineEvent>>> {
        std::future::ready(self.poll_inner(now))
    }
    fn persisted(&mut self) -> Result<()> {
        if self.reconnect_needed {
            if self.transport.commands.try_send(Command::Reconnect).is_ok() {
                self.reconnect_needed = false;
                self.connected = false;
            }
            return Ok(());
        }
        if !self.connected {
            return Ok(());
        }
        while let Some((generation, id, code)) = self.answers.pop_front() {
            if let Err(error) =
                self.transport.commands.try_send(Command::Answer { generation, id, code })
            {
                if let Command::Answer { generation, id, code } = error.into_inner() {
                    self.answers.push_front((generation, id, code));
                }
                break;
            }
        }
        // Queue selection runs only on admission, lifecycle events or maintenance.
        // Frame acknowledgements perform bounded O(1) lookups, without scanning state.
        while let Some(tag) = self.send_queue.front().cloned() {
            if let Some(call) = self.queued_call(&tag)
                && !self.send(tag.clone(), call)
            {
                break;
            }
            self.send_queue.pop_front();
            self.scheduled.remove(&tag);
        }
        Ok(())
    }
    fn decide(
        &mut self,
        conversation: &str,
        message: &str,
        decision_id: &str,
        approved: bool,
        now: u64,
    ) -> impl std::future::Future<Output = Result<()>> {
        std::future::ready(self.decide_inner(conversation, message, decision_id, approved, now))
    }
    fn cancel(&mut self, c: &str) -> impl std::future::Future<Output = Result<()>> {
        {
            self.cancel_inner(c);
            std::future::ready(Ok(()))
        }
    }
    async fn revoke(&mut self, c: &str) -> Result<()> {
        self.cancel(c).await?;
        let now = crate::bus::now_ms();
        self.state.controls.insert(
            format!("revoke:{c}"),
            Call {
                method: "inbound.control".into(),
                params: json!({"conversation_id":c,
            "kind":"agent_revoked","timestamp_ms":now,"idempotency_key":format!("rf:revoke:{c}")}),
            },
        );
        self.schedule(now);
        Ok(())
    }
    fn checkpoint(&self) -> Result<Option<Value>> {
        Ok(Some(serde_json::to_value(&self.state).map_err(|_| Error::State)?))
    }
    fn restore(&mut self, value: Option<&Value>) -> Result<()> {
        if let Some(value) = value.filter(|v| !v.is_null()) {
            let mut state: State =
                serde_json::from_value(value.clone()).map_err(|_| Error::State)?;
            if state.kind != KIND
                || state.inbound.len() > self.config.max_queued_inbound
                || state.erases.len() > 1024
                || state.turns.len() > MAX_TRACKED_TURNS
                || state.controls.len() > 4096
                || state.decisions.len() > 64
                || !state.valid_queues()
                || state.turns.values().any(|t| {
                    t.seen.len() > 512
                        || t.text.len() > MAX_BUFFER
                        || t.templates.len() > 96
                        || !t.valid_buffers()
                        || t.conversation.is_empty()
                        || t.conversation.len() > 1024
                        || t.message.is_empty()
                        || t.message.len() > 1024
                })
                || serde_json::to_vec(&state).map_err(|_| Error::State)?.len() > 15_000_000
            {
                return Err(Error::State);
            }
            let active_count = state
                .turns
                .values()
                .filter(|t| t.submitted_at.is_some() && t.terminal_at.is_none())
                .count();
            let active_conversations = state
                .turns
                .values()
                .filter(|t| t.submitted_at.is_some() && t.terminal_at.is_none())
                .map(|t| &t.conversation)
                .collect::<HashSet<_>>();
            if active_count > self.maximum || active_count != active_conversations.len() {
                return Err(Error::State);
            }
            let now = crate::bus::now_ms();
            for turn in state.turns.values_mut() {
                if let Some(at) = &mut turn.submitted_at {
                    *at = (*at).min(now);
                }
                if let Some(approval) = &mut turn.approval {
                    approval.deadline = approval
                        .deadline
                        .min(now.saturating_add(self.config.approval_timeout_s * 1000));
                }
            }
            self.state = state;
            self.active = self
                .state
                .turns
                .iter()
                .filter(|(_, t)| t.submitted_at.is_some() && t.terminal_at.is_none())
                .map(|(id, t)| (t.conversation.clone(), id.clone()))
                .collect();
        }
        Ok(())
    }
    fn active_conversations(&self) -> Vec<String> {
        self.state
            .turns
            .values()
            .map(|t| t.conversation.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
#[path = "../tests/support/prx_bridge.rs"]
mod test_support;
#[cfg(test)]
#[path = "prx_bridge/tests.rs"]
mod tests;
