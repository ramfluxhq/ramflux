// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded frame projection with stable local operations and independently versioned surfaces.
use super::{
    Call, MAX_BUFFER, Packet, PrxBridgeEngine, Turn,
    state::{Approval, Stream},
};
use crate::{EngineApproval, EngineFailure, Error, PrxAuthorization, Result, checkpoint::Output};
use ramflux_protocol::{
    A2uiConversationCommand as Command, CreateSurfaceCommand, DeleteSurfaceCommand,
    PatchSurfaceCommand, StreamAppendCommand, SurfacePatchOp, SurfaceType,
};
use serde_json::{Value, json};
use std::collections::VecDeque;
fn prefix(text: &str, limit: usize) -> &str {
    text.get(..text.floor_char_boundary(text.len().min(limit))).unwrap_or("")
}
fn operation(key: &str, index: usize) -> Result<String> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.agent.prx_bridge.op.v1",
        &ramflux_protocol::canonical_json_bytes(&(key, index)).map_err(|_| Error::State)?,
    ))
}
#[derive(Clone, Copy)]
struct Append<'a> {
    turn_id: &'a str,
    key: &'a str,
    version: u64,
    delta: &'a str,
    now: u64,
}
#[derive(Clone, Copy)]
struct Frame<'a> {
    turn_id: &'a str,
    key: &'a str,
    now: u64,
}
impl PrxBridgeEngine {
    fn text_outputs(turn: &Turn, key: &str, text: &str, now: u64) -> Result<Vec<Output>> {
        let mut outputs = Vec::new();
        let suffix = " […]";
        let mut text = if text.len() > MAX_BUFFER {
            format!("{}{suffix}", prefix(text, MAX_BUFFER - suffix.len()))
        } else {
            text.to_owned()
        };
        if text.is_empty() {
            return Ok(outputs);
        }
        for (part, chunk) in crate::engine::chunks(&text, 16_384).into_iter().take(4).enumerate() {
            for template in &turn.templates {
                let index = outputs.len();
                let op = operation(key, index)?;
                let mut output = template.clone();
                output.operation_id.clone_from(&op);
                let logical = operation(&format!("{key}:text"), part)?;
                output.body["message_id"] = json!(format!("prx-{logical}"));
                output.body["envelope_id"] = json!(format!("prx-env-{op}"));
                output.body["plaintext_body_base64"] =
                    json!(ramflux_protocol::encode_base64url(chunk.as_bytes()));
                output.body["created_at"] = json!(now / 1000);
                output.body["ttl"] = json!(300);
                outputs.push(output);
            }
        }
        text.clear();
        Ok(outputs)
    }
    fn surface_output(
        turn: &Turn,
        key: &str,
        index: usize,
        version: u64,
        command: &Command,
    ) -> Result<Output> {
        let mut request =
            ramflux_sdk::SurfaceSendRequest::event(&turn.conversation, version, command)
                .map_err(|_| Error::Limit)?;
        let op = operation(key, index)?;
        request.message_id = format!("prx-surface-{op}");
        Ok(Output {
            method: "surface.send".into(),
            operation_id: op,
            body: serde_json::to_value(request).map_err(|_| Error::State)?,
        })
    }
    fn new_stream(turn_id: &str, remote: u64, block: u64, now: u64, flush: u64) -> Stream {
        let surface_id = format!("prx-stream-{turn_id}-{block}");
        Stream {
            surface_id: surface_id.clone(),
            remote_version: remote,
            local_version: 1,
            block,
            appends: 0,
            total_appends: 0,
            snapshot: CreateSurfaceCommand {
                surface_id,
                surface_type: SurfaceType::StatusPanel,
                catalog: "basic".into(),
                catalog_version: "1".into(),
                fallback_text: "Working".into(),
                fallback_markdown: None,
                components: vec![json!({"id":"reply","type":"Text","text":""})],
                data_model: serde_json::Map::from_iter([
                    ("agent_host".into(), json!("ramflux.agent.prx_bridge.v1")),
                    ("block".into(), json!(block)),
                ]),
                allowed_actions: vec![],
            },
            buffered: String::new(),
            buffer_key: String::new(),
            flush_at: now.saturating_add(flush),
            closing: false,
        }
    }
    fn flush_stream(
        &mut self,
        turn: &mut Turn,
        key: &str,
        final_: bool,
        fallback: &str,
    ) -> Result<Vec<Output>> {
        let Some(mut stream) = turn.stream.take() else {
            return Ok(Vec::new());
        };
        let mut output = Vec::new();
        let budget = if final_ { 60 } else { 59 };
        let mut final_empty = final_ && stream.buffered.is_empty();
        while (!stream.buffered.is_empty() || final_empty) && stream.total_appends < budget {
            let delta =
                prefix(&stream.buffered, ramflux_protocol::MAX_SURFACE_TEXT_DELTA_BYTES).to_owned();
            let last = delta.len() == stream.buffered.len();
            stream.local_version = stream.local_version.checked_add(1).ok_or(Error::Limit)?;
            output.push(Self::surface_output(
                turn,
                key,
                output.len(),
                stream.local_version,
                &Command::StreamAppend(StreamAppendCommand {
                    surface_id: stream.surface_id.clone(),
                    component_id: "reply".into(),
                    text_delta: delta.clone(),
                    final_: final_ && last,
                }),
            )?);
            let previous = stream.snapshot.components[0]["text"].as_str().unwrap_or("").to_owned();
            stream.snapshot.components[0]["text"] = json!(format!("{previous}{delta}"));
            stream.buffered.drain(..delta.len());
            stream.appends = stream.appends.saturating_add(1);
            stream.total_appends = stream.total_appends.saturating_add(1);
            final_empty = false;
            self.count(&["stream_appends_sent"]);
            // Ordinary maintenance emits one append; closing batches must drain before close.
            if !final_ {
                break;
            }
        }
        if final_ && !stream.buffered.is_empty() {
            self.count(&["stream_capped"]);
        }
        if final_ {
            let base = ramflux_protocol::surface_snapshot_hash(&stream.snapshot)
                .map_err(|_| Error::State)?;
            let fallback = Self::fitted_fallback(&mut stream.snapshot, fallback)?;
            stream.local_version = stream.local_version.checked_add(1).ok_or(Error::Limit)?;
            output.push(Self::surface_output(
                turn,
                key,
                output.len(),
                stream.local_version,
                &Command::PatchSurface(PatchSurfaceCommand {
                    surface_id: stream.surface_id.clone(),
                    base_surface_hash: base,
                    ops: vec![SurfacePatchOp::SetFallbackText { fallback_text: fallback }],
                    new_surface_hash: ramflux_protocol::surface_snapshot_hash(&stream.snapshot)
                        .map_err(|_| Error::State)?,
                }),
            )?);
            stream.local_version = stream.local_version.checked_add(1).ok_or(Error::Limit)?;
            output.push(Self::surface_output(
                turn,
                key,
                output.len(),
                stream.local_version,
                &Command::DeleteSurface(DeleteSurfaceCommand {
                    surface_id: stream.surface_id,
                    reason: None,
                }),
            )?);
        } else {
            turn.stream = Some(stream);
        }
        Ok(output)
    }
    fn fitted_fallback(snapshot: &mut CreateSurfaceCommand, text: &str) -> Result<String> {
        let mut low = 0usize;
        let mut high = text.len().min(15_360);
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            snapshot.fallback_text = prefix(text, middle).into();
            if ramflux_protocol::canonical_json_bytes(snapshot).map_err(|_| Error::State)?.len()
                <= ramflux_protocol::MAX_SURFACE_DATA_BYTES
            {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        snapshot.fallback_text = prefix(text, low).into();
        Ok(snapshot.fallback_text.clone())
    }
    fn fitted_delta<'a>(stream: &Stream, text: &'a str, limit: usize) -> Result<&'a str> {
        let mut snapshot = stream.snapshot.clone();
        let base =
            snapshot.components[0]["text"].as_str().unwrap_or("").to_owned() + &stream.buffered;
        let mut low = 0usize;
        let mut high = text.len().min(limit);
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            snapshot.components[0]["text"] = json!(format!("{base}{}", prefix(text, middle)));
            if ramflux_protocol::canonical_json_bytes(&snapshot).map_err(|_| Error::State)?.len()
                <= ramflux_protocol::MAX_SURFACE_DATA_BYTES
            {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        Ok(prefix(text, low))
    }
    fn append_stream(&mut self, turn: &mut Turn, append: Append<'_>) -> Result<Vec<Output>> {
        let Append { turn_id, key, version, delta, now } = append;
        let mut outputs = Vec::new();
        if turn.stream.is_none() {
            if version != 1 {
                self.count(&["stream_gap"]);
                return Ok(outputs);
            }
            let stream = Self::new_stream(turn_id, 0, 0, now, self.config.stream_flush_ms);
            outputs.push(Self::surface_output(
                turn,
                key,
                outputs.len(),
                1,
                &Command::CreateSurface(stream.snapshot.clone()),
            )?);
            turn.stream = Some(stream);
        }
        let mut stream = turn.stream.take().ok_or(Error::State)?;
        if version != stream.remote_version.saturating_add(1) {
            turn.stream = Some(stream);
            self.count(&["stream_gap"]);
            return Ok(outputs);
        }
        stream.remote_version = version;
        let limit = self.config.stream_max_bytes.min(15_360);
        let mut remaining = prefix(delta, MAX_BUFFER);
        while !remaining.is_empty() {
            let current = stream.snapshot.components[0]["text"].as_str().map_or(0, str::len)
                + stream.buffered.len();
            if current >= limit
                || Self::fitted_delta(&stream, remaining, limit.saturating_sub(current))?.is_empty()
            {
                if stream.block >= 3 || stream.total_appends >= 59 {
                    self.count(&["stream_capped"]);
                    break;
                }
                let block = stream.block + 1;
                let total = stream.total_appends
                    + u64::try_from(
                        stream
                            .buffered
                            .len()
                            .max(1)
                            .div_ceil(ramflux_protocol::MAX_SURFACE_TEXT_DELTA_BYTES),
                    )
                    .map_err(|_| Error::Limit)?;
                let old = stream.snapshot.components[0]["text"].as_str().unwrap_or("").to_owned()
                    + &stream.buffered;
                turn.stream = Some(stream);
                outputs.extend(self.flush_stream(
                    turn,
                    &format!("{key}:close:{block}"),
                    true,
                    &old,
                )?);
                stream =
                    Self::new_stream(turn_id, version, block, now, self.config.stream_flush_ms);
                stream.total_appends = total.min(60);
                outputs.push(Self::surface_output(
                    turn,
                    &format!("{key}:create:{block}"),
                    0,
                    1,
                    &Command::CreateSurface(stream.snapshot.clone()),
                )?);
            }
            let current = stream.snapshot.components[0]["text"].as_str().map_or(0, str::len)
                + stream.buffered.len();
            let part = Self::fitted_delta(&stream, remaining, limit.saturating_sub(current))?;
            if part.is_empty() {
                self.count(&["stream_capped"]);
                break;
            }
            stream.buffered.push_str(part);
            stream.buffer_key = key.into();
            remaining = &remaining[part.len()..];
        }
        turn.stream = Some(stream);
        Ok(outputs)
    }
    fn progress(
        &mut self,
        turn: &mut Turn,
        turn_id: &str,
        key: &str,
        params: &Value,
        now: u64,
    ) -> Result<Vec<Output>> {
        let label = params["tool_name"]
            .as_str()
            .unwrap_or("tool")
            .chars()
            .filter(char::is_ascii_graphic)
            .take(80)
            .collect::<String>();
        let state = match params["kind"].as_str() {
            Some("finished") => "done",
            Some("failed") => "failed",
            _ => "running",
        };
        if let Some(task) =
            turn.task.as_mut().filter(|t| t["state"] == "running" && t["accepted"] == true)
        {
            let task_id = task["task_id"].as_str().ok_or(Error::State)?.to_owned();
            let step = format!(
                "prx-{}",
                ramflux_protocol::hash_base64url(
                    "ramflux.agent.prx_bridge.tool.v1",
                    params["tool_call_id"].as_str().unwrap_or("tool").as_bytes()
                )
            );
            let mut steps = task["steps"].as_array().cloned().unwrap_or_default();
            let row = json!({"id":step,"title":format!("{label} ({state})"),"state":state});
            if let Some(existing) = steps.iter_mut().find(|s| s["id"] == step) {
                *existing = row;
            } else if steps.len() < 32 {
                steps.push(row);
            } else {
                return Ok(Vec::new());
            }
            let version =
                task["version"].as_u64().ok_or(Error::State)?.checked_add(1).ok_or(Error::Limit)?;
            let op = operation(key, 0)?;
            task["version"] = json!(version);
            task["steps"] = json!(steps);
            return Ok(vec![Output {
                method: "task.update".into(),
                operation_id: op.clone(),
                body: json!({"conversation_id":turn.conversation,"task_id":task_id,
                "message_id":format!("prx-tool-{op}"),"version":version,"state":"running","steps":steps}),
            }]);
        }
        let delta = format!("\n{label}: {state}\n");
        let version = turn.stream.as_ref().map_or(1, |s| s.remote_version.saturating_add(1));
        let remote = turn.stream.as_ref().map_or(0, |s| s.remote_version);
        let outputs =
            self.append_stream(turn, Append { turn_id, key, version, delta: &delta, now })?;
        if let Some(stream) = &mut turn.stream {
            stream.remote_version = remote;
        }
        Ok(outputs)
    }
    fn render_reply(
        &mut self,
        method: &str,
        turn: &mut Turn,
        params: &Value,
        context: Frame<'_>,
    ) -> Result<Vec<Output>> {
        let Frame { turn_id, key, now } = context;
        match method {
            "reply.text" => {
                let text = params["text"].as_str().ok_or(Error::EngineRejected)?;
                if turn.final_sent {
                    return Ok(Vec::new());
                }
                if params["final"] == true && text.starts_with(&turn.text) {
                    turn.text = prefix(text, MAX_BUFFER).into();
                } else {
                    let left = MAX_BUFFER.saturating_sub(turn.text.len());
                    turn.text.push_str(prefix(text, left));
                }
                if params["final"] == true {
                    turn.final_received = true;
                    turn.final_sent = true;
                    Self::text_outputs(turn, key, &turn.text, now)
                } else {
                    Ok(Vec::new())
                }
            }
            "reply.surface" => match params["op"].as_str() {
                Some("stream_append") => self.append_stream(
                    turn,
                    Append {
                        turn_id,
                        key,
                        version: params["version"].as_u64().ok_or(Error::EngineRejected)?,
                        delta: params["text_delta"].as_str().ok_or(Error::EngineRejected)?,
                        now,
                    },
                ),
                Some("close") => {
                    if turn.stream.as_ref().is_none_or(|s| {
                        params["version"].as_u64() != Some(s.remote_version.saturating_add(1))
                    }) {
                        self.count(&["stream_gap"]);
                        return Ok(Vec::new());
                    }
                    self.flush_stream(
                        turn,
                        key,
                        true,
                        params["fallback_text"].as_str().unwrap_or(""),
                    )
                }
                Some("create") => {
                    let fallback = params["fallback_text"].as_str().unwrap_or("");
                    if params["surface_id"]
                        .as_str()
                        .is_some_and(|s| s == format!("final-{turn_id}"))
                    {
                        if !turn.final_received {
                            turn.text = prefix(fallback, MAX_BUFFER).into();
                        }
                        Ok(Vec::new())
                    } else {
                        Self::text_outputs(turn, key, fallback, now)
                    }
                }
                _ => Ok(Vec::new()),
            },
            _ => Ok(Vec::new()),
        }
    }
    fn render_approval(
        &mut self,
        turn: &mut Turn,
        params: &Value,
        context: Frame<'_>,
        packet: &mut Packet,
    ) -> Result<Vec<Output>> {
        let Frame { key, now, .. } = context;

        self.count(&["approvals", "requested"]);
        let id = params["approval_id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 256)
            .ok_or(Error::EngineRejected)?;
        let deadline = params["expires_at_ms"]
            .as_u64()
            .ok_or(Error::EngineRejected)?
            .min(now.saturating_add(self.config.approval_timeout_s * 1000));
        turn.approval = Some(Approval { id: id.into(), deadline, refused: false });
        if self.config.authorization == PrxAuthorization::Full {
            self.warn("authorization_mismatch", now);
            turn.final_sent = true;
            let call_key = format!("rf:approval:{id}");
            self.state.decisions.insert(call_key.clone(),Call{method:"approval.decision".into(),params:json!({"conversation_id":turn.conversation,
                            "approval_id":id,"decision":"expired","decided_by":turn.sender,"decided_at_ms":now,"idempotency_key":call_key})});
            self.queue(format!("rf:approval:{id}"));
            Self::text_outputs(turn, key, EngineFailure::AuthorizationMismatch.reply(), now)
        } else if turn.sender["kind"] != "human" || turn.sender["trust"] != "verified" {
            self.count(&["approvals", "refused_unverified"]);
            if let Some(approval) = &mut turn.approval {
                approval.refused = true;
            }
            turn.final_sent = true;
            Self::text_outputs(turn, key, EngineFailure::ApprovalUnavailable.reply(), now)
        } else {
            packet.approval_id = Some(id.into());
            packet.approval = Some(EngineApproval {
                tool: params["tool_name"]
                    .as_str()
                    .filter(|s| s.len() <= 256)
                    .ok_or(Error::EngineRejected)?
                    .into(),
                arguments_summary: params["arguments_redacted"].clone(),
                effect: params["risk"].as_str().unwrap_or("high").into(),
                call_digest: params["args_hash"]
                    .as_str()
                    .filter(|s| s.len() <= 256)
                    .ok_or(Error::EngineRejected)?
                    .into(),
                deadline_ms: deadline,
            });
            Ok(Vec::new())
        }
    }
    fn render_status(
        &mut self,
        turn: &mut Turn,
        params: &Value,
        context: Frame<'_>,
    ) -> Result<Vec<Output>> {
        let Frame { key, now, .. } = context;
        match params["state"].as_str() {
            Some("done") => {
                let fallback = turn.text.clone();
                let mut outputs =
                    self.flush_stream(turn, &format!("{key}:close"), true, &fallback)?;
                if !turn.final_sent {
                    outputs.extend(Self::text_outputs(turn, key, &turn.text, now)?);
                    turn.final_sent = true;
                }
                turn.terminal_at = Some(now);
                self.active.remove(&turn.conversation);
                Ok(outputs)
            }
            Some("failed" | "awaiting_approval") => {
                let reason = if params["state"] == "awaiting_approval" {
                    self.warn("prx_internal_approval_unavailable", now);
                    EngineFailure::PrxInternalApprovalUnavailable
                } else if turn.approval.is_some() {
                    EngineFailure::ApprovalTimeout
                } else {
                    EngineFailure::Rejected
                };
                turn.terminal_at = Some(now);
                self.active.remove(&turn.conversation);
                if turn.final_sent {
                    Ok(Vec::new())
                } else {
                    turn.final_sent = true;
                    Self::text_outputs(turn, key, reason.reply(), now)
                }
            }
            _ => Ok(Vec::new()),
        }
    }
    pub(super) fn render(&mut self, frame: &Value, generation: u64, now: u64) -> Result<()> {
        let method = frame["method"].as_str().filter(|m| m.len() <= 64).unwrap_or("");
        let params = &frame["params"];
        let turn_id =
            params["turn_id"].as_str().filter(|id| id.len() <= 256).unwrap_or("").to_owned();
        let key = params["idempotency_key"]
            .as_str()
            .filter(|k| k.len() <= 512)
            .map_or_else(|| format!("{turn_id}:{method}:{}", frame["id"]), str::to_owned);
        let key =
            ramflux_protocol::hash_base64url("ramflux.agent.prx_bridge.frame.v1", key.as_bytes());
        let supported = matches!(
            method,
            "reply.text"
                | "reply.surface"
                | "reply.task_update"
                | "reply.typing"
                | "tool.event"
                | "approval.request"
                | "turn.status"
        );
        let mut packet = Packet {
            key: key.clone(),
            turn_id: None,
            rpc_id: Some(frame["id"].clone()),
            rpc_generation: Some(generation),
            error: (!supported).then_some(-32601),
            outputs: VecDeque::new(),
            approval: None,
            approval_id: None,
        };
        if !supported {
            self.state.packet = Some(packet);
            return Ok(());
        }
        self.count(&["replies", method]);
        let Some(mut turn) = self.state.turns.remove(&turn_id) else {
            self.state.packet = Some(packet);
            return Ok(());
        };
        if params["conversation_id"] != turn.conversation
            || turn.terminal_at.is_some()
            || turn.seen.contains(&key)
            || turn.seen.len() >= 512
        {
            if turn.seen.contains(&key) {
                self.count(&["dup_frames"]);
            }
            self.state.turns.insert(turn_id, turn);
            self.state.packet = Some(packet);
            return Ok(());
        }
        packet.turn_id = Some(turn_id.clone());
        let context = Frame { turn_id: &turn_id, key: &key, now };
        let output = match method {
            "reply.text" | "reply.surface" => self.render_reply(method, &mut turn, params, context),
            "tool.event" => self.progress(&mut turn, &turn_id, &key, params, now),
            "approval.request" => self.render_approval(&mut turn, params, context, &mut packet),
            "turn.status" => self.render_status(&mut turn, params, context),
            _ => Ok(Vec::new()),
        };
        self.rendered(turn_id, turn, packet, output)
    }
    fn rendered(
        &mut self,
        turn_id: String,
        mut turn: Turn,
        mut packet: Packet,
        output: Result<Vec<Output>>,
    ) -> Result<()> {
        match output {
            Ok(outputs) => packet.outputs = outputs.into(),
            Err(_) => {
                self.count(&["frames_rejected", "parse"]);
            }
        }
        let buffered = turn.text.len()
            + turn.stream.as_ref().map_or(0, |s| {
                s.buffered.len() + s.snapshot.components[0]["text"].as_str().map_or(0, str::len)
            });
        if buffered > MAX_BUFFER {
            turn.text =
                prefix(&turn.text, MAX_BUFFER.saturating_sub(buffered - turn.text.len())).into();
            self.count(&["stream_capped"]);
        }
        if turn.terminal_at.is_some() {
            turn.text.clear();
            turn.templates.clear();
            turn.stream = None;
            turn.approval = None;
        }
        self.state.turns.insert(turn_id, turn);
        if serde_json::to_vec(&packet).map_err(|_| Error::State)?.len() > 262_144 {
            packet.outputs.clear();
            packet.approval = None;
            self.count(&["stream_capped"]);
        }
        self.state.packet = Some(packet);
        Ok(())
    }
    pub(super) fn timers(&mut self, now: u64) -> Result<()> {
        let expired = self
            .state
            .turns
            .iter()
            .filter(|(_, t)| t.terminal_at.is_some_and(|at| now >= at.saturating_add(600_000)))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            self.state.turns.remove(&id);
        }
        let ids = self.state.turns.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let Some(mut turn) = self.state.turns.remove(&id) else {
                continue;
            };
            let timeout = turn.terminal_at.is_none()
                && turn
                    .submitted_at
                    .is_some_and(|at| now >= at.saturating_add(self.config.turn_timeout_s * 1000));
            let approval_timeout = turn.terminal_at.is_none()
                && turn.approval.as_ref().is_some_and(|a| now >= a.deadline);
            let mut outputs = Vec::new();
            let key = format!("{id}:timer:{now}");
            if timeout || approval_timeout {
                self.state.controls.insert(format!("cancel:{id}"),Call{method:"turn.cancel".into(),params:json!({"conversation_id":turn.conversation,"turn_id":id,"reason":"host_turn_timeout"})});
                if let Some(approval) = turn.approval.as_ref().filter(|a| !a.refused) {
                    let key = format!("rf:approval:{}", approval.id);
                    self.state.decisions.insert(key.clone(),Call{method:"approval.decision".into(),params:json!({"conversation_id":turn.conversation,
                        "approval_id":approval.id,"decision":"expired","decided_by":turn.sender,"decided_at_ms":now,"idempotency_key":key})});
                    self.count(&["approvals", "expired"]);
                }
                let reason = if approval_timeout {
                    EngineFailure::ApprovalTimeout
                } else {
                    EngineFailure::TurnTimeout
                };
                if !turn.final_sent {
                    outputs = Self::text_outputs(&turn, &key, reason.reply(), now)?;
                    turn.final_sent = true;
                }
                turn.terminal_at = Some(now);
                self.active.remove(&turn.conversation);
                self.state.inbound.remove(&id);
            } else if turn
                .stream
                .as_ref()
                .is_some_and(|s| now >= s.flush_at && !s.buffered.is_empty())
            {
                outputs = self.flush_stream(&mut turn, &key, false, "")?;
                if let Some(stream) = &mut turn.stream {
                    stream.flush_at = now.saturating_add(self.config.stream_flush_ms);
                }
            }
            self.state.turns.insert(id.clone(), turn);
            if !outputs.is_empty() {
                self.state.packet = Some(Packet {
                    key,
                    turn_id: Some(id),
                    rpc_id: None,
                    rpc_generation: None,
                    error: None,
                    outputs: outputs.into(),
                    approval: None,
                    approval_id: None,
                });
                break;
            }
        }
        Ok(())
    }
}
