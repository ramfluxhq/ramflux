// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded bridge records serialized only within the host checkpoint.
use crate::{EngineApproval, checkpoint::Output};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub kind: String,
    pub inbound: HashMap<String, Inbound>,
    pub turns: HashMap<String, Turn>,
    pub erases: HashMap<String, Erase>,
    pub controls: HashMap<String, Call>,
    pub decisions: HashMap<String, Call>,
    pub packet: Option<Packet>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inbound {
    pub turn_id: String,
    pub params: Value,
    pub queued_at: u64,
    pub order: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Turn {
    pub conversation: String,
    pub message: String,
    pub sender: Value,
    pub templates: Vec<Output>,
    pub submitted_at: Option<u64>,
    #[serde(default)]
    pub was_sent: bool,
    pub terminal_at: Option<u64>,
    pub seen: HashSet<String>,
    pub text: String,
    pub final_received: bool,
    pub final_sent: bool,
    pub stream: Option<Stream>,
    pub task: Option<Value>,
    pub approval: Option<Approval>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Stream {
    pub surface_id: String,
    pub remote_version: u64,
    pub local_version: u64,
    pub block: u64,
    pub appends: u64,
    pub total_appends: u64,
    pub snapshot: ramflux_protocol::CreateSurfaceCommand,
    pub buffered: String,
    pub buffer_key: String,
    pub flush_at: u64,
    pub closing: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Approval {
    pub id: String,
    pub deadline: u64,
    #[serde(default)]
    pub refused: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Erase {
    pub params: Value,
    pub next_at: u64,
    pub attempts: u32,
    pub wait_hello: bool,
    #[serde(default)]
    pub wait_input: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Call {
    pub method: String,
    pub params: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Packet {
    pub key: String,
    pub turn_id: Option<String>,
    pub rpc_id: Option<Value>,
    #[serde(skip)]
    pub rpc_generation: Option<u64>,
    pub error: Option<i64>,
    pub outputs: VecDeque<Output>,
    pub approval: Option<EngineApproval>,
    pub approval_id: Option<String>,
}

impl Turn {
    pub(super) fn valid_buffers(&self) -> bool {
        if self.seen.iter().any(|key| key.len() != 43) {
            return false;
        }
        let stream_bytes = if let Some(stream) = &self.stream {
            if stream.snapshot.components.len() != 1
                || stream.block > 3
                || stream.total_appends > 60
                || stream.appends > 60
                || stream.buffer_key.len() > 512
            {
                return false;
            }
            let Some(text) = stream.snapshot.components[0]["text"].as_str() else {
                return false;
            };
            if stream.buffered.len() > 15_360 || text.len() + stream.buffered.len() > 15_360 {
                return false;
            }
            text.len() + stream.buffered.len()
        } else {
            0
        };
        self.text.len() + stream_bytes <= super::MAX_BUFFER
    }
}
impl State {
    pub(super) fn valid_queues(&self) -> bool {
        let mut counts = HashMap::<&str, usize>::new();
        for (id, input) in &self.inbound {
            let Some(turn) = self.turns.get(id) else {
                return false;
            };
            if input.turn_id != *id
                || input.params["conversation_id"] != turn.conversation
                || input.params["message_id"] != turn.message
                || input.params["text"]
                    .as_str()
                    .is_none_or(|s| s.len() > crate::config::MAX_TEXT_BYTES)
            {
                return false;
            }
            let n = counts.entry(&turn.conversation).or_default();
            *n += 1;
            if *n > 8 {
                return false;
            }
        }
        if let Some(packet) = &self.packet
            && (packet.outputs.len() > 96
                || packet.key.len() > 512
                || packet.turn_id.as_ref().is_some_and(|id| !self.turns.contains_key(id))
                || serde_json::to_vec(packet).map_or(true, |v| v.len() > 262_144))
        {
            return false;
        }
        true
    }
}
