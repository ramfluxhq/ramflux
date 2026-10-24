// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::support::Fake;
use ramflux_agent_host::{AgentBus, Error, Result};
use ramflux_protocol::{A2uiConversationCommand as C, A2uiConversationEvent, SurfaceState};
use ramflux_sdk::LocalBusFrame;
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Default)]
pub struct SurfaceBus {
    pub inner: Fake,
    pub state: SurfaceState,
    pub sent: Vec<Value>,
    pub requests: Vec<Value>,
    pub action: Option<Value>,
    pub lose_at: Option<usize>,
    pub conflict: bool,
    pub conflicts_remaining: u8,
    pub replica: bool,
    pub refusal: Option<ramflux_sdk::SurfaceRefusalCode>,
    pub get_failures: u8,
    pub out_of_sync: bool,
    pub resyncs: Vec<Value>,
    pub resync_failures: u8,
    pub faults: Faults,
    receipts: BTreeMap<String, Value>,
}
#[derive(Default)]
pub struct Faults {
    pub stale_stream: bool,
    pub disconnect_after_conflict: bool,
    pub lose_resync: bool,
}
impl SurfaceBus {
    pub fn id(&self) -> Result<&str> {
        self.state.content().map(|c| c.surface_id.as_str()).ok_or(Error::State)
    }
    pub fn decision(&mut self) -> Result<()> {
        let values = json!({});
        let wire=serde_json::to_vec(&json!({"schema":"ramflux.a2ui.action.v2","conversationId":"group-thread","surfaceId":self.id()?,"version":self.state.version(),"surfaceHash":self.state.hash(),"actionId":"thu","values":values,"argsHash":ramflux_protocol::surface_args_hash(&values).map_err(|_|Error::State)?})).map_err(|_|Error::State)?;
        self.action = Some(
            json!({"id":"decision","actionable":!self.replica,"wire_base64":ramflux_protocol::encode_base64url(wire)}),
        );
        Ok(())
    }
    fn send(&mut self, body: Value) -> Result<Value> {
        self.requests.push(body.clone());
        let id = body["message_id"].as_str().ok_or(Error::State)?.to_string();
        if let Some(receipt) = self.receipts.get(&id) {
            return Ok(receipt.clone());
        }
        let raw =
            ramflux_protocol::decode_base64url(body["wire_base64"].as_str().ok_or(Error::State)?)
                .map_err(|_| Error::State)?;
        let event = A2uiConversationEvent::from_wire_bytes(&raw).map_err(|_| Error::State)?;
        if let Some(reason) = self.refusal.take() {
            return Err(Error::SurfaceRefused(reason));
        }
        if self.faults.stale_stream
            && let C::StreamAppend(append) = event.command()
        {
            self.faults.stale_stream = false;
            let mut concurrent = append.clone();
            concurrent.final_ = false;
            let mut end = (concurrent.text_delta.len() / 2).max(1);
            while !concurrent.text_delta.is_char_boundary(end) {
                end -= 1;
            }
            concurrent.text_delta.truncate(end);
            let wire = ramflux_protocol::encode_a2ui_conversation_event(
                "group-thread",
                self.state.version() + 1,
                &C::StreamAppend(concurrent),
            )
            .map_err(|_| Error::State)?;
            self.state = self
                .state
                .apply(&A2uiConversationEvent::from_wire_bytes(&wire).map_err(|_| Error::State)?)
                .map_err(|_| Error::State)?;
            if self.faults.disconnect_after_conflict {
                self.get_failures = 1;
            }
        }
        if (self.conflict || self.conflicts_remaining > 0)
            && matches!(event.command(), C::PatchSurface(_))
            && self.action.is_some()
        {
            self.conflict = false;
            self.conflicts_remaining = self.conflicts_remaining.saturating_sub(1);
            let command = C::StreamAppend(ramflux_protocol::StreamAppendCommand {
                surface_id: self.id()?.into(),
                component_id: "result".into(),
                text_delta: "Concurrent update".into(),
                final_: false,
            });
            let raw = ramflux_protocol::encode_a2ui_conversation_event(
                "group-thread",
                self.state.version() + 1,
                &command,
            )
            .map_err(|_| Error::State)?;
            self.state = self
                .state
                .apply(&A2uiConversationEvent::from_wire_bytes(&raw).map_err(|_| Error::State)?)
                .map_err(|_| Error::State)?;
        }
        if self.faults.disconnect_after_conflict
            && self.action.is_some()
            && matches!(event.command(), C::PatchSurface(_))
            && self.state.version() >= event.version()
        {
            self.get_failures = 1;
            self.faults.disconnect_after_conflict = false;
        }
        let result = match self.state.apply(&event) {
            Ok(next) => {
                self.state = next;
                self.sent.push(body);
                json!({"accepted":true})
            }
            Err(error) => {
                let reason = match error {
                    ramflux_protocol::SurfaceReject::Version { .. }
                    | ramflux_protocol::SurfaceReject::Stale => {
                        ramflux_sdk::SurfaceRefusalCode::StaleVersion
                    }
                    _ => ramflux_sdk::SurfaceRefusalCode::StaleHash,
                };
                json!({"accepted":false,"reason_code":reason,"renderer_error":{"code":"renderer_error","reject":error}})
            }
        };
        self.receipts.insert(id, result.clone());
        if self.lose_at == Some(self.sent.len()) {
            self.lose_at = None;
            return Err(Error::Bus);
        }
        Ok(result)
    }
}
impl AgentBus for SurfaceBus {
    async fn request(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> Result<Value> {
        match method {
            "message.read" => Ok(
                json!({"messages":[{"conversation_id":"group-thread","message_id":"ping","sender_id":"human-device","body_utf8":"@agent checklist","deleted":false}]}),
            ),
            "surface.send" => self.send(body),
            "surface.get" if self.get_failures > 0 => {
                self.get_failures -= 1;
                Err(Error::Bus)
            }
            "surface.resync" => {
                let id = body["message_id"].as_str().ok_or(Error::State)?.to_string();
                if let Some(response) = self.receipts.get(&id) {
                    return Ok(response.clone());
                }
                self.resyncs.push(body);
                if self.resync_failures > 0 {
                    self.resync_failures -= 1;
                } else {
                    self.out_of_sync = false;
                }
                let response = json!({"accepted":true});
                self.receipts.insert(id, response.clone());
                if self.faults.lose_resync {
                    self.faults.lose_resync = false;
                    Err(Error::Bus)
                } else {
                    Ok(response)
                }
            }
            "surface.get" => Ok(
                json!({"surface_ref":"ref","conversation_id":"group-thread","author_principal_id":"agent-principal","executor_device_id":"agent-device","is_action_executor":!self.replica,"out_of_sync":self.out_of_sync,"version":self.state.version(),"closed":self.state.is_closed(),"surface_hash":self.state.hash(),"streams":self.state.stream_states(),"snapshot":self.state.content(),"actions":self.action.iter().collect::<Vec<_>>()}),
            ),
            _ => self.inner.request(method, body, operation).await,
        }
    }
    fn next_event(&mut self) -> impl std::future::Future<Output = Result<LocalBusFrame>> {
        std::future::ready(Err(Error::Bus))
    }
}
pub fn event(seq: u64, replica: bool) -> LocalBusFrame {
    let mut frame = super::support::incoming(seq, true);
    frame.method = "surface.changed".into();
    frame.body = json!({"conversation_id":"group-thread","surface_ref":"ref","author_principal_id":"agent-principal","executor_device_id":"agent-device","is_action_executor":!replica,"last_action_id":"decision"});
    frame
}
