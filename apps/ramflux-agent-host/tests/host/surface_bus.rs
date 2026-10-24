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
    receipts: BTreeMap<String, Value>,
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
        let result = match self.state.apply(&event) {
            Ok(next) => {
                self.state = next;
                self.sent.push(body);
                json!({"accepted":true})
            }
            Err(error) => {
                json!({"accepted":false,"renderer_error":{"code":"renderer_error","reject":error}})
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
            "surface.get" => Ok(
                json!({"surface_ref":"ref","conversation_id":"group-thread","author_principal_id":"agent-principal","executor_device_id":"agent-device","is_action_executor":!self.replica,"out_of_sync":false,"version":self.state.version(),"closed":self.state.is_closed(),"surface_hash":self.state.hash(),"snapshot":self.state.content(),"actions":self.action.iter().collect::<Vec<_>>()}),
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
