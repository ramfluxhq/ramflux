// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bridge outputs reuse one authenticated rfd session; frame projection performs no reads.
use crate::{AgentBus, AgentHost, EngineProvider, Error, Result, participant};
use serde_json::{Value, json};
impl<E: EngineProvider> AgentHost<E> {
    async fn save_bridge_state(&mut self) -> Result<()> {
        let engine = self.engine.checkpoint()?;
        if self.state.engine != engine {
            self.state.engine = engine;
            let store = std::sync::Arc::clone(&self.store);
            let state = self.state.clone();
            tokio::task::spawn_blocking(move || store.save(&state))
                .await
                .map_err(|_| Error::Storage)??;
        }
        self.engine.persisted()
    }

    pub(crate) async fn prepare_bridge(
        &mut self,
        bus: &mut impl AgentBus,
        conversation: &Value,
        message: &Value,
    ) -> Result<Option<String>> {
        if self.engine.bridge().is_none() {
            return Ok(None);
        }
        let sender = participant::field(message, "sender_id")?;
        let peer = participant::directory_find(bus, "identity.directory", "identities", |p| {
            p["principal_id"] == sender
                || p["devices"]
                    .as_array()
                    .is_some_and(|d| d.iter().any(|d| d["device_id"] == sender))
        })
        .await?
        .ok_or(Error::Unauthorized)?;
        let device = message["sender_device_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                peer["devices"]
                    .as_array()
                    .and_then(|ds| ds.iter().find(|d| d["device_id"] == sender))
                    .and_then(|d| d["device_id"].as_str())
            })
            .ok_or(Error::MalformedField("sender_device_id"))?;
        let principal = participant::field(&peer, "principal_id")?;
        let kind = peer["kind"]
            .as_str()
            .filter(|s| matches!(*s, "human" | "headless_ai"))
            .ok_or(Error::Unauthorized)?;
        let trust = match peer["safety_state"].as_str() {
            Some("verified") => "verified",
            Some("verification_stale" | "stale") => "stale",
            _ => "unverified",
        };
        let name = peer["display_name"]
            .as_str()
            .unwrap_or("unknown")
            .chars()
            .filter(|c| !c.is_control())
            .take(128)
            .collect::<String>();
        let actor = json!({"principal_id":principal,"device_id":device,"kind":kind,"display_name":name,"trust":trust,"is_self":false});
        let c = participant::field(conversation, "id")?;
        let group = conversation["group_id"].is_string();
        let chat = json!({"conversation_id":c,"kind":if group{"group"}else{"dm"},"title":conversation["title"].as_str(),
            "member_count":conversation["participants"].as_array().map_or(2,Vec::len),"mentioned":message["mentioned"].as_bool().unwrap_or(false) || message["metadata"]["mentions"].as_array().is_some_and(|rows|rows.iter().any(|p| p == &self.state.principal_id || p == &self.state.device_id))});
        let templates =
            participant::reply_outputs(bus, &self.state, conversation, message, "", 0).await?;
        self.engine.bridge().ok_or(Error::State)?.prepare(crate::prx_bridge::Source {
            sender: actor,
            chat,
            templates,
            task: None,
            timestamp_ms: message["created_at"]
                .as_u64()
                .ok_or(Error::MalformedField("created_at"))?
                .saturating_mul(1000),
            reply_to: message["metadata"]["reply_to"]["message_id"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 1024)
                .map(str::to_owned),
        });
        Ok(Some(name))
    }
    pub(crate) async fn bridge_work(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        if self.engine.bridge().and_then(|b| b.packet()).is_some() {
            self.save_bridge_state().await?;
        } else {
            return self.save_bridge_state().await;
        }
        loop {
            let Some(packet) = self.engine.bridge().and_then(|b| b.packet()) else {
                return Ok(());
            };
            if let Some(output) = packet.outputs.front() {
                let result = bus
                    .request(&output.method, output.body.clone(), Some(&output.operation_id))
                    .await;
                match result {
                    Err(Error::Bus | Error::Resync) => return Err(Error::Bus),
                    Err(error) if error.stops_host() => return Err(error),
                    Err(_) => {
                        eprintln!("agent host bridge output refused");
                    }
                    Ok(value) if output.method == "surface.send" && value["accepted"] != true => {
                        eprintln!("agent host bridge surface refused");
                    }
                    Ok(_) => {}
                }
                self.engine.bridge().ok_or(Error::State)?.output_done();
                continue;
            }
            if let Some(approval) = packet.approval {
                let turn = self.engine.bridge().ok_or(Error::State)?.approval_context()?;
                let request = crate::runner_approval::ApprovalRequest {
                    conversation_id: turn.0,
                    message_id: turn.1,
                    decision_id: packet.approval_id.ok_or(Error::State)?,
                    approval,
                    now_ms: crate::bus::now_ms(),
                };
                match self.start_approval(bus, request).await {
                    Err(Error::Bus | Error::Resync) => return Err(Error::Bus),
                    Err(error) if error.stops_host() => return Err(error),
                    Err(_) | Ok(_) => {}
                }
                self.engine.bridge().ok_or(Error::State)?.approval_done();
                self.save_bridge_state().await?;
                continue;
            }
            self.engine.bridge().ok_or(Error::State)?.finish_packet();
            self.save_bridge_state().await?;
            return Ok(());
        }
    }
    pub(crate) async fn bridge_decider(
        &mut self,
        bus: &mut impl AgentBus,
        view: &Value,
        grant: &str,
    ) -> Result<()> {
        if self.engine.bridge().is_none() {
            return Ok(());
        }
        let decision = view["approval_decisions"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["grant_id"] == grant))
            .ok_or(Error::EngineRejected)?;
        // This must be the verified decision packet signer, never the task requester.
        let principal = participant::field(&decision["decided_by"], "principal_id")?;
        let device = participant::field(&decision["decided_by"], "device_id")?;
        let peer = participant::directory_find(bus, "identity.directory", "identities", |p| {
            p["principal_id"] == principal
        })
        .await?
        .ok_or(Error::Unauthorized)?;
        if !peer["devices"].as_array().is_some_and(|rows| {
            rows.iter().any(|d| {
                d["device_id"] == device && d["revoked"] != true && d["status"] != "revoked"
            })
        }) {
            return Err(Error::Unauthorized);
        }
        let trust = match peer["safety_state"].as_str() {
            Some("verified") => "verified",
            Some("verification_stale" | "stale") => "stale",
            _ => "unverified",
        };
        let sender = json!({"principal_id":principal,"device_id":device,"kind":peer["kind"],"trust":trust,"is_self":false});
        self.engine.bridge().ok_or(Error::State)?.set_decider(sender, grant.into());
        Ok(())
    }
    pub(crate) async fn bridge_update(
        &mut self,
        bus: &mut impl AgentBus,
        event: &ramflux_sdk::LocalBusFrame,
        now: u64,
    ) -> Result<()> {
        if self.engine.bridge().is_none() {
            return Ok(());
        }
        if event.method == "message.updated" {
            let message = &event.body["message"];
            if message["deleted"] != true && message["removed"] != true {
                return Ok(());
            }
            let conversation = participant::field(message, "conversation_id")?;
            let id = participant::field(message, "message_id")?;
            if participant::conversation(
                bus,
                &self.state,
                conversation,
                self.config.max_conversations,
            )
            .await?
            .is_none()
            {
                return Ok(());
            }
            let deleted_by = if let Some(actor) =
                message.get("deleted_by").filter(|a| a.is_object())
            {
                let principal = participant::field(actor, "principal_id")?;
                let device = participant::field(actor, "device_id")?;
                let kind = actor["kind"]
                    .as_str()
                    .filter(|k| matches!(*k, "human" | "headless_ai"))
                    .ok_or(Error::Unauthorized)?;
                let trust = actor["trust"]
                    .as_str()
                    .filter(|t| matches!(*t, "verified" | "stale" | "unverified"))
                    .unwrap_or("unverified");
                json!({"principal_id":principal,"device_id":device,"kind":kind,"trust":trust,"is_self":principal == self.state.principal_id && device == self.state.device_id})
            } else {
                json!({"principal_id":self.state.principal_id,"device_id":self.state.device_id,"kind":"headless_ai","trust":"verified","is_self":true})
            };
            self.state.visible_failures.retain(|_, notice| {
                notice.conversation_id != conversation || notice.message_id != id
            });
            let reply = ramflux_protocol::hash_base64url(
                "ramflux.agent.reply.v1",
                &ramflux_protocol::canonical_json_bytes(&(
                    &self.state.account_id,
                    conversation,
                    id,
                    0usize,
                ))
                .map_err(|_| Error::State)?,
            );
            if self.state.pending.as_ref().is_some_and(|p| {
                p.conversation_id == conversation
                    && p.body["message_id"] == format!("agent-{reply}")
            }) {
                self.state.pending = None;
            }
            self.engine.bridge().ok_or(Error::State)?.erase(conversation, id, &deleted_by, now)?;
            self.state.approvals.remove(conversation);
            self.save_state()?;
        }
        if event.method == "task.changed" {
            let c = event.body["conversation_id"]
                .as_str()
                .or_else(|| event.body["task"]["conversation_id"].as_str());
            let task =
                event.body["task_id"].as_str().or_else(|| event.body["task"]["task_id"].as_str());
            if let (Some(c), Some(task)) = (c, task) {
                let view = bus
                    .request("task.get", json!({"conversation_id":c,"task_id":task}), None)
                    .await?;
                if view["assignee"] == self.state.principal_id {
                    self.engine.bridge().ok_or(Error::State)?.update_task(c, &view);
                }
            }
        }
        Ok(())
    }
}
