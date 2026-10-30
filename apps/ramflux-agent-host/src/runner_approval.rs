// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Human-authenticated Ramflux task bridge for remote PRX approval decisions.
use crate::checkpoint::{ApprovalBridge, ApprovalPhase};
use crate::{
    AgentBus, AgentHost, EngineApproval, EngineEvent, EngineFailure, EngineProvider, Error, Result,
};
use serde_json::{Value, json};

const MAX_APPROVALS: usize = 64;
const MCP_SERVER_ID: &str = "ramflux-prx-bridge";
const MCP_TOOL_NAME: &str = "prx_pending_approval";

pub(crate) struct ApprovalRequest {
    pub(crate) conversation_id: String,
    pub(crate) message_id: String,
    pub(crate) decision_id: String,
    pub(crate) approval: EngineApproval,
    pub(crate) now_ms: u64,
}

impl<E: EngineProvider> AgentHost<E> {
    pub(crate) async fn start_approval(
        &mut self,
        bus: &mut impl AgentBus,
        request: ApprovalRequest,
    ) -> Result<bool> {
        let ApprovalRequest { conversation_id, message_id, decision_id, approval, now_ms } =
            request;
        if let Some(existing) = self.state.approvals.get(&conversation_id) {
            if existing.decision_id == decision_id && existing.message_id == message_id {
                self.ensure_proposal(bus, &conversation_id).await?;
                return Ok(true);
            }
            return Err(Error::Limit);
        }
        if self.state.approvals.len() >= MAX_APPROVALS {
            return Err(Error::Limit);
        }
        let task_hash = ramflux_protocol::hash_base64url(
            "ramflux.agent.prx.task.v1",
            &ramflux_protocol::canonical_json_bytes(&(&conversation_id, &decision_id))
                .map_err(|_| Error::State)?,
        );
        let task_id = format!("prx-{task_hash}");
        let operation = |kind: &str| {
            ramflux_protocol::hash_base64url(
                "ramflux.agent.prx.operation.v1",
                format!("{kind}:{task_hash}").as_bytes(),
            )
        };
        bus.request(
            "mcp.server.add",
            json!({
                "server_id":MCP_SERVER_ID,
                "command":"prx-http-approval-bridge",
                "tool_name":MCP_TOOL_NAME,
                "capability":"external_tool_invoke",
                "tool_scope":"prx_pending_approval",
                "risk_level":"high"
            }),
            Some(&operation("server")),
        )
        .await?;
        let started = bus
            .request(
                "mcp.tool.started",
                json!({
                    "server_id":MCP_SERVER_ID,
                    "tool_name":MCP_TOOL_NAME,
                    "arguments":{"decision_id":decision_id,"pending_tool":approval.tool,
                        "arguments_summary":approval.arguments_summary,"effect":approval.effect,
                        "call_digest":approval.call_digest,"deadline_ms":approval.deadline_ms},
                    "operation_origin":"ai_mcp"
                }),
                Some(&operation("approval")),
            )
            .await?;
        if started["status"] != "approval_required" {
            // Standing or stale grants never authorize a fresh PRX decision.
            match self
                .engine
                .decide(&conversation_id, &message_id, &decision_id, false, now_ms)
                .await
            {
                Ok(()) | Err(Error::EngineRejected) => return Ok(false),
                Err(error) if error.stops_host() => return Err(error),
                Err(_) => return Ok(false),
            }
        }
        let grant_request = &started["approval"];
        let approval_id = field(grant_request, "approval_id")?.to_owned();
        let grant_id = grant_request["details"]["requested_grant_id"]
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .map_or_else(|| format!("grant_{approval_id}"), str::to_owned);
        let bridge = ApprovalBridge {
            conversation_id: conversation_id.clone(),
            message_id,
            decision_id,
            task_id,
            step_id: "approval".into(),
            pending_tool: safe_tool_label(&approval.tool),
            grant_id,
            approval_id,
            deadline_ms: approval.deadline_ms,
            phase: ApprovalPhase::Proposed,
        };
        self.state.approvals.insert(conversation_id.clone(), bridge);
        self.save_state()?;
        self.ensure_proposal(bus, &conversation_id).await?;
        Ok(true)
    }

    async fn ensure_proposal(
        &mut self,
        bus: &mut impl AgentBus,
        conversation_id: &str,
    ) -> Result<()> {
        let bridge = self.state.approvals.get(conversation_id).ok_or(Error::State)?.clone();
        let view = self.task_view(bus, &bridge).await?;
        if !view.is_null() {
            return validate_task(&view, &bridge, &self.state.principal_id);
        }
        let operation = task_operation(&bridge, "propose");
        bus.request(
            "task.propose",
            json!({
                "conversation_id":bridge.conversation_id,
                "task_id":bridge.task_id,
                "message_id":format!("prx-propose-{operation}"),
                "assignee":self.state.principal_id,
                "title":"Approve PRX tool request",
                "steps":[{
                    "id":bridge.step_id,
                    "title":format!("Approve {}",bridge.pending_tool),
                    "state":"proposed"
                }]
            }),
            Some(&operation),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn drive_approvals(
        &mut self,
        bus: &mut impl AgentBus,
        now_ms: u64,
    ) -> Result<Vec<EngineEvent>> {
        let conversations = self.state.approvals.keys().cloned().collect::<Vec<_>>();
        let mut events = Vec::new();
        for conversation_id in conversations {
            let bridge = self.state.approvals.get(&conversation_id).ok_or(Error::State)?.clone();
            let view = self.task_view(bus, &bridge).await?;
            if view.is_null() {
                if bridge.phase == ApprovalPhase::Proposed {
                    self.ensure_proposal(bus, &conversation_id).await?;
                    continue;
                }
                return Err(Error::State);
            }
            validate_task(&view, &bridge, &self.state.principal_id)?;
            if bridge.phase != ApprovalPhase::Resuming && now_ms >= bridge.deadline_ms {
                self.decline_bridge(&bridge, now_ms).await?;
                self.fail_approval(
                    bus,
                    &bridge,
                    &view,
                    EngineFailure::ApprovalTimeout,
                    &mut events,
                )
                .await?;
                continue;
            }
            match bridge.phase {
                ApprovalPhase::Proposed => {
                    if terminal(&view) {
                        self.retire_terminal_approval(&bridge, &view, now_ms, &mut events).await?;
                    } else if awaiting_decision(&view, &bridge) {
                        self.mark_awaiting_decision(&conversation_id)?;
                    } else if view["state"] == "running" {
                        self.open_needs_me(bus, &bridge, &view).await?;
                    }
                }
                ApprovalPhase::AwaitingDecision => {
                    if terminal(&view) {
                        self.retire_terminal_approval(&bridge, &view, now_ms, &mut events).await?;
                    } else if resolved(&view, &bridge) {
                        let approved = decision(&view, &bridge)?;
                        match self
                            .engine
                            .decide(
                                &bridge.conversation_id,
                                &bridge.message_id,
                                &bridge.decision_id,
                                approved,
                                now_ms,
                            )
                            .await
                        {
                            Ok(()) if approved => {
                                if let Some(saved) = self.state.approvals.get_mut(&conversation_id)
                                {
                                    saved.phase = ApprovalPhase::Resuming;
                                }
                                self.save_state()?;
                            }
                            Ok(()) => {
                                self.fail_approval(
                                    bus,
                                    &bridge,
                                    &view,
                                    EngineFailure::ApprovalDeclined,
                                    &mut events,
                                )
                                .await?;
                            }
                            Err(Error::EngineUnavailable | Error::EngineTimeout) => {}
                            Err(error) if error.stops_host() => return Err(error),
                            Err(_) => {
                                self.fail_approval(
                                    bus,
                                    &bridge,
                                    &view,
                                    EngineFailure::ApprovalUnavailable,
                                    &mut events,
                                )
                                .await?;
                            }
                        }
                    }
                }
                ApprovalPhase::Resuming => {}
            }
        }
        Ok(events)
    }

    async fn retire_terminal_approval(
        &mut self,
        bridge: &ApprovalBridge,
        view: &Value,
        now_ms: u64,
        events: &mut Vec<EngineEvent>,
    ) -> Result<()> {
        let denied = decision(view, bridge).is_ok_and(|approved| !approved);
        self.decline_bridge(bridge, now_ms).await?;
        self.state.approvals.remove(&bridge.conversation_id);
        self.save_state()?;
        if denied {
            events.push(EngineEvent::VisibleFailure {
                conversation_id: bridge.conversation_id.clone(),
                message_id: bridge.message_id.clone(),
                reason: EngineFailure::ApprovalDeclined,
            });
        }
        Ok(())
    }

    async fn fail_approval(
        &mut self,
        bus: &mut impl AgentBus,
        bridge: &ApprovalBridge,
        view: &Value,
        reason: EngineFailure,
        events: &mut Vec<EngineEvent>,
    ) -> Result<()> {
        if let Err(error) = self.update_task(bus, bridge, view, "failed", reason.reply()).await {
            match error {
                Error::SurfaceRefused(refusal) => {
                    // A signed task can refuse terminalization while a human step is open.
                    // Never turn that permanent refusal into a host-wide reconnect loop.
                    self.state.last_refusal = Some(crate::OutputRefusal {
                        group_reason: None,
                        conversation_id: bridge.conversation_id.clone(),
                        surface_id: None,
                        reason: refusal,
                    });
                }
                error => return Err(error),
            }
        }
        self.state.approvals.remove(&bridge.conversation_id);
        self.save_state()?;
        events.push(EngineEvent::VisibleFailure {
            conversation_id: bridge.conversation_id.clone(),
            message_id: bridge.message_id.clone(),
            reason,
        });
        Ok(())
    }

    async fn open_needs_me(
        &mut self,
        bus: &mut impl AgentBus,
        bridge: &ApprovalBridge,
        view: &Value,
    ) -> Result<()> {
        if view["version"] != 2 {
            return Err(Error::State);
        }
        bus.request(
            "task.update",
            task_update(bridge, 3, "needs_me", "needs_me", Some(&bridge.grant_id)),
            Some(&task_operation(bridge, "needs-me")),
        )
        .await?;
        self.mark_awaiting_decision(&bridge.conversation_id)
    }

    fn mark_awaiting_decision(&mut self, conversation_id: &str) -> Result<()> {
        let saved = self.state.approvals.get_mut(conversation_id).ok_or(Error::State)?;
        saved.phase = ApprovalPhase::AwaitingDecision;
        self.save_state()
    }

    pub(crate) async fn complete_resumed_task(
        &mut self,
        bus: &mut impl AgentBus,
        conversation_id: &str,
        succeeded: bool,
    ) -> Result<()> {
        let Some(bridge) = self.state.approvals.get(conversation_id).cloned() else {
            return Ok(());
        };
        if bridge.phase != ApprovalPhase::Resuming {
            return Ok(());
        }
        let view = self.task_view(bus, &bridge).await?;
        self.update_task(
            bus,
            &bridge,
            &view,
            if succeeded { "done" } else { "failed" },
            if succeeded { "PRX turn completed" } else { "PRX turn failed" },
        )
        .await?;
        self.state.approvals.remove(conversation_id);
        self.save_state()
    }

    async fn update_task(
        &mut self,
        bus: &mut impl AgentBus,
        bridge: &ApprovalBridge,
        view: &Value,
        state: &str,
        summary: &str,
    ) -> Result<()> {
        if terminal(view) {
            return Ok(());
        }
        let version =
            view["version"].as_u64().ok_or(Error::State)?.checked_add(1).ok_or(Error::Limit)?;
        let operation = task_operation(bridge, state);
        bus.request(
            "task.update",
            json!({
                "conversation_id":bridge.conversation_id,
                "task_id":bridge.task_id,
                "message_id":format!("prx-update-{operation}"),
                "version":version,
                "state":state,
                "steps":[{"id":bridge.step_id,"title":format!("Approve {}",bridge.pending_tool),"state":state}],
                "result_summary":summary
            }),
            Some(&operation),
        )
        .await?;
        Ok(())
    }

    async fn decline_bridge(&mut self, bridge: &ApprovalBridge, now_ms: u64) -> Result<()> {
        match self
            .engine
            .decide(&bridge.conversation_id, &bridge.message_id, &bridge.decision_id, false, now_ms)
            .await
        {
            Err(error) if error.stops_host() => Err(error),
            Ok(()) | Err(_) => Ok(()),
        }
    }

    async fn task_view(
        &mut self,
        bus: &mut impl AgentBus,
        bridge: &ApprovalBridge,
    ) -> Result<Value> {
        bus.request(
            "task.get",
            json!({"conversation_id":bridge.conversation_id,"task_id":bridge.task_id}),
            None,
        )
        .await
    }
}

pub(crate) fn valid(state: &crate::Checkpoint) -> bool {
    state.approvals.len() <= MAX_APPROVALS
        && state.approvals.iter().all(|(conversation, bridge)| {
            conversation == &bridge.conversation_id
                && [
                    bridge.conversation_id.as_str(),
                    bridge.message_id.as_str(),
                    bridge.decision_id.as_str(),
                    bridge.task_id.as_str(),
                    bridge.step_id.as_str(),
                    bridge.pending_tool.as_str(),
                    bridge.grant_id.as_str(),
                    bridge.approval_id.as_str(),
                ]
                .into_iter()
                .all(|value| !value.is_empty() && value.len() <= 1024)
        })
}

fn validate_task(view: &Value, bridge: &ApprovalBridge, principal_id: &str) -> Result<()> {
    if view["conversation_id"] != bridge.conversation_id
        || view["task_id"] != bridge.task_id
        || view["assignee"] != principal_id
    {
        return Err(Error::State);
    }
    Ok(())
}

fn resolved(view: &Value, bridge: &ApprovalBridge) -> bool {
    view["version"].as_u64().is_some_and(|version| version >= 4)
        && view["state"] == "running"
        && view["steps"].as_array().is_some_and(|steps| {
            steps.iter().any(|step| step["id"] == bridge.step_id && step["needs_me"].is_null())
        })
}

fn awaiting_decision(view: &Value, bridge: &ApprovalBridge) -> bool {
    view["version"].as_u64().is_some_and(|version| version >= 3)
        && view["state"] == "needs_me"
        && view["steps"].as_array().is_some_and(|steps| {
            steps.iter().any(|step| {
                step["id"] == bridge.step_id
                    && step["needs_me"]["kind"] == "approval"
                    && step["needs_me"]["grant_id"] == bridge.grant_id
            })
        })
}

fn decision(view: &Value, bridge: &ApprovalBridge) -> Result<bool> {
    view["approval_decisions"]
        .as_array()
        .and_then(|rows| {
            rows.iter().find(|row| {
                row["grant_id"] == bridge.grant_id
                    && row["task_binding"]["task_id"] == bridge.task_id
                    && row["task_binding"]["step_id"] == bridge.step_id
            })
        })
        .and_then(|row| match row["status"].as_str() {
            Some("approved") => Some(true),
            Some("denied") => Some(false),
            _ => None,
        })
        .ok_or(Error::State)
}

fn terminal(view: &Value) -> bool {
    matches!(view["state"].as_str(), Some("done" | "failed" | "cancelled"))
}

fn task_update(
    bridge: &ApprovalBridge,
    version: u64,
    state: &str,
    step_state: &str,
    grant_id: Option<&str>,
) -> Value {
    let mut step = json!({
        "id":bridge.step_id,
        "title":format!("Approve {}",bridge.pending_tool),
        "state":step_state
    });
    if let Some(grant_id) = grant_id {
        step["needs_me"] = json!({"kind":"approval","grant_id":grant_id});
    }
    json!({
        "conversation_id":bridge.conversation_id,
        "task_id":bridge.task_id,
        "message_id":format!("prx-task-{}-{version}",bridge.task_id),
        "version":version,
        "state":state,
        "steps":[step]
    })
}

fn task_operation(bridge: &ApprovalBridge, kind: &str) -> String {
    ramflux_protocol::hash_base64url(
        "ramflux.agent.prx.task.operation.v1",
        format!("{}:{kind}", bridge.task_id).as_bytes(),
    )
}

fn safe_tool_label(value: &str) -> String {
    let label = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || "._:/ -".contains(*character))
        .take(96)
        .collect::<String>();
    if label.is_empty() { "PRX tool request".into() } else { label }
}

fn field<'a>(value: &'a Value, name: &'static str) -> Result<&'a str> {
    value[name]
        .as_str()
        .filter(|field| !field.is_empty() && field.len() <= 1024)
        .ok_or(Error::MalformedField(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, ConversationInput, Intent, Rule};
    use ramflux_sdk::LocalBusFrame;
    use std::os::unix::fs::PermissionsExt;

    #[derive(Default)]
    struct TestEngine {
        decisions: Vec<(String, String, bool)>,
    }

    impl EngineProvider for TestEngine {
        fn intents(&mut self, _input: &ConversationInput<'_>) -> Result<Vec<Intent>> {
            Ok(Vec::new())
        }

        fn decide<'a>(
            &'a mut self,
            conversation_id: &'a str,
            _message_id: &'a str,
            decision_id: &'a str,
            approved: bool,
            _now_ms: u64,
        ) -> impl std::future::Future<Output = Result<()>> + 'a {
            self.decisions.push((conversation_id.into(), decision_id.into(), approved));
            std::future::ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct TestBus {
        task: Value,
        standing_grant: bool,
        requests: Vec<(String, Value)>,
        replies: Vec<Value>,
        removed: bool,
    }

    impl TestBus {
        fn respond(&mut self, method: &str, body: Value) -> Result<Value> {
            self.requests.push((method.into(), body.clone()));
            Ok(match method {
                "mcp.server.add" => json!({"accepted":true}),
                "mcp.tool.started" if self.standing_grant => {
                    json!({"status":"ok","standing_approval_id":"standing"})
                }
                "mcp.tool.started" => json!({
                    "status":"approval_required",
                    "approval":{
                        "approval_id":"approval-1",
                        "details":{"requested_grant_id":"grant-1"}
                    }
                }),
                "task.get" => {
                    if self.task["task_id"] == body["task_id"] {
                        self.task.clone()
                    } else {
                        Value::Null
                    }
                }
                "task.propose" => {
                    self.task = json!({
                        "conversation_id":body["conversation_id"],
                        "task_id":body["task_id"],
                        "assignee":body["assignee"],
                        "version":1,
                        "state":"proposed",
                        "steps":body["steps"],
                        "approval_decisions":[]
                    });
                    json!({"accepted":true})
                }
                "task.update" => {
                    if self.task["state"] == "proposed"
                        || self.task["steps"].as_array().is_some_and(|steps| {
                            steps.iter().any(|step| !step["needs_me"].is_null())
                        }) && self.task["steps"] != body["steps"]
                    {
                        return Err(Error::SurfaceRefused(
                            ramflux_sdk::SurfaceRefusalCode::NotPermitted,
                        ));
                    }
                    let assignee = self.task["assignee"].clone();
                    let decisions = self.task["approval_decisions"].clone();
                    self.task = body;
                    self.task["assignee"] = assignee;
                    self.task["approval_decisions"] = decisions;
                    json!({"accepted":true})
                }
                "account.status" => {
                    json!({"principal_id":"agent-principal","client_mode":"headless_ai","local_device_authorized":true})
                }
                "device.list" => {
                    json!({"principal_id":"agent-principal","local_device_id":"agent-device","devices":[{"device_id":"agent-device"}]})
                }
                "identity.directory" => {
                    json!({"identities":[{"principal_id":"agent-principal","is_self":true,"kind":"headless_ai"},{"principal_id":"human-principal","contact_identity_commitment":"human-commitment","devices":[{"device_id":"human-device","target_delivery_id":"human-target"}]}],"next_cursor":null})
                }
                "conversation.directory" if self.removed => {
                    json!({"conversations":[],"next_cursor":null})
                }
                "conversation.directory" => {
                    json!({"conversations":[{"id":"conversation","kind":"direct","participants":["agent-principal","human-principal"]},{"id":"other","kind":"direct","participants":["agent-principal","human-principal"]}],"next_cursor":null})
                }
                "message.read" => {
                    json!({"messages":[{"conversation_id":body["conversation_id"],"message_id":"message","sender_id":"human-principal","body_utf8":"hello","deleted":false}]})
                }
                "message.receive" => json!({}),
                "message.submit" => {
                    self.replies.push(body);
                    json!({"accepted":true})
                }
                _ => return Err(Error::Unauthorized),
            })
        }
    }

    impl AgentBus for TestBus {
        fn request(
            &mut self,
            method: &str,
            body: Value,
            _operation: Option<&str>,
        ) -> impl std::future::Future<Output = Result<Value>> {
            std::future::ready(self.respond(method, body))
        }

        async fn next_event(&mut self) -> Result<LocalBusFrame> {
            std::future::pending().await
        }
    }

    fn host()
    -> std::result::Result<(tempfile::TempDir, AgentHost<TestEngine>), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let config = Config {
            socket: root.path().join("rfd.sock"),
            state_file: root.path().join("state.json"),
            account_id: "agent".into(),
            rules: vec![Rule { pattern: "unused".into(), reply: "unused".into(), surface: None }],
            engine: None,
            poll_interval_ms: 250,
            per_conversation_interval_ms: 1_000,
            max_conversations: 8,
        };
        let mut host = AgentHost::new(config, TestEngine::default())?;
        host.state.principal_id = "agent-principal".into();
        Ok((root, host))
    }

    #[tokio::test]
    async fn signed_task_decision_is_the_only_path_to_prx_approval()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_root, mut host) = host()?;
        let mut bus = TestBus::default();
        let started = host
            .start_approval(
                &mut bus,
                ApprovalRequest {
                    conversation_id: "conversation".into(),
                    message_id: "message".into(),
                    decision_id: "decision-7".into(),
                    approval: approval("filesystem.write"),
                    now_ms: 10,
                },
            )
            .await?;
        assert!(started);
        let server = bus
            .requests
            .iter()
            .find(|(method, _)| method == "mcp.server.add")
            .ok_or("missing server registration")?;
        assert_eq!(server.1["tool_scope"], "prx_pending_approval");
        let tool = bus
            .requests
            .iter()
            .find(|(method, _)| method == "mcp.tool.started")
            .ok_or("missing tool request")?;
        assert_eq!(tool.1["arguments"]["decision_id"], "decision-7");
        assert_eq!(tool.1["arguments"]["pending_tool"], "filesystem.write");
        assert_eq!(host.engine.decisions, Vec::new());

        bus.task["version"] = json!(2);
        bus.task["state"] = json!("running");
        host.drive_approvals(&mut bus, 20).await?;
        assert_eq!(bus.task["version"], 3);
        assert_eq!(bus.task["steps"][0]["needs_me"]["grant_id"], "grant-1");
        assert_eq!(host.engine.decisions, Vec::new());
        host.state.approvals.get_mut("conversation").ok_or("missing bridge")?.phase =
            ApprovalPhase::Proposed;
        host.drive_approvals(&mut bus, 21).await?;
        assert!(host.state.approvals["conversation"].phase == ApprovalPhase::AwaitingDecision);

        let bridge = host.state.approvals["conversation"].clone();
        bus.task["version"] = json!(4);
        bus.task["state"] = json!("running");
        bus.task["steps"] = json!([{"id":&bridge.step_id,"state":"running"}]);
        bus.task["approval_decisions"] = json!([{
            "grant_id":&bridge.grant_id,
            "status":"approved",
            "task_binding":{"task_id":&bridge.task_id,"step_id":&bridge.step_id}
        }]);
        host.drive_approvals(&mut bus, 30).await?;
        assert_eq!(host.engine.decisions, vec![("conversation".into(), "decision-7".into(), true)]);
        assert!(host.state.approvals["conversation"].phase == ApprovalPhase::Resuming);
        Ok(())
    }

    #[tokio::test]
    async fn standing_grant_never_approves_a_prx_decision()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_root, mut host) = host()?;
        let mut bus = TestBus { standing_grant: true, ..TestBus::default() };
        let started = host
            .start_approval(
                &mut bus,
                ApprovalRequest {
                    conversation_id: "conversation".into(),
                    message_id: "message".into(),
                    decision_id: "decision-8".into(),
                    approval: approval("shell.exec"),
                    now_ms: 10,
                },
            )
            .await?;
        assert!(!started);
        assert_eq!(
            host.engine.decisions,
            vec![("conversation".into(), "decision-8".into(), false)]
        );
        assert!(host.state.approvals.is_empty());
        Ok(())
    }

    fn approval(tool: &str) -> EngineApproval {
        EngineApproval {
            tool: tool.into(),
            arguments_summary: json!({"path":"report.txt"}),
            effect: "file_write".into(),
            call_digest: "abc123".into(),
            deadline_ms: 600_010,
        }
    }

    fn prx_host(
        server: &crate::prx_test_support::FakePrx,
    ) -> std::result::Result<
        (tempfile::TempDir, AgentHost<crate::PrxEngine>),
        Box<dyn std::error::Error>,
    > {
        let (root, old) = host()?;
        let mut config = old.config.clone();
        drop(old);
        let token = root.path().join("token");
        std::fs::write(&token, "test-prx-token")?;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
        let prx = crate::PrxConfig {
            base_url: server.base_url.clone(),
            token_file: token,
            session_scope: crate::PrxSessionScope::PerConversation,
            request_timeout_s: 1,
            max_in_flight_per_conversation: 1,
            authorization: crate::PrxAuthorization::Supervised,
            turn_timeout_s: 120,
            approval_timeout_s: 600,
        };
        config.rules.clear();
        config.engine = Some(crate::EngineConfig { prx: prx.clone() });
        let engine = crate::PrxEngine::new(&prx, 8)?;
        let mut host = AgentHost::new(config, engine)?;
        host.state.principal_id = "agent-principal".into();
        Ok((root, host))
    }

    async fn request_approval(
        host: &mut AgentHost<crate::PrxEngine>,
        bus: &mut TestBus,
    ) -> Result<()> {
        host.engine
            .submit(
                crate::EngineInput {
                    conversation: ConversationInput {
                        conversation_id: "conversation",
                        message_id: "message",
                        text: "hello",
                    },
                    sender_display_name: "Human",
                    chat_kind: "direct",
                    mentioned: false,
                },
                1,
            )
            .await?;
        let events = host.engine.poll(2).await?;
        host.handle_engine_events(bus, events, 1, 2).await?;
        assert_eq!(bus.task["steps"][0]["title"], "Approve filesystem.write");
        let request = bus
            .requests
            .iter()
            .find(|(method, _)| method == "mcp.tool.started")
            .ok_or(Error::State)?;
        assert_eq!(request.1["arguments"]["call_digest"], "abc123");
        assert_eq!(request.1["arguments"]["arguments_summary"]["path"], "report.txt");
        assert_eq!(request.1["arguments"]["effect"], "file_write");
        bus.task["version"] = json!(2);
        bus.task["state"] = json!("running");
        host.drive_approvals(bus, 3).await?;
        Ok(())
    }

    fn human_decision(bus: &mut TestBus, approved: bool) {
        let task = bus.task["task_id"].clone();
        bus.task["version"] = json!(4);
        bus.task["state"] = json!(if approved { "running" } else { "failed" });
        bus.task["steps"] =
            json!([{"id":"approval","state":if approved {"running"} else {"failed"}}]);
        bus.task["approval_decisions"] = json!([{"grant_id":"grant-1","status":if approved {"approved"} else {"denied"},"task_binding":{"task_id":task,"step_id":"approval"}}]);
    }

    #[tokio::test]
    async fn host_decline_and_prx_expiry_retire_bridge_without_overriding_task_authority()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::prx_test_support::{FakePrx, approval_steps, step};
        for timeout in [false, true] {
            let mut steps = approval_steps("1970-01-01T00:00:01Z");
            steps.push(step(
                hyper::Method::DELETE,
                "/api/sessions/session-1/approvals/decision-1",
                hyper::StatusCode::OK,
                json!({}),
            ));
            let server = FakePrx::start(steps).await?;
            let (_root, mut host) = prx_host(&server)?;
            let mut bus = TestBus::default();
            request_approval(&mut host, &mut bus).await?;
            assert_eq!(host.state.approvals["conversation"].deadline_ms, 1000);
            if !timeout {
                human_decision(&mut bus, false);
            }
            let events = host.drive_approvals(&mut bus, if timeout { 1000 } else { 4 }).await?;
            assert_eq!(bus.task["state"], if timeout { "needs_me" } else { "failed" });
            if timeout {
                assert!(host.state.last_refusal.is_some());
            }
            assert!(host.state.approvals.is_empty());
            assert!(
                matches!(events.as_slice(), [EngineEvent::VisibleFailure {reason, ..}] if *reason == if timeout {EngineFailure::ApprovalTimeout} else {EngineFailure::ApprovalDeclined})
            );
            host.handle_engine_events(&mut bus, events, 1, 1000).await?;
            assert_eq!(bus.replies.len(), 1);
            assert!(server.seen().await.iter().any(|r| r.starts_with("DELETE ")));
        }
        Ok(())
    }

    #[tokio::test]
    async fn prx_409_fails_task_and_next_conversation_is_answered()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::prx_test_support::{FakePrx, accepted, approval_steps, step};
        use hyper::{Method, StatusCode};
        let mut steps = approval_steps("1970-01-01T00:05:00Z");
        steps.extend([
            step(Method::POST, "/api/sessions/session-1/approvals/decision-1", StatusCode::CONFLICT, json!({"error":"expired"})),
            step(Method::DELETE, "/api/sessions/session-1/approvals/decision-1", StatusCode::CONFLICT, json!({"error":"expired"})),
            step(Method::POST, "/api/sessions", StatusCode::CREATED, json!({"session_id":"session-2"})),
            step(Method::POST, "/api/sessions/session-2/message?mode=async", StatusCode::ACCEPTED, accepted("job-2")),
            step(Method::GET, "/api/jobs/job-2", StatusCode::OK, json!({"status":"succeeded","http_status":200,"result":{"status":"ok","reply":"other conversation answered"}})),
        ]);
        let server = FakePrx::start(steps).await?;
        let (_root, mut host) = prx_host(&server)?;
        let mut bus = TestBus::default();
        request_approval(&mut host, &mut bus).await?;
        human_decision(&mut bus, true);
        let events = host.drive_approvals(&mut bus, 4).await?;
        assert_eq!(bus.task["state"], "failed");
        assert!(host.state.approvals.is_empty());
        assert!(matches!(
            events.as_slice(),
            [EngineEvent::VisibleFailure { reason: EngineFailure::ApprovalUnavailable, .. }]
        ));
        host.handle_engine_events(&mut bus, events, 1, 4).await?;
        let mut event = LocalBusFrame::request(
            "event",
            Some("agent".into()),
            "stream",
            "message.received",
            json!({"message":{"conversation_id":"other","message_id":"message","sender_id":"human-principal"}}),
        );
        event.kind = ramflux_sdk::LocalBusFrameKind::Event;
        event.seq = Some(2);
        host.apply(&mut bus, event, 2000).await?;
        host.poll(&mut bus, 2001).await?;
        assert_eq!(bus.replies.len(), 2);
        assert_eq!(
            bus.replies[1]["plaintext_body_base64"],
            ramflux_protocol::encode_base64url(b"other conversation answered")
        );
        Ok(())
    }

    #[tokio::test]
    async fn resumed_turn_can_request_a_second_fresh_human_decision()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::prx_test_support::{FakePrx, accepted, approval_steps, approval_view, step};
        use hyper::{Method, StatusCode};
        let mut steps = approval_steps("1970-01-01T00:05:00Z");
        steps.extend([
            step(Method::POST, "/api/sessions/session-1/approvals/decision-1", StatusCode::OK, json!({})),
            step(Method::POST, "/api/sessions/session-1/approvals/decision-1/resume?mode=async", StatusCode::ACCEPTED, accepted("job-2")),
            step(Method::GET, "/api/jobs/job-2", StatusCode::OK, json!({"status":"succeeded","http_status":200,"result":{"status":"awaiting_approval","reply":"no approval needed","decision_id":"decision-2"}})),
            step(Method::GET, "/api/sessions/session-1/approvals/decision-2", StatusCode::OK, approval_view("decision-2", "1970-01-01T00:05:00Z")),
        ]);
        let server = FakePrx::start(steps).await?;
        let (_root, mut host) = prx_host(&server)?;
        let mut bus = TestBus::default();
        request_approval(&mut host, &mut bus).await?;
        let first_task = bus.task["task_id"].clone();
        let config = host.config.clone();
        drop(host);
        let engine =
            crate::PrxEngine::new(&config.engine.as_ref().ok_or("missing engine config")?.prx, 8)?;
        let mut host = AgentHost::new(config, engine)?;
        assert!(host.state.approvals["conversation"].phase == ApprovalPhase::AwaitingDecision);
        assert_eq!(host.state.approvals["conversation"].deadline_ms, 300_000);
        human_decision(&mut bus, true);
        host.drive_approvals(&mut bus, 4).await?;
        let events = host.engine.poll(5).await?;
        host.handle_engine_events(&mut bus, events, 1, 5).await?;
        assert_ne!(bus.task["task_id"], first_task);
        assert_eq!(host.state.approvals["conversation"].decision_id, "decision-2");
        assert!(host.state.approvals["conversation"].phase == ApprovalPhase::Proposed);
        assert_eq!(
            server
                .seen()
                .await
                .iter()
                .filter(|s| s.starts_with("POST ")
                    && s.contains("approvals/decision-")
                    && !s.contains("resume"))
                .count(),
            1
        );
        assert_eq!(bus.replies, Vec::<Value>::new());
        assert!(server.bodies().await.iter().any(|body| body["approved"] == true));
        Ok(())
    }

    #[tokio::test]
    async fn removal_discovered_before_output_retires_the_local_and_remote_approval()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::prx_test_support::{FakePrx, approval_steps, step};
        let mut steps = approval_steps("1970-01-01T00:05:00Z");
        steps.push(step(
            hyper::Method::DELETE,
            "/api/sessions/session-1/approvals/decision-1",
            hyper::StatusCode::OK,
            json!({}),
        ));
        let server = FakePrx::start(steps).await?;
        let (_root, mut host) = prx_host(&server)?;
        let mut bus = TestBus::default();
        request_approval(&mut host, &mut bus).await?;
        bus.removed = true;
        host.handle_engine_events(
            &mut bus,
            vec![EngineEvent::VisibleFailure {
                conversation_id: "conversation".into(),
                message_id: "message".into(),
                reason: EngineFailure::Rejected,
            }],
            2,
            4,
        )
        .await?;
        assert!(host.state.approvals.is_empty());
        assert_eq!(host.engine.active_conversations(), Vec::<String>::new());
        assert_eq!(bus.replies, Vec::<Value>::new());
        assert!(server.seen().await.iter().any(|s| s.starts_with("DELETE ")));
        Ok(())
    }
}
