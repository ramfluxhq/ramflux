// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use ramflux_agent_host::{AgentBus, Config, Error, Result, Rule};
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
pub type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
pub struct Fixture {
    pub root: PathBuf,
    pub config: Config,
}
impl Fixture {
    pub fn new() -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rf-agent-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            config: Config {
                socket: root.join("rfd.sock"),
                state_file: root.join("cursor.json"),
                account_id: "agent".into(),
                rules: vec![
                    Rule { pattern: "@agent ping".into(), reply: "pong".into(), surface: None },
                    Rule {
                        pattern: "@agent summarize".into(),
                        reply: "Summary\n- deterministic\n- complete".into(),
                        surface: None,
                    },
                ],
                poll_interval_ms: 250,
                per_conversation_interval_ms: 1000,
                max_conversations: 128,
            },
            root,
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[derive(Default)]
pub struct Fake {
    pub replies: Vec<Value>,
    pub requests: Vec<(String, Value)>,
    pub receipts: BTreeMap<String, Value>,
    pub faults: std::collections::BTreeSet<Fault>,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fault {
    LoseResponse,
    Gap,
    Human,
    Removed,
    ChangedContext,
    Absent,
    SelfSender,
    SpoofKind,
    RemoveBeforeSend,
    Revoked,
}
impl Fake {
    pub fn with(fault: Fault) -> Self {
        let mut fake = Self::default();
        fake.faults.insert(fault);
        fake
    }
    fn respond(&mut self, method: &str, body: Value, operation: Option<&str>) -> Result<Value> {
        self.requests.push((method.into(), body.clone()));
        Ok(match method {
            "account.status" => {
                json!({"principal_id":"agent-principal","local_device_authorized":!self.faults.contains(&Fault::Revoked),"client_mode":if self.faults.contains(&Fault::Human){"attended_cli"}else{"headless_ai"}})
            }
            "device.list" => {
                json!({"principal_id":"agent-principal","local_device_id":"agent-device","devices":[{"device_id":"agent-device"}]})
            }
            "identity.directory" => {
                json!({"identities":[{"principal_id":"agent-principal","is_self":true,"kind":if self.faults.contains(&Fault::Human) && !self.faults.contains(&Fault::SpoofKind){"human"}else{"headless_ai"}}, {"principal_id":"human-principal","contact_identity_commitment":"human-commitment","devices":[{"device_id":"human-device","target_delivery_id":"human-target"}]}],"next_cursor":null})
            }
            "conversation.directory" => {
                json!({"conversations":if self.faults.contains(&Fault::Absent){vec![]}else{vec![json!({"id":"dm","kind":"direct","participants":["agent-principal","human-principal"]}),json!({"id":"group-thread","kind":"group","group_id":if self.faults.contains(&Fault::ChangedContext){"another-group"}else{"group"}})]},"next_cursor":null})
            }
            "group.list" => json!({"groups":[],"next_cursor":null}),
            "group.members" => {
                json!({"group_id":"group","members":if self.faults.contains(&Fault::Removed) || self.faults.contains(&Fault::RemoveBeforeSend) && self.requests.iter().filter(|(m,_)|m=="group.members").count()>=2 {vec!["human-device"]}else{vec!["human-device","agent-device"]}})
            }
            "bus.subscribe" => {
                if self.faults.contains(&Fault::Gap) && !body["since_seq"].is_null() {
                    self.faults.remove(&Fault::Gap);
                    return Err(Error::Resync);
                }
                json!({"head_seq":10,"floor_seq":1,"subscribed":true})
            }
            "message.read" => {
                json!({"messages":[{"conversation_id":body["conversation_id"],"message_id":"ping","sender_id":if self.faults.contains(&Fault::SelfSender){"agent-principal"}else{"human-principal"},"body_utf8":"@agent ping","created_at":1000,"deleted":false}]})
            }
            "message.submit" | "group.send" => {
                let id = operation.ok_or(Error::Bus)?;
                if let Some(previous) = self.receipts.get(id) {
                    if previous != &body {
                        return Err(Error::Bus);
                    }
                } else {
                    self.receipts.insert(id.into(), body.clone());
                    self.replies.push(body);
                }
                if self.faults.contains(&Fault::LoseResponse) {
                    self.faults.remove(&Fault::LoseResponse);
                    return Err(Error::Bus);
                }
                json!({"accepted":true})
            }
            "contact.requests.policy.set" => {
                if body["contact_requests"] != "auto_accept" {
                    return Err(Error::State);
                }
                json!({"contact_requests":"auto_accept"})
            }
            "message.receive" => json!({}),
            _ => return Err(Error::Unauthorized),
        })
    }
}
impl AgentBus for Fake {
    fn request(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Value>> {
        std::future::ready(self.respond(method, body, operation))
    }
    async fn next_event(&mut self) -> Result<LocalBusFrame> {
        std::future::pending().await
    }
}
pub fn incoming(seq: u64, group: bool) -> LocalBusFrame {
    let mut event = LocalBusFrame::request(
        "event",
        Some("agent".into()),
        "stream",
        if group { "group.message.received" } else { "message.received" },
        json!({"message":{"conversation_id":if group{"group-thread"}else{"dm"},"message_id":"ping","sender_id":"human-device"}}),
    );
    event.kind = LocalBusFrameKind::Event;
    event.seq = Some(seq);
    event
}
