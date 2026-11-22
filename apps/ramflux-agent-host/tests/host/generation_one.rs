// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual native ciphertext receive, durable bus read, and headless engine input.
use super::support::{Fixture, TestResult};
use ramflux_agent_host::{
    AgentBus, AgentHost, ConversationInput, EngineEvent, EngineInput, EngineProvider, Error,
    Intent, Result,
};
use ramflux_sdk::{LocalBusFrame, NativeCallAccount, NativeMessageBus};
use serde_json::Value;
use std::{cell::RefCell, rc::Rc, time::Duration};

struct Bus {
    native: NativeMessageBus,
    exact_reads: usize,
    /// The local account id the agent creation flow chose.
    agent_id: String,
}
impl AgentBus for Bus {
    async fn request(&mut self, method: &str, body: Value, _: Option<&str>) -> Result<Value> {
        if method == "message.read" {
            assert!(
                body["message_id"].is_string(),
                "engine reads must select the exact durable message"
            );
            self.exact_reads += 1;
        }
        let response = self
            .native
            .request(LocalBusFrame::request(
                "agent-consumer",
                Some(self.agent_id.clone()),
                method.split('.').next().unwrap_or(""),
                method,
                body,
            ))
            .await
            .map_err(|error| {
                eprintln!("test: native bus {method} refused: {error}");
                Error::Bus
            })?;
        Ok(response.body)
    }
    fn next_event(&mut self) -> impl Future<Output = Result<LocalBusFrame>> {
        std::future::ready(Err(Error::Bus))
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Input {
    conversation: String,
    message: String,
    text: String,
    mentioned: bool,
}
#[derive(Clone)]
struct Probe(Rc<RefCell<Vec<Input>>>);
impl EngineProvider for Probe {
    fn intents(&mut self, _: &ConversationInput<'_>) -> Result<Vec<Intent>> {
        Err(Error::State)
    }
    fn submit<'a>(
        &'a mut self,
        input: EngineInput<'a>,
        _: u64,
    ) -> impl Future<Output = Result<Vec<EngineEvent>>> {
        let mut rows = self.0.borrow_mut();
        assert!(rows.is_empty(), "one receive must produce exactly one engine input");
        rows.push(Input {
            conversation: input.conversation.conversation_id.into(),
            message: input.conversation.message_id.into(),
            text: input.conversation.text.into(),
            mentioned: input.mentioned,
        });
        std::future::ready(Ok(Vec::new()))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn generation_one_native_message_reaches_headless_engine_through_durable_read_model()
-> TestResult {
    Box::pin(tokio::time::timeout(Duration::from_secs(60), async {
        let f = Fixture::new()?;
        let account_root = f.root.join("native");
        let mut human = NativeCallAccount::new(&account_root, "human").await?;
        let mut agent = NativeCallAccount::headless(&account_root, "agent", &mut human).await?;
        agent.prepare_call_peer(human.manifest.clone())?;
        human.prepare_call_peer(agent.manifest.clone())?;
        let content = ramflux_protocol::message::Message {
            text: "@agent ping from generation one".into(),
            entities: vec![ramflux_protocol::message::Entity {
                offset: 0,
                length: 6,
                kind: ramflux_protocol::message::EntityKind::EntityMention as i32,
                value: Some(agent.publication.record.body.account_anchor.clone()),
            }],
            ..Default::default()
        };
        let (conversation, message) = human.deliver_message(&mut agent, &content).await?;
        let agent_id = agent.account_id().to_owned();
        let native = agent.into_message_bus()?;
        let event = native.received_event(&agent_id, &message)?;
        let sequence = event.seq.ok_or("test: committed receive event sequence")?;
        let mut bus = Bus { native, exact_reads: 0, agent_id: agent_id.clone() };
        let probe = Probe(Rc::new(RefCell::new(Vec::new())));
        let mut config = f.config.clone();
        config.account_id.clone_from(&agent_id);
        let mut host = AgentHost::new(config, probe.clone())?;
        Box::pin(host.apply(&mut bus, event.clone(), 1000)).await?;
        assert_eq!(
            *probe.0.borrow(),
            vec![Input {
                conversation,
                message,
                text: "@agent ping from generation one".into(),
                mentioned: true
            }]
        );
        assert_eq!(host.checkpoint().cursor, Some(sequence));
        assert_eq!(
            bus.exact_reads, 1,
            "the native Message must be read through the generation-1 bus method"
        );
        Box::pin(host.apply(&mut bus, event, 2000)).await?;
        assert_eq!(bus.exact_reads, 1, "replayed receive cannot reread or rerun the engine");
        Ok::<(), Box<dyn std::error::Error>>(())
    }))
    .await??;
    Ok(())
}
