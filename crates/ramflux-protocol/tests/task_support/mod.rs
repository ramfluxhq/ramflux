// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(dead_code)]
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::*;
pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub struct Actor {
    pub id: &'static str,
    pub role: ActorType,
    pub key_id: &'static str,
    pub key: SigningKey,
    pub public: String,
}
impl Actor {
    pub fn new(id: &'static str, role: ActorType, seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public = encode_base64url(key.verifying_key().to_bytes());
        Self { id, role, key_id: id, key, public }
    }
    pub fn human() -> Self {
        Self::new("human", ActorType::Human, 17)
    }
    pub fn agent() -> Self {
        Self::new("agent", ActorType::Bot, 34)
    }
    pub fn other() -> Self {
        Self::new("other", ActorType::Human, 51)
    }
    pub fn signer(&self) -> TaskSigner<'_> {
        TaskSigner {
            principal_id: self.id,
            actor_type: self.role.clone(),
            signing_key_id: self.key_id,
            public_key_base64url: &self.public,
        }
    }
    pub fn event(&self, body: TaskEventBody) -> Result<TaskEvent> {
        self.sign(TaskEvent::new(
            "chat".to_owned(),
            body,
            SignedFields {
                signing_key_id: self.key_id.to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: String::new(),
            },
        ))
    }
    pub fn sign(&self, mut event: TaskEvent) -> Result<TaskEvent> {
        event.signed.signature = encode_base64url(self.key.sign(&signed_bytes(&event)?).to_bytes());
        Ok(event)
    }
}
pub fn start() -> TaskEventBody {
    TaskEventBody::Start(TaskStart {
        task_id: "task".to_owned(),
        conversation_id: "chat".to_owned(),
        requester: "human".to_owned(),
        assignee: "agent".to_owned(),
        text: "Summarize café 🦀".to_owned(),
        constraints: Some("No network".to_owned()),
    })
}
pub fn step(id: &str, state: TaskStatus) -> TaskStep {
    TaskStep { id: id.to_owned(), title: format!("Step {id}"), state, needs_me: None }
}
pub fn blocked(id: &str, target: NeedsMe) -> TaskStep {
    TaskStep { needs_me: Some(target), ..step(id, TaskStatus::NeedsMe) }
}
pub fn approval() -> NeedsMe {
    NeedsMe::Approval { grant_id: "grant".to_owned() }
}
pub fn proposal() -> TaskEventBody {
    TaskEventBody::Proposal(TaskProposal {
        task_id: "task".to_owned(),
        conversation_id: "chat".to_owned(),
        proposer: "agent".to_owned(),
        assignee: "agent".to_owned(),
        title: "Research 🦀".to_owned(),
        steps: vec![step("s", TaskStatus::Proposed)],
    })
}
pub fn update(version: u64, state: TaskStatus, steps: Vec<TaskStep>) -> TaskEventBody {
    TaskEventBody::Update(TaskUpdate {
        task_id: "task".to_owned(),
        version,
        state,
        steps,
        result_ref: None,
    })
}
pub fn resolve(version: u64, target: NeedsMe, decision: TaskDecision) -> TaskEventBody {
    TaskEventBody::Resolve(TaskResolve {
        task_id: "task".to_owned(),
        version,
        step_id: "s".to_owned(),
        target,
        decision_id: "decision".to_owned(),
        decision,
    })
}
pub fn running() -> Result<TaskState> {
    let mut state = TaskState::default();
    let human = Actor::human();
    state.apply(&human.event(start())?, &human.signer())?;
    Ok(state)
}
pub fn waiting() -> Result<TaskState> {
    let mut state = running()?;
    let agent = Actor::agent();
    state.apply(
        &agent.event(update(2, TaskStatus::NeedsMe, vec![blocked("s", approval())]))?,
        &agent.signer(),
    )?;
    Ok(state)
}
pub fn reject(
    state: &mut TaskState,
    event: &TaskEvent,
    signer: &TaskSigner<'_>,
    expected: &TaskReject,
) -> Result {
    let before = state.clone();
    let error = state.apply(event, signer).err().ok_or("expected task rejection")?;
    assert_eq!(std::mem::discriminant(&error), std::mem::discriminant(expected), "{error:?}");
    if let (
        TaskReject::StaleVersion { expected, actual },
        TaskReject::StaleVersion { expected: want, actual: received },
    ) = (&error, expected)
    {
        assert_eq!((expected, actual), (want, received));
    }
    assert_eq!(*state, before);
    Ok(())
}
