// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed task authority does not allow an agent to resolve a human intervention.
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::{
    ActorType, SignatureAlg, SignedFields, TaskEvent, TaskEventBody, TaskReject, TaskSigner,
    TaskState,
};
use serde_json::json;

#[test]
fn an_agent_cannot_fail_an_unaccepted_proposal_or_unresolved_human_step()
-> Result<(), Box<dyn std::error::Error>> {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = ramflux_protocol::encode_base64url(key.verifying_key().to_bytes());
    let signer = TaskSigner {
        principal_id: "agent",
        actor_type: ActorType::Bot,
        signing_key_id: "device",
        public_key_base64url: &public,
    };
    for accepted in [false, true] {
        let state = if accepted { "needs_me" } else { "proposed" };
        let version = if accepted { 3 } else { 1 };
        let mut step = json!({"id":"approval","title":"Approve tool","state":state});
        if accepted {
            step["needs_me"] = json!({"kind":"approval","grant_id":"grant"});
        }
        let mut task: TaskState = serde_json::from_value(json!({
            "task":{"task_id":"task","conversation_id":"conversation","requester":if accepted {Some("human")} else {None},"proposer":"agent","assignee":"agent","title":"Approve tool","text":null,"constraints":null,"version":version,"state":state,"steps":[step],"result_ref":null,"accepted":accepted},
            "decisions":[],"approvals":[],"pending_since":if accepted {json!({"approval":3})} else {json!({})}
        }))?;
        let update = TaskEventBody::Update(serde_json::from_value(json!({
            "task_id":"task","version":version+1,"state":"failed","steps":[{"id":"approval","title":"Approve tool","state":"failed"}],"result_summary":"PRX approval timed out"
        }))?);
        let event = TaskEvent::new(
            "conversation".into(),
            update,
            SignedFields {
                signing_key_id: "device".into(),
                signature_alg: SignatureAlg::Ed25519,
                signature: String::new(),
            },
        )?;
        let signature = key.sign(&ramflux_protocol::signed_bytes(&event)?);
        let event =
            event.with_signature(ramflux_protocol::encode_base64url(signature.to_bytes()))?;
        let result = task.apply(&event, &signer);
        assert!(
            matches!(result, Err(TaskReject::HumanDecisionPending)) && accepted
                || matches!(result, Err(TaskReject::IllegalTransition)) && !accepted
        );
    }
    Ok(())
}
