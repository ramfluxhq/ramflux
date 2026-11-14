// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed original-byte RPCs through the account projection and immutable response ledger.
use super::ResyncReply;
use super::rpc::ledger_key;
use super::{Carrier, PayloadKind, SurfaceSender};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{RPC_SCHEMA, RpcFrame, RpcKind, SurfaceRpc};
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    human: RamfluxClient,
    agent: RamfluxClient,
    _root: ramflux_test_support::TestPath,
}
impl Fixture {
    async fn new() -> TestResult<Self> {
        let root = ramflux_test_support::TestPath::new()?;
        let (human, agent) = super::test_support::owned_pair(&root, "human", "agent").await?;
        for client in [&human, &agent] {
            client.account_db()?.persist_client_record(
                "conversation",
                "thread",
                &json!({"kind":"direct","participants":["human","agent"]}),
            )?;
        }
        Ok(Self { human, agent, _root: root })
    }
    fn call(surface: Option<&str>, id: &str) -> RpcFrame {
        let mut body = json!({"functionCallId":id,"callFunction":{"@call":"unsupportedFunction","catalogId":ramflux_protocol::CATALOG_ID,"args":{}}});
        if let Some(surface) = surface
            && let Some(map) = body.as_object_mut()
        {
            map.insert("surfaceId".into(), json!(surface));
        }
        RpcFrame {
            schema: RPC_SCHEMA.into(),
            conversation_id: "thread".into(),
            surface_id: surface.unwrap_or("~rpc").into(),
            known_version: 0,
            known_hash: None,
            function_call_id: Some(id.into()),
            rejected_version: None,
            a2ui: json!({"version":"1.0","callRendererFunction":body}),
        }
    }
    fn carrier(&self, frame: &RpcFrame, message: &str) -> TestResult<Carrier> {
        let local = self.agent.device_branch.as_ref().ok_or("agent branch")?;
        Ok(self.agent.sign_surface_carrier(Carrier {
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            posted_at: None,
            updated_at: None,
            payload_kind: PayloadKind::FunctionCall,
            conversation_id: frame.conversation_id.clone(),
            surface_id: frame.surface_id.clone(),
            message_id: message.into(),
            sender_principal_id: local.principal_id.clone(),
            sender_device_id: local.device_id.clone(),
            author_principal_id: local.principal_id.clone(),
            wire_base64: ramflux_protocol::encode_base64url(
                frame.wire_bytes(RpcKind::FunctionCall)?,
            ),
            signature: String::new(),
            snapshot: None,
        })?)
    }
    fn deliver(&self, carrier: &Carrier) -> Result<super::Outcome, SdkError> {
        self.human
            .project_surface_message(
                "thread",
                &carrier.message_id,
                SurfaceSender {
                    principal: &carrier.sender_principal_id,
                    device: &carrier.sender_device_id,
                    envelope_id: &carrier.message_id,
                    expires_at: None,
                    group_epoch: None,
                },
                &carrier.bytes()?,
                false,
            )?
            .ok_or_else(|| super::invalid("RPC not recognized"))
    }
    fn replies(&self) -> Result<Vec<ResyncReply>, SdkError> {
        Ok(self.human.account_db()?.list_actor_states("surface/rpc-response/")?)
    }
}
#[tokio::test]
async fn surfaceless_nonexistent_and_malformed_calls_reply_without_creating_surface_state()
-> TestResult {
    let f = Fixture::new().await?;
    let before = f.human.surface_list("thread", "", 100)?;
    for (surface, id) in [(None, "surfaceless"), (Some("missing"), "nonexistent")] {
        let call = f.carrier(&Fixture::call(surface, id), id)?;
        assert!(
            f.deliver(&call)?.accepted,
            "well-formed unsupported calls must get a refusal response"
        );
        let replies = f.replies()?;
        let response = replies
            .iter()
            .find(|reply| {
                reply.carrier.payload_kind == PayloadKind::FunctionResponse
                    && ramflux_protocol::decode_base64url(&reply.carrier.wire_base64)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                        .and_then(|v| v.get("functionCallId").cloned())
                        == Some(json!(id))
            })
            .ok_or("response")?;
        let bytes = ramflux_protocol::decode_base64url(&response.carrier.wire_base64)?;
        let response = SurfaceRpc::from_wire_bytes(&bytes, RpcKind::FunctionResponse)?;
        assert_eq!(
            response.frame().a2ui,
            json!({"version":"1.0","rendererFunctionResponse":{"functionCallId":id,"error":{"code":"INVALID_FUNCTION_CALL","message":"function not callable by agent"}}}),
            "unsupported functions must never execute"
        );
        assert_eq!(response.frame().known_version, 0, "absent surfaces have no known state");
    }
    let mut malformed = Fixture::call(None, "malformed");
    malformed
        .a2ui
        .get_mut("callRendererFunction")
        .and_then(Value::as_object_mut)
        .ok_or("call body")?
        .remove("callFunction");
    assert!(
        f.deliver(&f.carrier(&malformed, "malformed")?)?.accepted,
        "a valid frame exposes its bound id for a malformed-call error"
    );
    assert!(
        f.replies()?.iter().any(|r| r.carrier.payload_kind == PayloadKind::Error),
        "malformed calls get the upstream error branch"
    );
    assert_eq!(
        f.human.surface_list("thread", "", 100)?,
        before,
        "RPC must not bootstrap state or consume a surface version"
    );
    Ok(())
}
#[tokio::test]
async fn bound_retry_keeps_response_bytes_and_conflicts_cannot_replace_the_ledger() -> TestResult {
    let f = Fixture::new().await?;
    let frame = Fixture::call(Some("s1"), "same-id");
    let original = f.carrier(&frame, "original")?;
    assert!(f.deliver(&original)?.accepted, "initial call must be answered");
    let first = f.replies()?.pop().ok_or("first response")?;
    let ledger = ledger_key(&original, "same-id")?;
    let stored = f.human.account_db()?.load_actor_state::<Value>(&ledger)?.ok_or("ledger")?;
    f.human.account_db()?.remove_actor_state(&response_key(&first)?)?;
    for (index, mut conflict) in
        [frame.clone(), frame.clone(), frame.clone()].into_iter().enumerate()
    {
        match index {
            0 => {
                conflict.surface_id = "s2".into();
                conflict.a2ui["callRendererFunction"]["surfaceId"] = json!("s2");
            }
            1 => {
                conflict.a2ui["callRendererFunction"]["callFunction"]["args"] =
                    json!({"changed":true});
            }
            _ => {
                conflict.known_version = 1;
                conflict.known_hash = Some("changed".into());
            }
        }
        assert!(
            !f.deliver(&f.carrier(&conflict, &format!("conflict-{index}"))?)?.accepted,
            "conflicting reuse must be dropped"
        );
        assert!(f.replies()?.is_empty(), "a conflict must not send any response");
        assert_eq!(
            f.human.account_db()?.load_actor_state::<Value>(&ledger)?,
            Some(stored.clone()),
            "the first ledger entry is immutable"
        );
    }
    // Advance the recipient's state after the first reply; the retry cannot rebind to it.
    let snapshot = super::test_support::text_snapshot("s1", "Advanced", "hello");
    let event = super::test_support::create_frame("thread", &snapshot)?;
    let mut create = original.clone();
    create.payload_kind = PayloadKind::Event;
    create.message_id = "create-after-call".into();
    create.wire_base64 = ramflux_protocol::encode_base64url(event.wire_bytes()?);
    create = f.agent.sign_surface_carrier(create)?;
    assert!(f.deliver(&create)?.accepted, "state advance must be admitted independently");
    assert!(
        f.deliver(&f.carrier(&frame, "exact-retry")?)?.accepted,
        "the original exact frame stays retryable after conflicts and state advance"
    );
    let retry = f.replies()?.pop().ok_or("retry response")?;
    assert_eq!(
        retry.carrier.wire_base64, first.carrier.wire_base64,
        "retry response bytes must remain byte-identical"
    );
    assert_ne!(
        retry.carrier.message_id, first.carrier.message_id,
        "a retry has a fresh carrier id"
    );
    assert_eq!(
        f.human.account_db()?.load_actor_state::<Value>(&ledger)?,
        Some(stored),
        "retry cannot rewrite its original known version/hash"
    );
    assert_eq!(
        f.human.surface_get("s1", 0, None)?["version"],
        1,
        "RPC must not advance the surface"
    );
    Ok(())
}
fn response_key(reply: &ResyncReply) -> Result<String, SdkError> {
    Ok(format!(
        "surface/rpc-response/{}",
        ramflux_protocol::hash_base64url(
            ramflux_protocol::domain::SURFACE_RPC_REQUEST,
            &ramflux_protocol::canonical_json_bytes(&(
                &reply.carrier.conversation_id,
                &reply.carrier.author_principal_id,
                &reply.destination.device,
                &reply.carrier.wire_base64
            ))?
        )
    ))
}

#[tokio::test]
async fn rpc_rate_cap_and_expired_ledger_entries_bound_work_without_surface_mutation() -> TestResult
{
    let f = Fixture::new().await?;
    let before = f.human.surface_list("thread", "", 100)?;
    let first = f.carrier(&Fixture::call(None, "first"), "first")?;
    assert!(f.deliver(&first)?.accepted, "first call must be answered");
    let original_key = ledger_key(&first, "first")?;
    let db = f.human.account_db()?;
    let entry = db.load_actor_state::<Value>(&original_key)?.ok_or("first ledger entry")?;
    for index in 1..8 {
        let id = format!("rate-{index}");
        assert!(
            f.deliver(&f.carrier(&Fixture::call(None, &id), &id)?)?.accepted,
            "eight calls per author per minute are permitted"
        );
    }
    assert!(
        !f.deliver(&f.carrier(&Fixture::call(None, "excess"), "excess")?)?.accepted,
        "the ninth call is silently dropped"
    );
    assert_eq!(f.replies()?.len(), 8, "excess calls cannot queue responses");
    db.remove_actor_state(&super::key("rpc-rate", "agent"))?;
    let prefix = super::key("rpc-ledger", "agent") + "/";
    for candidate in db.actor_state_key_page(&prefix, 257)? {
        db.remove_actor_state(&candidate)?;
    }
    for index in 0..256 {
        db.persist_actor_state(&ledger_key(&first, &format!("retained-{index}"))?, &entry)?;
    }
    assert!(
        !f.deliver(&f.carrier(&Fixture::call(None, "at-cap"), "at-cap")?)?.accepted,
        "new calls cannot overwrite retained entries at the per-author cap"
    );
    assert_eq!(db.actor_state_key_page(&prefix, 257)?.len(), 256, "the cap must remain exact");
    let mut expired = entry;
    expired
        .as_object_mut()
        .ok_or("entry object")?
        .insert("expires_at".into(), json!(crate::prelude::now_unix_timestamp() - 1));
    for candidate in db.actor_state_key_page(&prefix, 257)? {
        db.persist_actor_state(&candidate, &expired)?;
    }
    assert!(
        f.deliver(&f.carrier(&Fixture::call(None, "after-expiry"), "after-expiry")?)?.accepted,
        "expired entries free capacity without an overwrite"
    );
    assert_eq!(
        db.actor_state_key_page(&prefix, 257)?.len(),
        1,
        "expired entries are pruned before admission"
    );
    assert_eq!(
        f.human.surface_list("thread", "", 100)?,
        before,
        "rate limits and ledger maintenance cannot create renderer state"
    );
    Ok(())
}

#[tokio::test]
async fn repeated_rejected_versions_queue_one_error_report_and_never_bootstrap_state() -> TestResult
{
    let f = Fixture::new().await?;
    let snapshot = super::test_support::text_snapshot("s1", "Rejected", "hello");
    let mut event = super::test_support::create_frame("thread", &snapshot)?;
    event.new_surface_hash = "incorrect".into();
    for attempt in 0..2 {
        let mut carrier =
            f.carrier(&Fixture::call(None, "template"), &format!("rejected-{attempt}"))?;
        carrier.payload_kind = PayloadKind::Event;
        carrier.surface_id = "s1".into();
        carrier.wire_base64 = ramflux_protocol::encode_base64url(event.wire_bytes()?);
        carrier = f.agent.sign_surface_carrier(carrier)?;
        assert!(!f.deliver(&carrier)?.accepted, "a signed hash mismatch must be rejected");
    }
    let replies = f.replies()?;
    assert_eq!(replies.len(), 1, "the same attempted surface version reports at most once");
    let report = replies.first().ok_or("error report")?;
    assert_eq!(
        report.carrier.payload_kind,
        PayloadKind::Error,
        "the report uses the error carrier kind"
    );
    let bytes = ramflux_protocol::decode_base64url(&report.carrier.wire_base64)?;
    let error = SurfaceRpc::from_wire_bytes(&bytes, RpcKind::Error)?;
    assert_eq!(error.frame().rejected_version, Some(1), "report binds the rejected event version");
    assert_eq!(error.frame().known_version, 0, "rejection cannot install the offered state");
    assert!(
        f.human.surface_get("s1", 0, None)?.get("snapshot").is_none_or(Value::is_null),
        "rejected creates cannot bootstrap renderer state"
    );
    Ok(())
}
