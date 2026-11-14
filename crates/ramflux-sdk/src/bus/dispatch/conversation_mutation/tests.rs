// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native authority, exact retries and generated structural mutations.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::json;

fn request(method: &str, id: &str, extra: serde_json::Value) -> LocalBusFrame {
    let mut body = json!({"conversation_id":"thread","message_id":id});
    body.as_object_mut().expect("test object").extend(match extra {
        serde_json::Value::Object(fields) => fields,
        _ => panic!("test: fields must be an object"),
    });
    let mut request =
        LocalBusFrame::request(method, Some("source".into()), "conversation", method, body);
    request.operation_id = Some(format!("intent-{method}"));
    request
}
fn seed(client: &RamfluxClient) -> TestResult<String> {
    let identity = client.allocate_generated_identity("thread", 1000, false)?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let exact = RamfluxClient::encode_generated_inner(
        identity.clone(),
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "original".into(),
                ..Default::default()
            })),
        },
    )?;
    client.send_direct_message("thread", &id, "primary", b"ciphertext")?;
    client.account_db()?.store_message_content("thread", &id, &exact)?;
    client.record_authored_conversation_origin(&identity)?;
    client.account_db()?.persist_message_actor_state(
        &id,
        &format!("routed/generated-identity/{id}"),
        &identity,
    )?;
    Ok(id)
}
fn code<T>(result: Result<T, SdkError>, expected: Code) {
    match result {
        Err(SdkError::GeneratedApi(error)) => assert_eq!(error.code, expected as i32),
        _ => panic!("test: expected typed generated refusal"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn generation_zero_mutation_intents_allocate_nothing() -> TestResult {
    let source = Fixture::new("intent-generation-zero").await?;
    let db = source.client.account_db()?;
    let before = db.actor_state_keys("")?;
    for method in
        ["conversation.edit", "conversation.react", "conversation.reply", "conversation.delete"]
    {
        code(
            prepare(&source.client, &request(method, "absent", json!({}))),
            Code::PeerUpgradeRequired,
        );
    }
    assert_eq!(db.actor_state_keys("")?, before);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_mutation_intents_derive_references_revisions_and_exact_retry_payloads() -> TestResult
{
    let source = Fixture::new("intent-author").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let id = seed(&source.client)?;
    for (method, fields, kind) in [
        ("conversation.edit", json!({"text":"replacement"}), 3),
        ("conversation.react", json!({"token":"👍","remove":true}), 5),
        ("conversation.reply", json!({"text":"reply"}), 1),
        ("conversation.delete", json!({"scope":"everyone"}), 4),
    ] {
        let intent = request(method, &id, fields);
        let prepared = prepare(&source.client, &intent)?;
        let retry = prepare(&source.client, &intent)?;
        assert_eq!(
            prepared.exact, retry.exact,
            "retry must reuse private entropy and event identity"
        );
        assert_eq!(g::validation::scan_inner(&prepared.exact)?.kind, kind);
        let (identity, content) = RamfluxClient::decode_generated_inner(&prepared.exact)?;
        assert_eq!(
            identity.author.as_ref().ok_or("author")?.account_anchor,
            source.client.own_account_anchor()?
        );
        match content.value.ok_or("content")? {
            g::content::Value::Edit(edit) => {
                assert_eq!(edit.revision, 1);
                assert_eq!(
                    edit.target.ok_or("target")?.id,
                    ramflux_protocol::decode_base64url(&id)?
                );
                assert_eq!(edit.previous_content_digest.len(), 32);
                assert_eq!(edit.replacement.ok_or("replacement")?.erasure_nonce.len(), 32);
            }
            g::content::Value::Reaction(reaction) => {
                assert_eq!(reaction.operation_id, identity.id);
                assert!(reaction.remove);
            }
            g::content::Value::Message(message) => assert_eq!(
                message.reply_to.ok_or("reply")?.author_anchor,
                source.client.own_account_anchor()?
            ),
            g::content::Value::Delete(delete) => {
                assert_eq!(delete.tombstone_id, g::identity::delete_tombstone(&identity.id)?);
            }
            _ => return Err("unexpected content".into()),
        }
        let mut changed = intent.clone();
        changed.body["message_id"] = json!("changed");
        code(prepare(&source.client, &changed), Code::InvalidArgument);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn mutation_intents_refuse_forged_routing_cross_thread_and_deleted_targets() -> TestResult {
    let source = Fixture::new("intent-refusals").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let id = seed(&source.client)?;
    let mut intent =
        request("conversation.edit", &id, json!({"text":"replacement","sender_id":"forged"}));
    code(prepare(&source.client, &intent), Code::InvalidArgument);
    intent.body.as_object_mut().ok_or("body")?.remove("sender_id");
    intent.body["conversation_id"] = json!("other-thread");
    code(prepare(&source.client, &intent), Code::TargetNotFound);
    intent.body["conversation_id"] = json!("thread");
    source.client.delete_direct_message("thread", &id, "local", "test-delete")?;
    code(prepare(&source.client, &intent), Code::TargetDeleted);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn dispatcher_preserves_typed_generation_refusals_and_local_delete_never_routes() -> TestResult
{
    let root = tempfile::tempdir()?;
    let account = crate::bus::runtime_tests::account(
        root.path(),
        "source",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.path().join("bus.sock"), root.path()),
        accounts: BTreeMap::from([("source".into(), account)]),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let (outbound, _receiver) = tokio::sync::mpsc::channel::<LocalBusFrame>(4);
    let connection = LocalBusConnectionState::new(1, outbound);
    for method in
        ["conversation.edit", "conversation.react", "conversation.reply", "conversation.delete"]
    {
        let result = Box::pin(super::super::message::dispatch_message_bus_request(
            &request(method, "absent", json!({})),
            &mut state,
            &connection,
        ))
        .await;
        let error = result.err().ok_or("generation-zero effect was accepted")?;
        let frame = crate::bus::io::local_bus_error(&request(method, "absent", json!({})), &error);
        assert_eq!(frame.body["name"], "peer_upgrade_required");
        assert_eq!(frame.body["code"], Code::PeerUpgradeRequired as i32);
    }
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let id = seed(&state.accounts.get("source").ok_or("account")?.client)?;
    let response = Box::pin(super::super::message::dispatch_message_bus_request(
        &request("conversation.delete", &id, json!({"scope":"local"})),
        &mut state,
        &connection,
    ))
    .await?;
    assert_eq!(response.response_body["delivery_state"], "local");
    assert_eq!(response.response_body["deliveries"], json!([]));
    let db = state.accounts.get("source").ok_or("account")?.client.account_db()?;
    assert!(db.message_is_deleted(&id)?);
    assert!(db.message_content(&id)?.is_none(), "local deletion must erase the target content");
    assert!(
        db.actor_state_keys("conversation-intent/")?.is_empty(),
        "target erasure must retire private prepared content"
    );
    Ok(())
}
