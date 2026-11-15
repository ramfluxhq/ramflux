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

async fn within_deadline<T>(
    work: impl std::future::Future<Output = TestResult<T>>,
) -> TestResult<T> {
    tokio::time::timeout(std::time::Duration::from_secs(30), work).await?
}

#[tokio::test(flavor = "current_thread")]
async fn active_mutation_missing_targets_allocate_nothing() -> TestResult {
    within_deadline(async {
        let source = Fixture::new("intent-generation-zero").await?;
        let db = source.client.account_db()?;
        let before = db.actor_state_keys("")?;
        for method in
            ["conversation.edit", "conversation.react", "conversation.reply", "conversation.delete"]
        {
            code(
                prepare(
                    &source.client,
                    &request(
                        method,
                        "absent",
                        match method {
                            "conversation.edit" => json!({"text":"content","expected_revision":0}),
                            "conversation.reply" => json!({"text":"content"}),
                            "conversation.react" => json!({"token":"👍"}),
                            _ => json!({"scope":"everyone"}),
                        },
                    ),
                ),
                Code::TargetNotFound,
            );
        }
        assert_eq!(db.actor_state_keys("")?, before);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn native_mutation_intents_derive_references_revisions_and_exact_retry_payloads() -> TestResult
{
    within_deadline(async {
        let source = Fixture::new("intent-author").await?;
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let id = seed(&source.client)?;
        for (method, fields, kind) in [
            ("conversation.edit", json!({"text":"replacement","expected_revision":0}), 3),
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
    })
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn stale_expected_revision_is_edit_conflict_and_keeps_the_stored_bytes() -> TestResult {
    within_deadline(async {
        let source = Fixture::new("intent-conflict").await?;
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let id = seed(&source.client)?;
        let before = source.client.account_db()?.message_content(&id)?;
        let stale =
            request("conversation.edit", &id, json!({"text":"stale","expected_revision":4}));
        match prepare(&source.client, &stale) {
            Err(SdkError::EditConflict { target, expected, received }) => {
                assert_eq!(target, id, "the conflict names the message the caller tried to edit");
                assert_eq!(expected, 1, "stored revision 0 accepts only the next revision");
                assert_eq!(received, 5, "base 4 would have written revision 5");
            }
            Err(other) => {
                return Err(format!("stale edit must be edit_conflict, got {other}").into());
            }
            Ok(_) => return Err("stale edit must be edit_conflict, got a prepared edit".into()),
        }
        assert_eq!(
            source.client.account_db()?.message_content(&id)?,
            before,
            "a refused edit must not replace the stored bytes"
        );
        let current =
            request("conversation.edit", &id, json!({"text":"fresh","expected_revision":0}));
        let prepared = prepare(&source.client, &current)?;
        let (_, content) = RamfluxClient::decode_generated_inner(&prepared.exact)?;
        let g::content::Value::Edit(edit) = content.value.ok_or("edit")? else {
            return Err("matching base did not build an edit".into());
        };
        assert_eq!(edit.revision, 1, "a matching base writes the next revision");
        let wrapped =
            SdkError::from(crate::bindings::AdapterError::from_sdk(&SdkError::EditConflict {
                target: id.clone(),
                expected: 1,
                received: 5,
            }));
        let frame = crate::bus::io::local_bus_error(&stale, &wrapped);
        assert_eq!(frame.body["code"], 7, "the bus body carries generated code 7");
        assert_eq!(frame.body["name"], "edit_conflict", "the bus body names edit_conflict");
        assert_eq!(frame.body["details"]["target"], id);
        assert_eq!(frame.body["details"]["expected"], 1);
        assert_eq!(frame.body["details"]["received"], 5);
        let error = frame.error.as_ref().ok_or("bus error body")?;
        assert_eq!(error.code, "edit_conflict", "the bus error code is edit_conflict");
        assert_eq!(error.details.as_ref().ok_or("details")?["expected"], 1);
        let reply =
            request("conversation.reply", &id, json!({"text":"reply","expected_revision":0}));
        code(prepare(&source.client, &reply), Code::InvalidArgument);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn mutation_intents_refuse_forged_routing_cross_thread_and_deleted_targets() -> TestResult {
    within_deadline(async {
        let source = Fixture::new("intent-refusals").await?;
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let id = seed(&source.client)?;
        let mut intent = request(
            "conversation.edit",
            &id,
            json!({"text":"replacement","expected_revision":0,"sender_id":"forged"}),
        );
        code(prepare(&source.client, &intent), Code::InvalidArgument);
        intent.body.as_object_mut().ok_or("body")?.remove("sender_id");
        intent.body["conversation_id"] = json!("other-thread");
        code(prepare(&source.client, &intent), Code::TargetNotFound);
        intent.body["conversation_id"] = json!("thread");
        source.client.delete_direct_message(
            "thread",
            &id,
            "local",
            &ramflux_protocol::encode_base64url([17; 32]),
        )?;
        code(prepare(&source.client, &intent), Code::TargetDeleted);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn dispatcher_preserves_typed_input_refusals_and_local_delete_never_routes() -> TestResult {
    within_deadline(async {
        let mut native = Fixture::new("source").await?;
        let root = native.root.0.clone();
        let account = LocalBusAccountState::disconnected(
            std::mem::take(&mut native.client),
            native.config.clone(),
            native.manifest.principal_commitment.clone(),
        );
        let mut state = LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config: LocalBusConfig::new(root.join("bus.sock"), &root),
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
            let error = result.err().ok_or("invalid intent was accepted")?;
            let frame =
                crate::bus::io::local_bus_error(&request(method, "absent", json!({})), &error);
            assert_eq!(frame.body["name"], "invalid_argument");
            assert_eq!(frame.body["code"], Code::InvalidArgument as i32);
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
    })
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn edit_without_expected_revision_is_refused() -> TestResult {
    within_deadline(async {
        let source = Fixture::new("intent-edit-base-required").await?;
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let id = seed(&source.client)?;
        let before = source.client.account_db()?.actor_state_keys("")?;
        let missing = request("conversation.edit", &id, json!({"text":"replacement"}));
        let Err(error) = prepare(&source.client, &missing) else {
            return Err("edit without a base must be refused".into());
        };
        let adapter = AdapterError::from_sdk(&error);
        assert_eq!(
            adapter.code,
            Code::InvalidArgument as i32,
            "a missing base is invalid_argument"
        );
        assert!(adapter.message.contains("expected_revision is required"), "{}", adapter.message);
        assert_eq!(
            source.client.account_db()?.actor_state_keys("")?,
            before,
            "a missing base allocates nothing"
        );
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn same_base_reserves_one_edit_and_refuses_the_other_before_send() -> TestResult {
    within_deadline(async {
        let source = Fixture::new("intent-edit-reserve").await?;
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let id = seed(&source.client)?;
        let before = source.client.account_db()?.message_content(&id)?;
        let mut first =
            request("conversation.edit", &id, json!({"text":"one","expected_revision":0}));
        first.operation_id = Some("edit-a".into());
        let prepared = prepare(&source.client, &first)?;
        let mut second =
            request("conversation.edit", &id, json!({"text":"two","expected_revision":0}));
        second.operation_id = Some("edit-b".into());
        match prepare(&source.client, &second) {
            Err(SdkError::EditConflict { target, expected, received }) => {
                assert_eq!(target, id, "the conflict names the message");
                assert_eq!(
                    (expected, received),
                    (2, 1),
                    "the reserved next revision is the conflict"
                );
            }
            Err(error) => {
                return Err(format!("second edit must be edit_conflict, got {error}").into());
            }
            Ok(_) => return Err("second edit must be edit_conflict, got a prepared edit".into()),
        }
        let db = source.client.account_db()?;
        assert_eq!(db.message_content(&id)?, before, "neither edit is applied before send");
        assert_eq!(
            db.actor_state_keys("conversation-intent/")?.len(),
            1,
            "only the winner is prepared"
        );
        let loser = super::super::conversation_journal::key("edit-b");
        assert!(!db.actor_state_exists(&loser)?, "the loser has no operation receipt to send");
        assert!(db.actor_state_exists(&prepared.journal_key)?, "the winner keeps its receipt");
        assert!(
            db.actor_state_exists(&format!("conversation-edit-reservation/{id}"))?,
            "the base stays reserved for the winner"
        );
        let retry = prepare(&source.client, &first)?;
        assert_eq!(retry.exact, prepared.exact, "the owner retries the same payload");
        Ok(())
    })
    .await
}

fn direct_edit(
    client: &RamfluxClient,
    original: &g::EventIdentity,
    stored: &[u8],
    revision: u64,
    text: &str,
) -> TestResult<Vec<u8>> {
    let target = g::MessageRef {
        id: original.id.clone(),
        conversation_id: original.conversation_id.clone(),
        author_anchor: client.own_account_anchor()?,
    };
    let digest = crate::client::message_mutations::previous_content_digest(&target, stored)?;
    let identity = client.allocate_generated_identity(&original.conversation_id, 2_000, false)?;
    Ok(RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Edit(g::Edit {
                target: Some(target),
                revision,
                previous_content_digest: digest.to_vec(),
                replacement: Some(g::Message { text: text.into(), ..Default::default() }),
            })),
        },
    )?)
}

fn project_authored_edit(client: &RamfluxClient, exact: &[u8]) -> Result<bool, SdkError> {
    let device = client.owned_device_identity()?;
    let entry = crate::GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "local".into(),
        envelope: ramflux_protocol::Envelope {
            schema: "unused".into(),
            version: 1,
            domain: "unused".into(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "unused".into(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "unused".into(),
            },
            envelope_id: "unused".into(),
            source_principal_id: "unused".into(),
            source_device_id: "unused".into(),
            target_delivery_id: "unused".into(),
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::Message,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 1,
            created_at: 0,
            encrypted_payload: String::new(),
            payload_hash: String::new(),
            delivery_mode: None,
            collapse_tag: None,
            report_commitment: None,
        },
    };
    client.apply_generated_edit_authorized(
        crate::client::message_mutations::EditContext {
            entry: &entry,
            source: &device,
            imported: None,
            own_sent: false,
            author_submit: true,
        },
        "thread",
        exact,
        None,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn authored_projection_fork_is_edit_conflict_and_is_not_journalled() -> TestResult {
    within_deadline(async {
        let source = Fixture::new("intent-authored-fork").await?;
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let id = seed(&source.client)?;
        let original = source
            .client
            .account_db()?
            .load_actor_state::<g::EventIdentity>(&format!("routed/generated-identity/{id}"))?
            .ok_or("identity")?;
        let stored = source.client.account_db()?.message_content(&id)?.ok_or("stored")?;
        let first = direct_edit(&source.client, &original, &stored, 1, "winner")?;
        assert!(project_authored_edit(&source.client, &first)?, "the first authored edit applies");
        let winner = source.client.account_db()?.message_content(&id)?;
        let fork = direct_edit(&source.client, &original, &stored, 1, "loser")?;
        match project_authored_edit(&source.client, &fork) {
            Err(SdkError::EditConflict { target, expected, received }) => {
                assert_eq!(target, id, "the fork names the message");
                assert_eq!(
                    (expected, received),
                    (2, 1),
                    "an equal revision conflicts with the winner"
                );
            }
            Err(error) => return Err(format!("fork must be edit_conflict, got {error}").into()),
            Ok(applied) => {
                return Err(format!("fork must be edit_conflict, applied={applied}").into());
            }
        }
        assert_eq!(
            source.client.account_db()?.message_content(&id)?,
            winner,
            "the fork must not replace the winner"
        );
        assert!(
            source.client.account_db()?.latest_journal_event("message.edit.conflict")?.is_none(),
            "an author submit does not journal the fork"
        );
        Ok(())
    })
    .await
}
