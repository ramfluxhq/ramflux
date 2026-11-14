// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native admitted receive, winning edits and typed local search over real `SQLCipher` storage.
use super::*;
use crate::search::{LocalSearch, SearchError, SearchKind, SearchQuery};
use ramflux_protocol::message as g;
use ramflux_storage::local_search::{SearchActivation, SearchControl};

impl Fixture {
    async fn search_fixture(
        directory: &ramflux_test_support::TestPath,
        id: &str,
    ) -> TestResult<Self> {
        let root = Root(directory.child(id));
        std::fs::create_dir(&root.0)?;
        let vault = Arc::new(TestVault::default());
        let account = create_with_device(
            &root.0,
            id,
            "primary",
            vault.as_ref(),
            crate::custody::network_now()?,
        )?;
        let anchor = account.record().body.account_anchor.clone();
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.seal_new_account_data(id, &anchor, b"native fixture data passphrase")?;
        client.unlock_account(id, b"native fixture data passphrase")?;
        client.initialize_born_v3_branch("primary", vault.clone()).await?;
        Self::ready(client, root, vault, id, "primary", account.record().clone())
    }
}

fn inner(
    source: &Fixture,
    conversation: &str,
    text: &str,
) -> TestResult<(g::EventIdentity, Vec<u8>)> {
    let identity = source.client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let body = RamfluxClient::encode_generated_inner(
        identity.clone(),
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: text.into(),
                ..Default::default()
            })),
        },
    )?;
    Ok((identity, body))
}
async fn rebuild(runtime: &LocalSearch, client: &RamfluxClient) -> TestResult {
    let status = runtime.rebuild(client, 1, "rebuild").await?;
    assert_eq!(
        status.coverage,
        crate::search::SearchCoverage::Complete,
        "the real maintenance lease must finish admitted fixture sources without silently pausing"
    );
    assert_eq!(
        status.rebuild.ok_or("completed rebuild job")?.state,
        crate::search::SearchRebuildState::Complete,
        "Rust API must use the same tracked lease state machine as bus maintenance"
    );
    Ok(())
}
async fn hits(
    runtime: &LocalSearch,
    client: &RamfluxClient,
    text: &str,
) -> TestResult<crate::search::SearchPage> {
    let mut query = SearchQuery::new("query", text);
    query.kinds = vec![SearchKind::Message];
    let completion = runtime.query(client, 1, &query).await?;
    Ok(completion.take()?)
}

fn search_step(
    phase: &'static str,
    future: impl std::future::Future<Output = TestResult>,
) -> impl std::future::Future<Output = TestResult> {
    let future = Box::pin(future);
    async move { future.await.map_err(|error| format!("{phase}: {error}").into()) }
}

#[tokio::test(flavor = "current_thread")]
async fn local_search_live_versions_and_scope() -> TestResult {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        Box::pin(async {
            let directory = ramflux_test_support::TestPath::new()?;
            let source = Fixture::search_fixture(&directory, "source").await?;
            let mut target = Fixture::search_fixture(&directory, "target").await?;
            let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
            source.client.persist_fetched_identity_directory(&target.manifest)?;
            target.client.persist_fetched_identity_directory(&source.manifest)?;
            let source_anchor = source.client.own_account_anchor()?;
            let target_anchor = target.client.own_account_anchor()?;
            let conversation = g::dm_scope::derive(&source_anchor, &target_anchor)?;
            source.client.establish_friend_link("link", &source_anchor, &target_anchor)?;
            target.client.establish_friend_link("link", &target_anchor, &source_anchor)?;
            let runtime =
                LocalSearch::for_db(target.client.account_db()?, SearchActivation::testing())?;
            let (original, body) = inner(&source, &conversation, "oldcanary 東京都 café")?;
            target.receive(source.seal_inner_to(&target, &body)?, 1).await?;
            search_step("initial rebuild", rebuild(&runtime, &target.client)).await?;
            assert_eq!(
                hits(&runtime, &target.client, "oldcanary").await?.items.len(),
                1,
                "authenticated receive must enter the local index"
            );
            let mut wrong_scope = SearchQuery::new("scope", "oldcanary");
            wrong_scope.conversation_id = Some("different-conversation".into());
            assert!(
                runtime.query(&target.client, 1, &wrong_scope).await?.take()?.items.is_empty(),
                "conversation scope must be checked against authoritative sources"
            );
            let replacement = g::Message { text: "newcanary 中文".into(), ..Default::default() };
            let identity = source.client.allocate_generated_identity(
                &conversation,
                crate::client::generated_identity::now_ms(),
                false,
            )?;
            let target_ref = g::MessageRef {
                id: original.id.clone(),
                conversation_id: conversation.clone(),
                author_anchor: source_anchor,
            };
            let digest =
                crate::client::message_mutations::previous_content_digest(&target_ref, &body)?;
            let edit = RamfluxClient::encode_generated_inner(
                identity,
                &g::Content {
                    value: Some(g::content::Value::Edit(g::Edit {
                        target: Some(target_ref),
                        revision: 1,
                        previous_content_digest: digest.to_vec(),
                        replacement: Some(replacement),
                    })),
                },
            )?;
            target.receive(source.seal_inner_to(&target, &edit)?, 2).await?;
            assert!(
                hits(&runtime, &target.client, "oldcanary").await?.items.is_empty(),
                "winning edit must purge old terms with replacement indexing paused"
            );
            assert!(
                hits(&runtime, &target.client, "newcanary").await?.items.is_empty(),
                "new terms must not appear before ID-only rebuild"
            );
            search_step("winning edit rebuild", rebuild(&runtime, &target.client)).await?;
            assert_eq!(
                hits(&runtime, &target.client, "newcanary").await?.items.len(),
                1,
                "rebuild must index the accepted replacement"
            );
            search_step(
                "spoiler scope",
                spoiler_scope(&source, &mut target, &runtime, &conversation),
            )
            .await?;
            search_step(
                "attachment scope",
                Box::pin(attachment_scope(&source, &mut target, &runtime, &conversation)),
            )
            .await?;
            search_step("expiry boundary", expiry_boundary(&mut target, &runtime, &original.id))
                .await?;
            target
                .client
                .account_db()?
                .hide_conversation_at(&conversation, crate::time::now_unix_timestamp())?;
            assert!(
                hits(&runtime, &target.client, "newcanary").await?.items.is_empty(),
                "visibility restriction must purge all conversation derivatives"
            );
            search_step("group scope", group_scope(&source, &target, &runtime)).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        }),
    )
    .await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn local_search_epochs_and_pending_completions() -> TestResult {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        Box::pin(async {
            let directory = ramflux_test_support::TestPath::new()?;
            let mut fixture = Fixture::search_fixture(&directory, "epoch-owner").await?;
            let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
            let runtime =
                LocalSearch::for_db(fixture.client.account_db()?, SearchActivation::testing())?;
            shared_cancellation_and_lease_ownership(&runtime, &fixture).await?;
            let query = SearchQuery::new("empty-query", "canary");
            let completion = runtime.query(&fixture.client, 7, &query).await?;
            assert!(
                matches!(
                    runtime.cancel(7, runtime.unlock_epoch().wrapping_add(1), "empty-query"),
                    Err(SearchError::CursorStale)
                ),
                "an old unlock must not cancel current work"
            );
            completion.check_current()?;
            let token = runtime.queue_completion(7, completion)?;
            assert!(
                serde_json::to_string(&token)?.len() < 128,
                "queued frame must contain no page plaintext"
            );
            fixture.client.account_db()?.persist_client_record(
                "conversation",
                "thread",
                &serde_json::json!({"title":"changed"}),
            )?;
            let completion =
                runtime.take_completion(7, token["search_completion"].as_str().ok_or("token")?)?;
            assert!(
                matches!(completion.take(), Err(SearchError::CursorStale)),
                "canonical mutation must revoke queued completion before publication"
            );
            drop(completion);
            let completion = runtime
                .query(&fixture.client, 7, &SearchQuery::new("lock-query", "canary"))
                .await?;
            let mut closing = Box::pin(runtime.admit(7, "closing-queued"));
            std::future::poll_fn(|cx| {
                use std::future::Future as _;
                assert!(closing.as_mut().poll(cx).is_pending(), "closure fixture must have a real queued admission behind the held completion");
                std::task::Poll::Ready(())
            }).await;
            drop(fixture.client.active_account_db.take());
            assert!(matches!(closing.await, Err(crate::SdkError::Search(SearchError::Cancelled))), "closing the real writer must wake queued work while the old executor is still held");
            assert!(
                matches!(completion.take(), Err(SearchError::CursorStale)),
                "closing the real account writer must revoke pending plaintext without an explicit service callback"
            );
            drop(completion);
            fixture.client.unlock_account("epoch-owner", b"native fixture data passphrase")?;
            assert!(matches!(runtime.index_status(&fixture.client), Err(crate::SdkError::Search(SearchError::AccountLocked))), "a runtime from the old open must not bind to a new unlock of the same path and schema epoch");
            let reopened=LocalSearch::for_db(fixture.client.account_db()?, SearchActivation::testing())?;
            reopened.index_status(&fixture.client)?;
            let revision = fixture
                .client
                .account_db()?
                .search_revision(&SearchActivation::testing(), &SearchControl::new())?;
            assert!(revision.revision > 0, "epoch witness must use the actual keyed database");
            Ok::<_, Box<dyn std::error::Error>>(())
        }),
    )
    .await??;
    Ok(())
}

async fn shared_cancellation_and_lease_ownership(
    runtime: &Arc<LocalSearch>,
    fixture: &Fixture,
) -> TestResult {
    let peer = LocalSearch::for_db(fixture.client.account_db()?, SearchActivation::testing())?;
    let held = runtime.admit(7, "shared-executor").await?;
    let mut queued = Box::pin(peer.admit(7, "shared-queue"));
    std::future::poll_fn(|cx| {
        use std::future::Future as _;
        assert!(
            queued.as_mut().poll(cx).is_pending(),
            "another handle for the same open account must share its one executor"
        );
        std::task::Poll::Ready(())
    })
    .await;
    runtime.cancel(7, runtime.unlock_epoch(), "shared-queue")?;
    assert!(
        matches!(queued.await, Err(crate::SdkError::Search(SearchError::Cancelled))),
        "shared-account queue must retain out-of-queue cancellation"
    );
    drop(held);
    drop(peer);
    let ticket = runtime.start_rebuild(7, "paused-job")?;
    drop(ticket);
    assert_eq!(
        runtime.index_status(&fixture.client)?.rebuild.ok_or("paused job")?.state,
        crate::search::SearchRebuildState::Paused,
        "dropping a lease before its first poll must release job ownership"
    );
    let old_ticket = runtime.start_rebuild(7, "reused-job")?;
    runtime.cancel_rebuild(7, runtime.unlock_epoch(), "reused-job")?;
    let new_ticket = runtime.start_rebuild(7, "reused-job")?;
    drop(old_ticket);
    assert!(
        matches!(
            runtime.start_rebuild(7, "third-job"),
            Err(crate::SdkError::Search(SearchError::Capacity))
        ),
        "old lease destruction must not release a newly reused job ID"
    );
    drop(new_ticket);
    let ticket = runtime.start_rebuild(7, "shared-id")?;
    let shared =
        runtime.query(&fixture.client, 7, &SearchQuery::new("shared-id", "canary")).await?;
    runtime.cancel_rebuild(7, runtime.unlock_epoch(), "shared-id")?;
    shared.check_current()?;
    drop(shared);
    drop(ticket);
    let cancelled =
        runtime.query(&fixture.client, 7, &SearchQuery::new("cancelled-reply", "canary")).await?;
    let token = runtime.queue_completion(7, cancelled)?;
    runtime.cancel(7, runtime.unlock_epoch(), "cancelled-reply")?;
    assert!(
        matches!(
            runtime.take_completion(7, token["search_completion"].as_str().ok_or("cancel token")?),
            Err(crate::SdkError::Search(SearchError::CursorStale))
        ),
        "cancellation must release a queued completion and its executor admission immediately"
    );
    runtime
        .query(&fixture.client, 7, &SearchQuery::new("cancelled-reply", "canary"))
        .await?
        .take()?;
    Ok(())
}

async fn group_scope(source: &Fixture, target: &Fixture, runtime: &LocalSearch) -> TestResult {
    use ramflux_protocol::group_state::GroupStateChange;
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native source")?
        .group_primary(source.vault.as_ref())?;
    source.client.shared_group_create_with_primary(
        "search-group",
        "group-thread",
        Some("groupcanary".into()),
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let member = target.client.owned_group_actor(&target.config.target_delivery_id)?.identity;
    let state = source.client.shared_group_change_with_primary(
        "search-group",
        &source.config.target_delivery_id,
        GroupStateChange::Add {
            member: member.clone(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
    rebuild(runtime, &target.client).await?;
    let mut query = SearchQuery::new("group-query", "groupcanary");
    query.kinds = vec![SearchKind::Conversation];
    assert_eq!(
        runtime.query(&target.client, 1, &query).await?.take()?.items.len(),
        1,
        "verified current group member may search the signed conversation title"
    );
    let removed = source.client.shared_group_change_with_primary(
        "search-group",
        &source.config.target_delivery_id,
        GroupStateChange::Remove {
            root_commitment: member.root_commitment,
            device_id: member.device_id,
        },
        Some(&primary),
    )?;
    target.client.accept_shared_group_state(&removed, &target.config.target_delivery_id)?;
    assert!(
        runtime.query(&target.client, 1, &query).await?.take()?.items.is_empty(),
        "membership revocation must purge the title before replacement maintenance"
    );
    Ok(())
}

async fn expiry_boundary(target: &mut Fixture, runtime: &LocalSearch, id: &[u8]) -> TestResult {
    use std::sync::atomic::{AtomicI64, Ordering};
    let message = ramflux_protocol::encode_base64url(id);
    let input = target
        .client
        .account_db()?
        .search_message_input(&SearchActivation::testing(), &message, &SearchControl::new())?
        .ok_or("visible source before expiry")?;
    let expiry = input.created_at.checked_add(1_000_000).ok_or("expiry")?;
    let clock = Arc::new(AtomicI64::new(input.created_at + 1));
    target
        .client
        .active_account_db
        .as_mut()
        .ok_or("unlocked database")?
        .set_clock(ramflux_storage::AccountClock::Sequence(Arc::clone(&clock)));
    target.client.account_db()?.set_disappearing_policy(
        &input.conversation_id,
        1_000_000,
        "on_send",
        "local",
        input.created_at,
    )?;
    rebuild(runtime, &target.client).await?;
    let mut request = SearchQuery::new("expiry-query", "newcanary");
    request.kinds = vec![SearchKind::Message];
    let completion = runtime.query(&target.client, 1, &request).await?;
    clock.store(expiry, Ordering::Release);
    assert!(
        matches!(completion.take(), Err(SearchError::CursorStale)),
        "a queued page must become stale on clock expiry even without a database mutation"
    );
    drop(completion);
    assert!(
        hits(runtime, &target.client, "newcanary").await?.items.is_empty(),
        "authoritative hydration must refuse expired sources before the cleanup sweep"
    );
    let retired =
        target.client.account_db()?.expire_disappearing_messages(&input.conversation_id, expiry)?;
    assert!(
        retired.iter().any(|tombstone| tombstone.message_id == message),
        "real expiry must retire the original source and its search footprints"
    );
    target
        .client
        .active_account_db
        .as_mut()
        .ok_or("unlocked database")?
        .set_clock(ramflux_storage::AccountClock::Real);
    Ok(())
}

async fn spoiler_scope(
    source: &Fixture,
    target: &mut Fixture,
    runtime: &LocalSearch,
    conversation: &str,
) -> TestResult {
    let identity = source.client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let body = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "visiblecanary secretcanary".into(),
                entities: vec![g::Entity {
                    offset: 14,
                    length: 12,
                    kind: g::EntityKind::EntitySpoiler as i32,
                    value: None,
                }],
                ..Default::default()
            })),
        },
    )?;
    target.receive(source.seal_inner_to(target, &body)?, 3).await?;
    rebuild(runtime, &target.client).await?;
    assert!(
        hits(runtime, &target.client, "secretcanary").await?.items.is_empty(),
        "authenticated spoiler content must never be searchable"
    );
    let mut query = SearchQuery::new("spoiler-visible", "visiblecanary");
    query.kinds = vec![SearchKind::Message];
    query.include_snippets = true;
    let page = runtime.query(&target.client, 1, &query).await?.take()?;
    let item = page.items.first().ok_or("visible spoiler-free word")?;
    assert!(
        !item.snippet.as_ref().ok_or("opt-in snippet")?.expose().contains("secretcanary"),
        "an opt-in snippet must not disclose concealed content while retaining whole visible words"
    );
    Ok(())
}

async fn attachment_scope(
    source: &Fixture,
    target: &mut Fixture,
    runtime: &LocalSearch,
    conversation: &str,
) -> TestResult {
    let identity = source.client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let message = ramflux_protocol::encode_base64url(&identity.id);
    let manifest = ramflux_protocol::encode_base64url([7; 32]);
    let media =
        [("search-wire", "/private/parent/reportcanary.pdf"), ("other-wire", "survivorcanary.pdf")]
            .into_iter()
            .map(|(wire, name)| g::MediaRef {
                object_id: wire.into(),
                manifest_digest: vec![7; 32],
                mime_type: "application/octet-stream".into(),
                file_name: Some(name.into()),
                ..Default::default()
            })
            .collect();
    let body = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message { media, ..Default::default() })),
        },
    )?;
    target.receive(source.seal_inner_to(target, &body)?, 4).await?;
    let query = |text: &str| {
        let mut request = SearchQuery::new("attachment-query", text);
        request.kinds = vec![SearchKind::Attachment];
        request.include_snippets = true;
        request
    };
    for (wire, reference) in
        [("other-wire", "other-reference"), ("search-wire", "search-reference")]
    {
        admit_attachment_reference(target, &message, wire, &manifest, reference)?;
        rebuild(runtime, &target.client).await?;
        if wire == "other-wire" {
            assert!(
                runtime
                    .query(&target.client, 1, &query("reportcanary.pdf"))
                    .await?
                    .take()?
                    .items
                    .is_empty(),
                "an unrelated admitted attachment must not authorize the requested wire/manifest"
            );
        }
    }
    let page = runtime.query(&target.client, 1, &query("reportcanary.pdf")).await?.take()?;
    let item = page.items.first().ok_or("admitted attachment basename")?;
    assert!(
        !item.snippet.as_ref().ok_or("attachment snippet")?.expose().contains("private"),
        "attachment snippets must contain the basename without a private path"
    );
    let mut scoped = query("reportcanary.pdf");
    scoped.conversation_id = Some("wrong-scope".into());
    assert!(
        runtime.query(&target.client, 1, &scoped).await?.take()?.items.is_empty(),
        "attachment scope must be checked against its owning message"
    );
    target.client.account_db()?.set_object_tombstoned("search-wire")?;
    assert!(
        runtime
            .query(&target.client, 1, &query("reportcanary.pdf"))
            .await?
            .take()?
            .items
            .is_empty(),
        "canonical revocation must synchronously purge the filename before maintenance"
    );
    rebuild(runtime, &target.client).await?;
    assert!(
        runtime
            .query(&target.client, 1, &query("reportcanary.pdf"))
            .await?
            .take()?
            .items
            .is_empty(),
        "a retained reference cannot rebuild a tombstoned filename"
    );
    assert_eq!(
        runtime.query(&target.client, 1, &query("survivorcanary.pdf")).await?.take()?.items.len(),
        1,
        "revoking one attachment must preserve an independently admitted survivor in the same message"
    );
    Ok(())
}

fn admit_attachment_reference(
    target: &Fixture,
    message: &str,
    wire: &str,
    manifest: &str,
    reference: &str,
) -> TestResult {
    target.client.account_db()?.register_object_reference(
        ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash: reference,
            wire_id: wire,
            manifest_hash: manifest,
            selector: wire,
            message_id: message,
            reference: &serde_json::json!({"object_id":wire,"manifest_hash":manifest}),
            metadata: &serde_json::json!({"message_id":message,"object_id":wire}),
        },
    )?;
    Ok(())
}
