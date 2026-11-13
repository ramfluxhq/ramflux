// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native admitted receive, winning edits and typed local search over real SQLCipher storage.
use super::*;
use crate::search::{LocalSearch, SearchError, SearchKind, SearchQuery};
use ramflux_protocol::message as g;
use ramflux_storage::local_search::{SearchActivation, SearchControl};
use std::path::Path;

impl Fixture {
    async fn search_fixture(directory: &Path, id: &str) -> TestResult<Self> {
        let root = Root(directory.join(id));
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
    for _ in 0..32 {
        let admission = runtime.admit(1, "rebuild").await?;
        if runtime.rebuild_batch(client, 1, "rebuild", &admission)? {
            return Ok(());
        }
    }
    Err("search rebuild failed to converge within the bounded fixture".into())
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

#[tokio::test(flavor = "current_thread")]
async fn local_search_live_versions_and_scope() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let directory = tempfile::TempDir::new()?;
        let source = Fixture::search_fixture(directory.path(), "source").await?;
        let mut target = Fixture::search_fixture(directory.path(), "target").await?;
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
        rebuild(&runtime, &target.client).await?;
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
        let edit = RamfluxClient::encode_generated_inner(
            identity,
            &g::Content {
                value: Some(g::content::Value::Edit(g::Edit {
                    target: Some(g::MessageRef {
                        id: original.id.clone(),
                        conversation_id: conversation.clone(),
                        author_anchor: source_anchor,
                    }),
                    revision: 1,
                    previous_content_digest: vec![0; 32],
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
        rebuild(&runtime, &target.client).await?;
        assert_eq!(
            hits(&runtime, &target.client, "newcanary").await?.items.len(),
            1,
            "rebuild must index the accepted replacement"
        );
        target
            .client
            .account_db()?
            .hide_conversation_at(&conversation, crate::time::now_unix_timestamp())?;
        assert!(
            hits(&runtime, &target.client, "newcanary").await?.items.is_empty(),
            "visibility restriction must purge all conversation derivatives"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn local_search_epochs_and_pending_completions() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let directory = tempfile::TempDir::new()?;
        let fixture = Fixture::search_fixture(directory.path(), "epoch-owner").await?;
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let runtime =
            LocalSearch::for_db(fixture.client.account_db()?, SearchActivation::testing())?;
        let query = SearchQuery::new("empty-query", "canary");
        let completion = runtime.query(&fixture.client, 7, &query).await?;
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
        let completion =
            runtime.query(&fixture.client, 7, &SearchQuery::new("lock-query", "canary")).await?;
        runtime.invalidate();
        assert!(
            matches!(completion.take(), Err(SearchError::CursorStale)),
            "lock/publication invalidation must clear pending plaintext"
        );
        let revision = fixture
            .client
            .account_db()?
            .search_revision(&SearchActivation::testing(), &SearchControl::new())?;
        assert!(revision.revision > 0, "epoch witness must use the actual keyed database");
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}
