// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]
//! Authenticated attribution and replay through generated Message delivery and public reads.
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_protocol::message as g;

fn authored(
    source: &Fixture,
    target: &Fixture,
    text: &str,
) -> TestResult<(crate::GatewayDirectMessage, ramflux_protocol::Envelope)> {
    let mut message = crate::GatewayDirectMessage {
        conversation_id: g::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?,
        message_id: "same-caller-operation".into(),
        envelope_id: "same-caller-envelope".into(),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.client.own_account_anchor()?),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 300,
    };
    let prepared = source.client.prepare_authored_message(
        &mut message,
        None,
        &g::Message { text: text.into(), ..Default::default() },
    )?;
    let envelope = source.seal_inner_to_with_id(target, &prepared.wire, &message.envelope_id)?;
    source.client.project_authored_message(&message, &prepared.exact, &[])?;
    Ok((message, envelope))
}

pub(super) async fn duplicate_attribution() -> TestResult {
    let alice = Fixture::new("attribution-alice").await?;
    let carol = Fixture::new("attribution-carol").await?;
    let mut bob = Fixture::new("attribution-bob").await?;
    for source in [&alice, &carol] {
        source.accept_peer(&bob)?;
        bob.accept_peer(source)?;
    }
    let (original, envelope) = authored(&alice, &bob, "Alice original body")?;
    bob.receive(envelope.clone(), 1).await?;
    let before =
        bob.client.generated_message_detail(&original.conversation_id, &original.message_id)?;
    let owner = bob
        .client
        .direct_message_by_id(&original.message_id)?
        .ok_or("test: original row")?
        .sender_id;
    let (independent, own_frame) = authored(&carol, &bob, "Carol independent body")?;
    assert_ne!(
        original.message_id, independent.message_id,
        "independent native authors sharing operation labels must allocate distinct event ids"
    );
    bob.receive(own_frame, 2).await?;
    let mut forged = envelope.clone();
    forged.source_principal_id = carol.config.principal_id.clone();
    assert!(
        bob.receive(forged, 3).await.is_err(),
        "a changed sender replaced authenticated attribution"
    );
    bob.receive(envelope, 1).await?;
    let after =
        bob.client.generated_message_detail(&original.conversation_id, &original.message_id)?;
    assert_eq!(
        serde_json::to_value(&after.message)?,
        serde_json::to_value(&before.message)?,
        "independent delivery or a forged duplicate changed the original read model"
    );
    assert_eq!(after.schema, before.schema, "the detail response changed its read-model contract");
    assert!(
        after.snapshot_sequence >= before.snapshot_sequence,
        "independent delivery moved the read-model snapshot backwards"
    );
    assert_eq!(
        bob.client
            .direct_message_by_id(&original.message_id)?
            .ok_or("test: original row")?
            .sender_id,
        owner,
        "the committed original sender was replaced"
    );
    assert_eq!(
        bob.client
            .generated_message_detail(&independent.conversation_id, &independent.message_id)?
            .message
            .text
            .as_deref(),
        Some("Carol independent body"),
        "refusing the forged duplicate must preserve unrelated authenticated content"
    );
    Ok(())
}

async fn group_pair() -> TestResult<(Fixture, Fixture, ramflux_crypto::VerifiedGroupState)> {
    let source = Fixture::new("metadata-group-source").await?;
    let target = Fixture::new("metadata-group-target").await?;
    source.accept_peer(&target)?;
    target.accept_peer(&source)?;
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("test: native group owner")?
        .group_primary(source.vault.as_ref())?;
    source.client.shared_group_create_with_primary(
        "metadata-group",
        "metadata-thread",
        None,
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let state = source.client.shared_group_change_with_primary(
        "metadata-group",
        &source.config.target_delivery_id,
        ramflux_protocol::GroupStateChange::Add {
            member: target.client.owned_group_actor(&target.config.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
    Ok((source, target, state))
}

pub(super) async fn group_metadata() -> TestResult {
    let (source, mut target, state) = Box::pin(group_pair()).await?;
    let distribution = ramflux_protocol::parse_i_json(
        &source
            .client
            .export_group_sender_key_distribution("metadata-group", &source.config.device_id)?,
    )?;
    let key = source.client.generated_group_key_inner(
        "metadata-thread",
        state.view().epoch,
        &distribution,
        &target.client.owned_device_identity()?,
    )?;
    target.receive(source.seal_inner_to(&target, &key)?, 1).await?;
    {
        let db = target.client.account_db()?;
        let mut group =
            db.client_record("group", "metadata-group")?.ok_or("test: native group metadata")?;
        group["conversation_id"] = serde_json::Value::Null;
        group["conversation_ids"] = serde_json::json!(["metadata-thread", "other-thread"]);
        group["custom"] = serde_json::json!("keep");
        db.persist_client_record("group", "metadata-group", &group)?;
        let mut thread = db
            .client_record("conversation", "metadata-thread")?
            .ok_or("test: native group thread")?;
        thread["title"] = serde_json::json!("Existing title");
        db.persist_client_record("conversation", "metadata-thread", &thread)?;
    }
    let identity = source.client.allocate_generated_identity(
        "metadata-thread",
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let exact = source.client.encrypt_generated_group_inner(
        "metadata-group",
        &source.config.device_id,
        identity,
        &g::Message { text: "authenticated group body".into(), ..Default::default() },
    )?;
    target.receive(source.seal_inner_to(&target, &exact)?, 2).await?;
    let db = target.client.account_db()?;
    let group =
        db.client_record("group", "metadata-group")?.ok_or("test: retained group metadata")?;
    assert_eq!(
        group["conversation_ids"],
        serde_json::json!(["metadata-thread", "other-thread"]),
        "generated group delivery discarded a pre-existing conversation link"
    );
    assert_eq!(
        group["custom"], "keep",
        "generated group delivery replaced unrelated display metadata"
    );
    assert_eq!(
        db.client_record("conversation", "metadata-thread")?
            .ok_or("test: retained group thread")?["title"],
        "Existing title",
        "generated group delivery overwrote the local title"
    );
    assert_eq!(
        target.client.generated_message_detail("metadata-thread", &id)?.message.text.as_deref(),
        Some("authenticated group body"),
        "metadata preservation prevented real group projection"
    );
    Ok(())
}

pub(super) async fn transient_lookup() -> TestResult {
    use crate::client::routed::tests::{native_pair_tests, review::Inbox};
    let alice = Fixture::with_principal("backoff-alice", "alice", "alice").await?;
    let carol = Fixture::with_principal("backoff-carol", "carol", "carol").await?;
    let mut bob = Fixture::with_principal("backoff-bob", "bob", "bob").await?;
    alice.accept_peer(&bob)?;
    bob.accept_peer(&alice)?;
    carol.accept_peer(&bob)?;
    let carol_root = carol.client.own_account_anchor()?;
    bob.client.establish_friend_link(
        "carol-friend",
        &bob.client.own_account_anchor()?,
        &carol_root,
    )?;
    // Accepting a root is consent, not a fetched native publication or fresh authority.
    let pending = native_pair_tests::entry(
        &carol,
        &bob,
        &native_pair_tests::text(&carol, &bob, "retry me")?,
    )?;
    let mut good = native_pair_tests::entry(
        &alice,
        &bob,
        &native_pair_tests::text(&alice, &bob, "later good message")?,
    )?;
    good.inbox_seq = 2;
    let scope = g::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )?;
    let (engine, _) = Inbox::engine(bob.config.clone(), vec![pending.clone(), good])?;
    let target = bob.config.target_delivery_id.clone();
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "backoff-bob".into(),
    );
    let now = crate::time::now_unix_timestamp();
    crate::bus::sync_driver::run_at(&mut account, now).await?;
    assert_eq!(
        account.client.direct_messages(&scope)?.len(),
        1,
        "missing sender lookup stalled later traffic"
    );
    assert_eq!(account.client.gateway_receive_cursor(&target)?, 2);
    let db = account.client.account_db()?;
    assert_eq!(db.due_inbox_retries(now + 1)?.len(), 0);
    assert_eq!(db.due_inbox_retries(now + 2)?.len(), 1);
    assert!(!db.journal_after(0, 100)?.iter().any(|event| event.topic == "message.undeliverable"));
    let key = account.client.inbox_admission_key(&pending)?;
    assert_eq!(db.defer_inbox_entry(&key, &serde_json::to_vec(&pending)?, now + 3)?, 2);
    let (engine, _) = Inbox::engine(account.gateway_config.clone(), vec![pending])?;
    account.install_test_session(engine);
    crate::bus::sync_driver::run_at(&mut account, now + 3).await?;
    assert_eq!(account.client.account_db()?.due_inbox_retries(now + 6)?.len(), 0);
    assert_eq!(account.client.account_db()?.due_inbox_retries(now + 7)?.len(), 1);
    Ok(())
}
